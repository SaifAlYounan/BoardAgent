import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

// Controlled actual private resource callers. SQL/RLS and native delivery are
// separately exercised; these cases do not claim either boundary.
interface Seam {
  liveActor(...args: unknown[]): Promise<unknown>;
  authorizeRead(...args: unknown[]): void;
  loadBoardResource(client: PoolClient, principal: SurfacePrincipal, uri: URL): Promise<unknown>;
}
const boardId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const versionId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const caller = { organizationId: boardId, memberId: versionId } as SurfacePrincipal;
const occupied = responseAllocationPlan({
  kind: "document",
  representation: "resource",
  sourceId: versionId,
  sourceVersion: "1",
  sha256: "b".repeat(64),
  canonicalBytes: 10_485_760
});
const lanes = [
  {
    kind: "governance_profile",
    path: "governance-profile/7",
    tool: "get_board_governance_profile",
    table: "governance_profiles"
  },
  { kind: "ruleset", path: "rulesets/7", tool: "get_ruleset", table: "rulesets" }
] as const;

describe("JSON resource size policy", () => {
  const plan = (n: number) =>
    responseAllocationPlan({
      kind: "json_resource",
      representation: "resource",
      sourceId: versionId,
      sourceVersion: "1",
      sha256: "a".repeat(64),
      canonicalBytes: n
    });
  it("does not impose the document maximum on JSONB resources", () => {
    const largerThanDocument = plan(11 * 1_048_576);
    expect(largerThanDocument.units).toBe(1409);
    const manager = new ResponseAllocationManager();
    const lease = manager.tryReserve(largerThanDocument);
    lease.release();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("keeps the exact large-work boundary and small lane", () => {
    const manager = new ResponseAllocationManager();
    const boundary = plan(15_728_128);
    expect(boundary.units).toBe(1920);
    expect(plan(15_728_129).units).toBe(1921);
    expect(() => manager.tryReserve(plan(15_728_129))).toThrow(ResponseAllocationUnavailable);
    const held = manager.tryReserve(boundary);
    const small = Array.from({ length: 100 }, () => manager.tryReserve(plan(2)));
    expect(manager.accounting.usedUnits).toBe(2020);
    small.forEach((lease) => lease.release());
    held.release();
  });
  it("rejects invalid byte lengths and a tool representation", () => {
    for (const n of [0, 1, -1, 2.5, Number.NaN, Number.POSITIVE_INFINITY])
      expect(() => plan(n)).toThrow();
    expect(() => responseAllocationPlan({ ...plan(2), representation: "tool" })).toThrow(
      "resource representation"
    );
  });
});
function fixture(
  lane: (typeof lanes)[number],
  options: {
    length?: number;
    missing?: boolean;
    hiddenAfter?: boolean;
    corrupt?: "length" | "digest";
    afterMetadata?: () => void;
  } = {}
) {
  // PostgreSQL JSONB whitespace/member order are deliberately not JCS. Existing
  // public resource bytes are canonicalized after parsing, and must stay exact.
  const text = '{"z": [1, true, null, "Δ\\n"], "a": {"x": 0.00001}}';
  const bytes = Buffer.from(text);
  const payload = JSON.parse(text);
  const metadata = {
    id: versionId,
    version: 7,
    byte_length: options.length ?? bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
  const contentQueries: string[] = [];
  const query = vi.fn(async (sql: string, _values?: unknown[]) => {
    if (options.missing) return { rows: [] };
    if (sql.includes("as byte_length")) {
      options.afterMetadata?.();
      return { rows: [metadata] };
    }
    contentQueries.push(sql);
    if (options.hiddenAfter) return { rows: [] };
    const raw =
      options.corrupt === "length"
        ? Buffer.concat([bytes, Buffer.from(" ")])
        : options.corrupt === "digest"
          ? Buffer.alloc(bytes.length, 32)
          : bytes;
    // Preserve the old combined-query row shape for a meaningful baseline.
    return { rows: [{ ...metadata, canonical_payload: payload, raw_bytes: raw }] };
  });
  const repo = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repo as unknown as Seam;
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const read = () =>
    seam.loadBoardResource(
      { query } as unknown as PoolClient,
      caller,
      new URL(`board://${boardId}/${lane.path}`)
    );
  return {
    query,
    authorize,
    read,
    contentQueries,
    bytes,
    metadata,
    expected: Buffer.from(canonicalJson(payload))
  };
}

describe.each(lanes)("$kind JSON resource admission", (lane) => {
  it("refuses saturation before loading JSONB text or a parsed graph", async () => {
    const f = fixture(lane, { length: 10_485_760 });
    const manager = new ResponseAllocationManager();
    const lease = manager.tryReserve(occupied);
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.contentQueries).toEqual([]);
      expect(f.authorize).toHaveBeenCalledWith(caller, {}, lane.tool, { board_id: boardId });
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves canonical resource bytes and holds admission through settlement", async () => {
    const f = fixture(lane);
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toEqual({
        entityType: lane.kind,
        entityId: versionId,
        boardId,
        objectVersion: 7n,
        mediaType: "application/json",
        bytes: f.expected
      });
      expect(manager.accounting.usedUnits).toBe(1);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("returns a hidden target without a content query", async () => {
    const f = fixture(lane, { missing: true });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toBeNull();
      expect(f.contentQueries).toEqual([]);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("reselects the original board/version and binds the exact scalar digest", async () => {
    const f = fixture(lane);
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(f.read);
      expect(f.query).toHaveBeenCalledTimes(2);
      for (const [sql, values] of f.query.mock.calls) {
        expect(sql).toContain(`from ${lane.table}`);
        expect(sql).toContain("board_id=$1 and version=$2");
        expect(values?.slice(0, 2)).toEqual([boardId, 7]);
      }
      expect(f.query.mock.calls[1]?.[1]).toEqual([
        boardId,
        7,
        versionId,
        f.bytes.length,
        Buffer.from(f.metadata.sha256, "hex")
      ]);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it.each(["length", "digest"] as const)(
    "rejects a changed returned %s before parsing",
    async (corrupt) => {
      const f = fixture(lane, { corrupt });
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(owner.produce(f.read)).rejects.toThrow(
          "JSON resource failed integrity verification"
        );
        expect(manager.accounting.usedUnits).toBe(1);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
  );
  it("returns no bytes after the authorized target disappears", async () => {
    const f = fixture(lane, { hiddenAfter: true });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toBeNull();
      expect(f.query).toHaveBeenCalledTimes(2);
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("stops before content when cancelled after metadata", async () => {
    const controller = new AbortController();
    const f = fixture(lane, { afterMetadata: () => controller.abort() });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(controller.signal);
    try {
      await expect(owner.produce(f.read)).rejects.toThrow();
      expect(f.contentQueries).toEqual([]);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
});
