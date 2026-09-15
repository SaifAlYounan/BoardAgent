import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

// Actual private caller; authority and database rows are controlled. This is not
// PostgreSQL RLS, immutable-storage or native HTTPS evidence.
interface Seam {
  liveActor(...args: unknown[]): Promise<unknown>;
  authorizeRead(...args: unknown[]): void;
  loadBoardResource(client: PoolClient, principal: SurfacePrincipal, uri: URL): Promise<unknown>;
}
const boardId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const parentId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const versionId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
const caller = { organizationId: boardId, memberId: parentId } as SurfacePrincipal;
const maximum = responseAllocationPlan({
  kind: "document",
  representation: "resource",
  sourceId: versionId,
  sourceVersion: "7",
  sha256: "b".repeat(64),
  canonicalBytes: 10_485_760
});
const lanes = [
  {
    kind: "submission",
    path: `submissions/${parentId}/versions/7`,
    tool: "get_management_submission",
    entity: "management_submission_version"
  },
  {
    kind: "agenda",
    path: `meetings/${parentId}/agendas/7`,
    tool: "get_agenda",
    entity: "agenda_version"
  }
] as const;
const materializes = (sql: string) => !sql.includes("as byte_length");
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
  const bytes = Buffer.from('{"exact":"record Δ"}');
  const metadata = {
    id: versionId,
    version: 7,
    byte_length: options.length ?? bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
  const query = vi.fn(async (sql: string, _values?: unknown[]) => {
    if (options.missing) return { rows: [] };
    if (!materializes(sql)) {
      options.afterMetadata?.();
      return { rows: [metadata] };
    }
    if (options.hiddenAfter) return { rows: [] };
    const content =
      options.corrupt === "length"
        ? Buffer.concat([bytes, Buffer.from(" ")])
        : options.corrupt === "digest"
          ? Buffer.alloc(bytes.length, 32)
          : bytes;
    // The old combined queries receive their real row shape, allowing meaningful
    // failing-first execution rather than an artificial mock exception.
    return { rows: [{ ...metadata, canonical_payload: content }] };
  });
  const repository = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repository as unknown as Seam;
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const read = () =>
    seam.loadBoardResource(
      { query } as unknown as PoolClient,
      caller,
      new URL(`board://${boardId}/${lane.path}`)
    );
  return { bytes, metadata, query, authorize, read };
}

describe.each(lanes)("$kind canonical resource admission", (lane) => {
  it("refuses saturated large reads before materializing content", async () => {
    const f = fixture(lane, { length: 10_485_760 });
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(maximum);
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.authorize).toHaveBeenCalledWith(caller, {}, lane.tool, {});
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
      expect(manager.accounting.usedUnits).toBe(1281);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      held.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("preserves exact successful bytes and charges through collector settlement", async () => {
    const f = fixture(lane);
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toEqual({
        entityType: lane.entity,
        entityId: versionId,
        boardId,
        objectVersion: 7n,
        mediaType: "application/json",
        bytes: f.bytes
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

  it("returns hidden targets without consulting capacity", async () => {
    const f = fixture(lane, { missing: true });
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(maximum);
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toBeNull();
      expect(manager.accounting.usedUnits).toBe(1281);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      held.release();
    }
  });

  it("requires the native owner before loading a visible version", async () => {
    const f = fixture(lane);
    await expect(f.read()).rejects.toThrow("native response allocation owner is required");
    expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
  });

  it("stops after metadata when the request disconnects", async () => {
    const abort = new AbortController();
    const f = fixture(lane, { afterMetadata: () => abort.abort() });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(abort.signal);
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it.each([1, 10_485_761])("rejects stored length %s before loading", async (length) => {
    const f = fixture(lane, { length });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toThrow(
        "authorized response byte length is invalid"
      );
      expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it.each(["length", "digest"] as const)("refuses loaded %s corruption", async (corrupt) => {
    const f = fixture(lane, { corrupt });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toThrow(
        "canonical version failed integrity verification"
      );
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("pins the exact version, length and digest and retains all visibility predicates", async () => {
    const f = fixture(lane, { hiddenAfter: true });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toBeNull();
      const contentCall = f.query.mock.calls[1];
      expect(contentCall).toBeDefined();
      const [sql, values] = contentCall!;
      expect(sql).toContain(`version_row.id=$${lane.kind === "submission" ? 5 : 4}`);
      expect(sql).toContain(
        `octet_length(version_row.canonical_payload)=$${lane.kind === "submission" ? 6 : 5}`
      );
      expect(values).toEqual([
        boardId,
        parentId,
        7,
        ...(lane.kind === "submission" ? [caller.memberId] : []),
        versionId,
        f.bytes.length,
        Buffer.from(f.metadata.sha256, "hex")
      ]);
      if (lane.kind === "submission") {
        expect(sql).toContain("any(thread.management_owner_ids)");
        expect(sql).toContain("thread.assigned_secretary_id=$4");
        expect(sql).toContain("membership.state='active' and membership.is_secretary");
      } else expect(sql).toContain("meeting.id=$2");
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
});

describe("canonical resource policy boundary", () => {
  it("admits the supported maximum with the existing text-body allowance", () => {
    const plan = responseAllocationPlan({ ...maximum, kind: "canonical_resource" });
    const manager = new ResponseAllocationManager();
    const lease = manager.tryReserve(plan);
    try {
      expect(plan.units).toBe(1281);
      expect(plan.wireUpperBytes).toBe(65_536 + 6 * 10_485_760);
      expect(manager.accounting.largeUsedUnits).toBe(1281);
    } finally {
      lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("does not declare composite tool responses covered", () => {
    expect(() =>
      responseAllocationPlan({ ...maximum, kind: "canonical_resource", representation: "tool" })
    ).toThrow("canonical version allocation requires the resource representation");
  });
});
