import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { loadAdmittedGovernanceCanonicalResource } from "../../artifacts/server/src/governance-canonical-resource.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

// Actual private caller/helper, with synthetic authority and database rows.
// This is not PostgreSQL visibility, storage-trigger, SDK or delivery-audit evidence.
interface Seam {
  liveActor(...args: unknown[]): Promise<unknown>;
  authorizeRead(...args: unknown[]): void;
  loadBoardResource(client: PoolClient, principal: SurfacePrincipal, uri: URL): Promise<unknown>;
}
const boardId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const parentId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const versionId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
const caller = { organizationId: boardId, memberId: parentId } as SurfacePrincipal;
const documentPlan = (n: number) =>
  responseAllocationPlan({
    kind: "document",
    representation: "resource",
    sourceId: versionId,
    sourceVersion: "7",
    sha256: "b".repeat(64),
    canonicalBytes: n
  });
const lanes = [
  {
    kind: "minutes",
    path: `minutes/${parentId}/versions/7`,
    tool: "get_minutes",
    entity: "minutes_version",
    mediaType: "text/plain; charset=utf-8",
    version: 7,
    maximum: 41_943_040,
    minimum: 1,
    digest: "canonical_sha256",
    record: "version_row"
  },
  {
    kind: "minutes_review",
    path: `minutes/${parentId}/review/${versionId}`,
    tool: "list_minutes_review_items",
    entity: "minutes_review_item",
    mediaType: "application/json",
    version: 1,
    maximum: 1_048_576,
    minimum: 2,
    digest: "payload_sha256",
    record: "item"
  },
  {
    kind: "decision_package",
    path: `votes/${parentId}/packages/7`,
    tool: "get_vote",
    entity: "decision_package",
    mediaType: "application/json",
    version: 7,
    maximum: 10_485_760,
    minimum: 2,
    digest: "package_sha256",
    record: "package"
  }
] as const;
type Lane = (typeof lanes)[number];
function input(lane: Lane): Parameters<typeof loadAdmittedGovernanceCanonicalResource>[1] {
  return lane.kind === "minutes_review"
    ? { kind: lane.kind, boardId, parentId, itemId: versionId }
    : { kind: lane.kind, boardId, parentId, version: 7 };
}
const materializes = (sql: string) => !sql.includes("as byte_length");
function fixture(
  lane: Lane,
  options: {
    length?: number;
    missing?: boolean;
    hiddenAfter?: boolean;
    corrupt?: "length" | "digest";
    afterMetadata?: () => void;
    beforeContent?: () => Promise<void>;
  } = {}
) {
  const bytes = Buffer.from(lane.kind === "minutes" ? "Minutes Δ 🙂\n" : '{"exact":"record Δ 🙂"}');
  const metadata = {
    id: versionId,
    version: lane.version,
    byte_length: options.length ?? bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
  const query = vi.fn(async (sql: string, _values?: unknown[]) => {
    if (options.missing) return { rows: [] };
    if (!materializes(sql)) {
      options.afterMetadata?.();
      return { rows: [metadata] };
    }
    await options.beforeContent?.();
    if (options.hiddenAfter) return { rows: [] };
    const content =
      options.corrupt === "length"
        ? Buffer.concat([bytes, Buffer.from(" ")])
        : options.corrupt === "digest"
          ? Buffer.alloc(bytes.length, 32)
          : bytes;
    // Both old combined-query and new bound-query shapes are valid. Positive old
    // callers work; baseline saturation fails because the old branch loads bytes.
    return {
      rows: [
        {
          ...metadata,
          canonical_bytes: content,
          canonical_payload: content,
          canonical_text: content.toString("utf8")
        }
      ]
    };
  });
  const client = { query } as unknown as PoolClient;
  const repository = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repository as unknown as Seam;
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const read = () =>
    seam.loadBoardResource(client, caller, new URL(`board://${boardId}/${lane.path}`));
  return {
    bytes,
    metadata,
    query,
    authorize,
    read,
    helper: () => loadAdmittedGovernanceCanonicalResource(client, input(lane))
  };
}

// Apply plan+helper+this file BEFORE the caller patch. Exactly these three
// saturation cases then expose the original full-content path; positives pass.
describe.each(lanes)("$kind resource caller", (lane) => {
  it("preserves the exact ordinary alias response and authorization", async () => {
    const f = fixture(lane);
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toEqual({
        entityType: lane.entity,
        entityId: versionId,
        boardId,
        objectVersion: BigInt(lane.version),
        mediaType: lane.mediaType,
        bytes: f.bytes
      });
      expect(f.authorize).toHaveBeenCalledWith(caller, {}, lane.tool, {});
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses saturated content before the full-content query", async () => {
    const f = fixture(lane, { length: Math.min(lane.maximum, 10_485_760) });
    const manager = new ResponseAllocationManager();
    const held = [
      manager.tryReserve(documentPlan(10_485_760)),
      manager.tryReserve(documentPlan(4_194_304))
    ];
    expect(manager.accounting.usedUnits).toBe(1794);
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.authorize).toHaveBeenCalledWith(caller, {}, lane.tool, {});
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
      expect(manager.accounting.usedUnits).toBe(1794);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      for (const lease of held) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});

describe.each(lanes)("$kind canonical loader", (lane) => {
  it("pins identity, UTF-8 length and the record's digest and retains the lease", async () => {
    const f = fixture(lane);
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.helper)).resolves.toEqual({
        id: versionId,
        version: lane.version,
        bytes: f.bytes
      });
      expect(manager.accounting.usedUnits).toBe(1);
      const [sql, values] = f.query.mock.calls[1]!;
      expect(values).toEqual([
        boardId,
        parentId,
        lane.kind === "minutes_review" ? versionId : 7,
        versionId,
        f.bytes.length,
        Buffer.from(f.metadata.sha256, "hex")
      ]);
      expect(sql).toContain(`${lane.record}.id=$4`);
      expect(sql).toContain(`${lane.record}.${lane.digest}=$6`);
      const byteExpression =
        lane.kind === "minutes"
          ? "convert_to(version_row.canonical_text,'UTF8')"
          : `${lane.record}.canonical_payload`;
      expect(sql).toContain(`octet_length(${byteExpression})=$5`);
      const scopes =
        lane.kind === "decision_package"
          ? [
              "vote.board_id=$1",
              "vote.id=$2",
              "package.version=$3",
              "boardagent_member_vote_recused(vote.id",
              "boardagent_context_uuid('boardagent.member_id')"
            ]
          : [
              "minutes.board_id=$1",
              "minutes.id=$2",
              lane.kind === "minutes" ? "version_row.version=$3" : "item.id=$3"
            ];
      for (const [statement] of f.query.mock.calls)
        for (const scope of scopes) expect(statement).toContain(scope);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it.each([lane.minimum - 1, lane.maximum + 1])(
    "rejects impossible stored byte length %s before loading",
    async (length) => {
      const f = fixture(lane, { length });
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(owner.produce(f.helper)).rejects.toThrow(
          "authorized response byte length is invalid"
        );
        expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
  );
});

describe("shared governance canonical loader", () => {
  const lane = lanes[0];
  it("returns an initially hidden target without a reservation", async () => {
    const f = fixture(lane, { missing: true });
    // Hidden metadata needs no native owner and never enters the byte loader.
    await expect(f.helper()).resolves.toBeNull();
    expect(f.query).toHaveBeenCalledTimes(1);
    expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
  });
  it("requires a native owner before loading visible bytes", async () => {
    const f = fixture(lane);
    await expect(f.helper()).rejects.toThrow("native response allocation owner is required");
    expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
  });
  it("prevents the load when a disconnect follows preflight", async () => {
    const abort = new AbortController();
    const f = fixture(lane, { afterMetadata: () => abort.abort() });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(abort.signal);
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query.mock.calls.some(([sql]) => materializes(sql))).toBe(false);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it.each(["length", "digest"] as const)(
    "rejects loaded %s mismatch without releasing early",
    async (corrupt) => {
      const f = fixture(lane, { corrupt });
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(owner.produce(f.helper)).rejects.toThrow(
          "governance canonical resource failed integrity verification"
        );
        expect(manager.accounting.usedUnits).toBe(1);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
  );
  it("does not substitute a row lost at the content reselect", async () => {
    const f = fixture(lane, { hiddenAfter: true });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.helper)).resolves.toBeNull();
      expect(f.query).toHaveBeenCalledTimes(2);
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});

describe("minutes character-bound policy", () => {
  const plan = (canonicalBytes: number) =>
    responseAllocationPlan({ ...documentPlan(1), kind: "minutes_text", canonicalBytes });
  it("admits a one-byte text and a supported 10 MiB text alongside 100 small reservations", () => {
    const manager = new ResponseAllocationManager();
    const leases = [manager.tryReserve(plan(10_485_760))];
    try {
      expect(plan(1).units).toBe(1);
      expect(plan(10_485_760).units).toBe(1281);
      expect(plan(10_485_760).wireUpperBytes).toBe(65_536 + 6 * 10_485_760);
      for (let i = 0; i < 100; i += 1) leases.push(manager.tryReserve(plan(1)));
      expect(manager.accounting).toEqual({ usedUnits: 1381, largeUsedUnits: 1281 });
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("classifies a valid four-byte character maximum as capacity refusal, not invalid size", () => {
    const maximum = plan(41_943_040);
    expect(maximum.units).toBe(5121);
    expect(() => new ResponseAllocationManager().tryReserve(maximum)).toThrow(
      ResponseAllocationUnavailable
    );
    expect(() => plan(41_943_041)).toThrow("authorized response byte length is invalid");
  });
  it("admits the last 1920-unit byte count and refuses one further byte", () => {
    // Independently solve the stated BASE+128N <=1920MiB policy.
    const lastByte = (1920 * 1_048_576 - 65_536) / 128;
    const manager = new ResponseAllocationManager();
    const lease = manager.tryReserve(plan(lastByte));
    expect(plan(lastByte).units).toBe(1920);
    lease.release();
    expect(plan(lastByte + 1).units).toBe(1921);
    expect(() => manager.tryReserve(plan(lastByte + 1))).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("does not declare composite tool results covered", () => {
    expect(() => responseAllocationPlan({ ...plan(1), representation: "tool" })).toThrow(
      "minutes text allocation requires the resource representation"
    );
  });
  it("retains admitted bytes after early terminal signals until the producer ends", async () => {
    let started!: () => void, release!: () => void;
    const began = new Promise<void>((resolve) => {
      started = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const f = fixture(lanes[0], {
      beforeContent: async () => {
        started();
        await gate;
      }
    });
    const manager = new ResponseAllocationManager();
    const abort = new AbortController();
    const owner = manager.openRequest(abort.signal);
    const pending = owner.produce(f.helper);
    await began;
    try {
      abort.abort();
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      release();
    }
    await expect(pending).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
