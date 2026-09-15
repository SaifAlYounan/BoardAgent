import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

const boardId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const caller = { organizationId: boardId, memberId: boardId } as SurfacePrincipal;
const smallPlan = responseAllocationPlan({
  kind: "document",
  representation: "resource",
  sourceId: boardId,
  sourceVersion: "1",
  sha256: "a".repeat(64),
  canonicalBytes: 1
});
interface Seam {
  liveActor(...args: unknown[]): Promise<unknown>;
  authorizeRead(...args: unknown[]): void;
  prepareResourceAudit(...args: unknown[]): Promise<string>;
  observePreparedResource(
    principal: unknown,
    response: SurfaceToolResult,
    ...args: unknown[]
  ): SurfaceToolResult;
  getBoard(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    id: string
  ): Promise<SurfaceToolResult>;
  loadBoardResource(
    client: PoolClient,
    principal: SurfacePrincipal,
    uri: URL
  ): Promise<{ bytes: Buffer } | null>;
}
type Lane = "tool" | "resource";
function fixture(
  lane: Lane,
  options: { missing?: boolean; hidden?: boolean; afterMetadata?: () => void } = {}
) {
  const common = {
    board_id: boardId,
    slug: "mining-exploration-co",
    name: 'Mining Δ 🙂\n"',
    timezone: "Asia/Dubai",
    state: "active",
    current_version_id: null,
    governance_profile_id: null,
    ruleset_id: null,
    row_version: "7"
  };
  const view = { ...common, created_at: "2026-09-12T00:00:00.000000Z" };
  const payload = { schema_version: "boardagent.board-resource.v1", ...common };
  let contentQueries = 0;
  const query = vi.fn(async (sql: string) => {
    if (options.missing) return { rows: [] };
    if (sql.includes("as admitted_board_id")) {
      options.afterMetadata?.();
      return { rows: [{ admitted_board_id: boardId, row_version: "7" }] };
    }
    contentQueries += 1;
    if (options.hidden) return { rows: [] };
    // Both original projections are present, making the old public caller a
    // valid positive control before it is routed through the admitted helper.
    return {
      rows: [
        {
          id: boardId,
          row_version: "7",
          view,
          payload: sql.includes("'created_at'") ? view : payload
        }
      ]
    };
  });
  const repo = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repo as unknown as Seam;
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const audit = vi.spyOn(seam, "prepareResourceAudit").mockResolvedValue(boardId);
  vi.spyOn(seam, "observePreparedResource").mockImplementation((_principal, response) => response);
  const read = async (): Promise<SurfaceToolResult | { bytes: Buffer } | null> =>
    lane === "tool"
      ? seam.getBoard({ query } as unknown as PoolClient, caller, "get_board", boardId)
      : seam.loadBoardResource(
          { query } as unknown as PoolClient,
          caller,
          new URL(`board://${boardId}`)
        );
  return { read, query, audit, view, payload, contentQueries: () => contentQueries };
}

// These are actual private callers with controlled rows/authority/audit. Real
// PostgreSQL visibility and native delivery are separate evidence boundaries.
describe.each(["tool", "resource"] as const)("board %s admission", (lane) => {
  it("preserves its own exact original projection", async () => {
    const f = fixture(lane),
      manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      const value = await owner.produce(f.read);
      if (lane === "tool") {
        expect((value as SurfaceToolResult).data).toEqual({ board: f.view });
        expect(f.audit).toHaveBeenCalledOnce();
      } else {
        expect((value as { bytes: Buffer }).bytes).toEqual(Buffer.from(canonicalJson(f.payload)));
        expect(f.audit).not.toHaveBeenCalled();
      }
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("returns an absent board without spending capacity", async () => {
    const f = fixture(lane, { missing: true }),
      manager = new ResponseAllocationManager();
    const held = Array.from({ length: 2048 }, () => manager.tryReserve(smallPlan));
    const owner = manager.openRequest(new AbortController().signal);
    try {
      const value = await owner.produce(f.read);
      expect(lane === "tool" ? (value as SurfaceToolResult).data : value).toEqual(
        lane === "tool" ? { board: null } : null
      );
      expect(f.contentQueries()).toBe(0);
      expect(f.audit).not.toHaveBeenCalled();
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      held.forEach((lease) => lease.release());
    }
  });
  it("refuses a visible board before constructing content when capacity is full", async () => {
    const f = fixture(lane),
      manager = new ResponseAllocationManager();
    const held = Array.from({ length: 2048 }, () => manager.tryReserve(smallPlan));
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toThrow(ResponseAllocationUnavailable);
      expect(f.contentQueries()).toBe(0);
      expect(f.audit).not.toHaveBeenCalled();
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      held.forEach((lease) => lease.release());
    }
  });
  it("does not load content after disconnect during scalar metadata", async () => {
    const controller = new AbortController();
    const f = fixture(lane, { afterMetadata: () => controller.abort() });
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(controller.signal);
    try {
      await expect(owner.produce(f.read)).rejects.toThrow(ResponseAllocationUnavailable);
      expect(f.contentQueries()).toBe(0);
      expect(f.audit).not.toHaveBeenCalled();
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("holds its small reservation until producer, native and collector finish", async () => {
    const f = fixture(lane),
      manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(f.read);
      expect(manager.accounting.usedUnits).toBe(1);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(1);
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
});

describe("fixed board point policy", () => {
  const plan = (representation: Lane) =>
    responseAllocationPlan({
      ...smallPlan,
      kind: "board_projection",
      representation,
      canonicalBytes: 0
    });
  it("covers independently serialized maximum storage fields and escaping in both views", () => {
    for (const character of ["🙂", "界", "\u0001", '"', "\\"]) {
      const common = {
        board_id: boardId,
        slug: "a".repeat(80),
        name: character.repeat(512),
        timezone: character.repeat(128),
        state: "archived",
        current_version_id: boardId,
        governance_profile_id: boardId,
        ruleset_id: boardId,
        row_version: "9223372036854775807"
      };
      const views = [
        { ...common, created_at: "294276-12-31T23:59:59.999999Z" },
        { schema_version: "boardagent.board-resource.v1", ...common }
      ];
      for (const view of views) {
        expect(Object.keys(view)).toHaveLength(10);
        expect(Object.values(view).every((value) => typeof value === "string")).toBe(true);
        expect(Buffer.byteLength(JSON.stringify(view))).toBeLessThan(32768);
        expect(Buffer.byteLength(canonicalJson(view))).toBeLessThan(32768);
      }
    }
    expect(plan("tool").units).toBe(1);
    expect(plan("resource").units).toBe(1);
  });
  it("retains eligibility for 100 ordinary board reads alongside the entire large lane", () => {
    const manager = new ResponseAllocationManager();
    const large = manager.tryReserve(
      responseAllocationPlan({
        ...smallPlan,
        kind: "json_resource",
        canonicalBytes: 15_728_128
      })
    );
    const small = Array.from({ length: 100 }, (_, i) =>
      manager.tryReserve(plan(i % 2 ? "tool" : "resource"))
    );
    expect(manager.accounting).toEqual({ usedUnits: 2020, largeUsedUnits: 1920 });
    small.forEach((lease) => lease.release());
    large.release();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects a raw body or arbitrary projection under the fixed board plan", () => {
    expect(() => responseAllocationPlan({ ...plan("tool"), canonicalBytes: 1 })).toThrow(
      "fixed field allowance"
    );
    expect(() =>
      responseAllocationPlan({
        ...plan("resource"),
        listProjection: {
          jsonUpperBytes: "1",
          propertyCount: "1",
          objectOrArrayCount: "1"
        }
      })
    ).toThrow("fixed field allowance");
  });
});
