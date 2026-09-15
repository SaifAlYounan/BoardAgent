import { readFileSync } from "node:fs";
import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  loadAdmittedVoteProjection,
  VOTE_PROJECTION_PREFLIGHT_SQL,
  VOTE_PROJECTION_CONTENT_SQL,
  voteProjectionCost,
  voteProjectionPlan,
  type VoteProjectionMetadata
} from "../../artifacts/server/src/vote-projection-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_VOTE_RESOURCE_SQL } from "../helpers/vote-resource-original-sql.js";

const id = (n: number) => `01993400-0000-7000-8000-${String(n).padStart(12, "0")}`;
const at = "2026-09-12T18:00:00.000000Z";
function graph(
  hasOutcome = true,
  tally: JsonValue = { label: "Synthetic Δ", values: [1, null, true, {}], yesWeight: "1" }
) {
  return {
    schema_version: "boardagent.vote-resource.v1",
    vote_id: id(1),
    board_id: id(2),
    title: "Synthetic vote Δ 🙂\n",
    state: "closed",
    resolution_version_id: id(3),
    decision_package_id: id(4),
    approval_rule_id: id(5),
    governance_profile_id: id(6),
    ruleset_id: id(7),
    electorate_sha256: "a".repeat(64),
    close_mode: "automatic",
    deadline_at: at,
    row_version: "7",
    outcome: hasOutcome
      ? {
          outcome_id: id(8),
          canonical_tally: tally,
          tally_sha256: "b".repeat(64),
          outcome: "approved",
          certificate_id: id(9)
        }
      : null
  };
}
type Payload = ReturnType<typeof graph>;
type Metadata = { -readonly [K in keyof VoteProjectionMetadata]: VoteProjectionMetadata[K] };
function shape(value: unknown) {
  const stack: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (stack.length) {
    const item = stack.pop();
    if (item && typeof item === "object") {
      containers += 1;
      if (!Array.isArray(item)) properties += Object.keys(item).length;
      for (const child of Object.values(item)) stack.push(child);
    }
  }
  return { properties, containers };
}
// Independent enumeration, without using helper field maps or bound constants.
function measure(q: Payload): Metadata {
  const values: unknown[] = [
    q.schema_version,
    q.vote_id,
    q.board_id,
    q.title,
    q.state,
    q.resolution_version_id,
    q.decision_package_id,
    q.approval_rule_id,
    q.governance_profile_id,
    q.ruleset_id,
    q.electorate_sha256,
    q.close_mode,
    q.deadline_at,
    q.row_version
  ];
  if (q.outcome)
    values.push(
      q.outcome.outcome_id,
      q.outcome.tally_sha256,
      q.outcome.outcome,
      q.outcome.certificate_id
    );
  const json = q.outcome ? JSON.stringify(q.outcome.canonical_tally) : "";
  const nested = shape(q.outcome?.canonical_tally);
  return {
    id: q.vote_id,
    board_id: q.board_id,
    row_version: q.row_version,
    outcome_id: q.outcome?.outcome_id ?? null,
    outcome_count: q.outcome ? "1" : "0",
    scalar_utf8: String(
      values.reduce<number>((sum, v) => sum + (v === null ? 0 : Buffer.byteLength(String(v))), 0)
    ),
    json_utf8: String(Buffer.byteLength(json)),
    json_properties: String(nested.properties),
    json_containers: String(nested.containers)
  };
}
function fixture(q = graph()) {
  const metadata = measure(q);
  const state = {
    missing: false,
    hidden: false,
    fits: true,
    payload: q,
    returnedOutcomeId: metadata.outcome_id,
    constructions: 0,
    beforeContent: undefined as undefined | (() => Promise<void>),
    afterMetadata: undefined as undefined | (() => void)
  };
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === VOTE_PROJECTION_PREFLIGHT_SQL) {
      state.afterMetadata?.();
      return {
        rows:
          state.missing || values?.[0] !== metadata.board_id || values?.[1] !== metadata.id
            ? []
            : [{ ...metadata }]
      };
    }
    if (sql === VOTE_PROJECTION_CONTENT_SQL) {
      await state.beforeContent?.();
      if (state.hidden) return { rows: [] };
      if (state.fits) state.constructions += 1;
      return {
        rows: [
          {
            id: metadata.id,
            row_version: metadata.row_version,
            outcome_id: state.returnedOutcomeId,
            fits: state.fits,
            payload: state.fits ? state.payload : null
          }
        ]
      };
    }
    // Supports the old query and exact original values: the intended baseline
    // failure is premature full construction, not an unrecognized SQL string.
    if (sql === ORIGINAL_VOTE_RESOURCE_SQL) {
      state.constructions += 1;
      return {
        rows: state.missing ? [] : [{ id: q.vote_id, row_version: q.row_version, payload: q }]
      };
    }
    throw new Error("unexpected vote fixture query");
  });
  const client = { query } as unknown as PoolClient;
  const repository = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repository as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    loadBoardResource(
      client: PoolClient,
      principal: SurfacePrincipal,
      uri: URL
    ): Promise<{ bytes: Buffer; objectVersion: bigint } | null>;
  };
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const principal = { organizationId: id(99), memberId: id(98) } as SurfacePrincipal;
  return {
    q,
    metadata,
    state,
    query,
    client,
    authorize,
    read: () =>
      seam.loadBoardResource(
        client,
        principal,
        new URL(`board://${q.board_id}/votes/${q.vote_id}`)
      ),
    helper: () => loadAdmittedVoteProjection(client, q.board_id, q.vote_id)
  };
}
const small = () =>
  responseAllocationPlan({
    kind: "document",
    representation: "resource",
    sourceId: "small",
    sourceVersion: "1",
    sha256: "a".repeat(64),
    canonicalBytes: 1
  });
async function owned<T>(manager: ResponseAllocationManager, work: () => Promise<T>) {
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(work);
  } finally {
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}
function boundaryMetadata(): Metadata {
  return {
    id: id(1),
    board_id: id(2),
    row_version: "1",
    outcome_id: id(8),
    outcome_count: "1",
    scalar_utf8: "1000",
    json_utf8: "251637588",
    json_properties: "1",
    json_containers: "1"
  };
}

describe("vote resource measured projection admission", () => {
  it("refuses the saturated old resource caller before full content construction", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    const held = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
      expect(
        f.query.mock.calls.filter(([sql]) => sql === VOTE_PROJECTION_PREFLIGHT_SQL)
      ).toHaveLength(1);
      expect(f.query.mock.calls.some(([sql]) => sql === VOTE_PROJECTION_CONTENT_SQL)).toBe(false);
    } finally {
      for (const lease of held) lease.release();
    }
  });
  for (const hasOutcome of [true, false])
    it(`preserves frozen original bytes with outcome=${String(hasOutcome)}`, async () => {
      const f = fixture(graph(hasOutcome)),
        manager = new ResponseAllocationManager();
      const result = await owned(manager, f.read);
      const expected = readFileSync(
        path.resolve(
          import.meta.dirname,
          `../fixtures/vote-resource-${hasOutcome ? "with-outcome" : "without-outcome"}.txt`
        )
      );
      expect(result?.bytes).toEqual(expected);
      expect(result?.objectVersion).toBe(7n);
      expect(JSON.parse(expected.toString("utf8"))).toEqual(f.q);
      expect(Object.keys(f.q)).toHaveLength(15);
      if (f.q.outcome) expect(Object.keys(f.q.outcome)).toHaveLength(5);
      expect(f.authorize).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        "get_vote",
        {}
      );
      expect(f.state.constructions).toBe(1);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  it("returns absent roots without loading a payload", async () => {
    const f = fixture();
    f.state.missing = true;
    const manager = new ResponseAllocationManager();
    expect(await owned(manager, f.helper)).toBeNull();
    expect(f.state.constructions).toBe(0);
    expect(f.query).toHaveBeenCalledTimes(1);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("requires an explicit native owner for a visible vote", async () => {
    const f = fixture();
    await expect(f.helper()).rejects.toThrow("native response allocation owner is required");
    expect(f.query.mock.calls.some(([sql]) => sql === VOTE_PROJECTION_CONTENT_SQL)).toBe(false);
  });
  it("keeps the board and vote selectors at both boundaries", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    expect(
      await owned(manager, () => loadAdmittedVoteProjection(f.client, id(90), f.q.vote_id))
    ).toBeNull();
    await owned(manager, f.helper);
    expect(
      f.query.mock.calls.find(([sql]) => sql === VOTE_PROJECTION_CONTENT_SQL)?.[1]?.slice(0, 2)
    ).toEqual([f.q.board_id, f.q.vote_id]);
  });
  it("binds root version, selected outcome ID and every fresh scalar cost", async () => {
    const f = fixture();
    await owned(new ResponseAllocationManager(), f.helper);
    const call = f.query.mock.calls.find(([sql]) => sql === VOTE_PROJECTION_CONTENT_SQL)!;
    expect(call[1]).toEqual([
      f.metadata.board_id,
      f.metadata.id,
      f.metadata.row_version,
      f.metadata.outcome_id,
      f.metadata.outcome_count,
      f.metadata.scalar_utf8,
      f.metadata.json_utf8,
      f.metadata.json_properties,
      f.metadata.json_containers
    ]);
  });
  it("refuses a present changed or larger projection instead of pretending it vanished", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.fits = false;
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
      expect(manager.accounting.usedUnits).toBe(voteProjectionPlan(f.metadata).units);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
    f.state.hidden = true;
    expect(await owned(manager, f.helper)).toBeNull();
  });
  it("returns same-cost current content within the bound root/outcome identities", async () => {
    const f = fixture();
    f.state.payload = graph(true, {
      label: "Synthetic Ω",
      values: [2, null, true, {}],
      yesWeight: "1"
    });
    const fresh = measure(f.state.payload);
    expect(fresh.json_utf8).toBe(f.metadata.json_utf8);
    expect(fresh.json_properties).toBe(f.metadata.json_properties);
    expect(fresh.json_containers).toBe(f.metadata.json_containers);
    expect((await owned(new ResponseAllocationManager(), f.helper))?.payload).toEqual(
      f.state.payload
    );
  });
  it("rejects a returned outcome substitution even when a synthetic row says fits", async () => {
    const f = fixture();
    f.state.returnedOutcomeId = id(90);
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(
      "vote projection identity is invalid"
    );
  });
  it("rejects a payload tuple that differs from the selected private row", async () => {
    const f = fixture();
    f.state.payload = { ...f.q, board_id: id(90) };
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(
      "vote projection payload identity is invalid"
    );
  });
  it("refuses known oversized JSON before issuing content", async () => {
    const f = fixture();
    f.metadata.json_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.query.mock.calls.some(([sql]) => sql === VOTE_PROJECTION_CONTENT_SQL)).toBe(false);
  });
  it("does not begin content after metadata-time disconnect", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    const owner = manager.openRequest(abort.signal);
    f.state.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query.mock.calls.some(([sql]) => sql === VOTE_PROJECTION_CONTENT_SQL)).toBe(false);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("retains the lease after early terminal signals while content is still pending", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    let enter!: () => void, release!: () => void;
    const entered = new Promise<void>((r) => {
        enter = r;
      }),
      gate = new Promise<void>((r) => {
        release = r;
      });
    f.state.beforeContent = async () => {
      enter();
      await gate;
    };
    const owner = manager.openRequest(abort.signal),
      pending = owner.produce(f.helper);
    await entered;
    abort.abort();
    owner.nativeTerminal();
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(voteProjectionPlan(f.metadata).units);
    release();
    await expect(pending).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("has an exact 1920-unit boundary, recomputes forged weights and preserves 100 small reservations", () => {
    const metadata = boundaryMetadata(),
      manager = new ResponseAllocationManager();
    const plan = voteProjectionPlan(metadata);
    expect(plan.units).toBe(1920);
    const large = manager.tryReserve(plan),
      ordinary = voteProjectionPlan(measure(graph()));
    expect(ordinary.units).toBe(1);
    const held = Array.from({ length: 100 }, () => manager.tryReserve(ordinary));
    expect(manager.accounting).toEqual({ usedUnits: 2020, largeUsedUnits: 1920 });
    for (const lease of held) lease.release();
    large.release();
    metadata.json_utf8 = "251637589";
    const over = voteProjectionPlan(metadata);
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve({ ...over, units: 1 })).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects unsupported representations and malformed or overflowing scalars", () => {
    const metadata = measure(graph()),
      plan = voteProjectionPlan(metadata);
    expect(() => responseAllocationPlan({ ...plan, representation: "tool" })).toThrow(
      "requires resource representation"
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(
      "requires resource representation"
    );
    for (const value of ["-1", "01", "1.0", "1e2"]) {
      metadata.json_utf8 = value;
      expect(() => voteProjectionPlan(metadata)).toThrow(TypeError);
    }
    metadata.json_utf8 = "9".repeat(25);
    expect(() => voteProjectionPlan(metadata)).toThrow(ResponseAllocationUnavailable);
    metadata.json_utf8 = "0";
    metadata.outcome_count = "2";
    expect(() => voteProjectionPlan(metadata)).toThrow("outcome identity");
    metadata.outcome_count = "0";
    expect(() => voteProjectionPlan(metadata)).toThrow("outcome identity");
  });
  it("counts small-byte tallies with many containers instead of treating them as flat strings", () => {
    const q = graph(true, { nested: Array.from({ length: 3000 }, () => []) }),
      metadata = measure(q),
      cost = voteProjectionCost(metadata);
    expect(Number(metadata.json_utf8)).toBeLessThan(20000);
    expect(Number(metadata.json_containers)).toBeGreaterThan(3000);
    expect(BigInt(shape(q).containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    expect(voteProjectionPlan(metadata).units).toBeGreaterThan(
      voteProjectionPlan({ ...metadata, json_properties: "0", json_containers: "0" }).units
    );
  });
  it("bounds independent UTF8 serialization and graph oracles for escaped titles and arbitrary tally JSON", () => {
    const atoms = ["\u0001", "\b", "\t", "\n", "\f", "\r", '"', "\\", "Δ", "🙂", "\u2028"];
    for (let n = 0; n < 32; n += 1) {
      const text = Array.from({ length: 64 }, (_, i) => atoms[(i * 7 + n) % atoms.length]).join("");
      const q = {
        ...graph(true, {
          [text]: [{}, [], { text, number: 1e100, tiny: 1e-100, flag: false, empty: null }]
        }),
        title: text
      };
      const metadata = measure(q),
        cost = voteProjectionCost(metadata),
        actual = shape(q);
      const json = JSON.stringify(q);
      expect(BigInt(Buffer.byteLength(json))).toBeLessThanOrEqual(BigInt(cost.jsonUpperBytes));
      expect(BigInt(actual.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
      expect(BigInt(actual.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
      const wire = JSON.stringify({
        contents: [
          {
            uri: `board://${q.board_id}/votes/${q.vote_id}`,
            mimeType: "application/json",
            text: json
          }
        ]
      });
      expect(Buffer.byteLength(wire)).toBeLessThanOrEqual(
        voteProjectionPlan(metadata).wireUpperBytes
      );
    }
  });
});
