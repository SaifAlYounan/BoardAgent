import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import {
  VOTE_TOOL_PREFLIGHT_SQL,
  VOTE_TOOL_CONTENT_SQL,
  voteToolProjectionCost,
  voteToolProjectionPlan,
  loadAdmittedVoteToolProjection,
  type VoteToolProjectionMetadata
} from "../../artifacts/server/src/vote-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_VOTE_TOOL_SQL } from "../helpers/vote-tool-original-sql.js";

// The transaction port and authority collaborators are synthetic. The public
// executeRead input/registry path and exact get_vote branch run. These unit
// models do not execute PostgreSQL, prove RLS, or mutate immutable storage.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected vote tool fixture pool");
        return callback(client);
      }
    )
  };
});
const id = (n: number) => `01993500-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/vote-tool-${name}.txt`));
interface View extends Record<string, JsonValue> {
  vote_id: string;
  board_id: string;
  resolution: Record<string, JsonValue>;
  decision_package: Record<string, JsonValue>;
  my_ballots: Array<Record<string, JsonValue>>;
  outcome: Record<string, JsonValue> | null;
}
const graph = (name = "view") => JSON.parse(bytes(name).toString("utf8")) as View;
function shape(value: unknown) {
  const pending: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const node = pending.pop();
    if (node !== null && typeof node === "object") {
      containers += 1;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      for (const child of Object.values(node)) pending.push(child);
    }
  }
  return { properties, containers };
}
type Metadata = {
  -readonly [K in keyof VoteToolProjectionMetadata]: VoteToolProjectionMetadata[K];
};
const rootKeys = [
  "vote_id",
  "board_id",
  "title",
  "state",
  "resolution",
  "decision_package",
  "close_mode",
  "deadline_at",
  "row_version",
  "my_ballots",
  "outcome",
  "created_at",
  "opened_at",
  "closed_at"
];
const resolutionKeys = ["version_id", "version", "canonical_text", "sha256"];
const packageKeys = [
  "package_id",
  "version",
  "schema_version",
  "package_sha256",
  "canonical_payload",
  "governance_profile_id",
  "governance_profile_sha256",
  "ruleset_id",
  "ruleset_sha256",
  "approval_rule_id",
  "approval_rule_sha256",
  "electorate_sha256"
];
const ballotKeys = [
  "ballot_id",
  "principal_member_id",
  "caster_member_id",
  "choice",
  "statement",
  "voting_weight",
  "source",
  "cast_at"
];
const outcomeKeys = [
  "outcome_id",
  "canonical_tally",
  "tally_sha256",
  "outcome",
  "finalized_at",
  "certificate_id"
];
function measure(views: readonly View[], raw: Buffer): Metadata {
  let s = 0,
    n = 0,
    p = 0,
    o = 0,
    b = 0,
    e = 0;
  const flat = (values: readonly (JsonValue | undefined)[]) => {
    for (const value of values)
      if (value !== null && value !== undefined) s += Buffer.byteLength(String(value));
  };
  for (const q of views) {
    // Independent full inventory, never production field arrays/constants.
    flat([
      q.vote_id,
      q.board_id,
      q.title,
      q.state,
      q.close_mode,
      q.deadline_at,
      q.row_version,
      q.created_at,
      q.opened_at,
      q.closed_at
    ]);
    flat(resolutionKeys.map((key) => q.resolution[key]));
    flat(
      packageKeys.filter((key) => key !== "canonical_payload").map((key) => q.decision_package[key])
    );
    for (const ballot of q.my_ballots) flat(ballotKeys.map((key) => ballot[key]));
    b += q.my_ballots.length;
    if (q.outcome !== null) {
      e += 1;
      flat(outcomeKeys.filter((key) => key !== "canonical_tally").map((key) => q.outcome?.[key]));
    }
    // A hidden package is SQL NULL; a visible package may contain JSON null.
    const payload =
      q.decision_package.package_id === null ? undefined : q.decision_package.canonical_payload;
    for (const value of [payload, q.outcome?.canonical_tally])
      if (value !== undefined) {
        // JS spelling is a unit oracle only. PostgreSQL::text numeric expansion
        // and whitespace require the separate original-SQL PostgreSQL comparison.
        n += Buffer.byteLength(JSON.stringify(value));
        const counts = shape(value);
        p += counts.properties;
        o += counts.containers;
      }
  }
  return {
    vote_id: id(1),
    board_id: id(2),
    member_id: id(98),
    row_count: String(views.length),
    ballot_count: String(b),
    outcome_count: String(e),
    scalar_utf8: String(s),
    json_utf8: String(n),
    json_properties: String(p),
    json_containers: String(o),
    // Synthetic exact-content observation, not a claimed reimplementation or
    // test of the PostgreSQL private digest expression.
    observation_sha256: digest(JSON.stringify(views) + ":" + raw.length + ":" + digest(raw))
  };
}
function fixture(q = graph()) {
  const state = {
    views: [q],
    raw: Buffer.from(JSON.stringify(q.decision_package.canonical_payload)),
    missing: false,
    hidden: false,
    constructions: 0,
    contentStarted: false,
    preflightRows: undefined as unknown[] | undefined,
    contentRows: undefined as unknown[] | undefined,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined
  };
  const metadata = measure(state.views, state.raw);
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === VOTE_TOOL_CONTENT_SQL || sql === ORIGINAL_VOTE_TOOL_SQL) {
      state.contentStarted = true;
      await state.beforeContent?.();
    }
    if (sql === VOTE_TOOL_PREFLIGHT_SQL) {
      const rows = state.preflightRows ?? (state.missing ? [] : [{ ...metadata }]);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === VOTE_TOOL_CONTENT_SQL) {
      if (state.contentRows) return { rows: state.contentRows };
      if (state.hidden) return { rows: [] };
      const current = measure(state.views, state.raw);
      const fits =
        values?.[0] === current.vote_id &&
        values[1] === current.member_id &&
        values[2] === current.board_id &&
        values[3] === current.observation_sha256 &&
        values[4] === current.row_count &&
        values[5] === current.ballot_count &&
        values[6] === current.outcome_count &&
        ["scalar_utf8", "json_utf8", "json_properties", "json_containers"].every(
          (key, index) =>
            BigInt(current[key as keyof Metadata]) <= BigInt(String(values[7 + index]))
        );
      const binding = {
        vote_id: current.vote_id,
        board_id: current.board_id,
        member_id: current.member_id,
        observation_sha256: current.observation_sha256,
        fits
      };
      if (!fits) return { rows: [{ ...binding, view: null }] };
      state.constructions += state.views.length;
      return { rows: state.views.map((view) => ({ ...binding, view })) };
    }
    if (sql === ORIGINAL_VOTE_TOOL_SQL) {
      // The old caller succeeds with real original-shaped content, so baseline
      // admission failures cannot be attributed to an unsupported query mock.
      if (values?.[0] !== id(1) || values[1] !== id(98))
        throw new Error("incorrect original parameters");
      if (state.missing) return { rows: [] };
      state.constructions += state.views.length;
      return { rows: state.views.map((view) => ({ view })) };
    }
    throw new Error("unexpected vote tool fixture query");
  });
  const client = { query } as unknown as PoolClient;
  const repository = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
    cursorKey: Buffer.alloc(32, 1)
  });
  const principal: SurfacePrincipal = {
    organizationId: id(99),
    memberId: id(98),
    serviceOrigin: "https://boardagent.test",
    clientId: id(97),
    protocolClientId: "vote-tool-fixture",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture-key",
    scopes: ["governance:read"],
    roles: ["member"],
    boardIds: [id(2)]
  };
  const seam = repository as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    dispatch(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readVote(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, tool, input) => {
    if (tool !== "get_vote") throw new Error("out-of-scope fixture dispatch");
    return seam.readVote(connection, actor, tool, input);
  });
  return {
    state,
    metadata,
    query,
    client,
    authorize,
    liveActor,
    read: () =>
      repository.executeRead(principal, "get_vote", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: id(1)
      }),
    helper: () => loadAdmittedVoteToolProjection(client, id(1), id(98))
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
const zero = (): Metadata => ({
  vote_id: id(1),
  board_id: id(2),
  member_id: id(98),
  observation_sha256: "a".repeat(64),
  row_count: "1",
  ballot_count: "0",
  outcome_count: "0",
  scalar_utf8: "0",
  json_utf8: "0",
  json_properties: "0",
  json_containers: "0"
});

describe("get_vote tool projection admission", () => {
  it("refuses the public caller before any full construction when all shared units are occupied", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture();
    const leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.liveActor).toHaveBeenCalledOnce();
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(f.query.mock.calls.filter(([sql]) => sql === VOTE_TOOL_PREFLIGHT_SQL)).toHaveLength(1);
      expect(f.query.mock.calls.some(([sql]) => sql === VOTE_TOOL_CONTENT_SQL)).toBe(false);
      expect(f.state.constructions).toBe(0);
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves complete public bytes and every original 14/4/12/8/6 field", async () => {
    const f = fixture(),
      q = f.state.views[0]!;
    expect(Object.keys(q).sort()).toEqual([...rootKeys].sort());
    expect(Object.keys(q.resolution).sort()).toEqual([...resolutionKeys].sort());
    expect(Object.keys(q.decision_package).sort()).toEqual([...packageKeys].sort());
    for (const b of q.my_ballots) expect(Object.keys(b).sort()).toEqual([...ballotKeys].sort());
    expect(Object.keys(q.outcome!).sort()).toEqual([...outcomeKeys].sort());
    const result = await owned(new ResponseAllocationManager(), () => f.read());
    expect(Buffer.from(canonicalJson(result))).toEqual(bytes("complete"));
    expect(f.state.constructions).toBe(1);
  });
  it("preserves all-null joined child objects, an empty ballot array and null outcome", async () => {
    const f = fixture(graph("null-view"));
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes("null-children"));
    expect(f.metadata.json_utf8).toBe("0");
    const q = graph("null-view");
    q.decision_package.package_id = id(4);
    expect(measure([q], Buffer.from("null")).json_utf8).toBe("4");
  });
  it("preserves the absent envelope without requiring an owner", async () => {
    const f = fixture();
    f.state.missing = true;
    expect(Buffer.from(canonicalJson(await f.read()))).toEqual(bytes("absent"));
    expect(f.state.constructions).toBe(0);
  });
  it("keeps original authority before preflight or whole content", async () => {
    const f = fixture(),
      denial = new Error("synthetic authority denial");
    f.authorize.mockImplementation(() => {
      throw denial;
    });
    await expect(f.read()).rejects.toBe(denial);
    expect(f.query).not.toHaveBeenCalled();
  });
  it("requires native ownership at the public visible caller", async () => {
    const f = fixture();
    await expect(f.read()).rejects.toThrow("native response allocation owner is required");
    expect(f.state.constructions).toBe(0);
  });
  it("binds the exact principal, private observation, all-row counts and all byte/node scalars", async () => {
    const f = fixture(),
      m = f.metadata;
    await owned(new ResponseAllocationManager(), () => f.helper());
    expect(f.query).toHaveBeenLastCalledWith(VOTE_TOOL_CONTENT_SQL, [
      id(1),
      id(98),
      id(2),
      m.observation_sha256,
      m.row_count,
      m.ballot_count,
      m.outcome_count,
      m.scalar_utf8,
      m.json_utf8,
      m.json_properties,
      m.json_containers
    ]);
    expect(m.observation_sha256).not.toBe(f.state.views[0]!.decision_package.package_sha256);
  });
  it("preserves a modeled plural outer rowset while the public caller still selects row0", async () => {
    const f = fixture(),
      second = graph();
    second.outcome!.outcome_id = id(22);
    f.state.views.push(second);
    Object.assign(f.metadata, measure(f.state.views, f.state.raw));
    const rows = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.view)).toEqual(f.state.views);
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes("complete"));
    expect(f.state.constructions).toBe(4);
  });
  it.each([
    "ballot growth",
    "outcome appearance",
    "same-cost resolution text",
    "same-cost ballot statement",
    "raw whitespace",
    "same-cost tally",
    "ballot order"
  ])(
    "refuses modeled %s at unchanged root row_version before content construction",
    async (change) => {
      const q = graph();
      if (change === "outcome appearance") q.outcome = null;
      const f = fixture(q),
        originalVersion = q.row_version;
      f.state.afterMetadata = () => {
        if (change === "ballot growth")
          q.my_ballots.push({ ...q.my_ballots[0]!, ballot_id: id(23) });
        if (change === "outcome appearance") q.outcome = graph().outcome;
        if (change === "same-cost resolution text")
          q.resolution.canonical_text = String(q.resolution.canonical_text).replace(
            "Approve",
            "Decline"
          );
        if (change === "same-cost ballot statement")
          q.my_ballots[0]!.statement = "Synthetic accent Δ";
        if (change === "raw whitespace")
          f.state.raw = Buffer.concat([Buffer.from(" "), f.state.raw]);
        if (change === "same-cost tally")
          q.outcome!.canonical_tally = { approved: true, counts: [1, 2], nested: { empty: [] } };
        if (change === "ballot order") q.my_ballots.reverse();
      };
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(q.row_version).toBe(originalVersion);
      expect(f.state.constructions).toBe(0);
      if (change.startsWith("same-cost") || change === "ballot order") {
        const current = measure(f.state.views, f.state.raw);
        for (const key of [
          "row_count",
          "ballot_count",
          "outcome_count",
          "scalar_utf8",
          "json_utf8",
          "json_properties",
          "json_containers"
        ] as const)
          expect(current[key]).toBe(f.metadata[key]);
        expect(current.observation_sha256).not.toBe(f.metadata.observation_sha256);
      }
    }
  );
  it("returns no rows for a modeled fresh disappearance or recusal", async () => {
    const f = fixture();
    f.state.hidden = true;
    expect(await owned(new ResponseAllocationManager(), () => f.helper())).toEqual([]);
    expect(f.state.constructions).toBe(0);
  });
  it("rejects incorrect or duplicated scalar metadata before loading", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    for (const rows of [
      [{ ...f.metadata, vote_id: id(80) }],
      [{ ...f.metadata, member_id: id(80) }],
      [f.metadata, f.metadata]
    ]) {
      f.state.preflightRows = rows;
      await expect(owned(manager, () => f.helper())).rejects.toBeInstanceOf(TypeError);
    }
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects substituted identities, malformed payloads and an unbudgeted extra row", async () => {
    const f = fixture(),
      valid = { ...f.metadata, fits: true, view: f.state.views[0]! };
    for (const rows of [
      [{ ...valid, member_id: id(80) }],
      [{ ...valid, observation_sha256: "f".repeat(64) }],
      [{ ...valid, view: { ...valid.view, board_id: id(80) } }],
      [{ ...valid, view: [] }],
      [valid, valid]
    ]) {
      f.state.contentRows = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
  it("refuses oversized metadata before any content query", async () => {
    const f = fixture();
    f.metadata.json_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.query.mock.calls.some(([sql]) => sql === VOTE_TOOL_CONTENT_SQL)).toBe(false);
    expect(f.state.constructions).toBe(0);
  });
  it("prevents public content construction after disconnect during metadata", async () => {
    const manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal),
      f = fixture();
    f.state.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(() => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("holds a disconnected public producer's reservation until its real promise settles", async () => {
    const manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal),
      f = fixture();
    let resume!: () => void;
    const gate = new Promise<void>((resolve) => {
      resume = resolve;
    });
    f.state.beforeContent = () => gate;
    const pending = owner.produce(() => f.read());
    const outcome = pending.then(
      (value) => ({ value, error: undefined }),
      (error: unknown) => ({ value: undefined, error })
    );
    try {
      await vi.waitFor(() => expect(f.state.contentStarted).toBe(true), { timeout: 1000 });
      abort.abort();
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(voteToolProjectionPlan(f.metadata).units);
    } finally {
      resume();
      await outcome;
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect((await outcome).error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("holds successful public production until both terminal and collector settlement", async () => {
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal),
      f = fixture();
    try {
      await owner.produce(() => f.read());
      expect(manager.accounting.usedUnits).toBe(voteToolProjectionPlan(f.metadata).units);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("uses independently derived fixed and repeated-row byte/node arithmetic", () => {
    expect(voteToolProjectionCost(zero())).toEqual({
      jsonUpperBytes: "658",
      propertyCount: "53",
      objectOrArrayCount: "9"
    });
    expect(voteToolProjectionPlan(zero())).toMatchObject({ units: 1, wireUpperBytes: 79798 });
    expect(voteToolProjectionCost({ ...zero(), row_count: "2" })).toEqual({
      jsonUpperBytes: "5412",
      propertyCount: "106",
      objectOrArrayCount: "18"
    });
    expect(voteToolProjectionPlan({ ...zero(), row_count: "2" }).wireUpperBytes).toBe(94060);
    expect(voteToolProjectionPlan({ ...zero(), json_utf8: "115854" }).units).toBe(1);
    expect(voteToolProjectionPlan({ ...zero(), json_utf8: "115855" }).units).toBe(2);
    expect(
      voteToolProjectionCost({
        ...zero(),
        ballot_count: "1",
        outcome_count: "1",
        scalar_utf8: "1",
        json_utf8: "1",
        json_properties: "1",
        json_containers: "1"
      })
    ).toEqual({ jsonUpperBytes: "966", propertyCount: "68", objectOrArrayCount: "12" });
  });
  it("validates tool-only zero-canonical plans and rejects malformed counts or overflow", () => {
    const plan = voteToolProjectionPlan(zero());
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    for (const value of ["-1", "01", "1.5", "1e3"])
      expect(() => voteToolProjectionCost({ ...zero(), json_utf8: value })).toThrow(TypeError);
    expect(() => voteToolProjectionCost({ ...zero(), row_count: "0" })).toThrow(TypeError);
    expect(() => voteToolProjectionCost({ ...zero(), outcome_count: "2" })).toThrow(TypeError);
    expect(() => voteToolProjectionPlan({ ...zero(), json_utf8: "1".repeat(25) })).toThrow(
      ResponseAllocationUnavailable
    );
    expect(() =>
      voteToolProjectionPlan({ ...zero(), json_utf8: "999999999999999999999999" })
    ).toThrow(ResponseAllocationUnavailable);
  });
  it("retains the shared 1920-unit boundary and eligibility for 100 plus one small reads", () => {
    const boundary = { ...zero(), json_utf8: "251643022" };
    const plan = voteToolProjectionPlan(boundary),
      manager = new ResponseAllocationManager();
    expect(plan.units).toBe(1920);
    const lease = manager.tryReserve(plan),
      smalls = Array.from({ length: 101 }, () => manager.tryReserve(small()));
    try {
      expect(manager.accounting.usedUnits).toBe(2021);
    } finally {
      for (const smallLease of smalls) smallLease.release();
      lease.release();
    }
    const over = voteToolProjectionPlan({ ...boundary, json_utf8: "251643023" });
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve({ ...over, units: 1 })).toThrow(ResponseAllocationUnavailable);
  });
  it("bounds independent Unicode/numeric/arbitrary-container tool bytes and the complete result graph", () => {
    const q = graph();
    q.decision_package.canonical_payload = {
      escaped: '"\\\n\u0001Δ🙂',
      finite: [1e100, 1e-100],
      many: Array.from({ length: 50 }, () => ({ empty: [] }))
    };
    const m = measure([q], Buffer.from(JSON.stringify(q.decision_package.canonical_payload))),
      cost = voteToolProjectionCost(m),
      plan = voteToolProjectionPlan(m);
    const envelope = JSON.parse(bytes("complete").toString("utf8")) as { data: { vote: View } };
    envelope.data.vote = q;
    const wire = {
      content: [{ type: "text", text: JSON.stringify(envelope) }],
      structuredContent: envelope
    };
    const actual = shape(wire);
    expect(BigInt(cost.propertyCount)).toBeGreaterThanOrEqual(BigInt(actual.properties));
    expect(BigInt(cost.objectOrArrayCount)).toBeGreaterThanOrEqual(BigInt(actual.containers));
    expect(BigInt(cost.jsonUpperBytes) + 4096n).toBeGreaterThanOrEqual(
      BigInt(Buffer.byteLength(canonicalJson(envelope)))
    );
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
    expect(Number(m.json_properties)).toBeGreaterThan(50);
    expect(Number(m.json_containers)).toBeGreaterThan(100);
  });
});
