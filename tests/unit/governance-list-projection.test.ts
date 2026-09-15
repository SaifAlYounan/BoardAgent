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
  GOVERNANCE_LIST_PREFLIGHT_SQL,
  GOVERNANCE_LIST_CONTENT_SQL,
  loadAdmittedGovernanceList,
  governanceListProjectionCost,
  governanceListProjectionPlan,
  type GovernanceListInput,
  type GovernanceListKind,
  type GovernanceListMetadata
} from "../../artifacts/server/src/governance-list-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_GOVERNANCE_LIST_SQL } from "../helpers/governance-lists-original-sql.js";

// Public input/registry/page/cursor code is real. Database, actor and authority
// ports are explicit models, limited to these three governance lists. No PG/RLS proof.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected governance list pool");
        return callback(client);
      }
    )
  };
});
const id = (n: number) => `01993b00-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/governance-lists-${name}.txt`));
const literal = <T>(name: string) => JSON.parse(bytes(name).toString("utf8")) as T;
const clone = <T>(value: T) => JSON.parse(JSON.stringify(value)) as T;
type Item = Record<string, JsonValue>;
interface Row {
  item: Item;
  cursor_at: string | null;
  cursor_id: string;
}
type Metadata = { -readonly [K in keyof GovernanceListMetadata]: GovernanceListMetadata[K] };
const tool = {
  rulesets: "list_ruleset_versions",
  templates: "list_approval_rule_templates",
  matter_types: "list_matter_types"
} as const;
const original = ORIGINAL_GOVERNANCE_LIST_SQL;
const idKey = {
  rulesets: "ruleset_id",
  templates: "template_id",
  matter_types: "matter_type_id"
} as const;
const jsonKey = {
  rulesets: null,
  templates: "exact_rule",
  matter_types: "strict_fact_schema"
} as const;
const keys = {
  rulesets: [
    "ruleset_id",
    "version",
    "state",
    "schema_version",
    "sha256",
    "profile_id",
    "supersedes_id",
    "created_at"
  ],
  templates: ["template_id", "code", "approval_rule_id", "exact_rule", "sha256"],
  matter_types: ["matter_type_id", "code", "name", "strict_fact_schema", "sha256"]
} as const;
function graph(roots: readonly unknown[], shared = false) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object") continue;
    if (shared && seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (!Array.isArray(value)) properties += Object.keys(value).length;
    pending.push(...Object.values(value));
  }
  return { properties, containers };
}
function measure(kind: GovernanceListKind, row: Row, rawTime: string): Metadata {
  let scalar = 0n;
  for (const [key, value] of [
    ...Object.entries(row.item),
    ["cursor_at", row.cursor_at],
    ["cursor_id", row.cursor_id]
  ] as [string, JsonValue][]) {
    if (key === jsonKey[kind] || value === null) continue;
    if (typeof value !== "string" && typeof value !== "number")
      throw new Error("unexpected flat scalar");
    scalar += BigInt(Buffer.byteLength(String(value)));
  }
  const arbitrary = jsonKey[kind] === null ? undefined : row.item[jsonKey[kind]!];
  const g = graph([arbitrary]);
  // A JSON-string unit observation, not a claim of PostgreSQL jsonb/hash parity.
  return {
    id: row.cursor_id,
    cursor_at: row.cursor_at,
    raw_order_key: rawTime,
    observation_sha256: digest(JSON.stringify(row.item) + rawTime),
    scalar_utf8: String(scalar),
    normalized_json_utf8:
      arbitrary === undefined ? "0" : String(Buffer.byteLength(JSON.stringify(arbitrary))),
    json_property_count: String(g.properties),
    json_container_count: String(g.containers)
  };
}
function fixture(
  kind: GovernanceListKind,
  options: {
    rows?: Row[];
    limit?: number;
    cursorAt?: string | null;
    cursorId?: string | null;
    cursorWire?: string;
  } = {}
) {
  const input: GovernanceListInput = {
    kind,
    boardId: id(2),
    limit: options.limit ?? 100,
    cursorAt: options.cursorAt ?? null,
    cursorId: options.cursorId ?? null
  };
  const state = {
    sourceRows: options.rows ?? literal<Row[]>(kind + "-rows"),
    hiddenIds: new Set<string>(),
    rawTimes: new Map<string, string>(),
    contentStarted: false,
    constructions: 0,
    preflightRows: undefined as unknown[] | undefined,
    contentRows: undefined as unknown[] | undefined,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined
  };
  // Ordinary fixture timestamps use sortable finite UTC text. Separate raw-time
  // changes below test identity only; this model does not simulate PG ordering.
  const selected = () =>
    state.sourceRows
      .filter((row) => !state.hiddenIds.has(row.cursor_id))
      .filter(
        (row) =>
          input.cursorAt === null ||
          (row.cursor_at !== null &&
            (kind === "rulesets"
              ? row.cursor_at < input.cursorAt ||
                (row.cursor_at === input.cursorAt && row.cursor_id < input.cursorId!)
              : row.cursor_at > input.cursorAt ||
                (row.cursor_at === input.cursorAt && row.cursor_id > input.cursorId!)))
      )
      .slice(0, input.limit + 1);
  const current = () =>
    selected().map((row) =>
      measure(
        kind,
        row,
        state.rawTimes.get(row.cursor_id) ??
          (kind === "rulesets"
            ? row.cursor_at?.replace("T", " ").replace("Z", "+00")
            : row.cursor_at) ??
          "infinity"
      )
    );
  const metadata = current();
  const parameters = [input.boardId, input.cursorAt, input.cursorId, input.limit + 1];
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === GOVERNANCE_LIST_CONTENT_SQL[kind] || sql === original[kind]) {
      state.contentStarted = true;
      await state.beforeContent?.();
    }
    if (sql === GOVERNANCE_LIST_PREFLIGHT_SQL[kind]) {
      expect(values).toEqual(parameters);
      const rows = state.preflightRows ?? clone(metadata);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === GOVERNANCE_LIST_CONTENT_SQL[kind]) {
      expect(values?.slice(0, parameters.length)).toEqual(parameters);
      if (state.contentRows) return { rows: state.contentRows };
      const expected = JSON.parse(String(values?.[parameters.length])) as Metadata[],
        fresh = current();
      const fits = fresh.every((row) => {
        const old = expected.find((bound) => bound.id === row.id);
        return (
          old !== undefined &&
          old.cursor_at === row.cursor_at &&
          old.raw_order_key === row.raw_order_key &&
          old.observation_sha256 === row.observation_sha256 &&
          BigInt(row.scalar_utf8) <= BigInt(old.scalar_utf8) &&
          BigInt(row.normalized_json_utf8) <= BigInt(old.normalized_json_utf8) &&
          row.json_property_count === old.json_property_count &&
          row.json_container_count === old.json_container_count
        );
      });
      if (!fits) return { rows: [{ fits: false, item: null, cursor_at: null, cursor_id: null }] };
      const rows = selected();
      state.constructions += rows.length;
      return { rows: rows.map((row) => ({ fits: true, ...row })) };
    }
    if (sql === original[kind]) {
      expect(values).toEqual(parameters);
      const rows = selected();
      state.constructions += rows.length;
      return { rows };
    }
    throw new Error("unexpected governance list query");
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
    protocolClientId: "meeting-list-fixture",
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
    readRules(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({}),
    authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, name, args) => {
    if (name !== tool[kind]) throw new Error("out-of-scope meeting dispatch");
    return seam.readRules(connection, actor, name, args);
  });
  return {
    input,
    state,
    metadata,
    current,
    query,
    client,
    liveActor,
    authorize,
    read: (overrides: Record<string, unknown> = {}) =>
      repository.executeRead(principal, tool[kind], {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: input.boardId,
        limit: input.limit,
        ...(options.cursorWire ? { cursor: options.cursorWire } : {}),
        ...overrides
      }),
    helper: () => loadAdmittedGovernanceList(client, input)
  };
}
const small = () =>
  responseAllocationPlan({
    kind: "document",
    representation: "tool",
    canonicalBytes: 1,
    sourceId: "synthetic-small",
    sourceVersion: "1",
    sha256: "a".repeat(64)
  });
const close = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
async function owned<T>(manager: ResponseAllocationManager, work: () => Promise<T>) {
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(work);
  } finally {
    close(owner);
  }
}
async function fixedClock<T>(work: () => Promise<T>) {
  const clock = vi.spyOn(Date, "now").mockReturnValue(1800000000000);
  try {
    return await work();
  } finally {
    clock.mockRestore();
  }
}
const total = (rows: readonly GovernanceListMetadata[]) => ({
  row_count: String(rows.length),
  scalar_utf8: String(rows.reduce((s, r) => s + BigInt(r.scalar_utf8), 0n)),
  normalized_json_utf8: String(rows.reduce((s, r) => s + BigInt(r.normalized_json_utf8), 0n)),
  json_property_count: String(rows.reduce((s, r) => s + BigInt(r.json_property_count), 0n)),
  json_container_count: String(rows.reduce((s, r) => s + BigInt(r.json_container_count), 0n))
});

describe.each(["rulesets", "templates", "matter_types"] as const)("%s governance list", (kind) => {
  it("refuses saturated public calls before whole projection", async () => {
    const manager = new ResponseAllocationManager(),
      occupied = manager.openRequest(new AbortController().signal),
      f = fixture(kind);
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 2048; i++) occupied.reserve(small());
      });
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.liveActor).toHaveBeenCalledOnce();
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(f.state.contentStarted).toBe(false);
      expect(f.state.constructions).toBe(0);
    } finally {
      close(occupied);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves complete original fields and independent ordinary literal bytes", async () => {
    const f = fixture(kind);
    for (const row of f.state.sourceRows)
      expect(Object.keys(row.item).sort()).toEqual([...keys[kind]].sort());
    const result = await owned(new ResponseAllocationManager(), () => f.read());
    expect(Buffer.from(canonicalJson(result))).toEqual(bytes(kind + "-full"));
    expect(f.state.constructions).toBe(3);
  });
  it("preserves page bytes in the explicit three-row cursor model", async () => {
    const f = fixture(kind, { rows: literal<Row[]>(kind + "-rows"), limit: 2 });
    expect(
      Buffer.from(
        canonicalJson(
          await fixedClock(() => owned(new ResponseAllocationManager(), () => f.read()))
        )
      )
    ).toEqual(bytes(kind + "-page"));
    expect(f.metadata).toHaveLength(3);
    expect(f.state.constructions).toBe(3);
    expect(
      BigInt(governanceListProjectionCost(kind, total(f.metadata)).jsonUpperBytes)
    ).toBeGreaterThan(
      BigInt(governanceListProjectionCost(kind, total(f.metadata.slice(0, 2))).jsonUpperBytes)
    );
  });
  it("consumes the independently signed last-public-row cursor with original parameter order", async () => {
    const rows = literal<Row[]>(kind + "-rows"),
      page = literal<{ data: { next_cursor: string } }>(kind + "-page");
    const f = fixture(kind, {
      rows,
      limit: 2,
      cursorAt: rows[1]!.cursor_at,
      cursorId: rows[1]!.cursor_id,
      cursorWire: page.data.next_cursor
    });
    const result = await fixedClock(() => owned(new ResponseAllocationManager(), () => f.read()));
    expect(result.data).toEqual({ items: [rows[2]!.item], next_cursor: null });
    expect(f.state.constructions).toBe(1);
    expect(f.query.mock.calls[0]?.[1]).toEqual([id(2), rows[1]!.cursor_at, rows[1]!.cursor_id, 3]);
  });
  it("retains the literal empty public envelope lease until both signals", async () => {
    const f = fixture(kind, { rows: [] }),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      expect(Buffer.from(canonicalJson(await owner.produce(() => f.read())))).toEqual(
        bytes(kind + "-empty")
      );
      expect(manager.accounting.usedUnits).toBe(1);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      close(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("requires a native owner before visible public content", async () => {
    const f = fixture(kind);
    await expect(f.read()).rejects.toThrow("native response allocation owner is required");
    expect(f.state.constructions).toBe(0);
  });
  it("keeps actor and authority failures before either SQL phase", async () => {
    for (const gate of ["actor", "authority"]) {
      const f = fixture(kind),
        error = new Error("synthetic authority denial");
      if (gate === "actor") f.liveActor.mockRejectedValue(error);
      else
        f.authorize.mockImplementation(() => {
          throw error;
        });
      await expect(f.read()).rejects.toBe(error);
      expect(f.query).not.toHaveBeenCalled();
    }
  });
  it("models the common 501-row internal lookahead as an explicitly modeled page frontier", async () => {
    const source = literal<Row[]>(kind + "-rows")[0]!;
    const rows = Array.from({ length: 501 }, (_, index) => {
      const row = clone(source);
      row.cursor_id = id(kind === "rulesets" ? 2000 - index : 2000 + index);
      row.item[idKey[kind]] = row.cursor_id;
      return row;
    });
    const f = fixture(kind, { rows, limit: 500 });
    const result = await owned(new ResponseAllocationManager(), () => f.read());
    expect((result.data as { items: unknown[] }).items).toHaveLength(500);
    expect(f.state.constructions).toBe(501);
    const invalid = fixture(kind);
    await expect(invalid.read({ limit: 501 })).rejects.toBeDefined();
    expect(invalid.query).not.toHaveBeenCalled();
  });
  it("rejects a tampered cursor before any query", async () => {
    const f = fixture(kind, { cursorWire: "bad.cursor" });
    await expect(owned(new ResponseAllocationManager(), () => f.read())).rejects.toBeDefined();
    expect(f.query).not.toHaveBeenCalled();
  });
  it("allows known relative-order visibility loss including the empty set", async () => {
    const f = fixture(kind);
    f.state.afterMetadata = () => {
      f.state.hiddenIds.add(f.state.sourceRows[1]!.cursor_id);
    };
    const rows = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(rows.map((row) => row.cursor_id)).toEqual([f.metadata[0]!.id, f.metadata[2]!.id]);
  });
  it("refuses empty-to-visible growth before any construction", async () => {
    const f = fixture(kind, { rows: [] });
    f.state.afterMetadata = () => {
      f.state.sourceRows = literal<Row[]>(kind + "-rows");
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("rejects modeled unseen backfill globally even when another row is known", async () => {
    const f = fixture(kind, { rows: literal<Row[]>(kind + "-rows"), limit: 1 });
    f.state.afterMetadata = () => {
      f.state.hiddenIds.add(f.state.sourceRows[0]!.cursor_id);
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.current().map((row) => row.id)).toEqual([
      f.metadata[1]!.id,
      f.state.sourceRows[2]!.cursor_id
    ]);
    expect(f.state.constructions).toBe(0);
  });
  it("does not construct public content after a metadata-phase disconnect", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    f.state.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(() => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
    } finally {
      close(owner);
    }
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains a disconnected producer while the shared old/new content query is held", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    let resume!: () => void,
      settled = false;
    const gate = new Promise<void>((resolve) => {
      resume = resolve;
    });
    f.state.beforeContent = () => gate;
    const outcome = owner
      .produce(() => f.read())
      .then(
        (value) => ({ value, error: undefined }),
        (error: unknown) => ({ value: undefined, error })
      )
      .finally(() => {
        settled = true;
      });
    try {
      await vi.waitFor(() => expect(f.state.contentStarted).toBe(true), { timeout: 1000 });
      abort.abort();
      close(owner);
      expect(manager.accounting.usedUnits).toBe(
        governanceListProjectionPlan(f.input, f.metadata).units
      );
    } finally {
      resume();
      close(owner);
      await vi.waitFor(() => expect(settled).toBe(true), { timeout: 1000 });
    }
    expect((await outcome).error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains successful visible public production until native and collector completion", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(() => f.read());
      expect(manager.accounting.usedUnits).toBe(
        governanceListProjectionPlan(f.input, f.metadata).units
      );
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      close(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses oversized metadata before a content query", async () => {
    const f = fixture(kind);
    f.metadata[0]!.scalar_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.contentStarted).toBe(false);
  });
  it("rejects duplicate metadata and malformed returned identity or order", async () => {
    const duplicate = fixture(kind);
    duplicate.state.preflightRows = [duplicate.metadata[0], duplicate.metadata[0]];
    await expect(
      owned(new ResponseAllocationManager(), () => duplicate.helper())
    ).rejects.toBeInstanceOf(TypeError);
    for (const mode of [
      "unknown",
      "reversed",
      "duplicate",
      "wrong-selector",
      "wrong-time",
      "extra"
    ]) {
      const f = fixture(kind, { rows: literal<Row[]>(kind + "-rows") }),
        rows = f.state.sourceRows.map((row) => ({ fits: true, ...clone(row) }));
      if (mode === "unknown") rows[0]!.cursor_id = id(77);
      if (mode === "reversed") rows.reverse();
      if (mode === "duplicate") rows[1] = clone(rows[0]!);
      if (mode === "wrong-selector") rows[0]!.item[idKey[kind]] = id(77);
      if (mode === "wrong-time") rows[0]!.cursor_at = "different";
      if (mode === "extra") rows.push(clone(rows[0]!));
      f.state.contentRows = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
});

describe("ruleset nullable original timestamp", () => {
  it("preserves nullable timestamp formatters at the original page boundary", async () => {
    const kind = "rulesets" as const;
    const row = literal<Row[]>(kind + "-rows")[0]!;
    row.cursor_at = null;
    if (kind === "rulesets") row.item.created_at = null;
    const f = fixture(kind, { rows: [row] });
    expect((await owned(new ResponseAllocationManager(), () => f.read())).data).toEqual({
      items: [row.item],
      next_cursor: null
    });
    const other = clone(row);
    other.cursor_id = id(9);
    other.item[idKey[kind]] = id(9);
    const more = fixture(kind, { rows: [row, other], limit: 1 });
    await expect(owned(new ResponseAllocationManager(), () => more.read())).rejects.toBeDefined();
    expect(more.state.constructions).toBe(2);
  });
});

describe("governance list independent costs and returned-value binding", () => {
  it.each([
    ["rulesets", "version"],
    ["rulesets", "profile_id"],
    ["rulesets", "sha256"],
    ["rulesets", "supersedes_id"],
    ["rulesets", "raw timestamp"],
    ["templates", "approval_rule_id"],
    ["templates", "exact_rule"],
    ["templates", "sha256"],
    ["matter_types", "name"],
    ["matter_types", "strict_fact_schema"],
    ["matter_types", "sha256"]
  ] as const)(
    "refuses same-cost %s %s changes despite unchanged other fields",
    async (kind, field) => {
      const f = fixture(kind);
      f.state.afterMetadata = () => {
        const row = f.state.sourceRows[0]!;
        if (field === "version") row.item.version = 4;
        else if (
          field === "profile_id" ||
          field === "approval_rule_id" ||
          field === "supersedes_id"
        )
          row.item[field] = id(70);
        else if (field === "sha256") row.item.sha256 = "f".repeat(64);
        else if (field === "name")
          row.item.name = String(row.item.name).replace("Mining", "Survey");
        else if (field === "exact_rule")
          row.item.exact_rule = { ...(row.item.exact_rule as Item), threshold: 3 };
        else if (field === "strict_fact_schema")
          row.item.strict_fact_schema = {
            ...(row.item.strict_fact_schema as Item),
            type: "string"
          };
        else f.state.rawTimes.set(row.cursor_id, "2026-09-12 12:02:02.000002+00");
      };
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(total(f.current())).toEqual(total(f.metadata));
      expect(f.current()[0]!.observation_sha256).not.toBe(f.metadata[0]!.observation_sha256);
      expect(f.state.constructions).toBe(0);
    }
  );
  it("counts literal null wrappers and fixed policy overhead independently", () => {
    const expected = { rulesets: [197, 12], templates: [147, 9], matter_types: [146, 9] } as const;
    for (const kind of ["rulesets", "templates", "matter_types"] as const) {
      const empty = {
        row_count: "0",
        scalar_utf8: "0",
        normalized_json_utf8: "0",
        json_property_count: "0",
        json_container_count: "0"
      };
      expect(governanceListProjectionCost(kind, empty)).toEqual({
        jsonUpperBytes: "2",
        propertyCount: "25",
        objectOrArrayCount: "7"
      });
      const wrapper = {
        fits: false,
        item: Object.fromEntries(keys[kind].map((k) => [k, null])),
        cursor_at: null,
        cursor_id: null
      };
      expect(Buffer.byteLength(JSON.stringify(wrapper)) + 1 + (kind === "rulesets" ? 0 : 2)).toBe(
        expected[kind][0]
      );
      expect(governanceListProjectionCost(kind, { ...empty, row_count: "1" })).toEqual({
        jsonUpperBytes: String(2 + expected[kind][0]),
        propertyCount: String(25 + expected[kind][1]),
        objectOrArrayCount: "9"
      });
    }
  });
  it("rejects malformed metadata, invalid selectors and non-tool/canonical overrides", () => {
    const f = fixture("templates"),
      plan = governanceListProjectionPlan(f.input, f.metadata);
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    for (const field of [
      "row_count",
      "scalar_utf8",
      "normalized_json_utf8",
      "json_property_count",
      "json_container_count"
    ] as const) {
      for (const value of ["-1", "01", "1.5", "1e3"])
        expect(() =>
          governanceListProjectionCost("templates", { ...total(f.metadata), [field]: value })
        ).toThrow(TypeError);
      expect(() =>
        governanceListProjectionCost("templates", { ...total(f.metadata), [field]: "9".repeat(25) })
      ).toThrow(ResponseAllocationUnavailable);
    }
    expect(() =>
      governanceListProjectionCost("templates", { ...total(f.metadata), row_count: "502" })
    ).toThrow(TypeError);
    expect(() => governanceListProjectionCost("rulesets", total(f.metadata))).toThrow(TypeError);
    expect(() => governanceListProjectionPlan({ ...f.input, limit: 501 }, f.metadata)).toThrow(
      TypeError
    );
    expect(() => governanceListProjectionPlan({ ...f.input, boardId: "bad" }, f.metadata)).toThrow(
      TypeError
    );
    const bad = clone(f.metadata);
    bad[0]!.observation_sha256 = "bad";
    expect(() => governanceListProjectionPlan(f.input, bad)).toThrow(TypeError);
  });
  it("preserves independent one-unit and large-lane scalar boundaries", async () => {
    const make = (kind: GovernanceListKind, s: string) =>
      responseAllocationPlan({
        kind: "governance_list_projection",
        representation: "tool",
        canonicalBytes: 0,
        sourceId: id(2),
        sourceVersion: kind + ":1",
        sha256: "a".repeat(64),
        listProjection: governanceListProjectionCost(kind, {
          row_count: "1",
          scalar_utf8: s,
          normalized_json_utf8: "0",
          json_property_count: "0",
          json_container_count: "0"
        })
      });
    for (const [kind, threshold] of [
      ["rulesets", 19470],
      ["templates", 19495],
      ["matter_types", 19495]
    ] as const) {
      expect(make(kind, String(threshold)).units).toBe(1);
      expect(make(kind, String(threshold + 1)).units).toBe(2);
    }
    // Schema-shaped arithmetic only, not a claim of a normal writer accepting this amount of text.
    const last = (1920n * 1048576n - 112808n) / 48n;
    expect(make("templates", String(last)).units).toBe(1920);
    const oversized = make("templates", String(last + 1n));
    expect(oversized.units).toBe(1921);
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(async () => {
        expect(() => owner.reserve(oversized)).toThrow(ResponseAllocationUnavailable);
        expect(manager.accounting.usedUnits).toBe(0);
        owner.reserve(make("templates", String(last)));
      });
      expect(manager.accounting.usedUnits).toBe(1920);
    } finally {
      close(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("bounds retained and native-shaped graphs with nested JSON and UTF8 escaping", async () => {
    for (const kind of ["rulesets", "templates", "matter_types"] as const) {
      const row = literal<Row[]>(kind + "-rows")[0]!;
      if (kind !== "rulesets")
        row.item[jsonKey[kind]!] = {
          deep: [null, true, { 'quote"\n': "\u0001\\🙂Δ".repeat(400) }],
          many: Array.from({ length: 100 }, (_, i) => ({ [String(i)]: [] }))
        };
      const f = fixture(kind, { rows: [row] }),
        reply = await owned(new ResponseAllocationManager(), () => f.read());
      const wire = {
        content: [{ type: "text", text: JSON.stringify(reply) }],
        structuredContent: reply
      };
      const retained = f.state.sourceRows.map((v) => ({ fits: true, ...v }));
      const actual = graph([wire, retained], true),
        cost = governanceListProjectionCost(kind, total(f.metadata)),
        plan = governanceListProjectionPlan(f.input, f.metadata);
      expect(BigInt(actual.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
      expect(BigInt(actual.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
      expect(Buffer.byteLength(JSON.stringify(retained))).toBeLessThanOrEqual(
        Number(cost.jsonUpperBytes)
      );
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
      expect(Buffer.byteLength(canonicalJson(reply))).toBeLessThanOrEqual(
        Number(cost.jsonUpperBytes) + 4096
      );
    }
  });
  it("pays the native numeric-rendering carry without trusting a stored digest", async () => {
    for (const kind of ["templates", "matter_types"] as const) {
      const row = literal<Row[]>(kind + "-rows")[0]!,
        raw = '{"number":9999999999999999}';
      row.item[jsonKey[kind]!] = JSON.parse(raw) as JsonValue;
      const f = fixture(kind, { rows: [row] });
      f.metadata[0]!.normalized_json_utf8 = String(Buffer.byteLength(raw));
      expect(Buffer.byteLength(JSON.stringify(row.item[jsonKey[kind]!]))).toBe(
        Buffer.byteLength(raw) + 1
      );
      // Direct measured-plan bound only; SQL normalization parity is a separate PG proof.
      const cost = governanceListProjectionCost(kind, total(f.metadata));
      expect(Buffer.byteLength(JSON.stringify([{ fits: true, ...row }]))).toBeLessThanOrEqual(
        Number(cost.jsonUpperBytes)
      );
    }
  });
  it("returns a fully hidden known frontier under its existing one-unit empty-page lease", async () => {
    const f = fixture("templates"),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    f.state.afterMetadata = () =>
      f.state.sourceRows.forEach((r) => f.state.hiddenIds.add(r.cursor_id));
    try {
      expect(await owner.produce(() => f.helper())).toEqual([]);
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      close(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
