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
  MINUTES_LIST_PREFLIGHT_SQL,
  MINUTES_LIST_CONTENT_SQL,
  loadAdmittedMinutesList,
  minutesListProjectionCost,
  minutesListProjectionPlan,
  type MinutesListInput,
  type MinutesListKind,
  type MinutesListMetadata,
  type MinutesListScalars
} from "../../artifacts/server/src/minutes-list-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_MINUTES_VERSIONS_SQL,
  ORIGINAL_MINUTES_REVIEWS_SQL
} from "../helpers/minutes-lists-original-sql.js";

// Models only: public input/registry/page/cursor code is real; transaction and
// actor/authority ports are synthetic and restricted to the two minutes lists.
// These tests do not execute PG, prove RLS or authorize immutable-row changes.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected minutes list pool");
        return callback(client);
      }
    )
  };
});
const id = (n: number) => `01993b00-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/minutes-lists-${name}.txt`));
const literal = <T>(name: string) => JSON.parse(bytes(name).toString("utf8")) as T;
const clone = <T>(value: T) => JSON.parse(JSON.stringify(value)) as T;
type Item = Record<string, JsonValue>;
interface Row {
  item: Item;
  cursor_at: string | null;
  cursor_id: string;
}
type Metadata = { -readonly [K in keyof MinutesListMetadata]: MinutesListMetadata[K] };
const toolsByKind = {
  versions: "list_minutes_versions",
  reviews: "list_minutes_review_items"
} as const;
const original = { versions: ORIGINAL_MINUTES_VERSIONS_SQL, reviews: ORIGINAL_MINUTES_REVIEWS_SQL };
const versionKeys = [
  "version_id",
  "minutes_id",
  "version",
  "canonical_schema",
  "sha256",
  "package_base_sha256",
  "transcript_version_id",
  "supersedes_id",
  "created_at"
];
const reviewKeys = [
  "review_item_id",
  "minutes_id",
  "item_kind",
  "schema_version",
  "author_member_id",
  "author_seat_role",
  "base_version_id",
  "base_sha256",
  "anchor",
  "payload",
  "payload_sha256",
  "withdrawal",
  "disposition",
  "created_at"
];
const withdrawalKeys = ["withdrawal_id", "author_member_id", "withdrawn_at"];
const dispositionKeys = [
  "disposition_id",
  "decision",
  "reason",
  "resulting_minutes_version_id",
  "created_at"
];
const scalarKeys = [
  "withdrawal_count",
  "disposition_count",
  "scalar_utf8",
  "json_utf8",
  "json_properties",
  "json_containers"
] as const;
function graphCounts(roots: readonly unknown[], shared = false) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const node = pending.pop();
    if (node !== null && typeof node === "object") {
      if (shared && seen.has(node)) continue;
      seen.add(node);
      containers++;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      pending.push(...Object.values(node));
    }
  }
  return { properties, containers };
}
function measure(kind: MinutesListKind, row: Row, rawTime: string, rawPayload: Buffer): Metadata {
  let s = 0,
    w = 0,
    d = 0,
    n = 0,
    p = 0,
    o = 0;
  const flat = (values: readonly (JsonValue | undefined)[]) => {
    for (const value of values)
      if (value !== null && value !== undefined) s += Buffer.byteLength(String(value));
  };
  if (kind === "versions") flat(versionKeys.map((key) => row.item[key]));
  else {
    flat(
      reviewKeys
        .filter((key) => !["anchor", "payload", "withdrawal", "disposition"].includes(key))
        .map((key) => row.item[key])
    );
    for (const [key, keys] of [
      ["withdrawal", withdrawalKeys],
      ["disposition", dispositionKeys]
    ] as const) {
      const child = row.item[key];
      if (child !== null && typeof child === "object" && !Array.isArray(child)) {
        if (key === "withdrawal") w++;
        else d++;
        flat(keys.map((field) => (child as Item)[field]));
      }
    }
    for (const value of [row.item.anchor, row.item.payload]) {
      // Unit JavaScript spelling is deliberately not an actual PG::text oracle.
      n += Buffer.byteLength(JSON.stringify(value));
      const counts = graphCounts([value]);
      p += counts.properties;
      o += counts.containers;
    }
  }
  flat([row.cursor_at, row.cursor_id]);
  return {
    id: row.cursor_id,
    cursor_at: row.cursor_at,
    raw_created_at: rawTime,
    observation_sha256: digest(
      JSON.stringify(row.item) +
        rawTime +
        (kind === "reviews" ? digest(rawPayload) + rawPayload.length : "")
    ),
    withdrawal_count: String(w),
    disposition_count: String(d),
    scalar_utf8: String(s),
    json_utf8: String(n),
    json_properties: String(p),
    json_containers: String(o)
  };
}
function summed(rows: readonly MinutesListMetadata[]): MinutesListScalars {
  return {
    row_count: String(rows.length),
    ...Object.fromEntries(
      scalarKeys.map((key) => [
        key,
        rows.reduce((sum, row) => sum + BigInt(row[key]), 0n).toString()
      ])
    )
  } as unknown as MinutesListScalars;
}
function fixture(
  kind: MinutesListKind,
  options: {
    rows?: Row[];
    limit?: number;
    cursorAt?: string | null;
    cursorId?: string | null;
    cursorWire?: string;
  } = {}
) {
  const input: MinutesListInput = {
    kind,
    minutesId: id(1),
    limit: options.limit ?? 100,
    cursorAt: options.cursorAt ?? null,
    cursorId: options.cursorId ?? null
  };
  const state = {
    sourceRows: options.rows ?? literal<Row[]>(kind + "-rows"),
    hiddenIds: new Set<string>(),
    rawTimes: new Map<string, string>(),
    rawPayloads: new Map<string, Buffer>(),
    contentStarted: false,
    constructions: 0,
    preflightRows: undefined as unknown[] | undefined,
    contentRows: undefined as unknown[] | undefined,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined
  };
  const selected = () =>
    state.sourceRows
      .filter((row) => !state.hiddenIds.has(row.cursor_id))
      .filter(
        (row) =>
          input.cursorAt === null ||
          (row.cursor_at !== null &&
            (row.cursor_at < input.cursorAt ||
              (row.cursor_at === input.cursorAt && row.cursor_id < input.cursorId!)))
      )
      .slice(0, input.limit + 1);
  const current = () =>
    selected().map((row) =>
      measure(
        kind,
        row,
        state.rawTimes.get(row.cursor_id) ??
          row.cursor_at?.replace("T", " ").replace("Z", "+00") ??
          "infinity",
        state.rawPayloads.get(row.cursor_id) ??
          Buffer.from(JSON.stringify(row.item.payload ?? null))
      )
    );
  const metadata = current();
  const parameters = [input.minutesId, input.cursorAt, input.cursorId, input.limit + 1];
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === MINUTES_LIST_CONTENT_SQL[kind] || sql === original[kind]) {
      state.contentStarted = true;
      await state.beforeContent?.();
    }
    if (sql === MINUTES_LIST_PREFLIGHT_SQL[kind]) {
      expect(values).toEqual(parameters);
      const rows = state.preflightRows ?? clone(metadata);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === MINUTES_LIST_CONTENT_SQL[kind]) {
      expect(values?.slice(0, 4)).toEqual(parameters);
      if (state.contentRows) return { rows: state.contentRows };
      const expected = JSON.parse(String(values?.[4])) as Metadata[],
        fresh = current();
      const fits = fresh.every((row) => {
        const before = expected.find((bound) => bound.id === row.id);
        return (
          before !== undefined &&
          before.cursor_at === row.cursor_at &&
          before.raw_created_at === row.raw_created_at &&
          before.observation_sha256 === row.observation_sha256 &&
          before.withdrawal_count === row.withdrawal_count &&
          before.disposition_count === row.disposition_count &&
          scalarKeys.slice(2).every((key) => BigInt(row[key]) <= BigInt(before[key]))
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
    throw new Error("unexpected minutes list query");
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
    protocolClientId: "minutes-list-fixture",
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
    readMinutes(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, tool, args) => {
    if (tool !== toolsByKind[kind]) throw new Error("out-of-scope minutes list dispatch");
    return seam.readMinutes(connection, actor, tool, args);
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
      repository.executeRead(principal, toolsByKind[kind], {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: id(1),
        limit: input.limit,
        ...(options.cursorWire ? { cursor: options.cursorWire } : {}),
        ...overrides
      }),
    helper: () => loadAdmittedMinutesList(client, input)
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
async function fixedClock<T>(work: () => Promise<T>) {
  const clock = vi.spyOn(Date, "now").mockReturnValue(1800000000000);
  try {
    return await work();
  } finally {
    clock.mockRestore();
  }
}
const zero = (): MinutesListScalars => ({
  row_count: "0",
  withdrawal_count: "0",
  disposition_count: "0",
  scalar_utf8: "0",
  json_utf8: "0",
  json_properties: "0",
  json_containers: "0"
});

describe.each(["versions", "reviews"] as const)("minutes %s list admission", (kind) => {
  it("refuses a saturated public call before whole projection", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(kind),
      leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.liveActor).toHaveBeenCalledOnce();
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(f.state.contentStarted).toBe(false);
      expect(f.state.constructions).toBe(0);
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves complete original fields and literal public bytes", async () => {
    const f = fixture(kind);
    for (const row of f.state.sourceRows) {
      expect(Object.keys(row.item).sort()).toEqual(
        [...(kind === "versions" ? versionKeys : reviewKeys)].sort()
      );
      if (kind === "reviews")
        for (const [key, keys] of [
          ["withdrawal", withdrawalKeys],
          ["disposition", dispositionKeys]
        ] as const) {
          const child = row.item[key];
          if (child !== null) expect(Object.keys(child as object).sort()).toEqual([...keys].sort());
        }
    }
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes(kind + "-complete"));
    expect(f.state.constructions).toBe(3);
  });
  it("preserves page bytes and independently signed cursor after charging lookahead", async () => {
    const f = fixture(kind, { limit: 2 });
    const result = await fixedClock(() => owned(new ResponseAllocationManager(), () => f.read()));
    expect(Buffer.from(canonicalJson(result))).toEqual(bytes(kind + "-page"));
    expect(f.state.constructions).toBe(3);
    expect(summed(f.metadata).row_count).toBe("3");
    const total = minutesListProjectionCost(kind, summed(f.metadata)),
      trimmed = minutesListProjectionCost(kind, summed(f.metadata.slice(0, 2)));
    expect(BigInt(total.jsonUpperBytes)).toBeGreaterThan(BigInt(trimmed.jsonUpperBytes));
  });
  it("uses the last returned item as the exact next-page frontier", async () => {
    const rows = literal<Row[]>(kind + "-rows"),
      page = literal<{ data: { next_cursor: string } }>(kind + "-page");
    const f = fixture(kind, {
      limit: 2,
      cursorAt: rows[1]!.cursor_at,
      cursorId: rows[1]!.cursor_id,
      cursorWire: page.data.next_cursor
    });
    const result = await fixedClock(() => owned(new ResponseAllocationManager(), () => f.read()));
    expect(result.data).toEqual({ items: [rows[2]!.item], next_cursor: null });
    expect(f.state.constructions).toBe(1);
    expect(f.query.mock.calls[0]?.[1]).toEqual([id(1), rows[1]!.cursor_at, rows[1]!.cursor_id, 3]);
  });
  it("preserves the empty envelope and retains its small lease until settlement", async () => {
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
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("requires a native owner before visible content", async () => {
    const f = fixture(kind);
    await expect(f.read()).rejects.toThrow("native response allocation owner is required");
    expect(f.state.constructions).toBe(0);
  });
  it("keeps actor and authority failures before queries", async () => {
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
  it("accepts limit500 and measures/constructs the 501st lookahead", async () => {
    const row = literal<Row[]>(kind + "-rows")[0]!,
      rows = Array.from({ length: 501 }, (_, index) => {
        const q = clone(row);
        q.cursor_id = id(2000 - index);
        q.item[kind === "versions" ? "version_id" : "review_item_id"] = q.cursor_id;
        if (kind === "versions") q.item.version = 501 - index;
        return q;
      });
    const f = fixture(kind, { limit: 500, rows }),
      result = await owned(new ResponseAllocationManager(), () => f.read());
    expect((result.data as { items: unknown[] }).items).toHaveLength(500);
    expect(f.state.constructions).toBe(501);
    expect(f.metadata).toHaveLength(501);
    expect(f.query.mock.calls[0]?.[1]?.[3]).toBe(501);
    const invalid = fixture(kind);
    await expect(invalid.read({ limit: 501 })).rejects.toBeDefined();
    expect(invalid.query).not.toHaveBeenCalled();
  });
  it("preserves nullable cursor values and leaves next-cursor failure to the original page code", async () => {
    const row = literal<Row[]>(kind + "-rows")[0]!;
    row.cursor_at = null;
    row.item.created_at = null;
    const f = fixture(kind, { rows: [row] });
    expect((await owned(new ResponseAllocationManager(), () => f.read())).data).toEqual({
      items: [row.item],
      next_cursor: null
    });
    const another = clone(row);
    another.cursor_id = id(9);
    another.item[kind === "versions" ? "version_id" : "review_item_id"] = id(9);
    const more = fixture(kind, { rows: [row, another], limit: 1 });
    await expect(owned(new ResponseAllocationManager(), () => more.read())).rejects.toBeDefined();
    expect(more.state.constructions).toBe(2);
    expect(more.metadata[0]?.cursor_at).toBeNull();
  });
  it("rejects a tampered cursor before metadata or full projection", async () => {
    const f = fixture(kind, { cursorWire: "bad.cursor" });
    await expect(owned(new ResponseAllocationManager(), () => f.read())).rejects.toBeDefined();
    expect(f.query).not.toHaveBeenCalled();
  });
  it("allows a hidden relative-order subset without requiring absolute ranks", async () => {
    const f = fixture(kind);
    f.state.afterMetadata = () => {
      f.state.hiddenIds.add(f.state.sourceRows[1]!.cursor_id);
    };
    const result = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(result.map((row) => row.cursor_id)).toEqual([f.metadata[0]!.id, f.metadata[2]!.id]);
    expect(f.state.constructions).toBe(2);
  });
  it("refuses empty-to-visible growth before constructing any row", async () => {
    const f = fixture(kind, { rows: [] });
    f.state.afterMetadata = () => {
      f.state.sourceRows = literal<Row[]>(kind + "-rows");
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("rejects an unseen replacement lookahead globally while a known row still fits", async () => {
    const f = fixture(kind, { limit: 1 });
    expect(f.metadata).toHaveLength(2);
    f.state.afterMetadata = () => {
      f.state.hiddenIds.add(f.state.sourceRows[0]!.cursor_id);
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
    expect(f.current().map((row) => row.id)).toEqual([
      f.metadata[1]!.id,
      f.state.sourceRows[2]!.cursor_id
    ]);
  });
  it("does not construct public content after disconnect during preflight", async () => {
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
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains disconnected production until the held content query settles", async () => {
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
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(
        minutesListProjectionPlan(f.input, f.metadata).units
      );
    } finally {
      resume();
      owner.nativeTerminal();
      owner.collectorSettled();
      await vi.waitFor(() => expect(settled).toBe(true), { timeout: 1000 });
    }
    expect((await outcome).error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains a successful visible producer until both native and collector signals", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(() => f.read());
      expect(manager.accounting.usedUnits).toBe(
        minutesListProjectionPlan(f.input, f.metadata).units
      );
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses oversized metadata before any content query", async () => {
    const f = fixture(kind);
    f.metadata[0]!.scalar_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.contentStarted).toBe(false);
  });
  it("rejects duplicate metadata and malformed fresh identity/order/cardinality", async () => {
    const duplicate = fixture(kind);
    duplicate.state.preflightRows = [duplicate.metadata[0], duplicate.metadata[0]];
    await expect(
      owned(new ResponseAllocationManager(), () => duplicate.helper())
    ).rejects.toBeInstanceOf(TypeError);
    for (const mode of ["unknown", "reversed", "duplicate", "wrong-item", "wrong-time", "extra"]) {
      const f = fixture(kind),
        rows = f.state.sourceRows.map((row) => ({ fits: true, ...clone(row) }));
      if (mode === "unknown") rows[0]!.cursor_id = id(77);
      if (mode === "reversed") rows.reverse();
      if (mode === "duplicate") rows[1] = clone(rows[0]!);
      if (mode === "wrong-item") rows[0]!.item.minutes_id = id(77);
      if (mode === "wrong-time") rows[0]!.cursor_at = "different";
      if (mode === "extra") rows.push(clone(rows[0]!));
      f.state.contentRows = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
});

describe("minutes list independent JSON/byte/accounting oracles", () => {
  it("preserves null review children and actual JSON-null/array payload values", async () => {
    const row = literal<Row>("reviews-null-row"),
      f = fixture("reviews", { rows: [row] });
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes("reviews-null-result"));
    for (const payload of [null, [], [0.5, { nested: [] }, "Δ"]]) {
      const q = clone(row);
      q.item.payload = payload;
      const sample = fixture("reviews", { rows: [q] });
      expect(
        (await owned(new ResponseAllocationManager(), () => sample.helper()))[0]?.item
      ).toEqual(q.item);
    }
  });
  it.each([
    "anchor",
    "payload",
    "raw payload",
    "withdrawal",
    "disposition",
    "reason",
    "raw timestamp"
  ])("refuses same-cost modeled %s change with unchanged public stored hashes", async (change) => {
    const f = fixture("reviews");
    f.state.afterMetadata = () => {
      const row = f.state.sourceRows[0]!;
      if (change === "anchor") (row.item.anchor as Item).offset = 1;
      if (change === "payload") ((row.item.payload as Item).values as Item).ratio = 0.6;
      if (change === "raw payload") {
        const payload = row.item.payload as Item,
          raw = Buffer.from(JSON.stringify(payload));
        const reordered = Buffer.from(
          JSON.stringify({ values: payload.values, schema_version: payload.schema_version })
        );
        expect(reordered.length).toBe(raw.length);
        expect(JSON.parse(reordered.toString())).toEqual(payload);
        f.state.rawPayloads.set(row.cursor_id, reordered);
      }
      if (change === "withdrawal") (row.item.withdrawal as Item).author_member_id = id(97);
      if (change === "disposition") (row.item.disposition as Item).disposition_id = id(49);
      if (change === "reason") (row.item.disposition as Item).reason = "Synthetic Δ review season";
      if (change === "raw timestamp")
        f.state.rawTimes.set(row.cursor_id, "2026-09-12 12:02:02.000002+00");
    };
    const stored = f.state.sourceRows.map((row) => row.item.payload_sha256);
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    const fresh = f.current();
    expect(scalarKeys.map((key) => fresh[0]![key])).toEqual(
      scalarKeys.map((key) => f.metadata[0]![key])
    );
    expect(fresh[0]!.observation_sha256).not.toBe(f.metadata[0]!.observation_sha256);
    expect(f.state.sourceRows.map((row) => row.item.payload_sha256)).toEqual(stored);
    expect(f.state.constructions).toBe(0);
  });
  it("rejects review child appearance and reason growth before any row construction", async () => {
    for (const mode of ["child", "reason"]) {
      const rows = literal<Row[]>("reviews-rows");
      if (mode === "child") rows[0]!.item.disposition = null;
      const f = fixture("reviews", { rows });
      f.state.afterMetadata = () => {
        if (mode === "child")
          f.state.sourceRows[0]!.item.disposition =
            literal<Row[]>("reviews-rows")[0]!.item.disposition!;
        else
          (f.state.sourceRows[0]!.item.disposition as Item).reason =
            String((f.state.sourceRows[0]!.item.disposition as Item).reason) + " grows";
      };
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.state.constructions).toBe(0);
    }
  });
  it("uses independent fixed row/child graph arithmetic including the four-field wrapper", () => {
    for (const kind of ["versions", "reviews"] as const)
      expect(minutesListProjectionCost(kind, zero())).toEqual({
        jsonUpperBytes: "2",
        propertyCount: "25",
        objectOrArrayCount: "7"
      });
    expect(minutesListProjectionCost("versions", { ...zero(), row_count: "1" })).toEqual({
      jsonUpperBytes: "276",
      propertyCount: "38",
      objectOrArrayCount: "9"
    });
    expect(minutesListProjectionCost("reviews", { ...zero(), row_count: "1" })).toEqual({
      jsonUpperBytes: "379",
      propertyCount: "43",
      objectOrArrayCount: "9"
    });
    expect(
      minutesListProjectionCost("reviews", {
        ...zero(),
        row_count: "1",
        withdrawal_count: "1",
        disposition_count: "1"
      })
    ).toEqual({ jsonUpperBytes: "570", propertyCount: "51", objectOrArrayCount: "11" });
    expect(minutesListProjectionCost("versions", { ...zero(), row_count: "501" })).toEqual({
      jsonUpperBytes: "137276",
      propertyCount: "6538",
      objectOrArrayCount: "1009"
    });
  });
  it("validates selector/cost scalars and tool-only zero-canonical kind", () => {
    const f = fixture("versions"),
      plan = minutesListProjectionPlan(f.input, f.metadata);
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    for (const value of ["-1", "01", "1.5", "1e3"])
      expect(() => minutesListProjectionCost("reviews", { ...zero(), scalar_utf8: value })).toThrow(
        TypeError
      );
    for (const scalars of [
      { row_count: "502" },
      { withdrawal_count: "1" },
      { disposition_count: "1" }
    ])
      expect(() => minutesListProjectionCost("reviews", { ...zero(), ...scalars })).toThrow(
        TypeError
      );
    expect(() =>
      minutesListProjectionCost("versions", { ...zero(), row_count: "1", json_utf8: "1" })
    ).toThrow(TypeError);
    expect(() =>
      minutesListProjectionCost("reviews", { ...zero(), scalar_utf8: "1".repeat(25) })
    ).toThrow(ResponseAllocationUnavailable);
    expect(() => minutesListProjectionPlan({ ...f.input, limit: 501 }, f.metadata)).toThrow(
      TypeError
    );
    const invalid = clone(f.metadata);
    invalid[0]!.observation_sha256 = "invalid";
    expect(() => minutesListProjectionPlan(f.input, invalid)).toThrow(TypeError);
  });
  it("preserves the 1920/1921-unit arithmetic boundary and 100 plus one small reads", () => {
    const scalarCost = { ...zero(), row_count: "1", json_utf8: "251643621" };
    const make = (cost: MinutesListScalars) =>
      responseAllocationPlan({
        kind: "minutes_list_projection",
        representation: "tool",
        canonicalBytes: 0,
        sourceId: id(1),
        sourceVersion: "reviews:100",
        sha256: "a".repeat(64),
        listProjection: minutesListProjectionCost("reviews", cost)
      });
    const plan = make(scalarCost),
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
    const over = make({ ...scalarCost, json_utf8: "251643622" });
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve({ ...over, units: 1 })).toThrow(ResponseAllocationUnavailable);
  });
  it("bounds retained rows plus the complete native-shaped graph and escaped JSON wire", async () => {
    const row = literal<Row[]>("reviews-rows")[0]!;
    row.item.anchor = { escaped: '"\\\n\u0001Δ🙂', "😀": { values: [[], {}] } };
    row.item.payload = [
      0.5,
      1e100,
      1e-100,
      {
        text: '"\\\n\u0001Δ🙂'.repeat(30),
        values: Array.from({ length: 30 }, () => ({ empty: [] }))
      }
    ];
    const f = fixture("reviews", { rows: [row] }),
      reply = await owned(new ResponseAllocationManager(), () => f.read());
    const wire = {
      content: [{ type: "text", text: JSON.stringify(reply) }],
      structuredContent: reply
    };
    const retained = f.state.sourceRows.map((value) => ({ fits: true, ...value }));
    // page() shares item objects with retained pg rows. Count actual identities
    // across both roots rather than inventing another copy of every item graph.
    const actual = graphCounts([wire, retained], true),
      cost = minutesListProjectionCost("reviews", summed(f.metadata)),
      plan = minutesListProjectionPlan(f.input, f.metadata);
    expect(BigInt(cost.propertyCount)).toBeGreaterThanOrEqual(BigInt(actual.properties));
    expect(BigInt(cost.objectOrArrayCount)).toBeGreaterThanOrEqual(BigInt(actual.containers));
    expect(BigInt(cost.jsonUpperBytes) + 4096n).toBeGreaterThanOrEqual(
      BigInt(Buffer.byteLength(canonicalJson(reply)))
    );
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
    expect(Number(f.metadata[0]!.json_properties)).toBeGreaterThan(30);
    expect(Number(f.metadata[0]!.json_containers)).toBeGreaterThan(60);
  });
});
