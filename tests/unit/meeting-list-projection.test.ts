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
  MEETING_LIST_PREFLIGHT_SQL,
  MEETING_LIST_CONTENT_SQL,
  loadAdmittedMeetingList,
  meetingListProjectionCost,
  meetingListProjectionPlan,
  type MeetingListInput,
  type MeetingListKind,
  type MeetingListMetadata
} from "../../artifacts/server/src/meeting-list-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_MEETING_TRANSCRIPTS_SQL,
  ORIGINAL_MEETINGS_SQL
} from "../helpers/meeting-lists-original-sql.js";

// Public input/registry/page/cursor code is real. Database, actor and authority
// ports are explicit models, limited to these two flat lists. No PG/RLS proof.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected meeting list pool");
        return callback(client);
      }
    )
  };
});
const id = (n: number) => `01993b00-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/meeting-lists-${name}.txt`));
const literal = <T>(name: string) => JSON.parse(bytes(name).toString("utf8")) as T;
const clone = <T>(value: T) => JSON.parse(JSON.stringify(value)) as T;
type Item = Record<string, JsonValue>;
interface Row {
  item: Item;
  cursor_at: string | null;
  cursor_id: string;
}
type Metadata = { -readonly [K in keyof MeetingListMetadata]: MeetingListMetadata[K] };
const tool = { transcripts: "list_meeting_transcripts", meetings: "list_meetings" } as const;
const original = { transcripts: ORIGINAL_MEETING_TRANSCRIPTS_SQL, meetings: ORIGINAL_MEETINGS_SQL };
const keys = {
  transcripts: [
    "transcript_id",
    "meeting_id",
    "state",
    "row_version",
    "current_version_id",
    "version",
    "media_type",
    "verification_state",
    "sha256"
  ],
  meetings: [
    "meeting_id",
    "board_id",
    "title",
    "state",
    "scheduled_start_at",
    "scheduled_end_at",
    "current_version_id",
    "current_agenda_version_id",
    "current_minutes_id",
    "row_version",
    "my_rsvp",
    "created_at"
  ]
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
function measure(kind: MeetingListKind, row: Row, rawTime: string): Metadata {
  let scalar = 0n;
  for (const value of [...keys[kind].map((key) => row.item[key]), row.cursor_at, row.cursor_id]) {
    if (value === null) continue;
    if (typeof value !== "string" && typeof value !== "number")
      throw new Error("unexpected flat scalar");
    scalar += BigInt(Buffer.byteLength(String(value)));
  }
  // Deliberate unit model, not PostgreSQL jsonb::text/hash parity. Only visible
  // RSVP value/NULL participates; no unreturned RSVP row identity is invented.
  return {
    id: row.cursor_id,
    cursor_at: row.cursor_at,
    raw_created_at: rawTime,
    observation_sha256: digest(JSON.stringify(row.item) + rawTime),
    scalar_utf8: String(scalar)
  };
}
function fixture(
  kind: MeetingListKind,
  options: {
    rows?: Row[];
    limit?: number;
    cursorAt?: string | null;
    cursorId?: string | null;
    cursorWire?: string;
  } = {}
) {
  const input: MeetingListInput = {
    kind,
    selectorId: id(kind === "transcripts" ? 1 : 2),
    memberId: kind === "transcripts" ? null : id(98),
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
          "infinity"
      )
    );
  const metadata = current();
  const parameters =
    kind === "transcripts"
      ? [input.selectorId, input.cursorAt, input.cursorId, input.limit + 1]
      : [input.selectorId, input.memberId, input.cursorAt, input.cursorId, input.limit + 1];
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === MEETING_LIST_CONTENT_SQL[kind] || sql === original[kind]) {
      state.contentStarted = true;
      await state.beforeContent?.();
    }
    if (sql === MEETING_LIST_PREFLIGHT_SQL[kind]) {
      expect(values).toEqual(parameters);
      const rows = state.preflightRows ?? clone(metadata);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === MEETING_LIST_CONTENT_SQL[kind]) {
      expect(values?.slice(0, parameters.length)).toEqual(parameters);
      if (state.contentRows) return { rows: state.contentRows };
      const expected = JSON.parse(String(values?.[parameters.length])) as Metadata[],
        fresh = current();
      const fits = fresh.every((row) => {
        const old = expected.find((bound) => bound.id === row.id);
        return (
          old !== undefined &&
          old.cursor_at === row.cursor_at &&
          old.raw_created_at === row.raw_created_at &&
          old.observation_sha256 === row.observation_sha256 &&
          BigInt(row.scalar_utf8) <= BigInt(old.scalar_utf8)
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
    throw new Error("unexpected meeting list query");
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
    readMeeting(
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
    return seam.readMeeting(connection, actor, name, args);
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
        [kind === "transcripts" ? "meeting_id" : "board_id"]: input.selectorId,
        limit: input.limit,
        ...(options.cursorWire ? { cursor: options.cursorWire } : {}),
        ...overrides
      }),
    helper: () => loadAdmittedMeetingList(client, input)
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
const total = (rows: readonly MeetingListMetadata[]) => ({
  row_count: String(rows.length),
  scalar_utf8: String(rows.reduce((sum, row) => sum + BigInt(row.scalar_utf8), 0n))
});

describe.each(["transcripts", "meetings"] as const)("flat %s meeting list", (kind) => {
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
    expect(f.state.constructions).toBe(kind === "transcripts" ? 1 : 3);
  });
  it("preserves page bytes in the explicit three-row cursor model", async () => {
    // Three transcripts for one meeting are not a legal installed fixture.
    // This hypothetical model exercises unchanged generic page/cursor behavior.
    const f = fixture(kind, { rows: literal<Row[]>(kind + "-model-rows"), limit: 2 });
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
      BigInt(meetingListProjectionCost(kind, total(f.metadata)).jsonUpperBytes)
    ).toBeGreaterThan(
      BigInt(meetingListProjectionCost(kind, total(f.metadata.slice(0, 2))).jsonUpperBytes)
    );
  });
  it("consumes the independently signed last-public-row cursor with original parameter order", async () => {
    const rows = literal<Row[]>(kind + "-model-rows"),
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
    expect(f.query.mock.calls[0]?.[1]).toEqual(
      kind === "transcripts"
        ? [id(1), rows[1]!.cursor_at, rows[1]!.cursor_id, 3]
        : [id(2), id(98), rows[1]!.cursor_at, rows[1]!.cursor_id, 3]
    );
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
  it("models the common 501-row internal lookahead without a transcript storage claim", async () => {
    const source = literal<Row[]>(kind + "-rows")[0]!;
    const rows = Array.from({ length: 501 }, (_, index) => {
      const row = clone(source);
      row.cursor_id = id(2000 - index);
      row.item[kind === "transcripts" ? "transcript_id" : "meeting_id"] = row.cursor_id;
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
  it("preserves nullable formatter values and original page rejection for a null anchor", async () => {
    const row = literal<Row[]>(kind + "-rows")[0]!;
    row.cursor_at = null;
    if (kind === "meetings") {
      row.item.created_at = null;
      row.item.scheduled_end_at = null;
    }
    const f = fixture(kind, { rows: [row] });
    expect((await owned(new ResponseAllocationManager(), () => f.read())).data).toEqual({
      items: [row.item],
      next_cursor: null
    });
    const other = clone(row);
    other.cursor_id = id(9);
    other.item[kind === "transcripts" ? "transcript_id" : "meeting_id"] = id(9);
    const more = fixture(kind, { rows: [row, other], limit: 1 });
    await expect(owned(new ResponseAllocationManager(), () => more.read())).rejects.toBeDefined();
    expect(more.state.constructions).toBe(2);
  });
  it("rejects a tampered cursor before any query", async () => {
    const f = fixture(kind, { cursorWire: "bad.cursor" });
    await expect(owned(new ResponseAllocationManager(), () => f.read())).rejects.toBeDefined();
    expect(f.query).not.toHaveBeenCalled();
  });
  it("allows known relative-order visibility loss including a completely hidden transcript", async () => {
    const f = fixture(kind);
    f.state.afterMetadata = () => {
      f.state.hiddenIds.add(f.state.sourceRows[kind === "transcripts" ? 0 : 1]!.cursor_id);
    };
    const rows = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(rows.map((row) => row.cursor_id)).toEqual(
      kind === "transcripts" ? [] : [f.metadata[0]!.id, f.metadata[2]!.id]
    );
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
    const f = fixture(kind, { rows: literal<Row[]>(kind + "-model-rows"), limit: 1 });
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
        meetingListProjectionPlan(f.input, f.metadata).units
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
        meetingListProjectionPlan(f.input, f.metadata).units
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
      const f = fixture(kind, { rows: literal<Row[]>(kind + "-model-rows") }),
        rows = f.state.sourceRows.map((row) => ({ fits: true, ...clone(row) }));
      if (mode === "unknown") rows[0]!.cursor_id = id(77);
      if (mode === "reversed") rows.reverse();
      if (mode === "duplicate") rows[1] = clone(rows[0]!);
      if (mode === "wrong-selector")
        rows[0]!.item[kind === "transcripts" ? "meeting_id" : "board_id"] = id(77);
      if (mode === "wrong-time") rows[0]!.cursor_at = "different";
      if (mode === "extra") rows.push(clone(rows[0]!));
      f.state.contentRows = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
});

describe("flat meeting list independent bounds and scalar binding", () => {
  it.each([
    ["meetings", "title"],
    ["meetings", "my_rsvp"],
    ["meetings", "current_version_id"],
    ["meetings", "row_version"],
    ["transcripts", "current_version_id"],
    ["transcripts", "version"],
    ["transcripts", "sha256"],
    ["meetings", "raw timestamp"],
    ["transcripts", "raw timestamp"]
  ] as const)("refuses same-cost modeled %s %s changes", async (kind, field) => {
    const f = fixture(kind);
    f.state.afterMetadata = () => {
      const row = f.state.sourceRows[0]!;
      if (field === "title") row.item.title = String(row.item.title).replace("Mining", "Survey");
      else if (field === "my_rsvp") row.item.my_rsvp = "tentative";
      else if (field === "current_version_id") row.item.current_version_id = id(21);
      else if (field === "row_version") row.item.row_version = "9007199254740994";
      else if (field === "version") row.item.version = 4;
      else if (field === "sha256") row.item.sha256 = "f".repeat(64);
      else f.state.rawTimes.set(row.cursor_id, "2026-09-12 12:02:02.000002+00");
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    const fresh = f.current();
    expect(fresh).toHaveLength(f.metadata.length);
    expect(fresh[0]!.scalar_utf8).toBe(f.metadata[0]!.scalar_utf8);
    expect(fresh[0]!.observation_sha256).not.toBe(f.metadata[0]!.observation_sha256);
    expect(f.state.constructions).toBe(0);
  });
  it("preserves RSVP NULL and refuses a newly visible response", async () => {
    const rows = literal<Row[]>("meetings-rows");
    rows[0]!.item.my_rsvp = null;
    const f = fixture("meetings", { rows });
    f.state.afterMetadata = () => {
      f.state.sourceRows[0]!.item.my_rsvp = "attending";
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(BigInt(f.current()[0]!.scalar_utf8)).toBe(BigInt(f.metadata[0]!.scalar_utf8) + 9n);
  });
  it("uses independently counted fixed fields and inherited wrapper allowances", () => {
    for (const kind of ["transcripts", "meetings"] as const)
      expect(meetingListProjectionCost(kind, { row_count: "0", scalar_utf8: "0" })).toEqual({
        jsonUpperBytes: "2",
        propertyCount: "25",
        objectOrArrayCount: "7"
      });
    expect(meetingListProjectionCost("transcripts", { row_count: "1", scalar_utf8: "0" })).toEqual({
      jsonUpperBytes: "262",
      propertyCount: "38",
      objectOrArrayCount: "9"
    });
    expect(meetingListProjectionCost("meetings", { row_count: "1", scalar_utf8: "0" })).toEqual({
      jsonUpperBytes: "345",
      propertyCount: "41",
      objectOrArrayCount: "9"
    });
    expect(meetingListProjectionCost("meetings", { row_count: "501", scalar_utf8: "0" })).toEqual({
      jsonUpperBytes: "171845",
      propertyCount: "8041",
      objectOrArrayCount: "1009"
    });
  });
  it("validates costs, selector identity and the tool-only zero-canonical kind", () => {
    const f = fixture("transcripts"),
      plan = meetingListProjectionPlan(f.input, f.metadata);
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    for (const scalar_utf8 of ["-1", "01", "1.5", "1e3"])
      expect(() => meetingListProjectionCost("meetings", { row_count: "1", scalar_utf8 })).toThrow(
        TypeError
      );
    expect(() =>
      meetingListProjectionCost("transcripts", { row_count: "502", scalar_utf8: "0" })
    ).toThrow(TypeError);
    expect(() =>
      meetingListProjectionCost("meetings", { row_count: "1", scalar_utf8: "1".repeat(25) })
    ).toThrow(ResponseAllocationUnavailable);
    expect(() => meetingListProjectionPlan({ ...f.input, limit: 501 }, f.metadata)).toThrow(
      TypeError
    );
    expect(() => meetingListProjectionPlan({ ...f.input, memberId: id(98) }, f.metadata)).toThrow(
      TypeError
    );
    const bad = clone(f.metadata);
    bad[0]!.observation_sha256 = "bad";
    expect(() => meetingListProjectionPlan(f.input, bad)).toThrow(TypeError);
  });
  it("preserves a one-unit scalar arithmetic boundary without a transcript storage claim", () => {
    const make = (s: string) =>
      responseAllocationPlan({
        kind: "meeting_list_projection",
        representation: "tool",
        canonicalBytes: 0,
        sourceId: id(1),
        sourceVersion: "transcripts:1",
        sha256: "a".repeat(64),
        listProjection: meetingListProjectionCost("transcripts", { row_count: "1", scalar_utf8: s })
      });
    expect(make("19455").units).toBe(1);
    expect(make("19456").units).toBe(2);
  });
  it("bounds actual retained and native-shaped graphs with maximal-title UTF8 and escaping", async () => {
    for (const kind of ["transcripts", "meetings"] as const) {
      const row = literal<Row[]>(kind + "-rows")[0]!;
      if (kind === "meetings") row.item.title = '"\\\n\u0001Δ'.repeat(50) + "🙂".repeat(262); // 512 codepoints, bounded title.
      const f = fixture(kind, { rows: [row] }),
        reply = await owned(new ResponseAllocationManager(), () => f.read());
      const wire = {
        content: [{ type: "text", text: JSON.stringify(reply) }],
        structuredContent: reply
      };
      const retained = f.state.sourceRows.map((value) => ({ fits: true, ...value }));
      const actual = graph([wire, retained], true),
        cost = meetingListProjectionCost(kind, total(f.metadata)),
        plan = meetingListProjectionPlan(f.input, f.metadata);
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
});
