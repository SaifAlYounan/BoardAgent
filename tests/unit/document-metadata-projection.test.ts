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
  DOCUMENT_METADATA_PREFLIGHT_SQL,
  DOCUMENT_METADATA_CONTENT_SQL,
  loadAdmittedDocumentMetadata,
  documentMetadataProjectionCost,
  documentMetadataProjectionPlan,
  type DocumentMetadataInput,
  type DocumentMetadataKind,
  type DocumentMetadataObservation
} from "../../artifacts/server/src/document-metadata-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_DOCUMENT_HASH_SQL,
  ORIGINAL_DOCUMENT_VALIDATION_SQL,
  ORIGINAL_DOCUMENT_VERSIONS_SQL,
  ORIGINAL_DOCUMENT_DOCUMENTS_SQL
} from "../helpers/document-metadata-original-sql.js";

// Only transaction/actor/authority ports are models. Public input/registry/page
// and cursor code remains real; these units do not prove PostgreSQL/RLS behavior.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected document metadata pool");
        return callback(client);
      }
    )
  };
});
const kinds = ["hash", "validation", "versions", "documents"] as const;
const isList = (kind: DocumentMetadataKind) => kind === "versions" || kind === "documents";
const id = (n: number) => `01993b00-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/document-metadata-${name}.txt`));
const literal = <T>(name: string) => JSON.parse(bytes(name).toString("utf8")) as T;
const clone = <T>(value: T) => JSON.parse(JSON.stringify(value)) as T;
type Item = Record<string, JsonValue>;
interface Row {
  item: Item;
  cursor_at: string | null;
  cursor_id: string;
}
type Metadata = {
  -readonly [K in keyof DocumentMetadataObservation]: DocumentMetadataObservation[K];
};
const tools = {
  hash: "get_document_hash",
  validation: "get_document_validation_status",
  versions: "list_document_versions",
  documents: "list_documents"
} as const;
const originals = {
  hash: ORIGINAL_DOCUMENT_HASH_SQL,
  validation: ORIGINAL_DOCUMENT_VALIDATION_SQL,
  versions: ORIGINAL_DOCUMENT_VERSIONS_SQL,
  documents: ORIGINAL_DOCUMENT_DOCUMENTS_SQL
};
const keys = {
  hash: [
    "document_id",
    "version_id",
    "version",
    "media_type",
    "document_schema",
    "byte_length",
    "sha256"
  ],
  validation: [
    "validation_attempt_id",
    "board_id",
    "offered_media_type",
    "offered_name",
    "offered_length",
    "offered_sha256",
    "result",
    "result_code",
    "remediation",
    "accepted_document_version_id",
    "attempted_at"
  ],
  versions: [
    "document_id",
    "version_id",
    "version",
    "media_type",
    "document_schema",
    "byte_length",
    "sha256",
    "created_by",
    "created_at"
  ],
  documents: [
    "document_id",
    "board_id",
    "title",
    "state",
    "version_id",
    "version",
    "media_type",
    "document_schema",
    "byte_length",
    "sha256",
    "row_version",
    "resource_uri",
    "created_at"
  ]
} as const;
function graph(roots: readonly unknown[]) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (!Array.isArray(value)) properties += Object.keys(value).length;
    pending.push(...Object.values(value));
  }
  return { properties, containers };
}
function measure(kind: DocumentMetadataKind, row: Row, rawTime: string | null): Metadata {
  let scalar = 0n;
  for (const value of [...keys[kind].map((key) => row.item[key]), row.cursor_at, row.cursor_id]) {
    if (value === null) continue;
    if (typeof value !== "string" && typeof value !== "number")
      throw new Error("unexpected flat scalar");
    scalar += BigInt(Buffer.byteLength(String(value)));
  }
  // Explicit unit binding model, not a claim of PG jsonb::text/hash parity.
  return {
    id: row.cursor_id,
    cursor_at: row.cursor_at,
    raw_created_at: rawTime,
    observation_sha256: digest(JSON.stringify([row.item, rawTime])),
    scalar_utf8: String(scalar)
  };
}
function fixture(
  kind: DocumentMetadataKind,
  options: {
    rows?: Row[];
    limit?: number;
    cursorAt?: string | null;
    cursorId?: string | null;
    cursorWire?: string;
  } = {}
) {
  const input: DocumentMetadataInput = {
    kind,
    selectorId: id(kind === "validation" ? 30 : kind === "documents" ? 2 : 1),
    versionId: kind === "hash" ? id(20) : null,
    limit: options.limit ?? (isList(kind) ? 100 : 1),
    cursorAt: options.cursorAt ?? null,
    cursorId: options.cursorId ?? null
  };
  const state = {
    sourceRows: options.rows ?? literal<Row[]>(kind + "-rows"),
    hiddenIds: new Set<string>(),
    rawTimes: new Map<string, string>(),
    constructions: 0,
    contentStarted: false,
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
      .slice(0, isList(kind) ? input.limit + 1 : 2);
  const current = () =>
    selected().map((row) =>
      measure(
        kind,
        row,
        isList(kind)
          ? (state.rawTimes.get(row.cursor_id) ??
              row.cursor_at?.replace("T", " ").replace("Z", "+00") ??
              "infinity")
          : null
      )
    );
  const metadata = current();
  const parameters = isList(kind)
    ? [input.selectorId, input.cursorAt, input.cursorId, input.limit + 1]
    : kind === "hash"
      ? [input.selectorId, input.versionId]
      : [input.selectorId];
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === DOCUMENT_METADATA_CONTENT_SQL[kind] || sql === originals[kind]) {
      state.contentStarted = true;
      await state.beforeContent?.();
    }
    if (sql === DOCUMENT_METADATA_PREFLIGHT_SQL[kind]) {
      expect(values).toEqual(parameters);
      const rows = state.preflightRows ?? clone(metadata);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === DOCUMENT_METADATA_CONTENT_SQL[kind]) {
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
    if (sql === originals[kind]) {
      expect(values).toEqual(parameters);
      const rows = selected();
      state.constructions += rows.length;
      return { rows: isList(kind) ? rows : rows.map((row) => ({ view: row.item })) };
    }
    throw new Error("unexpected document metadata query");
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
    protocolClientId: "document-metadata-fixture",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture-key",
    scopes: ["documents:read"],
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
    readDocumentMetadata(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({}),
    authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, name, args) => {
    if (name !== tools[kind]) throw new Error("out-of-scope document dispatch");
    return seam.readDocumentMetadata(connection, actor, name, args);
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
      repository.executeRead(principal, tools[kind], {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        [kind === "validation"
          ? "validation_attempt_id"
          : kind === "documents"
            ? "board_id"
            : "document_id"]: input.selectorId,
        ...(kind === "hash" ? { version_id: input.versionId } : {}),
        ...(isList(kind) ? { limit: input.limit } : {}),
        ...(options.cursorWire ? { cursor: options.cursorWire } : {}),
        ...overrides
      }),
    helper: () => loadAdmittedDocumentMetadata(client, input)
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
const total = (rows: readonly DocumentMetadataObservation[]) => ({
  row_count: String(rows.length),
  scalar_utf8: String(rows.reduce((sum, row) => sum + BigInt(row.scalar_utf8), 0n))
});

describe.each(kinds)("%s document metadata", (kind) => {
  it("refuses saturated public calls before response construction", async () => {
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
  it("preserves every original field and independent public literal", async () => {
    const f = fixture(kind);
    for (const row of f.state.sourceRows)
      expect(Object.keys(row.item).sort()).toEqual([...keys[kind]].sort());
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes(kind + "-full"));
    expect(f.state.constructions).toBe(isList(kind) ? 3 : 1);
  });
  it("retains the original absent or empty envelope until both lifecycle signals", async () => {
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
  it("requires a native owner before public content", async () => {
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
  it("allows a known visibility subset including a fresh absent point", async () => {
    const f = fixture(kind);
    f.state.afterMetadata = () => {
      f.state.hiddenIds.add(f.metadata[0]!.id);
    };
    const rows = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(rows.map((row) => row.cursor_id)).toEqual(f.metadata.slice(1).map((row) => row.id));
  });
  it("refuses empty-to-visible growth before constructing content", async () => {
    const f = fixture(kind, { rows: [] });
    f.state.afterMetadata = () => {
      f.state.sourceRows = literal<Row[]>(kind + "-rows");
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("does not construct content after a metadata-phase disconnect", async () => {
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
  it("retains a disconnected producer while both old and new content queries are held", async () => {
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
    const failures: unknown[] = [];
    try {
      await vi.waitFor(() => expect(f.state.contentStarted).toBe(true), { timeout: 1000 });
      abort.abort();
      close(owner);
      expect(manager.accounting.usedUnits).toBe(
        documentMetadataProjectionPlan(f.input, f.metadata).units
      );
    } catch (error) {
      failures.push(error);
    } finally {
      resume();
      close(owner);
      try {
        await vi.waitFor(() => expect(settled).toBe(true), { timeout: 1000 });
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length)
      throw new AggregateError(failures, "document metadata body or bounded cleanup failed");
    expect((await outcome).error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains successful public production until native and collector completion", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(() => f.read());
      expect(manager.accounting.usedUnits).toBe(
        documentMetadataProjectionPlan(f.input, f.metadata).units
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
  it("rejects duplicate metadata and malformed returned identity", async () => {
    const duplicate = fixture(kind);
    duplicate.state.preflightRows = [duplicate.metadata[0], duplicate.metadata[0]];
    await expect(
      owned(new ResponseAllocationManager(), () => duplicate.helper())
    ).rejects.toBeInstanceOf(TypeError);
    for (const mode of ["unknown", "wrong-item", "wrong-time", "extra"]) {
      const f = fixture(kind),
        rows = f.state.sourceRows.map((row) => ({ fits: true, ...clone(row) }));
      if (mode === "unknown") rows[0]!.cursor_id = id(77);
      if (mode === "wrong-item")
        rows[0]!.item[
          kind === "validation"
            ? "validation_attempt_id"
            : kind === "documents"
              ? "board_id"
              : "document_id"
        ] = id(77);
      if (mode === "wrong-time") rows[0]!.cursor_at = "different";
      if (mode === "extra") rows.push(clone(rows[0]!));
      f.state.contentRows = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
  it("bounds complete retained and native-shaped UTF8 escaped graphs", async () => {
    const row = literal<Row[]>(kind + "-rows")[0]!;
    if (kind === "validation")
      row.item.remediation = '"\\\n\u0001Δ'.repeat(200) + "🙂".repeat(1048); // 2048 codepoints, not bytes.
    else row.item.document_schema = '"\\\n\u0001Δ🙂'.repeat(4096); // Initial-DDL width model; no public writer reachability claim.
    const f = fixture(kind, { rows: [row] }),
      reply = await owned(new ResponseAllocationManager(), () => f.read());
    const wire = {
      content: [{ type: "text", text: JSON.stringify(reply) }],
      structuredContent: reply
    };
    const retained = f.state.sourceRows.map((value) => ({ fits: true, ...value })),
      actual = graph([wire, retained]);
    const cost = documentMetadataProjectionCost(kind, total(f.metadata)),
      plan = documentMetadataProjectionPlan(f.input, f.metadata);
    expect(BigInt(actual.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(actual.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    expect(Buffer.byteLength(JSON.stringify(retained))).toBeLessThanOrEqual(
      Number(cost.jsonUpperBytes)
    );
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
    expect(Buffer.byteLength(canonicalJson(reply))).toBeLessThanOrEqual(
      Number(cost.jsonUpperBytes) + 4096
    );
  });
});

describe.each(["versions", "documents"] as const)("%s original pagination", (kind) => {
  it("preserves independently signed first-page bytes and charges lookahead", async () => {
    const f = fixture(kind, { limit: 2 });
    expect(
      Buffer.from(
        canonicalJson(
          await fixedClock(() => owned(new ResponseAllocationManager(), () => f.read()))
        )
      )
    ).toEqual(bytes(kind + "-page"));
    expect(f.metadata).toHaveLength(3);
    expect(f.state.constructions).toBe(3);
  });
  it("consumes the independent cursor with original argument ordering", async () => {
    const rows = literal<Row[]>(kind + "-rows"),
      page = literal<{ data: { next_cursor: string } }>(kind + "-page");
    const f = fixture(kind, {
      rows,
      limit: 2,
      cursorAt: rows[1]!.cursor_at,
      cursorId: rows[1]!.cursor_id,
      cursorWire: page.data.next_cursor
    });
    expect(
      (await fixedClock(() => owned(new ResponseAllocationManager(), () => f.read()))).data
    ).toEqual({ items: [rows[2]!.item], next_cursor: null });
    expect(f.query.mock.calls[0]?.[1]).toEqual([
      f.input.selectorId,
      rows[1]!.cursor_at,
      rows[1]!.cursor_id,
      3
    ]);
  });
  it("models 501 selected rows and preserves public limit rejection", async () => {
    const template = literal<Row[]>(kind + "-rows")[0]!;
    const rows = Array.from({ length: 501 }, (_, index) => {
      const row = clone(template);
      row.cursor_id = id(2000 - index);
      row.item[kind === "versions" ? "version_id" : "document_id"] = row.cursor_id;
      if (kind === "versions") row.item.version = 501 - index;
      else row.item.resource_uri = `board://${id(2)}/documents/${row.cursor_id}/versions/3`;
      return row;
    });
    const f = fixture(kind, { rows, limit: 500 });
    expect(
      ((await owned(new ResponseAllocationManager(), () => f.read())).data as { items: unknown[] })
        .items
    ).toHaveLength(500);
    expect(f.state.constructions).toBe(501);
    const invalid = fixture(kind);
    await expect(invalid.read({ limit: 501 })).rejects.toBeDefined();
    expect(invalid.query).not.toHaveBeenCalled();
  });
  it("preserves nullable formatter output and original invalid next-anchor error", async () => {
    const row = literal<Row[]>(kind + "-rows")[0]!;
    row.cursor_at = null;
    row.item.created_at = null;
    const f = fixture(kind, { rows: [row] });
    expect((await owned(new ResponseAllocationManager(), () => f.read())).data).toEqual({
      items: [row.item],
      next_cursor: null
    });
    const other = clone(row);
    other.cursor_id = id(9);
    other.item[kind === "versions" ? "version_id" : "document_id"] = id(9);
    const more = fixture(kind, { rows: [row, other], limit: 1 });
    await expect(owned(new ResponseAllocationManager(), () => more.read())).rejects.toBeDefined();
    expect(more.state.constructions).toBe(2);
  });
  it("rejects tampered public cursors before either SQL phase", async () => {
    const f = fixture(kind, { cursorWire: "bad.cursor" });
    await expect(owned(new ResponseAllocationManager(), () => f.read())).rejects.toBeDefined();
    expect(f.query).not.toHaveBeenCalled();
  });
  it("refuses unseen backfill globally while allowing a known relative-order subset", async () => {
    const f = fixture(kind, { limit: 1 });
    f.state.afterMetadata = () => {
      f.state.hiddenIds.add(f.metadata[0]!.id);
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
  it("rejects reversed or duplicate returned page order", async () => {
    for (const mode of ["reverse", "duplicate"]) {
      const f = fixture(kind),
        rows = f.state.sourceRows.map((row) => ({ fits: true, ...clone(row) }));
      if (mode === "reverse") rows.reverse();
      else rows[1] = clone(rows[0]!);
      f.state.contentRows = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
});

describe("document metadata independent binding and arithmetic", () => {
  it.each([
    ["hash", "document_schema"],
    ["hash", "sha256"],
    ["hash", "version"],
    ["validation", "remediation"],
    ["validation", "offered_length"],
    ["validation", "offered_name"],
    ["versions", "document_schema"],
    ["versions", "raw timestamp"],
    ["documents", "title"],
    ["documents", "version_id"],
    ["documents", "row_version"],
    ["documents", "raw timestamp"]
  ] as const)("refuses equal-cost modeled %s %s changes", async (kind, field) => {
    const f = fixture(kind);
    f.state.afterMetadata = () => {
      const row = f.state.sourceRows[0]!;
      if (field === "raw timestamp")
        f.state.rawTimes.set(row.cursor_id, "2026-09-12 12:02:02.000002+00");
      else if (field === "document_schema") row.item.document_schema = "boardagent.changed.v1";
      else if (field === "sha256") row.item.sha256 = "f".repeat(64);
      else if (field === "version") row.item.version = 4;
      else if (field === "version_id") row.item.version_id = id(21);
      else if (field === "offered_length" || field === "row_version")
        row.item[field] = "9007199254740994";
      else
        row.item[field] = String(row.item[field]).replace(
          field === "remediation" ? "Correct" : "Mining",
          field === "remediation" ? "Replace" : "Survey"
        );
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    const fresh = f.current();
    expect(total(fresh)).toEqual(total(f.metadata));
    expect(documentMetadataProjectionCost(kind, total(fresh))).toEqual(
      documentMetadataProjectionCost(kind, total(f.metadata))
    );
    expect(fresh[0]!.observation_sha256).not.toBe(f.metadata[0]!.observation_sha256);
    expect(f.state.constructions).toBe(0);
  });
  it("preserves optional validation nulls and bigint text without a document join", async () => {
    const row = literal<Row[]>("validation-rows")[0]!;
    for (const key of [
      "board_id",
      "offered_name",
      "offered_length",
      "offered_sha256",
      "attempted_at"
    ])
      row.item[key] = null;
    const f = fixture("validation", { rows: [row] });
    expect((await owned(new ResponseAllocationManager(), () => f.read())).data).toEqual({
      validation: row.item
    });
  });
  it("preserves historical hash and nullable schema without unreturned timestamp binding", async () => {
    const row = literal<Row[]>("hash-rows")[0]!;
    row.item.document_schema = null;
    row.item.media_type = "text/plain; charset=utf-8";
    const f = fixture("hash", { rows: [row] });
    f.state.afterMetadata = () => {
      f.state.rawTimes.set(row.cursor_id, "unreturned parent change");
    };
    expect((await owned(new ResponseAllocationManager(), () => f.read())).data).toEqual({
      document_hash: row.item
    });
    expect(f.current()).toEqual(f.metadata);
  });
  it("uses independently counted fields and inherited retained-wrapper margins", () => {
    const expected = {
      hash: ["214", "36"],
      validation: ["339", "40"],
      versions: ["254", "38"],
      documents: ["325", "42"]
    };
    for (const kind of kinds) {
      expect(documentMetadataProjectionCost(kind, { row_count: "0", scalar_utf8: "0" })).toEqual({
        jsonUpperBytes: "2",
        propertyCount: "25",
        objectOrArrayCount: "7"
      });
      expect(documentMetadataProjectionCost(kind, { row_count: "1", scalar_utf8: "0" })).toEqual({
        jsonUpperBytes: expected[kind][0],
        propertyCount: expected[kind][1],
        objectOrArrayCount: "9"
      });
    }
    expect(
      documentMetadataProjectionCost("documents", { row_count: "501", scalar_utf8: "0" })
    ).toEqual({ jsonUpperBytes: "161825", propertyCount: "8542", objectOrArrayCount: "1009" });
  });
  it("preserves the independently derived one-unit scalar boundary", () => {
    const make = (s: string) =>
      responseAllocationPlan({
        kind: "document_metadata_projection",
        representation: "tool",
        canonicalBytes: 0,
        sourceId: id(2),
        sourceVersion: "documents:1",
        sha256: "a".repeat(64),
        listProjection: documentMetadataProjectionCost("documents", {
          row_count: "1",
          scalar_utf8: s
        })
      });
    expect(make("19423").units).toBe(1);
    expect(make("19424").units).toBe(2);
  });
  it("validates costs, point cardinality and the zero-canonical tool kind", () => {
    const f = fixture("hash"),
      plan = documentMetadataProjectionPlan(f.input, f.metadata);
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    for (const scalar_utf8 of ["-1", "01", "1.5", "1e3"])
      expect(() => documentMetadataProjectionCost("hash", { row_count: "1", scalar_utf8 })).toThrow(
        TypeError
      );
    expect(() =>
      documentMetadataProjectionCost("hash", { row_count: "2", scalar_utf8: "0" })
    ).toThrow(TypeError);
    expect(() =>
      documentMetadataProjectionCost("documents", { row_count: "502", scalar_utf8: "0" })
    ).toThrow(TypeError);
    expect(() =>
      documentMetadataProjectionCost("hash", { row_count: "1", scalar_utf8: "1".repeat(25) })
    ).toThrow(ResponseAllocationUnavailable);
    expect(() => documentMetadataProjectionPlan({ ...f.input, limit: 2 }, f.metadata)).toThrow(
      TypeError
    );
    const bad = clone(f.metadata);
    bad[0]!.raw_created_at = "unexpected";
    expect(() => documentMetadataProjectionPlan(f.input, bad)).toThrow(TypeError);
  });
});
