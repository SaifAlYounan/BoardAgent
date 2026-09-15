import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  EXPORT_STATUS_PREFLIGHT_SQL,
  EXPORT_STATUS_CONTENT_SQL,
  exportStatusProjectionCost,
  exportStatusProjectionPlan,
  loadAdmittedExportStatus,
  type ExportStatusMetadata
} from "../../artifacts/server/src/export-status-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_EXPORT_STATUS_SQL } from "../helpers/export-status-original-sql.js";

// Parser, registry, public dispatch and result builder are real. Authority, transaction
// and SQL are modeled; these tests do not establish actual PG, RLS or export issuance.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, work: (client: PoolClient) => Promise<unknown>) =>
        work((pool as unknown as { fixtureClient: PoolClient }).fixtureClient)
    )
  };
});
type Item = Record<string, JsonValue>;
const id = (n: number) => `01993900-0000-7000-8000-${String(n).padStart(12, "0")}`;
const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const exportId = Buffer.alloc(32, 7).toString("base64url");
const principal: SurfacePrincipal = {
  organizationId: id(1),
  memberId: id(2),
  serviceOrigin: "https://boardagent.test",
  clientId: id(3),
  protocolClientId: "export-unit",
  accessTokenRecordId: id(4),
  tokenJti: id(5),
  keyId: "fixture",
  scopes: ["governance:read"],
  roles: ["member"],
  boardIds: [id(6)]
};
const object = (v: JsonValue): Item => {
  if (v === null || typeof v !== "object" || Array.isArray(v))
    throw new TypeError("literal object expected");
  return v as Item;
};
function view(): Item {
  return {
    export_id: exportId,
    request_id: id(10),
    board_id: id(6),
    export_type: "system_data",
    scope_sha256: "a".repeat(64),
    state: "succeeded",
    row_version: "9007199254740993",
    expires_at: "2026-09-14T00:00:00.000001Z",
    snapshot_sha256: "b".repeat(64),
    failure_class: null,
    artifact: {
      artifact_id: id(11),
      manifest_sha256: "c".repeat(64),
      content_set_sha256: "d".repeat(64),
      byte_length: "9007199254740993",
      state: "ready",
      created_at: "2026-09-13T00:00:00.000002Z",
      deleted_at: null
    },
    created_at: "2026-09-13T00:00:00.000001Z",
    completed_at: "2026-09-13T00:00:00.000003Z"
  };
}
const ROOT_FLAT = [
  "export_id",
  "request_id",
  "board_id",
  "export_type",
  "scope_sha256",
  "state",
  "row_version",
  "expires_at",
  "snapshot_sha256",
  "failure_class",
  "created_at",
  "completed_at"
];
const ARTIFACT_FLAT = [
  "artifact_id",
  "manifest_sha256",
  "content_set_sha256",
  "byte_length",
  "state",
  "created_at",
  "deleted_at"
];
function graph(roots: readonly unknown[]) {
  const pending = [...roots],
    seen = new Set<object>();
  let p = 0,
    o = 0;
  while (pending.length) {
    const x = pending.pop();
    if (x === null || typeof x !== "object" || seen.has(x)) continue;
    seen.add(x);
    o++;
    if (!Array.isArray(x)) p += Object.keys(x).length;
    for (const v of Object.values(x)) pending.push(v);
  }
  return { p, o };
}
function measure(v: Item | null, reference = exportId, privateVersion = "1"): ExportStatusMetadata {
  let s = Buffer.byteLength(reference);
  const flat = (x: Item, keys: readonly string[]) => {
    for (const k of keys) {
      const leaf = x[k];
      s += leaf === null ? 0 : Buffer.byteLength(String(leaf));
    }
  };
  const a = v?.artifact === null || !v ? null : object(v.artifact!);
  if (v) flat(v, ROOT_FLAT);
  if (a) flat(a, ARTIFACT_FLAT);
  return {
    row_count: v ? "1" : "0",
    artifact_count: a ? "1" : "0",
    scalar_utf8: String(s),
    request_id: v ? String(v.request_id) : null,
    artifact_id: a ? String(a.artifact_id) : null,
    row_version: v ? String(v.row_version) : null,
    observation_sha256: sha(
      canonicalJson({ reference, memberId: principal.memberId, view: v, privateVersion })
    )
  };
}
const expected = (v: Item | null, reference = exportId): SurfaceToolResult => ({
  schema_version: "boardagent.tool-result.v1",
  tool: "get_export_status",
  status: "ok",
  reference,
  resource_uri: null,
  data: { export: v }
});
function fixture(reference = exportId) {
  const state = {
    view: view() as Item | null,
    privateVersion: "1",
    constructions: 0,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined,
    metadataOverride: undefined as unknown[] | undefined,
    contentOverride: undefined as unknown[] | undefined,
    contentError: undefined as Error | undefined
  };
  state.view!.export_id = reference;
  const query = vi.fn(async (sql: string, args: unknown[] = []) => {
    expect(args.slice(0, 3)).toEqual([
      Buffer.from(reference, "base64url"),
      reference,
      principal.memberId
    ]);
    if (sql === EXPORT_STATUS_PREFLIGHT_SQL) {
      const m = measure(state.view, reference, state.privateVersion);
      const rows = state.metadataOverride ?? [m];
      state.afterMetadata?.();
      return { rows };
    }
    if (sql !== ORIGINAL_EXPORT_STATUS_SQL && sql !== EXPORT_STATUS_CONTENT_SQL)
      throw new Error("unexpected export SQL");
    await state.beforeContent?.();
    if (state.contentError) throw state.contentError;
    if (state.contentOverride) return { rows: state.contentOverride };
    if (sql === EXPORT_STATUS_CONTENT_SQL) {
      const m = measure(state.view, reference, state.privateVersion),
        b = args.slice(3);
      const fits =
        BigInt(m.scalar_utf8) <= BigInt(String(b[2])) &&
        (m.row_count === "0" ||
          (m.row_count === b[0] &&
            m.artifact_count === b[1] &&
            m.request_id === b[3] &&
            m.artifact_id === b[4] &&
            m.row_version === b[5] &&
            m.observation_sha256 === b[6]));
      if (!fits) return { rows: [{ fits: false, view: null }] };
    }
    state.constructions++;
    return {
      rows: state.view
        ? [{ ...(sql === ORIGINAL_EXPORT_STATUS_SQL ? {} : { fits: true }), view: state.view }]
        : []
    };
  });
  const client = { query } as unknown as PoolClient,
    repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
      cursorKey: Buffer.alloc(32, 1)
    });
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
  };
  const live = vi.spyOn(seam, "liveActor").mockResolvedValue({}),
    authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  return {
    state,
    query,
    client,
    live,
    authorize,
    read: () =>
      repo.executeRead(principal, "get_export_status", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        export_id: reference
      }),
    helper: () =>
      loadAdmittedExportStatus(
        client,
        Buffer.from(reference, "base64url"),
        reference,
        principal.memberId
      )
  };
}
const small = () =>
  responseAllocationPlan({
    kind: "document",
    representation: "resource",
    canonicalBytes: 1,
    sourceId: "small",
    sourceVersion: "1",
    sha256: "a".repeat(64)
  });
const terminal = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
async function owned<T>(m: ResponseAllocationManager, fn: () => Promise<T>) {
  const o = m.openRequest(new AbortController().signal);
  try {
    return await o.produce(fn);
  } finally {
    terminal(o);
  }
}
function defer() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
async function deadline<T>(p: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("bounded test deadline")), 2000);
      })
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

describe("export status projection admission", () => {
  for (const shape of ["artifact", "root-only", "absent", "nullable", "failed"] as const) {
    it(`preserves complete original ${shape} output and exact text/canonical bytes`, async () => {
      const f = fixture();
      if (shape === "root-only") f.state.view!.artifact = null;
      if (shape === "absent") f.state.view = null;
      if (shape === "nullable") {
        f.state.view!.state = "queued";
        f.state.view!.board_id = null;
        f.state.view!.snapshot_sha256 = null;
        f.state.view!.completed_at = null;
        object(f.state.view!.artifact!).state = "deleted";
        object(f.state.view!.artifact!).deleted_at = "2026-09-13T00:01:00.000004Z";
      }
      if (shape === "failed") {
        f.state.view!.state = "failed";
        f.state.view!.failure_class = "synthetic_failure";
      }
      const want = expected(f.state.view),
        out = await owned(new ResponseAllocationManager(), f.read);
      expect(out).toEqual(want);
      expect(JSON.stringify(out)).toBe(JSON.stringify(want));
      expect(canonicalJson(out)).toBe(canonicalJson(want));
      expect(f.live).toHaveBeenCalledTimes(1);
      expect(f.authorize).toHaveBeenCalledTimes(1);
    });
  }
  it("preserves the original 512-character absent reference without overflowing private source identity", async () => {
    const reference = Buffer.alloc(384, 8).toString("base64url"),
      f = fixture(reference);
    f.state.view = null;
    expect(reference.length).toBe(512);
    const out = await owned(new ResponseAllocationManager(), f.read);
    expect(out).toEqual(expected(null, reference));
    expect(measure(null, reference).scalar_utf8).toBe("512");
  });
  it("requires a public owner before any metadata or content query", async () => {
    const f = fixture();
    await expect(f.read()).rejects.toBeInstanceOf(TypeError);
    expect(f.query).not.toHaveBeenCalled();
  });
  it("refuses saturated public output before the original full constructor", async () => {
    const f = fixture(),
      m = new ResponseAllocationManager(),
      holder = m.openRequest(new AbortController().signal);
    try {
      await holder.produce(async () => {
        for (let i = 0; i < 2048; i++) holder.reserve(small());
      });
      const error = await owned(m, f.read).then(
        () => null,
        (e) => e
      );
      expect(f.state.constructions).toBe(0);
      expect(error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(
        f.query.mock.calls.filter(([sql]) => sql === EXPORT_STATUS_PREFLIGHT_SQL)
      ).toHaveLength(1);
      expect(f.query.mock.calls.filter(([sql]) => sql === EXPORT_STATUS_CONTENT_SQL)).toHaveLength(
        0
      );
    } finally {
      terminal(holder);
    }
    expect(m.accounting.usedUnits).toBe(0);
  });
  for (const denied of ["live", "authorize"] as const) {
    it(`keeps ${denied} denial before admission`, async () => {
      const f = fixture(),
        fault = new Error("authority denied");
      if (denied === "live") f.live.mockRejectedValue(fault);
      else
        f.authorize.mockImplementation(() => {
          throw fault;
        });
      await expect(owned(new ResponseAllocationManager(), f.read)).rejects.toBe(fault);
      expect(f.query).not.toHaveBeenCalled();
      expect(f.state.constructions).toBe(0);
    });
  }
  for (const shape of ["artifact", "root-only", "absent"] as const) {
    it(`bounds all retained PG and SDK ${shape} graphs`, async () => {
      const f = fixture();
      if (shape === "root-only") f.state.view!.artifact = null;
      if (shape === "absent") f.state.view = null;
      const m = measure(f.state.view),
        cost = exportStatusProjectionCost(m),
        plan = exportStatusProjectionPlan("test", m),
        rows = await owned(new ResponseAllocationManager(), f.helper);
      const r = Number(m.row_count),
        a = Number(m.artifact_count),
        s = Number(m.scalar_utf8);
      expect(cost).toEqual({
        jsonUpperBytes: String(2 + 298 * r + 152 * a + 6 * s),
        propertyCount: String(32 + 15 * r + 7 * a),
        objectOrArrayCount: String(12 + 2 * r + a)
      });
      const result = expected(f.state.view),
        wire = {
          content: [{ type: "text", text: JSON.stringify(result) }],
          structuredContent: result
        },
        g = graph([rows, wire]);
      expect(g.p).toBeLessThanOrEqual(Number(cost.propertyCount));
      expect(g.o).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
      expect(
        Buffer.byteLength(JSON.stringify(rows)) + 6 * Buffer.byteLength(exportId)
      ).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
    });
  }
  it("charges an independently measured wide snapshot hex body with 100 small leases held", async () => {
    const f = fixture(),
      m = new ResponseAllocationManager(),
      holder = m.openRequest(new AbortController().signal);
    f.state.view!.state = "queued";
    f.state.view!.snapshot_sha256 = Buffer.alloc(256 * 1024, 171).toString("hex");
    const observation = measure(f.state.view),
      plan = exportStatusProjectionPlan("wide", observation),
      want = expected(f.state.view);
    expect(String(f.state.view!.snapshot_sha256).length).toBe(524288);
    expect(plan.units).toBeGreaterThan(1);
    try {
      await holder.produce(async () => {
        for (let i = 0; i < 100; i++) holder.reserve(small());
      });
      const rows = await owned(m, f.helper);
      expect(rows[0]!.view).toEqual(f.state.view);
      expect(canonicalJson(expected(object(rows[0]!.view)))).toBe(canonicalJson(want));
      expect(m.accounting.usedUnits).toBe(100);
    } finally {
      terminal(holder);
    }
    expect(m.accounting.usedUnits).toBe(0);
  });
  it("distinguishes NULL and empty snapshot bytes without a fabricated fixed SHA width", async () => {
    const f = fixture();
    f.state.view!.state = "queued";
    f.state.view!.snapshot_sha256 = null;
    const absent = measure(f.state.view);
    f.state.view!.snapshot_sha256 = "";
    const empty = measure(f.state.view);
    expect(absent.scalar_utf8).toBe(empty.scalar_utf8);
    expect(absent.observation_sha256).not.toBe(empty.observation_sha256);
    const out = await owned(new ResponseAllocationManager(), f.helper);
    expect(object(out[0]!.view).snapshot_sha256).toBe("");
  });
  for (const change of [
    "request-id",
    "artifact-id",
    "artifact-gone",
    "artifact-arrives",
    "row-version",
    "same-width-bytes",
    "wider-bytes",
    "raw-time"
  ] as const) {
    it(`refuses modeled fresh nonempty ${change} before construction`, async () => {
      const f = fixture();
      if (change === "artifact-arrives") f.state.view!.artifact = null;
      const prior = measure(f.state.view);
      f.state.afterMetadata = () => {
        if (change === "request-id") f.state.view!.request_id = id(12);
        if (change === "artifact-id") object(f.state.view!.artifact!).artifact_id = id(12);
        if (change === "artifact-gone") f.state.view!.artifact = null;
        if (change === "artifact-arrives") f.state.view!.artifact = view().artifact!;
        if (change === "row-version") f.state.view!.row_version = "9007199254740994";
        if (change === "same-width-bytes") f.state.view!.snapshot_sha256 = "e".repeat(64);
        if (change === "wider-bytes") f.state.view!.snapshot_sha256 = "e".repeat(128);
        if (change === "raw-time") f.state.privateVersion = "2";
      };
      await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.state.constructions).toBe(0);
      if (change === "same-width-bytes") {
        const next = measure(f.state.view);
        expect({ ...next, observation_sha256: "" }).toEqual({ ...prior, observation_sha256: "" });
        expect(next.observation_sha256).not.toBe(prior.observation_sha256);
      }
    });
  }
  it("preserves fresh whole disappearance as no rows while keeping the reference", async () => {
    const f = fixture();
    f.state.afterMetadata = () => {
      f.state.view = null;
    };
    expect(await owned(new ResponseAllocationManager(), f.helper)).toEqual([]);
    expect(expected(f.state.view).reference).toBe(exportId);
  });
  for (const malformed of [
    "two-roots",
    "artifact-without-root",
    "bad-digest",
    "missing-request",
    "overlong-counter"
  ] as const) {
    it(`rejects ${malformed} metadata before content`, async () => {
      const f = fixture(),
        m = { ...measure(f.state.view) };
      if (malformed === "two-roots") m.row_count = "2";
      if (malformed === "artifact-without-root") m.row_count = "0";
      if (malformed === "bad-digest") m.observation_sha256 = "invalid";
      if (malformed === "missing-request") m.request_id = null;
      if (malformed === "overlong-counter") m.scalar_utf8 = "1".repeat(25);
      f.state.metadataOverride = [m];
      await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
        malformed === "overlong-counter" ? ResponseAllocationUnavailable : TypeError
      );
      expect(f.state.constructions).toBe(0);
      expect(f.query).toHaveBeenCalledTimes(1);
    });
  }
  it("rejects metadata/content shape drift and incorrect returned identities", async () => {
    const f = fixture();
    f.state.metadataOverride = [];
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
      TypeError
    );
    f.state.metadataOverride = undefined;
    for (const rows of [
      [{ fits: false, view: null }],
      [{ fits: true, view: null }],
      [{ fits: true, view: { ...view(), request_id: id(99) } }],
      [
        {
          fits: true,
          view: { ...view(), artifact: { ...object(view().artifact!), artifact_id: id(99) } }
        }
      ],
      [
        { fits: true, view: view() },
        { fits: true, view: view() }
      ]
    ]) {
      f.state.contentOverride = rows;
      await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
        rows[0]!.fits === false ? ResponseAllocationUnavailable : TypeError
      );
    }
  });
  it("preserves content query errors and settles their lease", async () => {
    const f = fixture(),
      m = new ResponseAllocationManager(),
      fault = new Error("original SQL failure");
    f.state.contentError = fault;
    await expect(owned(m, f.helper)).rejects.toBe(fault);
    expect(m.accounting.usedUnits).toBe(0);
  });
  it("refuses disconnect after metadata before content", async () => {
    const f = fixture(),
      m = new ResponseAllocationManager(),
      controller = new AbortController(),
      owner = m.openRequest(controller.signal);
    f.state.afterMetadata = () => controller.abort();
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    } finally {
      terminal(owner);
    }
    expect(f.state.constructions).toBe(0);
    expect(m.accounting.usedUnits).toBe(0);
  });
  it("checks exact 1920/1921 reservation boundaries without allocating the claimed body", async () => {
    const m = measure(view()),
      manager = new ResponseAllocationManager(),
      o = manager.openRequest(new AbortController().signal);
    const exact = exportStatusProjectionPlan("bound", { ...m, scalar_utf8: "41940468" }),
      over = exportStatusProjectionPlan("bound", { ...m, scalar_utf8: "41940469" });
    expect(exact.units).toBe(1920);
    expect(over.units).toBe(1921);
    try {
      await o.produce(async () => {
        expect(() => o.reserve(over)).toThrow(ResponseAllocationUnavailable);
        expect(manager.accounting.usedUnits).toBe(0);
        o.reserve(exact);
      });
      expect(manager.accounting.usedUnits).toBe(1920);
    } finally {
      terminal(o);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("restricts the private kind to zero-canonical tool plans", () => {
    const input = {
      kind: "export_status_projection" as const,
      sourceId: "export",
      sourceVersion: "1",
      sha256: "a".repeat(64),
      listProjection: exportStatusProjectionCost(measure(view()))
    };
    expect(() =>
      responseAllocationPlan({ ...input, representation: "resource", canonicalBytes: 0 })
    ).toThrow(TypeError);
    expect(() =>
      responseAllocationPlan({ ...input, representation: "tool", canonicalBytes: 1 })
    ).toThrow(TypeError);
  });
  it("keeps the public lease through terminal and collector while its producer is pending", async () => {
    const f = fixture(),
      m = new ResponseAllocationManager(),
      o = m.openRequest(new AbortController().signal),
      entered = defer(),
      release = defer();
    const units = exportStatusProjectionPlan("expected", measure(f.state.view)).units;
    f.state.beforeContent = async () => {
      entered.resolve();
      await release.promise;
    };
    const produced = o.produce(f.read),
      settled = produced.then(
        (value) => ({ ok: true as const, value }),
        (error) => ({ ok: false as const, error })
      );
    let bodyError: unknown, cleanupError: unknown;
    try {
      await deadline(
        Promise.race([
          entered.promise,
          settled.then((out) => {
            throw out.ok ? new Error("producer completed before content gate") : out.error;
          })
        ])
      );
      expect(m.accounting.usedUnits).toBe(units);
      o.nativeTerminal();
      o.collectorSettled();
      expect(m.accounting.usedUnits).toBe(units);
      release.resolve();
      const out = await deadline(settled);
      expect(out.ok).toBe(false);
      if (out.ok) throw new Error("closed native request returned a result");
      expect(out.error).toBeInstanceOf(ResponseAllocationUnavailable);
    } catch (error) {
      bodyError = error;
    } finally {
      release.resolve();
      terminal(o);
      try {
        await deadline(settled);
      } catch (error) {
        cleanupError = error;
      }
    }
    if (bodyError && cleanupError)
      throw new AggregateError([bodyError, cleanupError], "body and cleanup failed");
    if (bodyError) throw bodyError;
    if (cleanupError) throw cleanupError;
    expect(m.accounting.usedUnits).toBe(0);
  });
});
