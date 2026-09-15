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
  MINUTES_TOOL_PREFLIGHT_SQL,
  MINUTES_TOOL_CONTENT_SQL,
  minutesToolProjectionCost,
  minutesToolProjectionPlan,
  loadAdmittedMinutesToolProjection,
  type MinutesToolProjectionMetadata
} from "../../artifacts/server/src/minutes-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_MINUTES_TOOL_SQL } from "../helpers/minutes-tool-original-sql.js";

// Synthetic transaction/authority ports exercise the public executeRead registry
// and exact minutes branch. These models neither execute PostgreSQL nor prove
// RLS, canonical stored hashes, or legal mutations through immutable guards.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected minutes fixture pool");
        return callback(client);
      }
    )
  };
});
const id = (n: number) => `01993a00-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/minutes-tool-${name}.txt`));
type Flat = Record<string, JsonValue>;
interface Package extends Flat {
  required_signers: Flat[];
  signatures: Flat[];
}
interface View extends Flat {
  minutes_id: string;
  board_id: string;
  row_version: string;
  version: Flat | null;
  signature_package: Package | null;
  action_declaration: Flat | null;
}
const graph = (name = "view") => JSON.parse(bytes(name).toString("utf8")) as View;
type Metadata = {
  -readonly [K in keyof MinutesToolProjectionMetadata]: MinutesToolProjectionMetadata[K];
};
const rootKeys = [
  "minutes_id",
  "board_id",
  "meeting_id",
  "state",
  "row_version",
  "correction_of_minutes_id",
  "version",
  "signature_package",
  "action_declaration",
  "finalized_at",
  "cancelled_at"
];
const versionKeys = [
  "version_id",
  "version",
  "canonical_schema",
  "canonical_text",
  "sha256",
  "package_base_sha256",
  "transcript_version_id",
  "transcript_sha256",
  "supersedes_id",
  "created_at"
];
const packageKeys = [
  "package_id",
  "version",
  "minutes_version_id",
  "minutes_sha256",
  "package_sha256",
  "state",
  "required_signers",
  "signatures"
];
const requirementKeys = ["member_id", "seat_role", "requirement", "snapshot_sha256"];
const signatureKeys = [
  "signature_id",
  "signer_member_id",
  "signer_seat_role",
  "record_sha256",
  "signed_at"
];
const declarationKeys = [
  "declaration_id",
  "minutes_version_id",
  "declaration",
  "manifest_sha256",
  "declared_at"
];
const numericKeys = [
  "row_count",
  "version_count",
  "package_count",
  "declaration_count",
  "requirement_count",
  "signature_count",
  "scalar_utf8"
] as const;
function measure(views: readonly View[], pointers: readonly (string | null)[]): Metadata {
  let s = 0,
    v = 0,
    p = 0,
    d = 0,
    q = 0,
    t = 0;
  const flat = (values: readonly (JsonValue | undefined)[]) => {
    for (const value of values)
      if (value !== null && value !== undefined) s += Buffer.byteLength(String(value));
  };
  for (const view of views) {
    flat([
      view.minutes_id,
      view.board_id,
      view.meeting_id,
      view.state,
      view.row_version,
      view.correction_of_minutes_id,
      view.finalized_at,
      view.cancelled_at
    ]);
    if (view.version) {
      v++;
      flat(versionKeys.map((key) => view.version?.[key]));
    }
    if (view.signature_package) {
      p++;
      flat(
        packageKeys
          .filter((key) => key !== "required_signers" && key !== "signatures")
          .map((key) => view.signature_package?.[key])
      );
      for (const child of view.signature_package.required_signers)
        flat(requirementKeys.map((key) => child[key]));
      for (const child of view.signature_package.signatures)
        flat(signatureKeys.map((key) => child[key]));
      q += view.signature_package.required_signers.length;
      t += view.signature_package.signatures.length;
    }
    if (view.action_declaration) {
      d++;
      flat(declarationKeys.map((key) => view.action_declaration?.[key]));
    }
  }
  return {
    minutes_id: id(1),
    board_id: id(2),
    row_version: views[0]?.row_version ?? "1",
    row_count: String(views.length),
    version_count: String(v),
    package_count: String(p),
    declaration_count: String(d),
    requirement_count: String(q),
    signature_count: String(t),
    scalar_utf8: String(s),
    // Independent synthetic content/pointer binding, not the PostgreSQL tuple
    // hash oracle. Actual PG byte/order/digest behavior needs a separate case.
    observation_sha256: digest(JSON.stringify(views) + JSON.stringify(pointers))
  };
}
function shape(value: unknown) {
  const pending: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const node = pending.pop();
    if (node !== null && typeof node === "object") {
      containers++;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      for (const child of Object.values(node)) pending.push(child);
    }
  }
  return { properties, containers };
}
function fixture(view = graph()) {
  const state = {
    views: [view],
    pointers: [id(10), id(20)] as (string | null)[],
    missing: false,
    hidden: false,
    constructions: 0,
    contentStarted: false,
    preflightRows: undefined as unknown[] | undefined,
    contentRows: undefined as unknown[] | undefined,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined
  };
  const metadata = measure(state.views, state.pointers);
  const binding = (m: Metadata, fits = true) => ({
    minutes_id: m.minutes_id,
    board_id: m.board_id,
    row_version: m.row_version,
    observation_sha256: m.observation_sha256,
    fits
  });
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === MINUTES_TOOL_CONTENT_SQL || sql === ORIGINAL_MINUTES_TOOL_SQL) {
      state.contentStarted = true;
      await state.beforeContent?.();
    }
    if (sql === MINUTES_TOOL_PREFLIGHT_SQL) {
      const rows = state.preflightRows ?? (state.missing ? [] : [{ ...metadata }]);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === MINUTES_TOOL_CONTENT_SQL) {
      if (state.contentRows) return { rows: state.contentRows };
      if (state.hidden) return { rows: [] };
      const current = measure(state.views, state.pointers);
      const fits =
        values?.[0] === current.minutes_id &&
        values[1] === current.board_id &&
        values[2] === current.row_version &&
        values[3] === current.observation_sha256 &&
        numericKeys.slice(0, 6).every((key, index) => values[4 + index] === current[key]) &&
        BigInt(current.scalar_utf8) <= BigInt(String(values[10]));
      if (!fits) return { rows: [{ ...binding(current, false), view: null }] };
      state.constructions += state.views.length;
      return { rows: state.views.map((q) => ({ ...binding(current), view: q })) };
    }
    if (sql === ORIGINAL_MINUTES_TOOL_SQL) {
      if (values?.length !== 1 || values[0] !== id(1))
        throw new Error("incorrect original minutes parameters");
      if (state.missing) return { rows: [] };
      state.constructions += state.views.length;
      return { rows: state.views.map((q) => ({ view: q })) };
    }
    throw new Error("unexpected minutes fixture query");
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
    protocolClientId: "minutes-tool-fixture",
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
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, tool, input) => {
    if (tool !== "get_minutes") throw new Error("out-of-scope minutes fixture dispatch");
    return seam.readMinutes(connection, actor, tool, input);
  });
  return {
    state,
    metadata,
    binding,
    query,
    client,
    liveActor,
    authorize,
    read: () =>
      repository.executeRead(principal, "get_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: id(1)
      }),
    helper: () => loadAdmittedMinutesToolProjection(client, id(1))
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
  minutes_id: id(1),
  board_id: id(2),
  row_version: "1",
  observation_sha256: "a".repeat(64),
  row_count: "1",
  version_count: "0",
  package_count: "0",
  declaration_count: "0",
  requirement_count: "0",
  signature_count: "0",
  scalar_utf8: "0"
});
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

describe("get_minutes tool projection admission", () => {
  it("refuses the public caller before whole construction when shared capacity is occupied", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture();
    const leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.liveActor).toHaveBeenCalledOnce();
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(f.query.mock.calls.filter(([sql]) => sql === MINUTES_TOOL_PREFLIGHT_SQL)).toHaveLength(
        1
      );
      expect(f.state.contentStarted).toBe(false);
      expect(f.state.constructions).toBe(0);
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves full original 11/10/8/4/5/5 fields and literal public bytes", async () => {
    const f = fixture(),
      v = f.state.views[0]!;
    expect(Object.keys(v).sort()).toEqual([...rootKeys].sort());
    expect(Object.keys(v.version!).sort()).toEqual([...versionKeys].sort());
    expect(Object.keys(v.signature_package!).sort()).toEqual([...packageKeys].sort());
    for (const q of v.signature_package!.required_signers)
      expect(Object.keys(q).sort()).toEqual([...requirementKeys].sort());
    for (const t of v.signature_package!.signatures)
      expect(Object.keys(t).sort()).toEqual([...signatureKeys].sort());
    expect(Object.keys(v.action_declaration!).sort()).toEqual([...declarationKeys].sort());
    expect(v.row_version).toBe("9007199254740993");
    expect(v.signature_package!.minutes_version_id).not.toBe(v.version!.version_id);
    const result = await owned(new ResponseAllocationManager(), () => f.read());
    expect(Buffer.from(canonicalJson(result))).toEqual(bytes("complete"));
    expect(f.state.constructions).toBe(1);
  });
  it.each([
    ["null-view", "null-children"],
    ["package-only-view", "package-only"],
    ["version-only-view", "version-only"]
  ])("preserves independently visible children and URI in %s", async (viewName, resultName) => {
    const f = fixture(graph(viewName));
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes(resultName));
  });
  it("does not infer visible signature membership from visible requirements", async () => {
    const view = graph();
    view.signature_package!.required_signers = [];
    const f = fixture(view);
    expect(f.metadata.requirement_count).toBe("0");
    expect(f.metadata.signature_count).toBe("2");
    const result = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(result[0]?.view).toEqual(view);
    expect(() => minutesToolProjectionCost(f.metadata)).not.toThrow();
  });
  it("preserves empty package arrays and nullable version fields", async () => {
    const v = graph();
    v.signature_package!.required_signers = [];
    v.signature_package!.signatures = [];
    v.version!.transcript_version_id = null;
    v.version!.transcript_sha256 = null;
    v.version!.supersedes_id = null;
    v.correction_of_minutes_id = null;
    v.action_declaration = null;
    const f = fixture(v);
    expect((await owned(new ResponseAllocationManager(), () => f.helper()))[0]?.view).toEqual(v);
  });
  it("returns the literal absent envelope without an owner", async () => {
    const f = fixture();
    f.state.missing = true;
    expect(Buffer.from(canonicalJson(await f.read()))).toEqual(bytes("absent"));
    expect(f.state.constructions).toBe(0);
  });
  it.each(["actor", "authority"])("retains %s denial before metadata or content", async (kind) => {
    const f = fixture(),
      error = new Error("synthetic authority denial");
    if (kind === "actor") f.liveActor.mockRejectedValue(error);
    else
      f.authorize.mockImplementation(() => {
        throw error;
      });
    await expect(f.read()).rejects.toBe(error);
    expect(f.query).not.toHaveBeenCalled();
  });
  it("requires a native response owner for the visible public caller", async () => {
    const f = fixture();
    await expect(f.read()).rejects.toThrow("native response allocation owner is required");
    expect(f.state.constructions).toBe(0);
  });
  it("binds exact bigint version, private observation, counts and scalar cost", async () => {
    const f = fixture(),
      m = f.metadata;
    await owned(new ResponseAllocationManager(), () => f.helper());
    expect(f.query).toHaveBeenLastCalledWith(MINUTES_TOOL_CONTENT_SQL, [
      id(1),
      id(2),
      m.row_version,
      m.observation_sha256,
      m.row_count,
      m.version_count,
      m.package_count,
      m.declaration_count,
      m.requirement_count,
      m.signature_count,
      m.scalar_utf8
    ]);
    expect(m.observation_sha256).not.toBe(f.state.views[0]!.version!.sha256);
    expect(minutesToolProjectionPlan(m).sourceVersion).toBe("9007199254740993");
  });
  it("budgets all modeled rows and preserves the original public row zero selection", async () => {
    const second = graph();
    second.version!.canonical_text = "second modeled row";
    const f = fixture();
    f.state.views.push(second);
    Object.assign(f.metadata, measure(f.state.views, f.state.pointers));
    const all = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(all.map((row) => row.view)).toEqual(f.state.views);
    expect(f.metadata).toMatchObject({
      row_count: "2",
      version_count: "2",
      package_count: "2",
      declaration_count: "2",
      requirement_count: "4",
      signature_count: "4"
    });
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes("complete"));
    // This synthetic plural input checks code policy, not a claim that current PKs permit it.
  });
  it.each([
    "requirement growth",
    "signature growth",
    "declaration appearance",
    "same-cost text",
    "same-cost requirement hash",
    "same-cost signature hash",
    "same-cost declaration microseconds",
    "signature order",
    "requirement order",
    "hidden current pointer"
  ])("rejects fresh modeled %s without whole construction", async (change) => {
    const v = graph();
    if (change === "declaration appearance") v.action_declaration = null;
    if (change === "hidden current pointer") {
      v.version = null;
      v.action_declaration = null;
    }
    const f = fixture(v);
    f.state.afterMetadata = () => {
      const current = f.state.views[0]!;
      if (change === "requirement growth")
        current.signature_package!.required_signers.push({
          ...current.signature_package!.required_signers[0]!,
          member_id: id(32)
        });
      if (change === "signature growth")
        current.signature_package!.signatures.push({
          ...current.signature_package!.signatures[0]!,
          signature_id: id(42),
          signer_member_id: id(32)
        });
      if (change === "declaration appearance")
        current.action_declaration = graph().action_declaration;
      if (change === "same-cost text")
        current.version!.canonical_text = String(current.version!.canonical_text).replace(
          "Approve",
          "Decline"
        );
      if (change === "same-cost requirement hash")
        current.signature_package!.required_signers[0]!.snapshot_sha256 = "8".repeat(64);
      if (change === "same-cost signature hash")
        current.signature_package!.signatures[0]!.record_sha256 = "9".repeat(64);
      if (change === "same-cost declaration microseconds")
        current.action_declaration!.declared_at = "2026-09-12T10:02:00.000008Z";
      if (change === "signature order") current.signature_package!.signatures.reverse();
      if (change === "requirement order") current.signature_package!.required_signers.reverse();
      if (change === "hidden current pointer") f.state.pointers[0] = id(14);
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    const fresh = measure(f.state.views, f.state.pointers);
    expect(fresh.row_version).toBe(f.metadata.row_version);
    expect(fresh.observation_sha256).not.toBe(f.metadata.observation_sha256);
    if (
      change.startsWith("same-cost") ||
      change.endsWith("order") ||
      change === "hidden current pointer"
    )
      expect(numericKeys.map((key) => fresh[key])).toEqual(
        numericKeys.map((key) => f.metadata[key])
      );
    expect(f.state.constructions).toBe(0);
  });
  it("returns no rows after modeled fresh root invisibility", async () => {
    const f = fixture();
    f.state.afterMetadata = () => {
      f.state.hidden = true;
    };
    expect(await owned(new ResponseAllocationManager(), () => f.helper())).toEqual([]);
    expect(f.state.constructions).toBe(0);
  });
  it("rejects malformed preflight identities and cardinality", async () => {
    for (const mutate of [
      (m: Metadata) => {
        m.minutes_id = id(70);
      },
      (m: Metadata) => {
        m.board_id = "";
      },
      (m: Metadata) => {
        m.row_version = "0";
      }
    ]) {
      const f = fixture();
      mutate(f.metadata);
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
      expect(f.state.contentStarted).toBe(false);
    }
    const f = fixture();
    f.state.preflightRows = [f.metadata, f.metadata];
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      TypeError
    );
  });
  it("rejects malformed fresh headers, payload identities and row counts", async () => {
    for (const key of [
      "minutes_id",
      "board_id",
      "row_version",
      "observation_sha256",
      "fits",
      "view"
    ]) {
      const f = fixture(),
        row: Record<string, unknown> = { ...f.binding(f.metadata), view: graph() };
      row[key] = key === "view" ? null : "invalid";
      f.state.contentRows = [row];
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
    for (const key of ["minutes_id", "board_id", "row_version"]) {
      const f = fixture(),
        view = graph();
      view[key] = "invalid";
      f.state.contentRows = [{ ...f.binding(f.metadata), view }];
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
    const f = fixture(),
      row = { ...f.binding(f.metadata), view: graph() };
    f.state.contentRows = [row, row];
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      TypeError
    );
  });
  it("refuses oversized scalar metadata before querying content", async () => {
    const f = fixture();
    f.metadata.scalar_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.contentStarted).toBe(false);
    expect(f.state.constructions).toBe(0);
  });
  it("prevents public content after disconnect during metadata", async () => {
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
  it("holds disconnected public production until the actual pending query settles", async () => {
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
    let settled = false;
    const outcome = pending
      .then(
        (value) => ({ value, error: undefined }),
        (error: unknown) => ({ value: undefined, error })
      )
      .finally(() => {
        settled = true;
      });
    try {
      // Both the legacy query and admitted query enter the same bounded gate.
      await vi.waitFor(() => expect(f.state.contentStarted).toBe(true), { timeout: 1000 });
      abort.abort();
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(minutesToolProjectionPlan(f.metadata).units);
    } finally {
      resume();
      owner.nativeTerminal();
      owner.collectorSettled();
      await vi.waitFor(() => expect(settled).toBe(true), { timeout: 1000 });
    }
    expect((await outcome).error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains successful public production until terminal and collector settlement", async () => {
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal),
      f = fixture();
    try {
      await owner.produce(() => f.read());
      expect(manager.accounting.usedUnits).toBe(minutesToolProjectionPlan(f.metadata).units);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("uses independent fixed/repeated-row arithmetic and a one-unit scalar boundary", () => {
    expect(minutesToolProjectionCost(zero())).toEqual({
      jsonUpperBytes: "223",
      propertyCount: "34",
      objectOrArrayCount: "6"
    });
    expect(minutesToolProjectionPlan(zero())).toMatchObject({ units: 1, wireUpperBytes: 78493 });
    const full = { ...zero(), version_count: "1", package_count: "1", declaration_count: "1" };
    expect(minutesToolProjectionCost(full)).toEqual({
      jsonUpperBytes: "706",
      propertyCount: "57",
      objectOrArrayCount: "11"
    });
    expect(
      minutesToolProjectionCost({ ...full, requirement_count: "1", signature_count: "1" })
    ).toEqual({ jsonUpperBytes: "892", propertyCount: "66", objectOrArrayCount: "13" });
    expect(minutesToolProjectionCost({ ...zero(), row_count: "2" })).toEqual({
      jsonUpperBytes: "4542",
      propertyCount: "68",
      objectOrArrayCount: "12"
    });
    expect(minutesToolProjectionPlan({ ...zero(), scalar_utf8: "19514" }).units).toBe(1);
    expect(minutesToolProjectionPlan({ ...zero(), scalar_utf8: "19515" }).units).toBe(2);
  });
  it("validates tool-only zero-canonical plans, counts and bigint version bounds", () => {
    const plan = minutesToolProjectionPlan(zero());
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    for (const value of ["-1", "01", "1.5", "1e3"])
      expect(() => minutesToolProjectionCost({ ...zero(), scalar_utf8: value })).toThrow(TypeError);
    for (const override of [
      { row_count: "0" },
      { version_count: "2" },
      { package_count: "2" },
      { declaration_count: "1" },
      { requirement_count: "1" },
      { signature_count: "1" }
    ])
      expect(() => minutesToolProjectionCost({ ...zero(), ...override })).toThrow(TypeError);
    expect(() => minutesToolProjectionPlan({ ...zero(), scalar_utf8: "1".repeat(25) })).toThrow(
      ResponseAllocationUnavailable
    );
    expect(() =>
      minutesToolProjectionPlan({ ...zero(), scalar_utf8: "999999999999999999999999" })
    ).toThrow(ResponseAllocationUnavailable);
    for (const row_version of ["0", "9223372036854775808"])
      expect(() => minutesToolProjectionPlan({ ...zero(), row_version })).toThrow(TypeError);
    expect(
      minutesToolProjectionPlan({ ...zero(), row_version: "9223372036854775807" }).sourceVersion
    ).toBe("9223372036854775807");
    expect(() => minutesToolProjectionPlan({ ...zero(), observation_sha256: "bad" })).toThrow(
      TypeError
    );
  });
  it("retains the 1920-unit boundary and 100 plus one small-read eligibility", () => {
    const manager = new ResponseAllocationManager(),
      boundary = { ...zero(), scalar_utf8: "41940709" };
    const plan = minutesToolProjectionPlan(boundary);
    expect(plan.units).toBe(1920);
    const lease = manager.tryReserve(plan),
      smalls = Array.from({ length: 101 }, () => manager.tryReserve(small()));
    try {
      expect(manager.accounting.usedUnits).toBe(2021);
    } finally {
      for (const s of smalls) s.release();
      lease.release();
    }
    const over = minutesToolProjectionPlan({ ...boundary, scalar_utf8: "41940710" });
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve({ ...over, units: 1 })).toThrow(ResponseAllocationUnavailable);
  });
  it("bounds independent escaped Unicode bytes and the complete native tool graph", () => {
    const v = graph();
    v.version!.canonical_text = '"\\\n\u0001Δ🙂'.repeat(80);
    const metadata = measure([v], [id(10), id(20)]),
      cost = minutesToolProjectionCost(metadata),
      plan = minutesToolProjectionPlan(metadata);
    const envelope = JSON.parse(bytes("complete").toString("utf8")) as { data: { minutes: View } };
    envelope.data.minutes = v;
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
    expect(shape(clone(v))).toEqual(shape(v));
  });
});
