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
  CERTIFICATE_TOOL_PREFLIGHT_SQL,
  CERTIFICATE_TOOL_CONTENT_SQL,
  certificateToolProjectionCost,
  certificateToolProjectionPlan,
  loadAdmittedCertificateToolProjection,
  type CertificateToolProjectionMetadata
} from "../../artifacts/server/src/certificate-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_CERTIFICATE_TOOL_SQL } from "../helpers/certificate-tool-original-sql.js";

// Only the transaction port and authority collaborators are synthetic. The public
// executeRead input/registry path and exact get_vote_certificate branch run.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected certificate tool fixture pool");
        return callback(client);
      }
    )
  };
});
const id = (n: number) => `01993400-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (v: string | Buffer) => createHash("sha256").update(v).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/certificate-tool-${name}.txt`));
interface View {
  certificate_id: string;
  vote_id: string;
  outcome_id: string;
  public_id: string;
  schema_version: string;
  canonical_payload: JsonValue;
  payload_sha256: string;
  signature_base64url: string;
  signing_key_id: string;
  state: string;
  supersedes_id: string | null;
  issued_at: string;
}
const graph = () => JSON.parse(bytes("view").toString("utf8")) as View;
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
  -readonly [K in keyof CertificateToolProjectionMetadata]: CertificateToolProjectionMetadata[K];
};
function measure(
  q: View,
  raw: Buffer = Buffer.from(JSON.stringify(q.canonical_payload))
): Metadata {
  // Independently enumerate all eleven original flat values. JSON.stringify is
  // the unit graph oracle, not evidence of PostgreSQL JSONB numeric/space spelling.
  const flat = [
    q.certificate_id,
    q.vote_id,
    q.outcome_id,
    q.public_id,
    q.schema_version,
    q.payload_sha256,
    q.signature_base64url,
    q.signing_key_id,
    q.state,
    q.supersedes_id,
    q.issued_at
  ];
  const measuredShape = shape(q.canonical_payload);
  return {
    id: q.certificate_id,
    board_id: id(5),
    vote_id: q.vote_id,
    observation_sha256: digest(JSON.stringify([id(5), ...flat]) + raw.toString("base64")),
    raw_payload_bytes: String(raw.length),
    scalar_utf8: String(
      flat.reduce<number>((sum, item) => sum + (item === null ? 0 : Buffer.byteLength(item)), 0)
    ),
    json_utf8: String(Buffer.byteLength(JSON.stringify(q.canonical_payload))),
    json_properties: String(measuredShape.properties),
    json_containers: String(measuredShape.containers)
  };
}
function fixture(q = graph()) {
  const metadata = measure(q);
  const state = {
    missing: false,
    hidden: false,
    fits: true,
    constructions: 0,
    preflightRows: undefined as unknown[] | undefined,
    contentRows: undefined as unknown[] | undefined,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined
  };
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === CERTIFICATE_TOOL_PREFLIGHT_SQL) {
      const rows = state.preflightRows ?? (state.missing ? [] : [{ ...metadata }]);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === CERTIFICATE_TOOL_CONTENT_SQL) {
      await state.beforeContent?.();
      if (state.contentRows) return { rows: state.contentRows };
      if (state.hidden) return { rows: [] };
      if (state.fits) state.constructions += 1;
      return {
        rows: [
          {
            id: metadata.id,
            board_id: metadata.board_id,
            vote_id: metadata.vote_id,
            observation_sha256: metadata.observation_sha256,
            fits: state.fits,
            view: state.fits ? q : null
          }
        ]
      };
    }
    if (sql === ORIGINAL_CERTIFICATE_TOOL_SQL) {
      // A real old-call construction is accepted so the baseline failure is
      // admission absence, not an unrecognized query, schema or import error.
      state.constructions += 1;
      const selected =
        values?.[0] === q.vote_id &&
        (values?.[1] === q.certificate_id || (values?.[1] === null && q.state === "current"));
      return { rows: state.missing || !selected ? [] : [{ board_id: id(5), view: q }] };
    }
    throw new Error("unexpected certificate tool fixture query");
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
    protocolClientId: "certificate-tool-fixture",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture-key",
    scopes: ["governance:read"],
    roles: ["member"],
    boardIds: [id(5)]
  };
  const seam = repository as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    dispatch(
      client: PoolClient,
      principal: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readVote(
      client: PoolClient,
      principal: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, tool, input) => {
    if (tool !== "get_vote_certificate") throw new Error("out-of-scope fixture dispatch");
    return seam.readVote(connection, actor, tool, input);
  });
  return {
    q,
    metadata,
    state,
    query,
    client,
    authorize,
    liveActor,
    read: (selected: string | null = null) =>
      repository.executeRead(principal, "get_vote_certificate", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: q.vote_id,
        certificate_id: selected
      }),
    helper: (selected: string | null = null) =>
      loadAdmittedCertificateToolProjection(client, q.vote_id, selected)
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

describe("get_vote_certificate tool projection admission", () => {
  it("refuses the public caller before whole projection when all shared units are occupied", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture();
    const leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.liveActor).toHaveBeenCalledOnce();
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(
        f.query.mock.calls.filter(([sql]) => sql === CERTIFICATE_TOOL_PREFLIGHT_SQL)
      ).toHaveLength(1);
      expect(f.state.constructions).toBe(0);
      expect(f.query.mock.calls.some(([sql]) => sql === CERTIFICATE_TOOL_CONTENT_SQL)).toBe(false);
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("keeps the original current twelve-field view and complete public envelope bytes", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture();
    const result = await owned(manager, () => f.read());
    expect(Buffer.from(canonicalJson(result))).toEqual(bytes("current"));
    expect(f.authorize).toHaveBeenCalledOnce();
    expect(f.liveActor).toHaveBeenCalledOnce();
    expect(f.state.constructions).toBe(1);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("keeps explicit historical selection, stored schema/state, reference and URI", async () => {
    const q = graph();
    q.state = "superseded";
    const f = fixture(q);
    const result = await owned(new ResponseAllocationManager(), () => f.read(q.certificate_id));
    expect(Buffer.from(canonicalJson(result))).toEqual(bytes("historical"));
  });
  it("keeps the original absent envelope without requiring an owner", async () => {
    const f = fixture();
    f.state.missing = true;
    expect(Buffer.from(canonicalJson(await f.read()))).toEqual(bytes("absent"));
  });
  it("retains initial authorization before metadata or full projection", async () => {
    const f = fixture(),
      denial = new Error("synthetic authority denial");
    f.authorize.mockImplementation(() => {
      throw denial;
    });
    await expect(f.read()).rejects.toBe(denial);
    expect(f.query).not.toHaveBeenCalled();
  });
  it("requires native ownership for a visible projection", async () => {
    const f = fixture();
    await expect(f.helper()).rejects.toThrow("native response allocation owner is required");
    expect(f.state.constructions).toBe(0);
  });
  it("passes exact selected identity, private observation, raw length and every scalar bound", async () => {
    const f = fixture(),
      m = f.metadata;
    await owned(new ResponseAllocationManager(), () => f.helper());
    expect(f.query).toHaveBeenLastCalledWith(CERTIFICATE_TOOL_CONTENT_SQL, [
      m.vote_id,
      null,
      m.id,
      m.board_id,
      m.observation_sha256,
      m.raw_payload_bytes,
      m.scalar_utf8,
      m.json_utf8,
      m.json_properties,
      m.json_containers
    ]);
    expect(m.observation_sha256).not.toBe(f.q.payload_sha256);
  });
  it("refuses a changed visible selection but returns null for disappearance or recusal", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture();
    f.state.contentRows = [
      {
        id: f.metadata.id,
        board_id: f.metadata.board_id,
        vote_id: f.metadata.vote_id,
        observation_sha256: null,
        fits: false,
        view: null
      }
    ];
    await expect(owned(manager, () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
    f.state.contentRows = undefined;
    f.state.hidden = true;
    expect(await owned(manager, () => f.helper())).toBeNull();
  });
  it("rejects substituted or duplicated preflight identities before reservation", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.preflightRows = [{ ...f.metadata, id: id(11) }];
    await expect(owned(manager, () => f.helper(id(1)))).rejects.toBeInstanceOf(TypeError);
    f.state.preflightRows = [{ ...f.metadata, vote_id: id(12) }];
    await expect(owned(manager, () => f.helper())).rejects.toBeInstanceOf(TypeError);
    f.state.preflightRows = [f.metadata, f.metadata];
    await expect(owned(manager, () => f.helper())).rejects.toBeInstanceOf(TypeError);
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it.each(["id", "board_id", "vote_id", "observation_sha256"] as const)(
    "rejects returned %s substitution",
    async (key) => {
      const f = fixture();
      f.state.contentRows = [{ ...f.metadata, fits: true, view: f.q, [key]: "substituted" }];
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  );
  it("rejects malformed full-view identity and duplicate content rows", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.contentRows = [{ ...f.metadata, fits: true, view: { ...f.q, certificate_id: id(21) } }];
    await expect(owned(manager, () => f.helper())).rejects.toBeInstanceOf(TypeError);
    f.state.contentRows = [{ ...f.metadata, fits: true, view: [] }];
    await expect(owned(manager, () => f.helper())).rejects.toBeInstanceOf(TypeError);
    f.state.contentRows = [
      { ...f.metadata, fits: true, view: f.q },
      { ...f.metadata, fits: true, view: f.q }
    ];
    await expect(owned(manager, () => f.helper())).rejects.toBeInstanceOf(TypeError);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("binds private actual raw bytes independently of unchanged parsed JSON and signed hash", () => {
    const q = graph();
    q.canonical_payload = { a: 1 };
    const first = measure(q, Buffer.from('{"a":1}')),
      second = measure(q, Buffer.from('{ "a":1}'));
    expect(first.observation_sha256).not.toBe(second.observation_sha256);
    expect(first.json_utf8).toBe(second.json_utf8);
    expect(q.payload_sha256).toBe("a".repeat(64));
  });
  it("refuses known oversized projection before loading content", async () => {
    const f = fixture();
    f.metadata.json_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("prevents later content loading after disconnect during metadata", async () => {
    const manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal),
      f = fixture();
    f.state.afterMetadata = () => abort.abort();
    await expect(owner.produce(() => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    owner.nativeTerminal();
    owner.collectorSettled();
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains an early-disconnect lease while the content producer is alive", async () => {
    const manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal),
      f = fixture();
    let resume!: () => void, entered!: () => void;
    const ready = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      resume = resolve;
    });
    f.state.beforeContent = async () => {
      entered();
      await gate;
    };
    const pending = owner.produce(() => f.helper());
    const rejected = expect(pending).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    await ready;
    abort.abort();
    owner.nativeTerminal();
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(certificateToolProjectionPlan(f.metadata).units);
    resume();
    await rejected;
    expect(manager.accounting.usedUnits).toBe(0);
    owner.nativeTerminal();
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains completed production until both native delivery and collector settlement", async () => {
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal),
      f = fixture();
    await owner.produce(() => f.helper());
    expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    owner.nativeTerminal();
    expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("has an exact 1920-unit boundary, recomputes forged weights and leaves 100 small reads eligible", () => {
    const m = {
      ...measure(graph()),
      scalar_utf8: "1000",
      json_utf8: "251638085",
      json_properties: "1",
      json_containers: "1"
    };
    const plan = certificateToolProjectionPlan(m);
    expect(plan.units).toBe(1920);
    const manager = new ResponseAllocationManager(),
      large = manager.tryReserve(plan);
    const leases = Array.from({ length: 100 }, () => manager.tryReserve(small()));
    expect(manager.accounting.usedUnits).toBe(2020);
    for (const lease of leases) lease.release();
    large.release();
    const over = certificateToolProjectionPlan({ ...m, json_utf8: "251638086" });
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve({ ...over, units: 1 })).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects invalid representation, canonical bytes, storage lengths and malformed or overflowing scalars", () => {
    const m = measure(graph()),
      plan = certificateToolProjectionPlan(m);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    for (const raw of ["0", "1", "10485761"])
      expect(() => certificateToolProjectionPlan({ ...m, raw_payload_bytes: raw })).toThrow(
        TypeError
      );
    for (const value of ["-1", "01", "1.5", "1e3"])
      expect(() => certificateToolProjectionCost({ ...m, json_utf8: value })).toThrow(TypeError);
    expect(() => certificateToolProjectionCost({ ...m, json_utf8: "1".repeat(25) })).toThrow(
      ResponseAllocationUnavailable
    );
    expect(() =>
      certificateToolProjectionPlan({ ...m, json_utf8: "999999999999999999999999" })
    ).toThrow(ResponseAllocationUnavailable);
  });
  it("admits an actual 10 MiB ordinary raw JSON string with 100 small reads and bounds its full graph", () => {
    const q = graph();
    q.canonical_payload = "x".repeat(10485758);
    const raw = Buffer.from(JSON.stringify(q.canonical_payload));
    expect(raw.length).toBe(10485760);
    const metadata = measure(q, raw),
      cost = certificateToolProjectionCost(metadata),
      plan = certificateToolProjectionPlan(metadata);
    const envelope = JSON.parse(bytes("current").toString("utf8")) as {
      data: { certificate: View };
    };
    envelope.data.certificate = q;
    const actual = shape(envelope);
    expect(BigInt(cost.propertyCount)).toBeGreaterThanOrEqual(BigInt(actual.properties));
    expect(BigInt(cost.objectOrArrayCount)).toBeGreaterThanOrEqual(BigInt(actual.containers));
    expect(BigInt(cost.jsonUpperBytes) + 4096n).toBeGreaterThanOrEqual(
      BigInt(Buffer.byteLength(canonicalJson(envelope)))
    );
    const manager = new ResponseAllocationManager(),
      lease = manager.tryReserve(plan);
    const smalls = Array.from({ length: 100 }, () => manager.tryReserve(small()));
    expect(manager.accounting.usedUnits).toBe(plan.units + 100);
    for (const smallLease of smalls) smallLease.release();
    lease.release();
  });
  it("counts arbitrary payload containers and bounds independently serialized nested tool wire", () => {
    const q = graph();
    q.canonical_payload = {
      escaped: '"\\\n\u0001Δ🙂',
      many: Array.from({ length: 1000 }, () => ({ empty: [] }))
    };
    const metadata = measure(q),
      cost = certificateToolProjectionCost(metadata),
      plan = certificateToolProjectionPlan(metadata);
    const envelope = JSON.parse(bytes("current").toString("utf8")) as {
      data: { certificate: View };
    };
    envelope.data.certificate = q;
    const wire = {
      content: [{ type: "text", text: canonicalJson(envelope) }],
      structuredContent: envelope
    };
    const actualShape = shape(wire);
    expect(BigInt(cost.propertyCount)).toBeGreaterThanOrEqual(BigInt(actualShape.properties));
    expect(BigInt(cost.objectOrArrayCount)).toBeGreaterThanOrEqual(BigInt(actualShape.containers));
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
    const flat = certificateToolProjectionPlan({
      ...metadata,
      json_properties: "0",
      json_containers: "0"
    });
    expect(plan.units).toBeGreaterThan(flat.units);
  });
});
