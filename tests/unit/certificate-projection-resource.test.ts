import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
  canonicalJson,
  canonicalSha256,
  type JsonValue
} from "../../lib/contracts/src/canonical.js";
import {
  issueVoteCertificate,
  verifyOfflineCertificateBundle,
  type OfflineCertificateBundle
} from "../../lib/audit/src/index.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  loadAdmittedCertificateProjection,
  CERTIFICATE_PROJECTION_PREFLIGHT_SQL,
  CERTIFICATE_PROJECTION_CONTENT_SQL,
  certificateProjectionCost,
  certificateProjectionPlan,
  type CertificateProjectionMetadata
} from "../../artifacts/server/src/certificate-projection-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { voteCertificatePayload } from "../helpers/certificate-fixture.js";
import { ORIGINAL_CERTIFICATE_RESOURCE_SQL } from "../helpers/certificate-resource-original-sql.js";

const id = (n: number) => `01993400-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
interface Bundle {
  schema_version: string;
  certificate_id: string;
  vote_id: string;
  outcome_id: string;
  public_id: string;
  canonical_payload: JsonValue;
  payload_sha256: string;
  signature_base64url: string;
  signing_key: { id: string; kid: string; algorithm: string; public_jwk: JsonValue };
  issued_at: string;
}
const frozenBytes = readFileSync(
  path.resolve(import.meta.dirname, "../fixtures/certificate-resource-original.txt")
);
const graph = () => JSON.parse(frozenBytes.toString("utf8")) as Bundle;
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
type Metadata = {
  -readonly [K in keyof CertificateProjectionMetadata]: CertificateProjectionMetadata[K];
};
function measure(
  q: Bundle,
  raw: Buffer = Buffer.from(JSON.stringify(q.canonical_payload))
): Metadata {
  // Independent enumeration of the original eight + three flat values. Unit
  // JSON text uses JS spelling; actual PG JSONB spelling needs separate PG proof.
  const flat = [
    q.schema_version,
    q.certificate_id,
    q.vote_id,
    q.outcome_id,
    q.public_id,
    q.payload_sha256,
    q.signature_base64url,
    q.issued_at,
    q.signing_key.id,
    q.signing_key.kid,
    q.signing_key.algorithm
  ];
  const jsons = [q.canonical_payload, q.signing_key.public_jwk];
  const shapes = jsons.map(shape);
  return {
    id: q.certificate_id,
    board_id: id(5),
    vote_id: q.vote_id,
    signing_key_id: q.signing_key.id,
    // Synthetic observation includes actual raw bytes and independent key JSON,
    // not an asserted equality with the stored public payload commitment.
    observation_sha256: digest(
      JSON.stringify(flat) + raw.toString("base64") + JSON.stringify(q.signing_key.public_jwk)
    ),
    raw_payload_bytes: String(raw.length),
    scalar_utf8: String(flat.reduce((n, v) => n + Buffer.byteLength(v), 0)),
    json_utf8: String(jsons.reduce<number>((n, v) => n + Buffer.byteLength(JSON.stringify(v)), 0)),
    json_properties: String(shapes.reduce((n, v) => n + v.properties, 0)),
    json_containers: String(shapes.reduce((n, v) => n + v.containers, 0))
  };
}
function fixture(q = graph(), raw?: Buffer) {
  const metadata = measure(q, raw);
  const state = {
    missing: false,
    hidden: false,
    fits: true,
    payload: q,
    constructions: 0,
    returnedKey: metadata.signing_key_id,
    returnedObservation: metadata.observation_sha256,
    afterMetadata: undefined as undefined | (() => void),
    beforeContent: undefined as undefined | (() => Promise<void>)
  };
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === CERTIFICATE_PROJECTION_PREFLIGHT_SQL) {
      state.afterMetadata?.();
      return {
        rows:
          state.missing ||
          values?.[0] !== metadata.board_id ||
          values?.[1] !== metadata.vote_id ||
          values?.[2] !== metadata.id
            ? []
            : [{ ...metadata }]
      };
    }
    if (sql === CERTIFICATE_PROJECTION_CONTENT_SQL) {
      await state.beforeContent?.();
      if (state.hidden) return { rows: [] };
      if (state.fits) state.constructions += 1;
      return {
        rows: [
          {
            id: metadata.id,
            signing_key_id: state.returnedKey,
            observation_sha256: state.returnedObservation,
            fits: state.fits,
            payload: state.fits ? state.payload : null
          }
        ]
      };
    }
    // Exact old SQL is supported: the baseline failure must be full response
    // construction under saturation, not an unknown query or missing import.
    if (sql === ORIGINAL_CERTIFICATE_RESOURCE_SQL) {
      state.constructions += 1;
      return { rows: state.missing ? [] : [{ id: q.certificate_id, payload: q }] };
    }
    throw new Error("unexpected certificate fixture query");
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
        new URL(`board://${metadata.board_id}/votes/${q.vote_id}/certificates/${q.certificate_id}`)
      ),
    helper: () =>
      loadAdmittedCertificateProjection(client, metadata.board_id, q.vote_id, q.certificate_id)
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
function signed() {
  const trusted = generateKeyPairSync("ed25519"),
    attacker = generateKeyPairSync("ed25519");
  const payload = voteCertificatePayload(),
    certificate = issueVoteCertificate(payload, trusted.privateKey);
  const signingKey = {
    id: payload.signingKeyId,
    kid: payload.keyId,
    algorithm: "EdDSA" as const,
    public_jwk: trusted.publicKey.export({ format: "jwk" }) as JsonValue
  };
  const bundle = {
    schema_version: "boardagent.vote-certificate-bundle.v1" as const,
    certificate_id: payload.certificateId,
    vote_id: payload.vote.id,
    outcome_id: payload.outcomeId,
    public_id: payload.publicId,
    canonical_payload: certificate.payload,
    payload_sha256: certificate.payloadSha256,
    signature_base64url: certificate.signatureBase64Url,
    signing_key: signingKey,
    issued_at: "2026-09-01T12:00:00.000000Z"
  };
  const trust = {
    schema_version: "boardagent.trusted-evidence-keys.v1" as const,
    keys: [signingKey]
  };
  return { trusted, attacker, payload, bundle, trust };
}
function resourceBundle(value: ReturnType<typeof signed>["bundle"]): Bundle {
  // Same JSON representation that the original pg JSONB parser exposes.
  return JSON.parse(JSON.stringify(value)) as Bundle;
}
async function admittedSigned(base: ReturnType<typeof signed>) {
  const f = fixture(resourceBundle(base.bundle)),
    manager = new ResponseAllocationManager();
  const result = await owned(manager, f.read);
  expect(result).not.toBeNull();
  expect(result!.bytes).toEqual(Buffer.from(canonicalJson(base.bundle)));
  expect(manager.accounting.usedUnits).toBe(0);
  return JSON.parse(result!.bytes.toString("utf8")) as OfflineCertificateBundle;
}

describe("certificate resource measured projection admission", () => {
  it("refuses the saturated old resource caller before full content construction", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      held = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
      expect(
        f.query.mock.calls.filter(([sql]) => sql === CERTIFICATE_PROJECTION_PREFLIGHT_SQL)
      ).toHaveLength(1);
      expect(f.query.mock.calls.some(([sql]) => sql === CERTIFICATE_PROJECTION_CONTENT_SQL)).toBe(
        false
      );
    } finally {
      for (const lease of held) lease.release();
    }
  });
  it("preserves frozen original ten/four-field bytes and authorization", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      result = await owned(manager, f.read);
    expect(result?.bytes).toEqual(frozenBytes);
    expect(result?.objectVersion).toBe(1n);
    expect(Object.keys(f.q)).toHaveLength(10);
    expect(Object.keys(f.q.signing_key)).toHaveLength(4);
    expect(f.authorize).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      "get_vote_certificate",
      {}
    );
    expect(f.state.constructions).toBe(1);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("returns missing roots without requiring an owner or loading payload", async () => {
    const f = fixture();
    f.state.missing = true;
    expect(await f.helper()).toBeNull();
    expect(f.query).toHaveBeenCalledTimes(1);
    expect(f.state.constructions).toBe(0);
  });
  it("requires an explicit native owner before visible content", async () => {
    const f = fixture();
    await expect(f.helper()).rejects.toThrow("native response allocation owner is required");
    expect(f.query.mock.calls.some(([sql]) => sql === CERTIFICATE_PROJECTION_CONTENT_SQL)).toBe(
      false
    );
  });
  it("binds board, vote, certificate, signing key, private observation, raw length and every fresh cost", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    expect(
      await owned(manager, () =>
        loadAdmittedCertificateProjection(f.client, id(90), f.q.vote_id, f.q.certificate_id)
      )
    ).toBeNull();
    await owned(manager, f.helper);
    expect(
      f.query.mock.calls.find(([sql]) => sql === CERTIFICATE_PROJECTION_CONTENT_SQL)?.[1]
    ).toEqual([
      f.metadata.board_id,
      f.metadata.vote_id,
      f.metadata.id,
      f.metadata.signing_key_id,
      f.metadata.observation_sha256,
      f.metadata.raw_payload_bytes,
      f.metadata.scalar_utf8,
      f.metadata.json_utf8,
      f.metadata.json_properties,
      f.metadata.json_containers
    ]);
  });
  it("keeps private raw/key observations distinct from stored signed payload commitments", () => {
    const q = graph(),
      raw = Buffer.from(JSON.stringify(q.canonical_payload));
    const a = measure(q, raw),
      whitespace = measure(q, Buffer.concat([Buffer.from(" "), raw]));
    const otherKey = measure(
      {
        ...q,
        signing_key: {
          ...q.signing_key,
          public_jwk: { changed: "same schema-independent stored key" }
        }
      },
      raw
    );
    expect(a.observation_sha256).not.toBe(q.payload_sha256);
    expect(certificateProjectionPlan(a).sha256).not.toBe(
      certificateProjectionPlan(whitespace).sha256
    );
    expect(certificateProjectionPlan(a).sha256).not.toBe(
      certificateProjectionPlan(otherKey).sha256
    );
    expect(q.payload_sha256).toBe("a".repeat(64));
  });
  it("refuses changed observations or wider content and distinguishes hidden roots", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.fits = false;
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
      expect(manager.accounting.usedUnits).toBe(certificateProjectionPlan(f.metadata).units);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    f.state.hidden = true;
    expect(await owned(manager, f.helper)).toBeNull();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects returned private identity corruption even when fits is asserted", async () => {
    for (const field of ["returnedKey", "returnedObservation"] as const) {
      const f = fixture();
      f.state[field] = field === "returnedKey" ? id(90) : "f".repeat(64);
      await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(
        "certificate projection identity is invalid"
      );
    }
  });
  it("rejects a substituted certificate, vote or signing key inside the projected payload", async () => {
    for (const which of ["certificate", "vote", "key"]) {
      const f = fixture();
      if (which === "certificate") f.state.payload = { ...f.q, certificate_id: id(90) };
      if (which === "vote") f.state.payload = { ...f.q, vote_id: id(90) };
      if (which === "key")
        f.state.payload = { ...f.q, signing_key: { ...f.q.signing_key, id: id(90) } };
      await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(
        "certificate projection payload identity is invalid"
      );
    }
  });
  it("refuses known oversized metadata before content", async () => {
    const f = fixture();
    f.metadata.json_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.query.mock.calls.some(([sql]) => sql === CERTIFICATE_PROJECTION_CONTENT_SQL)).toBe(
      false
    );
  });
  it("does not begin loading after a metadata-time disconnect", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    const owner = manager.openRequest(abort.signal);
    f.state.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query.mock.calls.some(([sql]) => sql === CERTIFICATE_PROJECTION_CONTENT_SQL)).toBe(
        false
      );
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("retains its lease while the producer is pending after early terminal and collector signals", async () => {
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
    expect(manager.accounting.usedUnits).toBe(certificateProjectionPlan(f.metadata).units);
    release();
    await expect(pending).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("enforces exact storage bounds without inventing a JWK byte ceiling", () => {
    const metadata = measure(graph());
    for (const n of ["1", "10485761"]) {
      metadata.raw_payload_bytes = n;
      expect(() => certificateProjectionPlan(metadata)).toThrow("storage length");
    }
    metadata.raw_payload_bytes = "2";
    metadata.json_utf8 = "251637868";
    metadata.scalar_utf8 = "1000";
    metadata.json_properties = "1";
    metadata.json_containers = "2";
    const manager = new ResponseAllocationManager(),
      large = manager.tryReserve(certificateProjectionPlan(metadata));
    expect(certificateProjectionPlan(metadata).units).toBe(1920);
    const held = Array.from({ length: 100 }, () =>
      manager.tryReserve(certificateProjectionPlan(measure(graph())))
    );
    expect(manager.accounting).toEqual({ usedUnits: 2020, largeUsedUnits: 1920 });
    for (const lease of held) lease.release();
    large.release();
    metadata.json_utf8 = "251637869";
    const over = certificateProjectionPlan(metadata);
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve({ ...over, units: 1 })).toThrow(ResponseAllocationUnavailable);
  });
  it("keeps one supported ten-MiB raw storage value eligible with ordinary graph metadata", () => {
    const raw = Buffer.from(JSON.stringify("a".repeat(10485758))),
      q = { ...graph(), canonical_payload: JSON.parse(raw.toString()) as JsonValue };
    expect(raw.length).toBe(10485760);
    const metadata = measure(q, raw),
      plan = certificateProjectionPlan(metadata);
    const manager = new ResponseAllocationManager(),
      lease = manager.tryReserve(plan);
    expect(plan.units).toBeLessThanOrEqual(1920);
    expect(plan.canonicalBytes).toBe(0);
    const actual = shape(q),
      cost = certificateProjectionCost(metadata);
    expect(Buffer.byteLength(JSON.stringify(q))).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
    expect(actual.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
    expect(actual.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
    lease.release();
  });
  it("counts both arbitrary payload and JWK containers and escaped UTF8 wire bytes", () => {
    const atom = 'Δ🙂\n\r\t\b\f"\\\u0001';
    for (let n = 0; n < 16; n += 1) {
      const value = { nested: Array.from({ length: 1000 + n }, () => [{}, [], { [atom]: atom }]) };
      const q = {
        ...graph(),
        canonical_payload: value,
        signing_key: { ...graph().signing_key, public_jwk: { [atom]: value } }
      };
      const metadata = measure(q),
        cost = certificateProjectionCost(metadata),
        actual = shape(q),
        serialized = JSON.stringify(q);
      expect(Buffer.byteLength(serialized)).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
      expect(actual.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
      expect(actual.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
      const wire = JSON.stringify({
        contents: [
          {
            uri: `board://${id(5)}/votes/${q.vote_id}/certificates/${q.certificate_id}`,
            mimeType: "application/json",
            text: serialized
          }
        ]
      });
      expect(Buffer.byteLength(wire)).toBeLessThanOrEqual(
        certificateProjectionPlan(metadata).wireUpperBytes
      );
      expect(certificateProjectionPlan(metadata).units).toBeGreaterThan(
        certificateProjectionPlan({ ...metadata, json_properties: "0", json_containers: "0" }).units
      );
    }
  });
  it("preserves JSON-null payload/key semantics and rejects malformed private costs", async () => {
    const q = {
        ...graph(),
        canonical_payload: null,
        signing_key: { ...graph().signing_key, public_jwk: null }
      },
      f = fixture(q, Buffer.from("null"));
    expect((await owned(new ResponseAllocationManager(), f.helper))?.payload).toEqual(q);
    const plan = certificateProjectionPlan(f.metadata);
    expect(() => responseAllocationPlan({ ...plan, representation: "tool" })).toThrow(
      "requires resource representation"
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 2 })).toThrow(
      "requires resource representation"
    );
    for (const invalid of ["-1", "01", "1.0", "1e2"]) {
      f.metadata.json_utf8 = invalid;
      expect(() => certificateProjectionPlan(f.metadata)).toThrow(TypeError);
    }
    f.metadata.json_utf8 = "9".repeat(25);
    expect(() => certificateProjectionPlan(f.metadata)).toThrow(ResponseAllocationUnavailable);
    f.metadata.json_utf8 = "0";
    f.metadata.observation_sha256 = "f";
    expect(() => certificateProjectionPlan(f.metadata)).toThrow("observation hash");
  });
  it("preserves a genuinely signed bundle that verifies with separately supplied trust", async () => {
    const base = signed(),
      admitted = await admittedSigned(base);
    expect(verifyOfflineCertificateBundle(admitted, base.trust)).toBe(true);
    expect(admitted.payload_sha256).toBe(canonicalSha256(admitted.canonical_payload));
  });
  for (const mutation of ["payload", "tally", "signature", "key", "trust"] as const)
    it(`rejects ${mutation} tampering after the admitted signed resource`, async () => {
      const base = signed(),
        admitted = await admittedSigned(base);
      expect(verifyOfflineCertificateBundle(admitted, base.trust)).toBe(true);
      const wrongKey = {
        ...base.trust.keys[0]!,
        public_jwk: base.attacker.publicKey.export({ format: "jwk" }) as JsonValue
      };
      if (mutation === "payload") admitted.canonical_payload.vote.title += " altered";
      if (mutation === "tally") admitted.canonical_payload.tally.yesWeight = "2";
      if (mutation === "signature") {
        const signature = Buffer.from(admitted.signature_base64url, "base64url");
        signature[0] = signature[0]! ^ 1;
        admitted.signature_base64url = signature.toString("base64url");
      }
      if (mutation === "key")
        admitted.signing_key.public_jwk = wrongKey.public_jwk as Record<string, JsonValue>;
      const trust = mutation === "trust" ? { ...base.trust, keys: [wrongKey] } : base.trust;
      expect(verifyOfflineCertificateBundle(admitted, trust)).toBe(false);
    });
  it("preserves offline rejection of a freshly signed tally inconsistent with ballots", async () => {
    const base = signed(),
      tally = { ...base.payload.tally, yesWeight: "2" };
    const altered = { ...base.payload, tally, tallySha256: canonicalSha256(tally) };
    const signedBad = issueVoteCertificate(altered, base.trusted.privateKey);
    const variant = {
      ...base,
      bundle: {
        ...base.bundle,
        canonical_payload: signedBad.payload,
        payload_sha256: signedBad.payloadSha256,
        signature_base64url: signedBad.signatureBase64Url
      }
    };
    const admitted = await admittedSigned(variant);
    expect(verifyOfflineCertificateBundle(admitted, base.trust)).toBe(false);
  });
});
