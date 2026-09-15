import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { verifyOfflineCertificateBundle } from "../../lib/audit/src/offline.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
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
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedVoteProjectionFixture } from "../helpers/vote-projection-fixture.js";
import { seedCertificateProjectionFixture } from "../helpers/certificate-projection-fixture.js";
import { ORIGINAL_CERTIFICATE_RESOURCE_SQL } from "../helpers/certificate-resource-original-sql.js";

type ObjectValue = Readonly<Record<string, JsonValue>>;
function object(value: JsonValue): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected fixture object");
  return value as ObjectValue;
}
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
function flatBytes(q: ObjectValue) {
  const key = object(q["signing_key"]!);
  const values: unknown[] = [
    q["schema_version"],
    q["certificate_id"],
    q["vote_id"],
    q["outcome_id"],
    q["public_id"],
    q["payload_sha256"],
    q["signature_base64url"],
    q["issued_at"],
    key["id"],
    key["kid"],
    key["algorithm"]
  ];
  return values.reduce<number>(
    (sum, value) => sum + (value === null ? 0 : Buffer.byteLength(String(value))),
    0
  );
}
const bytes = (value: JsonValue) => Buffer.from(canonicalJson(value), "utf8");
const hash = (value: Buffer) => createHash("sha256").update(value).digest("hex");

it("admits the original signed certificate resource and gates fresh projection under the actual server role", async () => {
  await withMigratedDatabase("certificate_projection", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["governance:read"]
    });
    const vote = await seedVoteProjectionFixture(pool, actor),
      voteId = vote.voteId;
    const fixture = await seedCertificateProjectionFixture(pool, actor, voteId),
      certificateId = fixture.certificateId;
    await pool.query(`create function certificate_projection_fault() returns uuid language plpgsql volatile as $$
      begin raise exception 'certificate projection construction fault'; end $$`);
    interface Options {
      boardId?: string;
      voteId?: string;
      certificateId?: string;
      afterPreflight?: (metadata: CertificateProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      fault?: boolean;
      reducedParameter?: number;
    }
    const manager = new ResponseAllocationManager();
    let latest: CertificateProjectionMetadata | undefined;
    let metadataCalls = 0,
      contentCalls = 0,
      contentRows = 0,
      sequence = 0;
    async function read(options: Options = {}) {
      const owner = manager.openRequest(new AbortController().signal),
        initialUnits = manager.accounting.usedUnits;
      let chargedUnits: number | undefined;
      try {
        return await withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            if (options.mode) await client.query(`set local plan_cache_mode = ${options.mode}`);
            const proxy = new Proxy(client, {
              get(target, key) {
                if (key !== "query") return Reflect.get(target, key, target);
                return async (sql: string, values?: unknown[]) => {
                  if (sql === CERTIFICATE_PROJECTION_CONTENT_SQL) {
                    contentCalls += 1;
                    chargedUnits = certificateProjectionPlan(latest!).units;
                    expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      const needle = "'certificate_id',certificate.id";
                      expect(text.includes(needle)).toBe(true);
                      text = text.replace(
                        needle,
                        "'certificate_id',certificate_projection_fault()"
                      );
                    }
                    if (options.reducedParameter !== undefined) {
                      parameters = [...(values ?? [])];
                      parameters[options.reducedParameter] =
                        options.reducedParameter === 3
                          ? testId(229999)
                          : options.reducedParameter === 4
                            ? "0".repeat(64)
                            : "0";
                    }
                    const result = options.mode
                      ? await target.query({
                          name: `certificate-projection-${String(sequence++)}`,
                          text,
                          ...(parameters === undefined ? {} : { values: parameters })
                        })
                      : await target.query(text, parameters);
                    contentRows += result.rows.filter(
                      (row: { payload: unknown }) => row.payload !== null
                    ).length;
                    return result;
                  }
                  const result = await target.query(sql, values);
                  if (sql === CERTIFICATE_PROJECTION_PREFLIGHT_SQL) {
                    metadataCalls += 1;
                    latest = result.rows[0] as CertificateProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            const result = await owner.produce(() =>
              loadAdmittedCertificateProjection(
                proxy,
                options.boardId ?? actor.boardId,
                options.voteId ?? voteId,
                options.certificateId ?? certificateId
              )
            );
            if (chargedUnits !== undefined)
              expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
            return result;
          },
          { assumeRole: "boardagent_server" }
        );
      } catch (error) {
        if (chargedUnits !== undefined)
          expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
        throw error;
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        expect(manager.accounting.usedUnits).toBe(initialUnits);
      }
    }
    // Original full resource/byte and independent scalar oracles run BEFORE
    // capacity occupancy. Fixture reads here deliberately materialize test data.
    const original = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const found = await client.query<{ id: string; payload: JsonValue }>(
          ORIGINAL_CERTIFICATE_RESOURCE_SQL,
          [actor.boardId, voteId, certificateId]
        );
        expect(found.rows).toHaveLength(1);
        return found.rows[0]!;
      },
      { assumeRole: "boardagent_server" }
    );
    const admitted = await read();
    expect(admitted).toEqual(original);
    expect(bytes(admitted!.payload)).toEqual(bytes(original.payload));
    const q = object(original.payload),
      key = object(q["signing_key"]!);
    expect(Object.keys(q)).toHaveLength(10);
    expect(Object.keys(key)).toHaveLength(4);
    expect(q["certificate_id"]).toBe(certificateId);
    expect(q["outcome_id"]).toBe(fixture.outcomeId);
    expect(q["payload_sha256"]).toBe(fixture.signed.payloadSha256);
    expect(q["signature_base64url"]).toBe(fixture.signed.signatureBase64Url);
    // Trust is supplied from the local fixture's original key, never promoted
    // from the resource response. Signature validity is not persisted truth.
    expect(
      verifyOfflineCertificateBundle(JSON.parse(bytes(q).toString("utf8")), fixture.trust)
    ).toBe(true);
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const raw = await client.query<{ raw: Buffer; payload_json: string; key_json: string }>(
          `select certificate.canonical_payload as raw,
          (convert_from(certificate.canonical_payload,'UTF8')::jsonb)::text as payload_json,
          key.public_jwk::text as key_json from vote_certificates as certificate
          join crypto_key_registry as key on key.id=certificate.signing_key_id
          where certificate.id=$1 and certificate.board_id=$2 and certificate.vote_id=$3`,
          [certificateId, actor.boardId, voteId]
        );
        expect(raw.rows).toHaveLength(1);
        const measured = await client.query<CertificateProjectionMetadata>(
          CERTIFICATE_PROJECTION_PREFLIGHT_SQL,
          [actor.boardId, voteId, certificateId]
        );
        expect(measured.rows).toHaveLength(1);
        return { raw: raw.rows[0]!, metadata: measured.rows[0]! };
      },
      { assumeRole: "boardagent_server" }
    );
    expect(oracle.raw.raw).toEqual(fixture.canonicalPayload);
    expect(hash(oracle.raw.raw)).toBe(fixture.signed.payloadSha256);
    expect(oracle.metadata.observation_sha256).not.toBe(fixture.signed.payloadSha256);
    expect(oracle.metadata.raw_payload_bytes).toBe(String(oracle.raw.raw.length));
    expect(oracle.metadata.scalar_utf8).toBe(String(flatBytes(q)));
    const jsons = [oracle.raw.payload_json, oracle.raw.key_json],
      shapes = jsons.map((value) => shape(JSON.parse(value)));
    expect(oracle.metadata.json_utf8).toBe(
      String(jsons.reduce((n, v) => n + Buffer.byteLength(v), 0))
    );
    expect(oracle.metadata.json_properties).toBe(
      String(shapes.reduce((n, v) => n + v.properties, 0))
    );
    expect(oracle.metadata.json_containers).toBe(
      String(shapes.reduce((n, v) => n + v.containers, 0))
    );
    expect(oracle.raw.key_json.includes("10000000000000000000000000000000000000000")).toBe(true);
    expect(Buffer.byteLength(oracle.raw.key_json)).not.toBe(
      Buffer.byteLength(JSON.stringify(JSON.parse(oracle.raw.key_json)))
    );
    const cost = certificateProjectionCost(oracle.metadata),
      actualShape = shape(q);
    expect(bytes(q).length).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
    expect(actualShape.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
    expect(actualShape.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
    for (const options of [
      { boardId: testId(229999) },
      { voteId: testId(229999) },
      { certificateId: testId(229999) }
    ]) {
      const previous = contentCalls;
      expect(await read(options)).toBeNull();
      expect(contentCalls).toBe(previous);
    }
    const held = Array.from({ length: 2048 }, () =>
      manager.tryReserve(
        responseAllocationPlan({
          kind: "document",
          representation: "resource",
          sourceId: "small",
          sourceVersion: "1",
          sha256: "a".repeat(64),
          canonicalBytes: 1
        })
      )
    );
    const beforeMeta = metadataCalls,
      beforeContent = contentCalls;
    try {
      await expect(read()).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(metadataCalls - beforeMeta).toBe(1);
      expect(contentCalls - beforeContent).toBe(0);
    } finally {
      for (const lease of held) lease.release();
    }
    for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
      for (const reducedParameter of [3, 4, 5, 6, 7, 8, 9]) {
        const previousRows = contentRows;
        await expect(read({ mode, fault: true, reducedParameter })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(contentRows).toBe(previousRows);
        expect(manager.accounting.usedUnits).toBe(0);
      }
      await expect(read({ mode, fault: true })).rejects.toThrow(
        "certificate projection construction fault"
      );
      expect(manager.accounting.usedUnits).toBe(0);
    }
    // Change only a same-width JWK extension on the same key row. All scalar
    // widths/graph counts stay equal; the private exact observation must refuse.
    await expect(
      read({
        afterPreflight: async (metadata) => {
          const changed = await pool.query(
            `update crypto_key_registry set public_jwk=jsonb_set(public_jwk,'{fixture,label}','"Ω"'::jsonb)
        where id=$1 and public_jwk->'fixture'->>'label'='Δ' returning id`,
            [fixture.signingKeyId]
          );
          expect(changed.rowCount).toBe(1);
          const fresh = await withRequestTransaction(
            pool,
            actor.context,
            (client) =>
              client.query<CertificateProjectionMetadata>(CERTIFICATE_PROJECTION_PREFLIGHT_SQL, [
                actor.boardId,
                voteId,
                certificateId
              ]),
            { assumeRole: "boardagent_server" }
          );
          const observed = fresh.rows[0]!;
          expect(observed.id).toBe(metadata.id);
          expect(observed.signing_key_id).toBe(metadata.signing_key_id);
          for (const field of [
            "raw_payload_bytes",
            "scalar_utf8",
            "json_utf8",
            "json_properties",
            "json_containers"
          ] as const)
            expect(observed[field]).toBe(metadata[field]);
          expect(observed.observation_sha256).not.toBe(metadata.observation_sha256);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const changed = await read();
    expect(changed).not.toBeNull();
    expect(verifyOfflineCertificateBundle(changed!.payload, fixture.trust)).toBe(false);
    const restored = await pool.query(
      "update crypto_key_registry set public_jwk=$2::jsonb where id=$1 returning id",
      [fixture.signingKeyId, JSON.stringify(fixture.publicJwk)]
    );
    expect(restored.rowCount).toBe(1);
    expect(verifyOfflineCertificateBundle((await read())!.payload, fixture.trust)).toBe(true);
    // Actual SQL has returned, but its producer promise still owns the result.
    // Simulated native/collector settlement cannot release that live producer.
    const abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    try {
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            const proxy = new Proxy(client, {
              get(target, property) {
                if (property !== "query") return Reflect.get(target, property, target);
                return async (sql: string, values?: unknown[]) => {
                  const result = await target.query(sql, values);
                  if (sql === CERTIFICATE_PROJECTION_CONTENT_SQL) {
                    const charged = manager.accounting.usedUnits;
                    expect(charged).toBeGreaterThan(0);
                    abort.abort();
                    owner.nativeTerminal();
                    owner.collectorSettled();
                    expect(manager.accounting.usedUnits).toBe(charged);
                    await Promise.resolve();
                    expect(manager.accounting.usedUnits).toBe(charged);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            return owner.produce(() =>
              loadAdmittedCertificateProjection(proxy, actor.boardId, voteId, certificateId)
            );
          },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
    expect(
      await read({
        afterPreflight: async () => {
          await vote.exclude();
        }
      })
    ).toBeNull();
    const afterRecusal = contentCalls;
    expect(await read()).toBeNull();
    expect(contentCalls).toBe(afterRecusal);
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
