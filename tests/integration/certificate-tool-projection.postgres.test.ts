import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { verifyOfflineCertificateBundle } from "../../lib/audit/src/offline.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  loadAdmittedCertificateToolProjection,
  CERTIFICATE_TOOL_PREFLIGHT_SQL,
  CERTIFICATE_TOOL_CONTENT_SQL,
  certificateToolProjectionCost,
  certificateToolProjectionPlan,
  type CertificateToolProjectionMetadata
} from "../../artifacts/server/src/certificate-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedVoteProjectionFixture } from "../helpers/vote-projection-fixture.js";
import { seedCertificateProjectionFixture } from "../helpers/certificate-projection-fixture.js";
import { ORIGINAL_CERTIFICATE_TOOL_SQL } from "../helpers/certificate-tool-original-sql.js";

type ObjectValue = Readonly<Record<string, JsonValue>>;
function object(value: JsonValue): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected certificate tool object");
  return value as ObjectValue;
}
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
function flatBytes(q: ObjectValue) {
  // Independent enumeration of the original eleven flat values, not the helper map.
  const values = [
    q["certificate_id"],
    q["vote_id"],
    q["outcome_id"],
    q["public_id"],
    q["schema_version"],
    q["payload_sha256"],
    q["signature_base64url"],
    q["signing_key_id"],
    q["state"],
    q["supersedes_id"],
    q["issued_at"]
  ];
  return values.reduce<number>(
    (n, value) => n + (value === null ? 0 : Buffer.byteLength(String(value))),
    0
  );
}
const bytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");
const digest = (value: Buffer) => createHash("sha256").update(value).digest("hex");

it("admits the original certificate tool projection under the actual server role with complete fresh gates", async () => {
  await withMigratedDatabase("certificate_tool", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["governance:read"]
    });
    const vote = await seedVoteProjectionFixture(pool, actor),
      voteId = vote.voteId;
    const fixture = await seedCertificateProjectionFixture(pool, actor, voteId),
      certificateId = fixture.certificateId;
    await pool.query(`create function certificate_tool_fault() returns uuid language plpgsql volatile as $$
      begin raise exception 'certificate tool whole projection fault'; end $$`);
    const manager = new ResponseAllocationManager();
    let latest: CertificateToolProjectionMetadata | undefined;
    let metadataCalls = 0,
      contentCalls = 0,
      constructedRows = 0,
      sequence = 0;
    interface Options {
      voteId?: string;
      certificateId?: string | null;
      afterPreflight?: (metadata: CertificateToolProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      fault?: boolean;
      falseParameter?: number;
    }
    async function read(options: Options = {}) {
      const owner = manager.openRequest(new AbortController().signal),
        initial = manager.accounting.usedUnits;
      let charge: number | undefined;
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
                  if (sql === CERTIFICATE_TOOL_CONTENT_SQL) {
                    contentCalls += 1;
                    charge = certificateToolProjectionPlan(latest!).units;
                    expect(manager.accounting.usedUnits).toBe(initial + charge);
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      const needle = "'certificate_id',certificate.id";
                      expect(text.includes(needle)).toBe(true);
                      text = text.replace(needle, "'certificate_id',certificate_tool_fault()");
                    }
                    if (options.falseParameter !== undefined) {
                      parameters = [...(values ?? [])];
                      parameters[options.falseParameter] =
                        options.falseParameter <= 3
                          ? testId(239999)
                          : options.falseParameter === 4
                            ? "0".repeat(64)
                            : "0";
                    }
                    const result = options.mode
                      ? await target.query({
                          name: `certificate-tool-${String(sequence++)}`,
                          text,
                          ...(parameters === undefined ? {} : { values: parameters })
                        })
                      : await target.query(text, parameters);
                    constructedRows += result.rows.filter(
                      (row: { view: unknown }) => row.view !== null
                    ).length;
                    return result;
                  }
                  const result = await target.query(sql, values);
                  if (sql === CERTIFICATE_TOOL_PREFLIGHT_SQL) {
                    metadataCalls += 1;
                    latest = result.rows[0] as CertificateToolProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            const result = await owner.produce(() =>
              loadAdmittedCertificateToolProjection(
                proxy,
                options.voteId ?? voteId,
                options.certificateId ?? null
              )
            );
            if (charge !== undefined) expect(manager.accounting.usedUnits).toBe(initial + charge);
            return result;
          },
          { assumeRole: "boardagent_server" }
        );
      } catch (error) {
        if (charge !== undefined) expect(manager.accounting.usedUnits).toBe(initial + charge);
        throw error;
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        expect(manager.accounting.usedUnits).toBe(initial);
      }
    }
    // All original full-view/raw/scalar oracles run before occupancy. These
    // deliberately materialize only synthetic fixture data for independent proof.
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const current = await client.query<{ board_id: string; view: JsonValue }>(
          ORIGINAL_CERTIFICATE_TOOL_SQL,
          [voteId, null]
        );
        const explicit = await client.query<{ board_id: string; view: JsonValue }>(
          ORIGINAL_CERTIFICATE_TOOL_SQL,
          [voteId, certificateId]
        );
        const raw = await client.query<{ raw: Buffer; payload_json: string }>(
          `select certificate.canonical_payload as raw,
        (convert_from(certificate.canonical_payload,'UTF8')::jsonb)::text as payload_json
        from vote_certificates as certificate where certificate.id=$1 and certificate.vote_id=$2
        and not boardagent_member_vote_recused(certificate.vote_id,boardagent_context_uuid('boardagent.member_id'))`,
          [certificateId, voteId]
        );
        const metadata = await client.query<CertificateToolProjectionMetadata>(
          CERTIFICATE_TOOL_PREFLIGHT_SQL,
          [voteId, null]
        );
        expect(current.rows).toHaveLength(1);
        expect(explicit.rows).toHaveLength(1);
        expect(raw.rows).toHaveLength(1);
        expect(metadata.rows).toHaveLength(1);
        return {
          current: current.rows[0]!,
          explicit: explicit.rows[0]!,
          raw: raw.rows[0]!,
          metadata: metadata.rows[0]!
        };
      },
      { assumeRole: "boardagent_server" }
    );
    expect(oracle.current).toEqual(oracle.explicit);
    const admitted = await read();
    expect(admitted).toEqual(oracle.current);
    expect(bytes(admitted)).toEqual(bytes(oracle.current));
    expect(await read({ certificateId })).toEqual(oracle.explicit);
    const q = object(oracle.current.view),
      jsonShape = shape(JSON.parse(oracle.raw.payload_json));
    expect(Object.keys(q)).toHaveLength(12);
    expect(q["certificate_id"]).toBe(certificateId);
    expect(q["schema_version"]).toBe("boardagent.vote-certificate.v1");
    expect(q["state"]).toBe("current");
    expect(q["payload_sha256"]).toBe(fixture.signed.payloadSha256);
    expect(q["signature_base64url"]).toBe(fixture.signed.signatureBase64Url);
    expect(q["signing_key_id"]).toBe(fixture.signingKeyId);
    expect(q["signing_key"]).toBeUndefined();
    expect(oracle.raw.raw).toEqual(fixture.canonicalPayload);
    expect(digest(oracle.raw.raw)).toBe(fixture.signed.payloadSha256);
    expect(oracle.metadata.raw_payload_bytes).toBe(String(oracle.raw.raw.length));
    expect(oracle.metadata.scalar_utf8).toBe(String(flatBytes(q)));
    expect(oracle.metadata.json_utf8).toBe(String(Buffer.byteLength(oracle.raw.payload_json)));
    expect(oracle.metadata.json_properties).toBe(String(jsonShape.properties));
    expect(oracle.metadata.json_containers).toBe(String(jsonShape.containers));
    expect(oracle.metadata.observation_sha256).not.toBe(fixture.signed.payloadSha256);
    const privateTuple = [
      q["certificate_id"],
      oracle.current.board_id,
      q["vote_id"],
      q["outcome_id"],
      q["public_id"],
      q["schema_version"],
      q["payload_sha256"],
      q["signature_base64url"],
      q["signing_key_id"],
      q["state"],
      q["supersedes_id"],
      q["issued_at"],
      String(oracle.raw.raw.length),
      digest(oracle.raw.raw)
    ];
    const observation = await withRequestTransaction(
      pool,
      actor.context,
      (client) =>
        client.query<{ sha: string }>(
          "select encode(sha256(convert_to(($1::jsonb)::text,'UTF8')),'hex') as sha",
          [JSON.stringify(privateTuple)]
        ),
      { assumeRole: "boardagent_server" }
    );
    expect(observation.rows).toHaveLength(1);
    expect(oracle.metadata.observation_sha256).toBe(observation.rows[0]!.sha);
    // This signed fixture has ordinary integer numbers; retain actual PG text
    // including spaces. No exponent/JWK coverage is inferred for this tool.
    expect(oracle.raw.payload_json).toContain('"resolutionVersion": 1');
    expect(Buffer.byteLength(oracle.raw.payload_json)).not.toBe(
      Buffer.byteLength(JSON.stringify(JSON.parse(oracle.raw.payload_json)))
    );
    const cost = certificateToolProjectionCost(oracle.metadata),
      wholeShape = shape(q);
    expect(bytes(q).length).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
    expect(wholeShape.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
    expect(wholeShape.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
    // Reconstruct an offline bundle client-side using separately held trust.
    // The public tool response remains twelve fields and contains no JWK join.
    const bundle = {
      schema_version: "boardagent.vote-certificate-bundle.v1",
      certificate_id: q["certificate_id"],
      vote_id: q["vote_id"],
      outcome_id: q["outcome_id"],
      public_id: q["public_id"],
      canonical_payload: q["canonical_payload"],
      payload_sha256: q["payload_sha256"],
      signature_base64url: q["signature_base64url"],
      signing_key: fixture.trust.keys[0],
      issued_at: q["issued_at"]
    };
    expect(verifyOfflineCertificateBundle(bundle, fixture.trust)).toBe(true);
    for (const options of [{ voteId: testId(239999) }, { certificateId: testId(239999) }]) {
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
      // $2 selection mismatch proves the scalar-only bound-row fallback; $3..10
      // independently falsify selected ID/board/private hash/raw/S/N/P/O.
      for (const falseParameter of [1, 2, 3, 4, 5, 6, 7, 8, 9]) {
        const previous = constructedRows;
        await expect(read({ mode, fault: true, falseParameter })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(constructedRows).toBe(previous);
        expect(manager.accounting.usedUnits).toBe(0);
      }
      await expect(read({ mode, fault: true })).rejects.toThrow(
        "certificate tool whole projection fault"
      );
    }
    // The tool does not project key registry JSON: a same-ID JWK extension change
    // must leave its private observation and exact public bytes unchanged.
    expect(
      await read({
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
              client.query<CertificateToolProjectionMetadata>(CERTIFICATE_TOOL_PREFLIGHT_SQL, [
                voteId,
                null
              ]),
            { assumeRole: "boardagent_server" }
          );
          expect(fresh.rows).toHaveLength(1);
          expect(fresh.rows[0]).toEqual(metadata);
        }
      })
    ).toEqual(oracle.current);
    const restored = await pool.query(
      "update crypto_key_registry set public_jwk=$2::jsonb where id=$1 returning id",
      [fixture.signingKeyId, JSON.stringify(fixture.publicJwk)]
    );
    expect(restored.rowCount).toBe(1);
    const abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    try {
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            const proxy = new Proxy(client, {
              get(target, key) {
                if (key !== "query") return Reflect.get(target, key, target);
                return async (sql: string, values?: unknown[]) => {
                  const result = await target.query(sql, values);
                  if (sql === CERTIFICATE_TOOL_CONTENT_SQL) {
                    const charge = manager.accounting.usedUnits;
                    expect(charge).toBeGreaterThan(0);
                    abort.abort();
                    owner.nativeTerminal();
                    owner.collectorSettled();
                    expect(manager.accounting.usedUnits).toBe(charge);
                    await Promise.resolve();
                    expect(manager.accounting.usedUnits).toBe(charge);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            return owner.produce(() => loadAdmittedCertificateToolProjection(proxy, voteId, null));
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
    expect(await read({ certificateId })).toBeNull();
    expect(contentCalls).toBe(afterRecusal);
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
