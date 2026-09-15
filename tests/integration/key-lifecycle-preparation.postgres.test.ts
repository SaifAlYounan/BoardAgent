import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import type { Pool } from "pg";
import type { z } from "zod";
import { describe, expect, it } from "vitest";
import * as database from "../../lib/db/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";
import { symmetricKeyId } from "../../artifacts/server/src/symmetric-key-id.js";

type Proposal = z.input<typeof database.KeyLifecyclePreparationSchema>;
async function proposal(
  pool: Pool,
  organizationId: string,
  purpose = "evidence_signing",
  operation: Proposal["operation"] = "replace"
): Promise<Proposal> {
  const row = (
    await pool.query(
      "select instance_id,k.id as key_id,to_char(k.activated_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as activated_at from system_instance cross join crypto_key_registry k where k.purpose=$1",
      [purpose]
    )
  ).rows[0];
  const keyId = newWorkerTestId();
  let replacement: Proposal["replacement"] = null;
  if (operation === "replace") {
    if (purpose === "evidence_signing") {
      const exported = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
      const publicJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: exported.x! };
      const materialSha256 = canonicalSha256(publicJwk);
      replacement = {
        keyId,
        kid: `evidence-${materialSha256.slice(0, 24)}`,
        algorithm: "EdDSA",
        publicJwk,
        materialSha256,
        nonsecretLocator: "file:/run/boardagent/new-evidence.pem"
      };
    } else if (purpose === "oauth_signing") {
      const exported = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
        format: "jwk"
      });
      const kid = `oauth-synthetic-${keyId}`;
      const publicJwk = {
        kty: "EC" as const,
        crv: "P-256" as const,
        x: exported.x!,
        y: exported.y!,
        kid,
        alg: "ES256" as const,
        use: "sig" as const
      };
      replacement = {
        keyId,
        kid,
        algorithm: "ES256",
        publicJwk,
        materialSha256: canonicalSha256({
          kty: publicJwk.kty,
          crv: publicJwk.crv,
          x: publicJwk.x,
          y: publicJwk.y
        }),
        nonsecretLocator: "file:/run/boardagent/new-oauth.jwk"
      };
    } else {
      const material = randomBytes(32),
        materialSha256 = createHash("sha256").update(material).digest("hex");
      const kid =
        purpose === "backup_kek"
          ? `backup-${keyId}`
          : symmetricKeyId(purpose === "data_kek" ? "data" : "browser", material);
      replacement = {
        keyId,
        kid,
        algorithm: purpose === "browser_session" ? "HMAC-SHA256" : "A256GCM",
        publicJwk: null,
        materialSha256,
        nonsecretLocator:
          purpose === "backup_kek"
            ? `sha256:${materialSha256}`
            : "file:/run/boardagent/new-data.key"
      };
      material.fill(0);
    }
  }
  return {
    instanceId: row.instance_id,
    organizationId,
    keyId: row.key_id,
    operationId: newWorkerTestId(),
    operation,
    replacement,
    declaredCompromisedAt: operation === "mark_compromised" ? row.activated_at : null,
    retainedMaterialSha256: "a".repeat(64),
    operatorReference: "Synthetic operator ticket",
    reason: "Synthetic database preparation only"
  };
}
const prepare = (pool: Pool, input: Proposal) =>
  database.withBootstrapTransaction(
    pool,
    (client) => database.prepareKeyLifecycleInTransaction(client, input),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );

describe("protected key lifecycle preparation", () => {
  it("rejects a prior key with retirement or compromise dated after preparation", async () => {
    await withUnseededWorker("key-prepare-future-state", async ({ pool, organizationId }) => {
      const { request } = await prepare(pool, await proposal(pool, organizationId));
      for (const field of ["retiredAt", "compromisedAt"] as const) {
        expect(
          database.KeyLifecycleRequestSchema.safeParse({
            ...request,
            expectedKey: { ...request.expectedKey, [field]: request.expiresAt }
          }).success
        ).toBe(false);
      }
    });
  });
  it("refuses an OAuth key renamed as a replacement when the actual public key is unchanged", async () => {
    await withUnseededWorker("key-prepare-renamed-oauth", async ({ pool, organizationId }) => {
      const input = await proposal(pool, organizationId, "oauth_signing");
      const old = (
        await pool.query("select public_jwk from crypto_key_registry where id=$1", [input.keyId])
      ).rows[0].public_jwk;
      const publicJwk = { ...old, kid: input.replacement!.kid };
      input.replacement = {
        ...input.replacement!,
        publicJwk,
        materialSha256: canonicalSha256({
          kty: publicJwk.kty,
          crv: publicJwk.crv,
          x: publicJwk.x,
          y: publicJwk.y
        })
      };
      await expect(prepare(pool, input)).rejects.toThrow();
    });
  });
  it("binds a replacement proposal to exact current database facts without changing authority", async () => {
    await withUnseededWorker("key-lifecycle-prepare", async ({ pool, organizationId }) => {
      const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
        .instance_id;
      const oldKey = (
        await pool.query("select * from crypto_key_registry where purpose='evidence_signing'")
      ).rows[0];
      const jwk = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
      const publicJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: jwk.x! };
      const prepared = await database.withBootstrapTransaction(
        pool,
        (client) =>
          database.prepareKeyLifecycleInTransaction(client, {
            instanceId,
            organizationId,
            keyId: oldKey.id,
            operationId: newWorkerTestId(),
            operation: "replace",
            declaredCompromisedAt: null,
            replacement: {
              keyId: newWorkerTestId(),
              kid: `evidence-${canonicalSha256(publicJwk).slice(0, 24)}`,
              algorithm: "EdDSA",
              publicJwk,
              nonsecretLocator: "file:/run/boardagent/next-evidence.pem",
              materialSha256: canonicalSha256(publicJwk)
            },
            retainedMaterialSha256: "a".repeat(64),
            operatorReference: "Synthetic operator ticket",
            reason: "Synthetic preparation; no file custody claim"
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      expect(prepared.request.schemaVersion).toBe("boardagent.key-lifecycle-request.v1");
      expect(prepared.request.expectedKey.keyId).toBe(oldKey.id);
      expect(prepared.requestSha256).toBe(canonicalSha256(prepared.request));
      expect(
        (await pool.query("select * from crypto_key_registry where id=$1", [oldKey.id])).rows[0]
      ).toEqual(oldKey);
    });
  });

  it("prepares each purpose and operation and preserves all original key and audit records", async () => {
    await withUnseededWorker("key-prepare-purposes", async ({ pool, organizationId }) => {
      const before = (
        await pool.query("select to_jsonb(k) as key from crypto_key_registry k order by id")
      ).rows;
      const head = (await pool.query("select * from audit_chain_head")).rows;
      for (const purpose of [
        "oauth_signing",
        "evidence_signing",
        "browser_session",
        "data_kek",
        "backup_kek"
      ]) {
        for (const operation of ["replace", "retire", "mark_compromised"] as const) {
          const result = await prepare(
            pool,
            await proposal(pool, organizationId, purpose, operation)
          );
          expect(result.request.purpose).toBe(purpose);
          expect(result.request.operation).toBe(operation);
          expect(result.request.preparedAt).toBe(
            result.request.expectedInventory.keyDependencies.observedAt
          );
          expect(Date.parse(result.request.expiresAt) - Date.parse(result.request.preparedAt)).toBe(
            1_800_000
          );
          expect(result.request.expiresAt.slice(-4)).toBe(result.request.preparedAt.slice(-4));
          expect(result.requestSha256).toBe(canonicalSha256(result.request));
        }
      }
      expect(
        (await pool.query("select to_jsonb(k) as key from crypto_key_registry k order by id")).rows
      ).toEqual(before);
      expect((await pool.query("select * from audit_chain_head")).rows).toEqual(head);
    });
  });

  it("rejects malformed/private projections and mismatched identities, inventories or microsecond expiry", async () => {
    await withUnseededWorker("key-prepare-invalid", async ({ pool, organizationId }) => {
      const input = await proposal(pool, organizationId);
      const { request } = await prepare(pool, input);
      type Request = z.input<typeof database.KeyLifecycleRequestSchema>;
      const invalid: Array<(v: Request) => void> = [
        (v) => {
          v.instanceId = newWorkerTestId();
        },
        (v) => {
          v.expectedKey.keyId = newWorkerTestId();
        },
        (v) => {
          v.expectedInventory.keyDependencies.keyPurpose = "data_kek";
        },
        (v) => {
          v.expectedInventory.groups.pop();
        },
        (v) => {
          v.expectedInventory.groups[0]!.rowCount = "1";
        },
        (v) => {
          v.preparedAt = "2026-01-01T00:00:00.000000Z";
        },
        (v) => {
          v.expiresAt = v.preparedAt;
        },
        (v) => {
          v.expiresAt =
            v.expiresAt.slice(0, -4) + (v.expiresAt.slice(-4) === "001Z" ? "002Z" : "001Z");
        },
        (v) => {
          v.replacement!.keyId = v.keyId;
        },
        (v) => {
          v.replacement!.kid = "wrong-derived-kid";
        },
        (v) => {
          v.replacement!.materialSha256 = "b".repeat(64);
        },
        (v) => {
          v.replacement!.algorithm = "ES256";
        },
        (v) => {
          v.replacement!.publicJwk = null;
        },
        (v) => {
          v.replacement!.nonsecretLocator = "file:relative";
        },
        (v) => {
          v.replacement!.nonsecretLocator = "file:/run/../next.pem";
        },
        (v) => {
          v.replacement!.nonsecretLocator = "file:/run/next\u0000.pem";
        },
        (v) => {
          v.declaredCompromisedAt = v.preparedAt;
        },
        (v) => {
          v.reason = " ";
        }
      ];
      for (const change of invalid) {
        const changed: Request = structuredClone(request);
        change(changed);
        expect(database.KeyLifecycleRequestSchema.safeParse(changed).success).toBe(false);
      }
      const withPrivate = {
        ...input,
        replacement: {
          ...input.replacement!,
          publicJwk: { ...input.replacement!.publicJwk!, d: "synthetic-private-value" }
        }
      };
      await expect(prepare(pool, withPrivate)).rejects.toThrow();
      expect(
        database.KeyLifecycleRequestSchema.safeParse({ ...request, approveWithoutChecks: true })
          .success
      ).toBe(false);
    });
  });

  it("changes the prepared facts after real queued work appears, without claiming a prior request still applies", async () => {
    await withUnseededWorker("key-prepare-new-work", async ({ pool, organizationId }) => {
      const input = await proposal(pool, organizationId);
      const initial = await prepare(pool, input);
      await database.withWorkerTransaction(
        pool,
        (client) => database.scheduleAuditCheckpointInTransaction(client, newWorkerTestId()),
        { assumeRole: "boardagent_worker" }
      );
      const current = await prepare(pool, input);
      expect(
        current.request.expectedInventory.groups.find((g) => g.name === "unfinished_jobs")!.rowCount
      ).toBe("1");
      expect(current.request.expectedInventory.groups).not.toEqual(
        initial.request.expectedInventory.groups
      );
      expect(current.requestSha256).not.toBe(initial.requestSha256);
    });
  });
});
