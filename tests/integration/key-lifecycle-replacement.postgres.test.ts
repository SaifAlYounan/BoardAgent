import { generateKeyPairSync } from "node:crypto";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import * as db from "../../lib/db/src/index.js";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import { signCheckpoint } from "../../lib/audit/src/index.js";
import { loadBoardAgentKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

async function replacementInput(pool: Pool, organizationId: string, keyId?: string) {
  const target = (await pool.query("select instance_id from system_instance")).rows[0];
  keyId ??= (
    await pool.query(
      "select id from crypto_key_registry where purpose='evidence_signing' order by activated_at desc,id desc limit 1"
    )
  ).rows[0].id as string;
  const keys = generateKeyPairSync("ed25519"),
    exported = keys.publicKey.export({ format: "jwk" });
  const publicJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: exported.x! };
  const fingerprint = canonicalSha256(publicJwk);
  const input = await db.withBootstrapTransaction(
    pool,
    (c) =>
      db.prepareKeyLifecycleInTransaction(c, {
        instanceId: target.instance_id,
        organizationId,
        keyId,
        operationId: newWorkerTestId(),
        operation: "replace",
        declaredCompromisedAt: null,
        retainedMaterialSha256: "a".repeat(64),
        operatorReference: "Synthetic operator",
        reason: "Database replacement only",
        replacement: {
          keyId: newWorkerTestId(),
          kid: `evidence-${fingerprint.slice(0, 24)}`,
          algorithm: "EdDSA",
          publicJwk,
          materialSha256: fingerprint,
          nonsecretLocator: "file:/run/boardagent/next-evidence.pem"
        }
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
  return { input, keys };
}
const apply = (pool: Pool, input: Awaited<ReturnType<typeof replacementInput>>["input"]) =>
  db.withBootstrapTransaction(pool, (c) => db.applyKeyLifecycleInTransaction(c, input), {
    assumeRole: "boardagent_migrator"
  });

describe("atomic evidence key replacement", () => {
  it("replaces the evidence signer while preserving the old public identity and original receipt", async () => {
    await withUnseededWorker("key-lifecycle-replace", async ({ pool, organizationId, config }) => {
      const target = (
        await pool.query(
          "select instance_id,(select id from crypto_key_registry where purpose='evidence_signing') as key_id from system_instance"
        )
      ).rows[0];
      const before = (
        await pool.query("select * from crypto_key_registry where id=$1", [target.key_id])
      ).rows[0];
      const oldKeys = await loadBoardAgentKeyMaterial(config);
      await db.withWorkerTransaction(
        pool,
        async (c) => {
          const prepared = await db.prepareAuditCheckpointInTransaction(c, {
            checkpointId: newWorkerTestId(),
            signingKeyId: target.key_id
          });
          await db.commitAuditCheckpointInTransaction(c, {
            checkpoint: signCheckpoint(prepared.payload, oldKeys.evidencePrivateKey),
            auditEventId: newWorkerTestId()
          });
        },
        { assumeRole: "boardagent_worker" }
      );
      const priorCheckpoint = (await pool.query("select * from audit_checkpoints")).rows[0];
      const newKeys = generateKeyPairSync("ed25519");
      const generated = newKeys.publicKey.export({ format: "jwk" });
      const publicJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: generated.x! };
      const materialSha256 = canonicalSha256(publicJwk),
        newKeyId = newWorkerTestId();
      const input = await db.withBootstrapTransaction(
        pool,
        (c) =>
          db.prepareKeyLifecycleInTransaction(c, {
            instanceId: target.instance_id,
            organizationId,
            keyId: target.key_id,
            operationId: newWorkerTestId(),
            operation: "replace",
            declaredCompromisedAt: null,
            retainedMaterialSha256: "a".repeat(64),
            operatorReference: "Synthetic operator",
            reason: "Database replacement test; no private-file custody claim",
            replacement: {
              keyId: newKeyId,
              kid: `evidence-${materialSha256.slice(0, 24)}`,
              algorithm: "EdDSA",
              publicJwk,
              materialSha256,
              nonsecretLocator: "file:/run/boardagent/next-evidence.pem"
            }
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const run = () =>
        db.withBootstrapTransaction(pool, (c) => db.applyKeyLifecycleInTransaction(c, input), {
          assumeRole: "boardagent_migrator"
        });
      const first = await run();
      expect(first.details.replacement?.keyId).toBe(newKeyId);
      const old = (
        await pool.query("select * from crypto_key_registry where id=$1", [target.key_id])
      ).rows[0];
      expect(old.public_jwk).toEqual(before.public_jwk);
      expect(old.activated_at).toEqual(before.activated_at);
      expect(old.retired_at).not.toBeNull();
      expect(
        (
          await pool.query(
            "select id from crypto_key_registry where purpose='evidence_signing' and retired_at is null and compromised_at is null"
          )
        ).rows
      ).toEqual([{ id: newKeyId }]);
      expect(await run()).toEqual({ ...first, replayed: true });
      await expect(
        db.withWorkerTransaction(
          pool,
          (c) =>
            db.prepareAuditCheckpointInTransaction(c, {
              checkpointId: newWorkerTestId(),
              signingKeyId: target.key_id
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toThrow();
      await db.withWorkerTransaction(
        pool,
        async (c) => {
          const prepared = await db.prepareAuditCheckpointInTransaction(c, {
            checkpointId: newWorkerTestId(),
            signingKeyId: newKeyId
          });
          await db.commitAuditCheckpointInTransaction(c, {
            checkpoint: signCheckpoint(prepared.payload, newKeys.privateKey),
            auditEventId: newWorkerTestId()
          });
        },
        { assumeRole: "boardagent_worker" }
      );
      expect(
        (await pool.query("select * from audit_checkpoints where id=$1", [priorCheckpoint.id]))
          .rows[0]
      ).toEqual(priorCheckpoint);
      expect(
        await db.withBootstrapTransaction(pool, (c) => db.verifyPersistedAuditEvidence(c), {
          assumeRole: "boardagent_migrator",
          readOnly: true
        })
      ).toMatchObject({ valid: true });
    });
  });

  it("preserves prior retirement and compromise warnings while installing a distinct current signer", async () => {
    for (const state of ["retired", "compromised", "both"]) {
      await withUnseededWorker(`key-replacement-${state}`, async ({ pool, organizationId }) => {
        await pool.query(
          "update crypto_key_registry set activated_at=clock_timestamp()-interval '1 hour' where purpose='evidence_signing'"
        );
        await pool.query(
          "update crypto_key_registry set retired_at=case when $1 in ('retired','both') then clock_timestamp()-interval '10 minutes' end, compromised_at=case when $1 in ('compromised','both') then clock_timestamp()-interval '20 minutes' end where purpose='evidence_signing'",
          [state]
        );
        const { input } = await replacementInput(pool, organizationId);
        const receipt = await apply(pool, input);
        expect(receipt.details.after.compromisedAt).toBe(input.request.expectedKey.compromisedAt);
        expect(receipt.details.after.retiredAt).toBe(
          input.request.expectedKey.retiredAt ?? receipt.details.recordedAt
        );
        expect(receipt.details.replacement?.retiredAt).toBeNull();
        expect(receipt.details.replacement?.compromisedAt).toBeNull();
      });
    }
  });

  it("rolls back the replacement row, old-key change and receipt if new-key metadata changes before commit", async () => {
    await withUnseededWorker("key-replacement-new-row-tamper", async ({ pool, organizationId }) => {
      const { input } = await replacementInput(pool, organizationId);
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            await db.applyKeyLifecycleInTransaction(c, input);
            await c.query(
              "update crypto_key_registry set nonsecret_locator='file:/changed.pem' where id=$1",
              [input.request.replacement!.keyId]
            );
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (
          await pool.query("select * from crypto_key_registry where id=$1", [
            input.request.replacement!.keyId
          ])
        ).rowCount
      ).toBe(0);
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            input.request.keyId
          ])
        ).rows[0].retired_at
      ).toBeNull();
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
    });
  });

  it("allows one competing replacement and refuses a stale historical target even after fresh preparation", async () => {
    await withUnseededWorker("key-replacement-race", async ({ pool, organizationId }) => {
      const a = await replacementInput(pool, organizationId),
        b = await replacementInput(pool, organizationId);
      const results = await Promise.allSettled([apply(pool, a.input), apply(pool, b.input)]);
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
      expect(
        (
          await pool.query(
            "select * from crypto_key_registry where purpose='evidence_signing' and retired_at is null and compromised_at is null"
          )
        ).rowCount
      ).toBe(1);
      const stale = await replacementInput(pool, organizationId, a.input.request.keyId);
      await expect(apply(pool, stale.input)).rejects.toMatchObject({ code: "55000" });
    });
  });

  it("refuses malformed, reused or private replacement projections at the database boundary", async () => {
    await withUnseededWorker("key-replacement-invalid", async ({ pool, organizationId }) => {
      const { input } = await replacementInput(pool, organizationId);
      const old = (
        await pool.query("select public_jwk from crypto_key_registry where id=$1", [
          input.request.keyId
        ])
      ).rows[0].public_jwk;
      const { observedAt: _observedAt, ...deps } = input.request.expectedInventory.keyDependencies;
      const inventory = Buffer.from(
        canonicalJson({ ...input.request.expectedInventory, keyDependencies: deps })
      );
      const replacements: unknown[] = [
        {
          ...input.request.replacement,
          publicJwk: { ...input.request.replacement!.publicJwk, d: "private value" }
        },
        {
          ...input.request.replacement,
          publicJwk: old,
          materialSha256: canonicalSha256(old),
          kid: input.request.expectedKey.kid
        },
        { ...input.request.replacement, nonsecretLocator: "file:/tmp/../key.pem" },
        { ...input.request.replacement, nonsecretLocator: "file://tmp/key.pem" },
        { ...input.request.replacement, materialSha256: "0".repeat(64) },
        { ...input.request.replacement, kid: "unrelated-label" }
      ];
      for (const replacement of replacements) {
        const request = { ...input.request, replacement };
        const args = [
          Buffer.from(canonicalJson(request)),
          Buffer.from(canonicalSha256(request), "hex"),
          inventory
        ];
        await expect(
          db.withBootstrapTransaction(
            pool,
            (c) => c.query("select * from boardagent_begin_key_lifecycle($1,$2,$3)", args),
            { assumeRole: "boardagent_migrator" }
          )
        ).rejects.toMatchObject({ code: "55000" });
      }
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
    });
  });
});
