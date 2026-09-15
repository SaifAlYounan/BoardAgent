import type { Pool } from "pg";
import { generateKeyPairSync } from "node:crypto";
import { signCheckpoint, signRecoveryCheckpoint } from "../../lib/audit/src/index.js";
import {
  applyAuditRecoveryInTransaction,
  prepareAuditRecoveryInTransaction,
  prepareAuditCheckpointInTransaction,
  commitAuditCheckpointInTransaction,
  withBootstrapTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAgedAudit } from "./aged-audit.js";
import { testId } from "./authorized-actor.js";

/** Actual recovery over synthetic retained history, followed by ordinary worker signing.
 * No person, client, enrollment, consent or secret-custody ceremony is represented here.
 */
export async function seedRecoveredAudit(pool: Pool) {
  const fixture = await seedAgedAudit(pool);
  // The minimal identity fixture has no real public JWK. Backup inventory needs one.
  await pool.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
    generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" }),
    testId(8)
  ]);
  const proposal = await withBootstrapTransaction(
    pool,
    (client) =>
      prepareAuditRecoveryInTransaction(client, {
        recoveryId: testId(110_000),
        instanceId: testId(15),
        organizationId: fixture.actor.organizationId,
        signingKeyId: fixture.keyId,
        operatorReference: "synthetic-incident-3",
        reason: "Preserve the historical signing delay through exported records and recovery."
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
  let nextId = 110_010;
  const receipt = await withBootstrapTransaction(
    pool,
    (client) =>
      applyAuditRecoveryInTransaction(
        client,
        {
          request: proposal.request,
          requestSha256: proposal.requestSha256,
          instanceId: testId(15),
          organizationId: fixture.actor.organizationId
        },
        {
          createId: () => testId(nextId++),
          sign: async (payload) =>
            payload.schema === "boardagent.audit.recovery-checkpoint.v1"
              ? signRecoveryCheckpoint(payload, fixture.evidence.privateKey)
              : signCheckpoint(payload, fixture.evidence.privateKey)
        }
      ),
    { assumeRole: "boardagent_migrator" }
  );
  await withWorkerTransaction(
    pool,
    async (client) => {
      const next = await prepareAuditCheckpointInTransaction(client, {
        checkpointId: testId(110_100),
        signingKeyId: fixture.keyId
      });
      return commitAuditCheckpointInTransaction(client, {
        checkpoint: signCheckpoint(next.payload, fixture.evidence.privateKey),
        auditEventId: testId(110_101)
      });
    },
    { assumeRole: "boardagent_worker" }
  );
  return { ...fixture, proposal, receipt };
}
