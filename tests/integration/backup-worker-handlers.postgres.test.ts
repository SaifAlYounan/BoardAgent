import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  BoardAgentCoreWorkerHandlers,
  TypedJobExecutionError,
  loadBoardAgentKeyMaterial,
  type BoardAgentRuntimeBinding
} from "../../artifacts/server/src/index.js";
import { parseConfig } from "../../lib/config/src/index.js";
import { canonicalSha256, type JsonValue } from "../../lib/contracts/src/index.js";
import {
  captureBackupBoundaryInTransaction,
  finalizeBackupManifest,
  inspectBackupReceiptHealthInTransaction,
  recordBackupCompletedInTransaction,
  TypedJobEnvelopeSchema,
  withBackupTransaction,
  withWorkerTransaction,
  type ClaimedJob
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

function organizationJob(
  actor: { readonly organizationId: string },
  jobType: "backup_receipt_verify" | "backup_trigger",
  jobId: string
): ClaimedJob {
  const envelope = TypedJobEnvelopeSchema.parse({
    schemaVersion: `boardagent.job.${jobType}.v1`,
    organizationId: actor.organizationId,
    boardId: null,
    jobType,
    subjectType: "organization",
    subjectId: actor.organizationId,
    parameters: {}
  });
  return {
    jobId,
    envelope,
    payloadSha256: canonicalSha256(envelope),
    attempt: 1,
    leaseOwner: "backup-worker-test",
    leaseToken: testId(81_900),
    leaseStartedAt: "2026-09-04T12:00:00.000000Z",
    leaseExpiresAt: "2026-09-04T12:00:30.000000Z"
  };
}

describe("backup worker orchestration", () => {
  it("requests the external operator and verifies content-safe immutable receipt health", async () => {
    await withMigratedDatabase("backup-worker", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const config = parseConfig({
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: "postgresql://unused",
        BOARDAGENT_ORGANIZATION_ID: actor.organizationId,
        BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
        BOARDAGENT_AUTHORIZATION_MODE: "builtin",
        BOARDAGENT_BLOB_ROOT: "/tmp/boardagent-backup-worker-test",
        BOARDAGENT_DEV_MASTER_SECRET: "backup-worker-test-secret-material-is-long-enough"
      });
      const keys = await loadBoardAgentKeyMaterial(config);
      const binding: BoardAgentRuntimeBinding = {
        instanceId: testId(15),
        organizationId: actor.organizationId,
        canonicalResourceUri: "https://boardagent.test/mcp",
        keyIds: {
          oauth_signing: testId(8),
          evidence_signing: testId(81_001),
          browser_session: testId(81_002),
          data_kek: testId(81_003)
        },
        keyLocators: {
          oauth_signing: "test:oauth",
          evidence_signing: "test:evidence",
          browser_session: "test:browser",
          data_kek: "test:data"
        }
      };
      const alerts: { readonly alertClass: string; readonly details: JsonValue }[] = [];
      const handlers = new BoardAgentCoreWorkerHandlers(pool, {
        config,
        binding,
        keys,
        onOperationalAlert: (alertClass, details) => {
          alerts.push({ alertClass, details });
        },
        assumeRole: "boardagent_worker"
      }).handlers();
      expect(handlers.has("backup_trigger")).toBe(true);
      expect(handlers.has("backup_receipt_verify")).toBe(true);
      const verifyHandler = handlers.get("backup_receipt_verify")!;
      const triggerHandler = handlers.get("backup_trigger")!;
      const signal = new AbortController().signal;

      await expect(
        verifyHandler({
          job: organizationJob(actor, "backup_receipt_verify", testId(81_010)),
          signal
        })
      ).rejects.toMatchObject({
        errorClass: "backup_receipt_missing",
        permanent: false
      } satisfies Partial<TypedJobExecutionError>);
      expect(alerts.at(-1)?.alertClass).toBe("backup_receipt_missing");

      const oauthKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const backupKeyId = testId(81_020);
      await pool.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
        oauthKey.publicKey.export({ format: "jwk" }),
        testId(8)
      ]);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
         ) values ($1,$2,'backup-worker-key','backup_kek','A256GCM',null,
                   'sha256:'||repeat('a',64),transaction_timestamp()-interval '1 minute')`,
        [backupKeyId, actor.organizationId]
      );
      const boundary = await withBackupTransaction(
        pool,
        (client) =>
          captureBackupBoundaryInTransaction(client, {
            receiptId: testId(81_021),
            encryptionKeyId: backupKeyId,
            encryptionKeyFingerprintSha256: "a".repeat(64)
          }),
        { assumeRole: "boardagent_backup", statementTimeoutMs: 60_000 }
      );
      const manifest = finalizeBackupManifest(boundary, {
        format: "postgresql-custom-encrypted-v1",
        encryptedStorageLocator: "file:///operator/off-host/boardagent-worker-test.dump.age",
        artifactSha256: "ab".repeat(32),
        byteLength: "4096",
        pgDumpVersion: "pg_dump (PostgreSQL) 18.6",
        encryptionTool: "age 1.3.1",
        sourceImageDigest: `sha256:${"cd".repeat(32)}`
      });
      await withWorkerTransaction(
        pool,
        (client) =>
          recordBackupCompletedInTransaction(client, {
            manifest,
            auditEventId: testId(81_022)
          }),
        { assumeRole: "boardagent_worker" }
      );

      const healthy = await withWorkerTransaction(
        pool,
        (client) => inspectBackupReceiptHealthInTransaction(client, actor.organizationId),
        { assumeRole: "boardagent_worker" }
      );
      expect(healthy).toMatchObject({
        valid: true,
        issueClass: null,
        checkedReceipts: 1,
        backupReceipts: 1,
        restoreReceipts: 0,
        manifestHashMismatches: 0,
        manifestCanonicalMismatches: 0,
        manifestSchemaMismatches: 0,
        manifestBindingMismatches: 0,
        keyBindingMismatches: 0
      });
      await expect(
        verifyHandler({
          job: organizationJob(actor, "backup_receipt_verify", testId(81_011)),
          signal
        })
      ).resolves.toMatchObject({ valid: true, checkedReceipts: 1 });
      await expect(
        triggerHandler({ job: organizationJob(actor, "backup_trigger", testId(81_012)), signal })
      ).resolves.toMatchObject({ alertClass: "backup_trigger" });
      expect(alerts.at(-1)?.alertClass).toBe("backup_trigger");
      expect(JSON.stringify(alerts)).not.toContain(manifest.receiptId);

      await pool.query("alter table backup_receipts disable trigger boardagent_immutable");
      await pool.query(
        "update backup_receipts set canonical_manifest=set_byte(canonical_manifest,0,91) where id=$1",
        [manifest.receiptId]
      );
      await pool.query("alter table backup_receipts enable trigger boardagent_immutable");
      const corrupted = await withWorkerTransaction(
        pool,
        (client) => inspectBackupReceiptHealthInTransaction(client, actor.organizationId),
        { assumeRole: "boardagent_worker" }
      );
      expect(corrupted).toMatchObject({
        valid: false,
        issueClass: "manifest_hash_mismatch",
        manifestHashMismatches: 1
      });
      await expect(
        verifyHandler({
          job: organizationJob(actor, "backup_receipt_verify", testId(81_013)),
          signal
        })
      ).rejects.toMatchObject({
        errorClass: "backup_receipt_invalid",
        permanent: true
      } satisfies Partial<TypedJobExecutionError>);
      expect(alerts.at(-1)?.alertClass).toBe("backup_receipt_invalid");
      expect(JSON.stringify(alerts.at(-1)?.details)).not.toContain(manifest.receiptId);
    });
  });
});
