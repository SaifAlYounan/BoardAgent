import { randomBytes } from "node:crypto";
import path from "node:path";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  type BackupManifest,
  captureBackupBoundaryInTransaction,
  finalizeBackupManifest,
  migrate,
  recordBackupCompletedInTransaction,
  recordRestoreVerifiedInTransaction,
  verifyRestoredBackupInTransaction,
  withBackupTransaction,
  withRestoreTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedRecoveredAudit } from "../helpers/recovered-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

// A database clone tests evidence verification and receipt persistence. Actual encrypted
// pg_dump/pg_restore remains separately required in the operations tier.
describe("recovery evidence in isolated restored databases", () => {
  it("retains the finding, refuses a downgraded or altered manifest and preserves immutable receipt lineage", async () => {
    const base = new URL(
      process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
        "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent"
    );
    const suffix = `${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    const sourceName = `boardagent_recovery_source_${suffix}`;
    const restoredName = `boardagent_recovery_restored_${suffix}`;
    const url = (name: string) => {
      const result = new URL(base);
      result.pathname = `/${name}`;
      return result.toString();
    };
    const admin = new Pool({ connectionString: url("postgres"), max: 1 });
    const created: string[] = [];
    let source: Pool | undefined, restored: Pool | undefined;
    try {
      await admin.query(`create database "${sourceName}"`);
      created.push(sourceName);
      source = new Pool({ connectionString: url(sourceName), max: 4 });
      await migrate(
        source,
        path.resolve(import.meta.dirname, "../../lib/db/migrations"),
        "recovered-clone-test"
      );
      const fixture = await seedRecoveredAudit(source);
      const keyId = testId(113_000);
      await source.query(
        `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,nonsecret_locator,activated_at)
        values($1,$2,'recovery-restore-backup','backup_kek','A256GCM',$3,transaction_timestamp()-interval '1 minute')`,
        [keyId, fixture.actor.organizationId, `sha256:${"ab".repeat(32)}`]
      );
      const boundary = await withBackupTransaction(
        source,
        (client) =>
          captureBackupBoundaryInTransaction(client, {
            receiptId: testId(113_001),
            encryptionKeyId: keyId,
            encryptionKeyFingerprintSha256: "ab".repeat(32)
          }),
        { assumeRole: "boardagent_backup", statementTimeoutMs: 60000 }
      );
      const manifest = finalizeBackupManifest(boundary, {
        format: "postgresql-custom-encrypted-v1",
        encryptedStorageLocator: "file:///synthetic/clone.dump.enc",
        artifactSha256: "cd".repeat(32),
        byteLength: "4096",
        pgDumpVersion: "pg_dump (PostgreSQL) 18.6",
        encryptionTool: "synthetic metadata; this test uses a PostgreSQL clone",
        sourceImageDigest: `sha256:${"ef".repeat(32)}`
      });
      if (manifest.schemaVersion !== "boardagent.backup-receipt.v2")
        throw new Error("missing recovery finding");
      await source.end();
      source = undefined;
      await admin.query(`create database "${restoredName}" template "${sourceName}"`);
      created.push(restoredName);
      source = new Pool({ connectionString: url(sourceName), max: 4 });
      restored = new Pool({ connectionString: url(restoredName), max: 4 });
      const original = (
        await restored.query(
          "select canonical_manifest,signature from audit_checkpoints order by first_sequence"
        )
      ).rows;
      const verify = (sourceManifest: BackupManifest) =>
        withRestoreTransaction(
          restored!,
          (client) =>
            verifyRestoredBackupInTransaction(client, {
              sourceManifest,
              sourceBackupReceiptId: manifest.receiptId,
              sourceBackupManifestSha256: canonicalSha256(sourceManifest),
              restoreReceiptId: testId(113_003)
            }),
          { assumeRole: "boardagent_backup", statementTimeoutMs: 60000 }
        );
      const verified = await verify(manifest);
      expect(verified).toMatchObject({
        valid: true,
        ready: true,
        receiptManifest: {
          schemaVersion: "boardagent.restore-receipt.v2",
          auditRecoveryEvidence: manifest.auditRecoveryEvidence
        }
      });
      const { auditRecoveryEvidence: _evidence, ...legacy } = manifest;
      const altered = structuredClone(manifest);
      altered.auditRecoveryEvidence[0]!.signatureBase64Url = "a".repeat(86);
      for (const invalid of [
        { ...legacy, schemaVersion: "boardagent.backup-receipt.v1" as const },
        altered
      ])
        expect(await verify(invalid)).toMatchObject({
          valid: false,
          ready: false,
          failures: expect.arrayContaining(["audit_recovery_evidence_mismatch"])
        });
      expect(
        (
          await restored.query(
            "select canonical_manifest,signature from audit_checkpoints order by first_sequence"
          )
        ).rows
      ).toEqual(original);
      if (!verified.valid) throw new Error("restored evidence did not verify");
      await withWorkerTransaction(
        source,
        (client) =>
          recordBackupCompletedInTransaction(client, {
            manifest,
            auditEventId: testId(113_002)
          }),
        { assumeRole: "boardagent_worker" }
      );
      const restoredManifest = verified.receiptManifest;
      if (restoredManifest.schemaVersion !== "boardagent.restore-receipt.v2")
        throw new Error("missing restored finding");
      const { auditRecoveryEvidence: _restoredEvidence, ...legacyRestore } = restoredManifest;
      await expect(
        withWorkerTransaction(
          source,
          (client) =>
            recordRestoreVerifiedInTransaction(client, {
              manifest: { ...legacyRestore, schemaVersion: "boardagent.restore-receipt.v1" },
              auditEventId: testId(113_004)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      await expect(
        withWorkerTransaction(
          source,
          (client) =>
            recordRestoreVerifiedInTransaction(client, {
              manifest: restoredManifest,
              auditEventId: testId(113_005)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).resolves.toMatchObject({ replayed: false });
      const health = await withWorkerTransaction(
        source,
        (client) =>
          client.query("select * from boardagent_backup_receipt_health($1)", [
            fixture.actor.organizationId
          ]),
        { assumeRole: "boardagent_worker" }
      );
      expect(health.rows[0]).toMatchObject({
        checked_receipts: "2",
        manifest_schema_mismatches: "0",
        manifest_binding_mismatches: "0",
        key_binding_mismatches: "0"
      });
      await expect(
        source.query("update audit_recoveries set authorizing_principal='changed'")
      ).rejects.toMatchObject({ code: "55000" });
      await expect(source.query("delete from audit_recovery_completions")).rejects.toMatchObject({
        code: "55000"
      });
    } finally {
      await Promise.all([source?.end(), restored?.end()]);
      for (const name of created.toReversed()) await dropClosedTestDatabase(admin, name);
      await admin.end();
    }
  }, 30_000);
});
