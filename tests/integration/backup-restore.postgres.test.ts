import { generateKeyPairSync } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { signCheckpoint } from "../../lib/audit/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  BackupManifestSchema,
  appendAuditEventsInTransaction,
  captureBackupBoundaryInTransaction,
  commitAuditCheckpointInTransaction,
  finalizeBackupManifest,
  migrate,
  prepareAuditCheckpointInTransaction,
  recordBackupCompletedInTransaction,
  recordRestoreVerifiedInTransaction,
  verifyRestoredBackupInTransaction,
  withBackupTransaction,
  withRequestTransaction,
  withRestoreTransaction,
  withWorkerTransaction,
  type BackupManifest,
  type RestoreReceiptManifest
} from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import { administrativeHistory } from "../helpers/administrative-history.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

function databaseUrl(database: string): string {
  const url = new URL(BASE_URL);
  url.pathname = `/${database}`;
  return url.toString();
}

function nextDatabaseName(label: string): string {
  databaseCounter += 1;
  return `boardagent_${label}_${String(process.pid)}_${String(databaseCounter)}`;
}

describe("encrypted backup boundary and isolated restore receipts", () => {
  for (const { label, corruption } of [
    {
      label:
        "verifies a complete clone, records immutable receipts and rejects corruption without repair",
      corruption: "organization"
    },
    {
      label:
        "AC22 restore verification retains admin history and rejects an altered delegation without repair",
      corruption: "delegation"
    }
  ] as const) {
    it(
      label,
      async () => {
        const sourceDatabase = nextDatabaseName("backup_source");
        const restoredDatabase = nextDatabaseName("restore_clean");
        const corruptDatabase = nextDatabaseName("restore_corrupt");
        const adminUrl = new URL(BASE_URL);
        adminUrl.pathname = "/postgres";
        const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
        await admin.query(`create database "${sourceDatabase}"`);
        const createdDatabases = [sourceDatabase];

        let source = new Pool({ connectionString: databaseUrl(sourceDatabase), max: 6 });
        let sourceClosed = false;
        let restored: Pool | undefined;
        let corrupt: Pool | undefined;
        let manifest: BackupManifest;
        let restoreManifest: RestoreReceiptManifest;
        try {
          await migrate(source, MIGRATIONS, "backup-restore-test");
          const history = await administrativeHistory(source);
          const actor = history.issuer;
          const oauthKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
          await source.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
            oauthKey.publicKey.export({ format: "jwk" }),
            testId(8)
          ]);

          const evidenceKey = generateKeyPairSync("ed25519");
          const evidenceKeyId = testId(31_000);
          const backupKeyId = testId(31_001);
          await source.query(
            `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
         ) values
           ($1,$3,'restore-evidence-1','evidence_signing','EdDSA',$4,
             'operator-evidence-test',transaction_timestamp()-interval '1 minute'),
           ($2,$3,'restore-backup-1','backup_kek','A256GCM',null,
             'sha256:'||repeat('a',64),transaction_timestamp()-interval '1 minute')`,
            [
              evidenceKeyId,
              backupKeyId,
              actor.organizationId,
              evidenceKey.publicKey.export({ format: "jwk" })
            ]
          );
          await withRequestTransaction(
            source,
            actor.context,
            (client) =>
              appendAuditEventsInTransaction(client, [
                {
                  organizationId: actor.organizationId,
                  event: {
                    eventId: testId(31_010),
                    eventType: "context_read",
                    actorMemberId: actor.memberId,
                    actorClientId: actor.clientId,
                    tokenJti: actor.tokenJti,
                    entityType: "context",
                    entityId: testId(31_011),
                    boardId: actor.boardId,
                    origin: "mcp",
                    details: { purpose: "backup-restore-fixture" },
                    schemaVersion: 1
                  }
                }
              ]),
            { assumeRole: "boardagent_server" }
          );
          const prepared = await withWorkerTransaction(
            source,
            (client) =>
              prepareAuditCheckpointInTransaction(client, {
                checkpointId: testId(31_020),
                signingKeyId: evidenceKeyId
              }),
            { assumeRole: "boardagent_worker" }
          );
          await withWorkerTransaction(
            source,
            (client) =>
              commitAuditCheckpointInTransaction(client, {
                checkpoint: signCheckpoint(prepared.payload, evidenceKey.privateKey),
                auditEventId: testId(31_021)
              }),
            { assumeRole: "boardagent_worker" }
          );

          for (const invalid of [
            { encryptionKeyId: testId(31_099), encryptionKeyFingerprintSha256: "a".repeat(64) },
            { encryptionKeyId: backupKeyId, encryptionKeyFingerprintSha256: "b".repeat(64) }
          ]) {
            await expect(
              withBackupTransaction(
                source,
                (client) =>
                  captureBackupBoundaryInTransaction(client, {
                    receiptId: testId(31_030),
                    ...invalid
                  }),
                { assumeRole: "boardagent_backup" }
              )
            ).rejects.toMatchObject({ code: "backup_key_invalid" });
          }
          const boundary = await withBackupTransaction(
            source,
            (client) =>
              captureBackupBoundaryInTransaction(client, {
                receiptId: testId(31_030),
                encryptionKeyId: backupKeyId,
                encryptionKeyFingerprintSha256: "a".repeat(64)
              }),
            { assumeRole: "boardagent_backup", statementTimeoutMs: 60_000 }
          );
          for (const table of [
            "company_admin_proposals",
            "member_admin_delegations",
            "administrative_authority_changes"
          ]) {
            expect(boundary.tableInventory.find((entry) => entry.table === table)?.rowCount).toBe(
              table === "company_admin_proposals"
                ? "2"
                : table === "member_admin_delegations"
                  ? "1"
                  : "4"
            );
          }
          manifest = finalizeBackupManifest(boundary, {
            format: "postgresql-custom-encrypted-v1",
            encryptedStorageLocator: "file:///operator/off-host/boardagent-test.dump.age",
            artifactSha256: "ab".repeat(32),
            byteLength: "4096",
            pgDumpVersion: "pg_dump (PostgreSQL) 18.6",
            encryptionTool: "age 1.3.1",
            sourceImageDigest: `sha256:${"cd".repeat(32)}`
          });
          const {
            encryptionKeyFingerprintSha256: fingerprint,
            encryptionKeyActivatedAt: activatedAt,
            ...legacy
          } = manifest;
          expect(BackupManifestSchema.safeParse(legacy).success).toBe(true);
          expect(
            BackupManifestSchema.safeParse({ ...legacy, encryptionKeyActivatedAt: activatedAt })
              .success
          ).toBe(false);
          expect(
            BackupManifestSchema.safeParse({
              ...legacy,
              encryptionKeyFingerprintSha256: fingerprint
            }).success
          ).toBe(false);
          const {
            encryptionKeyFingerprintSha256: _fingerprint,
            encryptionKeyActivatedAt: _activatedAt,
            ...legacyBoundary
          } = boundary;
          expect(() => finalizeBackupManifest(legacyBoundary, manifest.artifact)).toThrow(
            "new backups require a registered key fingerprint"
          );

          await source.end();
          sourceClosed = true;
          await admin.query(`create database "${restoredDatabase}" template "${sourceDatabase}"`);
          createdDatabases.push(restoredDatabase);
          await admin.query(`create database "${corruptDatabase}" template "${sourceDatabase}"`);
          createdDatabases.push(corruptDatabase);
          source = new Pool({ connectionString: databaseUrl(sourceDatabase), max: 6 });
          sourceClosed = false;

          const backupReceipt = await withWorkerTransaction(
            source,
            (client) =>
              recordBackupCompletedInTransaction(client, {
                manifest,
                auditEventId: testId(31_031)
              }),
            { assumeRole: "boardagent_worker" }
          );
          expect(backupReceipt).toMatchObject({
            receiptId: manifest.receiptId,
            manifestSha256: canonicalSha256(manifest),
            replayed: false,
            auditEventId: testId(31_031)
          });
          expect(
            await withWorkerTransaction(
              source,
              (client) =>
                recordBackupCompletedInTransaction(client, {
                  manifest,
                  auditEventId: testId(31_032)
                }),
              { assumeRole: "boardagent_worker" }
            )
          ).toMatchObject({ replayed: true });

          restored = new Pool({ connectionString: databaseUrl(restoredDatabase), max: 3 });
          const restoredVerification = await withRestoreTransaction(
            restored,
            (client) =>
              verifyRestoredBackupInTransaction(client, {
                sourceManifest: manifest,
                sourceBackupReceiptId: manifest.receiptId,
                sourceBackupManifestSha256: canonicalSha256(manifest),
                restoreReceiptId: testId(31_040)
              }),
            { assumeRole: "boardagent_backup", statementTimeoutMs: 60_000 }
          );
          expect(restoredVerification.valid).toBe(true);
          expect(
            (
              await restored.query(
                "select state,row_version::text from member_admin_delegations where id=$1",
                [history.input.change.delegation_id]
              )
            ).rows
          ).toEqual([{ state: "revoked", row_version: "2" }]);
          expect(
            (
              await restored.query(
                "select count(*)::int as n from administrative_authority_changes"
              )
            ).rows[0]?.n
          ).toBe(4);
          for (const role of ["boardagent_server", "boardagent_worker"])
            expect(
              (
                await restored.query(
                  "select has_table_privilege($1,'member_admin_delegations','SELECT,INSERT,UPDATE,DELETE') as allowed",
                  [role]
                )
              ).rows[0]?.allowed
            ).toBe(false);
          if (!restoredVerification.valid) throw new Error("clean restore unexpectedly failed");
          restoreManifest = restoredVerification.receiptManifest;
          expect(restoreManifest).toMatchObject({
            sourceDatabase,
            restoredDatabase,
            sourceBackupReceiptId: manifest.receiptId,
            contentSetSha256: manifest.contentSetSha256,
            verification: {
              transactionReadOnly: true,
              evidenceRepaired: false,
              failures: []
            }
          });
          const restoreReceipt = await withWorkerTransaction(
            source,
            (client) =>
              recordRestoreVerifiedInTransaction(client, {
                manifest: restoreManifest,
                auditEventId: testId(31_041)
              }),
            { assumeRole: "boardagent_worker" }
          );
          expect(restoreReceipt).toMatchObject({
            receiptId: restoreManifest.receiptId,
            replayed: false,
            auditEventId: testId(31_041)
          });
          const persisted = await source.query<{
            receipt_kind: string;
            state: string;
            source_backup_receipt_id: string | null;
          }>(
            "select receipt_kind,state,source_backup_receipt_id from backup_receipts order by created_at,id"
          );
          expect(persisted.rows).toEqual([
            { receipt_kind: "backup", state: "created", source_backup_receipt_id: null },
            {
              receipt_kind: "restore",
              state: "verified",
              source_backup_receipt_id: manifest.receiptId
            }
          ]);
          await expect(
            source.query("update backup_receipts set state='failed' where id=$1", [
              manifest.receiptId
            ])
          ).rejects.toThrow(/immutable evidence/u);

          corrupt = new Pool({ connectionString: databaseUrl(corruptDatabase), max: 3 });
          if (corruption === "organization")
            await corrupt.query("update organizations set display_name='Corrupted clone'");
          else {
            await corrupt.query(
              "alter table member_admin_delegations disable trigger boardagent_member_admin_delegation_transition"
            );
            try {
              await corrupt.query(
                "update member_admin_delegations set reason='Altered restored delegation' where id=$1",
                [history.input.change.delegation_id]
              );
            } finally {
              await corrupt.query(
                "alter table member_admin_delegations enable trigger boardagent_member_admin_delegation_transition"
              );
            }
          }
          const inspectCorruption =
            corruption === "organization"
              ? "select display_name from organizations"
              : "select reason from member_admin_delegations";
          const before = await corrupt.query(inspectCorruption);
          const corruptVerification = await withRestoreTransaction(
            corrupt,
            (client) =>
              verifyRestoredBackupInTransaction(client, {
                sourceManifest: manifest,
                sourceBackupReceiptId: manifest.receiptId,
                sourceBackupManifestSha256: canonicalSha256(manifest),
                restoreReceiptId: testId(31_050)
              }),
            { assumeRole: "boardagent_backup", statementTimeoutMs: 60_000 }
          );
          expect(corruptVerification).toMatchObject({ valid: false, ready: false });
          if (corruptVerification.valid) throw new Error("corrupt restore unexpectedly passed");
          expect(corruptVerification.failures).toEqual(
            expect.arrayContaining(["content_set_mismatch", "table_content_mismatch"])
          );
          const after = await corrupt.query(inspectCorruption);
          expect(after.rows).toEqual(before.rows);
          expect(
            await corrupt.query("select count(*)::text as count from backup_receipts")
          ).toMatchObject({ rows: [{ count: "0" }] });
        } finally {
          try {
            await Promise.all([
              ...(sourceClosed ? [] : [source.end()]),
              restored?.end(),
              corrupt?.end()
            ]);
            for (const database of createdDatabases.toReversed()) {
              await dropClosedTestDatabase(admin, database);
            }
          } finally {
            await admin.end();
          }
        }
      },
      30_000
    );
  }
});
