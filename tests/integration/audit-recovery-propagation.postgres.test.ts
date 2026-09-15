import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  LocalExportArtifactStore,
  decryptExportEnvelope
} from "../../artifacts/server/src/export-artifact-store.js";
import { verifyOfflineAuditExport, signAuditExportAttestation } from "../../lib/audit/src/index.js";
import { fixtureExportAttestation } from "../helpers/export-attestation-fixture.js";
import { describe, expect, it } from "vitest";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  buildFrozenExportSnapshotInTransaction,
  captureBackupBoundaryInTransaction,
  finalizeBackupManifest,
  recordBackupCompletedInTransaction,
  withBackupTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedRecoveredAudit } from "../helpers/recovered-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("permanent recovery findings in exported records", () => {
  it.each(["audit_chain", "system_data"] as const)(
    "keeps signed recovery evidence in a scoped %s snapshot after ordinary signing resumes",
    async (exportType) => {
      await withMigratedDatabase(`recovery-export-${exportType}`, async (pool) => {
        const fixture = await seedRecoveredAudit(pool);
        const common = {
          schemaVersion: "boardagent.export-scope.v1" as const,
          exportType,
          organizationId: fixture.actor.organizationId,
          boardId: null
        };
        const scope =
          exportType === "audit_chain"
            ? {
                ...common,
                firstSequence: "3",
                lastSequence: "3",
                includeCheckpoints: true,
                includePublicKeys: true
              }
            : {
                ...common,
                scope: "organization",
                memberId: null,
                purpose: "Synthetic scoped export of governance records.",
                dataClasses: ["governance"],
                includeCanonicalContent: true,
                excludeSecretMaterial: true
              };
        // A queued-request fixture isolates real worker snapshot construction. This is
        // not evidence that a human consented or a client completed the request ceremony.
        await pool.query(
          `insert into export_requests(id,public_id,organization_id,board_id,requester_member_id,export_type,
        scope_manifest,scope_sha256,state,consent_record_id,recent_auth_at,expires_at)
        values($1,$2,$3,null,$4,$5,$6,$7,'queued',$8,transaction_timestamp(),transaction_timestamp()+interval '1 hour')`,
          [
            testId(111_000),
            Buffer.alloc(32, 111),
            fixture.actor.organizationId,
            fixture.actor.memberId,
            exportType,
            Buffer.from(canonicalJson(scope)),
            Buffer.from(canonicalSha256(scope), "hex"),
            fixture.actor.consentRecordId
          ]
        );
        const frozen = await withWorkerTransaction(
          pool,
          (client) =>
            buildFrozenExportSnapshotInTransaction(client, {
              exportRequestId: testId(111_000),
              exportStartedAuditEventId: testId(111_001)
            }),
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        );
        expect(frozen.snapshot).toMatchObject({
          schemaVersion: "boardagent.export-snapshot.v2",
          auditRecoveryEvidence: [
            {
              payload: {
                schema: "boardagent.audit.recovery-checkpoint.v1",
                recovery: {
                  requestSha256: fixture.proposal.requestSha256,
                  request: { recoveryId: fixture.receipt.recoveryId }
                }
              }
            }
          ]
        });
        const root = await mkdtemp(path.join(tmpdir(), "boardagent-recovered-export-"));
        try {
          const store = new LocalExportArtifactStore(root, {
            maximumArtifactBytes: 10_485_760,
            chunkBytes: 65_536
          });
          const encryptionKey = Buffer.alloc(32, 111);
          let chunkId = 112_000;
          const auditAttestation =
            exportType === "audit_chain"
              ? fixtureExportAttestation(
                  frozen,
                  fixture.evidence.privateKey,
                  fixture.keyId,
                  "recovery-evidence"
                )
              : undefined;
          const artifact = await store.publish({
            frozen,
            ...(auditAttestation === undefined ? {} : { auditAttestation }),
            artifactId: testId(112_900),
            encryptionKeyId: testId(112_901),
            encryptionKey,
            newChunkId: () => testId(chunkId++)
          });
          const encrypted = Buffer.concat(
            await Promise.all(
              artifact.chunks.map(async (chunk) =>
                Buffer.from(
                  await store.readExactChunk({
                    exportRequestId: artifact.exportRequestId,
                    artifactId: artifact.artifactId,
                    ordinal: chunk.ordinal,
                    storageLocator: chunk.storageLocator,
                    byteLength: chunk.byteLength,
                    expectedSha256: chunk.chunkSha256
                  })
                )
              )
            )
          );
          const decrypted = decryptExportEnvelope(encrypted, encryptionKey);
          expect(decrypted.snapshot).toEqual(frozen.snapshot);
          if (decrypted.scope.exportType === "audit_chain") {
            if (
              decrypted.snapshot.schemaVersion !== "boardagent.export-snapshot.v2" ||
              decrypted.auditAttestation?.payload.schemaVersion !==
                "boardagent.audit-export-attestation.v2"
            )
              throw new Error("missing versioned recovery evidence");
            const events = decrypted.components.find((c) => c.name === "audit:events")!.bytes;
            const checkpoints = decrypted.components.find(
              (c) => c.name === "audit:checkpoints"
            )!.bytes;
            const expected = {
              organizationId: decrypted.snapshot.organizationId,
              boardId: null,
              rangeFirstSequence: "3",
              rangeLastSequence: "3",
              auditHeadSequence: decrypted.snapshot.auditHeadSequence,
              auditHeadSha256: decrypted.snapshot.auditHeadSha256,
              latestCheckpointSha256: decrypted.snapshot.latestCheckpointSha256
            };
            const trusted = {
              schema_version: "boardagent.trusted-evidence-keys.v1",
              keys: [
                {
                  id: fixture.keyId,
                  kid: "recovery-evidence",
                  algorithm: "EdDSA",
                  public_jwk: fixture.evidence.publicKey.export({ format: "jwk" })
                }
              ]
            };
            const context = {
              signed: decrypted.auditAttestation,
              exportRequestId: frozen.exportRequestId,
              scopeSha256: frozen.snapshot.scopeSha256,
              snapshotSha256: frozen.snapshotSha256,
              auditRecoveryEvidence: decrypted.snapshot.auditRecoveryEvidence
            };
            expect(
              verifyOfflineAuditExport(events, checkpoints, expected, trusted, context)
            ).toMatchObject({
              valid: true,
              proof: "signed_export_snapshot",
              warnings: [
                `recovery:${fixture.receipt.recoveryId}:historical_checkpoint_deadline_missed`
              ],
              recoveryEvidence: context.auditRecoveryEvidence
            });
            expect(
              verifyOfflineAuditExport(events, checkpoints, expected, trusted, {
                ...context,
                auditRecoveryEvidence: []
              })
            ).toMatchObject({ valid: false });
            const { auditRecoveryEvidence: _evidence, ...legacyPayload } =
              decrypted.auditAttestation.payload;
            const downgraded = signAuditExportAttestation(
              { ...legacyPayload, schemaVersion: "boardagent.audit-export-attestation.v1" },
              fixture.evidence.privateKey
            );
            expect(
              verifyOfflineAuditExport(events, checkpoints, expected, trusted, {
                ...context,
                signed: downgraded,
                auditRecoveryEvidence: []
              })
            ).toMatchObject({
              valid: false,
              reason: "export_recovery_evidence_binding_mismatch"
            });
            const corrupted = structuredClone(context);
            corrupted.auditRecoveryEvidence[0]!.signatureBase64Url = "a".repeat(86);
            expect(
              verifyOfflineAuditExport(events, checkpoints, expected, trusted, corrupted)
            ).toMatchObject({ valid: false });
          }
        } finally {
          await rm(root, { recursive: true, force: true });
        }
        if (exportType === "system_data")
          expect(frozen.components.some((component) => component.name === "audit:events")).toBe(
            false
          );
      });
    }
  );

  it("records the missed-deadline evidence in the backup manifest even when its latest checkpoint is ordinary", async () => {
    await withMigratedDatabase("recovery-backup", async (pool) => {
      const fixture = await seedRecoveredAudit(pool);
      const keyId = testId(111_100);
      await pool.query(
        `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,nonsecret_locator,activated_at)
        values($1,$2,'recovery-backup','backup_kek','A256GCM',$3,transaction_timestamp()-interval '1 minute')`,
        [keyId, fixture.actor.organizationId, `sha256:${"ab".repeat(32)}`]
      );
      const boundary = await withBackupTransaction(
        pool,
        (client) =>
          captureBackupBoundaryInTransaction(client, {
            receiptId: testId(111_101),
            encryptionKeyId: keyId,
            encryptionKeyFingerprintSha256: "ab".repeat(32)
          }),
        { assumeRole: "boardagent_backup", statementTimeoutMs: 60000 }
      );
      expect(boundary).toMatchObject({
        schemaVersion: "boardagent.backup-receipt.v2",
        auditRecoveryEvidence: [
          {
            payload: {
              schema: "boardagent.audit.recovery-checkpoint.v1",
              recovery: {
                requestSha256: fixture.proposal.requestSha256,
                request: { recoveryId: fixture.receipt.recoveryId }
              }
            }
          }
        ]
      });
      const manifest = finalizeBackupManifest(boundary, {
        format: "postgresql-custom-encrypted-v1",
        encryptedStorageLocator: "file:///synthetic/recovery.dump.enc",
        artifactSha256: "cd".repeat(32),
        byteLength: "4096",
        pgDumpVersion: "pg_dump (PostgreSQL) 18.6",
        encryptionTool: "synthetic artifact metadata; no pg_dump run in this case",
        sourceImageDigest: `sha256:${"ef".repeat(32)}`
      });
      if (manifest.schemaVersion !== "boardagent.backup-receipt.v2")
        throw new Error("expected recovery backup");
      const { auditRecoveryEvidence: _recovery, ...legacy } = manifest;
      // Recomputed outer hashes cannot erase the finding at the retained audit boundary.
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            recordBackupCompletedInTransaction(client, {
              manifest: { ...legacy, schemaVersion: "boardagent.backup-receipt.v1" },
              auditEventId: testId(111_103)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      const altered = structuredClone(manifest);
      altered.auditRecoveryEvidence[0]!.signatureBase64Url = "a".repeat(86);
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            recordBackupCompletedInTransaction(client, {
              manifest: altered,
              auditEventId: testId(111_104)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      // This checks receipt persistence, not actual backup file creation or restore.
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            recordBackupCompletedInTransaction(client, {
              manifest,
              auditEventId: testId(111_102)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).resolves.toMatchObject({ replayed: false });
      const health = await withWorkerTransaction(
        pool,
        (client) =>
          client.query("select * from boardagent_backup_receipt_health($1)", [
            fixture.actor.organizationId
          ]),
        { assumeRole: "boardagent_worker" }
      );
      expect(health.rows[0]).toMatchObject({
        checked_receipts: "1",
        manifest_hash_mismatches: "0",
        manifest_schema_mismatches: "0",
        manifest_binding_mismatches: "0",
        key_binding_mismatches: "0"
      });
    });
  });
});
