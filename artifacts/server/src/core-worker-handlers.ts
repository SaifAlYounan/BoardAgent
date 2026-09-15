import { createPublicKey, randomBytes as nodeRandomBytes, type JsonWebKey } from "node:crypto";

import {
  issueVoteCertificate,
  signCheckpoint,
  signAuditExportAttestation,
  verifyAuditExportAttestation
} from "@boardagent/audit";
import type { BoardAgentConfig } from "@boardagent/config";
import { Rfc3339UtcSchema, canonicalSha256, type JsonValue } from "@boardagent/contracts";
import {
  buildFrozenExportSnapshotInTransaction,
  claimExportArtifactCleanupInTransaction,
  commitAuditCheckpointInTransaction,
  completeExportArtifactCleanupInTransaction,
  completeExportBuildInTransaction,
  FeedProjectionConsistencyError,
  failExportBuildInTransaction,
  failQueuedExportBuildInTransaction,
  failStoppedQueuedExportsInTransaction,
  finalizeVoteCloseInTransaction,
  initiateAutomaticVoteCloseInTransaction,
  inspectExportReconcileTargetInTransaction,
  inspectBackupReceiptHealthInTransaction,
  inspectFeedConsistencyInTransaction,
  markDueBoardQuestionsOverdueInTransaction,
  prepareAutomaticVoteCloseInTransaction,
  prepareAuditCheckpointInTransaction,
  prepareVoteCertificateRecoveryInTransaction,
  projectDueActionItemsInTransaction,
  projectDueTasksInTransaction,
  readDatabaseClockInTransaction,
  reconcileFeedEntitlementsInTransaction,
  reapExpiredJobLeasesInTransaction,
  releaseExportArtifactCleanupInTransaction,
  recordClockHealthInTransaction,
  runOperationalRetentionInTransaction,
  runWorkerMaintenanceInTransaction,
  scheduleDueAutomaticVoteClosesInTransaction,
  settleReconciledExportBuildJobsInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction,
  VoteCloseTransactionError,
  type ExportArtifactManifest,
  type OperationalRetentionInput,
  type WorkerMaintenanceInput
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import type { Pool } from "pg";

import type { BoardAgentWorkerKeyMaterial } from "./key-material.js";
import type { LocalExportArtifactStore } from "./export-artifact-store.js";
import type { BoardAgentRuntimeBinding } from "./runtime-binding.js";
import { TypedJobExecutionError, type TypedJobHandler, type TypedJobType } from "./worker.js";

type MaintenanceJobType = WorkerMaintenanceInput["jobType"];
type OperationalRetentionJobType = OperationalRetentionInput["jobType"];

export const CORE_WORKER_JOB_TYPES = [
  "action_due_scan",
  "action_stage_expiry",
  "audit_checkpoint",
  "audit_verify",
  "automatic_vote_close",
  "backup_receipt_verify",
  "backup_trigger",
  "certificate_recovery",
  "clock_health",
  "compatibility_alert",
  "dependency_compatibility_alert",
  "export_artifact_expiry",
  "export_build",
  "export_reconcile",
  "feed_consistency_check",
  "feed_reconcile",
  "job_lease_reaper",
  "job_retention",
  "key_compatibility_alert",
  "log_retention",
  "oauth_ephemera_expiry",
  "protocol_compatibility_alert",
  "question_due_scan",
  "rate_bucket_retention",
  "refresh_session_revocation",
  "restore_due_alert",
  "task_due_scan",
  "vote_deadline_scan",
  "wizard_expiry"
] as const satisfies readonly TypedJobType[];

const OPERATIONAL_ALERT_JOB_TYPES = new Set<TypedJobType>([
  "backup_trigger",
  "compatibility_alert",
  "dependency_compatibility_alert",
  "key_compatibility_alert",
  "protocol_compatibility_alert",
  "restore_due_alert"
]);

export interface CoreWorkerHandlersOptions {
  readonly config: BoardAgentConfig;
  readonly binding: BoardAgentRuntimeBinding;
  readonly keys: BoardAgentWorkerKeyMaterial;
  readonly newId?: () => string;
  readonly now?: () => Date;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly onOperationalAlert?: (alertClass: string, details: JsonValue) => void | Promise<void>;
  readonly exportArtifacts?: Pick<
    LocalExportArtifactStore,
    | "publish"
    | "deleteArtifact"
    | "deletePartialArtifact"
    | "restoreManifestMarker"
    | "scanArtifacts"
  >;
  /** Test/local-owner seam only. Production connects as boardagent_worker directly. */
  readonly assumeRole?: "boardagent_worker";
}

/** Real database-owned handlers for the core clock, evidence, lease, and expiry jobs. */
export class BoardAgentCoreWorkerHandlers {
  private readonly newId: () => string;
  private readonly now: () => Date;
  private readonly entropy: (length: number) => Buffer;
  private readonly assumeRole: "boardagent_worker" | undefined;

  public constructor(
    private readonly pool: Pool,
    private readonly options: CoreWorkerHandlersOptions
  ) {
    this.newId = options.newId ?? (() => uuidV7(Date.now(), nodeRandomBytes(10)));
    this.now = options.now ?? (() => new Date());
    const randomBytes = options.randomBytes ?? nodeRandomBytes;
    this.entropy = (length) => {
      const bytes = Buffer.from(randomBytes(length));
      if (bytes.length !== length) throw new Error("worker entropy source returned wrong length");
      return bytes;
    };
    this.assumeRole = options.assumeRole;
    if (
      options.binding.organizationId !== options.config.organizationId ||
      options.binding.keyIds.evidence_signing === options.binding.keyIds.oauth_signing
    ) {
      throw new Error("worker runtime binding is inconsistent");
    }
  }

  private transaction<T>(
    run: Parameters<typeof withWorkerTransaction<T>>[1],
    options: { readonly isolation?: "read committed" | "repeatable read" | "serializable" } = {}
  ): Promise<T> {
    return withWorkerTransaction(this.pool, run, {
      ...options,
      ...(this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole })
    });
  }

  private assertOrganization(organizationId: string): void {
    if (organizationId !== this.options.binding.organizationId) {
      throw new TypedJobExecutionError("worker_organization_mismatch", true);
    }
  }

  private assertLease(signal: AbortSignal): void {
    if (signal.aborted) throw new TypedJobExecutionError("worker_lease_lost", false);
  }

  private operationalAlertDetails(
    jobId: string,
    alertClass: string,
    extra: Readonly<Record<string, JsonValue>> = {}
  ): JsonValue {
    return {
      schemaVersion: "boardagent.operational-alert.v1",
      alertJobRef: canonicalSha256({
        schemaVersion: "boardagent.operational-reference.v1",
        kind: "job",
        id: jobId
      }),
      alertClass,
      organizationRef: canonicalSha256({
        schemaVersion: "boardagent.operational-reference.v1",
        kind: "organization",
        id: this.options.binding.organizationId
      }),
      ...extra
    };
  }

  private async sendOperationalAlert(
    jobId: string,
    alertClass: string,
    extra: Readonly<Record<string, JsonValue>> = {}
  ): Promise<void> {
    if (!this.options.onOperationalAlert) {
      throw new TypedJobExecutionError("operational_alert_unavailable", false);
    }
    try {
      await this.options.onOperationalAlert(
        alertClass,
        this.operationalAlertDetails(jobId, alertClass, extra)
      );
    } catch {
      throw new TypedJobExecutionError("operational_alert_delivery_failed", false);
    }
  }

  private async tryOperationalAlert(
    jobId: string,
    alertClass: string,
    extra: Readonly<Record<string, JsonValue>> = {}
  ): Promise<void> {
    if (!this.options.onOperationalAlert) return;
    try {
      await this.options.onOperationalAlert(
        alertClass,
        this.operationalAlertDetails(jobId, alertClass, extra)
      );
    } catch {
      // The owning job already fails/retries on the underlying health condition.
    }
  }

  private throwVoteFailure(error: unknown): never {
    if (error instanceof VoteCloseTransactionError) {
      const permanent =
        error.code === "vote_close_invalid" ||
        error.code === "vote_close_integrity_failure" ||
        error.code === "idempotency_conflict";
      throw new TypedJobExecutionError(error.code, permanent);
    }
    throw error;
  }

  private maintenance(jobType: MaintenanceJobType): TypedJobHandler {
    return async ({ job }) => {
      if (job.envelope.jobType !== jobType) {
        throw new TypedJobExecutionError("maintenance_job_type_mismatch", true);
      }
      this.assertOrganization(job.envelope.organizationId);
      const result = await this.transaction((client) =>
        runWorkerMaintenanceInTransaction(client, {
          jobType,
          organizationId: job.envelope.organizationId,
          limit: 100
        })
      );
      return { ...result };
    };
  }

  private operationalRetention(jobType: OperationalRetentionJobType): TypedJobHandler {
    return async ({ job }) => {
      if (job.envelope.jobType !== jobType) {
        throw new TypedJobExecutionError("operational_retention_job_type_mismatch", true);
      }
      this.assertOrganization(job.envelope.organizationId);
      const result = await this.transaction((client) =>
        runOperationalRetentionInTransaction(client, {
          jobType,
          organizationId: job.envelope.organizationId,
          limit: 100
        })
      );
      return { ...result };
    };
  }

  private readonly feedReconcile: TypedJobHandler = async ({ job, signal }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "feed_reconcile") {
      throw new TypedJobExecutionError("feed_reconcile_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.boardId === null || envelope.subjectId !== envelope.parameters.memberId) {
      throw new TypedJobExecutionError("feed_reconcile_binding_mismatch", true);
    }
    try {
      const reconciled = await this.transaction(
        async (client) => {
          let total = 0;
          for (;;) {
            this.assertLease(signal);
            const batch = await reconcileFeedEntitlementsInTransaction(client, {
              organizationId: envelope.organizationId,
              boardId: envelope.boardId!,
              memberId: envelope.parameters.memberId,
              newId: this.newId,
              limit: 1_000
            });
            total += batch.reconciled;
            if (!batch.hasMore) return total;
          }
        },
        { isolation: "serializable" }
      );
      return { reconciled };
    } catch (error) {
      if (error instanceof FeedProjectionConsistencyError) {
        await this.tryOperationalAlert(job.jobId, "feed_reconciliation_inconsistent", {
          issueClass: error.issueClass
        });
        throw new TypedJobExecutionError("feed_reconciliation_inconsistent", true);
      }
      throw error;
    }
  };

  private readonly feedConsistencyCheck: TypedJobHandler = async ({ job, signal }) => {
    if (job.envelope.jobType !== "feed_consistency_check") {
      throw new TypedJobExecutionError("feed_consistency_type_mismatch", true);
    }
    this.assertOrganization(job.envelope.organizationId);
    this.assertLease(signal);
    const result = await this.transaction(
      (client) => inspectFeedConsistencyInTransaction(client, job.envelope.organizationId),
      { isolation: "repeatable read" }
    );
    this.assertLease(signal);
    if (!result.valid) {
      await this.tryOperationalAlert(job.jobId, "feed_consistency_invalid", {
        evidenceSha256: result.evidenceSha256,
        checkedFeedRows: result.checkedFeedRows,
        checkedTombstoneRows: result.checkedTombstoneRows,
        payloadHashMismatches: result.payloadHashMismatches,
        payloadCanonicalMismatches: result.payloadCanonicalMismatches,
        payloadBindingMismatches: result.payloadBindingMismatches,
        membershipStalePendingRows: result.membershipStalePendingRows,
        relationMismatches: result.relationMismatches
      });
      throw new TypedJobExecutionError("feed_consistency_invalid", true);
    }
    return { ...result };
  };

  private readonly backupReceiptVerify: TypedJobHandler = async ({ job, signal }) => {
    if (job.envelope.jobType !== "backup_receipt_verify") {
      throw new TypedJobExecutionError("backup_receipt_verify_type_mismatch", true);
    }
    this.assertOrganization(job.envelope.organizationId);
    this.assertLease(signal);
    const result = await this.transaction(
      (client) => inspectBackupReceiptHealthInTransaction(client, job.envelope.organizationId),
      { isolation: "repeatable read" }
    );
    this.assertLease(signal);
    if (!result.valid) {
      const alertClass =
        result.issueClass === "receipt_missing"
          ? "backup_receipt_missing"
          : result.issueClass === "backup_stale"
            ? "backup_receipt_stale"
            : "backup_receipt_invalid";
      await this.tryOperationalAlert(job.jobId, alertClass, {
        issueClass: result.issueClass,
        evidenceSha256: result.evidenceSha256,
        checkedReceipts: result.checkedReceipts,
        backupReceipts: result.backupReceipts,
        restoreReceipts: result.restoreReceipts,
        manifestHashMismatches: result.manifestHashMismatches,
        manifestCanonicalMismatches: result.manifestCanonicalMismatches,
        manifestSchemaMismatches: result.manifestSchemaMismatches,
        manifestBindingMismatches: result.manifestBindingMismatches,
        keyBindingMismatches: result.keyBindingMismatches,
        latestBackupAgeSeconds: result.latestBackupAgeSeconds
      });
      throw new TypedJobExecutionError(
        alertClass,
        result.issueClass !== "receipt_missing" && result.issueClass !== "backup_stale"
      );
    }
    return { ...result };
  };

  private readonly questionDueScan: TypedJobHandler = async ({ job }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "question_due_scan") {
      throw new TypedJobExecutionError("question_scan_job_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.boardId === null || envelope.boardId !== envelope.subjectId) {
      throw new TypedJobExecutionError("question_scan_board_mismatch", true);
    }
    const projections = await this.transaction((client) =>
      markDueBoardQuestionsOverdueInTransaction(client, {
        organizationId: envelope.organizationId,
        boardId: envelope.boardId!,
        through: envelope.parameters.through,
        limit: 100
      })
    );
    return { transitioned: projections.length };
  };

  private readonly actionDueScan: TypedJobHandler = async ({ job }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "action_due_scan") {
      throw new TypedJobExecutionError("action_due_scan_job_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.boardId === null || envelope.boardId !== envelope.subjectId) {
      throw new TypedJobExecutionError("action_due_scan_board_mismatch", true);
    }
    const projections = await this.transaction((client) =>
      projectDueActionItemsInTransaction(client, {
        organizationId: envelope.organizationId,
        boardId: envelope.boardId!,
        through: envelope.parameters.through,
        newId: this.newId,
        limit: 100
      })
    );
    return { projected: projections.length };
  };

  private readonly taskDueScan: TypedJobHandler = async ({ job }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "task_due_scan") {
      throw new TypedJobExecutionError("task_due_scan_job_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.boardId === null || envelope.boardId !== envelope.subjectId) {
      throw new TypedJobExecutionError("task_due_scan_board_mismatch", true);
    }
    const projections = await this.transaction((client) =>
      projectDueTasksInTransaction(client, {
        organizationId: envelope.organizationId,
        boardId: envelope.boardId!,
        through: envelope.parameters.through,
        newId: this.newId,
        limit: 100
      })
    );
    return { projected: projections.length };
  };

  private readonly voteDeadlineScan: TypedJobHandler = async ({ job }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "vote_deadline_scan") {
      throw new TypedJobExecutionError("vote_deadline_scan_job_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.boardId === null || envelope.boardId !== envelope.subjectId) {
      throw new TypedJobExecutionError("vote_deadline_scan_board_mismatch", true);
    }
    const scheduled = await this.transaction((client) =>
      scheduleDueAutomaticVoteClosesInTransaction(client, {
        organizationId: envelope.organizationId,
        boardId: envelope.boardId!,
        through: envelope.parameters.through,
        newId: this.newId,
        limit: 100
      })
    );
    return {
      scheduled: scheduled.length,
      replayed: scheduled.filter((candidate) => candidate.replayed).length
    };
  };

  private readonly jobLeaseReaper: TypedJobHandler = async ({ job }) => {
    if (job.envelope.jobType !== "job_lease_reaper") {
      throw new TypedJobExecutionError("job_reaper_type_mismatch", true);
    }
    this.assertOrganization(job.envelope.organizationId);
    return this.transaction((client) => reapExpiredJobLeasesInTransaction(client, { limit: 100 }));
  };

  private readonly clockHealth: TypedJobHandler = async ({ job }) => {
    if (job.envelope.jobType !== "clock_health") {
      throw new TypedJobExecutionError("clock_health_type_mismatch", true);
    }
    this.assertOrganization(job.envelope.organizationId);
    const before = this.now().getTime();
    const databaseNow = await this.transaction((client) => readDatabaseClockInTransaction(client));
    const after = this.now().getTime();
    if (!Number.isFinite(before) || !Number.isFinite(after) || after < before) {
      throw new TypedJobExecutionError("local_clock_invalid", false);
    }
    const databaseMilliseconds = Date.parse(databaseNow);
    if (!Number.isFinite(databaseMilliseconds)) {
      throw new TypedJobExecutionError("database_clock_invalid", true);
    }
    const midpoint = Math.floor(before + (after - before) / 2);
    const driftMicroseconds = (BigInt(databaseMilliseconds) - BigInt(midpoint)) * 1_000n;
    const validUntil = Rfc3339UtcSchema.parse(
      new Date(databaseMilliseconds + 5 * 60 * 1_000).toISOString()
    );
    const recorded = await this.transaction((client) =>
      recordClockHealthInTransaction(client, {
        sampleId: this.newId(),
        organizationId: job.envelope.organizationId,
        source: "worker.database_clock",
        measuredAt: databaseNow,
        driftMicroseconds: driftMicroseconds.toString(10),
        validUntil
      })
    );
    if (!recorded.healthy) {
      await this.sendOperationalAlert(job.jobId, "clock_drift_unhealthy", {
        driftMicroseconds: recorded.driftMicroseconds
      });
    }
    return {
      sampleId: recorded.sampleId,
      healthy: recorded.healthy,
      driftMicroseconds: recorded.driftMicroseconds,
      validUntil: recorded.validUntil
    };
  };

  private readonly automaticVoteClose: TypedJobHandler = async ({ job, signal }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "automatic_vote_close") {
      throw new TypedJobExecutionError("automatic_vote_close_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.boardId === null || envelope.subjectId !== envelope.parameters.voteId) {
      throw new TypedJobExecutionError("automatic_vote_close_binding_mismatch", true);
    }
    const generated = {
      outcomeId: this.newId(),
      certificateId: this.newId(),
      certificatePublicId: this.entropy(32).toString("base64url"),
      closingAuditEventId: this.newId()
    };
    try {
      const prepared = await this.transaction(
        (client) =>
          prepareAutomaticVoteCloseInTransaction(client, {
            organizationId: envelope.organizationId,
            voteId: envelope.parameters.voteId,
            signingKeyId: this.options.binding.keyIds.evidence_signing,
            ...generated
          }),
        { isolation: "serializable" }
      );
      if (
        prepared.boardId !== envelope.boardId ||
        prepared.signingKeyId !== this.options.binding.keyIds.evidence_signing ||
        prepared.signingKeyLocator !== this.options.binding.keyLocators.evidence_signing
      ) {
        throw new TypedJobExecutionError("automatic_vote_close_runtime_binding_mismatch", true);
      }
      this.assertLease(signal);
      const draft = await this.transaction(
        (client) =>
          initiateAutomaticVoteCloseInTransaction(client, {
            organizationId: prepared.organizationId,
            voteId: prepared.voteId,
            outcomeId: prepared.outcomeId,
            certificateId: prepared.certificateId,
            certificatePublicId: prepared.certificatePublicId,
            expectedPackageSha256: prepared.expectedPackageSha256,
            expectedTallySha256: prepared.expectedTallySha256,
            signingKeyId: prepared.signingKeyId,
            closingAuditEventId: generated.closingAuditEventId
          }),
        { isolation: "serializable" }
      );
      this.assertLease(signal);
      const issued = issueVoteCertificate(draft.payload, this.options.keys.evidencePrivateKey);
      if (issued.payloadSha256 !== draft.payloadSha256) {
        throw new TypedJobExecutionError("vote_certificate_payload_mismatch", true);
      }
      const finalized = await this.transaction(
        (client) =>
          finalizeVoteCloseInTransaction(client, {
            organizationId: prepared.organizationId,
            voteId: prepared.voteId,
            outcomeId: prepared.outcomeId,
            certificateId: prepared.certificateId,
            signatureBase64Url: issued.signatureBase64Url,
            certificateIssuedAuditEventId: this.newId(),
            voteClosedAuditEventId: this.newId()
          }),
        { isolation: "serializable" }
      );
      return {
        voteId: finalized.voteId,
        certificateId: finalized.certificateId,
        state: finalized.state,
        replayed: finalized.replayed,
        payloadSha256: finalized.payloadSha256
      };
    } catch (error) {
      this.throwVoteFailure(error);
    }
  };

  private readonly exportBuild: TypedJobHandler = async ({ job, signal }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "export_build") {
      throw new TypedJobExecutionError("export_build_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.subjectId !== envelope.parameters.exportRequestId) {
      throw new TypedJobExecutionError("export_build_binding_mismatch", true);
    }
    if (!this.options.exportArtifacts) {
      throw new TypedJobExecutionError("export_storage_unavailable", false);
    }

    // Each export obtains a real current checkpoint before taking its repeatable-read snapshot.
    // Signing is local cryptography; no external I/O is held inside the audit transaction.
    const { frozen, auditAttestation } = await (async () => {
      await this.signCurrentAuditHead(undefined, signal);
      return this.transaction(
        async (client) => {
          const auditEvidence = await verifyPersistedAuditEvidence(client);
          if (!auditEvidence.valid) {
            throw new TypedJobExecutionError("export_audit_evidence_invalid", true);
          }
          if (!auditEvidence.ready) {
            throw new TypedJobExecutionError("export_audit_checkpoint_overdue", false);
          }
          const frozen = await buildFrozenExportSnapshotInTransaction(client, {
            exportRequestId: envelope.parameters.exportRequestId,
            exportStartedAuditEventId: this.newId()
          });

          if (
            frozen.snapshot.organizationId !== envelope.organizationId ||
            frozen.snapshot.boardId !== envelope.boardId
          ) {
            throw new TypedJobExecutionError("export_build_scope_mismatch", true);
          }
          if (frozen.scope.exportType !== "audit_chain") return { frozen };
          const issuedAt = await readDatabaseClockInTransaction(client);
          // Existing worker-only authority validates purpose, instance and active key at
          // the actual signing time. No new database grant or runtime secret is needed.
          const keyResult = await client.query<{
            instance_id: string;
            organization_id: string;
            key_id: string;
            public_jwk: JsonWebKey;
          }>(
            `select instance_id,organization_id,key_id,public_jwk
             from public.boardagent_audit_checkpoint_key($1,$2::timestamptz)`,
            [this.options.binding.keyIds.evidence_signing, issuedAt]
          );
          const key = keyResult.rows[0];
          const events = frozen.components.find(({ name }) => name === "audit:events");
          const checkpoints = frozen.components.find(({ name }) => name === "audit:checkpoints");
          if (
            keyResult.rows.length !== 1 ||
            !key ||
            key.instance_id !== this.options.binding.instanceId ||
            key.organization_id !== frozen.snapshot.organizationId ||
            !events ||
            !checkpoints
          ) {
            throw new TypedJobExecutionError("export_attestation_binding_mismatch", true);
          }
          const auditAttestation = signAuditExportAttestation(
            {
              ...(frozen.snapshot.schemaVersion === "boardagent.export-snapshot.v2"
                ? {
                    schemaVersion: "boardagent.audit-export-attestation.v2" as const,
                    auditRecoveryEvidence: frozen.snapshot.auditRecoveryEvidence
                  }
                : { schemaVersion: "boardagent.audit-export-attestation.v1" as const }),
              instanceId: key.instance_id,
              exportRequestId: frozen.exportRequestId,
              organizationId: frozen.snapshot.organizationId,
              boardId: frozen.snapshot.boardId,
              scopeSha256: frozen.snapshot.scopeSha256,
              snapshotSha256: frozen.snapshotSha256,
              firstSequence: frozen.scope.firstSequence,
              lastSequence: frozen.scope.lastSequence,
              auditHeadSequence: frozen.snapshot.auditHeadSequence,
              auditHeadSha256: frozen.snapshot.auditHeadSha256,
              latestCheckpointSha256: frozen.snapshot.latestCheckpointSha256,
              eventComponentSha256: events.sha256,
              checkpointComponentSha256: checkpoints.sha256,
              issuedAt,
              signingKeyId: this.options.binding.keyIds.evidence_signing,
              keyId: key.key_id
            },
            this.options.keys.evidencePrivateKey
          );
          if (
            !verifyAuditExportAttestation(
              auditAttestation,
              createPublicKey({ key: key.public_jwk, format: "jwk" })
            )
          ) {
            throw new TypedJobExecutionError("export_attestation_signature_invalid", true);
          }
          return { frozen, auditAttestation };
        },
        { isolation: "repeatable read" }
      );
    })().catch(async (error: unknown) => {
      if (error instanceof TypedJobExecutionError && error.permanent) {
        const stateRecorded = await this.transaction((client) =>
          failQueuedExportBuildInTransaction(client, {
            exportRequestId: envelope.parameters.exportRequestId,
            failureClass: error.errorClass,
            exportFailedAuditEventId: this.newId()
          })
        ).catch(() => false);
        const details = { failureClass: error.errorClass, stateRecorded };
        await this.sendOperationalAlert(job.jobId, "export_preparation_failed", details).catch(
          () => {
            process.stderr.write(
              `${JSON.stringify({ event: "export_preparation_failed", jobId: job.jobId, ...details })}\n`
            );
          }
        );
      }
      throw error;
    });
    this.assertLease(signal);
    const artifactId = this.newId();
    let manifest: ExportArtifactManifest;
    try {
      manifest = await this.options.exportArtifacts.publish({
        frozen,
        ...(auditAttestation === undefined ? {} : { auditAttestation }),
        artifactId,
        encryptionKeyId: this.options.binding.keyIds.data_kek,
        encryptionKey: this.options.keys.dataEncryptionKey,
        newChunkId: this.newId,
        randomBytes: (length) => this.entropy(length),
        signal
      });
    } catch {
      await this.transaction((client) =>
        failExportBuildInTransaction(client, {
          exportRequestId: frozen.exportRequestId,
          failureClass: "artifact_storage_failed",
          exportFailedAuditEventId: this.newId()
        })
      ).catch(() => undefined);
      await this.tryOperationalAlert(job.jobId, "export_artifact_storage_failed");
      throw new TypedJobExecutionError("export_artifact_storage_failed", true);
    }
    this.assertLease(signal);
    try {
      const completed = await this.transaction((client) =>
        completeExportBuildInTransaction(client, {
          manifest,
          exportPerformedAuditEventId: this.newId()
        })
      );
      return {
        exportRequestId: completed.exportRequestId,
        artifactId: completed.artifactId,
        manifestSha256: completed.manifestSha256,
        chunkCount: manifest.chunks.length,
        byteLength: manifest.byteLength
      };
    } catch {
      await this.tryOperationalAlert(job.jobId, "export_artifact_commit_failed");
      throw new TypedJobExecutionError("export_artifact_commit_failed", false);
    }
  };

  private async cleanupKnownExportArtifacts(
    jobId: string,
    organizationId: string,
    mode: "expiry" | "reconcile",
    signal: AbortSignal
  ): Promise<number> {
    const store = this.options.exportArtifacts;
    if (!store) throw new TypedJobExecutionError("export_storage_unavailable", false);
    let deleted = 0;
    for (; deleted < 100;) {
      this.assertLease(signal);
      const claim = await this.transaction((client) =>
        claimExportArtifactCleanupInTransaction(client, {
          organizationId,
          mode,
          cleanupToken: this.newId(),
          leaseSeconds: 120
        })
      );
      if (!claim) break;
      try {
        await store.deleteArtifact(claim.manifest);
        this.assertLease(signal);
        await this.transaction((client) =>
          completeExportArtifactCleanupInTransaction(client, {
            organizationId,
            exportRequestId: claim.exportRequestId,
            artifactId: claim.artifactId,
            cleanupToken: claim.cleanupToken,
            cleanupReason: claim.cleanupReason,
            storageDeletionVerified: true,
            exportArtifactDeletedAuditEventId: this.newId()
          })
        );
        deleted += 1;
      } catch (error) {
        await this.transaction((client) =>
          releaseExportArtifactCleanupInTransaction(client, {
            organizationId,
            exportRequestId: claim.exportRequestId,
            artifactId: claim.artifactId,
            cleanupToken: claim.cleanupToken
          })
        ).catch(() => false);
        await this.tryOperationalAlert(jobId, "export_artifact_cleanup_failed", {
          cleanupMode: mode,
          cleanupReason: claim.cleanupReason
        });
        if (error instanceof TypedJobExecutionError) throw error;
        throw new TypedJobExecutionError("export_artifact_cleanup_failed", false);
      }
    }
    return deleted;
  }

  private readonly exportArtifactExpiry: TypedJobHandler = async ({ job, signal }) => {
    if (job.envelope.jobType !== "export_artifact_expiry") {
      throw new TypedJobExecutionError("export_artifact_expiry_type_mismatch", true);
    }
    this.assertOrganization(job.envelope.organizationId);
    const deleted = await this.cleanupKnownExportArtifacts(
      job.jobId,
      job.envelope.organizationId,
      "expiry",
      signal
    );
    return { deleted };
  };

  private readonly exportReconcile: TypedJobHandler = async ({ job, signal }) => {
    if (job.envelope.jobType !== "export_reconcile") {
      throw new TypedJobExecutionError("export_reconcile_type_mismatch", true);
    }
    const organizationId = job.envelope.organizationId;
    this.assertOrganization(organizationId);
    const preparationFailed = await this.transaction(
      (client) =>
        failStoppedQueuedExportsInTransaction(client, {
          organizationId,
          newAuditEventId: this.newId
        }),
      { isolation: "serializable" }
    );
    if (preparationFailed > 0) {
      const details = {
        failureClass: "export_build_stopped",
        stateRecorded: true,
        reconciled: true,
        count: preparationFailed
      };
      await this.sendOperationalAlert(job.jobId, "export_preparation_failed", details).catch(() => {
        process.stderr.write(
          `${JSON.stringify({ event: "export_preparation_failed", jobId: job.jobId, ...details })}\n`
        );
      });
    }
    const store = this.options.exportArtifacts;
    if (!store) throw new TypedJobExecutionError("export_storage_unavailable", false);

    const cleaned = await this.cleanupKnownExportArtifacts(
      job.jobId,
      organizationId,
      "reconcile",
      signal
    );
    let healthy = 0;
    let recovered = 0;
    let orphanDeleted = 0;
    let partialFailed = 0;
    let markersRestored = 0;
    let preservedActive = 0;
    let anomalies = 0;
    let inventory;
    try {
      inventory = await store.scanArtifacts(100);
    } catch {
      await this.tryOperationalAlert(job.jobId, "export_storage_inventory_invalid");
      throw new TypedJobExecutionError("export_storage_inventory_invalid", false);
    }

    for (const entry of inventory) {
      this.assertLease(signal);
      const target = await this.transaction((client) =>
        inspectExportReconcileTargetInTransaction(client, {
          organizationId,
          exportRequestId: entry.exportRequestId
        })
      );
      if (!target) {
        anomalies += 1;
        continue;
      }

      if (target.artifactId !== null) {
        if (
          target.artifactId !== entry.artifactId ||
          target.manifest === null ||
          target.manifestSha256 === null
        ) {
          anomalies += 1;
          continue;
        }
        if (entry.state === "committed") {
          if (entry.manifestSha256 !== target.manifestSha256) {
            anomalies += 1;
          } else if (target.artifactState === "deleted") {
            await store.deleteArtifact(target.manifest);
            orphanDeleted += 1;
          } else if (target.artifactState === "ready" && target.requestState === "succeeded") {
            healthy += 1;
          } else {
            preservedActive += 1;
          }
        } else if (target.artifactState === "ready" && target.requestState === "succeeded") {
          await store.restoreManifestMarker(target.manifest);
          markersRestored += 1;
        } else if (
          target.artifactState === "deleted" ||
          target.artifactState === "expired" ||
          target.artifactState === "quarantined"
        ) {
          await store.deleteArtifact(target.manifest);
          orphanDeleted += 1;
        } else {
          anomalies += 1;
        }
        continue;
      }

      if (entry.state === "committed") {
        if (target.requestState === "running" && !target.activeExportBuild) {
          try {
            await this.transaction((client) =>
              completeExportBuildInTransaction(client, {
                manifest: entry.manifest,
                exportPerformedAuditEventId: this.newId()
              })
            );
            await this.transaction((client) =>
              settleReconciledExportBuildJobsInTransaction(client, {
                organizationId,
                exportRequestId: entry.exportRequestId
              })
            );
            recovered += 1;
          } catch {
            const refreshed = await this.transaction((client) =>
              inspectExportReconcileTargetInTransaction(client, {
                organizationId,
                exportRequestId: entry.exportRequestId
              })
            );
            if (
              refreshed?.requestState === "succeeded" &&
              refreshed.artifactId === entry.artifactId &&
              refreshed.manifestSha256 === entry.manifestSha256
            ) {
              healthy += 1;
            } else if (refreshed?.requestState === "running" && refreshed.safeToFailPartial) {
              await this.transaction(async (client) => {
                await failExportBuildInTransaction(client, {
                  exportRequestId: entry.exportRequestId,
                  failureClass: "artifact_publication_incomplete",
                  exportFailedAuditEventId: this.newId()
                });
                await settleReconciledExportBuildJobsInTransaction(client, {
                  organizationId,
                  exportRequestId: entry.exportRequestId
                });
              });
              await store.deleteArtifact(entry.manifest);
              orphanDeleted += 1;
            } else {
              anomalies += 1;
            }
          }
        } else if (target.requestState === "failed" || target.requestState === "cancelled") {
          await store.deleteArtifact(entry.manifest);
          orphanDeleted += 1;
        } else if (target.requestState === "running" && target.activeExportBuild) {
          preservedActive += 1;
        } else {
          anomalies += 1;
        }
        continue;
      }

      if (target.requestState === "running" && target.safeToFailPartial) {
        await this.transaction(async (client) => {
          await failExportBuildInTransaction(client, {
            exportRequestId: entry.exportRequestId,
            failureClass: "artifact_publication_incomplete",
            exportFailedAuditEventId: this.newId()
          });
          await settleReconciledExportBuildJobsInTransaction(client, {
            organizationId,
            exportRequestId: entry.exportRequestId
          });
        });
        await store.deletePartialArtifact(entry);
        partialFailed += 1;
      } else if (target.requestState === "failed" || target.requestState === "cancelled") {
        await store.deletePartialArtifact(entry);
        orphanDeleted += 1;
      } else if (target.requestState === "running" && target.activeExportBuild) {
        preservedActive += 1;
      } else {
        anomalies += 1;
      }
    }

    if (anomalies > 0) {
      await this.tryOperationalAlert(job.jobId, "export_reconciliation_inconsistent", {
        anomalyCount: anomalies
      });
      throw new TypedJobExecutionError("export_reconciliation_inconsistent", false);
    }
    return {
      preparationFailed,
      cleaned,
      healthy,
      recovered,
      orphanDeleted,
      partialFailed,
      markersRestored,
      preservedActive,
      anomalies
    };
  };

  private readonly certificateRecovery: TypedJobHandler = async ({ job, signal }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "certificate_recovery") {
      throw new TypedJobExecutionError("certificate_recovery_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    if (envelope.boardId === null || envelope.subjectId !== envelope.parameters.voteId) {
      throw new TypedJobExecutionError("certificate_recovery_binding_mismatch", true);
    }
    try {
      const recovery = await this.transaction(
        (client) =>
          prepareVoteCertificateRecoveryInTransaction(client, {
            organizationId: envelope.organizationId,
            voteId: envelope.parameters.voteId
          }),
        { isolation: "serializable" }
      );
      if (recovery.boardId !== envelope.boardId) {
        throw new TypedJobExecutionError("certificate_recovery_board_mismatch", true);
      }
      if (!recovery.required) {
        return {
          voteId: recovery.voteId,
          certificateId: recovery.certificateId,
          state: recovery.state,
          replayed: true
        };
      }
      if (
        recovery.signingKeyId !== this.options.binding.keyIds.evidence_signing ||
        recovery.signingKeyLocator !== this.options.binding.keyLocators.evidence_signing
      ) {
        throw new TypedJobExecutionError("certificate_recovery_runtime_binding_mismatch", true);
      }
      this.assertLease(signal);
      const issued = issueVoteCertificate(recovery.payload, this.options.keys.evidencePrivateKey);
      if (issued.payloadSha256 !== recovery.payloadSha256) {
        throw new TypedJobExecutionError("vote_certificate_payload_mismatch", true);
      }
      const finalized = await this.transaction(
        (client) =>
          finalizeVoteCloseInTransaction(client, {
            organizationId: recovery.organizationId,
            voteId: recovery.voteId,
            outcomeId: recovery.outcomeId,
            certificateId: recovery.certificateId,
            signatureBase64Url: issued.signatureBase64Url,
            certificateIssuedAuditEventId: this.newId(),
            voteClosedAuditEventId: this.newId()
          }),
        { isolation: "serializable" }
      );
      return {
        voteId: finalized.voteId,
        certificateId: finalized.certificateId,
        state: finalized.state,
        replayed: finalized.replayed,
        payloadSha256: finalized.payloadSha256
      };
    } catch (error) {
      this.throwVoteFailure(error);
    }
  };

  private readonly auditCheckpoint: TypedJobHandler = async ({ job, signal }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "audit_checkpoint") {
      throw new TypedJobExecutionError("audit_checkpoint_type_mismatch", true);
    }
    this.assertOrganization(envelope.organizationId);
    return this.signCurrentAuditHead(envelope.parameters.throughSequence, signal);
  };

  private async signCurrentAuditHead(throughSequence: string | undefined, signal: AbortSignal) {
    return this.transaction(async (client) => {
      this.assertLease(signal);
      // Serialize each prefix and its own audit event with appenders and other signers.
      // Holding the head keeps the catch-up target finite: only our attestations extend it.
      const head = await client.query<{ last_sequence: string }>(
        "select last_sequence::text from boardagent_lock_audit_head()"
      );
      let target = BigInt(head.rows[0]!.last_sequence);
      if (throughSequence !== undefined && target < BigInt(throughSequence)) {
        throw new TypedJobExecutionError("audit_checkpoint_watermark_not_reached", false);
      }
      // At most 1m retained events are in the supported envelope. Each full segment
      // clears 999 net events after its own attestation; 1002 segments cover that
      // envelope. This is a worker loop bound, not a larger caller append allowance.
      for (let segment = 0; segment < 1002; segment += 1) {
        this.assertLease(signal);
        const prepared = await prepareAuditCheckpointInTransaction(client, {
          checkpointId: this.newId(),
          signingKeyId: this.options.binding.keyIds.evidence_signing
        });
        if (
          prepared.payload.organizationId !== this.options.binding.organizationId ||
          prepared.payload.signingKeyId !== this.options.binding.keyIds.evidence_signing
        ) {
          throw new TypedJobExecutionError("audit_checkpoint_binding_mismatch", true);
        }
        this.assertLease(signal);
        const signed = signCheckpoint(prepared.payload, this.options.keys.evidencePrivateKey);
        const committed = await commitAuditCheckpointInTransaction(client, {
          checkpoint: signed,
          auditEventId: this.newId()
        });
        this.assertLease(signal);
        if (BigInt(prepared.payload.lastSequence) === target) {
          return {
            checkpointId: committed.checkpointId,
            manifestSha256: committed.manifestSha256,
            throughSequence: prepared.payload.lastSequence,
            replayed: committed.replayed
          };
        }
        target += 1n;
      }
      throw new TypedJobExecutionError("audit_checkpoint_catchup_envelope_exceeded", true);
    });
  }

  private readonly auditVerify: TypedJobHandler = async ({ job }) => {
    if (job.envelope.jobType !== "audit_verify") {
      throw new TypedJobExecutionError("audit_verify_type_mismatch", true);
    }
    this.assertOrganization(job.envelope.organizationId);
    const verification = await this.transaction((client) => verifyPersistedAuditEvidence(client));
    if (!verification.valid) {
      await this.tryOperationalAlert(job.jobId, "audit_evidence_invalid");
      throw new TypedJobExecutionError("audit_evidence_invalid", true);
    }
    if (!verification.ready) {
      await this.tryOperationalAlert(job.jobId, "audit_checkpoint_overdue");
      throw new TypedJobExecutionError("audit_checkpoint_overdue", false);
    }
    return {
      valid: true,
      ready: true,
      eventCount: verification.eventCount,
      checkpointCount: verification.checkpointCount,
      coveredThrough: verification.coveredThrough,
      lagEvents: verification.lagEvents,
      lagSeconds: verification.lagSeconds,
      warningCount: verification.warnings.length
    };
  };

  private readonly operationalAlert: TypedJobHandler = async ({ job, signal }) => {
    const jobType = job.envelope.jobType;
    if (!OPERATIONAL_ALERT_JOB_TYPES.has(jobType)) {
      throw new TypedJobExecutionError("operational_alert_type_mismatch", true);
    }
    this.assertOrganization(job.envelope.organizationId);
    this.assertLease(signal);
    await this.sendOperationalAlert(job.jobId, jobType);
    return this.operationalAlertDetails(job.jobId, jobType);
  };

  public handlers(): ReadonlyMap<TypedJobType, TypedJobHandler> {
    return new Map<TypedJobType, TypedJobHandler>([
      ["action_due_scan", this.actionDueScan],
      ["action_stage_expiry", this.maintenance("action_stage_expiry")],
      ["audit_checkpoint", this.auditCheckpoint],
      ["audit_verify", this.auditVerify],
      ["automatic_vote_close", this.automaticVoteClose],
      ["backup_receipt_verify", this.backupReceiptVerify],
      ["backup_trigger", this.operationalAlert],
      ["certificate_recovery", this.certificateRecovery],
      ["clock_health", this.clockHealth],
      ["compatibility_alert", this.operationalAlert],
      ["dependency_compatibility_alert", this.operationalAlert],
      ["export_artifact_expiry", this.exportArtifactExpiry],
      ["export_build", this.exportBuild],
      ["export_reconcile", this.exportReconcile],
      ["feed_consistency_check", this.feedConsistencyCheck],
      ["feed_reconcile", this.feedReconcile],
      ["job_lease_reaper", this.jobLeaseReaper],
      ["job_retention", this.operationalRetention("job_retention")],
      ["key_compatibility_alert", this.operationalAlert],
      ["log_retention", this.operationalRetention("log_retention")],
      ["oauth_ephemera_expiry", this.maintenance("oauth_ephemera_expiry")],
      ["protocol_compatibility_alert", this.operationalAlert],
      ["question_due_scan", this.questionDueScan],
      ["rate_bucket_retention", this.maintenance("rate_bucket_retention")],
      ["refresh_session_revocation", this.maintenance("refresh_session_revocation")],
      ["restore_due_alert", this.operationalAlert],
      ["task_due_scan", this.taskDueScan],
      ["vote_deadline_scan", this.voteDeadlineScan],
      ["wizard_expiry", this.maintenance("wizard_expiry")]
    ]);
  }
}
