import type { PoolClient } from "pg";
import { z } from "zod";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual
} from "@boardagent/contracts";

const jobBase = <T extends string>(jobType: T) => ({
  schemaVersion: z.literal(`boardagent.job.${jobType}.v1` as const),
  organizationId: UuidV7Schema,
  boardId: UuidV7Schema.nullable()
});

const organizationJob = <T extends string>(jobType: T) =>
  z
    .object({
      ...jobBase(jobType),
      jobType: z.literal(jobType),
      subjectType: z.literal("organization"),
      subjectId: UuidV7Schema,
      parameters: z.object({}).strict()
    })
    .strict();

const boardScanJob = <T extends string>(jobType: T) =>
  z
    .object({
      ...jobBase(jobType),
      jobType: z.literal(jobType),
      subjectType: z.literal("board"),
      subjectId: UuidV7Schema,
      parameters: z.object({ through: z.iso.datetime({ offset: true }) }).strict()
    })
    .strict();

const notificationJob = <T extends string>(jobType: T) =>
  z
    .object({
      ...jobBase(jobType),
      jobType: z.literal(jobType),
      subjectType: z.literal("notification_job"),
      subjectId: UuidV7Schema,
      parameters: z.object({ notificationJobId: UuidV7Schema }).strict()
    })
    .strict();

export const TYPED_JOB_TYPES = [
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
  "notice_fanout",
  "notification_dead_letter_alert",
  "notification_lease_reaper",
  "notification_retry",
  "oauth_ephemera_expiry",
  "protocol_compatibility_alert",
  "question_due_scan",
  "rate_bucket_retention",
  "refresh_session_revocation",
  "restore_due_alert",
  "task_due_scan",
  "vote_deadline_scan",
  "webhook_delivery",
  "wizard_expiry"
] as const;

const organizationJobTypes = new Set<string>([
  "action_stage_expiry",
  "audit_checkpoint",
  "audit_verify",
  "backup_receipt_verify",
  "backup_trigger",
  "clock_health",
  "compatibility_alert",
  "dependency_compatibility_alert",
  "export_artifact_expiry",
  "export_reconcile",
  "feed_consistency_check",
  "job_lease_reaper",
  "job_retention",
  "key_compatibility_alert",
  "log_retention",
  "notification_lease_reaper",
  "oauth_ephemera_expiry",
  "protocol_compatibility_alert",
  "rate_bucket_retention",
  "refresh_session_revocation",
  "restore_due_alert",
  "wizard_expiry"
]);

const typedJobUnion = z.discriminatedUnion("jobType", [
  z
    .object({
      ...jobBase("notice_fanout"),
      jobType: z.literal("notice_fanout"),
      subjectType: z.literal("notice"),
      subjectId: UuidV7Schema,
      parameters: z.object({ noticeId: UuidV7Schema }).strict()
    })
    .strict(),
  notificationJob("webhook_delivery"),
  notificationJob("notification_retry"),
  notificationJob("notification_dead_letter_alert"),
  boardScanJob("action_due_scan"),
  boardScanJob("question_due_scan"),
  boardScanJob("task_due_scan"),
  boardScanJob("vote_deadline_scan"),
  z
    .object({
      ...jobBase("automatic_vote_close"),
      jobType: z.literal("automatic_vote_close"),
      subjectType: z.literal("vote"),
      subjectId: UuidV7Schema,
      parameters: z.object({ voteId: UuidV7Schema }).strict()
    })
    .strict(),
  z
    .object({
      ...jobBase("export_build"),
      jobType: z.literal("export_build"),
      subjectType: z.literal("export_request"),
      subjectId: UuidV7Schema,
      parameters: z.object({ exportRequestId: UuidV7Schema }).strict()
    })
    .strict(),
  z
    .object({
      ...jobBase("certificate_recovery"),
      jobType: z.literal("certificate_recovery"),
      subjectType: z.literal("vote"),
      subjectId: UuidV7Schema,
      parameters: z.object({ voteId: UuidV7Schema }).strict()
    })
    .strict(),
  z
    .object({
      ...jobBase("feed_reconcile"),
      jobType: z.literal("feed_reconcile"),
      subjectType: z.literal("member"),
      subjectId: UuidV7Schema,
      parameters: z.object({ memberId: UuidV7Schema }).strict()
    })
    .strict(),
  z
    .object({
      ...jobBase("audit_checkpoint"),
      jobType: z.literal("audit_checkpoint"),
      subjectType: z.literal("organization"),
      subjectId: UuidV7Schema,
      parameters: z.object({ throughSequence: z.string().regex(/^[1-9]\d*$/u) }).strict()
    })
    .strict(),
  organizationJob("action_stage_expiry"),
  organizationJob("wizard_expiry"),
  organizationJob("oauth_ephemera_expiry"),
  organizationJob("refresh_session_revocation"),
  organizationJob("export_reconcile"),
  organizationJob("export_artifact_expiry"),
  organizationJob("feed_consistency_check"),
  organizationJob("audit_verify"),
  organizationJob("notification_lease_reaper"),
  organizationJob("job_lease_reaper"),
  organizationJob("clock_health"),
  organizationJob("backup_trigger"),
  organizationJob("backup_receipt_verify"),
  organizationJob("restore_due_alert"),
  organizationJob("compatibility_alert"),
  organizationJob("key_compatibility_alert"),
  organizationJob("protocol_compatibility_alert"),
  organizationJob("dependency_compatibility_alert"),
  organizationJob("job_retention"),
  organizationJob("log_retention"),
  organizationJob("rate_bucket_retention")
]);

export const TypedJobEnvelopeSchema = typedJobUnion.superRefine((envelope, context) => {
  const reject = (message: string): void => {
    context.addIssue({ code: "custom", message });
  };
  if (organizationJobTypes.has(envelope.jobType)) {
    if (envelope.boardId !== null || envelope.subjectId !== envelope.organizationId) {
      reject("organization job must have no board and must bind its organization subject");
    }
    return;
  }
  if (
    envelope.jobType === "action_due_scan" ||
    envelope.jobType === "question_due_scan" ||
    envelope.jobType === "task_due_scan" ||
    envelope.jobType === "vote_deadline_scan"
  ) {
    if (envelope.boardId === null || envelope.subjectId !== envelope.boardId) {
      reject("board scan job must bind its exact board subject");
    }
    return;
  }
  if (
    envelope.boardId === null &&
    envelope.jobType !== "export_build" &&
    envelope.jobType !== "webhook_delivery"
  ) {
    reject("object-bound job must include its exact board");
  }
  const parameterId =
    envelope.jobType === "notice_fanout"
      ? envelope.parameters.noticeId
      : envelope.jobType === "webhook_delivery" ||
          envelope.jobType === "notification_retry" ||
          envelope.jobType === "notification_dead_letter_alert"
        ? envelope.parameters.notificationJobId
        : envelope.jobType === "export_build"
          ? envelope.parameters.exportRequestId
          : envelope.jobType === "feed_reconcile"
            ? envelope.parameters.memberId
            : "voteId" in envelope.parameters
              ? envelope.parameters.voteId
              : null;
  if (parameterId === null) {
    reject("typed object job must bind one exact parameter identifier");
    return;
  }
  if (parameterId !== envelope.subjectId) {
    reject("typed job parameter must match the exact subject identifier");
  }
});

export type TypedJobEnvelope = z.infer<typeof TypedJobEnvelopeSchema>;

export interface EnqueueRequestJobInput {
  readonly jobId: string;
  readonly envelope: unknown;
  readonly idempotencyKey: string;
  readonly availableAt?: string;
}

export interface ClaimedJob {
  readonly jobId: string;
  readonly envelope: TypedJobEnvelope;
  readonly payloadSha256: string;
  readonly attempt: number;
  readonly leaseOwner: string;
  readonly leaseToken: string;
  readonly leaseStartedAt: string;
  readonly leaseExpiresAt: string;
}

export type ClaimJobResult =
  | { readonly claimed: true; readonly job: ClaimedJob }
  | { readonly claimed: false; readonly rejectedJobId?: string; readonly reason?: string };

export type CompleteJobResult =
  | {
      readonly completed: true;
      readonly jobId: string;
      readonly state: "succeeded" | "retry" | "dead";
      readonly replayed: boolean;
    }
  | { readonly completed: false; readonly jobId: string; readonly reason: "lease_unavailable" };

export class JobTransactionError extends Error {
  public constructor(
    public readonly code: "job_invalid" | "job_conflict" | "lease_unavailable",
    message: string
  ) {
    super(message);
    this.name = "JobTransactionError";
  }
}

interface ClaimedJobRow {
  readonly job_id: string;
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly job_type: string;
  readonly schema_version: string;
  readonly subject_type: string;
  readonly subject_id: string | null;
  readonly canonical_payload: Buffer;
  readonly payload_sha256: Buffer;
  readonly attempt: number;
  readonly lease_token: string;
  readonly lease_started_at: string;
  readonly lease_expires_at: string;
}

function exactIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("job idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function exactLeaseOwner(value: string): string {
  if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(value)) {
    throw new TypeError("lease owner must be an opaque bounded worker identifier");
  }
  return value;
}

function boundedSeconds(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(
      `${label} must be an integer from ${String(minimum)} through ${String(maximum)}`
    );
  }
  return value;
}

function assertEnvelopeMatchesRow(row: ClaimedJobRow, envelope: TypedJobEnvelope): void {
  if (
    envelope.organizationId !== row.organization_id ||
    envelope.boardId !== row.board_id ||
    envelope.jobType !== row.job_type ||
    envelope.subjectType !== row.subject_type ||
    envelope.subjectId !== row.subject_id ||
    envelope.schemaVersion !== row.schema_version
  ) {
    throw new JobTransactionError("job_invalid", "typed job row and canonical envelope differ");
  }
}

export async function enqueueRequestJobInTransaction(
  client: PoolClient,
  rawInput: EnqueueRequestJobInput
): Promise<{ readonly jobId: string; readonly replayed: boolean; readonly payloadSha256: string }> {
  const input = z
    .object({
      jobId: UuidV7Schema,
      envelope: TypedJobEnvelopeSchema,
      idempotencyKey: z.string().min(16).max(256),
      availableAt: z.iso.datetime({ offset: true }).optional()
    })
    .strict()
    .parse(rawInput);
  const jobId = input.jobId;
  const envelope = input.envelope;
  const key = exactIdempotencyKey(input.idempotencyKey);
  const canonicalPayload = Buffer.from(canonicalJson(envelope), "utf8");
  const payloadSha256 = canonicalSha256(envelope);
  let protectedResult;
  try {
    protectedResult = await client.query<{
      job_id: string;
      replayed: boolean;
      stored_payload_sha256: Buffer;
      stored_canonical_payload: Buffer;
    }>(
      `select job_id,replayed,stored_payload_sha256,stored_canonical_payload
         from boardagent_enqueue_request_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        jobId,
        envelope.organizationId,
        envelope.boardId,
        envelope.jobType,
        envelope.schemaVersion,
        envelope.subjectType,
        envelope.subjectId,
        canonicalPayload,
        Buffer.from(payloadSha256, "hex"),
        key,
        input.availableAt ?? null
      ]
    );
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error) {
      if (error.code === "23514" || error.code === "42501") {
        throw new JobTransactionError("job_invalid", "typed job target or payload is invalid");
      }
    }
    throw error;
  }
  const row = protectedResult.rows[0];
  if (!row) throw new JobTransactionError("job_invalid", "typed job enqueue returned no row");
  if (
    !safeHashEqual(row.stored_payload_sha256.toString("hex"), payloadSha256) ||
    !row.stored_canonical_payload.equals(canonicalPayload)
  ) {
    throw new JobTransactionError(
      "job_conflict",
      "job idempotency key was used for different canonical bytes"
    );
  }
  return { jobId: row.job_id, replayed: row.replayed, payloadSha256 };
}

function protectedCompletionHash(input: {
  readonly jobId: string;
  readonly attempt: number;
  readonly result: string;
  readonly errorClass: string | null;
}): string {
  return canonicalSha256({
    schemaVersion: "boardagent.job-attempt-result.v1",
    jobId: input.jobId,
    attempt: input.attempt,
    result: input.result,
    errorClass: input.errorClass
  });
}

export async function claimTypedJobInTransaction(
  client: PoolClient,
  rawInput: { readonly leaseOwner: string; readonly leaseSeconds: number }
): Promise<ClaimJobResult> {
  const input = z
    .object({
      leaseOwner: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/u),
      leaseSeconds: z.number().int().min(5).max(300)
    })
    .strict()
    .parse(rawInput);
  const leaseOwner = exactLeaseOwner(input.leaseOwner);
  const leaseSeconds = boundedSeconds(input.leaseSeconds, "lease duration", 5, 300);
  const candidate = await client.query<ClaimedJobRow>(
    `select job_id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
            canonical_payload,payload_sha256,attempt,lease_token,
            to_char(lease_started_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as lease_started_at,
            to_char(lease_expires_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as lease_expires_at
       from boardagent_claim_typed_job($1,$2)`,
    [leaseOwner, leaseSeconds]
  );
  const row = candidate.rows[0];
  if (!row) return { claimed: false };
  let envelope: TypedJobEnvelope;
  try {
    envelope = TypedJobEnvelopeSchema.parse(
      JSON.parse(row.canonical_payload.toString("utf8")) as unknown
    );
    const canonicalPayload = Buffer.from(canonicalJson(envelope), "utf8");
    if (
      !canonicalPayload.equals(row.canonical_payload) ||
      !safeHashEqual(row.payload_sha256.toString("hex"), canonicalSha256(envelope))
    ) {
      throw new JobTransactionError(
        "job_invalid",
        "typed job payload is not the exact canonical byte representation"
      );
    }
    assertEnvelopeMatchesRow(row, envelope);
  } catch (error) {
    const errorClass = "invalid_typed_payload";
    await client.query(`select * from boardagent_complete_typed_job($1,$2,$3,$4,$5,$6,$7)`, [
      row.job_id,
      leaseOwner,
      row.attempt,
      row.lease_token,
      "permanent_failure",
      Buffer.from(
        protectedCompletionHash({
          jobId: row.job_id,
          attempt: row.attempt,
          result: "permanent_failure",
          errorClass
        }),
        "hex"
      ),
      errorClass
    ]);
    return {
      claimed: false,
      rejectedJobId: row.job_id,
      reason: error instanceof Error ? error.message : errorClass
    };
  }
  return {
    claimed: true,
    job: {
      jobId: row.job_id,
      envelope,
      payloadSha256: row.payload_sha256.toString("hex"),
      attempt: row.attempt,
      leaseOwner,
      leaseToken: row.lease_token,
      leaseStartedAt: row.lease_started_at,
      leaseExpiresAt: row.lease_expires_at
    }
  };
}

export async function heartbeatJobLeaseInTransaction(
  client: PoolClient,
  rawInput: {
    readonly jobId: string;
    readonly leaseOwner: string;
    readonly attempt: number;
    readonly leaseToken: string;
    readonly leaseSeconds: number;
  }
): Promise<{ readonly extended: boolean; readonly leaseExpiresAt?: string }> {
  const input = z
    .object({
      jobId: UuidV7Schema,
      leaseOwner: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/u),
      attempt: z.number().int().min(1).max(100),
      leaseToken: z.uuid(),
      leaseSeconds: z.number().int().min(5).max(300)
    })
    .strict()
    .parse(rawInput);
  const result = await client.query<{ lease_expires_at: string | null }>(
    `select to_char(
              boardagent_heartbeat_typed_job($1,$2,$3,$4,$5) at time zone 'UTC',
              'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
            ) as lease_expires_at`,
    [input.jobId, input.leaseOwner, input.attempt, input.leaseToken, input.leaseSeconds]
  );
  const leaseExpiresAt = result.rows[0]?.lease_expires_at;
  return leaseExpiresAt ? { extended: true, leaseExpiresAt } : { extended: false };
}

export async function completeTypedJobInTransaction(
  client: PoolClient,
  rawInput: {
    readonly jobId: string;
    readonly leaseOwner: string;
    readonly attempt: number;
    readonly leaseToken: string;
    readonly result: "succeeded" | "retryable_failure" | "permanent_failure";
    readonly resultSha256: string;
    readonly errorClass?: string;
  }
): Promise<CompleteJobResult> {
  const input = z
    .object({
      jobId: UuidV7Schema,
      leaseOwner: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/u),
      attempt: z.number().int().min(1).max(100),
      leaseToken: z.uuid(),
      result: z.enum(["succeeded", "retryable_failure", "permanent_failure"]),
      resultSha256: Sha256HexSchema,
      errorClass: z
        .string()
        .regex(/^[a-z][a-z0-9_.-]{1,127}$/u)
        .optional()
    })
    .strict()
    .parse(rawInput);
  const errorClass =
    input.result === "succeeded"
      ? null
      : (input.errorClass ??
        (input.result === "permanent_failure" ? "permanent_failure" : "retryable_failure"));
  if (input.result === "succeeded" && input.errorClass !== undefined) {
    throw new TypeError("successful job completion cannot carry an error class");
  }
  let result;
  try {
    result = await client.query<{
      resulting_state: "succeeded" | "retry" | "dead";
      replayed: boolean;
    }>(
      `select resulting_state,replayed
         from boardagent_complete_typed_job($1,$2,$3,$4,$5,$6,$7)`,
      [
        input.jobId,
        input.leaseOwner,
        input.attempt,
        input.leaseToken,
        input.result,
        Buffer.from(input.resultSha256, "hex"),
        errorClass
      ]
    );
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
      throw new JobTransactionError(
        "job_conflict",
        "job attempt already has a different immutable result"
      );
    }
    throw error;
  }
  const row = result.rows[0];
  if (!row) return { completed: false, jobId: input.jobId, reason: "lease_unavailable" };
  return {
    completed: true,
    jobId: input.jobId,
    state: row.resulting_state,
    replayed: row.replayed
  };
}

export async function reapExpiredJobLeasesInTransaction(
  client: PoolClient,
  rawInput: { readonly limit?: number } = {}
): Promise<{ readonly retried: number; readonly dead: number }> {
  const input = z
    .object({ limit: z.number().int().min(1).max(10_000).optional() })
    .strict()
    .parse(rawInput);
  const limit = boundedSeconds(input.limit ?? 100, "lease reap limit", 1, 10_000);
  const result = await client.query<{ retried: number; dead: number }>(
    "select retried,dead from boardagent_reap_expired_typed_jobs($1)",
    [limit]
  );
  return result.rows[0] ?? { retried: 0, dead: 0 };
}
