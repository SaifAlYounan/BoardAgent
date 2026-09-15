import type { PoolClient } from "pg";
import { z } from "zod";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";

const WakeClassSchema = z.enum(["pending_action", "notice", "security"]);
const DeliveryResultClassSchema = z.enum([
  "delivered",
  "retryable_failure",
  "permanent_failure",
  "cancelled"
]);

export interface NoticeWebhookTarget {
  readonly organizationId: string;
  readonly boardId: string;
  readonly memberId: string;
  readonly webhookId: string;
  readonly wakeClass: "pending_action" | "notice";
}

interface NoticeWebhookTargetRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly member_id: string;
  readonly webhook_id: string;
  readonly wake_class: string;
}

export async function listNoticeWebhookTargetsInTransaction(
  client: PoolClient,
  noticeIdValue: string
): Promise<readonly NoticeWebhookTarget[]> {
  const noticeId = UuidV7Schema.parse(noticeIdValue);
  const result = await client.query<NoticeWebhookTargetRow>(
    `select organization_id,board_id,member_id,webhook_id,wake_class
       from boardagent_notice_webhook_targets($1)`,
    [noticeId]
  );
  return result.rows.map((row) => {
    const wakeClass = WakeClassSchema.parse(row.wake_class);
    if (wakeClass === "security") {
      throw new Error("notice fanout returned an invalid security wake class");
    }
    return {
      organizationId: UuidV7Schema.parse(row.organization_id),
      boardId: UuidV7Schema.parse(row.board_id),
      memberId: UuidV7Schema.parse(row.member_id),
      webhookId: UuidV7Schema.parse(row.webhook_id),
      wakeClass
    };
  });
}

export interface CreateNotificationDeliveryInput {
  readonly notificationJobId: string;
  readonly noticeId: string;
  readonly webhookId: string;
  readonly wakeClass: "pending_action" | "notice";
  readonly randomWakeId: Uint8Array;
  readonly occurredAt: string;
}

export interface CreateNotificationDeliveryResult {
  readonly notificationJobId: string;
  readonly replayed: boolean;
  readonly canonicalPayload: Buffer;
  readonly payloadSha256: string;
}

export async function createNotificationDeliveryInTransaction(
  client: PoolClient,
  rawInput: CreateNotificationDeliveryInput
): Promise<CreateNotificationDeliveryResult> {
  const input = z
    .object({
      notificationJobId: UuidV7Schema,
      noticeId: UuidV7Schema,
      webhookId: UuidV7Schema,
      wakeClass: z.enum(["pending_action", "notice"]),
      randomWakeId: z.instanceof(Uint8Array),
      occurredAt: Rfc3339UtcSchema
    })
    .strict()
    .parse(rawInput);
  const randomWakeId = Buffer.from(input.randomWakeId);
  if (randomWakeId.length !== 32) {
    throw new RangeError("notification wake ID must contain exactly 32 bytes");
  }
  const payload = {
    schemaVersion: "boardagent.webhook-wake.v1" as const,
    eventClass: input.wakeClass,
    wakeId: randomWakeId.toString("base64url"),
    occurredAt: input.occurredAt
  };
  const canonicalPayload = Buffer.from(canonicalJson(payload), "utf8");
  const payloadSha256 = canonicalSha256(payload);
  const result = await client.query<{ notification_job_id: string; replayed: boolean }>(
    `select notification_job_id,replayed
       from boardagent_create_notification_delivery($1,$2,$3,$4,$5,$6,$7)`,
    [
      input.notificationJobId,
      input.noticeId,
      input.webhookId,
      input.wakeClass,
      randomWakeId,
      canonicalPayload,
      Buffer.from(payloadSha256, "hex")
    ]
  );
  const row = result.rows[0];
  if (!row) throw new Error("notification delivery creation returned no row");
  return {
    notificationJobId: UuidV7Schema.parse(row.notification_job_id),
    replayed: row.replayed,
    canonicalPayload,
    payloadSha256
  };
}

interface ClaimedNotificationDeliveryRow {
  readonly notification_job_id: string;
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly member_id: string;
  readonly webhook_id: string;
  readonly endpoint_ciphertext: Buffer;
  readonly secret_ciphertext: Buffer;
  readonly endpoint_sha256: Buffer;
  readonly secret_sha256: Buffer;
  readonly key_id: string;
  readonly webhook_generation: string;
  readonly source_kind: string;
  readonly wake_class: string;
  readonly random_wake_id: Buffer;
  readonly canonical_payload: Buffer;
  readonly payload_sha256: Buffer;
  readonly attempt: number;
  readonly lease_expires_at: string;
}

export interface ClaimedNotificationDelivery {
  readonly notificationJobId: string;
  readonly organizationId: string;
  readonly boardId: string | null;
  readonly memberId: string;
  readonly webhookId: string;
  readonly endpointCiphertext: Buffer;
  readonly secretCiphertext: Buffer;
  readonly endpointSha256: string;
  readonly secretSha256: string;
  readonly keyId: string;
  readonly webhookGeneration: bigint;
  readonly sourceKind: "notice" | "test";
  readonly wakeClass: "pending_action" | "notice" | "security";
  readonly randomWakeId: Buffer;
  readonly canonicalPayload: Buffer;
  readonly payloadSha256: string;
  readonly attempt: number;
  readonly leaseExpiresAt: string;
}

export async function claimNotificationDeliveryInTransaction(
  client: PoolClient,
  rawInput: {
    readonly notificationJobId: string | null;
    readonly leaseOwner: string;
    readonly leaseSeconds: number;
  }
): Promise<ClaimedNotificationDelivery | null> {
  const input = z
    .object({
      notificationJobId: UuidV7Schema.nullable(),
      leaseOwner: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/u),
      leaseSeconds: z.number().int().min(5).max(300)
    })
    .strict()
    .parse(rawInput);
  const result = await client.query<ClaimedNotificationDeliveryRow>(
    `select notification_job_id,organization_id,board_id,member_id,webhook_id,
            endpoint_ciphertext,secret_ciphertext,endpoint_sha256,secret_sha256,key_id,
            webhook_generation::text,source_kind,wake_class,random_wake_id,
            canonical_payload,payload_sha256,attempt,
            to_char(lease_expires_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as lease_expires_at
       from boardagent_claim_notification_delivery($1,$2,$3)`,
    [input.notificationJobId, input.leaseOwner, input.leaseSeconds]
  );
  const row = result.rows[0];
  if (!row) return null;
  const sourceKind = z.enum(["notice", "test"]).parse(row.source_kind);
  const wakeClass = WakeClassSchema.parse(row.wake_class);
  const canonicalPayload = Buffer.from(row.canonical_payload);
  const payloadSha256 = Sha256HexSchema.parse(row.payload_sha256.toString("hex"));
  let parsedPayload: unknown;
  try {
    parsedPayload = JSON.parse(canonicalPayload.toString("utf8")) as unknown;
  } catch {
    throw new Error("claimed notification payload is not strict JSON");
  }
  const expectedPayload = {
    schemaVersion: "boardagent.webhook-wake.v1" as const,
    eventClass: wakeClass,
    wakeId: row.random_wake_id.toString("base64url"),
    occurredAt: z.object({ occurredAt: Rfc3339UtcSchema }).passthrough().parse(parsedPayload)
      .occurredAt
  };
  if (
    canonicalJson(parsedPayload) !== canonicalPayload.toString("utf8") ||
    canonicalJson(expectedPayload) !== canonicalPayload.toString("utf8") ||
    !safeHashEqual(payloadSha256, canonicalSha256(expectedPayload))
  ) {
    throw new Error("claimed notification payload, wake ID, and digest differ");
  }
  if (
    (sourceKind === "test" && (row.board_id !== null || wakeClass !== "security")) ||
    (sourceKind === "notice" && (row.board_id === null || wakeClass === "security"))
  ) {
    throw new Error("claimed notification source projection is invalid");
  }
  return {
    notificationJobId: UuidV7Schema.parse(row.notification_job_id),
    organizationId: UuidV7Schema.parse(row.organization_id),
    boardId: row.board_id === null ? null : UuidV7Schema.parse(row.board_id),
    memberId: UuidV7Schema.parse(row.member_id),
    webhookId: UuidV7Schema.parse(row.webhook_id),
    endpointCiphertext: Buffer.from(row.endpoint_ciphertext),
    secretCiphertext: Buffer.from(row.secret_ciphertext),
    endpointSha256: Sha256HexSchema.parse(row.endpoint_sha256.toString("hex")),
    secretSha256: Sha256HexSchema.parse(row.secret_sha256.toString("hex")),
    keyId: UuidV7Schema.parse(row.key_id),
    webhookGeneration: BigInt(row.webhook_generation),
    sourceKind,
    wakeClass,
    randomWakeId: Buffer.from(row.random_wake_id),
    canonicalPayload,
    payloadSha256,
    attempt: row.attempt,
    leaseExpiresAt: Rfc3339UtcSchema.parse(row.lease_expires_at)
  };
}

export type NotificationDeliveryResultClass = z.infer<typeof DeliveryResultClassSchema>;

export interface CompleteNotificationDeliveryResult {
  readonly completed: boolean;
  readonly notificationJobId: string;
  readonly state?: "delivered" | "retry" | "dead" | "cancelled";
  readonly replayed?: boolean;
}

export async function readNotificationDeliveryStateInTransaction(
  client: PoolClient,
  notificationJobIdValue: string
): Promise<"queued" | "leased" | "retry" | "delivered" | "dead" | "cancelled" | null> {
  const notificationJobId = UuidV7Schema.parse(notificationJobIdValue);
  const result = await client.query<{ state: string }>(
    "select boardagent_notification_delivery_state($1) as state",
    [notificationJobId]
  );
  const state = result.rows[0]?.state ?? null;
  return state === null
    ? null
    : z.enum(["queued", "leased", "retry", "delivered", "dead", "cancelled"]).parse(state);
}

export interface ReapExpiredNotificationLeasesResult {
  readonly reaped: number;
  readonly retried: number;
  readonly dead: number;
  readonly deadNotificationIds: readonly string[];
}

export async function reapExpiredNotificationLeasesInTransaction(
  client: PoolClient,
  rawInput: {
    readonly organizationId: string;
    readonly attemptIds: readonly string[];
  }
): Promise<ReapExpiredNotificationLeasesResult> {
  const input = z
    .object({
      organizationId: UuidV7Schema,
      attemptIds: z.array(UuidV7Schema).min(1).max(100)
    })
    .strict()
    .parse(rawInput);
  if (new Set(input.attemptIds).size !== input.attemptIds.length) {
    throw new TypeError("notification lease attempt IDs must be unique");
  }
  const result = await client.query<{
    reaped: number;
    retried: number;
    dead: number;
    dead_notification_ids: string[];
  }>(
    `select reaped,retried,dead,dead_notification_ids
       from boardagent_reap_expired_notification_leases($1,$2::uuid[])`,
    [input.organizationId, input.attemptIds]
  );
  const row = result.rows[0];
  if (!row) throw new Error("notification lease reaper returned no row");
  return {
    reaped: row.reaped,
    retried: row.retried,
    dead: row.dead,
    deadNotificationIds: row.dead_notification_ids.map((id) => UuidV7Schema.parse(id))
  };
}

export interface NotificationDeadLetterTarget {
  readonly notificationJobId: string;
  readonly organizationId: string;
  readonly boardId: string;
  readonly state: "dead";
}

export async function readNotificationDeadLetterTargetInTransaction(
  client: PoolClient,
  notificationJobIdValue: string
): Promise<NotificationDeadLetterTarget | null> {
  const notificationJobId = UuidV7Schema.parse(notificationJobIdValue);
  const result = await client.query<{
    notification_job_id: string;
    organization_id: string;
    board_id: string;
    state: string;
  }>(
    `select notification_job_id,organization_id,board_id,state
       from boardagent_notification_dead_letter_target($1)`,
    [notificationJobId]
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    notificationJobId: UuidV7Schema.parse(row.notification_job_id),
    organizationId: UuidV7Schema.parse(row.organization_id),
    boardId: UuidV7Schema.parse(row.board_id),
    state: z.literal("dead").parse(row.state)
  };
}

export async function enqueueNotificationDeadLetterAlertInTransaction(
  client: PoolClient,
  rawInput: { readonly jobId: string; readonly notificationJobId: string }
): Promise<{ readonly jobId: string; readonly replayed: boolean } | null> {
  const input = z
    .object({ jobId: UuidV7Schema, notificationJobId: UuidV7Schema })
    .strict()
    .parse(rawInput);
  const result = await client.query<{ job_id: string; replayed: boolean }>(
    `select job_id,replayed
       from boardagent_enqueue_notification_dead_letter_alert($1,$2)`,
    [input.jobId, input.notificationJobId]
  );
  const row = result.rows[0];
  return row ? { jobId: UuidV7Schema.parse(row.job_id), replayed: row.replayed } : null;
}

export async function completeNotificationDeliveryInTransaction(
  client: PoolClient,
  rawInput: {
    readonly attemptId: string;
    readonly auditEventId: string;
    readonly notificationJobId: string;
    readonly leaseOwner: string;
    readonly attempt: number;
    readonly requestSha256: string;
    readonly resultClass: NotificationDeliveryResultClass;
    readonly errorClass: string | null;
    readonly httpStatus: number | null;
    readonly responseSha256: string | null;
  }
): Promise<CompleteNotificationDeliveryResult> {
  const input = z
    .object({
      attemptId: UuidV7Schema,
      auditEventId: UuidV7Schema,
      notificationJobId: UuidV7Schema,
      leaseOwner: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/u),
      attempt: z.number().int().min(1).max(10),
      requestSha256: Sha256HexSchema,
      resultClass: DeliveryResultClassSchema,
      errorClass: z
        .string()
        .regex(/^[a-z][a-z0-9_.-]{1,127}$/u)
        .nullable(),
      httpStatus: z.number().int().min(100).max(599).nullable(),
      responseSha256: Sha256HexSchema.nullable()
    })
    .strict()
    .parse(rawInput);
  if (
    (input.resultClass === "delivered" && input.errorClass !== null) ||
    (input.resultClass !== "delivered" && input.errorClass === null)
  ) {
    throw new TypeError("notification result and error class do not match");
  }
  const completed = await client.query<{
    organization_id: string;
    board_id: string | null;
    webhook_id: string;
    resulting_state: string;
    replayed: boolean;
  }>(
    `select organization_id,board_id,webhook_id,resulting_state,replayed
       from boardagent_complete_notification_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      input.attemptId,
      input.notificationJobId,
      input.leaseOwner,
      input.attempt,
      Buffer.from(input.requestSha256, "hex"),
      input.resultClass,
      input.errorClass,
      input.httpStatus,
      input.responseSha256 === null ? null : Buffer.from(input.responseSha256, "hex")
    ]
  );
  const row = completed.rows[0];
  if (!row) return { completed: false, notificationJobId: input.notificationJobId };
  const state = z.enum(["delivered", "retry", "dead", "cancelled"]).parse(row.resulting_state);
  if (!row.replayed) {
    await appendAuditEventsInTransaction(client, [
      {
        organizationId: UuidV7Schema.parse(row.organization_id),
        objectVersion: BigInt(input.attempt),
        event: {
          eventId: input.auditEventId,
          eventType: "webhook_delivery_attempted",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "notification_job",
          entityId: input.notificationJobId,
          boardId: row.board_id === null ? null : UuidV7Schema.parse(row.board_id),
          origin: "worker",
          details: {
            webhookId: UuidV7Schema.parse(row.webhook_id),
            attempt: input.attempt,
            requestSha256: input.requestSha256,
            resultClass: input.resultClass,
            errorClass: input.errorClass,
            httpStatus: input.httpStatus,
            responseSha256: input.responseSha256,
            resultingState: state
          },
          schemaVersion: 1
        }
      }
    ]);
  }
  return {
    completed: true,
    notificationJobId: input.notificationJobId,
    state,
    replayed: row.replayed
  };
}
