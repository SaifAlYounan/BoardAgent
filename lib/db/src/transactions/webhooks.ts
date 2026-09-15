import type { PoolClient } from "pg";
import { z } from "zod";

import type { AuditEventType } from "@boardagent/audit";
import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { enqueueRequestJobInTransaction } from "../jobs.js";
import { readRequestContext } from "./request-context.js";

const EventClassSchema = z.enum(["pending_action", "notice", "security"]);
const SnapshotSchema = z
  .object({
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    webhookId: UuidV7Schema,
    state: z.enum(["absent", "active"]),
    generation: z.string().regex(/^\d+$/u),
    endpointSha256: Sha256HexSchema.nullable(),
    keyId: UuidV7Schema,
    eventClasses: z.array(EventClassSchema).optional()
  })
  .strict();

const ConfigureRequestSchema = z
  .object({
    kind: z.literal("configure_webhook"),
    webhookId: UuidV7Schema,
    endpointCiphertext: z.string().min(44).max(5_464),
    endpointSha256: Sha256HexSchema,
    validationReceiptSha256: Sha256HexSchema,
    eventClasses: z.array(EventClassSchema).min(1).max(3),
    keyId: UuidV7Schema,
    recentAuthProofSha256: Sha256HexSchema,
    exactOrigin: z.url()
  })
  .strict();
const RotateRequestSchema = z
  .object({
    kind: z.literal("rotate_webhook_secret"),
    webhookId: UuidV7Schema,
    keyId: UuidV7Schema,
    recentAuthProofSha256: Sha256HexSchema,
    exactOrigin: z.url()
  })
  .strict();
const DisableRequestSchema = z
  .object({
    kind: z.literal("disable_webhook"),
    webhookId: UuidV7Schema,
    keyId: z.null(),
    reason: z.string().min(1).max(65_536),
    exactOrigin: z.url()
  })
  .strict();
const RequestSchema = z.discriminatedUnion("kind", [
  ConfigureRequestSchema,
  RotateRequestSchema,
  DisableRequestSchema
]);
const CanonicalPayloadSchema = z
  .object({
    schemaVersion: z.literal("boardagent.webhook-administration.v1"),
    actionCode: z.enum(["configure_webhook", "rotate_webhook_secret", "disable_webhook"]),
    webhookId: UuidV7Schema,
    request: RequestSchema,
    current: SnapshotSchema
  })
  .strict();

export type WebhookAdministrationRequest = z.infer<typeof RequestSchema>;

export interface PreparedWebhookAdministrationAction {
  readonly actionCode: WebhookAdministrationRequest["kind"];
  readonly boardId: null;
  readonly targetType: "webhook";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.webhook-administration.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: null;
}

export interface WebhookAdministrationStageInput {
  readonly prepared: PreparedWebhookAdministrationAction;
  readonly stage: Omit<
    StageActionInput,
    | "boardId"
    | "actingForMemberId"
    | "actionCode"
    | "targetType"
    | "targetId"
    | "canonicalSchema"
    | "canonicalPayload"
    | "packageSha256"
    | "originalName"
  >;
}

export interface WebhookSecretMaterial {
  readonly keyId: string;
  readonly secretCiphertext: Uint8Array;
  readonly secretSha256: string;
}

export interface WebhookAdministrationConfirmationInput {
  readonly confirmation: ConfirmStagedActionInput;
  readonly secretMaterial: WebhookSecretMaterial | null;
  readonly auditEventId: string;
}

export interface WebhookAdministrationResult {
  readonly actionCode: WebhookAdministrationRequest["kind"];
  readonly webhookId: string;
  readonly data: JsonValue;
}

export interface OwnedWebhookMaterial {
  readonly organizationId: string;
  readonly memberId: string;
  readonly webhookId: string;
  readonly endpointCiphertext: Buffer;
  readonly secretCiphertext: Buffer;
  readonly endpointSha256: string;
  readonly secretSha256: string;
  readonly keyId: string;
  readonly generation: bigint;
  readonly eventClasses: readonly z.infer<typeof EventClassSchema>[];
}

export type TestWebhookResult =
  | {
      readonly replayed: true;
      readonly webhookId: string;
      readonly notificationJobId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly webhookId: string;
      readonly notificationJobId: string;
      readonly payloadSha256: string;
      readonly responseSha256: string;
      readonly auditSequence: bigint;
    };

export class WebhookTransactionError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "WebhookTransactionError";
  }
}

function exactOrigin(value: string): string {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== value ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new TypeError("webhook action requires one exact HTTPS service origin");
  }
  return value;
}

function canonicalBase64(value: string): string {
  const bytes = Buffer.from(value, "base64");
  if (bytes.length < 32 || bytes.length > 4_096 || bytes.toString("base64") !== value) {
    throw new TypeError("webhook ciphertext must use canonical bounded base64");
  }
  return value;
}

function eventClasses(
  values: readonly z.infer<typeof EventClassSchema>[]
): readonly z.infer<typeof EventClassSchema>[] {
  const normalized = values.map((value) => EventClassSchema.parse(value)).toSorted();
  if (
    normalized.length < 1 ||
    normalized.length > 3 ||
    new Set(normalized).size !== normalized.length
  ) {
    throw new WebhookTransactionError("webhook event classes must be one unique allowlist");
  }
  return normalized;
}

export function normalizeWebhookAdministrationRequest(
  input: WebhookAdministrationRequest
): WebhookAdministrationRequest {
  const parsed = RequestSchema.parse(input);
  if (parsed.kind === "configure_webhook") {
    return {
      ...parsed,
      endpointCiphertext: canonicalBase64(parsed.endpointCiphertext),
      eventClasses: [...eventClasses(parsed.eventClasses)],
      exactOrigin: exactOrigin(parsed.exactOrigin)
    };
  }
  if (parsed.kind === "rotate_webhook_secret") {
    return { ...parsed, exactOrigin: exactOrigin(parsed.exactOrigin) };
  }
  return {
    ...parsed,
    reason: canonicalText(parsed.reason),
    exactOrigin: exactOrigin(parsed.exactOrigin)
  };
}

async function snapshot(
  client: PoolClient,
  request: WebhookAdministrationRequest
): Promise<z.infer<typeof SnapshotSchema>> {
  const result = await client.query<{ snapshot: unknown }>(
    "select boardagent_webhook_snapshot($1,$2,$3,$4) as snapshot",
    [request.kind, request.webhookId, request.keyId, request.exactOrigin]
  );
  return SnapshotSchema.parse(result.rows[0]?.snapshot);
}

function preparedFromPayload(rawPayload: unknown): PreparedWebhookAdministrationAction {
  const payload = CanonicalPayloadSchema.parse(rawPayload);
  if (
    payload.actionCode !== payload.request.kind ||
    payload.webhookId !== payload.request.webhookId
  ) {
    throw new WebhookTransactionError("webhook action target binding is invalid");
  }
  return {
    actionCode: payload.actionCode,
    boardId: null,
    targetType: "webhook",
    targetId: payload.webhookId,
    canonicalSchema: "boardagent.webhook-administration.v1",
    canonicalPayload: payload as JsonValue,
    payloadSha256: canonicalSha256(payload),
    packageSha256: null
  };
}

export async function prepareWebhookAdministrationActionInTransaction(
  client: PoolClient,
  rawRequest: WebhookAdministrationRequest
): Promise<PreparedWebhookAdministrationAction> {
  const request = normalizeWebhookAdministrationRequest(rawRequest);
  const current = await snapshot(client, request);
  return preparedFromPayload({
    schemaVersion: "boardagent.webhook-administration.v1",
    actionCode: request.kind,
    webhookId: request.webhookId,
    request,
    current
  });
}

async function revalidatePrepared(
  client: PoolClient,
  input: PreparedWebhookAdministrationAction
): Promise<PreparedWebhookAdministrationAction> {
  const prepared = preparedFromPayload(input.canonicalPayload);
  if (
    prepared.actionCode !== input.actionCode ||
    prepared.targetId !== input.targetId ||
    prepared.canonicalSchema !== input.canonicalSchema ||
    !safeHashEqual(prepared.payloadSha256, input.payloadSha256) ||
    input.packageSha256 !== null
  ) {
    throw new WebhookTransactionError("prepared webhook action changed after rendering");
  }
  const payload = CanonicalPayloadSchema.parse(prepared.canonicalPayload);
  const live = await snapshot(client, payload.request);
  if (!safeHashEqual(canonicalSha256(live), canonicalSha256(payload.current))) {
    throw new WebhookTransactionError("webhook authority or state changed");
  }
  return prepared;
}

export async function stageWebhookAdministrationActionInTransaction(
  client: PoolClient,
  input: WebhookAdministrationStageInput
): Promise<StagedAction & PreparedWebhookAdministrationAction> {
  const prepared = await revalidatePrepared(client, input.prepared);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: null,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: "webhook",
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: null,
      originalName: prepared.actionCode
    },
    async () => undefined
  );
  return { ...prepared, ...staged, packageSha256: null };
}

function eventType(action: WebhookAdministrationRequest["kind"]): AuditEventType {
  if (action === "configure_webhook") return "webhook_configured";
  if (action === "rotate_webhook_secret") return "webhook_secret_rotated";
  return "webhook_disabled";
}

export async function confirmWebhookAdministrationActionInTransaction(
  client: PoolClient,
  input: WebhookAdministrationConfirmationInput
): Promise<StagedActionResolution<WebhookAdministrationResult>> {
  const stageState = await client.query<{ state: string }>(
    "select state from action_stages where id=$1",
    [input.confirmation.stageId]
  );
  if (!stageState.rows[0]) return { confirmed: false, reason: "stage_unavailable" };
  if (stageState.rows[0].state !== "active") {
    return { confirmed: false, reason: "stage_not_active" };
  }
  let prepared: PreparedWebhookAdministrationAction | undefined;
  let payload: z.infer<typeof CanonicalPayloadSchema> | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      const stage = await requestClient.query<{ canonical_payload: Buffer }>(
        "select canonical_payload from action_stages where id=$1",
        [input.confirmation.stageId]
      );
      const bytes = stage.rows[0]?.canonical_payload;
      if (!bytes) throw new WebhookTransactionError("webhook stage is unavailable");
      prepared = await revalidatePrepared(
        requestClient,
        preparedFromPayload(JSON.parse(bytes.toString("utf8")) as unknown)
      );
      payload = CanonicalPayloadSchema.parse(prepared.canonicalPayload);
      return { payloadSha256: prepared.payloadSha256, packageSha256: null };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared || !payload) throw new Error("webhook confirmation preparation is unavailable");
      const requiresSecret = prepared.actionCode !== "disable_webhook";
      const material = input.secretMaterial;
      if (
        requiresSecret !== (material !== null) ||
        (material !== null && material.keyId !== payload.request.keyId)
      ) {
        throw new WebhookTransactionError("webhook secret material does not match the action key");
      }
      const secretCiphertext = material === null ? null : Buffer.from(material.secretCiphertext);
      if (
        secretCiphertext !== null &&
        (secretCiphertext.length < 32 || secretCiphertext.length > 4096)
      ) {
        throw new WebhookTransactionError("webhook secret ciphertext is invalid");
      }
      const applied = await requestClient.query<{ result: unknown }>(
        `select boardagent_apply_webhook_action($1,$2,$3::jsonb,$4,$5,$6,$7) as result`,
        [
          prepared.actionCode,
          prepared.targetId,
          payload,
          Buffer.from(prepared.payloadSha256, "hex"),
          consentRecordId,
          secretCiphertext,
          material === null
            ? null
            : Buffer.from(Sha256HexSchema.parse(material.secretSha256), "hex")
        ]
      );
      const data = z.record(z.string(), z.json()).parse(applied.rows[0]?.result) as JsonValue;
      const context = await readRequestContext(requestClient);
      const auditEvents: AuditAppendInput[] = [
        {
          organizationId: context.organizationId,
          consentRecordId,
          event: {
            eventId: UuidV7Schema.parse(input.auditEventId),
            eventType: eventType(prepared.actionCode),
            actorMemberId: context.memberId,
            actorClientId: context.clientId,
            tokenJti: context.tokenJti,
            entityType: "webhook",
            entityId: prepared.targetId,
            boardId: null,
            origin: "mcp",
            details: {
              actionCode: prepared.actionCode,
              endpointFingerprint:
                payload.request.kind === "configure_webhook"
                  ? payload.request.endpointSha256
                  : payload.current.endpointSha256,
              generation: (data as Readonly<Record<string, JsonValue>>)["generation"] ?? null,
              reason: payload.request.kind === "disable_webhook" ? payload.request.reason : null
            },
            schemaVersion: 1
          }
        }
      ];
      return {
        value: { actionCode: prepared.actionCode, webhookId: prepared.targetId, data },
        auditEvents
      };
    }
  );
}

export async function readOwnedWebhookMaterialInTransaction(
  client: PoolClient,
  rawInput: { readonly webhookId: string; readonly exactOrigin: string }
): Promise<OwnedWebhookMaterial> {
  const webhookId = UuidV7Schema.parse(rawInput.webhookId);
  const origin = exactOrigin(rawInput.exactOrigin);
  const result = await client.query<{
    organization_id: string;
    member_id: string;
    webhook_id: string;
    endpoint_ciphertext: Buffer;
    secret_ciphertext: Buffer;
    endpoint_sha256: Buffer;
    secret_sha256: Buffer;
    key_id: string;
    generation: string;
    event_classes: string[];
  }>("select * from boardagent_owned_webhook_material($1,$2)", [webhookId, origin]);
  const row = result.rows[0];
  if (!row || result.rows.length !== 1)
    throw new WebhookTransactionError("owned webhook is unavailable");
  return {
    organizationId: UuidV7Schema.parse(row.organization_id),
    memberId: UuidV7Schema.parse(row.member_id),
    webhookId: UuidV7Schema.parse(row.webhook_id),
    endpointCiphertext: row.endpoint_ciphertext,
    secretCiphertext: row.secret_ciphertext,
    endpointSha256: Sha256HexSchema.parse(row.endpoint_sha256.toString("hex")),
    secretSha256: Sha256HexSchema.parse(row.secret_sha256.toString("hex")),
    keyId: UuidV7Schema.parse(row.key_id),
    generation: BigInt(row.generation),
    eventClasses: eventClasses(row.event_classes.map((value) => EventClassSchema.parse(value)))
  };
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 200 || !/^[A-Za-z0-9._~-]+$/u.test(value)) {
    throw new RangeError("idempotency key must match the frozen 16-to-200 character form");
  }
  return value;
}

function testResponseSha256(webhookId: string, notificationJobId: string): string {
  return canonicalSha256({
    schemaVersion: "boardagent.webhook-test-safe-response.v1",
    webhookId,
    notificationJobId
  });
}

export async function testWebhookInTransaction(
  client: PoolClient,
  input: {
    readonly webhookId: string;
    readonly exactOrigin: string;
    readonly idempotencyRecordId: string;
    readonly idempotencyKey: string;
    readonly notificationJobId: string;
    readonly randomWakeId: Uint8Array;
    readonly auditEventId: string;
  }
): Promise<TestWebhookResult> {
  const webhookId = UuidV7Schema.parse(input.webhookId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const notificationJobId = UuidV7Schema.parse(input.notificationJobId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const wakeId = Buffer.from(input.randomWakeId);
  if (wakeId.length !== 32) throw new RangeError("webhook wake ID must contain 32 bytes");
  const material = await readOwnedWebhookMaterialInTransaction(client, {
    webhookId,
    exactOrigin: input.exactOrigin
  });
  const context = await readRequestContext(client);
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.webhook-test-request.v1",
    webhookId,
    endpointSha256: material.endpointSha256,
    generation: material.generation.toString(10)
  });
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'test_webhook',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      idempotencyRecordId,
      context.organizationId,
      context.memberId,
      context.clientId,
      key,
      Buffer.from(requestSha256, "hex")
    ]
  );
  const record = await client.query<{
    request_sha256: Buffer;
    state: string;
    safe_response_type: string | null;
    safe_response_id: string | null;
    safe_response_sha256: Buffer | null;
  }>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation='test_webhook' and idempotency_key=$3
      for update`,
    [context.memberId, context.clientId, key]
  );
  const idempotency = record.rows[0];
  if (!idempotency || !safeHashEqual(idempotency.request_sha256.toString("hex"), requestSha256)) {
    throw new WebhookTransactionError("webhook test idempotency binding conflicts");
  }
  if (inserted.rowCount === 0) {
    if (
      idempotency.state !== "succeeded" ||
      idempotency.safe_response_type !== "notification_job" ||
      !idempotency.safe_response_id ||
      !idempotency.safe_response_sha256
    ) {
      throw new WebhookTransactionError("identical webhook test is already in progress");
    }
    const responseSha256 = testResponseSha256(webhookId, idempotency.safe_response_id);
    if (!safeHashEqual(idempotency.safe_response_sha256.toString("hex"), responseSha256)) {
      throw new Error("webhook test safe response hash is invalid");
    }
    return {
      replayed: true,
      webhookId,
      notificationJobId: idempotency.safe_response_id,
      responseSha256
    };
  }
  const timestamp = await client.query<{ occurred_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
  );
  const occurredAt = Rfc3339UtcSchema.parse(timestamp.rows[0]?.occurred_at);
  const payload = {
    schemaVersion: "boardagent.webhook-wake.v1" as const,
    eventClass: "security" as const,
    wakeId: wakeId.toString("base64url"),
    occurredAt
  };
  const canonicalPayload = Buffer.from(canonicalJson(payload), "utf8");
  const payloadSha256 = canonicalSha256(payload);
  await client.query(
    `insert into notification_jobs(
       id,organization_id,notice_id,recipient_member_id,webhook_id,source_kind,
       wake_class,random_wake_id,canonical_payload,payload_sha256,state
     ) values ($1,$2,null,$3,$4,'test','security',$5,$6,$7,'queued')`,
    [
      notificationJobId,
      context.organizationId,
      context.memberId,
      webhookId,
      wakeId,
      canonicalPayload,
      Buffer.from(payloadSha256, "hex")
    ]
  );
  await enqueueRequestJobInTransaction(client, {
    jobId: notificationJobId,
    idempotencyKey: `webhook-delivery:${notificationJobId}`,
    envelope: {
      schemaVersion: "boardagent.job.webhook_delivery.v1",
      organizationId: context.organizationId,
      boardId: null,
      jobType: "webhook_delivery",
      subjectType: "notification_job",
      subjectId: notificationJobId,
      parameters: { notificationJobId }
    }
  });
  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: context.organizationId,
      event: {
        eventId: auditEventId,
        eventType: "webhook_tested",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "webhook",
        entityId: webhookId,
        boardId: null,
        origin: "mcp",
        details: {
          notificationJobId,
          endpointFingerprint: material.endpointSha256,
          generation: material.generation.toString(10),
          payloadSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("webhook test audit append returned no event");
  const responseSha256 = testResponseSha256(webhookId, notificationJobId);
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='notification_job',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4 and operation='test_webhook'
        and idempotency_key=$5 and state='in_progress'`,
    [notificationJobId, Buffer.from(responseSha256, "hex"), context.memberId, context.clientId, key]
  );
  if (completed.rowCount !== 1) throw new Error("webhook test idempotency completion failed");
  return {
    replayed: false,
    webhookId,
    notificationJobId,
    payloadSha256,
    responseSha256,
    auditSequence: audit.sequence
  };
}

export function webhookSecretFingerprint(secret: Uint8Array): string {
  return sha256Hex(secret);
}
