import { randomBytes } from "node:crypto";

import type { PoolClient } from "pg";
import { z } from "zod";

import {
  PendingActionDeltaSchema,
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
import { uuidV7 } from "@boardagent/domain";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

const MAX_IDEMPOTENCY_KEY = 256;

const DocumentEvidenceReferenceSchema = z
  .object({
    documentVersionId: UuidV7Schema,
    sha256: Sha256HexSchema
  })
  .strict();
const ResourceEvidenceReferenceSchema = z
  .object({
    resourceUri: z.url().max(4_096),
    sha256: Sha256HexSchema
  })
  .strict();
const TaskEvidencePayloadSchema = z
  .object({
    schemaVersion: z.literal("boardagent.task-evidence.v1"),
    taskId: UuidV7Schema,
    canonicalText: z
      .string()
      .transform((value) => canonicalText(value))
      .pipe(z.string().min(1).max(262_144))
      .nullable(),
    documentReferences: z.array(DocumentEvidenceReferenceSchema).max(1_000),
    resourceReferences: z.array(ResourceEvidenceReferenceSchema).max(1_000)
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.canonicalText === null &&
      value.documentReferences.length === 0 &&
      value.resourceReferences.length === 0
    ) {
      context.addIssue({
        code: "custom",
        message: "task evidence requires text or at least one exact reference"
      });
    }
    const exactReferences = [
      ...value.documentReferences.map(
        ({ documentVersionId, sha256 }) => `document:${documentVersionId}:${sha256}`
      ),
      ...value.resourceReferences.map(
        ({ resourceUri, sha256 }) => `resource:${resourceUri}:${sha256}`
      )
    ];
    if (new Set(exactReferences).size !== exactReferences.length) {
      context.addIssue({ code: "custom", message: "task evidence references must be unique" });
    }
  });

export type TaskEvidencePayload = z.infer<typeof TaskEvidencePayloadSchema>;

export interface StartTaskInput {
  readonly taskId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface SubmitTaskEvidenceInput {
  readonly evidenceId: string;
  readonly payload: unknown;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface DirectTaskResult {
  readonly replayed: boolean;
  readonly taskId: string;
  readonly safeResponseId: string;
  readonly responseSha256: string;
}

export interface TaskCreationAction {
  readonly taskId: string;
  readonly boardId: string;
  readonly ownerMemberId: string;
  readonly dueAt: string;
  readonly description: string;
  readonly requiredEvidence: readonly string[];
  readonly sourceMinutesId: string | null;
  readonly sourceMinutesVersionId: string | null;
}

export interface PreparedTaskCreationAction {
  readonly actionCode: "create_task";
  readonly organizationId: string;
  readonly actorMemberId: string;
  readonly actorClientId: string;
  readonly tokenJti: string;
  readonly boardId: string;
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.task-creation.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
  readonly ownerEntitlementGeneration: string;
  readonly sourceMeetingId: string | null;
  readonly sourceMinutesSha256: string | null;
  readonly sourceLocator: JsonValue | null;
  readonly action: TaskCreationAction;
}

export interface TaskCreationStageInput {
  readonly action: TaskCreationAction;
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

export interface TaskCreationConfirmationInput {
  readonly action: TaskCreationAction;
  readonly confirmation: ConfirmStagedActionInput;
}

export interface TaskCreationResult {
  readonly taskId: string;
  readonly taskSha256: string;
  readonly ownerMemberId: string;
}

export interface ReplacementTaskInput {
  readonly ownerMemberId: string;
  readonly dueAt: string;
  readonly description: string;
  readonly requiredEvidence: readonly string[];
}

export type TaskLifecycleAction =
  | {
      readonly kind: "evidence_review";
      readonly taskId: string;
      readonly evidenceId: string;
      readonly decision: "accepted" | "rejected";
      readonly reason: string;
    }
  | {
      readonly kind: "closure";
      readonly taskId: string;
      readonly acceptedEvidenceIds: readonly string[];
    }
  | {
      readonly kind: "completed_correction";
      readonly taskId: string;
      readonly replacementTaskId: string;
      readonly reason: string;
      readonly replacement: ReplacementTaskInput;
    }
  | {
      readonly kind: "cancellation";
      readonly taskId: string;
      readonly reason: string;
    };

export interface TaskLifecycleStageInput {
  readonly action: TaskLifecycleAction;
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

export interface TaskLifecycleConfirmationInput {
  readonly action: TaskLifecycleAction;
  readonly confirmation: ConfirmStagedActionInput;
}

export interface PreparedTaskLifecycleAction {
  readonly actionCode: string;
  readonly boardId: string;
  readonly targetId: string;
  readonly canonicalSchema: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
}

export interface StagedTaskLifecycleAction extends StagedAction {
  readonly actionCode: string;
  readonly boardId: string;
  readonly targetId: string;
}

export type TaskLifecycleResult =
  | {
      readonly kind: "evidence_review";
      readonly taskId: string;
      readonly evidenceId: string;
      readonly reviewId: string;
      readonly decision: "accepted" | "rejected";
    }
  | {
      readonly kind: "closure";
      readonly taskId: string;
      readonly closureId: string;
      readonly closureSha256: string;
    }
  | {
      readonly kind: "completed_correction";
      readonly priorTaskId: string;
      readonly replacementTaskId: string;
      readonly correctionCycleId: string;
    }
  | {
      readonly kind: "cancellation";
      readonly taskId: string;
    };

export class TaskTransactionError extends Error {
  public constructor(
    public readonly code:
      | "task_unavailable"
      | "task_invalid"
      | "task_evidence_unavailable"
      | "task_closure_unavailable"
      | "idempotency_conflict",
    message: string
  ) {
    super(message);
    this.name = "TaskTransactionError";
  }
}

interface TaskRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly id: string;
  readonly owner_member_id: string;
  readonly state:
    | "draft"
    | "open"
    | "in_progress"
    | "evidence_submitted"
    | "completed"
    | "cancelled"
    | "superseded";
  readonly row_version: string;
  readonly task_sha256: Buffer;
  readonly source_meeting_id: string | null;
  readonly source_minutes_id: string | null;
  readonly source_minutes_version_id: string | null;
  readonly source_minutes_sha256: Buffer | null;
  readonly source_locator: JsonValue | null;
  readonly actor_is_secretary: boolean;
  readonly actor_entitlement_generation: string;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface EvidenceRow {
  readonly id: string;
  readonly canonical_sha256: Buffer;
  readonly state: "submitted" | "accepted" | "rejected";
  readonly review_id: string | null;
}

interface PreparedTaskAction {
  readonly action: NormalizedTaskAction;
  readonly root: TaskRootRow;
  readonly context: ActiveRequestContext;
  readonly payload: JsonValue;
  readonly payloadSha256: string;
  readonly details: PreparedTaskDetails;
}

type NormalizedTaskAction =
  | (Extract<TaskLifecycleAction, { readonly kind: "evidence_review" }> & {
      readonly taskId: string;
      readonly evidenceId: string;
      readonly reason: string;
    })
  | (Extract<TaskLifecycleAction, { readonly kind: "closure" }> & {
      readonly taskId: string;
      readonly acceptedEvidenceIds: readonly string[];
    })
  | (Extract<TaskLifecycleAction, { readonly kind: "completed_correction" }> & {
      readonly taskId: string;
      readonly replacementTaskId: string;
      readonly reason: string;
      readonly replacement: ReplacementTaskInput;
    })
  | (Extract<TaskLifecycleAction, { readonly kind: "cancellation" }> & {
      readonly taskId: string;
      readonly reason: string;
    });

type PreparedTaskDetails =
  | { readonly kind: "evidence_review"; readonly evidence: EvidenceRow }
  | {
      readonly kind: "closure";
      readonly evidence: readonly EvidenceRow[];
      readonly acceptedEvidenceManifest: JsonValue;
      readonly closureSha256: string;
    }
  | {
      readonly kind: "completed_correction";
      readonly closureId: string;
      readonly closureSha256: string;
      readonly replacementTaskSha256: string;
      readonly ownerEntitlementGeneration: string;
    }
  | { readonly kind: "cancellation" };

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > MAX_IDEMPOTENCY_KEY) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function reason(value: string): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > 65_536) {
    throw new RangeError("task reason must contain 1 through 65536 characters");
  }
  return normalized;
}

function description(value: string, label: string): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > 262_144) {
    throw new RangeError(`${label} must contain 1 through 262144 characters`);
  }
  return normalized;
}

function requiredEvidence(values: readonly string[]): readonly string[] {
  if (values.length === 0 || values.length > 256) {
    throw new RangeError("required evidence requires 1 through 256 items");
  }
  const normalized = values.map((item) => description(item, "required evidence item"));
  if (new Set(normalized).size !== normalized.length) {
    throw new TypeError("required evidence items must be unique");
  }
  return normalized;
}

function normalizeTaskCreation(input: TaskCreationAction): TaskCreationAction {
  const sourceMinutesId =
    input.sourceMinutesId === null ? null : UuidV7Schema.parse(input.sourceMinutesId);
  const sourceMinutesVersionId =
    input.sourceMinutesVersionId === null ? null : UuidV7Schema.parse(input.sourceMinutesVersionId);
  if ((sourceMinutesId === null) !== (sourceMinutesVersionId === null)) {
    throw new TaskTransactionError(
      "task_invalid",
      "task source minutes and source minutes version must both be present or both be null"
    );
  }
  return {
    taskId: UuidV7Schema.parse(input.taskId),
    boardId: UuidV7Schema.parse(input.boardId),
    ownerMemberId: UuidV7Schema.parse(input.ownerMemberId),
    dueAt: Rfc3339UtcSchema.parse(input.dueAt),
    description: description(input.description, "task description"),
    requiredEvidence: requiredEvidence(input.requiredEvidence),
    sourceMinutesId,
    sourceMinutesVersionId
  };
}

async function lockTask(
  client: PoolClient,
  taskId: string,
  authority: "owner" | "secretary"
): Promise<{ readonly root: TaskRootRow; readonly context: ActiveRequestContext }> {
  const context = await readRequestContext(client);
  const result = await client.query<TaskRootRow>(
    `select task.organization_id,task.board_id,task.id,task.owner_member_id,task.state,
            task.row_version::text,task.task_sha256,task.source_meeting_id,
            task.source_minutes_id,task.source_minutes_version_id,task.source_minutes_sha256,
            task.source_locator,membership.is_secretary as actor_is_secretary,
            membership.entitlement_generation::text as actor_entitlement_generation
       from tasks as task
       join board_memberships as membership
         on membership.organization_id=task.organization_id
        and membership.board_id=task.board_id
        and membership.member_id=boardagent_context_uuid('boardagent.member_id')
       join members as actor on actor.id=membership.member_id
       join access_token_records as token
         on token.organization_id=actor.organization_id and token.member_id=actor.id
        and token.client_id=boardagent_context_uuid('boardagent.client_id')
        and token.jti=boardagent_context_uuid('boardagent.token_jti')
       join oauth_clients as oauth_client on oauth_client.id=token.client_id
       join system_instance as instance
         on instance.organization_id=actor.organization_id
        and instance.canonical_resource_uri=token.resource_uri
      where task.id=$1
        and task.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(task.board_id)
        and actor.state='active' and membership.state='active'
        and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
        and oauth_client.state='active' and token.revoked_at is null
        and token.expires_at>transaction_timestamp()
        and (($2='owner' and task.owner_member_id=actor.id and 'task:act'=any(token.scope_set))
          or ($2='secretary' and membership.is_secretary and 'secretariat:admin'=any(token.scope_set)))
        and exists (
          select 1 from onboarding_attestations as attestation
           where attestation.organization_id=actor.organization_id
             and attestation.member_id=actor.id and attestation.board_id=task.board_id
             and attestation.terms_version_id=(
               select terms.id from onboarding_terms_versions as terms
                where terms.organization_id=actor.organization_id
                  and terms.seat_role=membership.seat_role
                  and terms.effective_at<=transaction_timestamp()
                order by terms.effective_at desc,terms.version desc,terms.id desc limit 1
             )
             and attestation.support_version_id=(
               select support.id from secretary_support_versions as support
                where support.organization_id=actor.organization_id
                  and (support.board_id=task.board_id or support.board_id is null)
                  and support.effective_at<=transaction_timestamp()
                order by (support.board_id=task.board_id) desc,
                         support.effective_at desc,support.version desc,support.id desc limit 1
             )
        )
      for update of task`,
    [taskId, authority]
  );
  const root = result.rows[0];
  if (!root || result.rows.length !== 1) {
    throw new TaskTransactionError("task_unavailable", "task is unavailable");
  }
  return { root, context };
}

async function lockIdempotency(
  client: PoolClient,
  context: ActiveRequestContext,
  operation: string,
  key: string,
  requestSha256: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      for update`,
    [context.memberId, context.clientId, operation, key]
  );
  const row = result.rows[0];
  if (!row) return undefined;
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new TaskTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for different task bytes"
    );
  }
  if (row.state !== "succeeded" || !row.safe_response_id || !row.safe_response_sha256) {
    throw new TaskTransactionError(
      "idempotency_conflict",
      "identical task operation is not a completed safe response"
    );
  }
  return row;
}

async function insertIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly context: ActiveRequestContext;
    readonly operation: string;
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<void> {
  await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'in_progress',transaction_timestamp()+interval '24 hours')`,
    [
      input.id,
      input.context.organizationId,
      input.context.memberId,
      input.context.clientId,
      input.operation,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
}

async function completeIdempotency(
  client: PoolClient,
  id: string,
  responseType: string,
  responseId: string,
  responseSha256: string
): Promise<void> {
  const updated = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type=$1,safe_response_id=$2,
            safe_response_sha256=$3,completed_at=transaction_timestamp()
      where id=$4 and state='in_progress'`,
    [responseType, responseId, Buffer.from(responseSha256, "hex"), id]
  );
  if (updated.rowCount !== 1) throw new Error("task idempotency completion failed");
}

function directAudit(
  root: TaskRootRow,
  context: ActiveRequestContext,
  eventId: string,
  eventType: "task_started" | "task_evidence_submitted",
  entityType: string,
  entityId: string,
  details: Readonly<Record<string, JsonValue>>,
  objectVersion: bigint
): AuditAppendInput {
  return {
    organizationId: root.organization_id,
    objectVersion,
    event: {
      eventId,
      eventType,
      actorMemberId: context.memberId,
      actorClientId: context.clientId,
      tokenJti: context.tokenJti,
      entityType,
      entityId,
      boardId: root.board_id,
      origin: "mcp",
      details,
      schemaVersion: 1
    }
  };
}

export async function startTaskInTransaction(
  client: PoolClient,
  rawInput: StartTaskInput
): Promise<DirectTaskResult> {
  const taskId = UuidV7Schema.parse(rawInput.taskId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const key = idempotencyKey(rawInput.idempotencyKey);
  const { root, context } = await lockTask(client, taskId, "owner");
  const requestSha256 = canonicalSha256({ operation: "start_task", taskId });
  const replay = await lockIdempotency(client, context, "start_task", key, requestSha256);
  if (replay) {
    return {
      replayed: true,
      taskId,
      safeResponseId: replay.safe_response_id!,
      responseSha256: replay.safe_response_sha256!.toString("hex")
    };
  }
  if (root.state !== "open") {
    throw new TaskTransactionError("task_unavailable", "only an open owned task may start");
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    context,
    operation: "start_task",
    key,
    requestSha256
  });
  const updated = await client.query(
    `update tasks set state='in_progress',row_version=row_version+1
      where id=$1 and row_version=$2::bigint and state='open'`,
    [taskId, root.row_version]
  );
  if (updated.rowCount !== 1) throw new Error("task changed while starting");
  await appendAuditEventsInTransaction(client, [
    directAudit(
      root,
      context,
      auditEventId,
      "task_started",
      "task",
      taskId,
      { taskSha256: root.task_sha256.toString("hex") },
      BigInt(root.row_version) + 1n
    )
  ]);
  const responseSha256 = canonicalSha256({ taskId, state: "in_progress" });
  await completeIdempotency(client, idempotencyRecordId, "task", taskId, responseSha256);
  return { replayed: false, taskId, safeResponseId: taskId, responseSha256 };
}

export async function submitTaskEvidenceInTransaction(
  client: PoolClient,
  rawInput: SubmitTaskEvidenceInput
): Promise<DirectTaskResult> {
  const payload = TaskEvidencePayloadSchema.parse(rawInput.payload);
  const evidenceId = UuidV7Schema.parse(rawInput.evidenceId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const key = idempotencyKey(rawInput.idempotencyKey);
  const { root, context } = await lockTask(client, payload.taskId, "owner");
  const evidenceSha256 = canonicalSha256(payload);
  const requestSha256 = canonicalSha256({ operation: "submit_task_evidence", payload });
  const replay = await lockIdempotency(client, context, "submit_task_evidence", key, requestSha256);
  if (replay) {
    return {
      replayed: true,
      taskId: root.id,
      safeResponseId: replay.safe_response_id!,
      responseSha256: replay.safe_response_sha256!.toString("hex")
    };
  }
  if (!(["open", "in_progress", "evidence_submitted"] as const).includes(root.state as never)) {
    throw new TaskTransactionError(
      "task_evidence_unavailable",
      "evidence is unavailable for the current task state"
    );
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    context,
    operation: "submit_task_evidence",
    key,
    requestSha256
  });
  await client.query(
    `insert into task_evidence(
       id,organization_id,board_id,task_id,owner_member_id,canonical_text,
       document_references,resource_references,canonical_sha256,state
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'submitted')`,
    [
      evidenceId,
      root.organization_id,
      root.board_id,
      root.id,
      context.memberId,
      payload.canonicalText,
      JSON.stringify(payload.documentReferences),
      JSON.stringify(payload.resourceReferences),
      Buffer.from(evidenceSha256, "hex")
    ]
  );
  const updated = await client.query(
    `update tasks set state='evidence_submitted',row_version=row_version+1
      where id=$1 and row_version=$2::bigint and state in ('open','in_progress','evidence_submitted')`,
    [root.id, root.row_version]
  );
  if (updated.rowCount !== 1) throw new Error("task changed during evidence submission");
  await appendAuditEventsInTransaction(client, [
    directAudit(
      root,
      context,
      auditEventId,
      "task_evidence_submitted",
      "task_evidence",
      evidenceId,
      { taskId: root.id, evidenceSha256 },
      BigInt(root.row_version) + 1n
    )
  ]);
  const responseSha256 = canonicalSha256({ taskId: root.id, evidenceId });
  await completeIdempotency(
    client,
    idempotencyRecordId,
    "task_evidence",
    evidenceId,
    responseSha256
  );
  return { replayed: false, taskId: root.id, safeResponseId: evidenceId, responseSha256 };
}

function normalizeTaskAction(input: TaskLifecycleAction): NormalizedTaskAction {
  const taskId = UuidV7Schema.parse(input.taskId);
  switch (input.kind) {
    case "evidence_review":
      return {
        ...input,
        taskId,
        evidenceId: UuidV7Schema.parse(input.evidenceId),
        reason: reason(input.reason)
      };
    case "closure": {
      const acceptedEvidenceIds = input.acceptedEvidenceIds
        .map((id) => UuidV7Schema.parse(id))
        .toSorted();
      if (
        acceptedEvidenceIds.length === 0 ||
        new Set(acceptedEvidenceIds).size !== acceptedEvidenceIds.length
      ) {
        throw new TaskTransactionError(
          "task_invalid",
          "task closure requires a nonempty unique accepted-evidence set"
        );
      }
      return { ...input, taskId, acceptedEvidenceIds };
    }
    case "completed_correction":
      return {
        ...input,
        taskId,
        replacementTaskId: UuidV7Schema.parse(input.replacementTaskId),
        reason: reason(input.reason),
        replacement: {
          ownerMemberId: UuidV7Schema.parse(input.replacement.ownerMemberId),
          dueAt: Rfc3339UtcSchema.parse(input.replacement.dueAt),
          description: description(input.replacement.description, "replacement task description"),
          requiredEvidence: requiredEvidence(input.replacement.requiredEvidence)
        }
      };
    case "cancellation":
      return { ...input, taskId, reason: reason(input.reason) };
  }
}

function taskOperation(action: NormalizedTaskAction): {
  readonly actionCode: string;
  readonly canonicalSchema: string;
} {
  switch (action.kind) {
    case "evidence_review":
      return {
        actionCode: "review_task_evidence",
        canonicalSchema: "boardagent.task-evidence-review.v1"
      };
    case "closure":
      return { actionCode: "complete_task", canonicalSchema: "boardagent.task-closure.v1" };
    case "completed_correction":
      return {
        actionCode: "create_task_correction_cycle",
        canonicalSchema: "boardagent.task-correction-cycle.v1"
      };
    case "cancellation":
      return { actionCode: "cancel_task", canonicalSchema: "boardagent.task-cancellation.v1" };
  }
}

async function prepareEvidenceReview(
  client: PoolClient,
  action: Extract<NormalizedTaskAction, { readonly kind: "evidence_review" }>,
  root: TaskRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedTaskDetails }> {
  if (root.state !== "evidence_submitted") {
    throw new TaskTransactionError(
      "task_evidence_unavailable",
      "only evidence on an evidence-submitted task may be reviewed"
    );
  }
  const evidence = await client.query<EvidenceRow>(
    `select evidence.id,evidence.canonical_sha256,evidence.state,review.id as review_id
       from task_evidence as evidence
       left join task_evidence_reviews as review on review.evidence_id=evidence.id
      where evidence.id=$1 and evidence.task_id=$2`,
    [action.evidenceId, root.id]
  );
  const row = evidence.rows[0];
  if (!row || evidence.rows.length !== 1 || row.state !== "submitted" || row.review_id !== null) {
    throw new TaskTransactionError(
      "task_evidence_unavailable",
      "pending exact task evidence is unavailable"
    );
  }
  return {
    payload: {
      schemaVersion: "boardagent.task-evidence-review.v1",
      taskId: root.id,
      taskSha256: root.task_sha256.toString("hex"),
      evidenceId: row.id,
      evidenceSha256: row.canonical_sha256.toString("hex"),
      decision: action.decision,
      reason: action.reason
    },
    details: { kind: "evidence_review", evidence: row }
  };
}

async function prepareClosure(
  client: PoolClient,
  action: Extract<NormalizedTaskAction, { readonly kind: "closure" }>,
  root: TaskRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedTaskDetails }> {
  if (root.state !== "evidence_submitted") {
    throw new TaskTransactionError(
      "task_closure_unavailable",
      "only an evidence-submitted task may close"
    );
  }
  const evidence = await client.query<EvidenceRow>(
    `select evidence.id,evidence.canonical_sha256,evidence.state,review.id as review_id
       from task_evidence as evidence
       join task_evidence_reviews as review
         on review.evidence_id=evidence.id and review.decision='accepted'
      where evidence.task_id=$1 and evidence.state='accepted'
      order by evidence.id`,
    [root.id]
  );
  const pendingEvidence = await client.query<{ pending: boolean }>(
    `select exists (
       select 1 from task_evidence
        where task_id=$1 and state='submitted'
     ) as pending`,
    [root.id]
  );
  if (pendingEvidence.rows[0]?.pending !== false) {
    throw new TaskTransactionError(
      "task_closure_unavailable",
      "task closure cannot ignore pending evidence"
    );
  }
  const exactIds = evidence.rows.map(({ id }) => id);
  if (
    exactIds.length === 0 ||
    exactIds.length !== action.acceptedEvidenceIds.length ||
    exactIds.some((id, index) => id !== action.acceptedEvidenceIds[index])
  ) {
    throw new TaskTransactionError(
      "task_closure_unavailable",
      "closure must bind every exact accepted evidence record"
    );
  }
  const acceptedEvidenceManifest: JsonValue = evidence.rows.map((row) => ({
    evidenceId: row.id,
    evidenceSha256: row.canonical_sha256.toString("hex"),
    reviewId: row.review_id
  }));
  const closureSha256 = canonicalSha256({
    schemaVersion: "boardagent.task-closure.v1",
    taskId: root.id,
    taskSha256: root.task_sha256.toString("hex"),
    sourceMinutesSha256: root.source_minutes_sha256?.toString("hex") ?? null,
    acceptedEvidenceManifest
  });
  return {
    payload: {
      schemaVersion: "boardagent.task-closure.v1",
      taskId: root.id,
      taskSha256: root.task_sha256.toString("hex"),
      sourceMinutesSha256: root.source_minutes_sha256?.toString("hex") ?? null,
      acceptedEvidenceManifest,
      closureSha256
    },
    details: { kind: "closure", evidence: evidence.rows, acceptedEvidenceManifest, closureSha256 }
  };
}

async function prepareCompletedCorrection(
  client: PoolClient,
  action: Extract<NormalizedTaskAction, { readonly kind: "completed_correction" }>,
  root: TaskRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedTaskDetails }> {
  if (root.state !== "completed") {
    throw new TaskTransactionError(
      "task_closure_unavailable",
      "only a completed task may start a correction cycle"
    );
  }
  const closure = await client.query<{ id: string; closure_sha256: Buffer }>(
    "select id,closure_sha256 from task_closures where task_id=$1",
    [root.id]
  );
  const closureRow = closure.rows[0];
  if (!closureRow || closure.rows.length !== 1) {
    throw new TaskTransactionError(
      "task_closure_unavailable",
      "completed task closure evidence is unavailable"
    );
  }
  const existing = await client.query<{ id: string }>(
    "select id from task_correction_cycles where prior_task_id=$1",
    [root.id]
  );
  if (existing.rows.length !== 0) {
    throw new TaskTransactionError(
      "task_closure_unavailable",
      "completed task already has a direct correction cycle"
    );
  }
  const owner = await client.query<{ entitlement_generation: string }>(
    `select entitlement_generation::text
       from boardagent_lock_board_members($1,$2,array[$3]::uuid[])
      where active_now and seat_role<>'observer'`,
    [root.organization_id, root.board_id, action.replacement.ownerMemberId]
  );
  const ownerGeneration = owner.rows[0]?.entitlement_generation;
  if (!ownerGeneration || owner.rows.length !== 1) {
    throw new TaskTransactionError(
      "task_invalid",
      "replacement task owner must be an active non-observer board participant"
    );
  }
  const replacementTaskSha256 = canonicalSha256({
    schemaVersion: "boardagent.task.v1",
    taskId: action.replacementTaskId,
    correctionOfTaskId: root.id,
    correctionOfClosureId: closureRow.id,
    ownerMemberId: action.replacement.ownerMemberId,
    dueAt: action.replacement.dueAt,
    description: action.replacement.description,
    requiredEvidence: action.replacement.requiredEvidence,
    reason: action.reason
  });
  return {
    payload: {
      schemaVersion: "boardagent.task-correction-cycle.v1",
      priorTaskId: root.id,
      priorTaskSha256: root.task_sha256.toString("hex"),
      priorClosureId: closureRow.id,
      priorClosureSha256: closureRow.closure_sha256.toString("hex"),
      replacementTaskId: action.replacementTaskId,
      replacement: action.replacement as unknown as JsonValue,
      replacementTaskSha256,
      reason: action.reason
    },
    details: {
      kind: "completed_correction",
      closureId: closureRow.id,
      closureSha256: closureRow.closure_sha256.toString("hex"),
      replacementTaskSha256,
      ownerEntitlementGeneration: ownerGeneration
    }
  };
}

function prepareCancellation(
  action: Extract<NormalizedTaskAction, { readonly kind: "cancellation" }>,
  root: TaskRootRow
): { readonly payload: JsonValue; readonly details: PreparedTaskDetails } {
  if (
    !(["draft", "open", "in_progress", "evidence_submitted"] as const).includes(root.state as never)
  ) {
    throw new TaskTransactionError("task_unavailable", "only a nonterminal task may be cancelled");
  }
  return {
    payload: {
      schemaVersion: "boardagent.task-cancellation.v1",
      taskId: root.id,
      taskSha256: root.task_sha256.toString("hex"),
      reason: action.reason
    },
    details: { kind: "cancellation" }
  };
}

async function prepareTaskAction(
  client: PoolClient,
  rawAction: TaskLifecycleAction
): Promise<PreparedTaskAction> {
  const action = normalizeTaskAction(rawAction);
  const { root, context } = await lockTask(client, action.taskId, "secretary");
  let prepared: { readonly payload: JsonValue; readonly details: PreparedTaskDetails };
  switch (action.kind) {
    case "evidence_review":
      prepared = await prepareEvidenceReview(client, action, root);
      break;
    case "closure":
      prepared = await prepareClosure(client, action, root);
      break;
    case "completed_correction":
      prepared = await prepareCompletedCorrection(client, action, root);
      break;
    case "cancellation":
      prepared = prepareCancellation(action, root);
      break;
  }
  return {
    action,
    root,
    context,
    payload: prepared.payload,
    payloadSha256: canonicalSha256(prepared.payload),
    details: prepared.details
  };
}

function taskAudit(
  prepared: PreparedTaskAction,
  consentRecordId: string,
  eventType:
    | "task_evidence_reviewed"
    | "task_completed"
    | "task_correction_cycle_created"
    | "task_cancelled",
  entityType: string,
  entityId: string,
  details: Readonly<Record<string, JsonValue>>,
  eventId = newId(),
  objectVersion = BigInt(prepared.root.row_version) + 1n
): AuditAppendInput {
  return {
    organizationId: prepared.root.organization_id,
    consentRecordId,
    objectVersion,
    event: {
      eventId,
      eventType,
      actorMemberId: prepared.context.memberId,
      actorClientId: prepared.context.clientId,
      tokenJti: prepared.context.tokenJti,
      entityType,
      entityId,
      boardId: prepared.root.board_id,
      origin: "mcp",
      details,
      schemaVersion: 1
    }
  };
}

async function assertTaskConsent(
  client: PoolClient,
  prepared: PreparedTaskAction,
  consentRecordId: string
): Promise<void> {
  const descriptor = taskOperation(prepared.action);
  const result = await client.query<{ valid: boolean }>(
    `select exists (
       select 1 from consent_records as consent
       join action_stages as stage on stage.id=consent.stage_id
       join input_required_attempts as attempt on attempt.id=consent.input_required_attempt_id
       where consent.id=$1 and consent.organization_id=$2 and consent.board_id=$3
         and consent.actor_member_id=$4 and consent.client_id=$5 and consent.token_jti=$6
         and consent.action_code=$7 and consent.target_type='task' and consent.target_id=$8
         and consent.payload_sha256=$9 and consent.package_sha256=$10
         and stage.state='active' and attempt.state='prepared'
         and stage.payload_sha256=consent.payload_sha256
         and stage.package_sha256=consent.package_sha256
         and attempt.original_name=$7
     ) as valid`,
    [
      consentRecordId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.context.memberId,
      prepared.context.clientId,
      prepared.context.tokenJti,
      descriptor.actionCode,
      prepared.root.id,
      Buffer.from(prepared.payloadSha256, "hex"),
      prepared.root.task_sha256
    ]
  );
  if (result.rows[0]?.valid !== true) {
    throw new TaskTransactionError(
      "task_unavailable",
      "exact confirmed task action is unavailable"
    );
  }
}

async function nextFeedSequence(
  client: PoolClient,
  boardId: string,
  memberId: string
): Promise<bigint> {
  const result = await client.query<{ next_sequence: string }>(
    `select (coalesce(max(feed_sequence),0)+1)::text as next_sequence
       from pending_action_feed where board_id=$1 and member_id=$2`,
    [boardId, memberId]
  );
  return BigInt(result.rows[0]?.next_sequence ?? "1");
}

async function timestamp(client: PoolClient): Promise<string> {
  const result = await client.query<{ occurred_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
  );
  const value = result.rows[0]?.occurred_at;
  if (!value) throw new Error("task transaction timestamp is unavailable");
  return value;
}

async function insertTaskNotice(
  client: PoolClient,
  scope: { readonly boardId: string; readonly organizationId: string },
  input: {
    readonly taskId: string;
    readonly taskVersion: number;
    readonly recipientMemberId: string;
    readonly entitlementGeneration: string;
    readonly auditEventId: string;
    readonly noticeType: string;
    readonly safeRefs: Readonly<Record<string, string>>;
  }
): Promise<void> {
  const noticeId = newId();
  const feedId = newId();
  const feedSequence = await nextFeedSequence(client, scope.boardId, input.recipientMemberId);
  const entitlementGeneration = Number(input.entitlementGeneration);
  if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
    throw new Error("task owner entitlement generation is invalid");
  }
  const delta = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: feedSequence.toString(10),
    deltaType: "task_assigned",
    objectType: "task",
    objectId: input.taskId,
    objectVersion: input.taskVersion,
    entitlementGeneration,
    actionState: "pending",
    safeRefs: input.safeRefs,
    createdAt: await timestamp(client)
  });
  const noticeSha256 = canonicalSha256({
    noticeType: input.noticeType,
    taskId: input.taskId,
    taskVersion: input.taskVersion,
    recipientMemberId: input.recipientMemberId,
    safeRefs: input.safeRefs
  });
  await client.query(
    `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,$4,'task',$5,$6,$7,$8,$9,$10)`,
    [
      noticeId,
      scope.organizationId,
      scope.boardId,
      input.noticeType,
      input.taskId,
      input.taskVersion,
      input.recipientMemberId,
      Buffer.from(noticeSha256, "hex"),
      feedSequence.toString(10),
      input.auditEventId
    ]
  );
  const canonicalPayload = Buffer.from(canonicalJson(delta), "utf8");
  await client.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,notice_id,audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,$7,'task',$8,$9,$10,$11,$12,$13,$14)`,
    [
      feedId,
      scope.organizationId,
      scope.boardId,
      input.recipientMemberId,
      input.entitlementGeneration,
      feedSequence.toString(10),
      input.noticeType,
      input.taskId,
      input.taskVersion,
      Buffer.from(canonicalSha256(input.safeRefs), "hex"),
      canonicalPayload,
      Buffer.from(canonicalSha256(delta), "hex"),
      noticeId,
      input.auditEventId
    ]
  );
}

async function actEvidenceReview(
  client: PoolClient,
  prepared: PreparedTaskAction,
  consentRecordId: string
): Promise<{
  readonly value: TaskLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "evidence_review" || prepared.details.kind !== "evidence_review") {
    throw new Error("task evidence review preparation mismatch");
  }
  const reviewId = newId();
  await client.query(
    `insert into task_evidence_reviews(
       id,organization_id,evidence_id,secretary_member_id,decision,reason,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7)`,
    [
      reviewId,
      prepared.root.organization_id,
      prepared.action.evidenceId,
      prepared.context.memberId,
      prepared.action.decision,
      prepared.action.reason,
      consentRecordId
    ]
  );
  const evidence = await client.query(
    `update task_evidence set state=$1,row_version=row_version+1
      where id=$2 and state='submitted'`,
    [prepared.action.decision, prepared.action.evidenceId]
  );
  if (evidence.rowCount !== 1) throw new Error("task evidence changed during review");
  const nextTaskState = prepared.action.decision === "rejected" ? "open" : "evidence_submitted";
  const task = await client.query(
    `update tasks set state=$1,row_version=row_version+1
      where id=$2 and row_version=$3::bigint and state='evidence_submitted'`,
    [nextTaskState, prepared.root.id, prepared.root.row_version]
  );
  if (task.rowCount !== 1) throw new Error("task changed during evidence review");
  return {
    value: {
      kind: "evidence_review",
      taskId: prepared.root.id,
      evidenceId: prepared.action.evidenceId,
      reviewId,
      decision: prepared.action.decision
    },
    auditEvents: [
      taskAudit(
        prepared,
        consentRecordId,
        "task_evidence_reviewed",
        "task_evidence_review",
        reviewId,
        {
          taskId: prepared.root.id,
          evidenceId: prepared.action.evidenceId,
          evidenceSha256: prepared.details.evidence.canonical_sha256.toString("hex"),
          decision: prepared.action.decision,
          reason: prepared.action.reason
        }
      )
    ]
  };
}

async function actClosure(
  client: PoolClient,
  prepared: PreparedTaskAction,
  consentRecordId: string
): Promise<{
  readonly value: TaskLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "closure" || prepared.details.kind !== "closure") {
    throw new Error("task closure preparation mismatch");
  }
  const closureId = newId();
  await client.query(
    `insert into task_closures(
       id,organization_id,board_id,task_id,primary_evidence_id,accepted_evidence_manifest,
       source_minutes_sha256,secretary_member_id,consent_record_id,closure_sha256
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      closureId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.id,
      prepared.details.evidence[0]!.id,
      JSON.stringify(prepared.details.acceptedEvidenceManifest),
      prepared.root.source_minutes_sha256,
      prepared.context.memberId,
      consentRecordId,
      Buffer.from(prepared.details.closureSha256, "hex")
    ]
  );
  const updated = await client.query<{ next_row_version: string | null }>(
    `select boardagent_apply_task_terminal_transition($1,$2::bigint,'completed',$3)::text
              as next_row_version`,
    [prepared.root.id, prepared.root.row_version, consentRecordId]
  );
  if (updated.rows[0]?.next_row_version !== (BigInt(prepared.root.row_version) + 1n).toString(10)) {
    throw new Error("task changed during closure");
  }
  await client.query(
    `update pending_action_feed
        set state='resolved',resolved_at=transaction_timestamp()
      where board_id=$1 and member_id=$2 and object_type='task' and object_id=$3
        and state='pending'`,
    [prepared.root.board_id, prepared.root.owner_member_id, prepared.root.id]
  );
  return {
    value: {
      kind: "closure",
      taskId: prepared.root.id,
      closureId,
      closureSha256: prepared.details.closureSha256
    },
    auditEvents: [
      taskAudit(prepared, consentRecordId, "task_completed", "task_closure", closureId, {
        taskId: prepared.root.id,
        taskSha256: prepared.root.task_sha256.toString("hex"),
        acceptedEvidenceManifest: prepared.details.acceptedEvidenceManifest,
        sourceMinutesSha256: prepared.root.source_minutes_sha256?.toString("hex") ?? null,
        closureSha256: prepared.details.closureSha256
      })
    ]
  };
}

async function actCompletedCorrection(
  client: PoolClient,
  prepared: PreparedTaskAction,
  consentRecordId: string
): Promise<{
  readonly value: TaskLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "completed_correction" ||
    prepared.details.kind !== "completed_correction"
  ) {
    throw new Error("completed task correction preparation mismatch");
  }
  const replacementTaskId = prepared.action.replacementTaskId;
  const correctionCycleId = newId();
  const correctionAuditEventId = newId();
  await client.query(
    `insert into tasks(
       id,organization_id,board_id,source_meeting_id,source_minutes_id,
       source_minutes_version_id,source_minutes_sha256,source_locator,owner_member_id,
       due_at,description_schema,canonical_description,required_evidence,task_sha256,
       state,created_by
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'boardagent.task.v1',$11,$12,$13,'open',$14)`,
    [
      replacementTaskId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.source_meeting_id,
      prepared.root.source_minutes_id,
      prepared.root.source_minutes_version_id,
      prepared.root.source_minutes_sha256,
      prepared.root.source_locator === null ? null : JSON.stringify(prepared.root.source_locator),
      prepared.action.replacement.ownerMemberId,
      prepared.action.replacement.dueAt,
      prepared.action.replacement.description,
      JSON.stringify({ items: prepared.action.replacement.requiredEvidence }),
      Buffer.from(prepared.details.replacementTaskSha256, "hex"),
      prepared.context.memberId
    ]
  );
  await client.query(
    `insert into task_correction_cycles(
       id,organization_id,board_id,prior_task_id,prior_closure_id,replacement_task_id,
       secretary_member_id,reason,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      correctionCycleId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.id,
      prepared.details.closureId,
      replacementTaskId,
      prepared.context.memberId,
      prepared.action.reason,
      consentRecordId
    ]
  );
  await insertTaskNotice(
    client,
    { organizationId: prepared.root.organization_id, boardId: prepared.root.board_id },
    {
      taskId: replacementTaskId,
      taskVersion: 1,
      recipientMemberId: prepared.action.replacement.ownerMemberId,
      entitlementGeneration: prepared.details.ownerEntitlementGeneration,
      auditEventId: correctionAuditEventId,
      noticeType: "task_correction_assigned",
      safeRefs: {
        priorTaskId: prepared.root.id,
        priorClosureId: prepared.details.closureId,
        correctionCycleId
      }
    }
  );
  return {
    value: {
      kind: "completed_correction",
      priorTaskId: prepared.root.id,
      replacementTaskId,
      correctionCycleId
    },
    auditEvents: [
      taskAudit(
        prepared,
        consentRecordId,
        "task_correction_cycle_created",
        "task_correction_cycle",
        correctionCycleId,
        {
          priorTaskId: prepared.root.id,
          priorTaskSha256: prepared.root.task_sha256.toString("hex"),
          priorClosureId: prepared.details.closureId,
          priorClosureSha256: prepared.details.closureSha256,
          replacementTaskId,
          replacementTaskSha256: prepared.details.replacementTaskSha256,
          reason: prepared.action.reason
        },
        correctionAuditEventId,
        BigInt(prepared.root.row_version)
      )
    ]
  };
}

async function actCancellation(
  client: PoolClient,
  prepared: PreparedTaskAction,
  consentRecordId: string
): Promise<{
  readonly value: TaskLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "cancellation" || prepared.details.kind !== "cancellation") {
    throw new Error("task cancellation preparation mismatch");
  }
  const updated = await client.query<{ next_row_version: string | null }>(
    `select boardagent_apply_task_terminal_transition($1,$2::bigint,'cancelled',$3)::text
              as next_row_version`,
    [prepared.root.id, prepared.root.row_version, consentRecordId]
  );
  if (updated.rows[0]?.next_row_version !== (BigInt(prepared.root.row_version) + 1n).toString(10)) {
    throw new Error("task changed during cancellation");
  }
  await client.query(
    `update pending_action_feed
        set state='resolved',resolved_at=transaction_timestamp()
      where board_id=$1 and member_id=$2 and object_type='task' and object_id=$3
        and state='pending'`,
    [prepared.root.board_id, prepared.root.owner_member_id, prepared.root.id]
  );
  return {
    value: { kind: "cancellation", taskId: prepared.root.id },
    auditEvents: [
      taskAudit(prepared, consentRecordId, "task_cancelled", "task", prepared.root.id, {
        taskSha256: prepared.root.task_sha256.toString("hex"),
        reason: prepared.action.reason
      })
    ]
  };
}

async function performTaskAction(
  client: PoolClient,
  prepared: PreparedTaskAction,
  consentRecordId: string
): Promise<{
  readonly value: TaskLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  await assertTaskConsent(client, prepared, consentRecordId);
  switch (prepared.action.kind) {
    case "evidence_review":
      return actEvidenceReview(client, prepared, consentRecordId);
    case "closure":
      return actClosure(client, prepared, consentRecordId);
    case "completed_correction":
      return actCompletedCorrection(client, prepared, consentRecordId);
    case "cancellation":
      return actCancellation(client, prepared, consentRecordId);
  }
}

export async function prepareTaskCreationInTransaction(
  client: PoolClient,
  rawAction: TaskCreationAction
): Promise<PreparedTaskCreationAction> {
  const action = normalizeTaskCreation(rawAction);
  const context = await readRequestContext(client);
  const board = await client.query<{
    organization_id: string;
    state: string;
    actor_ready: boolean;
  }>(
    `select organization_id,state,actor_ready
       from boardagent_lock_board_root($1)`,
    [action.boardId]
  );
  const actor = await client.query<{ active_now: boolean; is_secretary: boolean }>(
    `select active_now,is_secretary
       from boardagent_lock_board_members($1,$2,array[$3]::uuid[])`,
    [context.organizationId, action.boardId, context.memberId]
  );
  const boardRow = board.rows[0];
  const actorRow = actor.rows[0];
  if (
    !boardRow ||
    board.rows.length !== 1 ||
    boardRow.organization_id !== context.organizationId ||
    boardRow.state !== "active" ||
    !boardRow.actor_ready ||
    !actorRow ||
    actor.rows.length !== 1 ||
    !actorRow.active_now ||
    !actorRow.is_secretary
  ) {
    throw new TaskTransactionError("task_unavailable", "task creation is unavailable");
  }
  const existing = await client.query<{ exists: boolean }>(
    "select exists(select 1 from tasks where id=$1) as exists",
    [action.taskId]
  );
  if (existing.rows[0]?.exists !== false) {
    throw new TaskTransactionError("task_unavailable", "task creation is unavailable");
  }
  const owner = await client.query<{ entitlement_generation: string }>(
    `select entitlement_generation::text
       from boardagent_lock_board_members($1,$2,array[$3]::uuid[])
      where active_now and seat_role<>'observer'`,
    [context.organizationId, action.boardId, action.ownerMemberId]
  );
  const ownerEntitlementGeneration = owner.rows[0]?.entitlement_generation;
  if (!ownerEntitlementGeneration || owner.rows.length !== 1) {
    throw new TaskTransactionError(
      "task_invalid",
      "task owner must be an active non-observer board participant"
    );
  }
  const due = await client.query<{ valid: boolean }>(
    "select $1::timestamptz > transaction_timestamp() as valid",
    [action.dueAt]
  );
  if (due.rows[0]?.valid !== true) {
    throw new TaskTransactionError("task_invalid", "task due time must be in the future");
  }
  let sourceMeetingId: string | null = null;
  let sourceMinutesSha256: string | null = null;
  let sourceLocator: JsonValue | null = null;
  if (action.sourceMinutesId !== null && action.sourceMinutesVersionId !== null) {
    const source = await client.query<{ meeting_id: string; minutes_sha256: string }>(
      `select meeting_id,encode(minutes_sha256,'hex') as minutes_sha256
         from boardagent_lock_task_source($1,$2,$3)`,
      [action.boardId, action.sourceMinutesId, action.sourceMinutesVersionId]
    );
    const sourceRow = source.rows[0];
    if (!sourceRow || source.rows.length !== 1) {
      throw new TaskTransactionError(
        "task_invalid",
        "task source must identify one exact minutes version on the active board"
      );
    }
    sourceMeetingId = sourceRow.meeting_id;
    sourceMinutesSha256 = sourceRow.minutes_sha256;
    sourceLocator = {
      sourceType: "minutes_version",
      minutesId: action.sourceMinutesId,
      minutesVersionId: action.sourceMinutesVersionId
    };
  }
  const taskSha256 = canonicalSha256({
    schemaVersion: "boardagent.task.v1",
    taskId: action.taskId,
    boardId: action.boardId,
    ownerMemberId: action.ownerMemberId,
    dueAt: action.dueAt,
    description: action.description,
    requiredEvidence: action.requiredEvidence,
    sourceMinutesId: action.sourceMinutesId,
    sourceMinutesVersionId: action.sourceMinutesVersionId,
    sourceMinutesSha256
  });
  const canonicalPayload: JsonValue = {
    schemaVersion: "boardagent.task-creation.v1",
    taskId: action.taskId,
    boardId: action.boardId,
    ownerMemberId: action.ownerMemberId,
    dueAt: action.dueAt,
    descriptionSha256: sha256Hex(action.description),
    requiredEvidenceSha256: canonicalSha256(action.requiredEvidence),
    sourceMinutesId: action.sourceMinutesId,
    sourceMinutesVersionId: action.sourceMinutesVersionId,
    sourceMinutesSha256,
    taskSha256
  };
  return {
    actionCode: "create_task",
    organizationId: context.organizationId,
    actorMemberId: context.memberId,
    actorClientId: context.clientId,
    tokenJti: context.tokenJti,
    boardId: action.boardId,
    targetId: action.taskId,
    canonicalSchema: "boardagent.task-creation.v1",
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    packageSha256: taskSha256,
    ownerEntitlementGeneration,
    sourceMeetingId,
    sourceMinutesSha256,
    sourceLocator,
    action
  };
}

export async function stageTaskCreationInTransaction(
  client: PoolClient,
  input: TaskCreationStageInput
): Promise<StagedTaskLifecycleAction> {
  const prepared = await prepareTaskCreationInTransaction(client, input.action);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: "task",
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => {
      // Creation authority, board, owner and duplicate target were locked by preparation.
    }
  );
  return {
    ...staged,
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetId: prepared.targetId
  };
}

export async function confirmTaskCreationInTransaction(
  client: PoolClient,
  input: TaskCreationConfirmationInput
): Promise<StagedActionResolution<TaskCreationResult>> {
  let prepared: PreparedTaskCreationAction | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareTaskCreationInTransaction(requestClient, input.action);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("task creation preparation is unavailable");
      const taskAuditEventId = newId();
      const noticeAuditEventId = newId();
      await requestClient.query(
        `insert into tasks(
           id,organization_id,board_id,source_meeting_id,source_minutes_id,
           source_minutes_version_id,source_minutes_sha256,source_locator,owner_member_id,
           due_at,description_schema,canonical_description,required_evidence,task_sha256,
           state,created_by
         ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'boardagent.task.v1',$11,$12,$13,'open',$14)`,
        [
          prepared.action.taskId,
          prepared.organizationId,
          prepared.boardId,
          prepared.sourceMeetingId,
          prepared.action.sourceMinutesId,
          prepared.action.sourceMinutesVersionId,
          prepared.sourceMinutesSha256 === null
            ? null
            : Buffer.from(prepared.sourceMinutesSha256, "hex"),
          prepared.sourceLocator === null ? null : JSON.stringify(prepared.sourceLocator),
          prepared.action.ownerMemberId,
          prepared.action.dueAt,
          prepared.action.description,
          JSON.stringify({ items: prepared.action.requiredEvidence }),
          Buffer.from(prepared.packageSha256, "hex"),
          prepared.actorMemberId
        ]
      );
      await insertTaskNotice(
        requestClient,
        { organizationId: prepared.organizationId, boardId: prepared.boardId },
        {
          taskId: prepared.action.taskId,
          taskVersion: 1,
          recipientMemberId: prepared.action.ownerMemberId,
          entitlementGeneration: prepared.ownerEntitlementGeneration,
          auditEventId: noticeAuditEventId,
          noticeType: "task_assigned",
          safeRefs: {
            taskSha256: prepared.packageSha256,
            ...(prepared.action.sourceMinutesId === null
              ? {}
              : {
                  sourceMinutesId: prepared.action.sourceMinutesId,
                  sourceMinutesVersionId: prepared.action.sourceMinutesVersionId ?? ""
                })
          }
        }
      );
      const auditBase = {
        organizationId: prepared.organizationId,
        consentRecordId,
        objectVersion: 1n
      } as const;
      const eventBase = {
        actorMemberId: prepared.actorMemberId,
        actorClientId: prepared.actorClientId,
        tokenJti: prepared.tokenJti,
        boardId: prepared.boardId,
        origin: "mcp" as const,
        schemaVersion: 1 as const
      };
      return {
        value: {
          taskId: prepared.action.taskId,
          taskSha256: prepared.packageSha256,
          ownerMemberId: prepared.action.ownerMemberId
        },
        auditEvents: [
          {
            ...auditBase,
            event: {
              ...eventBase,
              eventId: taskAuditEventId,
              eventType: "task_created",
              entityType: "task",
              entityId: prepared.action.taskId,
              details: {
                ownerMemberId: prepared.action.ownerMemberId,
                dueAt: prepared.action.dueAt,
                sourceMinutesId: prepared.action.sourceMinutesId,
                sourceMinutesVersionId: prepared.action.sourceMinutesVersionId,
                sourceMinutesSha256: prepared.sourceMinutesSha256,
                taskSha256: prepared.packageSha256
              }
            }
          },
          {
            ...auditBase,
            event: {
              ...eventBase,
              eventId: noticeAuditEventId,
              eventType: "notice_delivered",
              entityType: "task",
              entityId: prepared.action.taskId,
              details: {
                meaning: "committed_recipient_feed_handoff",
                recipientMemberId: prepared.action.ownerMemberId,
                noticeType: "task_assigned"
              }
            }
          }
        ]
      };
    }
  );
}

export async function stageTaskLifecycleActionInTransaction(
  client: PoolClient,
  input: TaskLifecycleStageInput
): Promise<StagedTaskLifecycleAction> {
  const prepared = await prepareTaskAction(client, input.action);
  const descriptor = taskOperation(prepared.action);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.root.board_id,
      actingForMemberId: null,
      actionCode: descriptor.actionCode,
      targetType: "task",
      targetId: prepared.root.id,
      canonicalSchema: descriptor.canonicalSchema,
      canonicalPayload: prepared.payload,
      packageSha256: prepared.root.task_sha256.toString("hex"),
      originalName: descriptor.actionCode
    },
    async () => {
      // The aggregate/dependents were locked by prepareTaskAction before the stage key.
    }
  );
  return {
    ...staged,
    actionCode: descriptor.actionCode,
    boardId: prepared.root.board_id,
    targetId: prepared.root.id
  };
}

/** Read-only preparation for protocol presentation; the caller persists no stage here. */
export async function prepareTaskLifecycleActionInTransaction(
  client: PoolClient,
  action: TaskLifecycleAction
): Promise<PreparedTaskLifecycleAction> {
  const prepared = await prepareTaskAction(client, action);
  const descriptor = taskOperation(prepared.action);
  return {
    actionCode: descriptor.actionCode,
    boardId: prepared.root.board_id,
    targetId: prepared.root.id,
    canonicalSchema: descriptor.canonicalSchema,
    canonicalPayload: prepared.payload,
    payloadSha256: prepared.payloadSha256,
    packageSha256: prepared.root.task_sha256.toString("hex")
  };
}

export async function confirmTaskLifecycleActionInTransaction(
  client: PoolClient,
  input: TaskLifecycleConfirmationInput
): Promise<StagedActionResolution<TaskLifecycleResult>> {
  let prepared: PreparedTaskAction | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareTaskAction(requestClient, input.action);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.root.task_sha256.toString("hex")
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("task lifecycle preparation is unavailable");
      return performTaskAction(requestClient, prepared, consentRecordId);
    }
  );
}
