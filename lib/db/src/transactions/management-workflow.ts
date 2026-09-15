import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";
import type { ManagementSubmissionDocumentReferenceInput } from "./management-submissions.js";
import { readRequestContext } from "./request-context.js";

type ManagementWorkflowOperation =
  | "submit_document_to_secretariat"
  | "request_management_revision"
  | "reply_to_management_revision"
  | "approve_management_submission"
  | "reject_management_submission";

interface ManagementWorkflowEvidenceInput {
  readonly organizationId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface SubmitDocumentToSecretariatInput extends ManagementWorkflowEvidenceInput {
  readonly submissionId: string;
  readonly versionId: string;
  readonly boardId: string;
  /** Resolved by the trusted service from the board's live secretary assignment. */
  readonly assignedSecretaryMemberId: string;
  readonly documentReferences: readonly ManagementSubmissionDocumentReferenceInput[];
  readonly purpose: string;
}

export interface RequestManagementRevisionInput extends ManagementWorkflowEvidenceInput {
  readonly requestId: string;
  readonly submissionId: string;
  readonly reason: string;
}

export interface ReplyToManagementRevisionInput extends ManagementWorkflowEvidenceInput {
  readonly replyId: string;
  readonly submissionId: string;
  readonly revisionRequestId: string;
  readonly reply: string;
}

export interface ApproveManagementSubmissionInput extends ManagementWorkflowEvidenceInput {
  readonly dispositionId: string;
  readonly submissionId: string;
  readonly versionId: string;
  readonly resultingDraftId: string;
  /** Opaque context signed by the trusted service; never accepted from the MCP caller. */
  readonly signedContext: Uint8Array;
  readonly contextSha256: string;
}

export interface RejectManagementSubmissionInput extends ManagementWorkflowEvidenceInput {
  readonly dispositionId: string;
  readonly submissionId: string;
  readonly versionId: string;
  readonly reason: string;
}

export type ManagementWorkflowResult =
  | {
      readonly replayed: true;
      readonly operation: ManagementWorkflowOperation;
      readonly submissionId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly operation: ManagementWorkflowOperation;
      readonly submissionId: string;
      readonly state: string;
      readonly rowVersion: bigint;
      readonly boardId: string;
      readonly versionId: string;
      readonly responseSha256: string;
      readonly auditEvent: AuditEvent;
      readonly revisionRequestId?: string;
      readonly replyId?: string;
      readonly resultingDraftId?: string;
    };

export class ManagementWorkflowTransactionError extends Error {
  public constructor(
    public readonly code:
      | "submission_unavailable"
      | "document_reference_unavailable"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "ManagementWorkflowTransactionError";
  }
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface WorkflowMutationRow {
  readonly submission_id: string;
  readonly submission_state: string;
  readonly row_version: string;
  readonly board_id: string;
  readonly version_id: string;
  readonly request_id?: string | null;
  readonly reply_id?: string | null;
  readonly draft_id?: string | null;
}

const SAFE_RESPONSE_TYPE = "management_submission";

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 200 || !/^[A-Za-z0-9._~-]+$/u.test(value)) {
    throw new RangeError("idempotency key must match the frozen 16-to-200 character form");
  }
  return value;
}

function boundedCanonicalText(value: string, label: string, maximum: number): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > maximum) {
    throw new RangeError(`${label} must contain 1 through ${String(maximum)} characters`);
  }
  return normalized;
}

function documentReferences(
  values: readonly ManagementSubmissionDocumentReferenceInput[]
): readonly ManagementSubmissionDocumentReferenceInput[] {
  if (values.length < 1 || values.length > 1000) {
    throw new RangeError("management submission requires 1 through 1,000 document references");
  }
  const normalized = values
    .map((reference) => ({
      documentId: UuidV7Schema.parse(reference.documentId),
      versionId: UuidV7Schema.parse(reference.versionId),
      sha256: Sha256HexSchema.parse(reference.sha256)
    }))
    .toSorted((left, right) =>
      left.documentId === right.documentId
        ? left.versionId.localeCompare(right.versionId)
        : left.documentId.localeCompare(right.documentId)
    );
  if (
    new Set(normalized.map(({ documentId }) => documentId)).size !== normalized.length ||
    new Set(normalized.map(({ versionId }) => versionId)).size !== normalized.length
  ) {
    throw new TypeError("management submission document and version references must be unique");
  }
  return normalized;
}

function responseSha256(operation: ManagementWorkflowOperation, submissionId: string): string {
  return canonicalSha256({
    schemaVersion: "boardagent.management-workflow-safe-response.v1",
    operation,
    submissionId
  });
}

async function assertOrganization(client: PoolClient, organizationId: string) {
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new ManagementWorkflowTransactionError(
      "submission_unavailable",
      "management submission is unavailable"
    );
  }
  return context;
}

/** Completed retries retain their result, but never the caller's old authority. */
async function assertWorkflowAuthority(
  client: PoolClient,
  operation: ManagementWorkflowOperation,
  submissionId: string,
  boardId: string | null = null
): Promise<void> {
  const result = await client.query<{ authorized: boolean }>(
    `select case
       when $1::text='submit_document_to_secretariat' then
         boardagent_management_actor_for_board($3::uuid)
       when $1::text='reply_to_management_revision' then
         boardagent_management_submission_actor_allowed($2::uuid)
       when $1::text in (
         'request_management_revision','approve_management_submission','reject_management_submission'
       ) then exists (
         select 1 from management_submission_threads as thread
          where thread.id=$2::uuid
            and thread.organization_id=boardagent_context_uuid('boardagent.organization_id')
            and thread.assigned_secretary_id=boardagent_context_uuid('boardagent.member_id')
            and boardagent_secretariat_for_board(thread.board_id)
       )
       else false
     end as authorized`,
    [operation, submissionId, boardId]
  );
  if (result.rows[0]?.authorized !== true) {
    throw new ManagementWorkflowTransactionError(
      "submission_unavailable",
      "management submission is unavailable"
    );
  }
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  operation: ManagementWorkflowOperation,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      for update`,
    [actorMemberId, clientId, operation, key]
  );
  return result.rows[0];
}

function replayResult(
  record: IdempotencyRow,
  operation: ManagementWorkflowOperation,
  requestSha256: string
): Extract<ManagementWorkflowResult, { readonly replayed: true }> {
  if (!safeHashEqual(record.request_sha256.toString("hex"), requestSha256)) {
    throw new ManagementWorkflowTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different management request"
    );
  }
  if (record.state !== "succeeded") {
    throw new ManagementWorkflowTransactionError(
      "idempotency_in_progress",
      "identical management request is already in progress"
    );
  }
  if (
    record.safe_response_type !== SAFE_RESPONSE_TYPE ||
    !record.safe_response_id ||
    !record.safe_response_sha256
  ) {
    throw new Error("management idempotency record has no safe response");
  }
  const expected = responseSha256(operation, record.safe_response_id);
  if (!safeHashEqual(record.safe_response_sha256.toString("hex"), expected)) {
    throw new Error("management idempotency safe response hash is invalid");
  }
  return {
    replayed: true,
    operation,
    submissionId: record.safe_response_id,
    responseSha256: expected
  };
}

async function acquireIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly operation: ManagementWorkflowOperation;
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<Extract<ManagementWorkflowResult, { readonly replayed: true }> | undefined> {
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      input.id,
      input.organizationId,
      input.actorMemberId,
      input.clientId,
      input.operation,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
  const record = await readIdempotency(
    client,
    input.actorMemberId,
    input.clientId,
    input.operation,
    input.key
  );
  if (!record) throw new Error("management idempotency record disappeared");
  if (inserted.rowCount === 0) return replayResult(record, input.operation, input.requestSha256);
  if (!safeHashEqual(record.request_sha256.toString("hex"), input.requestSha256)) {
    throw new ManagementWorkflowTransactionError(
      "idempotency_conflict",
      "management idempotency record does not bind this request"
    );
  }
  return undefined;
}

async function completeIdempotency(
  client: PoolClient,
  input: {
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly operation: ManagementWorkflowOperation;
    readonly key: string;
    readonly submissionId: string;
    readonly responseSha256: string;
  }
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type=$1,safe_response_id=$2,
            safe_response_sha256=$3,completed_at=transaction_timestamp()
      where actor_member_id=$4 and client_id=$5 and operation=$6 and idempotency_key=$7
        and state='in_progress'`,
    [
      SAFE_RESPONSE_TYPE,
      input.submissionId,
      Buffer.from(input.responseSha256, "hex"),
      input.actorMemberId,
      input.clientId,
      input.operation,
      input.key
    ]
  );
  if (result.rowCount !== 1) throw new Error("management idempotency completion failed");
}

function mutationRow(row: WorkflowMutationRow | undefined) {
  if (!row) throw new Error("management workflow mutation returned no row");
  const rowVersion = BigInt(row.row_version);
  if (rowVersion < 1n) throw new Error("management workflow returned an invalid row version");
  return {
    submissionId: UuidV7Schema.parse(row.submission_id),
    state: row.submission_state,
    rowVersion,
    boardId: UuidV7Schema.parse(row.board_id),
    versionId: UuidV7Schema.parse(row.version_id),
    ...(row.request_id ? { revisionRequestId: UuidV7Schema.parse(row.request_id) } : {}),
    ...(row.reply_id ? { replyId: UuidV7Schema.parse(row.reply_id) } : {}),
    ...(row.draft_id ? { resultingDraftId: UuidV7Schema.parse(row.draft_id) } : {})
  };
}

async function finishMutation(
  client: PoolClient,
  input: {
    readonly context: Awaited<ReturnType<typeof readRequestContext>>;
    readonly organizationId: string;
    readonly operation: ManagementWorkflowOperation;
    readonly idempotencyKey: string;
    readonly auditEventId: string;
    readonly eventType:
      | "management_submission_created"
      | "management_revision_requested"
      | "management_revision_replied"
      | "management_submission_approved_to_draft"
      | "management_submission_rejected";
    readonly changed: ReturnType<typeof mutationRow>;
    readonly details: Readonly<Record<string, JsonValue>>;
  }
): Promise<Extract<ManagementWorkflowResult, { readonly replayed: false }>> {
  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      objectVersion: input.changed.rowVersion,
      event: {
        eventId: input.auditEventId,
        eventType: input.eventType,
        actorMemberId: input.context.memberId,
        actorClientId: input.context.clientId,
        tokenJti: input.context.tokenJti,
        entityType: "management_submission",
        entityId: input.changed.submissionId,
        boardId: input.changed.boardId,
        origin: "mcp",
        details: input.details,
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("management workflow audit append returned no event");
  const safeResponseSha256 = responseSha256(input.operation, input.changed.submissionId);
  await completeIdempotency(client, {
    actorMemberId: input.context.memberId,
    clientId: input.context.clientId,
    operation: input.operation,
    key: input.idempotencyKey,
    submissionId: input.changed.submissionId,
    responseSha256: safeResponseSha256
  });
  return {
    replayed: false,
    operation: input.operation,
    submissionId: input.changed.submissionId,
    state: input.changed.state,
    rowVersion: input.changed.rowVersion,
    boardId: input.changed.boardId,
    versionId: input.changed.versionId,
    responseSha256: safeResponseSha256,
    auditEvent,
    ...(input.changed.revisionRequestId
      ? { revisionRequestId: input.changed.revisionRequestId }
      : {}),
    ...(input.changed.replyId ? { replyId: input.changed.replyId } : {}),
    ...(input.changed.resultingDraftId ? { resultingDraftId: input.changed.resultingDraftId } : {})
  };
}

export async function submitDocumentToSecretariatInTransaction(
  client: PoolClient,
  input: SubmitDocumentToSecretariatInput
): Promise<ManagementWorkflowResult> {
  const operation = "submit_document_to_secretariat";
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const submissionId = UuidV7Schema.parse(input.submissionId);
  const versionId = UuidV7Schema.parse(input.versionId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const assignedSecretaryMemberId = UuidV7Schema.parse(input.assignedSecretaryMemberId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const purpose = boundedCanonicalText(input.purpose, "management submission purpose", 1024);
  const references = documentReferences(input.documentReferences);
  const context = await assertOrganization(client, organizationId);
  const payload = {
    schemaVersion: "boardagent.management-submission.v1" as const,
    submissionId,
    versionId,
    version: 1,
    documentReferences: references,
    purpose,
    authorMemberId: context.memberId
  };
  const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
  const payloadSha256 = canonicalSha256(payload);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.management-submission-request.v1",
    submissionId,
    boardId,
    documentReferences: references,
    purpose
  });
  await assertWorkflowAuthority(client, operation, submissionId, boardId);
  const validDocuments = await client.query<{ valid: boolean }>(
    "select boardagent_management_submission_documents_valid($1,$2::jsonb) as valid",
    [boardId, JSON.stringify(references)]
  );
  if (!validDocuments.rows[0]?.valid) {
    throw new ManagementWorkflowTransactionError(
      "document_reference_unavailable",
      "management submission requires exact accepted document versions available to the actor"
    );
  }
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation,
    key,
    requestSha256: requestHash
  });
  if (replayed) return replayed;
  const result = await client.query<WorkflowMutationRow>(
    `select submission_id,submission_state,result_row_version::text as row_version,
            result_board_id as board_id,result_version_id as version_id
       from boardagent_create_management_submission(
         $1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10
       )`,
    [
      submissionId,
      versionId,
      boardId,
      assignedSecretaryMemberId,
      payloadBytes,
      JSON.stringify(references),
      Buffer.from(payloadSha256, "hex"),
      purpose,
      idempotencyRecordId,
      auditEventId
    ]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation,
    idempotencyKey: key,
    auditEventId,
    eventType: "management_submission_created",
    changed,
    details: {
      versionId,
      payloadSha256,
      purposeSha256: canonicalSha256(purpose),
      assignedSecretaryMemberId,
      documentReferences: references.map(
        ({ documentId, versionId: documentVersionId, sha256 }) => ({
          documentId,
          versionId: documentVersionId,
          sha256
        })
      ),
      requestSha256: requestHash
    }
  });
}

export async function requestManagementRevisionInTransaction(
  client: PoolClient,
  input: RequestManagementRevisionInput
): Promise<ManagementWorkflowResult> {
  const operation = "request_management_revision";
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const submissionId = UuidV7Schema.parse(input.submissionId);
  const requestId = UuidV7Schema.parse(input.requestId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const reason = boundedCanonicalText(input.reason, "management revision reason", 65_536);
  const reasonSha256 = canonicalSha256(reason);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.management-revision-request.v1",
    submissionId,
    reasonSha256
  });
  const context = await assertOrganization(client, organizationId);
  await assertWorkflowAuthority(client, operation, submissionId);
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation,
    key,
    requestSha256: requestHash
  });
  if (replayed) return replayed;
  const result = await client.query<WorkflowMutationRow>(
    `select submission_id,submission_state,result_row_version::text as row_version,
            result_board_id as board_id,result_version_id as version_id,
            result_request_id as request_id
       from boardagent_request_management_revision($1,$2,$3,$4,$5,$6)`,
    [
      requestId,
      submissionId,
      reason,
      Buffer.from(reasonSha256, "hex"),
      idempotencyRecordId,
      auditEventId
    ]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation,
    idempotencyKey: key,
    auditEventId,
    eventType: "management_revision_requested",
    changed,
    details: {
      requestId,
      versionId: changed.versionId,
      reasonSha256,
      requestSha256: requestHash
    }
  });
}

export async function replyToManagementRevisionInTransaction(
  client: PoolClient,
  input: ReplyToManagementRevisionInput
): Promise<ManagementWorkflowResult> {
  const operation = "reply_to_management_revision";
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const submissionId = UuidV7Schema.parse(input.submissionId);
  const revisionRequestId = UuidV7Schema.parse(input.revisionRequestId);
  const replyId = UuidV7Schema.parse(input.replyId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const reply = boundedCanonicalText(input.reply, "management revision reply", 1_048_576);
  const replySha256 = canonicalSha256(reply);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.management-revision-reply.v1",
    submissionId,
    revisionRequestId,
    replySha256
  });
  const context = await assertOrganization(client, organizationId);
  await assertWorkflowAuthority(client, operation, submissionId);
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation,
    key,
    requestSha256: requestHash
  });
  if (replayed) return replayed;
  const result = await client.query<WorkflowMutationRow>(
    `select submission_id,submission_state,result_row_version::text as row_version,
            result_board_id as board_id,result_version_id as version_id,
            result_request_id as request_id,result_reply_id as reply_id
       from boardagent_reply_management_revision($1,$2,$3,$4,$5,$6,$7)`,
    [
      replyId,
      submissionId,
      revisionRequestId,
      reply,
      Buffer.from(replySha256, "hex"),
      idempotencyRecordId,
      auditEventId
    ]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation,
    idempotencyKey: key,
    auditEventId,
    eventType: "management_revision_replied",
    changed,
    details: {
      revisionRequestId,
      replyId,
      versionId: changed.versionId,
      replySha256,
      requestSha256: requestHash
    }
  });
}

async function disposeManagementSubmissionInTransaction(
  client: PoolClient,
  input: ApproveManagementSubmissionInput | RejectManagementSubmissionInput,
  disposition: "approved_to_draft" | "rejected"
): Promise<ManagementWorkflowResult> {
  const operation =
    disposition === "approved_to_draft"
      ? "approve_management_submission"
      : "reject_management_submission";
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const submissionId = UuidV7Schema.parse(input.submissionId);
  const versionId = UuidV7Schema.parse(input.versionId);
  const dispositionId = UuidV7Schema.parse(input.dispositionId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const approval = disposition === "approved_to_draft" ? input : null;
  const rejection = disposition === "rejected" ? (input as RejectManagementSubmissionInput) : null;
  const reason = rejection
    ? boundedCanonicalText(rejection.reason, "management rejection reason", 65_536)
    : null;
  const resultingDraftId = approval
    ? UuidV7Schema.parse((approval as ApproveManagementSubmissionInput).resultingDraftId)
    : null;
  const signedContext = approval
    ? Buffer.from((approval as ApproveManagementSubmissionInput).signedContext)
    : null;
  if (signedContext && (signedContext.length < 32 || signedContext.length > 1_048_576)) {
    throw new RangeError("signed management draft context must contain 32 through 1,048,576 bytes");
  }
  const contextSha256 = approval
    ? Sha256HexSchema.parse((approval as ApproveManagementSubmissionInput).contextSha256)
    : null;
  if (signedContext && !safeHashEqual(sha256Hex(signedContext), contextSha256!)) {
    throw new ManagementWorkflowTransactionError(
      "submission_unavailable",
      "signed management draft context hash is invalid"
    );
  }
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.management-disposition-request.v1",
    operation,
    submissionId,
    versionId,
    reasonSha256: reason ? canonicalSha256(reason) : null
  });
  const context = await assertOrganization(client, organizationId);
  await assertWorkflowAuthority(client, operation, submissionId);
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation,
    key,
    requestSha256: requestHash
  });
  if (replayed) return replayed;
  const result = await client.query<WorkflowMutationRow>(
    `select submission_id,submission_state,result_row_version::text as row_version,
            result_board_id as board_id,result_version_id as version_id,
            result_draft_id as draft_id
       from boardagent_dispose_management_submission(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
       )`,
    [
      dispositionId,
      submissionId,
      versionId,
      disposition,
      reason,
      resultingDraftId,
      signedContext,
      contextSha256 ? Buffer.from(contextSha256, "hex") : null,
      idempotencyRecordId,
      auditEventId
    ]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation,
    idempotencyKey: key,
    auditEventId,
    eventType:
      disposition === "approved_to_draft"
        ? "management_submission_approved_to_draft"
        : "management_submission_rejected",
    changed,
    details: {
      dispositionId,
      versionId,
      requestSha256: requestHash,
      ...(reason ? { reasonSha256: canonicalSha256(reason) } : {}),
      ...(resultingDraftId && contextSha256 ? { resultingDraftId, contextSha256 } : {})
    }
  });
}

export function approveManagementSubmissionInTransaction(
  client: PoolClient,
  input: ApproveManagementSubmissionInput
): Promise<ManagementWorkflowResult> {
  return disposeManagementSubmissionInTransaction(client, input, "approved_to_draft");
}

export function rejectManagementSubmissionInTransaction(
  client: PoolClient,
  input: RejectManagementSubmissionInput
): Promise<ManagementWorkflowResult> {
  return disposeManagementSubmissionInTransaction(client, input, "rejected");
}
