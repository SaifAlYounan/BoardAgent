import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  canonicalJson,
  canonicalSha256,
  canonicalText,
  PendingActionDeltaSchema,
  safeHashEqual,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export class ManagementSubmissionTransactionError extends Error {
  public constructor(
    public readonly code:
      | "resubmission_unavailable"
      | "document_reference_unavailable"
      | "secretary_delivery_invalid"
      | "source_update_input_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "ManagementSubmissionTransactionError";
  }
}

export interface ManagementSubmissionDocumentReferenceInput {
  readonly documentId: string;
  readonly versionId: string;
  readonly sha256: string;
}

export interface ManagementSubmissionSecretaryDeliveryInput {
  readonly secretaryMemberId: string;
  readonly noticeId: string;
  readonly feedId: string;
}

export interface ManagementSubmissionSourceUpdateInput {
  readonly voteId: string;
  readonly causeId: string;
  readonly auditEventId: string;
}

export interface ResubmitManagementMaterialsInput {
  readonly organizationId: string;
  readonly submissionId: string;
  readonly versionId: string;
  readonly documentReferences: readonly ManagementSubmissionDocumentReferenceInput[];
  readonly reason: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
  readonly secretaryDelivery: ManagementSubmissionSecretaryDeliveryInput;
  readonly sourceUpdateAuditEvents: readonly ManagementSubmissionSourceUpdateInput[];
}

export type ResubmitManagementMaterialsResult =
  | {
      readonly replayed: true;
      readonly submissionId: string;
      readonly versionId: string;
      readonly version: number;
      readonly payloadSha256: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly submissionId: string;
      readonly versionId: string;
      readonly version: number;
      readonly payloadSha256: string;
      readonly threadRowVersion: bigint;
      readonly sourceUpdateVoteIds: readonly string[];
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

interface LockedSubmissionRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly submission_state: string;
  readonly current_version_id: string;
  readonly current_version: number;
  readonly current_payload_sha256: Buffer;
  readonly revision_request_id: string | null;
  readonly assigned_secretary_id: string;
  readonly secretary_entitlement_generation: string;
  readonly thread_row_version: string;
}

interface LinkedVoteRow {
  readonly vote_id: string;
  readonly vote_row_version: string;
  readonly vote_state: "open" | "source_update_pending";
  readonly decision_package_id: string;
  readonly decision_package_sha256: Buffer;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
  readonly state: string;
}

interface StoredSubmissionVersionRow {
  readonly version: number;
  readonly payload_sha256: Buffer;
}

const IDEMPOTENCY_OPERATION = "resubmit_management_materials";

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 200 || !/^[A-Za-z0-9._~-]+$/u.test(value)) {
    throw new RangeError("idempotency key must match the frozen 16-to-200 character form");
  }
  return value;
}

function normalizeReason(value: string): string {
  const reason = canonicalText(value);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("management resubmission reason must contain 1 through 65,536 characters");
  }
  return reason;
}

function normalizeDocumentReferences(
  inputs: readonly ManagementSubmissionDocumentReferenceInput[]
): readonly ManagementSubmissionDocumentReferenceInput[] {
  if (inputs.length < 1 || inputs.length > 1000) {
    throw new RangeError("management resubmission requires 1 through 1,000 document references");
  }
  const references = inputs
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
    new Set(references.map(({ documentId }) => documentId)).size !== references.length ||
    new Set(references.map(({ versionId }) => versionId)).size !== references.length
  ) {
    throw new TypeError("management resubmission document and version references must be unique");
  }
  return references;
}

function normalizeSecretaryDelivery(
  input: ManagementSubmissionSecretaryDeliveryInput
): ManagementSubmissionSecretaryDeliveryInput {
  return {
    secretaryMemberId: UuidV7Schema.parse(input.secretaryMemberId),
    noticeId: UuidV7Schema.parse(input.noticeId),
    feedId: UuidV7Schema.parse(input.feedId)
  };
}

function normalizeSourceUpdateInputs(
  inputs: readonly ManagementSubmissionSourceUpdateInput[]
): readonly ManagementSubmissionSourceUpdateInput[] {
  const normalized = inputs
    .map((input) => ({
      voteId: UuidV7Schema.parse(input.voteId),
      causeId: UuidV7Schema.parse(input.causeId),
      auditEventId: UuidV7Schema.parse(input.auditEventId)
    }))
    .toSorted((left, right) => left.voteId.localeCompare(right.voteId));
  if (
    new Set(normalized.map(({ voteId }) => voteId)).size !== normalized.length ||
    new Set(normalized.map(({ causeId }) => causeId)).size !== normalized.length ||
    new Set(normalized.map(({ auditEventId }) => auditEventId)).size !== normalized.length
  ) {
    throw new TypeError("management source-update vote, cause and audit IDs must be unique");
  }
  return normalized;
}

function requestSha256(input: {
  readonly submissionId: string;
  readonly documentReferences: readonly ManagementSubmissionDocumentReferenceInput[];
  readonly reason: string;
}): string {
  return canonicalSha256({
    schemaVersion: "boardagent.management-resubmission-request.v1",
    submissionId: input.submissionId,
    documentReferences: input.documentReferences,
    reason: input.reason
  });
}

function responseMaterial(input: {
  readonly submissionId: string;
  readonly versionId: string;
  readonly version: number;
  readonly payloadSha256: string;
}) {
  return {
    schemaVersion: "boardagent.management-resubmission-response.v1" as const,
    submissionId: input.submissionId,
    versionId: input.versionId,
    version: input.version,
    payloadSha256: input.payloadSha256
  };
}

async function lockSubmission(
  client: PoolClient,
  submissionId: string
): Promise<LockedSubmissionRow> {
  const result = await client.query<LockedSubmissionRow>(
    `select organization_id,board_id,submission_state,current_version_id,current_version,
            current_payload_sha256,revision_request_id,assigned_secretary_id,
            secretary_entitlement_generation::text,thread_row_version::text
       from boardagent_lock_management_submission_for_resubmission($1)`,
    [submissionId]
  );
  const submission = result.rows[0];
  if (!submission || result.rows.length !== 1) {
    throw new ManagementSubmissionTransactionError(
      "resubmission_unavailable",
      "management resubmission is unavailable"
    );
  }
  if (
    !Number.isSafeInteger(submission.current_version) ||
    submission.current_version < 1 ||
    BigInt(submission.thread_row_version) < 1n ||
    BigInt(submission.secretary_entitlement_generation) < 1n ||
    submission.current_payload_sha256.length !== 32
  ) {
    throw new Error("locked management submission has an invalid durable shape");
  }
  return submission;
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  idempotencyKey: string,
  lock: boolean
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      ${lock ? "for update" : ""}`,
    [actorMemberId, clientId, IDEMPOTENCY_OPERATION, idempotencyKey]
  );
  return result.rows[0];
}

async function replayResult(
  client: PoolClient,
  record: IdempotencyRow,
  expectedRequestSha256: string,
  submissionId: string
): Promise<Extract<ResubmitManagementMaterialsResult, { readonly replayed: true }>> {
  if (!safeHashEqual(record.request_sha256.toString("hex"), expectedRequestSha256)) {
    throw new ManagementSubmissionTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different management resubmission"
    );
  }
  if (record.state !== "succeeded") {
    throw new ManagementSubmissionTransactionError(
      "idempotency_in_progress",
      "identical management resubmission is already in progress"
    );
  }
  if (
    record.safe_response_type !== "management_submission_version" ||
    !record.safe_response_id ||
    !record.safe_response_sha256
  ) {
    throw new Error("management resubmission idempotency record has no safe response");
  }
  const stored = await client.query<StoredSubmissionVersionRow>(
    `select version,payload_sha256
       from management_submission_versions
      where id=$1 and thread_id=$2`,
    [record.safe_response_id, submissionId]
  );
  const version = stored.rows[0];
  if (!version || !Number.isSafeInteger(version.version) || version.payload_sha256.length !== 32) {
    throw new Error("management resubmission safe response version is unavailable");
  }
  const payloadSha256 = version.payload_sha256.toString("hex");
  const expectedResponseSha256 = canonicalSha256(
    responseMaterial({
      submissionId,
      versionId: record.safe_response_id,
      version: version.version,
      payloadSha256
    })
  );
  if (!safeHashEqual(record.safe_response_sha256.toString("hex"), expectedResponseSha256)) {
    throw new Error("management resubmission safe response hash is invalid");
  }
  return {
    replayed: true,
    submissionId,
    versionId: record.safe_response_id,
    version: version.version,
    payloadSha256,
    responseSha256: expectedResponseSha256
  };
}

async function acquireIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly key: string;
    readonly requestSha256: string;
    readonly submissionId: string;
  }
): Promise<
  | { readonly replayed: false }
  | {
      readonly replayed: true;
      readonly result: Extract<ResubmitManagementMaterialsResult, { readonly replayed: true }>;
    }
> {
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
      IDEMPOTENCY_OPERATION,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
  const record = await readIdempotency(
    client,
    input.actorMemberId,
    input.clientId,
    input.key,
    true
  );
  if (!record) throw new Error("management resubmission idempotency record disappeared");
  if (inserted.rowCount === 0) {
    return {
      replayed: true,
      result: await replayResult(client, record, input.requestSha256, input.submissionId)
    };
  }
  if (!safeHashEqual(record.request_sha256.toString("hex"), input.requestSha256)) {
    throw new ManagementSubmissionTransactionError(
      "idempotency_conflict",
      "management resubmission idempotency record does not bind this request"
    );
  }
  return { replayed: false };
}

async function validateAcceptedDocuments(
  client: PoolClient,
  boardId: string,
  references: readonly ManagementSubmissionDocumentReferenceInput[]
): Promise<void> {
  const result = await client.query<{ valid: boolean }>(
    "select boardagent_management_submission_documents_valid($1,$2::jsonb) as valid",
    [boardId, JSON.stringify(references)]
  );
  if (!result.rows[0]?.valid) {
    throw new ManagementSubmissionTransactionError(
      "document_reference_unavailable",
      "management resubmission requires exact accepted document versions available to the actor"
    );
  }
}

async function lockLinkedVotes(
  client: PoolClient,
  priorVersionId: string,
  priorVersion: number,
  priorPayloadSha256: Buffer
): Promise<readonly LinkedVoteRow[]> {
  const corrupt = await client.query<{ invalid: boolean }>(
    `select exists (
       select 1
         from decision_package_components as component
         join decision_packages as package on package.id=component.decision_package_id
         join votes as vote
           on vote.id=package.vote_id and vote.current_decision_package_id=package.id
        where component.component_class='submission'
          and component.object_id=$1
          and vote.state in ('open','source_update_pending')
          and (
            component.object_type <> 'management_submission_version'
            or component.object_version is distinct from $2::bigint
            or component.object_sha256 is distinct from $3
          )
     ) as invalid`,
    [priorVersionId, priorVersion, priorPayloadSha256]
  );
  if (corrupt.rows[0]?.invalid) {
    throw new ManagementSubmissionTransactionError(
      "resubmission_unavailable",
      "linked vote contains an invalid management submission component"
    );
  }
  const result = await client.query<LinkedVoteRow>(
    `select vote.id as vote_id,vote.row_version::text as vote_row_version,
            vote.state as vote_state,package.id as decision_package_id,
            package.package_sha256 as decision_package_sha256
       from votes as vote
       join decision_packages as package
         on package.vote_id=vote.id and package.id=vote.current_decision_package_id
      where vote.state in ('open','source_update_pending')
        and exists (
          select 1
            from decision_package_components as component
           where component.decision_package_id=package.id
             and component.component_class='submission'
             and component.object_type='management_submission_version'
             and component.object_id=$1
             and component.object_version=$2::bigint
             and component.object_sha256=$3
        )
      order by vote.id
      for update of vote`,
    [priorVersionId, priorVersion, priorPayloadSha256]
  );
  if (
    result.rows.some(
      (vote) => BigInt(vote.vote_row_version) < 1n || vote.decision_package_sha256.length !== 32
    )
  ) {
    throw new Error("linked management-submission vote has an invalid durable shape");
  }
  return result.rows;
}

function assertSourceUpdateInputs(
  supplied: readonly ManagementSubmissionSourceUpdateInput[],
  linkedVotes: readonly LinkedVoteRow[],
  primaryAuditEventId: string
): void {
  if (
    supplied.length !== linkedVotes.length ||
    supplied.some((input, index) => input.voteId !== linkedVotes[index]?.vote_id) ||
    supplied.some((input) => input.auditEventId === primaryAuditEventId)
  ) {
    throw new ManagementSubmissionTransactionError(
      "source_update_input_invalid",
      "source-update IDs must match every linked open vote exactly once"
    );
  }
}

async function nextFeedSequence(
  client: PoolClient,
  boardId: string,
  memberId: string
): Promise<bigint> {
  const result = await client.query<{ next_sequence: string }>(
    `select (
       greatest(
         coalesce((select max(feed_sequence) from notices
                    where board_id=$1 and recipient_member_id=$2),0),
         coalesce((select max(feed_sequence) from pending_action_feed
                    where board_id=$1 and member_id=$2),0),
         coalesce((select max(feed_sequence) from feed_tombstones
                    where board_id=$1 and member_id=$2),0)
       ) + 1
     )::text as next_sequence`,
    [boardId, memberId]
  );
  const sequence = BigInt(result.rows[0]?.next_sequence ?? "0");
  if (sequence < 1n) throw new Error("failed to allocate a positive secretary feed sequence");
  return sequence;
}

async function transactionTime(client: PoolClient): Promise<string> {
  const result = await client.query<{ occurred_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
  );
  const occurredAt = result.rows[0]?.occurred_at;
  if (!occurredAt) throw new Error("management resubmission transaction time is unavailable");
  return occurredAt;
}

async function completeIdempotency(
  client: PoolClient,
  input: {
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly key: string;
    readonly versionId: string;
    readonly responseSha256: string;
  }
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='management_submission_version',
            safe_response_id=$1,safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4 and operation=$5 and idempotency_key=$6
        and state='in_progress'`,
    [
      input.versionId,
      Buffer.from(input.responseSha256, "hex"),
      input.actorMemberId,
      input.clientId,
      IDEMPOTENCY_OPERATION,
      input.key
    ]
  );
  if (result.rowCount !== 1)
    throw new Error("management resubmission idempotency completion failed");
}

export async function resubmitManagementMaterialsInTransaction(
  client: PoolClient,
  input: ResubmitManagementMaterialsInput
): Promise<ResubmitManagementMaterialsResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const submissionId = UuidV7Schema.parse(input.submissionId);
  const versionId = UuidV7Schema.parse(input.versionId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const reason = normalizeReason(input.reason);
  const documentReferences = normalizeDocumentReferences(input.documentReferences);
  const secretaryDelivery = normalizeSecretaryDelivery(input.secretaryDelivery);
  const sourceUpdateAuditEvents = normalizeSourceUpdateInputs(input.sourceUpdateAuditEvents);
  const requestHash = requestSha256({ submissionId, documentReferences, reason });
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new ManagementSubmissionTransactionError(
      "resubmission_unavailable",
      "management resubmission is unavailable"
    );
  }

  const submission = await lockSubmission(client, submissionId);
  if (submission.organization_id !== organizationId) {
    throw new ManagementSubmissionTransactionError(
      "resubmission_unavailable",
      "management resubmission is unavailable"
    );
  }

  const existingIdempotency = await readIdempotency(
    client,
    context.memberId,
    context.clientId,
    idempotencyKey,
    false
  );
  if (existingIdempotency) {
    return replayResult(client, existingIdempotency, requestHash, submissionId);
  }
  if (submission.submission_state !== "revision_requested") {
    throw new ManagementSubmissionTransactionError(
      "resubmission_unavailable",
      "management submission is not awaiting a revision"
    );
  }
  if (!submission.revision_request_id) {
    throw new ManagementSubmissionTransactionError(
      "resubmission_unavailable",
      "management submission has no revision request for its current version"
    );
  }
  if (secretaryDelivery.secretaryMemberId !== submission.assigned_secretary_id) {
    throw new ManagementSubmissionTransactionError(
      "secretary_delivery_invalid",
      "management resubmission delivery must target the assigned secretary"
    );
  }

  await validateAcceptedDocuments(client, submission.board_id, documentReferences);
  const linkedVotes = await lockLinkedVotes(
    client,
    submission.current_version_id,
    submission.current_version,
    submission.current_payload_sha256
  );
  assertSourceUpdateInputs(sourceUpdateAuditEvents, linkedVotes, auditEventId);
  const idempotency = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    key: idempotencyKey,
    requestSha256: requestHash,
    submissionId
  });
  if (idempotency.replayed) return idempotency.result;

  const nextVersion = submission.current_version + 1;
  if (!Number.isSafeInteger(nextVersion)) {
    throw new RangeError("management submission version exceeds the safe integer range");
  }
  const canonicalPayload = {
    schemaVersion: "boardagent.management-submission.v1" as const,
    submissionId,
    versionId,
    version: nextVersion,
    documentReferences,
    changeReason: reason,
    supersedesVersionId: submission.current_version_id,
    authorMemberId: context.memberId,
    revisionRequestId: submission.revision_request_id
  };
  const canonicalPayloadBytes = Buffer.from(canonicalJson(canonicalPayload), "utf8");
  const payloadSha256 = canonicalSha256(canonicalPayload);
  await client.query(
    `insert into management_submission_versions(
       id,organization_id,board_id,thread_id,version,schema_version,canonical_payload,
       document_references,payload_sha256,author_member_id,change_reason,supersedes_id,
       audit_event_id
     ) values ($1,$2,$3,$4,$5,'boardagent.management-submission.v1',$6,$7,$8,$9,$10,$11,$12)`,
    [
      versionId,
      organizationId,
      submission.board_id,
      submissionId,
      nextVersion,
      canonicalPayloadBytes,
      JSON.stringify(documentReferences),
      Buffer.from(payloadSha256, "hex"),
      context.memberId,
      reason,
      submission.current_version_id,
      auditEventId
    ]
  );

  const nextThreadRowVersion = BigInt(submission.thread_row_version) + 1n;
  const updatedThread = await client.query<{ row_version: string }>(
    `select boardagent_apply_management_resubmission($1,$2::bigint,$3,$4,$5)::text
            as row_version`,
    [
      submissionId,
      submission.thread_row_version,
      submission.current_version_id,
      versionId,
      auditEventId
    ]
  );
  if (updatedThread.rows[0]?.row_version !== nextThreadRowVersion.toString(10)) {
    throw new ManagementSubmissionTransactionError(
      "resubmission_unavailable",
      "management submission changed while recording the resubmission"
    );
  }

  for (const vote of linkedVotes) {
    const updatedVote = await client.query(
      `update votes
          set state='source_update_pending',row_version=row_version+1
        where id=$1 and state in ('open','source_update_pending')
          and row_version=$2::bigint`,
      [vote.vote_id, vote.vote_row_version]
    );
    if (updatedVote.rowCount !== 1) {
      throw new ManagementSubmissionTransactionError(
        "resubmission_unavailable",
        "linked vote changed while recording the management resubmission"
      );
    }
  }
  for (const [index, vote] of linkedVotes.entries()) {
    const sourceInput = sourceUpdateAuditEvents[index];
    if (!sourceInput || sourceInput.voteId !== vote.vote_id) {
      throw new Error("management source-update order changed inside the transaction");
    }
    await client.query(
      `insert into vote_source_update_causes(
         id,organization_id,board_id,vote_id,source_class,source_id,source_version,
         source_sha256,trigger_audit_event_id
       ) values ($1,$2,$3,$4,'management_submission',$5,$6,$7,$8)`,
      [
        sourceInput.causeId,
        organizationId,
        submission.board_id,
        vote.vote_id,
        submissionId,
        nextVersion,
        Buffer.from(payloadSha256, "hex"),
        sourceInput.auditEventId
      ]
    );
  }

  const occurredAt = await transactionTime(client);
  const sequence = await nextFeedSequence(
    client,
    submission.board_id,
    submission.assigned_secretary_id
  );
  const entitlementGeneration = Number(submission.secretary_entitlement_generation);
  if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
    throw new Error("assigned secretary entitlement generation is invalid");
  }
  const feedPayload = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: sequence.toString(10),
    deltaType: "action_required",
    objectType: "submission",
    objectId: submissionId,
    objectVersion: nextVersion,
    entitlementGeneration,
    actionState: "pending",
    changedComponentClasses: ["management_submission"],
    safeRefs: {
      versionId,
      payloadSha256,
      revisionRequestId: submission.revision_request_id
    },
    createdAt: occurredAt
  });
  const visibilitySha256 = canonicalSha256({
    schemaVersion: "boardagent.management-submission-secretary-visibility.v1",
    submissionId,
    secretaryMemberId: submission.assigned_secretary_id,
    entitlementGeneration
  });
  const noticeSha256 = canonicalSha256({
    noticeType: "management_submission_version_created",
    submissionId,
    versionId,
    version: nextVersion,
    payloadSha256,
    recipientMemberId: submission.assigned_secretary_id
  });
  const canonicalFeed = canonicalJson(feedPayload);
  await client.query(
    `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,'management_submission_version_created','submission',$4,$5,$6,$7,$8,$9)`,
    [
      secretaryDelivery.noticeId,
      organizationId,
      submission.board_id,
      submissionId,
      nextVersion,
      submission.assigned_secretary_id,
      Buffer.from(noticeSha256, "hex"),
      sequence.toString(10),
      auditEventId
    ]
  );
  await client.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,notice_id,audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,'management_submission_version_created','submission',
       $7,$8,$9,$10,$11,$12,$13)`,
    [
      secretaryDelivery.feedId,
      organizationId,
      submission.board_id,
      submission.assigned_secretary_id,
      submission.secretary_entitlement_generation,
      sequence.toString(10),
      submissionId,
      nextVersion,
      Buffer.from(visibilitySha256, "hex"),
      Buffer.from(canonicalFeed, "utf8"),
      Buffer.from(canonicalSha256(feedPayload), "hex"),
      secretaryDelivery.noticeId,
      auditEventId
    ]
  );

  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: nextThreadRowVersion,
      event: {
        eventId: auditEventId,
        eventType: "management_submission_version_created",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "management_submission",
        entityId: submissionId,
        boardId: submission.board_id,
        origin: "mcp",
        details: {
          versionId,
          version: nextVersion,
          payloadSha256,
          supersedesVersionId: submission.current_version_id,
          revisionRequestId: submission.revision_request_id,
          requestSha256: requestHash,
          documentReferences: documentReferences.map(({ documentId, versionId, sha256 }) => ({
            documentId,
            versionId,
            sha256
          })),
          sourceUpdateVoteIds: linkedVotes.map(({ vote_id }) => vote_id)
        },
        schemaVersion: 1
      }
    },
    ...linkedVotes.map((vote, index) => ({
      organizationId,
      objectVersion: BigInt(vote.vote_row_version) + 1n,
      event: {
        eventId: sourceUpdateAuditEvents[index]!.auditEventId,
        eventType: "vote_source_update_pending" as const,
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: vote.vote_id,
        boardId: submission.board_id,
        origin: "mcp",
        details: {
          sourceType: "management_submission",
          sourceCauseId: sourceUpdateAuditEvents[index]!.causeId,
          submissionId,
          priorVersionId: submission.current_version_id,
          versionId,
          version: nextVersion,
          payloadSha256,
          decisionPackageId: vote.decision_package_id,
          decisionPackageSha256: vote.decision_package_sha256.toString("hex")
        },
        schemaVersion: 1 as const
      }
    }))
  ]);

  const responseSha256 = canonicalSha256(
    responseMaterial({ submissionId, versionId, version: nextVersion, payloadSha256 })
  );
  await completeIdempotency(client, {
    actorMemberId: context.memberId,
    clientId: context.clientId,
    key: idempotencyKey,
    versionId,
    responseSha256
  });
  return {
    replayed: false,
    submissionId,
    versionId,
    version: nextVersion,
    payloadSha256,
    threadRowVersion: nextThreadRowVersion,
    sourceUpdateVoteIds: linkedVotes.map(({ vote_id }) => vote_id),
    responseSha256,
    auditEvents
  };
}
