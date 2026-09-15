import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  canonicalJson,
  canonicalSha256,
  PendingActionDeltaSchema,
  safeHashEqual,
  UuidV7Schema
} from "@boardagent/contracts";
import {
  prepareManagementQuestion,
  prepareManagementQuestionTurn,
  type ManagementQuestionCitation,
  type PreparedManagementQuestion,
  type PreparedManagementQuestionTurn
} from "@boardagent/domain";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export class QuestionTransactionError extends Error {
  public constructor(
    public readonly code:
      | "question_creation_unavailable"
      | "question_turn_unavailable"
      | "question_owner_unavailable"
      | "question_citation_unavailable"
      | "question_due_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress"
      | "invalid_prepared_question"
      | "invalid_prepared_turn"
      | "source_update_input_invalid",
    message: string
  ) {
    super(message);
    this.name = "QuestionTransactionError";
  }
}

export interface QuestionOwnerDeliveryInput {
  readonly ownerMemberId: string;
  readonly noticeId: string;
  readonly feedId: string;
}

export interface AskManagementQuestionInput {
  readonly organizationId: string;
  readonly prepared: PreparedManagementQuestion;
  readonly initialTurnId: string;
  readonly auditEventId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly visibilityRecordIds: readonly string[];
  readonly ownerDeliveries: readonly QuestionOwnerDeliveryInput[];
}

export type AskManagementQuestionResult =
  | {
      readonly replayed: true;
      readonly questionId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly questionId: string;
      readonly turnId: string;
      readonly responseSha256: string;
      readonly auditEvent: AuditEvent;
    };

export interface QuestionRecipientDeliveryInput {
  readonly recipientMemberId: string;
  readonly noticeId: string;
  readonly feedId: string;
}

export interface QuestionOwnerResolutionInput {
  readonly ownerMemberId: string;
  readonly tombstoneId: string;
}

export interface VoteSourceUpdateAuditInput {
  readonly voteId: string;
  readonly causeId: string;
  readonly auditEventId: string;
}

export interface AnswerManagementQuestionInput {
  readonly organizationId: string;
  readonly prepared: PreparedManagementQuestionTurn;
  readonly turnId: string;
  readonly answerRecordId: string;
  readonly auditEventId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly askerDelivery: QuestionRecipientDeliveryInput;
  readonly ownerResolutions: readonly QuestionOwnerResolutionInput[];
  readonly sourceUpdateAuditEvents: readonly VoteSourceUpdateAuditInput[];
}

export interface FollowUpManagementQuestionInput {
  readonly organizationId: string;
  readonly prepared: PreparedManagementQuestionTurn;
  readonly turnId: string;
  readonly auditEventId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly ownerDeliveries: readonly QuestionOwnerDeliveryInput[];
  readonly sourceUpdateAuditEvents: readonly VoteSourceUpdateAuditInput[];
}

export type ManagementQuestionTurnResult =
  | {
      readonly replayed: true;
      readonly questionId: string;
      readonly turnId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly questionId: string;
      readonly turnId: string;
      readonly turnOrdinal: number;
      readonly questionRowVersion: bigint;
      readonly sourceUpdateVoteIds: readonly string[];
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
  readonly state: string;
}

interface CitationRow {
  readonly board_id: string;
  readonly document_id: string;
  readonly id: string;
  readonly sha256: Buffer;
}

interface OwnerMembershipRow {
  readonly entitlement_generation: string;
  readonly has_management_role: boolean;
  readonly member_id: string;
  readonly seat_role: string;
}

interface LockedQuestionRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly asker_member_id: string;
  readonly assigned_owner_ids: string[];
  readonly due_at: string;
  readonly acl_policy: {
    readonly schemaVersion: string;
    readonly grants: readonly unknown[];
    readonly inheritedDocumentIds: readonly string[];
  };
  readonly question_state: "pending" | "overdue" | "answered";
  readonly current_turn_id: string;
  readonly current_ordinal: number;
  readonly row_version: string;
}

interface LinkedVoteRow {
  readonly decision_package_id: string;
  readonly decision_package_sha256: Buffer;
  readonly inclusive_turn_ordinal: number;
  readonly vote_id: string;
  readonly vote_row_version: string;
  readonly vote_state: "open" | "source_update_pending";
}

interface PendingOwnerActionRow {
  readonly entitlement_generation: string;
  readonly feed_id: string;
  readonly member_id: string;
}

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function assertPreparedQuestion(prepared: PreparedManagementQuestion): void {
  const reconstructed = prepareManagementQuestion({
    questionId: prepared.questionId,
    boardId: prepared.boardId,
    question: prepared.question,
    assignedOwnerIds: prepared.assignedOwnerIds,
    dueAt: prepared.dueAt,
    citations: prepared.citations,
    visibility: prepared.visibility
  });
  if (
    !safeHashEqual(reconstructed.requestSha256, prepared.requestSha256) ||
    !safeHashEqual(reconstructed.textSha256, prepared.textSha256) ||
    !Buffer.from(reconstructed.canonicalPayload).equals(Buffer.from(prepared.canonicalPayload))
  ) {
    throw new QuestionTransactionError(
      "invalid_prepared_question",
      "prepared management question failed canonical integrity validation"
    );
  }
}

function assertPreparedTurn(
  prepared: PreparedManagementQuestionTurn,
  expectedKind: "answer" | "follow_up"
): void {
  if (prepared.turnKind !== expectedKind) {
    throw new QuestionTransactionError(
      "invalid_prepared_turn",
      `prepared management question turn must be ${expectedKind}`
    );
  }
  const reconstructed =
    expectedKind === "answer"
      ? prepareManagementQuestionTurn({
          questionId: prepared.questionId,
          turnKind: "answer",
          text: prepared.text,
          citations: prepared.citations
        })
      : prepareManagementQuestionTurn({
          questionId: prepared.questionId,
          turnKind: "follow_up",
          text: prepared.text,
          citations: prepared.citations,
          dueAt: prepared.dueAt ?? ""
        });
  if (
    reconstructed.dueAt !== prepared.dueAt ||
    !safeHashEqual(reconstructed.requestSha256, prepared.requestSha256) ||
    !safeHashEqual(reconstructed.textSha256, prepared.textSha256) ||
    !Buffer.from(reconstructed.canonicalPayload).equals(Buffer.from(prepared.canonicalPayload))
  ) {
    throw new QuestionTransactionError(
      "invalid_prepared_turn",
      "prepared management question turn failed canonical integrity validation"
    );
  }
}

async function lockVisibleCitations(
  client: PoolClient,
  citations: readonly ManagementQuestionCitation[],
  expectedBoardId: string | undefined
): Promise<readonly string[]> {
  if (citations.length === 0) return [];
  const citationIds = citations.map((citation) => citation.sourceDocumentVersionId);
  const result = await client.query<CitationRow>(
    `select id,document_id,board_id,sha256
       from boardagent_lock_visible_question_citations($1::uuid[])`,
    [citationIds]
  );
  const expected = new Map(
    citations.map((citation) => [citation.sourceDocumentVersionId, citation.sourceDocumentSha256])
  );
  if (
    result.rows.length !== expected.size ||
    result.rows.some(
      (citation) =>
        (expectedBoardId !== undefined && citation.board_id !== expectedBoardId) ||
        !safeHashEqual(citation.sha256.toString("hex"), expected.get(citation.id) ?? "")
    )
  ) {
    throw new QuestionTransactionError(
      "question_citation_unavailable",
      "one or more question citations are unavailable"
    );
  }
  return [...new Set(result.rows.map(({ document_id }) => document_id))].toSorted();
}

function normalizedRecipientDelivery(
  input: QuestionRecipientDeliveryInput
): QuestionRecipientDeliveryInput {
  return {
    recipientMemberId: UuidV7Schema.parse(input.recipientMemberId),
    noticeId: UuidV7Schema.parse(input.noticeId),
    feedId: UuidV7Schema.parse(input.feedId)
  };
}

function normalizedOwnerResolutions(
  inputs: readonly QuestionOwnerResolutionInput[],
  expectedOwners: readonly string[]
): readonly QuestionOwnerResolutionInput[] {
  const resolutions = inputs
    .map((resolution) => ({
      ownerMemberId: UuidV7Schema.parse(resolution.ownerMemberId),
      tombstoneId: UuidV7Schema.parse(resolution.tombstoneId)
    }))
    .toSorted((left, right) => left.ownerMemberId.localeCompare(right.ownerMemberId));
  if (
    resolutions.length !== expectedOwners.length ||
    resolutions.some((resolution, index) => resolution.ownerMemberId !== expectedOwners[index])
  ) {
    throw new TypeError("owner resolutions must match every assigned owner exactly once");
  }
  return resolutions;
}

function normalizedSourceUpdateAudits(
  inputs: readonly VoteSourceUpdateAuditInput[]
): readonly VoteSourceUpdateAuditInput[] {
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
    throw new TypeError("source-update inputs must contain unique vote, cause and event IDs");
  }
  return normalized;
}

async function acquireTurnIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly operation: "answer_management_question" | "follow_up_management_question";
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<
  | { readonly replayed: false }
  | { readonly replayed: true; readonly turnId: string; readonly responseSha256: string }
> {
  const inserted = await client.query<{ id: string }>(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'in_progress',
       transaction_timestamp() + interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing
     returning id`,
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
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      for update`,
    [input.actorMemberId, input.clientId, input.operation, input.key]
  );
  const record = result.rows[0];
  if (!record) throw new Error("question-turn idempotency record disappeared");
  if (!safeHashEqual(record.request_sha256.toString("hex"), input.requestSha256)) {
    throw new QuestionTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different request"
    );
  }
  if (inserted.rowCount === 0) {
    if (record.state === "succeeded" && record.safe_response_id && record.safe_response_sha256) {
      return {
        replayed: true,
        turnId: record.safe_response_id,
        responseSha256: record.safe_response_sha256.toString("hex")
      };
    }
    throw new QuestionTransactionError(
      "idempotency_in_progress",
      "identical management question turn is already in progress"
    );
  }
  return { replayed: false };
}

async function completeTurnIdempotency(
  client: PoolClient,
  input: {
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly operation: "answer_management_question" | "follow_up_management_question";
    readonly key: string;
    readonly turnId: string;
    readonly responseSha256: string;
  }
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='management_question_turn',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4 and operation=$5 and idempotency_key=$6`,
    [
      input.turnId,
      Buffer.from(input.responseSha256, "hex"),
      input.actorMemberId,
      input.clientId,
      input.operation,
      input.key
    ]
  );
  if (result.rowCount !== 1) throw new Error("question-turn idempotency completion failed");
}

function normalizedDeliveries(
  inputs: readonly QuestionOwnerDeliveryInput[],
  expectedOwners: readonly string[]
): readonly QuestionOwnerDeliveryInput[] {
  const deliveries = inputs.map((delivery) => ({
    ownerMemberId: UuidV7Schema.parse(delivery.ownerMemberId),
    noticeId: UuidV7Schema.parse(delivery.noticeId),
    feedId: UuidV7Schema.parse(delivery.feedId)
  }));
  deliveries.sort((left, right) =>
    left.ownerMemberId < right.ownerMemberId ? -1 : left.ownerMemberId > right.ownerMemberId ? 1 : 0
  );
  if (
    deliveries.length !== expectedOwners.length ||
    deliveries.some((delivery, index) => delivery.ownerMemberId !== expectedOwners[index])
  ) {
    throw new TypeError("owner deliveries must match every assigned owner exactly once");
  }
  return deliveries;
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
  if (sequence < 1n) throw new Error("failed to allocate a positive feed sequence");
  return sequence;
}

export async function askManagementQuestionInTransaction(
  client: PoolClient,
  input: AskManagementQuestionInput
): Promise<AskManagementQuestionResult> {
  assertPreparedQuestion(input.prepared);
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const initialTurnId = UuidV7Schema.parse(input.initialTurnId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const visibilityRecordIds = input.visibilityRecordIds.map((id) => UuidV7Schema.parse(id));
  if (visibilityRecordIds.length !== input.prepared.visibility.length) {
    throw new TypeError("visibility record IDs must match normalized visibility grants");
  }
  if (new Set(visibilityRecordIds).size !== visibilityRecordIds.length) {
    throw new TypeError("visibility record IDs must be unique");
  }
  const deliveries = normalizedDeliveries(input.ownerDeliveries, input.prepared.assignedOwnerIds);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new QuestionTransactionError(
      "question_creation_unavailable",
      "management question creation is unavailable"
    );
  }

  const boardLock = await client.query<{ allowed: boolean }>(
    "select boardagent_lock_board_for_question($1) as allowed",
    [input.prepared.boardId]
  );
  if (!boardLock.rows[0]?.allowed) {
    throw new QuestionTransactionError(
      "question_creation_unavailable",
      "management question creation is unavailable"
    );
  }
  const ownersValid = await client.query<{ valid: boolean }>(
    "select boardagent_question_owners_valid($1,$2::uuid[]) as valid",
    [input.prepared.boardId, input.prepared.assignedOwnerIds]
  );
  if (!ownersValid.rows[0]?.valid) {
    throw new QuestionTransactionError(
      "question_owner_unavailable",
      "one or more assigned management owners are unavailable"
    );
  }
  const due = await client.query<{ due_valid: boolean; occurred_at: string }>(
    `select $1::timestamptz > transaction_timestamp() as due_valid,
            to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`,
    [input.prepared.dueAt]
  );
  const inheritedDocumentIds = await lockVisibleCitations(
    client,
    input.prepared.citations,
    input.prepared.boardId
  );
  const recipientsEntitled = await client.query<{ entitled: boolean }>(
    "select boardagent_question_recipients_entitled($1,$2::uuid[],$3::uuid[]) as entitled",
    [input.prepared.boardId, input.prepared.assignedOwnerIds, inheritedDocumentIds]
  );
  if (!recipientsEntitled.rows[0]?.entitled) {
    throw new QuestionTransactionError(
      "question_owner_unavailable",
      "one or more assigned management owners cannot receive the question"
    );
  }
  const aclPolicy = {
    ...input.prepared.aclPolicy,
    inheritedDocumentIds
  };

  const memberIds = [...input.prepared.assignedOwnerIds, context.memberId].toSorted();
  const lockedMemberships = await client.query<OwnerMembershipRow>(
    `select locked.member_id,locked.entitlement_generation::text,
            locked.seat_role,locked.has_management_role
       from boardagent_lock_board_members($1,$2,$3::uuid[]) as locked
      where locked.active_now
      order by locked.member_id`,
    [organizationId, input.prepared.boardId, memberIds]
  );
  if (lockedMemberships.rows.length !== memberIds.length) {
    throw new QuestionTransactionError(
      "question_owner_unavailable",
      "one or more management-question participants are unavailable"
    );
  }
  const authorMembership = lockedMemberships.rows.find(
    ({ member_id }) => member_id === context.memberId
  );
  const authorRole = authorMembership?.seat_role;
  if (authorRole !== "voting_member" && authorRole !== "observer") {
    throw new QuestionTransactionError(
      "question_creation_unavailable",
      "management question creation is unavailable"
    );
  }
  const ownerMemberships = lockedMemberships.rows.filter(({ member_id }) =>
    input.prepared.assignedOwnerIds.includes(member_id)
  );

  const insertedIdempotency = await client.query<{ id: string }>(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'ask_management',$5,$6,'in_progress',
       transaction_timestamp() + interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing
     returning id`,
    [
      idempotencyRecordId,
      organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(input.prepared.requestSha256, "hex")
    ]
  );
  const idempotency = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
      from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='ask_management' and idempotency_key=$3
      for update`,
    [context.memberId, context.clientId, idempotencyKey]
  );
  const record = idempotency.rows[0];
  if (!record) throw new Error("idempotency record disappeared inside its transaction");
  if (!safeHashEqual(record.request_sha256.toString("hex"), input.prepared.requestSha256)) {
    throw new QuestionTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different request"
    );
  }
  if (insertedIdempotency.rowCount === 0) {
    if (record.state === "succeeded" && record.safe_response_id && record.safe_response_sha256) {
      return {
        replayed: true,
        questionId: record.safe_response_id,
        responseSha256: record.safe_response_sha256.toString("hex")
      };
    }
    throw new QuestionTransactionError(
      "idempotency_in_progress",
      "identical management question is already in progress"
    );
  }

  if (!due.rows[0]?.due_valid) {
    throw new QuestionTransactionError(
      "question_due_invalid",
      "management question due time must be in the future"
    );
  }

  await client.query(
    `insert into management_questions(
       id,organization_id,board_id,asker_member_id,assigned_owner_ids,due_at,
       acl_policy,current_turn_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      input.prepared.questionId,
      organizationId,
      input.prepared.boardId,
      context.memberId,
      input.prepared.assignedOwnerIds,
      input.prepared.dueAt,
      aclPolicy,
      initialTurnId
    ]
  );
  await client.query(
    `insert into management_question_turns(
       id,organization_id,board_id,question_id,ordinal,turn_kind,author_member_id,
       author_role,canonical_text,text_sha256,citation_snapshot,idempotency_record_id
     ) values ($1,$2,$3,$4,1,'question',$5,$6,$7,$8,$9,$10)`,
    [
      initialTurnId,
      organizationId,
      input.prepared.boardId,
      input.prepared.questionId,
      context.memberId,
      authorRole,
      input.prepared.question,
      Buffer.from(input.prepared.textSha256, "hex"),
      canonicalJson(input.prepared.citations),
      idempotencyRecordId
    ]
  );
  for (const [index, grant] of input.prepared.visibility.entries()) {
    await client.query(
      `insert into question_visibility(
         id,organization_id,board_id,question_id,grantee_member_id,grantee_seat_role,
         effect,reason,created_by
       ) values ($1,$2,$3,$4,$5,$6,'grant','question creation ACL',$7)`,
      [
        visibilityRecordIds[index],
        organizationId,
        input.prepared.boardId,
        input.prepared.questionId,
        grant.granteeType === "member" ? grant.memberId : null,
        grant.granteeType === "seat_role" ? grant.seatRole : null,
        context.memberId
      ]
    );
  }

  if (ownerMemberships.length !== deliveries.length) {
    throw new QuestionTransactionError(
      "question_owner_unavailable",
      "one or more assigned management owners are unavailable"
    );
  }
  const visibilitySha256 = canonicalSha256(aclPolicy);
  for (const [index, delivery] of deliveries.entries()) {
    const membership = ownerMemberships[index];
    if (!membership || membership.member_id !== delivery.ownerMemberId) {
      throw new Error("locked owner memberships do not match normalized deliveries");
    }
    const entitlementGeneration = Number(membership.entitlement_generation);
    if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
      throw new Error("owner entitlement generation is invalid");
    }
    const feedSequence = await nextFeedSequence(
      client,
      input.prepared.boardId,
      delivery.ownerMemberId
    );
    const feedPayload = PendingActionDeltaSchema.parse({
      schemaVersion: "boardagent.pending-action.v1",
      sequence: feedSequence.toString(10),
      deltaType: "management_question_due",
      objectType: "question",
      objectId: input.prepared.questionId,
      objectVersion: 1,
      entitlementGeneration,
      actionState: "pending",
      safeRefs: { dueAt: input.prepared.dueAt, askerMemberId: context.memberId },
      createdAt: due.rows[0]!.occurred_at
    });
    const canonicalFeed = canonicalJson(feedPayload);
    const noticeSha256 = canonicalSha256({
      noticeType: "management_question_due",
      questionId: input.prepared.questionId,
      dueAt: input.prepared.dueAt,
      recipientMemberId: delivery.ownerMemberId
    });
    await client.query(
      `insert into notices(
         id,organization_id,board_id,notice_type,object_type,object_id,object_version,
         recipient_member_id,content_sha256,feed_sequence,audit_event_id
       ) values ($1,$2,$3,'management_question_due','question',$4,1,$5,$6,$7,$8)`,
      [
        delivery.noticeId,
        organizationId,
        input.prepared.boardId,
        input.prepared.questionId,
        delivery.ownerMemberId,
        Buffer.from(noticeSha256, "hex"),
        feedSequence.toString(10),
        auditEventId
      ]
    );
    await client.query(
      `insert into pending_action_feed(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         action_type,object_type,object_id,object_version,visibility_sha256,
         canonical_payload,payload_sha256,notice_id,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,'management_question_due','question',$7,1,$8,$9,$10,$11,$12)`,
      [
        delivery.feedId,
        organizationId,
        input.prepared.boardId,
        delivery.ownerMemberId,
        membership.entitlement_generation,
        feedSequence.toString(10),
        input.prepared.questionId,
        Buffer.from(visibilitySha256, "hex"),
        Buffer.from(canonicalFeed, "utf8"),
        Buffer.from(canonicalSha256(feedPayload), "hex"),
        delivery.noticeId,
        auditEventId
      ]
    );
  }

  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: 1n,
      event: {
        eventId: auditEventId,
        eventType: "management_question_asked",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "management_question",
        entityId: input.prepared.questionId,
        boardId: input.prepared.boardId,
        origin: "mcp",
        details: {
          initialTurnId,
          assignedOwnerIds: input.prepared.assignedOwnerIds,
          dueAt: input.prepared.dueAt,
          textSha256: input.prepared.textSha256,
          aclPolicySha256: visibilitySha256,
          requestSha256: input.prepared.requestSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("management question audit event was not appended");
  const safeResponse = { questionId: input.prepared.questionId, turnId: initialTurnId };
  const responseSha256 = canonicalSha256(safeResponse);
  await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='management_question',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4
        and operation='ask_management' and idempotency_key=$5`,
    [
      input.prepared.questionId,
      Buffer.from(responseSha256, "hex"),
      context.memberId,
      context.clientId,
      idempotencyKey
    ]
  );
  return {
    replayed: false,
    ...safeResponse,
    responseSha256,
    auditEvent
  };
}

async function lockQuestionForTurn(
  client: PoolClient,
  questionId: string,
  permission: "answer" | "follow_up" | "mutate"
): Promise<LockedQuestionRow> {
  const result = await client.query<LockedQuestionRow>(
    `select organization_id,board_id,asker_member_id,assigned_owner_ids,due_at,
            acl_policy,question_state,current_turn_id,current_ordinal,row_version::text
       from boardagent_lock_question_for_turn($1,$2)`,
    [questionId, permission]
  );
  const question = result.rows[0];
  if (!question || result.rows.length !== 1) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question turn is unavailable"
    );
  }
  if (
    !Number.isSafeInteger(question.current_ordinal) ||
    question.current_ordinal < 1 ||
    BigInt(question.row_version) < 1n ||
    question.acl_policy.schemaVersion !== "boardagent.question-acl.v1" ||
    !Array.isArray(question.acl_policy.grants) ||
    !Array.isArray(question.acl_policy.inheritedDocumentIds)
  ) {
    throw new Error("locked management question has an invalid durable shape");
  }
  return question;
}

async function lockLinkedOpenVotes(
  client: PoolClient,
  questionId: string,
  nextOrdinal: number
): Promise<readonly LinkedVoteRow[]> {
  const result = await client.query<LinkedVoteRow>(
    `select vote_id,vote_row_version::text,vote_state,decision_package_id,
            decision_package_sha256,inclusive_turn_ordinal
       from boardagent_lock_linked_question_votes($1,$2)`,
    [questionId, nextOrdinal]
  );
  return result.rows;
}

function assertSourceUpdateInputs(
  supplied: readonly VoteSourceUpdateAuditInput[],
  linkedVotes: readonly LinkedVoteRow[],
  primaryAuditEventId: string
): void {
  if (
    supplied.length !== linkedVotes.length ||
    supplied.some((input, index) => input.voteId !== linkedVotes[index]?.vote_id) ||
    supplied.some((input) => input.auditEventId === primaryAuditEventId)
  ) {
    throw new QuestionTransactionError(
      "source_update_input_invalid",
      "source-update audit IDs must match every affected linked open vote"
    );
  }
}

async function lockQuestionMemberships(
  client: PoolClient,
  organizationId: string,
  boardId: string,
  memberIds: readonly string[]
): Promise<readonly OwnerMembershipRow[]> {
  const normalizedIds = [...new Set(memberIds)].toSorted();
  const result = await client.query<OwnerMembershipRow>(
    `select locked.member_id,locked.entitlement_generation::text,
            locked.seat_role,locked.has_management_role
       from boardagent_lock_board_members($1,$2,$3::uuid[]) as locked
      order by locked.member_id`,
    [organizationId, boardId, normalizedIds]
  );
  if (
    result.rows.length !== normalizedIds.length ||
    result.rows.some((membership, index) => membership.member_id !== normalizedIds[index])
  ) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question participant membership is unavailable"
    );
  }
  return result.rows;
}

function membershipFor(
  memberships: readonly OwnerMembershipRow[],
  memberId: string
): OwnerMembershipRow {
  const membership = memberships.find(({ member_id }) => member_id === memberId);
  if (!membership) throw new Error("locked question membership disappeared");
  const generation = Number(membership.entitlement_generation);
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new Error("question participant entitlement generation is invalid");
  }
  return membership;
}

async function requireQuestionRecipientsEntitled(
  client: PoolClient,
  boardId: string,
  memberIds: readonly string[],
  documentIds: readonly string[]
): Promise<void> {
  const result = await client.query<{ entitled: boolean }>(
    "select boardagent_question_recipients_entitled($1,$2::uuid[],$3::uuid[]) as entitled",
    [boardId, [...new Set(memberIds)].toSorted(), documentIds]
  );
  if (!result.rows[0]?.entitled) {
    throw new QuestionTransactionError(
      "question_citation_unavailable",
      "question citations are not available to every required participant"
    );
  }
}

async function transactionTime(
  client: PoolClient,
  dueAt: string | null
): Promise<{ readonly dueValid: boolean; readonly occurredAt: string }> {
  const result = await client.query<{ due_valid: boolean; occurred_at: string }>(
    `select ($1::timestamptz is null or $1::timestamptz > transaction_timestamp()) as due_valid,
            to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`,
    [dueAt]
  );
  const row = result.rows[0];
  if (!row) throw new Error("database transaction time is unavailable");
  return { dueValid: row.due_valid, occurredAt: row.occurred_at };
}

async function transitionLinkedVotes(
  client: PoolClient,
  linkedVotes: readonly LinkedVoteRow[]
): Promise<void> {
  for (const vote of linkedVotes) {
    const updated = await client.query(
      `update votes
          set state='source_update_pending',row_version=row_version+1
        where id=$1 and state in ('open','source_update_pending')
          and row_version=$2::bigint`,
      [vote.vote_id, vote.vote_row_version]
    );
    if (updated.rowCount !== 1) {
      throw new QuestionTransactionError(
        "question_turn_unavailable",
        "linked vote changed while appending the management question turn"
      );
    }
  }
}

async function recordSourceUpdateCauses(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly boardId: string;
    readonly questionId: string;
    readonly turnOrdinal: number;
    readonly turnSha256: string;
    readonly linkedVotes: readonly LinkedVoteRow[];
    readonly causeInputs: readonly VoteSourceUpdateAuditInput[];
  }
): Promise<void> {
  for (const [index, vote] of input.linkedVotes.entries()) {
    const cause = input.causeInputs[index];
    if (!cause || cause.voteId !== vote.vote_id) {
      throw new Error("source-update cause order changed inside the question transaction");
    }
    await client.query(
      `insert into vote_source_update_causes(
         id,organization_id,board_id,vote_id,source_class,source_id,source_version,
         source_sha256,trigger_audit_event_id
       ) values ($1,$2,$3,$4,'question_cutoff',$5,$6,$7,$8)`,
      [
        cause.causeId,
        input.organizationId,
        input.boardId,
        vote.vote_id,
        input.questionId,
        input.turnOrdinal,
        Buffer.from(input.turnSha256, "hex"),
        cause.auditEventId
      ]
    );
  }
}

function sourceUpdateAuditInputs(input: {
  readonly organizationId: string;
  readonly boardId: string;
  readonly actorMemberId: string;
  readonly clientId: string;
  readonly tokenJti: string;
  readonly questionId: string;
  readonly turnId: string;
  readonly turnKind: "answer" | "follow_up";
  readonly turnOrdinal: number;
  readonly linkedVotes: readonly LinkedVoteRow[];
  readonly auditInputs: readonly VoteSourceUpdateAuditInput[];
}) {
  return input.linkedVotes.map((vote, index) => ({
    organizationId: input.organizationId,
    objectVersion: BigInt(vote.vote_row_version) + 1n,
    event: {
      eventId: input.auditInputs[index]!.auditEventId,
      eventType: "vote_source_update_pending" as const,
      actorMemberId: input.actorMemberId,
      actorClientId: input.clientId,
      tokenJti: input.tokenJti,
      entityType: "vote",
      entityId: vote.vote_id,
      boardId: input.boardId,
      origin: "mcp",
      details: {
        sourceType: "management_question",
        sourceCauseId: input.auditInputs[index]!.causeId,
        questionId: input.questionId,
        turnId: input.turnId,
        turnKind: input.turnKind,
        turnOrdinal: input.turnOrdinal,
        inclusiveTurnOrdinal: vote.inclusive_turn_ordinal,
        decisionPackageId: vote.decision_package_id,
        decisionPackageSha256: vote.decision_package_sha256.toString("hex")
      },
      schemaVersion: 1 as const
    }
  }));
}

// Filter only declared recusal causes; normal live membership/source ACL checks remain mandatory.
async function unrecusedQuestionMembers(
  client: PoolClient,
  questionId: string,
  memberIds: readonly string[]
): Promise<string[]> {
  const result = await client.query<{ id: string }>(
    `select id from unnest($2::uuid[]) m(id)
    where not boardagent_member_record_recused('question',$1,id) order by id`,
    [questionId, memberIds]
  );
  return result.rows.map((r) => r.id);
}

export async function answerManagementQuestionInTransaction(
  client: PoolClient,
  input: AnswerManagementQuestionInput
): Promise<ManagementQuestionTurnResult> {
  assertPreparedTurn(input.prepared, "answer");
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const turnId = UuidV7Schema.parse(input.turnId);
  const answerRecordId = UuidV7Schema.parse(input.answerRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const askerDelivery = normalizedRecipientDelivery(input.askerDelivery);
  const suppliedSourceAudits = normalizedSourceUpdateAudits(input.sourceUpdateAuditEvents);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question turn is unavailable"
    );
  }

  const citedDocumentIds = await lockVisibleCitations(client, input.prepared.citations, undefined);
  const question = await lockQuestionForTurn(client, input.prepared.questionId, "mutate");
  if (question.organization_id !== organizationId) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question turn is unavailable"
    );
  }
  if (askerDelivery.recipientMemberId !== question.asker_member_id) {
    throw new TypeError("answer delivery must target the management question asker");
  }
  const suppliedOwnerResolutions = normalizedOwnerResolutions(
    input.ownerResolutions,
    question.assigned_owner_ids
  );
  const eligibleOwnerIds = await unrecusedQuestionMembers(
    client,
    input.prepared.questionId,
    question.assigned_owner_ids
  );
  const notifyAsker =
    (await unrecusedQuestionMembers(client, input.prepared.questionId, [question.asker_member_id]))
      .length === 1;
  const inheritedDocumentIds = [
    ...new Set([...question.acl_policy.inheritedDocumentIds, ...citedDocumentIds])
  ].toSorted();
  await requireQuestionRecipientsEntitled(
    client,
    question.board_id,
    [context.memberId, ...(notifyAsker ? [question.asker_member_id] : [])],
    inheritedDocumentIds
  );
  const nextOrdinal = question.current_ordinal + 1;
  const nextQuestionVersion = BigInt(question.row_version) + 1n;
  const lockedLinkedVotes = await lockLinkedOpenVotes(
    client,
    input.prepared.questionId,
    nextOrdinal
  );
  const memberships = await lockQuestionMemberships(client, organizationId, question.board_id, [
    question.asker_member_id,
    ...question.assigned_owner_ids
  ]);
  const authorMembership = membershipFor(memberships, context.memberId);
  if (
    !question.assigned_owner_ids.includes(context.memberId) ||
    authorMembership.seat_role === "observer" ||
    (authorMembership.seat_role !== "management" && !authorMembership.has_management_role)
  ) {
    throw new QuestionTransactionError(
      "question_owner_unavailable",
      "assigned management authority is unavailable"
    );
  }
  const pendingOwnerActions = await client.query<PendingOwnerActionRow>(
    `select feed.id as feed_id,feed.member_id,feed.entitlement_generation::text
       from pending_action_feed as feed
      where feed.board_id=$1 and feed.object_type='question' and feed.object_id=$2
        and feed.action_type='management_question_due' and feed.state='pending'
        and feed.member_id=any($3::uuid[])
      order by feed.member_id
      for update`,
    [question.board_id, input.prepared.questionId, eligibleOwnerIds]
  );
  const idempotency = await acquireTurnIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "answer_management_question",
    key: idempotencyKey,
    requestSha256: input.prepared.requestSha256
  });
  if (idempotency.replayed) {
    return {
      replayed: true,
      questionId: input.prepared.questionId,
      turnId: idempotency.turnId,
      responseSha256: idempotency.responseSha256
    };
  }

  if (!["pending", "overdue"].includes(question.question_state)) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question cannot be answered in its current state"
    );
  }
  const linkedVotes = lockedLinkedVotes;
  assertSourceUpdateInputs(suppliedSourceAudits, linkedVotes, auditEventId);
  // A recusal permanently removes a pending projection. After authority is restored,
  // a fresh answer may complete the still-pending question without reviving that old row.
  // Missing projections without the exact retained recusal tombstone remain an error.
  const removedOwnerIds = (
    await client.query<{ member_id: string }>(
      `
    select distinct f.member_id from pending_action_feed f
    join feed_tombstones t on t.removed_feed_id=f.id and t.member_id=f.member_id
      and t.board_id=f.board_id and t.object_type=f.object_type and t.object_id=f.object_id
      and t.reason_class='recused'
    join audit_events a on a.id=t.audit_event_id and a.event_type='recusal_changed'
    where f.board_id=$1 and f.object_type='question' and f.object_id=$2
      and f.action_type='management_question_due' and f.state='superseded'
      and f.member_id=any($3::uuid[])
      and not exists(select 1 from pending_action_feed newer where newer.board_id=f.board_id
        and newer.member_id=f.member_id and newer.object_type='question' and newer.object_id=f.object_id
        and newer.action_type=f.action_type and newer.feed_sequence>f.feed_sequence)
    order by f.member_id`,
      [question.board_id, input.prepared.questionId, eligibleOwnerIds]
    )
  ).rows.map((r) => r.member_id);
  const pendingIds = pendingOwnerActions.rows.map((r) => r.member_id);
  if (
    eligibleOwnerIds.some((id) => !pendingIds.includes(id) && !removedOwnerIds.includes(id)) ||
    new Set(pendingIds).size !== pendingIds.length
  ) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question owner action projection is unavailable"
    );
  }
  const ownerResolutions = suppliedOwnerResolutions.filter((r) =>
    pendingIds.includes(r.ownerMemberId)
  );

  const time = await transactionTime(client, null);
  const aclPolicy = { ...question.acl_policy, inheritedDocumentIds };
  const visibilitySha256 = canonicalSha256(aclPolicy);
  await client.query(
    `insert into management_question_turns(
       id,organization_id,board_id,question_id,ordinal,turn_kind,author_member_id,
       author_role,canonical_text,text_sha256,citation_snapshot,idempotency_record_id
     ) values ($1,$2,$3,$4,$5,'answer',$6,$7,$8,$9,$10,$11)`,
    [
      turnId,
      organizationId,
      question.board_id,
      input.prepared.questionId,
      nextOrdinal,
      context.memberId,
      authorMembership.seat_role,
      input.prepared.text,
      Buffer.from(input.prepared.textSha256, "hex"),
      canonicalJson(input.prepared.citations),
      idempotencyRecordId
    ]
  );
  await client.query(
    `insert into management_question_answers(
       id,organization_id,question_id,answer_turn_id,management_author_id
     ) values ($1,$2,$3,$4,$5)`,
    [answerRecordId, organizationId, input.prepared.questionId, turnId, context.memberId]
  );
  const updatedQuestion = await client.query<{ next_row_version: string | null }>(
    `select boardagent_apply_question_turn($1,$2::bigint,$3,'answered',$4,$5)::text
              as next_row_version`,
    [input.prepared.questionId, question.row_version, turnId, question.due_at, aclPolicy]
  );
  if (updatedQuestion.rows[0]?.next_row_version !== nextQuestionVersion.toString(10)) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question changed while recording its answer"
    );
  }
  await transitionLinkedVotes(client, linkedVotes);
  await recordSourceUpdateCauses(client, {
    organizationId,
    boardId: question.board_id,
    questionId: input.prepared.questionId,
    turnOrdinal: nextOrdinal,
    turnSha256: input.prepared.textSha256,
    linkedVotes,
    causeInputs: suppliedSourceAudits
  });

  for (const [index, action] of pendingOwnerActions.rows.entries()) {
    const resolution = ownerResolutions[index]!;
    if (action.member_id !== resolution.ownerMemberId) {
      throw new Error("owner action resolution order does not match its locked projection");
    }
    const resolved = await client.query(
      `update pending_action_feed
          set state='resolved',resolved_at=transaction_timestamp()
        where id=$1 and state='pending'`,
      [action.feed_id]
    );
    if (resolved.rowCount !== 1)
      throw new Error("management question owner action was not resolved");
    const sequence = await nextFeedSequence(client, question.board_id, action.member_id);
    const tombstoneSha256 = canonicalSha256({
      schemaVersion: "boardagent.feed-tombstone.v1",
      memberId: action.member_id,
      questionId: input.prepared.questionId,
      removedFeedId: action.feed_id,
      reasonClass: "resolved",
      sequence: sequence.toString(10),
      turnId
    });
    await client.query(
      `insert into feed_tombstones(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,$7,'question',$8,'resolved',$9,$10)`,
      [
        resolution.tombstoneId,
        organizationId,
        question.board_id,
        action.member_id,
        action.entitlement_generation,
        sequence.toString(10),
        action.feed_id,
        input.prepared.questionId,
        Buffer.from(tombstoneSha256, "hex"),
        auditEventId
      ]
    );
  }

  if (notifyAsker) {
    const askerMembership = membershipFor(memberships, question.asker_member_id);
    const askerGeneration = Number(askerMembership.entitlement_generation);
    const askerSequence = await nextFeedSequence(
      client,
      question.board_id,
      question.asker_member_id
    );
    const answerFeedPayload = PendingActionDeltaSchema.parse({
      schemaVersion: "boardagent.pending-action.v1",
      sequence: askerSequence.toString(10),
      deltaType: "notice",
      objectType: "question",
      objectId: input.prepared.questionId,
      objectVersion: Number(nextQuestionVersion),
      entitlementGeneration: askerGeneration,
      actionState: "informational",
      safeRefs: { turnId, textSha256: input.prepared.textSha256 },
      createdAt: time.occurredAt
    });
    const canonicalAnswerFeed = canonicalJson(answerFeedPayload);
    const answerNoticeSha256 = canonicalSha256({
      noticeType: "management_question_answered",
      questionId: input.prepared.questionId,
      recipientMemberId: question.asker_member_id,
      turnId
    });
    await client.query(
      `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,'management_question_answered','question',$4,$5,$6,$7,$8,$9)`,
      [
        askerDelivery.noticeId,
        organizationId,
        question.board_id,
        input.prepared.questionId,
        nextQuestionVersion.toString(10),
        question.asker_member_id,
        Buffer.from(answerNoticeSha256, "hex"),
        askerSequence.toString(10),
        auditEventId
      ]
    );
    await client.query(
      `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,state,notice_id,audit_event_id,resolved_at
     ) values ($1,$2,$3,$4,$5,$6,'management_question_answered','question',$7,$8,$9,
       $10,$11,'resolved',$12,$13,transaction_timestamp())`,
      [
        askerDelivery.feedId,
        organizationId,
        question.board_id,
        question.asker_member_id,
        askerMembership.entitlement_generation,
        askerSequence.toString(10),
        input.prepared.questionId,
        nextQuestionVersion.toString(10),
        Buffer.from(visibilitySha256, "hex"),
        Buffer.from(canonicalAnswerFeed, "utf8"),
        Buffer.from(canonicalSha256(answerFeedPayload), "hex"),
        askerDelivery.noticeId,
        auditEventId
      ]
    );
  }
  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: nextQuestionVersion,
      event: {
        eventId: auditEventId,
        eventType: "management_question_answered",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "management_question",
        entityId: input.prepared.questionId,
        boardId: question.board_id,
        origin: "mcp",
        details: {
          answerRecordId,
          askerNotified: notifyAsker,
          previouslyRecusedOwnerProjections: removedOwnerIds,
          turnId,
          turnOrdinal: nextOrdinal,
          textSha256: input.prepared.textSha256,
          requestSha256: input.prepared.requestSha256,
          aclPolicySha256: visibilitySha256,
          sourceUpdateVoteIds: linkedVotes.map(({ vote_id }) => vote_id)
        },
        schemaVersion: 1
      }
    },
    ...sourceUpdateAuditInputs({
      organizationId,
      boardId: question.board_id,
      actorMemberId: context.memberId,
      clientId: context.clientId,
      tokenJti: context.tokenJti,
      questionId: input.prepared.questionId,
      turnId,
      turnKind: "answer",
      turnOrdinal: nextOrdinal,
      linkedVotes,
      auditInputs: suppliedSourceAudits
    })
  ]);
  const safeResponse = {
    questionId: input.prepared.questionId,
    turnId,
    turnOrdinal: nextOrdinal,
    questionRowVersion: nextQuestionVersion.toString(10)
  };
  const responseSha256 = canonicalSha256(safeResponse);
  await completeTurnIdempotency(client, {
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "answer_management_question",
    key: idempotencyKey,
    turnId,
    responseSha256
  });
  return {
    replayed: false,
    questionId: input.prepared.questionId,
    turnId,
    turnOrdinal: nextOrdinal,
    questionRowVersion: nextQuestionVersion,
    sourceUpdateVoteIds: linkedVotes.map(({ vote_id }) => vote_id),
    responseSha256,
    auditEvents
  };
}

export async function followUpManagementQuestionInTransaction(
  client: PoolClient,
  input: FollowUpManagementQuestionInput
): Promise<ManagementQuestionTurnResult> {
  assertPreparedTurn(input.prepared, "follow_up");
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const turnId = UuidV7Schema.parse(input.turnId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const suppliedSourceAudits = normalizedSourceUpdateAudits(input.sourceUpdateAuditEvents);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question turn is unavailable"
    );
  }

  const citedDocumentIds = await lockVisibleCitations(client, input.prepared.citations, undefined);
  const question = await lockQuestionForTurn(client, input.prepared.questionId, "mutate");
  if (question.organization_id !== organizationId) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question turn is unavailable"
    );
  }
  const suppliedOwnerDeliveries = normalizedDeliveries(
    input.ownerDeliveries,
    question.assigned_owner_ids
  );
  const eligibleOwnerIds = await unrecusedQuestionMembers(
    client,
    input.prepared.questionId,
    question.assigned_owner_ids
  );
  if (eligibleOwnerIds.length === 0)
    throw new QuestionTransactionError(
      "question_owner_unavailable",
      "no assigned management owner can receive this follow-up"
    );
  const ownerDeliveries = suppliedOwnerDeliveries.filter((r) =>
    eligibleOwnerIds.includes(r.ownerMemberId)
  );
  const ownersValid = await client.query<{ valid: boolean }>(
    "select boardagent_question_owners_valid($1,$2::uuid[]) as valid",
    [question.board_id, eligibleOwnerIds]
  );
  if (!ownersValid.rows[0]?.valid) {
    throw new QuestionTransactionError(
      "question_owner_unavailable",
      "one or more assigned management owners are unavailable"
    );
  }
  const inheritedDocumentIds = [
    ...new Set([...question.acl_policy.inheritedDocumentIds, ...citedDocumentIds])
  ].toSorted();
  await requireQuestionRecipientsEntitled(
    client,
    question.board_id,
    [context.memberId, ...eligibleOwnerIds],
    inheritedDocumentIds
  );
  const nextOrdinal = question.current_ordinal + 1;
  const nextQuestionVersion = BigInt(question.row_version) + 1n;
  const lockedLinkedVotes = await lockLinkedOpenVotes(
    client,
    input.prepared.questionId,
    nextOrdinal
  );
  const memberships = await lockQuestionMemberships(client, organizationId, question.board_id, [
    question.asker_member_id,
    context.memberId,
    ...question.assigned_owner_ids
  ]);
  const authorMembership = membershipFor(memberships, context.memberId);
  if (authorMembership.seat_role !== "voting_member" && authorMembership.seat_role !== "observer") {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question follow-up authority is unavailable"
    );
  }
  const existingOwnerActions = await client.query<{ id: string }>(
    `select id from pending_action_feed
      where board_id=$1 and object_type='question' and object_id=$2
        and action_type='management_question_due' and state='pending'
      order by member_id
      for update`,
    [question.board_id, input.prepared.questionId]
  );
  const idempotency = await acquireTurnIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "follow_up_management_question",
    key: idempotencyKey,
    requestSha256: input.prepared.requestSha256
  });
  if (idempotency.replayed) {
    return {
      replayed: true,
      questionId: input.prepared.questionId,
      turnId: idempotency.turnId,
      responseSha256: idempotency.responseSha256
    };
  }

  if (question.question_state !== "answered") {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question requires a recorded answer before follow-up"
    );
  }
  const time = await transactionTime(client, input.prepared.dueAt);
  if (!time.dueValid || input.prepared.dueAt === null) {
    throw new QuestionTransactionError(
      "question_due_invalid",
      "management question follow-up due time must be in the future"
    );
  }
  const linkedVotes = lockedLinkedVotes;
  assertSourceUpdateInputs(suppliedSourceAudits, linkedVotes, auditEventId);
  if (existingOwnerActions.rowCount !== 0) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "answered question still has unresolved management actions"
    );
  }

  const aclPolicy = { ...question.acl_policy, inheritedDocumentIds };
  const visibilitySha256 = canonicalSha256(aclPolicy);
  await client.query(
    `insert into management_question_turns(
       id,organization_id,board_id,question_id,ordinal,turn_kind,author_member_id,
       author_role,canonical_text,text_sha256,citation_snapshot,idempotency_record_id
     ) values ($1,$2,$3,$4,$5,'follow_up',$6,$7,$8,$9,$10,$11)`,
    [
      turnId,
      organizationId,
      question.board_id,
      input.prepared.questionId,
      nextOrdinal,
      context.memberId,
      authorMembership.seat_role,
      input.prepared.text,
      Buffer.from(input.prepared.textSha256, "hex"),
      canonicalJson(input.prepared.citations),
      idempotencyRecordId
    ]
  );
  const updatedQuestion = await client.query<{ next_row_version: string | null }>(
    `select boardagent_apply_question_turn($1,$2::bigint,$3,'pending',$4,$5)::text
              as next_row_version`,
    [input.prepared.questionId, question.row_version, turnId, input.prepared.dueAt, aclPolicy]
  );
  if (updatedQuestion.rows[0]?.next_row_version !== nextQuestionVersion.toString(10)) {
    throw new QuestionTransactionError(
      "question_turn_unavailable",
      "management question changed while recording its follow-up"
    );
  }
  await transitionLinkedVotes(client, linkedVotes);
  await recordSourceUpdateCauses(client, {
    organizationId,
    boardId: question.board_id,
    questionId: input.prepared.questionId,
    turnOrdinal: nextOrdinal,
    turnSha256: input.prepared.textSha256,
    linkedVotes,
    causeInputs: suppliedSourceAudits
  });

  for (const delivery of ownerDeliveries) {
    const ownerMembership = membershipFor(memberships, delivery.ownerMemberId);
    const entitlementGeneration = Number(ownerMembership.entitlement_generation);
    const sequence = await nextFeedSequence(client, question.board_id, delivery.ownerMemberId);
    const feedPayload = PendingActionDeltaSchema.parse({
      schemaVersion: "boardagent.pending-action.v1",
      sequence: sequence.toString(10),
      deltaType: "management_question_due",
      objectType: "question",
      objectId: input.prepared.questionId,
      objectVersion: Number(nextQuestionVersion),
      entitlementGeneration,
      actionState: "pending",
      safeRefs: { dueAt: input.prepared.dueAt, askerMemberId: context.memberId, turnId },
      createdAt: time.occurredAt
    });
    const canonicalFeed = canonicalJson(feedPayload);
    const noticeSha256 = canonicalSha256({
      noticeType: "management_question_due",
      questionId: input.prepared.questionId,
      dueAt: input.prepared.dueAt,
      recipientMemberId: delivery.ownerMemberId,
      turnId
    });
    await client.query(
      `insert into notices(
         id,organization_id,board_id,notice_type,object_type,object_id,object_version,
         recipient_member_id,content_sha256,feed_sequence,audit_event_id
       ) values ($1,$2,$3,'management_question_due','question',$4,$5,$6,$7,$8,$9)`,
      [
        delivery.noticeId,
        organizationId,
        question.board_id,
        input.prepared.questionId,
        nextQuestionVersion.toString(10),
        delivery.ownerMemberId,
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
       ) values ($1,$2,$3,$4,$5,$6,'management_question_due','question',$7,$8,$9,$10,$11,$12,$13)`,
      [
        delivery.feedId,
        organizationId,
        question.board_id,
        delivery.ownerMemberId,
        ownerMembership.entitlement_generation,
        sequence.toString(10),
        input.prepared.questionId,
        nextQuestionVersion.toString(10),
        Buffer.from(visibilitySha256, "hex"),
        Buffer.from(canonicalFeed, "utf8"),
        Buffer.from(canonicalSha256(feedPayload), "hex"),
        delivery.noticeId,
        auditEventId
      ]
    );
  }

  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: nextQuestionVersion,
      event: {
        eventId: auditEventId,
        eventType: "management_question_followed_up",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "management_question",
        entityId: input.prepared.questionId,
        boardId: question.board_id,
        origin: "mcp",
        details: {
          turnId,
          turnOrdinal: nextOrdinal,
          dueAt: input.prepared.dueAt,
          textSha256: input.prepared.textSha256,
          requestSha256: input.prepared.requestSha256,
          aclPolicySha256: visibilitySha256,
          sourceUpdateVoteIds: linkedVotes.map(({ vote_id }) => vote_id)
        },
        schemaVersion: 1
      }
    },
    ...sourceUpdateAuditInputs({
      organizationId,
      boardId: question.board_id,
      actorMemberId: context.memberId,
      clientId: context.clientId,
      tokenJti: context.tokenJti,
      questionId: input.prepared.questionId,
      turnId,
      turnKind: "follow_up",
      turnOrdinal: nextOrdinal,
      linkedVotes,
      auditInputs: suppliedSourceAudits
    })
  ]);
  const safeResponse = {
    questionId: input.prepared.questionId,
    turnId,
    turnOrdinal: nextOrdinal,
    questionRowVersion: nextQuestionVersion.toString(10)
  };
  const responseSha256 = canonicalSha256(safeResponse);
  await completeTurnIdempotency(client, {
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "follow_up_management_question",
    key: idempotencyKey,
    turnId,
    responseSha256
  });
  return {
    replayed: false,
    questionId: input.prepared.questionId,
    turnId,
    turnOrdinal: nextOrdinal,
    questionRowVersion: nextQuestionVersion,
    sourceUpdateVoteIds: linkedVotes.map(({ vote_id }) => vote_id),
    responseSha256,
    auditEvents
  };
}
