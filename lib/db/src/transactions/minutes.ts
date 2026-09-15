import type { PoolClient } from "pg";

import {
  MinutesCommentSchema,
  MinutesRedlineSchema,
  PendingActionDeltaSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  type MinutesComment,
  type MinutesRedline
} from "@boardagent/contracts";
import { applyExactMinutesRedline } from "@boardagent/domain";
import type { AuditEvent } from "@boardagent/audit";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const MAX_IDEMPOTENCY_KEY = 256;

export type MinutesReviewPayload = MinutesComment | MinutesRedline;

export interface MinutesReviewDelivery {
  readonly recipientMemberId: string;
  readonly noticeId: string;
  readonly feedId: string;
}

export interface SubmitMinutesReviewInput {
  readonly reviewItemId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly payload: unknown;
  readonly deliveries?: readonly MinutesReviewDelivery[];
  readonly deliveryFactory?: (
    recipientMemberId: string
  ) => Omit<MinutesReviewDelivery, "recipientMemberId">;
  readonly auditEventId: string;
}

export interface SubmitMinutesReviewResult {
  readonly replayed: boolean;
  readonly reviewItemId: string;
  readonly responseSha256: string;
  readonly auditEvent?: AuditEvent;
}

export interface WithdrawMinutesCommentInput {
  readonly withdrawalId: string;
  readonly minutesId?: string;
  readonly reviewItemId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface WithdrawMinutesCommentResult {
  readonly replayed: boolean;
  readonly withdrawalId: string;
  readonly reviewItemId: string;
  readonly responseSha256: string;
  readonly auditEvent?: AuditEvent;
}

export class MinutesTransactionError extends Error {
  public constructor(
    public readonly code:
      | "minutes_review_unavailable"
      | "minutes_review_stale"
      | "minutes_comment_withdrawal_unavailable"
      | "minutes_review_delivery_invalid"
      | "idempotency_conflict",
    message: string
  ) {
    super(message);
    this.name = "MinutesTransactionError";
  }
}

interface LockedMinutesReviewRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly minutes_id: string;
  readonly minutes_state: string;
  readonly row_version: string;
  readonly version_id: string;
  readonly version: number;
  readonly canonical_text: string;
  readonly canonical_sha256: Buffer;
  readonly author_seat_role: "voting_member" | "management" | "observer";
}

interface SecretaryRow {
  readonly member_id: string;
  readonly entitlement_generation: string;
}

interface IdempotencyRow {
  readonly id: string;
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface CompletedIdempotencyRow extends IdempotencyRow {
  readonly safe_response_id: string;
  readonly safe_response_sha256: Buffer;
}

function exactIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > MAX_IDEMPOTENCY_KEY) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function parseReviewPayload(input: unknown): MinutesReviewPayload {
  const comment = MinutesCommentSchema.safeParse(input);
  return comment.success ? comment.data : MinutesRedlineSchema.parse(input);
}

async function lockAuthorizedMinutes(
  client: PoolClient,
  minutesId: string
): Promise<LockedMinutesReviewRow> {
  const result = await client.query<LockedMinutesReviewRow>(
    `select minutes.organization_id,minutes.board_id,minutes.id as minutes_id,
            minutes.state as minutes_state,minutes.row_version::text,
            version.id as version_id,version.version,version.canonical_text,
            version.canonical_sha256,membership.seat_role as author_seat_role
       from minutes
       join minutes_versions as version on version.id=minutes.current_version_id
       join board_memberships as membership
         on membership.organization_id=minutes.organization_id
        and membership.board_id=minutes.board_id
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
      where minutes.id=$1
        and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(minutes.board_id)
        and actor.state='active' and membership.state='active'
        and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
        and oauth_client.state='active' and token.revoked_at is null
        and token.expires_at>transaction_timestamp() and 'minutes:act'=any(token.scope_set)
        and exists (
          select 1 from onboarding_attestations as attestation
           where attestation.organization_id=actor.organization_id
             and attestation.member_id=actor.id and attestation.board_id=minutes.board_id
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
                  and (support.board_id=minutes.board_id or support.board_id is null)
                  and support.effective_at<=transaction_timestamp()
                order by (support.board_id=minutes.board_id) desc,
                         support.effective_at desc,support.version desc,support.id desc limit 1
             )
        )
      for update of minutes`,
    [minutesId]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new MinutesTransactionError(
      "minutes_review_unavailable",
      "minutes review package is unavailable"
    );
  }
  return row;
}

async function lockSecretaries(
  client: PoolClient,
  organizationId: string,
  boardId: string,
  minutesId: string
): Promise<readonly SecretaryRow[]> {
  const result = await client.query<SecretaryRow>(
    `select member_id,entitlement_generation::text
       from boardagent_lock_minutes_review_secretaries($1,$2)
      where not boardagent_member_record_recused('minutes',$3,member_id)`,
    [organizationId, boardId, minutesId]
  );
  if (result.rows.length === 0) {
    throw new MinutesTransactionError(
      "minutes_review_delivery_invalid",
      "minutes review requires at least one active board secretary"
    );
  }
  return result.rows;
}

function normalizeDeliveries(
  input: readonly MinutesReviewDelivery[],
  secretaries: readonly SecretaryRow[]
): readonly MinutesReviewDelivery[] {
  const normalized = input
    .map((delivery) => ({
      recipientMemberId: UuidV7Schema.parse(delivery.recipientMemberId),
      noticeId: UuidV7Schema.parse(delivery.noticeId),
      feedId: UuidV7Schema.parse(delivery.feedId)
    }))
    .toSorted((left, right) => left.recipientMemberId.localeCompare(right.recipientMemberId));
  if (
    normalized.length !== secretaries.length ||
    normalized.some(
      (delivery, index) => delivery.recipientMemberId !== secretaries[index]?.member_id
    ) ||
    new Set(normalized.map(({ noticeId }) => noticeId)).size !== normalized.length ||
    new Set(normalized.map(({ feedId }) => feedId)).size !== normalized.length
  ) {
    throw new MinutesTransactionError(
      "minutes_review_delivery_invalid",
      "delivery IDs must cover every active board secretary exactly once"
    );
  }
  return normalized;
}

async function lockCompletedIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  operation: string,
  idempotencyKey: string
): Promise<CompletedIdempotencyRow | undefined> {
  const existing = await client.query<IdempotencyRow>(
    `select id,request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      for update`,
    [actorMemberId, clientId, operation, idempotencyKey]
  );
  const row = existing.rows[0];
  if (!row) return undefined;
  if (row.state !== "succeeded" || !row.safe_response_id || !row.safe_response_sha256) {
    throw new MinutesTransactionError(
      "idempotency_conflict",
      "idempotency record is not a completed safe response"
    );
  }
  return {
    ...row,
    safe_response_id: row.safe_response_id,
    safe_response_sha256: row.safe_response_sha256
  };
}

function assertReplayRequest(row: CompletedIdempotencyRow, requestSha256: string): void {
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new MinutesTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for different minutes review bytes"
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

export async function submitMinutesReviewInTransaction(
  client: PoolClient,
  rawInput: SubmitMinutesReviewInput
): Promise<SubmitMinutesReviewResult> {
  const payload = parseReviewPayload(rawInput.payload);
  const minutesId = UuidV7Schema.parse(payload.minutesId);
  const reviewItemId = UuidV7Schema.parse(rawInput.reviewItemId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const idempotencyKey = exactIdempotencyKey(rawInput.idempotencyKey);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const canonicalPayload = canonicalJson(payload);
  const payloadSha256 = canonicalSha256(payload);
  const operation =
    payload.schemaVersion === "boardagent.minutes-comment.v1"
      ? "comment_minutes"
      : "propose_minutes_redline";
  const requestSha256 = canonicalSha256({ operation, payload });
  const context = await readRequestContext(client);
  // Completed effects still require all current identity/onboarding/RLS checks,
  // but no longer require the package to remain open for new review submissions.
  const minutes = await lockAuthorizedMinutes(client, minutesId);
  const replay = await lockCompletedIdempotency(
    client,
    context.memberId,
    context.clientId,
    operation,
    idempotencyKey
  );
  if (replay) {
    assertReplayRequest(replay, requestSha256);
    const persisted = await client.query<{ canonical_payload: Buffer; payload_sha256: Buffer }>(
      `select canonical_payload,payload_sha256 from minutes_review_items
        where id=$1 and idempotency_record_id=$2 and minutes_id=$3
          and organization_id=$4 and board_id=$5 and author_member_id=$6`,
      [
        replay.safe_response_id,
        replay.id,
        minutesId,
        minutes.organization_id,
        minutes.board_id,
        context.memberId
      ]
    );
    const prior = persisted.rows[0];
    if (
      replay.safe_response_type !== "minutes_review_item" ||
      persisted.rows.length !== 1 ||
      !prior ||
      !prior.canonical_payload.equals(Buffer.from(canonicalPayload, "utf8")) ||
      !safeHashEqual(prior.payload_sha256.toString("hex"), payloadSha256) ||
      !safeHashEqual(
        replay.safe_response_sha256.toString("hex"),
        canonicalSha256({ reviewItemId: replay.safe_response_id })
      )
    ) {
      throw new MinutesTransactionError(
        "idempotency_conflict",
        "completed minutes review evidence is unavailable"
      );
    }
    return {
      replayed: true,
      reviewItemId: replay.safe_response_id,
      responseSha256: replay.safe_response_sha256.toString("hex")
    };
  }
  if (minutes.minutes_state !== "published_review") {
    throw new MinutesTransactionError(
      "minutes_review_unavailable",
      "published minutes review package is unavailable"
    );
  }
  if (
    payload.baseVersion !== minutes.version ||
    !safeHashEqual(payload.baseSha256, minutes.canonical_sha256.toString("hex"))
  ) {
    throw new MinutesTransactionError(
      "minutes_review_stale",
      "minutes review must bind the current published version and hash"
    );
  }
  if (payload.schemaVersion === "boardagent.minutes-redline.v1") {
    applyExactMinutesRedline(minutes.canonical_text, payload);
  }
  const secretaries = await lockSecretaries(
    client,
    minutes.organization_id,
    minutes.board_id,
    minutesId
  );
  if ((rawInput.deliveries === undefined) === (rawInput.deliveryFactory === undefined)) {
    throw new MinutesTransactionError(
      "minutes_review_delivery_invalid",
      "minutes review requires exactly one delivery source"
    );
  }
  const proposedDeliveries =
    rawInput.deliveries ??
    secretaries.map(({ member_id: recipientMemberId }) => ({
      recipientMemberId,
      ...rawInput.deliveryFactory!(recipientMemberId)
    }));
  const deliveries = normalizeDeliveries(proposedDeliveries, secretaries);
  await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'in_progress',transaction_timestamp()+interval '24 hours')`,
    [
      idempotencyRecordId,
      context.organizationId,
      context.memberId,
      context.clientId,
      operation,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  const exactAnchor =
    payload.schemaVersion === "boardagent.minutes-redline.v1"
      ? payload.anchor
      : { kind: "whole_package" };
  await client.query(
    `insert into minutes_review_items(
       id,organization_id,board_id,minutes_id,item_kind,schema_version,author_member_id,
       author_seat_role,base_version_id,base_sha256,exact_anchor,canonical_payload,
       payload_sha256,idempotency_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      reviewItemId,
      minutes.organization_id,
      minutes.board_id,
      minutesId,
      payload.schemaVersion === "boardagent.minutes-comment.v1" ? "comment" : "redline",
      payload.schemaVersion,
      context.memberId,
      minutes.author_seat_role,
      minutes.version_id,
      minutes.canonical_sha256,
      JSON.stringify(exactAnchor),
      Buffer.from(canonicalPayload, "utf8"),
      Buffer.from(payloadSha256, "hex"),
      idempotencyRecordId
    ]
  );
  const occurred = await client.query<{ occurred_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
  );
  const occurredAt = occurred.rows[0]?.occurred_at;
  if (!occurredAt) throw new Error("minutes review transaction time is unavailable");
  for (const [index, delivery] of deliveries.entries()) {
    const secretary = secretaries[index]!;
    const entitlementGeneration = Number(secretary.entitlement_generation);
    if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
      throw new Error("secretary entitlement generation is invalid");
    }
    const feedSequence = await nextFeedSequence(
      client,
      minutes.board_id,
      delivery.recipientMemberId
    );
    const feedPayload = PendingActionDeltaSchema.parse({
      schemaVersion: "boardagent.pending-action.v1",
      sequence: feedSequence.toString(10),
      deltaType: "action_required",
      objectType: "minutes",
      objectId: minutesId,
      objectVersion: Number(minutes.row_version),
      entitlementGeneration,
      actionState: "pending",
      safeRefs: { reviewItemId, authorMemberId: context.memberId },
      createdAt: occurredAt
    });
    const noticeSha256 = canonicalSha256({
      noticeType: "minutes_review_submitted",
      minutesId,
      reviewItemId,
      recipientMemberId: delivery.recipientMemberId
    });
    await client.query(
      `insert into notices(
         id,organization_id,board_id,notice_type,object_type,object_id,object_version,
         recipient_member_id,content_sha256,feed_sequence,audit_event_id
       ) values ($1,$2,$3,'minutes_review_submitted','minutes_review_item',$4,1,$5,$6,$7,$8)`,
      [
        delivery.noticeId,
        minutes.organization_id,
        minutes.board_id,
        reviewItemId,
        delivery.recipientMemberId,
        Buffer.from(noticeSha256, "hex"),
        feedSequence.toString(10),
        auditEventId
      ]
    );
    const canonicalFeed = canonicalJson(feedPayload);
    await client.query(
      `insert into pending_action_feed(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         action_type,object_type,object_id,object_version,visibility_sha256,
         canonical_payload,payload_sha256,notice_id,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,'minutes_review_submitted','minutes',$7,$8,$9,$10,$11,$12,$13)`,
      [
        delivery.feedId,
        minutes.organization_id,
        minutes.board_id,
        delivery.recipientMemberId,
        secretary.entitlement_generation,
        feedSequence.toString(10),
        minutesId,
        minutes.row_version,
        Buffer.from(
          canonicalSha256({ minutesId, reviewItemId, recipient: delivery.recipientMemberId }),
          "hex"
        ),
        Buffer.from(canonicalFeed, "utf8"),
        Buffer.from(canonicalSha256(feedPayload), "hex"),
        delivery.noticeId,
        auditEventId
      ]
    );
  }
  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: minutes.organization_id,
      objectVersion: BigInt(minutes.row_version),
      event: {
        eventId: auditEventId,
        eventType:
          payload.schemaVersion === "boardagent.minutes-comment.v1"
            ? "minutes_commented"
            : "minutes_redline_proposed",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "minutes_review_item",
        entityId: reviewItemId,
        boardId: minutes.board_id,
        origin: "mcp",
        details: {
          minutesId,
          baseVersionId: minutes.version_id,
          baseVersion: minutes.version,
          baseSha256: payload.baseSha256,
          payloadSha256,
          itemKind:
            payload.schemaVersion === "boardagent.minutes-comment.v1" ? "comment" : "redline"
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("minutes review audit event was not appended");
  const responseSha256 = canonicalSha256({ reviewItemId });
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='minutes_review_item',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [reviewItemId, Buffer.from(responseSha256, "hex"), idempotencyRecordId]
  );
  if (completed.rowCount !== 1) throw new Error("minutes review idempotency completion failed");
  return { replayed: false, reviewItemId, responseSha256, auditEvent };
}

interface ReviewItemForWithdrawal {
  readonly minutes_id: string;
  readonly item_kind: string;
  readonly author_member_id: string;
  readonly base_version_id: string;
  readonly payload_sha256: Buffer;
  readonly already_withdrawn: boolean;
  readonly already_dispositioned: boolean;
}

export async function withdrawMinutesCommentInTransaction(
  client: PoolClient,
  rawInput: WithdrawMinutesCommentInput
): Promise<WithdrawMinutesCommentResult> {
  const withdrawalId = UuidV7Schema.parse(rawInput.withdrawalId);
  const reviewItemId = UuidV7Schema.parse(rawInput.reviewItemId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const idempotencyKey = exactIdempotencyKey(rawInput.idempotencyKey);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const expectedMinutesId =
    rawInput.minutesId === undefined ? undefined : UuidV7Schema.parse(rawInput.minutesId);
  const context = await readRequestContext(client);
  const itemLookup = await client.query<{ minutes_id: string }>(
    "select minutes_id from minutes_review_items where id=$1",
    [reviewItemId]
  );
  const minutesId = itemLookup.rows[0]?.minutes_id;
  if (!minutesId || (expectedMinutesId !== undefined && minutesId !== expectedMinutesId)) {
    throw new MinutesTransactionError(
      "minutes_comment_withdrawal_unavailable",
      "minutes comment is unavailable"
    );
  }
  const minutes = await lockAuthorizedMinutes(client, minutesId);
  const itemResult = await client.query<ReviewItemForWithdrawal>(
    `select item.minutes_id,item.item_kind,item.author_member_id,item.base_version_id,
            item.payload_sha256,
            exists(select 1 from minutes_review_withdrawals where review_item_id=item.id)
              as already_withdrawn,
            exists(select 1 from minutes_review_dispositions where review_item_id=item.id)
              as already_dispositioned
       from minutes_review_items as item where item.id=$1 and item.minutes_id=$2`,
    [reviewItemId, minutesId]
  );
  const item = itemResult.rows[0];
  if (!item || item.item_kind !== "comment" || item.author_member_id !== context.memberId) {
    throw new MinutesTransactionError(
      "minutes_comment_withdrawal_unavailable",
      "only the exact author may withdraw a pending minutes comment"
    );
  }
  const replay = await lockCompletedIdempotency(
    client,
    context.memberId,
    context.clientId,
    "withdraw_minutes_comment",
    idempotencyKey
  );
  if (replay) {
    const persisted = await client.query<{ current_minutes_version_id: string }>(
      `select withdrawal.current_minutes_version_id
         from minutes_review_withdrawals as withdrawal
         join minutes_versions as version on version.id=withdrawal.current_minutes_version_id
        where withdrawal.id=$1 and withdrawal.idempotency_record_id=$2
          and withdrawal.review_item_id=$3 and withdrawal.author_member_id=$4
          and withdrawal.organization_id=$5 and version.minutes_id=$6`,
      [
        replay.safe_response_id,
        replay.id,
        reviewItemId,
        context.memberId,
        minutes.organization_id,
        minutesId
      ]
    );
    const prior = persisted.rows[0];
    if (
      replay.safe_response_type !== "minutes_review_withdrawal" ||
      persisted.rows.length !== 1 ||
      !prior ||
      !safeHashEqual(
        replay.safe_response_sha256.toString("hex"),
        canonicalSha256({ withdrawalId: replay.safe_response_id, reviewItemId })
      )
    ) {
      throw new MinutesTransactionError(
        "idempotency_conflict",
        "completed minutes withdrawal evidence is unavailable"
      );
    }
    // Existing withdrawals bind the version current at the original action. Use
    // that immutable version to verify their original digest after later edits.
    assertReplayRequest(
      replay,
      canonicalSha256({
        operation: "withdraw_minutes_comment",
        reviewItemId,
        currentMinutesVersionId: prior.current_minutes_version_id
      })
    );
    return {
      replayed: true,
      withdrawalId: replay.safe_response_id,
      reviewItemId,
      responseSha256: replay.safe_response_sha256.toString("hex")
    };
  }
  if (
    minutes.minutes_state !== "published_review" ||
    item.already_withdrawn ||
    item.already_dispositioned
  ) {
    throw new MinutesTransactionError(
      "minutes_comment_withdrawal_unavailable",
      "only the exact author may withdraw a pending current-package comment"
    );
  }
  const requestSha256 = canonicalSha256({
    operation: "withdraw_minutes_comment",
    reviewItemId,
    currentMinutesVersionId: minutes.version_id
  });
  await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'withdraw_minutes_comment',$5,$6,'in_progress',
               transaction_timestamp()+interval '24 hours')`,
    [
      idempotencyRecordId,
      context.organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  await client.query(
    `insert into minutes_review_withdrawals(
       id,organization_id,review_item_id,author_member_id,current_minutes_version_id,
       idempotency_record_id
     ) values ($1,$2,$3,$4,$5,$6)`,
    [
      withdrawalId,
      minutes.organization_id,
      reviewItemId,
      context.memberId,
      minutes.version_id,
      idempotencyRecordId
    ]
  );
  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: minutes.organization_id,
      objectVersion: BigInt(minutes.row_version),
      event: {
        eventId: auditEventId,
        eventType: "minutes_review_withdrawn",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "minutes_review_withdrawal",
        entityId: withdrawalId,
        boardId: minutes.board_id,
        origin: "mcp",
        details: {
          minutesId,
          reviewItemId,
          currentMinutesVersionId: minutes.version_id,
          commentPayloadSha256: item.payload_sha256.toString("hex")
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("minutes withdrawal audit event was not appended");
  const responseSha256 = canonicalSha256({ withdrawalId, reviewItemId });
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='minutes_review_withdrawal',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [withdrawalId, Buffer.from(responseSha256, "hex"), idempotencyRecordId]
  );
  if (completed.rowCount !== 1) {
    throw new Error("minutes withdrawal idempotency completion failed");
  }
  return { replayed: false, withdrawalId, reviewItemId, responseSha256, auditEvent };
}
