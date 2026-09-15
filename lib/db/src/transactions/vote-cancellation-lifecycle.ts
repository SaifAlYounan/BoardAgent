import type { PoolClient } from "pg";

import {
  PendingActionDeltaSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";

import type { AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

export class VoteCancellationLifecycleTransactionError extends Error {
  public constructor(
    public readonly code: "vote_cancellation_unavailable" | "vote_cancellation_invalid",
    message: string
  ) {
    super(message);
    this.name = "VoteCancellationLifecycleTransactionError";
  }
}

export interface VoteCancellationLifecycleAction {
  readonly voteId: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

export interface PreparedVoteCancellationLifecycleAction {
  readonly actionCode: "cancel_vote";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.vote-cancellation.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string | null;
  readonly voteId: string;
  readonly voteTitle: string;
  readonly voteState: "draft" | "open" | "source_update_pending";
  readonly resolutionVersionId: string | null;
  readonly resolutionText: string | null;
  readonly resolutionSha256: string | null;
  readonly decisionPackage: JsonValue | null;
  readonly deadlineAt: string | null;
  readonly reason: string;
  readonly recipientMemberIds: readonly string[];
}

export interface VoteCancellationLifecycleStageInput {
  readonly action: VoteCancellationLifecycleAction;
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

export interface StagedVoteCancellationLifecycleAction extends StagedAction {
  readonly actionCode: "cancel_vote";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
}

export interface VoteCancellationLifecycleConfirmationInput {
  readonly action: VoteCancellationLifecycleAction;
  readonly confirmation: ConfirmStagedActionInput;
  readonly newId: () => string;
}

export interface VoteCancellationLifecycleResult {
  readonly voteId: string;
  readonly state: "cancelled";
  readonly rowVersion: string;
  readonly cancelledAt: string;
  readonly packageSha256: string | null;
  readonly retainedActs: true;
  readonly noticeCount: number;
}

interface VoteRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_id: string;
  readonly vote_title: string;
  readonly vote_state: "draft" | "open" | "source_update_pending" | string;
  readonly row_version: string;
  readonly resolution_version_id: string | null;
  readonly resolution_text: string | null;
  readonly resolution_sha256: Buffer | null;
  readonly package_sha256: Buffer | null;
  readonly decision_package: JsonValue | null;
  readonly deadline_at: string | null;
  readonly actor_ready: boolean;
}

interface RecipientRow {
  readonly member_id: string;
  readonly entitlement_generation: string;
}

interface PreparedRecipient {
  readonly memberId: string;
  readonly entitlementGeneration: number;
}

interface PreparedInternal extends PreparedVoteCancellationLifecycleAction {
  readonly organizationId: string;
  readonly rowVersion: bigint;
  readonly context: ActiveRequestContext;
  readonly recipients: readonly PreparedRecipient[];
}

function unavailable(message = "vote cancellation is unavailable"): never {
  throw new VoteCancellationLifecycleTransactionError("vote_cancellation_unavailable", message);
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
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

async function prepareInternal(
  client: PoolClient,
  action: VoteCancellationLifecycleAction
): Promise<PreparedInternal> {
  const context = await readRequestContext(client);
  const voteId = UuidV7Schema.parse(action.voteId);
  const reason = canonicalText(action.reason);
  idempotencyKey(action.idempotencyKey);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("vote cancellation reason must contain 1 through 65536 characters");
  }
  const rootResult = await client.query<VoteRootRow>(
    `select vote.organization_id,vote.board_id,vote.id as vote_id,
            vote.title as vote_title,vote.state as vote_state,vote.row_version::text,
            resolution.id as resolution_version_id,resolution.canonical_text as resolution_text,
            resolution.canonical_sha256 as resolution_sha256,
            package.package_sha256,
            case when package.id is null then null
                 else convert_from(package.canonical_payload,'UTF8')::jsonb end
              as decision_package,
            case when vote.deadline_at is null then null
                 else to_char(vote.deadline_at at time zone 'UTC',
                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end as deadline_at,
            boardagent_vote_actor_ready(vote.board_id) as actor_ready
       from votes as vote
       left join resolution_versions as resolution on resolution.id=vote.current_resolution_version_id
       left join decision_packages as package
         on package.id=vote.current_decision_package_id and package.vote_id=vote.id
      where vote.id=$1
        and vote.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(vote.board_id)
        and not boardagent_member_vote_recused(vote.id,
          boardagent_context_uuid('boardagent.member_id'))
      for update of vote`,
    [voteId]
  );
  const root = rootResult.rows[0];
  if (
    !root ||
    rootResult.rows.length !== 1 ||
    root.organization_id !== context.organizationId ||
    !root.actor_ready ||
    !["draft", "open", "source_update_pending"].includes(root.vote_state)
  ) {
    unavailable();
  }
  const visibility = await client.query<{ recused: boolean }>(
    `select boardagent_member_vote_recused($1,
       boardagent_context_uuid('boardagent.member_id')) as recused`,
    [voteId]
  );
  if (visibility.rows[0]?.recused !== false) unavailable();
  if (root.decision_package !== null) canonicalJson(root.decision_package);
  const recipientResult =
    root.vote_state === "draft"
      ? { rows: [] as RecipientRow[] }
      : await client.query<RecipientRow>(
          `select member_id,entitlement_generation::text
             from boardagent_lock_replacement_recipients($1)`,
          [voteId]
        );
  const recipients = recipientResult.rows.map((row) => {
    const entitlementGeneration = Number(row.entitlement_generation);
    if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
      throw new Error("vote cancellation recipient entitlement generation is invalid");
    }
    return { memberId: UuidV7Schema.parse(row.member_id), entitlementGeneration };
  });
  const rowVersion = BigInt(root.row_version);
  if (rowVersion < 1n || rowVersion > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("vote cancellation row version is outside the presentation range");
  }
  const packageSha256 =
    root.package_sha256 === null
      ? null
      : Sha256HexSchema.parse(root.package_sha256.toString("hex"));
  const resolutionSha256 =
    root.resolution_sha256 === null
      ? null
      : Sha256HexSchema.parse(root.resolution_sha256.toString("hex"));
  const canonicalPayload: JsonValue = {
    schemaVersion: "boardagent.vote-cancellation.v1",
    boardId: root.board_id,
    voteId,
    title: root.vote_title,
    voteState: root.vote_state,
    rowVersion: Number(rowVersion),
    resolutionVersionId: root.resolution_version_id,
    resolutionSha256,
    packageSha256,
    deadlineAt: root.deadline_at,
    reason,
    recipientMemberIds: recipients.map(({ memberId }) => memberId)
  };
  return {
    actionCode: "cancel_vote",
    boardId: root.board_id,
    targetType: "vote",
    targetId: voteId,
    canonicalSchema: "boardagent.vote-cancellation.v1",
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    packageSha256,
    voteId,
    voteTitle: root.vote_title,
    voteState: root.vote_state as PreparedVoteCancellationLifecycleAction["voteState"],
    resolutionVersionId: root.resolution_version_id,
    resolutionText: root.resolution_text,
    resolutionSha256,
    decisionPackage: root.decision_package,
    deadlineAt: root.deadline_at,
    reason,
    recipientMemberIds: recipients.map(({ memberId }) => memberId),
    organizationId: root.organization_id,
    rowVersion,
    context,
    recipients
  };
}

function publicView(prepared: PreparedInternal): PreparedVoteCancellationLifecycleAction {
  const {
    organizationId: _organizationId,
    rowVersion: _rowVersion,
    context: _context,
    recipients: _recipients,
    ...view
  } = prepared;
  return view;
}

export async function prepareVoteCancellationLifecycleActionInTransaction(
  client: PoolClient,
  action: VoteCancellationLifecycleAction
): Promise<PreparedVoteCancellationLifecycleAction> {
  return publicView(await prepareInternal(client, action));
}

export async function stageVoteCancellationLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteCancellationLifecycleStageInput
): Promise<StagedVoteCancellationLifecycleAction> {
  const prepared = await prepareInternal(client, input.action);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => {
      // Preparation locked the exact vote and every cancellation recipient.
    }
  );
  return {
    ...staged,
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetType: prepared.targetType,
    targetId: prepared.targetId
  };
}

async function insertCancellationNotice(
  client: PoolClient,
  prepared: PreparedInternal,
  recipient: PreparedRecipient,
  rowVersion: bigint,
  cancelledAt: string,
  input: { readonly noticeId: string; readonly feedId: string; readonly auditEventId: string }
): Promise<AuditAppendInput> {
  const sequence = await nextFeedSequence(client, prepared.boardId, recipient.memberId);
  const safeRefs = {
    voteId: prepared.voteId,
    packageSha256: prepared.packageSha256,
    cancellationSha256: prepared.payloadSha256
  } as const;
  const delta = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: sequence.toString(10),
    deltaType: "notice",
    objectType: "vote",
    objectId: prepared.voteId,
    objectVersion: Number(rowVersion),
    entitlementGeneration: recipient.entitlementGeneration,
    actionState: "informational",
    safeRefs,
    createdAt: cancelledAt
  });
  const noticeSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-cancellation-notice.v1",
    recipientMemberId: recipient.memberId,
    entitlementGeneration: recipient.entitlementGeneration,
    voteId: prepared.voteId,
    packageSha256: prepared.packageSha256,
    cancellationSha256: prepared.payloadSha256
  });
  const visibilitySha256 = canonicalSha256({
    boardId: prepared.boardId,
    voteId: prepared.voteId,
    recipientMemberId: recipient.memberId,
    entitlementGeneration: recipient.entitlementGeneration
  });
  await client.query(
    `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,'vote_cancelled','vote',$4,$5,$6,$7,$8,$9)`,
    [
      input.noticeId,
      prepared.organizationId,
      prepared.boardId,
      prepared.voteId,
      rowVersion.toString(10),
      recipient.memberId,
      Buffer.from(noticeSha256, "hex"),
      sequence.toString(10),
      input.auditEventId
    ]
  );
  const canonicalPayload = canonicalJson(delta);
  await client.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,state,notice_id,audit_event_id,resolved_at
     ) values ($1,$2,$3,$4,$5,$6,'vote_cancelled','vote',$7,$8,$9,$10,$11,
       'resolved',$12,$13,$14)`,
    [
      input.feedId,
      prepared.organizationId,
      prepared.boardId,
      recipient.memberId,
      recipient.entitlementGeneration,
      sequence.toString(10),
      prepared.voteId,
      rowVersion.toString(10),
      Buffer.from(visibilitySha256, "hex"),
      Buffer.from(canonicalPayload, "utf8"),
      Buffer.from(canonicalSha256(delta), "hex"),
      input.noticeId,
      input.auditEventId,
      cancelledAt
    ]
  );
  return {
    organizationId: prepared.organizationId,
    objectVersion: rowVersion,
    event: {
      eventId: input.auditEventId,
      eventType: "notice_delivered",
      actorMemberId: prepared.context.memberId,
      actorClientId: prepared.context.clientId,
      tokenJti: prepared.context.tokenJti,
      entityType: "vote",
      entityId: prepared.voteId,
      boardId: prepared.boardId,
      origin: "mcp",
      details: {
        meaning: "committed_recipient_feed_handoff",
        noticeType: "vote_cancelled",
        recipientMemberId: recipient.memberId,
        feedSequence: sequence.toString(10)
      },
      schemaVersion: 1
    }
  };
}

async function actCancellation(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string,
  newId: () => string
): Promise<{
  readonly value: VoteCancellationLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  const changed = await client.query<{ row_version: string; cancelled_at: string }>(
    `select row_version::text,cancelled_at
       from boardagent_apply_vote_cancellation($1,$2::bigint,$3,$4,$5)`,
    [
      prepared.voteId,
      prepared.rowVersion.toString(10),
      consentRecordId,
      Buffer.from(prepared.payloadSha256, "hex"),
      prepared.packageSha256 === null ? null : Buffer.from(prepared.packageSha256, "hex")
    ]
  );
  const row = changed.rows[0];
  if (!row || changed.rows.length !== 1) throw new Error("vote cancellation result is unavailable");
  const rowVersion = BigInt(row.row_version);
  const auditEventId = UuidV7Schema.parse(newId());
  const audits: AuditAppendInput[] = [
    {
      organizationId: prepared.organizationId,
      consentRecordId,
      objectVersion: rowVersion,
      event: {
        eventId: auditEventId,
        eventType: "vote_cancelled",
        actorMemberId: prepared.context.memberId,
        actorClientId: prepared.context.clientId,
        tokenJti: prepared.context.tokenJti,
        entityType: "vote",
        entityId: prepared.voteId,
        boardId: prepared.boardId,
        origin: "mcp",
        details: {
          reason: prepared.reason,
          reasonSha256: sha256Hex(prepared.reason),
          packageSha256: prepared.packageSha256,
          priorState: prepared.voteState,
          actsRetainedNonOutcomeBearing: true,
          recipientMemberIds: prepared.recipientMemberIds
        },
        schemaVersion: 1
      }
    }
  ];
  for (const recipient of prepared.recipients) {
    audits.push(
      await insertCancellationNotice(client, prepared, recipient, rowVersion, row.cancelled_at, {
        noticeId: UuidV7Schema.parse(newId()),
        feedId: UuidV7Schema.parse(newId()),
        auditEventId: UuidV7Schema.parse(newId())
      })
    );
  }
  return {
    value: {
      voteId: prepared.voteId,
      state: "cancelled",
      rowVersion: rowVersion.toString(10),
      cancelledAt: row.cancelled_at,
      packageSha256: prepared.packageSha256,
      retainedActs: true,
      noticeCount: prepared.recipients.length
    },
    auditEvents: audits
  };
}

export async function confirmVoteCancellationLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteCancellationLifecycleConfirmationInput
): Promise<StagedActionResolution<VoteCancellationLifecycleResult>> {
  let prepared: PreparedInternal | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareInternal(requestClient, input.action);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("vote cancellation preparation is unavailable");
      return actCancellation(requestClient, prepared, consentRecordId, input.newId);
    },
    { appendConsentBeforeAct: true, exposeConfirmedProjectionToAct: true }
  );
}
