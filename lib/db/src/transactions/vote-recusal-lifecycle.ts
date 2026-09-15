import type { PoolClient } from "pg";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  type JsonValue
} from "@boardagent/contracts";
import { voteRecusalConsentHash } from "@boardagent/domain";

import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import {
  manageVoteRecusalInTransaction,
  lockVoteRecusalRecipientsInTransaction,
  type ManageVoteRecusalResult,
  type VoteRecusalDeliveryInput,
  type VoteRecusalTombstoneInput
} from "./recusals.js";
import { readRequestContext } from "./request-context.js";
import type {
  VoteBallotReplacementInput,
  VoteProxyReplacementInput,
  VoteStageReplacementInput
} from "./votes.js";

export class VoteRecusalLifecycleTransactionError extends Error {
  public constructor(
    public readonly code: "vote_recusal_unavailable" | "vote_recusal_invalid",
    message: string
  ) {
    super(message);
    this.name = "VoteRecusalLifecycleTransactionError";
  }
}

export interface VoteRecusalLifecycleAction {
  readonly boardId: string;
  readonly voteId: string;
  readonly memberId: string;
  readonly operation: "add" | "lift";
  readonly reason: string;
  readonly idempotencyKey: string;
}

export interface PreparedVoteRecusalLifecycleAction {
  readonly actionCode: "manage_recusal";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.vote-recusal-consent.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
  readonly voteId: string;
  readonly voteTitle: string;
  readonly resolutionText: string;
  readonly resolutionSha256: string;
  readonly decisionPackage: JsonValue;
  readonly memberId: string;
  readonly memberDisplayName: string;
  readonly state: "excluded" | "lifted";
  readonly reason: string;
  readonly affectedStageCount: number;
  readonly affectedProxyCount: number;
  readonly affectedBallotCount: number;
  readonly removedPendingFeedCount: number;
  readonly deliveryRecipientCount: number;
}

export interface VoteRecusalLifecycleStageInput {
  readonly action: VoteRecusalLifecycleAction;
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

export interface StagedVoteRecusalLifecycleAction extends StagedAction {
  readonly actionCode: "manage_recusal";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
}

export interface VoteRecusalLifecycleConfirmationInput {
  readonly action: VoteRecusalLifecycleAction;
  readonly confirmation: ConfirmStagedActionInput;
  readonly newId: () => string;
}

interface VoteRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_id: string;
  readonly vote_title: string;
  readonly vote_state: string;
  readonly package_sha256: Buffer;
  readonly decision_package: JsonValue;
  readonly resolution_text: string;
  readonly resolution_sha256: Buffer;
  readonly member_display_name: string;
  readonly current_exclusion_state: "excluded" | "lifted" | null;
  readonly actor_ready: boolean;
  readonly board_recused: boolean;
}

interface IdRow {
  readonly id: string;
}

interface ProxyRow {
  readonly id: string;
}

interface BallotRow {
  readonly id: string;
}

export interface PreparedVoteRecusalInternal extends PreparedVoteRecusalLifecycleAction {
  readonly effectiveState: "excluded" | "lifted";
  readonly organizationId: string;
  readonly affectedStageIds: readonly string[];
  readonly affectedProxyIds: readonly string[];
  readonly affectedBallotIds: readonly string[];
  readonly removedPendingFeedIds: readonly string[];
  readonly deliveryRecipientIds: readonly string[];
}

function unavailable(message = "vote recusal is unavailable"): never {
  throw new VoteRecusalLifecycleTransactionError("vote_recusal_unavailable", message);
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

async function prepareInternal(
  client: PoolClient,
  action: VoteRecusalLifecycleAction,
  excludedStageId: string | null = null,
  boardCause = false
): Promise<PreparedVoteRecusalInternal> {
  const context = await readRequestContext(client);
  const boardId = UuidV7Schema.parse(action.boardId);
  const voteId = UuidV7Schema.parse(action.voteId);
  const memberId = UuidV7Schema.parse(action.memberId);
  const stageId = excludedStageId === null ? null : UuidV7Schema.parse(excludedStageId);
  const state = action.operation === "add" ? "excluded" : "lifted";
  const reason = canonicalText(action.reason);
  idempotencyKey(action.idempotencyKey);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("recusal reason must contain 1 through 65536 characters");
  }
  const rootResult = await client.query<VoteRootRow>(
    `select vote.organization_id,vote.board_id,vote.id as vote_id,
            vote.title as vote_title,vote.state as vote_state,
            package.package_sha256,
            convert_from(package.canonical_payload,'UTF8')::jsonb as decision_package,
            resolution.canonical_text as resolution_text,
            resolution.canonical_sha256 as resolution_sha256,
            target.display_name as member_display_name,
            current_exclusion.state as current_exclusion_state,
            boardagent_member_board_recused(vote.board_id,$2) as board_recused,
            boardagent_vote_actor_ready(vote.board_id) as actor_ready
       from votes as vote
       join decision_packages as package
         on package.id=vote.current_decision_package_id and package.vote_id=vote.id
       join resolution_versions as resolution on resolution.id=vote.current_resolution_version_id
       join vote_electorate as electorate
         on electorate.vote_id=vote.id and electorate.member_id=$2
       join members as target
         on target.organization_id=vote.organization_id and target.id=electorate.member_id
       join board_memberships as membership
         on membership.organization_id=vote.organization_id
        and membership.board_id=vote.board_id and membership.member_id=electorate.member_id
       left join lateral (
         select coalesce(exclusion.cause_requested_state,exclusion.state) as state
           from vote_exclusions as exclusion
          where exclusion.vote_id=vote.id and exclusion.member_id=electorate.member_id
            and exclusion.source_board_exclusion_id is null
          order by exclusion.version desc,exclusion.id desc limit 1
       ) as current_exclusion on true
      where vote.id=$1
        and vote.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(vote.board_id)
        and target.state='active' and membership.state='active'
        and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
      for update of vote`,
    [voteId, memberId]
  );
  const root = rootResult.rows[0];
  if (
    !root ||
    rootResult.rows.length !== 1 ||
    root.organization_id !== context.organizationId ||
    root.board_id !== boardId ||
    !root.actor_ready ||
    !["open", "source_update_pending"].includes(root.vote_state)
  ) {
    unavailable();
  }
  if (!boardCause) {
    const visibility = await client.query<{ allowed: boolean }>(
      "select not boardagent_member_vote_recused($1,$2) as allowed",
      [voteId, context.memberId]
    );
    if (visibility.rows[0]?.allowed !== true) unavailable();
  }
  if (
    !boardCause &&
    ((state === "excluded" && root.current_exclusion_state === "excluded") ||
      (state === "lifted" && root.current_exclusion_state !== "excluded"))
  ) {
    throw new VoteRecusalLifecycleTransactionError(
      "vote_recusal_invalid",
      "requested recusal transition is not available"
    );
  }
  canonicalJson(root.decision_package);
  const stages = await client.query<IdRow>(
    `select id from action_stages
      where organization_id=$1 and board_id=$2 and target_type='vote' and target_id=$3
        and state='active' and (actor_member_id=$4 or acting_for_member_id=$4)
        and ($5::uuid is null or id<>$5)
      order by id for update`,
    [root.organization_id, boardId, voteId, memberId, stageId]
  );
  const proxies = await client.query<ProxyRow>(
    `select proxy.id
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.organization_id=$1 and proxy.board_id=$2 and proxy.vote_id=$3
        and (proxy.principal_member_id=$4 or proxy.holder_member_id=$4)
        and revocation.id is null
      order by proxy.id`,
    [root.organization_id, boardId, voteId, memberId]
  );
  const ballots = await client.query<BallotRow>(
    `select ballot.id
       from ballots as ballot
       left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
      where ballot.organization_id=$1 and ballot.board_id=$2 and ballot.vote_id=$3
        and (ballot.principal_member_id=$4
          or (ballot.ballot_source='proxy' and ballot.caster_member_id=$4))
        and disposition.id is null
      order by ballot.id`,
    [root.organization_id, boardId, voteId, memberId]
  );
  const feeds = await client.query<IdRow>(
    `select id from pending_action_feed
      where organization_id=$1 and board_id=$2 and member_id=$3
        and object_type='vote' and object_id=$4 and state='pending'
      order by id for update`,
    [root.organization_id, boardId, memberId, voteId]
  );
  const effectiveState =
    state === "excluded" ||
    (boardCause ? root.current_exclusion_state === "excluded" : root.board_recused)
      ? "excluded"
      : "lifted";
  const deliveryRecipientIds = (
    await lockVoteRecusalRecipientsInTransaction(
      client,
      voteId,
      memberId,
      effectiveState,
      boardCause && state === "lifted"
    )
  ).map((r) => r.member_id);
  const packageSha256 = Sha256HexSchema.parse(root.package_sha256.toString("hex"));
  const canonicalPayload: JsonValue = {
    schemaVersion: "boardagent.vote-recusal-consent.v1",
    voteId,
    memberId,
    state,
    reason,
    packageSha256
  };
  const payloadSha256 = canonicalSha256(canonicalPayload);
  if (
    payloadSha256 !== voteRecusalConsentHash({ voteId, memberId, state, reason, packageSha256 })
  ) {
    throw new Error("vote recusal consent payload construction drifted");
  }
  return {
    actionCode: "manage_recusal",
    boardId,
    targetType: "vote",
    targetId: voteId,
    canonicalSchema: "boardagent.vote-recusal-consent.v1",
    canonicalPayload,
    payloadSha256,
    packageSha256,
    voteId,
    voteTitle: root.vote_title,
    resolutionText: root.resolution_text,
    resolutionSha256: Sha256HexSchema.parse(root.resolution_sha256.toString("hex")),
    decisionPackage: root.decision_package,
    memberId,
    memberDisplayName: root.member_display_name,
    state,
    reason,
    affectedStageCount: stages.rows.length,
    affectedProxyCount: proxies.rows.length,
    affectedBallotCount: ballots.rows.length,
    removedPendingFeedCount: feeds.rows.length,
    deliveryRecipientCount: deliveryRecipientIds.length,
    effectiveState,
    organizationId: root.organization_id,
    affectedStageIds: stages.rows.map(({ id }) => id),
    affectedProxyIds: proxies.rows.map(({ id }) => id),
    affectedBallotIds: ballots.rows.map(({ id }) => id),
    removedPendingFeedIds: feeds.rows.map(({ id }) => id),
    deliveryRecipientIds
  };
}

export async function prepareBoardVoteRecusalInTransaction(
  client: PoolClient,
  action: VoteRecusalLifecycleAction,
  excludedStageId: string
): Promise<PreparedVoteRecusalInternal> {
  return prepareInternal(client, action, excludedStageId, true);
}

function publicView(prepared: PreparedVoteRecusalInternal): PreparedVoteRecusalLifecycleAction {
  const {
    effectiveState: _effectiveState,
    organizationId: _organizationId,
    affectedStageIds: _affectedStageIds,
    affectedProxyIds: _affectedProxyIds,
    affectedBallotIds: _affectedBallotIds,
    removedPendingFeedIds: _removedPendingFeedIds,
    deliveryRecipientIds: _deliveryRecipientIds,
    ...view
  } = prepared;
  return view;
}

export async function prepareVoteRecusalLifecycleActionInTransaction(
  client: PoolClient,
  action: VoteRecusalLifecycleAction
): Promise<PreparedVoteRecusalLifecycleAction> {
  return publicView(await prepareInternal(client, action));
}

export async function stageVoteRecusalLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteRecusalLifecycleStageInput
): Promise<StagedVoteRecusalLifecycleAction> {
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
      // Preparation locked the vote, affected projections and exact delivery recipients.
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

export function generatedVoteRecusalDispositions(
  prepared: PreparedVoteRecusalInternal,
  newId: () => string
): {
  readonly exclusionId: string;
  readonly idempotencyRecordId: string;
  readonly auditEventId: string;
  readonly stageDispositions: readonly VoteStageReplacementInput[];
  readonly proxyDispositions: readonly VoteProxyReplacementInput[];
  readonly ballotDispositions: readonly VoteBallotReplacementInput[];
  readonly feedTombstones: readonly VoteRecusalTombstoneInput[];
  readonly deliveries: readonly VoteRecusalDeliveryInput[];
} {
  const id = () => UuidV7Schema.parse(newId());
  return {
    exclusionId: id(),
    idempotencyRecordId: id(),
    auditEventId: id(),
    stageDispositions: prepared.affectedStageIds.map((stageId) => ({
      stageId,
      auditEventId: id()
    })),
    proxyDispositions: prepared.affectedProxyIds.map((proxyGrantId) => ({
      proxyGrantId,
      proxyRevocationId: id(),
      auditEventId: id()
    })),
    ballotDispositions: prepared.affectedBallotIds.map((ballotId) => ({
      ballotId,
      ballotDispositionId: id(),
      auditEventId: id()
    })),
    feedTombstones: prepared.removedPendingFeedIds.map((removedFeedId) => ({
      removedFeedId,
      tombstoneId: id()
    })),
    deliveries: prepared.deliveryRecipientIds.map((memberId) => ({
      memberId,
      noticeId: id(),
      feedId: id(),
      noticeAuditEventId: id()
    }))
  };
}

export async function confirmVoteRecusalLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteRecusalLifecycleConfirmationInput
): Promise<StagedActionResolution<ManageVoteRecusalResult>> {
  let prepared: PreparedVoteRecusalInternal | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareInternal(requestClient, input.action, input.confirmation.stageId);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("vote recusal preparation is unavailable");
      const generated = generatedVoteRecusalDispositions(prepared, input.newId);
      const result = await manageVoteRecusalInTransaction(requestClient, {
        organizationId: prepared.organizationId,
        voteId: prepared.voteId,
        memberId: prepared.memberId,
        decisionPackageSha256: prepared.packageSha256,
        state: prepared.state,
        exclusionId: generated.exclusionId,
        reason: prepared.reason,
        consentRecordId,
        idempotencyRecordId: generated.idempotencyRecordId,
        idempotencyKey: input.action.idempotencyKey,
        stageDispositions: generated.stageDispositions,
        proxyDispositions: generated.proxyDispositions,
        ballotDispositions: generated.ballotDispositions,
        feedTombstones: generated.feedTombstones,
        deliveries: generated.deliveries,
        auditEventId: generated.auditEventId
      });
      return {
        value: result,
        auditEvents: [],
        preappendedAuditSequences: result.replayed
          ? []
          : result.auditEvents.map(({ sequence }) => sequence)
      };
    },
    { appendConsentBeforeAct: true, exposeConfirmedProjectionToAct: true }
  );
}
