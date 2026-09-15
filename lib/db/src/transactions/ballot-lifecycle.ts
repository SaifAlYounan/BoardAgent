import type { PoolClient } from "pg";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  type JsonValue
} from "@boardagent/contracts";
import {
  ballotConsentHash,
  proxyGrantConsentHash,
  proxyRevokeConsentHash,
  type BallotChoice,
  type PrincipalSupersessionRule
} from "@boardagent/domain";

import {
  castBallotInTransaction,
  grantProxyInTransaction,
  revokeProxyInTransaction,
  type CastBallotResult,
  type GrantProxyResult,
  type RevokeProxyResult
} from "./ballots.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

export class BallotLifecycleTransactionError extends Error {
  public constructor(
    public readonly code: "ballot_action_unavailable" | "ballot_action_invalid",
    message: string
  ) {
    super(message);
    this.name = "BallotLifecycleTransactionError";
  }
}

export type BallotLifecycleAction =
  | {
      readonly kind: "grant_proxy";
      readonly voteId: string;
      readonly holderMemberId: string;
      readonly idempotencyKey: string;
    }
  | {
      readonly kind: "revoke_proxy";
      readonly proxyGrantId: string;
      readonly reason: string;
      readonly idempotencyKey: string;
    }
  | {
      readonly kind: "ballot";
      readonly voteId: string;
      readonly principalMemberId: string | null;
      readonly choice: BallotChoice;
      readonly statement: string | null;
      readonly idempotencyKey: string;
    };

export interface PreparedBallotLifecycleAction {
  readonly actionCode: "grant_proxy" | "revoke_proxy" | "stage_ballot";
  readonly boardId: string;
  readonly targetType: "vote" | "proxy_grant";
  readonly targetId: string;
  readonly actingForMemberId: string | null;
  readonly canonicalSchema: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
  readonly voteId: string;
  readonly voteTitle: string;
  readonly resolutionText: string;
  readonly resolutionSha256: string;
  readonly decisionPackage: JsonValue;
  readonly principalMemberId: string;
  readonly principalDisplayName: string;
  readonly actorMemberId: string;
  readonly actorDisplayName: string;
  readonly holderMemberId: string | null;
  readonly holderDisplayName: string | null;
  readonly proxyGrantId: string | null;
}

export interface BallotLifecycleStageInput {
  readonly action: BallotLifecycleAction;
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

export interface BallotLifecycleGeneratedIds {
  readonly recordId: string;
  readonly supersessionDispositionId: string;
  readonly supersessionAuditEventId: string;
  readonly idempotencyRecordId: string;
  readonly auditEventId: string;
}

export interface BallotLifecycleConfirmationInput {
  readonly action: BallotLifecycleAction;
  readonly generatedIds: BallotLifecycleGeneratedIds;
  readonly confirmation: ConfirmStagedActionInput;
}

export interface StagedBallotLifecycleAction extends StagedAction {
  readonly actionCode: PreparedBallotLifecycleAction["actionCode"];
  readonly boardId: string;
  readonly targetType: PreparedBallotLifecycleAction["targetType"];
  readonly targetId: string;
  readonly actingForMemberId: string | null;
}

export type BallotLifecycleResult =
  | { readonly kind: "grant_proxy"; readonly result: GrantProxyResult }
  | { readonly kind: "revoke_proxy"; readonly result: RevokeProxyResult }
  | { readonly kind: "ballot"; readonly result: CastBallotResult };

interface VoteRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_id: string;
  readonly vote_title: string;
  readonly vote_state: string;
  readonly decision_package_id: string;
  readonly package_sha256: Buffer;
  readonly decision_package: JsonValue;
  readonly proxy_policy: PrincipalSupersessionRule;
  readonly deadline_open: boolean;
  readonly actor_ready: boolean;
  readonly resolution_text: string;
  readonly resolution_sha256: Buffer;
}

interface ParticipantRow {
  readonly member_id: string;
  readonly voting_weight: string;
  readonly ready: boolean;
}

interface ProxyGrantRow {
  readonly id: string;
  readonly vote_id: string;
  readonly principal_member_id: string;
  readonly holder_member_id: string;
  readonly policy: PrincipalSupersessionRule;
  readonly active: boolean;
}

interface ActiveBallotRow {
  readonly id: string;
  readonly ballot_source: "own" | "proxy";
}

type PreparedDetails =
  | {
      readonly kind: "grant_proxy";
      readonly policy: PrincipalSupersessionRule;
      readonly expiresAt: null;
    }
  | {
      readonly kind: "revoke_proxy";
      readonly grant: ProxyGrantRow;
      readonly reason: string;
    }
  | {
      readonly kind: "ballot";
      readonly choice: BallotChoice;
      readonly statement: string | null;
      readonly proxyGrantId: string | null;
    };

interface PreparedInternal extends PreparedBallotLifecycleAction {
  readonly action: BallotLifecycleAction;
  readonly context: ActiveRequestContext;
  readonly organizationId: string;
  readonly details: PreparedDetails;
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function unavailable(message = "ballot or proxy action is unavailable"): never {
  throw new BallotLifecycleTransactionError("ballot_action_unavailable", message);
}

async function lockVoteRoot(
  client: PoolClient,
  voteId: string,
  scope: "proxy:manage" | "vote:act"
): Promise<VoteRootRow> {
  const result = await client.query<VoteRootRow>(
    `select vote.organization_id,vote.board_id,vote.id as vote_id,
            vote.title as vote_title,vote.state as vote_state,
            package.id as decision_package_id,package.package_sha256,
            convert_from(package.canonical_payload,'UTF8')::jsonb as decision_package,
            rule.proxy_policy,
            vote.deadline_at>transaction_timestamp() as deadline_open,
            boardagent_vote_actor_ready_for_scope(vote.board_id,$2) as actor_ready,
            resolution.canonical_text as resolution_text,
            resolution.canonical_sha256 as resolution_sha256
       from votes as vote
       join decision_packages as package
         on package.id=vote.current_decision_package_id and package.vote_id=vote.id
       join approval_rules as rule on rule.id=vote.approval_rule_id
       join resolution_versions as resolution on resolution.id=vote.current_resolution_version_id
      where vote.id=$1
        and vote.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(vote.board_id)
      for update of vote`,
    [voteId, scope]
  );
  const root = result.rows[0];
  if (!root || result.rows.length !== 1 || !root.actor_ready) unavailable();
  canonicalJson(root.decision_package);
  return root;
}

async function participants(
  client: PoolClient,
  root: VoteRootRow,
  memberIds: readonly string[]
): Promise<readonly ParticipantRow[]> {
  const ids = [...new Set(memberIds)].toSorted();
  const result = await client.query<ParticipantRow>(
    `select locked.member_id,electorate.voting_weight::text,
            (locked.active_now and locked.seat_role='voting_member'
             and locked.voting_weight>0) as ready
       from boardagent_lock_board_members($1,$2,$4::uuid[]) as locked
       join vote_electorate as electorate
         on electorate.organization_id=$1 and electorate.board_id=$2
        and electorate.member_id=locked.member_id
      where electorate.vote_id=$3 and electorate.member_id=any($4::uuid[])
      order by locked.member_id`,
    [root.organization_id, root.board_id, root.vote_id, ids]
  );
  return result.rows;
}

async function excluded(
  client: PoolClient,
  voteId: string,
  memberIds: readonly string[]
): Promise<ReadonlySet<string>> {
  const result = await client.query<{ member_id: string; state: "excluded" | "lifted" }>(
    `select distinct on (member_id) member_id,state
       from vote_exclusions
      where vote_id=$1 and member_id=any($2::uuid[])
      order by member_id,version desc,id desc`,
    [voteId, [...new Set(memberIds)]]
  );
  return new Set(
    result.rows.filter(({ state }) => state === "excluded").map(({ member_id }) => member_id)
  );
}

async function displayNames(
  client: PoolClient,
  organizationId: string,
  memberIds: readonly string[]
): Promise<ReadonlyMap<string, string>> {
  const ids = [...new Set(memberIds)];
  const result = await client.query<{ id: string; display_name: string }>(
    `select id,display_name from members
      where organization_id=$1 and id=any($2::uuid[]) order by id`,
    [organizationId, ids]
  );
  if (result.rows.length !== ids.length) unavailable();
  return new Map(result.rows.map((row) => [row.id, row.display_name]));
}

async function activeRelationships(client: PoolClient, voteId: string): Promise<ProxyGrantRow[]> {
  const result = await client.query<ProxyGrantRow>(
    `select proxy.id,proxy.vote_id,proxy.principal_member_id,proxy.holder_member_id,
            proxy.policy,(revocation.id is null and
              (proxy.expires_at is null or proxy.expires_at>transaction_timestamp())) as active
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.vote_id=$1 order by proxy.id`,
    [voteId]
  );
  return result.rows;
}

function commonPrepared(
  root: VoteRootRow,
  context: ActiveRequestContext,
  names: ReadonlyMap<string, string>,
  input: {
    readonly actionCode: PreparedBallotLifecycleAction["actionCode"];
    readonly targetType: PreparedBallotLifecycleAction["targetType"];
    readonly targetId: string;
    readonly actingForMemberId: string | null;
    readonly canonicalSchema: string;
    readonly canonicalPayload: JsonValue;
    readonly principalMemberId: string;
    readonly holderMemberId: string | null;
    readonly proxyGrantId: string | null;
  }
): PreparedBallotLifecycleAction {
  const packageSha256 = Sha256HexSchema.parse(root.package_sha256.toString("hex"));
  const payloadSha256 = canonicalSha256(input.canonicalPayload);
  return {
    actionCode: input.actionCode,
    boardId: root.board_id,
    targetType: input.targetType,
    targetId: input.targetId,
    actingForMemberId: input.actingForMemberId,
    canonicalSchema: input.canonicalSchema,
    canonicalPayload: input.canonicalPayload,
    payloadSha256,
    packageSha256,
    voteId: root.vote_id,
    voteTitle: root.vote_title,
    resolutionText: root.resolution_text,
    resolutionSha256: root.resolution_sha256.toString("hex"),
    decisionPackage: root.decision_package,
    principalMemberId: input.principalMemberId,
    principalDisplayName: names.get(input.principalMemberId) ?? "unavailable",
    actorMemberId: context.memberId,
    actorDisplayName: names.get(context.memberId) ?? "unavailable",
    holderMemberId: input.holderMemberId,
    holderDisplayName:
      input.holderMemberId === null ? null : (names.get(input.holderMemberId) ?? "unavailable"),
    proxyGrantId: input.proxyGrantId
  };
}

async function prepareGrant(
  client: PoolClient,
  action: Extract<BallotLifecycleAction, { readonly kind: "grant_proxy" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const voteId = UuidV7Schema.parse(action.voteId);
  const holderMemberId = UuidV7Schema.parse(action.holderMemberId);
  idempotencyKey(action.idempotencyKey);
  if (holderMemberId === context.memberId) {
    throw new BallotLifecycleTransactionError(
      "ballot_action_invalid",
      "proxy holder must differ from principal"
    );
  }
  const root = await lockVoteRoot(client, voteId, "proxy:manage");
  if (root.vote_state !== "open" || !root.deadline_open) unavailable();
  const involved = [context.memberId, holderMemberId];
  const eligible = await participants(client, root, involved);
  if (eligible.length !== 2 || eligible.some(({ ready }) => !ready)) unavailable();
  if ((await excluded(client, voteId, involved)).size !== 0) unavailable();
  const relationships = await activeRelationships(client, voteId);
  if (relationships.some(({ principal_member_id }) => principal_member_id === context.memberId)) {
    unavailable("principal already has immutable proxy history for this vote");
  }
  const active = relationships.filter(({ active: isActive }) => isActive);
  if (
    active.some(({ principal_member_id }) => principal_member_id === holderMemberId) ||
    active.some(({ holder_member_id }) => holder_member_id === context.memberId)
  ) {
    unavailable("proxy chain or cycle is forbidden");
  }
  const names = await displayNames(client, root.organization_id, involved);
  const packageSha256 = root.package_sha256.toString("hex");
  const payload: JsonValue = {
    schemaVersion: "boardagent.proxy-grant-consent.v1",
    voteId,
    principalMemberId: context.memberId,
    holderMemberId,
    policy: root.proxy_policy,
    expiresAt: null,
    packageSha256
  };
  if (
    !Sha256HexSchema.safeParse(
      proxyGrantConsentHash({
        voteId,
        principalMemberId: context.memberId,
        holderMemberId,
        policy: root.proxy_policy,
        expiresAt: null,
        packageSha256
      })
    ).success ||
    canonicalSha256(payload) !==
      proxyGrantConsentHash({
        voteId,
        principalMemberId: context.memberId,
        holderMemberId,
        policy: root.proxy_policy,
        expiresAt: null,
        packageSha256
      })
  ) {
    throw new Error("proxy grant consent payload construction drifted");
  }
  return {
    ...commonPrepared(root, context, names, {
      actionCode: "grant_proxy",
      targetType: "vote",
      targetId: voteId,
      actingForMemberId: null,
      canonicalSchema: "boardagent.proxy-grant-consent.v1",
      canonicalPayload: payload,
      principalMemberId: context.memberId,
      holderMemberId,
      proxyGrantId: null
    }),
    action,
    context,
    organizationId: root.organization_id,
    details: { kind: "grant_proxy", policy: root.proxy_policy, expiresAt: null }
  };
}

async function prepareRevoke(
  client: PoolClient,
  action: Extract<BallotLifecycleAction, { readonly kind: "revoke_proxy" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const proxyGrantId = UuidV7Schema.parse(action.proxyGrantId);
  const reason = canonicalText(action.reason);
  idempotencyKey(action.idempotencyKey);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("proxy revocation reason must contain 1 through 65536 characters");
  }
  const reference = await client.query<{ vote_id: string }>(
    `select vote_id from proxy_grants
      where id=$1 and principal_member_id=boardagent_context_uuid('boardagent.member_id')`,
    [proxyGrantId]
  );
  const voteId = reference.rows[0]?.vote_id;
  if (!voteId || reference.rows.length !== 1) unavailable();
  const root = await lockVoteRoot(client, voteId, "proxy:manage");
  if (!(["open", "source_update_pending"] as const).includes(root.vote_state as never)) {
    unavailable();
  }
  const grantResult = await client.query<ProxyGrantRow>(
    `select proxy.id,proxy.vote_id,proxy.principal_member_id,proxy.holder_member_id,
            proxy.policy,(revocation.id is null and
              (proxy.expires_at is null or proxy.expires_at>transaction_timestamp())) as active
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.id=$1 and proxy.vote_id=$2 and proxy.principal_member_id=$3`,
    [proxyGrantId, voteId, context.memberId]
  );
  const grant = grantResult.rows[0];
  if (!grant || grantResult.rows.length !== 1 || !grant.active) unavailable();
  const names = await displayNames(client, root.organization_id, [
    context.memberId,
    grant.holder_member_id
  ]);
  const packageSha256 = root.package_sha256.toString("hex");
  const payload: JsonValue = {
    schemaVersion: "boardagent.proxy-revoke-consent.v1",
    voteId,
    proxyGrantId,
    principalMemberId: context.memberId,
    reason,
    packageSha256
  };
  if (
    canonicalSha256(payload) !==
    proxyRevokeConsentHash({
      voteId,
      proxyGrantId,
      principalMemberId: context.memberId,
      reason,
      packageSha256
    })
  ) {
    throw new Error("proxy revocation consent payload construction drifted");
  }
  return {
    ...commonPrepared(root, context, names, {
      actionCode: "revoke_proxy",
      targetType: "proxy_grant",
      targetId: proxyGrantId,
      actingForMemberId: null,
      canonicalSchema: "boardagent.proxy-revoke-consent.v1",
      canonicalPayload: payload,
      principalMemberId: context.memberId,
      holderMemberId: grant.holder_member_id,
      proxyGrantId
    }),
    action,
    context,
    organizationId: root.organization_id,
    details: { kind: "revoke_proxy", grant, reason }
  };
}

/** Return only a completed, exactly bound ballot result; never stage or cast a new act.
 * Live vote, seat, exclusion and proxy checks still apply to this read. The original
 * consent ID remains part of the request hash, so retry does not manufacture consent.
 */
export async function replayCompletedBallotInTransaction(
  client: PoolClient,
  action: Extract<BallotLifecycleAction, { readonly kind: "ballot" }>
): Promise<CastBallotResult | null> {
  const context = await readRequestContext(client);
  const voteId = UuidV7Schema.parse(action.voteId);
  const principalMemberId =
    action.principalMemberId === null
      ? context.memberId
      : UuidV7Schema.parse(action.principalMemberId);
  const key = idempotencyKey(action.idempotencyKey);
  const statement = action.statement === null ? null : canonicalText(action.statement);
  if (statement !== null && statement.length > 500) {
    throw new RangeError("ballot statement must not exceed 500 characters");
  }
  const root = await lockVoteRoot(client, voteId, "vote:act");
  const records = await client.query<{
    request_sha256: Buffer;
    state: string;
    safe_response_type: string | null;
    safe_response_id: string | null;
    safe_response_sha256: Buffer | null;
  }>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where organization_id=$1 and actor_member_id=$2 and client_id=$3
        and operation='cast_ballot' and idempotency_key=$4 for update`,
    [context.organizationId, context.memberId, context.clientId, key]
  );
  const record = records.rows[0];
  if (!record) return null;
  if (
    record.state !== "succeeded" ||
    record.safe_response_type !== "ballot" ||
    !record.safe_response_id ||
    !record.safe_response_sha256
  ) {
    throw new BallotLifecycleTransactionError(
      "ballot_action_invalid",
      "ballot idempotency result is unavailable"
    );
  }
  const ballots = await client.query<{
    id: string;
    consent_record_id: string;
    proxy_grant_id: string | null;
    ballot_source: "own" | "proxy";
  }>(
    `select id,consent_record_id,proxy_grant_id,ballot_source from ballots
      where id=$1 and organization_id=$2 and board_id=$3 and vote_id=$4
        and principal_member_id=$5 and caster_member_id=$6 and decision_package_id=$7`,
    [
      record.safe_response_id,
      root.organization_id,
      root.board_id,
      voteId,
      principalMemberId,
      context.memberId,
      root.decision_package_id
    ]
  );
  const ballot = ballots.rows[0];
  if (!ballot) {
    throw new BallotLifecycleTransactionError(
      "ballot_action_invalid",
      "ballot idempotency conflict"
    );
  }
  const expected = canonicalSha256({
    schemaVersion: "boardagent.ballot-request.v1",
    organizationId: context.organizationId,
    voteId,
    principalMemberId,
    casterMemberId: context.memberId,
    choice: action.choice,
    statement,
    proxyGrantId: ballot.proxy_grant_id,
    decisionPackageSha256: root.package_sha256.toString("hex"),
    consentRecordId: ballot.consent_record_id
  });
  if (!safeHashEqual(expected, record.request_sha256.toString("hex"))) {
    throw new BallotLifecycleTransactionError(
      "ballot_action_invalid",
      "ballot idempotency conflict"
    );
  }
  const involved = [...new Set([principalMemberId, context.memberId])];
  const eligible = await participants(client, root, involved);
  if (
    eligible.length !== involved.length ||
    eligible.some(({ ready }) => !ready) ||
    (await excluded(client, voteId, involved)).size !== 0
  )
    unavailable();
  if (ballot.ballot_source === "proxy") {
    const grants = (await activeRelationships(client, voteId)).filter(
      (grant) =>
        grant.id === ballot.proxy_grant_id &&
        grant.principal_member_id === principalMemberId &&
        grant.holder_member_id === context.memberId &&
        grant.active &&
        grant.policy === root.proxy_policy
    );
    if (grants.length !== 1) unavailable();
  }
  return {
    replayed: true,
    voteId,
    ballotId: ballot.id,
    principalMemberId,
    source: ballot.ballot_source,
    responseSha256: Sha256HexSchema.parse(record.safe_response_sha256.toString("hex"))
  };
}

async function prepareBallot(
  client: PoolClient,
  action: Extract<BallotLifecycleAction, { readonly kind: "ballot" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const voteId = UuidV7Schema.parse(action.voteId);
  const principalMemberId =
    action.principalMemberId === null
      ? context.memberId
      : UuidV7Schema.parse(action.principalMemberId);
  const statement = action.statement === null ? null : canonicalText(action.statement);
  idempotencyKey(action.idempotencyKey);
  if (statement !== null && statement.length > 500) {
    throw new RangeError("ballot statement must not exceed 500 characters");
  }
  const root = await lockVoteRoot(client, voteId, "vote:act");
  if (root.vote_state !== "open" || !root.deadline_open) unavailable();
  const involved = [...new Set([principalMemberId, context.memberId])];
  const eligible = await participants(client, root, involved);
  if (eligible.length !== involved.length || eligible.some(({ ready }) => !ready)) unavailable();
  if ((await excluded(client, voteId, involved)).size !== 0) unavailable();
  let proxyGrantId: string | null = null;
  let holderMemberId: string | null = null;
  if (principalMemberId !== context.memberId) {
    const grants = (await activeRelationships(client, voteId)).filter(
      (grant) =>
        grant.principal_member_id === principalMemberId &&
        grant.holder_member_id === context.memberId &&
        grant.active
    );
    const grant = grants[0];
    if (grants.length !== 1 || !grant || grant.policy !== root.proxy_policy) unavailable();
    proxyGrantId = grant.id;
    holderMemberId = context.memberId;
  }
  const active = await client.query<ActiveBallotRow>(
    `select ballot.id,ballot.ballot_source
       from ballots as ballot
       left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
      where ballot.vote_id=$1 and ballot.principal_member_id=$2 and disposition.id is null
      order by ballot.id`,
    [voteId, principalMemberId]
  );
  if (active.rows.length > 1) throw new Error("multiple effective ballots violate invariants");
  const activeBallot = active.rows[0];
  const maySupersede =
    activeBallot !== undefined &&
    principalMemberId === context.memberId &&
    activeBallot.ballot_source === "proxy" &&
    root.proxy_policy === "principal_supersedes_proxy";
  if (activeBallot && !maySupersede) {
    throw new BallotLifecycleTransactionError(
      "ballot_action_invalid",
      "principal already has an effective ballot under the frozen precedence rule"
    );
  }
  const names = await displayNames(client, root.organization_id, involved);
  const packageSha256 = root.package_sha256.toString("hex");
  const payload: JsonValue = {
    schemaVersion: "boardagent.ballot-consent.v1",
    voteId,
    principalMemberId,
    casterMemberId: context.memberId,
    choice: action.choice,
    statement,
    proxyGrantId,
    packageSha256
  };
  if (
    canonicalSha256(payload) !==
    ballotConsentHash({
      voteId,
      principalMemberId,
      casterMemberId: context.memberId,
      choice: action.choice,
      statement,
      proxyGrantId,
      packageSha256
    })
  ) {
    throw new Error("ballot consent payload construction drifted");
  }
  return {
    ...commonPrepared(root, context, names, {
      actionCode: "stage_ballot",
      targetType: "vote",
      targetId: voteId,
      actingForMemberId: principalMemberId === context.memberId ? null : principalMemberId,
      canonicalSchema: "boardagent.ballot-consent.v1",
      canonicalPayload: payload,
      principalMemberId,
      holderMemberId,
      proxyGrantId
    }),
    action,
    context,
    organizationId: root.organization_id,
    details: { kind: "ballot", choice: action.choice, statement, proxyGrantId }
  };
}

async function prepareInternal(
  client: PoolClient,
  action: BallotLifecycleAction
): Promise<PreparedInternal> {
  const context = await readRequestContext(client);
  switch (action.kind) {
    case "grant_proxy":
      return prepareGrant(client, action, context);
    case "revoke_proxy":
      return prepareRevoke(client, action, context);
    case "ballot":
      return prepareBallot(client, action, context);
  }
}

export async function prepareBallotLifecycleActionInTransaction(
  client: PoolClient,
  action: BallotLifecycleAction
): Promise<PreparedBallotLifecycleAction> {
  const prepared = await prepareInternal(client, action);
  const {
    action: _action,
    context: _context,
    organizationId: _organizationId,
    details: _details,
    ...view
  } = prepared;
  return view;
}

export async function stageBallotLifecycleActionInTransaction(
  client: PoolClient,
  input: BallotLifecycleStageInput
): Promise<StagedBallotLifecycleAction> {
  const prepared = await prepareInternal(client, input.action);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.boardId,
      actingForMemberId: prepared.actingForMemberId,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => {
      // Preparation locked the vote, participants, exclusions, proxy graph and ballot row.
    }
  );
  return {
    ...staged,
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetType: prepared.targetType,
    targetId: prepared.targetId,
    actingForMemberId: prepared.actingForMemberId
  };
}

function auditSequences(result: GrantProxyResult | RevokeProxyResult | CastBallotResult): bigint[] {
  return result.replayed ? [] : result.auditEvents.map(({ sequence }) => sequence);
}

async function performAction(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string,
  ids: BallotLifecycleGeneratedIds
): Promise<BallotLifecycleResult> {
  switch (prepared.details.kind) {
    case "grant_proxy": {
      if (prepared.action.kind !== "grant_proxy")
        throw new Error("proxy grant preparation mismatch");
      return {
        kind: "grant_proxy",
        result: await grantProxyInTransaction(client, {
          organizationId: prepared.organizationId,
          voteId: prepared.voteId,
          holderMemberId: prepared.action.holderMemberId,
          decisionPackageSha256: prepared.packageSha256,
          policy: prepared.details.policy,
          expiresAt: prepared.details.expiresAt,
          consentRecordId,
          proxyGrantId: ids.recordId,
          idempotencyRecordId: ids.idempotencyRecordId,
          idempotencyKey: prepared.action.idempotencyKey,
          auditEventId: ids.auditEventId
        })
      };
    }
    case "revoke_proxy": {
      if (prepared.action.kind !== "revoke_proxy") {
        throw new Error("proxy revocation preparation mismatch");
      }
      return {
        kind: "revoke_proxy",
        result: await revokeProxyInTransaction(client, {
          organizationId: prepared.organizationId,
          voteId: prepared.voteId,
          proxyGrantId: prepared.targetId,
          decisionPackageSha256: prepared.packageSha256,
          reason: prepared.details.reason,
          consentRecordId,
          proxyRevocationId: ids.recordId,
          idempotencyRecordId: ids.idempotencyRecordId,
          idempotencyKey: prepared.action.idempotencyKey,
          auditEventId: ids.auditEventId
        })
      };
    }
    case "ballot": {
      if (prepared.action.kind !== "ballot") throw new Error("ballot preparation mismatch");
      return {
        kind: "ballot",
        result: await castBallotInTransaction(client, {
          organizationId: prepared.organizationId,
          voteId: prepared.voteId,
          principalMemberId: prepared.principalMemberId,
          decisionPackageSha256: prepared.packageSha256,
          choice: prepared.details.choice,
          statement: prepared.details.statement,
          proxyGrantId: prepared.details.proxyGrantId,
          consentRecordId,
          ballotId: ids.recordId,
          supersessionDispositionId: ids.supersessionDispositionId,
          supersessionAuditEventId: ids.supersessionAuditEventId,
          idempotencyRecordId: ids.idempotencyRecordId,
          idempotencyKey: prepared.action.idempotencyKey,
          auditEventId: ids.auditEventId
        })
      };
    }
  }
}

export async function confirmBallotLifecycleActionInTransaction(
  client: PoolClient,
  input: BallotLifecycleConfirmationInput
): Promise<StagedActionResolution<BallotLifecycleResult>> {
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
      if (!prepared) throw new Error("ballot lifecycle preparation is unavailable");
      const value = await performAction(
        requestClient,
        prepared,
        consentRecordId,
        input.generatedIds
      );
      return {
        value,
        auditEvents: [],
        preappendedAuditSequences: auditSequences(value.result)
      };
    },
    { appendConsentBeforeAct: true, exposeConfirmedProjectionToAct: true }
  );
}
