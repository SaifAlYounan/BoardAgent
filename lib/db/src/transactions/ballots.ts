import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex
} from "@boardagent/contracts";
import {
  ballotConsentHash,
  proxyGrantConsentHash,
  proxyRevokeConsentHash,
  type BallotChoice,
  type PrincipalSupersessionRule
} from "@boardagent/domain";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export class BallotProxyTransactionError extends Error {
  public constructor(
    public readonly code:
      | "ballot_unavailable"
      | "ballot_invalid"
      | "proxy_unavailable"
      | "proxy_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "BallotProxyTransactionError";
  }
}

export interface GrantProxyInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly holderMemberId: string;
  readonly decisionPackageSha256: string;
  readonly policy: PrincipalSupersessionRule;
  readonly expiresAt: string | null;
  readonly consentRecordId: string;
  readonly proxyGrantId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface RevokeProxyInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly proxyGrantId: string;
  readonly decisionPackageSha256: string;
  readonly reason: string;
  readonly consentRecordId: string;
  readonly proxyRevocationId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface CastBallotInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly principalMemberId: string;
  readonly decisionPackageSha256: string;
  readonly choice: BallotChoice;
  readonly statement: string | null;
  readonly proxyGrantId: string | null;
  readonly consentRecordId: string;
  readonly ballotId: string;
  /** Preallocated and used only if an active proxy ballot is superseded. */
  readonly supersessionDispositionId: string;
  /** Preallocated and used only if an active proxy ballot is superseded. */
  readonly supersessionAuditEventId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export type GrantProxyResult =
  | {
      readonly replayed: true;
      readonly voteId: string;
      readonly proxyGrantId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly voteId: string;
      readonly proxyGrantId: string;
      readonly principalMemberId: string;
      readonly holderMemberId: string;
      readonly policy: PrincipalSupersessionRule;
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

export type RevokeProxyResult =
  | {
      readonly replayed: true;
      readonly voteId: string;
      readonly proxyGrantId: string;
      readonly proxyRevocationId: string;
      readonly effect: "revoked";
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly voteId: string;
      readonly proxyGrantId: string;
      readonly proxyRevocationId: string;
      readonly effect: "revoked";
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

export type CastBallotResult =
  | {
      readonly replayed: true;
      readonly voteId: string;
      readonly ballotId: string;
      readonly principalMemberId: string;
      readonly source: "own" | "proxy";
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly voteId: string;
      readonly ballotId: string;
      readonly principalMemberId: string;
      readonly casterMemberId: string;
      readonly source: "own" | "proxy";
      readonly supersededBallotId: string | null;
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

interface VoteRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_state: string;
  readonly vote_row_version: string;
  readonly decision_package_id: string;
  readonly package_sha256: Buffer;
  readonly proxy_policy: PrincipalSupersessionRule;
  readonly deadline_open: boolean;
  readonly actor_ready: boolean;
}

interface ParticipantRow {
  readonly member_id: string;
  readonly voting_weight: string;
  readonly ready: boolean;
}

interface ExclusionRow {
  readonly member_id: string;
  readonly state: "excluded" | "lifted";
}

interface ProxyGrantRow {
  readonly id: string;
  readonly principal_member_id: string;
  readonly holder_member_id: string;
  readonly policy: PrincipalSupersessionRule;
  readonly active: boolean;
}

interface ActiveBallotRow {
  readonly id: string;
  readonly caster_member_id: string;
  readonly ballot_source: "own" | "proxy";
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

type VoteOperation = "cast_ballot" | "grant_proxy" | "revoke_proxy";

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function uniqueGeneratedIds<const Values extends readonly string[]>(
  values: Values,
  label: string
): Values {
  const parsed = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(parsed).size !== parsed.length) {
    throw new TypeError(`${label} must be globally unique`);
  }
  return parsed as unknown as Values;
}

async function lockVoteRoot(
  client: PoolClient,
  voteId: string,
  requiredScope: "proxy:manage" | "vote:act"
): Promise<VoteRootRow | undefined> {
  const query = `select vote.organization_id,vote.board_id,vote.state as vote_state,
                        vote.row_version::text as vote_row_version,
                        package.id as decision_package_id,package.package_sha256,
                        rule.proxy_policy,
                        vote.deadline_at > transaction_timestamp() as deadline_open,
                        boardagent_vote_actor_ready_for_scope(vote.board_id,$2) as actor_ready
                   from votes as vote
                   join decision_packages as package
                     on package.id=vote.current_decision_package_id and package.vote_id=vote.id
                   join approval_rules as rule on rule.id=vote.approval_rule_id
                  where vote.id=$1
                    and vote.organization_id=boardagent_context_uuid('boardagent.organization_id')
                    and boardagent_context_board_allowed(vote.board_id)
                  for update of vote`;
  await client.query<VoteRootRow>(query, [voteId, requiredScope]);
  // The first statement establishes the root lock. A waiter then needs a new READ
  // COMMITTED snapshot to observe exclusions, grants or a replacement committed by
  // the winner before it acquired that lock.
  const refreshed = await client.query<VoteRootRow>(query, [voteId, requiredScope]);
  return refreshed.rows.length === 1 ? refreshed.rows[0] : undefined;
}

async function lockParticipants(
  client: PoolClient,
  organizationId: string,
  boardId: string,
  voteId: string,
  memberIds: readonly string[]
): Promise<readonly ParticipantRow[]> {
  const ids = [...new Set(memberIds)].toSorted();
  const result = await client.query<ParticipantRow>(
    `select locked.member_id,electorate.voting_weight::text,
            (locked.active_now
             and locked.seat_role='voting_member'
             and locked.voting_weight > 0) as ready
       from boardagent_lock_board_members($1,$2,$4::uuid[]) as locked
       join vote_electorate as electorate
         on electorate.organization_id=$1
        and electorate.board_id=$2
        and electorate.member_id=locked.member_id
      where electorate.organization_id=$1 and electorate.board_id=$2
        and electorate.vote_id=$3 and electorate.member_id=any($4::uuid[])
      order by locked.member_id`,
    [organizationId, boardId, voteId, ids]
  );
  return result.rows;
}

async function excludedMembers(
  client: PoolClient,
  voteId: string,
  memberIds: readonly string[]
): Promise<ReadonlySet<string>> {
  const result = await client.query<ExclusionRow>(
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

async function consentValid(
  client: PoolClient,
  input: {
    readonly consentRecordId: string;
    readonly actionCode: "grant_proxy" | "revoke_proxy" | "stage_ballot";
    readonly targetType: "proxy_grant" | "vote";
    readonly targetId: string;
    readonly payloadSha256: string;
    readonly packageSha256: string;
  }
): Promise<boolean> {
  const result = await client.query<{ valid: boolean }>(
    `select exists (
       select 1
         from consent_records as consent
         join action_stages as stage on stage.id=consent.stage_id
         join input_required_attempts as attempt
           on attempt.id=consent.input_required_attempt_id
        where consent.id=$1
          and consent.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
          and consent.client_id=boardagent_context_uuid('boardagent.client_id')
          and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
          and consent.action_code=$2
          and consent.target_type=$3
          and consent.target_id=$4
          and consent.payload_sha256=$5
          and consent.package_sha256=$6
          and stage.organization_id=consent.organization_id
          and stage.board_id=consent.board_id
          and stage.actor_member_id=consent.actor_member_id
          and stage.client_id=consent.client_id
          and stage.token_jti=consent.token_jti
          and stage.action_code=consent.action_code
          and stage.target_type=consent.target_type
          and stage.target_id=consent.target_id
          and stage.payload_sha256=consent.payload_sha256
          and stage.package_sha256=consent.package_sha256
          and stage.state='confirmed' and stage.confirmed_at is not null
          and attempt.organization_id=consent.organization_id
          and attempt.stage_id=stage.id
          and attempt.original_method='tools/call'
          and attempt.original_name=$2
          and attempt.response_action='accept'
          and attempt.state='confirmed'
     ) as valid`,
    [
      input.consentRecordId,
      input.actionCode,
      input.targetType,
      input.targetId,
      Buffer.from(input.payloadSha256, "hex"),
      Buffer.from(input.packageSha256, "hex")
    ]
  );
  return result.rows[0]?.valid === true;
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  operation: VoteOperation,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      for update`,
    [actorMemberId, clientId, operation, key]
  );
  return result.rows[0];
}

function checkedReplay(
  row: IdempotencyRow | undefined,
  requestSha256: string
): { readonly id: string; readonly responseSha256: string } | undefined {
  if (!row) return undefined;
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new BallotProxyTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different vote action"
    );
  }
  if (row.state === "succeeded" && row.safe_response_id && row.safe_response_sha256) {
    return {
      id: row.safe_response_id,
      responseSha256: row.safe_response_sha256.toString("hex")
    };
  }
  throw new BallotProxyTransactionError(
    "idempotency_in_progress",
    "identical vote action is already in progress"
  );
}

async function insertIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly operation: VoteOperation;
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<void> {
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'in_progress',transaction_timestamp()+interval '24 hours')
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
  const row = await readIdempotency(
    client,
    input.actorMemberId,
    input.clientId,
    input.operation,
    input.key
  );
  if (!row) throw new Error("vote-action idempotency record disappeared");
  if (inserted.rowCount === 0) checkedReplay(row, input.requestSha256);
  if (!safeHashEqual(row.request_sha256.toString("hex"), input.requestSha256)) {
    throw new BallotProxyTransactionError(
      "idempotency_conflict",
      "vote-action idempotency record does not bind this request"
    );
  }
}

async function finishIdempotency(
  client: PoolClient,
  id: string,
  safeResponseType: "ballot" | "proxy_grant" | "proxy_revocation",
  safeResponseId: string,
  responseSha256: string
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type=$1,safe_response_id=$2,
            safe_response_sha256=$3,completed_at=transaction_timestamp()
      where id=$4 and state='in_progress'`,
    [safeResponseType, safeResponseId, Buffer.from(responseSha256, "hex"), id]
  );
  if (result.rowCount !== 1) throw new Error("vote-action idempotency completion failed");
}

async function advanceVoteVersion(
  client: PoolClient,
  voteId: string,
  rowVersion: string,
  permittedStates: readonly string[]
): Promise<bigint> {
  const result = await client.query<{ row_version: string }>(
    `update votes set row_version=row_version+1
      where id=$1 and row_version=$2::bigint and state=any($3::text[])
      returning row_version::text`,
    [voteId, rowVersion, permittedStates]
  );
  const next = result.rows[0]?.row_version;
  if (!next || result.rows.length !== 1) {
    throw new BallotProxyTransactionError(
      "ballot_unavailable",
      "vote changed during the confirmed action"
    );
  }
  return BigInt(next);
}

export async function grantProxyInTransaction(
  client: PoolClient,
  input: GrantProxyInput
): Promise<GrantProxyResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const holderMemberId = UuidV7Schema.parse(input.holderMemberId);
  const decisionPackageSha256 = Sha256HexSchema.parse(input.decisionPackageSha256);
  const policy = input.policy;
  const expiresAt = input.expiresAt === null ? null : Rfc3339UtcSchema.parse(input.expiresAt);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const [proxyGrantId, idempotencyRecordId, auditEventId] = uniqueGeneratedIds(
    [input.proxyGrantId, input.idempotencyRecordId, input.auditEventId],
    "proxy-grant generated IDs"
  );
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy grant is unavailable");
  }
  const principalMemberId = context.memberId;
  const consentPayloadSha256 = proxyGrantConsentHash({
    voteId,
    principalMemberId,
    holderMemberId,
    policy,
    expiresAt,
    packageSha256: decisionPackageSha256
  });
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.proxy-grant-request.v1",
    organizationId,
    voteId,
    principalMemberId,
    holderMemberId,
    policy,
    expiresAt,
    decisionPackageSha256,
    consentRecordId
  });
  const vote = await lockVoteRoot(client, voteId, "proxy:manage");
  if (!vote || vote.organization_id !== organizationId) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy grant is unavailable");
  }
  const replay = checkedReplay(
    await readIdempotency(
      client,
      context.memberId,
      context.clientId,
      "grant_proxy",
      idempotencyKey
    ),
    requestSha256
  );
  if (replay) {
    return {
      replayed: true,
      voteId,
      proxyGrantId: replay.id,
      responseSha256: replay.responseSha256
    };
  }
  if (
    vote.vote_state !== "open" ||
    !vote.deadline_open ||
    !vote.actor_ready ||
    vote.proxy_policy !== policy ||
    !safeHashEqual(vote.package_sha256.toString("hex"), decisionPackageSha256)
  ) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy grant is unavailable");
  }
  const participants = await lockParticipants(client, organizationId, vote.board_id, voteId, [
    principalMemberId,
    holderMemberId
  ]);
  if (participants.length !== 2 || participants.some(({ ready }) => !ready)) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy grant is unavailable");
  }
  const exclusions = await excludedMembers(client, voteId, [principalMemberId, holderMemberId]);
  if (exclusions.size > 0) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy grant is unavailable");
  }
  if (
    !(await consentValid(client, {
      consentRecordId,
      actionCode: "grant_proxy",
      targetType: "vote",
      targetId: voteId,
      payloadSha256: consentPayloadSha256,
      packageSha256: decisionPackageSha256
    }))
  ) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy grant is unavailable");
  }
  const expiry = await client.query<{ valid: boolean }>(
    "select $1::timestamptz is null or $1::timestamptz > transaction_timestamp() as valid",
    [expiresAt]
  );
  if (expiry.rows[0]?.valid !== true) {
    throw new BallotProxyTransactionError(
      "proxy_invalid",
      "proxy expiry must remain in the future"
    );
  }
  const relationships = await client.query<ProxyGrantRow>(
    `select proxy.id,proxy.principal_member_id,proxy.holder_member_id,proxy.policy,
            (revocation.id is null
             and (proxy.expires_at is null or proxy.expires_at > transaction_timestamp())) as active
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.vote_id=$1
      order by proxy.id`,
    [voteId]
  );
  if (
    relationships.rows.some(({ principal_member_id }) => principal_member_id === principalMemberId)
  ) {
    throw new BallotProxyTransactionError(
      "proxy_invalid",
      "principal already has immutable proxy history for this vote"
    );
  }
  const active = relationships.rows.filter(({ active }) => active);
  if (
    active.some(({ principal_member_id }) => principal_member_id === holderMemberId) ||
    active.some(({ holder_member_id }) => holder_member_id === principalMemberId)
  ) {
    throw new BallotProxyTransactionError("proxy_invalid", "proxy chain or cycle is forbidden");
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "grant_proxy",
    key: idempotencyKey,
    requestSha256
  });
  await client.query(
    `insert into proxy_grants(
       id,organization_id,board_id,vote_id,principal_member_id,holder_member_id,
       policy,consent_record_id,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      proxyGrantId,
      organizationId,
      vote.board_id,
      voteId,
      principalMemberId,
      holderMemberId,
      policy,
      consentRecordId,
      expiresAt
    ]
  );
  const objectVersion = await advanceVoteVersion(client, voteId, vote.vote_row_version, ["open"]);
  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      consentRecordId,
      objectVersion,
      event: {
        eventId: auditEventId,
        eventType: "proxy_granted",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "proxy_grant",
        entityId: proxyGrantId,
        boardId: vote.board_id,
        origin: "mcp",
        details: {
          voteId,
          principalMemberId,
          holderMemberId,
          policy,
          expiresAt,
          decisionPackageId: vote.decision_package_id,
          packageSha256: decisionPackageSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  const responseSha256 = canonicalSha256({
    schemaVersion: "boardagent.proxy-grant-result.v1",
    voteId,
    proxyGrantId,
    principalMemberId,
    holderMemberId,
    policy,
    objectVersion: objectVersion.toString(10)
  });
  await finishIdempotency(client, idempotencyRecordId, "proxy_grant", proxyGrantId, responseSha256);
  return {
    replayed: false,
    voteId,
    proxyGrantId,
    principalMemberId,
    holderMemberId,
    policy,
    responseSha256,
    auditEvents
  };
}

export async function revokeProxyInTransaction(
  client: PoolClient,
  input: RevokeProxyInput
): Promise<RevokeProxyResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const proxyGrantId = UuidV7Schema.parse(input.proxyGrantId);
  const decisionPackageSha256 = Sha256HexSchema.parse(input.decisionPackageSha256);
  const reason = canonicalText(input.reason);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("proxy revocation reason must contain 1 through 65536 characters");
  }
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const [proxyRevocationId, idempotencyRecordId, auditEventId] = uniqueGeneratedIds(
    [input.proxyRevocationId, input.idempotencyRecordId, input.auditEventId],
    "proxy-revoke generated IDs"
  );
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy revocation is unavailable");
  }
  const principalMemberId = context.memberId;
  const consentPayloadSha256 = proxyRevokeConsentHash({
    voteId,
    proxyGrantId,
    principalMemberId,
    reason,
    packageSha256: decisionPackageSha256
  });
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.proxy-revoke-request.v1",
    organizationId,
    voteId,
    proxyGrantId,
    principalMemberId,
    reason,
    decisionPackageSha256,
    consentRecordId
  });
  const vote = await lockVoteRoot(client, voteId, "proxy:manage");
  if (!vote || vote.organization_id !== organizationId) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy revocation is unavailable");
  }
  const replay = checkedReplay(
    await readIdempotency(
      client,
      context.memberId,
      context.clientId,
      "revoke_proxy",
      idempotencyKey
    ),
    requestSha256
  );
  if (replay) {
    return {
      replayed: true,
      voteId,
      proxyGrantId,
      proxyRevocationId: replay.id,
      effect: "revoked",
      responseSha256: replay.responseSha256
    };
  }
  if (
    !["open", "source_update_pending"].includes(vote.vote_state) ||
    !vote.actor_ready ||
    !safeHashEqual(vote.package_sha256.toString("hex"), decisionPackageSha256)
  ) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy revocation is unavailable");
  }
  const grantResult = await client.query<ProxyGrantRow>(
    `select proxy.id,proxy.principal_member_id,proxy.holder_member_id,proxy.policy,
            (revocation.id is null
             and (proxy.expires_at is null or proxy.expires_at > transaction_timestamp())) as active
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.id=$1 and proxy.vote_id=$2 and proxy.principal_member_id=$3`,
    [proxyGrantId, voteId, principalMemberId]
  );
  const grant = grantResult.rows[0];
  if (!grant || grantResult.rows.length !== 1 || !grant.active) {
    throw new BallotProxyTransactionError(
      "proxy_invalid",
      "active owned proxy grant is unavailable"
    );
  }
  if (
    !(await consentValid(client, {
      consentRecordId,
      actionCode: "revoke_proxy",
      targetType: "proxy_grant",
      targetId: proxyGrantId,
      payloadSha256: consentPayloadSha256,
      packageSha256: decisionPackageSha256
    }))
  ) {
    throw new BallotProxyTransactionError("proxy_unavailable", "proxy revocation is unavailable");
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "revoke_proxy",
    key: idempotencyKey,
    requestSha256
  });
  await client.query(
    `insert into proxy_revocations(
       id,organization_id,grant_id,revoker_member_id,reason,effect,consent_record_id
     ) values ($1,$2,$3,$4,$5,'revoked',$6)`,
    [proxyRevocationId, organizationId, proxyGrantId, principalMemberId, reason, consentRecordId]
  );
  const objectVersion = await advanceVoteVersion(client, voteId, vote.vote_row_version, [
    "open",
    "source_update_pending"
  ]);
  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      consentRecordId,
      objectVersion,
      event: {
        eventId: auditEventId,
        eventType: "proxy_revoked",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "proxy_grant",
        entityId: proxyGrantId,
        boardId: vote.board_id,
        origin: "mcp",
        details: {
          voteId,
          proxyGrantId,
          proxyRevocationId,
          principalMemberId,
          effect: "revoked",
          reasonSha256: sha256Hex(reason),
          packageSha256: decisionPackageSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  const responseSha256 = canonicalSha256({
    schemaVersion: "boardagent.proxy-revoke-result.v1",
    voteId,
    proxyGrantId,
    proxyRevocationId,
    effect: "revoked",
    objectVersion: objectVersion.toString(10)
  });
  await finishIdempotency(
    client,
    idempotencyRecordId,
    "proxy_revocation",
    proxyRevocationId,
    responseSha256
  );
  return {
    replayed: false,
    voteId,
    proxyGrantId,
    proxyRevocationId,
    effect: "revoked",
    responseSha256,
    auditEvents
  };
}

export async function castBallotInTransaction(
  client: PoolClient,
  input: CastBallotInput
): Promise<CastBallotResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const principalMemberId = UuidV7Schema.parse(input.principalMemberId);
  const decisionPackageSha256 = Sha256HexSchema.parse(input.decisionPackageSha256);
  const choice = input.choice;
  const statement = input.statement === null ? null : canonicalText(input.statement);
  if (statement !== null && statement.length > 500) {
    throw new RangeError("ballot statement must not exceed 500 characters");
  }
  const proxyGrantId = input.proxyGrantId === null ? null : UuidV7Schema.parse(input.proxyGrantId);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const [
    ballotId,
    supersessionDispositionId,
    supersessionAuditEventId,
    idempotencyRecordId,
    auditEventId
  ] = uniqueGeneratedIds(
    [
      input.ballotId,
      input.supersessionDispositionId,
      input.supersessionAuditEventId,
      input.idempotencyRecordId,
      input.auditEventId
    ],
    "ballot generated IDs"
  );
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new BallotProxyTransactionError("ballot_unavailable", "ballot is unavailable");
  }
  const casterMemberId = context.memberId;
  const source = casterMemberId === principalMemberId ? "own" : "proxy";
  const consentPayloadSha256 = ballotConsentHash({
    voteId,
    principalMemberId,
    casterMemberId,
    choice,
    statement,
    proxyGrantId,
    packageSha256: decisionPackageSha256
  });
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.ballot-request.v1",
    organizationId,
    voteId,
    principalMemberId,
    casterMemberId,
    choice,
    statement,
    proxyGrantId,
    decisionPackageSha256,
    consentRecordId
  });
  const vote = await lockVoteRoot(client, voteId, "vote:act");
  if (!vote || vote.organization_id !== organizationId) {
    throw new BallotProxyTransactionError("ballot_unavailable", "ballot is unavailable");
  }
  const replay = checkedReplay(
    await readIdempotency(
      client,
      context.memberId,
      context.clientId,
      "cast_ballot",
      idempotencyKey
    ),
    requestSha256
  );
  if (replay) {
    return {
      replayed: true,
      voteId,
      ballotId: replay.id,
      principalMemberId,
      source,
      responseSha256: replay.responseSha256
    };
  }
  if (
    vote.vote_state !== "open" ||
    !vote.deadline_open ||
    !vote.actor_ready ||
    !safeHashEqual(vote.package_sha256.toString("hex"), decisionPackageSha256)
  ) {
    throw new BallotProxyTransactionError("ballot_unavailable", "ballot is unavailable");
  }
  const participants = await lockParticipants(client, organizationId, vote.board_id, voteId, [
    principalMemberId,
    casterMemberId
  ]);
  if (
    participants.length !== new Set([principalMemberId, casterMemberId]).size ||
    participants.some(({ ready }) => !ready)
  ) {
    throw new BallotProxyTransactionError("ballot_unavailable", "ballot is unavailable");
  }
  const exclusions = await excludedMembers(client, voteId, [principalMemberId, casterMemberId]);
  if (exclusions.size > 0) {
    throw new BallotProxyTransactionError("ballot_unavailable", "ballot is unavailable");
  }
  if (source === "own" && proxyGrantId !== null) {
    throw new BallotProxyTransactionError("ballot_invalid", "own ballot cannot cite a proxy grant");
  }
  if (source === "proxy") {
    if (proxyGrantId === null) {
      throw new BallotProxyTransactionError("ballot_invalid", "proxy ballot requires a grant");
    }
    const grantResult = await client.query<ProxyGrantRow>(
      `select proxy.id,proxy.principal_member_id,proxy.holder_member_id,proxy.policy,
              (revocation.id is null
               and (proxy.expires_at is null or proxy.expires_at > transaction_timestamp())) as active
         from proxy_grants as proxy
         left join proxy_revocations as revocation on revocation.grant_id=proxy.id
        where proxy.id=$1 and proxy.vote_id=$2
          and proxy.principal_member_id=$3 and proxy.holder_member_id=$4`,
      [proxyGrantId, voteId, principalMemberId, casterMemberId]
    );
    const grant = grantResult.rows[0];
    if (
      !grant ||
      grantResult.rows.length !== 1 ||
      !grant.active ||
      grant.policy !== vote.proxy_policy
    ) {
      throw new BallotProxyTransactionError("ballot_unavailable", "ballot is unavailable");
    }
  }
  const activeResult = await client.query<ActiveBallotRow>(
    `select ballot.id,ballot.caster_member_id,ballot.ballot_source
       from ballots as ballot
       left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
      where ballot.vote_id=$1 and ballot.principal_member_id=$2 and disposition.id is null
      order by ballot.id`,
    [voteId, principalMemberId]
  );
  if (activeResult.rows.length > 1)
    throw new Error("multiple effective ballots violate invariants");
  const activeBallot = activeResult.rows[0];
  const supersedes =
    activeBallot !== undefined &&
    source === "own" &&
    activeBallot.ballot_source === "proxy" &&
    vote.proxy_policy === "principal_supersedes_proxy";
  if (activeBallot && !supersedes) {
    throw new BallotProxyTransactionError(
      "ballot_invalid",
      "principal already has an effective ballot under the frozen precedence rule"
    );
  }
  if (
    !(await consentValid(client, {
      consentRecordId,
      actionCode: "stage_ballot",
      targetType: "vote",
      targetId: voteId,
      payloadSha256: consentPayloadSha256,
      packageSha256: decisionPackageSha256
    }))
  ) {
    throw new BallotProxyTransactionError("ballot_unavailable", "ballot is unavailable");
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "cast_ballot",
    key: idempotencyKey,
    requestSha256
  });
  const principal = participants.find(({ member_id }) => member_id === principalMemberId);
  if (!principal) throw new Error("locked ballot principal disappeared");
  const statementSha256 = statement === null ? null : sha256Hex(statement);
  await client.query(
    `insert into ballots(
       id,organization_id,board_id,vote_id,decision_package_id,principal_member_id,
       caster_member_id,choice,statement_text,statement_sha256,voting_weight,
       ballot_source,proxy_grant_id,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      ballotId,
      organizationId,
      vote.board_id,
      voteId,
      vote.decision_package_id,
      principalMemberId,
      casterMemberId,
      choice,
      statement,
      statementSha256 === null ? null : Buffer.from(statementSha256, "hex"),
      principal.voting_weight,
      source,
      proxyGrantId,
      consentRecordId
    ]
  );
  if (supersedes && activeBallot) {
    await client.query(
      `insert into ballot_dispositions(
         id,prior_ballot_id,superseding_ballot_id,reason,effect,audit_event_id
       ) values ($1,$2,$3,'principal direct ballot superseded the active proxy ballot',
         'superseded',$4)`,
      [supersessionDispositionId, activeBallot.id, ballotId, supersessionAuditEventId]
    );
  }
  await client.query(
    `update pending_action_feed
        set state='resolved',resolved_at=transaction_timestamp()
      where board_id=$1 and member_id=$2 and object_type='vote' and object_id=$3
        and state='pending'
        and action_type in ('vote_opened','revote_required','recusal_changed')`,
    [vote.board_id, principalMemberId, voteId]
  );
  const objectVersion = await advanceVoteVersion(client, voteId, vote.vote_row_version, ["open"]);
  const auditInputs: AuditAppendInput[] = [];
  if (supersedes && activeBallot) {
    auditInputs.push({
      organizationId,
      consentRecordId,
      objectVersion,
      event: {
        eventId: supersessionAuditEventId,
        eventType: "ballot_superseded",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "ballot",
        entityId: activeBallot.id,
        boardId: vote.board_id,
        origin: "mcp",
        details: {
          voteId,
          priorBallotId: activeBallot.id,
          supersedingBallotId: ballotId,
          reasonClass: "principal_direct_precedence"
        },
        schemaVersion: 1
      }
    });
  }
  auditInputs.push({
    organizationId,
    actingForMemberId: source === "proxy" ? principalMemberId : null,
    consentRecordId,
    objectVersion,
    event: {
      eventId: auditEventId,
      eventType: "ballot_cast",
      actorMemberId: context.memberId,
      actorClientId: context.clientId,
      tokenJti: context.tokenJti,
      entityType: "ballot",
      entityId: ballotId,
      boardId: vote.board_id,
      origin: "mcp",
      details: {
        voteId,
        decisionPackageId: vote.decision_package_id,
        packageSha256: decisionPackageSha256,
        principalMemberId,
        casterMemberId,
        choice,
        statementSha256,
        votingWeight: Number(principal.voting_weight),
        source,
        proxyGrantId
      },
      schemaVersion: 1
    }
  });
  const auditEvents = await appendAuditEventsInTransaction(client, auditInputs);
  const responseSha256 = canonicalSha256({
    schemaVersion: "boardagent.ballot-result.v1",
    voteId,
    ballotId,
    principalMemberId,
    casterMemberId,
    choice,
    statementSha256,
    source,
    proxyGrantId,
    supersededBallotId: supersedes && activeBallot ? activeBallot.id : null,
    objectVersion: objectVersion.toString(10)
  });
  await finishIdempotency(client, idempotencyRecordId, "ballot", ballotId, responseSha256);
  return {
    replayed: false,
    voteId,
    ballotId,
    principalMemberId,
    casterMemberId,
    source,
    supersededBallotId: supersedes && activeBallot ? activeBallot.id : null,
    responseSha256,
    auditEvents
  };
}
