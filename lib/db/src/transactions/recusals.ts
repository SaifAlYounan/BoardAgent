import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  PendingActionDeltaSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual
} from "@boardagent/contracts";
import { eligibleVotingWeight, voteRecusalConsentHash } from "@boardagent/domain";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";
import type {
  VoteBallotReplacementInput,
  VoteProxyReplacementInput,
  VoteStageReplacementInput
} from "./votes.js";

export class VoteRecusalTransactionError extends Error {
  public constructor(
    public readonly code:
      | "vote_recusal_unavailable"
      | "vote_recusal_invalid"
      | "vote_recusal_recipient_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "VoteRecusalTransactionError";
  }
}

export interface VoteRecusalDeliveryInput {
  readonly memberId: string;
  readonly noticeId: string;
  readonly feedId: string;
  readonly noticeAuditEventId: string;
}

export interface VoteRecusalTombstoneInput {
  readonly removedFeedId: string;
  readonly tombstoneId: string;
}

export interface ManageVoteRecusalInput {
  readonly boardCause?: { readonly exclusionId: string; readonly payloadSha256: string };
  readonly organizationId: string;
  readonly voteId: string;
  readonly memberId: string;
  readonly decisionPackageSha256: string;
  readonly state: "excluded" | "lifted";
  readonly exclusionId: string;
  readonly reason: string;
  readonly consentRecordId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly stageDispositions: readonly VoteStageReplacementInput[];
  readonly proxyDispositions: readonly VoteProxyReplacementInput[];
  readonly ballotDispositions: readonly VoteBallotReplacementInput[];
  readonly feedTombstones: readonly VoteRecusalTombstoneInput[];
  readonly deliveries: readonly VoteRecusalDeliveryInput[];
  readonly auditEventId: string;
}

export type ManageVoteRecusalResult =
  | {
      readonly replayed: true;
      readonly voteId: string;
      readonly memberId: string;
      readonly exclusionId: string;
      readonly exclusionVersion: number;
      readonly state: "excluded" | "lifted";
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly voteId: string;
      readonly memberId: string;
      readonly exclusionId: string;
      readonly exclusionVersion: number;
      readonly state: "excluded" | "lifted";
      readonly eligibleWeight: bigint;
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

interface LockedRecusalRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_state: string;
  readonly vote_row_version: string;
  readonly decision_package_id: string;
  readonly package_sha256: Buffer;
  readonly electorate_weight: string;
  readonly current_exclusion_id: string | null;
  readonly current_exclusion_version: number | null;
  readonly current_exclusion_state: "excluded" | "lifted" | null;
  readonly actor_ready: boolean;
  readonly consent_valid: boolean;
}

interface LockedRecipientRow {
  readonly member_id: string;
  readonly entitlement_generation: string;
}

interface ActiveStageRow {
  readonly id: string;
}

interface ActiveProxyRow {
  readonly id: string;
  readonly principal_member_id: string;
  readonly holder_member_id: string;
}

interface ActiveBallotRow {
  readonly id: string;
  readonly principal_member_id: string;
  readonly caster_member_id: string;
}

interface PendingFeedRow {
  readonly id: string;
  readonly entitlement_generation: string;
  readonly feed_sequence: string;
  readonly object_version: string;
}

interface ElectorateEligibilityRow {
  readonly member_id: string;
  readonly voting_weight: string;
  readonly recused: boolean;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
  readonly state: string;
}

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function unique(values: readonly string[], label: string): readonly string[] {
  const parsed = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(parsed).size !== parsed.length) throw new TypeError(`${label} must be unique`);
  return parsed;
}

function normalizeStages(
  inputs: readonly VoteStageReplacementInput[]
): readonly VoteStageReplacementInput[] {
  const rows = inputs
    .map((input) => ({
      stageId: UuidV7Schema.parse(input.stageId),
      auditEventId: UuidV7Schema.parse(input.auditEventId)
    }))
    .toSorted((left, right) => left.stageId.localeCompare(right.stageId));
  unique(
    rows.map(({ stageId }) => stageId),
    "recusal stage IDs"
  );
  unique(
    rows.map(({ auditEventId }) => auditEventId),
    "recusal stage audit IDs"
  );
  return rows;
}

function normalizeProxies(
  inputs: readonly VoteProxyReplacementInput[]
): readonly VoteProxyReplacementInput[] {
  const rows = inputs
    .map((input) => ({
      proxyGrantId: UuidV7Schema.parse(input.proxyGrantId),
      proxyRevocationId: UuidV7Schema.parse(input.proxyRevocationId),
      auditEventId: UuidV7Schema.parse(input.auditEventId)
    }))
    .toSorted((left, right) => left.proxyGrantId.localeCompare(right.proxyGrantId));
  unique(
    rows.map(({ proxyGrantId }) => proxyGrantId),
    "recusal proxy grant IDs"
  );
  unique(
    rows.map(({ proxyRevocationId }) => proxyRevocationId),
    "recusal proxy revocation IDs"
  );
  unique(
    rows.map(({ auditEventId }) => auditEventId),
    "recusal proxy audit IDs"
  );
  return rows;
}

function normalizeBallots(
  inputs: readonly VoteBallotReplacementInput[]
): readonly VoteBallotReplacementInput[] {
  const rows = inputs
    .map((input) => ({
      ballotId: UuidV7Schema.parse(input.ballotId),
      ballotDispositionId: UuidV7Schema.parse(input.ballotDispositionId),
      auditEventId: UuidV7Schema.parse(input.auditEventId)
    }))
    .toSorted((left, right) => left.ballotId.localeCompare(right.ballotId));
  unique(
    rows.map(({ ballotId }) => ballotId),
    "recusal ballot IDs"
  );
  unique(
    rows.map(({ ballotDispositionId }) => ballotDispositionId),
    "recusal ballot disposition IDs"
  );
  unique(
    rows.map(({ auditEventId }) => auditEventId),
    "recusal ballot audit IDs"
  );
  return rows;
}

function normalizeTombstones(
  inputs: readonly VoteRecusalTombstoneInput[]
): readonly VoteRecusalTombstoneInput[] {
  const rows = inputs
    .map((input) => ({
      removedFeedId: UuidV7Schema.parse(input.removedFeedId),
      tombstoneId: UuidV7Schema.parse(input.tombstoneId)
    }))
    .toSorted((left, right) => left.removedFeedId.localeCompare(right.removedFeedId));
  unique(
    rows.map(({ removedFeedId }) => removedFeedId),
    "recusal removed feed IDs"
  );
  unique(
    rows.map(({ tombstoneId }) => tombstoneId),
    "recusal tombstone IDs"
  );
  return rows;
}

function normalizeDeliveries(
  inputs: readonly VoteRecusalDeliveryInput[]
): readonly VoteRecusalDeliveryInput[] {
  const rows = inputs
    .map((input) => ({
      memberId: UuidV7Schema.parse(input.memberId),
      noticeId: UuidV7Schema.parse(input.noticeId),
      feedId: UuidV7Schema.parse(input.feedId),
      noticeAuditEventId: UuidV7Schema.parse(input.noticeAuditEventId)
    }))
    .toSorted((left, right) => left.memberId.localeCompare(right.memberId));
  for (const [label, ids] of [
    ["recusal delivery members", rows.map(({ memberId }) => memberId)],
    ["recusal notice IDs", rows.map(({ noticeId }) => noticeId)],
    ["recusal feed IDs", rows.map(({ feedId }) => feedId)],
    ["recusal notice audit IDs", rows.map(({ noticeAuditEventId }) => noticeAuditEventId)]
  ] as const) {
    unique(ids, label);
  }
  return rows;
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='manage_recusal' and idempotency_key=$3
      for update`,
    [actorMemberId, clientId, key]
  );
  return result.rows[0];
}

function replayResult(
  record: IdempotencyRow | undefined,
  requestSha256: string,
  input: {
    readonly voteId: string;
    readonly memberId: string;
    readonly exclusionId: string;
    readonly exclusionVersion: number;
    readonly state: "excluded" | "lifted";
  }
): ManageVoteRecusalResult | undefined {
  if (!record) return undefined;
  if (!safeHashEqual(record.request_sha256.toString("hex"), requestSha256)) {
    throw new VoteRecusalTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different recusal request"
    );
  }
  if (
    record.state === "succeeded" &&
    record.safe_response_id === input.exclusionId &&
    record.safe_response_sha256
  ) {
    return {
      replayed: true,
      ...input,
      responseSha256: record.safe_response_sha256.toString("hex")
    };
  }
  throw new VoteRecusalTransactionError(
    "idempotency_in_progress",
    "identical recusal request is already in progress"
  );
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

export async function lockVoteRecusalRecipientsInTransaction(
  client: PoolClient,
  voteId: string,
  memberId: string,
  state: "excluded" | "lifted",
  boardLift = false
): Promise<LockedRecipientRow[]> {
  return (
    await client.query<LockedRecipientRow>(
      "select member_id,entitlement_generation::text from boardagent_lock_vote_recusal_recipients($1,$2,$3,$4)",
      [voteId, memberId, state, boardLift]
    )
  ).rows;
}

export async function manageVoteRecusalInTransaction(
  client: PoolClient,
  input: ManageVoteRecusalInput
): Promise<ManageVoteRecusalResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const memberId = UuidV7Schema.parse(input.memberId);
  const decisionPackageSha256 = Sha256HexSchema.parse(input.decisionPackageSha256);
  const requestedState = input.state;
  let state = requestedState;
  if (state !== "excluded" && state !== "lifted") {
    throw new TypeError("vote recusal state must be excluded or lifted");
  }
  const exclusionId = UuidV7Schema.parse(input.exclusionId);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const reason = canonicalText(input.reason);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("recusal reason must contain 1 through 65536 characters");
  }
  const stages = normalizeStages(input.stageDispositions);
  const proxies = normalizeProxies(input.proxyDispositions);
  const ballots = normalizeBallots(input.ballotDispositions);
  const tombstones = normalizeTombstones(input.feedTombstones);
  const deliveries = normalizeDeliveries(input.deliveries);
  const allGeneratedIds = [
    exclusionId,
    idempotencyRecordId,
    auditEventId,
    ...stages.flatMap(({ stageId, auditEventId: id }) => [stageId, id]),
    ...proxies.flatMap(({ proxyGrantId, proxyRevocationId, auditEventId: id }) => [
      proxyGrantId,
      proxyRevocationId,
      id
    ]),
    ...ballots.flatMap(({ ballotId, ballotDispositionId, auditEventId: id }) => [
      ballotId,
      ballotDispositionId,
      id
    ]),
    ...tombstones.flatMap(({ removedFeedId, tombstoneId }) => [removedFeedId, tombstoneId]),
    ...deliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
      noticeId,
      feedId,
      noticeAuditEventId
    ])
  ];
  if (new Set(allGeneratedIds).size !== allGeneratedIds.length) {
    throw new TypeError("recusal generated IDs must be globally unique");
  }
  const consentPayloadSha256 = input.boardCause
    ? Sha256HexSchema.parse(input.boardCause.payloadSha256)
    : voteRecusalConsentHash({
        voteId,
        memberId,
        state,
        reason,
        packageSha256: decisionPackageSha256
      });
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-recusal-request.v1",
    organizationId,
    voteId,
    memberId,
    state,
    exclusionId,
    reason,
    decisionPackageSha256,
    consentPayloadSha256,
    consentRecordId
  });
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new VoteRecusalTransactionError(
      "vote_recusal_unavailable",
      "vote recusal is unavailable"
    );
  }
  await client.query<LockedRecusalRow>(
    "select * from boardagent_lock_vote_for_recusal($1,$2,$3,$4)",
    [voteId, memberId, consentRecordId, Buffer.from(consentPayloadSha256, "hex")]
  );
  // A concurrent caller can begin this SELECT before the winning transaction commits.
  // The row lock serializes it, but the statement snapshot can still predate a newly
  // appended exclusion. Re-read in a fresh statement while retaining the vote lock.
  const lockResult = await client.query<LockedRecusalRow>(
    "select * from boardagent_lock_vote_for_recusal($1,$2,$3,$4)",
    [voteId, memberId, consentRecordId, Buffer.from(consentPayloadSha256, "hex")]
  );
  const locked = lockResult.rows[0];
  if (
    !locked ||
    lockResult.rows.length !== 1 ||
    locked.organization_id !== organizationId ||
    !locked.actor_ready ||
    !locked.consent_valid ||
    !safeHashEqual(locked.package_sha256.toString("hex"), decisionPackageSha256)
  ) {
    throw new VoteRecusalTransactionError(
      "vote_recusal_unavailable",
      "vote recusal is unavailable"
    );
  }
  const cause = await client.query<{ state: "excluded" | "lifted" | null; board_recused: boolean }>(
    `select (select coalesce(e.cause_requested_state,e.state) from vote_exclusions e
      where e.vote_id=$1 and e.member_id=$2 and e.source_board_exclusion_id is null
      order by e.version desc limit 1) as state,
      boardagent_member_board_recused($3,$2) as board_recused`,
    [voteId, memberId, locked.board_id]
  );
  const manualState = cause.rows[0]?.state;
  state =
    requestedState === "excluded" ||
    (input.boardCause ? manualState === "excluded" : cause.rows[0]?.board_recused)
      ? "excluded"
      : "lifted";
  const currentVersion = locked.current_exclusion_version ?? 0;
  const exclusionVersion = currentVersion + 1;
  if (!input.boardCause && manualState === requestedState) {
    if (locked.current_exclusion_id !== exclusionId) {
      throw new VoteRecusalTransactionError(
        "vote_recusal_invalid",
        "member already has a different current recusal state record"
      );
    }
    return (
      replayResult(
        await readIdempotency(client, context.memberId, context.clientId, idempotencyKey),
        requestSha256,
        { voteId, memberId, exclusionId, exclusionVersion: currentVersion, state }
      ) ??
      (() => {
        throw new VoteRecusalTransactionError(
          "vote_recusal_unavailable",
          "recusal replay evidence is unavailable"
        );
      })()
    );
  }
  if (
    !["open", "source_update_pending"].includes(locked.vote_state) ||
    (!input.boardCause && requestedState === "lifted" && manualState !== "excluded")
  ) {
    throw new VoteRecusalTransactionError(
      "vote_recusal_invalid",
      "requested recusal transition is not available"
    );
  }

  const activeStages = await client.query<ActiveStageRow>(
    `select id from action_stages
      where organization_id=$1 and board_id=$2 and target_type='vote' and target_id=$3
        and state='active' and (actor_member_id=$4 or acting_for_member_id=$4)
      order by id for update`,
    [organizationId, locked.board_id, voteId, memberId]
  );
  const activeProxies = await client.query<ActiveProxyRow>(
    `select proxy.id,proxy.principal_member_id,proxy.holder_member_id
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.organization_id=$1 and proxy.board_id=$2 and proxy.vote_id=$3
        and (proxy.principal_member_id=$4 or proxy.holder_member_id=$4)
        and revocation.id is null
      order by proxy.id`,
    [organizationId, locked.board_id, voteId, memberId]
  );
  const activeBallots = await client.query<ActiveBallotRow>(
    `select ballot.id,ballot.principal_member_id,ballot.caster_member_id
       from ballots as ballot
       left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
      where ballot.organization_id=$1 and ballot.board_id=$2 and ballot.vote_id=$3
        and (ballot.principal_member_id=$4
          or (ballot.ballot_source='proxy' and ballot.caster_member_id=$4))
        and disposition.id is null
      order by ballot.id`,
    [organizationId, locked.board_id, voteId, memberId]
  );
  const pendingFeeds = await client.query<PendingFeedRow>(
    `select id,entitlement_generation::text,feed_sequence::text,object_version::text
       from pending_action_feed
      where organization_id=$1 and board_id=$2 and member_id=$3
        and object_type='vote' and object_id=$4 and state='pending'
      order by id for update`,
    [organizationId, locked.board_id, memberId, voteId]
  );
  if (
    activeStages.rows.length !== stages.length ||
    activeStages.rows.some((row, index) => row.id !== stages[index]?.stageId) ||
    activeProxies.rows.length !== proxies.length ||
    activeProxies.rows.some((row, index) => row.id !== proxies[index]?.proxyGrantId) ||
    activeBallots.rows.length !== ballots.length ||
    activeBallots.rows.some((row, index) => row.id !== ballots[index]?.ballotId) ||
    pendingFeeds.rows.length !== tombstones.length ||
    pendingFeeds.rows.some((row, index) => row.id !== tombstones[index]?.removedFeedId)
  ) {
    throw new VoteRecusalTransactionError(
      "vote_recusal_invalid",
      "recusal dispositions do not cover every current affected projection"
    );
  }

  const expectedRecipients = await lockVoteRecusalRecipientsInTransaction(
    client,
    voteId,
    memberId,
    state,
    Boolean(input.boardCause && requestedState === "lifted")
  );
  if (
    expectedRecipients.length !== deliveries.length ||
    expectedRecipients.some((row, index) => row.member_id !== deliveries[index]?.memberId)
  ) {
    throw new VoteRecusalTransactionError(
      "vote_recusal_recipient_invalid",
      "recusal deliveries must cover every current entitled recipient exactly once"
    );
  }

  const insertedIdempotency = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'manage_recusal',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      idempotencyRecordId,
      organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  const existingIdempotency = await readIdempotency(
    client,
    context.memberId,
    context.clientId,
    idempotencyKey
  );
  if (!existingIdempotency) throw new Error("recusal idempotency record disappeared");
  if (insertedIdempotency.rowCount === 0) {
    const replayed = replayResult(existingIdempotency, requestSha256, {
      voteId,
      memberId,
      exclusionId,
      exclusionVersion,
      state
    });
    if (replayed) return replayed;
  }

  await client.query(
    `insert into vote_exclusions(
       id,organization_id,board_id,vote_id,member_id,version,state,reason,
       actor_member_id,consent_record_id,cause_requested_state,source_board_exclusion_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [
      exclusionId,
      organizationId,
      locked.board_id,
      voteId,
      memberId,
      exclusionVersion,
      state,
      reason,
      context.memberId,
      consentRecordId,
      requestedState,
      input.boardCause ? UuidV7Schema.parse(input.boardCause.exclusionId) : null
    ]
  );
  for (const [index, disposition] of stages.entries()) {
    const updated = await client.query(
      "update action_stages set state='replaced' where id=$1 and state='active'",
      [activeStages.rows[index]?.id]
    );
    if (updated.rowCount !== 1 || activeStages.rows[index]?.id !== disposition.stageId) {
      throw new VoteRecusalTransactionError(
        "vote_recusal_unavailable",
        "an affected stage changed during recusal"
      );
    }
  }
  for (const [index, disposition] of proxies.entries()) {
    const proxy = activeProxies.rows[index]!;
    await client.query(
      `insert into proxy_revocations(
         id,organization_id,grant_id,revoker_member_id,reason,effect,consent_record_id
       ) values ($1,$2,$3,$4,$5,'revoked',$6)`,
      [
        disposition.proxyRevocationId,
        organizationId,
        proxy.id,
        context.memberId,
        reason,
        consentRecordId
      ]
    );
  }
  for (const [index, disposition] of ballots.entries()) {
    await client.query(
      `insert into ballot_dispositions(
         id,prior_ballot_id,reason,effect,audit_event_id
       ) values ($1,$2,$3,'invalidated_by_recusal',$4)`,
      [
        disposition.ballotDispositionId,
        activeBallots.rows[index]!.id,
        reason,
        disposition.auditEventId
      ]
    );
  }
  const updatedVote = await client.query<{ row_version: string; changed_at: string }>(
    `update votes set row_version=row_version+1
      where id=$1 and row_version=$2::bigint and state in ('open','source_update_pending')
      returning row_version::text,
        to_char(transaction_timestamp() at time zone 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as changed_at`,
    [voteId, locked.vote_row_version]
  );
  const changedVote = updatedVote.rows[0];
  if (!changedVote || updatedVote.rows.length !== 1) {
    throw new VoteRecusalTransactionError(
      "vote_recusal_unavailable",
      "vote changed during recusal"
    );
  }
  const voteObjectVersion = BigInt(changedVote.row_version);
  for (const [index, tombstone] of tombstones.entries()) {
    const feed = pendingFeeds.rows[index]!;
    const updatedFeed = await client.query(
      `update pending_action_feed
          set state='superseded',resolved_at=transaction_timestamp()
        where id=$1 and state='pending'`,
      [feed.id]
    );
    if (updatedFeed.rowCount !== 1) {
      throw new VoteRecusalTransactionError(
        "vote_recusal_unavailable",
        "an affected feed changed during recusal"
      );
    }
    const tombstoneSha256 = canonicalSha256({
      schemaVersion: "boardagent.feed-tombstone.v1",
      removedFeedId: feed.id,
      voteId,
      memberId,
      exclusionId,
      exclusionVersion,
      reasonClass: "recused"
    });
    await client.query(
      `insert into feed_tombstones(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,$7,'vote',$8,'recused',$9,$10)`,
      [
        tombstone.tombstoneId,
        organizationId,
        locked.board_id,
        memberId,
        feed.entitlement_generation,
        feed.feed_sequence,
        feed.id,
        voteId,
        Buffer.from(tombstoneSha256, "hex"),
        auditEventId
      ]
    );
  }

  const electorateRows = await client.query<ElectorateEligibilityRow>(
    `select electorate.member_id,electorate.voting_weight::text,
            coalesce((
              select exclusion.state='excluded'
                from vote_exclusions as exclusion
               where exclusion.vote_id=electorate.vote_id
                 and exclusion.member_id=electorate.member_id
               order by exclusion.version desc,exclusion.id desc
               limit 1
            ),false) as recused
       from vote_electorate as electorate
      where electorate.vote_id=$1
      order by electorate.member_id`,
    [voteId]
  );
  if (electorateRows.rows.length < 1) {
    throw new Error("recusal electorate disappeared during eligibility recomputation");
  }
  const eligibleWeight = eligibleVotingWeight(
    electorateRows.rows.map((row) => ({
      memberId: row.member_id,
      role: "voting_member",
      weight: BigInt(row.voting_weight),
      eligible: true,
      recused: row.recused,
      chair: false
    }))
  );

  const auditInputs: AuditAppendInput[] = [];
  for (const [index, disposition] of stages.entries()) {
    auditInputs.push({
      organizationId,
      consentRecordId,
      event: {
        eventId: disposition.auditEventId,
        eventType: "stage_replaced",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "action_stage",
        entityId: activeStages.rows[index]!.id,
        boardId: locked.board_id,
        origin: "mcp",
        details: { voteId, memberId, reason: "live_recusal" },
        schemaVersion: 1
      }
    });
  }
  for (const [index, disposition] of proxies.entries()) {
    const proxy = activeProxies.rows[index]!;
    auditInputs.push({
      organizationId,
      consentRecordId,
      actingForMemberId: proxy.principal_member_id,
      event: {
        eventId: disposition.auditEventId,
        eventType: "proxy_revoked",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "proxy_grant",
        entityId: proxy.id,
        boardId: locked.board_id,
        origin: "mcp",
        details: { voteId, memberId, effect: "revoked_by_recusal" },
        schemaVersion: 1
      }
    });
  }
  for (const [index, disposition] of ballots.entries()) {
    const ballot = activeBallots.rows[index]!;
    auditInputs.push({
      organizationId,
      consentRecordId,
      actingForMemberId:
        ballot.principal_member_id === ballot.caster_member_id ? null : ballot.principal_member_id,
      event: {
        eventId: disposition.auditEventId,
        eventType: "ballot_superseded",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "ballot",
        entityId: ballot.id,
        boardId: locked.board_id,
        origin: "mcp",
        details: { voteId, memberId, effect: "invalidated_by_recusal" },
        schemaVersion: 1
      }
    });
  }
  auditInputs.push({
    organizationId,
    consentRecordId,
    objectVersion: voteObjectVersion,
    event: {
      eventId: auditEventId,
      eventType: "recusal_changed",
      actorMemberId: context.memberId,
      actorClientId: context.clientId,
      tokenJti: context.tokenJti,
      entityType: "vote",
      entityId: voteId,
      boardId: locked.board_id,
      origin: "mcp",
      details: {
        memberId,
        exclusionId,
        exclusionVersion,
        state,
        reason,
        decisionPackageId: locked.decision_package_id,
        packageSha256: decisionPackageSha256,
        eligibleWeight: eligibleWeight.toString(10),
        invalidatedStageCount: stages.length,
        invalidatedProxyCount: proxies.length,
        invalidatedBallotCount: ballots.length,
        tombstoneCount: tombstones.length
      },
      schemaVersion: 1
    }
  });

  const recipientByMember = new Map(
    expectedRecipients.map((recipient) => [recipient.member_id, recipient] as const)
  );
  for (const delivery of deliveries) {
    const recipient = recipientByMember.get(delivery.memberId)!;
    const generation = Number(recipient.entitlement_generation);
    if (!Number.isSafeInteger(generation) || generation < 1) {
      throw new Error("recusal recipient entitlement generation is invalid");
    }
    const actionRequired = state === "lifted" && delivery.memberId === memberId;
    const sequence = await nextFeedSequence(client, locked.board_id, delivery.memberId);
    const safeRefs = {
      voteId,
      memberId,
      decisionPackageId: locked.decision_package_id,
      packageSha256: decisionPackageSha256,
      exclusionId,
      exclusionVersion,
      eligibleWeight: Number(eligibleWeight)
    } as const;
    if (!Number.isSafeInteger(safeRefs.eligibleWeight)) {
      throw new Error("recusal eligible weight exceeds the safe feed reference range");
    }
    const payload = PendingActionDeltaSchema.parse({
      schemaVersion: "boardagent.pending-action.v1",
      sequence: sequence.toString(10),
      deltaType: actionRequired ? "action_required" : "notice",
      objectType: "vote",
      objectId: voteId,
      objectVersion: Number(voteObjectVersion),
      entitlementGeneration: generation,
      actionState: actionRequired ? "pending" : "informational",
      safeRefs,
      createdAt: changedVote.changed_at
    });
    const noticeSha256 = canonicalSha256({
      noticeType: "recusal_changed",
      recipientMemberId: delivery.memberId,
      state,
      ...safeRefs
    });
    const visibilitySha256 = canonicalSha256({
      boardId: locked.board_id,
      voteId,
      recipientMemberId: delivery.memberId,
      entitlementGeneration: generation
    });
    await client.query(
      `insert into notices(
         id,organization_id,board_id,notice_type,object_type,object_id,object_version,
         recipient_member_id,content_sha256,feed_sequence,audit_event_id
       ) values ($1,$2,$3,'recusal_changed','vote',$4,$5,$6,$7,$8,$9)`,
      [
        delivery.noticeId,
        organizationId,
        locked.board_id,
        voteId,
        voteObjectVersion.toString(10),
        delivery.memberId,
        Buffer.from(noticeSha256, "hex"),
        sequence.toString(10),
        delivery.noticeAuditEventId
      ]
    );
    const canonicalPayload = canonicalJson(payload);
    await client.query(
      `insert into pending_action_feed(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         action_type,object_type,object_id,object_version,visibility_sha256,
         canonical_payload,payload_sha256,state,notice_id,audit_event_id,resolved_at
       ) values ($1,$2,$3,$4,$5,$6,'recusal_changed','vote',$7,$8,$9,$10,$11,$12,$13,
         $14,$15)`,
      [
        delivery.feedId,
        organizationId,
        locked.board_id,
        delivery.memberId,
        generation,
        sequence.toString(10),
        voteId,
        voteObjectVersion.toString(10),
        Buffer.from(visibilitySha256, "hex"),
        Buffer.from(canonicalPayload, "utf8"),
        Buffer.from(canonicalSha256(payload), "hex"),
        actionRequired ? "pending" : "resolved",
        delivery.noticeId,
        delivery.noticeAuditEventId,
        actionRequired ? null : changedVote.changed_at
      ]
    );
    auditInputs.push({
      organizationId,
      consentRecordId,
      objectVersion: voteObjectVersion,
      event: {
        eventId: delivery.noticeAuditEventId,
        eventType: "notice_delivered",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: voteId,
        boardId: locked.board_id,
        origin: "mcp",
        details: {
          noticeType: "recusal_changed",
          recipientMemberId: delivery.memberId,
          feedSequence: sequence.toString(10),
          recusalState: state,
          actionRequired,
          ...safeRefs
        },
        schemaVersion: 1
      }
    });
  }

  const auditEvents = await appendAuditEventsInTransaction(client, auditInputs);
  const safeResponse = {
    voteId,
    memberId,
    exclusionId,
    exclusionVersion,
    state,
    eligibleWeight
  };
  const responseSha256 = canonicalSha256({
    ...safeResponse,
    eligibleWeight: eligibleWeight.toString(10)
  });
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='vote_exclusion',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4 and operation='manage_recusal'
        and idempotency_key=$5 and state='in_progress'`,
    [
      exclusionId,
      Buffer.from(responseSha256, "hex"),
      context.memberId,
      context.clientId,
      idempotencyKey
    ]
  );
  if (completed.rowCount !== 1) throw new Error("recusal idempotency completion failed");
  return { replayed: false, ...safeResponse, responseSha256, auditEvents };
}
