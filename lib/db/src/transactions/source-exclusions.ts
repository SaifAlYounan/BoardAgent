import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex
} from "@boardagent/contracts";
import { voteSourceExclusionConsentHash } from "@boardagent/domain";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export class VoteSourceExclusionTransactionError extends Error {
  public constructor(
    public readonly code:
      | "vote_source_exclusion_unavailable"
      | "vote_source_exclusion_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "VoteSourceExclusionTransactionError";
  }
}

export interface ExcludePendingVoteSourceInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly causeId: string;
  readonly decisionPackageSha256: string;
  readonly reason: string;
  readonly consentRecordId: string;
  readonly dispositionId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export type ExcludePendingVoteSourceResult =
  | {
      readonly replayed: true;
      readonly voteId: string;
      readonly causeId: string;
      readonly dispositionId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly voteId: string;
      readonly causeId: string;
      readonly dispositionId: string;
      readonly sourceClass: "management_submission" | "document" | "question_cutoff";
      readonly remainingPendingSources: number;
      readonly voteState: "open" | "source_update_pending";
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
  readonly actor_ready: boolean;
}

interface SourceCauseRow {
  readonly cause_id: string;
  readonly source_class: "management_submission" | "document" | "question_cutoff";
  readonly source_id: string;
  readonly source_version: number;
  readonly source_sha256: Buffer;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function uniqueGeneratedIds(values: readonly string[]): readonly string[] {
  const parsed = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(parsed).size !== parsed.length) {
    throw new TypeError("source-exclusion generated IDs must be globally unique");
  }
  return parsed;
}

async function lockVoteRoot(client: PoolClient, voteId: string): Promise<VoteRootRow | undefined> {
  const query = `select vote.organization_id,vote.board_id,vote.state as vote_state,
                        vote.row_version::text as vote_row_version,
                        package.id as decision_package_id,package.package_sha256,
                        boardagent_vote_actor_ready(vote.board_id) as actor_ready
                   from votes as vote
                   join decision_packages as package
                     on package.id=vote.current_decision_package_id and package.vote_id=vote.id
                  where vote.id=$1
                    and vote.organization_id=boardagent_context_uuid('boardagent.organization_id')
                    and boardagent_context_board_allowed(vote.board_id)
                  for update of vote`;
  await client.query<VoteRootRow>(query, [voteId]);
  const refreshed = await client.query<VoteRootRow>(query, [voteId]);
  return refreshed.rows.length === 1 ? refreshed.rows[0] : undefined;
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='exclude_pending_vote_source' and idempotency_key=$3
      for update`,
    [actorMemberId, clientId, key]
  );
  return result.rows[0];
}

function replayResult(
  row: IdempotencyRow | undefined,
  requestSha256: string,
  voteId: string,
  causeId: string
): ExcludePendingVoteSourceResult | undefined {
  if (!row) return undefined;
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new VoteSourceExclusionTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different source exclusion"
    );
  }
  if (
    row.state === "succeeded" &&
    row.safe_response_type === "vote_source_update_disposition" &&
    row.safe_response_id &&
    row.safe_response_sha256
  ) {
    return {
      replayed: true,
      voteId,
      causeId,
      dispositionId: row.safe_response_id,
      responseSha256: row.safe_response_sha256.toString("hex")
    };
  }
  throw new VoteSourceExclusionTransactionError(
    "idempotency_in_progress",
    "identical source exclusion is already in progress"
  );
}

async function consentValid(
  client: PoolClient,
  input: {
    readonly consentRecordId: string;
    readonly voteId: string;
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
          and consent.action_code='exclude_pending_vote_source'
          and consent.target_type='vote'
          and consent.target_id=$2
          and consent.payload_sha256=$3
          and consent.package_sha256=$4
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
          and attempt.original_name='exclude_pending_vote_source'
          and attempt.response_action='accept'
          and attempt.state='confirmed'
     ) as valid`,
    [
      input.consentRecordId,
      input.voteId,
      Buffer.from(input.payloadSha256, "hex"),
      Buffer.from(input.packageSha256, "hex")
    ]
  );
  return result.rows[0]?.valid === true;
}

async function insertIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<void> {
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'exclude_pending_vote_source',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      input.id,
      input.organizationId,
      input.actorMemberId,
      input.clientId,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
  const row = await readIdempotency(client, input.actorMemberId, input.clientId, input.key);
  if (!row) throw new Error("source-exclusion idempotency record disappeared");
  if (inserted.rowCount === 0) {
    if (!safeHashEqual(row.request_sha256.toString("hex"), input.requestSha256)) {
      throw new VoteSourceExclusionTransactionError(
        "idempotency_conflict",
        "idempotency key was already used for a different source exclusion"
      );
    }
    throw new VoteSourceExclusionTransactionError(
      "idempotency_in_progress",
      "identical source exclusion is already in progress"
    );
  }
  if (!safeHashEqual(row.request_sha256.toString("hex"), input.requestSha256)) {
    throw new VoteSourceExclusionTransactionError(
      "idempotency_conflict",
      "source-exclusion idempotency record does not bind this request"
    );
  }
}

async function finishIdempotency(
  client: PoolClient,
  id: string,
  dispositionId: string,
  responseSha256: string
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='vote_source_update_disposition',
            safe_response_id=$1,safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [dispositionId, Buffer.from(responseSha256, "hex"), id]
  );
  if (result.rowCount !== 1) throw new Error("source-exclusion idempotency completion failed");
}

export async function excludePendingVoteSourceInTransaction(
  client: PoolClient,
  input: ExcludePendingVoteSourceInput
): Promise<ExcludePendingVoteSourceResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const causeId = UuidV7Schema.parse(input.causeId);
  const decisionPackageSha256 = Sha256HexSchema.parse(input.decisionPackageSha256);
  const reason = canonicalText(input.reason);
  if (reason.trim().length < 1 || reason.length > 65_536) {
    throw new RangeError("source-exclusion reason must contain 1 through 65536 characters");
  }
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const [dispositionId, idempotencyRecordId, auditEventId] = uniqueGeneratedIds([
    input.dispositionId,
    input.idempotencyRecordId,
    input.auditEventId
  ]) as readonly [string, string, string];
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new VoteSourceExclusionTransactionError(
      "vote_source_exclusion_unavailable",
      "pending vote source is unavailable"
    );
  }
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-source-exclusion-request.v1",
    organizationId,
    voteId,
    causeId,
    decisionPackageSha256,
    reason,
    consentRecordId
  });
  const vote = await lockVoteRoot(client, voteId);
  if (
    !vote ||
    vote.organization_id !== organizationId ||
    !vote.actor_ready ||
    !safeHashEqual(vote.package_sha256.toString("hex"), decisionPackageSha256)
  ) {
    throw new VoteSourceExclusionTransactionError(
      "vote_source_exclusion_unavailable",
      "pending vote source is unavailable"
    );
  }
  const replay = replayResult(
    await readIdempotency(client, context.memberId, context.clientId, idempotencyKey),
    requestSha256,
    voteId,
    causeId
  );
  if (replay) return replay;
  if (vote.vote_state !== "source_update_pending") {
    throw new VoteSourceExclusionTransactionError(
      "vote_source_exclusion_invalid",
      "vote has no pending source-update disposition state"
    );
  }
  const pending = await client.query<SourceCauseRow>(
    "select * from boardagent_lock_vote_source_causes($1)",
    [voteId]
  );
  const cause = pending.rows.find((row) => row.cause_id === causeId);
  if (!cause) {
    throw new VoteSourceExclusionTransactionError(
      "vote_source_exclusion_unavailable",
      "exact pending vote source is unavailable"
    );
  }
  const sourceSha256 = cause.source_sha256.toString("hex");
  const consentPayloadSha256 = voteSourceExclusionConsentHash({
    voteId,
    causeId,
    sourceClass: cause.source_class,
    sourceId: cause.source_id,
    sourceVersion: cause.source_version,
    sourceSha256,
    reason,
    packageSha256: decisionPackageSha256
  });
  if (
    !(await consentValid(client, {
      consentRecordId,
      voteId,
      payloadSha256: consentPayloadSha256,
      packageSha256: decisionPackageSha256
    }))
  ) {
    throw new VoteSourceExclusionTransactionError(
      "vote_source_exclusion_unavailable",
      "confirmed source exclusion is unavailable"
    );
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    key: idempotencyKey,
    requestSha256
  });
  await client.query(
    `insert into vote_source_update_dispositions(
       id,organization_id,board_id,cause_id,source_vote_id,replacement_vote_id,effect,
       consent_record_id,reason,audit_event_id
     ) values ($1,$2,$3,$4,$5,null,'excluded',$6,$7,$8)`,
    [
      dispositionId,
      organizationId,
      vote.board_id,
      causeId,
      voteId,
      consentRecordId,
      reason,
      auditEventId
    ]
  );
  const remainingPendingSources = pending.rows.length - 1;
  const voteState = remainingPendingSources === 0 ? "open" : "source_update_pending";
  const updated = await client.query<{ row_version: string }>(
    `update votes
        set state=$1,row_version=row_version+1
      where id=$2 and state='source_update_pending' and row_version=$3::bigint
      returning row_version::text`,
    [voteState, voteId, vote.vote_row_version]
  );
  const nextVersion = updated.rows[0]?.row_version;
  if (!nextVersion || updated.rows.length !== 1) {
    throw new VoteSourceExclusionTransactionError(
      "vote_source_exclusion_unavailable",
      "vote changed during source exclusion"
    );
  }
  const responseSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-source-exclusion-result.v1",
    voteId,
    causeId,
    dispositionId,
    sourceClass: cause.source_class,
    sourceId: cause.source_id,
    sourceVersion: cause.source_version,
    sourceSha256,
    decisionPackageId: vote.decision_package_id,
    decisionPackageSha256,
    remainingPendingSources,
    voteState,
    voteVersion: nextVersion
  });
  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      consentRecordId,
      objectVersion: BigInt(nextVersion),
      event: {
        eventId: auditEventId,
        eventType: "vote_source_excluded",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: voteId,
        boardId: vote.board_id,
        origin: "mcp",
        details: {
          causeId,
          dispositionId,
          sourceClass: cause.source_class,
          sourceId: cause.source_id,
          sourceVersion: cause.source_version,
          sourceSha256,
          reasonSha256: sha256Hex(reason),
          decisionPackageId: vote.decision_package_id,
          decisionPackageSha256,
          remainingPendingSources,
          voteState,
          responseSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  await finishIdempotency(client, idempotencyRecordId, dispositionId, responseSha256);
  return {
    replayed: false,
    voteId,
    causeId,
    dispositionId,
    sourceClass: cause.source_class,
    remainingPendingSources,
    voteState,
    responseSha256,
    auditEvents
  };
}
