import { randomBytes } from "node:crypto";

import type { PoolClient } from "pg";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  parseTranscriptAnnex,
  safeHashEqual,
  sha256Hex,
  type JsonValue,
  type TranscriptMediaType
} from "@boardagent/contracts";
import { uuidV7 } from "@boardagent/domain";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StagedAction,
  type StagedActionResolution,
  type StageActionInput
} from "./consent.js";
import {
  refreshMinutesTranscriptAnnexInTransaction,
  type TranscriptMinutesRefreshResult
} from "./minutes-lifecycle.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

const MAX_IDEMPOTENCY_KEY = 200;

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

export class TranscriptTransactionError extends Error {
  public constructor(
    public readonly code:
      | "transcript_contribution_unavailable"
      | "transcript_challenge_unavailable"
      | "transcript_action_unavailable"
      | "transcript_action_invalid"
      | "idempotency_conflict",
    message: string
  ) {
    super(message);
    this.name = "TranscriptTransactionError";
  }
}

export interface CreateMeetingTranscriptVersionInput {
  readonly meetingId: string;
  readonly transcriptId: string;
  readonly transcriptVersionId: string;
  readonly mediaType: TranscriptMediaType;
  readonly canonicalBody: string;
  readonly coverageStatement: string;
  readonly supersedesVersionId: string | null;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface ChallengeTranscriptTurnInput {
  readonly transcriptVersionId: string;
  readonly turnId: string;
  readonly comment: string;
  readonly challengeId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface TranscriptMinutesRefreshView {
  readonly minutesId: string;
  readonly minutesVersionId: string;
  readonly version: number;
  readonly canonicalSha256: string;
  readonly packageBaseSha256: string;
  readonly state: "unpublished_draft" | "published_review";
}

export type DirectTranscriptResult =
  | {
      readonly kind: "version";
      readonly replayed: boolean;
      readonly boardId: string;
      readonly meetingId: string;
      readonly transcriptId: string;
      readonly transcriptVersionId: string;
      readonly version: number;
      readonly mediaType: TranscriptMediaType;
      readonly canonicalSchema:
        "boardagent.transcript-markdown.v1" | "boardagent.transcript-turns.v1";
      readonly canonicalSha256: string;
      readonly coverageStatement: string;
      readonly turnIds: readonly string[];
      readonly responseSha256: string;
      readonly minutesRefresh: TranscriptMinutesRefreshView | null;
    }
  | {
      readonly kind: "challenge";
      readonly replayed: boolean;
      readonly boardId: string;
      readonly transcriptId: string;
      readonly transcriptVersionId: string;
      readonly turnId: string;
      readonly challengeId: string;
      readonly commentSha256: string;
      readonly responseSha256: string;
    };

export type TranscriptLifecycleAction =
  | {
      readonly kind: "verification";
      readonly transcriptId: string;
      readonly versionId: string;
      readonly sha256: string;
      readonly verificationStatement: "secretary_verified_annex_hash";
    }
  | {
      readonly kind: "qna_link";
      readonly transcriptVersionId: string;
      readonly turnIds: readonly string[];
      readonly questionId: string;
    }
  | {
      readonly kind: "challenge_resolution";
      readonly challengeId: string;
      readonly decision: "accepted" | "rejected";
      readonly reason: string;
      readonly correctedVersionId: string | null;
    };

export interface TranscriptLifecycleStageInput {
  readonly action: TranscriptLifecycleAction;
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

export interface TranscriptLifecycleConfirmationInput {
  readonly action: TranscriptLifecycleAction;
  readonly confirmation: ConfirmStagedActionInput;
}

export interface PreparedTranscriptLifecycleAction {
  readonly actionCode:
    "verify_meeting_transcript" | "link_meeting_qna" | "resolve_transcript_challenge";
  readonly boardId: string;
  readonly targetType: "meeting_transcript" | "transcript_challenge";
  readonly targetId: string;
  readonly canonicalSchema: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
}

export interface StagedTranscriptLifecycleAction extends StagedAction {
  readonly actionCode: PreparedTranscriptLifecycleAction["actionCode"];
  readonly boardId: string;
  readonly targetType: PreparedTranscriptLifecycleAction["targetType"];
  readonly targetId: string;
}

export type TranscriptLifecycleResult =
  | {
      readonly kind: "verification";
      readonly verificationId: string;
      readonly transcriptId: string;
      readonly versionId: string;
      readonly sha256: string;
      readonly state: "secretary_verified";
      readonly rowVersion: number;
    }
  | {
      readonly kind: "qna_link";
      readonly linkId: string;
      readonly transcriptId: string;
      readonly transcriptVersionId: string;
      readonly turnIds: readonly string[];
      readonly turnsSha256: string;
      readonly questionId: string;
      readonly managementQuestionSha256: string;
      readonly managementActionPreserved: boolean;
    }
  | {
      readonly kind: "challenge_resolution";
      readonly dispositionId: string;
      readonly challengeId: string;
      readonly state: "accepted" | "rejected";
      readonly correctedVersionId: string | null;
    };

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface CompletedIdempotencyRow extends IdempotencyRow {
  readonly safe_response_id: string;
  readonly safe_response_sha256: Buffer;
}

interface TranscriptRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly meeting_id: string;
  readonly transcript_id: string;
  readonly state: "unverified" | "secretary_verified";
  readonly current_version_id: string;
  readonly row_version: string;
  readonly version: number;
  readonly canonical_sha256: Buffer;
  readonly supersedes_id: string | null;
}

interface PreparedInternal extends PreparedTranscriptLifecycleAction {
  readonly action: TranscriptLifecycleAction;
  readonly context: ActiveRequestContext;
  readonly organizationId: string;
  readonly details: PreparedDetails;
}

type PreparedDetails =
  | { readonly kind: "verification"; readonly root: TranscriptRootRow }
  | {
      readonly kind: "qna_link";
      readonly root: TranscriptRootRow;
      readonly turns: readonly TranscriptTurnRow[];
      readonly turnsSha256: string;
      readonly questionSha256: string;
      readonly managementActionPreserved: boolean;
    }
  | {
      readonly kind: "challenge_resolution";
      readonly root: TranscriptRootRow;
      readonly challenge: ChallengeRow;
      readonly correctedSha256: string | null;
    };

interface TranscriptTurnRow {
  readonly id: string;
  readonly ordinal: number;
  readonly text_sha256: Buffer;
}

interface ChallengeRow {
  readonly id: string;
  readonly transcript_version_id: string;
  readonly turn_id: string;
  readonly challenger_member_id: string;
  readonly canonical_comment: string;
  readonly comment_sha256: Buffer;
  readonly state: "pending";
}

function idempotencyKey(value: string): string {
  if (
    value.length < 16 ||
    value.length > MAX_IDEMPOTENCY_KEY ||
    !/^[A-Za-z0-9._~-]+$/u.test(value)
  ) {
    throw new RangeError("idempotency key must contain 16 through 200 safe characters");
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

async function existingIdempotency(
  client: PoolClient,
  context: ActiveRequestContext,
  operation: "create_meeting_transcript_version" | "challenge_transcript_turn",
  key: string,
  requestSha256: string
): Promise<CompletedIdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      for update`,
    [context.memberId, context.clientId, operation, key]
  );
  const row = result.rows[0];
  if (!row) return undefined;
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new TranscriptTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for different transcript bytes"
    );
  }
  if (row.state !== "succeeded" || !row.safe_response_id || !row.safe_response_sha256) {
    throw new TranscriptTransactionError(
      "idempotency_conflict",
      "identical transcript operation is not a completed safe response"
    );
  }
  return {
    ...row,
    safe_response_id: row.safe_response_id,
    safe_response_sha256: row.safe_response_sha256
  };
}

async function insertIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly context: ActiveRequestContext;
    readonly operation: "create_meeting_transcript_version" | "challenge_transcript_turn";
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<void> {
  await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'in_progress',transaction_timestamp()+interval '24 hours')`,
    [
      input.id,
      input.context.organizationId,
      input.context.memberId,
      input.context.clientId,
      input.operation,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
}

async function completeIdempotency(
  client: PoolClient,
  id: string,
  responseType: "meeting_transcript_version" | "transcript_challenge",
  responseId: string,
  responseSha256: string
): Promise<void> {
  const updated = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type=$1,safe_response_id=$2,
            safe_response_sha256=$3,completed_at=transaction_timestamp()
      where id=$4 and state='in_progress'`,
    [responseType, responseId, Buffer.from(responseSha256, "hex"), id]
  );
  if (updated.rowCount !== 1) throw new Error("transcript idempotency completion failed");
}

function directAudit(input: {
  readonly context: ActiveRequestContext;
  readonly organizationId: string;
  readonly boardId: string;
  readonly eventId: string;
  readonly eventType: "transcript_version_created" | "transcript_turn_challenged";
  readonly entityType: "meeting_transcript" | "transcript_challenge";
  readonly entityId: string;
  readonly objectVersion: bigint;
  readonly details: Readonly<Record<string, JsonValue>>;
}): AuditAppendInput {
  return {
    organizationId: input.organizationId,
    objectVersion: input.objectVersion,
    event: {
      eventId: input.eventId,
      eventType: input.eventType,
      actorMemberId: input.context.memberId,
      actorClientId: input.context.clientId,
      tokenJti: input.context.tokenJti,
      entityType: input.entityType,
      entityId: input.entityId,
      boardId: input.boardId,
      origin: "mcp",
      details: input.details,
      schemaVersion: 1
    }
  };
}

function refreshView(
  value: TranscriptMinutesRefreshResult | null
): TranscriptMinutesRefreshView | null {
  if (value === null) return null;
  return {
    minutesId: value.minutesId,
    minutesVersionId: value.minutesVersionId,
    version: value.version,
    canonicalSha256: value.canonicalSha256,
    packageBaseSha256: value.packageBaseSha256,
    state: value.state
  };
}

export async function createMeetingTranscriptVersionInTransaction(
  client: PoolClient,
  input: CreateMeetingTranscriptVersionInput
): Promise<Extract<DirectTranscriptResult, { readonly kind: "version" }>> {
  const meetingId = UuidV7Schema.parse(input.meetingId);
  const transcriptId = UuidV7Schema.parse(input.transcriptId);
  const transcriptVersionId = UuidV7Schema.parse(input.transcriptVersionId);
  const supersedesVersionId =
    input.supersedesVersionId === null ? null : UuidV7Schema.parse(input.supersedesVersionId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const coverageStatement = boundedCanonicalText(
    input.coverageStatement,
    "transcript coverage statement",
    1024
  );
  const annex = parseTranscriptAnnex(input.mediaType, input.canonicalBody);
  const canonicalSha256Hex = sha256Hex(annex.canonicalBody);
  const context = await readRequestContext(client);
  const meetingResult = await client.query<{
    organization_id: string;
    board_id: string;
    state: "called" | "completed";
  }>(
    `select organization_id,board_id,state
       from meetings
      where id=$1 and state in ('called','completed')
        and boardagent_meeting_secretary_for_board(board_id)
      for update`,
    [meetingId]
  );
  const meeting = meetingResult.rows[0];
  if (!meeting || meetingResult.rows.length !== 1) {
    throw new TranscriptTransactionError(
      "transcript_contribution_unavailable",
      "transcript annex contribution is unavailable"
    );
  }
  const requestPayload = {
    schemaVersion: "boardagent.transcript-version-request.v1",
    meetingId,
    transcriptId,
    mediaType: input.mediaType,
    canonicalSchema: annex.canonicalSchema,
    canonicalBody: annex.canonicalBody,
    canonicalSha256: canonicalSha256Hex,
    coverageStatement,
    supersedesVersionId
  };
  const requestSha256 = canonicalSha256(requestPayload);
  const replay = await existingIdempotency(
    client,
    context,
    "create_meeting_transcript_version",
    key,
    requestSha256
  );
  if (replay) {
    const versionResult = await client.query<{
      transcript_id: string;
      version: number;
      media_type: TranscriptMediaType;
      canonical_schema: "boardagent.transcript-markdown.v1" | "boardagent.transcript-turns.v1";
      canonical_sha256: Buffer;
      coverage_statement: string;
    }>(
      `select transcript_id,version,media_type,canonical_schema,canonical_sha256,
              coverage_statement
         from meeting_transcript_versions where id=$1`,
      [replay.safe_response_id]
    );
    const version = versionResult.rows[0];
    if (!version || versionResult.rows.length !== 1) {
      throw new Error("replayed transcript version evidence disappeared");
    }
    const turns = await client.query<{ id: string }>(
      "select id from transcript_turns where transcript_version_id=$1 order by ordinal",
      [replay.safe_response_id]
    );
    return {
      kind: "version",
      replayed: true,
      boardId: meeting.board_id,
      meetingId,
      transcriptId: version.transcript_id,
      transcriptVersionId: replay.safe_response_id,
      version: version.version,
      mediaType: version.media_type,
      canonicalSchema: version.canonical_schema,
      canonicalSha256: version.canonical_sha256.toString("hex"),
      coverageStatement: version.coverage_statement,
      turnIds: turns.rows.map(({ id }) => id),
      responseSha256: replay.safe_response_sha256!.toString("hex"),
      minutesRefresh: null
    };
  }

  const rootResult = await client.query<TranscriptRootRow>(
    `select transcript.organization_id,transcript.board_id,transcript.meeting_id,
            transcript.id as transcript_id,transcript.state,
            transcript.current_version_id,transcript.row_version::text,
            version.version,version.canonical_sha256,version.supersedes_id
       from meeting_transcripts as transcript
       join meeting_transcript_versions as version on version.id=transcript.current_version_id
      where transcript.meeting_id=$1
      for update of transcript`,
    [meetingId]
  );
  const root = rootResult.rows[0];
  let version = 1;
  if (root) {
    if (
      rootResult.rows.length !== 1 ||
      root.transcript_id !== transcriptId ||
      supersedesVersionId !== root.current_version_id
    ) {
      throw new TranscriptTransactionError(
        "transcript_contribution_unavailable",
        "a successor annex must name the exact current transcript and version"
      );
    }
    version = root.version + 1;
  } else if (supersedesVersionId !== null) {
    throw new TranscriptTransactionError(
      "transcript_contribution_unavailable",
      "the first transcript annex cannot supersede a version"
    );
  }

  await insertIdempotency(client, {
    id: idempotencyRecordId,
    context,
    operation: "create_meeting_transcript_version",
    key,
    requestSha256
  });
  if (!root) {
    await client.query(
      `insert into meeting_transcripts(
         id,organization_id,board_id,meeting_id,state,current_version_id,row_version
       ) values ($1,$2,$3,$4,'unverified',$5,1)`,
      [transcriptId, meeting.organization_id, meeting.board_id, meetingId, transcriptVersionId]
    );
  }
  await client.query(
    `insert into meeting_transcript_versions(
       id,organization_id,board_id,transcript_id,version,canonical_schema,media_type,
       canonical_bytes,canonical_sha256,source_type,coverage_start,coverage_end,
       verification_state,created_by,supersedes_id,coverage_statement
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'agent_prepared',null,null,
       'agent_prepared_unverified',$10,$11,$12)`,
    [
      transcriptVersionId,
      meeting.organization_id,
      meeting.board_id,
      transcriptId,
      version,
      annex.canonicalSchema,
      input.mediaType,
      Buffer.from(annex.canonicalBody, "utf8"),
      Buffer.from(canonicalSha256Hex, "hex"),
      context.memberId,
      supersedesVersionId,
      coverageStatement
    ]
  );
  for (const [index, turn] of annex.turns.entries()) {
    await client.query(
      `insert into transcript_turns(
         id,transcript_version_id,ordinal,speaker_member_id,speaker_label,
         starts_at_ms,ends_at_ms,canonical_text,text_sha256
       ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        turn.turn_id,
        transcriptVersionId,
        index + 1,
        turn.speaker_member_id,
        turn.speaker_label,
        turn.starts_at_ms,
        turn.ends_at_ms,
        turn.canonical_text,
        Buffer.from(sha256Hex(turn.canonical_text), "hex")
      ]
    );
  }
  if (root) {
    const updated = await client.query(
      `update meeting_transcripts
          set current_version_id=$1,state='unverified',row_version=row_version+1
        where id=$2 and row_version=$3::bigint`,
      [transcriptVersionId, transcriptId, root.row_version]
    );
    if (updated.rowCount !== 1) throw new Error("transcript root changed during successor append");
  }
  const minutesRefresh = await refreshMinutesTranscriptAnnexInTransaction(client, {
    meetingId,
    transcriptVersionId,
    transcriptSha256: canonicalSha256Hex
  });
  const transcriptAudit = directAudit({
    context,
    organizationId: meeting.organization_id,
    boardId: meeting.board_id,
    eventId: auditEventId,
    eventType: "transcript_version_created",
    entityType: "meeting_transcript",
    entityId: transcriptId,
    objectVersion: BigInt(version),
    details: {
      meetingId,
      transcriptVersionId,
      version,
      canonicalSchema: annex.canonicalSchema,
      mediaType: input.mediaType,
      canonicalSha256: canonicalSha256Hex,
      sourceType: "agent_prepared",
      coverageStatement,
      verificationState: "agent_prepared_unverified",
      supersedesVersionId,
      turnIds: annex.turns.map(({ turn_id: turnId }) => turnId),
      recordingStored: false,
      transcriptionPerformed: false,
      minutesVersionId: minutesRefresh?.minutesVersionId ?? null
    }
  });
  await appendAuditEventsInTransaction(client, [
    transcriptAudit,
    ...(minutesRefresh?.auditEvents ?? [])
  ]);
  const response = {
    transcriptId,
    transcriptVersionId,
    version,
    canonicalSha256: canonicalSha256Hex
  };
  const responseSha256 = canonicalSha256(response);
  await completeIdempotency(
    client,
    idempotencyRecordId,
    "meeting_transcript_version",
    transcriptVersionId,
    responseSha256
  );
  return {
    kind: "version",
    replayed: false,
    boardId: meeting.board_id,
    meetingId,
    transcriptId,
    transcriptVersionId,
    version,
    mediaType: input.mediaType,
    canonicalSchema: annex.canonicalSchema,
    canonicalSha256: canonicalSha256Hex,
    coverageStatement,
    turnIds: annex.turns.map(({ turn_id: turnId }) => turnId),
    responseSha256,
    minutesRefresh: refreshView(minutesRefresh)
  };
}

export async function challengeTranscriptTurnInTransaction(
  client: PoolClient,
  input: ChallengeTranscriptTurnInput
): Promise<Extract<DirectTranscriptResult, { readonly kind: "challenge" }>> {
  const transcriptVersionId = UuidV7Schema.parse(input.transcriptVersionId);
  const turnId = UuidV7Schema.parse(input.turnId);
  const challengeId = UuidV7Schema.parse(input.challengeId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const comment = boundedCanonicalText(input.comment, "transcript challenge", 1_048_576);
  const commentSha256 = sha256Hex(comment);
  const context = await readRequestContext(client);
  const available = await client.query<{
    organization_id: string;
    board_id: string;
    transcript_id: string;
    meeting_id: string;
    version: number;
    text_sha256: Buffer;
  }>(
    `select version.organization_id,version.board_id,version.transcript_id,
            transcript.meeting_id,version.version,turn.text_sha256
       from meeting_transcript_versions as version
       join meeting_transcripts as transcript on transcript.id=version.transcript_id
       join transcript_turns as turn
         on turn.transcript_version_id=version.id and turn.id=$2
       join notices as attendee
         on attendee.object_type='meeting' and attendee.object_id=transcript.meeting_id
        and attendee.notice_type='meeting_called' and attendee.recipient_member_id=$3
       join board_memberships as membership
         on membership.organization_id=version.organization_id
        and membership.board_id=version.board_id and membership.member_id=$3
      where version.id=$1
        and membership.state='active' and membership.seat_role<>'observer'
        and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
        and boardagent_communication_actor_ready(version.board_id,'secretariat:message')`,
    [transcriptVersionId, turnId, context.memberId]
  );
  const row = available.rows[0];
  if (!row || available.rows.length !== 1) {
    throw new TranscriptTransactionError(
      "transcript_challenge_unavailable",
      "transcript turn challenge is unavailable"
    );
  }
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.transcript-turn-challenge.v1",
    transcriptVersionId,
    turnId,
    turnSha256: row.text_sha256.toString("hex"),
    challengerMemberId: context.memberId,
    comment,
    commentSha256
  });
  const replay = await existingIdempotency(
    client,
    context,
    "challenge_transcript_turn",
    key,
    requestSha256
  );
  if (replay) {
    return {
      kind: "challenge",
      replayed: true,
      boardId: row.board_id,
      transcriptId: row.transcript_id,
      transcriptVersionId,
      turnId,
      challengeId: replay.safe_response_id!,
      commentSha256,
      responseSha256: replay.safe_response_sha256!.toString("hex")
    };
  }
  const duplicate = await client.query<{ id: string }>(
    `select id from transcript_challenges
      where transcript_version_id=$1 and turn_id=$2 and challenger_member_id=$3`,
    [transcriptVersionId, turnId, context.memberId]
  );
  if (duplicate.rows.length !== 0) {
    throw new TranscriptTransactionError(
      "transcript_challenge_unavailable",
      "this participant already challenged the exact transcript turn"
    );
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    context,
    operation: "challenge_transcript_turn",
    key,
    requestSha256
  });
  await client.query(
    `insert into transcript_challenges(
       id,organization_id,board_id,transcript_version_id,turn_id,
       challenger_member_id,canonical_comment,comment_sha256,state
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,'pending')`,
    [
      challengeId,
      row.organization_id,
      row.board_id,
      transcriptVersionId,
      turnId,
      context.memberId,
      comment,
      Buffer.from(commentSha256, "hex")
    ]
  );
  await appendAuditEventsInTransaction(client, [
    directAudit({
      context,
      organizationId: row.organization_id,
      boardId: row.board_id,
      eventId: auditEventId,
      eventType: "transcript_turn_challenged",
      entityType: "transcript_challenge",
      entityId: challengeId,
      objectVersion: 1n,
      details: {
        transcriptId: row.transcript_id,
        transcriptVersionId,
        transcriptVersion: row.version,
        turnId,
        turnSha256: row.text_sha256.toString("hex"),
        challengerMemberId: context.memberId,
        commentSha256
      }
    })
  ]);
  const responseSha256 = canonicalSha256({ challengeId, transcriptVersionId, turnId });
  await completeIdempotency(
    client,
    idempotencyRecordId,
    "transcript_challenge",
    challengeId,
    responseSha256
  );
  return {
    kind: "challenge",
    replayed: false,
    boardId: row.board_id,
    transcriptId: row.transcript_id,
    transcriptVersionId,
    turnId,
    challengeId,
    commentSha256,
    responseSha256
  };
}

function normalizeAction(action: TranscriptLifecycleAction): TranscriptLifecycleAction {
  switch (action.kind) {
    case "verification":
      if (action.verificationStatement !== "secretary_verified_annex_hash") {
        throw new TranscriptTransactionError(
          "transcript_action_invalid",
          "transcript verification statement is invalid"
        );
      }
      return {
        kind: "verification",
        transcriptId: UuidV7Schema.parse(action.transcriptId),
        versionId: UuidV7Schema.parse(action.versionId),
        sha256: Sha256HexSchema.parse(action.sha256),
        verificationStatement: action.verificationStatement
      };
    case "qna_link": {
      const turnIds = action.turnIds.map((id) => UuidV7Schema.parse(id));
      if (
        turnIds.length < 1 ||
        turnIds.length > 10_000 ||
        new Set(turnIds).size !== turnIds.length
      ) {
        throw new TranscriptTransactionError(
          "transcript_action_invalid",
          "transcript Q&A link requires one through 10000 unique turns"
        );
      }
      return {
        kind: "qna_link",
        transcriptVersionId: UuidV7Schema.parse(action.transcriptVersionId),
        turnIds,
        questionId: UuidV7Schema.parse(action.questionId)
      };
    }
    case "challenge_resolution": {
      const correctedVersionId =
        action.correctedVersionId === null ? null : UuidV7Schema.parse(action.correctedVersionId);
      if ((action.decision === "accepted") !== (correctedVersionId !== null)) {
        throw new TranscriptTransactionError(
          "transcript_action_invalid",
          "accepted challenges require a corrected successor; rejected challenges forbid one"
        );
      }
      return {
        kind: "challenge_resolution",
        challengeId: UuidV7Schema.parse(action.challengeId),
        decision: action.decision,
        reason: boundedCanonicalText(action.reason, "transcript challenge reason", 65_536),
        correctedVersionId
      };
    }
  }
}

async function currentTranscriptRoot(
  client: PoolClient,
  transcriptId: string
): Promise<TranscriptRootRow> {
  const result = await client.query<TranscriptRootRow>(
    `select transcript.organization_id,transcript.board_id,transcript.meeting_id,
            transcript.id as transcript_id,transcript.state,
            transcript.current_version_id,transcript.row_version::text,
            version.version,version.canonical_sha256,version.supersedes_id
       from meeting_transcripts as transcript
       join meeting_transcript_versions as version on version.id=transcript.current_version_id
      where transcript.id=$1 and boardagent_meeting_secretary_for_board(transcript.board_id)
      for update of transcript`,
    [transcriptId]
  );
  const root = result.rows[0];
  if (!root || result.rows.length !== 1) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "transcript action is unavailable"
    );
  }
  return root;
}

async function prepareVerification(
  client: PoolClient,
  action: Extract<TranscriptLifecycleAction, { readonly kind: "verification" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const root = await currentTranscriptRoot(client, action.transcriptId);
  if (
    root.current_version_id !== action.versionId ||
    root.state !== "unverified" ||
    !safeHashEqual(root.canonical_sha256.toString("hex"), action.sha256)
  ) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "only the exact current unverified transcript annex may be verified"
    );
  }
  const existing = await client.query<{ id: string }>(
    "select id from transcript_verifications where transcript_version_id=$1",
    [action.versionId]
  );
  if (existing.rows.length !== 0) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "the current transcript annex is already verified"
    );
  }
  const payload: JsonValue = {
    schemaVersion: "boardagent.transcript-verification.v1",
    transcriptId: root.transcript_id,
    transcriptVersionId: root.current_version_id,
    transcriptVersion: root.version,
    transcriptSha256: action.sha256,
    verificationStatement: action.verificationStatement,
    evidenceBoundary:
      "Secretary verifies this stored annex hash only; BoardAgent stores no recording and makes no comparison claim."
  };
  return {
    action,
    actionCode: "verify_meeting_transcript",
    organizationId: root.organization_id,
    boardId: root.board_id,
    targetType: "meeting_transcript",
    targetId: root.transcript_id,
    canonicalSchema: "boardagent.transcript-verification.v1",
    canonicalPayload: payload,
    payloadSha256: canonicalSha256(payload),
    packageSha256: action.sha256,
    context,
    details: { kind: "verification", root }
  };
}

async function prepareQnaLink(
  client: PoolClient,
  action: Extract<TranscriptLifecycleAction, { readonly kind: "qna_link" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const versionResult = await client.query<{
    transcript_id: string;
  }>(`select transcript_id from meeting_transcript_versions where id=$1`, [
    action.transcriptVersionId
  ]);
  const transcriptId = versionResult.rows[0]?.transcript_id;
  if (!transcriptId || versionResult.rows.length !== 1) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "transcript Q&A link is unavailable"
    );
  }
  const root = await currentTranscriptRoot(client, transcriptId);
  if (root.current_version_id !== action.transcriptVersionId) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "only exact current transcript turns may be linked"
    );
  }
  const turnsResult = await client.query<TranscriptTurnRow>(
    `select id,ordinal,text_sha256 from transcript_turns
      where transcript_version_id=$1 and id=any($2::uuid[])
      order by ordinal`,
    [action.transcriptVersionId, action.turnIds]
  );
  const turns = turnsResult.rows;
  if (
    turns.length !== action.turnIds.length ||
    turns.some((turn, index) => turn.id !== action.turnIds[index]) ||
    turns.some((turn, index) => index > 0 && turn.ordinal !== turns[index - 1]!.ordinal + 1)
  ) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "transcript Q&A link turns must be one exact contiguous ordered range"
    );
  }
  const questionResult = await client.query<{
    id: string;
    board_id: string;
    state: "pending" | "overdue" | "answered";
    due_at: string;
    assigned_owner_ids: string[];
    current_turn_id: string;
    row_version: string;
  }>(
    `select id,board_id,state,
            to_char(due_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as due_at,
            assigned_owner_ids,current_turn_id,row_version::text
       from management_questions
      where id=$1 and board_id=$2 and boardagent_question_permission(id,'read')`,
    [action.questionId, root.board_id]
  );
  const question = questionResult.rows[0];
  if (!question || questionResult.rows.length !== 1) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "management question is unavailable for transcript linkage"
    );
  }
  const questionTurns = await client.query<{
    id: string;
    ordinal: number;
    turn_kind: string;
    text_sha256: Buffer;
  }>(
    `select id,ordinal,turn_kind,text_sha256 from management_question_turns
      where question_id=$1 order by ordinal`,
    [question.id]
  );
  const questionSha256 = canonicalSha256({
    schemaVersion: "boardagent.management-question-transcript-link.v1",
    questionId: question.id,
    state: question.state,
    dueAt: question.due_at,
    assignedOwnerIds: question.assigned_owner_ids,
    currentTurnId: question.current_turn_id,
    rowVersion: question.row_version,
    turns: questionTurns.rows.map((turn) => ({
      turnId: turn.id,
      ordinal: turn.ordinal,
      turnKind: turn.turn_kind,
      textSha256: turn.text_sha256.toString("hex")
    }))
  });
  const pendingActions = await client.query<{ member_id: string }>(
    `select distinct member_id from pending_action_feed
      where board_id=$1 and object_type='question' and object_id=$2
        and action_type='management_question_due' and state='pending'
      order by member_id`,
    [root.board_id, question.id]
  );
  const managementActionPreserved =
    question.state === "answered" ||
    (pendingActions.rows.length === question.assigned_owner_ids.length &&
      pendingActions.rows.every(
        (row, index) => row.member_id === question.assigned_owner_ids[index]
      ));
  if (!managementActionPreserved) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "unanswered transcript-linked question lacks its exact management pending action"
    );
  }
  const duplicate = await client.query<{ id: string }>(
    `select id from transcript_question_links
      where transcript_version_id=$1 and first_turn_id=$2 and last_turn_id=$3
        and management_question_id=$4`,
    [action.transcriptVersionId, turns[0]!.id, turns.at(-1)!.id, question.id]
  );
  if (duplicate.rows.length !== 0) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "the exact transcript Q&A range is already linked"
    );
  }
  const turnsSha256 = canonicalSha256(
    turns.map((turn) => ({
      turnId: turn.id,
      ordinal: turn.ordinal,
      textSha256: turn.text_sha256.toString("hex")
    }))
  );
  const payload: JsonValue = {
    schemaVersion: "boardagent.transcript-qna-link.v1",
    transcriptId: root.transcript_id,
    transcriptVersionId: root.current_version_id,
    transcriptSha256: root.canonical_sha256.toString("hex"),
    turnIds: action.turnIds,
    turnsSha256,
    managementQuestionId: question.id,
    managementQuestionSha256: questionSha256,
    managementQuestionState: question.state,
    managementActionPreserved
  };
  return {
    action,
    actionCode: "link_meeting_qna",
    organizationId: root.organization_id,
    boardId: root.board_id,
    targetType: "meeting_transcript",
    targetId: root.transcript_id,
    canonicalSchema: "boardagent.transcript-qna-link.v1",
    canonicalPayload: payload,
    payloadSha256: canonicalSha256(payload),
    packageSha256: root.canonical_sha256.toString("hex"),
    context,
    details: {
      kind: "qna_link",
      root,
      turns,
      turnsSha256,
      questionSha256,
      managementActionPreserved
    }
  };
}

async function prepareChallengeResolution(
  client: PoolClient,
  action: Extract<TranscriptLifecycleAction, { readonly kind: "challenge_resolution" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const challengeResult = await client.query<ChallengeRow & { readonly transcript_id: string }>(
    `select challenge.id,challenge.transcript_version_id,challenge.turn_id,
            challenge.challenger_member_id,challenge.canonical_comment,
            challenge.comment_sha256,challenge.state,version.transcript_id
       from transcript_challenges as challenge
       join meeting_transcript_versions as version on version.id=challenge.transcript_version_id
      where challenge.id=$1 and challenge.state='pending'
        and boardagent_meeting_secretary_for_board(challenge.board_id)
      for update of challenge`,
    [action.challengeId]
  );
  const challenge = challengeResult.rows[0];
  if (!challenge || challengeResult.rows.length !== 1) {
    throw new TranscriptTransactionError(
      "transcript_action_unavailable",
      "pending transcript challenge is unavailable"
    );
  }
  const root = await currentTranscriptRoot(client, challenge.transcript_id);
  let correctedSha256: string | null = null;
  if (action.decision === "accepted" && action.correctedVersionId !== null) {
    const corrected = await client.query<{ canonical_sha256: Buffer }>(
      `select canonical_sha256 from meeting_transcript_versions
        where id=$1 and transcript_id=$2 and supersedes_id=$3`,
      [action.correctedVersionId, root.transcript_id, challenge.transcript_version_id]
    );
    if (
      root.current_version_id !== action.correctedVersionId ||
      !corrected.rows[0] ||
      corrected.rows.length !== 1
    ) {
      throw new TranscriptTransactionError(
        "transcript_action_unavailable",
        "accepted transcript challenge requires the exact current direct successor annex"
      );
    }
    correctedSha256 = corrected.rows[0].canonical_sha256.toString("hex");
  }
  const challengeSha256 = canonicalSha256({
    schemaVersion: "boardagent.transcript-challenge-evidence.v1",
    challengeId: challenge.id,
    transcriptVersionId: challenge.transcript_version_id,
    turnId: challenge.turn_id,
    challengerMemberId: challenge.challenger_member_id,
    commentSha256: challenge.comment_sha256.toString("hex")
  });
  const payload: JsonValue = {
    schemaVersion: "boardagent.transcript-challenge-resolution.v1",
    challengeId: challenge.id,
    challengeSha256,
    decision: action.decision,
    reason: action.reason,
    correctedTranscriptVersionId: action.correctedVersionId,
    correctedTranscriptSha256: correctedSha256
  };
  return {
    action,
    actionCode: "resolve_transcript_challenge",
    organizationId: root.organization_id,
    boardId: root.board_id,
    targetType: "transcript_challenge",
    targetId: challenge.id,
    canonicalSchema: "boardagent.transcript-challenge-resolution.v1",
    canonicalPayload: payload,
    payloadSha256: canonicalSha256(payload),
    packageSha256: challengeSha256,
    context,
    details: { kind: "challenge_resolution", root, challenge, correctedSha256 }
  };
}

async function prepareInternal(
  client: PoolClient,
  rawAction: TranscriptLifecycleAction
): Promise<PreparedInternal> {
  const action = normalizeAction(rawAction);
  const context = await readRequestContext(client);
  switch (action.kind) {
    case "verification":
      return prepareVerification(client, action, context);
    case "qna_link":
      return prepareQnaLink(client, action, context);
    case "challenge_resolution":
      return prepareChallengeResolution(client, action, context);
  }
}

export async function prepareTranscriptLifecycleActionInTransaction(
  client: PoolClient,
  action: TranscriptLifecycleAction
): Promise<PreparedTranscriptLifecycleAction> {
  const prepared = await prepareInternal(client, action);
  return {
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetType: prepared.targetType,
    targetId: prepared.targetId,
    canonicalSchema: prepared.canonicalSchema,
    canonicalPayload: prepared.canonicalPayload,
    payloadSha256: prepared.payloadSha256,
    packageSha256: prepared.packageSha256
  };
}

export async function stageTranscriptLifecycleActionInTransaction(
  client: PoolClient,
  input: TranscriptLifecycleStageInput
): Promise<StagedTranscriptLifecycleAction> {
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
      // Preparation locked and authorized the exact transcript aggregate and dependencies.
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

function confirmedAudit(
  prepared: PreparedInternal,
  consentRecordId: string,
  eventId: string,
  eventType:
    "transcript_secretary_verified" | "transcript_qna_linked" | "transcript_challenge_resolved",
  entityType: "meeting_transcript" | "transcript_question_link" | "transcript_challenge",
  entityId: string,
  details: Readonly<Record<string, JsonValue>>,
  objectVersion: bigint
): AuditAppendInput {
  return {
    organizationId: prepared.organizationId,
    consentRecordId,
    objectVersion,
    event: {
      eventId,
      eventType,
      actorMemberId: prepared.context.memberId,
      actorClientId: prepared.context.clientId,
      tokenJti: prepared.context.tokenJti,
      entityType,
      entityId,
      boardId: prepared.boardId,
      origin: "mcp",
      details,
      schemaVersion: 1
    }
  };
}

async function actVerification(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: TranscriptLifecycleResult;
  readonly auditEvents: AuditAppendInput[];
}> {
  if (prepared.action.kind !== "verification" || prepared.details.kind !== "verification") {
    throw new Error("transcript verification preparation mismatch");
  }
  const verificationId = newId();
  const auditEventId = newId();
  await client.query(
    `insert into transcript_verifications(
       id,organization_id,transcript_version_id,transcript_sha256,
       secretary_member_id,status,consent_record_id
     ) values ($1,$2,$3,$4,$5,'secretary_verified',$6)`,
    [
      verificationId,
      prepared.organizationId,
      prepared.action.versionId,
      Buffer.from(prepared.action.sha256, "hex"),
      prepared.context.memberId,
      consentRecordId
    ]
  );
  const updated = await client.query<{ row_version: string }>(
    `update meeting_transcripts
        set state='secretary_verified',row_version=row_version+1
      where id=$1 and current_version_id=$2 and row_version=$3::bigint and state='unverified'
      returning row_version::text`,
    [prepared.targetId, prepared.action.versionId, prepared.details.root.row_version]
  );
  const rowVersion = Number(updated.rows[0]?.row_version);
  if (!Number.isSafeInteger(rowVersion) || rowVersion < 2) {
    throw new Error("transcript verification projection changed concurrently");
  }
  return {
    value: {
      kind: "verification",
      verificationId,
      transcriptId: prepared.targetId,
      versionId: prepared.action.versionId,
      sha256: prepared.action.sha256,
      state: "secretary_verified",
      rowVersion
    },
    auditEvents: [
      confirmedAudit(
        prepared,
        consentRecordId,
        auditEventId,
        "transcript_secretary_verified",
        "meeting_transcript",
        prepared.targetId,
        {
          verificationId,
          transcriptVersionId: prepared.action.versionId,
          transcriptSha256: prepared.action.sha256,
          verificationStatement: prepared.action.verificationStatement,
          originalRecordingComparedByBoardAgent: false
        },
        BigInt(rowVersion)
      )
    ]
  };
}

async function actQnaLink(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: TranscriptLifecycleResult;
  readonly auditEvents: AuditAppendInput[];
}> {
  if (prepared.action.kind !== "qna_link" || prepared.details.kind !== "qna_link") {
    throw new Error("transcript Q&A link preparation mismatch");
  }
  const linkId = newId();
  const auditEventId = newId();
  const firstTurnId = prepared.details.turns[0]!.id;
  const lastTurnId = prepared.details.turns.at(-1)!.id;
  await client.query(
    `insert into transcript_question_links(
       id,organization_id,board_id,transcript_version_id,first_turn_id,last_turn_id,
       turns_sha256,management_question_id,management_question_sha256,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      linkId,
      prepared.organizationId,
      prepared.boardId,
      prepared.action.transcriptVersionId,
      firstTurnId,
      lastTurnId,
      Buffer.from(prepared.details.turnsSha256, "hex"),
      prepared.action.questionId,
      Buffer.from(prepared.details.questionSha256, "hex"),
      consentRecordId
    ]
  );
  return {
    value: {
      kind: "qna_link",
      linkId,
      transcriptId: prepared.targetId,
      transcriptVersionId: prepared.action.transcriptVersionId,
      turnIds: prepared.action.turnIds,
      turnsSha256: prepared.details.turnsSha256,
      questionId: prepared.action.questionId,
      managementQuestionSha256: prepared.details.questionSha256,
      managementActionPreserved: prepared.details.managementActionPreserved
    },
    auditEvents: [
      confirmedAudit(
        prepared,
        consentRecordId,
        auditEventId,
        "transcript_qna_linked",
        "transcript_question_link",
        linkId,
        {
          transcriptId: prepared.targetId,
          transcriptVersionId: prepared.action.transcriptVersionId,
          turnIds: prepared.action.turnIds,
          turnsSha256: prepared.details.turnsSha256,
          managementQuestionId: prepared.action.questionId,
          managementQuestionSha256: prepared.details.questionSha256,
          managementActionPreserved: prepared.details.managementActionPreserved
        },
        1n
      )
    ]
  };
}

async function actChallengeResolution(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: TranscriptLifecycleResult;
  readonly auditEvents: AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "challenge_resolution" ||
    prepared.details.kind !== "challenge_resolution"
  ) {
    throw new Error("transcript challenge resolution preparation mismatch");
  }
  const dispositionId = newId();
  const auditEventId = newId();
  await client.query(
    `insert into transcript_challenge_dispositions(
       id,organization_id,challenge_id,secretary_member_id,decision,reason,
       corrected_transcript_version_id,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      dispositionId,
      prepared.organizationId,
      prepared.action.challengeId,
      prepared.context.memberId,
      prepared.action.decision,
      prepared.action.reason,
      prepared.action.correctedVersionId,
      consentRecordId
    ]
  );
  const updated = await client.query(
    `update transcript_challenges set state=$1 where id=$2 and state='pending'`,
    [prepared.action.decision, prepared.action.challengeId]
  );
  if (updated.rowCount !== 1) throw new Error("transcript challenge changed during resolution");
  return {
    value: {
      kind: "challenge_resolution",
      dispositionId,
      challengeId: prepared.action.challengeId,
      state: prepared.action.decision,
      correctedVersionId: prepared.action.correctedVersionId
    },
    auditEvents: [
      confirmedAudit(
        prepared,
        consentRecordId,
        auditEventId,
        "transcript_challenge_resolved",
        "transcript_challenge",
        prepared.action.challengeId,
        {
          dispositionId,
          decision: prepared.action.decision,
          reason: prepared.action.reason,
          challengedTranscriptVersionId: prepared.details.challenge.transcript_version_id,
          challengedTurnId: prepared.details.challenge.turn_id,
          correctedTranscriptVersionId: prepared.action.correctedVersionId,
          correctedTranscriptSha256: prepared.details.correctedSha256
        },
        1n
      )
    ]
  };
}

async function performConfirmedAction(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: TranscriptLifecycleResult;
  readonly auditEvents: AuditAppendInput[];
}> {
  switch (prepared.action.kind) {
    case "verification":
      return actVerification(client, prepared, consentRecordId);
    case "qna_link":
      return actQnaLink(client, prepared, consentRecordId);
    case "challenge_resolution":
      return actChallengeResolution(client, prepared, consentRecordId);
  }
}

export async function confirmTranscriptLifecycleActionInTransaction(
  client: PoolClient,
  input: TranscriptLifecycleConfirmationInput
): Promise<StagedActionResolution<TranscriptLifecycleResult>> {
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
      if (!prepared) throw new Error("transcript lifecycle preparation is unavailable");
      return performConfirmedAction(requestClient, prepared, consentRecordId);
    }
  );
}
