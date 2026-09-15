import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const MAX_IDEMPOTENCY_KEY = 256;
const MAX_MINUTES_BYTES = 10_485_760;

export interface CreateMinutesVersionInput {
  readonly minutesId: string;
  readonly meetingId: string;
  readonly canonicalText: string;
  readonly transcriptVersionId: string | null;
  readonly expectedCurrentVersionId: string | null;
  readonly minutesVersionId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export type CreateMinutesVersionResult =
  | {
      readonly replayed: true;
      readonly boardId: string;
      readonly minutesId: string;
      readonly minutesVersionId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly boardId: string;
      readonly minutesId: string;
      readonly minutesVersionId: string;
      readonly version: number;
      readonly canonicalSha256: string;
      readonly packageBaseSha256: string;
      readonly responseSha256: string;
      readonly auditEvent: AuditEvent;
    };

export class MinutesDraftTransactionError extends Error {
  public constructor(
    public readonly code:
      | "minutes_draft_unavailable"
      | "minutes_draft_stale"
      | "minutes_transcript_unavailable"
      | "idempotency_conflict",
    message: string
  ) {
    super(message);
    this.name = "MinutesDraftTransactionError";
  }
}

interface MeetingRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly state: "draft" | "called" | "completed" | "cancelled";
  readonly current_minutes_id: string | null;
}

interface BoardRow {
  readonly organization_id: string;
  readonly state: string;
  readonly actor_ready: boolean;
}

interface MemberRow {
  readonly is_secretary: boolean;
  readonly active_now: boolean;
}

interface MinutesRow {
  readonly id: string;
  readonly state: string;
  readonly current_version_id: string | null;
  readonly current_version: number | null;
  readonly row_version: string;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

function exactIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > MAX_IDEMPOTENCY_KEY) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

async function lockAuthorizedMeeting(client: PoolClient, meetingId: string): Promise<MeetingRow> {
  const discovered = await client.query<Pick<MeetingRow, "organization_id" | "board_id">>(
    `select organization_id,board_id
       from meetings
      where id=$1
        and organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(board_id)`,
    [meetingId]
  );
  const identity = discovered.rows[0];
  if (!identity || discovered.rows.length !== 1) {
    throw new MinutesDraftTransactionError(
      "minutes_draft_unavailable",
      "minutes draft meeting is unavailable"
    );
  }
  const board = await client.query<BoardRow>(
    `select organization_id,state,actor_ready
       from boardagent_lock_board_root($1)`,
    [identity.board_id]
  );
  const boardRow = board.rows[0];
  const member = await client.query<MemberRow>(
    `select is_secretary,active_now
       from boardagent_lock_board_members($1,$2,array[boardagent_context_uuid('boardagent.member_id')]::uuid[])`,
    [identity.organization_id, identity.board_id]
  );
  const memberRow = member.rows[0];
  if (
    !boardRow ||
    board.rows.length !== 1 ||
    boardRow.organization_id !== identity.organization_id ||
    boardRow.state !== "active" ||
    !boardRow.actor_ready ||
    !memberRow ||
    member.rows.length !== 1 ||
    !memberRow.is_secretary ||
    !memberRow.active_now
  ) {
    throw new MinutesDraftTransactionError(
      "minutes_draft_unavailable",
      "minutes draft authority is unavailable"
    );
  }
  const locked = await client.query<MeetingRow>(
    `select organization_id,board_id,state,current_minutes_id
       from meetings
      where id=$1 and organization_id=$2 and board_id=$3
      for update`,
    [meetingId, identity.organization_id, identity.board_id]
  );
  const meeting = locked.rows[0];
  if (
    !meeting ||
    locked.rows.length !== 1 ||
    (meeting.state !== "called" && meeting.state !== "completed")
  ) {
    throw new MinutesDraftTransactionError(
      "minutes_draft_unavailable",
      "minutes may be drafted only for a called or completed meeting"
    );
  }
  return meeting;
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
        and operation='create_minutes_version' and idempotency_key=$3
      for update`,
    [actorMemberId, clientId, key]
  );
  return result.rows[0];
}

export async function createMinutesVersionInTransaction(
  client: PoolClient,
  rawInput: CreateMinutesVersionInput
): Promise<CreateMinutesVersionResult> {
  const minutesId = UuidV7Schema.parse(rawInput.minutesId);
  const meetingId = UuidV7Schema.parse(rawInput.meetingId);
  const minutesVersionId = UuidV7Schema.parse(rawInput.minutesVersionId);
  const transcriptVersionId =
    rawInput.transcriptVersionId === null ? null : UuidV7Schema.parse(rawInput.transcriptVersionId);
  const expectedCurrentVersionId =
    rawInput.expectedCurrentVersionId === null
      ? null
      : UuidV7Schema.parse(rawInput.expectedCurrentVersionId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  if (new Set([minutesVersionId, idempotencyRecordId, auditEventId]).size !== 3) {
    throw new TypeError("minutes draft generated IDs must be globally unique");
  }
  const idempotencyKey = exactIdempotencyKey(rawInput.idempotencyKey);
  const text = canonicalText(rawInput.canonicalText);
  const textBytes = Buffer.from(text, "utf8");
  if (textBytes.length < 1 || textBytes.length > MAX_MINUTES_BYTES) {
    throw new RangeError("canonical minutes must contain 1 through 10485760 UTF-8 bytes");
  }
  const canonicalSha256Hex = sha256Hex(textBytes);
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.create-minutes-version.v1",
    minutesId,
    meetingId,
    canonicalSha256: canonicalSha256Hex,
    transcriptVersionId,
    expectedCurrentVersionId
  });
  const context = await readRequestContext(client);
  const meeting = await lockAuthorizedMeeting(client, meetingId);
  if (meeting.organization_id !== context.organizationId) {
    throw new MinutesDraftTransactionError(
      "minutes_draft_unavailable",
      "minutes draft meeting is unavailable"
    );
  }

  const priorIdempotency = await readIdempotency(
    client,
    context.memberId,
    context.clientId,
    idempotencyKey
  );
  if (priorIdempotency) {
    if (!safeHashEqual(priorIdempotency.request_sha256.toString("hex"), requestSha256)) {
      throw new MinutesDraftTransactionError(
        "idempotency_conflict",
        "idempotency key was already used for different minutes draft bytes"
      );
    }
    if (
      priorIdempotency.state !== "succeeded" ||
      !priorIdempotency.safe_response_id ||
      !priorIdempotency.safe_response_sha256
    ) {
      throw new MinutesDraftTransactionError(
        "idempotency_conflict",
        "minutes draft idempotency record is not a completed safe response"
      );
    }
    return {
      replayed: true,
      boardId: meeting.board_id,
      minutesId,
      minutesVersionId: priorIdempotency.safe_response_id,
      responseSha256: priorIdempotency.safe_response_sha256.toString("hex")
    };
  }

  const existing = await client.query<MinutesRow>(
    `select minutes.id,minutes.state,minutes.current_version_id,
            version.version as current_version,minutes.row_version::text
       from minutes
       left join minutes_versions as version on version.id=minutes.current_version_id
      where minutes.id=$1 and minutes.organization_id=$2 and minutes.board_id=$3
        and minutes.meeting_id=$4
      for update of minutes`,
    [minutesId, meeting.organization_id, meeting.board_id, meetingId]
  );
  const prior = existing.rows[0];
  let version: number;
  if (!prior) {
    if (meeting.current_minutes_id !== null || expectedCurrentVersionId !== null) {
      throw new MinutesDraftTransactionError(
        "minutes_draft_stale",
        "initial minutes draft requires an empty meeting lineage and null expected version"
      );
    }
    version = 1;
  } else {
    if (
      existing.rows.length !== 1 ||
      meeting.current_minutes_id !== minutesId ||
      prior.state !== "unpublished_draft" ||
      !prior.current_version_id ||
      prior.current_version === null
    ) {
      throw new MinutesDraftTransactionError(
        "minutes_draft_unavailable",
        "only the current unpublished minutes draft may receive a direct version"
      );
    }
    if (expectedCurrentVersionId !== prior.current_version_id) {
      throw new MinutesDraftTransactionError(
        "minutes_draft_stale",
        "minutes draft expected-current-version binding is stale"
      );
    }
    version = prior.current_version + 1;
  }

  let transcriptSha256: Buffer | null = null;
  if (transcriptVersionId !== null) {
    const transcript = await client.query<{ canonical_sha256: Buffer }>(
      `select version.canonical_sha256
         from meeting_transcript_versions as version
         join meeting_transcripts as transcript on transcript.id=version.transcript_id
        where version.id=$1 and version.organization_id=$2 and version.board_id=$3
          and transcript.meeting_id=$4`,
      [transcriptVersionId, meeting.organization_id, meeting.board_id, meetingId]
    );
    transcriptSha256 = transcript.rows[0]?.canonical_sha256 ?? null;
    if (!transcriptSha256 || transcript.rows.length !== 1) {
      throw new MinutesDraftTransactionError(
        "minutes_transcript_unavailable",
        "minutes transcript version is unavailable for this meeting"
      );
    }
  }
  const packageBaseSha256 = canonicalSha256({
    schemaVersion: "boardagent.minutes-package-base.v1",
    minutesId,
    version,
    canonicalSha256: canonicalSha256Hex,
    transcriptVersionId,
    transcriptSha256: transcriptSha256?.toString("hex") ?? null
  });

  await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'create_minutes_version',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')`,
    [
      idempotencyRecordId,
      meeting.organization_id,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  if (!prior) {
    await client.query(
      `insert into minutes(
         id,organization_id,board_id,meeting_id,current_version_id,created_by
       ) values ($1,$2,$3,$4,$5,$6)`,
      [
        minutesId,
        meeting.organization_id,
        meeting.board_id,
        meetingId,
        minutesVersionId,
        context.memberId
      ]
    );
  }
  await client.query(
    `insert into minutes_versions(
       id,organization_id,board_id,minutes_id,version,canonical_schema,canonical_text,
       canonical_sha256,package_base_sha256,transcript_version_id,transcript_sha256,
       created_by,supersedes_id
     ) values ($1,$2,$3,$4,$5,'boardagent.minutes.v1',$6,$7,$8,$9,$10,$11,$12)`,
    [
      minutesVersionId,
      meeting.organization_id,
      meeting.board_id,
      minutesId,
      version,
      text,
      Buffer.from(canonicalSha256Hex, "hex"),
      Buffer.from(packageBaseSha256, "hex"),
      transcriptVersionId,
      transcriptSha256,
      context.memberId,
      prior?.current_version_id ?? null
    ]
  );
  if (!prior) {
    const advanced = await client.query(
      `update meetings set current_minutes_id=$1,row_version=row_version+1
        where id=$2 and current_minutes_id is null`,
      [minutesId, meetingId]
    );
    if (advanced.rowCount !== 1) throw new Error("meeting minutes draft lineage changed");
  } else {
    const advanced = await client.query(
      `update minutes set current_version_id=$1,row_version=row_version+1
        where id=$2 and row_version=$3::bigint and state='unpublished_draft'`,
      [minutesVersionId, minutesId, prior.row_version]
    );
    if (advanced.rowCount !== 1) throw new Error("minutes draft changed during version append");
  }

  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: meeting.organization_id,
      objectVersion: BigInt(version),
      event: {
        eventId: auditEventId,
        eventType: "minutes_version_created",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "minutes_version",
        entityId: minutesVersionId,
        boardId: meeting.board_id,
        origin: "mcp",
        details: {
          minutesId,
          meetingId,
          version,
          canonicalSha256: canonicalSha256Hex,
          packageBaseSha256,
          transcriptVersionId,
          transcriptSha256: transcriptSha256?.toString("hex") ?? null,
          supersedesVersionId: prior?.current_version_id ?? null,
          requestSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("minutes version audit event was not appended");
  const responseSha256 = canonicalSha256({
    minutesId,
    minutesVersionId,
    version,
    canonicalSha256: canonicalSha256Hex,
    packageBaseSha256
  });
  await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='minutes_version',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [minutesVersionId, Buffer.from(responseSha256, "hex"), idempotencyRecordId]
  );
  return {
    replayed: false,
    boardId: meeting.board_id,
    minutesId,
    minutesVersionId,
    version,
    canonicalSha256: canonicalSha256Hex,
    packageBaseSha256,
    responseSha256,
    auditEvent
  };
}
