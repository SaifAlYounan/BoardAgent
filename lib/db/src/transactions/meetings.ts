import { randomBytes } from "node:crypto";

import type { PoolClient } from "pg";

import {
  PendingActionDeltaSchema,
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  type JsonValue
} from "@boardagent/contracts";
import { uuidV7 } from "@boardagent/domain";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

export interface MeetingAgendaItem {
  readonly title: string;
  readonly source_document_version_id: string | null;
  readonly source_document_sha256: string | null;
}

export interface MeetingAgenda {
  readonly schema_version: "boardagent.agenda.v1";
  readonly values: { readonly items: readonly MeetingAgendaItem[] };
}

export type MeetingLifecycleAction =
  | {
      readonly kind: "create";
      readonly boardId: string;
      readonly meetingId: string;
      readonly title: string;
      readonly scheduledStartAt: string;
      readonly scheduledEndAt: string;
      readonly timezone: string;
      readonly agenda: MeetingAgenda;
      readonly attendeeMemberIds: readonly string[];
    }
  | {
      readonly kind: "amend";
      readonly meetingId: string;
      readonly expectedRowVersion: number;
      readonly title: string;
      readonly scheduledStartAt: string;
      readonly scheduledEndAt: string;
      readonly timezone: string;
      readonly agenda: MeetingAgenda;
      readonly reason: string;
    }
  | {
      readonly kind: "attendance_correction";
      readonly attendanceId: string;
      readonly status: "present" | "absent" | "excused";
      readonly reason: string;
    }
  | {
      readonly kind: "cancellation";
      readonly meetingId: string;
      readonly reason: string;
    }
  | {
      readonly kind: "completion";
      readonly meetingId: string;
      readonly completionStatement: "attendance_record_is_complete";
    };

export interface PreparedMeetingLifecycleAction {
  readonly actionCode:
    | "create_meeting"
    | "amend_meeting"
    | "correct_attendance"
    | "cancel_meeting"
    | "complete_meeting";
  readonly boardId: string;
  readonly targetType: "meeting" | "meeting_attendance";
  readonly targetId: string;
  readonly canonicalSchema: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
}

export interface MeetingLifecycleStageInput {
  readonly action: MeetingLifecycleAction;
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

export interface StagedMeetingLifecycleAction extends StagedAction {
  readonly actionCode: PreparedMeetingLifecycleAction["actionCode"];
  readonly boardId: string;
  readonly targetType: PreparedMeetingLifecycleAction["targetType"];
  readonly targetId: string;
}

export interface MeetingLifecycleConfirmationInput {
  readonly action: MeetingLifecycleAction;
  readonly confirmation: ConfirmStagedActionInput;
}

export type MeetingLifecycleResult =
  | {
      readonly kind: "create" | "amend";
      readonly meetingId: string;
      readonly meetingVersionId: string;
      readonly agendaVersionId: string;
      readonly version: number;
      readonly packageSha256: string;
      readonly recipientMemberIds: readonly string[];
    }
  | {
      readonly kind: "attendance_correction";
      readonly meetingId: string;
      readonly priorAttendanceId: string;
      readonly attendanceId: string;
      readonly status: "present" | "absent" | "excused";
    }
  | {
      readonly kind: "cancellation" | "completion";
      readonly meetingId: string;
      readonly state: "cancelled" | "completed";
      readonly rowVersion: number;
    };

export interface RecordMeetingRsvpInput {
  readonly meetingId: string;
  readonly response: "attending" | "not_attending" | "tentative";
  readonly note: string | null;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly rsvpId: string;
  readonly auditEventId: string;
}

export interface RecordMeetingAttendanceInput {
  readonly meetingId: string;
  readonly memberId: string;
  readonly status: "present" | "absent" | "excused";
  readonly source: "secretary_record";
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly attendanceId: string;
  readonly auditEventId: string;
}

export interface DirectMeetingResult {
  readonly replayed: boolean;
  readonly meetingId: string;
  readonly recordId: string;
  readonly version: number;
  readonly responseSha256: string;
}

export class MeetingTransactionError extends Error {
  public constructor(
    public readonly code:
      | "meeting_action_invalid"
      | "meeting_action_unavailable"
      | "meeting_attendee_unavailable"
      | "meeting_attendance_incomplete"
      | "idempotency_conflict",
    message: string
  ) {
    super(message);
    this.name = "MeetingTransactionError";
  }
}

interface MeetingRootRow {
  readonly id: string;
  readonly organization_id: string;
  readonly board_id: string;
  readonly title: string;
  readonly state: "draft" | "called" | "completed" | "cancelled";
  readonly scheduled_start_at: string;
  readonly scheduled_end_at: string;
  readonly row_version: string;
  readonly meeting_version_id: string;
  readonly meeting_version: number;
  readonly meeting_sha256: Buffer;
  readonly agenda_version_id: string;
  readonly agenda_version: number;
  readonly agenda_sha256: Buffer;
}

interface PreparedRecipient {
  readonly memberId: string;
  readonly entitlementGeneration: number;
  readonly visibilitySha256: string;
}

interface CurrentAttendance {
  readonly attendanceId: string;
  readonly memberId: string;
  readonly status: "present" | "absent" | "excused" | "partial";
}

type PreparedDetails =
  | { readonly kind: "create"; readonly recipients: readonly PreparedRecipient[] }
  | {
      readonly kind: "amend";
      readonly root: MeetingRootRow;
      readonly recipients: readonly PreparedRecipient[];
    }
  | {
      readonly kind: "attendance_correction";
      readonly root: MeetingRootRow;
      readonly priorAttendanceId: string;
      readonly memberId: string;
    }
  | {
      readonly kind: "cancellation";
      readonly root: MeetingRootRow;
      readonly recipients: readonly PreparedRecipient[];
    }
  | {
      readonly kind: "completion";
      readonly root: MeetingRootRow;
      readonly attendance: readonly CurrentAttendance[];
      readonly attendanceManifestSha256: string;
    };

interface PreparedInternal extends PreparedMeetingLifecycleAction {
  readonly action: MeetingLifecycleAction;
  readonly organizationId: string;
  readonly context: ActiveRequestContext;
  readonly details: PreparedDetails;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

const MAX_IDEMPOTENCY_KEY = 200;

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

function boundedText(value: string, label: string, maximum: number): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > maximum) {
    throw new RangeError(`${label} must contain 1 through ${String(maximum)} characters`);
  }
  return normalized;
}

function schedule(start: string, end: string): { readonly start: string; readonly end: string } {
  const normalizedStart = Rfc3339UtcSchema.parse(start);
  const normalizedEnd = Rfc3339UtcSchema.parse(end);
  if (Date.parse(normalizedEnd) <= Date.parse(normalizedStart)) {
    throw new MeetingTransactionError(
      "meeting_action_invalid",
      "meeting end must be after meeting start"
    );
  }
  return { start: normalizedStart, end: normalizedEnd };
}

function normalizeAgenda(rawAgenda: MeetingAgenda): MeetingAgenda {
  if (rawAgenda.schema_version !== "boardagent.agenda.v1") {
    throw new MeetingTransactionError("meeting_action_invalid", "meeting agenda schema is invalid");
  }
  const items = rawAgenda.values.items.map((item) => {
    const sourceDocumentVersionId =
      item.source_document_version_id === null
        ? null
        : UuidV7Schema.parse(item.source_document_version_id);
    const sourceDocumentSha256 =
      item.source_document_sha256 === null
        ? null
        : Sha256HexSchema.parse(item.source_document_sha256);
    if ((sourceDocumentVersionId === null) !== (sourceDocumentSha256 === null)) {
      throw new MeetingTransactionError(
        "meeting_action_invalid",
        "agenda document version and SHA-256 must both be present or both be null"
      );
    }
    return {
      title: boundedText(item.title, "agenda item title", 1024),
      source_document_version_id: sourceDocumentVersionId,
      source_document_sha256: sourceDocumentSha256
    };
  });
  if (items.length < 1 || items.length > 1000) {
    throw new MeetingTransactionError(
      "meeting_action_invalid",
      "meeting agenda requires one through 1000 items"
    );
  }
  return { schema_version: "boardagent.agenda.v1", values: { items } };
}

function normalizeAction(input: MeetingLifecycleAction): MeetingLifecycleAction {
  switch (input.kind) {
    case "create": {
      const normalizedSchedule = schedule(input.scheduledStartAt, input.scheduledEndAt);
      const attendeeMemberIds = input.attendeeMemberIds
        .map((id) => UuidV7Schema.parse(id))
        .toSorted();
      if (
        attendeeMemberIds.length < 1 ||
        attendeeMemberIds.length > 1000 ||
        new Set(attendeeMemberIds).size !== attendeeMemberIds.length
      ) {
        throw new MeetingTransactionError(
          "meeting_action_invalid",
          "meeting call requires one through 1000 unique attendees"
        );
      }
      return {
        kind: "create",
        boardId: UuidV7Schema.parse(input.boardId),
        meetingId: UuidV7Schema.parse(input.meetingId),
        title: boundedText(input.title, "meeting title", 512),
        scheduledStartAt: normalizedSchedule.start,
        scheduledEndAt: normalizedSchedule.end,
        timezone: boundedText(input.timezone, "meeting timezone", 1024),
        agenda: normalizeAgenda(input.agenda),
        attendeeMemberIds
      };
    }
    case "amend": {
      if (!Number.isSafeInteger(input.expectedRowVersion) || input.expectedRowVersion < 1) {
        throw new MeetingTransactionError(
          "meeting_action_invalid",
          "expected meeting row version must be a positive safe integer"
        );
      }
      const normalizedSchedule = schedule(input.scheduledStartAt, input.scheduledEndAt);
      return {
        kind: "amend",
        meetingId: UuidV7Schema.parse(input.meetingId),
        expectedRowVersion: input.expectedRowVersion,
        title: boundedText(input.title, "meeting title", 512),
        scheduledStartAt: normalizedSchedule.start,
        scheduledEndAt: normalizedSchedule.end,
        timezone: boundedText(input.timezone, "meeting timezone", 1024),
        agenda: normalizeAgenda(input.agenda),
        reason: boundedText(input.reason, "meeting amendment reason", 65_536)
      };
    }
    case "attendance_correction":
      return {
        kind: "attendance_correction",
        attendanceId: UuidV7Schema.parse(input.attendanceId),
        status: input.status,
        reason: boundedText(input.reason, "attendance correction reason", 65_536)
      };
    case "cancellation":
      return {
        kind: "cancellation",
        meetingId: UuidV7Schema.parse(input.meetingId),
        reason: boundedText(input.reason, "meeting cancellation reason", 65_536)
      };
    case "completion":
      if (input.completionStatement !== "attendance_record_is_complete") {
        throw new MeetingTransactionError(
          "meeting_action_invalid",
          "meeting completion requires the exact attendance completeness statement"
        );
      }
      return {
        kind: "completion",
        meetingId: UuidV7Schema.parse(input.meetingId),
        completionStatement: input.completionStatement
      };
  }
}

async function validateAgendaDocuments(
  client: PoolClient,
  boardId: string,
  agenda: MeetingAgenda
): Promise<void> {
  const references = agenda.values.items.filter(
    (
      item
    ): item is MeetingAgendaItem & {
      readonly source_document_version_id: string;
      readonly source_document_sha256: string;
    } => item.source_document_version_id !== null && item.source_document_sha256 !== null
  );
  if (references.length === 0) return;
  const expected = new Map<string, string>();
  for (const reference of references) {
    const prior = expected.get(reference.source_document_version_id);
    if (prior !== undefined && !safeHashEqual(prior, reference.source_document_sha256)) {
      throw new MeetingTransactionError(
        "meeting_action_invalid",
        "one agenda document version cannot carry two hashes"
      );
    }
    expected.set(reference.source_document_version_id, reference.source_document_sha256);
  }
  const found = await client.query<{ id: string; sha256: string }>(
    `select version.id,encode(version.sha256,'hex') as sha256
       from document_versions as version
       join documents as document on document.id=version.document_id
      where version.id=any($1::uuid[])
        and document.board_id=$2
        and document.state<>'soft_deleted'
        and boardagent_document_permission(document.id,'read')
      order by version.id`,
    [[...expected.keys()], boardId]
  );
  if (
    found.rows.length !== expected.size ||
    found.rows.some((row) => !safeHashEqual(row.sha256, expected.get(row.id) ?? ""))
  ) {
    throw new MeetingTransactionError(
      "meeting_action_unavailable",
      "every agenda document must be an exact readable version on this board"
    );
  }
}

async function lockRecipients(
  client: PoolClient,
  boardId: string,
  meetingId: string,
  actionCode: PreparedMeetingLifecycleAction["actionCode"],
  memberIds: readonly string[],
  requireEvery: boolean
): Promise<readonly PreparedRecipient[]> {
  if (memberIds.length === 0) return [];
  const recipients = await client.query<{
    member_id: string;
    entitlement_generation: string;
  }>(
    `select member_id,entitlement_generation::text
       from boardagent_lock_meeting_recipients($1,$2::uuid[])
      where not boardagent_member_record_recused('meeting',$3,member_id)`,
    [boardId, memberIds, meetingId]
  );
  if (requireEvery && recipients.rows.length !== memberIds.length) {
    throw new MeetingTransactionError(
      "meeting_attendee_unavailable",
      "every meeting attendee must be an active member of this board"
    );
  }
  return recipients.rows.map((recipient) => {
    const entitlementGeneration = Number(recipient.entitlement_generation);
    if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
      throw new Error("meeting recipient entitlement generation is invalid");
    }
    return {
      memberId: recipient.member_id,
      entitlementGeneration,
      visibilitySha256: canonicalSha256({
        schemaVersion: "boardagent.meeting-recipient-entitlement.v1",
        boardId,
        meetingId,
        actionCode,
        memberId: recipient.member_id,
        entitlementGeneration
      })
    };
  });
}

async function currentRoot(client: PoolClient, meetingId: string): Promise<MeetingRootRow> {
  const result = await client.query<MeetingRootRow>(
    `select meeting.id,meeting.organization_id,meeting.board_id,meeting.title,meeting.state,
            to_char(meeting.scheduled_start at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as scheduled_start_at,
            to_char(meeting.scheduled_end at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as scheduled_end_at,
            meeting.row_version::text,version.id as meeting_version_id,
            version.version as meeting_version,version.canonical_sha256 as meeting_sha256,
            agenda.id as agenda_version_id,agenda.version as agenda_version,
            agenda.canonical_sha256 as agenda_sha256
       from meetings as meeting
       join meeting_versions as version on version.id=meeting.current_version_id
       join agenda_versions as agenda on agenda.id=meeting.current_agenda_version_id
      where meeting.id=$1
        and boardagent_meeting_secretary_for_board(meeting.board_id)
      for update of meeting`,
    [meetingId]
  );
  const root = result.rows[0];
  if (!root || result.rows.length !== 1) {
    throw new MeetingTransactionError("meeting_action_unavailable", "meeting is unavailable");
  }
  return root;
}

async function originalRecipientIds(
  client: PoolClient,
  meetingId: string
): Promise<readonly string[]> {
  const result = await client.query<{ recipient_member_id: string }>(
    `select recipient_member_id from notices
      where object_type='meeting' and object_id=$1 and notice_type='meeting_called'
      order by recipient_member_id`,
    [meetingId]
  );
  return result.rows.map(({ recipient_member_id }) => recipient_member_id);
}

async function currentAttendance(
  client: PoolClient,
  meetingId: string
): Promise<readonly CurrentAttendance[]> {
  const result = await client.query<{
    id: string;
    member_id: string;
    attendance_status: CurrentAttendance["status"];
  }>(
    `select attendance.id,attendance.member_id,attendance.attendance_status
       from meeting_attendance as attendance
      where attendance.meeting_id=$1
        and not exists (
          select 1 from meeting_attendance as later where later.corrects_id=attendance.id
        )
      order by attendance.member_id,attendance.recorded_at,attendance.id`,
    [meetingId]
  );
  return result.rows.map((row) => ({
    attendanceId: row.id,
    memberId: row.member_id,
    status: row.attendance_status
  }));
}

async function prepareCreate(
  client: PoolClient,
  action: Extract<MeetingLifecycleAction, { readonly kind: "create" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const board = await client.query<{ organization_id: string }>(
    `select organization_id from boards
      where id=$1
        and organization_id=$2
        and state='active'
        and boardagent_meeting_secretary_for_board(id)
        and not exists (select 1 from meetings where id=$3)`,
    [action.boardId, context.organizationId, action.meetingId]
  );
  const organizationId = board.rows[0]?.organization_id;
  if (!organizationId || board.rows.length !== 1) {
    throw new MeetingTransactionError("meeting_action_unavailable", "meeting call is unavailable");
  }
  await validateAgendaDocuments(client, action.boardId, action.agenda);
  const recipients = await lockRecipients(
    client,
    action.boardId,
    action.meetingId,
    "create_meeting",
    action.attendeeMemberIds,
    true
  );
  const payload = {
    schemaVersion: "boardagent.meeting-call.v1",
    boardId: action.boardId,
    meetingId: action.meetingId,
    title: action.title,
    scheduledStartAt: action.scheduledStartAt,
    scheduledEndAt: action.scheduledEndAt,
    timezone: action.timezone,
    agenda: JSON.parse(canonicalJson(action.agenda)) as JsonValue,
    attendeeMemberIds: recipients.map(({ memberId }) => memberId),
    attendeeEntitlements: recipients.map(({ memberId, entitlementGeneration }) => ({
      memberId,
      entitlementGeneration
    }))
  };
  const payloadSha256 = canonicalSha256(payload);
  return {
    action,
    actionCode: "create_meeting",
    organizationId,
    boardId: action.boardId,
    targetType: "meeting",
    targetId: action.meetingId,
    canonicalSchema: "boardagent.meeting-call.v1",
    canonicalPayload: payload,
    payloadSha256,
    packageSha256: payloadSha256,
    context,
    details: { kind: "create", recipients }
  };
}

async function prepareAmendment(
  client: PoolClient,
  action: Extract<MeetingLifecycleAction, { readonly kind: "amend" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const root = await currentRoot(client, action.meetingId);
  if (root.state !== "called" || BigInt(root.row_version) !== BigInt(action.expectedRowVersion)) {
    throw new MeetingTransactionError(
      "meeting_action_unavailable",
      "only the exact current called meeting may be amended"
    );
  }
  await validateAgendaDocuments(client, root.board_id, action.agenda);
  const recipients = await lockRecipients(
    client,
    root.board_id,
    root.id,
    "amend_meeting",
    await originalRecipientIds(client, root.id),
    false
  );
  const payload = {
    schemaVersion: "boardagent.meeting-amendment.v1",
    boardId: root.board_id,
    meetingId: root.id,
    expectedRowVersion: action.expectedRowVersion,
    priorMeetingVersionId: root.meeting_version_id,
    priorMeetingSha256: root.meeting_sha256.toString("hex"),
    priorAgendaVersionId: root.agenda_version_id,
    priorAgendaSha256: root.agenda_sha256.toString("hex"),
    title: action.title,
    scheduledStartAt: action.scheduledStartAt,
    scheduledEndAt: action.scheduledEndAt,
    timezone: action.timezone,
    agenda: JSON.parse(canonicalJson(action.agenda)) as JsonValue,
    reason: action.reason,
    recipientMemberIds: recipients.map(({ memberId }) => memberId)
  };
  const payloadSha256 = canonicalSha256(payload);
  return {
    action,
    actionCode: "amend_meeting",
    organizationId: root.organization_id,
    boardId: root.board_id,
    targetType: "meeting",
    targetId: root.id,
    canonicalSchema: "boardagent.meeting-amendment.v1",
    canonicalPayload: payload,
    payloadSha256,
    packageSha256: payloadSha256,
    context,
    details: { kind: "amend", root, recipients }
  };
}

async function prepareAttendanceCorrection(
  client: PoolClient,
  action: Extract<MeetingLifecycleAction, { readonly kind: "attendance_correction" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const priorResult = await client.query<{
    meeting_id: string;
    member_id: string;
    attendance_status: "present" | "absent" | "excused" | "partial";
  }>(
    `select attendance.meeting_id,attendance.member_id,attendance.attendance_status
       from meeting_attendance as attendance
       join meetings as meeting on meeting.id=attendance.meeting_id
      where attendance.id=$1
        and meeting.state in ('called','completed')
        and boardagent_meeting_secretary_for_board(meeting.board_id)
        and not exists (
          select 1 from meeting_attendance as later where later.corrects_id=attendance.id
        )`,
    [action.attendanceId]
  );
  const prior = priorResult.rows[0];
  if (!prior || priorResult.rows.length !== 1 || prior.attendance_status === action.status) {
    throw new MeetingTransactionError(
      "meeting_action_unavailable",
      "only a current attendance record may be corrected to a different status"
    );
  }
  const root = await currentRoot(client, prior.meeting_id);
  const payload = {
    schemaVersion: "boardagent.meeting-attendance-correction.v1",
    boardId: root.board_id,
    meetingId: root.id,
    attendanceId: action.attendanceId,
    memberId: prior.member_id,
    priorStatus: prior.attendance_status,
    correctedStatus: action.status,
    reason: action.reason,
    meetingVersionId: root.meeting_version_id,
    meetingSha256: root.meeting_sha256.toString("hex")
  };
  const payloadSha256 = canonicalSha256(payload);
  return {
    action,
    actionCode: "correct_attendance",
    organizationId: root.organization_id,
    boardId: root.board_id,
    targetType: "meeting_attendance",
    targetId: action.attendanceId,
    canonicalSchema: "boardagent.meeting-attendance-correction.v1",
    canonicalPayload: payload,
    payloadSha256,
    packageSha256: payloadSha256,
    context,
    details: {
      kind: "attendance_correction",
      root,
      priorAttendanceId: action.attendanceId,
      memberId: prior.member_id
    }
  };
}

async function prepareCancellation(
  client: PoolClient,
  action: Extract<MeetingLifecycleAction, { readonly kind: "cancellation" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const root = await currentRoot(client, action.meetingId);
  if (root.state !== "draft" && root.state !== "called") {
    throw new MeetingTransactionError(
      "meeting_action_unavailable",
      "only a nonterminal meeting may be cancelled"
    );
  }
  const recipients = await lockRecipients(
    client,
    root.board_id,
    root.id,
    "cancel_meeting",
    await originalRecipientIds(client, root.id),
    false
  );
  const payload = {
    schemaVersion: "boardagent.meeting-cancellation.v1",
    boardId: root.board_id,
    meetingId: root.id,
    rowVersion: Number(root.row_version),
    meetingVersionId: root.meeting_version_id,
    meetingSha256: root.meeting_sha256.toString("hex"),
    agendaVersionId: root.agenda_version_id,
    agendaSha256: root.agenda_sha256.toString("hex"),
    reason: action.reason,
    recipientMemberIds: recipients.map(({ memberId }) => memberId)
  };
  const payloadSha256 = canonicalSha256(payload);
  return {
    action,
    actionCode: "cancel_meeting",
    organizationId: root.organization_id,
    boardId: root.board_id,
    targetType: "meeting",
    targetId: root.id,
    canonicalSchema: "boardagent.meeting-cancellation.v1",
    canonicalPayload: payload,
    payloadSha256,
    packageSha256: payloadSha256,
    context,
    details: { kind: "cancellation", root, recipients }
  };
}

async function prepareCompletion(
  client: PoolClient,
  action: Extract<MeetingLifecycleAction, { readonly kind: "completion" }>,
  context: ActiveRequestContext
): Promise<PreparedInternal> {
  const root = await currentRoot(client, action.meetingId);
  if (root.state !== "called") {
    throw new MeetingTransactionError(
      "meeting_action_unavailable",
      "only a called meeting may be completed"
    );
  }
  const attendeeIds = await originalRecipientIds(client, root.id);
  const attendance = await currentAttendance(client, root.id);
  if (
    attendance.length !== attendeeIds.length ||
    attendance.some((record, index) => record.memberId !== attendeeIds[index])
  ) {
    throw new MeetingTransactionError(
      "meeting_attendance_incomplete",
      "every listed attendee requires one current recorded attendance status"
    );
  }
  const attendanceManifestSha256 = canonicalSha256({
    schemaVersion: "boardagent.meeting-attendance-manifest.v1",
    meetingId: root.id,
    records: attendance
  });
  const payload = {
    schemaVersion: "boardagent.meeting-completion.v1",
    boardId: root.board_id,
    meetingId: root.id,
    rowVersion: Number(root.row_version),
    meetingVersionId: root.meeting_version_id,
    meetingSha256: root.meeting_sha256.toString("hex"),
    agendaVersionId: root.agenda_version_id,
    agendaSha256: root.agenda_sha256.toString("hex"),
    completionStatement: action.completionStatement,
    attendanceManifestSha256,
    attendance: attendance.map(({ attendanceId, memberId, status }) => ({
      attendanceId,
      memberId,
      status
    }))
  };
  const payloadSha256 = canonicalSha256(payload);
  return {
    action,
    actionCode: "complete_meeting",
    organizationId: root.organization_id,
    boardId: root.board_id,
    targetType: "meeting",
    targetId: root.id,
    canonicalSchema: "boardagent.meeting-completion.v1",
    canonicalPayload: payload,
    payloadSha256,
    packageSha256: payloadSha256,
    context,
    details: { kind: "completion", root, attendance, attendanceManifestSha256 }
  };
}

async function prepareInternal(
  client: PoolClient,
  rawAction: MeetingLifecycleAction
): Promise<PreparedInternal> {
  const action = normalizeAction(rawAction);
  const context = await readRequestContext(client);
  switch (action.kind) {
    case "create":
      return prepareCreate(client, action, context);
    case "amend":
      return prepareAmendment(client, action, context);
    case "attendance_correction":
      return prepareAttendanceCorrection(client, action, context);
    case "cancellation":
      return prepareCancellation(client, action, context);
    case "completion":
      return prepareCompletion(client, action, context);
  }
}

export async function prepareMeetingLifecycleActionInTransaction(
  client: PoolClient,
  action: MeetingLifecycleAction
): Promise<PreparedMeetingLifecycleAction> {
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

export async function stageMeetingLifecycleActionInTransaction(
  client: PoolClient,
  input: MeetingLifecycleStageInput
): Promise<StagedMeetingLifecycleAction> {
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
      // Exact meeting, role, schedule, agenda and recipient rows were checked by preparation.
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

async function transactionTimestamp(client: PoolClient): Promise<string> {
  const result = await client.query<{ occurred_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
  );
  const occurredAt = result.rows[0]?.occurred_at;
  if (!occurredAt) throw new Error("meeting transaction timestamp is unavailable");
  return Rfc3339UtcSchema.parse(occurredAt);
}

async function nextFeedSequence(
  client: PoolClient,
  boardId: string,
  memberId: string
): Promise<bigint> {
  const result = await client.query<{ next_sequence: string }>(
    `select (greatest(
              coalesce((select max(feed_sequence) from pending_action_feed
                         where board_id=$1 and member_id=$2),0),
              coalesce((select max(feed_sequence) from feed_tombstones
                         where board_id=$1 and member_id=$2),0)
            )+1)::text as next_sequence`,
    [boardId, memberId]
  );
  return BigInt(result.rows[0]?.next_sequence ?? "1");
}

function confirmedAudit(
  prepared: PreparedInternal,
  consentRecordId: string,
  eventId: string,
  eventType:
    | "meeting_called"
    | "meeting_amended"
    | "meeting_attendance_corrected"
    | "meeting_cancelled"
    | "meeting_completed"
    | "notice_delivered",
  entityType: "meeting" | "meeting_attendance",
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

async function insertAgendaItems(
  client: PoolClient,
  agendaVersionId: string,
  agenda: MeetingAgenda
): Promise<void> {
  for (const [index, item] of agenda.values.items.entries()) {
    const ordinal = index + 1;
    const itemSha256 = canonicalSha256({
      schemaVersion: "boardagent.agenda-item.v1",
      ordinal,
      title: item.title,
      sourceDocumentVersionId: item.source_document_version_id,
      sourceDocumentSha256: item.source_document_sha256
    });
    await client.query(
      `insert into agenda_items(
         id,agenda_version_id,ordinal,title,source_document_version_id,
         source_document_sha256,item_sha256
       ) values ($1,$2,$3,$4,$5,$6,$7)`,
      [
        newId(),
        agendaVersionId,
        ordinal,
        item.title,
        item.source_document_version_id,
        item.source_document_sha256 === null
          ? null
          : Buffer.from(item.source_document_sha256, "hex"),
        Buffer.from(itemSha256, "hex")
      ]
    );
  }
}

async function insertMeetingNotice(
  client: PoolClient,
  input: {
    readonly prepared: PreparedInternal;
    readonly recipient: PreparedRecipient;
    readonly noticeType: "meeting_called" | "meeting_amended" | "meeting_cancelled";
    readonly objectVersion: number;
    readonly packageSha256: string;
    readonly noticeAuditEventId: string;
  }
): Promise<void> {
  const noticeId = newId();
  const feedId = newId();
  const meetingId = input.prepared.targetId;
  const feedSequence = await nextFeedSequence(
    client,
    input.prepared.boardId,
    input.recipient.memberId
  );
  const delta = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: feedSequence.toString(10),
    deltaType: "notice",
    objectType: "meeting",
    objectId: meetingId,
    objectVersion: input.objectVersion,
    entitlementGeneration: input.recipient.entitlementGeneration,
    actionState: "informational",
    safeRefs: { packageSha256: input.packageSha256 },
    createdAt: await transactionTimestamp(client)
  });
  const contentSha256 = canonicalSha256({
    noticeType: input.noticeType,
    meetingId,
    objectVersion: input.objectVersion,
    packageSha256: input.packageSha256,
    recipientMemberId: input.recipient.memberId
  });
  await client.query(
    `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,$4,'meeting',$5,$6,$7,$8,$9,$10)`,
    [
      noticeId,
      input.prepared.organizationId,
      input.prepared.boardId,
      input.noticeType,
      meetingId,
      input.objectVersion,
      input.recipient.memberId,
      Buffer.from(contentSha256, "hex"),
      feedSequence.toString(10),
      input.noticeAuditEventId
    ]
  );
  const canonicalPayload = Buffer.from(canonicalJson(delta), "utf8");
  await client.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,notice_id,audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,$7,'meeting',$8,$9,$10,$11,$12,$13,$14)`,
    [
      feedId,
      input.prepared.organizationId,
      input.prepared.boardId,
      input.recipient.memberId,
      input.recipient.entitlementGeneration,
      feedSequence.toString(10),
      input.noticeType,
      meetingId,
      input.objectVersion,
      Buffer.from(input.recipient.visibilitySha256, "hex"),
      canonicalPayload,
      Buffer.from(canonicalSha256(delta), "hex"),
      noticeId,
      input.noticeAuditEventId
    ]
  );
}

function meetingVersionPayload(
  action: Extract<MeetingLifecycleAction, { readonly kind: "create" | "amend" }>,
  boardId: string,
  meetingId: string,
  version: number,
  agendaSha256: string,
  recipientMemberIds: readonly string[]
): JsonValue {
  return {
    schemaVersion: "boardagent.meeting.v1",
    boardId,
    meetingId,
    version,
    title: action.title,
    scheduledStartAt: action.scheduledStartAt,
    scheduledEndAt: action.scheduledEndAt,
    timezone: action.timezone,
    agendaSha256,
    recipientMemberIds,
    changeReason: action.kind === "create" ? "Initial meeting call." : action.reason
  };
}

async function insertMeetingVersionSet(
  client: PoolClient,
  input: {
    readonly prepared: PreparedInternal;
    readonly action: Extract<MeetingLifecycleAction, { readonly kind: "create" | "amend" }>;
    readonly consentRecordId: string;
    readonly meetingVersionId: string;
    readonly agendaVersionId: string;
    readonly version: number;
    readonly recipients: readonly PreparedRecipient[];
  }
): Promise<{ readonly meetingSha256: string; readonly agendaSha256: string }> {
  const agendaSha256 = canonicalSha256(input.action.agenda);
  const versionPayload = meetingVersionPayload(
    input.action,
    input.prepared.boardId,
    input.prepared.targetId,
    input.version,
    agendaSha256,
    input.recipients.map(({ memberId }) => memberId)
  );
  const meetingSha256 = canonicalSha256(versionPayload);
  await client.query(
    `insert into meeting_versions(
       id,organization_id,board_id,meeting_id,version,canonical_schema,canonical_title,
       scheduled_start,scheduled_end,notice_package,notice_package_sha256,canonical_sha256,
       change_reason,consent_record_id,created_by
     ) values ($1,$2,$3,$4,$5,'boardagent.meeting.v1',$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      input.meetingVersionId,
      input.prepared.organizationId,
      input.prepared.boardId,
      input.prepared.targetId,
      input.version,
      input.action.title,
      input.action.scheduledStartAt,
      input.action.scheduledEndAt,
      Buffer.from(canonicalJson(input.prepared.canonicalPayload), "utf8"),
      Buffer.from(input.prepared.packageSha256, "hex"),
      Buffer.from(meetingSha256, "hex"),
      input.action.kind === "create" ? "Initial meeting call." : input.action.reason,
      input.consentRecordId,
      input.prepared.context.memberId
    ]
  );
  await client.query(
    `insert into agenda_versions(
       id,organization_id,board_id,meeting_id,meeting_version_id,version,schema_version,
       canonical_payload,canonical_sha256,created_by
     ) values ($1,$2,$3,$4,$5,$6,'boardagent.agenda.v1',$7,$8,$9)`,
    [
      input.agendaVersionId,
      input.prepared.organizationId,
      input.prepared.boardId,
      input.prepared.targetId,
      input.meetingVersionId,
      input.version,
      Buffer.from(canonicalJson(input.action.agenda), "utf8"),
      Buffer.from(agendaSha256, "hex"),
      input.prepared.context.memberId
    ]
  );
  await insertAgendaItems(client, input.agendaVersionId, input.action.agenda);
  return { meetingSha256, agendaSha256 };
}

async function actCreate(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: MeetingLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "create" || prepared.details.kind !== "create") {
    throw new Error("meeting creation preparation mismatch");
  }
  const meetingVersionId = newId();
  const agendaVersionId = newId();
  const meetingAuditEventId = newId();
  const noticeAuditEventIds = prepared.details.recipients.map(() => newId());
  await client.query(
    `insert into meetings(
       id,organization_id,board_id,title,state,scheduled_start,scheduled_end,
       current_version_id,current_agenda_version_id,row_version,created_by
     ) values ($1,$2,$3,$4,'called',$5,$6,$7,$8,1,$9)`,
    [
      prepared.targetId,
      prepared.organizationId,
      prepared.boardId,
      prepared.action.title,
      prepared.action.scheduledStartAt,
      prepared.action.scheduledEndAt,
      meetingVersionId,
      agendaVersionId,
      prepared.context.memberId
    ]
  );
  const hashes = await insertMeetingVersionSet(client, {
    prepared,
    action: prepared.action,
    consentRecordId,
    meetingVersionId,
    agendaVersionId,
    version: 1,
    recipients: prepared.details.recipients
  });
  for (const [index, recipient] of prepared.details.recipients.entries()) {
    const noticeAuditEventId = noticeAuditEventIds[index];
    if (!noticeAuditEventId) throw new Error("meeting notice audit ID is unavailable");
    await insertMeetingNotice(client, {
      prepared,
      recipient,
      noticeType: "meeting_called",
      objectVersion: 1,
      packageSha256: prepared.packageSha256,
      noticeAuditEventId
    });
  }
  const auditEvents: AuditAppendInput[] = [
    confirmedAudit(
      prepared,
      consentRecordId,
      meetingAuditEventId,
      "meeting_called",
      "meeting",
      prepared.targetId,
      {
        meetingVersionId,
        meetingSha256: hashes.meetingSha256,
        agendaVersionId,
        agendaSha256: hashes.agendaSha256,
        packageSha256: prepared.packageSha256,
        recipientMemberIds: prepared.details.recipients.map(({ memberId }) => memberId)
      },
      1n
    )
  ];
  for (const [index, recipient] of prepared.details.recipients.entries()) {
    const noticeAuditEventId = noticeAuditEventIds[index];
    if (!noticeAuditEventId) throw new Error("meeting notice audit ID is unavailable");
    auditEvents.push(
      confirmedAudit(
        prepared,
        consentRecordId,
        noticeAuditEventId,
        "notice_delivered",
        "meeting",
        prepared.targetId,
        {
          meaning: "committed_recipient_feed_handoff",
          noticeType: "meeting_called",
          recipientMemberId: recipient.memberId
        },
        1n
      )
    );
  }
  return {
    value: {
      kind: "create",
      meetingId: prepared.targetId,
      meetingVersionId,
      agendaVersionId,
      version: 1,
      packageSha256: prepared.packageSha256,
      recipientMemberIds: prepared.details.recipients.map(({ memberId }) => memberId)
    },
    auditEvents
  };
}

async function applyMeetingChange(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string,
  meetingVersionId: string | null,
  agendaVersionId: string | null
): Promise<number> {
  const root = prepared.details.kind === "create" ? undefined : prepared.details.root;
  if (!root) throw new Error("existing meeting root is unavailable");
  const changed = await client.query<{ row_version: string }>(
    `select boardagent_apply_meeting_change(
       $1,$2::bigint,$3,$4,$5,$6,$7,$8
     )::text as row_version`,
    [
      root.id,
      root.row_version,
      prepared.actionCode,
      consentRecordId,
      Buffer.from(prepared.payloadSha256, "hex"),
      Buffer.from(prepared.packageSha256, "hex"),
      meetingVersionId,
      agendaVersionId
    ]
  );
  const rowVersion = Number(changed.rows[0]?.row_version);
  if (!Number.isSafeInteger(rowVersion) || rowVersion < 2) {
    throw new Error("meeting transition returned an invalid row version");
  }
  return rowVersion;
}

async function actAmendment(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: MeetingLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "amend" || prepared.details.kind !== "amend") {
    throw new Error("meeting amendment preparation mismatch");
  }
  const version = prepared.details.root.meeting_version + 1;
  const meetingVersionId = newId();
  const agendaVersionId = newId();
  const meetingAuditEventId = newId();
  const noticeAuditEventIds = prepared.details.recipients.map(() => newId());
  const hashes = await insertMeetingVersionSet(client, {
    prepared,
    action: prepared.action,
    consentRecordId,
    meetingVersionId,
    agendaVersionId,
    version,
    recipients: prepared.details.recipients
  });
  const rowVersion = await applyMeetingChange(
    client,
    prepared,
    consentRecordId,
    meetingVersionId,
    agendaVersionId
  );
  for (const [index, recipient] of prepared.details.recipients.entries()) {
    const noticeAuditEventId = noticeAuditEventIds[index];
    if (!noticeAuditEventId) throw new Error("meeting notice audit ID is unavailable");
    await insertMeetingNotice(client, {
      prepared,
      recipient,
      noticeType: "meeting_amended",
      objectVersion: version,
      packageSha256: prepared.packageSha256,
      noticeAuditEventId
    });
  }
  const auditEvents: AuditAppendInput[] = [
    confirmedAudit(
      prepared,
      consentRecordId,
      meetingAuditEventId,
      "meeting_amended",
      "meeting",
      prepared.targetId,
      {
        priorMeetingVersionId: prepared.details.root.meeting_version_id,
        meetingVersionId,
        meetingSha256: hashes.meetingSha256,
        agendaVersionId,
        agendaSha256: hashes.agendaSha256,
        packageSha256: prepared.packageSha256,
        reason: prepared.action.reason,
        recipientMemberIds: prepared.details.recipients.map(({ memberId }) => memberId)
      },
      BigInt(rowVersion)
    )
  ];
  for (const [index, recipient] of prepared.details.recipients.entries()) {
    const noticeAuditEventId = noticeAuditEventIds[index];
    if (!noticeAuditEventId) throw new Error("meeting notice audit ID is unavailable");
    auditEvents.push(
      confirmedAudit(
        prepared,
        consentRecordId,
        noticeAuditEventId,
        "notice_delivered",
        "meeting",
        prepared.targetId,
        {
          meaning: "committed_recipient_feed_handoff",
          noticeType: "meeting_amended",
          recipientMemberId: recipient.memberId
        },
        BigInt(rowVersion)
      )
    );
  }
  return {
    value: {
      kind: "amend",
      meetingId: prepared.targetId,
      meetingVersionId,
      agendaVersionId,
      version,
      packageSha256: prepared.packageSha256,
      recipientMemberIds: prepared.details.recipients.map(({ memberId }) => memberId)
    },
    auditEvents
  };
}

async function actAttendanceCorrection(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: MeetingLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "attendance_correction" ||
    prepared.details.kind !== "attendance_correction"
  ) {
    throw new Error("attendance correction preparation mismatch");
  }
  const attendanceId = newId();
  const auditEventId = newId();
  await client.query(
    `insert into meeting_attendance(
       id,organization_id,board_id,meeting_id,member_id,attendance_status,source,
       recorder_member_id,corrects_id,correction_reason,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,'correction',$7,$8,$9,$10)`,
    [
      attendanceId,
      prepared.organizationId,
      prepared.boardId,
      prepared.details.root.id,
      prepared.details.memberId,
      prepared.action.status,
      prepared.context.memberId,
      prepared.details.priorAttendanceId,
      prepared.action.reason,
      consentRecordId
    ]
  );
  return {
    value: {
      kind: "attendance_correction",
      meetingId: prepared.details.root.id,
      priorAttendanceId: prepared.details.priorAttendanceId,
      attendanceId,
      status: prepared.action.status
    },
    auditEvents: [
      confirmedAudit(
        prepared,
        consentRecordId,
        auditEventId,
        "meeting_attendance_corrected",
        "meeting_attendance",
        attendanceId,
        {
          meetingId: prepared.details.root.id,
          priorAttendanceId: prepared.details.priorAttendanceId,
          memberId: prepared.details.memberId,
          correctedStatus: prepared.action.status,
          reason: prepared.action.reason
        },
        BigInt(prepared.details.root.row_version)
      )
    ]
  };
}

async function actCancellation(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: MeetingLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "cancellation" || prepared.details.kind !== "cancellation") {
    throw new Error("meeting cancellation preparation mismatch");
  }
  const auditEventId = newId();
  const noticeAuditEventIds = prepared.details.recipients.map(() => newId());
  const rowVersion = await applyMeetingChange(client, prepared, consentRecordId, null, null);
  for (const [index, recipient] of prepared.details.recipients.entries()) {
    const noticeAuditEventId = noticeAuditEventIds[index];
    if (!noticeAuditEventId) throw new Error("meeting notice audit ID is unavailable");
    await insertMeetingNotice(client, {
      prepared,
      recipient,
      noticeType: "meeting_cancelled",
      objectVersion: rowVersion,
      packageSha256: prepared.packageSha256,
      noticeAuditEventId
    });
  }
  const auditEvents: AuditAppendInput[] = [
    confirmedAudit(
      prepared,
      consentRecordId,
      auditEventId,
      "meeting_cancelled",
      "meeting",
      prepared.targetId,
      {
        meetingVersionId: prepared.details.root.meeting_version_id,
        meetingSha256: prepared.details.root.meeting_sha256.toString("hex"),
        reason: prepared.action.reason,
        packageSha256: prepared.packageSha256,
        recipientMemberIds: prepared.details.recipients.map(({ memberId }) => memberId)
      },
      BigInt(rowVersion)
    )
  ];
  for (const [index, recipient] of prepared.details.recipients.entries()) {
    const noticeAuditEventId = noticeAuditEventIds[index];
    if (!noticeAuditEventId) throw new Error("meeting notice audit ID is unavailable");
    auditEvents.push(
      confirmedAudit(
        prepared,
        consentRecordId,
        noticeAuditEventId,
        "notice_delivered",
        "meeting",
        prepared.targetId,
        {
          meaning: "committed_recipient_feed_handoff",
          noticeType: "meeting_cancelled",
          recipientMemberId: recipient.memberId
        },
        BigInt(rowVersion)
      )
    );
  }
  return {
    value: { kind: "cancellation", meetingId: prepared.targetId, state: "cancelled", rowVersion },
    auditEvents
  };
}

async function actCompletion(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: MeetingLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "completion" || prepared.details.kind !== "completion") {
    throw new Error("meeting completion preparation mismatch");
  }
  const auditEventId = newId();
  const rowVersion = await applyMeetingChange(client, prepared, consentRecordId, null, null);
  return {
    value: { kind: "completion", meetingId: prepared.targetId, state: "completed", rowVersion },
    auditEvents: [
      confirmedAudit(
        prepared,
        consentRecordId,
        auditEventId,
        "meeting_completed",
        "meeting",
        prepared.targetId,
        {
          meetingVersionId: prepared.details.root.meeting_version_id,
          meetingSha256: prepared.details.root.meeting_sha256.toString("hex"),
          attendanceManifestSha256: prepared.details.attendanceManifestSha256,
          attendanceRecordIds: prepared.details.attendance.map(({ attendanceId }) => attendanceId)
        },
        BigInt(rowVersion)
      )
    ]
  };
}

async function performConfirmedAction(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: MeetingLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  switch (prepared.action.kind) {
    case "create":
      return actCreate(client, prepared, consentRecordId);
    case "amend":
      return actAmendment(client, prepared, consentRecordId);
    case "attendance_correction":
      return actAttendanceCorrection(client, prepared, consentRecordId);
    case "cancellation":
      return actCancellation(client, prepared, consentRecordId);
    case "completion":
      return actCompletion(client, prepared, consentRecordId);
  }
}

export async function confirmMeetingLifecycleActionInTransaction(
  client: PoolClient,
  input: MeetingLifecycleConfirmationInput
): Promise<StagedActionResolution<MeetingLifecycleResult>> {
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
      if (!prepared) throw new Error("meeting lifecycle preparation is unavailable");
      return performConfirmedAction(requestClient, prepared, consentRecordId);
    }
  );
}

function normalizeIdempotencyKey(value: string): string {
  if (
    value.length < 16 ||
    value.length > MAX_IDEMPOTENCY_KEY ||
    !/^[A-Za-z0-9._~-]+$/u.test(value)
  ) {
    throw new RangeError("idempotency key must contain 16 through 200 safe characters");
  }
  return value;
}

async function lockIdempotency(
  client: PoolClient,
  context: ActiveRequestContext,
  operation: "rsvp" | "record_attendance",
  key: string,
  requestSha256: string
): Promise<IdempotencyRow | undefined> {
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
    throw new MeetingTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for different meeting bytes"
    );
  }
  if (row.state !== "succeeded" || !row.safe_response_id || !row.safe_response_sha256) {
    throw new MeetingTransactionError(
      "idempotency_conflict",
      "identical meeting operation is not a completed safe response"
    );
  }
  return row;
}

async function insertIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly context: ActiveRequestContext;
    readonly operation: "rsvp" | "record_attendance";
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
  responseType: "meeting_rsvp" | "meeting_attendance",
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
  if (updated.rowCount !== 1) throw new Error("meeting idempotency completion failed");
}

function directAudit(input: {
  readonly context: ActiveRequestContext;
  readonly organizationId: string;
  readonly boardId: string;
  readonly eventId: string;
  readonly eventType: "meeting_rsvp_recorded" | "meeting_attendance_recorded";
  readonly entityType: "meeting_rsvp" | "meeting_attendance";
  readonly entityId: string;
  readonly details: Readonly<Record<string, JsonValue>>;
  readonly objectVersion: bigint;
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

export async function recordMeetingRsvpInTransaction(
  client: PoolClient,
  rawInput: RecordMeetingRsvpInput
): Promise<DirectMeetingResult> {
  const meetingId = UuidV7Schema.parse(rawInput.meetingId);
  const rsvpId = UuidV7Schema.parse(rawInput.rsvpId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const key = normalizeIdempotencyKey(rawInput.idempotencyKey);
  const note =
    rawInput.note === null ? null : boundedText(rawInput.note, "meeting RSVP note", 4096);
  const context = await readRequestContext(client);
  const meetingResult = await client.query<{
    organization_id: string;
    board_id: string;
    row_version: string;
  }>(
    `select meeting.organization_id,meeting.board_id,meeting.row_version::text
       from meetings as meeting
       join board_memberships as membership
         on membership.organization_id=meeting.organization_id
        and membership.board_id=meeting.board_id
        and membership.member_id=$2
      where meeting.id=$1
        and meeting.state='called'
        and membership.state='active'
        and membership.seat_role<>'observer'
        and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
        and boardagent_meeting_actor_ready(meeting.board_id,'meeting:act')`,
    [meetingId, context.memberId]
  );
  const meeting = meetingResult.rows[0];
  if (!meeting || meetingResult.rows.length !== 1) {
    throw new MeetingTransactionError("meeting_action_unavailable", "meeting RSVP is unavailable");
  }
  const requestSha256 = canonicalSha256({
    operation: "rsvp",
    meetingId,
    response: rawInput.response,
    note
  });
  const replay = await lockIdempotency(client, context, "rsvp", key, requestSha256);
  if (replay) {
    const safeResponseId = replay.safe_response_id;
    const safeResponseSha256 = replay.safe_response_sha256;
    if (!safeResponseId || !safeResponseSha256) {
      throw new Error("meeting RSVP replay is incomplete");
    }
    const prior = await client.query<{ meeting_id: string; version: number }>(
      "select meeting_id,version from meeting_rsvps where id=$1",
      [safeResponseId]
    );
    const row = prior.rows[0];
    if (!row || row.meeting_id !== meetingId) throw new Error("meeting RSVP replay is unavailable");
    return {
      replayed: true,
      meetingId,
      recordId: safeResponseId,
      version: row.version,
      responseSha256: safeResponseSha256.toString("hex")
    };
  }
  const current = await client.query<{ id: string; version: number }>(
    `select id,version from meeting_rsvps
      where meeting_id=$1 and member_id=$2 and is_current
      for update`,
    [meetingId, context.memberId]
  );
  const nextVersion = (current.rows[0]?.version ?? 0) + 1;
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    context,
    operation: "rsvp",
    key,
    requestSha256
  });
  if (current.rows[0]) {
    const changed = await client.query(
      "update meeting_rsvps set is_current=false where id=$1 and is_current",
      [current.rows[0].id]
    );
    if (changed.rowCount !== 1) throw new Error("meeting RSVP changed during replacement");
  }
  await client.query(
    `insert into meeting_rsvps(
       id,organization_id,board_id,meeting_id,member_id,version,response,is_current,
       idempotency_record_id,note
     ) values ($1,$2,$3,$4,$5,$6,$7,true,$8,$9)`,
    [
      rsvpId,
      meeting.organization_id,
      meeting.board_id,
      meetingId,
      context.memberId,
      nextVersion,
      rawInput.response,
      idempotencyRecordId,
      note
    ]
  );
  await appendAuditEventsInTransaction(client, [
    directAudit({
      context,
      organizationId: meeting.organization_id,
      boardId: meeting.board_id,
      eventId: auditEventId,
      eventType: "meeting_rsvp_recorded",
      entityType: "meeting_rsvp",
      entityId: rsvpId,
      details: { meetingId, response: rawInput.response, note, version: nextVersion },
      objectVersion: BigInt(nextVersion)
    })
  ]);
  const responseSha256 = canonicalSha256({ meetingId, rsvpId, version: nextVersion });
  await completeIdempotency(client, idempotencyRecordId, "meeting_rsvp", rsvpId, responseSha256);
  return {
    replayed: false,
    meetingId,
    recordId: rsvpId,
    version: nextVersion,
    responseSha256
  };
}

export async function recordMeetingAttendanceInTransaction(
  client: PoolClient,
  rawInput: RecordMeetingAttendanceInput
): Promise<DirectMeetingResult> {
  const meetingId = UuidV7Schema.parse(rawInput.meetingId);
  const memberId = UuidV7Schema.parse(rawInput.memberId);
  const attendanceId = UuidV7Schema.parse(rawInput.attendanceId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const key = normalizeIdempotencyKey(rawInput.idempotencyKey);
  if (rawInput.source !== "secretary_record") {
    throw new MeetingTransactionError(
      "meeting_action_invalid",
      "secretary attendance recording requires secretary_record source"
    );
  }
  const context = await readRequestContext(client);
  const meetingResult = await client.query<{
    organization_id: string;
    board_id: string;
    row_version: string;
  }>(
    `select meeting.organization_id,meeting.board_id,meeting.row_version::text
       from meetings as meeting
      where meeting.id=$1
        and meeting.state in ('called','completed')
        and boardagent_meeting_secretary_for_board(meeting.board_id)
        and exists (
          select 1 from notices as notice
           where notice.object_type='meeting'
             and notice.object_id=meeting.id
             and notice.notice_type='meeting_called'
             and notice.recipient_member_id=$2
        )
      for update of meeting`,
    [meetingId, memberId]
  );
  const meeting = meetingResult.rows[0];
  if (!meeting || meetingResult.rows.length !== 1) {
    throw new MeetingTransactionError(
      "meeting_action_unavailable",
      "meeting attendance recording is unavailable"
    );
  }
  const requestSha256 = canonicalSha256({
    operation: "record_attendance",
    meetingId,
    memberId,
    status: rawInput.status,
    source: rawInput.source
  });
  const replay = await lockIdempotency(client, context, "record_attendance", key, requestSha256);
  if (replay) {
    const safeResponseId = replay.safe_response_id;
    const safeResponseSha256 = replay.safe_response_sha256;
    if (!safeResponseId || !safeResponseSha256) {
      throw new Error("meeting attendance replay is incomplete");
    }
    const prior = await client.query<{ meeting_id: string }>(
      "select meeting_id from meeting_attendance where id=$1",
      [safeResponseId]
    );
    if (prior.rows[0]?.meeting_id !== meetingId) {
      throw new Error("meeting attendance replay is unavailable");
    }
    return {
      replayed: true,
      meetingId,
      recordId: safeResponseId,
      version: 1,
      responseSha256: safeResponseSha256.toString("hex")
    };
  }
  const existing = await client.query<{ id: string }>(
    "select id from meeting_attendance where meeting_id=$1 and member_id=$2 and corrects_id is null",
    [meetingId, memberId]
  );
  if (existing.rows.length !== 0) {
    throw new MeetingTransactionError(
      "meeting_action_unavailable",
      "attendance was already recorded; use a confirmed correction"
    );
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    context,
    operation: "record_attendance",
    key,
    requestSha256
  });
  await client.query(
    `insert into meeting_attendance(
       id,organization_id,board_id,meeting_id,member_id,attendance_status,source,
       recorder_member_id
     ) values ($1,$2,$3,$4,$5,$6,'secretary_record',$7)`,
    [
      attendanceId,
      meeting.organization_id,
      meeting.board_id,
      meetingId,
      memberId,
      rawInput.status,
      context.memberId
    ]
  );
  await appendAuditEventsInTransaction(client, [
    directAudit({
      context,
      organizationId: meeting.organization_id,
      boardId: meeting.board_id,
      eventId: auditEventId,
      eventType: "meeting_attendance_recorded",
      entityType: "meeting_attendance",
      entityId: attendanceId,
      details: { meetingId, memberId, status: rawInput.status, source: rawInput.source },
      objectVersion: 1n
    })
  ]);
  const responseSha256 = canonicalSha256({ meetingId, attendanceId, memberId });
  await completeIdempotency(
    client,
    idempotencyRecordId,
    "meeting_attendance",
    attendanceId,
    responseSha256
  );
  return {
    replayed: false,
    meetingId,
    recordId: attendanceId,
    version: 1,
    responseSha256
  };
}
