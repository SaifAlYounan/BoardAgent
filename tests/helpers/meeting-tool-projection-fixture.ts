import type { Pool } from "pg";
import { expect } from "vitest";
import {
  PgBoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  canonicalJson,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { seedAuthorizedActor, testId, type AuthorizedActorFixture } from "./authorized-actor.js";
import { confirmSyntheticSurfaceAction } from "./confirmed-surface-action.js";

type FixtureTool =
  | "create_document_version"
  | "create_meeting"
  | "amend_meeting"
  | "record_attendance"
  | "correct_attendance"
  | "rsvp"
  | "create_meeting_transcript_version";
export interface MeetingToolProjectionFixture {
  readonly secretary: AuthorizedActorFixture;
  readonly meetingId: string;
  readonly emptyMeetingId: string;
  readonly documentVersionId: string;
  readonly documentSha256: string;
  readonly originalAgendaId: string;
  readonly amendedAgendaId: string;
  readonly originalAttendanceId: string;
  readonly commands: readonly { readonly tool: FixtureTool; readonly reference: string | null }[];
  currentVersion(): number;
  currentAttendanceId(): string;
  amendAgain(): Promise<{ readonly agendaVersionId: string; readonly version: number }>;
  correctAgain(): Promise<string>;
  createThirdMeeting(): Promise<string>;
  rsvpAttending(): Promise<void>;
  rsvpTentative(): Promise<void>;
  createTranscript(): Promise<{
    readonly transcriptId: string;
    readonly versionId: string;
    readonly sha256: string;
  }>;
  replaceTranscript(): Promise<{
    readonly transcriptId: string;
    readonly versionId: string;
    readonly sha256: string;
  }>;
}

// Six ordinary supported commands by default. Confirmation acceptance is synthetic
// test data. No unrestricted service/confirmation port escapes this closure.
// Named RSVP/transcript/third-meeting methods are optional and single-use.
// Their commands are not performed or counted by the six-command base.
export async function seedMeetingToolProjectionFixture(
  pool: Pool
): Promise<MeetingToolProjectionFixture> {
  const scopes = [
    "secretariat:admin",
    "governance:read",
    "meeting:act",
    "documents:read",
    "documents:contribute"
  ];
  const secretary = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes,
    isSecretary: true
  });
  // This is the ordinary command fixture principal. Public read/native tests add
  // a constrained session and derive their principal from the actual live resolver.
  const commandPrincipal: SurfacePrincipal = {
    organizationId: secretary.organizationId,
    memberId: secretary.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: secretary.clientId,
    protocolClientId: "https://meeting-agent.test/client.json",
    accessTokenRecordId: secretary.accessTokenRecordId,
    tokenJti: secretary.tokenJti,
    keyId: "test-oauth",
    scopes,
    roles: ["member", "secretariat"],
    boardIds: [secretary.boardId]
  };
  let nextId = 286000;
  const service = new PgBoardAgentSurfaceService(pool, {
    transaction: { assumeRole: "boardagent_server" },
    newId: () => testId(nextId++),
    reads: {
      executeRead: async () => {
        throw new Error("fixture read port is unavailable");
      },
      readResource: async () => {
        throw new Error("fixture resource port is unavailable");
      }
    }
  });
  const commands: { tool: FixtureTool; reference: string | null }[] = [];
  async function confirm(
    tool: "create_meeting" | "amend_meeting" | "correct_attendance",
    input: JsonValue
  ) {
    const { result } = await confirmSyntheticSurfaceAction(service, commandPrincipal, tool, input);
    expect(result.status).toBe("accepted");
    commands.push({ tool, reference: result.reference });
    return result;
  }
  const meetingId = testId(285002),
    emptyMeetingId = testId(285003);
  const body = "# Synthetic meeting source\n\nAgenda reference Δ.\n";
  const document = await service.executeDirect(commandPrincipal, "create_document_version", {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    board_id: secretary.boardId,
    document_id: testId(285001),
    title: "Synthetic meeting source",
    media_type: "text/markdown; charset=utf-8",
    schema_name: null,
    canonical_body: body,
    expected_current_version_id: null,
    idempotency_key: "meeting-projection-document-0001"
  });
  expect(document.status).toBe("accepted");
  if (document.reference === null) throw new Error("document fixture has no version identity");
  const documentVersionId = document.reference,
    documentSha256 = sha256Hex(body);
  expect(document).toMatchObject({
    data: { document_version_id: documentVersionId, sha256: documentSha256 }
  });
  commands.push({ tool: "create_document_version", reference: document.reference });
  const agenda = (version: number) => ({
    schema_version: "boardagent.agenda.v1",
    values: {
      items: [
        {
          title: `First item v${version}: permits Δ`,
          source_document_version_id: null,
          source_document_sha256: null
        },
        {
          title: `Second item v${version}: source "review"`,
          source_document_version_id: documentVersionId,
          source_document_sha256: documentSha256
        },
        {
          title: `Third item v${version}: attendance 🙂`,
          source_document_version_id: null,
          source_document_sha256: null
        }
      ]
    }
  });
  const createInput = (id: string, title: string, key: string) => ({
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    board_id: secretary.boardId,
    meeting_id: id,
    title,
    scheduled_start_at: "2026-10-01T09:00:00.000Z",
    scheduled_end_at: "2026-10-01T10:30:00.000Z",
    timezone: "Asia/Dubai",
    agenda: agenda(1),
    attendee_member_ids: [secretary.memberId],
    idempotency_key: key
  });
  async function currentRoot() {
    // Setup observation only; actual-role visibility is independently tested.
    const found = await pool.query<{
      row_version: string;
      agenda_version_id: string;
      version: number;
    }>(
      `select meeting.row_version::text,agenda.id as agenda_version_id,agenda.version
       from meetings as meeting join agenda_versions as agenda
         on agenda.id=meeting.current_agenda_version_id and agenda.meeting_id=meeting.id
       where meeting.id=$1`,
      [meetingId]
    );
    expect(found.rows).toHaveLength(1);
    return found.rows[0]!;
  }
  const created = await confirm(
    "create_meeting",
    createInput(meetingId, "Synthetic projection meeting", "meeting-projection-create-main-0001")
  );
  expect(created).toMatchObject({ data: { meeting_id: meetingId, version: 1 } });
  const original = await currentRoot();
  expect(original.version).toBe(1);
  let currentVersion = 1;
  async function amend(version: number) {
    const current = await currentRoot(),
      rowVersion = Number(current.row_version);
    if (!Number.isSafeInteger(rowVersion) || rowVersion < 1)
      throw new Error("fixture row version is invalid");
    const result = await confirm("amend_meeting", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      meeting_id: meetingId,
      expected_row_version: rowVersion,
      title: `Synthetic projection meeting v${version}`,
      scheduled_start_at: "2026-10-01T09:30:00.000Z",
      scheduled_end_at: "2026-10-01T11:00:00.000Z",
      timezone: "Asia/Dubai",
      agenda: agenda(version),
      reason: `Exact synthetic agenda revision ${version}.`,
      idempotency_key: `meeting-projection-amend-${version}-0001`
    });
    expect(result).toMatchObject({ data: { meeting_id: meetingId, version } });
    const fresh = await currentRoot();
    expect(fresh.version).toBe(version);
    currentVersion = fresh.version;
    return fresh;
  }
  const amended = await amend(2);
  expect(amended.agenda_version_id).not.toBe(original.agenda_version_id);
  const recorded = await service.executeDirect(commandPrincipal, "record_attendance", {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    meeting_id: meetingId,
    member_id: secretary.memberId,
    status: "present",
    source: "secretary_record",
    idempotency_key: "meeting-projection-attendance-0001"
  });
  expect(recorded.status).toBe("accepted");
  if (recorded.reference === null) throw new Error("attendance fixture has no identity");
  const originalAttendanceId = recorded.reference;
  let currentAttendanceId = originalAttendanceId;
  commands.push({ tool: "record_attendance", reference: recorded.reference });
  async function correct(sequence: number, status: "excused" | "absent") {
    const prior = currentAttendanceId;
    const result = await confirm("correct_attendance", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      attendance_id: prior,
      status,
      reason: `Synthetic attendance correction ${sequence}: status Δ.`,
      idempotency_key: `meeting-projection-correction-${sequence}-0001`
    });
    expect(result).toMatchObject({
      data: { meeting_id: meetingId, prior_attendance_id: prior, status }
    });
    const found = await pool.query<{ id: string }>(
      "select id from meeting_attendance where meeting_id=$1 and corrects_id=$2",
      [meetingId, prior]
    );
    expect(found.rows).toHaveLength(1);
    currentAttendanceId = found.rows[0]!.id;
    return currentAttendanceId;
  }
  await correct(1, "excused");
  await confirm(
    "create_meeting",
    createInput(
      emptyMeetingId,
      "Synthetic empty attendance meeting",
      "meeting-projection-create-empty-0001"
    )
  );
  const counts = await pool.query<{ meeting_id: string; count: string }>(
    "select meeting_id,count(*)::text as count from meeting_attendance where meeting_id=any($1::uuid[]) group by meeting_id",
    [[meetingId, emptyMeetingId]]
  );
  expect(counts.rows).toEqual([{ meeting_id: meetingId, count: "2" }]);
  expect(commands).toHaveLength(6);
  let thirdCreated = false,
    rsvpStage = 0,
    transcriptStage = 0,
    transcriptVersionId: string | null = null;
  const thirdMeetingId = testId(285004),
    transcriptId = testId(285005);
  async function rsvp(stage: 1 | 2, response: "attending" | "tentative") {
    if (rsvpStage !== stage - 1) throw new Error("fixture RSVP sequence is invalid");
    rsvpStage = stage;
    const result = await service.executeDirect(commandPrincipal, "rsvp", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      meeting_id: meetingId,
      response,
      note: stage === 1 ? "Synthetic secure attendance Δ." : null,
      idempotency_key: `meeting-projection-rsvp-${stage}-0001`
    });
    expect(result).toMatchObject({ status: "accepted", data: { version: stage } });
    commands.push({ tool: "rsvp", reference: result.reference });
    const current = await pool.query<{ response: string }>(
      "select response from meeting_rsvps where meeting_id=$1 and member_id=$2 and is_current",
      [meetingId, secretary.memberId]
    );
    expect(current.rows).toEqual([{ response }]);
  }
  async function transcript(version: 1 | 2) {
    if (transcriptStage !== version - 1) throw new Error("fixture transcript sequence is invalid");
    transcriptStage = version;
    const prior = transcriptVersionId;
    if ((version === 1) !== (prior === null))
      throw new Error("fixture transcript version binding is invalid");
    const body = canonicalJson({
      schema_version: "boardagent.transcript-turns.v1",
      values: {
        turns: [
          {
            turn_id: testId(version === 1 ? 285006 : 285007),
            speaker_member_id: secretary.memberId,
            speaker_label: "Synthetic secretary",
            starts_at_ms: 0,
            ends_at_ms: 1000,
            canonical_text:
              version === 1 ? "Synthetic permits review Δ." : "Synthetic permits update Δ."
          }
        ]
      }
    });
    const expectedHash = sha256Hex(body);
    const result = await service.executeDirect(
      commandPrincipal,
      "create_meeting_transcript_version",
      {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        transcript_id: transcriptId,
        media_type: "application/json",
        canonical_body: body,
        coverage_statement: "Synthetic one-turn meeting excerpt.",
        supersedes_version_id: prior,
        idempotency_key: `meeting-projection-transcript-${version}-0001`
      }
    );
    expect(result).toMatchObject({
      status: "accepted",
      data: { transcript_id: transcriptId, version, canonical_sha256: expectedHash }
    });
    if (result.reference === null) throw new Error("fixture transcript has no version identity");
    transcriptVersionId = result.reference;
    commands.push({ tool: "create_meeting_transcript_version", reference: result.reference });
    const stored = await pool.query<{
      id: string;
      version_id: string;
      version: number;
      sha256: string;
    }>(
      `select transcript.id,version.id as version_id,version.version,encode(version.canonical_sha256,'hex') as sha256
       from meeting_transcripts as transcript join meeting_transcript_versions as version on version.id=transcript.current_version_id
       where transcript.id=$1 and transcript.meeting_id=$2`,
      [transcriptId, meetingId]
    );
    expect(stored.rows).toEqual([
      { id: transcriptId, version_id: result.reference, version, sha256: expectedHash }
    ]);
    return { transcriptId, versionId: result.reference, sha256: expectedHash };
  }
  let amendedAgain = false,
    correctedAgain = false;
  return {
    secretary,
    meetingId,
    emptyMeetingId,
    documentVersionId,
    documentSha256,
    originalAgendaId: original.agenda_version_id,
    amendedAgendaId: amended.agenda_version_id,
    originalAttendanceId,
    commands,
    currentVersion: () => currentVersion,
    currentAttendanceId: () => currentAttendanceId,
    amendAgain: async () => {
      if (amendedAgain) throw new Error("fixture amendment already consumed");
      amendedAgain = true;
      const fresh = await amend(3);
      return { agendaVersionId: fresh.agenda_version_id, version: fresh.version };
    },
    correctAgain: async () => {
      if (correctedAgain) throw new Error("fixture correction already consumed");
      correctedAgain = true;
      return correct(2, "absent");
    },
    createThirdMeeting: async () => {
      if (thirdCreated) throw new Error("fixture third meeting already consumed");
      thirdCreated = true;
      const result = await confirm(
        "create_meeting",
        createInput(
          thirdMeetingId,
          'Synthetic third meeting: "review" Δ',
          "meeting-projection-create-third-0001"
        )
      );
      expect(result).toMatchObject({ data: { meeting_id: thirdMeetingId, version: 1 } });
      return thirdMeetingId;
    },
    rsvpAttending: () => rsvp(1, "attending"),
    rsvpTentative: () => rsvp(2, "tentative"),
    createTranscript: () => transcript(1),
    replaceTranscript: () => transcript(2)
  };
}
