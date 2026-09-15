import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import {
  migrate,
  scheduleAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { withConfiguredFixtureWorker } from "../helpers/configured-worker.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_surface_meeting_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "surface-meeting-lifecycle-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function principal(
  actor: AuthorizedActorFixture,
  roles: readonly ("admin" | "member" | "observer" | "secretariat")[],
  scopes: readonly string[]
): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://meeting-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes,
    roles,
    boardIds: [actor.boardId]
  };
}

let confirmationSequence = 0;

async function confirmSurfaceAction(
  service: BoardAgentSurfaceService,
  actorPrincipal: SurfacePrincipal,
  tool: string,
  input: JsonValue,
  afterStage?: () => Promise<void>
) {
  confirmationSequence += 1;
  const requestLabel = `surface-meeting-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const prepared = await service.prepareHumanAction(actorPrincipal, tool, input);
  expect(prepared).toMatchObject({
    action_code: tool,
    target_type: tool === "correct_attendance" ? "meeting_attendance" : "meeting"
  });
  const clientCapabilities = { elicitation: { form: {} } } as const;
  const requestState = `${requestLabel}-request-state-bound-by-client`;
  await service.persistHumanStage({
    principal: actorPrincipal,
    tool,
    input,
    prepared,
    client_capabilities: clientCapabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm exact ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${requestLabel}-prepare`)
  });
  await afterStage?.();
  const resolution = await service.resolveHumanAction({
    principal: actorPrincipal,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: clientCapabilities,
    request_state: requestState,
    retry_request_id: Buffer.from(`${requestLabel}-retry`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolution.confirmed) throw new Error(`${tool} failed: ${resolution.reason}`);
  return resolution.result;
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by meeting lifecycle test");
  },
  readResource: async () => {
    throw new Error("resource read not used by meeting lifecycle test");
  }
};

function meetingCallInput(
  boardId: string,
  meetingId: string,
  attendeeMemberIds: readonly string[],
  suffix: string
) {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    board_id: boardId,
    meeting_id: meetingId,
    title: `Exploration committee ${suffix}`,
    scheduled_start_at: "2026-10-01T09:00:00.000Z",
    scheduled_end_at: "2026-10-01T10:30:00.000Z",
    timezone: "Asia/Dubai",
    agenda: {
      schema_version: "boardagent.agenda.v1",
      values: {
        items: [
          {
            title: "Approve the phase-one drilling programme",
            source_document_version_id: null,
            source_document_sha256: null
          }
        ]
      }
    },
    attendee_member_ids: attendeeMemberIds,
    idempotency_key: `surface-meeting-call-${suffix}-0001`
  } as const;
}

describe("confirmed meeting lifecycle surface", () => {
  it("can call a meeting at the supported 1000-seat envelope after a fresh checkpoint", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin", "governance:read", "meeting:act"],
        isSecretary: true
      });
      const members = Array.from({ length: 999 }, (_, i) => testId(6_000_000 + i));
      const memberships = Array.from({ length: 999 }, (_, i) => testId(6_100_000 + i));
      // Disposable actor/seat fixtures only; the action below uses normal surface,
      // confirmation, server role and actual worker signing.
      await pool.query(
        `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
         select id,$1,'human','Capacity fixture','Capacity fixture','active'
           from unnest($2::uuid[]) as actor(id)`,
        [secretary.organizationId, members]
      );
      await pool.query(
        `insert into board_memberships(id,organization_id,board_id,member_id,seat_role,
          is_secretary,voting_weight,state)
         select membership_id,$1,$2,member_id,'voting_member',false,1,'active'
           from unnest($3::uuid[],$4::uuid[]) as actor(membership_id,member_id)`,
        [secretary.organizationId, secretary.boardId, memberships, members]
      );
      let nextId = 6_200_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      await withConfiguredFixtureWorker(pool, secretary.organizationId, async (worker) => {
        let headBefore = "";
        let result: unknown;
        let failure: unknown;
        try {
          result = await confirmSurfaceAction(
            service,
            principal(
              secretary,
              ["member", "secretariat"],
              ["secretariat:admin", "governance:read", "meeting:act"]
            ),
            "create_meeting",
            meetingCallInput(
              secretary.boardId,
              testId(6_300_000),
              [secretary.memberId, ...members],
              "capacity-envelope"
            ),
            async () => {
              await worker.worker.runOnce();
              expect(
                (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]
                  ?.count
              ).toBeGreaterThan(0);
              headBefore = (await pool.query("select last_sequence::text from audit_chain_head"))
                .rows[0]!.last_sequence as string;
            }
          );
        } catch (error) {
          failure = error;
        }
        if (failure) {
          expect(
            (await pool.query("select count(*)::int as count from meetings")).rows[0]?.count
          ).toBe(0);
          expect(
            (await pool.query("select count(*)::int as count from notices")).rows[0]?.count
          ).toBe(0);
          if (headBefore !== "") {
            expect(
              (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]
                ?.last_sequence
            ).toBe(headBefore);
          }
        }
        expect(
          failure,
          failure instanceof Error ? failure.message : String(failure)
        ).toBeUndefined();
        expect(result).toMatchObject({
          tool: "create_meeting",
          status: "accepted",
          reference: testId(6_300_000),
          data: {
            meeting_id: testId(6_300_000),
            version: 1,
            recipient_member_ids: [secretary.memberId, ...members].toSorted()
          }
        });
        expect(
          (await pool.query("select count(*)::int as count from notices")).rows[0]!.count
        ).toBe(1000);
        const headAfter = (await pool.query("select last_sequence::text from audit_chain_head"))
          .rows[0]!.last_sequence as string;
        expect(BigInt(headAfter) - BigInt(headBefore)).toBe(1002n);
        await withWorkerTransaction(
          pool,
          (client) => scheduleAuditCheckpointInTransaction(client, testId(nextId++)),
          {
            assumeRole: "boardagent_worker"
          }
        );
        await worker.worker.runOnce();
        expect(
          await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({ valid: true, ready: true });
      });
    });
  }, 30_000);

  it("calls, amends, records RSVP and attendance history, completes, and cancels with exact authority", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: [
          "secretariat:admin",
          "governance:read",
          "meeting:act",
          "documents:read",
          "documents:contribute"
        ],
        isSecretary: true
      });
      const member = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 150_100,
        seatRole: "voting_member",
        scopes: ["governance:read", "meeting:act"]
      });
      const observer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 150_200,
        seatRole: "observer",
        scopes: ["governance:read", "meeting:act"]
      });
      const adminOnly = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 150_300,
        seatRole: "voting_member",
        scopes: ["secretariat:admin", "governance:read", "meeting:act"]
      });
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','Exact meeting secretary boundary test.')`,
        [testId(150_350), secretary.organizationId, adminOnly.memberId]
      );

      let nextId = 150_500;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const secretaryPrincipal = principal(
        secretary,
        ["member", "secretariat"],
        [
          "secretariat:admin",
          "governance:read",
          "meeting:act",
          "documents:read",
          "documents:contribute"
        ]
      );
      const memberPrincipal = principal(member, ["member"], ["governance:read", "meeting:act"]);
      const observerPrincipal = principal(
        observer,
        ["observer"],
        ["governance:read", "meeting:act"]
      );
      const adminOnlyPrincipal = principal(
        adminOnly,
        ["admin", "member"],
        ["secretariat:admin", "governance:read", "meeting:act"]
      );

      const meetingId = testId(151_000);
      const sourceDocumentId = testId(151_001);
      const sourceBody = "# Drilling programme\n\nExact phase-one authority and safeguards.\n";
      const sourceVersion = await service.executeDirect(
        secretaryPrincipal,
        "create_document_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: secretary.boardId,
          document_id: sourceDocumentId,
          title: "Phase-one drilling programme",
          media_type: "text/markdown; charset=utf-8",
          schema_name: null,
          canonical_body: sourceBody,
          expected_current_version_id: null,
          idempotency_key: "surface-meeting-source-document-0001"
        }
      );
      if (sourceVersion.reference === null) throw new Error("source document version is missing");
      const baseCallInput = meetingCallInput(
        secretary.boardId,
        meetingId,
        [observer.memberId, member.memberId],
        "primary"
      );
      const callInput = {
        ...baseCallInput,
        agenda: {
          schema_version: "boardagent.agenda.v1",
          values: {
            items: [
              {
                title: "Approve the phase-one drilling programme",
                source_document_version_id: sourceVersion.reference,
                source_document_sha256: sha256Hex(sourceBody)
              }
            ]
          }
        }
      } as const;
      await expect(
        service.prepareHumanAction(secretaryPrincipal, "create_meeting", {
          ...callInput,
          meeting_id: testId(151_002),
          agenda: {
            ...callInput.agenda,
            values: {
              items: [
                {
                  ...callInput.agenda.values.items[0],
                  source_document_sha256: Buffer.alloc(32, 222).toString("hex")
                }
              ]
            }
          },
          idempotency_key: "surface-meeting-source-hash-denied-0001"
        })
      ).rejects.toThrow("every agenda document must be an exact readable version on this board");
      const called = await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "create_meeting",
        callInput
      );
      expect(called).toMatchObject({
        tool: "create_meeting",
        status: "accepted",
        reference: meetingId,
        data: {
          meeting_id: meetingId,
          version: 1,
          recipient_member_ids: [member.memberId, observer.memberId].toSorted()
        }
      });

      const calledEvidence = await pool.query<{
        state: string;
        row_version: string;
        meeting_versions: string;
        agenda_versions: string;
        agenda_items: string;
        notices: string;
        feeds: string;
        called_events: string;
        notice_events: string;
      }>(
        `select meeting.state,meeting.row_version::text,
                (select count(*)::text from meeting_versions where meeting_id=meeting.id)
                  as meeting_versions,
                (select count(*)::text from agenda_versions where meeting_id=meeting.id)
                  as agenda_versions,
                (select count(*)::text from agenda_items as item
                  join agenda_versions as agenda on agenda.id=item.agenda_version_id
                 where agenda.meeting_id=meeting.id) as agenda_items,
                (select count(*)::text from notices
                  where object_type='meeting' and object_id=meeting.id
                    and notice_type='meeting_called') as notices,
                (select count(*)::text from pending_action_feed
                  where object_type='meeting' and object_id=meeting.id
                    and action_type='meeting_called') as feeds,
                (select count(*)::text from audit_events
                  where object_id=meeting.id and event_type='meeting_called') as called_events,
                (select count(*)::text from audit_events
                  where object_id=meeting.id and event_type='notice_delivered') as notice_events
           from meetings as meeting where meeting.id=$1`,
        [meetingId]
      );
      expect(calledEvidence.rows[0]).toEqual({
        state: "called",
        row_version: "1",
        meeting_versions: "1",
        agenda_versions: "1",
        agenda_items: "1",
        notices: "2",
        feeds: "2",
        called_events: "1",
        notice_events: "2"
      });

      await expect(
        service.prepareHumanAction(
          adminOnlyPrincipal,
          "create_meeting",
          meetingCallInput(
            secretary.boardId,
            testId(151_010),
            [member.memberId],
            "admin-only-denied"
          )
        )
      ).rejects.toThrow("meeting call is unavailable");

      const tamperInput = meetingCallInput(
        secretary.boardId,
        testId(151_020),
        [member.memberId],
        "tamper-proof"
      );
      const tamperPrepared = await service.prepareHumanAction(
        secretaryPrincipal,
        "create_meeting",
        tamperInput
      );
      await expect(
        service.persistHumanStage({
          principal: secretaryPrincipal,
          tool: "create_meeting",
          input: tamperInput,
          prepared: {
            ...tamperPrepared,
            canonical_payload: {
              ...(tamperPrepared.canonical_payload as Record<string, JsonValue>),
              title: "Tampered after presentation"
            }
          },
          client_capabilities: { elicitation: { form: {} } },
          embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
          embedded_result: { message: "Tampered meeting binding" },
          request_state: "surface-meeting-tamper-request-state-bound-by-client",
          prepared_request_id: Buffer.from("surface-meeting-tamper-prepare")
        })
      ).rejects.toThrow("changed after presentation");
      const tamperEvidence = await pool.query<{ stages: string }>(
        "select count(*)::text as stages from action_stages where id=$1",
        [tamperPrepared.stage_id]
      );
      expect(tamperEvidence.rows[0]?.stages).toBe("0");

      const firstRsvpInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        response: "attending",
        note: "Joining by secure video.",
        idempotency_key: "surface-meeting-rsvp-member-0001"
      } as const;
      const firstRsvp = await service.executeDirect(memberPrincipal, "rsvp", firstRsvpInput);
      const firstRsvpReplay = await service.executeDirect(memberPrincipal, "rsvp", firstRsvpInput);
      expect(firstRsvp).toMatchObject({ status: "accepted", data: { version: 1 } });
      expect(firstRsvpReplay).toMatchObject({
        status: "already_applied",
        reference: firstRsvp.reference,
        data: { version: 1, replayed: true }
      });
      const secondRsvp = await service.executeDirect(memberPrincipal, "rsvp", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        response: "tentative",
        note: null,
        idempotency_key: "surface-meeting-rsvp-member-0002"
      });
      expect(secondRsvp).toMatchObject({ status: "accepted", data: { version: 2 } });
      await expect(
        service.executeDirect(observerPrincipal, "rsvp", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          meeting_id: meetingId,
          response: "attending",
          note: null,
          idempotency_key: "surface-meeting-rsvp-observer-denied-0001"
        })
      ).rejects.toThrow("meeting RSVP is unavailable");

      const memberAttendanceInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        member_id: member.memberId,
        status: "present",
        source: "secretary_record",
        idempotency_key: "surface-meeting-attendance-member-0001"
      } as const;
      const memberAttendance = await service.executeDirect(
        secretaryPrincipal,
        "record_attendance",
        memberAttendanceInput
      );
      const memberAttendanceReplay = await service.executeDirect(
        secretaryPrincipal,
        "record_attendance",
        memberAttendanceInput
      );
      expect(memberAttendance).toMatchObject({ status: "accepted", data: { replayed: false } });
      expect(memberAttendanceReplay).toMatchObject({
        status: "already_applied",
        reference: memberAttendance.reference,
        data: { replayed: true }
      });
      await expect(
        service.executeDirect(secretaryPrincipal, "record_attendance", {
          ...memberAttendanceInput,
          status: "absent",
          idempotency_key: "surface-meeting-attendance-member-0002"
        })
      ).rejects.toThrow("use a confirmed correction");
      await expect(
        service.prepareHumanAction(secretaryPrincipal, "complete_meeting", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          meeting_id: meetingId,
          completion_statement: "attendance_record_is_complete",
          idempotency_key: "surface-meeting-complete-incomplete-0001"
        })
      ).rejects.toThrow("every listed attendee requires one current recorded attendance status");

      const correctedAttendance = await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "correct_attendance",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          attendance_id: memberAttendance.reference,
          status: "excused",
          reason: "The original attendance record used the wrong status.",
          idempotency_key: "surface-meeting-attendance-correct-0001"
        }
      );
      expect(correctedAttendance).toMatchObject({
        data: {
          meeting_id: meetingId,
          prior_attendance_id: memberAttendance.reference,
          status: "excused"
        }
      });

      await service.executeDirect(secretaryPrincipal, "record_attendance", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        member_id: observer.memberId,
        status: "present",
        source: "secretary_record",
        idempotency_key: "surface-meeting-attendance-observer-0001"
      });

      const amended = await confirmSurfaceAction(service, secretaryPrincipal, "amend_meeting", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        expected_row_version: 1,
        title: "Exploration committee — amended",
        scheduled_start_at: "2026-10-01T09:30:00.000Z",
        scheduled_end_at: "2026-10-01T11:00:00.000Z",
        timezone: "Asia/Dubai",
        agenda: {
          schema_version: "boardagent.agenda.v1",
          values: {
            items: [
              {
                title: "Review drilling permits",
                source_document_version_id: null,
                source_document_sha256: null
              },
              {
                title: "Approve phase-one drilling",
                source_document_version_id: null,
                source_document_sha256: null
              }
            ]
          }
        },
        reason: "Permit review must precede drilling approval.",
        idempotency_key: "surface-meeting-amend-primary-0001"
      });
      expect(amended).toMatchObject({ data: { meeting_id: meetingId, version: 2 } });

      const completed = await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "complete_meeting",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          meeting_id: meetingId,
          completion_statement: "attendance_record_is_complete",
          idempotency_key: "surface-meeting-complete-primary-0001"
        }
      );
      expect(completed).toMatchObject({
        data: { meeting_id: meetingId, state: "completed", row_version: 3 }
      });
      await expect(
        service.prepareHumanAction(secretaryPrincipal, "amend_meeting", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          meeting_id: meetingId,
          expected_row_version: 3,
          title: "Forbidden terminal amendment",
          scheduled_start_at: "2026-10-01T09:30:00.000Z",
          scheduled_end_at: "2026-10-01T11:00:00.000Z",
          timezone: "Asia/Dubai",
          agenda: {
            schema_version: "boardagent.agenda.v1",
            values: {
              items: [
                {
                  title: "Forbidden terminal amendment",
                  source_document_version_id: null,
                  source_document_sha256: null
                }
              ]
            }
          },
          reason: "Terminal mutation must fail.",
          idempotency_key: "surface-meeting-amend-terminal-denied-0001"
        })
      ).rejects.toThrow("only the exact current called meeting may be amended");

      const cancelledMeetingId = testId(151_100);
      await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "create_meeting",
        meetingCallInput(secretary.boardId, cancelledMeetingId, [member.memberId], "cancelled")
      );
      const cancelled = await confirmSurfaceAction(service, secretaryPrincipal, "cancel_meeting", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: cancelledMeetingId,
        reason: "The permit hearing moved beyond the decision window.",
        idempotency_key: "surface-meeting-cancel-secondary-0001"
      });
      expect(cancelled).toMatchObject({
        data: { meeting_id: cancelledMeetingId, state: "cancelled", row_version: 2 }
      });

      const retainedEvidence = await pool.query<{
        title: string;
        state: string;
        row_version: string;
        meeting_versions: string;
        agenda_versions: string;
        agenda_items: string;
        rsvps: string;
        current_rsvps: string;
        attendance_records: string;
        amended_notices: string;
        completed_events: string;
        corrected_events: string;
      }>(
        `select meeting.title,meeting.state,meeting.row_version::text,
                (select count(*)::text from meeting_versions where meeting_id=meeting.id)
                  as meeting_versions,
                (select count(*)::text from agenda_versions where meeting_id=meeting.id)
                  as agenda_versions,
                (select count(*)::text from agenda_items as item
                  join agenda_versions as agenda on agenda.id=item.agenda_version_id
                 where agenda.meeting_id=meeting.id) as agenda_items,
                (select count(*)::text from meeting_rsvps where meeting_id=meeting.id) as rsvps,
                (select count(*)::text from meeting_rsvps
                  where meeting_id=meeting.id and is_current) as current_rsvps,
                (select count(*)::text from meeting_attendance where meeting_id=meeting.id)
                  as attendance_records,
                (select count(*)::text from notices
                  where object_id=meeting.id and notice_type='meeting_amended')
                  as amended_notices,
                (select count(*)::text from audit_events
                  where object_id=meeting.id and event_type='meeting_completed')
                  as completed_events,
                (select count(*)::text from audit_events
                  where event_type='meeting_attendance_corrected') as corrected_events
           from meetings as meeting where meeting.id=$1`,
        [meetingId]
      );
      expect(retainedEvidence.rows[0]).toEqual({
        title: "Exploration committee — amended",
        state: "completed",
        row_version: "3",
        meeting_versions: "2",
        agenda_versions: "2",
        agenda_items: "3",
        rsvps: "2",
        current_rsvps: "1",
        attendance_records: "3",
        amended_notices: "2",
        completed_events: "1",
        corrected_events: "1"
      });
      const cancelledEvidence = await pool.query<{ notices: string; events: string }>(
        `select
           (select count(*)::text from notices
             where object_id=$1 and notice_type='meeting_cancelled') as notices,
           (select count(*)::text from audit_events
             where object_id=$1 and event_type='meeting_cancelled') as events`,
        [cancelledMeetingId]
      );
      expect(cancelledEvidence.rows[0]).toEqual({ notices: "1", events: "1" });
    });
  });
});
