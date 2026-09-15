import { expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedMeetingToolProjectionFixture } from "../helpers/meeting-tool-projection-fixture.js";

it("builds the shared normal meeting projection fixture and both named growth transitions", async () => {
  await withMigratedDatabase("meeting_projection_base", async (pool) => {
    const fixture = await seedMeetingToolProjectionFixture(pool);
    expect(fixture.commands.map((command) => command.tool)).toEqual([
      "create_document_version",
      "create_meeting",
      "amend_meeting",
      "record_attendance",
      "correct_attendance",
      "create_meeting"
    ]);
    expect(fixture.currentVersion()).toBe(2);
    expect(fixture.currentAttendanceId()).not.toBe(fixture.originalAttendanceId);
    const nextAgenda = await fixture.amendAgain(),
      nextAttendance = await fixture.correctAgain();
    expect(nextAgenda.version).toBe(3);
    expect(nextAgenda.agendaVersionId).not.toBe(fixture.amendedAgendaId);
    expect(fixture.currentVersion()).toBe(3);
    expect(fixture.currentAttendanceId()).toBe(nextAttendance);
    expect(fixture.commands.map((command) => command.tool)).toEqual([
      "create_document_version",
      "create_meeting",
      "amend_meeting",
      "record_attendance",
      "correct_attendance",
      "create_meeting",
      "amend_meeting",
      "correct_attendance"
    ]);
    const visible = await withRequestTransaction(
      pool,
      fixture.secretary.context,
      async (client) => {
        expect((await client.query("select current_user")).rows).toEqual([
          { current_user: "boardagent_server" }
        ]);
        return (
          await client.query<{
            id: string;
            state: string;
            version: number;
            attendance_count: string;
          }>(
            `select meeting.id,meeting.state,agenda.version,
          (select count(*)::text from meeting_attendance as attendance where attendance.meeting_id=meeting.id) as attendance_count
         from meetings as meeting join agenda_versions as agenda on agenda.id=meeting.current_agenda_version_id
         where meeting.id=any($1::uuid[]) order by meeting.id`,
            [[fixture.meetingId, fixture.emptyMeetingId]]
          )
        ).rows;
      },
      { assumeRole: "boardagent_server" }
    );
    expect(visible).toEqual([
      { id: fixture.meetingId, state: "called", version: 3, attendance_count: "3" },
      { id: fixture.emptyMeetingId, state: "called", version: 1, attendance_count: "0" }
    ]);
    process.stdout.write(
      JSON.stringify({
        proof: "normal shared fixture only",
        supportedCommands: fixture.commands.length,
        meetings: visible,
        agendaVersions: {
          original: fixture.originalAgendaId,
          amended: fixture.amendedAgendaId,
          next: nextAgenda.agendaVersionId
        },
        attendance: { original: fixture.originalAttendanceId, current: nextAttendance },
        sqlAdmissionOrNativeDeliveryProven: false
      }) + "\n"
    );
  });
}, 90000);
