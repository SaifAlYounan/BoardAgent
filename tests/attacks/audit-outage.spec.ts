import { describe, expect, it } from "vitest";

import { proposeActionInTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("TH-14 audit sink outage", () => {
  it("rolls back the protected act and its idempotency record when audit append fails", async () => {
    await withMigratedDatabase("audit_outage", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["member:propose"]
      });
      const input = {
        organizationId: actor.organizationId,
        proposalId: testId(14_100),
        boardId: actor.boardId,
        proposalType: "meeting" as const,
        title: "Proposal that must not outlive its audit event",
        payload: {
          schema_version: "boardagent.proposal.meeting.v1",
          values: { purpose: "Exercise the mandatory evidence sink" }
        },
        references: [],
        idempotencyRecordId: testId(14_101),
        idempotencyKey: "audit-outage-proposal-0001",
        auditEventId: testId(14_102)
      };
      await pool.query(`
        create function boardagent_test_fail_audit() returns trigger language plpgsql as $$
        begin
          raise exception 'synthetic mandatory audit outage';
        end
        $$;
        create trigger boardagent_test_fail_audit
          before insert on audit_events
          for each row execute function boardagent_test_fail_audit()
      `);

      const submit = () =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) => proposeActionInTransaction(client, input),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        );
      await expect(submit()).rejects.toThrow("synthetic mandatory audit outage");
      expect(
        (
          await pool.query<{ idempotency: string; proposals: string }>(
            `select
               (select count(*)::text from proposals where id=$1) as proposals,
               (select count(*)::text from idempotency_records where id=$2) as idempotency`,
            [input.proposalId, input.idempotencyRecordId]
          )
        ).rows
      ).toEqual([{ proposals: "0", idempotency: "0" }]);

      await pool.query("drop trigger boardagent_test_fail_audit on audit_events");
      await pool.query("drop function boardagent_test_fail_audit()");
      await expect(submit()).resolves.toMatchObject({ state: "pending", replayed: false });
      expect((await pool.query("select id from audit_events")).rowCount).toBe(1);
    });
  });
});
