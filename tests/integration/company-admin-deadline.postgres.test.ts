import { describe, expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { stageAdministrativeAction } from "../helpers/administrative-service.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("AC05 exact company-administrator proposal deadline", () => {
  it("allows preparation one microsecond before expiry and refuses at and after the database deadline without granting authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const proposalId = testId(112101);
      const grant = await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
        schema_version: SCHEMA,
        idempotency_key: "admin-exact-deadline-offer",
        change: {
          operation: "grant",
          proposal_id: proposalId,
          member_id: target.memberId,
          expected_member_version: 1,
          reason: "Synthetic appointment expiry boundary"
        }
      });
      expect((await grant.confirm()).confirmed).toBe(true);
      const acceptance = {
        schema_version: SCHEMA,
        idempotency_key: "admin-exact-deadline-acceptance",
        change: {
          operation: "accept",
          proposal_id: proposalId,
          expected_proposal_version: 1,
          reason: "Personally accept this administrative appointment"
        }
      };
      const before = (await pool.query("select * from organization_role_assignments order by id"))
        .rows;
      for (const offset of [1, 0, -1]) {
        const snapshot = withRequestTransaction(
          pool,
          target.context,
          async (client) => {
            // Disposable superuser date fixture only. Keep the exact 24-hour lifetime,
            // re-enable its guard, then exercise the server role at this DB timestamp.
            await client.query("reset role");
            await client.query(
              "alter table company_admin_proposals disable trigger boardagent_company_admin_proposal_transition"
            );
            await client.query(
              "update company_admin_proposals set created_at=transaction_timestamp()-interval '24 hours'+$2*interval '1 microsecond', expires_at=transaction_timestamp()+$2*interval '1 microsecond' where id=$1",
              [proposalId, offset]
            );
            await client.query(
              "alter table company_admin_proposals enable trigger boardagent_company_admin_proposal_transition"
            );
            await client.query("set local role boardagent_server");
            return (
              await client.query(
                "select boardagent_company_admin_snapshot($1::jsonb) as snapshot",
                [acceptance]
              )
            ).rows[0].snapshot;
          },
          { assumeRole: "boardagent_server", isolation: "serializable" }
        );
        if (offset > 0)
          await expect(snapshot).resolves.toMatchObject({
            operation: "accept",
            after: { state: "accepted" }
          });
        else await expect(snapshot).rejects.toMatchObject({ code: "42501" });
      }
      expect(
        (await pool.query("select * from organization_role_assignments order by id")).rows
      ).toEqual(before);
      expect(
        (
          await pool.query(
            "select state,row_version::text from company_admin_proposals where id=$1",
            [proposalId]
          )
        ).rows[0]
      ).toEqual({ state: "pending", row_version: "1" });
    });
  });
});
