import { describe, expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

const args = (memberId: string) => ({
  schema_version: "boardagent.tool-input.v1",
  idempotency_key: "admin-proposal-fixture-0001",
  change: {
    operation: "grant",
    proposal_id: testId(73_000),
    member_id: memberId,
    expected_member_version: 1,
    reason: "Appointed additional administrator"
  }
});
describe("AC01/AC02/AC03 company administrator proposal authority", () => {
  it("denies ordinary secretary plus S:A scope without an administrator assignment", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool, false);
      await expect(
        withRequestTransaction(
          pool,
          issuer.context,
          (client) =>
            client.query("select boardagent_company_admin_snapshot($1::jsonb) as snapshot", [
              args(target.memberId)
            ]),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "42501" });
    });
  });
  it("prepares an exact pending offer without granting authority or persisting a proposal", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const result = await withRequestTransaction(
        pool,
        issuer.context,
        (client) =>
          client.query("select boardagent_company_admin_snapshot($1::jsonb) as snapshot", [
            args(target.memberId)
          ]),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(result.rows[0]?.snapshot).toMatchObject({
        operation: "grant",
        before: null,
        after: { state: "pending", targetMemberId: target.memberId, validForSeconds: 86400 },
        affectedMemberIds: []
      });
      expect(
        (await pool.query("select count(*)::int as count from company_admin_proposals")).rows[0]
          ?.count
      ).toBe(0);
      expect(
        (
          await pool.query(
            "select count(*)::int as count from organization_role_assignments where member_id=$1 and role='admin'",
            [target.memberId]
          )
        ).rows[0]?.count
      ).toBe(0);
    });
  });
  it("rejects stale target versions, self-proposal, observer recipients and unknown fields", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const prepare = (input: unknown) =>
        withRequestTransaction(
          pool,
          issuer.context,
          (client) =>
            client.query("select boardagent_company_admin_snapshot($1::jsonb) as snapshot", [
              input
            ]),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        );
      const original = args(target.memberId);
      await expect(
        prepare({ ...original, change: { ...original.change, expected_member_version: 2 } })
      ).rejects.toMatchObject({ code: "42501" });
      await expect(prepare(args(issuer.memberId))).rejects.toMatchObject({ code: "42501" });
      await expect(prepare({ ...original, hidden: true })).rejects.toMatchObject({ code: "22023" });
      await pool.query(
        "update board_memberships set seat_role='observer',voting_weight=0 where member_id=$1",
        [target.memberId]
      );
      await expect(prepare(original)).rejects.toMatchObject({ code: "42501" });
    });
  });
});
