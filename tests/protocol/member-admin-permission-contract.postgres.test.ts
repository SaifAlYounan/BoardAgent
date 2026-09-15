import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("AC01 actual OAuth member-administration permission contract", () => {
  for (const persona of ["ordinary_secretary", "company_admin", "admin_without_scope"] as const) {
    for (const operation of ["invite", "suspend"] as const) {
      it(`${persona} ${operation} obeys the independent role and OAuth scope requirements`, async () => {
        await withAdministrativeDatabase(async (pool) => {
          const f = await administrativeOAuthFixture(pool, true);
          try {
            if (!f.third) throw new Error("ordinary director fixture missing");
            const personId =
              persona === "ordinary_secretary" ? f.target.memberId : f.issuer.memberId;
            const token =
              persona === "admin_without_scope"
                ? await f.login(personId, false, ["governance:read"])
                : await f.login(personId);
            const agent = await f.connect(token);
            const membersBefore = (await pool.query("select * from members order by id")).rows;
            const seatsBefore = (await pool.query("select * from board_memberships order by id"))
              .rows;
            const rolesBefore = (
              await pool.query("select * from organization_role_assignments order by id")
            ).rows;
            const change =
              operation === "invite"
                ? {
                    operation,
                    member_id: testId(112001),
                    board_id: f.issuer.boardId,
                    member_kind: "human",
                    seat_role: "voting_member",
                    legal_name: "Appointed ordinary director",
                    display_name: "Appointed ordinary director",
                    voting_weight: 1,
                    accountable_principal_id: null,
                    reason: "Record a synthetic appointment"
                  }
                : {
                    operation,
                    member_id: f.third.memberId,
                    board_id: f.issuer.boardId,
                    reason: "Record a synthetic suspension"
                  };
            const result = await agent.callTool({
              name: "manage_member",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: `permission-contract-${persona}-${operation}`,
                change
              }
            });
            if (persona === "company_admin") {
              expect(result.isError).not.toBe(true);
              if (operation === "invite") {
                expect(
                  (await pool.query("select state from members where id=$1", [testId(112001)]))
                    .rows[0]
                ).toEqual({ state: "invited" });
                expect(
                  (
                    await pool.query(
                      "select seat_role,is_secretary from board_memberships where member_id=$1",
                      [testId(112001)]
                    )
                  ).rows[0]
                ).toEqual({ seat_role: "voting_member", is_secretary: false });
              } else {
                expect(
                  (
                    await pool.query("select state from board_memberships where member_id=$1", [
                      f.third.memberId
                    ])
                  ).rows[0]
                ).toEqual({ state: "suspended" });
                expect(
                  (await pool.query("select state from members where id=$1", [f.third.memberId]))
                    .rows[0]
                ).toEqual({ state: "active" });
              }
            } else {
              expect(result.isError).toBe(true);
              expect((await pool.query("select * from members order by id")).rows).toEqual(
                membersBefore
              );
              expect(
                (await pool.query("select * from board_memberships order by id")).rows
              ).toEqual(seatsBefore);
            }
            expect(
              (await pool.query("select * from organization_role_assignments order by id")).rows
            ).toEqual(rolesBefore);
            expect(f.errors).toEqual([]);
          } finally {
            await f.close();
          }
        });
      });
    }
  }
});
