import { describe, expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

const cases = [
  "non_admin_issuer",
  "issuer_without_scope",
  "foreign_organization_target",
  "suspended_target",
  "pending_activation_target",
  "stale_onboarding_target",
  "ai_target",
  "self_target",
  "already_admin_target",
  "stale_target_version"
] as const;

describe("AC03 current human administrator eligibility", () => {
  for (const scenario of cases) {
    it(`refuses ${scenario} without a proposal, new role or authority event`, async () => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(
          pool,
          scenario !== "non_admin_issuer"
        );
        let targetId = target.memberId;
        switch (scenario) {
          case "issuer_without_scope":
            await pool.query(
              "update access_token_records set scope_set=array['governance:read'] where id=$1",
              [issuer.accessTokenRecordId]
            );
            break;
          case "foreign_organization_target": {
            const organizationId = testId(109_000);
            targetId = testId(109_001);
            await pool.query(
              "insert into organizations(id,legal_name,display_name,slug,timezone) values($1,'Foreign','Foreign','foreign','UTC')",
              [organizationId]
            );
            await pool.query(
              "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Foreign Person','Foreign Person','active')",
              [targetId, organizationId]
            );
            break;
          }
          case "suspended_target":
          case "pending_activation_target":
            targetId = testId(109_040);
            await pool.query(
              "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Inactive Person','Inactive Person',$3)",
              [
                targetId,
                issuer.organizationId,
                scenario === "suspended_target" ? "suspended" : "pending_activation"
              ]
            );
            break;
          case "stale_onboarding_target": {
            // Only the target receives a second board seat without an attestation;
            // the proposing administrator remains current on their existing board.
            const boardId = testId(109_010);
            await pool.query(
              "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'second-board','Second Board','UTC')",
              [boardId, issuer.organizationId]
            );
            await pool.query(
              "insert into board_memberships(id,organization_id,board_id,member_id,seat_role,voting_weight,state) values($1,$2,$3,$4,'voting_member',1,'active')",
              [testId(109_011), issuer.organizationId, boardId, targetId]
            );
            break;
          }
          case "ai_target": {
            const principalId = testId(109_020);
            targetId = testId(109_021);
            await pool.query(
              "insert into accountable_principals(id,organization_id,legal_name) values($1,$2,'Synthetic accountable principal')",
              [principalId, issuer.organizationId]
            );
            await pool.query(
              "insert into members(id,organization_id,member_kind,legal_name,display_name,state,accountable_principal_id) values($1,$2,'ai_system','Synthetic AI','Synthetic AI','active',$3)",
              [targetId, issuer.organizationId, principalId]
            );
            break;
          }
          case "self_target":
            targetId = issuer.memberId;
            break;
          case "already_admin_target":
            await pool.query(
              "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Existing synthetic administrator')",
              [testId(109_030), issuer.organizationId, targetId]
            );
            break;
          case "non_admin_issuer":
          case "stale_target_version":
            break;
        }
        const before = (
          await pool.query(
            "select id,member_id,role,active_from,active_until from organization_role_assignments order by id"
          )
        ).rows;
        const input = {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "eligibility-proposal-" + scenario,
          change: {
            operation: "grant",
            proposal_id: testId(109_100),
            member_id: targetId,
            expected_member_version: scenario === "stale_target_version" ? 2 : 1,
            reason: "Only a current eligible named human can receive administrator authority"
          }
        };
        await expect(
          withRequestTransaction(
            pool,
            issuer.context,
            (client) =>
              client.query("select boardagent_company_admin_snapshot($1::jsonb) as snapshot", [
                input
              ]),
            { assumeRole: "boardagent_server", isolation: "serializable" }
          )
        ).rejects.toMatchObject({ code: "42501" });
        expect(
          (
            await pool.query(
              "select id,member_id,role,active_from,active_until from organization_role_assignments order by id"
            )
          ).rows
        ).toEqual(before);
        expect(
          (await pool.query("select count(*)::int as n from company_admin_proposals")).rows[0]?.n
        ).toBe(0);
        expect(
          (await pool.query("select count(*)::int as n from administrative_authority_changes"))
            .rows[0]?.n
        ).toBe(0);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from audit_events where event_type like 'company_admin_%'"
            )
          ).rows[0]?.n
        ).toBe(0);
      });
    });
  }
});
