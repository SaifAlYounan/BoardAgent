import { describe, expect, it } from "vitest";
import {
  appendAuditEventsInTransaction,
  finalizeAdministrativeAuthorityInTransaction,
  planAdministrativeAuthorityInTransaction,
  prepareAdministrativeAuthorityInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { delegationFixture } from "../helpers/administrative-delegation.js";
import { stageAdministrativeAction } from "../helpers/administrative-service.js";
import { testId } from "../helpers/authorized-actor.js";

describe("AC19 raw runtime consent cannot authorize administrative changes", () => {
  it.each(["manage_company_admin", "manage_member_admin_delegation", "manage_member"] as const)(
    "%s refuses a runtime-inserted consent without the protected confirmation response",
    async (tool) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await delegationFixture(pool);
        const input =
          tool === "manage_company_admin"
            ? {
                schema_version: "boardagent.tool-input.v1",
                idempotency_key: "raw-admin-unconfirmed-offer",
                change: {
                  operation: "grant",
                  proposal_id: testId(112501),
                  member_id: f.target.memberId,
                  expected_member_version: 1,
                  reason: "Synthetic database boundary appointment"
                }
              }
            : tool === "manage_member_admin_delegation"
              ? f.input
              : {
                  schema_version: "boardagent.tool-input.v1",
                  idempotency_key: "raw-member-unconfirmed-invite",
                  change: {
                    operation: "invite",
                    member_id: testId(112503),
                    board_id: f.issuer.boardId,
                    member_kind: "human",
                    seat_role: "voting_member",
                    legal_name: "Synthetic appointee",
                    display_name: "Synthetic appointee",
                    voting_weight: 1,
                    accountable_principal_id: null,
                    reason: "Record an appointment after confirmation"
                  }
                };
        const staged = await stageAdministrativeAction(pool, f.issuer, tool, input);
        const before = (await pool.query("select * from organization_role_assignments order by id"))
          .rows;
        await expect(
          withRequestTransaction(
            pool,
            f.issuer.context,
            async (client) => {
              const prepared =
                tool === "manage_member"
                  ? undefined
                  : await prepareAdministrativeAuthorityInTransaction(client, input, tool);
              const consentId = testId(112502);
              // Deliberately bypass the confirmation service using only the runtime role.
              // No protected response/code was submitted; the real stage remains prepared.
              await client.query(
                `insert into consent_records(
            id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
            action_code,target_type,target_id,canonical_schema,payload_sha256,
            protected_code_record_sha256,access_token_record_id,token_jti,client_id,
            exact_origin,staged_at,confirmed_at,record_sha256)
            select $1,s.organization_id,s.board_id,s.id,a.id,s.actor_member_id,
              s.action_code,s.target_type,s.target_id,'boardagent.consent-record.v1',s.payload_sha256,
              $3,s.access_token_record_id,s.token_jti,s.client_id,s.exact_origin,s.created_at,
              transaction_timestamp(),$3
            from action_stages s join input_required_attempts a on a.stage_id=s.id
            where s.id=$2 and s.state='active' and a.state='prepared'`,
                [consentId, staged.prepared.stage_id, Buffer.alloc(32, 139)]
              );
              if (!prepared) return;
              let next = 112510;
              const plan = await planAdministrativeAuthorityInTransaction(
                client,
                prepared,
                consentId,
                () => testId(next++)
              );
              await appendAuditEventsInTransaction(client, [plan.auditEvent]);
              await finalizeAdministrativeAuthorityInTransaction(client, plan);
            },
            { assumeRole: "boardagent_server", isolation: "serializable" }
          )
        ).rejects.toMatchObject({ code: "42501" });
        expect(
          (await pool.query("select * from organization_role_assignments order by id")).rows
        ).toEqual(before);
        expect(
          (await pool.query("select count(*)::int as n from company_admin_proposals")).rows[0]
        ).toEqual({ n: 0 });
        expect(
          (await pool.query("select count(*)::int as n from member_admin_delegations")).rows[0]
        ).toEqual({ n: 0 });
        expect(
          (await pool.query("select count(*)::int as n from administrative_authority_changes"))
            .rows[0]
        ).toEqual({ n: 0 });
      });
    }
  );
});
