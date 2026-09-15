import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";

describe("AC25 administrative actions through production TLS OAuth and MCP", () => {
  it("uses signed passkeys and issued bearer tokens for exact H actions, revocation and personal reconnect", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const adminToken = await f.login(f.issuer.memberId, true);
        const secretaryToken = await f.login(f.target.memberId);
        const admin = await f.connect(adminToken);
        const secretary = await f.connect(secretaryToken);
        const who = await secretary.callTool({
          name: "whoami",
          arguments: { schema_version: SCHEMA }
        });
        expect(who.isError).not.toBe(true);
        expect(who.structuredContent).toMatchObject({ data: { member_id: f.target.memberId } });
        const beforeAdmin = await secretary.callTool({
          name: "list_administrative_access",
          arguments: { schema_version: SCHEMA, mode: "organization" }
        });
        expect(beforeAdmin.isError).toBe(true);

        const grant = await admin.callTool({
          name: "manage_member_admin_delegation",
          arguments: f.input
        });
        expect(grant.isError).not.toBe(true);
        expect((await pool.query("select state from member_admin_delegations")).rows).toEqual([
          { state: "active" }
        ]);
        const rejectedAccess = await f.trustedFetch(f.resource, {
          method: "POST",
          headers: {
            authorization: `Bearer ${secretaryToken.access_token}`,
            "content-type": "application/json"
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: "old-token",
            method: "tools/call",
            params: { name: "whoami", arguments: { schema_version: SCHEMA } }
          })
        });
        expect(rejectedAccess.status).toBe(401);
        const rejectedRefresh = await f.trustedFetch(new URL("/token", f.origin), {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: secretaryToken.refresh_token,
            client_id: secretaryToken.protocolId,
            resource: f.resource
          }).toString()
        });
        expect(rejectedRefresh.status).toBe(400);
        expect(await rejectedRefresh.json()).toEqual({ error: "invalid_grant" });

        const currentSecretaryToken = await f.login(f.target.memberId);
        const currentSecretary = await f.connect(currentSecretaryToken);
        const access = await currentSecretary.callTool({
          name: "list_administrative_access",
          arguments: { schema_version: SCHEMA }
        });
        expect(access.isError).not.toBe(true);
        const directorId = testId(103_000);
        const invite = {
          schema_version: SCHEMA,
          idempotency_key: "oauth-mcp-delegated-director-invite",
          authority_evidence: f.input.change.authority_evidence,
          change: {
            operation: "invite",
            member_id: directorId,
            board_id: f.issuer.boardId,
            member_kind: "human",
            seat_role: "voting_member",
            legal_name: "Invited Director",
            display_name: "Invited Director",
            voting_weight: 1,
            accountable_principal_id: null,
            reason: "Register the appointed ordinary director"
          }
        };
        const invited = await currentSecretary.callTool({
          name: "manage_member",
          arguments: invite
        });
        expect(invited.isError).not.toBe(true);
        expect(
          (
            await pool.query(
              "select member_id,is_secretary,seat_role from board_memberships where member_id=$1",
              [directorId]
            )
          ).rows
        ).toEqual([{ member_id: directorId, is_secretary: false, seat_role: "voting_member" }]);
        const revoked = await admin.callTool({
          name: "manage_member_admin_delegation",
          arguments: {
            schema_version: SCHEMA,
            idempotency_key: "oauth-mcp-revoke-secretary-delegation",
            change: {
              operation: "revoke",
              delegation_id: f.input.change.delegation_id,
              board_id: f.issuer.boardId,
              expected_delegation_version: 1,
              reason: "End temporary member administration"
            }
          }
        });
        expect(revoked.isError).not.toBe(true);
        const afterRevocation = await f.connect(await f.login(f.target.memberId));
        const denied = await afterRevocation.callTool({
          name: "manage_member",
          arguments: {
            ...invite,
            idempotency_key: "oauth-mcp-no-longer-authorized-invite",
            change: { ...invite.change, member_id: testId(103_001) }
          }
        });
        expect(denied.isError).toBe(true);
        expect(
          (
            await pool.query("select count(*)::int as n from members where id=$1", [
              testId(103_001)
            ])
          ).rows[0]?.n
        ).toBe(0);

        const proposalId = testId(103_002);
        const targetVersion = Number(
          (await pool.query("select row_version from members where id=$1", [f.target.memberId]))
            .rows[0]?.row_version
        );
        const proposed = await admin.callTool({
          name: "manage_company_admin",
          arguments: {
            schema_version: SCHEMA,
            idempotency_key: "oauth-mcp-additional-admin-proposal",
            change: {
              operation: "grant",
              proposal_id: proposalId,
              member_id: f.target.memberId,
              expected_member_version: targetVersion,
              reason: "Appoint a second accountable administrator"
            }
          }
        });
        expect(proposed.isError).not.toBe(true);
        const accepted = await afterRevocation.callTool({
          name: "manage_company_admin",
          arguments: {
            schema_version: SCHEMA,
            idempotency_key: "oauth-mcp-personal-admin-acceptance",
            change: {
              operation: "accept",
              proposal_id: proposalId,
              expected_proposal_version: 1,
              reason: "I accept my administrator responsibility"
            }
          }
        });
        expect(accepted.isError).not.toBe(true);
        const newAdmin = await f.connect(await f.login(f.target.memberId));
        const orgAccess = await newAdmin.callTool({
          name: "list_administrative_access",
          arguments: { schema_version: SCHEMA, mode: "organization" }
        });
        expect(orgAccess.isError).not.toBe(true);
        expect(
          (
            await pool.query(
              "select member_id from organization_role_assignments where role='admin' and active_until is null order by member_id"
            )
          ).rows.map((r: { member_id: string }) => r.member_id)
        ).toEqual([f.issuer.memberId, f.target.memberId].sort());
        expect(
          (await pool.query("select state from company_admin_proposals where id=$1", [proposalId]))
            .rows
        ).toEqual([{ state: "accepted" }]);
        expect(
          (await pool.query("select count(*)::int as n from administrative_authority_changes"))
            .rows[0]?.n
        ).toBe(4);
        expect(
          (
            await pool.query(
              `select count(*)::int as n from input_required_attempts a
             join action_stages s on s.id=a.stage_id
            where a.original_name in ('manage_member','manage_member_admin_delegation','manage_company_admin')
              and a.state='confirmed' and s.state='confirmed' and a.response_action='accept'
              and a.prepared_request_id<>a.retry_request_id and a.protocol_version='2026-07-28'
              and s.exact_origin=$1`,
              [f.origin]
            )
          ).rows[0]?.n
        ).toBe(5);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from auth_sessions where member_id=$1 and state='revoked'",
              [f.target.memberId]
            )
          ).rows[0]?.n
        ).toBeGreaterThan(0);
        // A grant affects its target; the unchanged issuer remains connected.
        expect(
          (await admin.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } })).isError
        ).not.toBe(true);
        expect(f.wire.filter((entry) => entry.response.includes('"input_required"')).length).toBe(
          5
        );
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  }, 120_000);
});
