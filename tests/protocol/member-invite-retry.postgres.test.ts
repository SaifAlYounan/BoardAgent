import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  createBoardAgentMcpHandler,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { delegationFixture } from "../helpers/administrative-delegation.js";
import {
  administrativeService,
  freshAdministrativeTestCredential,
  stageAdministrativeAction
} from "../helpers/administrative-service.js";

const RESOURCE = new URL("https://boardagent.test/mcp");

describe("ordinary member invitation receipt retry", () => {
  it("returns the saved safe reference without another consent and refuses changed arguments", async () => {
    await withMigratedDatabase("member_invite_retry", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const targetMemberId = testId(291001);
      const sessionId = testId(291002);
      await pool.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Synthetic invitation retry fixture')",
        [testId(291003), actor.organizationId, actor.memberId]
      );
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
           transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, testHash(112), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);

      const service = new PgBoardAgentSurfaceService(pool, {
        reads: new PgSurfaceReadRepository(pool, {
          cursorKey: Buffer.alloc(32, 7),
          transaction: { assumeRole: "boardagent_server" }
        }),
        transaction: { assumeRole: "boardagent_server" }
      });
      const handler = createBoardAgentMcpHandler({
        service,
        requestStateKey: Buffer.alloc(32, 0x4d),
        requestStateTtlSeconds: 600
      });
      const authInfo: AuthInfo = {
        token: "synthetic-member-invite-retry-token",
        clientId: "authorized-test-client",
        scopes: ["governance:read", "secretariat:admin"],
        expiresAt: Math.floor(Date.now() / 1000) + 600,
        resource: RESOURCE,
        extra: {
          organizationId: actor.organizationId,
          memberId: actor.memberId,
          internalClientId: actor.clientId,
          accessTokenRecordId: actor.accessTokenRecordId,
          jti: actor.tokenJti,
          keyId: "test-oauth",
          roles: ["admin", "member", "secretariat"],
          boardIds: [actor.boardId]
        }
      };
      const client = new Client(
        { name: "synthetic-member-invite-retry", version: "1.0.0" },
        {
          capabilities: { elicitation: { form: {} } },
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          inputRequired: { autoFulfill: true, maxRounds: 2 },
          cachePartition: actor.memberId
        }
      );
      try {
        const forward = handler.fetch.bind(handler);
        await client.connect(
          new StreamableHTTPClientTransport(RESOURCE, {
            fetch: async (input, init) => forward(new Request(input, init), { authInfo })
          })
        );
        let elicitationCount = 0;
        client.setRequestHandler("elicitation/create", async (request) => {
          elicitationCount += 1;
          const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(request.params.message)?.[1];
          if (!code) throw new Error("synthetic confirmation omitted the code");
          return { action: "accept", content: { approve: true, confirmation_code: code } };
        });
        const args = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          change: {
            operation: "invite",
            member_id: targetMemberId,
            board_id: actor.boardId,
            member_kind: "human",
            seat_role: "voting_member",
            legal_name: "Mina Synthetic Director",
            display_name: "Mina Synthetic Director",
            voting_weight: 1,
            accountable_principal_id: null
          },
          idempotency_key: "member-invite-safe-retry-000001"
        } as const;
        const counts = async () =>
          (
            await pool.query(
              `select
                 (select count(*)::int from members where id=$1) as members,
                 (select count(*)::int from board_memberships where member_id=$1) as memberships,
                 (select count(*)::int from membership_versions where member_id=$1) as versions,
                 (select count(*)::int from action_stages where action_code='manage_member' and target_id=$1) as stages,
                 (select count(*)::int from consent_records where action_code='manage_member' and target_id=$1) as consents,
                 (select count(*)::int from audit_events where event_type='member_changed' and object_id=$1) as changes,
                 (select count(*)::int from idempotency_records where operation='manage_member' and idempotency_key=$2 and state='succeeded') as receipts`,
              [targetMemberId, args.idempotency_key]
            )
          ).rows[0];

        const original = await client.callTool({ name: "manage_member", arguments: args });
        expect(original.isError).not.toBe(true);
        expect(original.structuredContent).toMatchObject({
          tool: "manage_member",
          status: "accepted",
          reference: targetMemberId,
          data: { operation: "invite", member_id: targetMemberId, state: "invited" }
        });
        const initialCounts = await counts();
        expect(initialCounts).toEqual({
          members: 1,
          memberships: 1,
          versions: 1,
          stages: 1,
          consents: 1,
          changes: 1,
          receipts: 1
        });
        expect(elicitationCount).toBe(1);

        // D2-044: this is a new ordinary request, not a reused confirmation response.
        const repeated = await client.callTool({ name: "manage_member", arguments: args });
        const repeatCounts = await counts();
        const changed = await client.callTool({
          name: "manage_member",
          arguments: { ...args, change: { ...args.change, display_name: "Changed request" } }
        });
        expect(changed.isError).toBe(true);
        expect(await counts()).toEqual(initialCounts);
        expect(repeatCounts).toEqual(initialCounts);
        expect(elicitationCount).toBe(1);
        expect(repeated.isError).not.toBe(true);
        expect(repeated.structuredContent).toEqual({
          ...(original.structuredContent as SurfaceToolResult),
          status: "already_applied"
        });
        // The transport's old role claim cannot retain a now-expired admin grant.
        await pool.query(
          "update organization_role_assignments set active_until=transaction_timestamp() where id=$1",
          [testId(291003)]
        );
        expect((await client.callTool({ name: "manage_member", arguments: args })).isError).toBe(
          true
        );
        expect(await counts()).toEqual(initialCounts);
        expect(elicitationCount).toBe(1);
      } finally {
        try {
          await client.close();
        } finally {
          await handler.close();
        }
      }
    });
  });

  it.each(["delegation", "citation"] as const)(
    "returns an exact delegated receipt, then refuses after current %s authority is lost",
    async (loss) => {
      await withMigratedDatabase("delegated_invite_retry", async (pool) => {
        const fixture = await delegationFixture(pool);
        const grant = await stageAdministrativeAction(
          pool,
          fixture.issuer,
          "manage_member_admin_delegation",
          fixture.input
        );
        expect((await grant.confirm()).confirmed).toBe(true);
        const secretary = await freshAdministrativeTestCredential(pool, fixture.target, 292000);
        const targetMemberId = testId(292010);
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "delegated-invite-safe-retry-000001",
          authority_evidence: fixture.input.change.authority_evidence,
          change: {
            operation: "invite",
            member_id: targetMemberId,
            board_id: fixture.issuer.boardId,
            member_kind: "human",
            seat_role: "voting_member",
            legal_name: "Delegated Synthetic Director",
            display_name: "Delegated Synthetic Director",
            voting_weight: 1,
            accountable_principal_id: null,
            reason: "Record the appointed ordinary director"
          }
        };
        const invitation = await stageAdministrativeAction(pool, secretary, "manage_member", input);
        const original = await invitation.confirm();
        expect(original.confirmed).toBe(true);
        if (!original.confirmed) throw new Error("synthetic invitation was not confirmed");
        let current = await administrativeService(pool, secretary);
        expect(
          await current.service.replayHumanAction(current.principal, "manage_member", input)
        ).toEqual({ ...original.result, status: "already_applied" });
        // A receipt read does not revive the consumed confirmation stage.
        // The existing delegated preparation refusal can abort its transaction;
        // retain that observed refusal without accepting an arbitrary test error.
        const repeatedConsent = await invitation.confirm().catch((error: unknown) => {
          expect(error).toMatchObject({ code: "25P02" });
          return { confirmed: false };
        });
        expect(repeatedConsent.confirmed).toBe(false);
        if (loss === "delegation") {
          const revoked = await stageAdministrativeAction(
            pool,
            fixture.issuer,
            "manage_member_admin_delegation",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              idempotency_key: "end-delegated-invite-retry-000001",
              change: {
                operation: "revoke",
                delegation_id: fixture.input.change.delegation_id,
                board_id: fixture.issuer.boardId,
                expected_delegation_version: 1,
                reason: "End the synthetic appointment administration grant"
              }
            }
          );
          expect((await revoked.confirm()).confirmed).toBe(true);
          const reconnected = await freshAdministrativeTestCredential(pool, secretary, 292100);
          current = await administrativeService(pool, reconnected);
        } else {
          await pool.query(
            "update document_access_grants set active_until=transaction_timestamp() where grantee_member_id=$1",
            [secretary.memberId]
          );
        }
        await expect(
          current.service.replayHumanAction(current.principal, "manage_member", input)
        ).rejects.toMatchObject({ code: "42501" });
        expect(
          (
            await pool.query(
              `select
                 (select count(*)::int from consent_records where action_code='manage_member' and target_id=$1) as consents,
                 (select count(*)::int from membership_versions where member_id=$1) as versions,
                 (select count(*)::int from audit_events where event_type='member_changed' and object_id=$1) as changes`,
              [targetMemberId]
            )
          ).rows[0]
        ).toEqual({ consents: 1, versions: 1, changes: 1 });
      });
    }
  );
});
