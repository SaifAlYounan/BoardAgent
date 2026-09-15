import { createHash } from "node:crypto";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { Pool } from "pg";
import { afterEach, describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  createBoardAgentMcpHandler,
  type SurfacePrincipal,
  type SurfaceResourceResult,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION, type JsonValue } from "../../lib/contracts/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const RESOURCE = new URL("https://boardagent.test/mcp");
let databaseCounter = 0;
const clients: Client[] = [];
const handlers: Array<ReturnType<typeof createBoardAgentMcpHandler>> = [];

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_enrollment_mcp_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "enrollment-mcp-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

const unusedReads = {
  async executeRead(
    _principal: SurfacePrincipal,
    _tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    throw new Error("read lane is not used by this focused test");
  },
  async readResource(_principal: SurfacePrincipal, _uri: URL): Promise<SurfaceResourceResult> {
    throw new Error("resource lane is not used by this focused test");
  }
};

afterEach(async () => {
  await Promise.allSettled(clients.splice(0).map((client) => client.close()));
  await Promise.allSettled(handlers.splice(0).map((handler) => handler.close()));
});

describe("real MCP secretary enrollment issuance", () => {
  it("precreates the exact member seat, then carries the invitation secret once", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const targetMemberId = testId(1201);
      const secretarySessionId = testId(1203);
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','real MCP member invitation test')`,
        [testId(1202), actor.organizationId, actor.memberId]
      );
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
           transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [secretarySessionId, actor.organizationId, testHash(111), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        secretarySessionId,
        actor.accessTokenRecordId
      ]);

      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unusedReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const handler = createBoardAgentMcpHandler({
        service,
        requestStateKey: Buffer.alloc(32, 0x4d),
        requestStateTtlSeconds: 600
      });
      handlers.push(handler);
      const authInfo: AuthInfo = {
        token: "synthetic-secretary-token",
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
          roles: ["member", "secretariat"],
          boardIds: [actor.boardId]
        }
      };
      const wireBodies: string[] = [];
      const client = new Client(
        { name: "secretary-agent", version: "1.0.0" },
        {
          capabilities: { elicitation: { form: {} } },
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          inputRequired: { autoFulfill: true, maxRounds: 2 },
          cachePartition: actor.memberId
        }
      );
      const forward = handler.fetch.bind(handler);
      await client.connect(
        new StreamableHTTPClientTransport(RESOURCE, {
          fetch: async (input, init) => {
            const response = await forward(new Request(input, init), { authInfo });
            wireBodies.push(await response.clone().text());
            return response;
          }
        })
      );
      clients.push(client);

      let confirmationMessage = "";
      client.setRequestHandler("elicitation/create", async (request) => {
        confirmationMessage = String(request.params.message);
        const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(confirmationMessage)?.[1];
        if (!code) throw new Error("confirmation code was not rendered");
        return { action: "accept", content: { approve: true, confirmation_code: code } };
      });
      const manageArgs = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        change: {
          operation: "invite",
          member_id: targetMemberId,
          board_id: actor.boardId,
          member_kind: "human",
          seat_role: "voting_member",
          legal_name: "Mina Director",
          display_name: "Mina Director",
          voting_weight: 1,
          accountable_principal_id: null
        },
        idempotency_key: "mcp-manage-member-000001"
      } as const;
      const managed = await client.callTool({ name: "manage_member", arguments: manageArgs });
      expect(managed.isError).not.toBe(true);
      expect(confirmationMessage).toContain("BOARDAGENT MEMBER INVITE CONFIRMATION");
      expect(confirmationMessage).toContain(`Member: Mina Director (${targetMemberId})`);
      expect(confirmationMessage).toContain(`Board: Board (${actor.boardId})`);
      expect(confirmationMessage).toContain("Seat: voting_member; secretary: no; voting weight: 1");
      expect(managed.structuredContent).toMatchObject({
        tool: "manage_member",
        status: "accepted",
        reference: targetMemberId,
        data: {
          operation: "invite",
          member_id: targetMemberId,
          board_id: actor.boardId,
          state: "invited",
          next_action: "issue_enrollment"
        }
      });
      const memberProjection = await pool.query<{
        state: string;
        seat_role: string;
        voting_weight: string;
        evidence: string;
      }>(
        `select member.state,membership.seat_role,membership.voting_weight::text,
                count(version.id)::text as evidence
           from members as member
           join board_memberships as membership on membership.member_id=member.id
           join membership_versions as version on version.membership_id=membership.id
          where member.id=$1
          group by member.state,membership.seat_role,membership.voting_weight`,
        [targetMemberId]
      );
      expect(memberProjection.rows[0]).toEqual({
        state: "invited",
        seat_role: "voting_member",
        voting_weight: "1",
        evidence: "1"
      });

      confirmationMessage = "";
      const args = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        member_id: targetMemberId,
        handoff_method: "operator_display",
        expires_in_seconds: 900,
        idempotency_key: "mcp-issue-enrollment-000001"
      } as const;
      const response = await client.callTool({ name: "issue_enrollment", arguments: args });
      expect(response.isError).not.toBe(true);
      expect(confirmationMessage).toContain("Member: Mina Director");
      expect(confirmationMessage).toContain(`Board: Board (${actor.boardId})`);
      expect(confirmationMessage).toContain(
        "One-time enrollment link is created only after approval"
      );
      expect(confirmationMessage).not.toContain("/enroll#");

      const structured = response.structuredContent as {
        status?: unknown;
        reference?: unknown;
        data?: {
          enrollment_link?: unknown;
          secret_once?: unknown;
          replayed?: unknown;
        };
      };
      expect(structured.status).toBe("accepted");
      expect(structured.data?.secret_once).toBe(true);
      expect(structured.data?.replayed).toBe(false);
      const enrollmentLink = structured.data?.enrollment_link;
      expect(enrollmentLink).toMatch(/^https:\/\/boardagent\.test\/enroll#[A-Za-z0-9_-]{43}$/u);
      if (typeof enrollmentLink !== "string") throw new Error("one-time link is absent");
      const invitationToken = enrollmentLink.split("#")[1];
      if (!invitationToken) throw new Error("one-time token is absent");
      const tokenOccurrences = wireBodies.reduce(
        (count, body) => count + body.split(invitationToken).length - 1,
        0
      );
      expect(tokenOccurrences).toBe(1);

      const persisted = await pool.query<{
        invitation_id: string;
        token_sha256: Buffer;
        issued_events: string;
      }>(
        `select invitation.id as invitation_id,invitation.token_sha256,
                (select count(*)::text from audit_events where event_type='enrollment_issued')
                  as issued_events
           from enrollment_invitations as invitation
          where invitation.member_id=$1`,
        [targetMemberId]
      );
      expect(persisted.rows[0]?.invitation_id).toBe(structured.reference);
      expect(persisted.rows[0]?.token_sha256.toString("hex")).toBe(
        createHash("sha256").update(invitationToken, "utf8").digest("hex")
      );
      expect(persisted.rows[0]?.issued_events).toBe("1");

      const humanActivationCode = "ACT-2V4Q";
      const activationChallengeId = testId(1250);
      await pool.query(
        `update enrollment_invitations
            set consumed_at=transaction_timestamp(),pending_activation_member_id=member_id
          where id=$1`,
        [structured.reference]
      );
      await pool.query(
        "update members set state='enrollment_pending',row_version=row_version+1 where id=$1",
        [targetMemberId]
      );
      await pool.query(
        "update members set state='pending_activation',row_version=row_version+1 where id=$1",
        [targetMemberId]
      );
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,signature_counter,
           transports,backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
        [
          testId(1251),
          actor.organizationId,
          targetMemberId,
          Buffer.alloc(32, 0x21),
          Buffer.alloc(32, 0x22)
        ]
      );
      await pool.query(
        `insert into enrollment_activation_challenges(
           id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,
           expires_at
         ) values ($1,$2,$3,$4,$5,'verified_number_call','issued',
           transaction_timestamp()+interval '10 minutes')`,
        [
          activationChallengeId,
          actor.organizationId,
          targetMemberId,
          structured.reference,
          createHash("sha256").update(humanActivationCode, "utf8").digest()
        ]
      );
      confirmationMessage = "";
      const activation = await client.callTool({
        name: "confirm_enrollment_activation",
        arguments: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          member_id: targetMemberId,
          invitation_id: structured.reference,
          challenge_id: activationChallengeId,
          confirmation_code: humanActivationCode,
          proofing_method: "verified_number_call",
          idempotency_key: "mcp-activate-member-000001"
        }
      });
      expect(activation.isError).not.toBe(true);
      expect(confirmationMessage).toContain("BOARDAGENT MEMBER ACTIVATION CONFIRMATION");
      expect(confirmationMessage).toContain(`Member: Mina Director (${targetMemberId})`);
      expect(confirmationMessage).toContain(`Member's activation code: ${humanActivationCode}`);
      expect(confirmationMessage).toContain("Identity proofing: verified_number_call");
      expect(activation.structuredContent).toMatchObject({
        tool: "confirm_enrollment_activation",
        status: "accepted",
        reference: targetMemberId,
        data: {
          activated: true,
          member_id: targetMemberId,
          challenge_id: activationChallengeId,
          challenge_state: "consumed",
          onboarding_tasks_created: 1,
          next_action: "complete_onboarding"
        }
      });
      const activationProjection = await pool.query<{
        member_state: string;
        challenge_state: string;
        activation_events: string;
        onboarding_tasks: string;
      }>(
        `select member.state as member_state,challenge.state as challenge_state,
                (select count(*)::text from audit_events
                  where event_type='member_activated' and object_id=member.id)
                  as activation_events,
                (select count(*)::text from pending_action_feed
                  where member_id=member.id and action_type='complete_onboarding')
                  as onboarding_tasks
           from members as member
           join enrollment_activation_challenges as challenge on challenge.member_id=member.id
          where member.id=$1`,
        [targetMemberId]
      );
      expect(activationProjection.rows[0]).toEqual({
        member_state: "active",
        challenge_state: "consumed",
        activation_events: "1",
        onboarding_tasks: "1"
      });

      const repeated = await client.callTool({ name: "issue_enrollment", arguments: args });
      expect(repeated.isError).toBe(true);
      expect(JSON.stringify(repeated)).not.toContain(invitationToken);
      const count = await pool.query<{ invitations: string }>(
        "select count(*)::text as invitations from enrollment_invitations where member_id=$1",
        [targetMemberId]
      );
      expect(count.rows[0]?.invitations).toBe("1");
    });
  });
});
