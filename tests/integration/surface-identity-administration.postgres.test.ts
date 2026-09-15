import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { DirectReadRepository } from "../helpers/direct-response-allocation.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { migrate, withRequestTransaction } from "../../lib/db/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_surface_identity_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "surface-identity-administration-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function principal(actor: AuthorizedActorFixture): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "authorized-test-client",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: ["secretariat:admin"],
    roles: ["admin", "member", "secretariat"],
    boardIds: [actor.boardId]
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by identity administration test");
  },
  readResource: async () => {
    throw new Error("resource read not used by identity administration test");
  }
};

let confirmationSequence = 0;
async function confirm(
  service: BoardAgentSurfaceService,
  actor: SurfacePrincipal,
  tool: string,
  input: JsonValue
) {
  confirmationSequence += 1;
  const label = `surface-identity-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const prepared = await service.prepareHumanAction(actor, tool, input);
  expect(prepared).toMatchObject({ action_code: tool, board_id: null });
  const clientCapabilities = { elicitation: { form: {} } } as const;
  const requestState = `${label}-request-state-is-bound-to-the-client`;
  await service.persistHumanStage({
    principal: actor,
    tool,
    input,
    prepared,
    client_capabilities: clientCapabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm exact ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${label}-prepare`)
  });
  const resolved = await service.resolveHumanAction({
    principal: actor,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: clientCapabilities,
    request_state: requestState,
    retry_request_id: Buffer.from(`${label}-retry`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolved.confirmed) throw new Error(`${tool} failed: ${resolved.reason}`);
  return resolved.result;
}

async function seedAdmin(pool: Pool) {
  const admin = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["secretariat:admin"],
    isSecretary: true
  });
  await pool.query(
    `insert into organization_role_assignments(
       id,organization_id,member_id,role,change_reason
     ) values ($1,$2,$3,'admin','Identity administration integration authority')`,
    [testId(166_000), admin.organizationId, admin.memberId]
  );
  return admin;
}

async function recentProof(pool: Pool, actor: SurfacePrincipal): Promise<string> {
  const reads = new DirectReadRepository(pool, {
    cursorKey: Buffer.alloc(32, 7),
    transaction: { assumeRole: "boardagent_server" }
  });
  const result = await reads.executeRead(actor, "whoami", {
    schema_version: TOOL_INPUT_SCHEMA_VERSION
  });
  const view = result.data as { recent_auth: { proof: string } | null };
  if (!view.recent_auth) throw new Error("recent authentication unavailable in test journey");
  return view.recent_auth.proof;
}

describe("confirmed identity administration surface", () => {
  it("revokes an expired own connection using fresh same-client authentication and exact confirmation", async () => {
    await withDatabase(async (pool) => {
      const admin = await seedAdmin(pool);
      const other = await seedAdditionalAuthorizedActor(pool, admin, {
        idBase: 185_100,
        seatRole: "voting_member",
        scopes: ["onboarding:read"]
      });
      const targetSession = testId(185_200);
      const proofSession = testId(185_201);
      const otherSession = testId(185_202);
      const family = testId(185_203);
      const proof = Buffer.alloc(32, 81).toString("base64url");
      const otherProof = Buffer.alloc(32, 82).toString("base64url");
      await pool.query(
        `insert into auth_sessions(
        id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
        created_at,expires_at,last_authenticated_at
      ) values
        ($1,$4,$5,$6,$7,'expired','https://boardagent.test',transaction_timestamp()-interval '9 hours',
          transaction_timestamp()-interval '1 hour',transaction_timestamp()-interval '9 hours'),
        ($2,$4,$8,$6,$7,'authenticated','https://boardagent.test',transaction_timestamp(),
          transaction_timestamp()+interval '1 hour',transaction_timestamp()),
        ($3,$4,$9,$10,$7,'authenticated','https://boardagent.test',transaction_timestamp(),
          transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [
          targetSession,
          proofSession,
          otherSession,
          admin.organizationId,
          testHash(80),
          admin.memberId,
          admin.clientId,
          Buffer.from(sha256Hex(Buffer.from(proof, "base64url")), "hex"),
          Buffer.from(sha256Hex(Buffer.from(otherProof, "base64url")), "hex"),
          other.memberId
        ]
      );
      await pool.query(
        `insert into refresh_families(
        id,organization_id,member_id,client_id,resource_uri,generation,state,idle_expires_at,absolute_expires_at
      ) values ($1,$2,$3,$4,'https://boardagent.test/mcp',1,'active',
        transaction_timestamp()+interval '30 days',transaction_timestamp()+interval '90 days')`,
        [family, admin.organizationId, admin.memberId, admin.clientId]
      );
      await pool.query(
        `insert into access_token_records(
        id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,refresh_family_id,signing_key_id,expires_at
      ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',array['onboarding:read'],$6,$7,$8,
        transaction_timestamp()+interval '15 minutes')`,
        [
          testId(185_204),
          admin.organizationId,
          testId(185_205),
          admin.memberId,
          admin.clientId,
          targetSession,
          family,
          testId(8)
        ]
      );
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        proofSession,
        admin.accessTokenRecordId
      ]);
      const reads = new DirectReadRepository(pool, {
        cursorKey: Buffer.alloc(32, 7),
        transaction: { assumeRole: "boardagent_server" }
      });
      const firstPage = (
        await reads.executeRead(principal(admin), "list_my_sessions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: null,
          limit: 1
        })
      ).data as { items: Array<{ session_id: string }>; next_cursor: string | null };
      expect(firstPage.items.map((row) => row.session_id)).toEqual([proofSession]);
      expect(firstPage.next_cursor).toEqual(expect.any(String));
      const secondPage = (
        await reads.executeRead(principal(admin), "list_my_sessions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: firstPage.next_cursor,
          limit: 1
        })
      ).data as { items: Array<{ session_id: string }>; next_cursor: string | null };
      expect(secondPage.items.map((row) => row.session_id)).toEqual([targetSession]);
      expect(secondPage.next_cursor).toBeNull();
      expect(JSON.stringify([firstPage, secondPage])).not.toContain("opaque_session");
      expect(JSON.stringify([firstPage, secondPage])).not.toContain(otherSession);
      const rawRows = await withRequestTransaction(
        pool,
        admin.context,
        (client) =>
          client.query<{ count: number }>("select count(*)::int as count from auth_sessions"),
        { assumeRole: "boardagent_server" }
      );
      expect(rawRows.rows).toEqual([{ count: 0 }]);
      await expect(
        pool.query("select * from boardagent_own_session_page(null,null,1)")
      ).rejects.toMatchObject({ code: "25000" });
      await expect(
        withRequestTransaction(
          pool,
          { ...admin.context, memberId: other.memberId },
          (client) => client.query("select * from boardagent_own_session_page(null,null,1)"),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "expired-own-session-revoke-0001",
        session_id: targetSession,
        recent_auth_proof: await recentProof(pool, principal(admin))
      };
      await expect(
        surface.prepareHumanAction(principal(admin), "revoke_my_session", {
          ...input,
          recent_auth_proof: otherProof
        })
      ).rejects.toThrow();
      await pool.query(
        "update auth_sessions set last_authenticated_at=transaction_timestamp()-interval '16 minutes' where id=$1",
        [proofSession]
      );
      await expect(
        surface.prepareHumanAction(principal(admin), "revoke_my_session", input)
      ).rejects.toThrow();
      await pool.query(
        "update auth_sessions set last_authenticated_at=transaction_timestamp() where id=$1",
        [proofSession]
      );
      await expect(
        surface.prepareHumanAction(principal(admin), "revoke_my_session", input)
      ).rejects.toThrow();
      input.recent_auth_proof = await recentProof(pool, principal(admin));
      const alternateTokenId = testId(185_210);
      const alternateJti = testId(185_211);
      await pool.query(
        `insert into access_token_records(
        id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,signing_key_id,expires_at
      ) select $1,organization_id,$2,member_id,client_id,resource_uri,scope_set,session_id,signing_key_id,expires_at
        from access_token_records where id=$3`,
        [alternateTokenId, alternateJti, admin.accessTokenRecordId]
      );
      await expect(
        surface.prepareHumanAction(
          { ...principal(admin), accessTokenRecordId: alternateTokenId, tokenJti: alternateJti },
          "revoke_my_session",
          input
        )
      ).rejects.toThrow();
      await expect(
        surface.prepareHumanAction(principal(admin), "revoke_my_session", {
          ...input,
          session_id: otherSession
        })
      ).rejects.toThrow();
      await confirm(surface, principal(admin), "revoke_my_session", input);
      expect(
        (
          await pool.query<{ session_state: string; family_state: string; live_tokens: number }>(
            `select (select state from auth_sessions where id=$1) as session_state,
          (select state from refresh_families where id=$2) as family_state,
          (select count(*)::int from access_token_records where refresh_family_id=$2 and revoked_at is null) as live_tokens`,
            [targetSession, family]
          )
        ).rows
      ).toEqual([{ session_state: "revoked", family_state: "revoked", live_tokens: 0 }]);
      expect(
        (
          await pool.query<{ state: string }>("select state from auth_sessions where id=$1", [
            proofSession
          ])
        ).rows
      ).toEqual([{ state: "authenticated" }]);
    });
  });
  it("revokes a live enrollment and an own recent session, then blocks and unblocks a client", async () => {
    await withDatabase(async (pool) => {
      const admin = await seedAdmin(pool);
      const target = await seedAdditionalAuthorizedActor(pool, admin, {
        idBase: 166_100,
        seatRole: "voting_member",
        scopes: ["board:read"]
      });
      const invitationId = testId(166_200);
      await pool.query(
        `insert into enrollment_invitations(
           id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at
         ) values ($1,$2,$3,$4,$5,'operator_display',transaction_timestamp()+interval '1 hour')`,
        [invitationId, admin.organizationId, target.memberId, testHash(166), admin.memberId]
      );
      const sessionProof = Buffer.alloc(32, 73).toString("base64url");
      const sessionId = testId(166_201);
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [
          sessionId,
          admin.organizationId,
          Buffer.from(sha256Hex(Buffer.from(sessionProof, "base64url")), "hex"),
          admin.memberId,
          admin.clientId
        ]
      );
      // Keep the current bearer on a different recent browser anchor from the target.
      const currentSession = testId(166_202);
      await pool.query(
        `insert into auth_sessions(
        id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
        expires_at,last_authenticated_at
      ) select $1,organization_id,$2,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at
        from auth_sessions where id=$3`,
        [currentSession, testHash(74), sessionId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        currentSession,
        admin.accessTokenRecordId
      ]);
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const actor = principal(admin);
      expect(
        (
          await pool.query<{ state: string }>("select state from oauth_clients where id=$1", [
            target.clientId
          ])
        ).rows[0]
      ).toEqual({ state: "active" });

      await confirm(surface, actor, "revoke_enrollment", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "identity-revoke-enrollment-0001",
        invitation_id: invitationId,
        reason: "The enrollment link was exposed."
      });
      await confirm(surface, actor, "revoke_my_session", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "identity-revoke-session-0001",
        session_id: sessionId,
        recent_auth_proof: await recentProof(pool, actor)
      });
      await confirm(surface, actor, "block_oauth_client", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "identity-block-client-0001",
        client_id: target.clientId,
        reason: "The client is under incident review."
      });
      await confirm(surface, actor, "unblock_oauth_client", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "identity-unblock-client-0001",
        client_id: target.clientId,
        reason: "The client review completed successfully."
      });

      const proof = await pool.query<{
        client_state: string;
        invitation_revoked: boolean;
        session_state: string;
        event_count: string;
      }>(
        `select
          (select state from oauth_clients where id=$1) as client_state,
          (select revoked_at is not null from enrollment_invitations where id=$2) as invitation_revoked,
          (select state from auth_sessions where id=$3) as session_state,
          (select count(*)::text from audit_events where event_type in (
             'enrollment_revoked','session_revoked','oauth_client_blocked','oauth_client_unblocked'
           )) as event_count`,
        [target.clientId, invitationId, sessionId]
      );
      expect(proof.rows[0]).toEqual({
        client_state: "active",
        invitation_revoked: true,
        session_state: "revoked",
        event_count: "4"
      });
    });
  });

  it("starts bounded credential recovery and confirms then safely unlinks an OIDC-proved identity", async () => {
    await withDatabase(async (pool) => {
      const admin = await seedAdmin(pool);
      // Recovery issuance re-resolves the real database token/session boundary.
      // This integration fixture previously supplied only a synthetic principal.
      const recoveryAdminSession = testId(167_099);
      await pool.query(
        `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
        values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [
          recoveryAdminSession,
          admin.organizationId,
          Buffer.alloc(32, 79),
          admin.memberId,
          admin.clientId
        ]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        recoveryAdminSession,
        admin.accessTokenRecordId
      ]);
      const recoveryMember = await seedAdditionalAuthorizedActor(pool, admin, {
        idBase: 167_100,
        seatRole: "voting_member",
        scopes: ["board:read"]
      });
      const preservedCredentialId = testId(167_200);
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,false,false,'active')`,
        [
          preservedCredentialId,
          admin.organizationId,
          recoveryMember.memberId,
          Buffer.alloc(32, 80),
          Buffer.alloc(64, 81)
        ]
      );

      const linkMember = await seedAdditionalAuthorizedActor(pool, admin, {
        idBase: 167_300,
        seatRole: "voting_member",
        scopes: ["board:read"]
      });
      const linkRecoveryCredentialId = testId(167_301);
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,false,false,'active')`,
        [
          linkRecoveryCredentialId,
          admin.organizationId,
          linkMember.memberId,
          Buffer.alloc(32, 82),
          Buffer.alloc(64, 83)
        ]
      );
      const browserProof = Buffer.alloc(32, 84).toString("base64url");
      const invitationTokenSha = testHash(167);
      const invitationId = testId(167_302);
      const identityLinkId = testId(167_303);
      const browserSessionId = testId(167_304);
      const authorizationRequestId = testId(167_305);
      const oidcTransactionId = testId(167_306);
      const resource = await pool.query<{ canonical_resource_uri: string }>(
        "select canonical_resource_uri from system_instance where organization_id=$1",
        [admin.organizationId]
      );
      const resourceUri = resource.rows[0]!.canonical_resource_uri;
      await pool.query(
        `insert into enrollment_invitations(
           id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at
         ) values ($1,$2,$3,$4,$5,'operator_display',transaction_timestamp()+interval '1 hour')`,
        [
          invitationId,
          admin.organizationId,
          linkMember.memberId,
          invitationTokenSha,
          admin.memberId
        ]
      );
      await pool.query(
        `insert into external_identity_links(
           id,organization_id,member_id,issuer,subject,state,invitation_id
         ) values ($1,$2,$3,'https://issuer.example/','subject-167','pending',$4)`,
        [identityLinkId, admin.organizationId, linkMember.memberId, invitationId]
      );
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,client_id,state,exact_origin,expires_at
         ) values ($1,$2,$3,$4,'anonymous','https://boardagent.test',
                   transaction_timestamp()+interval '1 hour')`,
        [browserSessionId, admin.organizationId, testHash(168), admin.clientId]
      );
      await pool.query(
        `insert into oauth_authorization_requests(
           id,organization_id,client_id,resource_uri,redirect_uri,scope_set,session_id,
           state_hash,request_state,expires_at
         ) values ($1,$2,$3,$4,'https://agent.example/callback',array['board:read'],$5,$6,
                   'pending',transaction_timestamp()+interval '10 minutes')`,
        [
          authorizationRequestId,
          admin.organizationId,
          admin.clientId,
          resourceUri,
          browserSessionId,
          testHash(169)
        ]
      );
      await pool.query(
        `insert into oidc_login_transactions(
           id,organization_id,provider_id,provider_kind,exact_issuer,interaction_uid,
           authorization_request_id,state_sha256,nonce_sha256,session_id,client_id,resource_uri,
           callback_uri,pkce_s256_challenge,invitation_token_sha256,issued_at,expires_at,
           consumed_at,failure_code
         ) values ($1,$2,'uae_pass','uae_pass','https://issuer.example/',
                   'interaction_uid_167000000000',$3,$4,$5,$6,$7,$8,
                   'https://boardagent.test/auth/oidc/callback/uae_pass',$9,$10,
                   transaction_timestamp()-interval '1 minute',
                   transaction_timestamp()+interval '9 minutes',transaction_timestamp(),
                   'pending_link')`,
        [
          oidcTransactionId,
          admin.organizationId,
          authorizationRequestId,
          Buffer.from(sha256Hex(Buffer.from(browserProof, "base64url")), "hex"),
          testHash(170),
          browserSessionId,
          admin.clientId,
          resourceUri,
          "A".repeat(43),
          invitationTokenSha
        ]
      );

      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const actor = principal(admin);
      const recovery = await confirm(surface, actor, "initiate_identity_recovery", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "identity-recovery-0001",
        member_id: recoveryMember.memberId,
        reason: "The member reported loss of all other authenticators.",
        proofing_method: "verified_number_call",
        credential_disposition: "preserve_named",
        preserved_credential_ids: [preservedCredentialId]
      });
      expect(recovery.data).toMatchObject({ state: "initiated", newIdentityGeneration: "2" });
      await confirm(surface, actor, "link_external_identity", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "identity-link-0001",
        member_id: linkMember.memberId,
        issuer: "https://issuer.example/",
        subject: "subject-167",
        browser_proof: browserProof
      });
      await confirm(surface, actor, "unlink_external_identity", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "identity-unlink-0001",
        identity_link_id: identityLinkId,
        reason: "The member requested removal of this login identity."
      });

      const proof = await pool.query<{
        credential_state: string;
        identity_generation: string;
        link_state: string;
        recovery_count: string;
        event_count: string;
      }>(
        `select
          (select state from webauthn_credentials where id=$1) as credential_state,
          (select identity_generation::text from members where id=$2) as identity_generation,
          (select state from external_identity_links where id=$3) as link_state,
          (select count(*)::text from identity_recovery_requests where member_id=$2) as recovery_count,
          (select count(*)::text from audit_events where event_type in (
             'identity_recovery_started','external_identity_linked','external_identity_unlinked'
           )) as event_count`,
        [preservedCredentialId, recoveryMember.memberId, identityLinkId]
      );
      expect(proof.rows[0]).toEqual({
        credential_state: "active",
        identity_generation: "2",
        link_state: "revoked",
        recovery_count: "1",
        event_count: "3"
      });
    });
  });
});
