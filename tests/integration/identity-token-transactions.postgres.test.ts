import { createHash } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  activateEnrollmentInTransaction,
  issueTokensFromAuthorizationCodeInTransaction,
  migrate,
  rotateRefreshTokenInTransaction,
  withIdentityTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_identity_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "identity-token-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

describe("enrollment activation and OAuth token transactions", () => {
  it("requires passkey plus recent secretary proof, gates scopes, rotates and kills reuse", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const targetMemberId = testId(33_001);
      const targetMembershipId = testId(33_002);
      const invitationId = testId(33_003);
      const challengeId = testId(33_004);
      const secretarySessionId = testId(33_005);
      const targetSessionId = testId(33_006);
      const activationCodeHash = "31".repeat(32);
      await pool.query(
        `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
         values ($1,$2,'human','Target member','Target member','pending_activation')`,
        [targetMemberId, secretary.organizationId]
      );
      await pool.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
         ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
        [targetMembershipId, secretary.organizationId, secretary.boardId, targetMemberId]
      );
      await pool.query(
        `insert into enrollment_invitations(
           id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at,
           consumed_at,pending_activation_member_id
         ) values ($1,$2,$3,$4,$5,'verified call',transaction_timestamp()+interval '1 hour',
                   transaction_timestamp(),$3)`,
        [invitationId, secretary.organizationId, targetMemberId, testHash(31), secretary.memberId]
      );
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,signature_counter,
           transports,backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
        [
          testId(33_007),
          secretary.organizationId,
          targetMemberId,
          Buffer.alloc(32, 1),
          Buffer.alloc(32, 2)
        ]
      );
      await pool.query(
        `insert into enrollment_activation_challenges(
           id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,
           expires_at
         ) values ($1,$2,$3,$4,$5,'verified-number callback','issued',
                   transaction_timestamp()+interval '10 minutes')`,
        [
          challengeId,
          secretary.organizationId,
          targetMemberId,
          invitationId,
          Buffer.from(activationCodeHash, "hex")
        ]
      );
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values
           ($1,$3,$4,$5,$6,'authenticated','https://client.example',
             transaction_timestamp()+interval '1 hour',transaction_timestamp()),
           ($2,$3,$7,$8,$6,'authenticated','https://client.example',
             transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [
          secretarySessionId,
          targetSessionId,
          secretary.organizationId,
          testHash(32),
          secretary.memberId,
          secretary.clientId,
          testHash(33),
          targetMemberId
        ]
      );

      const secondBoardId = testId(32_980);
      const secondTargetMembershipId = testId(32_981);
      await pool.query(
        `insert into boards(id,organization_id,slug,name,timezone)
         values ($1,$2,'second-board','Second board','UTC')`,
        [secondBoardId, secretary.organizationId]
      );
      await pool.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
         ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
        [secondTargetMembershipId, secretary.organizationId, secondBoardId, targetMemberId]
      );
      const partialSecretary = await withIdentityTransaction(
        pool,
        {
          organizationId: secretary.organizationId,
          boardIds: [secretary.boardId, secondBoardId]
        },
        (client) =>
          client.query<{ result_status: string }>(
            `select result_status from boardagent_prepare_enrollment_activation(
               $1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[]
             )`,
            [
              secretary.organizationId,
              targetMemberId,
              invitationId,
              challengeId,
              Buffer.from(activationCodeHash, "hex"),
              "verified-number callback",
              secretary.memberId,
              secretarySessionId,
              [secretary.boardId, secondBoardId]
            ]
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(partialSecretary.rows[0]).toEqual({ result_status: "secretary_invalid" });
      await pool.query(
        `update board_memberships
            set state='ended',active_until=transaction_timestamp()
          where id=$1`,
        [secondTargetMembershipId]
      );
      const extraBoardContext = await withIdentityTransaction(
        pool,
        {
          organizationId: secretary.organizationId,
          boardIds: [secretary.boardId, secondBoardId]
        },
        (client) =>
          client.query<{ result_status: string }>(
            `select result_status from boardagent_prepare_enrollment_activation(
               $1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[]
             )`,
            [
              secretary.organizationId,
              targetMemberId,
              invitationId,
              challengeId,
              Buffer.from(activationCodeHash, "hex"),
              "verified-number callback",
              secretary.memberId,
              secretarySessionId,
              [secretary.boardId]
            ]
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(extraBoardContext.rows[0]).toEqual({ result_status: "unavailable" });

      const activationFunction = await pool.query<{
        server_finalize: boolean;
        server_prepare: boolean;
        worker_finalize: boolean;
        worker_prepare: boolean;
      }>(
        `select
           has_function_privilege(
             'boardagent_server',
             'public.boardagent_prepare_enrollment_activation(uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[])',
             'EXECUTE'
           ) as server_prepare,
           has_function_privilege(
             'boardagent_worker',
             'public.boardagent_prepare_enrollment_activation(uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[])',
             'EXECUTE'
           ) as worker_prepare,
           has_function_privilege(
             'boardagent_server',
             'public.boardagent_finalize_enrollment_activation(uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[],uuid,uuid[])',
             'EXECUTE'
           ) as server_finalize,
           has_function_privilege(
             'boardagent_worker',
             'public.boardagent_finalize_enrollment_activation(uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[],uuid,uuid[])',
             'EXECUTE'
           ) as worker_finalize`
      );
      expect(activationFunction.rows[0]).toEqual({
        server_prepare: true,
        worker_prepare: false,
        server_finalize: true,
        worker_finalize: false
      });
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
          (client) =>
            client.query(
              "update members set state='active',row_version=row_version+1 where id=$1",
              [targetMemberId]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
          (client) =>
            client.query(
              `update enrollment_activation_challenges
                  set state='consumed',consumed_at=transaction_timestamp(),confirmed_by=$2
                where id=$1`,
              [challengeId, secretary.memberId]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            client.query(
              `select * from boardagent_prepare_enrollment_activation(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[]
               )`,
              [
                secretary.organizationId,
                targetMemberId,
                invitationId,
                challengeId,
                Buffer.from(activationCodeHash, "hex"),
                "verified-number callback",
                secretary.memberId,
                secretarySessionId,
                [secretary.boardId]
              ]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "25000" });

      const preparedOnly = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
        (client) =>
          client.query<{ result_status: string }>(
            `select result_status from boardagent_prepare_enrollment_activation(
               $1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[]
             )`,
            [
              secretary.organizationId,
              targetMemberId,
              invitationId,
              challengeId,
              Buffer.from(activationCodeHash, "hex"),
              "verified-number callback",
              secretary.memberId,
              secretarySessionId,
              [secretary.boardId]
            ]
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(preparedOnly.rows[0]).toEqual({ result_status: "activated" });
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
          (client) =>
            client.query(
              `select * from boardagent_finalize_enrollment_activation(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[],$10,$11::uuid[]
               )`,
              [
                secretary.organizationId,
                targetMemberId,
                invitationId,
                challengeId,
                Buffer.from(activationCodeHash, "hex"),
                "verified-number callback",
                secretary.memberId,
                secretarySessionId,
                [secretary.boardId],
                testId(32_992),
                [testId(32_993)]
              ]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "55000" });
      const prepareOnlyState = await pool.query<{
        attempt_count: number;
        challenge_state: string;
        member_state: string;
      }>(
        `select challenge.attempt_count,challenge.state as challenge_state,
                member.state as member_state
           from enrollment_activation_challenges as challenge
           join members as member on member.id=challenge.member_id
          where challenge.id=$1`,
        [challengeId]
      );
      expect(prepareOnlyState.rows[0]).toEqual({
        attempt_count: 0,
        challenge_state: "issued",
        member_state: "pending_activation"
      });

      await pool.query(
        `update auth_sessions
            set last_authenticated_at=transaction_timestamp()-interval '11 minutes'
          where id=$1`,
        [secretarySessionId]
      );
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
          (client) =>
            activateEnrollmentInTransaction(client, {
              organizationId: secretary.organizationId,
              memberId: targetMemberId,
              invitationId,
              challengeId,
              protectedCodeSha256: activationCodeHash,
              proofingMethod: "verified-number callback",
              secretaryMemberId: secretary.memberId,
              secretarySessionId,
              feedEntries: [{ boardId: secretary.boardId, feedId: testId(32_990) }],
              auditEventId: testId(32_991)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "secretary_confirmation_invalid" });
      const unchanged = await pool.query<{ attempt_count: number; member_state: string }>(
        `select challenge.attempt_count,member.state as member_state
           from enrollment_activation_challenges as challenge
           join members as member on member.id=challenge.member_id
          where challenge.id=$1`,
        [challengeId]
      );
      expect(unchanged.rows[0]).toEqual({ attempt_count: 0, member_state: "pending_activation" });
      await pool.query(
        "update auth_sessions set last_authenticated_at=transaction_timestamp() where id=$1",
        [secretarySessionId]
      );

      const wrong = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
        (client) =>
          activateEnrollmentInTransaction(client, {
            organizationId: secretary.organizationId,
            memberId: targetMemberId,
            invitationId,
            challengeId,
            protectedCodeSha256: "ff".repeat(32),
            proofingMethod: "verified-number callback",
            secretaryMemberId: secretary.memberId,
            secretarySessionId,
            feedEntries: [{ boardId: secretary.boardId, feedId: testId(33_008) }],
            auditEventId: testId(33_009)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(wrong).toMatchObject({
        activated: false,
        reason: "code_mismatch",
        challengeState: "issued",
        attemptCount: 1
      });
      const activated = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
        (client) =>
          activateEnrollmentInTransaction(client, {
            organizationId: secretary.organizationId,
            memberId: targetMemberId,
            invitationId,
            challengeId,
            protectedCodeSha256: activationCodeHash,
            proofingMethod: "verified-number callback",
            secretaryMemberId: secretary.memberId,
            secretarySessionId,
            feedEntries: [{ boardId: secretary.boardId, feedId: testId(33_010) }],
            auditEventId: testId(33_011)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(activated).toMatchObject({
        activated: true,
        memberId: targetMemberId,
        rowVersion: "2",
        feedCount: 1
      });
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
          (client) =>
            activateEnrollmentInTransaction(client, {
              organizationId: secretary.organizationId,
              memberId: targetMemberId,
              invitationId,
              challengeId,
              protectedCodeSha256: activationCodeHash,
              proofingMethod: "verified-number callback",
              secretaryMemberId: secretary.memberId,
              secretarySessionId,
              feedEntries: [{ boardId: secretary.boardId, feedId: testId(33_012) }],
              auditEventId: testId(33_013)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "enrollment_unavailable" });

      await pool.query(
        `insert into oauth_client_grants(client_id,grant_type,scope) values
           ($1,'authorization_code','onboarding:read'),
           ($1,'refresh_token','onboarding:read'),
           ($1,'authorization_code','governance:read'),
           ($1,'refresh_token','governance:read')`,
        [secretary.clientId]
      );
      const verifier = "A".repeat(43);
      const redirectUri = "https://client.example/callback";
      const resourceUri = "https://boardagent.test/mcp";
      const seedCode = async (
        base: number,
        scope: "onboarding:read" | "governance:read"
      ): Promise<{ requestId: string; codeHash: string }> => {
        const requestId = testId(base);
        const codeId = testId(base + 1);
        const codeHash = (base % 256).toString(16).padStart(2, "0").repeat(32);
        await pool.query(
          `insert into oauth_authorization_requests(
             id,organization_id,client_id,resource_uri,redirect_uri,scope_set,member_id,
             session_id,state_hash,request_state,expires_at
           ) values ($1,$2,$3,$4,$5,array[$6],$7,$8,$9,'approved',
                     transaction_timestamp()+interval '5 minutes')`,
          [
            requestId,
            secretary.organizationId,
            secretary.clientId,
            resourceUri,
            redirectUri,
            scope,
            targetMemberId,
            targetSessionId,
            testHash(base % 256)
          ]
        );
        await pool.query(
          `insert into oauth_authorization_codes(
             id,organization_id,code_sha256,authorization_request_id,client_id,member_id,
             redirect_uri,resource_uri,scope_set,pkce_s256_challenge,expires_at
           ) values ($1,$2,$3,$4,$5,$6,$7,$8,array[$9],$10,
                     transaction_timestamp()+interval '60 seconds')`,
          [
            codeId,
            secretary.organizationId,
            Buffer.from(codeHash, "hex"),
            requestId,
            secretary.clientId,
            targetMemberId,
            redirectUri,
            resourceUri,
            scope,
            pkceChallenge(verifier)
          ]
        );
        return { requestId, codeHash };
      };
      const ordinary = await seedCode(33_100, "governance:read");
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: secretary.organizationId },
          (client) =>
            issueTokensFromAuthorizationCodeInTransaction(client, {
              organizationId: secretary.organizationId,
              clientId: secretary.clientId,
              authorizationCodeSha256: ordinary.codeHash,
              pkceVerifier: verifier,
              redirectUri,
              resourceUri,
              refreshFamilyId: testId(33_110),
              refreshTokenId: testId(33_111),
              refreshTokenSha256: "41".repeat(32),
              accessTokenRecordId: testId(33_112),
              accessTokenJti: testId(33_113),
              signingKeyId: testId(8),
              auditEventId: testId(33_114)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/current onboarding/u);

      const onboarding = await seedCode(33_120, "onboarding:read");
      const familyId = testId(33_130);
      const firstRefreshHash = "51".repeat(32);
      const issued = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId },
        (client) =>
          issueTokensFromAuthorizationCodeInTransaction(client, {
            organizationId: secretary.organizationId,
            clientId: secretary.clientId,
            authorizationCodeSha256: onboarding.codeHash,
            pkceVerifier: verifier,
            redirectUri,
            resourceUri,
            refreshFamilyId: familyId,
            refreshTokenId: testId(33_131),
            refreshTokenSha256: firstRefreshHash,
            accessTokenRecordId: testId(33_132),
            accessTokenJti: testId(33_133),
            signingKeyId: testId(8),
            auditEventId: testId(33_134)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(issued).toMatchObject({
        familyId,
        generation: "1",
        claims: {
          subject: targetMemberId,
          clientId: secretary.clientId,
          audience: resourceUri,
          scopes: ["onboarding:read"]
        }
      });

      const replacementHash = "61".repeat(32);
      const refreshed = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId },
        (client) =>
          rotateRefreshTokenInTransaction(client, {
            organizationId: secretary.organizationId,
            clientId: secretary.clientId,
            resourceUri,
            presentedRefreshTokenSha256: firstRefreshHash,
            replacementRefreshTokenId: testId(33_140),
            replacementRefreshTokenSha256: replacementHash,
            accessTokenRecordId: testId(33_141),
            accessTokenJti: testId(33_142),
            signingKeyId: testId(8),
            auditEventId: testId(33_143)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(refreshed).toMatchObject({ refreshed: true, familyId, generation: "2" });
      const reused = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId },
        (client) =>
          rotateRefreshTokenInTransaction(client, {
            organizationId: secretary.organizationId,
            clientId: secretary.clientId,
            resourceUri,
            presentedRefreshTokenSha256: firstRefreshHash,
            replacementRefreshTokenId: testId(33_150),
            replacementRefreshTokenSha256: "71".repeat(32),
            accessTokenRecordId: testId(33_151),
            accessTokenJti: testId(33_152),
            signingKeyId: testId(8),
            auditEventId: testId(33_153)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(reused).toMatchObject({
        refreshed: false,
        familyId,
        state: "compromised",
        reuseDetected: true,
        auditEventId: testId(33_153)
      });
      const family = await pool.query<{ state: string; live_refresh: string; live_access: string }>(
        `select family.state,
                (select count(*)::text from refresh_tokens
                  where family_id=family.id and used_at is null and revoked_at is null) as live_refresh,
                (select count(*)::text from access_token_records
                  where refresh_family_id=family.id and revoked_at is null) as live_access
           from refresh_families as family where family.id=$1`,
        [familyId]
      );
      expect(family.rows).toEqual([{ state: "compromised", live_refresh: "0", live_access: "0" }]);
      const events = await pool.query<{ event_type: string }>(
        "select event_type from audit_events order by sequence"
      );
      expect(events.rows.map((row) => row.event_type)).toEqual([
        "authorization_denied",
        "member_activated",
        "token_issued",
        "token_refreshed",
        "token_reuse_detected"
      ]);
    });
  });
});
