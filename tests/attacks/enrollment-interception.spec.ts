import { createHash } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  BuiltinEnrollmentError,
  BuiltinEnrollmentService,
  PgBuiltinEnrollmentStore,
  PgWebAuthnStore,
  WebAuthnCeremony
} from "../../artifacts/server/src/index.js";
import { authorize } from "../../lib/authz/src/index.js";
import {
  activateEnrollmentInTransaction,
  migrate,
  withIdentityTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import {
  ORIGIN,
  RP_ID,
  allowAllWebAuthnAttempts,
  fakeWebAuthnCrypto,
  idSequence,
  registrationResponse
} from "../browser/webauthn-harness.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const INVITATION_TOKEN = Buffer.alloc(32, 0xa1).toString("base64url");
const WRONG_TOKEN = Buffer.alloc(32, 0xa2).toString("base64url");
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_enrollment_attack_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "enrollment-interception-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

describe("TH-17 intercepted builtin enrollment invitation", () => {
  it("binds the invitation to one UV passkey but grants nothing until fresh secretary proof", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const memberId = testId(91_001);
      const membershipId = testId(91_002);
      const invitationId = testId(91_003);
      const secretarySessionId = testId(91_004);
      await pool.query(
        `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
         values ($1,$2,'human','Target Director','Target Director','invited')`,
        [memberId, secretary.organizationId]
      );
      await pool.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
         ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
        [membershipId, secretary.organizationId, secretary.boardId, memberId]
      );
      await pool.query(
        `insert into enrollment_invitations(
           id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at
         ) values ($1,$2,$3,$4,$5,'operator_qr',transaction_timestamp()+interval '24 hours')`,
        [
          invitationId,
          secretary.organizationId,
          memberId,
          createHash("sha256").update(INVITATION_TOKEN).digest(),
          secretary.memberId
        ]
      );
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://client.example',
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [
          secretarySessionId,
          secretary.organizationId,
          Buffer.alloc(32, 0xa3),
          secretary.memberId,
          secretary.clientId
        ]
      );

      const fake = fakeWebAuthnCrypto();
      const webauthn = new WebAuthnCeremony({
        rpName: "BoardAgent",
        rpId: RP_ID,
        origin: ORIGIN,
        store: new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" }),
        attemptLimiter: allowAllWebAuthnAttempts,
        crypto: fake.crypto,
        newId: idSequence(91_100)
      });
      const enrollment = new BuiltinEnrollmentService({
        organizationId: secretary.organizationId,
        store: new PgBuiltinEnrollmentStore(pool, { assumeRole: "boardagent_server" }),
        webauthn,
        newId: idSequence(91_200),
        entropy: (length) => Buffer.alloc(length, 0x04)
      });

      await expect(enrollment.begin({ invitationToken: WRONG_TOKEN })).rejects.toBeInstanceOf(
        BuiltinEnrollmentError
      );
      expect(
        await pool.query("select count(*)::int as count from webauthn_challenges")
      ).toMatchObject({ rows: [{ count: 0 }] });

      const begun = await enrollment.begin({ invitationToken: INVITATION_TOKEN });
      expect(begun).toMatchObject({
        organizationDisplayName: "Org",
        memberDisplayName: "Target Director",
        seats: [
          {
            boardId: secretary.boardId,
            boardName: "Board",
            seatRole: "voting_member"
          }
        ],
        publicKey: {
          rp: { id: RP_ID, name: "BoardAgent" },
          authenticatorSelection: { userVerification: "required" }
        }
      });

      const completed = await enrollment.complete({
        invitationToken: INVITATION_TOKEN,
        proofingMethod: "verified_number_call",
        response: registrationResponse
      });
      expect(completed).toMatchObject({
        status: "pending_activation",
        memberId,
        invitationId,
        expiresInSeconds: 600
      });
      expect(completed.activationCode).toMatch(
        /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{3}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$/u
      );

      const persisted = await pool.query<{
        activation_code_sha256: Buffer;
        activation_state: string;
        consumed_at: Date | null;
        credential_count: string;
        member_state: string;
        pending_activation_member_id: string | null;
        proofing_method: string;
        row_version: string;
        webauthn_consumed_at: Date | null;
      }>(
        `select member.state as member_state,member.row_version::text,
                invitation.consumed_at,invitation.pending_activation_member_id,
                activation.state as activation_state,activation.proofing_method,
                activation.protected_code as activation_code_sha256,
                challenge.consumed_at as webauthn_consumed_at,
                (select count(*)::text from webauthn_credentials as credential
                  where credential.organization_id=member.organization_id
                    and credential.member_id=member.id and credential.state='active') as credential_count
           from members as member
           join enrollment_invitations as invitation
             on invitation.organization_id=member.organization_id and invitation.member_id=member.id
           join enrollment_activation_challenges as activation
             on activation.organization_id=member.organization_id and activation.member_id=member.id
           join webauthn_challenges as challenge
             on challenge.organization_id=member.organization_id and challenge.member_id=member.id
          where member.id=$1`,
        [memberId]
      );
      expect(persisted.rows[0]).toMatchObject({
        member_state: "pending_activation",
        row_version: "3",
        pending_activation_member_id: memberId,
        activation_state: "issued",
        proofing_method: "verified_number_call",
        credential_count: "1"
      });
      expect(persisted.rows[0]?.consumed_at).not.toBeNull();
      expect(persisted.rows[0]?.webauthn_consumed_at).not.toBeNull();
      expect(persisted.rows[0]?.activation_code_sha256.toString("hex")).toBe(
        createHash("sha256").update(completed.activationCode).digest("hex")
      );

      const pendingAuthorization = authorize(
        {
          memberId,
          active: false,
          onboardingCurrent: false,
          roles: new Set(["member"]),
          scopes: new Set(["governance:read"]),
          memberBoardIds: new Set([secretary.boardId])
        },
        {
          boardId: secretary.boardId,
          ownerMemberId: memberId,
          visible: true,
          recused: false,
          terminal: false
        },
        {
          toolName: "list_pending_actions",
          actionClass: "R",
          requiredScopes: ["governance:read"],
          ownPlatformSelfService: false,
          allowTerminalRead: true
        }
      );
      expect(pendingAuthorization).toEqual({ allowed: false, reason: "inactive_identity" });

      await expect(enrollment.begin({ invitationToken: INVITATION_TOKEN })).rejects.toMatchObject({
        code: "enrollment_unavailable"
      });

      const wrong = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
        (client) =>
          activateEnrollmentInTransaction(client, {
            organizationId: secretary.organizationId,
            memberId,
            invitationId,
            challengeId: completed.activationChallengeId,
            protectedCodeSha256: "ff".repeat(32),
            proofingMethod: "verified_number_call",
            secretaryMemberId: secretary.memberId,
            secretarySessionId,
            feedEntries: [{ boardId: secretary.boardId, feedId: testId(91_301) }],
            auditEventId: testId(91_302)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(wrong).toMatchObject({ activated: false, reason: "code_mismatch" });

      const activated = await withIdentityTransaction(
        pool,
        { organizationId: secretary.organizationId, boardIds: [secretary.boardId] },
        (client) =>
          activateEnrollmentInTransaction(client, {
            organizationId: secretary.organizationId,
            memberId,
            invitationId,
            challengeId: completed.activationChallengeId,
            protectedCodeSha256: createHash("sha256")
              .update(completed.activationCode)
              .digest("hex"),
            proofingMethod: "verified_number_call",
            secretaryMemberId: secretary.memberId,
            secretarySessionId,
            feedEntries: [{ boardId: secretary.boardId, feedId: testId(91_303) }],
            auditEventId: testId(91_304)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(activated).toMatchObject({ activated: true, memberId, rowVersion: "4" });

      const audit = await pool.query<{ canonical_payload: Buffer; event_type: string }>(
        "select event_type,canonical_payload from audit_events order by sequence"
      );
      expect(audit.rows.map((row) => row.event_type)).toEqual([
        "enrollment_redeemed",
        "authorization_denied",
        "member_activated"
      ]);
      const serializedAudit = Buffer.concat(
        audit.rows.map((row) => row.canonical_payload)
      ).toString("utf8");
      expect(serializedAudit).not.toContain(INVITATION_TOKEN);
      expect(serializedAudit).not.toContain(completed.activationCode);
    });
  });
});
