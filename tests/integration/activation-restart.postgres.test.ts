import { createHash } from "node:crypto";
import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { TOOL_INPUT_SCHEMA_VERSION, sha256Hex } from "../../lib/contracts/src/index.js";
import {
  completeActivationRestartInTransaction,
  confirmStagedActionInTransaction,
  finalizeEnrollmentActivationInTransaction,
  issueActivationRestartInTransaction,
  issueFirstActivationRestartInTransaction,
  lookupActivationRestartInTransaction,
  migrate,
  planEnrollmentActivationInTransaction,
  prepareActivationRestartInTransaction,
  prepareEnrollmentActivationInTransaction,
  stageActionInTransaction,
  withBootstrapTransaction,
  withIdentityTransaction,
  withRequestTransaction,
  type RequestDatabaseContext,
  type PreparedActivationRestart,
  type PreparedEnrollmentActivation
} from "../../lib/db/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
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
const CAPABILITIES = { elicitation: { form: {} } } as const;
const ORIGIN = "https://boardagent.test";
const SERVER = { assumeRole: "boardagent_server", isolation: "serializable" } as const;
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_activation_restart_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "activation-restart-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

/** Bearer resolution requires an authenticated browser session behind every token. */
async function attachSession(pool: Pool, actor: AuthorizedActorFixture, sessionId: string) {
  await pool.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated',$6,
       transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
    [
      sessionId,
      actor.organizationId,
      createHash("sha256").update(`session:${sessionId}`).digest(),
      actor.memberId,
      actor.clientId,
      ORIGIN
    ]
  );
  await pool.query("update access_token_records set session_id=$1 where id=$2", [
    sessionId,
    actor.accessTokenRecordId
  ]);
}

type StaleMode = "expired" | "exhausted" | "live";

const STUCK = {
  memberId: testId(3102),
  membershipId: testId(3103),
  invitationId: testId(3104),
  challengeId: testId(3105),
  credentialId: testId(3106),
  sessionId: testId(3101)
} as const;

/** Same shape as the activation-administration seed, then aged or exhausted. */
async function seedStuckMember(pool: Pool, mode: StaleMode, code = "ACT-OLD1") {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["governance:read", "secretariat:admin"],
    isSecretary: true
  });
  await attachSession(pool, actor, STUCK.sessionId);
  await pool.query(
    `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
     values ($1,$2,'human','Mina Al Noor','Mina Al Noor','pending_activation')`,
    [STUCK.memberId, actor.organizationId]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
    [STUCK.membershipId, actor.organizationId, actor.boardId, STUCK.memberId]
  );
  await pool.query(
    `insert into enrollment_invitations(
       id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at,
       consumed_at,pending_activation_member_id
     ) values ($1,$2,$3,$4,$5,'operator_display',transaction_timestamp()+interval '1 hour',
       transaction_timestamp(),$3)`,
    [STUCK.invitationId, actor.organizationId, STUCK.memberId, testHash(92), actor.memberId]
  );
  await pool.query(
    `insert into webauthn_credentials(
       id,organization_id,member_id,credential_id,public_key,signature_counter,
       transports,backup_eligible,backup_state,state
     ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
    [
      STUCK.credentialId,
      actor.organizationId,
      STUCK.memberId,
      Buffer.alloc(32, 3),
      Buffer.alloc(32, 4)
    ]
  );
  await pool.query(
    `insert into enrollment_activation_challenges(
       id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,
       attempt_count,issued_at,expires_at
     ) values ($1,$2,$3,$4,$5,'verified_number_call','issued',$6,
       transaction_timestamp()-$7::interval,transaction_timestamp()-$7::interval+interval '10 minutes')`,
    [
      STUCK.challengeId,
      actor.organizationId,
      STUCK.memberId,
      STUCK.invitationId,
      createHash("sha256").update(code, "utf8").digest(),
      mode === "exhausted" ? 20 : 0,
      mode === "expired" ? "11 minutes" : "1 minute"
    ]
  );
  return { actor, ...STUCK };
}

async function seedCompanyAdmin(pool: Pool, board: AuthorizedActorFixture, idBase: number) {
  const admin = await seedAdditionalAuthorizedActor(pool, board, {
    idBase,
    seatRole: "voting_member",
    scopes: ["governance:read", "secretariat:admin"],
    isSecretary: false
  });
  await attachSession(pool, admin, testId(idBase + 20));
  await pool.query(
    `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
     values ($1,$2,$3,'admin','test company administrator')`,
    [testId(idBase + 21), admin.organizationId, admin.memberId]
  );
  return admin;
}

function restartArguments(memberId: string, challengeId: string, idempotencyKey: string) {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    member_id: memberId,
    challenge_id: challengeId,
    proofing_method: "verified_number_call",
    idempotency_key: idempotencyKey
  } as const;
}

function prepareRestart(
  pool: Pool,
  context: RequestDatabaseContext,
  args: ReturnType<typeof restartArguments>
) {
  return withRequestTransaction(
    pool,
    context,
    (client) => prepareActivationRestartInTransaction(client, args),
    SERVER
  );
}

async function stageRestart(
  pool: Pool,
  actor: AuthorizedActorFixture,
  args: ReturnType<typeof restartArguments>,
  sequence: number
) {
  const prepared = await prepareRestart(pool, actor.context, args);
  const requestState = Buffer.alloc(48, sequence % 256);
  const confirmationCode = `R${sequence.toString(10).padStart(7, "0")}`;
  const staged = await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      stageActionInTransaction(
        client,
        {
          stageId: testId(sequence),
          inputRequiredAttemptId: testId(sequence + 1),
          boardId: null,
          actingForMemberId: null,
          actionCode: "reissue_activation",
          targetType: "member",
          targetId: prepared.memberId,
          canonicalSchema: "boardagent.activation-restart.v1",
          canonicalPayload: prepared.canonicalPayload,
          packageSha256: null,
          nonce: Buffer.alloc(32, (sequence + 2) % 256),
          confirmationCode,
          accessTokenRecordId: actor.accessTokenRecordId,
          exactOrigin: ORIGIN,
          originalName: "reissue_activation",
          originalArguments: args,
          clientCapabilities: CAPABILITIES,
          embeddedForm: { schema_version: "boardagent.confirmation-form.v1" },
          embeddedResult: { schema_version: "boardagent.input-required.v1" },
          requestStateBytes: requestState,
          preparedRequestId: Buffer.from(`prepared-restart-${String(sequence)}`),
          auditEventIds: {
            stageReplaced: testId(sequence + 2),
            stageCreated: testId(sequence + 3),
            elicitationSent: testId(sequence + 4)
          }
        },
        async (requestClient) => {
          const current = await prepareActivationRestartInTransaction(requestClient, args);
          expect(current.payloadSha256).toBe(prepared.payloadSha256);
        }
      ),
    SERVER
  );
  return { prepared, stageId: staged.stageId, requestState, confirmationCode };
}

async function confirmRestart(
  pool: Pool,
  actor: AuthorizedActorFixture,
  args: ReturnType<typeof restartArguments>,
  staged: Awaited<ReturnType<typeof stageRestart>>,
  sequence: number,
  token: string
) {
  return withRequestTransaction(
    pool,
    actor.context,
    (client) => {
      let current: PreparedActivationRestart | undefined;
      return confirmStagedActionInTransaction(
        client,
        {
          stageId: staged.stageId,
          consentRecordId: testId(sequence),
          retryRequestId: Buffer.from(`retry-restart-${String(sequence)}`),
          originalArguments: args,
          clientCapabilities: CAPABILITIES,
          exactOrigin: ORIGIN,
          requestStateBytes: staged.requestState,
          responseAction: "accept",
          inputResponse: { approve: true, confirmation_code: staged.confirmationCode },
          auditEventIds: {
            consentRecorded: testId(sequence + 1),
            consentRejected: testId(sequence + 2)
          }
        },
        async (requestClient) => {
          current = await prepareActivationRestartInTransaction(requestClient, args);
          return { payloadSha256: current.payloadSha256, packageSha256: null };
        },
        async (requestClient, consentRecordId) => {
          if (!current) throw new Error("restart binding was not prepared");
          const issued = await issueActivationRestartInTransaction(requestClient, {
            originalArguments: args,
            expectedPayloadSha256: current.payloadSha256,
            grantId: testId(sequence + 3),
            tokenSha256: sha256Hex(token),
            consentRecordId,
            auditEventId: testId(sequence + 4)
          });
          return {
            value: issued,
            auditEvents: issued.auditEvent === null ? [] : [issued.auditEvent]
          };
        }
      );
    },
    SERVER
  );
}

async function issueRestart(
  pool: Pool,
  actor: AuthorizedActorFixture,
  memberId: string,
  challengeId: string,
  sequence: number,
  token = `restart-token-${String(sequence)}`
) {
  const args = restartArguments(memberId, challengeId, `restart-member-${String(sequence)}`);
  const staged = await stageRestart(pool, actor, args, sequence);
  const resolution = await confirmRestart(pool, actor, args, staged, sequence + 20, token);
  if (!resolution.confirmed) throw new Error(`restart was not confirmed: ${resolution.reason}`);
  return { ...resolution.value, token, tokenSha256: sha256Hex(token), args };
}

async function grantRow(pool: Pool, grantId: string) {
  return (
    await pool.query<{
      issuer_kind: string;
      issued_by: string | null;
      proofing_method: string;
      stale_challenge_id: string;
      consumed_at: string | null;
      fresh_challenge_id: string | null;
      completed_audit_event_id: string | null;
      ten_minutes: boolean;
      token_hex: string;
    }>(
      `select issuer_kind,issued_by,proofing_method,stale_challenge_id,consumed_at::text,
              fresh_challenge_id,completed_audit_event_id,
              expires_at=created_at+interval '10 minutes' as ten_minutes,
              encode(token_sha256,'hex') as token_hex
         from activation_restart_grants where id=$1`,
      [grantId]
    )
  ).rows[0];
}

async function challengeState(pool: Pool, challengeId: string) {
  return (
    await pool.query<{ state: string; attempt_count: number }>(
      "select state,attempt_count from enrollment_activation_challenges where id=$1",
      [challengeId]
    )
  ).rows[0];
}

async function auditRows(pool: Pool, eventType: string) {
  return (
    await pool.query<{
      object_id: string;
      actor_member_id: string | null;
      consent_record_id: string | null;
      payload: string;
    }>(
      `select object_id,actor_member_id,consent_record_id,
              convert_from(canonical_payload,'UTF8') as payload
         from audit_events where event_type=$1 order by sequence`,
      [eventType]
    )
  ).rows;
}

/** The browser store's assertion row, marked consumed inside the completing transaction. */
async function insertAssertionChallenge(
  pool: Pool,
  organizationId: string,
  memberId: string,
  grantId: string,
  challengeId: string,
  byte: number
) {
  await pool.query(
    `insert into webauthn_challenges(
       id,organization_id,challenge_sha256,session_id,member_id,purpose,rp_id,exact_origin,
       expires_at,activation_restart_grant_id
     ) values ($1,$2,$3,null,$4,'activation_restart','boardagent.test',$5,
       transaction_timestamp()+interval '5 minutes',$6)`,
    [challengeId, organizationId, Buffer.alloc(32, byte), memberId, ORIGIN, grantId]
  );
}

function completeRestart(
  pool: Pool,
  organizationId: string,
  input: Omit<Parameters<typeof completeActivationRestartInTransaction>[1], "organizationId">,
  options: { readonly consume?: boolean } = {}
) {
  return withIdentityTransaction(
    pool,
    { organizationId },
    async (client) => {
      if (options.consume !== false) {
        await client.query(
          "update webauthn_challenges set consumed_at=transaction_timestamp() where id=$1 and consumed_at is null",
          [input.webauthnChallengeId]
        );
      }
      return completeActivationRestartInTransaction(client, { ...input, organizationId });
    },
    { assumeRole: "boardagent_server" }
  );
}

async function ageGrant(pool: Pool, grantId: string) {
  await pool.query(
    "alter table activation_restart_grants disable trigger boardagent_activation_restart_grant_transition"
  );
  await pool.query(
    `update activation_restart_grants
        set created_at=transaction_timestamp()-interval '11 minutes',
            expires_at=transaction_timestamp()-interval '1 minute'
      where id=$1`,
    [grantId]
  );
  await pool.query(
    "alter table activation_restart_grants enable trigger boardagent_activation_restart_grant_transition"
  );
}

function activationArguments(
  memberId: string,
  invitationId: string,
  challengeId: string,
  confirmationCode: string,
  idempotencyKey: string
) {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    member_id: memberId,
    invitation_id: invitationId,
    challenge_id: challengeId,
    confirmation_code: confirmationCode,
    proofing_method: "verified_number_call",
    idempotency_key: idempotencyKey
  } as const;
}

/** Drives confirm_enrollment_activation exactly as the administration test does. */
async function confirmFreshCode(
  pool: Pool,
  actor: AuthorizedActorFixture,
  args: ReturnType<typeof activationArguments>,
  sequence: number
) {
  const prepared = await withRequestTransaction(
    pool,
    actor.context,
    (client) => prepareEnrollmentActivationInTransaction(client, args),
    SERVER
  );
  const requestState = Buffer.alloc(48, sequence % 256);
  const confirmationCode = `A${sequence.toString(10).padStart(7, "0")}`;
  const staged = await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      stageActionInTransaction(
        client,
        {
          stageId: testId(sequence),
          inputRequiredAttemptId: testId(sequence + 1),
          boardId: null,
          actingForMemberId: null,
          actionCode: "confirm_enrollment_activation",
          targetType: "member",
          targetId: args.member_id,
          canonicalSchema: "boardagent.enrollment-activation.v1",
          canonicalPayload: prepared.canonicalPayload,
          packageSha256: null,
          nonce: Buffer.alloc(32, (sequence + 2) % 256),
          confirmationCode,
          accessTokenRecordId: actor.accessTokenRecordId,
          exactOrigin: ORIGIN,
          originalName: "confirm_enrollment_activation",
          originalArguments: args,
          clientCapabilities: CAPABILITIES,
          embeddedForm: { schema_version: "boardagent.confirmation-form.v1" },
          embeddedResult: { schema_version: "boardagent.input-required.v1" },
          requestStateBytes: requestState,
          preparedRequestId: Buffer.from(`prepared-activation-${String(sequence)}`),
          auditEventIds: {
            stageReplaced: testId(sequence + 2),
            stageCreated: testId(sequence + 3),
            elicitationSent: testId(sequence + 4)
          }
        },
        async (requestClient) => {
          const current = await prepareEnrollmentActivationInTransaction(requestClient, args);
          expect(current.payloadSha256).toBe(prepared.payloadSha256);
        }
      ),
    SERVER
  );
  const confirmSequence = sequence + 20;
  return withRequestTransaction(
    pool,
    actor.context,
    (client) => {
      let current: PreparedEnrollmentActivation | undefined;
      return confirmStagedActionInTransaction(
        client,
        {
          stageId: staged.stageId,
          consentRecordId: testId(confirmSequence),
          retryRequestId: Buffer.from(`retry-activation-${String(confirmSequence)}`),
          originalArguments: args,
          clientCapabilities: CAPABILITIES,
          exactOrigin: ORIGIN,
          requestStateBytes: requestState,
          responseAction: "accept",
          inputResponse: { approve: true, confirmation_code: confirmationCode },
          auditEventIds: {
            consentRecorded: testId(confirmSequence + 1),
            consentRejected: testId(confirmSequence + 2)
          }
        },
        async (requestClient) => {
          current = await prepareEnrollmentActivationInTransaction(requestClient, args);
          return { payloadSha256: current.payloadSha256, packageSha256: null };
        },
        async (requestClient, consentRecordId) => {
          if (!current) throw new Error("activation binding was not prepared");
          const plan = await planEnrollmentActivationInTransaction(requestClient, {
            originalArguments: args,
            expectedPayloadSha256: current.payloadSha256,
            consentRecordId,
            idempotencyRecordId: testId(confirmSequence + 3),
            auditEventId: testId(confirmSequence + 4),
            feedIds: current.seats.map((seat, index) => ({
              boardId: seat.boardId,
              feedId: testId(confirmSequence + 5 + index)
            }))
          });
          return {
            value: plan.outcome,
            auditEvents: [plan.auditEvent],
            finalizeAfterAudit: async (finalClient: PoolClient) => {
              await finalizeEnrollmentActivationInTransaction(finalClient, plan);
            }
          };
        }
      );
    },
    SERVER
  );
}

describe("pending-activation restart: confirmed issuance", () => {
  it.each(["expired", "exhausted"] as const)(
    "lets the board secretary restart a %s activation, revoking the stale code and recording one grant",
    async (mode) => {
      await withDatabase(async (pool) => {
        const seeded = await seedStuckMember(pool, mode);
        const args = restartArguments(seeded.memberId, seeded.challengeId, "restart-member-000001");
        const prepared = await prepareRestart(pool, seeded.actor.context, args);
        expect(prepared).toMatchObject({
          memberId: seeded.memberId,
          memberDisplayName: "Mina Al Noor",
          staleChallengeId: seeded.challengeId,
          staleChallengeState: "issued",
          attemptCount: mode === "exhausted" ? 20 : 0,
          proofingMethod: "verified_number_call",
          seats: [
            {
              boardId: seeded.actor.boardId,
              boardName: "Board",
              seatRole: "voting_member",
              isSecretary: false,
              votingWeight: "1"
            }
          ]
        });
        expect(JSON.stringify(prepared.canonicalPayload)).not.toContain("ACT-OLD1");

        const issued = await issueRestart(
          pool,
          seeded.actor,
          seeded.memberId,
          seeded.challengeId,
          3200
        );
        expect(issued.staleChallengeId).toBe(seeded.challengeId);
        expect(issued.memberDisplayName).toBe("Mina Al Noor");
        expect(issued.auditEvent).toBeNull();
        expect(issued.appendedAuditEvent.eventType).toBe("activation_restart_issued");
        expect(await grantRow(pool, issued.grantId)).toEqual({
          issuer_kind: "member",
          issued_by: seeded.actor.memberId,
          proofing_method: "verified_number_call",
          stale_challenge_id: seeded.challengeId,
          consumed_at: null,
          fresh_challenge_id: null,
          completed_audit_event_id: null,
          ten_minutes: true,
          token_hex: issued.tokenSha256
        });
        expect(await challengeState(pool, seeded.challengeId)).toEqual({
          state: "revoked",
          attempt_count: mode === "exhausted" ? 20 : 0
        });
        expect(
          (await pool.query("select state from members where id=$1", [seeded.memberId])).rows
        ).toEqual([{ state: "pending_activation" }]);
        const audits = await auditRows(pool, "activation_restart_issued");
        expect(audits).toHaveLength(1);
        expect(audits[0]).toMatchObject({
          object_id: issued.grantId,
          actor_member_id: seeded.actor.memberId,
          consent_record_id: testId(3220)
        });
        expect(JSON.parse(audits[0]!.payload).details).toEqual({
          memberId: seeded.memberId,
          staleChallengeId: seeded.challengeId,
          grantId: issued.grantId,
          proofingMethod: "verified_number_call",
          expiresAt: issued.expiresAt
        });
        const everything = await pool.query(
          "select string_agg(convert_from(canonical_payload,'UTF8'),' ') as all_payloads from audit_events"
        );
        expect(everything.rows[0]?.all_payloads).not.toContain(issued.token);
        expect(everything.rows[0]?.all_payloads).not.toContain(issued.tokenSha256);

        // A second live handoff for the same person is refused; the stale code is already gone.
        await expect(prepareRestart(pool, seeded.actor.context, args)).rejects.toMatchObject({
          code: "activation_restart_unavailable"
        });
      });
    }
  );

  it("lets a company administrator who is not a secretary issue the restart", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedStuckMember(pool, "expired");
      const admin = await seedCompanyAdmin(pool, seeded.actor, 3400);
      const issued = await issueRestart(pool, admin, seeded.memberId, seeded.challengeId, 3500);
      expect((await grantRow(pool, issued.grantId))?.issued_by).toBe(admin.memberId);
      expect((await challengeState(pool, seeded.challengeId))?.state).toBe("revoked");
    });
  });

  it("refuses the person themselves, observers, other boards' secretaries and a stale confirmation", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedStuckMember(pool, "expired");
      const args = restartArguments(seeded.memberId, seeded.challengeId, "restart-member-000002");
      const unavailable = { code: "activation_restart_unavailable" };
      // The pending person acting for themselves.
      await expect(
        prepareRestart(pool, { ...seeded.actor.context, memberId: seeded.memberId }, args)
      ).rejects.toMatchObject(unavailable);
      // An observer holding the scope and even the admin role.
      const observer = await seedAdditionalAuthorizedActor(pool, seeded.actor, {
        idBase: 3600,
        seatRole: "observer",
        scopes: ["governance:read", "secretariat:admin"]
      });
      await attachSession(pool, observer, testId(3620));
      await pool.query(
        `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
         values ($1,$2,$3,'admin','test observer administrator')`,
        [testId(3621), observer.organizationId, observer.memberId]
      );
      await expect(prepareRestart(pool, observer.context, args)).rejects.toMatchObject(unavailable);
      // The secretary of a board where the person holds no seat.
      const otherBoardId = testId(3700);
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'other','Other','UTC')",
        [otherBoardId, seeded.actor.organizationId]
      );
      const foreign = await seedAdditionalAuthorizedActor(
        pool,
        { ...seeded.actor, boardId: otherBoardId },
        {
          idBase: 3710,
          seatRole: "voting_member",
          scopes: ["governance:read", "secretariat:admin"],
          isSecretary: true
        }
      );
      await attachSession(pool, foreign, testId(3731));
      await expect(prepareRestart(pool, foreign.context, args)).rejects.toMatchObject(unavailable);
      // A secretary without secretariat:admin on the token.
      await pool.query(
        "update access_token_records set scope_set=array['governance:read'] where id=$1",
        [seeded.actor.accessTokenRecordId]
      );
      await expect(prepareRestart(pool, seeded.actor.context, args)).rejects.toMatchObject(
        unavailable
      );
      await pool.query(
        "update access_token_records set scope_set=array['governance:read','secretariat:admin'] where id=$1",
        [seeded.actor.accessTokenRecordId]
      );
      // The confirmation is bound to the exact prepared projection.
      const staged = await stageRestart(pool, seeded.actor, args, 3800);
      await pool.query(
        "update enrollment_activation_challenges set attempt_count=attempt_count+1 where id=$1",
        [seeded.challengeId]
      );
      const drifted = await confirmRestart(pool, seeded.actor, args, staged, 3820, "drift-token");
      expect(drifted.confirmed).toBe(false);
      expect(
        (await pool.query("select count(*)::int as n from activation_restart_grants")).rows
      ).toEqual([{ n: 0 }]);
      expect((await challengeState(pool, seeded.challengeId))?.state).toBe("issued");
    });
  });

  it.each([
    ["is still in another state", "active"],
    ["still has a live code", "live"],
    ["already consumed a code", "consumed"],
    ["registered no passkey", "no_credential"],
    ["names a different challenge", "wrong_challenge"]
  ] as const)("refuses when the member %s", async (_label, variant) => {
    await withDatabase(async (pool) => {
      const seeded = await seedStuckMember(pool, variant === "live" ? "live" : "expired");
      let challengeId: string = seeded.challengeId;
      if (variant === "active")
        await pool.query(
          "update members set state='active',row_version=row_version+1 where id=$1",
          [seeded.memberId]
        );
      if (variant === "consumed")
        await pool.query(
          "update enrollment_activation_challenges set state='consumed',consumed_at=transaction_timestamp(),confirmed_by=$2 where id=$1",
          [seeded.challengeId, seeded.actor.memberId]
        );
      if (variant === "no_credential")
        await pool.query("delete from webauthn_credentials where id=$1", [seeded.credentialId]);
      if (variant === "wrong_challenge") challengeId = testId(3999);
      await expect(
        prepareRestart(
          pool,
          seeded.actor.context,
          restartArguments(seeded.memberId, challengeId, "restart-member-000003")
        )
      ).rejects.toMatchObject({ code: "activation_restart_unavailable" });
      expect(
        (await pool.query("select count(*)::int as n from activation_restart_grants")).rows
      ).toEqual([{ n: 0 }]);
    });
  });

  it("grants execution only to the server role and keeps the grant table migrator-private", async () => {
    await withDatabase(async (pool) => {
      const privileges = await pool.query<Record<string, boolean>>(
        `select
           has_function_privilege('boardagent_server','public.boardagent_prepare_activation_restart(uuid,uuid,text)','EXECUTE') as server_prepare,
           has_function_privilege('boardagent_server','public.boardagent_issue_activation_restart(jsonb,bytea,uuid,bytea,uuid,uuid)','EXECUTE') as server_issue,
           has_function_privilege('boardagent_server','public.boardagent_lookup_activation_restart(bytea)','EXECUTE') as server_lookup,
           has_function_privilege('boardagent_server','public.boardagent_complete_activation_restart(bytea,uuid,uuid,uuid,bytea,uuid)','EXECUTE') as server_complete,
           has_function_privilege('boardagent_server','public.boardagent_issue_first_activation_restart(bytea,uuid,uuid,text)','EXECUTE') as server_first,
           has_function_privilege('boardagent_worker','public.boardagent_issue_activation_restart(jsonb,bytea,uuid,bytea,uuid,uuid)','EXECUTE') as worker_issue,
           has_table_privilege('boardagent_server','activation_restart_grants','SELECT,INSERT,UPDATE,DELETE') as server_table,
           has_table_privilege('boardagent_worker','activation_restart_grants','SELECT,INSERT,UPDATE,DELETE') as worker_table,
           (select relforcerowsecurity from pg_class where oid='activation_restart_grants'::regclass) as forced`
      );
      expect(privileges.rows[0]).toEqual({
        server_prepare: true,
        server_issue: true,
        server_lookup: true,
        server_complete: true,
        server_first: false,
        worker_issue: false,
        server_table: false,
        worker_table: false,
        forced: true
      });
      await expect(
        pool.query(
          "insert into webauthn_challenges(id,organization_id,challenge_sha256,purpose,rp_id,exact_origin,expires_at) values ($1,$2,$3,'unknown','r','https://x',transaction_timestamp()+interval '1 minute')",
          [testId(1), testId(1), testHash(1)]
        )
      ).rejects.toMatchObject({ code: "23514" });
    });
  });
});

describe("pending-activation restart: handoff lookup and completion", () => {
  it("shows the handoff only while live, mints one fresh code on completion, then closes", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedStuckMember(pool, "exhausted");
      const issued = await issueRestart(
        pool,
        seeded.actor,
        seeded.memberId,
        seeded.challengeId,
        4000
      );
      const organizationId = seeded.actor.organizationId;
      const lookup = (tokenSha256: string) =>
        withIdentityTransaction(
          pool,
          { organizationId },
          (client) => lookupActivationRestartInTransaction(client, { tokenSha256 }),
          { assumeRole: "boardagent_server" }
        );
      expect(await lookup(issued.tokenSha256)).toEqual({
        grantId: issued.grantId,
        organizationId,
        memberId: seeded.memberId,
        memberDisplayName: "Mina Al Noor",
        organizationDisplayName: "Org",
        proofingMethod: "verified_number_call",
        expiresAt: issued.expiresAt
      });
      expect(await lookup(sha256Hex("not-the-token"))).toBeNull();

      const assertionChallengeId = testId(4100);
      await insertAssertionChallenge(
        pool,
        organizationId,
        seeded.memberId,
        issued.grantId,
        assertionChallengeId,
        41
      );
      const freshCode = "ACT-NEW1";
      const freshChallengeId = testId(4101);
      const base = {
        memberId: seeded.memberId,
        grantId: issued.grantId,
        tokenSha256: issued.tokenSha256,
        freshChallengeId,
        activationCodeSha256: sha256Hex(freshCode),
        auditEventId: testId(4102),
        webauthnChallengeId: assertionChallengeId,
        webauthnCredentialId: seeded.credentialId
      };
      // Refusals before the real completion: an unconsumed assertion, a foreign passkey,
      // and a different principal. None of them leaves a challenge or an audit behind.
      expect(await completeRestart(pool, organizationId, base, { consume: false })).toEqual({
        completed: false
      });
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,signature_counter,
           transports,backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
        [
          testId(4103),
          organizationId,
          seeded.actor.memberId,
          Buffer.alloc(32, 5),
          Buffer.alloc(32, 6)
        ]
      );
      expect(
        await completeRestart(pool, organizationId, { ...base, webauthnCredentialId: testId(4103) })
      ).toEqual({ completed: false });
      expect(
        await completeRestart(pool, organizationId, { ...base, memberId: seeded.actor.memberId })
      ).toEqual({ completed: false });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from enrollment_activation_challenges where id=$1",
            [freshChallengeId]
          )
        ).rows
      ).toEqual([{ n: 0 }]);
      expect(await auditRows(pool, "activation_restart_completed")).toEqual([]);
      // The consumed assertion from the refused attempts must not satisfy a later one.
      await pool.query("update webauthn_challenges set consumed_at=null where id=$1", [
        assertionChallengeId
      ]);

      const completed = await completeRestart(pool, organizationId, base);
      expect(completed).toEqual({
        completed: true,
        activationChallengeId: freshChallengeId,
        invitationId: seeded.invitationId
      });
      const fresh = await pool.query<{
        state: string;
        attempt_count: number;
        proofing_method: string;
        invitation_id: string;
        member_id: string;
        ten_minutes: boolean;
        code_hex: string;
      }>(
        `select state,attempt_count,proofing_method,invitation_id,member_id,
                expires_at=issued_at+interval '10 minutes' as ten_minutes,
                encode(protected_code,'hex') as code_hex
           from enrollment_activation_challenges where id=$1`,
        [freshChallengeId]
      );
      expect(fresh.rows[0]).toEqual({
        state: "issued",
        attempt_count: 0,
        proofing_method: "verified_number_call",
        invitation_id: seeded.invitationId,
        member_id: seeded.memberId,
        ten_minutes: true,
        code_hex: sha256Hex(freshCode)
      });
      expect(await grantRow(pool, issued.grantId)).toMatchObject({
        fresh_challenge_id: freshChallengeId,
        completed_audit_event_id: testId(4102)
      });
      expect((await grantRow(pool, issued.grantId))?.consumed_at).not.toBeNull();
      const completions = await auditRows(pool, "activation_restart_completed");
      expect(completions).toHaveLength(1);
      expect(JSON.parse(completions[0]!.payload).details).toMatchObject({
        grantId: issued.grantId,
        memberId: seeded.memberId,
        credentialId: seeded.credentialId,
        staleChallengeId: seeded.challengeId,
        freshChallengeId,
        passkeyUserVerified: true,
        expiresInSeconds: 600
      });
      expect(completions[0]!.payload).not.toContain(freshCode);
      expect(completions[0]!.payload).not.toContain(sha256Hex(freshCode));

      // Replay: the handoff is consumed, so it is no longer visible and cannot complete again.
      expect(await lookup(issued.tokenSha256)).toBeNull();
      await insertAssertionChallenge(
        pool,
        organizationId,
        seeded.memberId,
        issued.grantId,
        testId(4110),
        42
      );
      expect(
        await completeRestart(pool, organizationId, {
          ...base,
          webauthnChallengeId: testId(4110),
          freshChallengeId: testId(4111),
          auditEventId: testId(4112)
        })
      ).toEqual({ completed: false });
      // The old code is dead; the fresh one is confirmed through the unchanged ceremony.
      await expect(
        withRequestTransaction(
          pool,
          seeded.actor.context,
          (client) =>
            prepareEnrollmentActivationInTransaction(
              client,
              activationArguments(
                seeded.memberId,
                seeded.invitationId,
                seeded.challengeId,
                "ACT-OLD1",
                "activate-member-000009"
              )
            ),
          SERVER
        )
      ).rejects.toMatchObject({ code: "enrollment_activation_unavailable" });
      const activation = await confirmFreshCode(
        pool,
        seeded.actor,
        activationArguments(
          seeded.memberId,
          seeded.invitationId,
          freshChallengeId,
          freshCode,
          "activate-member-000010"
        ),
        4200
      );
      expect(activation).toMatchObject({ confirmed: true, value: "activated" });
      expect(
        (
          await pool.query("select state,row_version::text from members where id=$1", [
            seeded.memberId
          ])
        ).rows
      ).toEqual([{ state: "active", row_version: "2" }]);
      expect((await challengeState(pool, freshChallengeId))?.state).toBe("consumed");
      expect((await challengeState(pool, seeded.challengeId))?.state).toBe("revoked");
    });
  });

  it("refuses an expired handoff and never lets the grant be reopened", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedStuckMember(pool, "expired");
      const issued = await issueRestart(
        pool,
        seeded.actor,
        seeded.memberId,
        seeded.challengeId,
        4300
      );
      const organizationId = seeded.actor.organizationId;
      await ageGrant(pool, issued.grantId);
      expect(
        await withIdentityTransaction(
          pool,
          { organizationId },
          (client) =>
            lookupActivationRestartInTransaction(client, { tokenSha256: issued.tokenSha256 }),
          { assumeRole: "boardagent_server" }
        )
      ).toBeNull();
      await insertAssertionChallenge(
        pool,
        organizationId,
        seeded.memberId,
        issued.grantId,
        testId(4310),
        43
      );
      expect(
        await completeRestart(pool, organizationId, {
          memberId: seeded.memberId,
          grantId: issued.grantId,
          tokenSha256: issued.tokenSha256,
          freshChallengeId: testId(4311),
          activationCodeSha256: sha256Hex("ACT-NEW2"),
          auditEventId: testId(4312),
          webauthnChallengeId: testId(4310),
          webauthnCredentialId: seeded.credentialId
        })
      ).toEqual({ completed: false });
      expect(
        (await pool.query("select count(*)::int as n from enrollment_activation_challenges")).rows
      ).toEqual([{ n: 1 }]);
      // Authority columns and the consumed state are immutable even for the schema owner.
      await expect(
        pool.query("update activation_restart_grants set member_id=$2 where id=$1", [
          issued.grantId,
          seeded.actor.memberId
        ])
      ).rejects.toMatchObject({ code: "23514" });
      // A restart audit claim cannot be committed without its grant.
      await expect(
        pool.query(
          `insert into audit_events(
             id,sequence,organization_id,event_type,schema_version,object_type,object_id,
             canonical_payload,previous_event_sha256,event_sha256
           ) select $1,max(sequence)+1,$2,'activation_restart_issued','boardagent.audit-event.v1',
                    'activation_restart_grant',$3,convert_to('{}','UTF8'),
                    (select event_sha256 from audit_events order by sequence desc limit 1),$4
             from audit_events`,
          [testId(4320), organizationId, testId(4321), testHash(44)]
        )
      ).rejects.toThrow(/lacks its committed grant/u);
    });
  });
});

describe("pending-activation restart: operator path for the first administrator", () => {
  const setup = {
    organizationLegalName: "Synthetic Restart Company",
    organizationDisplayName: "Synthetic Restart Company",
    organizationSlug: "restart-test",
    timezone: "UTC",
    canonicalResourceUri: "https://restart.boardagent.test/mcp",
    boardSlug: "main",
    boardName: "Main Board",
    boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main Board" },
    firstSecretaryLegalName: "First Administrator",
    firstSecretaryDisplayName: "First Administrator",
    votingWeight: 1,
    supportName: "Secretary office",
    supportContactMethods: [{ kind: "phone", value: "synthetic-test-number" }],
    onboardingTermsText: "Read the canonical records and confirm personally.",
    invitationHandoffMethod: "in-person QR"
  };

  /** The first person registered a passkey and let the code expire before activate-first. */
  async function stuckFirstAdministrator(pool: Pool) {
    const operator = new BoardAgentBootstrapOperator(pool, {
      assumeRole: "boardagent_migrator",
      expectedCanonicalResourceUri: setup.canonicalResourceUri
    });
    const first = await operator.initialize(setup);
    if (first.status !== "created") throw new Error("expected new bootstrap fixture");
    await pool.query(
      "update members set state='enrollment_pending',row_version=row_version+1 where id=$1",
      [first.firstMemberId]
    );
    await pool.query(
      "update members set state='pending_activation',row_version=row_version+1 where id=$1",
      [first.firstMemberId]
    );
    await pool.query(
      "update enrollment_invitations set consumed_at=transaction_timestamp(),pending_activation_member_id=$2 where id=$1",
      [first.invitationId, first.firstMemberId]
    );
    await pool.query(
      `insert into webauthn_credentials(
         id,organization_id,member_id,credential_id,public_key,signature_counter,
         transports,backup_eligible,backup_state,state
       ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
      [
        testId(5001),
        first.organizationId,
        first.firstMemberId,
        Buffer.alloc(32, 7),
        Buffer.alloc(32, 8)
      ]
    );
    const challengeId = testId(5002);
    await pool.query(
      `insert into enrollment_activation_challenges(
         id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,
         issued_at,expires_at
       ) values ($1,$2,$3,$4,$5,'in_person','issued',
         transaction_timestamp()-interval '11 minutes',transaction_timestamp()-interval '1 minute')`,
      [challengeId, first.organizationId, first.firstMemberId, first.invitationId, testHash(50)]
    );
    return {
      first,
      challengeId,
      request: {
        instanceId: first.instanceId,
        organizationId: first.organizationId,
        memberId: first.firstMemberId,
        canonicalResourceUri: setup.canonicalResourceUri,
        proofingMethod: "in_person" as const,
        reason: "The first administrator's activation code expired before activate-first"
      }
    };
  }

  function restartFirst(pool: Pool, request: Record<string, unknown>, sequence: number) {
    return withBootstrapTransaction(
      pool,
      (client) =>
        issueFirstActivationRestartInTransaction(client, {
          ...request,
          grantId: testId(sequence),
          tokenSha256: sha256Hex(`first-restart-${String(sequence)}`),
          auditEventId: testId(sequence + 1)
        } as Parameters<typeof issueFirstActivationRestartInTransaction>[1]),
      { assumeRole: "boardagent_migrator" }
    );
  }

  it("restarts only the singleton first administrator's stuck activation", async () => {
    await withDatabase(async (pool) => {
      const { first, challengeId, request } = await stuckFirstAdministrator(pool);
      const result = await restartFirst(pool, request, 5100);
      expect(result).toEqual({
        instanceId: first.instanceId,
        organizationId: first.organizationId,
        firstMemberId: first.firstMemberId,
        grantId: testId(5100),
        staleChallengeId: challengeId,
        expiresAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u)
      });
      expect(await grantRow(pool, testId(5100))).toMatchObject({
        issuer_kind: "operator",
        issued_by: null,
        proofing_method: "in_person",
        stale_challenge_id: challengeId,
        consumed_at: null
      });
      expect((await challengeState(pool, challengeId))?.state).toBe("revoked");
      const audits = await auditRows(pool, "activation_restart_issued");
      expect(audits).toHaveLength(1);
      expect(JSON.parse(audits[0]!.payload)).toMatchObject({
        origin: "cli",
        actorMemberId: null,
        details: {
          bootstrap: true,
          firstMemberId: first.firstMemberId,
          staleChallengeId: challengeId,
          grantId: testId(5100),
          proofingMethod: "in_person",
          reason: request.reason
        }
      });
      expect(JSON.stringify(audits)).not.toContain(sha256Hex("first-restart-5100"));
      // The live handoff blocks a second one; the stale code cannot be restarted twice.
      await expect(restartFirst(pool, request, 5110)).rejects.toMatchObject({
        code: "bootstrap_restart_unavailable"
      });
    });
  });

  it.each([
    ["another member exists", "another_member"],
    ["the code is still live", "live_code"],
    ["the instance does not match", "wrong_instance"],
    ["there is no registered passkey or code to restart", "invited"]
  ] as const)("refuses when %s", async (_label, variant) => {
    await withDatabase(async (pool) => {
      const { first, challengeId, request } = await stuckFirstAdministrator(pool);
      let candidate: Record<string, unknown> = request;
      if (variant === "another_member")
        await pool.query(
          `insert into members(id,organization_id,member_kind,legal_name,display_name)
           values ($1,$2,'human','Second Person','Second Person')`,
          [testId(5200), first.organizationId]
        );
      if (variant === "live_code")
        await pool.query(
          "update enrollment_activation_challenges set issued_at=transaction_timestamp(),expires_at=transaction_timestamp()+interval '9 minutes' where id=$1",
          [challengeId]
        );
      if (variant === "wrong_instance") candidate = { ...request, instanceId: testId(5201) };
      if (variant === "invited") {
        await pool.query("delete from enrollment_activation_challenges where id=$1", [challengeId]);
        await pool.query("delete from webauthn_credentials where member_id=$1", [
          first.firstMemberId
        ]);
      }
      const before = (await pool.query("select count(*)::int as n from audit_events")).rows;
      await expect(restartFirst(pool, candidate, 5300)).rejects.toMatchObject({
        code: "bootstrap_restart_unavailable"
      });
      expect(
        (await pool.query("select count(*)::int as n from activation_restart_grants")).rows
      ).toEqual([{ n: 0 }]);
      expect((await pool.query("select count(*)::int as n from audit_events")).rows).toEqual(
        before
      );
    });
  });

  it("refuses server and worker roles even with a claimed bootstrap scope", async () => {
    await withDatabase(async (pool) => {
      const { request } = await stuckFirstAdministrator(pool);
      for (const role of ["boardagent_server", "boardagent_worker"] as const) {
        const client = await pool.connect();
        try {
          await client.query("begin isolation level serializable");
          await client.query(`set local role ${role}`);
          await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(
            issueFirstActivationRestartInTransaction(client, {
              ...request,
              grantId: testId(5400),
              tokenSha256: sha256Hex("first-restart-5400"),
              auditEventId: testId(5401)
            })
          ).rejects.toThrow("managed serializable migrator transaction");
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
    });
  });
});
