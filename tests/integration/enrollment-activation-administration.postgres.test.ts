import { createHash } from "node:crypto";
import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import {
  confirmStagedActionInTransaction,
  finalizeEnrollmentActivationInTransaction,
  migrate,
  planEnrollmentActivationInTransaction,
  prepareEnrollmentActivationInTransaction,
  stageActionInTransaction,
  withRequestTransaction,
  type PreparedEnrollmentActivation
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const CAPABILITIES = { elicitation: { form: {} } } as const;
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_activation_admin_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "enrollment-activation-administration-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedPendingActivation(pool: Pool, code: string) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["governance:read", "secretariat:admin"],
    isSecretary: true
  });
  const secretarySessionId = testId(3101);
  const targetMemberId = testId(3102);
  const targetMembershipId = testId(3103);
  const invitationId = testId(3104);
  const challengeId = testId(3105);
  await pool.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
       transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
    [secretarySessionId, actor.organizationId, testHash(91), actor.memberId, actor.clientId]
  );
  await pool.query("update access_token_records set session_id=$1 where id=$2", [
    secretarySessionId,
    actor.accessTokenRecordId
  ]);
  await pool.query(
    `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
     values ($1,$2,'human','Mina Al Noor','Mina Al Noor','pending_activation')`,
    [targetMemberId, actor.organizationId]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
    [targetMembershipId, actor.organizationId, actor.boardId, targetMemberId]
  );
  await pool.query(
    `insert into enrollment_invitations(
       id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at,
       consumed_at,pending_activation_member_id
     ) values ($1,$2,$3,$4,$5,'operator_display',transaction_timestamp()+interval '1 hour',
       transaction_timestamp(),$3)`,
    [invitationId, actor.organizationId, targetMemberId, testHash(92), actor.memberId]
  );
  await pool.query(
    `insert into webauthn_credentials(
       id,organization_id,member_id,credential_id,public_key,signature_counter,
       transports,backup_eligible,backup_state,state
     ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
    [testId(3106), actor.organizationId, targetMemberId, Buffer.alloc(32, 3), Buffer.alloc(32, 4)]
  );
  await pool.query(
    `insert into enrollment_activation_challenges(
       id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,
       expires_at
     ) values ($1,$2,$3,$4,$5,'verified_number_call','issued',
       transaction_timestamp()+interval '10 minutes')`,
    [
      challengeId,
      actor.organizationId,
      targetMemberId,
      invitationId,
      createHash("sha256").update(code, "utf8").digest()
    ]
  );
  return { actor, targetMemberId, invitationId, challengeId };
}

function activationArguments(
  seeded: Awaited<ReturnType<typeof seedPendingActivation>>,
  confirmationCode: string,
  idempotencyKey: string
) {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    member_id: seeded.targetMemberId,
    invitation_id: seeded.invitationId,
    challenge_id: seeded.challengeId,
    confirmation_code: confirmationCode,
    proofing_method: "verified_number_call",
    idempotency_key: idempotencyKey
  } as const;
}

async function stageActivation(
  pool: Pool,
  seeded: Awaited<ReturnType<typeof seedPendingActivation>>,
  args: ReturnType<typeof activationArguments>,
  sequence: number
) {
  const prepared = await withRequestTransaction(
    pool,
    seeded.actor.context,
    (client) => prepareEnrollmentActivationInTransaction(client, args),
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
  const requestState = Buffer.alloc(48, sequence % 256);
  const confirmationCode = `A${sequence.toString(10).padStart(7, "0")}`;
  const staged = await withRequestTransaction(
    pool,
    seeded.actor.context,
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
          targetId: seeded.targetMemberId,
          canonicalSchema: "boardagent.enrollment-activation.v1",
          canonicalPayload: prepared.canonicalPayload,
          packageSha256: null,
          nonce: Buffer.alloc(32, (sequence + 2) % 256),
          confirmationCode,
          accessTokenRecordId: seeded.actor.accessTokenRecordId,
          exactOrigin: "https://boardagent.test",
          originalName: "confirm_enrollment_activation",
          originalArguments: args,
          clientCapabilities: CAPABILITIES,
          embeddedForm: { schema_version: "boardagent.confirmation-form.v1" },
          embeddedResult: { schema_version: "boardagent.input-required.v1" },
          requestStateBytes: requestState,
          preparedRequestId: Buffer.from(`prepared-${String(sequence)}`),
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
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
  return { prepared, stageId: staged.stageId, requestState, confirmationCode };
}

async function confirmActivation(
  pool: Pool,
  seeded: Awaited<ReturnType<typeof seedPendingActivation>>,
  args: ReturnType<typeof activationArguments>,
  staged: Awaited<ReturnType<typeof stageActivation>>,
  sequence: number
) {
  return withRequestTransaction(
    pool,
    seeded.actor.context,
    (client) => {
      let current: PreparedEnrollmentActivation | undefined;
      return confirmStagedActionInTransaction(
        client,
        {
          stageId: staged.stageId,
          consentRecordId: testId(sequence),
          retryRequestId: Buffer.from(`retry-activation-${String(sequence)}`),
          originalArguments: args,
          clientCapabilities: CAPABILITIES,
          exactOrigin: "https://boardagent.test",
          requestStateBytes: staged.requestState,
          responseAction: "accept",
          inputResponse: { approve: true, confirmation_code: staged.confirmationCode },
          auditEventIds: {
            consentRecorded: testId(sequence + 1),
            consentRejected: testId(sequence + 2)
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
            idempotencyRecordId: testId(sequence + 3),
            auditEventId: testId(sequence + 4),
            feedIds: current.seats.map((seat, index) => ({
              boardId: seat.boardId,
              feedId: testId(sequence + 5 + index)
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
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
}

describe("confirmed enrollment activation administration", () => {
  it("atomically binds recent secretary consent, member activation, audit and onboarding feed", async () => {
    await withDatabase(async (pool) => {
      const humanCode = "ACT-2V4Q";
      const seeded = await seedPendingActivation(pool, humanCode);
      const args = activationArguments(seeded, humanCode, "activate-member-000001");
      const staged = await stageActivation(pool, seeded, args, 3200);
      expect(JSON.stringify(staged.prepared.canonicalPayload)).not.toContain(humanCode);
      expect(staged.prepared).toMatchObject({
        memberId: seeded.targetMemberId,
        memberDisplayName: "Mina Al Noor",
        memberState: "pending_activation",
        invitationId: seeded.invitationId,
        challengeId: seeded.challengeId,
        proofingMethod: "verified_number_call"
      });

      const resolution = await confirmActivation(pool, seeded, args, staged, 3220);
      expect(resolution).toMatchObject({ confirmed: true, value: "activated" });
      const projection = await pool.query<{
        member_state: string;
        row_version: string;
        challenge_state: string;
        confirmed_by: string | null;
        feed_count: string;
        activation_events: string;
        consent_record_id: string | null;
        token_jti: string | null;
      }>(
        `select member.state as member_state,member.row_version::text,
                challenge.state as challenge_state,challenge.confirmed_by,
                (select count(*)::text from pending_action_feed
                  where member_id=member.id and action_type='complete_onboarding') as feed_count,
                (select count(*)::text from audit_events
                  where object_id=member.id and event_type='member_activated') as activation_events,
                audit.consent_record_id,audit.token_jti
           from members as member
           join enrollment_activation_challenges as challenge on challenge.member_id=member.id
           join audit_events as audit
             on audit.object_id=member.id and audit.event_type='member_activated'
          where member.id=$1`,
        [seeded.targetMemberId]
      );
      expect(projection.rows[0]).toEqual({
        member_state: "active",
        row_version: "2",
        challenge_state: "consumed",
        confirmed_by: seeded.actor.memberId,
        feed_count: "1",
        activation_events: "1",
        consent_record_id: testId(3220),
        token_jti: seeded.actor.tokenJti
      });
      const protectedMaterial = await pool.query<{
        challenge_hash: string;
        stage_payload: string;
      }>(
        `select encode(challenge.protected_code,'hex') as challenge_hash,
                convert_from(stage.canonical_payload,'UTF8') as stage_payload
           from enrollment_activation_challenges as challenge
           join action_stages as stage
             on stage.target_id=challenge.member_id
            and stage.action_code='confirm_enrollment_activation'
          where challenge.id=$1`,
        [seeded.challengeId]
      );
      expect(protectedMaterial.rows[0]?.stage_payload).not.toContain(humanCode);
      expect(protectedMaterial.rows[0]?.stage_payload).toContain(
        createHash("sha256").update(humanCode, "utf8").digest("hex")
      );
      expect(protectedMaterial.rows[0]?.challenge_hash).toBe(
        createHash("sha256").update(humanCode, "utf8").digest("hex")
      );
    });
  });

  it("counts one freshly confirmed wrong code without activating or creating a feed", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedPendingActivation(pool, "ACT-2V4Q");
      const args = activationArguments(seeded, "BAD-9ZZZ", "activate-member-000002");
      const staged = await stageActivation(pool, seeded, args, 3300);
      const resolution = await confirmActivation(pool, seeded, args, staged, 3320);
      expect(resolution).toMatchObject({ confirmed: true, value: "code_mismatch" });

      const projection = await pool.query<{
        attempt_count: number;
        challenge_state: string;
        member_state: string;
        feeds: string;
        denials: string;
        consent_record_id: string | null;
      }>(
        `select challenge.attempt_count,challenge.state as challenge_state,
                member.state as member_state,
                (select count(*)::text from pending_action_feed where member_id=member.id) as feeds,
                (select count(*)::text from audit_events
                  where object_id=challenge.id and event_type='authorization_denied') as denials,
                audit.consent_record_id
           from enrollment_activation_challenges as challenge
           join members as member on member.id=challenge.member_id
           join audit_events as audit
             on audit.object_id=challenge.id and audit.event_type='authorization_denied'
          where challenge.id=$1`,
        [seeded.challengeId]
      );
      expect(projection.rows[0]).toEqual({
        attempt_count: 1,
        challenge_state: "issued",
        member_state: "pending_activation",
        feeds: "0",
        denials: "1",
        consent_record_id: testId(3320)
      });
    });
  });

  it("normalizes pre-confirmation code checks and requires a recent token-bound login", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedPendingActivation(pool, "ACT-2V4Q");
      const wrong = activationArguments(seeded, "BAD-9ZZZ", "activate-member-000003");
      const preparedWrong = await withRequestTransaction(
        pool,
        seeded.actor.context,
        (client) => prepareEnrollmentActivationInTransaction(client, wrong),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(preparedWrong).toMatchObject({
        memberId: seeded.targetMemberId,
        memberState: "pending_activation"
      });

      await pool.query(
        `update auth_sessions
            set last_authenticated_at=transaction_timestamp()-interval '11 minutes'
          where id=(select session_id from access_token_records where id=$1)`,
        [seeded.actor.accessTokenRecordId]
      );
      await expect(
        withRequestTransaction(
          pool,
          seeded.actor.context,
          (client) => prepareEnrollmentActivationInTransaction(client, wrong),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "enrollment_activation_unavailable" });

      const privileges = await pool.query<{
        server_finalize: boolean;
        server_plan: boolean;
        server_prepare: boolean;
        worker_finalize: boolean;
        worker_plan: boolean;
        worker_prepare: boolean;
      }>(
        `select
           has_function_privilege('boardagent_server',
             'public.boardagent_prepare_confirmed_enrollment_activation(uuid,uuid,uuid,bytea,text)',
             'EXECUTE') as server_prepare,
           has_function_privilege('boardagent_worker',
             'public.boardagent_prepare_confirmed_enrollment_activation(uuid,uuid,uuid,bytea,text)',
             'EXECUTE') as worker_prepare,
           has_function_privilege('boardagent_server',
             'public.boardagent_plan_confirmed_enrollment_activation(uuid,uuid,uuid,bytea,text,text,bytea,uuid)',
             'EXECUTE') as server_plan,
           has_function_privilege('boardagent_worker',
             'public.boardagent_plan_confirmed_enrollment_activation(uuid,uuid,uuid,bytea,text,text,bytea,uuid)',
             'EXECUTE') as worker_plan,
           has_function_privilege('boardagent_server',
             'public.boardagent_finalize_confirmed_enrollment_activation(uuid,uuid,uuid,bytea,text,text,bytea,bytea,uuid,uuid,uuid,uuid[],bytea)',
             'EXECUTE') as server_finalize,
           has_function_privilege('boardagent_worker',
             'public.boardagent_finalize_confirmed_enrollment_activation(uuid,uuid,uuid,bytea,text,text,bytea,bytea,uuid,uuid,uuid,uuid[],bytea)',
             'EXECUTE') as worker_finalize`
      );
      expect(privileges.rows[0]).toEqual({
        server_prepare: true,
        worker_prepare: false,
        server_plan: true,
        worker_plan: false,
        server_finalize: true,
        worker_finalize: false
      });
      await expect(
        withRequestTransaction(
          pool,
          seeded.actor.context,
          (client) =>
            client.query(
              "update members set state='active',row_version=row_version+1 where id=$1",
              [seeded.targetMemberId]
            ),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "42501" });
    });
  });
});
