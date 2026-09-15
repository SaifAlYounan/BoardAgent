import { createHash } from "node:crypto";
import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { TOOL_INPUT_SCHEMA_VERSION, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  confirmStagedActionInTransaction,
  issueEnrollmentInTransaction,
  migrate,
  prepareEnrollmentIssuanceInTransaction,
  stageActionInTransaction,
  withRequestTransaction,
  type PreparedEnrollmentIssuance
} from "../../lib/db/src/index.js";

import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const CAPABILITIES = { elicitation: { form: {} } } as const;
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_enrollment_admin_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "enrollment-administration-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function seedInvitedTarget(
  pool: Pool,
  organizationId: string,
  boardId: string
): Promise<string> {
  const memberId = testId(301);
  await pool.query(
    `insert into members(
       id,organization_id,member_kind,legal_name,display_name,state
     ) values ($1,$2,'human','Ada Director','Ada Director','invited')`,
    [memberId, organizationId]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
    [testId(302), organizationId, boardId, memberId]
  );
  return memberId;
}

function issueArguments(memberId: string, idempotencyKey = "issue-enrollment-000001") {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    member_id: memberId,
    handoff_method: "operator_display" as const,
    expires_in_seconds: 900,
    idempotency_key: idempotencyKey
  };
}

interface ConfirmedIssue {
  readonly invitationId: string;
  readonly replayed: boolean;
  readonly auditEventId: string | null;
}

async function stageIssue(
  pool: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  memberId: string,
  sequence: number,
  idempotencyKey = "issue-enrollment-000001"
): Promise<{
  readonly prepared: PreparedEnrollmentIssuance;
  readonly stageId: string;
  readonly requestState: Buffer;
  readonly confirmationCode: string;
  readonly arguments: ReturnType<typeof issueArguments>;
}> {
  const args = issueArguments(memberId, idempotencyKey);
  const prepared = await withRequestTransaction(
    pool,
    actor.context,
    (client) => prepareEnrollmentIssuanceInTransaction(client, args),
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
  const requestState = Buffer.alloc(48, sequence % 256);
  const confirmationCode = `I${sequence.toString(10).padStart(7, "0")}`;
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
          actionCode: "issue_enrollment",
          targetType: "member",
          targetId: memberId,
          canonicalSchema: "boardagent.enrollment-issuance.v1",
          canonicalPayload: prepared.canonicalPayload,
          packageSha256: null,
          nonce: Buffer.alloc(32, (sequence + 2) % 256),
          confirmationCode,
          accessTokenRecordId: actor.accessTokenRecordId,
          exactOrigin: "https://boardagent.test",
          originalName: "issue_enrollment",
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
          const current = await prepareEnrollmentIssuanceInTransaction(requestClient, args);
          expect(current.payloadSha256).toBe(prepared.payloadSha256);
        }
      ),
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
  return {
    prepared,
    stageId: staged.stageId,
    requestState,
    confirmationCode,
    arguments: args
  };
}

async function confirmIssue(
  pool: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  staged: Awaited<ReturnType<typeof stageIssue>>,
  sequence: number,
  invitationToken: string
): Promise<ConfirmedIssue> {
  return withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      confirmStagedActionInTransaction(
        client,
        {
          stageId: staged.stageId,
          consentRecordId: testId(sequence),
          retryRequestId: Buffer.from(`retry-${String(sequence)}`),
          originalArguments: staged.arguments,
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
          const current = await prepareEnrollmentIssuanceInTransaction(
            requestClient,
            staged.arguments
          );
          return { payloadSha256: current.payloadSha256, packageSha256: null };
        },
        async (requestClient: PoolClient, consentRecordId) => {
          const issued = await issueEnrollmentInTransaction(requestClient, {
            originalArguments: staged.arguments,
            expectedPayloadSha256: staged.prepared.payloadSha256,
            invitationId: testId(sequence + 3),
            invitationTokenSha256: sha256(invitationToken),
            idempotencyRecordId: testId(sequence + 4),
            consentRecordId,
            auditEventId: testId(sequence + 5)
          });
          return {
            value: {
              invitationId: issued.invitationId,
              replayed: issued.replayed,
              auditEventId: issued.auditEvent?.event.eventId ?? null
            },
            auditEvents: issued.auditEvent === null ? [] : [issued.auditEvent]
          };
        }
      ),
    { assumeRole: "boardagent_server", isolation: "serializable" }
  ).then((resolution) => {
    if (!resolution.confirmed) throw new Error(`issue confirmation failed: ${resolution.reason}`);
    return resolution.value;
  });
}

describe("secretary enrollment issuance", () => {
  it("requires a current secretary/admin actor with scope over every target seat", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"]
      });
      const targetMemberId = await seedInvitedTarget(pool, actor.organizationId, actor.boardId);
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            prepareEnrollmentIssuanceInTransaction(client, issueArguments(targetMemberId)),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "enrollment_issuance_unavailable" });

      await pool.query(
        `update board_memberships set is_secretary=true
          where organization_id=$1 and board_id=$2 and member_id=$3`,
        [actor.organizationId, actor.boardId, actor.memberId]
      );
      const secondBoardId = testId(330);
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'second','Second Board','UTC')",
        [secondBoardId, actor.organizationId]
      );
      await pool.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
         ) values ($1,$2,$3,$4,'observer',false,0,'active')`,
        [testId(331), actor.organizationId, secondBoardId, targetMemberId]
      );
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            prepareEnrollmentIssuanceInTransaction(client, issueArguments(targetMemberId)),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "enrollment_issuance_unavailable" });

      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'secretariat','organization enrollment administration')`,
        [testId(332), actor.organizationId, actor.memberId]
      );
      const prepared = await withRequestTransaction(
        pool,
        actor.context,
        (client) => prepareEnrollmentIssuanceInTransaction(client, issueArguments(targetMemberId)),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(prepared.seats.map(({ boardId }) => boardId)).toEqual([actor.boardId, secondBoardId]);

      await pool.query(
        `insert into onboarding_terms_versions(
           id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
           material_change,effective_at,created_by
         ) values ($1,$2,'voting_member',2,'boardagent.onboarding-terms.v1','New terms',$3,
           true,transaction_timestamp(),$4)`,
        [testId(333), actor.organizationId, Buffer.alloc(32, 0x44), actor.memberId]
      );
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            prepareEnrollmentIssuanceInTransaction(client, issueArguments(targetMemberId)),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "enrollment_issuance_unavailable" });
    });
  });

  it("returns one redeemable secret while persistence, consent, audit and replay stay secret-free", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const targetMemberId = await seedInvitedTarget(pool, actor.organizationId, actor.boardId);
      const token = Buffer.alloc(32, 0x5a).toString("base64url");
      const staged = await stageIssue(pool, actor, targetMemberId, 400);

      expect(staged.prepared).toMatchObject({
        memberId: targetMemberId,
        memberDisplayName: "Ada Director",
        memberState: "invited",
        seats: [
          {
            boardId: actor.boardId,
            boardName: "Board",
            seatRole: "voting_member",
            votingWeight: "1"
          }
        ]
      });
      expect(JSON.stringify(staged.prepared.canonicalPayload)).not.toContain(token);

      const confirmed = await confirmIssue(pool, actor, staged, 420, token);
      expect(confirmed).toEqual({
        invitationId: testId(423),
        replayed: false,
        auditEventId: testId(425)
      });

      const invitation = await pool.query<{
        token_sha256: Buffer;
        lifetime_seconds: string;
        member_state: string;
      }>(
        `select invitation.token_sha256,
                extract(epoch from invitation.expires_at-invitation.issued_at)::text
                  as lifetime_seconds,
                member.state as member_state
           from enrollment_invitations as invitation
           join members as member on member.id=invitation.member_id
          where invitation.id=$1`,
        [confirmed.invitationId]
      );
      expect(invitation.rows[0]?.token_sha256.toString("hex")).toBe(sha256(token));
      expect(Number(invitation.rows[0]?.lifetime_seconds)).toBe(900);
      expect(invitation.rows[0]?.member_state).toBe("invited");

      const evidence = await pool.query<{ material: string }>(
        `select concat_ws(E'\\n',
           (select convert_from(canonical_payload,'UTF8') from action_stages where id=$1),
           (select string_agg(convert_from(canonical_payload,'UTF8'),E'\\n' order by sequence)
              from audit_events),
           (select string_agg(coalesce(safe_response_type,'') || ':' ||
                                     coalesce(safe_response_id::text,''),E'\\n')
              from idempotency_records)
         ) as material`,
        [staged.stageId]
      );
      expect(evidence.rows[0]?.material).not.toContain(token);
      expect(evidence.rows[0]?.material).not.toContain(sha256(token));

      const issuedAudit = await pool.query<{
        consent_record_id: string | null;
        details: unknown;
      }>(
        `select consent_record_id,
                convert_from(canonical_payload,'UTF8')::jsonb->'details' as details
           from audit_events where id=$1`,
        [confirmed.auditEventId]
      );
      expect(issuedAudit.rows[0]).toMatchObject({
        consent_record_id: testId(420),
        details: {
          memberId: targetMemberId,
          handoffMethod: "operator_display",
          expiresInSeconds: 900,
          oneTimeSecret: true
        }
      });
    });
  });

  it("never mints or returns a second secret for a completed idempotency key", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const targetMemberId = await seedInvitedTarget(pool, actor.organizationId, actor.boardId);
      const firstToken = Buffer.alloc(32, 0x31).toString("base64url");
      const firstStage = await stageIssue(pool, actor, targetMemberId, 500);
      const first = await confirmIssue(pool, actor, firstStage, 520, firstToken);
      expect(first.replayed).toBe(false);

      await pool.query(
        "update enrollment_invitations set expires_at=transaction_timestamp()-interval '1 second' where id=$1",
        [first.invitationId]
      );

      const replayToken = Buffer.alloc(32, 0x32).toString("base64url");
      const replayStage = await stageIssue(pool, actor, targetMemberId, 540);
      const replay = await confirmIssue(pool, actor, replayStage, 560, replayToken);
      expect(replay).toEqual({
        invitationId: first.invitationId,
        replayed: true,
        auditEventId: null
      });

      const rows = await pool.query<{
        invitations: string;
        issued_events: string;
        replay_token_rows: string;
      }>(
        `select
           (select count(*)::text from enrollment_invitations) as invitations,
           (select count(*)::text from audit_events where event_type='enrollment_issued')
             as issued_events,
           (select count(*)::text from enrollment_invitations where token_sha256=$1)
             as replay_token_rows`,
        [Buffer.from(sha256(replayToken), "hex")]
      );
      expect(rows.rows[0]).toEqual({
        invitations: "1",
        issued_events: "1",
        replay_token_rows: "0"
      });

      const idempotency = await pool.query<{
        state: string;
        safe_response_id: string;
        safe_response_sha256: Buffer;
      }>(
        `select state,safe_response_id,safe_response_sha256
           from idempotency_records
          where operation='issue_enrollment'`,
        []
      );
      expect(idempotency.rows[0]).toMatchObject({
        state: "succeeded",
        safe_response_id: first.invitationId
      });
      expect(idempotency.rows[0]?.safe_response_sha256.toString("hex")).toBe(
        canonicalSha256({
          schemaVersion: "boardagent.enrollment-safe-response.v1",
          invitationId: first.invitationId,
          memberId: targetMemberId
        })
      );
    });
  });

  it("serializes two secretaries so only one live invitation and issuance event commit", async () => {
    await withDatabase(async (pool) => {
      const firstActor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const secondActor = await seedAdditionalAuthorizedActor(pool, firstActor, {
        idBase: 700,
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const targetMemberId = await seedInvitedTarget(
        pool,
        firstActor.organizationId,
        firstActor.boardId
      );
      const firstStage = await stageIssue(pool, firstActor, targetMemberId, 800);
      const secondStage = await stageIssue(pool, secondActor, targetMemberId, 900);
      const outcomes = await Promise.allSettled([
        confirmIssue(
          pool,
          firstActor,
          firstStage,
          820,
          Buffer.alloc(32, 0x71).toString("base64url")
        ),
        confirmIssue(
          pool,
          secondActor,
          secondStage,
          920,
          Buffer.alloc(32, 0x72).toString("base64url")
        )
      ]);
      expect(outcomes.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter(({ status }) => status === "rejected")).toHaveLength(1);

      const committed = await pool.query<{
        invitations: string;
        issued_events: string;
        consents: string;
      }>(
        `select
           (select count(*)::text from enrollment_invitations where member_id=$1)
             as invitations,
           (select count(*)::text from audit_events where event_type='enrollment_issued')
             as issued_events,
           (select count(*)::text from consent_records where action_code='issue_enrollment')
             as consents`,
        [targetMemberId]
      );
      expect(committed.rows[0]).toEqual({
        invitations: "1",
        issued_events: "1",
        consents: "1"
      });
    });
  });
});
