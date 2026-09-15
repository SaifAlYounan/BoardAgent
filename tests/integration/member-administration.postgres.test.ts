import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import {
  TOOL_INPUT_SCHEMA_VERSION,
  canonicalJson,
  canonicalSha256
} from "../../lib/contracts/src/index.js";
import {
  MemberAdministrationError,
  confirmStagedActionInTransaction,
  finalizeMemberInviteInTransaction,
  migrate,
  planMemberInviteInTransaction,
  prepareMemberInviteInTransaction,
  stageActionInTransaction,
  withRequestTransaction,
  type PreparedMemberInvite
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

async function bindLiveSession(
  pool: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  index: number
) {
  const sessionId = testId(78_000 + index);
  await pool.query(
    "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())",
    [sessionId, actor.organizationId, Buffer.alloc(32, index), actor.memberId, actor.clientId]
  );
  await pool.query("update access_token_records set session_id=$1 where id=$2", [
    sessionId,
    actor.accessTokenRecordId
  ]);
}

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_member_admin_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "member-administration-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function inviteArguments(boardId: string, memberId: string) {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    change: {
      operation: "invite" as const,
      member_id: memberId,
      board_id: boardId,
      member_kind: "human" as const,
      seat_role: "voting_member" as const,
      legal_name: "Mina Al Noor",
      display_name: "Mina Al Noor",
      voting_weight: 1,
      accountable_principal_id: null
    },
    idempotency_key: "manage-member-invite-000001"
  };
}

async function stageInvite(
  pool: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  args: ReturnType<typeof inviteArguments>,
  sequence: number
): Promise<{
  readonly prepared: PreparedMemberInvite;
  readonly stageId: string;
  readonly requestState: Buffer;
  readonly confirmationCode: string;
}> {
  const prepared = await withRequestTransaction(
    pool,
    actor.context,
    (client) => prepareMemberInviteInTransaction(client, args),
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
  const requestState = Buffer.alloc(48, sequence % 256);
  const staged = await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      stageActionInTransaction(
        client,
        {
          stageId: testId(sequence),
          inputRequiredAttemptId: testId(sequence + 1),
          boardId: args.change.board_id,
          actingForMemberId: null,
          actionCode: "manage_member",
          targetType: "member",
          targetId: args.change.member_id,
          canonicalSchema: "boardagent.member-invite.v1",
          canonicalPayload: prepared.canonicalPayload,
          packageSha256: null,
          nonce: Buffer.alloc(32, (sequence + 2) % 256),
          confirmationCode: `M${sequence.toString(10).padStart(7, "0")}`,
          accessTokenRecordId: actor.accessTokenRecordId,
          exactOrigin: "https://boardagent.test",
          originalName: "manage_member",
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
          const current = await prepareMemberInviteInTransaction(requestClient, args);
          expect(current.payloadSha256).toBe(prepared.payloadSha256);
        }
      ),
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
  return {
    prepared,
    stageId: staged.stageId,
    requestState,
    confirmationCode: `M${sequence.toString(10).padStart(7, "0")}`
  };
}

async function confirmInvite(
  pool: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  args: ReturnType<typeof inviteArguments>,
  staged: Awaited<ReturnType<typeof stageInvite>>,
  sequence: number,
  forgedDigest?: "authority" | "response"
) {
  const unavailablePayloadSha256 = canonicalSha256({
    schemaVersion: "boardagent.member-invite-unavailable.v1",
    stageId: staged.stageId
  });
  return withRequestTransaction(
    pool,
    actor.context,
    (client) => {
      let current: PreparedMemberInvite | undefined;
      return confirmStagedActionInTransaction(
        client,
        {
          stageId: staged.stageId,
          consentRecordId: testId(sequence),
          retryRequestId: Buffer.from(`retry-member-${String(sequence)}`),
          originalArguments: args,
          clientCapabilities: CAPABILITIES,
          exactOrigin: "https://boardagent.test",
          requestStateBytes: staged.requestState,
          responseAction: "accept",
          inputResponse: {
            approve: true,
            confirmation_code: staged.confirmationCode
          },
          auditEventIds: {
            consentRecorded: testId(sequence + 1),
            consentRejected: testId(sequence + 2)
          }
        },
        async (requestClient) => {
          try {
            current = await prepareMemberInviteInTransaction(requestClient, args);
            return { payloadSha256: current.payloadSha256, packageSha256: null };
          } catch (error) {
            if (
              error instanceof MemberAdministrationError &&
              error.code === "member_invite_unavailable"
            ) {
              return { payloadSha256: unavailablePayloadSha256, packageSha256: null };
            }
            throw error;
          }
        },
        async (requestClient, consentRecordId) => {
          if (!current) throw new Error("member invite binding was not prepared");
          const preparedPlan = await planMemberInviteInTransaction(requestClient, {
            originalArguments: args,
            expectedPayloadSha256: current.payloadSha256,
            consentRecordId,
            idempotencyRecordId: testId(sequence + 3),
            membershipId: testId(sequence + 4),
            membershipVersionId: testId(sequence + 5),
            auditEventId: testId(sequence + 6)
          });
          // Exercise the runtime-role SQL boundary with a malicious caller, even
          // though the ordinary TypeScript planner computes the correct digest.
          const wrongDigest = "ab".repeat(32);
          const plan =
            forgedDigest === "authority"
              ? {
                  ...preparedPlan,
                  authoritySnapshotSha256: wrongDigest,
                  auditEvent: {
                    ...preparedPlan.auditEvent,
                    event: {
                      ...preparedPlan.auditEvent.event,
                      details: {
                        ...preparedPlan.auditEvent.event.details,
                        authoritySnapshotSha256: wrongDigest
                      }
                    }
                  }
                }
              : forgedDigest === "response"
                ? {
                    ...preparedPlan,
                    safeResponseSha256: wrongDigest
                  }
                : preparedPlan;
          return {
            value: plan.memberId,
            auditEvents: [plan.auditEvent],
            finalizeAfterAudit: async (finalClient: PoolClient) => {
              if (forgedDigest) {
                await finalClient.query(
                  `select * from boardagent_finalize_member_invite(
                  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
                )`,
                  [
                    plan.boardId,
                    plan.memberId,
                    plan.memberKind,
                    plan.memberLegalName,
                    plan.memberDisplayName,
                    plan.seatRole,
                    Number(plan.votingWeight),
                    plan.accountablePrincipalId,
                    args.idempotency_key,
                    Buffer.from(plan.requestSha256, "hex"),
                    Buffer.from(plan.payloadSha256, "hex"),
                    plan.consentRecordId,
                    plan.idempotencyRecordId,
                    plan.membershipId,
                    plan.membershipVersionId,
                    plan.auditEvent.event.eventId,
                    plan.authoritySnapshot,
                    Buffer.from(plan.authoritySnapshotSha256, "hex"),
                    Buffer.from(plan.safeResponseSha256, "hex"),
                    Buffer.from(canonicalJson(plan.authoritySnapshot), "utf8"),
                    Buffer.from(
                      canonicalJson({
                        schemaVersion: "boardagent.member-safe-response.v1",
                        memberId: plan.memberId,
                        membershipId: plan.membershipId,
                        boardId: plan.boardId
                      }),
                      "utf8"
                    )
                  ]
                );
                return;
              }
              await finalizeMemberInviteInTransaction(finalClient, plan);
            }
          };
        }
      );
    },
    { assumeRole: "boardagent_server", isolation: "serializable" }
  );
}

describe("confirmed member invitation administration", () => {
  it.each(["authority", "response"] as const)(
    "rejects a forged %s digest at the runtime-role finalizer and rolls back all writes",
    async (forgedDigest) => {
      await withDatabase(async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["governance:read", "secretariat:admin"],
          isSecretary: true
        });
        await bindLiveSession(pool, actor, 1);
        await pool.query(
          "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','digest-integrity test')",
          [testId(76001), actor.organizationId, actor.memberId]
        );
        const args = inviteArguments(actor.boardId, testId(76002));
        const staged = await stageInvite(pool, actor, args, 76100);
        await expect(
          confirmInvite(pool, actor, args, staged, 76200, forgedDigest)
        ).rejects.toThrow();
        const persisted = await pool.query(
          `select
        (select count(*)::int from members where id=$1) as members,
        (select count(*)::int from membership_versions where member_id=$1) as versions,
        (select count(*)::int from audit_events where object_id=$1) as events,
        (select count(*)::int from consent_records where target_id=$1) as consents,
        (select count(*)::int from idempotency_records where operation='manage_member') as idempotency`,
          [args.change.member_id]
        );
        expect(persisted.rows[0]).toEqual({
          members: 0,
          versions: 0,
          events: 0,
          consents: 0,
          idempotency: 0
        });
        // The legitimate confirmation still works after the malicious transaction
        // was rejected; no consent or idempotency record was partially consumed.
        expect((await confirmInvite(pool, actor, args, staged, 76300)).confirmed).toBe(true);
      });
    }
  );

  it("requires organization admin and atomically links member, seat, consent and audit evidence", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const invitedMemberId = testId(1401);
      await bindLiveSession(pool, actor, 1);
      const args = inviteArguments(actor.boardId, invitedMemberId);

      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) => prepareMemberInviteInTransaction(client, args),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "member_invite_unavailable" });
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','member administration test')`,
        [testId(1402), actor.organizationId, actor.memberId]
      );

      const staged = await stageInvite(pool, actor, args, 1420);
      expect(staged.prepared).toMatchObject({
        memberId: invitedMemberId,
        memberKind: "human",
        persistedMemberKind: "human",
        memberDisplayName: "Mina Al Noor",
        boardId: actor.boardId,
        boardName: "Board",
        seatRole: "voting_member",
        votingWeight: "1"
      });

      let finalized = false;
      const resolution = await withRequestTransaction(
        pool,
        actor.context,
        (client) => {
          let current: PreparedMemberInvite | undefined;
          return confirmStagedActionInTransaction(
            client,
            {
              stageId: staged.stageId,
              consentRecordId: testId(1440),
              retryRequestId: Buffer.from("retry-member-invite"),
              originalArguments: args,
              clientCapabilities: CAPABILITIES,
              exactOrigin: "https://boardagent.test",
              requestStateBytes: staged.requestState,
              responseAction: "accept",
              inputResponse: { approve: true, confirmation_code: "M0001420" },
              auditEventIds: {
                consentRecorded: testId(1441),
                consentRejected: testId(1442)
              }
            },
            async (requestClient) => {
              current = await prepareMemberInviteInTransaction(requestClient, args);
              return { payloadSha256: current.payloadSha256, packageSha256: null };
            },
            async (requestClient: PoolClient, consentRecordId) => {
              if (!current) throw new Error("member invite binding was not prepared");
              const plan = await planMemberInviteInTransaction(requestClient, {
                originalArguments: args,
                expectedPayloadSha256: current.payloadSha256,
                consentRecordId,
                idempotencyRecordId: testId(1443),
                membershipId: testId(1444),
                membershipVersionId: testId(1445),
                auditEventId: testId(1446)
              });
              return {
                value: {
                  memberId: plan.memberId,
                  membershipId: plan.membershipId,
                  auditEventId: plan.auditEvent.event.eventId
                },
                auditEvents: [plan.auditEvent],
                finalizeAfterAudit: async (finalClient: PoolClient) => {
                  const result = await finalizeMemberInviteInTransaction(finalClient, plan);
                  expect(result.replayed).toBe(false);
                  finalized = true;
                }
              };
            }
          );
        },
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(resolution).toMatchObject({
        confirmed: true,
        value: {
          memberId: invitedMemberId,
          membershipId: testId(1444),
          auditEventId: testId(1446)
        }
      });
      expect(finalized).toBe(true);

      const projection = await pool.query<{
        audit_event_id: string | null;
        consent_record_id: string | null;
        member_kind: string;
        member_state: string;
        membership_state: string;
        seat_role: string;
        voting_weight: string;
      }>(
        `select member.member_kind,member.state as member_state,
                membership.state as membership_state,membership.seat_role,
                membership.voting_weight::text,version.consent_record_id,
                version.audit_event_id
           from members as member
           join board_memberships as membership on membership.member_id=member.id
           join membership_versions as version on version.membership_id=membership.id
          where member.id=$1`,
        [invitedMemberId]
      );
      expect(projection.rows[0]).toEqual({
        audit_event_id: testId(1446),
        consent_record_id: testId(1440),
        member_kind: "human",
        member_state: "invited",
        membership_state: "active",
        seat_role: "voting_member",
        voting_weight: "1"
      });
      const audit = await pool.query<{
        consent_record_id: string | null;
        object_version: string | null;
        details: unknown;
      }>(
        `select consent_record_id,object_version::text,
                convert_from(canonical_payload,'UTF8')::jsonb->'details' as details
           from audit_events where id=$1`,
        [testId(1446)]
      );
      expect(audit.rows[0]).toMatchObject({
        consent_record_id: testId(1440),
        object_version: "1",
        details: {
          operation: "invite",
          memberId: invitedMemberId,
          boardId: actor.boardId,
          seatRole: "voting_member"
        }
      });
    });
  });

  it("rejects invalid AI-observer/accountable-principal and seat-weight combinations", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"]
      });
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','member administration test')`,
        [testId(1501), actor.organizationId, actor.memberId]
      );
      const base = inviteArguments(actor.boardId, testId(1502));
      await bindLiveSession(pool, actor, 1);
      const invalidAi = {
        ...base,
        change: {
          ...base.change,
          member_kind: "ai_observer" as const,
          seat_role: "observer" as const,
          voting_weight: 0
        }
      };
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) => prepareMemberInviteInTransaction(client, invalidAi),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "member_invite_unavailable" });

      const invalidWeight = {
        ...base,
        change: { ...base.change, voting_weight: 0 }
      };
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) => prepareMemberInviteInTransaction(client, invalidWeight),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "member_invite_unavailable" });

      const principalId = testId(1503);
      await pool.query(
        `insert into accountable_principals(id,organization_id,legal_name,reference)
         values ($1,$2,'Accountable Operator','demo-operator')`,
        [principalId, actor.organizationId]
      );
      const validAi = {
        ...invalidAi,
        change: { ...invalidAi.change, accountable_principal_id: principalId }
      };
      const prepared = await withRequestTransaction(
        pool,
        actor.context,
        (client) => prepareMemberInviteInTransaction(client, validAi),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(prepared).toMatchObject({
        memberKind: "ai_observer",
        persistedMemberKind: "ai_system",
        accountablePrincipalId: principalId,
        accountablePrincipalName: "Accountable Operator",
        seatRole: "observer",
        votingWeight: "0"
      });
    });
  });

  it("admits only one of two concurrent secretaries inviting the same member", async () => {
    await withDatabase(async (pool) => {
      const first = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const second = await seedAdditionalAuthorizedActor(pool, first, {
        idBase: 2000,
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values
           ($1,$3,$4,'admin','concurrent member administration test'),
           ($2,$3,$5,'admin','concurrent member administration test')`,
        [testId(2101), testId(2102), first.organizationId, first.memberId, second.memberId]
      );
      const targetMemberId = testId(2103);
      await bindLiveSession(pool, first, 1);
      await bindLiveSession(pool, second, 2);
      const firstArgs = inviteArguments(first.boardId, targetMemberId);
      const secondArgs = {
        ...inviteArguments(second.boardId, targetMemberId),
        idempotency_key: "manage-member-invite-000002"
      };
      const firstStage = await stageInvite(pool, first, firstArgs, 2220);
      const secondStage = await stageInvite(pool, second, secondArgs, 2260);

      const outcomes = await Promise.all([
        confirmInvite(pool, first, firstArgs, firstStage, 2300),
        confirmInvite(pool, second, secondArgs, secondStage, 2340)
      ]);
      expect(outcomes.map((outcome) => outcome.confirmed).toSorted()).toEqual([false, true]);

      const persisted = await pool.query<{
        members: string;
        memberships: string;
        versions: string;
        changes: string;
        consents: string;
      }>(
        `select
           (select count(*)::text from members where id=$1) as members,
           (select count(*)::text from board_memberships where member_id=$1) as memberships,
           (select count(*)::text from membership_versions where member_id=$1) as versions,
           (select count(*)::text from audit_events
             where event_type='member_changed' and object_id=$1) as changes,
           (select count(*)::text from consent_records
             where action_code='manage_member' and target_id=$1) as consents`,
        [targetMemberId]
      );
      expect(persisted.rows[0]).toEqual({
        members: "1",
        memberships: "1",
        versions: "1",
        changes: "1",
        consents: "1"
      });
    });
  });
});
