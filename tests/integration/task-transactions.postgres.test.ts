import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  confirmStagedActionInTransaction,
  confirmTaskLifecycleActionInTransaction,
  migrate,
  prepareTaskLifecycleActionInTransaction,
  stageTaskLifecycleActionInTransaction,
  startTaskInTransaction,
  submitTaskEvidenceInTransaction,
  withRequestTransaction,
  type TaskLifecycleAction,
  type TaskLifecycleResult
} from "../../lib/db/src/index.js";
import {
  canonicalSha256,
  sha256Hex,
  TOOL_INPUT_SCHEMA_VERSION,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import {
  PgBoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { confirmSyntheticSurfaceAction } from "../helpers/confirmed-surface-action.js";
import { assertTransition, taskTransitions } from "../../lib/domain/src/state-machines.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;
let confirmationSequence = 10_000;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_tasks_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "task-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function exactBytes(sequence: number): Buffer {
  const bytes = Buffer.alloc(48);
  bytes.writeUInt32BE(sequence, 0);
  return bytes;
}

function jsonValue(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

async function confirmTaskAction(
  pool: Pool,
  actor: AuthorizedActorFixture,
  action: TaskLifecycleAction
): Promise<TaskLifecycleResult> {
  confirmationSequence += 32;
  const sequence = confirmationSequence;
  const confirmationCode = `T${sequence.toString(36).toUpperCase().padStart(7, "0").slice(-7)}`;
  const originalArguments = jsonValue(action);
  const clientCapabilities = { elicitation: { form: {} } };
  const requestStateBytes = exactBytes(sequence);
  const staged = await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      stageTaskLifecycleActionInTransaction(client, {
        action,
        stage: {
          stageId: testId(sequence),
          inputRequiredAttemptId: testId(sequence + 1),
          nonce: exactBytes(sequence + 2),
          confirmationCode,
          accessTokenRecordId: actor.accessTokenRecordId,
          exactOrigin: "https://client.example",
          originalArguments,
          clientCapabilities,
          embeddedForm: { type: "object", required: ["approve", "confirmation_code"] },
          embeddedResult: { message: "Confirm exact task lifecycle action" },
          requestStateBytes,
          preparedRequestId: Buffer.from(`prepared-task-${String(sequence)}`),
          auditEventIds: {
            stageReplaced: testId(sequence + 3),
            stageCreated: testId(sequence + 4),
            elicitationSent: testId(sequence + 5)
          }
        }
      }),
    { assumeRole: "boardagent_server" }
  );
  const confirmed = await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      confirmTaskLifecycleActionInTransaction(client, {
        action,
        confirmation: {
          stageId: staged.stageId,
          consentRecordId: testId(sequence + 6),
          retryRequestId: Buffer.from(`retry-task-${String(sequence)}`),
          originalArguments,
          clientCapabilities,
          exactOrigin: "https://client.example",
          requestStateBytes,
          responseAction: "accept",
          inputResponse: { approve: true, confirmation_code: confirmationCode },
          auditEventIds: {
            consentRecorded: testId(sequence + 7),
            consentRejected: testId(sequence + 8)
          }
        }
      }),
    { assumeRole: "boardagent_server" }
  );
  if (!confirmed.confirmed) throw new Error(`task confirmation failed: ${confirmed.reason}`);
  return confirmed.value;
}

describe("task evidence and terminal correction transactions", () => {
  it.each(["draft", "evidence_submitted"] as const)(
    "keeps the declared task model aligned with confirmed cancellation from %s",
    async (initialState) => {
      await withDatabase(async (pool) => {
        const secretary = await seedAuthorizedActor(pool, {
          seatRole: "management",
          scopes: ["secretariat:admin"],
          isSecretary: true
        });
        const taskId = testId(8_500);
        const source =
          initialState === "draft"
            ? { meetingId: testId(8_501), minutesId: testId(8_502), versionId: testId(8_503) }
            : null;
        if (source) {
          const seed = await pool.connect();
          try {
            await seed.query("begin");
            await seed.query(
              `insert into meetings(id,organization_id,board_id,title,state,scheduled_start,
               scheduled_end,created_by) values ($1,$2,$3,'Synthetic action meeting','called',
               transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
              [source.meetingId, secretary.organizationId, secretary.boardId, secretary.memberId]
            );
            await seed.query(
              `insert into minutes(id,organization_id,board_id,meeting_id,created_by)
               values ($1,$2,$3,$4,$5)`,
              [
                source.minutesId,
                secretary.organizationId,
                secretary.boardId,
                source.meetingId,
                secretary.memberId
              ]
            );
            await seed.query(
              `insert into minutes_versions(id,organization_id,board_id,minutes_id,version,
               canonical_schema,canonical_text,canonical_sha256,package_base_sha256,created_by)
               values ($1,$2,$3,$4,1,'boardagent.minutes.v1','Synthetic action source.',$5,$5,$6)`,
              [
                source.versionId,
                secretary.organizationId,
                secretary.boardId,
                source.minutesId,
                Buffer.alloc(32, 9),
                secretary.memberId
              ]
            );
            await seed.query(
              "update minutes set current_version_id=$1,row_version=row_version+1 where id=$2",
              [source.versionId, source.minutesId]
            );
            await seed.query(
              "update meetings set current_minutes_id=$1,row_version=row_version+1 where id=$2",
              [source.minutesId, source.meetingId]
            );
            await seed.query("commit");
          } catch (error) {
            await seed.query("rollback");
            throw error;
          } finally {
            seed.release();
          }
        }
        await pool.query(
          `insert into tasks(
             id,organization_id,board_id,owner_member_id,due_at,description_schema,
             canonical_description,required_evidence,task_sha256,state,created_by,
             source_meeting_id,source_minutes_id,source_minutes_version_id,source_minutes_sha256,source_locator
           ) values ($1,$2,$3,$4,transaction_timestamp()+interval '1 day',
             'boardagent.task.v1','Deliver the synthetic report.',
             '{"text":"Canonical report."}',$5,$6,$4,$7,$8,$9,$10,$11)`,
          [
            taskId,
            secretary.organizationId,
            secretary.boardId,
            secretary.memberId,
            Buffer.alloc(32, 8),
            initialState,
            source?.meetingId ?? null,
            source?.minutesId ?? null,
            source?.versionId ?? null,
            source ? Buffer.alloc(32, 9) : null,
            source ? { section: "Actions" } : null
          ]
        );
        await expect(
          confirmTaskAction(pool, secretary, {
            kind: "cancellation",
            taskId,
            reason: "Synthetic board action is no longer required."
          })
        ).resolves.toMatchObject({ kind: "cancellation", taskId });
        const row = (await pool.query("select state from tasks where id=$1", [taskId])).rows[0];
        expect(row).toEqual({ state: "cancelled" });
        expect(() => assertTransition(taskTransitions, initialState, row.state)).not.toThrow();
        await expect(
          confirmTaskAction(pool, secretary, {
            kind: "cancellation",
            taskId,
            reason: "Repeated cancellation must not create another act."
          })
        ).rejects.toThrow("only a nonterminal task may be cancelled");
      });
    }
  );

  it("separates owner evidence from secretary review/closure and never reopens terminal work", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const owner = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 700,
        seatRole: "management",
        scopes: ["task:act"]
      });
      const taskId = testId(8_000);
      const taskSha256 = canonicalSha256({
        schemaVersion: "boardagent.task.v1",
        taskId,
        ownerMemberId: owner.memberId,
        dueAt: "2026-10-01T12:00:00Z",
        description: "Deliver the board report."
      });
      await pool.query(
        `insert into tasks(
           id,organization_id,board_id,owner_member_id,due_at,description_schema,
           canonical_description,required_evidence,task_sha256,state,created_by
         ) values ($1,$2,$3,$4,'2026-10-01T12:00:00Z','boardagent.task.v1',
                   'Deliver the board report.','{"text":"Canonical report."}',$5,'open',$6)`,
        [
          taskId,
          secretary.organizationId,
          secretary.boardId,
          owner.memberId,
          Buffer.from(taskSha256, "hex"),
          secretary.memberId
        ]
      );

      const firstStartInput = {
        taskId,
        idempotencyRecordId: testId(8_001),
        idempotencyKey: "task-start-idempotency-0001",
        auditEventId: testId(8_002)
      };
      const firstStart = await withRequestTransaction(
        pool,
        owner.context,
        (client) => startTaskInTransaction(client, firstStartInput),
        { assumeRole: "boardagent_server" }
      );
      const firstStartReplay = await withRequestTransaction(
        pool,
        owner.context,
        (client) => startTaskInTransaction(client, firstStartInput),
        { assumeRole: "boardagent_server" }
      );
      expect(firstStart.replayed).toBe(false);
      expect(firstStartReplay.replayed).toBe(true);

      const rejectedEvidenceInput = {
        evidenceId: testId(8_010),
        payload: {
          schemaVersion: "boardagent.task-evidence.v1",
          taskId,
          canonicalText: "Draft report evidence.",
          documentReferences: [],
          resourceReferences: []
        },
        idempotencyRecordId: testId(8_011),
        idempotencyKey: "task-evidence-idempotency-0001",
        auditEventId: testId(8_012)
      };
      const rejectedEvidence = await withRequestTransaction(
        pool,
        owner.context,
        (client) => submitTaskEvidenceInTransaction(client, rejectedEvidenceInput),
        { assumeRole: "boardagent_server" }
      );
      expect(rejectedEvidence.replayed).toBe(false);
      const rejected = await confirmTaskAction(pool, secretary, {
        kind: "evidence_review",
        taskId,
        evidenceId: rejectedEvidence.safeResponseId,
        decision: "rejected",
        reason: "The draft does not contain the canonical final report."
      });
      expect(rejected).toMatchObject({ kind: "evidence_review", decision: "rejected" });

      await withRequestTransaction(
        pool,
        owner.context,
        (client) =>
          startTaskInTransaction(client, {
            taskId,
            idempotencyRecordId: testId(8_020),
            idempotencyKey: "task-start-idempotency-0002",
            auditEventId: testId(8_021)
          }),
        { assumeRole: "boardagent_server" }
      );
      const acceptedEvidence = await withRequestTransaction(
        pool,
        owner.context,
        (client) =>
          submitTaskEvidenceInTransaction(client, {
            evidenceId: testId(8_030),
            payload: {
              schemaVersion: "boardagent.task-evidence.v1",
              taskId,
              canonicalText: "Final canonical report evidence.",
              documentReferences: [],
              resourceReferences: []
            },
            idempotencyRecordId: testId(8_031),
            idempotencyKey: "task-evidence-idempotency-0002",
            auditEventId: testId(8_032)
          }),
        { assumeRole: "boardagent_server" }
      );
      await confirmTaskAction(pool, secretary, {
        kind: "evidence_review",
        taskId,
        evidenceId: acceptedEvidence.safeResponseId,
        decision: "accepted",
        reason: "The submitted evidence is the exact final report."
      });
      const closure = await confirmTaskAction(pool, secretary, {
        kind: "closure",
        taskId,
        acceptedEvidenceIds: [acceptedEvidence.safeResponseId]
      });
      expect(closure.kind).toBe("closure");

      const correction = await confirmTaskAction(pool, secretary, {
        kind: "completed_correction",
        taskId,
        replacementTaskId: testId(4_301),
        reason: "A separately tracked corrected report is required.",
        replacement: {
          ownerMemberId: owner.memberId,
          dueAt: "2026-10-15T12:00:00Z",
          description: "Deliver the separately corrected board report.",
          requiredEvidence: ["Corrected canonical report."]
        }
      });
      expect(correction).toMatchObject({
        kind: "completed_correction",
        replacementTaskId: testId(4_301)
      });
      if (correction.kind !== "completed_correction") throw new Error("unexpected result");
      await confirmTaskAction(pool, secretary, {
        kind: "cancellation",
        taskId: correction.replacementTaskId,
        reason: "The replacement obligation was withdrawn by the board."
      });

      const final = await pool.query<{
        closure_count: string;
        correction_count: string;
        original_state: string;
        replacement_state: string;
      }>(
        `select
          (select state from tasks where id=$1) as original_state,
          (select state from tasks where id=$2) as replacement_state,
          (select count(*)::text from task_closures where task_id=$1) as closure_count,
          (select count(*)::text from task_correction_cycles where prior_task_id=$1) as correction_count`,
        [taskId, correction.replacementTaskId]
      );
      expect(final.rows[0]).toEqual({
        closure_count: "1",
        correction_count: "1",
        original_state: "completed",
        replacement_state: "cancelled"
      });
    });
  }, 60_000);

  it("refuses duplicate pending evidence, blocks closure over pending work and cancels nonterminal evidence", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const owner = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 900,
        seatRole: "management",
        scopes: ["task:act"]
      });
      const taskId = testId(8_200);
      const taskSha256 = canonicalSha256({
        schemaVersion: "boardagent.task.v1",
        taskId,
        ownerMemberId: owner.memberId,
        dueAt: "2026-10-01T12:00:00Z",
        description: "Deliver the evidence-controlled report."
      });
      await pool.query(
        `insert into tasks(
           id,organization_id,board_id,owner_member_id,due_at,description_schema,
           canonical_description,required_evidence,task_sha256,state,created_by
         ) values ($1,$2,$3,$4,'2026-10-01T12:00:00Z','boardagent.task.v1',
                   'Deliver the evidence-controlled report.','{"text":"Canonical report."}',
                   $5,'open',$6)`,
        [
          taskId,
          secretary.organizationId,
          secretary.boardId,
          owner.memberId,
          Buffer.from(taskSha256, "hex"),
          secretary.memberId
        ]
      );

      const firstEvidence = await withRequestTransaction(
        pool,
        owner.context,
        (client) =>
          submitTaskEvidenceInTransaction(client, {
            evidenceId: testId(8_210),
            payload: {
              schemaVersion: "boardagent.task-evidence.v1",
              taskId,
              canonicalText: "First exact report.",
              documentReferences: [],
              resourceReferences: []
            },
            idempotencyRecordId: testId(8_211),
            idempotencyKey: "task-evidence-pending-0001",
            auditEventId: testId(8_212)
          }),
        { assumeRole: "boardagent_server" }
      );
      const secondEvidenceInput = {
        evidenceId: testId(8_220),
        payload: {
          schemaVersion: "boardagent.task-evidence.v1" as const,
          taskId,
          canonicalText: "Second exact report.",
          documentReferences: [],
          resourceReferences: []
        },
        idempotencyRecordId: testId(8_221),
        idempotencyKey: "task-evidence-pending-0002",
        auditEventId: testId(8_222)
      };
      await expect(
        withRequestTransaction(
          pool,
          owner.context,
          (client) => submitTaskEvidenceInTransaction(client, secondEvidenceInput),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "23505" });

      await confirmTaskAction(pool, secretary, {
        kind: "evidence_review",
        taskId,
        evidenceId: firstEvidence.safeResponseId,
        decision: "accepted",
        reason: "The first report is accepted evidence."
      });
      const pendingEvidence = await withRequestTransaction(
        pool,
        owner.context,
        (client) => submitTaskEvidenceInTransaction(client, secondEvidenceInput),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        confirmTaskAction(pool, secretary, {
          kind: "closure",
          taskId,
          acceptedEvidenceIds: [firstEvidence.safeResponseId]
        })
      ).rejects.toMatchObject({ code: "task_closure_unavailable" });
      await expect(
        withRequestTransaction(
          pool,
          owner.context,
          (client) =>
            client.query(
              `update tasks
                  set state='completed',completed_at=transaction_timestamp(),
                      row_version=row_version+1
                where id=$1`,
              [taskId]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/terminal task transition requires the guarded task authority/u);
      const cancelled = await confirmTaskAction(pool, secretary, {
        kind: "cancellation",
        taskId,
        reason: "The board withdrew the nonterminal obligation."
      });
      expect(cancelled).toMatchObject({ kind: "cancellation", taskId });

      const final = await pool.query<{
        closure_count: string;
        pending_count: string;
        state: string;
      }>(
        `select task.state,
                (select count(*)::text from task_closures where task_id=task.id) as closure_count,
                (select count(*)::text from task_evidence
                  where task_id=task.id and state='submitted') as pending_count
           from tasks as task where task.id=$1`,
        [taskId]
      );
      expect(pendingEvidence.safeResponseId).toBe(secondEvidenceInput.evidenceId);
      expect(final.rows[0]).toEqual({
        closure_count: "0",
        pending_count: "1",
        state: "cancelled"
      });
    });
  }, 60_000);
});

async function taskBoundarySurface(pool: Pool) {
  const secretary = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["minutes:act", "secretariat:admin"],
    isSecretary: true
  });
  const owner = await seedAdditionalAuthorizedActor(pool, secretary, {
    idBase: 792_000,
    seatRole: "management",
    scopes: ["task:act"]
  });
  const principal = (actor: AuthorizedActorFixture, secretariat: boolean): SurfacePrincipal => ({
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://task-boundary.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: secretariat ? ["minutes:act", "secretariat:admin"] : ["task:act"],
    roles: [secretariat ? "secretariat" : "member"],
    boardIds: [actor.boardId]
  });
  let nextId = 793_000;
  const service = new PgBoardAgentSurfaceService(pool, {
    reads: {
      executeRead: async () => {
        throw new Error("task boundary does not use read tools");
      },
      readResource: async () => {
        throw new Error("task boundary does not use resources");
      }
    },
    transaction: { assumeRole: "boardagent_server" },
    newId: () => testId(nextId++)
  });
  const secretaryPrincipal = principal(secretary, true);
  const ownerPrincipal = principal(owner, false);
  const taskId = testId(794_000);
  const createInput = (source: { minutesId: string; versionId: string } | null) => ({
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    task_id: taskId,
    board_id: secretary.boardId,
    owner_member_id: owner.memberId,
    due_at: "2026-10-22T12:00:00Z",
    description: "Prepare the synthetic exploration programme report.",
    required_evidence: ["Canonical report hash."],
    source_minutes_id: source?.minutesId ?? null,
    source_minutes_version_id: source?.versionId ?? null,
    idempotency_key: "task-boundary-public-create-0001"
  });
  const confirm = (tool: string, input: JsonValue) =>
    confirmSyntheticSurfaceAction(service, secretaryPrincipal, tool, input);
  const taskObservation = async () =>
    (
      await pool.query<{
        state: string;
        row_version: string;
        notices: number;
        pending: number;
        source_minutes_id: string | null;
        source_minutes_version_id: string | null;
      }>(
        `select task.state,task.row_version::text,task.source_minutes_id,task.source_minutes_version_id,
              (select count(*)::int from notices
                where object_id=task.id and notice_type='task_assigned') as notices,
              (select count(*)::int from pending_action_feed
                where object_id=task.id and member_id=$2 and action_type='task_assigned'
                  and state='pending') as pending
         from tasks task where task.id=$1`,
        [taskId, owner.memberId]
      )
    ).rows;
  return {
    secretary,
    owner,
    service,
    secretaryPrincipal,
    ownerPrincipal,
    taskId,
    createInput,
    confirm,
    taskObservation
  };
}

describe("task terminal SQL boundary with real cancellation consent", () => {
  it.each(["null_version", "stale", "exact", "null_state"] as const)(
    "keeps committed task effects bound to the %s input",
    async (boundary) => {
      await withDatabase(async (pool) => {
        const fixture = await taskBoundarySurface(pool);
        await fixture.confirm("create_task", fixture.createInput(null));
        const { secretary, taskId } = fixture;
        const action = {
          kind: "cancellation",
          taskId,
          reason: "Synthetic SQL boundary probe."
        } as const;
        const originalArguments = jsonValue(action);
        const clientCapabilities = { elicitation: { form: {} } };
        const requestStateBytes = exactBytes(794_010);
        const confirmationCode = "TASK7940";
        const staged = await withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            stageTaskLifecycleActionInTransaction(client, {
              action,
              stage: {
                stageId: testId(794_010),
                inputRequiredAttemptId: testId(794_011),
                nonce: exactBytes(794_012),
                confirmationCode,
                accessTokenRecordId: secretary.accessTokenRecordId,
                exactOrigin: "https://client.example",
                originalArguments,
                clientCapabilities,
                embeddedForm: { type: "object", required: ["approve", "confirmation_code"] },
                embeddedResult: { message: "Confirm the synthetic task cancellation" },
                requestStateBytes,
                preparedRequestId: Buffer.from("task-boundary-prepare"),
                auditEventIds: {
                  stageReplaced: testId(794_013),
                  stageCreated: testId(794_014),
                  elicitationSent: testId(794_015)
                }
              }
            }),
          { assumeRole: "boardagent_server" }
        );
        const snapshot = async () => ({
          task: (await pool.query("select row_to_json(r)::text as row from tasks r order by id"))
            .rows,
          evidence: (
            await pool.query("select row_to_json(r)::text as row from task_evidence r order by id")
          ).rows,
          closures: (
            await pool.query("select row_to_json(r)::text as row from task_closures r order by id")
          ).rows,
          notices: (
            await pool.query("select row_to_json(r)::text as row from notices r order by id")
          ).rows,
          feeds: (
            await pool.query(
              "select row_to_json(r)::text as row from pending_action_feed r order by id"
            )
          ).rows
        });
        const before = await snapshot();
        const current = (await fixture.taskObservation())[0]!.row_version;
        const expectedVersion =
          boundary === "null_version"
            ? null
            : boundary === "stale"
              ? (BigInt(current) - 1n).toString()
              : current;
        let called = false;
        // Only the act callback probes SQL: staging, live revalidation and consent
        // are real. Return the observation and assert after commit, so application
        // result checks cannot roll back and conceal a database boundary failure.
        // This does not represent a complete application cancellation/audit run.
        const confirmation = withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            confirmStagedActionInTransaction(
              client,
              {
                stageId: staged.stageId,
                consentRecordId: testId(794_016),
                retryRequestId: Buffer.from("task-boundary-retry"),
                originalArguments,
                clientCapabilities,
                exactOrigin: "https://client.example",
                requestStateBytes,
                responseAction: "accept",
                inputResponse: { approve: true, confirmation_code: confirmationCode },
                auditEventIds: {
                  consentRecorded: testId(794_017),
                  consentRejected: testId(794_018)
                }
              },
              async (requestClient) => {
                const prepared = await prepareTaskLifecycleActionInTransaction(
                  requestClient,
                  action
                );
                return {
                  payloadSha256: prepared.payloadSha256,
                  packageSha256: prepared.packageSha256
                };
              },
              async (requestClient, consentRecordId) => {
                called = true;
                expect(
                  (
                    await requestClient.query(`select current_user as role,
              row_security_active('public.tasks'::regclass) as tasks_rls`)
                  ).rows[0]
                ).toEqual({ role: "boardagent_server", tasks_rls: true });
                const result = await requestClient.query<{ next_row_version: string | null }>(
                  `select boardagent_apply_task_terminal_transition($1,$2::bigint,$3,$4)::text as next_row_version`,
                  [
                    taskId,
                    expectedVersion,
                    boundary === "null_state" ? null : "cancelled",
                    consentRecordId
                  ]
                );
                return { value: result.rows, auditEvents: [] };
              }
            ),
          { assumeRole: "boardagent_server" }
        );
        if (boundary === "null_state") {
          const outcome = await confirmation.then(
            () => ({ accepted: true, code: null }),
            (error: unknown) => ({
              accepted: false,
              code:
                typeof error === "object" && error !== null && "code" in error ? error.code : null
            })
          );
          expect(called).toBe(true);
          expect({ outcome, rows: await snapshot() }).toEqual({
            outcome: { accepted: false, code: "25000" },
            rows: before
          });
          return;
        }
        const observed = await confirmation;
        expect(called).toBe(true);
        if (!observed.confirmed) throw new Error(`task SQL consent failed: ${observed.reason}`);
        const after = await snapshot();
        if (boundary !== "exact") {
          expect({ result: observed.value, rows: after }).toEqual({
            result: [{ next_row_version: null }],
            rows: before
          });
        } else {
          expect(observed.value).toEqual([{ next_row_version: (BigInt(current) + 1n).toString() }]);
          expect(await fixture.taskObservation()).toMatchObject([
            { state: "cancelled", row_version: (BigInt(current) + 1n).toString() }
          ]);
          expect({ ...after, task: before.task }).toEqual(before);
        }
      });
    },
    60_000
  );
});

describe("public task source activation boundary", () => {
  it.each(["standalone", "unfinalized", "declared_finalized"] as const)(
    "keeps owner action consistent with the %s source",
    async (sourceCase) => {
      await withDatabase(async (pool) => {
        const f = await taskBoundarySurface(pool);
        const minutesId = testId(795_000);
        const meetingId = testId(795_001);
        let versionId: string | null = null;
        const text = "# Synthetic minutes\nPrepare the exploration programme report.\n";
        if (sourceCase !== "standalone") {
          // The called meeting is the existing component seed. All minutes/task
          // creation, declaration, signature and finalization use the public service.
          await pool.query(
            `insert into meetings(id,organization_id,board_id,title,state,
            scheduled_start,scheduled_end,created_by) values($1,$2,$3,'Task source meeting','called',
            transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
            [meetingId, f.secretary.organizationId, f.secretary.boardId, f.secretary.memberId]
          );
          const draft = await f.service.executeDirect(
            f.secretaryPrincipal,
            "create_minutes_version",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              minutes_id: minutesId,
              meeting_id: meetingId,
              canonical_text: text,
              transcript_version_id: null,
              expected_current_version_id: null,
              idempotency_key: "task-source-boundary-minutes-0001"
            }
          );
          if (!draft.reference) throw new Error("source minutes version is missing");
          versionId = draft.reference;
          expect(
            (await pool.query("select state from minutes where id=$1", [minutesId])).rows
          ).toEqual([{ state: "unpublished_draft" }]);
        }
        if (sourceCase === "declared_finalized") {
          await f.confirm("publish_minutes", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: minutesId,
            version_id: versionId,
            minutes_sha256: sha256Hex(text),
            signer_member_ids: [f.secretary.memberId],
            idempotency_key: "task-source-publish-0001"
          });
          await f.confirm("log_minutes_action_items", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            manifest: {
              schemaVersion: "boardagent.minutes-action-manifest.v1",
              minutesId,
              minutesVersion: 1,
              minutesSha256: sha256Hex(text),
              declaration: "items_logged",
              items: [
                {
                  itemId: f.taskId,
                  ownerMemberId: f.owner.memberId,
                  dueAt: "2026-10-22T12:00:00Z",
                  sourceLocator: { section: "Minutes", line: 2 },
                  description: "Prepare the synthetic exploration programme report.",
                  requiredEvidence: "Canonical report hash.",
                  visibility: "board"
                }
              ]
            },
            idempotency_key: "task-source-declare-0001"
          });
          expect(await f.taskObservation()).toMatchObject([
            {
              state: "draft",
              notices: 0,
              pending: 0,
              source_minutes_id: minutesId,
              source_minutes_version_id: versionId
            }
          ]);
          const issued = await f.confirm("prepare_minutes_for_signature", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: minutesId,
            expected_version_id: versionId,
            signer_member_ids: [f.secretary.memberId],
            idempotency_key: "task-source-package-0001"
          });
          await f.confirm("stage_minutes_signature", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: minutesId,
            package_id: issued.result.reference,
            reservation: null,
            idempotency_key: "task-source-signature-0001"
          });
          await f.confirm("finalize_minutes", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: minutesId,
            package_id: issued.result.reference,
            idempotency_key: "task-source-finalize-0001"
          });
          expect(
            (await pool.query("select state from minutes where id=$1", [minutesId])).rows
          ).toEqual([{ state: "finalized" }]);
        } else {
          const input = f.createInput(versionId ? { minutesId, versionId } : null);
          // Either a generic refusal with no task effects or a nonactionable draft
          // satisfies this boundary; the test does not invent a draft activation path.
          const outcome = await f.confirm("create_task", input).then(
            () => ({ accepted: true, error: "" }),
            (error: unknown) => ({
              accepted: false,
              error: error instanceof Error ? error.message : String(error)
            })
          );
          if (!outcome.accepted) {
            expect(sourceCase).toBe("unfinalized");
            expect(outcome.error).toMatch(/task creation is unavailable|task source|minutes/iu);
            expect(await f.taskObservation()).toEqual([]);
            return;
          }
        }
        const beforeOwnerAction = await f.taskObservation();
        const started = await f.service
          .executeDirect(f.ownerPrincipal, "start_task", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            task_id: f.taskId,
            idempotency_key: "task-source-owner-start-0001"
          })
          .then(
            () => true,
            () => false
          );
        if (sourceCase === "unfinalized") {
          expect({ rows: beforeOwnerAction, started }).toMatchObject({
            rows: [{ state: "draft", notices: 0, pending: 0 }],
            started: false
          });
        } else {
          expect({ rows: beforeOwnerAction, started }).toMatchObject({
            rows: [{ state: "open", notices: 1, pending: 1 }],
            started: true
          });
        }
      });
    },
    60_000
  );
});
