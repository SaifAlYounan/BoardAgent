import path from "node:path";
import { withConfiguredFixtureWorker } from "../helpers/configured-worker.js";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  markDueManagementQuestionsOverdueInTransaction,
  migrate,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
  testId
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_question_scheduler_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "question-scheduler-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedQuestion(
  pool: Pool,
  input: {
    readonly organizationId: string;
    readonly boardId: string;
    readonly askerMemberId: string;
    readonly ownerMemberId: string;
    readonly clientId: string;
    readonly questionId: string;
    readonly turnId: string;
    readonly idempotencyRecordId: string;
    readonly idempotencyKey: string;
    readonly due: "past" | "future";
    readonly hashByte: number;
  }
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("set constraints all deferred");
    await client.query(
      `insert into idempotency_records(
         id,organization_id,actor_member_id,client_id,operation,idempotency_key,
         request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256,
         created_at,expires_at,completed_at
       ) values (
         $1,$2,$3,$4,'ask_management_question',$5,$6,'succeeded','management_question',$7,$8,
         transaction_timestamp() - interval '8 days',
         transaction_timestamp() + interval '1 day',transaction_timestamp()
       )`,
      [
        input.idempotencyRecordId,
        input.organizationId,
        input.askerMemberId,
        input.clientId,
        input.idempotencyKey,
        testHash(input.hashByte),
        input.questionId,
        testHash(input.hashByte + 1)
      ]
    );
    await client.query(
      `insert into management_questions(
         id,organization_id,board_id,asker_member_id,assigned_owner_ids,due_at,acl_policy,
         state,current_turn_id,row_version,created_at
       ) values (
         $1,$2,$3,$4,$5,
         case when $6='past' then transaction_timestamp() - interval '1 day'
              else transaction_timestamp() + interval '1 day' end,
         $7,'pending',$8,1,transaction_timestamp() - interval '2 days'
       )`,
      [
        input.questionId,
        input.organizationId,
        input.boardId,
        input.askerMemberId,
        [input.ownerMemberId],
        input.due,
        JSON.stringify({
          schemaVersion: "boardagent.question-acl.v1",
          grants: [{ granteeType: "seat_role", seatRole: "voting_member" }],
          inheritedDocumentIds: []
        }),
        input.turnId
      ]
    );
    await client.query(
      `insert into management_question_turns(
         id,organization_id,board_id,question_id,ordinal,turn_kind,author_member_id,
         author_role,canonical_text,text_sha256,citation_snapshot,idempotency_record_id,created_at
       ) values (
         $1,$2,$3,$4,1,'question',$5,'voting_member','Scheduler test question',$6,'[]',$7,
         transaction_timestamp() - interval '2 days'
       )`,
      [
        input.turnId,
        input.organizationId,
        input.boardId,
        input.questionId,
        input.askerMemberId,
        testHash(input.hashByte + 2),
        input.idempotencyRecordId
      ]
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

describe("management-question overdue scheduler", () => {
  it("the production worker finds an overdue question without an injected scan", async () => {
    await withDatabase(async (pool) => {
      const asker = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["management:question"]
      });
      const manager = await seedAdditionalAuthorizedActor(pool, asker, {
        idBase: 100,
        seatRole: "management",
        scopes: ["management:question"]
      });
      const questionId = testId(800);
      await seedQuestion(pool, {
        organizationId: asker.organizationId,
        boardId: asker.boardId,
        askerMemberId: asker.memberId,
        ownerMemberId: manager.memberId,
        clientId: asker.clientId,
        questionId,
        turnId: testId(801),
        idempotencyRecordId: testId(802),
        idempotencyKey: "runtime-question-0001",
        due: "past",
        hashByte: 60
      });
      expect((await pool.query("select count(*)::int as count from jobs")).rows[0]?.count).toBe(0);
      await withConfiguredFixtureWorker(pool, asker.organizationId, async (worker) => {
        const abort = new AbortController();
        let error: unknown;
        const loop = worker.run(abort.signal).catch((value: unknown) => {
          error = value;
        });
        try {
          await expect
            .poll(
              async () => {
                if (error) throw error;
                return (
                  await pool.query("select state from management_questions where id=$1", [
                    questionId
                  ])
                ).rows[0]?.state;
              },
              { timeout: 5_000, interval: 50 }
            )
            .toBe("overdue");
          expect(
            (
              await pool.query(
                "select count(*)::int as count from management_question_turns where question_id=$1",
                [questionId]
              )
            ).rows[0]?.count
          ).toBe(1);
        } finally {
          abort.abort();
          await loop;
        }
      });
    });
  }, 20_000);

  it("is worker-only, deterministic, bounded and safe under concurrent batches", async () => {
    await withDatabase(async (pool) => {
      const asker = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["management:question"]
      });
      const manager = await seedAdditionalAuthorizedActor(pool, asker, {
        idBase: 100,
        seatRole: "management",
        scopes: ["management:question"]
      });
      const questions = [
        {
          questionId: testId(300),
          turnId: testId(301),
          idempotencyRecordId: testId(302),
          idempotencyKey: "scheduler-question-0001",
          due: "past" as const,
          hashByte: 30
        },
        {
          questionId: testId(310),
          turnId: testId(311),
          idempotencyRecordId: testId(312),
          idempotencyKey: "scheduler-question-0002",
          due: "past" as const,
          hashByte: 40
        },
        {
          questionId: testId(320),
          turnId: testId(321),
          idempotencyRecordId: testId(322),
          idempotencyKey: "scheduler-question-0003",
          due: "future" as const,
          hashByte: 50
        }
      ];
      for (const question of questions) {
        await seedQuestion(pool, {
          ...question,
          organizationId: asker.organizationId,
          boardId: asker.boardId,
          askerMemberId: asker.memberId,
          ownerMemberId: manager.memberId,
          clientId: asker.clientId
        });
      }

      await expect(
        withRequestTransaction(
          pool,
          asker.context,
          (client) => markDueManagementQuestionsOverdueInTransaction(client, { limit: 1 }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied/i);
      await expect(
        withWorkerTransaction(
          pool,
          (client) => client.query("update management_questions set row_version=row_version + 1"),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toThrow(/permission denied/i);
      await expect(
        withWorkerTransaction(
          pool,
          (client) => markDueManagementQuestionsOverdueInTransaction(client, { limit: 0 }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toThrow(/integer from 1 through 1000/);

      const batches = await Promise.all(
        [0, 1].map(() =>
          withWorkerTransaction(
            pool,
            (client) => markDueManagementQuestionsOverdueInTransaction(client, { limit: 1 }),
            { assumeRole: "boardagent_worker" }
          )
        )
      );
      expect(
        batches
          .flat()
          .map(({ questionId }) => questionId)
          .toSorted()
      ).toEqual(
        questions
          .filter(({ due }) => due === "past")
          .map(({ questionId }) => questionId)
          .toSorted()
      );
      expect(batches.flat().map(({ rowVersion }) => rowVersion)).toEqual([2n, 2n]);
      await expect(
        withWorkerTransaction(
          pool,
          (client) => markDueManagementQuestionsOverdueInTransaction(client),
          { assumeRole: "boardagent_worker" }
        )
      ).resolves.toEqual([]);

      const readback = await pool.query<{
        id: string;
        row_version: string;
        state: string;
      }>(
        `select id,row_version::text,state
           from management_questions
          order by id`
      );
      expect(readback.rows).toEqual([
        { id: questions[0]!.questionId, row_version: "2", state: "overdue" },
        { id: questions[1]!.questionId, row_version: "2", state: "overdue" },
        { id: questions[2]!.questionId, row_version: "1", state: "pending" }
      ]);
    });
  });
});
