import { readQuestionWithTestOwner } from "../helpers/question-projection-owner.js";
import path from "node:path";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  askManagementQuestionInTransaction,
  listManagementQuestionsInTransaction,
  migrate,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { prepareManagementQuestion } from "../../lib/domain/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_question_queries_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  let passed = false;
  try {
    await migrate(pool, MIGRATIONS, "question-query-test");
    const result = await run(pool);
    passed = true;
    return result;
  } finally {
    if (!passed) process.stderr.write(`Preserved failed question-query fixture: ${database}\n`);
    try {
      await pool.end();
      if (passed) await dropClosedTestDatabase(admin, database);
    } finally {
      await admin.end();
    }
  }
}

describe("confidential management-question queries", () => {
  it("filters root, count, turns and delivery lineage through one deny-wins policy", async () => {
    await withDatabase(async (pool) => {
      const asker = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["management:question", "governance:read"]
      });
      const manager = await seedAdditionalAuthorizedActor(pool, asker, {
        idBase: 100,
        seatRole: "management",
        scopes: ["management:question"]
      });
      const outsider = await seedAdditionalAuthorizedActor(pool, asker, {
        idBase: 200,
        seatRole: "observer",
        scopes: ["governance:read"]
      });
      const prepared = prepareManagementQuestion({
        questionId: testId(30),
        boardId: asker.boardId,
        question: "What is the visible management response?\n",
        assignedOwnerIds: [manager.memberId],
        dueAt: "2099-09-03T12:00:00Z",
        citations: [],
        visibility: [{ granteeType: "seat_role", seatRole: "voting_member" }]
      });
      await withRequestTransaction(
        pool,
        asker.context,
        (client) =>
          askManagementQuestionInTransaction(client, {
            organizationId: asker.organizationId,
            prepared,
            initialTurnId: testId(31),
            auditEventId: testId(32),
            idempotencyRecordId: testId(33),
            idempotencyKey: "question-query-create-0001",
            visibilityRecordIds: [testId(34)],
            ownerDeliveries: [
              { ownerMemberId: manager.memberId, noticeId: testId(35), feedId: testId(36) }
            ]
          }),
        { assumeRole: "boardagent_server" }
      );
      const second = prepareManagementQuestion({
        questionId: testId(40),
        boardId: asker.boardId,
        question: "What is the second visible management response?\n",
        assignedOwnerIds: [manager.memberId],
        dueAt: "2099-09-04T12:00:00Z",
        citations: [],
        visibility: [{ granteeType: "seat_role", seatRole: "voting_member" }]
      });
      await withRequestTransaction(
        pool,
        asker.context,
        (client) =>
          askManagementQuestionInTransaction(client, {
            organizationId: asker.organizationId,
            prepared: second,
            initialTurnId: testId(41),
            auditEventId: testId(42),
            idempotencyRecordId: testId(43),
            idempotencyKey: "question-query-create-0002",
            visibilityRecordIds: [testId(44)],
            ownerDeliveries: [
              { ownerMemberId: manager.memberId, noticeId: testId(45), feedId: testId(46) }
            ]
          }),
        { assumeRole: "boardagent_server" }
      );

      const visible = await withRequestTransaction(
        pool,
        asker.context,
        async (client) => ({
          list: await listManagementQuestionsInTransaction(client, {
            boardId: asker.boardId,
            limit: 1
          }),
          question: await readQuestionWithTestOwner(client, prepared.questionId)
        }),
        { assumeRole: "boardagent_server" }
      );
      expect(visible.list).toMatchObject({ totalVisible: 2 });
      expect(visible.list.items).toHaveLength(1);
      expect(visible.list.items[0]?.questionId).toBe(second.questionId);
      expect(visible.list.nextCursor).not.toBeNull();
      expect(visible.question).toMatchObject({
        questionId: prepared.questionId,
        turnCount: 1,
        answerCount: 0
      });
      expect(visible.question?.turns).toMatchObject([
        { turnKind: "question", canonicalText: prepared.question }
      ]);
      expect(visible.question?.deliveries).toMatchObject([
        { noticeType: "management_question_due", recipientMemberId: manager.memberId }
      ]);
      const afterCursor = await withRequestTransaction(
        pool,
        asker.context,
        (client) =>
          listManagementQuestionsInTransaction(client, {
            boardId: asker.boardId,
            limit: 1,
            after: visible.list.nextCursor!
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(afterCursor).toMatchObject({ totalVisible: 2, nextCursor: null });
      expect(afterCursor.items).toMatchObject([{ questionId: prepared.questionId }]);

      const hidden = await withRequestTransaction(
        pool,
        outsider.context,
        async (client) => ({
          list: await listManagementQuestionsInTransaction(client, { boardId: outsider.boardId }),
          question: await readQuestionWithTestOwner(client, prepared.questionId)
        }),
        { assumeRole: "boardagent_server" }
      );
      expect(hidden).toEqual({
        list: { items: [], totalVisible: 0, nextCursor: null },
        question: null
      });

      await pool.query(
        `insert into question_visibility(
           id,organization_id,board_id,question_id,grantee_seat_role,effect,reason,created_by
         ) values ($1,$2,$3,$4,'observer','grant','query visibility test',$5)`,
        [testId(60), asker.organizationId, asker.boardId, prepared.questionId, asker.memberId]
      );
      const granted = await withRequestTransaction(
        pool,
        outsider.context,
        async (client) => ({
          list: await listManagementQuestionsInTransaction(client, { boardId: outsider.boardId }),
          question: await readQuestionWithTestOwner(client, prepared.questionId)
        }),
        { assumeRole: "boardagent_server" }
      );
      expect(granted.list.totalVisible).toBe(1);
      expect(granted.question?.questionId).toBe(prepared.questionId);

      await pool.query(
        `insert into question_visibility(
           id,organization_id,board_id,question_id,grantee_member_id,effect,reason,created_by
         ) values ($1,$2,$3,$4,$5,'exclude','deny wins query test',$6)`,
        [
          testId(61),
          asker.organizationId,
          asker.boardId,
          prepared.questionId,
          outsider.memberId,
          asker.memberId
        ]
      );
      const excluded = await withRequestTransaction(
        pool,
        outsider.context,
        async (client) => ({
          list: await listManagementQuestionsInTransaction(client, { boardId: outsider.boardId }),
          question: await readQuestionWithTestOwner(client, prepared.questionId)
        }),
        { assumeRole: "boardagent_server" }
      );
      expect(excluded).toEqual({
        list: { items: [], totalVisible: 0, nextCursor: null },
        question: null
      });
    });
  });
});
