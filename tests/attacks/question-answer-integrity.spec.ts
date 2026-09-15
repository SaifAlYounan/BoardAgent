import { describe, expect, it } from "vitest";

import {
  answerManagementQuestionInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { prepareManagementQuestionTurn } from "../../lib/domain/src/question.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedQuestionFixture } from "../helpers/question-fixture.js";

describe("TH-25 management answer integrity", () => {
  it("cannot mark a question answered without a nonblank immutable answer turn", async () => {
    await withMigratedDatabase("question_answer", async (pool) => {
      const fixture = await seedQuestionFixture(pool, 25_000);

      expect(() =>
        prepareManagementQuestionTurn({
          questionId: fixture.prepared.questionId,
          turnKind: "answer",
          text: "   ",
          citations: []
        })
      ).toThrow();
      await expect(
        pool.query("update management_questions set state='answered' where id=$1", [
          fixture.prepared.questionId
        ])
      ).rejects.toThrow(/recorded answer turn/u);
      expect(
        (
          await pool.query<{ state: string }>(
            "select state from management_questions where id=$1",
            [fixture.prepared.questionId]
          )
        ).rows
      ).toEqual([{ state: "pending" }]);

      const prepared = prepareManagementQuestionTurn({
        questionId: fixture.prepared.questionId,
        turnKind: "answer",
        text: "The variance is caused by the delayed renewal.\n",
        citations: []
      });
      await withRequestTransaction(
        pool,
        fixture.manager.context,
        (client) =>
          answerManagementQuestionInTransaction(client, {
            organizationId: fixture.manager.organizationId,
            prepared,
            turnId: testId(25_310),
            answerRecordId: testId(25_311),
            auditEventId: testId(25_312),
            idempotencyRecordId: testId(25_313),
            idempotencyKey: "question-integrity-answer-0001",
            askerDelivery: {
              recipientMemberId: fixture.asker.memberId,
              noticeId: testId(25_314),
              feedId: testId(25_315)
            },
            ownerResolutions: [
              { ownerMemberId: fixture.manager.memberId, tombstoneId: testId(25_316) }
            ],
            sourceUpdateAuditEvents: []
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(
        (
          await pool.query<{ answer_count: string; state: string }>(
            `select question.state,
                    (select count(*)::text from management_question_answers
                      where question_id=question.id) as answer_count
               from management_questions as question where question.id=$1`,
            [fixture.prepared.questionId]
          )
        ).rows
      ).toEqual([{ state: "answered", answer_count: "1" }]);
      await expect(
        pool.query("update management_question_turns set canonical_text='tampered' where id=$1", [
          testId(25_310)
        ])
      ).rejects.toThrow(/immutable evidence/u);
    });
  });
});
