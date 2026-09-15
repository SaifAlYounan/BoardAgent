import { readQuestionWithTestOwner } from "../helpers/question-projection-owner.js";
import { describe, expect, it } from "vitest";

import {
  listManagementQuestionsInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedQuestionFixture } from "../helpers/question-fixture.js";

describe("TH-24 confidential Q&A probing", () => {
  it("returns the same empty/null shape before access and after a deny-wins exclusion", async () => {
    await withMigratedDatabase("question_confidentiality", async (pool) => {
      const fixture = await seedQuestionFixture(pool, 24_000);
      const readAsObserver = () =>
        withRequestTransaction(
          pool,
          fixture.observer.context,
          async (client) => ({
            list: await listManagementQuestionsInTransaction(client, {
              boardId: fixture.observer.boardId
            }),
            get: await readQuestionWithTestOwner(client, fixture.prepared.questionId)
          }),
          { assumeRole: "boardagent_server" }
        );

      expect(await readAsObserver()).toEqual({
        list: { items: [], totalVisible: 0, nextCursor: null },
        get: null
      });

      await pool.query(
        `insert into question_visibility(
           id,organization_id,board_id,question_id,grantee_seat_role,effect,reason,created_by
         ) values ($1,$2,$3,$4,'observer','grant','attack fixture grant',$5)`,
        [
          testId(24_310),
          fixture.asker.organizationId,
          fixture.asker.boardId,
          fixture.prepared.questionId,
          fixture.asker.memberId
        ]
      );
      expect((await readAsObserver()).list.totalVisible).toBe(1);

      await pool.query(
        `insert into question_visibility(
           id,organization_id,board_id,question_id,grantee_member_id,effect,reason,created_by
         ) values ($1,$2,$3,$4,$5,'exclude','deny wins attack fixture',$6)`,
        [
          testId(24_311),
          fixture.asker.organizationId,
          fixture.asker.boardId,
          fixture.prepared.questionId,
          fixture.observer.memberId,
          fixture.asker.memberId
        ]
      );
      expect(await readAsObserver()).toEqual({
        list: { items: [], totalVisible: 0, nextCursor: null },
        get: null
      });
    });
  });
});
