import type { Pool } from "pg";

import {
  askManagementQuestionInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { prepareManagementQuestion } from "../../lib/domain/src/question.js";
import { seedAdditionalAuthorizedActor, seedAuthorizedActor, testId } from "./authorized-actor.js";

export async function seedQuestionFixture(pool: Pool, idBase: number) {
  const asker = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["management:question", "governance:read"]
  });
  const manager = await seedAdditionalAuthorizedActor(pool, asker, {
    idBase,
    seatRole: "management",
    scopes: ["management:question"]
  });
  const observer = await seedAdditionalAuthorizedActor(pool, asker, {
    idBase: idBase + 100,
    seatRole: "observer",
    scopes: ["governance:read", "management:question"]
  });
  const prepared = prepareManagementQuestion({
    questionId: testId(idBase + 200),
    boardId: asker.boardId,
    question: "What changed in the forecast?\n",
    assignedOwnerIds: [manager.memberId],
    dueAt: "2099-09-02T12:00:00Z",
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
        initialTurnId: testId(idBase + 201),
        auditEventId: testId(idBase + 202),
        idempotencyRecordId: testId(idBase + 203),
        idempotencyKey: `question-fixture-${String(idBase).padStart(6, "0")}`,
        visibilityRecordIds: [testId(idBase + 204)],
        ownerDeliveries: [
          {
            ownerMemberId: manager.memberId,
            noticeId: testId(idBase + 205),
            feedId: testId(idBase + 206)
          }
        ]
      }),
    { assumeRole: "boardagent_server" }
  );
  return { asker, manager, observer, prepared };
}
