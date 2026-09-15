import type { Pool, PoolClient } from "pg";
import { expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedManagementProjectionFixture } from "../helpers/management-projection-fixture.js";
import {
  ORIGINAL_SUBMISSION_POINT_SQL,
  ORIGINAL_SUBMISSION_LIST_SQL,
  ORIGINAL_QUESTION_LIST_SQL
} from "../helpers/management-read-original-sql.js";

type ObjectValue = Readonly<Record<string, JsonValue>>;
function object(value: JsonValue | undefined): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected management smoke object");
  return value as ObjectValue;
}
function items(value: JsonValue | undefined): readonly JsonValue[] {
  if (!Array.isArray(value)) throw new TypeError("expected management smoke array");
  return value;
}
const CASE = "supports named normal management submission and question fixture transitions";
it(
  CASE,
  async () => {
    const observations: Record<string, unknown>[] = [];
    await withMigratedDatabase("mg_projection_fixture", async (pool: Pool) => {
      const fixture = await seedManagementProjectionFixture(pool);
      const read = <T>(
        actor: "management" | "secretary" | "asker",
        work: (client: PoolClient) => Promise<T>
      ) =>
        withRequestTransaction(pool, fixture.actors[actor].context, work, {
          assumeRole: "boardagent_server"
        });
      const point = (actor: "management" | "secretary", id = fixture.submissionIds[0]) =>
        read(actor, async (client) => {
          expect((await client.query("select current_user::text as role")).rows).toEqual([
            { role: "boardagent_server" }
          ]);
          const rows = (
            await client.query<{ view: JsonValue }>(ORIGINAL_SUBMISSION_POINT_SQL, [
              id,
              fixture.actors[actor].memberId
            ])
          ).rows;
          expect(rows).toHaveLength(1);
          return object(rows[0]!.view);
        });
      const questions = () =>
        read("asker", async (client) => {
          const rows = (
            await client.query<{ total_visible: string; items: JsonValue[] }>(
              ORIGINAL_QUESTION_LIST_SQL,
              [fixture.boardId, null, null, null, 101]
            )
          ).rows;
          expect(rows).toHaveLength(1);
          return rows[0]!;
        });
      const base = await point("management");
      expect(canonicalJson(await point("secretary"))).toBe(canonicalJson(base));
      expect(Object.keys(base).sort()).toEqual(
        [
          "submission_id",
          "board_id",
          "management_owner_ids",
          "assigned_secretary_id",
          "state",
          "current_version_id",
          "row_version",
          "queue_entered_at",
          "versions",
          "revision_requests",
          "dispositions",
          "created_by",
          "created_at"
        ].sort()
      );
      expect(base.state).toBe("submitted");
      expect(items(base.versions)).toHaveLength(1);
      // Mutation input uses snake_case; stored/public references retain the
      // domain's camelCase IDs, as in the previously passed management journey.
      expect(object(items(base.versions)[0]).document_references).toEqual([
        {
          documentId: fixture.firstDocumentReference.document_id,
          versionId: fixture.firstDocumentReference.version_id,
          sha256: fixture.firstDocumentReference.sha256
        }
      ]);
      expect(base.revision_requests).toEqual([]);
      expect(base.dispositions).toEqual([]);
      const initialQuestions = await questions();
      expect(initialQuestions.total_visible).toBe("3");
      expect(initialQuestions.items).toHaveLength(3);
      for (const item of initialQuestions.items)
        expect(item).toMatchObject({ state: "pending", turnCount: 1, answerCount: 0 });
      observations.push({
        phase: "base",
        commands: fixture.commands.length,
        versions: 1,
        questions: initialQuestions
      });
      await fixture.requestMainRevision();
      let current = await point("secretary");
      expect(current.state).toBe("revision_requested");
      expect(items(current.revision_requests)).toHaveLength(1);
      expect(object(items(current.revision_requests)[0])).toMatchObject({
        request_id: fixture.requestId,
        request_text: fixture.revisionReason,
        replies: []
      });
      await fixture.replyToMainRevision();
      current = await point("secretary");
      const request = object(items(current.revision_requests)[0]),
        replies = items(request.replies);
      expect(replies).toHaveLength(1);
      expect(replies[0]).toMatchObject({ canonical_reply: fixture.replyText });
      await fixture.reviseSourceAndResubmitMain();
      current = await point("secretary");
      expect(current.state).toBe("resubmitted");
      expect(items(current.versions)).toHaveLength(2);
      expect(object(items(current.versions)[1])).toMatchObject({
        version_id: fixture.currentSubmissionVersion,
        version: 2,
        document_references: [
          {
            documentId: fixture.currentDocumentReference.document_id,
            versionId: fixture.currentDocumentReference.version_id,
            sha256: fixture.currentDocumentReference.sha256
          }
        ],
        change_reason: fixture.resubmissionReason
      });
      expect(object(items(current.versions)[1]).document_references).toEqual([
        {
          documentId: fixture.currentDocumentReference.document_id,
          versionId: fixture.currentDocumentReference.version_id,
          sha256: fixture.currentDocumentReference.sha256
        }
      ]);
      await fixture.approveMain();
      current = await point("secretary");
      expect(current.state).toBe("approved_to_draft");
      expect(items(current.dispositions)).toHaveLength(1);
      expect(object(items(current.dispositions)[0]).resulting_draft_id).toBe(
        fixture.resultingDraftId
      );
      expect(canonicalJson(await point("management"))).toBe(canonicalJson(current));
      const submissionRows = await read(
        "secretary",
        async (client) =>
          (
            await client.query<{ item: JsonValue }>(ORIGINAL_SUBMISSION_LIST_SQL, [
              fixture.boardId,
              fixture.actors.secretary.memberId,
              null,
              null,
              101
            ])
          ).rows
      );
      expect(submissionRows).toHaveLength(3);
      expect(submissionRows.map((row) => object(row.item).submission_id).sort()).toEqual(
        [...fixture.submissionIds].sort()
      );
      await fixture.answerFirstQuestion();
      expect(
        (await questions()).items.find(
          (value) => object(value).questionId === fixture.questionIds[0]
        )
      ).toMatchObject({ state: "answered", turnCount: 2, answerCount: 1 });
      await fixture.followUpFirstQuestion();
      expect(
        (await questions()).items.find(
          (value) => object(value).questionId === fixture.questionIds[0]
        )
      ).toMatchObject({ state: "pending", turnCount: 3, answerCount: 1 });
      await fixture.answerFirstQuestionAgain();
      const completeQuestions = await questions();
      expect(
        completeQuestions.items.find((value) => object(value).questionId === fixture.questionIds[0])
      ).toMatchObject({ state: "answered", turnCount: 4, answerCount: 2 });
      expect(fixture.commands).toHaveLength(15);
      observations.push({
        phase: "complete",
        commands: fixture.commands.length,
        submission: current,
        questions: completeQuestions
      });
      await fixture.appendFourthSubmission();
      await fixture.appendFourthQuestion();
      const finalQuestions = await questions();
      expect(finalQuestions.total_visible).toBe("4");
      expect(finalQuestions.items).toHaveLength(4);
      const finalSubmissions = await read(
        "secretary",
        async (client) =>
          (
            await client.query(ORIGINAL_SUBMISSION_LIST_SQL, [
              fixture.boardId,
              fixture.actors.secretary.memberId,
              null,
              null,
              101
            ])
          ).rows
      );
      expect(finalSubmissions).toHaveLength(4);
      expect(fixture.commands).toHaveLength(17);
      observations.push({
        phase: "newcomers",
        commands: fixture.commands,
        submissions: finalSubmissions.length,
        questions: finalQuestions.total_visible,
        roles: Object.fromEntries(
          Object.entries(fixture.principals).map(([key, value]) => [
            key,
            { roles: value.roles, scopes: value.scopes }
          ])
        )
      });
    });
    process.stdout.write(
      `MANAGEMENT_PROJECTION_FIXTURE_SMOKE ${JSON.stringify({
        observations,
        limitations: [
          "Synthetic constrained sessions and bearer identity, not browser authentication",
          "Original actual-role reads only; admission and native delivery are separate tests",
          "Approval stops at an inert draft; no proposal activation or vote/worker path"
        ]
      })}\n`
    );
  },
  90_000
);
