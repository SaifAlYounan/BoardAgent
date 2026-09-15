import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  confirmMinutesLifecycleActionInTransaction,
  confirmStagedActionInTransaction,
  createMinutesVersionInTransaction,
  migrate,
  prepareMinutesLifecycleActionInTransaction,
  stageMinutesLifecycleActionInTransaction,
  submitMinutesReviewInTransaction,
  withdrawMinutesCommentInTransaction,
  withRequestTransaction,
  type MinutesLifecycleAction,
  type MinutesLifecycleResult
} from "../../lib/db/src/index.js";
import { canonicalSha256, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_minutes_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "minutes-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedPublishedMinutes(
  pool: Pool,
  actor: { organizationId: string; boardId: string; memberId: string }
): Promise<{
  meetingId: string;
  minutesId: string;
  versionId: string;
  text: string;
  sha256: string;
}> {
  const meetingId = testId(200);
  const minutesId = testId(201);
  const versionId = testId(202);
  const text = "# Minutes\nApproved draft.\n";
  const sha256 = sha256Hex(text);
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query(
      `insert into meetings(
         id,organization_id,board_id,title,scheduled_start,scheduled_end,created_by
       ) values ($1,$2,$3,'Review meeting',transaction_timestamp()+interval '1 hour',
                 transaction_timestamp()+interval '2 hours',$4)`,
      [meetingId, actor.organizationId, actor.boardId, actor.memberId]
    );
    await client.query(
      `insert into minutes(id,organization_id,board_id,meeting_id,created_by)
       values ($1,$2,$3,$4,$5)`,
      [minutesId, actor.organizationId, actor.boardId, meetingId, actor.memberId]
    );
    await client.query(
      `insert into minutes_versions(
         id,organization_id,board_id,minutes_id,version,canonical_schema,canonical_text,
         canonical_sha256,package_base_sha256,created_by
       ) values ($1,$2,$3,$4,1,'boardagent.minutes.v1',$5,$6,$7,$8)`,
      [
        versionId,
        actor.organizationId,
        actor.boardId,
        minutesId,
        text,
        Buffer.from(sha256, "hex"),
        Buffer.from(canonicalSha256({ minutesId, version: 1, sha256 }), "hex"),
        actor.memberId
      ]
    );
    await client.query(
      `update minutes
          set current_version_id=$1,state='published_review',row_version=row_version+1
        where id=$2`,
      [versionId, minutesId]
    );
    await client.query(
      "update meetings set current_minutes_id=$1,row_version=row_version+1 where id=$2",
      [minutesId, meetingId]
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return { meetingId, minutesId, versionId, text, sha256 };
}

let lifecycleSequence = 2_000;

function jsonValue(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function exactBytes(sequence: number): Buffer {
  const bytes = Buffer.alloc(48);
  bytes.writeUInt32BE(sequence, 0);
  return bytes;
}

async function confirmLifecycleAction(
  pool: Pool,
  actor: AuthorizedActorFixture,
  action: MinutesLifecycleAction
): Promise<MinutesLifecycleResult> {
  lifecycleSequence += 32;
  const sequence = lifecycleSequence;
  const confirmationCode = `C${sequence.toString(36).toUpperCase().padStart(7, "0").slice(-7)}`;
  const originalArguments = jsonValue(action);
  const clientCapabilities = { elicitation: { form: {} } };
  const requestStateBytes = exactBytes(sequence);
  const staged = await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      stageMinutesLifecycleActionInTransaction(client, {
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
          embeddedResult: { message: "Confirm exact minutes lifecycle action" },
          requestStateBytes,
          preparedRequestId: Buffer.from(`prepared-minutes-${String(sequence)}`),
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
      confirmMinutesLifecycleActionInTransaction(client, {
        action,
        confirmation: {
          stageId: staged.stageId,
          consentRecordId: testId(sequence + 6),
          retryRequestId: Buffer.from(`retry-minutes-${String(sequence)}`),
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
  if (!confirmed.confirmed) {
    throw new Error(`minutes lifecycle confirmation failed: ${confirmed.reason}`);
  }
  return confirmed.value;
}

async function seedCompletedReview(pool: Pool, kind: "comment" | "redline" = "comment") {
  const secretary = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["minutes:act", "secretariat:admin"],
    isSecretary: true
  });
  const reviewer = await seedAdditionalAuthorizedActor(pool, secretary, {
    idBase: 300,
    seatRole: "voting_member",
    scopes: ["minutes:act"]
  });
  const minutes = await seedPublishedMinutes(pool, secretary);
  const reviewInput = {
    reviewItemId: testId(95_000),
    idempotencyRecordId: testId(95_001),
    idempotencyKey: `minutes-completed-${kind}-retry-0001`,
    payload:
      kind === "comment"
        ? {
            schemaVersion: "boardagent.minutes-comment.v1",
            minutesId: minutes.minutesId,
            baseVersion: 1,
            baseSha256: minutes.sha256,
            comment: "Retain the approved exploration programme wording.",
            citations: []
          }
        : {
            schemaVersion: "boardagent.minutes-redline.v1",
            minutesId: minutes.minutesId,
            baseVersion: 1,
            baseSha256: minutes.sha256,
            anchor: { kind: "lines", startLine: 2, endLine: 2 },
            anchoredTextSha256: sha256Hex("Approved draft."),
            operation: "replace",
            proposedText: "Approved exploration programme.",
            rationale: "Use the agreed programme wording.",
            citations: []
          },
    deliveries: [
      {
        recipientMemberId: secretary.memberId,
        noticeId: testId(95_002),
        feedId: testId(95_003)
      }
    ],
    auditEventId: testId(95_004)
  };
  const submit = () =>
    withRequestTransaction(
      pool,
      reviewer.context,
      (client) => submitMinutesReviewInTransaction(client, reviewInput),
      { assumeRole: "boardagent_server" }
    );
  const originalReview = await submit();
  const withdrawalInput = {
    withdrawalId: testId(95_010),
    minutesId: minutes.minutesId,
    reviewItemId: reviewInput.reviewItemId,
    idempotencyRecordId: testId(95_011),
    idempotencyKey: "minutes-completed-withdrawal-retry-0001",
    auditEventId: testId(95_012)
  };
  const withdraw = () =>
    withRequestTransaction(
      pool,
      reviewer.context,
      (client) => withdrawMinutesCommentInTransaction(client, withdrawalInput),
      { assumeRole: "boardagent_server" }
    );
  const counts = async () =>
    (
      await pool.query(
        `select (select count(*)::int from minutes_review_items) as reviews,
                (select count(*)::int from minutes_review_withdrawals) as withdrawals,
                (select count(*)::int from idempotency_records) as idempotency,
                (select count(*)::int from audit_events) as audits,
                (select count(*)::int from notices) as notices,
                (select count(*)::int from pending_action_feed) as feed`
      )
    ).rows[0];
  return {
    secretary,
    reviewer,
    minutes,
    reviewInput,
    withdrawalInput,
    originalReview,
    submit,
    withdraw,
    counts
  };
}

async function finalizeReplayFixture(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedCompletedReview>>,
  versionId: string,
  version: number,
  text: string
) {
  await confirmLifecycleAction(pool, fixture.secretary, {
    kind: "action_declaration",
    minutesId: fixture.minutes.minutesId,
    manifest: {
      schemaVersion: "boardagent.minutes-action-manifest.v1",
      minutesId: fixture.minutes.minutesId,
      minutesVersion: version,
      minutesSha256: sha256Hex(text),
      declaration: "no_action_items"
    }
  });
  const issued = await confirmLifecycleAction(pool, fixture.secretary, {
    kind: "signature_package_issue",
    minutesId: fixture.minutes.minutesId,
    expectedVersionId: versionId,
    requirements: [{ memberId: fixture.secretary.memberId, requirement: "required" }]
  });
  if (issued.kind !== "signature_package_issue") throw new Error("unexpected package result");
  await confirmLifecycleAction(pool, fixture.secretary, {
    kind: "signature",
    minutesId: fixture.minutes.minutesId,
    packageId: issued.signaturePackageId,
    reservation: null
  });
  await confirmLifecycleAction(pool, fixture.secretary, {
    kind: "finalization",
    minutesId: fixture.minutes.minutesId,
    packageId: issued.signaturePackageId
  });
}

describe("published minutes review transactions", () => {
  it.each(["comment", "redline"] as const)(
    "WF01 replays a completed %s after correction and finalization without new effects",
    async (kind) => {
      await withDatabase(async (pool) => {
        const fixture = await seedCompletedReview(pool, kind);
        const correctedText = "# Minutes\nCorrected exploration programme wording.\n";
        const corrected = await confirmLifecycleAction(pool, fixture.secretary, {
          kind: "package_correction",
          minutesId: fixture.minutes.minutesId,
          expectedVersionId: fixture.minutes.versionId,
          canonicalText: correctedText,
          reason: "Correct the programme description while preserving review history."
        });
        if (corrected.kind !== "package_correction") throw new Error("unexpected correction");
        const afterCorrection = await fixture.counts();
        const expectedReplay = {
          replayed: true,
          reviewItemId: fixture.originalReview.reviewItemId,
          responseSha256: fixture.originalReview.responseSha256
        };
        await expect(fixture.submit()).resolves.toMatchObject(expectedReplay);
        expect(await fixture.counts()).toEqual(afterCorrection);
        await expect(
          withRequestTransaction(
            pool,
            fixture.reviewer.context,
            (client) =>
              submitMinutesReviewInTransaction(client, {
                ...fixture.reviewInput,
                idempotencyKey: "minutes-new-stale-review-request-0001"
              }),
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toMatchObject({ code: "minutes_review_stale" });
        await confirmLifecycleAction(pool, fixture.secretary, {
          kind: "review_disposition",
          minutesId: fixture.minutes.minutesId,
          reviewItemId: fixture.originalReview.reviewItemId,
          decision: kind === "comment" ? "accepted" : "rejected",
          reason:
            "The corrected programme incorporates the discussion; old redlines are not rebased."
        });
        await finalizeReplayFixture(pool, fixture, corrected.minutesVersionId, 2, correctedText);
        const afterFinalization = await fixture.counts();
        await expect(fixture.submit()).resolves.toMatchObject(expectedReplay);
        expect(await fixture.counts()).toEqual(afterFinalization);
      });
    }
  );

  it("WF02 replays a completed withdrawal after correction and finalization without new effects", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCompletedReview(pool);
      const original = await fixture.withdraw();
      const correctedText = "# Minutes\nConfirmed exploration programme.\n";
      const corrected = await confirmLifecycleAction(pool, fixture.secretary, {
        kind: "package_correction",
        minutesId: fixture.minutes.minutesId,
        expectedVersionId: fixture.minutes.versionId,
        canonicalText: correctedText,
        reason: "Correct minutes after the author withdrew their comment."
      });
      if (corrected.kind !== "package_correction") throw new Error("unexpected correction");
      const expectedReplay = {
        replayed: true,
        withdrawalId: original.withdrawalId,
        reviewItemId: original.reviewItemId,
        responseSha256: original.responseSha256
      };
      const afterCorrection = await fixture.counts();
      await expect(fixture.withdraw()).resolves.toMatchObject(expectedReplay);
      expect(await fixture.counts()).toEqual(afterCorrection);
      await finalizeReplayFixture(pool, fixture, corrected.minutesVersionId, 2, correctedText);
      const afterFinalization = await fixture.counts();
      await expect(fixture.withdraw()).resolves.toMatchObject(expectedReplay);
      expect(await fixture.counts()).toEqual(afterFinalization);
      expect(
        (
          await pool.query<{ current_minutes_version_id: string; request_sha256: string }>(
            `select withdrawal.current_minutes_version_id,encode(record.request_sha256,'hex') as request_sha256
               from minutes_review_withdrawals as withdrawal
               join idempotency_records as record on record.id=withdrawal.idempotency_record_id
              where withdrawal.id=$1`,
            [original.withdrawalId]
          )
        ).rows
      ).toEqual([
        {
          current_minutes_version_id: fixture.minutes.versionId,
          request_sha256: canonicalSha256({
            operation: "withdraw_minutes_comment",
            reviewItemId: original.reviewItemId,
            currentMinutesVersionId: fixture.minutes.versionId
          })
        }
      ]);
    });
  });

  it("WF01/WF02 rejects changed replay payloads and withdrawal targets without changing history", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCompletedReview(pool);
      await fixture.withdraw();
      const secondReview = await withRequestTransaction(
        pool,
        fixture.reviewer.context,
        (client) =>
          submitMinutesReviewInTransaction(client, {
            ...fixture.reviewInput,
            reviewItemId: testId(95_020),
            idempotencyRecordId: testId(95_021),
            idempotencyKey: "minutes-second-review-for-retry-target-0001",
            deliveries: [
              {
                recipientMemberId: fixture.secretary.memberId,
                noticeId: testId(95_022),
                feedId: testId(95_023)
              }
            ],
            auditEventId: testId(95_024)
          }),
        { assumeRole: "boardagent_server" }
      );
      const before = await fixture.counts();
      await expect(
        withRequestTransaction(
          pool,
          fixture.reviewer.context,
          (client) =>
            submitMinutesReviewInTransaction(client, {
              ...fixture.reviewInput,
              payload: { ...fixture.reviewInput.payload, comment: "Different requested wording." }
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "idempotency_conflict" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.reviewer.context,
          (client) =>
            withdrawMinutesCommentInTransaction(client, {
              ...fixture.withdrawalInput,
              reviewItemId: secondReview.reviewItemId
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "idempotency_conflict" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.reviewer.context,
          (client) =>
            withdrawMinutesCommentInTransaction(client, {
              ...fixture.withdrawalInput,
              minutesId: testId(95_030)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "minutes_comment_withdrawal_unavailable" });
      expect(await fixture.counts()).toEqual(before);
    });
  });

  it.each(["review", "withdrawal"] as const)(
    "WF01/WF02 refuses completed %s replay after token revocation or token-context mismatch",
    async (operation) => {
      await withDatabase(async (pool) => {
        const fixture = await seedCompletedReview(pool);
        await fixture.withdraw();
        await finalizeReplayFixture(
          pool,
          fixture,
          fixture.minutes.versionId,
          1,
          fixture.minutes.text
        );
        const before = await fixture.counts();
        const run = (context: AuthorizedActorFixture["context"]) =>
          withRequestTransaction(
            pool,
            context,
            (client) =>
              operation === "review"
                ? submitMinutesReviewInTransaction(client, fixture.reviewInput)
                : withdrawMinutesCommentInTransaction(client, fixture.withdrawalInput),
            { assumeRole: "boardagent_server" }
          );
        await expect(
          run({ ...fixture.reviewer.context, tokenJti: fixture.secretary.tokenJti })
        ).rejects.toThrow(/unavailable/u);
        await pool.query(
          "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
          [fixture.reviewer.accessTokenRecordId]
        );
        await expect(run(fixture.reviewer.context)).rejects.toThrow(/unavailable/u);
        expect(await fixture.counts()).toEqual(before);
      });
    }
  );

  it("creates unpublished versions, publishes exact review notices, and guards cancellation", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const reviewer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 800,
        seatRole: "observer",
        scopes: ["minutes:act"]
      });
      const meetingId = testId(8_000);
      const minutesId = testId(8_001);
      await pool.query(
        `insert into meetings(
           id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by
         ) values ($1,$2,$3,'Draft lifecycle meeting','called',
                   transaction_timestamp()+interval '1 hour',
                   transaction_timestamp()+interval '2 hours',$4)`,
        [meetingId, secretary.organizationId, secretary.boardId, secretary.memberId]
      );

      const firstInput = {
        minutesId,
        meetingId,
        canonicalText: "# Draft minutes\nFirst exact draft.\n",
        transcriptVersionId: null,
        expectedCurrentVersionId: null,
        minutesVersionId: testId(8_002),
        idempotencyRecordId: testId(8_003),
        idempotencyKey: "minutes-draft-create-0001",
        auditEventId: testId(8_004)
      } as const;
      const first = await withRequestTransaction(
        pool,
        secretary.context,
        (client) => createMinutesVersionInTransaction(client, firstInput),
        { assumeRole: "boardagent_server" }
      );
      expect(first).toMatchObject({
        replayed: false,
        minutesId,
        minutesVersionId: firstInput.minutesVersionId,
        version: 1
      });
      const replay = await withRequestTransaction(
        pool,
        secretary.context,
        (client) => createMinutesVersionInTransaction(client, firstInput),
        { assumeRole: "boardagent_server" }
      );
      expect(replay).toMatchObject({
        replayed: true,
        minutesId,
        minutesVersionId: firstInput.minutesVersionId
      });

      const secondInput = {
        minutesId,
        meetingId,
        canonicalText: "# Draft minutes\nSecond exact draft.\n",
        transcriptVersionId: null,
        expectedCurrentVersionId: firstInput.minutesVersionId,
        minutesVersionId: testId(8_005),
        idempotencyRecordId: testId(8_006),
        idempotencyKey: "minutes-draft-create-0002",
        auditEventId: testId(8_007)
      } as const;
      const second = await withRequestTransaction(
        pool,
        secretary.context,
        (client) => createMinutesVersionInTransaction(client, secondInput),
        { assumeRole: "boardagent_server" }
      );
      expect(second).toMatchObject({
        replayed: false,
        minutesVersionId: secondInput.minutesVersionId,
        version: 2
      });
      if (second.replayed) throw new Error("unexpected minutes draft replay");

      const published = await confirmLifecycleAction(pool, secretary, {
        kind: "publication",
        minutesId,
        versionId: second.minutesVersionId,
        minutesSha256: second.canonicalSha256,
        signerMemberIds: [reviewer.memberId, secretary.memberId]
      });
      expect(published).toEqual({
        kind: "publication",
        minutesId,
        minutesVersionId: second.minutesVersionId,
        minutesSha256: second.canonicalSha256,
        reviewRecipientMemberIds: [secretary.memberId, reviewer.memberId].toSorted()
      });
      const publishedEvidence = await pool.query<{
        feeds: string;
        notices: string;
        state: string;
        version_events: string;
      }>(
        `select
          (select state from minutes where id=$1) as state,
          (select count(*)::text from notices
            where object_id=$1 and notice_type='minutes_review_requested') as notices,
          (select count(*)::text from pending_action_feed
            where object_id=$1 and action_type='minutes_review_requested' and state='pending') as feeds,
          (select count(*)::text from audit_events
            where event_type='minutes_version_created' and object_id in ($2,$3)) as version_events`,
        [minutesId, firstInput.minutesVersionId, secondInput.minutesVersionId]
      );
      expect(publishedEvidence.rows[0]).toEqual({
        feeds: "2",
        notices: "2",
        state: "published_review",
        version_events: "2"
      });

      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            client.query(
              `update minutes
                  set state='cancelled',cancelled_at=transaction_timestamp(),
                      row_version=row_version+1
                where id=$1`,
              [minutesId]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      const cancelled = await confirmLifecycleAction(pool, secretary, {
        kind: "cancellation",
        minutesId,
        reason: "The meeting record requires a new minutes process."
      });
      expect(cancelled).toEqual({
        kind: "cancellation",
        minutesId,
        supersededDraftTaskIds: []
      });
      const cancelledEvidence = await pool.query<{
        pending_feeds: string;
        state: string;
      }>(
        `select
          (select state from minutes where id=$1) as state,
          (select count(*)::text from pending_action_feed
            where object_id=$1 and state='pending') as pending_feeds`,
        [minutesId]
      );
      expect(cancelledEvidence.rows[0]).toEqual({ pending_feeds: "0", state: "cancelled" });

      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            createMinutesVersionInTransaction(client, {
              ...secondInput,
              canonicalText: "# Draft minutes\nForbidden terminal rewrite.\n",
              expectedCurrentVersionId: second.minutesVersionId,
              minutesVersionId: testId(8_008),
              idempotencyRecordId: testId(8_009),
              idempotencyKey: "minutes-draft-create-0003",
              auditEventId: testId(8_010)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "minutes_draft_unavailable" });
    });
  }, 60_000);

  it("accepts exact member/observer reviews, replays once, and rejects stale or closed packages", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act"],
        isSecretary: true
      });
      const minutes = await seedPublishedMinutes(pool, secretary);
      const commentInput = {
        reviewItemId: testId(210),
        idempotencyRecordId: testId(211),
        idempotencyKey: "minutes-comment-idempotency-0001",
        payload: {
          schemaVersion: "boardagent.minutes-comment.v1" as const,
          minutesId: minutes.minutesId,
          baseVersion: 1,
          baseSha256: minutes.sha256,
          comment: "Please retain the approved wording.\n",
          citations: []
        },
        deliveries: [
          {
            recipientMemberId: secretary.memberId,
            noticeId: testId(212),
            feedId: testId(213)
          }
        ],
        auditEventId: testId(214)
      };
      const [first, replay] = await Promise.all([
        withRequestTransaction(
          pool,
          secretary.context,
          (client) => submitMinutesReviewInTransaction(client, commentInput),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          secretary.context,
          (client) => submitMinutesReviewInTransaction(client, commentInput),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect([first.replayed, replay.replayed].toSorted()).toEqual([false, true]);
      expect(first.reviewItemId).toBe(commentInput.reviewItemId);
      expect(replay.reviewItemId).toBe(commentInput.reviewItemId);
      const firstCounts = await pool.query<{
        audit: string;
        feed: string;
        items: string;
        notices: string;
      }>(
        `select (select count(*)::text from minutes_review_items) as items,
                (select count(*)::text from notices) as notices,
                (select count(*)::text from pending_action_feed) as feed,
                (select count(*)::text from audit_events) as audit`
      );
      expect(firstCounts.rows[0]).toEqual({ audit: "1", feed: "1", items: "1", notices: "1" });

      const withdrawalInput = {
        withdrawalId: testId(220),
        reviewItemId: commentInput.reviewItemId,
        idempotencyRecordId: testId(221),
        idempotencyKey: "minutes-comment-withdrawal-0001",
        auditEventId: testId(222)
      };
      const withdrawal = await withRequestTransaction(
        pool,
        secretary.context,
        (client) => withdrawMinutesCommentInTransaction(client, withdrawalInput),
        { assumeRole: "boardagent_server" }
      );
      const withdrawalReplay = await withRequestTransaction(
        pool,
        secretary.context,
        (client) => withdrawMinutesCommentInTransaction(client, withdrawalInput),
        { assumeRole: "boardagent_server" }
      );
      expect(withdrawal.replayed).toBe(false);
      expect(withdrawalReplay).toMatchObject({
        replayed: true,
        withdrawalId: withdrawalInput.withdrawalId,
        reviewItemId: commentInput.reviewItemId
      });

      const observer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 300,
        seatRole: "observer",
        scopes: ["minutes:act"]
      });
      const redlineInput = {
        reviewItemId: testId(410),
        idempotencyRecordId: testId(411),
        idempotencyKey: "minutes-redline-idempotency-0001",
        payload: {
          schemaVersion: "boardagent.minutes-redline.v1" as const,
          minutesId: minutes.minutesId,
          baseVersion: 1,
          baseSha256: minutes.sha256,
          anchor: { kind: "lines" as const, startLine: 2, endLine: 2 },
          anchoredTextSha256: sha256Hex("Approved draft."),
          operation: "replace" as const,
          proposedText: "Approved final wording.",
          rationale: "Use the exact resolution wording.",
          citations: []
        },
        deliveries: [
          {
            recipientMemberId: secretary.memberId,
            noticeId: testId(412),
            feedId: testId(413)
          }
        ],
        auditEventId: testId(414)
      };
      const redline = await withRequestTransaction(
        pool,
        observer.context,
        (client) => submitMinutesReviewInTransaction(client, redlineInput),
        { assumeRole: "boardagent_server" }
      );
      expect(redline.replayed).toBe(false);
      expect(redline.auditEvent?.eventType).toBe("minutes_redline_proposed");
      const observerItem = await pool.query<{ author_seat_role: string; item_kind: string }>(
        "select author_seat_role,item_kind from minutes_review_items where id=$1",
        [redline.reviewItemId]
      );
      expect(observerItem.rows[0]).toEqual({ author_seat_role: "observer", item_kind: "redline" });

      await expect(
        withRequestTransaction(
          pool,
          observer.context,
          (client) =>
            withdrawMinutesCommentInTransaction(client, {
              withdrawalId: testId(415),
              reviewItemId: commentInput.reviewItemId,
              idempotencyRecordId: testId(416),
              idempotencyKey: "minutes-comment-withdrawal-other-author",
              auditEventId: testId(417)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "minutes_comment_withdrawal_unavailable" });
      await expect(
        withRequestTransaction(
          pool,
          observer.context,
          (client) =>
            withdrawMinutesCommentInTransaction(client, {
              withdrawalId: testId(418),
              reviewItemId: redline.reviewItemId,
              idempotencyRecordId: testId(419),
              idempotencyKey: "minutes-redline-withdrawal-disallowed",
              auditEventId: testId(420)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "minutes_comment_withdrawal_unavailable" });

      await expect(
        withRequestTransaction(
          pool,
          observer.context,
          (client) =>
            submitMinutesReviewInTransaction(client, {
              ...redlineInput,
              reviewItemId: testId(420),
              idempotencyRecordId: testId(421),
              idempotencyKey: "minutes-redline-idempotency-stale",
              payload: { ...redlineInput.payload, anchoredTextSha256: "f".repeat(64) },
              deliveries: [
                {
                  recipientMemberId: secretary.memberId,
                  noticeId: testId(422),
                  feedId: testId(423)
                }
              ],
              auditEventId: testId(424)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("anchored text hash");

      await pool.query(
        `update minutes
            set state='signature_ready',row_version=row_version+1
          where id=$1`,
        [minutes.minutesId]
      );
      await expect(
        withRequestTransaction(
          pool,
          observer.context,
          (client) =>
            submitMinutesReviewInTransaction(client, {
              ...redlineInput,
              reviewItemId: testId(430),
              idempotencyRecordId: testId(431),
              idempotencyKey: "minutes-redline-idempotency-closed",
              deliveries: [
                {
                  recipientMemberId: secretary.memberId,
                  noticeId: testId(432),
                  feedId: testId(433)
                }
              ],
              auditEventId: testId(434)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "minutes_review_unavailable" });
      const finalCounts = await pool.query<{ audits: string; items: string }>(
        `select (select count(*)::text from minutes_review_items) as items,
                (select count(*)::text from audit_events) as audits`
      );
      expect(finalCounts.rows[0]).toEqual({ audits: "3", items: "2" });
    });
  });

  it("keeps prior-version comments and redlines pending through correction until explicitly resolved", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const minutes = await seedPublishedMinutes(pool, secretary);
      for (const [index, kind] of ["comment", "redline"].entries()) {
        await withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            submitMinutesReviewInTransaction(client, {
              reviewItemId: testId(90_000 + index * 10),
              idempotencyRecordId: testId(90_001 + index * 10),
              idempotencyKey: `cross-version-review-${kind}-0001`,
              payload:
                kind === "comment"
                  ? {
                      schemaVersion: "boardagent.minutes-comment.v1",
                      minutesId: minutes.minutesId,
                      baseVersion: 1,
                      baseSha256: minutes.sha256,
                      comment: "Pending prior-version input.",
                      citations: []
                    }
                  : {
                      schemaVersion: "boardagent.minutes-redline.v1",
                      minutesId: minutes.minutesId,
                      baseVersion: 1,
                      baseSha256: minutes.sha256,
                      anchor: { kind: "lines", startLine: 2, endLine: 2 },
                      anchoredTextSha256: sha256Hex("Approved draft."),
                      operation: "replace",
                      proposedText: "Reviewer's wording.",
                      rationale: "Exact proposed wording.",
                      citations: []
                    },
              deliveries: [
                {
                  recipientMemberId: secretary.memberId,
                  noticeId: testId(90_003 + index * 10),
                  feedId: testId(90_004 + index * 10)
                }
              ],
              auditEventId: testId(90_002 + index * 10)
            }),
          { assumeRole: "boardagent_server" }
        );
      }
      const correctedText = "# Minutes\nCorrected draft.\n";
      const corrected = await confirmLifecycleAction(pool, secretary, {
        kind: "package_correction",
        minutesId: minutes.minutesId,
        expectedVersionId: minutes.versionId,
        canonicalText: correctedText,
        reason: "Correct the package without silently resolving reviewer input."
      });
      if (corrected.kind !== "package_correction") throw new Error("unexpected result");
      const issue: MinutesLifecycleAction = {
        kind: "signature_package_issue",
        minutesId: minutes.minutesId,
        expectedVersionId: corrected.minutesVersionId,
        requirements: [{ memberId: secretary.memberId, requirement: "required" }]
      };
      await expect(confirmLifecycleAction(pool, secretary, issue)).rejects.toMatchObject({
        code: "minutes_review_pending"
      });
      await withRequestTransaction(
        pool,
        secretary.context,
        (client) =>
          withdrawMinutesCommentInTransaction(client, {
            withdrawalId: testId(90_100),
            reviewItemId: testId(90_000),
            idempotencyRecordId: testId(90_101),
            idempotencyKey: "cross-version-withdrawal-0001",
            auditEventId: testId(90_102)
          }),
        { assumeRole: "boardagent_server" }
      );
      await expect(confirmLifecycleAction(pool, secretary, issue)).rejects.toMatchObject({
        code: "minutes_review_pending"
      });
      // Carry-forward never rebases a redline or weakens its signed exact-base binding.
      await expect(
        confirmLifecycleAction(pool, secretary, {
          kind: "review_disposition",
          minutesId: minutes.minutesId,
          reviewItemId: testId(90_010),
          decision: "accepted",
          reason: "Attempt stale exact-base redline.",
          replacementText: "# Minutes\nReviewer's wording.\n"
        })
      ).rejects.toThrow("minutes redline base hash mismatch");
      await confirmLifecycleAction(pool, secretary, {
        kind: "review_disposition",
        minutesId: minutes.minutesId,
        reviewItemId: testId(90_010),
        decision: "rejected",
        reason: "Superseded by the correction; request a new exact-base proposal."
      });
      await confirmLifecycleAction(pool, secretary, {
        kind: "action_declaration",
        minutesId: minutes.minutesId,
        manifest: {
          schemaVersion: "boardagent.minutes-action-manifest.v1",
          minutesId: minutes.minutesId,
          minutesVersion: 2,
          minutesSha256: sha256Hex(correctedText),
          declaration: "no_action_items"
        }
      });
      expect(await confirmLifecycleAction(pool, secretary, issue)).toMatchObject({
        kind: "signature_package_issue"
      });
    });
  });

  it("runs disposition, correction, declaration, signatures, finalization and linked correction atomically", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const reviewer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 500,
        seatRole: "voting_member",
        scopes: ["minutes:act"]
      });
      const observer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 600,
        seatRole: "observer",
        scopes: ["minutes:act"]
      });
      const minutes = await seedPublishedMinutes(pool, secretary);

      const comment = await withRequestTransaction(
        pool,
        reviewer.context,
        (client) =>
          submitMinutesReviewInTransaction(client, {
            reviewItemId: testId(5_000),
            idempotencyRecordId: testId(5_001),
            idempotencyKey: "lifecycle-comment-review-0001",
            payload: {
              schemaVersion: "boardagent.minutes-comment.v1",
              minutesId: minutes.minutesId,
              baseVersion: 1,
              baseSha256: minutes.sha256,
              comment: "Record the exact vote wording.",
              citations: []
            },
            deliveries: [
              {
                recipientMemberId: secretary.memberId,
                noticeId: testId(5_002),
                feedId: testId(5_003)
              }
            ],
            auditEventId: testId(5_004)
          }),
        { assumeRole: "boardagent_server" }
      );
      const redlinePayload = {
        schemaVersion: "boardagent.minutes-redline.v1" as const,
        minutesId: minutes.minutesId,
        baseVersion: 1,
        baseSha256: minutes.sha256,
        anchor: { kind: "lines" as const, startLine: 2, endLine: 2 },
        anchoredTextSha256: sha256Hex("Approved draft."),
        operation: "replace" as const,
        proposedText: "Approved exact resolution wording.",
        rationale: "Match the certified resolution.",
        citations: []
      };
      const redline = await withRequestTransaction(
        pool,
        observer.context,
        (client) =>
          submitMinutesReviewInTransaction(client, {
            reviewItemId: testId(5_010),
            idempotencyRecordId: testId(5_011),
            idempotencyKey: "lifecycle-redline-review-0001",
            payload: redlinePayload,
            deliveries: [
              {
                recipientMemberId: secretary.memberId,
                noticeId: testId(5_012),
                feedId: testId(5_013)
              }
            ],
            auditEventId: testId(5_014)
          }),
        { assumeRole: "boardagent_server" }
      );

      const resultingText = "# Minutes\nApproved exact resolution wording.\n";
      const accepted = await confirmLifecycleAction(pool, secretary, {
        kind: "review_disposition",
        minutesId: minutes.minutesId,
        reviewItemId: redline.reviewItemId,
        decision: "accepted",
        reason: "The exact redline matches the certified resolution.",
        replacementText: resultingText
      });
      expect(accepted).toMatchObject({
        kind: "review_disposition",
        decision: "accepted",
        minutesSha256: sha256Hex(resultingText)
      });
      if (accepted.kind !== "review_disposition") throw new Error("unexpected result");

      const firstTaskId = testId(7_000);
      const firstManifest = {
        schemaVersion: "boardagent.minutes-action-manifest.v1" as const,
        minutesId: minutes.minutesId,
        minutesVersion: 2,
        minutesSha256: accepted.minutesSha256,
        declaration: "items_logged" as const,
        items: [
          {
            itemId: firstTaskId,
            ownerMemberId: reviewer.memberId,
            dueAt: "2026-10-01T12:00:00Z",
            sourceLocator: { section: "Minutes", line: 2 },
            description: "Deliver the certified resolution report.",
            requiredEvidence: "Canonical report hash.",
            visibility: "board" as const
          }
        ]
      };
      // Accepting one redline must not hide a sibling review item on the prior version.
      await expect(
        confirmLifecycleAction(pool, secretary, {
          kind: "action_declaration",
          minutesId: minutes.minutesId,
          manifest: firstManifest
        })
      ).rejects.toMatchObject({ code: "minutes_review_pending" });
      await expect(
        confirmLifecycleAction(pool, secretary, {
          kind: "signature_package_issue",
          minutesId: minutes.minutesId,
          expectedVersionId: accepted.minutesVersionId,
          requirements: [{ memberId: secretary.memberId, requirement: "required" }]
        })
      ).rejects.toMatchObject({ code: "minutes_review_pending" });
      const rejected = await confirmLifecycleAction(pool, secretary, {
        kind: "review_disposition",
        minutesId: minutes.minutesId,
        reviewItemId: comment.reviewItemId,
        decision: "rejected",
        reason: "The final wording is represented by the exact redline."
      });
      expect(rejected).toMatchObject({ kind: "review_disposition", decision: "rejected" });
      await confirmLifecycleAction(pool, secretary, {
        kind: "action_declaration",
        minutesId: minutes.minutesId,
        manifest: firstManifest
      });
      const firstPackage = await confirmLifecycleAction(pool, secretary, {
        kind: "signature_package_issue",
        minutesId: minutes.minutesId,
        expectedVersionId: accepted.minutesVersionId,
        requirements: [
          { memberId: secretary.memberId, requirement: "required" },
          { memberId: reviewer.memberId, requirement: "required" },
          { memberId: observer.memberId, requirement: "permitted" }
        ]
      });
      expect(firstPackage.kind).toBe("signature_package_issue");
      for (const actor of [secretary, reviewer, observer]) {
        const signature = await confirmLifecycleAction(pool, actor, {
          kind: "signature",
          minutesId: minutes.minutesId,
          packageId:
            firstPackage.kind === "signature_package_issue"
              ? firstPackage.signaturePackageId
              : testId(9_990),
          reservation: actor === observer ? "Observer attestation only; not a vote." : null
        });
        expect(signature.kind).toBe("signature");
      }

      const correctedText = `${resultingText}\n# Correction\nClarified after signature review.\n`;
      const corrected = await confirmLifecycleAction(pool, secretary, {
        kind: "package_correction",
        minutesId: minutes.minutesId,
        expectedVersionId: accepted.minutesVersionId,
        canonicalText: correctedText,
        reason: "Clarify the recorded signature reservation."
      });
      expect(corrected).toMatchObject({
        kind: "package_correction",
        minutesSha256: sha256Hex(correctedText)
      });
      if (corrected.kind !== "package_correction") throw new Error("unexpected result");

      const secondTaskId = testId(7_001);
      await confirmLifecycleAction(pool, secretary, {
        kind: "action_declaration",
        minutesId: minutes.minutesId,
        manifest: {
          schemaVersion: "boardagent.minutes-action-manifest.v1",
          minutesId: minutes.minutesId,
          minutesVersion: 3,
          minutesSha256: corrected.minutesSha256,
          declaration: "items_logged",
          items: [
            {
              itemId: secondTaskId,
              ownerMemberId: reviewer.memberId,
              dueAt: "2026-10-02T12:00:00Z",
              sourceLocator: { section: "Correction", line: 5 },
              description: "Deliver the corrected report.",
              requiredEvidence: "Corrected canonical report hash.",
              visibility: "board"
            }
          ]
        }
      });
      const secondPackage = await confirmLifecycleAction(pool, secretary, {
        kind: "signature_package_issue",
        minutesId: minutes.minutesId,
        expectedVersionId: corrected.minutesVersionId,
        requirements: [
          { memberId: secretary.memberId, requirement: "required" },
          { memberId: reviewer.memberId, requirement: "required" },
          { memberId: observer.memberId, requirement: "permitted" }
        ]
      });
      expect(secondPackage.kind).toBe("signature_package_issue");
      for (const actor of [secretary, reviewer, observer]) {
        await confirmLifecycleAction(pool, actor, {
          kind: "signature",
          minutesId: minutes.minutesId,
          packageId:
            secondPackage.kind === "signature_package_issue"
              ? secondPackage.signaturePackageId
              : testId(9_991),
          reservation: null
        });
      }
      await expect(
        confirmLifecycleAction(pool, secretary, {
          kind: "finalization",
          minutesId: minutes.minutesId,
          packageId: testId(9_992)
        })
      ).rejects.toThrow("exact current signature package");
      const finalized = await confirmLifecycleAction(pool, secretary, {
        kind: "finalization",
        minutesId: minutes.minutesId,
        packageId:
          secondPackage.kind === "signature_package_issue"
            ? secondPackage.signaturePackageId
            : testId(9_993)
      });
      expect(finalized).toMatchObject({
        kind: "finalization",
        activatedTaskIds: [secondTaskId]
      });
      const linked = await confirmLifecycleAction(pool, secretary, {
        kind: "finalized_correction",
        minutesId: minutes.minutesId,
        replacementMinutesId: testId(7_002),
        canonicalText: `${correctedText}\n# Final correction\nLinked replacement.\n`,
        reason: "Create the permanent linked correction aggregate."
      });
      expect(linked).toMatchObject({
        kind: "finalized_correction",
        replacementMinutesId: testId(7_002)
      });

      const state = await pool.query<{
        attributed_signatures: string;
        first_task_state: string;
        observer_signatures: string;
        original_state: string;
        pending_resigns: string;
        replacement_state: string;
        second_task_state: string;
        signatures: string;
        supersessions: string;
      }>(
        `select
          (select state from minutes where id=$1) as original_state,
          (select state from minutes where id=$2) as replacement_state,
          (select state from tasks where id=$3) as first_task_state,
          (select state from tasks where id=$4) as second_task_state,
          (select count(*)::text from minutes_signature_supersessions) as supersessions,
          (select count(*)::text from minutes_resign_requirements where state='pending') as pending_resigns,
          (select count(*)::text from minutes_signatures) as signatures,
          (select count(*)::text from minutes_signatures
            where signer_seat_role='observer') as observer_signatures,
          (select count(*)::text
             from minutes_signatures as signature
             join consent_records as consent on consent.id=signature.consent_record_id
            where signature.access_token_record_id=consent.access_token_record_id
              and signature.client_id=consent.client_id
              and signature.exact_origin=consent.exact_origin
              and octet_length(signature.package_sha256)=32
              and octet_length(signature.signature_record_sha256)=32) as attributed_signatures`,
        [
          minutes.minutesId,
          linked.kind === "finalized_correction" ? linked.replacementMinutesId : testId(9_999),
          firstTaskId,
          secondTaskId
        ]
      );
      expect(state.rows[0]).toEqual({
        attributed_signatures: "6",
        first_task_state: "superseded",
        observer_signatures: "2",
        original_state: "finalized",
        pending_resigns: "0",
        replacement_state: "published_review",
        second_task_state: "open",
        signatures: "6",
        supersessions: "3"
      });
      await expect(
        pool.query(
          `insert into minutes(
             id,organization_id,board_id,meeting_id,correction_of_minutes_id,created_by
           ) values ($1,$2,$3,$4,$5,$6)`,
          [
            testId(9_998),
            secretary.organizationId,
            secretary.boardId,
            minutes.meetingId,
            minutes.minutesId,
            secretary.memberId
          ]
        )
      ).rejects.toMatchObject({ code: "23505" });

      const replacementMinutesId =
        linked.kind === "finalized_correction" ? linked.replacementMinutesId : testId(9_999);
      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            client.query(
              `insert into minutes(
                 id,organization_id,board_id,meeting_id,correction_of_minutes_id,created_by
               ) values ($1,$2,$3,$4,$5,$6)`,
              [
                testId(9_997),
                secretary.organizationId,
                secretary.boardId,
                minutes.meetingId,
                replacementMinutesId,
                secretary.memberId
              ]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({
        code: "23514",
        message: expect.stringMatching(/exact correction cycle|lineage tip/u)
      });

      const existingCycle = await pool.query<{ consent_record_id: string }>(
        "select consent_record_id from minutes_correction_cycles where replacement_minutes_id=$1",
        [replacementMinutesId]
      );
      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          async (client) => {
            const wrongStateReplacement = testId(9_996);
            await client.query(
              `insert into minutes(
                 id,organization_id,board_id,meeting_id,state,correction_of_minutes_id,created_by
               ) values ($1,$2,$3,$4,'published_review',$5,$6)`,
              [
                wrongStateReplacement,
                secretary.organizationId,
                secretary.boardId,
                minutes.meetingId,
                replacementMinutesId,
                secretary.memberId
              ]
            );
            await client.query(
              `insert into minutes_correction_cycles(
                 id,organization_id,board_id,original_minutes_id,replacement_minutes_id,
                 reason,secretary_member_id,consent_record_id
               ) values ($1,$2,$3,$4,$5,'invalid raw state link',$6,$7)`,
              [
                testId(9_995),
                secretary.organizationId,
                secretary.boardId,
                replacementMinutesId,
                wrongStateReplacement,
                secretary.memberId,
                existingCycle.rows[0]?.consent_record_id
              ]
            );
          },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({
        code: "23514",
        message: expect.stringMatching(/finalized original/u)
      });
      await expect(
        pool.query(
          `update meetings
              set current_minutes_id=$1,row_version=row_version+1
            where id=$2`,
          [minutes.minutesId, minutes.meetingId]
        )
      ).rejects.toThrow(/exact finalized correction tip/u);
    });
  }, 60_000);
});

describe("minutes terminal SQL expected-version boundary", () => {
  it.each(["null", "stale", "exact", "null_state"] as const)(
    "keeps terminal projections bound to the %s expected version",
    async (versionCase) => {
      await withMigratedDatabase("minutes-version-boundary", async (pool) => {
        const secretary = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["minutes:act", "secretariat:admin"],
          isSecretary: true
        });
        const meetingId = testId(791_000);
        const minutesId = testId(791_001);
        const minutesVersionId = testId(791_002);
        const taskId = testId(791_005);
        const text = "# Synthetic minutes\nReview the exploration programme.\n";
        await pool.query(
          `insert into meetings(id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by)
           values($1,$2,$3,'Synthetic version boundary meeting','called',
             transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
          [meetingId, secretary.organizationId, secretary.boardId, secretary.memberId]
        );
        const draft = await withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            createMinutesVersionInTransaction(client, {
              meetingId,
              minutesId,
              minutesVersionId,
              canonicalText: text,
              transcriptVersionId: null,
              expectedCurrentVersionId: null,
              idempotencyRecordId: testId(791_003),
              idempotencyKey: "minutes-version-boundary-draft",
              auditEventId: testId(791_004)
            }),
          { assumeRole: "boardagent_server" }
        );
        if (draft.replayed) throw new Error("unexpected boundary draft replay");
        await confirmLifecycleAction(pool, secretary, {
          kind: "publication",
          minutesId,
          versionId: minutesVersionId,
          minutesSha256: draft.canonicalSha256,
          signerMemberIds: [secretary.memberId]
        });
        await confirmLifecycleAction(pool, secretary, {
          kind: "action_declaration",
          minutesId,
          manifest: {
            schemaVersion: "boardagent.minutes-action-manifest.v1",
            minutesId,
            minutesVersion: 1,
            minutesSha256: draft.canonicalSha256,
            declaration: "items_logged",
            items: [
              {
                itemId: taskId,
                ownerMemberId: secretary.memberId,
                dueAt: "2026-10-01T12:00:00Z",
                sourceLocator: { section: "Minutes", line: 2 },
                description: "Prepare the synthetic programme summary.",
                requiredEvidence: "Canonical summary hash.",
                visibility: "board"
              }
            ]
          }
        });
        const issued = await confirmLifecycleAction(pool, secretary, {
          kind: "signature_package_issue",
          minutesId,
          expectedVersionId: minutesVersionId,
          requirements: [{ memberId: secretary.memberId, requirement: "required" }]
        });
        if (issued.kind !== "signature_package_issue") throw new Error("expected current package");

        const action = {
          kind: "cancellation",
          minutesId,
          reason: "Synthetic SQL expected-version boundary probe."
        } as const;
        const originalArguments = jsonValue(action);
        const clientCapabilities = { elicitation: { form: {} } };
        const requestStateBytes = exactBytes(791_010);
        const confirmationCode = "NULL7910";
        const staged = await withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            stageMinutesLifecycleActionInTransaction(client, {
              action,
              stage: {
                stageId: testId(791_010),
                inputRequiredAttemptId: testId(791_011),
                nonce: exactBytes(791_012),
                confirmationCode,
                accessTokenRecordId: secretary.accessTokenRecordId,
                exactOrigin: "https://client.example",
                originalArguments,
                clientCapabilities,
                embeddedForm: { type: "object", required: ["approve", "confirmation_code"] },
                embeddedResult: { message: "Confirm the synthetic minutes cancellation" },
                requestStateBytes,
                preparedRequestId: Buffer.from("minutes-version-boundary-prepare"),
                auditEventIds: {
                  stageReplaced: testId(791_013),
                  stageCreated: testId(791_014),
                  elicitationSent: testId(791_015)
                }
              }
            }),
          { assumeRole: "boardagent_server" }
        );
        const snapshot = async () => ({
          minutes: (
            await pool.query("select row_to_json(r)::text as row from minutes r order by id")
          ).rows,
          packages: (
            await pool.query(
              "select row_to_json(r)::text as row from minutes_signature_packages r order by id"
            )
          ).rows,
          tasks: (await pool.query("select row_to_json(r)::text as row from tasks r order by id"))
            .rows,
          resign: (
            await pool.query(
              "select row_to_json(r)::text as row from minutes_resign_requirements r order by id"
            )
          ).rows,
          versions: (
            await pool.query(
              "select row_to_json(r)::text as row from minutes_versions r order by id"
            )
          ).rows
        });
        const before = await snapshot();
        const current = (
          await pool.query<{ row_version: string }>(
            "select row_version::text from minutes where id=$1",
            [minutesId]
          )
        ).rows[0]!.row_version;
        const expectedVersion =
          versionCase === "null"
            ? null
            : versionCase === "stale"
              ? (BigInt(current) - 1n).toString()
              : current;
        let called = false;
        // Real staging, current-authority revalidation and protected consent creation
        // surround this SQL-only act callback. No consent row or projection is forged.
        // Returning the SQL observation lets the transaction commit before assertions;
        // it does not claim the full application cancellation/audit workflow succeeded.
        const confirmation = withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            confirmStagedActionInTransaction(
              client,
              {
                stageId: staged.stageId,
                consentRecordId: testId(791_016),
                retryRequestId: Buffer.from("minutes-version-boundary-retry"),
                originalArguments,
                clientCapabilities,
                exactOrigin: "https://client.example",
                requestStateBytes,
                responseAction: "accept",
                inputResponse: { approve: true, confirmation_code: confirmationCode },
                auditEventIds: {
                  consentRecorded: testId(791_017),
                  consentRejected: testId(791_018)
                }
              },
              async (requestClient) => {
                const prepared = await prepareMinutesLifecycleActionInTransaction(
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
                row_security_active('public.minutes'::regclass) as minutes_rls,
                row_security_active('public.tasks'::regclass) as tasks_rls`)
                  ).rows[0]
                ).toEqual({
                  role: "boardagent_server",
                  minutes_rls: true,
                  tasks_rls: true
                });
                const result = await requestClient.query<{
                  next_row_version: string | null;
                  superseded_task_ids: string[];
                }>(
                  `select next_row_version::text,superseded_task_ids
                  from boardagent_apply_minutes_terminal_transition($1,$2::bigint,$3,$4)`,
                  [
                    minutesId,
                    expectedVersion,
                    versionCase === "null_state" ? null : "cancelled",
                    consentRecordId
                  ]
                );
                return { value: result.rows, auditEvents: [] };
              }
            ),
          { assumeRole: "boardagent_server" }
        );
        if (versionCase === "null_state") {
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
        if (!observed.confirmed) throw new Error(`SQL boundary consent failed: ${observed.reason}`);
        const after = await snapshot();
        if (versionCase !== "exact") {
          expect({ result: observed.value, rows: after }).toEqual({ result: [], rows: before });
        } else {
          expect(observed.value).toEqual([
            {
              next_row_version: (BigInt(current) + 1n).toString(),
              superseded_task_ids: [taskId]
            }
          ]);
          expect(
            (
              await pool.query("select state,row_version::text from minutes where id=$1", [
                minutesId
              ])
            ).rows
          ).toEqual([{ state: "cancelled", row_version: (BigInt(current) + 1n).toString() }]);
          expect(
            (
              await pool.query("select state from minutes_signature_packages where id=$1", [
                issued.signaturePackageId
              ])
            ).rows
          ).toEqual([{ state: "terminal" }]);
          expect((await pool.query("select state from tasks where id=$1", [taskId])).rows).toEqual([
            { state: "superseded" }
          ]);
          expect(after.versions).toEqual(before.versions);
        }
      });
    }
  );
});
