import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { sha256Hex } from "../../lib/contracts/src/index.js";
import {
  approveManagementSubmissionInTransaction,
  migrate,
  rejectManagementSubmissionInTransaction,
  replyToManagementRevisionInTransaction,
  requestManagementRevisionInTransaction,
  resubmitManagementMaterialsInTransaction,
  submitDocumentToSecretariatInTransaction,
  withRequestTransaction,
  type SubmitDocumentToSecretariatInput
} from "../../lib/db/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_management_workflow_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  let passed = false;
  try {
    await migrate(pool, MIGRATIONS, "management-workflow-test");
    const result = await run(pool);
    passed = true;
    return result;
  } finally {
    try {
      await pool.end();
      if (passed) await dropClosedTestDatabase(admin, database);
      else console.error(`Preserved failed management workflow fixture: ${database}`);
    } finally {
      await admin.end();
    }
  }
}

function request<T>(
  pool: Pool,
  actor: AuthorizedActorFixture,
  run: Parameters<typeof withRequestTransaction<T>>[2]
): Promise<T> {
  return withRequestTransaction(pool, actor.context, run, {
    assumeRole: "boardagent_server",
    isolation: "serializable"
  });
}

async function seedActorsAndDocument(pool: Pool) {
  const management = await seedAuthorizedActor(pool, {
    seatRole: "management",
    scopes: ["documents:read", "documents:contribute"]
  });
  const secretary = await seedAdditionalAuthorizedActor(pool, management, {
    idBase: 100,
    seatRole: "voting_member",
    scopes: ["governance:read", "secretariat:admin"],
    isSecretary: true
  });
  const otherManagement = await seedAdditionalAuthorizedActor(pool, management, {
    idBase: 140,
    seatRole: "management",
    scopes: ["documents:read", "documents:contribute"]
  });
  const documentId = testId(200);
  const versionId = testId(201);
  const validationAttemptId = testId(202);
  const content = Buffer.from("Accepted board pack source\n", "utf8");
  const hash = sha256Hex(content);
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("set constraints all deferred");
    await client.query(
      `insert into documents(
         id,organization_id,board_id,title,state,current_version_id,created_by
       ) values ($1,$2,$3,'Accepted board pack source','active',$4,$5)`,
      [documentId, management.organizationId, management.boardId, versionId, management.memberId]
    );
    await client.query(
      `insert into document_versions(
         id,organization_id,board_id,document_id,version,media_type,
         canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,
         created_by
       ) values ($1,$2,$3,$4,1,'text/plain; charset=utf-8','RFC8785+NFC-LF-v1',
         $5,$6,$7,'{}',$8)`,
      [
        versionId,
        management.organizationId,
        management.boardId,
        documentId,
        content,
        content.length,
        Buffer.from(hash, "hex"),
        management.memberId
      ]
    );
    await client.query(
      `insert into document_validation_attempts(
         id,organization_id,board_id,actor_member_id,offered_media_type,offered_name,
         offered_length,offered_sha256,result,result_code,remediation,
         accepted_document_version_id
       ) values ($1,$2,$3,$4,'text/plain; charset=utf-8','board-pack.txt',$5,$6,
         'accepted','accepted','No remediation required.',$7)`,
      [
        validationAttemptId,
        management.organizationId,
        management.boardId,
        management.memberId,
        content.length,
        Buffer.from(hash, "hex"),
        versionId
      ]
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
  return {
    management,
    secretary,
    otherManagement,
    reference: { documentId, versionId, sha256: hash }
  };
}

function submissionInput(
  fixture: Awaited<ReturnType<typeof seedActorsAndDocument>>,
  base = 300
): SubmitDocumentToSecretariatInput {
  return {
    organizationId: fixture.management.organizationId,
    submissionId: testId(base),
    versionId: testId(base + 1),
    boardId: fixture.management.boardId,
    assignedSecretaryMemberId: fixture.secretary.memberId,
    documentReferences: [fixture.reference],
    purpose: "Quarterly operating report for secretariat review",
    idempotencyRecordId: testId(base + 2),
    idempotencyKey: `management-submit-${String(base).padStart(4, "0")}`,
    auditEventId: testId(base + 3)
  };
}

describe("complete management submission workflow", () => {
  it.each([
    "request_management_revision",
    "reply_to_management_revision",
    "approve_management_submission",
    "reject_management_submission"
  ] as const)("refuses completed %s replay after its actor token is revoked", async (operation) => {
    await withDatabase(async (pool) => {
      const fixture = await seedActorsAndDocument(pool);
      const submitted = submissionInput(fixture);
      await request(pool, fixture.management, (client) =>
        submitDocumentToSecretariatInTransaction(client, submitted)
      );
      const revisionInput = {
        organizationId: fixture.management.organizationId,
        requestId: testId(320),
        submissionId: submitted.submissionId,
        reason: "Please explain the operating assumptions in this version.",
        idempotencyRecordId: testId(321),
        idempotencyKey: "management-retry-revision-request-0001",
        auditEventId: testId(322)
      };
      if (operation === "reply_to_management_revision") {
        await request(pool, fixture.secretary, (client) =>
          requestManagementRevisionInTransaction(client, revisionInput)
        );
      }
      const actor =
        operation === "reply_to_management_revision" ? fixture.management : fixture.secretary;
      const evidence = {
        organizationId: fixture.management.organizationId,
        submissionId: submitted.submissionId,
        idempotencyRecordId: testId(331),
        idempotencyKey: `management-retry-${operation}-0001`,
        auditEventId: testId(332)
      };
      const signedContext = Buffer.from(
        '{"schemaVersion":"boardagent.management-draft-context.v1","reviewed":true}',
        "utf8"
      );
      // Every attempt uses the same actor, key and complete transaction input.
      const act = () =>
        request(pool, actor, (client) => {
          switch (operation) {
            case "request_management_revision":
              return requestManagementRevisionInTransaction(client, revisionInput);
            case "reply_to_management_revision":
              return replyToManagementRevisionInTransaction(client, {
                ...evidence,
                replyId: testId(330),
                revisionRequestId: revisionInput.requestId,
                reply: "The assumptions use the approved forecast recorded in this version."
              });
            case "approve_management_submission":
              return approveManagementSubmissionInTransaction(client, {
                ...evidence,
                dispositionId: testId(340),
                versionId: submitted.versionId,
                resultingDraftId: testId(341),
                signedContext,
                contextSha256: sha256Hex(signedContext)
              });
            case "reject_management_submission":
              return rejectManagementSubmissionInTransaction(client, {
                ...evidence,
                dispositionId: testId(340),
                versionId: submitted.versionId,
                reason: "The assumptions need further support before approval."
              });
          }
        });
      const expectedState = {
        request_management_revision: "revision_requested",
        reply_to_management_revision: "revision_requested",
        approve_management_submission: "approved_to_draft",
        reject_management_submission: "rejected"
      }[operation];
      const completed = await act();
      expect(completed).toMatchObject({
        replayed: false,
        operation,
        submissionId: submitted.submissionId,
        state: expectedState,
        rowVersion: operation === "reply_to_management_revision" ? 3n : 2n
      });
      // Full rows catch changed payloads, hashes and row versions as well as new records.
      const snapshot = async () =>
        (
          await pool.query(
            `select
               (select jsonb_agg(to_jsonb(record) order by record.id)
                  from management_submission_threads as record) as threads,
               (select jsonb_agg(to_jsonb(record) order by record.id)
                  from management_submission_versions as record) as versions,
               (select jsonb_agg(to_jsonb(record) order by record.id)
                  from management_revision_requests as record) as revision_requests,
               (select jsonb_agg(to_jsonb(record) order by record.id)
                  from management_revision_replies as record) as revision_replies,
               (select jsonb_agg(to_jsonb(record) order by record.id)
                  from management_submission_dispositions as record) as dispositions,
               (select jsonb_agg(to_jsonb(record) order by record.id)
                  from wizard_drafts as record) as drafts,
               (select jsonb_agg(to_jsonb(record) order by record.id)
                  from idempotency_records as record) as idempotency,
               (select jsonb_agg(to_jsonb(record) order by record.sequence)
                  from audit_events as record) as audit`
          )
        ).rows;
      const afterOriginal = await snapshot();
      await expect(act()).resolves.toEqual({
        replayed: true,
        operation,
        submissionId: submitted.submissionId,
        responseSha256: completed.responseSha256
      });
      expect(await snapshot()).toEqual(afterOriginal);

      const revoked = await pool.query(
        "update access_token_records set revoked_at=transaction_timestamp() where jti=$1 and revoked_at is null returning jti",
        [actor.context.tokenJti]
      );
      expect(revoked.rowCount).toBe(1);
      const beforeDeniedRetry = await snapshot();
      expect(beforeDeniedRetry).toEqual(afterOriginal);
      await expect(act()).rejects.toMatchObject({
        name: "ManagementWorkflowTransactionError",
        code: "submission_unavailable"
      });
      expect(await snapshot()).toEqual(beforeDeniedRetry);
    });
  });

  it.each(["revoked_token", "ended_membership"] as const)(
    "refuses a completed submission retry after %s without new effects",
    async (authorityLoss) => {
      await withDatabase(async (pool) => {
        const fixture = await seedActorsAndDocument(pool);
        const input = submissionInput(fixture);
        const retry = () =>
          request(pool, fixture.management, (client) =>
            submitDocumentToSecretariatInTransaction(client, {
              ...input,
              idempotencyRecordId: testId(310),
              auditEventId: testId(311)
            })
          );
        const created = await request(pool, fixture.management, (client) =>
          submitDocumentToSecretariatInTransaction(client, input)
        );
        await expect(retry()).resolves.toMatchObject({
          replayed: true,
          submissionId: input.submissionId,
          responseSha256: created.responseSha256
        });
        if (authorityLoss === "revoked_token") {
          await pool.query(
            "update access_token_records set revoked_at=transaction_timestamp() where jti=$1",
            [fixture.management.context.tokenJti]
          );
        } else {
          await pool.query(
            "update board_memberships set state='ended',active_until=transaction_timestamp() where member_id=$1 and board_id=$2",
            [fixture.management.memberId, fixture.management.boardId]
          );
        }
        const snapshot = async () =>
          (
            await pool.query(
              `select
                 (select count(*)::int from management_submission_threads) as threads,
                 (select count(*)::int from management_submission_versions) as versions,
                 (select count(*)::int from idempotency_records) as idempotency,
                 (select count(*)::int from audit_events) as audit`
            )
          ).rows;
        const before = await snapshot();
        await expect(retry()).rejects.toThrow();
        expect(await snapshot()).toEqual(before);
      });
    }
  );

  it("persists submission, revision/reply, resubmission, and inert approval with safe replay", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedActorsAndDocument(pool);
      const input = submissionInput(fixture);
      const created = await request(pool, fixture.management, (client) =>
        submitDocumentToSecretariatInTransaction(client, input)
      );
      expect(created).toMatchObject({
        replayed: false,
        operation: "submit_document_to_secretariat",
        submissionId: input.submissionId,
        state: "submitted",
        rowVersion: 1n,
        versionId: input.versionId
      });
      const replayed = await request(pool, fixture.management, (client) =>
        submitDocumentToSecretariatInTransaction(client, {
          ...input,
          idempotencyRecordId: testId(310),
          auditEventId: testId(311)
        })
      );
      expect(replayed).toEqual({
        replayed: true,
        operation: "submit_document_to_secretariat",
        submissionId: input.submissionId,
        responseSha256: created.responseSha256
      });

      await expect(
        request(pool, fixture.otherManagement, (client) =>
          requestManagementRevisionInTransaction(client, {
            organizationId: fixture.management.organizationId,
            requestId: testId(320),
            submissionId: input.submissionId,
            reason: "This actor is not the assigned secretary.",
            idempotencyRecordId: testId(321),
            idempotencyKey: "management-revision-wrong-actor-0001",
            auditEventId: testId(322)
          })
        )
      ).rejects.toThrow(/not authorized|unavailable/u);

      const revision = await request(pool, fixture.secretary, (client) =>
        requestManagementRevisionInTransaction(client, {
          organizationId: fixture.management.organizationId,
          requestId: testId(330),
          submissionId: input.submissionId,
          reason: "Please replace the operating assumptions with the approved figures.",
          idempotencyRecordId: testId(331),
          idempotencyKey: "management-revision-request-0001",
          auditEventId: testId(332)
        })
      );
      expect(revision).toMatchObject({
        state: "revision_requested",
        rowVersion: 2n,
        revisionRequestId: testId(330)
      });

      await expect(
        request(pool, fixture.otherManagement, (client) =>
          replyToManagementRevisionInTransaction(client, {
            organizationId: fixture.management.organizationId,
            replyId: testId(340),
            submissionId: input.submissionId,
            revisionRequestId: testId(330),
            reply: "An unrelated management member cannot reply.",
            idempotencyRecordId: testId(341),
            idempotencyKey: "management-reply-wrong-owner-0001",
            auditEventId: testId(342)
          })
        )
      ).rejects.toThrow(/not authorized|unavailable/u);

      const reply = await request(pool, fixture.management, (client) =>
        replyToManagementRevisionInTransaction(client, {
          organizationId: fixture.management.organizationId,
          replyId: testId(350),
          submissionId: input.submissionId,
          revisionRequestId: testId(330),
          reply: "The approved figures are now reflected in the attached immutable version.",
          idempotencyRecordId: testId(351),
          idempotencyKey: "management-revision-reply-0001",
          auditEventId: testId(352)
        })
      );
      expect(reply).toMatchObject({
        state: "revision_requested",
        rowVersion: 3n,
        replyId: testId(350)
      });

      const resubmitted = await request(pool, fixture.management, (client) =>
        resubmitManagementMaterialsInTransaction(client, {
          organizationId: fixture.management.organizationId,
          submissionId: input.submissionId,
          versionId: testId(360),
          documentReferences: [fixture.reference],
          reason: "Replaced the assumptions with the approved figures.",
          secretaryDelivery: {
            secretaryMemberId: fixture.secretary.memberId,
            noticeId: testId(361),
            feedId: testId(362)
          },
          sourceUpdateAuditEvents: [],
          idempotencyRecordId: testId(363),
          idempotencyKey: "management-materials-resubmit-0001",
          auditEventId: testId(364)
        })
      );
      expect(resubmitted).toMatchObject({
        replayed: false,
        submissionId: input.submissionId,
        version: 2,
        threadRowVersion: 4n
      });

      const signedContext = Buffer.from(
        '{"schemaVersion":"boardagent.management-draft-context.v1","reviewed":true}',
        "utf8"
      );
      const approved = await request(pool, fixture.secretary, (client) =>
        approveManagementSubmissionInTransaction(client, {
          organizationId: fixture.management.organizationId,
          dispositionId: testId(370),
          submissionId: input.submissionId,
          versionId: testId(360),
          resultingDraftId: testId(371),
          signedContext,
          contextSha256: sha256Hex(signedContext),
          idempotencyRecordId: testId(372),
          idempotencyKey: "management-submission-approve-0001",
          auditEventId: testId(373)
        })
      );
      expect(approved).toMatchObject({
        state: "approved_to_draft",
        rowVersion: 5n,
        resultingDraftId: testId(371)
      });

      const stored = await pool.query<{
        state: string;
        row_version: string;
        version_count: string;
        request_count: string;
        reply_count: string;
        disposition: string;
        draft_state: string;
        audit_types: string[];
      }>(
        `select thread.state,thread.row_version::text,
                (select count(*)::text from management_submission_versions
                  where thread_id=thread.id) as version_count,
                (select count(*)::text from management_revision_requests
                  where thread_id=thread.id) as request_count,
                (select count(*)::text from management_revision_replies as reply
                  join management_revision_requests as request on request.id=reply.request_id
                 where request.thread_id=thread.id) as reply_count,
                disposition.disposition,draft.state as draft_state,
                (select array_agg(event_type order by sequence) from audit_events) as audit_types
           from management_submission_threads as thread
           join management_submission_dispositions as disposition
             on disposition.thread_id=thread.id
           join wizard_drafts as draft on draft.id=disposition.resulting_draft_id
          where thread.id=$1`,
        [input.submissionId]
      );
      expect(stored.rows[0]).toEqual({
        state: "approved_to_draft",
        row_version: "5",
        version_count: "2",
        request_count: "1",
        reply_count: "1",
        disposition: "approved_to_draft",
        draft_state: "active",
        audit_types: [
          "management_submission_created",
          "management_revision_requested",
          "management_revision_replied",
          "management_submission_version_created",
          "management_submission_approved_to_draft"
        ]
      });
    });
  });

  it("serializes competing dispositions and rolls every mutation back if audit append fails", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedActorsAndDocument(pool);
      const input = submissionInput(fixture, 500);
      await request(pool, fixture.management, (client) =>
        submitDocumentToSecretariatInTransaction(client, input)
      );
      const signedContext = Buffer.alloc(32, 17);
      const results = await Promise.allSettled([
        request(pool, fixture.secretary, (client) =>
          approveManagementSubmissionInTransaction(client, {
            organizationId: fixture.management.organizationId,
            dispositionId: testId(510),
            submissionId: input.submissionId,
            versionId: input.versionId,
            resultingDraftId: testId(511),
            signedContext,
            contextSha256: sha256Hex(signedContext),
            idempotencyRecordId: testId(512),
            idempotencyKey: "management-disposition-race-approve-0001",
            auditEventId: testId(513)
          })
        ),
        request(pool, fixture.secretary, (client) =>
          rejectManagementSubmissionInTransaction(client, {
            organizationId: fixture.management.organizationId,
            dispositionId: testId(520),
            submissionId: input.submissionId,
            versionId: input.versionId,
            reason: "The submission is not ready for a confirmable draft.",
            idempotencyRecordId: testId(521),
            idempotencyKey: "management-disposition-race-reject-0001",
            auditEventId: testId(522)
          })
        )
      ]);
      expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(results.filter(({ status }) => status === "rejected")).toHaveLength(1);
      const counts = await pool.query<{ dispositions: string; drafts: string }>(
        `select (select count(*)::text from management_submission_dispositions
                  where thread_id=$1) as dispositions,
                (select count(*)::text from wizard_drafts where board_id=$2) as drafts`,
        [input.submissionId, fixture.management.boardId]
      );
      expect(counts.rows[0]?.dispositions).toBe("1");
      expect(Number(counts.rows[0]?.drafts ?? "0")).toBeLessThanOrEqual(1);
    });

    await withDatabase(async (pool) => {
      const fixture = await seedActorsAndDocument(pool);
      const input = submissionInput(fixture, 600);
      await pool.query(`
        create function fail_management_audit() returns trigger language plpgsql as $$
        begin
          if new.event_type='management_submission_created' then
            raise exception 'forced management audit failure';
          end if;
          return new;
        end
        $$;
        create trigger fail_management_audit before insert on audit_events
          for each row execute function fail_management_audit();
      `);
      await expect(
        request(pool, fixture.management, (client) =>
          submitDocumentToSecretariatInTransaction(client, input)
        )
      ).rejects.toThrow(/forced management audit failure/u);
      const counts = await pool.query<{
        threads: string;
        versions: string;
        idempotency: string;
      }>(
        `select (select count(*)::text from management_submission_threads) as threads,
                (select count(*)::text from management_submission_versions) as versions,
                (select count(*)::text from idempotency_records
                  where operation='submit_document_to_secretariat') as idempotency`
      );
      expect(counts.rows[0]).toEqual({ threads: "0", versions: "0", idempotency: "0" });
    });
  });
});
