import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
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

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_surface_management_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "surface-management-workflow-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function principal(
  actor: AuthorizedActorFixture,
  roles: readonly ("admin" | "member" | "observer" | "secretariat" | "management")[],
  scopes: readonly string[]
): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://management-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes,
    roles,
    boardIds: [actor.boardId]
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by management workflow test");
  },
  readResource: async () => {
    throw new Error("resource read not used by management workflow test");
  }
};

async function seedActorsAndDocument(pool: Pool) {
  const management = await seedAuthorizedActor(pool, {
    seatRole: "management",
    scopes: ["documents:read", "documents:contribute", "member:propose", "secretariat:message"]
  });
  const secretary = await seedAdditionalAuthorizedActor(pool, management, {
    idBase: 100,
    seatRole: "voting_member",
    scopes: ["governance:read", "secretariat:admin"],
    isSecretary: true
  });
  const documentId = testId(200);
  const versionId = testId(201);
  const validationAttemptId = testId(202);
  const content = Buffer.from("Accepted management board pack source\n", "utf8");
  const hash = sha256Hex(content);
  await pool.query("begin");
  try {
    await pool.query("set constraints all deferred");
    await pool.query(
      `insert into documents(
         id,organization_id,board_id,title,state,current_version_id,created_by
       ) values ($1,$2,$3,'Accepted management source','active',$4,$5)`,
      [documentId, management.organizationId, management.boardId, versionId, management.memberId]
    );
    await pool.query(
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
    await pool.query(
      `insert into document_validation_attempts(
         id,organization_id,board_id,actor_member_id,offered_media_type,offered_name,
         offered_length,offered_sha256,result,result_code,remediation,
         accepted_document_version_id
       ) values ($1,$2,$3,$4,'text/plain; charset=utf-8','management-source.txt',$5,$6,
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
    await pool.query("commit");
  } catch (error) {
    await pool.query("rollback");
    throw error;
  }
  return { management, secretary, reference: { documentId, versionId, sha256: hash } };
}

function service(pool: Pool): PgBoardAgentSurfaceService {
  let nextId = 10_000;
  return new PgBoardAgentSurfaceService(pool, {
    reads: unavailableReads,
    transaction: { assumeRole: "boardagent_server" },
    newId: () => testId(nextId++)
  });
}

async function seedQuestionActors(pool: Pool) {
  const member = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["governance:read", "management:question"]
  });
  const manager = await seedAdditionalAuthorizedActor(pool, member, {
    idBase: 500,
    seatRole: "management",
    scopes: ["governance:read", "management:question"]
  });
  const observer = await seedAdditionalAuthorizedActor(pool, member, {
    idBase: 550,
    seatRole: "observer",
    scopes: ["governance:read", "management:question"]
  });
  return { member, manager, observer };
}

describe("management workflow direct MCP surface", () => {
  it("submits, requests and answers revision, resubmits, approves to an inert draft, and replays safely", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedActorsAndDocument(pool);
      const surface = service(pool);
      const managementPrincipal = principal(
        fixture.management,
        ["management"],
        ["documents:read", "documents:contribute"]
      );
      const secretaryPrincipal = principal(
        fixture.secretary,
        ["secretariat"],
        ["governance:read", "secretariat:admin"]
      );
      const submissionId = testId(300);
      const submitInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-management-submit-0001",
        board_id: fixture.management.boardId,
        submission_id: submissionId,
        document_references: [
          {
            document_id: fixture.reference.documentId,
            version_id: fixture.reference.versionId,
            sha256: fixture.reference.sha256
          }
        ],
        purpose: "Quarterly operating report for secretariat review"
      } as const;

      const submitted = await surface.executeDirect(
        managementPrincipal,
        "submit_document_to_secretariat",
        submitInput
      );
      expect(submitted).toMatchObject({
        tool: "submit_document_to_secretariat",
        status: "accepted",
        reference: submissionId,
        data: { state: "submitted", version: 1, replayed: false }
      });
      const replayed = await surface.executeDirect(
        managementPrincipal,
        "submit_document_to_secretariat",
        submitInput
      );
      expect(replayed).toMatchObject({
        tool: "submit_document_to_secretariat",
        status: "already_applied",
        reference: submissionId,
        data: { replayed: true }
      });

      const revision = await surface.executeDirect(
        secretaryPrincipal,
        "request_management_revision",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "surface-management-revision-0001",
          submission_id: submissionId,
          reason: "Replace the assumptions with the approved figures."
        }
      );
      expect(revision).toMatchObject({
        status: "accepted",
        data: { state: "revision_requested", replayed: false }
      });
      const revisionRequestId = (revision.data as Record<string, JsonValue>)["revision_request_id"];
      expect(typeof revisionRequestId).toBe("string");
      if (typeof revisionRequestId !== "string") {
        throw new Error("surface revision request ID is unavailable");
      }

      const reply = await surface.executeDirect(
        managementPrincipal,
        "reply_to_management_revision",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "surface-management-reply-0001",
          submission_id: submissionId,
          revision_request_id: revisionRequestId,
          reply: "The immutable source now contains the approved figures."
        }
      );
      expect(reply).toMatchObject({ status: "accepted", data: { replayed: false } });

      const resubmitted = await surface.executeDirect(
        managementPrincipal,
        "resubmit_management_materials",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "surface-management-resubmit-0001",
          submission_id: submissionId,
          document_references: submitInput.document_references,
          reason: "Replaced the assumptions with the approved figures."
        }
      );
      expect(resubmitted).toMatchObject({
        status: "accepted",
        data: { state: "resubmitted", version: 2, replayed: false }
      });
      const resubmittedVersionId = (resubmitted.data as Record<string, JsonValue>)["version_id"];
      expect(typeof resubmittedVersionId).toBe("string");
      if (typeof resubmittedVersionId !== "string") {
        throw new Error("surface resubmission version ID is unavailable");
      }

      const approved = await surface.executeDirect(
        secretaryPrincipal,
        "approve_management_submission",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "surface-management-approve-0001",
          submission_id: submissionId,
          version_id: resubmittedVersionId
        }
      );
      expect(approved).toMatchObject({
        status: "accepted",
        data: { state: "approved_to_draft", replayed: false }
      });

      const stored = await pool.query<{
        state: string;
        version_count: string;
        request_count: string;
        reply_count: string;
        draft_count: string;
      }>(
        `select thread.state,
                (select count(*)::text from management_submission_versions
                  where thread_id=thread.id) as version_count,
                (select count(*)::text from management_revision_requests
                  where thread_id=thread.id) as request_count,
                (select count(*)::text from management_revision_replies as reply
                  join management_revision_requests as request on request.id=reply.request_id
                 where request.thread_id=thread.id) as reply_count,
                (select count(*)::text from wizard_drafts as draft
                  join management_submission_dispositions as disposition
                    on disposition.resulting_draft_id=draft.id
                 where disposition.thread_id=thread.id and draft.state='active') as draft_count
           from management_submission_threads as thread where thread.id=$1`,
        [submissionId]
      );
      expect(stored.rows[0]).toEqual({
        state: "approved_to_draft",
        version_count: "2",
        request_count: "1",
        reply_count: "1",
        draft_count: "1"
      });
    });
  });

  it("submits and disposes proposals and completes a secretariat request thread", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedActorsAndDocument(pool);
      const surface = service(pool);
      const managementPrincipal = principal(
        fixture.management,
        ["management"],
        ["documents:read", "documents:contribute", "member:propose", "secretariat:message"]
      );
      const secretaryPrincipal = principal(
        fixture.secretary,
        ["secretariat"],
        ["governance:read", "secretariat:admin", "secretariat:message"]
      );
      const proposalPayload = {
        schema_version: "boardagent.proposal-details.v1",
        values: { requested_action: "schedule_site_review" }
      } as const;

      const approvedProposalId = testId(400);
      const proposed = await surface.executeDirect(managementPrincipal, "propose_action", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-proposal-submit-0001",
        proposal_id: approvedProposalId,
        board_id: fixture.management.boardId,
        proposal_type: "meeting",
        title: "Schedule the quarterly site review",
        payload: proposalPayload,
        references: []
      });
      expect(proposed).toMatchObject({ status: "accepted", data: { state: "pending" } });

      const approvedDraftId = testId(401);
      const approved = await surface.executeDirect(secretaryPrincipal, "approve_proposal", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-proposal-approve-0001",
        proposal_id: approvedProposalId,
        resulting_draft_id: approvedDraftId,
        draft_type: "meeting"
      });
      expect(approved).toMatchObject({
        status: "accepted",
        data: {
          state: "approved_to_draft",
          resulting_draft_id: approvedDraftId,
          replayed: false
        }
      });

      const withdrawnProposalId = testId(410);
      await surface.executeDirect(managementPrincipal, "propose_action", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-proposal-submit-0002",
        proposal_id: withdrawnProposalId,
        board_id: fixture.management.boardId,
        proposal_type: "document",
        title: "Withdrawn proposal",
        payload: proposalPayload,
        references: []
      });
      const withdrawn = await surface.executeDirect(managementPrincipal, "withdraw_proposal", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-proposal-withdraw-0001",
        proposal_id: withdrawnProposalId
      });
      expect(withdrawn).toMatchObject({
        status: "accepted",
        data: { state: "withdrawn", replayed: false }
      });

      const rejectedProposalId = testId(420);
      await surface.executeDirect(managementPrincipal, "propose_action", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-proposal-submit-0003",
        proposal_id: rejectedProposalId,
        board_id: fixture.management.boardId,
        proposal_type: "other",
        title: "Rejected proposal",
        payload: proposalPayload,
        references: []
      });
      const rejected = await surface.executeDirect(secretaryPrincipal, "reject_proposal", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-proposal-reject-0001",
        proposal_id: rejectedProposalId,
        reason: "The request is outside the approved quarterly agenda."
      });
      expect(rejected).toMatchObject({
        status: "accepted",
        data: { state: "rejected", replayed: false }
      });

      const requestId = testId(430);
      const requested = await surface.executeDirect(managementPrincipal, "ask_secretariat", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-secretariat-request-0001",
        request_id: requestId,
        board_id: fixture.management.boardId,
        topic: "Meeting pack timing",
        message: "Please confirm when the final meeting pack will be available.",
        references: []
      });
      expect(requested).toMatchObject({ status: "accepted", data: { state: "open" } });
      const answered = await surface.executeDirect(
        secretaryPrincipal,
        "reply_secretariat_request",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "surface-secretariat-reply-0001",
          request_id: requestId,
          reply: "The final meeting pack will be available on Friday at 12:00 UTC."
        }
      );
      expect(answered).toMatchObject({ status: "accepted", data: { state: "answered" } });
      const closed = await surface.executeDirect(managementPrincipal, "close_secretariat_request", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-secretariat-close-0001",
        request_id: requestId
      });
      expect(closed).toMatchObject({
        status: "accepted",
        data: { state: "closed", replayed: false }
      });

      const states = await pool.query<{
        approved: string;
        closed: string;
        rejected: string;
        request_state: string;
        withdrawn: string;
      }>(
        `select
           (select state from proposals where id=$1) as approved,
           (select state from proposals where id=$2) as withdrawn,
           (select state from proposals where id=$3) as rejected,
           (select state from wizard_drafts where id=$4) as closed,
           (select state from secretariat_requests where id=$5) as request_state`,
        [approvedProposalId, withdrawnProposalId, rejectedProposalId, approvedDraftId, requestId]
      );
      expect(states.rows[0]).toEqual({
        approved: "approved_to_draft",
        withdrawn: "withdrawn",
        rejected: "rejected",
        closed: "active",
        request_state: "closed"
      });
    });
  });

  it("records member and observer questions, management answers, and a newly-due follow-up", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedQuestionActors(pool);
      const surface = service(pool);
      const memberPrincipal = principal(
        fixture.member,
        ["member"],
        ["governance:read", "management:question"]
      );
      const managerPrincipal = principal(
        fixture.manager,
        ["management"],
        ["governance:read", "management:question"]
      );
      const observerPrincipal = principal(
        fixture.observer,
        ["observer"],
        ["governance:read", "management:question"]
      );
      const questionId = testId(600);

      const asked = await surface.executeDirect(memberPrincipal, "ask_management", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-management-question-0001",
        board_id: fixture.member.boardId,
        question_id: questionId,
        owner_member_id: fixture.manager.memberId,
        due_at: "2099-09-03T12:00:00Z",
        question: "What changed in the operating forecast?",
        citations: []
      });
      expect(asked).toMatchObject({
        status: "accepted",
        reference: questionId,
        data: { state: "pending", turn_ordinal: 1, replayed: false }
      });
      const askedReplay = await surface.executeDirect(memberPrincipal, "ask_management", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-management-question-0001",
        board_id: fixture.member.boardId,
        question_id: questionId,
        owner_member_id: fixture.manager.memberId,
        due_at: "2099-09-03T12:00:00Z",
        question: "What changed in the operating forecast?",
        citations: []
      });
      expect(askedReplay).toMatchObject({ status: "already_applied", data: { replayed: true } });

      const answered = await surface.executeDirect(managerPrincipal, "answer_management_question", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-management-answer-0001",
        question_id: questionId,
        answer: "Commodity prices fell while exploration costs remained within plan."
      });
      expect(answered).toMatchObject({
        status: "accepted",
        data: { state: "answered", turn_ordinal: 2, replayed: false }
      });

      const followedUp = await surface.executeDirect(
        memberPrincipal,
        "follow_up_management_question",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "surface-management-follow-up-0001",
          question_id: questionId,
          follow_up: "Please quantify the exploration-cost variance.",
          due_at: "2099-09-10T12:00:00Z"
        }
      );
      expect(followedUp).toMatchObject({
        status: "accepted",
        data: {
          state: "pending",
          due_at: "2099-09-10T12:00:00Z",
          turn_ordinal: 3,
          replayed: false
        }
      });

      const observerQuestionId = testId(610);
      const observerAsked = await surface.executeDirect(observerPrincipal, "ask_management", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-observer-question-0001",
        board_id: fixture.member.boardId,
        question_id: observerQuestionId,
        owner_member_id: fixture.manager.memberId,
        due_at: "2099-09-11T12:00:00Z",
        question: "Which exploration permits remain outstanding?",
        citations: []
      });
      expect(observerAsked).toMatchObject({
        status: "accepted",
        reference: observerQuestionId,
        data: { state: "pending", replayed: false }
      });

      const stored = await pool.query<{
        current_ordinal: number;
        due_at: string;
        owner_pending: string;
        state: string;
      }>(
        `select question.state,turn.ordinal as current_ordinal,
                to_char(question.due_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"') as due_at,
                (select count(*)::text from pending_action_feed as feed
                  where feed.object_type='question' and feed.object_id=question.id
                    and feed.action_type='management_question_due' and feed.state='pending')
                  as owner_pending
           from management_questions as question
           join management_question_turns as turn on turn.id=question.current_turn_id
          where question.id=$1`,
        [questionId]
      );
      expect(stored.rows[0]).toEqual({
        state: "pending",
        current_ordinal: 3,
        due_at: "2099-09-10T12:00:00Z",
        owner_pending: "1"
      });
    });
  });
});
