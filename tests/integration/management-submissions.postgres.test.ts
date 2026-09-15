import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  migrate,
  resubmitManagementMaterialsInTransaction,
  withRequestTransaction,
  type ResubmitManagementMaterialsInput
} from "../../lib/db/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
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
  const database = `boardagent_management_submission_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "management-submission-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

interface ManagementSubmissionFixture {
  readonly actor: AuthorizedActorFixture;
  readonly secretary: AuthorizedActorFixture;
  readonly submissionId: string;
  readonly priorVersionId: string;
  readonly priorPayloadSha256: string;
  readonly documentReference: {
    readonly documentId: string;
    readonly versionId: string;
    readonly sha256: string;
  };
}

async function seedManagementSubmission(
  pool: Pool,
  options: { readonly acceptedDocument?: boolean } = {}
): Promise<ManagementSubmissionFixture> {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "management",
    scopes: ["documents:read", "documents:contribute"]
  });
  const secretary = await seedAdditionalAuthorizedActor(pool, actor, {
    idBase: 100,
    seatRole: "voting_member",
    scopes: ["governance:read"],
    isSecretary: true
  });
  const documentId = testId(200);
  const documentVersionId = testId(201);
  const validationAttemptId = testId(202);
  const submissionId = testId(210);
  const priorVersionId = testId(211);
  const revisionRequestId = testId(212);
  const documentSha256 = testHash(60);
  const priorPayloadSha256 = testHash(61);
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("set constraints all deferred");
    await client.query(
      `insert into documents(
         id,organization_id,board_id,title,state,current_version_id,created_by
       ) values ($1,$2,$3,'Accepted management source','active',$4,$5)`,
      [documentId, actor.organizationId, actor.boardId, documentVersionId, actor.memberId]
    );
    await client.query(
      `insert into document_versions(
         id,organization_id,board_id,document_id,version,media_type,
         canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,
         created_by
       ) values ($1,$2,$3,$4,1,'text/plain; charset=utf-8','RFC8785+NFC-LF-v1',
         $5,$6,$7,'{}',$8)`,
      [
        documentVersionId,
        actor.organizationId,
        actor.boardId,
        documentId,
        Buffer.from("Accepted management source\n", "utf8"),
        Buffer.byteLength("Accepted management source\n"),
        documentSha256,
        actor.memberId
      ]
    );
    if (options.acceptedDocument !== false) {
      await client.query(
        `insert into document_validation_attempts(
           id,organization_id,board_id,actor_member_id,offered_media_type,offered_name,
           offered_length,offered_sha256,result,result_code,remediation,
           accepted_document_version_id
         ) values ($1,$2,$3,$4,'text/plain; charset=utf-8','management.txt',$5,$6,
           'accepted','accepted','No remediation required.',$7)`,
        [
          validationAttemptId,
          actor.organizationId,
          actor.boardId,
          actor.memberId,
          Buffer.byteLength("Accepted management source\n"),
          documentSha256,
          documentVersionId
        ]
      );
    }
    await client.query(
      `insert into management_submission_threads(
         id,organization_id,board_id,management_owner_ids,assigned_secretary_id,
         state,current_version_id,created_by
       ) values ($1,$2,$3,array[$4]::uuid[],$5,'revision_requested',$6,$4)`,
      [
        submissionId,
        actor.organizationId,
        actor.boardId,
        actor.memberId,
        secretary.memberId,
        priorVersionId
      ]
    );
    await client.query(
      `insert into management_submission_versions(
         id,organization_id,board_id,thread_id,version,schema_version,canonical_payload,
         document_references,payload_sha256,author_member_id,change_reason,supersedes_id
       ) values ($1,$2,$3,$4,1,'boardagent.management-submission.v1','{}','[]',$5,$6,
         'Initial accepted submission',null)`,
      [
        priorVersionId,
        actor.organizationId,
        actor.boardId,
        submissionId,
        priorPayloadSha256,
        actor.memberId
      ]
    );
    await client.query(
      `insert into management_revision_requests(
         id,organization_id,board_id,thread_id,submission_version_id,
         secretary_member_id,request_text,request_sha256
       ) values ($1,$2,$3,$4,$5,$6,'Please replace the source with the corrected version.',$7)`,
      [
        revisionRequestId,
        actor.organizationId,
        actor.boardId,
        submissionId,
        priorVersionId,
        secretary.memberId,
        testHash(62)
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
    actor,
    secretary,
    submissionId,
    priorVersionId,
    priorPayloadSha256: priorPayloadSha256.toString("hex"),
    documentReference: {
      documentId,
      versionId: documentVersionId,
      sha256: documentSha256.toString("hex")
    }
  };
}

async function seedLinkedOpenVote(pool: Pool, fixture: ManagementSubmissionFixture) {
  const approvalRuleId = testId(300);
  const governanceProfileId = testId(301);
  const rulesetId = testId(302);
  const voteId = testId(303);
  const resolutionId = testId(304);
  const packageId = testId(305);
  const matterTypeId = testId(306);
  const selectedRulesetRuleId = testId(307);
  const matterEvaluationId = testId(308);
  const componentId = testId(309);
  const packageSha256 = testHash(81);
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query(
      `insert into approval_rules(
         id,organization_id,board_id,schema_version,threshold_numerator,
         threshold_denominator,quorum_numerator,quorum_denominator,approval_denominator,
         abstentions_count_for_quorum,tie_behavior,proxy_policy,close_mode,canonical_sha256,
         created_by
       ) values ($1,$2,$3,'boardagent.approval-rule.v1',1,2,1,2,'eligible',true,'reject',
         'principal_supersedes_proxy','secretariat_confirmed',$4,$5)`,
      [
        approvalRuleId,
        fixture.actor.organizationId,
        fixture.actor.boardId,
        testHash(70),
        fixture.actor.memberId
      ]
    );
    await client.query(
      `insert into governance_profiles(
         id,organization_id,board_id,version,state,schema_version,canonical_payload,
         canonical_sha256,source_agreement_references,created_by
       ) values ($1,$2,$3,1,'draft','boardagent.governance-profile.v1','{}',$4,'[]',$5)`,
      [
        governanceProfileId,
        fixture.actor.organizationId,
        fixture.actor.boardId,
        testHash(71),
        fixture.actor.memberId
      ]
    );
    await client.query(
      `insert into rulesets(
         id,organization_id,board_id,profile_id,version,state,schema_version,
         canonical_payload,canonical_sha256,created_by
       ) values ($1,$2,$3,$4,1,'draft','boardagent.ruleset.v1','{}',$5,$6)`,
      [
        rulesetId,
        fixture.actor.organizationId,
        fixture.actor.boardId,
        governanceProfileId,
        testHash(72),
        fixture.actor.memberId
      ]
    );
    await client.query(
      `insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256)
       values ($1,$2,'management_submission','Management submission',
         '{"code":"management_submission","fields":[]}',$3)`,
      [matterTypeId, rulesetId, testHash(73)]
    );
    await client.query(
      `insert into ruleset_rules(
         id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
         approval_rule_id,canonical_sha256
       ) values ($1,$2,$3,1,1,'{"kind":"exists","field":"management_submission"}',$4,$5)`,
      [selectedRulesetRuleId, rulesetId, matterTypeId, approvalRuleId, testHash(74)]
    );
    await client.query(
      `insert into matter_evaluations(
         id,organization_id,board_id,requester_member_id,profile_id,ruleset_id,
         matter_type_id,engine_version,canonical_facts,facts_sha256,result,matched_rule_id,
         candidate_rule_ids,citation_snapshot,result_details,result_sha256
       ) values ($1,$2,$3,$4,$5,$6,$7,'boardagent.rules-engine.v1','{}',$8,'matched',$9,
         array[$9]::uuid[],'[]','{}',$10)`,
      [
        matterEvaluationId,
        fixture.actor.organizationId,
        fixture.actor.boardId,
        fixture.actor.memberId,
        governanceProfileId,
        rulesetId,
        matterTypeId,
        testHash(75),
        selectedRulesetRuleId,
        testHash(76)
      ]
    );
    await client.query(
      `insert into votes(
         id,organization_id,board_id,title,approval_rule_id,governance_profile_id,
         ruleset_id,close_mode,created_by
       ) values ($1,$2,$3,'Linked management decision',$4,$5,$6,
         'secretariat_confirmed',$7)`,
      [
        voteId,
        fixture.actor.organizationId,
        fixture.actor.boardId,
        approvalRuleId,
        governanceProfileId,
        rulesetId,
        fixture.actor.memberId
      ]
    );
    await client.query(
      `insert into resolution_versions(
         id,organization_id,board_id,vote_id,version,canonical_schema,canonical_text,
         canonical_sha256,author_member_id
       ) values ($1,$2,$3,$4,1,'boardagent.resolution.v1','Approve the management proposal',$5,$6)`,
      [
        resolutionId,
        fixture.actor.organizationId,
        fixture.actor.boardId,
        voteId,
        testHash(77),
        fixture.actor.memberId
      ]
    );
    await client.query(
      `insert into decision_packages(
         id,organization_id,board_id,vote_id,version,schema_version,resolution_version_id,
         resolution_sha256,submission_manifest,submission_manifest_sha256,document_manifest,
         document_manifest_sha256,question_cutoff_manifest,question_cutoff_sha256,
         approval_rule_id,approval_rule_sha256,governance_profile_id,
         governance_profile_sha256,ruleset_id,ruleset_sha256,matter_evaluation_id,
         matter_evaluation_result_sha256,selected_ruleset_rule_id,
         selected_ruleset_rule_sha256,rule_override_id,rule_override_sha256,
         electorate_sha256,canonical_payload,package_sha256,created_by
       ) values ($1,$2,$3,$4,1,'boardagent.decision-package.v1',$5,$6,$7,$8,'[]',$9,
         '[]',$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,null,null,$21,'{}',$22,$23)`,
      [
        packageId,
        fixture.actor.organizationId,
        fixture.actor.boardId,
        voteId,
        resolutionId,
        testHash(77),
        JSON.stringify([
          {
            type: "management_submission",
            ordinal: 0,
            id: fixture.priorVersionId,
            version: 1,
            sha256: fixture.priorPayloadSha256
          }
        ]),
        testHash(78),
        testHash(79),
        testHash(80),
        approvalRuleId,
        testHash(70),
        governanceProfileId,
        testHash(71),
        rulesetId,
        testHash(72),
        matterEvaluationId,
        testHash(76),
        selectedRulesetRuleId,
        testHash(74),
        testHash(82),
        packageSha256,
        fixture.actor.memberId
      ]
    );
    await client.query(
      `insert into decision_package_components(
         id,decision_package_id,component_class,ordinal,object_type,object_id,
         object_version,object_sha256
       ) values ($1,$2,'submission',0,'management_submission_version',$3,1,$4)`,
      [
        componentId,
        packageId,
        fixture.priorVersionId,
        Buffer.from(fixture.priorPayloadSha256, "hex")
      ]
    );
    await client.query(
      `update votes
          set state='open',current_resolution_version_id=$1,current_decision_package_id=$2,
              electorate_sha256=$3,deadline_at='2099-09-10T12:00:00Z',
              matter_evaluation_id=$4,selected_ruleset_rule_id=$5,
              opened_at=transaction_timestamp(),row_version=row_version+1
        where id=$6`,
      [resolutionId, packageId, testHash(82), matterEvaluationId, selectedRulesetRuleId, voteId]
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
  return { voteId, packageId };
}

function resubmissionInput(
  fixture: ManagementSubmissionFixture,
  base: number,
  options: {
    readonly key: string;
    readonly reason?: string;
    readonly linkedVoteId?: string;
  }
): ResubmitManagementMaterialsInput {
  return {
    organizationId: fixture.actor.organizationId,
    submissionId: fixture.submissionId,
    versionId: testId(base),
    documentReferences: [fixture.documentReference],
    reason: options.reason ?? "Corrected the source document requested by the secretary.",
    idempotencyRecordId: testId(base + 1),
    idempotencyKey: options.key,
    auditEventId: testId(base + 2),
    secretaryDelivery: {
      secretaryMemberId: fixture.secretary.memberId,
      noticeId: testId(base + 3),
      feedId: testId(base + 4)
    },
    sourceUpdateAuditEvents: options.linkedVoteId
      ? [
          {
            voteId: options.linkedVoteId,
            causeId: testId(base + 5),
            auditEventId: testId(base + 6)
          }
        ]
      : []
  };
}

function resubmit(
  pool: Pool,
  actor: AuthorizedActorFixture,
  input: ResubmitManagementMaterialsInput
) {
  return withRequestTransaction(
    pool,
    actor.context,
    (client) => resubmitManagementMaterialsInTransaction(client, input),
    { assumeRole: "boardagent_server" }
  );
}

describe("management submission resubmission transaction", () => {
  it("appends one immutable revision, notifies the secretary, and blocks the exact linked vote", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedManagementSubmission(pool);
      const linked = await seedLinkedOpenVote(pool, fixture);
      const input = resubmissionInput(fixture, 400, {
        key: "management-resubmit-linked-0001",
        linkedVoteId: linked.voteId
      });
      const created = await resubmit(pool, fixture.actor, input);
      expect(created).toMatchObject({
        replayed: false,
        submissionId: fixture.submissionId,
        versionId: testId(400),
        version: 2,
        threadRowVersion: 2n,
        sourceUpdateVoteIds: [linked.voteId]
      });

      const replayed = await resubmit(
        pool,
        fixture.actor,
        resubmissionInput(fixture, 420, {
          key: "management-resubmit-linked-0001",
          linkedVoteId: linked.voteId
        })
      );
      expect(replayed).toMatchObject({
        replayed: true,
        versionId: testId(400),
        version: 2,
        responseSha256: created.responseSha256
      });

      const stored = await pool.query<{
        audit_types: string[];
        cause_count: string;
        current_version_id: string;
        feed_count: string;
        notice_count: string;
        row_version: string;
        state: string;
        version_count: string;
        vote_state: string;
      }>(
        `select thread.state,thread.current_version_id,thread.row_version::text,
                vote.state as vote_state,
                (select count(*)::text from management_submission_versions
                  where thread_id=thread.id) as version_count,
                (select count(*)::text from vote_source_update_causes
                  where vote_id=vote.id and source_class='management_submission'
                    and source_id=thread.id and source_version=2) as cause_count,
                (select count(*)::text from notices
                  where object_id=thread.id and recipient_member_id=$3) as notice_count,
                (select count(*)::text from pending_action_feed
                  where object_id=thread.id and member_id=$3 and state='pending') as feed_count,
                (select array_agg(event_type order by sequence) from audit_events) as audit_types
           from management_submission_threads as thread
           join votes as vote on vote.id=$2
          where thread.id=$1`,
        [fixture.submissionId, linked.voteId, fixture.secretary.memberId]
      );
      expect(stored.rows[0]).toEqual({
        state: "resubmitted",
        current_version_id: testId(400),
        row_version: "2",
        vote_state: "source_update_pending",
        version_count: "2",
        cause_count: "1",
        notice_count: "1",
        feed_count: "1",
        audit_types: ["management_submission_version_created", "vote_source_update_pending"]
      });
      const version = await pool.query<{
        canonical_payload: Buffer;
        document_references: unknown;
        payload_sha256: string;
        supersedes_id: string;
        version: number;
      }>(
        `select canonical_payload,document_references,encode(payload_sha256,'hex') as payload_sha256,
                supersedes_id,version
           from management_submission_versions where id=$1`,
        [testId(400)]
      );
      expect(version.rows[0]).toMatchObject({
        document_references: [fixture.documentReference],
        supersedes_id: fixture.priorVersionId,
        version: 2,
        payload_sha256: created.payloadSha256
      });
      expect(JSON.parse(version.rows[0]!.canonical_payload.toString("utf8"))).toMatchObject({
        submissionId: fixture.submissionId,
        versionId: testId(400),
        version: 2,
        documentReferences: [fixture.documentReference]
      });
      await expect(
        pool.query(
          "update management_submission_versions set change_reason='tampered' where id=$1",
          [testId(400)]
        )
      ).rejects.toThrow(/immutable evidence/u);
    });
  });

  it("serializes competing revisions so exactly one next version wins", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedManagementSubmission(pool);
      const first = resubmit(
        pool,
        fixture.actor,
        resubmissionInput(fixture, 500, {
          key: "management-resubmit-race-first-0001",
          reason: "First competing corrected source."
        })
      );
      const second = resubmit(
        pool,
        fixture.actor,
        resubmissionInput(fixture, 520, {
          key: "management-resubmit-race-second-0001",
          reason: "Second competing corrected source."
        })
      );
      const results = await Promise.allSettled([first, second]);
      expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(results.filter(({ status }) => status === "rejected")).toHaveLength(1);
      const rejected = results.find(({ status }) => status === "rejected");
      expect(rejected).toMatchObject({ status: "rejected" });
      if (rejected?.status === "rejected") {
        expect(String(rejected.reason)).toMatch(
          /management resubmission is unavailable|not awaiting a revision/u
        );
      }
      const readback = await pool.query<{
        audit_count: string;
        row_version: string;
        state: string;
        version_count: string;
        versions: number[];
      }>(
        `select thread.state,thread.row_version::text,
                (select count(*)::text from management_submission_versions
                  where thread_id=thread.id) as version_count,
                (select array_agg(version order by version) from management_submission_versions
                  where thread_id=thread.id) as versions,
                (select count(*)::text from audit_events) as audit_count
           from management_submission_threads as thread where thread.id=$1`,
        [fixture.submissionId]
      );
      expect(readback.rows[0]).toEqual({
        state: "resubmitted",
        row_version: "2",
        version_count: "2",
        versions: [1, 2],
        audit_count: "1"
      });
    });
  });

  it("rejects unaccepted document versions and rolls back every write when audit append fails", async () => {
    await withDatabase(async (pool) => {
      const unavailable = await seedManagementSubmission(pool, { acceptedDocument: false });
      await expect(
        resubmit(
          pool,
          unavailable.actor,
          resubmissionInput(unavailable, 600, { key: "management-resubmit-unaccepted-0001" })
        )
      ).rejects.toThrow(/exact accepted document versions/u);
      const unavailableReadback = await pool.query<{
        idempotency_count: string;
        state: string;
        version_count: string;
      }>(
        `select thread.state,
                (select count(*)::text from management_submission_versions) as version_count,
                (select count(*)::text from idempotency_records
                  where operation='resubmit_management_materials') as idempotency_count
           from management_submission_threads as thread where thread.id=$1`,
        [unavailable.submissionId]
      );
      expect(unavailableReadback.rows[0]).toEqual({
        state: "revision_requested",
        version_count: "1",
        idempotency_count: "0"
      });
    });

    await withDatabase(async (pool) => {
      const fixture = await seedManagementSubmission(pool);
      await pool.query(`
        create function boardagent_test_reject_management_audit()
        returns trigger language plpgsql as $$
        begin
          if new.event_type='management_submission_version_created' then
            raise exception 'synthetic audit sink failure';
          end if;
          return new;
        end
        $$;
        create trigger boardagent_test_reject_management_audit
          before insert on audit_events
          for each row execute function boardagent_test_reject_management_audit()
      `);
      await expect(
        resubmit(
          pool,
          fixture.actor,
          resubmissionInput(fixture, 620, { key: "management-resubmit-audit-failure-0001" })
        )
      ).rejects.toThrow(/synthetic audit sink failure/u);
      const rolledBack = await pool.query<{
        audit_count: string;
        feed_count: string;
        idempotency_count: string;
        notice_count: string;
        row_version: string;
        state: string;
        version_count: string;
      }>(
        `select thread.state,thread.row_version::text,
                (select count(*)::text from management_submission_versions) as version_count,
                (select count(*)::text from notices) as notice_count,
                (select count(*)::text from pending_action_feed) as feed_count,
                (select count(*)::text from audit_events) as audit_count,
                (select count(*)::text from idempotency_records
                  where operation='resubmit_management_materials') as idempotency_count
           from management_submission_threads as thread where thread.id=$1`,
        [fixture.submissionId]
      );
      expect(rolledBack.rows[0]).toEqual({
        state: "revision_requested",
        row_version: "1",
        version_count: "1",
        notice_count: "0",
        feed_count: "0",
        audit_count: "0",
        idempotency_count: "0"
      });
    });
  });
});
