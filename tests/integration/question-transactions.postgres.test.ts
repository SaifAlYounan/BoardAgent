import { createHash } from "node:crypto";
import { copyFile, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  prepareManagementQuestion,
  prepareManagementQuestionTurn
} from "../../lib/domain/src/index.js";
import {
  answerManagementQuestionInTransaction,
  askManagementQuestionInTransaction,
  followUpManagementQuestionInTransaction,
  inspectFeedConsistencyInTransaction,
  markDueBoardQuestionsOverdueInTransaction,
  migrate,
  reconcileFeedEntitlementsInTransaction,
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

async function withDatabase<T>(
  run: (pool: Pool) => Promise<T>,
  migrationDirectory = MIGRATIONS
): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_questions_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, migrationDirectory, "question-transactions-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedManagementOwner(
  pool: Pool,
  organizationId: string,
  boardId: string,
  suffix = 20
): Promise<string> {
  const ownerId = testId(suffix);
  await pool.query(
    "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Management owner','Management owner','active')",
    [ownerId, organizationId]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'management',false,0,'active')`,
    [testId(suffix + 1), organizationId, boardId, ownerId]
  );
  return ownerId;
}

async function seedQuestionWorkflow(pool: Pool, dueAt = "2099-09-02T12:00:00Z") {
  const asker = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["management:question", "governance:read"]
  });
  const manager = await seedAdditionalAuthorizedActor(pool, asker, {
    idBase: 100,
    seatRole: "management",
    scopes: ["management:question"]
  });
  const prepared = prepareManagementQuestion({
    questionId: testId(30),
    boardId: asker.boardId,
    question: "What changed in the forecast?\n",
    assignedOwnerIds: [manager.memberId],
    dueAt,
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
        idempotencyKey: "question-workflow-create-0001",
        visibilityRecordIds: [testId(34)],
        ownerDeliveries: [
          { ownerMemberId: manager.memberId, noticeId: testId(35), feedId: testId(36) }
        ]
      }),
    { assumeRole: "boardagent_server" }
  );
  return { asker, manager, prepared };
}

async function answerFeedQuestion(
  pool: Pool,
  workflow: Awaited<ReturnType<typeof seedQuestionWorkflow>>
) {
  const { asker, manager, prepared } = workflow;
  return withRequestTransaction(
    pool,
    manager.context,
    (client) =>
      answerManagementQuestionInTransaction(client, {
        organizationId: asker.organizationId,
        prepared: prepareManagementQuestionTurn({
          questionId: prepared.questionId,
          turnKind: "answer",
          text: "The synthetic permit register is now current.",
          citations: []
        }),
        turnId: testId(83_200),
        answerRecordId: testId(83_201),
        auditEventId: testId(83_202),
        idempotencyRecordId: testId(83_203),
        idempotencyKey: "feed-question-history-answer-0001",
        askerDelivery: {
          recipientMemberId: asker.memberId,
          noticeId: testId(83_204),
          feedId: testId(83_205)
        },
        ownerResolutions: [{ ownerMemberId: manager.memberId, tombstoneId: testId(83_206) }],
        sourceUpdateAuditEvents: []
      }),
    { assumeRole: "boardagent_server" }
  );
}

async function followUpFeedQuestion(
  pool: Pool,
  workflow: Awaited<ReturnType<typeof seedQuestionWorkflow>>
) {
  const { asker, manager, prepared } = workflow;
  return withRequestTransaction(
    pool,
    asker.context,
    (client) =>
      followUpManagementQuestionInTransaction(client, {
        organizationId: asker.organizationId,
        prepared: prepareManagementQuestionTurn({
          questionId: prepared.questionId,
          turnKind: "follow_up",
          text: "When will the next register review occur?",
          citations: [],
          dueAt: "2099-09-04T12:00:00Z"
        }),
        turnId: testId(83_210),
        auditEventId: testId(83_211),
        idempotencyRecordId: testId(83_212),
        idempotencyKey: "feed-question-history-follow-up-0001",
        ownerDeliveries: [
          { ownerMemberId: manager.memberId, noticeId: testId(83_213), feedId: testId(83_214) }
        ],
        sourceUpdateAuditEvents: []
      }),
    { assumeRole: "boardagent_server" }
  );
}

async function questionFeedHistory(pool: Pool): Promise<Record<string, unknown>> {
  return (
    await pool.query(`select jsonb_build_object(
      'questions',(select jsonb_agg(to_jsonb(q) order by q.id) from management_questions q),
      'turns',(select jsonb_agg(to_jsonb(t) order by t.id) from management_question_turns t),
      'answers',(select jsonb_agg(to_jsonb(a) order by a.id) from management_question_answers a),
      'visibility',(select jsonb_agg(to_jsonb(v) order by v.id) from question_visibility v),
      'notices',(select jsonb_agg(to_jsonb(n) order by n.id) from notices n),
      'feed',(select jsonb_agg(to_jsonb(f) order by f.id) from pending_action_feed f),
      'tombstones',(select jsonb_agg(to_jsonb(t) order by t.id) from feed_tombstones t),
      'audits',(select jsonb_agg(to_jsonb(a) order by a.id) from audit_events a),
      'memberships',(select jsonb_agg(to_jsonb(m) order by m.id) from board_memberships m),
      'idempotency',(select jsonb_agg(to_jsonb(i) order by i.id) from idempotency_records i)
    ) as evidence`)
  ).rows[0]!.evidence;
}

async function seedLinkedAndUnlinkedOpenVotes(
  pool: Pool,
  workflow: Awaited<ReturnType<typeof seedQuestionWorkflow>>
) {
  const approvalRuleId = testId(200);
  const governanceProfileId = testId(201);
  const rulesetId = testId(202);
  const linkedVoteId = testId(203);
  const linkedResolutionId = testId(204);
  const linkedPackageId = testId(205);
  const questionLinkId = testId(206);
  const unlinkedVoteId = testId(207);
  const unlinkedResolutionId = testId(208);
  const unlinkedPackageId = testId(209);
  const matterTypeId = testId(210);
  const selectedRulesetRuleId = testId(211);
  const matterEvaluationId = testId(212);
  const client = await pool.connect();
  try {
    await client.query("begin");
    const cutoffResult = await client.query<{
      ordinal: number;
      text_sha256: string;
    }>(
      `select turn.ordinal,encode(turn.text_sha256,'hex') as text_sha256
         from management_questions as question
         join management_question_turns as turn on turn.id=question.current_turn_id
        where question.id=$1`,
      [workflow.prepared.questionId]
    );
    const cutoff = cutoffResult.rows[0];
    if (!cutoff) throw new Error("management question cutoff fixture is unavailable");
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
        workflow.asker.organizationId,
        workflow.asker.boardId,
        testHash(40),
        workflow.asker.memberId
      ]
    );
    await client.query(
      `insert into governance_profiles(
         id,organization_id,board_id,version,state,schema_version,canonical_payload,
         canonical_sha256,source_agreement_references,created_by
       ) values ($1,$2,$3,1,'draft','boardagent.governance-profile.v1','{}',$4,'[]',$5)`,
      [
        governanceProfileId,
        workflow.asker.organizationId,
        workflow.asker.boardId,
        testHash(41),
        workflow.asker.memberId
      ]
    );
    await client.query(
      `insert into rulesets(
         id,organization_id,board_id,profile_id,version,state,schema_version,
         canonical_payload,canonical_sha256,created_by
       ) values ($1,$2,$3,$4,1,'draft','boardagent.ruleset.v1','{}',$5,$6)`,
      [
        rulesetId,
        workflow.asker.organizationId,
        workflow.asker.boardId,
        governanceProfileId,
        testHash(42),
        workflow.asker.memberId
      ]
    );
    await client.query(
      `insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256)
       values ($1,$2,'forecast','Forecast','{"code":"forecast","fields":[]}',$3)`,
      [matterTypeId, rulesetId, testHash(49)]
    );
    await client.query(
      `insert into ruleset_rules(
         id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
         approval_rule_id,canonical_sha256
       ) values ($1,$2,$3,1,1,'{"kind":"exists","field":"forecast"}',$4,$5)`,
      [selectedRulesetRuleId, rulesetId, matterTypeId, approvalRuleId, testHash(50)]
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
        workflow.asker.organizationId,
        workflow.asker.boardId,
        workflow.asker.memberId,
        governanceProfileId,
        rulesetId,
        matterTypeId,
        testHash(51),
        selectedRulesetRuleId,
        testHash(52)
      ]
    );
    for (const [voteId, resolutionId, packageId, hashByte, linked] of [
      [linkedVoteId, linkedResolutionId, linkedPackageId, 43, true],
      [unlinkedVoteId, unlinkedResolutionId, unlinkedPackageId, 44, false]
    ] as const) {
      const questionCutoffManifest = linked
        ? [
            {
              type: "question_cutoff",
              ordinal: 1,
              id: workflow.prepared.questionId,
              version: cutoff.ordinal,
              sha256: cutoff.text_sha256
            }
          ]
        : [];
      await client.query(
        `insert into votes(
           id,organization_id,board_id,title,approval_rule_id,governance_profile_id,
           ruleset_id,close_mode,created_by
         ) values ($1,$2,$3,'Forecast decision',$4,$5,$6,'secretariat_confirmed',$7)`,
        [
          voteId,
          workflow.asker.organizationId,
          workflow.asker.boardId,
          approvalRuleId,
          governanceProfileId,
          rulesetId,
          workflow.asker.memberId
        ]
      );
      await client.query(
        `insert into resolution_versions(
           id,organization_id,board_id,vote_id,version,canonical_schema,canonical_text,
           canonical_sha256,author_member_id
         ) values ($1,$2,$3,$4,1,'boardagent.resolution.v1','Approve forecast',$5,$6)`,
        [
          resolutionId,
          workflow.asker.organizationId,
          workflow.asker.boardId,
          voteId,
          testHash(hashByte),
          workflow.asker.memberId
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
         ) values ($1,$2,$3,$4,1,'boardagent.decision-package.v1',$5,$6,'[]',$7,'[]',$8,
           $9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,null,null,$21,$22,$23,$24)`,
        [
          packageId,
          workflow.asker.organizationId,
          workflow.asker.boardId,
          voteId,
          resolutionId,
          testHash(hashByte),
          testHash(45),
          testHash(46),
          JSON.stringify(questionCutoffManifest),
          testHash(47),
          approvalRuleId,
          testHash(40),
          governanceProfileId,
          testHash(41),
          rulesetId,
          testHash(42),
          matterEvaluationId,
          testHash(52),
          selectedRulesetRuleId,
          testHash(50),
          testHash(48),
          Buffer.from("{}"),
          testHash(hashByte + 20),
          workflow.asker.memberId
        ]
      );
      await client.query(
        `update votes
            set state='open',current_resolution_version_id=$1,current_decision_package_id=$2,
                electorate_sha256=$3,deadline_at='2099-09-10T12:00:00Z',
                matter_evaluation_id=$4,selected_ruleset_rule_id=$5,
                opened_at=transaction_timestamp(),row_version=row_version+1
          where id=$6`,
        [resolutionId, packageId, testHash(48), matterEvaluationId, selectedRulesetRuleId, voteId]
      );
    }
    await client.query(
      `insert into question_decision_links(
         id,organization_id,board_id,question_id,inclusive_turn_ordinal,
         inclusive_turn_sha256,decision_package_id,decision_package_version,
         decision_package_sha256,selected_by,consent_record_id
       ) values ($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)`,
      [
        questionLinkId,
        workflow.asker.organizationId,
        workflow.asker.boardId,
        workflow.prepared.questionId,
        cutoff.ordinal,
        Buffer.from(cutoff.text_sha256, "hex"),
        linkedPackageId,
        testHash(63),
        workflow.asker.memberId,
        workflow.asker.consentRecordId
      ]
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
  return { linkedVoteId, linkedPackageId, unlinkedVoteId };
}

describe("permanent management-question transactions", () => {
  it("MR-FEED-QUESTION-001 keeps actual question lifecycle projections consistent with their audit evidence", async () => {
    await withDatabase(async (pool) => {
      const dueAt = new Date(Date.now() + 3_000).toISOString();
      const { asker, manager, prepared } = await seedQuestionWorkflow(pool, dueAt);
      const observations: {
        phase: string;
        result: Awaited<ReturnType<typeof inspectFeedConsistencyInTransaction>>;
      }[] = [];
      const inspect = async (phase: string) => {
        observations.push({
          phase,
          result: await withWorkerTransaction(
            pool,
            (client) => inspectFeedConsistencyInTransaction(client, asker.organizationId),
            { assumeRole: "boardagent_worker", isolation: "repeatable read" }
          )
        });
      };
      await inspect("asked");
      await delay(Math.max(0, Date.parse(dueAt) - Date.now() + 25));
      const overdue = await withWorkerTransaction(
        pool,
        async (client) => {
          const clock = await client.query<{ through: string }>(
            `select to_char(transaction_timestamp() at time zone 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as through`
          );
          return markDueBoardQuestionsOverdueInTransaction(client, {
            organizationId: asker.organizationId,
            boardId: asker.boardId,
            through: clock.rows[0]!.through
          });
        },
        { assumeRole: "boardagent_worker" }
      );
      expect(overdue).toEqual([
        { questionId: prepared.questionId, boardId: asker.boardId, rowVersion: 2n }
      ]);
      await inspect("overdue");
      await withRequestTransaction(
        pool,
        manager.context,
        (client) =>
          answerManagementQuestionInTransaction(client, {
            organizationId: asker.organizationId,
            prepared: prepareManagementQuestionTurn({
              questionId: prepared.questionId,
              turnKind: "answer",
              text: "The synthetic permit register is now current.",
              citations: []
            }),
            turnId: testId(83_100),
            answerRecordId: testId(83_101),
            auditEventId: testId(83_102),
            idempotencyRecordId: testId(83_103),
            idempotencyKey: "feed-question-answer-0001",
            askerDelivery: {
              recipientMemberId: asker.memberId,
              noticeId: testId(83_104),
              feedId: testId(83_105)
            },
            ownerResolutions: [{ ownerMemberId: manager.memberId, tombstoneId: testId(83_106) }],
            sourceUpdateAuditEvents: []
          }),
        { assumeRole: "boardagent_server" }
      );
      await inspect("answered");
      await withRequestTransaction(
        pool,
        asker.context,
        (client) =>
          followUpManagementQuestionInTransaction(client, {
            organizationId: asker.organizationId,
            prepared: prepareManagementQuestionTurn({
              questionId: prepared.questionId,
              turnKind: "follow_up",
              text: "When will the next register review occur?",
              citations: [],
              dueAt: "2099-09-04T12:00:00Z"
            }),
            turnId: testId(83_110),
            auditEventId: testId(83_111),
            idempotencyRecordId: testId(83_112),
            idempotencyKey: "feed-question-follow-up-0001",
            ownerDeliveries: [
              {
                ownerMemberId: manager.memberId,
                noticeId: testId(83_113),
                feedId: testId(83_114)
              }
            ],
            sourceUpdateAuditEvents: []
          }),
        { assumeRole: "boardagent_server" }
      );
      await inspect("followed_up");
      const bindings = await pool.query(
        `select feed.action_type,feed.object_type as feed_object_type,
                audit.object_type as audit_object_type,
                feed.object_id=audit.object_id as same_object_id,
                feed.board_id=audit.board_id as same_board_id
           from pending_action_feed feed
           join audit_events audit on audit.id=feed.audit_event_id
          order by feed.feed_sequence,feed.id`
      );
      expect(bindings.rows).toHaveLength(3);
      expect(
        observations,
        JSON.stringify({ observations, actualFeedAuditBindings: bindings.rows }, null, 2)
      ).toEqual(
        ["asked", "overdue", "answered", "followed_up"].map((phase, index) => ({
          phase,
          result: {
            valid: true,
            checkedFeedRows: index < 2 ? 1 : index,
            checkedTombstoneRows: index < 2 ? 0 : 1,
            payloadHashMismatches: 0,
            payloadCanonicalMismatches: 0,
            payloadBindingMismatches: 0,
            membershipStalePendingRows: 0,
            noticeBindingMismatches: 0,
            auditBindingMismatches: 0,
            tombstoneBindingMismatches: 0,
            duplicateRemovalTombstones: 0,
            relationMismatches: 0,
            evidenceSha256: expect.stringMatching(/^[0-9a-f]{64}$/u)
          }
        }))
      );
    });
  });

  it("MR-FEED-QUESTION-002 rejects malformed projection bindings without retaining fixture corruption", async () => {
    await withDatabase(async (pool) => {
      const workflow = await seedQuestionWorkflow(pool);
      await answerFeedQuestion(pool, workflow);
      await followUpFeedQuestion(pool, workflow);
      const otherBoardId = testId(83_280);
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'other-feed-control','Other feed control','UTC')",
        [otherBoardId, workflow.asker.organizationId]
      );
      const original = await questionFeedHistory(pool);
      const cases = [
        {
          name: "due action cannot borrow an answer event pairing",
          sql: "update pending_action_feed set action_type='management_question_answered' where id=$1",
          values: [testId(83_214)],
          counter: "auditBindingMismatches"
        },
        {
          name: "question UUID must match its audit and notice",
          sql: "update pending_action_feed set object_id=$2 where id=$1",
          values: [testId(83_214), testId(83_299)],
          counter: "auditBindingMismatches"
        },
        {
          name: "question evidence cannot move to a different board",
          sql: `insert into pending_action_feed(
                  id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
                  action_type,object_type,object_id,object_version,visibility_sha256,
                  canonical_payload,payload_sha256,state,notice_id,audit_event_id,resolved_at
                ) select $3::uuid,organization_id,$2::uuid,member_id,entitlement_generation,feed_sequence,
                         action_type,object_type,object_id,object_version,visibility_sha256,
                         canonical_payload,payload_sha256,state,notice_id,audit_event_id,resolved_at
                    from pending_action_feed where id=$1`,
          values: [testId(36), otherBoardId, testId(83_281)],
          counter: "auditBindingMismatches"
        },
        {
          name: "unrelated object vocabulary is not mapped",
          sql: "update pending_action_feed set object_type='task' where id=$1",
          values: [testId(83_214)],
          counter: "auditBindingMismatches"
        },
        {
          name: "notice version and sequence remain bound",
          sql: "update pending_action_feed set notice_id=$2 where id=$1",
          values: [testId(83_214), testId(35)],
          counter: "noticeBindingMismatches"
        },
        {
          name: "payload hash still detects drift",
          sql: "update pending_action_feed set payload_sha256=decode(repeat('00',32),'hex') where id=$1",
          values: [testId(83_214)],
          counter: "payloadHashMismatches"
        },
        {
          name: "matching hash does not excuse noncanonical payload bytes",
          sql: `update pending_action_feed
                   set canonical_payload=canonical_payload||convert_to(' ','UTF8'),
                       payload_sha256=sha256(canonical_payload||convert_to(' ','UTF8'))
                 where id=$1`,
          values: [testId(83_214)],
          counter: "payloadCanonicalMismatches"
        },
        {
          name: "current membership remains required for pending actions",
          sql: `update board_memberships
                   set state='ended',active_until=transaction_timestamp(),
                       entitlement_generation=entitlement_generation+1
                 where member_id=$1`,
          values: [workflow.manager.memberId],
          counter: "membershipStalePendingRows"
        },
        {
          name: "removal must identify its historical feed row",
          sql: `insert into feed_tombstones(
                  id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
                  removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
                ) select $2::uuid,organization_id,board_id,member_id,entitlement_generation,
                         feed_sequence+100,null,object_type,object_id,reason_class,
                         sha256(convert_to('rollback-missing-feed:'||$2::text,'UTF8')),audit_event_id
                    from feed_tombstones where id=$1`,
          values: [testId(83_206), testId(83_290)],
          counter: "tombstoneBindingMismatches"
        },
        {
          name: "answer evidence cannot justify a revocation tombstone",
          sql: `insert into feed_tombstones(
                  id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
                  removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
                ) select $2::uuid,organization_id,board_id,member_id,entitlement_generation,
                         feed_sequence+100,removed_feed_id,object_type,object_id,'revoked',
                         sha256(convert_to('rollback-wrong-reason:'||$2::text,'UTF8')),audit_event_id
                    from feed_tombstones where id=$1`,
          values: [testId(83_206), testId(83_291)],
          counter: "tombstoneBindingMismatches"
        }
      ] as const;
      for (const candidate of cases) {
        const rollback = new Error(`rollback fixture: ${candidate.name}`);
        await expect(
          withWorkerTransaction(pool, async (client) => {
            // Deliberate malformed component fixture, rolled back in the same transaction.
            await client.query(candidate.sql, [...candidate.values]);
            await client.query("set local role boardagent_worker");
            const result = await inspectFeedConsistencyInTransaction(
              client,
              workflow.asker.organizationId
            );
            expect(result.valid, candidate.name).toBe(false);
            expect(
              result[candidate.counter],
              JSON.stringify({ candidate: candidate.name, result })
            ).toBeGreaterThan(0);
            throw rollback;
          })
        ).rejects.toBe(rollback);
        expect(await questionFeedHistory(pool), candidate.name).toEqual(original);
      }
      const valid = await withWorkerTransaction(
        pool,
        (client) => inspectFeedConsistencyInTransaction(client, workflow.asker.organizationId),
        { assumeRole: "boardagent_worker", isolation: "repeatable read" }
      );
      expect(valid, JSON.stringify(valid)).toMatchObject({ valid: true, relationMismatches: 0 });
      expect(await questionFeedHistory(pool)).toEqual(original);
    });
  });

  it("MR-FEED-QUESTION-003 reconciles a genuine question feed only after its entitlement becomes stale", async () => {
    await withDatabase(async (pool) => {
      const workflow = await seedQuestionWorkflow(pool);
      const original = await questionFeedHistory(pool);
      const reconcile = () =>
        withWorkerTransaction(
          pool,
          (client) =>
            reconcileFeedEntitlementsInTransaction(client, {
              organizationId: workflow.asker.organizationId,
              boardId: workflow.asker.boardId,
              memberId: workflow.manager.memberId,
              newId: () => testId(83_300)
            }),
          { assumeRole: "boardagent_worker", isolation: "serializable" }
        );
      expect(await reconcile()).toEqual({ reconciled: 0, hasMore: false });
      expect(await questionFeedHistory(pool)).toEqual(original);
      // Existing component-fixture seam models an ended entitlement; the question,
      // its notice, audit and pending feed were produced by the actual transaction.
      await pool.query(
        `update board_memberships set state='ended',active_until=transaction_timestamp(),
                entitlement_generation=entitlement_generation+1
          where member_id=$1 and board_id=$2`,
        [workflow.manager.memberId, workflow.asker.boardId]
      );
      const stale = await questionFeedHistory(pool);
      let result: unknown;
      try {
        result = await reconcile();
      } catch (error) {
        expect(await questionFeedHistory(pool)).toEqual(stale);
        throw error;
      }
      expect(result).toEqual({ reconciled: 1, hasMore: false });
      expect(await reconcile()).toEqual({ reconciled: 0, hasMore: false });
      const consistency = await withWorkerTransaction(
        pool,
        (client) => inspectFeedConsistencyInTransaction(client, workflow.asker.organizationId),
        { assumeRole: "boardagent_worker", isolation: "repeatable read" }
      );
      expect(consistency, JSON.stringify(consistency)).toMatchObject({
        valid: true,
        checkedFeedRows: 1,
        checkedTombstoneRows: 1,
        membershipStalePendingRows: 0,
        relationMismatches: 0
      });
      expect(
        (await pool.query("select state from pending_action_feed where id=$1", [testId(36)])).rows
      ).toEqual([{ state: "superseded" }]);
    });
  });

  it("MR-FEED-QUESTION-004 upgrades genuine version160 question history without rewriting any recorded rows", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-question-feed-upgrade-"));
    try {
      const previous = (await readdir(MIGRATIONS))
        .filter((name) => /^\d{4}_.+\.sql$/u.test(name) && Number(name.slice(0, 4)) <= 160)
        .sort();
      expect(previous).toHaveLength(160);
      for (const name of previous) {
        await copyFile(path.join(MIGRATIONS, name), path.join(directory, name));
      }
      await withDatabase(async (pool) => {
        const workflow = await seedQuestionWorkflow(pool);
        await answerFeedQuestion(pool, workflow);
        await followUpFeedQuestion(pool, workflow);
        const inspect = () =>
          withWorkerTransaction(
            pool,
            (client) => inspectFeedConsistencyInTransaction(client, workflow.asker.organizationId),
            { assumeRole: "boardagent_worker", isolation: "repeatable read" }
          );
        const before = await inspect();
        expect(before).toMatchObject({
          valid: false,
          auditBindingMismatches: 3,
          tombstoneBindingMismatches: 1,
          relationMismatches: 4
        });
        const historicalRows = await questionFeedHistory(pool);
        const functionAuthority = () =>
          pool.query(
            `select procedure.proname,pg_get_userbyid(procedure.proowner) as owner,
                  procedure.proacl::text as acl,procedure.proconfig
             from pg_proc procedure join pg_namespace namespace on namespace.oid=procedure.pronamespace
            where namespace.nspname='public' and procedure.proname in (
              'boardagent_feed_reconcile_candidates','boardagent_commit_feed_revocation',
              'boardagent_feed_consistency_relations') order by procedure.proname`
          );
        const authorityBefore = (await functionAuthority()).rows;
        expect(authorityBefore).toHaveLength(3);
        for (const routine of authorityBefore) {
          expect(routine.owner).toBe("boardagent_migrator");
          expect(routine.proconfig).toEqual(["search_path=pg_catalog, public, pg_temp"]);
        }
        const oldAudits = historicalRows["audits"] as { id: string }[];
        const oldAuditIds = new Set(oldAudits.map(({ id }) => id));
        const ledgerBefore = (
          await pool.query("select to_jsonb(m) as row from schema_migrations m order by version")
        ).rows;
        expect(ledgerBefore).toHaveLength(160);
        const migrationName = "0161_question_feed_audit_bindings.sql";
        const migrationSha256 = createHash("sha256")
          .update(await readFile(path.join(MIGRATIONS, migrationName)))
          .digest("hex");
        await copyFile(path.join(MIGRATIONS, migrationName), path.join(directory, migrationName));
        expect(await migrate(pool, directory, "question-feed-upgrade160-161")).toBe(1);
        expect((await functionAuthority()).rows).toEqual(authorityBefore);
        const afterRows = await questionFeedHistory(pool);
        const afterAudits = afterRows["audits"] as { id: string }[];
        expect(afterAudits.filter(({ id }) => oldAuditIds.has(id))).toEqual(oldAudits);
        expect(afterAudits).toHaveLength(oldAudits.length + 1);
        expect(afterRows).toEqual({ ...historicalRows, audits: afterAudits });
        const migrationAudit = await pool.query<{
          payload: unknown;
          previous_hash: string;
          prior_hash: string;
        }>(
          `select convert_from(a.canonical_payload,'UTF8')::jsonb as payload,
                  encode(a.previous_event_sha256,'hex') as previous_hash,
                  encode(previous.event_sha256,'hex') as prior_hash
             from audit_events a join audit_events previous on previous.sequence=a.sequence-1
            where a.event_type='migration_applied'`
        );
        expect(migrationAudit.rows).toHaveLength(1);
        expect(migrationAudit.rows[0]!.previous_hash).toBe(migrationAudit.rows[0]!.prior_hash);
        expect(migrationAudit.rows[0]!.payload).toMatchObject({
          eventType: "migration_applied",
          entityType: "schema_migration",
          entityId: migrationName,
          origin: "migration",
          details: {
            version: 161,
            name: migrationName,
            sha256: migrationSha256,
            appBuild: "question-feed-upgrade160-161"
          }
        });
        const ledgerAfter = (
          await pool.query("select to_jsonb(m) as row from schema_migrations m order by version")
        ).rows;
        expect(ledgerAfter).toHaveLength(161);
        expect(ledgerAfter.slice(0, 160)).toEqual(ledgerBefore);
        expect(ledgerAfter[160]!.row).toMatchObject({
          version: 161,
          name: migrationName,
          sha256: migrationSha256,
          app_build: "question-feed-upgrade160-161"
        });
        expect(await inspect()).toMatchObject({
          valid: true,
          checkedFeedRows: 3,
          checkedTombstoneRows: 1,
          auditBindingMismatches: 0,
          tombstoneBindingMismatches: 0,
          relationMismatches: 0
        });
        expect(await migrate(pool, directory, "question-feed-upgrade-idempotent")).toBe(0);
        expect(await questionFeedHistory(pool)).toEqual(afterRows);
        expect(
          (await pool.query("select to_jsonb(m) as row from schema_migrations m order by version"))
            .rows
        ).toEqual(ledgerAfter);
      }, directory);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("MR-QUESTION-001 replays a completed ask after its due time while refusing a new expired ask", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["management:question"]
      });
      const ownerId = await seedManagementOwner(pool, actor.organizationId, actor.boardId);
      const clock = await pool.query<{ due_at: string }>(
        `select to_char((clock_timestamp()+interval '5 seconds') at time zone 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as due_at`
      );
      const prepared = prepareManagementQuestion({
        questionId: testId(30),
        boardId: actor.boardId,
        question: "Please confirm the current forecast.\n",
        assignedOwnerIds: [ownerId],
        dueAt: clock.rows[0]!.due_at,
        citations: [],
        visibility: [{ granteeType: "seat_role", seatRole: "voting_member" }]
      });
      const ask = (base: number, key = "expired-question-replay-0001", question = prepared) =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            askManagementQuestionInTransaction(client, {
              organizationId: actor.organizationId,
              prepared: question,
              initialTurnId: testId(base),
              auditEventId: testId(base + 1),
              idempotencyRecordId: testId(base + 2),
              idempotencyKey: key,
              visibilityRecordIds: [testId(base + 3)],
              ownerDeliveries: [
                { ownerMemberId: ownerId, noticeId: testId(base + 4), feedId: testId(base + 5) }
              ]
            }),
          { assumeRole: "boardagent_server" }
        );
      const snapshot = async () =>
        (
          await pool.query(`select jsonb_build_object(
          'questions',(select jsonb_agg(to_jsonb(q) order by q.id) from management_questions q),
          'turns',(select jsonb_agg(to_jsonb(t) order by t.id) from management_question_turns t),
          'notices',(select jsonb_agg(to_jsonb(n) order by n.id) from notices n),
          'feed',(select jsonb_agg(to_jsonb(f) order by f.id) from pending_action_feed f),
          'audits',(select jsonb_agg(to_jsonb(a) order by a.id) from audit_events a),
          'idempotency',(select jsonb_agg(to_jsonb(i) order by i.id) from idempotency_records i)
        ) as evidence`)
        ).rows[0]!.evidence;

      const created = await ask(31);
      expect(created).toMatchObject({ replayed: false, questionId: prepared.questionId });
      const before = await snapshot();
      const remaining = await pool.query<{ wait_ms: number }>(
        `select greatest(0,extract(epoch from ($1::timestamptz-clock_timestamp()))*1000)::float8
          as wait_ms`,
        [prepared.dueAt]
      );
      await delay(Math.ceil(remaining.rows[0]!.wait_ms) + 100);
      expect(
        (
          await pool.query<{ elapsed: boolean }>(
            "select $1::timestamptz<=transaction_timestamp() as elapsed",
            [prepared.dueAt]
          )
        ).rows[0]!.elapsed
      ).toBe(true);

      const newQuestion = prepareManagementQuestion({
        ...prepared,
        questionId: testId(60)
      });
      await expect(ask(61, "expired-new-question-0001", newQuestion)).rejects.toMatchObject({
        code: "question_due_invalid"
      });
      await expect(ask(41)).resolves.toEqual({
        replayed: true,
        questionId: prepared.questionId,
        responseSha256: created.responseSha256
      });
      expect(await snapshot()).toEqual(before);

      await pool.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [actor.accessTokenRecordId]
      );
      await expect(ask(71)).rejects.toMatchObject({ code: "question_creation_unavailable" });
      expect(await snapshot()).toEqual(before);
    });
  }, 30_000);

  it("atomically creates the first turn, owner action, notice and audit with safe replay", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["management:question"]
      });
      const ownerId = await seedManagementOwner(pool, actor.organizationId, actor.boardId);
      const prepared = prepareManagementQuestion({
        questionId: testId(30),
        boardId: actor.boardId,
        question: "What changed in the forecast?\n",
        assignedOwnerIds: [ownerId],
        dueAt: "2099-09-02T12:00:00Z",
        citations: [],
        visibility: [{ granteeType: "seat_role", seatRole: "voting_member" }]
      });
      const ask = (base: number, question = prepared) =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            askManagementQuestionInTransaction(client, {
              organizationId: actor.organizationId,
              prepared: question,
              initialTurnId: testId(base),
              auditEventId: testId(base + 1),
              idempotencyRecordId: testId(base + 2),
              idempotencyKey: "question-create-0001",
              visibilityRecordIds: [testId(base + 3)],
              ownerDeliveries: [
                {
                  ownerMemberId: ownerId,
                  noticeId: testId(base + 4),
                  feedId: testId(base + 5)
                }
              ]
            }),
          { assumeRole: "boardagent_server" }
        );

      const created = await ask(31);
      expect(created).toMatchObject({
        replayed: false,
        questionId: prepared.questionId,
        turnId: testId(31)
      });
      const replayed = await ask(40);
      expect(replayed).toMatchObject({ replayed: true, questionId: prepared.questionId });
      const conflicting = prepareManagementQuestion({
        questionId: prepared.questionId,
        boardId: actor.boardId,
        question: "A different question\n",
        assignedOwnerIds: [ownerId],
        dueAt: "2099-09-02T12:00:00Z",
        citations: [],
        visibility: [{ granteeType: "seat_role", seatRole: "voting_member" }]
      });
      await expect(ask(50, conflicting)).rejects.toThrow(
        "idempotency key was already used for a different request"
      );

      const stored = await pool.query<{
        audit_count: string;
        feed_count: string;
        notice_count: string;
        question_count: string;
        state: string;
        turn_count: string;
      }>(
        `select question.state,
                (select count(*)::text from management_questions) as question_count,
                (select count(*)::text from management_question_turns) as turn_count,
                (select count(*)::text from pending_action_feed) as feed_count,
                (select count(*)::text from notices) as notice_count,
                (select count(*)::text from audit_events) as audit_count
           from management_questions question
          where question.id=$1`,
        [prepared.questionId]
      );
      expect(stored.rows[0]).toEqual({
        state: "pending",
        question_count: "1",
        turn_count: "1",
        feed_count: "1",
        notice_count: "1",
        audit_count: "1"
      });
      const feed = await pool.query<{
        action_type: string;
        audit_event_id: string;
        canonical_payload: Buffer;
        feed_sequence: string;
        member_id: string;
      }>(
        "select action_type,audit_event_id,canonical_payload,feed_sequence,member_id from pending_action_feed"
      );
      expect(feed.rows[0]).toMatchObject({
        action_type: "management_question_due",
        audit_event_id: testId(32),
        feed_sequence: "1",
        member_id: ownerId
      });
      expect(JSON.parse(feed.rows[0]!.canonical_payload.toString("utf8"))).toMatchObject({
        objectId: prepared.questionId,
        actionState: "pending"
      });
    });
  });

  it("requires a recorded management answer and atomically reopens on follow-up", async () => {
    await withDatabase(async (pool) => {
      const { asker, manager, prepared } = await seedQuestionWorkflow(pool);

      await expect(
        withRequestTransaction(
          pool,
          asker.context,
          (client) =>
            client.query(
              "update management_questions set state='answered',row_version=row_version+1 where id=$1",
              [prepared.questionId]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied/u);

      await expect(
        pool.query(
          "update management_questions set state='answered',row_version=row_version+1 where id=$1",
          [prepared.questionId]
        )
      ).rejects.toThrow(/recorded answer turn/u);

      const answer = prepareManagementQuestionTurn({
        questionId: prepared.questionId,
        turnKind: "answer",
        text: "The variance is caused by the delayed renewal.\n",
        citations: []
      });
      const recordAnswer = (base: number) =>
        withRequestTransaction(
          pool,
          manager.context,
          (client) =>
            answerManagementQuestionInTransaction(client, {
              organizationId: manager.organizationId,
              prepared: answer,
              turnId: testId(base),
              answerRecordId: testId(base + 1),
              auditEventId: testId(base + 2),
              idempotencyRecordId: testId(base + 3),
              idempotencyKey: "question-workflow-answer-0001",
              askerDelivery: {
                recipientMemberId: asker.memberId,
                noticeId: testId(base + 4),
                feedId: testId(base + 5)
              },
              ownerResolutions: [
                { ownerMemberId: manager.memberId, tombstoneId: testId(base + 6) }
              ],
              sourceUpdateAuditEvents: []
            }),
          { assumeRole: "boardagent_server" }
        );
      const answered = await recordAnswer(40);
      expect(answered).toMatchObject({
        replayed: false,
        questionId: prepared.questionId,
        turnId: testId(40),
        turnOrdinal: 2,
        questionRowVersion: 2n
      });
      await expect(recordAnswer(60)).resolves.toMatchObject({
        replayed: true,
        questionId: prepared.questionId,
        turnId: testId(40)
      });

      const followUp = prepareManagementQuestionTurn({
        questionId: prepared.questionId,
        turnKind: "follow_up",
        text: "What is the recovery date?\n",
        citations: [],
        dueAt: "2099-09-04T12:00:00Z"
      });
      const recordFollowUp = (base: number) =>
        withRequestTransaction(
          pool,
          asker.context,
          (client) =>
            followUpManagementQuestionInTransaction(client, {
              organizationId: asker.organizationId,
              prepared: followUp,
              turnId: testId(base),
              auditEventId: testId(base + 1),
              idempotencyRecordId: testId(base + 2),
              idempotencyKey: "question-workflow-follow-up-0001",
              ownerDeliveries: [
                {
                  ownerMemberId: manager.memberId,
                  noticeId: testId(base + 3),
                  feedId: testId(base + 4)
                }
              ],
              sourceUpdateAuditEvents: []
            }),
          { assumeRole: "boardagent_server" }
        );
      const followedUp = await recordFollowUp(70);
      expect(followedUp).toMatchObject({
        replayed: false,
        questionId: prepared.questionId,
        turnId: testId(70),
        turnOrdinal: 3,
        questionRowVersion: 3n
      });
      await expect(recordFollowUp(80)).resolves.toMatchObject({
        replayed: true,
        questionId: prepared.questionId,
        turnId: testId(70)
      });

      const projection = await pool.query<{
        answer_count: string;
        audit_types: string[];
        current_turn_id: string;
        due_at: string;
        pending_owner_actions: string;
        row_version: string;
        state: string;
        tombstone_count: string;
        turn_count: string;
      }>(
        `select question.state,question.current_turn_id,question.row_version::text,
                to_char(question.due_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"') as due_at,
                (select count(*)::text from management_question_turns) as turn_count,
                (select count(*)::text from management_question_answers) as answer_count,
                (select count(*)::text from feed_tombstones) as tombstone_count,
                (select count(*)::text from pending_action_feed
                  where member_id=$2 and action_type='management_question_due' and state='pending')
                  as pending_owner_actions,
                (select array_agg(event_type order by sequence) from audit_events) as audit_types
           from management_questions as question
          where question.id=$1`,
        [prepared.questionId, manager.memberId]
      );
      expect(projection.rows[0]).toEqual({
        state: "pending",
        current_turn_id: testId(70),
        row_version: "3",
        due_at: "2099-09-04T12:00:00Z",
        turn_count: "3",
        answer_count: "1",
        tombstone_count: "1",
        pending_owner_actions: "1",
        audit_types: [
          "management_question_asked",
          "management_question_answered",
          "management_question_followed_up"
        ]
      });
    });
  });

  it("blocks vote closing at an unanswered linked cutoff but ignores unlinked questions", async () => {
    await withDatabase(async (pool) => {
      const workflow = await seedQuestionWorkflow(pool);
      const votes = await seedLinkedAndUnlinkedOpenVotes(pool, workflow);

      const linked = await pool.query<{ ready: boolean }>(
        "select boardagent_vote_qna_close_ready($1) as ready",
        [votes.linkedVoteId]
      );
      expect(linked.rows).toEqual([{ ready: false }]);

      const unlinked = await pool.query<{ ready: boolean }>(
        "select boardagent_vote_qna_close_ready($1) as ready",
        [votes.unlinkedVoteId]
      );
      expect(unlinked.rows).toEqual([{ ready: true }]);

      const readback = await pool.query<{ id: string; state: string }>(
        `select id,state from votes where id=any($1::uuid[]) order by id`,
        [[votes.linkedVoteId, votes.unlinkedVoteId]]
      );
      expect(readback.rows).toEqual([
        { id: votes.linkedVoteId, state: "open" },
        { id: votes.unlinkedVoteId, state: "open" }
      ]);
    });
  });

  it("allows vote closing only when the exact linked cutoff endpoint is a recorded answer", async () => {
    await withDatabase(async (pool) => {
      const workflow = await seedQuestionWorkflow(pool);
      const answer = prepareManagementQuestionTurn({
        questionId: workflow.prepared.questionId,
        turnKind: "answer",
        text: "The linked package now contains the recorded management answer.\n",
        citations: []
      });
      await withRequestTransaction(
        pool,
        workflow.manager.context,
        (client) =>
          answerManagementQuestionInTransaction(client, {
            organizationId: workflow.manager.organizationId,
            prepared: answer,
            turnId: testId(70),
            answerRecordId: testId(71),
            auditEventId: testId(72),
            idempotencyRecordId: testId(73),
            idempotencyKey: "answered-cutoff-close-0001",
            askerDelivery: {
              recipientMemberId: workflow.asker.memberId,
              noticeId: testId(74),
              feedId: testId(75)
            },
            ownerResolutions: [
              { ownerMemberId: workflow.manager.memberId, tombstoneId: testId(76) }
            ],
            sourceUpdateAuditEvents: []
          }),
        { assumeRole: "boardagent_server" }
      );
      const votes = await seedLinkedAndUnlinkedOpenVotes(pool, workflow);

      const closing = await pool.query<{ ready: boolean }>(
        "select boardagent_vote_qna_close_ready($1) as ready",
        [votes.linkedVoteId]
      );
      expect(closing.rows).toEqual([{ ready: true }]);
    });
  });

  it("blocks only an explicitly linked open vote when a turn passes its frozen cutoff", async () => {
    await withDatabase(async (pool) => {
      const workflow = await seedQuestionWorkflow(pool);
      const votes = await seedLinkedAndUnlinkedOpenVotes(pool, workflow);
      const answer = prepareManagementQuestionTurn({
        questionId: workflow.prepared.questionId,
        turnKind: "answer",
        text: "The revised source is now recorded.\n",
        citations: []
      });
      const recordAnswer = (
        sourceUpdateAuditEvents: readonly {
          voteId: string;
          causeId: string;
          auditEventId: string;
        }[]
      ) =>
        withRequestTransaction(
          pool,
          workflow.manager.context,
          (client) =>
            answerManagementQuestionInTransaction(client, {
              organizationId: workflow.manager.organizationId,
              prepared: answer,
              turnId: testId(40),
              answerRecordId: testId(41),
              auditEventId: testId(42),
              idempotencyRecordId: testId(43),
              idempotencyKey: "linked-question-answer-0001",
              askerDelivery: {
                recipientMemberId: workflow.asker.memberId,
                noticeId: testId(44),
                feedId: testId(45)
              },
              ownerResolutions: [
                { ownerMemberId: workflow.manager.memberId, tombstoneId: testId(46) }
              ],
              sourceUpdateAuditEvents
            }),
          { assumeRole: "boardagent_server" }
        );

      await expect(recordAnswer([])).rejects.toThrow(/match every affected linked open vote/u);
      const afterRejectedAttempt = await pool.query<{
        audit_count: string;
        question_state: string;
        vote_state: string;
      }>(
        `select question.state as question_state,vote.state as vote_state,
                (select count(*)::text from audit_events) as audit_count
           from management_questions as question
           join votes as vote on vote.id=$2
          where question.id=$1`,
        [workflow.prepared.questionId, votes.linkedVoteId]
      );
      expect(afterRejectedAttempt.rows[0]).toEqual({
        question_state: "pending",
        vote_state: "open",
        audit_count: "1"
      });

      const result = await recordAnswer([
        { voteId: votes.linkedVoteId, causeId: testId(47), auditEventId: testId(49) }
      ]);
      expect(result).toMatchObject({
        replayed: false,
        sourceUpdateVoteIds: [votes.linkedVoteId]
      });
      await expect(
        recordAnswer([
          { voteId: votes.linkedVoteId, causeId: testId(47), auditEventId: testId(49) }
        ])
      ).resolves.toMatchObject({ replayed: true, turnId: testId(40) });

      const followUp = prepareManagementQuestionTurn({
        questionId: workflow.prepared.questionId,
        turnKind: "follow_up",
        text: "Please bind this later immutable turn too.\n",
        citations: [],
        dueAt: "2099-09-04T12:00:00Z"
      });
      await withRequestTransaction(
        pool,
        workflow.asker.context,
        (client) =>
          followUpManagementQuestionInTransaction(client, {
            organizationId: workflow.asker.organizationId,
            prepared: followUp,
            turnId: testId(900),
            auditEventId: testId(901),
            idempotencyRecordId: testId(902),
            idempotencyKey: "linked-question-follow-up-0001",
            ownerDeliveries: [
              {
                ownerMemberId: workflow.manager.memberId,
                noticeId: testId(903),
                feedId: testId(904)
              }
            ],
            sourceUpdateAuditEvents: [
              {
                voteId: votes.linkedVoteId,
                causeId: testId(905),
                auditEventId: testId(906)
              }
            ]
          }),
        { assumeRole: "boardagent_server" }
      );

      const state = await pool.query<{
        event_types: string[];
        linked_row_version: string;
        linked_state: string;
        source_package_id: string;
        source_cause_count: string;
        unlinked_row_version: string;
        unlinked_state: string;
      }>(
        `select linked.state as linked_state,linked.row_version::text as linked_row_version,
                unlinked.state as unlinked_state,
                unlinked.row_version::text as unlinked_row_version,
                (select array_agg(event_type order by sequence) from audit_events) as event_types,
                (select convert_from(canonical_payload,'UTF8')::jsonb
                          #>> '{details,decisionPackageId}'
                   from audit_events where event_type='vote_source_update_pending'
                   order by sequence limit 1)
                  as source_package_id,
                (select count(*)::text from vote_source_update_causes
                  where vote_id=linked.id and source_class='question_cutoff')
                  as source_cause_count
           from votes as linked
           join votes as unlinked on unlinked.id=$2
          where linked.id=$1`,
        [votes.linkedVoteId, votes.unlinkedVoteId]
      );
      expect(state.rows[0]).toEqual({
        linked_state: "source_update_pending",
        linked_row_version: "4",
        unlinked_state: "open",
        unlinked_row_version: "2",
        event_types: [
          "management_question_asked",
          "management_question_answered",
          "vote_source_update_pending",
          "management_question_followed_up",
          "vote_source_update_pending"
        ],
        source_package_id: votes.linkedPackageId,
        source_cause_count: "2"
      });
    });
  });

  it("rolls an answered projection, deliveries and audit back together and retries safely", async () => {
    await withDatabase(async (pool) => {
      const workflow = await seedQuestionWorkflow(pool);
      const answer = prepareManagementQuestionTurn({
        questionId: workflow.prepared.questionId,
        turnKind: "answer",
        text: "This answer must commit exactly once.\n",
        citations: []
      });
      const writeAnswer = (client: Parameters<typeof answerManagementQuestionInTransaction>[0]) =>
        answerManagementQuestionInTransaction(client, {
          organizationId: workflow.manager.organizationId,
          prepared: answer,
          turnId: testId(40),
          answerRecordId: testId(41),
          auditEventId: testId(42),
          idempotencyRecordId: testId(43),
          idempotencyKey: "question-answer-crash-retry-0001",
          askerDelivery: {
            recipientMemberId: workflow.asker.memberId,
            noticeId: testId(44),
            feedId: testId(45)
          },
          ownerResolutions: [{ ownerMemberId: workflow.manager.memberId, tombstoneId: testId(46) }],
          sourceUpdateAuditEvents: []
        });

      await expect(
        withRequestTransaction(
          pool,
          workflow.manager.context,
          async (client) => {
            await writeAnswer(client);
            throw new Error("synthetic crash before commit");
          },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("synthetic crash before commit");

      const rolledBack = await pool.query<{
        answer_idempotency: string;
        audit_count: string;
        notice_count: string;
        owner_pending: string;
        state: string;
        tombstone_count: string;
        turn_count: string;
      }>(
        `select question.state,
                (select count(*)::text from management_question_turns) as turn_count,
                (select count(*)::text from audit_events) as audit_count,
                (select count(*)::text from notices) as notice_count,
                (select count(*)::text from feed_tombstones) as tombstone_count,
                (select count(*)::text from pending_action_feed
                  where member_id=$2 and state='pending') as owner_pending,
                (select count(*)::text from idempotency_records
                  where operation='answer_management_question') as answer_idempotency
           from management_questions as question where question.id=$1`,
        [workflow.prepared.questionId, workflow.manager.memberId]
      );
      expect(rolledBack.rows[0]).toEqual({
        state: "pending",
        turn_count: "1",
        audit_count: "1",
        notice_count: "1",
        tombstone_count: "0",
        owner_pending: "1",
        answer_idempotency: "0"
      });

      await expect(
        withRequestTransaction(pool, workflow.manager.context, writeAnswer, {
          assumeRole: "boardagent_server"
        })
      ).resolves.toMatchObject({ replayed: false, turnId: testId(40) });
    });
  });

  it("serializes concurrent questions into contiguous owner feed and audit sequences", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["management:question"]
      });
      const ownerId = await seedManagementOwner(pool, actor.organizationId, actor.boardId);
      const questions = [
        prepareManagementQuestion({
          questionId: testId(30),
          boardId: actor.boardId,
          question: "Concurrent question one\n",
          assignedOwnerIds: [ownerId],
          dueAt: "2099-09-02T12:00:00Z",
          citations: [],
          visibility: [{ granteeType: "seat_role", seatRole: "observer" }]
        }),
        prepareManagementQuestion({
          questionId: testId(40),
          boardId: actor.boardId,
          question: "Concurrent question two\n",
          assignedOwnerIds: [ownerId],
          dueAt: "2099-09-02T13:00:00Z",
          citations: [],
          visibility: [{ granteeType: "seat_role", seatRole: "observer" }]
        })
      ] as const;
      await Promise.all(
        questions.map((prepared, index) => {
          const base = index === 0 ? 31 : 41;
          return withRequestTransaction(
            pool,
            actor.context,
            (client) =>
              askManagementQuestionInTransaction(client, {
                organizationId: actor.organizationId,
                prepared,
                initialTurnId: testId(base),
                auditEventId: testId(base + 1),
                idempotencyRecordId: testId(base + 2),
                idempotencyKey: `concurrent-question-${String(index + 1).padStart(4, "0")}`,
                visibilityRecordIds: [testId(base + 3)],
                ownerDeliveries: [
                  { ownerMemberId: ownerId, noticeId: testId(base + 4), feedId: testId(base + 5) }
                ]
              }),
            { assumeRole: "boardagent_server" }
          );
        })
      );

      const sequences = await pool.query<{ feed_sequence: string }>(
        `select feed_sequence::text from pending_action_feed
          where member_id=$1 order by feed_sequence`,
        [ownerId]
      );
      const audit = await pool.query<{ sequence: string }>(
        "select sequence::text from audit_events order by sequence"
      );
      expect(sequences.rows).toEqual([{ feed_sequence: "1" }, { feed_sequence: "2" }]);
      expect(audit.rows).toEqual([{ sequence: "1" }, { sequence: "2" }]);
    });
  });

  it("fails closed on an inactive assigned owner before any durable question write", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["management:question"]
      });
      const ownerId = await seedManagementOwner(pool, actor.organizationId, actor.boardId);
      await pool.query(
        "update members set state='suspended',row_version=row_version+1 where id=$1",
        [ownerId]
      );
      const prepared = prepareManagementQuestion({
        questionId: testId(30),
        boardId: actor.boardId,
        question: "This must not create a partial thread.\n",
        assignedOwnerIds: [ownerId],
        dueAt: "2099-09-02T12:00:00Z",
        citations: [],
        visibility: [{ granteeType: "seat_role", seatRole: "observer" }]
      });
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            askManagementQuestionInTransaction(client, {
              organizationId: actor.organizationId,
              prepared,
              initialTurnId: testId(31),
              auditEventId: testId(32),
              idempotencyRecordId: testId(33),
              idempotencyKey: "inactive-owner-question-0001",
              visibilityRecordIds: [testId(34)],
              ownerDeliveries: [
                { ownerMemberId: ownerId, noticeId: testId(35), feedId: testId(36) }
              ]
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/assigned management owners are unavailable/u);
      const counts = await pool.query<{ audits: string; idempotency: string; questions: string }>(
        `select (select count(*)::text from management_questions) as questions,
                (select count(*)::text from idempotency_records) as idempotency,
                (select count(*)::text from audit_events) as audits`
      );
      expect(counts.rows[0]).toEqual({ questions: "0", idempotency: "0", audits: "0" });
    });
  });

  it("inherits cited-document ACL and refuses to assign an owner who cannot read it", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["management:question", "documents:read"]
      });
      const ownerId = await seedManagementOwner(pool, actor.organizationId, actor.boardId);
      const documentId = testId(60);
      const versionId = testId(61);
      const documentSha256 = testHash(70);
      const client = await pool.connect();
      try {
        await client.query("begin");
        await client.query(
          `insert into documents(
             id,organization_id,board_id,title,current_version_id,created_by
           ) values ($1,$2,$3,'Cited source',$4,$5)`,
          [documentId, actor.organizationId, actor.boardId, versionId, actor.memberId]
        );
        await client.query(
          `insert into document_versions(
             id,organization_id,board_id,document_id,version,media_type,
             canonicalization_version,canonical_bytes,byte_length,sha256,
             canonical_metadata,created_by
           ) values ($1,$2,$3,$4,1,'text/plain; charset=utf-8','RFC8785+NFC-LF-v1',
             $5,6,$6,'{}',$7)`,
          [
            versionId,
            actor.organizationId,
            actor.boardId,
            documentId,
            Buffer.from("Source"),
            documentSha256,
            actor.memberId
          ]
        );
        await client.query("commit");
      } catch (error) {
        await client.query("rollback");
        throw error;
      } finally {
        client.release();
      }
      const prepared = prepareManagementQuestion({
        questionId: testId(30),
        boardId: actor.boardId,
        question: "Please explain the cited source.\n",
        assignedOwnerIds: [ownerId],
        dueAt: "2099-09-02T12:00:00Z",
        citations: [
          {
            sourceDocumentVersionId: versionId,
            sourceDocumentSha256: documentSha256.toString("hex"),
            clause: "Forecast",
            locator: "line 1"
          }
        ],
        visibility: [{ granteeType: "seat_role", seatRole: "observer" }]
      });
      const ask = () =>
        withRequestTransaction(
          pool,
          actor.context,
          (requestClient) =>
            askManagementQuestionInTransaction(requestClient, {
              organizationId: actor.organizationId,
              prepared,
              initialTurnId: testId(31),
              auditEventId: testId(32),
              idempotencyRecordId: testId(33),
              idempotencyKey: "question-citation-owner-acl-0001",
              visibilityRecordIds: [testId(34)],
              ownerDeliveries: [
                { ownerMemberId: ownerId, noticeId: testId(35), feedId: testId(36) }
              ]
            }),
          { assumeRole: "boardagent_server" }
        );
      await expect(ask()).rejects.toThrow(/cannot receive the question/u);
      await pool.query(
        `insert into document_access_grants(
           id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by
         ) values ($1,$2,$3,$4,$5,'read',$6)`,
        [testId(62), actor.organizationId, actor.boardId, documentId, ownerId, actor.memberId]
      );
      await expect(ask()).resolves.toMatchObject({
        replayed: false,
        questionId: prepared.questionId
      });
      const stored = await pool.query<{ inherited: string[] }>(
        `select array(select jsonb_array_elements_text(acl_policy->'inheritedDocumentIds'))
                  as inherited
           from management_questions where id=$1`,
        [prepared.questionId]
      );
      expect(stored.rows[0]?.inherited).toEqual([documentId]);
    });
  });
});
