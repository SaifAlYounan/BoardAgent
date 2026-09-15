// Test-only frozen original getter SQL and mapping from f4974fc9… question-queries.ts.
// This oracle intentionally loads this bounded fixture before saturation. It is
// never imported by runtime code and supplies no production admission bypass.
import type { PoolClient } from "pg";
import { UuidV7Schema } from "../../lib/contracts/src/index.js";
import type {
  ManagementQuestionView,
  ManagementQuestionState,
  ManagementQuestionTurnView,
  ManagementQuestionDeliveryView,
  ManagementQuestionDecisionLinkView
} from "../../lib/db/src/question-queries.js";
import { readRequestContext } from "../../lib/db/src/transactions/request-context.js";

interface GetQueryRow {
  readonly acl_policy: Readonly<Record<string, unknown>>;
  readonly answer_count: string;
  readonly asker_member_id: string;
  readonly assigned_owner_ids: string[];
  readonly board_id: string;
  readonly created_at: string;
  readonly current_turn_id: string;
  readonly decision_links: ManagementQuestionDecisionLinkView[];
  readonly deliveries: ManagementQuestionDeliveryView[];
  readonly due_at: string;
  readonly question_id: string;
  readonly row_version: string;
  readonly state: ManagementQuestionState;
  readonly turn_count: string;
  readonly turns: ManagementQuestionTurnView[];
}

function count(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} returned an invalid count`);
  }
  return parsed;
}

export async function readOriginalQuestionProjection(
  client: PoolClient,
  questionIdInput: string
): Promise<ManagementQuestionView | null> {
  await readRequestContext(client);
  const questionId = UuidV7Schema.parse(questionIdInput);
  const result = await client.query<GetQueryRow>(
    `with visible_question as materialized (
       select question.id as question_id,
              question.board_id,
              question.asker_member_id,
              question.assigned_owner_ids,
              to_char(question.due_at at time zone 'UTC',
                      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as due_at,
              question.acl_policy,
              question.state,
              question.current_turn_id,
              question.row_version::text as row_version,
              to_char(question.created_at at time zone 'UTC',
                      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as created_at
         from management_questions as question
        where question.id=$1
     )
     select question.*,
            (select count(*)::text from management_question_turns as turn
              where turn.question_id=question.question_id) as turn_count,
            (select count(*)::text from management_question_answers as answer
              where answer.question_id=question.question_id) as answer_count,
            coalesce((
              select jsonb_agg(jsonb_build_object(
                'turnId',turn.id,
                'ordinal',turn.ordinal,
                'turnKind',turn.turn_kind,
                'authorMemberId',turn.author_member_id,
                'authorRole',turn.author_role,
                'canonicalText',turn.canonical_text,
                'textSha256',encode(turn.text_sha256,'hex'),
                'citations',turn.citation_snapshot,
                'answerRecordId',answer.id,
                'createdAt',to_char(turn.created_at at time zone 'UTC',
                                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
              ) order by turn.ordinal)
                from management_question_turns as turn
                left join management_question_answers as answer
                  on answer.question_id=turn.question_id and answer.answer_turn_id=turn.id
               where turn.question_id=question.question_id
            ),'[]'::jsonb) as turns,
            coalesce((
              select jsonb_agg(jsonb_build_object(
                'noticeId',notice.id,
                'noticeType',notice.notice_type,
                'objectVersion',notice.object_version::text,
                'recipientMemberId',notice.recipient_member_id,
                'feedSequence',notice.feed_sequence::text,
                'state',notice.state,
                'auditEventId',notice.audit_event_id,
                'createdAt',to_char(notice.created_at at time zone 'UTC',
                                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
              ) order by notice.created_at,notice.id)
                from notices as notice
               where notice.object_type='question'
                 and notice.object_id=question.question_id
            ),'[]'::jsonb) as deliveries,
            coalesce((
              select jsonb_agg(jsonb_build_object(
                'linkId',link.id,
                'inclusiveTurnOrdinal',link.inclusive_turn_ordinal,
                'inclusiveTurnSha256',encode(link.inclusive_turn_sha256,'hex'),
                'decisionPackageId',link.decision_package_id,
                'decisionPackageVersion',link.decision_package_version,
                'decisionPackageSha256',encode(link.decision_package_sha256,'hex'),
                'createdAt',to_char(link.created_at at time zone 'UTC',
                                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
              ) order by link.created_at,link.id)
                from question_decision_links as link
               where link.question_id=question.question_id
                 and exists (select 1 from decision_packages as package
                   where package.id=link.decision_package_id
                     and not boardagent_member_vote_recused(package.vote_id,
                       boardagent_context_uuid('boardagent.member_id')))
            ),'[]'::jsonb) as decision_links
       from visible_question as question`,
    [questionId]
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    questionId: row.question_id,
    boardId: row.board_id,
    askerMemberId: row.asker_member_id,
    assignedOwnerIds: row.assigned_owner_ids,
    dueAt: row.due_at,
    state: row.state,
    currentTurnId: row.current_turn_id,
    rowVersion: row.row_version,
    turnCount: count(row.turn_count, "management question turn"),
    answerCount: count(row.answer_count, "management question answer"),
    createdAt: row.created_at,
    aclPolicy: row.acl_policy,
    turns: row.turns,
    deliveries: row.deliveries,
    decisionLinks: row.decision_links
  };
}
