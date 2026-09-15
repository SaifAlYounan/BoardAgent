import type { PoolClient } from "pg";

import { Rfc3339UtcSchema, UuidV7Schema } from "@boardagent/contracts";
import type { ManagementQuestionCitation } from "@boardagent/domain";

import { readRequestContext } from "./transactions/request-context.js";

export type ManagementQuestionState = "pending" | "overdue" | "answered";

export interface ManagementQuestionListCursor {
  readonly createdAt: string;
  readonly questionId: string;
}

export interface ManagementQuestionListItem {
  readonly questionId: string;
  readonly boardId: string;
  readonly askerMemberId: string;
  readonly assignedOwnerIds: readonly string[];
  readonly dueAt: string;
  readonly state: ManagementQuestionState;
  readonly currentTurnId: string;
  readonly rowVersion: string;
  readonly turnCount: number;
  readonly answerCount: number;
  readonly createdAt: string;
}

export interface ListManagementQuestionsInput {
  readonly boardId: string;
  readonly state?: ManagementQuestionState;
  readonly limit?: number;
  readonly after?: ManagementQuestionListCursor;
}

export interface ListManagementQuestionsResult {
  readonly items: readonly ManagementQuestionListItem[];
  readonly totalVisible: number;
  readonly nextCursor: ManagementQuestionListCursor | null;
}

export interface ManagementQuestionTurnView {
  readonly turnId: string;
  readonly ordinal: number;
  readonly turnKind: "question" | "answer" | "follow_up";
  readonly authorMemberId: string;
  readonly authorRole: "voting_member" | "management" | "observer" | "secretariat";
  readonly canonicalText: string;
  readonly textSha256: string;
  readonly citations: readonly ManagementQuestionCitation[];
  readonly answerRecordId: string | null;
  readonly createdAt: string;
}

export interface ManagementQuestionDeliveryView {
  readonly noticeId: string;
  readonly noticeType: string;
  readonly objectVersion: string;
  readonly recipientMemberId: string;
  readonly feedSequence: string;
  readonly state: "committed" | "delivered" | "superseded" | "cancelled";
  readonly auditEventId: string;
  readonly createdAt: string;
}

export interface ManagementQuestionDecisionLinkView {
  readonly linkId: string;
  readonly inclusiveTurnOrdinal: number;
  readonly inclusiveTurnSha256: string;
  readonly decisionPackageId: string;
  readonly decisionPackageVersion: number;
  readonly decisionPackageSha256: string;
  readonly createdAt: string;
}

export interface ManagementQuestionView extends ManagementQuestionListItem {
  readonly aclPolicy: Readonly<Record<string, unknown>>;
  readonly turns: readonly ManagementQuestionTurnView[];
  readonly deliveries: readonly ManagementQuestionDeliveryView[];
  readonly decisionLinks: readonly ManagementQuestionDecisionLinkView[];
}

interface ListQueryRow {
  readonly items: ManagementQuestionListItem[];
  readonly total_visible: string;
}

function boundedLimit(value: number | undefined): number {
  const limit = value ?? 50;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
    throw new RangeError("management question list limit must be an integer from 1 through 500");
  }
  return limit;
}

function stateFilter(value: ManagementQuestionState | undefined): ManagementQuestionState | null {
  if (value === undefined) return null;
  if (value !== "pending" && value !== "overdue" && value !== "answered") {
    throw new TypeError("management question state filter is invalid");
  }
  return value;
}

function count(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} returned an invalid count`);
  }
  return parsed;
}

function normalizeCursor(
  cursor: ManagementQuestionListCursor | undefined
): ManagementQuestionListCursor | null {
  if (!cursor) return null;
  return {
    createdAt: Rfc3339UtcSchema.parse(cursor.createdAt),
    questionId: UuidV7Schema.parse(cursor.questionId)
  };
}

export async function listManagementQuestionsInTransaction(
  client: PoolClient,
  input: ListManagementQuestionsInput
): Promise<ListManagementQuestionsResult> {
  await readRequestContext(client);
  const boardId = UuidV7Schema.parse(input.boardId);
  const state = stateFilter(input.state);
  const limit = boundedLimit(input.limit);
  const cursor = normalizeCursor(input.after);
  const result = await client.query<ListQueryRow>(
    `with visible as materialized (
       select question.id as question_id,
              question.board_id,
              question.asker_member_id,
              question.assigned_owner_ids,
              to_char(question.due_at at time zone 'UTC',
                      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as due_at,
              question.state,
              question.current_turn_id,
              question.row_version::text as row_version,
              to_char(question.created_at at time zone 'UTC',
                      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as created_at,
              question.created_at as created_sort,
              (select count(*)::integer from management_question_turns as turn
                where turn.question_id=question.id) as turn_count,
              (select count(*)::integer from management_question_answers as answer
                where answer.question_id=question.id) as answer_count
         from management_questions as question
        where question.board_id=$1 and ($2::text is null or question.state=$2)
     ), page as (
       select * from visible
        where ($3::timestamptz is null or (created_sort,question_id) < ($3::timestamptz,$4::uuid))
        order by created_sort desc,question_id desc
        limit $5
     )
     select (select count(*)::text from visible) as total_visible,
            coalesce((
              select jsonb_agg(jsonb_build_object(
                'questionId',page.question_id,
                'boardId',page.board_id,
                'askerMemberId',page.asker_member_id,
                'assignedOwnerIds',to_jsonb(page.assigned_owner_ids),
                'dueAt',page.due_at,
                'state',page.state,
                'currentTurnId',page.current_turn_id,
                'rowVersion',page.row_version,
                'turnCount',page.turn_count,
                'answerCount',page.answer_count,
                'createdAt',page.created_at
              ) order by page.created_sort desc,page.question_id desc)
                from page
            ),'[]'::jsonb) as items`,
    [boardId, state, cursor?.createdAt ?? null, cursor?.questionId ?? null, limit + 1]
  );
  const row = result.rows[0];
  if (!row) throw new Error("management question list query returned no aggregate row");
  const totalVisible = count(row.total_visible, "management question list");
  const hasMore = row.items.length > limit;
  const items = row.items.slice(0, limit);
  const last = items.at(-1);
  return {
    items,
    totalVisible,
    nextCursor: hasMore && last ? { createdAt: last.createdAt, questionId: last.questionId } : null
  };
}

// These scalar observations cross the database boundary before any question
// result/child object is constructed. PostgreSQL's own workspace is not bounded.
export interface ManagementQuestionProjectionMetadata {
  readonly question_id: string;
  readonly board_id: string;
  readonly row_version: string;
  readonly current_turn_id: string | null;
  readonly turn_count: string;
  readonly answer_count: string;
  readonly projected_turn_count: string;
  readonly delivery_count: string;
  readonly link_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}

// A required server-owned port keeps lib/db independent of native request state.
// reserve must throw before content if the plan is inadmissible; there is no
// release capability here. The native owner retains the lease through delivery.
export interface ManagementQuestionProjectionAdmission {
  assertLive(): void;
  reserve(metadata: ManagementQuestionProjectionMetadata): void;
  unavailable(): never;
}

const questionUtc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const questionUtf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const questionFields = {
  root: [
    ["questionId", "question.question_id"],
    ["boardId", "question.board_id"],
    ["askerMemberId", "question.asker_member_id"],
    ["dueAt", "question.due_at"],
    ["state", "question.state"],
    ["currentTurnId", "question.current_turn_id"],
    ["rowVersion", "question.row_version"],
    ["turnCount", "question.turn_count"],
    ["answerCount", "question.answer_count"],
    ["createdAt", "question.created_at"]
  ],
  turn: [
    ["turnId", "turn.id"],
    ["ordinal", "turn.ordinal"],
    ["turnKind", "turn.turn_kind"],
    ["authorMemberId", "turn.author_member_id"],
    ["authorRole", "turn.author_role"],
    ["canonicalText", "turn.canonical_text"],
    ["textSha256", "encode(turn.text_sha256,'hex')"],
    ["answerRecordId", "turn.answer_record_id"],
    ["createdAt", questionUtc("turn.created_at")]
  ],
  notice: [
    ["noticeId", "notice.id"],
    ["noticeType", "notice.notice_type"],
    ["objectVersion", "notice.object_version::text"],
    ["recipientMemberId", "notice.recipient_member_id"],
    ["feedSequence", "notice.feed_sequence::text"],
    ["state", "notice.state"],
    ["auditEventId", "notice.audit_event_id"],
    ["createdAt", questionUtc("notice.created_at")]
  ],
  link: [
    ["linkId", "link.id"],
    ["inclusiveTurnOrdinal", "link.inclusive_turn_ordinal"],
    ["inclusiveTurnSha256", "encode(link.inclusive_turn_sha256,'hex')"],
    ["decisionPackageId", "link.decision_package_id"],
    ["decisionPackageVersion", "link.decision_package_version"],
    ["decisionPackageSha256", "encode(link.decision_package_sha256,'hex')"],
    ["createdAt", questionUtc("link.created_at")]
  ]
} as const;
const questionScalarSum = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([, value]) => questionUtf8(value)).join("+");
const questionJsonPairs = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([key, value]) => `'${key}',${value}`).join(",\n");

// Both statements reuse the complete visibility and cost query. The optional
// board selector is a resource-URI boundary; changed versions do not disappear
// from visible_question, so they produce an explicit blocked result below.
const questionMeasured = `with recursive visible_question as materialized (
  select question.id as question_id,question.board_id,question.asker_member_id,
    question.assigned_owner_ids,${questionUtc("question.due_at")} as due_at,
    question.acl_policy,question.state,question.current_turn_id,
    question.row_version::text as row_version,${questionUtc("question.created_at")} as created_at
  from management_questions as question
  where question.id=$1 and ($2::uuid is null or question.board_id=$2)
), question_root as materialized (
  select question.*,
    (select count(*) from management_question_turns as turn
      where turn.question_id=question.question_id) as turn_count,
    (select count(*) from management_question_answers as answer
      where answer.question_id=question.question_id) as answer_count
  from visible_question as question
), projected_turns as materialized (
  select turn.*,answer.id as answer_record_id
  from management_question_turns as turn
  left join management_question_answers as answer
    on answer.question_id=turn.question_id and answer.answer_turn_id=turn.id
  where turn.question_id in (select question_id from question_root)
), projected_notices as materialized (
  select notice.* from notices as notice
  where notice.object_type='question'
    and notice.object_id in (select question_id from question_root)
), projected_links as materialized (
  select link.* from question_decision_links as link
  where link.question_id in (select question_id from question_root)
    and exists (select 1 from decision_packages as package
      where package.id=link.decision_package_id
        and not boardagent_member_vote_recused(package.vote_id,
          boardagent_context_uuid('boardagent.member_id')))
), json_roots(value) as materialized (
  select acl_policy from question_root
  union all select to_jsonb(assigned_owner_ids) from question_root
  union all select citation_snapshot from projected_turns
), json_nodes(value,member) as (
  select value,false from json_roots
  union all
  select child.value,child.member from json_nodes as node
  cross join lateral (
    select entry.value,true as member from jsonb_each(
      case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member from jsonb_array_elements(
      case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), measured as materialized (
  select question.question_id,question.board_id,question.row_version,question.current_turn_id,
    question.turn_count::text as turn_count,question.answer_count::text as answer_count,
    (select count(*)::text from projected_turns) as projected_turn_count,
    (select count(*)::text from projected_notices) as delivery_count,
    (select count(*)::text from projected_links) as link_count,
    ((${questionScalarSum(questionFields.root)})
      +coalesce((select sum(${questionScalarSum(questionFields.turn)}) from projected_turns as turn),0)
      +coalesce((select sum(${questionScalarSum(questionFields.notice)}) from projected_notices as notice),0)
      +coalesce((select sum(${questionScalarSum(questionFields.link)}) from projected_links as link),0)
    )::text as scalar_utf8,
    (select coalesce(sum(${questionUtf8("value")}),0)::text from json_roots) as json_utf8,
    (select count(*) filter (where member)::text from json_nodes) as json_properties,
    (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text
       from json_nodes) as json_containers
  from question_root as question
)`;

export const QUESTION_PROJECTION_PREFLIGHT_SQL = `${questionMeasured}
select * from measured`;
const questionBoundFields = [
  "turn_count",
  "answer_count",
  "projected_turn_count",
  "delivery_count",
  "link_count",
  "scalar_utf8",
  "json_utf8",
  "json_properties",
  "json_containers"
] as const;

// The outer CASE protects a SEPARATE scalar content subquery. No row or child
// object/aggregate is constructed on a false branch, even if a later collection
// grew while another stayed the same. The inspected scalar work remains in PG.
export const QUESTION_PROJECTION_CONTENT_SQL = `${questionMeasured}, gated as materialized (
  select measured.*,
    board_id=$3::uuid and row_version=$4::text
    and current_turn_id is not distinct from $5::uuid
    and ${questionBoundFields.map((field, index) => `${field}::numeric<=$${String(index + 6)}::numeric`).join("\n    and ")}
      as fits
  from measured
)
select gated.fits,case when gated.fits then (
  select jsonb_build_object(
    ${questionJsonPairs(questionFields.root)},
    'assignedOwnerIds',question.assigned_owner_ids,'aclPolicy',question.acl_policy,
    'turns',coalesce((select jsonb_agg(jsonb_build_object(
      ${questionJsonPairs(questionFields.turn)},'citations',turn.citation_snapshot
    ) order by turn.ordinal) from projected_turns as turn),'[]'::jsonb),
    'deliveries',coalesce((select jsonb_agg(jsonb_build_object(
      ${questionJsonPairs(questionFields.notice)}
    ) order by notice.created_at,notice.id) from projected_notices as notice),'[]'::jsonb),
    'decisionLinks',coalesce((select jsonb_agg(jsonb_build_object(
      ${questionJsonPairs(questionFields.link)}
    ) order by link.created_at,link.id) from projected_links as link),'[]'::jsonb)
  ) from question_root as question
) else null end as question from gated`;

export async function getAdmittedManagementQuestionInTransaction(
  client: PoolClient,
  questionIdInput: string,
  admission: ManagementQuestionProjectionAdmission,
  boardIdInput?: string
): Promise<ManagementQuestionView | null> {
  admission.assertLive();
  await readRequestContext(client);
  const questionId = UuidV7Schema.parse(questionIdInput);
  const boardId = boardIdInput === undefined ? null : UuidV7Schema.parse(boardIdInput);
  admission.assertLive();
  const observed = await client.query<ManagementQuestionProjectionMetadata>(
    QUESTION_PROJECTION_PREFLIGHT_SQL,
    [questionId, boardId]
  );
  if (observed.rows.length > 1) throw new TypeError("question preflight returned multiple roots");
  const metadata = observed.rows[0];
  if (!metadata) return null;
  if (metadata.question_id !== questionId || (boardId !== null && metadata.board_id !== boardId))
    throw new TypeError("question preflight identity is invalid");
  admission.reserve(metadata);
  admission.assertLive();
  const loaded = await client.query<{ fits: boolean; question: ManagementQuestionView | null }>(
    QUESTION_PROJECTION_CONTENT_SQL,
    [
      questionId,
      boardId,
      metadata.board_id,
      metadata.row_version,
      metadata.current_turn_id,
      ...questionBoundFields.map((field) => metadata[field])
    ]
  );
  admission.assertLive();
  if (loaded.rows.length > 1) throw new TypeError("question projection returned multiple roots");
  const row = loaded.rows[0];
  if (!row) return null;
  if (row.fits === false) return admission.unavailable();
  if (
    row.fits !== true ||
    !row.question ||
    row.question.questionId !== questionId ||
    row.question.boardId !== metadata.board_id ||
    row.question.rowVersion !== metadata.row_version ||
    row.question.currentTurnId !== metadata.current_turn_id
  )
    throw new TypeError("question projection identity is invalid");
  count(String(row.question.turnCount), "management question turn");
  count(String(row.question.answerCount), "management question answer");
  return row.question;
}

// Admitted management-question list. The original list export above remains
// unchanged; this required port keeps lib/db independent of native owner state.
export interface ManagementQuestionListProjectionMetadata {
  readonly question_id: string;
  readonly created_at: string | null;
  readonly raw_created_at: string;
  readonly observation_sha256: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface ManagementQuestionListProjectionObservation {
  readonly rows: readonly ManagementQuestionListProjectionMetadata[];
  readonly total_visible: string;
  readonly row_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface ManagementQuestionListProjectionAdmission {
  assertLive(): void;
  reserve(observation: ManagementQuestionListProjectionObservation): void;
  unavailable(): never;
}
interface QuestionListPreflightRow {
  readonly total_visible: string;
  readonly question_id: string | null;
  readonly created_at: string | null;
  readonly raw_created_at: string | null;
  readonly observation_sha256: string | null;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
const questionListHash = (value: string) =>
  `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const questionListFlat = [
  "page.question_id",
  "page.board_id",
  "page.asker_member_id",
  "page.due_at",
  "page.state",
  "page.current_turn_id",
  "page.row_version",
  "page.turn_count",
  "page.answer_count",
  "page.created_at"
];
// Exact original visible/page expressions and integer count casts. The visible
// total stays independent of the cursor; only selected owners enter JSON metrics.
const questionListMeasured = `with recursive visible as materialized (
       select question.id as question_id,
              question.board_id,
              question.asker_member_id,
              question.assigned_owner_ids,
              to_char(question.due_at at time zone 'UTC',
                      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as due_at,
              question.state,
              question.current_turn_id,
              question.row_version::text as row_version,
              to_char(question.created_at at time zone 'UTC',
                      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as created_at,
              question.created_at as created_sort,
              (select count(*)::integer from management_question_turns as turn
                where turn.question_id=question.id) as turn_count,
              (select count(*)::integer from management_question_answers as answer
                where answer.question_id=question.id) as answer_count
         from management_questions as question
        where question.board_id=$1 and ($2::text is null or question.state=$2)
     ), page as materialized (
       select * from visible
        where ($3::timestamptz is null or (created_sort,question_id) < ($3::timestamptz,$4::uuid))
        order by created_sort desc,question_id desc
        limit $5
     ), json_roots(id,value) as (
  select question_id,to_jsonb(assigned_owner_ids) from page
), json_nodes(id,value,member) as (
  select id,value,false from json_roots where value is not null
  union all
  select node.id,child.value,child.member from json_nodes as node cross join lateral (
    select entry.value,true as member from jsonb_each(
      case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member from jsonb_array_elements(
      case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), json_metrics as materialized (
  select id,(count(*) filter(where member))::numeric as json_properties,
    (count(*) filter(where jsonb_typeof(value) in ('object','array')))::numeric as json_containers
  from json_nodes group by id
), measured as materialized (
  select page.*,page.created_sort::text as raw_created_at,
    (${questionListFlat.map(questionUtf8).join("+")})::text as scalar_utf8,
    ${questionUtf8("to_jsonb(page.assigned_owner_ids)")}::text as json_utf8,
    coalesce(metrics.json_properties,0)::text as json_properties,
    coalesce(metrics.json_containers,0)::text as json_containers,
    ${questionListHash(`jsonb_build_array(${questionListFlat.join(",")},${questionListHash("to_jsonb(page.assigned_owner_ids)")},page.created_sort::text)`)} as observation_sha256
  from page left join json_metrics as metrics on metrics.id=page.question_id
), total as materialized (select count(*)::text as total_visible from visible)`;
export const QUESTION_LIST_PROJECTION_PREFLIGHT_SQL = `${questionListMeasured}
  select total.total_visible,measured.question_id::text,measured.created_at,
    measured.raw_created_at,measured.observation_sha256,
    coalesce(measured.scalar_utf8,'0') as scalar_utf8,
    coalesce(measured.json_utf8,'0') as json_utf8,
    coalesce(measured.json_properties,'0') as json_properties,
    coalesce(measured.json_containers,'0') as json_containers
  from total left join measured on true order by measured.created_sort desc,measured.question_id desc`;
export const QUESTION_LIST_PROJECTION_CONTENT_SQL = `${questionListMeasured}, expected as materialized (
  select * from jsonb_to_recordset($6::jsonb) as bound(question_id uuid,created_at text,
    raw_created_at text,observation_sha256 text,scalar_utf8 numeric,json_utf8 numeric,
    json_properties numeric,json_containers numeric)
), matched as materialized (
  select fresh.*,(bound.question_id is not null and fresh.created_at is not distinct from bound.created_at
    and fresh.scalar_utf8::numeric<=bound.scalar_utf8 and fresh.json_utf8::numeric<=bound.json_utf8
    and fresh.json_properties::numeric=bound.json_properties and fresh.json_containers::numeric=bound.json_containers) as fits
  from measured as fresh left join expected as bound on bound.question_id=fresh.question_id
    and fresh.created_sort=bound.raw_created_at::timestamptz and fresh.observation_sha256=bound.observation_sha256
), global_gate as materialized (select coalesce(bool_and(fits),true) as fits from matched)
select gate.fits,total.total_visible,case when gate.fits then (
  select coalesce((select jsonb_agg(jsonb_build_object(
                'questionId',page.question_id,
                'boardId',page.board_id,
                'askerMemberId',page.asker_member_id,
                'assignedOwnerIds',to_jsonb(page.assigned_owner_ids),
                'dueAt',page.due_at,
                'state',page.state,
                'currentTurnId',page.current_turn_id,
                'rowVersion',page.row_version,
                'turnCount',page.turn_count,
                'answerCount',page.answer_count,
                'createdAt',page.created_at
              ) order by page.created_sort desc,page.question_id desc)
                from matched as page
            ),'[]'::jsonb)
) else null end as items from total cross join global_gate as gate`;
const questionListMetricFields = [
  "scalar_utf8",
  "json_utf8",
  "json_properties",
  "json_containers"
] as const;
function questionListMetric(
  value: string,
  admission: ManagementQuestionListProjectionAdmission
): bigint {
  if (typeof value !== "string") throw new TypeError("management question list scalar is invalid");
  if (value.length > 24) return admission.unavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("management question list scalar is invalid");
  return BigInt(value);
}
export async function listAdmittedManagementQuestionsInTransaction(
  client: PoolClient,
  input: ListManagementQuestionsInput,
  admission: ManagementQuestionListProjectionAdmission
): Promise<ListManagementQuestionsResult> {
  admission.assertLive();
  await readRequestContext(client);
  const boardId = UuidV7Schema.parse(input.boardId);
  const state = stateFilter(input.state);
  const limit = boundedLimit(input.limit);
  const cursor = normalizeCursor(input.after);
  const parameters = [
    boardId,
    state,
    cursor?.createdAt ?? null,
    cursor?.questionId ?? null,
    limit + 1
  ];
  admission.assertLive();
  const inspected = await client.query<QuestionListPreflightRow>(
    QUESTION_LIST_PROJECTION_PREFLIGHT_SQL,
    parameters
  );
  admission.assertLive();
  const first = inspected.rows[0];
  if (!first) throw new Error("management question list query returned no aggregate row");
  if (inspected.rows.length > limit + 1)
    throw new TypeError("management question list metadata is oversized");
  // Keep the original safe-number count validator, rather than clamp or relabel.
  count(first.total_visible, "management question list");
  if (inspected.rows.some((row) => row.total_visible !== first.total_visible))
    throw new TypeError("management question list total is inconsistent");
  let rows: readonly ManagementQuestionListProjectionMetadata[];
  if (first.question_id === null) {
    if (
      inspected.rows.length !== 1 ||
      first.created_at !== null ||
      first.raw_created_at !== null ||
      first.observation_sha256 !== null ||
      questionListMetricFields.some((field) => first[field] !== "0")
    )
      throw new TypeError("management question empty footer is invalid");
    rows = Object.freeze([]);
  } else {
    const seen = new Set<string>();
    rows = Object.freeze(
      inspected.rows.map((row) => {
        const questionId = UuidV7Schema.parse(row.question_id);
        if (
          seen.has(questionId) ||
          (row.created_at !== null && typeof row.created_at !== "string") ||
          typeof row.raw_created_at !== "string" ||
          !row.raw_created_at ||
          typeof row.observation_sha256 !== "string" ||
          !/^[0-9a-f]{64}$/u.test(row.observation_sha256)
        )
          throw new TypeError("management question list metadata identity is invalid");
        seen.add(questionId);
        for (const field of questionListMetricFields) questionListMetric(row[field], admission);
        return Object.freeze({
          question_id: questionId,
          created_at: row.created_at,
          raw_created_at: row.raw_created_at,
          observation_sha256: row.observation_sha256,
          scalar_utf8: row.scalar_utf8,
          json_utf8: row.json_utf8,
          json_properties: row.json_properties,
          json_containers: row.json_containers
        });
      })
    );
  }
  const sums = questionListMetricFields.map((field) =>
    rows.reduce((value, row) => value + questionListMetric(row[field], admission), 0n)
  );
  const observation = Object.freeze({
    rows,
    total_visible: first.total_visible,
    row_count: String(rows.length),
    scalar_utf8: sums[0]!.toString(),
    json_utf8: sums[1]!.toString(),
    json_properties: sums[2]!.toString(),
    json_containers: sums[3]!.toString()
  });
  admission.reserve(observation);
  admission.assertLive();
  const loaded = await client.query<{
    fits: boolean;
    total_visible: string;
    items: ManagementQuestionListItem[] | null;
  }>(QUESTION_LIST_PROJECTION_CONTENT_SQL, [...parameters, JSON.stringify(rows)]);
  admission.assertLive();
  const row = loaded.rows[0];
  if (!row) throw new Error("management question list query returned no aggregate row");
  if (loaded.rows.length !== 1)
    throw new TypeError("management question list returned extra aggregate rows");
  if (row.fits === false) return admission.unavailable();
  const totalVisible = count(row.total_visible, "management question list");
  if (row.fits !== true || !Array.isArray(row.items) || row.items.length > rows.length)
    throw new TypeError("management question list projection is invalid");
  let previous = -1;
  for (const item of row.items) {
    if (!item || typeof item !== "object" || Array.isArray(item))
      throw new TypeError("management question list returned an invalid item");
    const index = rows.findIndex((bound) => bound.question_id === item.questionId),
      bound = rows[index];
    if (!bound || index <= previous || item.createdAt !== bound.created_at)
      throw new TypeError("management question list returned tuple mismatch");
    previous = index;
  }
  const hasMore = row.items.length > limit;
  const items = row.items.slice(0, limit);
  const last = items.at(-1);
  return {
    items,
    totalVisible,
    nextCursor: hasMore && last ? { createdAt: last.createdAt, questionId: last.questionId } : null
  };
}
