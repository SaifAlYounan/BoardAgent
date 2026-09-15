import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface TaskToolProjectionMetadata {
  readonly task_id: string;
  readonly board_id: string;
  readonly member_id: string;
  readonly row_version: string;
  readonly observation_sha256: string;
  readonly evidence_count: string;
  readonly review_count: string;
  readonly closure_count: string;
  readonly cycle_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface TaskToolProjectionRow {
  readonly view: JsonValue;
}

const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hashText = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const root = [
  ["task_id", "task.id"],
  ["board_id", "task.board_id"],
  ["source_meeting_id", "task.source_meeting_id"],
  ["source_minutes_id", "task.source_minutes_id"],
  ["source_minutes_version_id", "task.source_minutes_version_id"],
  ["source_minutes_sha256", "task.source_minutes_sha256"],
  ["owner_member_id", "task.owner_member_id"],
  ["due_at", "task.due_at"],
  ["description_schema", "task.description_schema"],
  ["canonical_description", "task.canonical_description"],
  ["task_sha256", "task.task_sha256"],
  ["state", "task.state"],
  ["row_version", "task.row_version"],
  ["created_at", "task.created_at"],
  ["completed_at", "task.completed_at"],
  ["cancelled_at", "task.cancelled_at"]
] as const;
const evidence = [
  ["evidence_id", "evidence.id"],
  ["canonical_text", "evidence.canonical_text"],
  ["sha256", "evidence.sha256"],
  ["state", "evidence.state"],
  ["row_version", "evidence.row_version"],
  ["submitted_at", "evidence.submitted_at_text"]
] as const;
const review = [
  ["review_id", "evidence.review_id"],
  ["decision", "evidence.decision"],
  ["reason", "evidence.reason"],
  ["secretary_member_id", "evidence.secretary_member_id"],
  ["reviewed_at", "evidence.reviewed_at"]
] as const;
const closure = [
  ["closure_id", "closure.id"],
  ["primary_evidence_id", "closure.primary_evidence_id"],
  ["source_minutes_sha256", "closure.source_minutes_sha256"],
  ["secretary_member_id", "closure.secretary_member_id"],
  ["closure_sha256", "closure.closure_sha256"],
  ["closed_at", "closure.closed_at"]
] as const;
const cycle = [
  ["cycle_id", "cycle.id"],
  ["prior_task_id", "cycle.prior_task_id"],
  ["replacement_task_id", "cycle.replacement_task_id"],
  ["reason", "cycle.reason"],
  ["created_at", "cycle.created_at"]
] as const;
const pairs = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([key, value]) => `'${key}',${value}`).join(",\n");
const sum = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([, value]) => utf8(value)).join("+");

// Preserve the original get_task/get_action_item graph exactly: the task row, every
// evidence row with its latest review, the single closure and every correction cycle
// on either side of the task. Parsing, traversal, hashing and aggregate workspace stay
// in PostgreSQL and are not covered by the Node allocation policy.
const measured = `with recursive visible_task as materialized (
  select task.id,task.board_id,task.source_meeting_id,task.source_minutes_id,
    task.source_minutes_version_id,
    case when task.source_minutes_sha256 is null then null
      else encode(task.source_minutes_sha256,'hex') end as source_minutes_sha256,
    task.source_locator,task.owner_member_id,${utc("task.due_at")} as due_at,
    task.description_schema,task.canonical_description,task.required_evidence,
    encode(task.task_sha256,'hex') as task_sha256,task.state,task.row_version::text as row_version,
    ${utc("task.created_at")} as created_at,
    case when task.completed_at is null then null else ${utc("task.completed_at")} end as completed_at,
    case when task.cancelled_at is null then null else ${utc("task.cancelled_at")} end as cancelled_at
  from tasks as task
  where task.id=$1 and (not $2::boolean or task.source_minutes_id is not null)
    and (task.owner_member_id=$3 or task.created_by=$3 or exists (
      select 1 from board_memberships as membership where membership.board_id=task.board_id
        and membership.member_id=$3 and membership.state='active'
    ))
), selected_evidence as materialized (
  select evidence.id,evidence.canonical_text,evidence.document_references,
    evidence.resource_references,encode(evidence.canonical_sha256,'hex') as sha256,
    evidence.state,evidence.row_version::text as row_version,evidence.submitted_at,
    ${utc("evidence.submitted_at")} as submitted_at_text,
    review.id as review_id,review.decision,review.reason,review.secretary_member_id,
    ${utc("review.reviewed_at")} as reviewed_at
  from task_evidence as evidence
  left join lateral (
    select review.id,review.decision,review.reason,review.secretary_member_id,review.reviewed_at
    from task_evidence_reviews as review where review.evidence_id=evidence.id
    order by review.reviewed_at desc limit 1
  ) as review on true
  where evidence.task_id in (select id from visible_task)
), selected_closure as materialized (
  select closure.id,closure.primary_evidence_id,closure.accepted_evidence_manifest,
    case when closure.source_minutes_sha256 is null then null
      else encode(closure.source_minutes_sha256,'hex') end as source_minutes_sha256,
    closure.secretary_member_id,encode(closure.closure_sha256,'hex') as closure_sha256,
    ${utc("closure.closed_at")} as closed_at
  from task_closures as closure where closure.task_id in (select id from visible_task) limit 1
), selected_cycles as materialized (
  select cycle.id,cycle.prior_task_id,cycle.replacement_task_id,cycle.reason,
    cycle.created_at as created_at_order,${utc("cycle.created_at")} as created_at
  from task_correction_cycles as cycle
  where exists (select 1 from visible_task as task
    where cycle.prior_task_id=task.id or cycle.replacement_task_id=task.id)
), json_roots(value) as (
  select source_locator from visible_task where source_locator is not null
  union all
  select required_evidence from visible_task
  union all
  select document_references from selected_evidence
  union all
  select resource_references from selected_evidence
  union all
  select accepted_evidence_manifest from selected_closure
), json_nodes(value,member) as (
  select value,false from json_roots
  union all
  select child.value,child.member from json_nodes as node cross join lateral (
    select entry.value,true as member from jsonb_each(
      case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member from jsonb_array_elements(
      case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), measured as materialized (
  select task.id as task_id,task.board_id,$3::uuid as member_id,task.row_version,
    (select count(*)::text from selected_evidence) as evidence_count,
    (select count(*) filter (where review_id is not null)::text from selected_evidence) as review_count,
    (select count(*)::text from selected_closure) as closure_count,
    (select count(*)::text from selected_cycles) as cycle_count,
    ((${sum(root)})+
      coalesce((select sum(${sum(evidence)}+${sum(review)}) from selected_evidence as evidence),0)+
      coalesce((select sum(${sum(closure)}) from selected_closure as closure),0)+
      coalesce((select sum(${sum(cycle)}) from selected_cycles as cycle),0))::text as scalar_utf8,
    (select coalesce(sum(${utf8("value")}),0)::text from json_roots) as json_utf8,
    (select count(*) filter (where member)::text from json_nodes) as json_properties,
    (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text from json_nodes) as json_containers,
    ${hashText(`jsonb_build_array(task.id,task.board_id,$3::uuid,task.row_version,
      (select string_agg(evidence.id::text||':'||evidence.row_version||':'||coalesce(evidence.review_id::text,''),','
        order by evidence.submitted_at,evidence.id) from selected_evidence as evidence),
      (select id from selected_closure),
      (select string_agg(cycle.id::text,',' order by cycle.created_at_order,cycle.id) from selected_cycles as cycle))`)} as observation_sha256
  from visible_task as task
)`;
export const TASK_TOOL_PREFLIGHT_SQL = `${measured} select * from measured`;
export const TASK_TOOL_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,board_id=$4::uuid and observation_sha256=$5::text
    and evidence_count=$6::text and review_count=$7::text and closure_count=$8::text
    and cycle_count=$9::text
    and scalar_utf8::numeric<=$10::numeric and json_utf8::numeric<=$11::numeric
    and json_properties::numeric<=$12::numeric and json_containers::numeric<=$13::numeric as fits
  from measured
)
select gated.task_id,gated.board_id,gated.member_id,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${pairs(root)},
      'source_locator',task.source_locator,
      'required_evidence',task.required_evidence,
      'evidence',coalesce((select jsonb_agg(jsonb_build_object(${pairs(evidence)},
        'document_references',evidence.document_references,
        'resource_references',evidence.resource_references,
        'review',case when evidence.review_id is null then null
          else jsonb_build_object(${pairs(review)}) end)
        order by evidence.submitted_at,evidence.id) from selected_evidence as evidence),'[]'::jsonb),
      'closure',(select jsonb_build_object(${pairs(closure)},
        'accepted_evidence_manifest',closure.accepted_evidence_manifest) from selected_closure as closure),
      'correction_cycles',coalesce((select jsonb_agg(jsonb_build_object(${pairs(cycle)})
        order by cycle.created_at_order,cycle.id) from selected_cycles as cycle),'[]'::jsonb))
    from visible_task as task
  ) else null end as view from gated`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("task tool projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("task tool projection scalar is invalid");
  return BigInt(value);
}
export function taskToolProjectionCost(
  metadata: TaskToolProjectionMetadata
): ListProjectionScalars {
  const e = scalar(metadata.evidence_count),
    r = scalar(metadata.review_count),
    c = scalar(metadata.closure_count),
    y = scalar(metadata.cycle_count),
    s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  if (r > e) throw new TypeError("task tool projection review count is invalid");
  if (c > 1n) throw new TypeError("task tool projection closure count is invalid");
  // Fixed 21/9/5/7/5-key objects cost 495/197/105/190/110 (2 + sum(key + 10), plus two
  // bytes per array item). Existing JSONB text N enters once; graph counts are exact.
  // This is policy accounting, not measured RSS.
  return {
    jsonUpperBytes: (495n + 197n * e + 105n * r + 190n * c + 110n * y + 6n * s + n).toString(),
    propertyCount: (21n + 9n * e + 5n * r + 7n * c + 5n * y + p).toString(),
    objectOrArrayCount: (3n + e + r + c + y + o).toString()
  };
}
export function taskToolProjectionPlan(
  metadata: TaskToolProjectionMetadata
): ResponseAllocationPlan {
  if (scalar(metadata.row_version) < 1n) throw new TypeError("task row version is invalid");
  if (!/^[0-9a-f]{64}$/u.test(metadata.observation_sha256))
    throw new TypeError("task tool observation hash is invalid");
  return responseAllocationPlan({
    kind: "task_tool_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.task_id,
    sourceVersion: metadata.row_version,
    sha256: metadata.observation_sha256,
    listProjection: taskToolProjectionCost(metadata)
  });
}
export async function loadAdmittedTaskToolProjection(
  client: PoolClient,
  input: { readonly taskId: string; readonly actionOnly: boolean; readonly memberId: string }
): Promise<TaskToolProjectionRow | null> {
  const { taskId, actionOnly, memberId } = input;
  const observed = await client.query<TaskToolProjectionMetadata>(TASK_TOOL_PREFLIGHT_SQL, [
    taskId,
    actionOnly,
    memberId
  ]);
  if (observed.rows.length > 1) throw new TypeError("task tool preflight returned multiple rows");
  const metadata = observed.rows[0];
  if (!metadata) return null;
  if (metadata.task_id !== taskId || metadata.member_id !== memberId || !metadata.board_id)
    throw new TypeError("task tool preflight identity is invalid");
  const loaded = await loadWithResponseAllocation(taskToolProjectionPlan(metadata), () =>
    client.query<{
      task_id: string;
      board_id: string;
      member_id: string;
      observation_sha256: string;
      fits: boolean;
      view: JsonValue;
    }>(TASK_TOOL_CONTENT_SQL, [
      taskId,
      actionOnly,
      memberId,
      metadata.board_id,
      metadata.observation_sha256,
      metadata.evidence_count,
      metadata.review_count,
      metadata.closure_count,
      metadata.cycle_count,
      metadata.scalar_utf8,
      metadata.json_utf8,
      metadata.json_properties,
      metadata.json_containers
    ])
  );
  if (loaded.rows.length > 1) throw new TypeError("task tool projection returned multiple rows");
  const row = loaded.rows[0];
  if (!row) return null;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    row.task_id !== taskId ||
    row.board_id !== metadata.board_id ||
    row.member_id !== memberId ||
    row.observation_sha256 !== metadata.observation_sha256 ||
    row.view === null ||
    typeof row.view !== "object" ||
    Array.isArray(row.view)
  )
    throw new TypeError("task tool projection identity is invalid");
  const view = row.view as Readonly<Record<string, JsonValue>>;
  const evidenceRows = view["evidence"];
  const cycles = view["correction_cycles"];
  if (
    view["task_id"] !== taskId ||
    view["board_id"] !== metadata.board_id ||
    view["row_version"] !== metadata.row_version ||
    !Array.isArray(evidenceRows) ||
    BigInt(evidenceRows.length) !== scalar(metadata.evidence_count) ||
    !Array.isArray(cycles) ||
    BigInt(cycles.length) !== scalar(metadata.cycle_count) ||
    (view["closure"] === null) !== (metadata.closure_count === "0")
  )
    throw new TypeError("task tool payload identity is invalid");
  return { view: row.view };
}
