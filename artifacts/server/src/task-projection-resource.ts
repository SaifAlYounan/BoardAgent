import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface TaskProjectionMetadata {
  readonly id: string;
  readonly board_id: string;
  readonly row_version: string;
  readonly closure_id: string | null;
  readonly observation_sha256: string;
  readonly evidence_count: string;
  readonly closure_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface TaskProjectionRow {
  readonly id: string;
  readonly row_version: string;
  readonly payload: JsonValue;
}

const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hashText = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const rootFields = [
  ["schema_version", "'boardagent.task-resource.v1'"],
  ["task_id", "task.id"],
  ["board_id", "task.board_id"],
  ["source_minutes_id", "task.source_minutes_id"],
  ["source_minutes_version_id", "task.source_minutes_version_id"],
  ["source_minutes_sha256", "task.source_minutes_sha256"],
  ["owner_member_id", "task.owner_member_id"],
  ["due_at", "task.due_at"],
  ["description_schema", "task.description_schema"],
  ["canonical_description", "task.canonical_description"],
  ["task_sha256", "task.task_sha256"],
  ["state", "task.state"],
  ["row_version", "task.row_version"]
] as const;
const evidenceFields = [
  ["evidence_id", "evidence.id"],
  ["canonical_text", "evidence.canonical_text"],
  ["sha256", "evidence.sha256"],
  ["state", "evidence.state"]
] as const;
const closureFields = [
  ["closure_id", "closure.id"],
  ["closure_sha256", "closure.closure_sha256"]
] as const;
const scalarSum = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([, value]) => utf8(value)).join("+");
const jsonPairs = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([key, value]) => `'${key}',${value}`).join(",\n");

// Only the original 16/6/3 resource fields are selected: the task row, its evidence
// rows and the single closure. Evidence reviews, correction cycles and unrelated
// tasks are never read here. PostgreSQL detoast, JSONB traversal/serialization and
// RLS workspace are outside this Node policy; only bounded scalars reach Node.
const measured = `with recursive visible_task as materialized (
  select task.id,task.board_id,task.source_minutes_id,task.source_minutes_version_id,
    case when task.source_minutes_sha256 is null then null
      else encode(task.source_minutes_sha256,'hex') end as source_minutes_sha256,
    task.owner_member_id,${utc("task.due_at")} as due_at,task.description_schema,
    task.canonical_description,task.required_evidence,
    encode(task.task_sha256,'hex') as task_sha256,task.state,task.row_version::text as row_version
  from tasks as task where task.board_id=$1 and task.id=$2
    and (not $3::boolean or task.source_minutes_id is not null)
    and (task.owner_member_id=$4 or task.created_by=$4 or exists (
      select 1 from board_memberships as membership where membership.board_id=task.board_id
        and membership.member_id=$4 and membership.state='active'))
), selected_evidence as materialized (
  select evidence.id,evidence.canonical_text,evidence.document_references,
    evidence.resource_references,encode(evidence.canonical_sha256,'hex') as sha256,
    evidence.state,evidence.row_version::text as row_version,evidence.submitted_at
  from task_evidence as evidence where evidence.task_id in (select id from visible_task)
), selected_closure as materialized (
  select closure.id,closure.accepted_evidence_manifest,
    encode(closure.closure_sha256,'hex') as closure_sha256
  from task_closures as closure where closure.task_id in (select id from visible_task) limit 1
), json_roots(value) as (
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
  select task.id,task.board_id,task.row_version,
    (select id from selected_closure) as closure_id,
    (select count(*)::text from selected_evidence) as evidence_count,
    (select count(*)::text from selected_closure) as closure_count,
    ((${scalarSum(rootFields)})+
      coalesce((select sum(${scalarSum(evidenceFields)}) from selected_evidence as evidence),0)+
      coalesce((select sum(${scalarSum(closureFields)}) from selected_closure as closure),0))::text as scalar_utf8,
    (select coalesce(sum(${utf8("value")}),0)::text from json_roots) as json_utf8,
    (select count(*) filter (where member)::text from json_nodes) as json_properties,
    (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text from json_nodes) as json_containers,
    ${hashText(`jsonb_build_array(task.id,task.board_id,task.row_version,
      (select string_agg(evidence.id::text||':'||evidence.row_version,','
        order by evidence.submitted_at,evidence.id) from selected_evidence as evidence),
      (select id from selected_closure))`)} as observation_sha256
  from visible_task as task
)`;
export const TASK_PROJECTION_PREFLIGHT_SQL = `${measured} select * from measured`;

// The fresh gate binds the observed identity tuple (task version, evidence rows and
// versions, closure) and every scalar bound. A present-but-changed or larger task
// graph is refused, not reported as absent.
export const TASK_PROJECTION_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,observation_sha256=$5::text
    and evidence_count=$6::text and closure_count=$7::text
    and scalar_utf8::numeric<=$8::numeric and json_utf8::numeric<=$9::numeric
    and json_properties::numeric<=$10::numeric and json_containers::numeric<=$11::numeric as fits
  from measured
)
select gated.id,gated.row_version,gated.closure_id,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${jsonPairs(rootFields)},
      'required_evidence',task.required_evidence,
      'evidence',coalesce((select jsonb_agg(jsonb_build_object(${jsonPairs(evidenceFields)},
        'document_references',evidence.document_references,
        'resource_references',evidence.resource_references)
        order by evidence.submitted_at,evidence.id) from selected_evidence as evidence),'[]'::jsonb),
      'closure',(select jsonb_build_object(${jsonPairs(closureFields)},
        'accepted_evidence_manifest',closure.accepted_evidence_manifest) from selected_closure as closure))
    from visible_task as task
  ) else null end as payload from gated`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("task projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("task projection scalar is invalid");
  return BigInt(value);
}
export function taskProjectionCost(metadata: TaskProjectionMetadata): ListProjectionScalars {
  const c = scalar(metadata.closure_count);
  if ((c !== 0n && c !== 1n) || (metadata.closure_id === null) !== (c === 0n))
    throw new TypeError("task projection closure identity is invalid");
  const e = scalar(metadata.evidence_count),
    s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  // Each object: 2 + sum(keyLength + 10); arrays add two bytes per item. Root with
  // its two container keys: 375; evidence item 138; closure 82. Existing JSONB text
  // N enters once; arbitrary JSON graph counts are exact from the recursion.
  return {
    jsonUpperBytes: (375n + 138n * e + 82n * c + 6n * s + n).toString(),
    propertyCount: (16n + 6n * e + 3n * c + p).toString(),
    objectOrArrayCount: (2n + e + c + o).toString()
  };
}
export function taskProjectionPlan(metadata: TaskProjectionMetadata): ResponseAllocationPlan {
  if (scalar(metadata.row_version) < 1n) throw new TypeError("task row version is invalid");
  if (!/^[0-9a-f]{64}$/u.test(metadata.observation_sha256))
    throw new TypeError("task observation hash is invalid");
  return responseAllocationPlan({
    kind: "task_projection",
    representation: "resource",
    canonicalBytes: 0,
    sourceId: metadata.id,
    sourceVersion: metadata.row_version,
    // Observation identity only. No claim that it hashes the resource bytes.
    sha256: metadata.observation_sha256,
    listProjection: taskProjectionCost(metadata)
  });
}

export async function loadAdmittedTaskProjection(
  client: PoolClient,
  input: {
    readonly boardId: string;
    readonly taskId: string;
    readonly actionOnly: boolean;
    readonly memberId: string;
  }
): Promise<TaskProjectionRow | null> {
  const { boardId, taskId, actionOnly, memberId } = input;
  const observed = await client.query<TaskProjectionMetadata>(TASK_PROJECTION_PREFLIGHT_SQL, [
    boardId,
    taskId,
    actionOnly,
    memberId
  ]);
  if (observed.rows.length > 1) throw new TypeError("task preflight returned multiple roots");
  const metadata = observed.rows[0];
  if (!metadata) return null;
  if (metadata.id !== taskId || metadata.board_id !== boardId)
    throw new TypeError("task preflight identity is invalid");
  const plan = taskProjectionPlan(metadata);
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<
      TaskProjectionRow & {
        closure_id: string | null;
        observation_sha256: string;
        fits: boolean;
      }
    >(TASK_PROJECTION_CONTENT_SQL, [
      boardId,
      taskId,
      actionOnly,
      memberId,
      metadata.observation_sha256,
      metadata.evidence_count,
      metadata.closure_count,
      metadata.scalar_utf8,
      metadata.json_utf8,
      metadata.json_properties,
      metadata.json_containers
    ])
  );
  if (loaded.rows.length > 1) throw new TypeError("task projection returned multiple roots");
  const row = loaded.rows[0];
  if (!row) return null;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    row.id !== metadata.id ||
    row.row_version !== metadata.row_version ||
    row.closure_id !== metadata.closure_id ||
    row.observation_sha256 !== metadata.observation_sha256 ||
    row.payload === null ||
    typeof row.payload !== "object" ||
    Array.isArray(row.payload)
  )
    throw new TypeError("task projection identity is invalid");
  const payload = row.payload as Readonly<Record<string, JsonValue>>;
  const closure = payload["closure"];
  const evidence = payload["evidence"];
  if (
    payload["task_id"] !== taskId ||
    payload["board_id"] !== boardId ||
    payload["row_version"] !== metadata.row_version ||
    !Array.isArray(evidence) ||
    BigInt(evidence.length) !== scalar(metadata.evidence_count) ||
    (metadata.closure_id === null
      ? closure !== null
      : closure === null ||
        typeof closure !== "object" ||
        Array.isArray(closure) ||
        (closure as Readonly<Record<string, JsonValue>>)["closure_id"] !== metadata.closure_id)
  )
    throw new TypeError("task projection payload identity is invalid");
  return { id: row.id, row_version: row.row_version, payload: row.payload };
}
