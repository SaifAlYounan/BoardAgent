import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  currentResponseAllocationOwner,
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

type Fields = ReadonlyArray<readonly [string, string]>;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const pairs = (fields: Fields) => fields.map(([key, value]) => `'${key}',${value}`).join(",");
const sum = (fields: Fields) => fields.map(([, value]) => utf8(value)).join("+");
const leaves = (fields: Fields) => fields.map(([, value]) => hash(value)).join(",");
const rootFields: Fields = [
  ["draft_id", "draft.draft_id"],
  ["board_id", "draft.board_id"],
  ["draft_type", "draft.draft_type"],
  ["current_step", "draft.current_step"],
  ["state", "draft.state"],
  ["ruleset_id", "draft.ruleset_id"],
  ["package_sha256", "draft.package_sha256"],
  ["row_version", "draft.row_version"],
  ["expires_at", "draft.expires_at_text"]
];
const stepFields: Fields = [
  ["step_id", "step.step_id"],
  ["ordinal", "step.ordinal"],
  ["question_code", "step.question_code"],
  ["value_schema", "step.value_schema"],
  ["value_sha256", "step.value_sha256"],
  ["recommended_rule_id", "step.recommended_rule_id"],
  ["override_selected", "step.override_selected"],
  ["override_reason", "step.override_reason"],
  ["attempt", "step.attempt"],
  ["recorded_at", "step.recorded_at_text"]
];
export interface DraftResumeMetadata {
  readonly row_count: string;
  readonly step_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
  readonly observation_sha256: string;
}
export interface DraftResumeRow {
  readonly fits: boolean;
  readonly view: JsonValue;
}

// Freeze the exact visible draft/step relation BEFORE converting canonical bytes.
// Unselected bytes never enter the parser, and no signed_context is selected.
const measured = `with recursive selected_drafts as materialized (
  select draft.id as draft_id,draft.creator_member_id,draft.board_id,draft.draft_type,draft.current_step,draft.state,
    draft.ruleset_id,case when draft.package_sha256 is null then null else encode(draft.package_sha256,'hex') end as package_sha256,
    draft.row_version::text,draft.expires_at,${date("draft.expires_at")} as expires_at_text
  from wizard_drafts as draft where draft.id=$1 and draft.creator_member_id=$2
    and draft.state in ('active','ready_to_confirm') and draft.expires_at>transaction_timestamp()
), selected_raw_steps as materialized (
  select step.id as step_id,step.draft_id,step.ordinal,step.question_code,step.value_schema,step.canonical_value,
    encode(step.value_sha256,'hex') as value_sha256,step.recommended_rule_id,step.citation_snapshot,
    step.override_selected,step.override_reason,step.attempt,step.recorded_at,${date("step.recorded_at")} as recorded_at_text
  from wizard_steps as step join selected_drafts as draft on step.draft_id=draft.draft_id
), selected_steps as materialized (
  select raw.*,convert_from(raw.canonical_value,'UTF8')::jsonb as canonical_json from selected_raw_steps as raw
), json_values as materialized (
  select canonical_json as value from selected_steps union all select citation_snapshot from selected_steps
), nodes(value,member) as (
  select value,false from json_values union all
  select child.value,child.member from nodes as node cross join lateral (
    select entry.value,true as member from jsonb_each(case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all select element.value,false from jsonb_array_elements(case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as element
  ) as child
), observed_roots as materialized (
  select draft.draft_id,${hash(`jsonb_build_array(${leaves(rootFields)},draft.creator_member_id,${hash("draft.expires_at")})`)} as row_hash
  from selected_drafts as draft
), observed_steps as materialized (
  select step.ordinal,step.attempt,${hash(`jsonb_build_array(${leaves(stepFields)},step.draft_id,${hash("step.recorded_at")},encode(sha256(step.canonical_value),'hex'),${hash("step.canonical_json")},${hash("step.citation_snapshot")})`)} as row_hash
  from selected_steps as step
), measured as materialized (
  select (select count(*)::text from selected_drafts) as row_count,
    (select count(*)::text from selected_steps) as step_count,
    ((select coalesce(sum(${sum(rootFields)}),0) from selected_drafts as draft)+
     (select coalesce(sum(${sum(stepFields)}),0) from selected_steps as step))::text as scalar_utf8,
    (select coalesce(sum(${utf8("value")}),0)::text from json_values) as json_utf8,
    (select count(*) filter(where member)::text from nodes) as json_properties,
    (select count(*) filter(where jsonb_typeof(value) in ('object','array'))::text from nodes) as json_containers,
    ${hash("jsonb_build_array((select coalesce(string_agg(row_hash,',' order by draft_id),'') from observed_roots),(select coalesce(string_agg(row_hash,',' order by ordinal,attempt),'') from observed_steps))")} as observation_sha256
)`;
export const DRAFT_RESUME_PREFLIGHT_SQL = `${measured} select * from measured`;
export const DRAFT_RESUME_CONTENT_SQL = `${measured}, gate as materialized (
  select (row_count='0' or (row_count=$3::text and step_count=$4::text and observation_sha256=$9::text
    and scalar_utf8::numeric<=$5::numeric and json_utf8::numeric<=$6::numeric
    and json_properties::numeric<=$7::numeric and json_containers::numeric<=$8::numeric)) as fits from measured
) select gate.fits,case when gate.fits then (
    select jsonb_build_object(${pairs(rootFields)},'steps',coalesce((
      select jsonb_agg(jsonb_build_object(
        'step_id',step.step_id,'ordinal',step.ordinal,'question_code',step.question_code,'value_schema',step.value_schema,
        'canonical_value',step.canonical_json,'value_sha256',step.value_sha256,'recommended_rule_id',step.recommended_rule_id,
        'citation_snapshot',step.citation_snapshot,'override_selected',step.override_selected,'override_reason',step.override_reason,
        'attempt',step.attempt,'recorded_at',step.recorded_at_text
      ) order by step.ordinal,step.attempt) from selected_steps as step where step.draft_id=draft.draft_id
    ),'[]'::jsonb)) from selected_drafts as draft where draft.draft_id=chosen.draft_id
  ) else null end as view from selected_drafts as chosen cross join gate where gate.fits
  union all select false,null::jsonb from gate where not gate.fits`;
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("draft resume scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("draft resume scalar is invalid");
  return BigInt(value);
}
export function draftResumeProjectionCost(m: DraftResumeMetadata): ListProjectionScalars {
  const r = scalar(m.row_count),
    t = scalar(m.step_count),
    s = scalar(m.scalar_utf8),
    n = scalar(m.json_utf8),
    p = scalar(m.json_properties),
    o = scalar(m.json_containers);
  if (
    r > 1n ||
    (r === 0n && (t !== 0n || s !== 0n || n !== 0n || p !== 0n || o !== 0n)) ||
    (t === 0n && (n !== 0n || p !== 0n || o !== 0n)) ||
    n < 2n * t ||
    o < t
  )
    throw new TypeError("draft resume scalar relationship is invalid");
  return {
    jsonUpperBytes: (4096n + 512n * r + 512n * t + 6n * s + 2n * n).toString(),
    propertyCount: (32n + 12n * r + 12n * t + p).toString(),
    objectOrArrayCount: (12n + 3n * r + t + o).toString()
  };
}
export function draftResumeProjectionPlan(
  draftId: string,
  m: DraftResumeMetadata
): ResponseAllocationPlan {
  if (!/^[a-f0-9]{64}$/u.test(m.observation_sha256))
    throw new TypeError("draft resume observation is invalid");
  return responseAllocationPlan({
    kind: "draft_resume_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: draftId,
    sourceVersion: "1",
    sha256: m.observation_sha256,
    listProjection: draftResumeProjectionCost(m)
  });
}
export async function loadAdmittedResumeDraft(
  client: PoolClient,
  draftId: string,
  memberId: string
): Promise<readonly DraftResumeRow[]> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new TypeError("native draft resume allocation owner is required");
  owner.assertLive();
  const selected = await client.query<DraftResumeMetadata>(DRAFT_RESUME_PREFLIGHT_SQL, [
    draftId,
    memberId
  ]);
  if (selected.rows.length !== 1)
    throw new TypeError("draft resume preflight cardinality is invalid");
  const m = Object.freeze({ ...selected.rows[0]! }),
    plan = draftResumeProjectionPlan(draftId, m);
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<DraftResumeRow>(DRAFT_RESUME_CONTENT_SQL, [
      draftId,
      memberId,
      m.row_count,
      m.step_count,
      m.scalar_utf8,
      m.json_utf8,
      m.json_properties,
      m.json_containers,
      m.observation_sha256
    ])
  );
  if (loaded.rows.some((row) => row.fits === false)) throw new ResponseAllocationUnavailable();
  if (loaded.rows.length !== 0 && BigInt(loaded.rows.length) !== scalar(m.row_count))
    throw new TypeError("draft resume content cardinality is invalid");
  for (const row of loaded.rows) {
    if (
      row.fits !== true ||
      row.view === null ||
      typeof row.view !== "object" ||
      Array.isArray(row.view) ||
      (row.view as Readonly<Record<string, JsonValue>>)["draft_id"] !== draftId.toLowerCase()
    )
      throw new TypeError("draft resume content identity is invalid");
  }
  return loaded.rows;
}
