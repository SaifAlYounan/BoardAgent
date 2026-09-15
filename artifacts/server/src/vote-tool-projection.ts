import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface VoteToolProjectionMetadata {
  readonly vote_id: string;
  readonly board_id: string;
  readonly member_id: string;
  readonly observation_sha256: string;
  readonly row_count: string;
  readonly ballot_count: string;
  readonly outcome_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface VoteToolProjectionRow {
  readonly view: JsonValue;
}
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hashText = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const root = [
  ["vote_id", "vote.vote_id"],
  ["board_id", "vote.board_id"],
  ["title", "vote.title"],
  ["state", "vote.state"],
  ["close_mode", "vote.close_mode"],
  ["deadline_at", "vote.deadline_at"],
  ["row_version", "vote.row_version"],
  ["created_at", "vote.created_at"],
  ["opened_at", "vote.opened_at"],
  ["closed_at", "vote.closed_at"]
] as const;
const resolution = [
  ["version_id", "vote.resolution_id"],
  ["version", "vote.resolution_version"],
  ["canonical_text", "vote.resolution_text"],
  ["sha256", "vote.resolution_sha256"]
] as const;
const pkg = [
  ["package_id", "vote.package_id"],
  ["version", "vote.package_version"],
  ["schema_version", "vote.package_schema_version"],
  ["package_sha256", "vote.package_sha256"],
  ["governance_profile_id", "vote.governance_profile_id"],
  ["governance_profile_sha256", "vote.governance_profile_sha256"],
  ["ruleset_id", "vote.ruleset_id"],
  ["ruleset_sha256", "vote.ruleset_sha256"],
  ["approval_rule_id", "vote.approval_rule_id"],
  ["approval_rule_sha256", "vote.approval_rule_sha256"],
  ["electorate_sha256", "vote.electorate_sha256"]
] as const;
const outcome = [
  ["outcome_id", "vote.outcome_id"],
  ["tally_sha256", "vote.tally_sha256"],
  ["outcome", "vote.outcome"],
  ["finalized_at", "vote.finalized_at"],
  ["certificate_id", "vote.certificate_id"]
] as const;
const ballot = [
  ["ballot_id", "ballot.id"],
  ["principal_member_id", "ballot.principal_member_id"],
  ["caster_member_id", "ballot.caster_member_id"],
  ["choice", "ballot.choice"],
  ["statement", "ballot.statement_text"],
  ["voting_weight", "ballot.voting_weight"],
  ["source", "ballot.ballot_source"],
  ["cast_at", "ballot.cast_at_text"]
] as const;
const pairs = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([key, value]) => `'${key}',${value}`).join(",\n");
const flat = [...root, ...resolution, ...pkg, ...outcome];
const flatSum = flat.map(([, value]) => utf8(value)).join("+");
const ballotSum = ballot.map(([, value]) => utf8(value)).join("+");
const rowObservation = flat
  .map(([, value]) => (value === "vote.resolution_text" ? hashText(value) : value))
  .join(",");
const ballotObservation = ballot
  .map(([, value]) => (value === "ballot.statement_text" ? hashText(value) : value))
  .join(",");

// Preserve all original LEFT JOINs, caller principal-or-caster ballots and the
// absence of an outer LIMIT/ORDER. Even if the declared outcome uniqueness were
// absent, preflight admits all rows that the original pg query would materialize.
// Parsing, traversal, hashing and aggregate workspace stay in PostgreSQL and are
// not covered by the Node allocation policy. Only bounded scalars reach Node.
const measured = `with recursive selected_vote as materialized (
  select vote.id as vote_id,vote.board_id,vote.title,vote.state,vote.close_mode,
    ${date("vote.deadline_at")} as deadline_at,vote.row_version::text as row_version,
    ${date("vote.created_at")} as created_at,${date("vote.opened_at")} as opened_at,
    ${date("vote.closed_at")} as closed_at,
    vote.current_resolution_version_id,vote.current_decision_package_id,
    resolution.id as resolution_id,resolution.version as resolution_version,
    resolution.canonical_text as resolution_text,
    encode(resolution.canonical_sha256,'hex') as resolution_sha256,
    package.id as package_id,package.version as package_version,
    package.schema_version as package_schema_version,
    encode(package.package_sha256,'hex') as package_sha256,
    convert_from(package.canonical_payload,'UTF8')::jsonb as canonical_payload,
    octet_length(package.canonical_payload) as raw_payload_bytes,
    encode(sha256(package.canonical_payload),'hex') as actual_payload_sha256,
    package.governance_profile_id,encode(package.governance_profile_sha256,'hex') as governance_profile_sha256,
    package.ruleset_id,encode(package.ruleset_sha256,'hex') as ruleset_sha256,
    package.approval_rule_id,encode(package.approval_rule_sha256,'hex') as approval_rule_sha256,
    encode(package.electorate_sha256,'hex') as electorate_sha256,
    outcome.id as outcome_id,outcome.canonical_tally,encode(outcome.tally_sha256,'hex') as tally_sha256,
    outcome.outcome,${date("outcome.finalized_at")} as finalized_at,outcome.certificate_id
  from votes as vote
  left join resolution_versions as resolution on resolution.id=vote.current_resolution_version_id
  left join decision_packages as package on package.id=vote.current_decision_package_id
  left join vote_outcomes as outcome on outcome.vote_id=vote.id
  where vote.id=$1 and not boardagent_member_vote_recused(vote.id,$2)
), selected_ballots as materialized (
  select ballot.id,ballot.principal_member_id,ballot.caster_member_id,ballot.choice,
    ballot.statement_text,ballot.voting_weight::text as voting_weight,ballot.ballot_source,
    ballot.cast_at,${date("ballot.cast_at")} as cast_at_text
  from ballots as ballot where ballot.vote_id=$1
    and (ballot.principal_member_id=$2 or ballot.caster_member_id=$2)
    and exists (select 1 from selected_vote)
), ballot_metrics as materialized (
  select count(*)::numeric as ballot_count,coalesce(sum(${ballotSum}),0)::numeric as scalar_utf8,
    ${hashText(`coalesce(string_agg(${hashText(`jsonb_build_array(${ballotObservation})`)},'' order by ballot.cast_at,ballot.id),'')`)} as observation_sha256
  from selected_ballots as ballot
), json_roots(value) as (
  select canonical_payload from selected_vote where canonical_payload is not null
  union all
  select canonical_tally from selected_vote where outcome_id is not null and canonical_tally is not null
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
), row_metrics as materialized (
  select vote.board_id,vote.outcome_id,(${flatSum})::numeric as scalar_utf8,
    (${utf8("vote.canonical_payload")}+${utf8("vote.canonical_tally")})::numeric as json_utf8,
    ${hashText(`jsonb_build_array(${rowObservation},vote.current_resolution_version_id,
      vote.current_decision_package_id,vote.raw_payload_bytes,vote.actual_payload_sha256,
      ${hashText("vote.canonical_tally")})`)} as observation_sha256
  from selected_vote as vote
), measured as materialized (
  select $1::uuid as vote_id,$2::uuid as member_id,
    (select min(board_id::text)::uuid from row_metrics) as board_id,
    (select count(*)::text from row_metrics) as row_count,
    ((select count(*)::numeric from row_metrics)*ballot_metrics.ballot_count)::text as ballot_count,
    (select count(*) filter (where outcome_id is not null)::text from row_metrics) as outcome_count,
    ((select coalesce(sum(scalar_utf8),0) from row_metrics)+
      (select count(*)::numeric from row_metrics)*ballot_metrics.scalar_utf8)::text as scalar_utf8,
    (select coalesce(sum(json_utf8),0)::text from row_metrics) as json_utf8,
    (select count(*) filter (where member)::text from json_nodes) as json_properties,
    (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text from json_nodes) as json_containers,
    ${hashText(`jsonb_build_array($1::uuid,$2::uuid,
      (select string_agg(observation_sha256,'' order by observation_sha256) from row_metrics),
      ballot_metrics.observation_sha256)`)} as observation_sha256
  from ballot_metrics where exists (select 1 from row_metrics)
)`;
export const VOTE_TOOL_PREFLIGHT_SQL = `${measured} select * from measured`;
export const VOTE_TOOL_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,board_id=$3::uuid and observation_sha256=$4::text
    and row_count=$5::text and ballot_count=$6::text and outcome_count=$7::text
    and scalar_utf8::numeric<=$8::numeric and json_utf8::numeric<=$9::numeric
    and json_properties::numeric<=$10::numeric and json_containers::numeric<=$11::numeric as fits
  from measured
)
select gated.vote_id,gated.board_id,gated.member_id,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${pairs(root)},
      'resolution',jsonb_build_object(${pairs(resolution)}),
      'decision_package',jsonb_build_object(${pairs(pkg)},'canonical_payload',vote.canonical_payload),
      'my_ballots',coalesce((select jsonb_agg(jsonb_build_object(${pairs(ballot)})
        order by ballot.cast_at,ballot.id) from selected_ballots as ballot),'[]'::jsonb),
      'outcome',case when vote.outcome_id is null then null else
        jsonb_build_object(${pairs(outcome)},'canonical_tally',vote.canonical_tally) end)
  ) else null end as view
from selected_vote as vote cross join gated where gated.fits
union all
select gated.vote_id,gated.board_id,gated.member_id,gated.observation_sha256,gated.fits,null::jsonb as view
from gated where not gated.fits`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("vote tool projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("vote tool projection scalar is invalid");
  return BigInt(value);
}
export function voteToolProjectionCost(
  metadata: VoteToolProjectionMetadata
): ListProjectionScalars {
  const r = scalar(metadata.row_count),
    b = scalar(metadata.ballot_count),
    e = scalar(metadata.outcome_count),
    s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  if (r < 1n || e > r) throw new TypeError("vote tool projection row count is invalid");
  // All counts/bytes below are totals over every original joined row. Fixed
  // 14/4/12/8/6-key objects cost270/79/307/167/132; ballots add2 per item.
  // Repeat the inherited envelope allowance per row even though the caller
  // ultimately selects row0. This is policy accounting, not measured RSS.
  return {
    jsonUpperBytes: (658n * r + 169n * b + 132n * e + 6n * s + n + 4096n * (r - 1n)).toString(),
    propertyCount: (53n * r + 8n * b + 6n * e + p).toString(),
    objectOrArrayCount: (9n * r + b + e + o).toString()
  };
}
export function voteToolProjectionPlan(
  metadata: VoteToolProjectionMetadata
): ResponseAllocationPlan {
  if (!/^[0-9a-f]{64}$/u.test(metadata.observation_sha256))
    throw new TypeError("vote tool observation hash is invalid");
  return responseAllocationPlan({
    kind: "vote_tool_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.vote_id,
    sourceVersion: metadata.member_id,
    sha256: metadata.observation_sha256,
    listProjection: voteToolProjectionCost(metadata)
  });
}
export async function loadAdmittedVoteToolProjection(
  client: PoolClient,
  voteId: string,
  memberId: string
): Promise<readonly VoteToolProjectionRow[]> {
  const observed = await client.query<VoteToolProjectionMetadata>(VOTE_TOOL_PREFLIGHT_SQL, [
    voteId,
    memberId
  ]);
  if (observed.rows.length > 1) throw new TypeError("vote tool preflight returned multiple rows");
  const metadata = observed.rows[0];
  if (!metadata) return [];
  if (metadata.vote_id !== voteId || metadata.member_id !== memberId || !metadata.board_id)
    throw new TypeError("vote tool preflight identity is invalid");
  const loaded = await loadWithResponseAllocation(voteToolProjectionPlan(metadata), () =>
    client.query<{
      vote_id: string;
      board_id: string;
      member_id: string;
      observation_sha256: string;
      fits: boolean;
      view: JsonValue;
    }>(VOTE_TOOL_CONTENT_SQL, [
      voteId,
      memberId,
      metadata.board_id,
      metadata.observation_sha256,
      metadata.row_count,
      metadata.ballot_count,
      metadata.outcome_count,
      metadata.scalar_utf8,
      metadata.json_utf8,
      metadata.json_properties,
      metadata.json_containers
    ])
  );
  if (loaded.rows.length === 0) return [];
  if (loaded.rows.length === 1 && loaded.rows[0]?.fits === false)
    throw new ResponseAllocationUnavailable();
  if (BigInt(loaded.rows.length) !== scalar(metadata.row_count))
    throw new TypeError("vote tool projection row count is invalid");
  for (const row of loaded.rows) {
    if (
      row.fits !== true ||
      row.vote_id !== voteId ||
      row.board_id !== metadata.board_id ||
      row.member_id !== memberId ||
      row.observation_sha256 !== metadata.observation_sha256 ||
      row.view === null ||
      typeof row.view !== "object" ||
      Array.isArray(row.view)
    )
      throw new TypeError("vote tool projection identity is invalid");
    const view = row.view as Readonly<Record<string, JsonValue>>;
    if (view["vote_id"] !== voteId || view["board_id"] !== metadata.board_id)
      throw new TypeError("vote tool payload identity is invalid");
  }
  return loaded.rows;
}
