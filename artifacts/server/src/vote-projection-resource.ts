import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface VoteProjectionMetadata {
  readonly id: string;
  readonly board_id: string;
  readonly row_version: string;
  readonly outcome_id: string | null;
  readonly outcome_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface VoteProjectionRow {
  readonly id: string;
  readonly row_version: string;
  readonly payload: JsonValue;
}

const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const rootFields = [
  ["schema_version", "'boardagent.vote-resource.v1'"],
  ["vote_id", "vote.id"],
  ["board_id", "vote.board_id"],
  ["title", "vote.title"],
  ["state", "vote.state"],
  ["resolution_version_id", "vote.current_resolution_version_id"],
  ["decision_package_id", "vote.current_decision_package_id"],
  ["approval_rule_id", "vote.approval_rule_id"],
  ["governance_profile_id", "vote.governance_profile_id"],
  ["ruleset_id", "vote.ruleset_id"],
  ["electorate_sha256", "vote.electorate_sha256"],
  ["close_mode", "vote.close_mode"],
  ["deadline_at", "vote.deadline_at"],
  ["row_version", "vote.row_version"]
] as const;
const outcomeFields = [
  ["outcome_id", "outcome.id"],
  ["tally_sha256", "outcome.tally_sha256"],
  ["outcome", "outcome.outcome"],
  ["certificate_id", "outcome.certificate_id"]
] as const;
const scalarSum = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([, value]) => utf8(value)).join("+");
const jsonPairs = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([key, value]) => `'${key}',${value}`).join(",\n");

// Only the original 15/5 resource fields are selected, never stored certificate
// bytes, closing evidence or unrelated vote projections. PostgreSQL detoast,
// JSONB traversal/serialization and RLS workspace are outside this Node policy.
const measured = `with recursive visible_vote as materialized (
  select vote.id,vote.board_id,vote.title,vote.state,vote.current_resolution_version_id,
    vote.current_decision_package_id,vote.approval_rule_id,vote.governance_profile_id,
    vote.ruleset_id,case when vote.electorate_sha256 is null then null
      else encode(vote.electorate_sha256,'hex') end as electorate_sha256,
    vote.close_mode,${utc("vote.deadline_at")} as deadline_at,vote.row_version::text as row_version
  from votes as vote where vote.board_id=$1 and vote.id=$2
    and not boardagent_member_vote_recused(vote.id,boardagent_context_uuid('boardagent.member_id'))
), selected_outcome as materialized (
  select outcome.id,outcome.canonical_tally,encode(outcome.tally_sha256,'hex') as tally_sha256,
    outcome.outcome,outcome.certificate_id
  from vote_outcomes as outcome
  where outcome.vote_id in (select id from visible_vote) limit 1
), json_nodes(value,member) as (
  select canonical_tally,false from selected_outcome
  union all
  select child.value,child.member from json_nodes as node cross join lateral (
    select entry.value,true as member from jsonb_each(
      case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member from jsonb_array_elements(
      case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), measured as materialized (
  select vote.id,vote.board_id,vote.row_version,
    (select id from selected_outcome) as outcome_id,
    (select count(*)::text from selected_outcome) as outcome_count,
    ((${scalarSum(rootFields)})+
      coalesce((select sum(${scalarSum(outcomeFields)}) from selected_outcome as outcome),0))::text as scalar_utf8,
    (select coalesce(sum(${utf8("canonical_tally")}),0)::text from selected_outcome) as json_utf8,
    (select count(*) filter (where member)::text from json_nodes) as json_properties,
    (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text from json_nodes) as json_containers
  from visible_vote as vote
)`;
export const VOTE_PROJECTION_PREFLIGHT_SQL = `${measured} select * from measured`;

// Preserve the original LIMIT1 selection, explicitly binding whichever outcome
// it selected. The fresh gate includes every scalar bound even when both IDs
// are unchanged. A present-but-changed root/outcome is blocked, not absent.
export const VOTE_PROJECTION_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,row_version=$3::text and outcome_id is not distinct from $4::uuid
    and outcome_count::numeric<=$5::numeric and scalar_utf8::numeric<=$6::numeric
    and json_utf8::numeric<=$7::numeric and json_properties::numeric<=$8::numeric
    and json_containers::numeric<=$9::numeric as fits
  from measured
)
select gated.id,gated.row_version,gated.outcome_id,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${jsonPairs(rootFields)},
      'outcome',(select jsonb_build_object(${jsonPairs(outcomeFields)},
        'canonical_tally',outcome.canonical_tally) from selected_outcome as outcome))
    from visible_vote as vote
  ) else null end as payload from gated`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("vote projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("vote projection scalar is invalid");
  return BigInt(value);
}
export function voteProjectionCost(metadata: VoteProjectionMetadata): ListProjectionScalars {
  const e = scalar(metadata.outcome_count);
  if ((e !== 0n && e !== 1n) || (metadata.outcome_id === null) !== (e === 0n))
    throw new TypeError("vote projection outcome identity is invalid");
  const s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  // Each object:2+sum(keyLength+10), hence root334 and optional outcome110.
  // Existing JSONB text N enters once; arbitrary JSON graph counts are exact.
  return {
    jsonUpperBytes: (334n + 110n * e + 6n * s + n).toString(),
    propertyCount: (38n + 5n * e + p).toString(),
    objectOrArrayCount: (6n + e + o).toString()
  };
}
export function voteProjectionPlan(metadata: VoteProjectionMetadata): ResponseAllocationPlan {
  if (scalar(metadata.row_version) < 1n) throw new TypeError("vote row version is invalid");
  return responseAllocationPlan({
    kind: "vote_projection",
    representation: "resource",
    canonicalBytes: 0,
    sourceId: metadata.id,
    sourceVersion: metadata.row_version,
    // Observation identity only. No claim that tally_sha256 hashes resource bytes.
    sha256: createHash("sha256")
      .update(
        JSON.stringify([metadata.board_id, metadata.id, metadata.row_version, metadata.outcome_id])
      )
      .digest("hex"),
    listProjection: voteProjectionCost(metadata)
  });
}

export async function loadAdmittedVoteProjection(
  client: PoolClient,
  boardId: string,
  voteId: string
): Promise<VoteProjectionRow | null> {
  const observed = await client.query<VoteProjectionMetadata>(VOTE_PROJECTION_PREFLIGHT_SQL, [
    boardId,
    voteId
  ]);
  if (observed.rows.length > 1) throw new TypeError("vote preflight returned multiple roots");
  const metadata = observed.rows[0];
  if (!metadata) return null;
  if (metadata.id !== voteId || metadata.board_id !== boardId)
    throw new TypeError("vote preflight identity is invalid");
  const plan = voteProjectionPlan(metadata);
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<
      VoteProjectionRow & {
        fits: boolean;
        outcome_id: string | null;
      }
    >(VOTE_PROJECTION_CONTENT_SQL, [
      boardId,
      voteId,
      metadata.row_version,
      metadata.outcome_id,
      metadata.outcome_count,
      metadata.scalar_utf8,
      metadata.json_utf8,
      metadata.json_properties,
      metadata.json_containers
    ])
  );
  if (loaded.rows.length > 1) throw new TypeError("vote projection returned multiple roots");
  const row = loaded.rows[0];
  if (!row) return null;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    row.id !== metadata.id ||
    row.row_version !== metadata.row_version ||
    row.outcome_id !== metadata.outcome_id ||
    row.payload === null ||
    typeof row.payload !== "object" ||
    Array.isArray(row.payload)
  )
    throw new TypeError("vote projection identity is invalid");
  const payload = row.payload as Readonly<Record<string, JsonValue>>;
  const outcome = payload["outcome"];
  if (
    payload["vote_id"] !== voteId ||
    payload["board_id"] !== boardId ||
    payload["row_version"] !== metadata.row_version ||
    (metadata.outcome_id === null
      ? outcome !== null
      : outcome === null ||
        typeof outcome !== "object" ||
        Array.isArray(outcome) ||
        (outcome as Readonly<Record<string, JsonValue>>)["outcome_id"] !== metadata.outcome_id)
  )
    throw new TypeError("vote projection payload identity is invalid");
  return { id: row.id, row_version: row.row_version, payload: row.payload };
}
