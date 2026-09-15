import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export type GovernanceToolSelector =
  | Readonly<{ kind: "profile"; boardId: string; version: number | null }>
  | Readonly<{ kind: "ruleset"; boardId: string; rulesetId: string | null }>;
export interface GovernanceToolProjectionMetadata {
  readonly entity_id: string;
  readonly board_id: string;
  readonly version: number;
  readonly observation_sha256: string;
  readonly rule_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const profileFlat = [
  ["profile_id", "entity_id"],
  ["board_id", "board_id"],
  ["version", "version"],
  ["state", "state"],
  ["schema_version", "schema_version"],
  ["sha256", "sha256"],
  ["supersedes_id", "supersedes_id"],
  ["created_at", "created_at"],
  ["activated_at", "activated_at"]
] as const;
const rulesetFlat = [
  ["ruleset_id", "entity_id"],
  ["board_id", "board_id"],
  ["profile_id", "profile_id"],
  ["version", "version"],
  ["state", "state"],
  ["schema_version", "schema_version"],
  ["sha256", "sha256"],
  ["supersedes_id", "supersedes_id"],
  ["created_at", "created_at"],
  ["activated_at", "activated_at"]
] as const;
const ruleFlat = [
  ["rule_id", "rule_id"],
  ["matter_type_id", "matter_type_id"],
  ["priority", "priority"],
  ["specificity", "specificity"],
  ["approval_rule_id", "approval_rule_id"],
  ["sha256", "sha256"]
] as const;
const pairs = (fields: ReadonlyArray<readonly [string, string]>, alias: string) =>
  fields.map(([key, column]) => `'${key}',${alias}.${column}`).join(",\n");
const values = (fields: ReadonlyArray<readonly [string, string]>, alias: string) =>
  fields.map(([, column]) => `${alias}.${column}`);

// These are the original selectors, joins and LIMIT/ORDER choices. No state
// predicate is added: explicit/current pointers can select draft or superseded
// versions too. Scalar hashing/traversal/detoast workspace remains in PostgreSQL.
const profileSelection = `select profile.id as entity_id,profile.board_id,profile.version,
  profile.state,profile.schema_version,profile.canonical_payload,
  profile.source_agreement_references,encode(profile.canonical_sha256,'hex') as sha256,
  profile.supersedes_id,${date("profile.created_at")} as created_at,
  ${date("profile.activated_at")} as activated_at
  from governance_profiles as profile join boards as board on board.id=profile.board_id
  where profile.board_id=$1 and (($2::integer is null and profile.id=board.current_governance_profile_id)
    or profile.version=$2) order by profile.version desc limit 1`;
const rulesetSelection = `select ruleset.id as entity_id,ruleset.board_id,ruleset.profile_id,
  ruleset.version,ruleset.state,ruleset.schema_version,ruleset.canonical_payload,
  encode(ruleset.canonical_sha256,'hex') as sha256,ruleset.supersedes_id,
  ${date("ruleset.created_at")} as created_at,${date("ruleset.activated_at")} as activated_at
  from rulesets as ruleset join boards as board on board.id=ruleset.board_id
  where ruleset.board_id=$1 and (($2::uuid is null and ruleset.id=board.current_ruleset_id)
    or ruleset.id=$2) limit 1`;

function sql(kind: GovernanceToolSelector["kind"]) {
  const profile = kind === "profile";
  const flat = profile ? profileFlat : rulesetFlat;
  const rootValues = values(flat, "root");
  const ruleValues = values(ruleFlat, "rule");
  const ruleCtes = profile
    ? ""
    : `, selected_rules as materialized (
    select rule.id as rule_id,rule.matter_type_id,rule.priority,rule.specificity,
      rule.condition_tree as condition,rule.approval_rule_id,
      encode(rule.canonical_sha256,'hex') as sha256
    from ruleset_rules as rule join selected_root as root on rule.ruleset_id=root.entity_id
  ), rule_metrics as materialized (
    select count(*)::text as rule_count,
      coalesce(sum(${ruleValues.map(utf8).join("+")}),0)::numeric as scalar_utf8,
      ${hash(`coalesce(string_agg(${hash(`jsonb_build_array(${ruleValues.join(",")},${hash("rule.condition")})`)},''
        order by rule.priority desc,rule.specificity desc,rule.rule_id),'')`)} as observation_sha256
    from selected_rules as rule
  )`;
  const jsonRoots = profile
    ? "select source_agreement_references from selected_root"
    : "select condition from selected_rules";
  const privateJson = profile
    ? `${hash("root.canonical_payload")},${hash("root.source_agreement_references")}`
    : `${hash("root.canonical_payload")},(select observation_sha256 from rule_metrics)`;
  const measured = `with recursive selected_root as materialized (${profile ? profileSelection : rulesetSelection})
  ${ruleCtes}, json_roots(value) as (
    select canonical_payload from selected_root union all ${jsonRoots}
  ), json_nodes(value,member) as (
    select value,false from json_roots where value is not null
    union all
    select child.value,child.member from json_nodes as node cross join lateral (
      select entry.value,true as member from jsonb_each(
        case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
      union all
      select entry.value,false as member from jsonb_array_elements(
        case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
    ) as child
  ), measured as materialized (
    select root.entity_id,root.board_id,root.version,
      ${profile ? "'0'::text" : "(select rule_count from rule_metrics)"} as rule_count,
      ((${rootValues.map(utf8).join("+")})${profile ? "" : "+(select scalar_utf8 from rule_metrics)"})::text as scalar_utf8,
      (select coalesce(sum(${utf8("value")}),0)::text from json_roots) as json_utf8,
      (select count(*) filter (where member)::text from json_nodes) as json_properties,
      (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text from json_nodes) as json_containers,
      ${hash(`jsonb_build_array(${rootValues.join(",")},${privateJson})`)} as observation_sha256
    from selected_root as root
  )`;
  const nested = profile
    ? `'source_agreement_references',root.source_agreement_references`
    : `'rules',coalesce((select jsonb_agg(jsonb_build_object(${pairs(ruleFlat, "rule")},
        'condition',rule.condition) order by rule.priority desc,rule.specificity desc,rule.rule_id)
        from selected_rules as rule),'[]'::jsonb)`;
  return {
    preflight: `${measured} select * from measured`,
    content: `${measured}, gated as materialized (
      select measured.*,entity_id=$3::uuid and version=$4::integer
        and observation_sha256=$5::text and rule_count=$6::text
        and scalar_utf8::numeric<=$7::numeric and json_utf8::numeric<=$8::numeric
        and json_properties::numeric<=$9::numeric and json_containers::numeric<=$10::numeric as fits
      from measured
    ) select entity_id,board_id,version,observation_sha256,fits,
      case when fits then (
        select jsonb_build_object(${pairs(flat, "root")},'canonical_payload',root.canonical_payload,
          ${nested}) from selected_root as root
      ) else null end as view from gated`
  };
}
const profileSql = sql("profile"),
  rulesetSql = sql("ruleset");
export const GOVERNANCE_PROFILE_TOOL_PREFLIGHT_SQL = profileSql.preflight;
export const GOVERNANCE_PROFILE_TOOL_CONTENT_SQL = profileSql.content;
export const RULESET_TOOL_PREFLIGHT_SQL = rulesetSql.preflight;
export const RULESET_TOOL_CONTENT_SQL = rulesetSql.content;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("governance projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("governance projection scalar is invalid");
  return BigInt(value);
}
export function governanceToolProjectionCost(
  kind: GovernanceToolSelector["kind"],
  metadata: GovernanceToolProjectionMetadata
): ListProjectionScalars {
  if (kind !== "profile" && kind !== "ruleset")
    throw new TypeError("unknown governance projection");
  const r = scalar(metadata.rule_count),
    s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  if (kind === "profile" && r !== 0n) throw new TypeError("profile cannot contain rule rows");
  // Fixed bytes use 2 + sum(key UTF8 bytes + 10); arrays add2 per item.
  // P/O retain the existing tool policy: visible view plus23 properties and
  //5 containers for the envelope/SDK pipeline. Arbitrary JSON contributes its
  // separately measured exact graph. The manager adds its existing4KiB byte
  // allowance and64KiB base; these constants are accounting policy, not RSS.
  return {
    jsonUpperBytes: ((kind === "profile" ? 241n : 239n + 145n * r) + 6n * s + n).toString(),
    propertyCount: ((kind === "profile" ? 34n : 35n + 7n * r) + p).toString(),
    objectOrArrayCount: ((kind === "profile" ? 6n : 7n + r) + o).toString()
  };
}
export function governanceToolProjectionPlan(
  kind: GovernanceToolSelector["kind"],
  metadata: GovernanceToolProjectionMetadata
): ResponseAllocationPlan {
  if (
    !Number.isInteger(metadata.version) ||
    metadata.version < 1 ||
    metadata.version > 2_147_483_647
  )
    throw new TypeError("governance projection version is invalid");
  return responseAllocationPlan({
    kind: "governance_tool_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.entity_id,
    sourceVersion: `${kind}:${metadata.board_id}:${String(metadata.version)}`,
    sha256: metadata.observation_sha256,
    listProjection: governanceToolProjectionCost(kind, metadata)
  });
}
export async function loadAdmittedGovernanceToolProjection(
  client: PoolClient,
  input: GovernanceToolSelector
): Promise<JsonValue | null> {
  const profile = input.kind === "profile";
  const statements = profile ? profileSql : rulesetSql;
  const selector = profile ? input.version : input.rulesetId;
  const observed = await client.query<GovernanceToolProjectionMetadata>(statements.preflight, [
    input.boardId,
    selector
  ]);
  if (observed.rows.length > 1) throw new TypeError("governance preflight returned multiple rows");
  const metadata = observed.rows[0];
  if (!metadata) return null;
  if (
    metadata.board_id !== input.boardId ||
    (profile
      ? selector !== null && metadata.version !== selector
      : selector !== null && metadata.entity_id !== selector)
  )
    throw new TypeError("governance preflight selector mismatch");
  const loaded = await loadWithResponseAllocation(
    governanceToolProjectionPlan(input.kind, metadata),
    () =>
      client.query<
        Pick<
          GovernanceToolProjectionMetadata,
          "entity_id" | "board_id" | "version" | "observation_sha256"
        > & { fits: boolean; view: JsonValue }
      >(statements.content, [
        input.boardId,
        selector,
        metadata.entity_id,
        metadata.version,
        metadata.observation_sha256,
        metadata.rule_count,
        metadata.scalar_utf8,
        metadata.json_utf8,
        metadata.json_properties,
        metadata.json_containers
      ])
  );
  if (loaded.rows.length > 1) throw new TypeError("governance content returned multiple rows");
  const row = loaded.rows[0];
  if (!row) return null;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    row.entity_id !== metadata.entity_id ||
    row.board_id !== input.boardId ||
    row.version !== metadata.version ||
    row.observation_sha256 !== metadata.observation_sha256 ||
    row.view === null ||
    typeof row.view !== "object" ||
    Array.isArray(row.view)
  )
    throw new TypeError("governance content identity mismatch");
  const view = row.view as Readonly<Record<string, JsonValue>>;
  if (
    view[profile ? "profile_id" : "ruleset_id"] !== metadata.entity_id ||
    view["board_id"] !== input.boardId ||
    view["version"] !== metadata.version
  )
    throw new TypeError("governance payload identity mismatch");
  return row.view;
}
