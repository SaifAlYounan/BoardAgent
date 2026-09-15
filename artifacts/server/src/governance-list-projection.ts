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

export type GovernanceListKind = "rulesets" | "templates" | "matter_types";
export interface GovernanceListInput {
  readonly kind: GovernanceListKind;
  readonly boardId: string;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface GovernanceListMetadata {
  readonly id: string;
  readonly cursor_at: string | null;
  readonly raw_order_key: string;
  readonly observation_sha256: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
}
export interface GovernanceListScalars {
  readonly row_count: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
}
export interface GovernanceListPageRow {
  readonly item: JsonValue;
  // Preserve the existing PageRow contract; SQL to_char may still return NULL.
  readonly cursor_at: string;
  readonly cursor_id: string;
}
const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const fields = {
  rulesets: [
    ["ruleset_id", "id"],
    ["version", "version"],
    ["state", "state"],
    ["schema_version", "schema_version"],
    ["sha256", "sha256"],
    ["profile_id", "profile_id"],
    ["supersedes_id", "supersedes_id"],
    ["created_at", "cursor_at"]
  ],
  templates: [
    ["template_id", "id"],
    ["code", "code"],
    ["approval_rule_id", "approval_rule_id"],
    ["exact_rule", "json_payload"],
    ["sha256", "sha256"]
  ],
  matter_types: [
    ["matter_type_id", "id"],
    ["code", "code"],
    ["name", "name"],
    ["strict_fact_schema", "json_payload"],
    ["sha256", "sha256"]
  ]
} as const;
const selected = {
  rulesets: `select ruleset.id,ruleset.version,ruleset.state,ruleset.schema_version,
    encode(ruleset.canonical_sha256,'hex') as sha256,ruleset.profile_id,ruleset.supersedes_id,
    ruleset.created_at as sort_key,ruleset.created_at::text as raw_order_key,
    ${utc("ruleset.created_at")} as cursor_at,ruleset.id::text as cursor_id,null::jsonb as json_payload
    from rulesets as ruleset where ruleset.board_id=$1
      and ($2::timestamptz is null or (ruleset.created_at,ruleset.id)<($2::timestamptz,$3::uuid))
    order by ruleset.created_at desc,ruleset.id desc limit $4`,
  templates: `select template.id,template.code,template.approval_rule_id,
    template.exact_rule_payload as json_payload,encode(template.canonical_sha256,'hex') as sha256,
    template.code as sort_key,template.code as raw_order_key,template.code as cursor_at,
    template.id::text as cursor_id
    from governance_rule_templates as template
    join boards as board on board.current_governance_profile_id=template.profile_id
    where board.id=$1 and ($2::text is null or (template.code,template.id)>($2::text,$3::uuid))
    order by template.code,template.id limit $4`,
  matter_types: `select matter.id,matter.code,matter.name,matter.strict_fact_schema as json_payload,
    encode(matter.schema_sha256,'hex') as sha256,matter.code as sort_key,
    matter.code as raw_order_key,matter.code as cursor_at,matter.id::text as cursor_id
    from matter_types as matter
    join boards as board on board.current_ruleset_id=matter.ruleset_id
    where board.id=$1 and ($2::text is null or (matter.code,matter.id)>($2::text,$3::uuid))
    order by matter.code,matter.id limit $4`
};
function statements(kind: GovernanceListKind) {
  const columns = fields[kind].map(([, column]) => column);
  const flat = columns
    .filter((column) => column !== "json_payload")
    .map((column) => `chosen.${column}`);
  const privateValues = columns.map((column) =>
    column === "json_payload" || column === "name" ? hash(`chosen.${column}`) : `chosen.${column}`
  );
  const direction = kind === "rulesets" ? "desc" : "asc";
  const order = `sort_key ${direction},id ${direction}`;
  const sortType = kind === "rulesets" ? "timestamptz" : "text";
  // The original selected frontier precedes all recursive JSON work. PostgreSQL
  // normalization/traversal/hash workspace is separate from retained Node output.
  const measured = `with recursive frontier as materialized (${selected[kind]}),
    json_nodes(id,value,member) as (
      select id,json_payload,false from frontier where json_payload is not null
      union all
      select node.id,child.value,child.member from json_nodes as node
      cross join lateral (
        select entry.value,true as member
        from jsonb_each(case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
        union all
        select entry.value,false as member
        from jsonb_array_elements(case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
      ) as child
    ), json_metrics as materialized (
      select id,(count(*) filter(where member))::numeric as json_property_count,
        (count(*) filter(where jsonb_typeof(value) in ('object','array')))::numeric as json_container_count
      from json_nodes group by id
    ), measured as materialized (
      select chosen.*,
        (${[...flat, "chosen.cursor_at", "chosen.cursor_id"].map(utf8).join("+")})::text as scalar_utf8,
        ${utf8("chosen.json_payload")}::text as normalized_json_utf8,
        coalesce(metrics.json_property_count,0)::text as json_property_count,
        coalesce(metrics.json_container_count,0)::text as json_container_count,
        ${hash(`jsonb_build_array(${privateValues.join(",")},chosen.raw_order_key)`)} as observation_sha256
      from frontier as chosen left join json_metrics as metrics on metrics.id=chosen.id
    )`;
  const constructor = `jsonb_build_object(${fields[kind].map(([key, column]) => `'${key}',chosen.${column}`).join(",")})`;
  return {
    preflight: `${measured} select id::text,cursor_at,raw_order_key,observation_sha256,
      scalar_utf8,normalized_json_utf8,json_property_count,json_container_count
      from measured order by ${order}`,
    content: `${measured}, expected as materialized (
      select * from jsonb_to_recordset($5::jsonb) as bound(
        id uuid,cursor_at text,raw_order_key text,observation_sha256 text,scalar_utf8 numeric,
        normalized_json_utf8 numeric,json_property_count numeric,json_container_count numeric)
    ), matched as materialized (
      select fresh.*,(bound.id is not null and fresh.cursor_at is not distinct from bound.cursor_at
        and fresh.scalar_utf8::numeric<=bound.scalar_utf8
        and fresh.normalized_json_utf8::numeric<=bound.normalized_json_utf8
        and fresh.json_property_count::numeric=bound.json_property_count
        and fresh.json_container_count::numeric=bound.json_container_count) as fits
      from measured as fresh left join expected as bound on bound.id=fresh.id
        and fresh.sort_key=bound.raw_order_key::${sortType}
        and fresh.observation_sha256=bound.observation_sha256
    ), global_gate as materialized (select coalesce(bool_and(fits),true) as fits from matched)
    select fits,item,cursor_at,cursor_id from (
      select gate.fits,case when gate.fits then (select ${constructor}) else null end as item,
        chosen.cursor_at,chosen.cursor_id,chosen.sort_key,chosen.id
      from matched as chosen cross join global_gate as gate where gate.fits
      union all
      select gate.fits,null::jsonb,null::text,null::text,null::${sortType},null::uuid
      from global_gate as gate where not gate.fits
    ) as projected order by ${order}`
  };
}
export const GOVERNANCE_LIST_PREFLIGHT_SQL = {
  rulesets: statements("rulesets").preflight,
  templates: statements("templates").preflight,
  matter_types: statements("matter_types").preflight
};
export const GOVERNANCE_LIST_CONTENT_SQL = {
  rulesets: statements("rulesets").content,
  templates: statements("templates").content,
  matter_types: statements("matter_types").content
};
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("governance list scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("governance list scalar is invalid");
  return BigInt(value);
}
function validKind(kind: unknown): kind is GovernanceListKind {
  return kind === "rulesets" || kind === "templates" || kind === "matter_types";
}
export function governanceListProjectionCost(
  kind: GovernanceListKind,
  input: GovernanceListScalars
): ListProjectionScalars {
  if (!validKind(kind)) throw new TypeError("unknown governance list projection");
  const r = scalar(input.row_count),
    s = scalar(input.scalar_utf8),
    n = scalar(input.normalized_json_utf8),
    p = scalar(input.json_property_count),
    o = scalar(input.json_container_count);
  if (r > 501n || (kind === "rulesets" && (n !== 0n || p !== 0n || o !== 0n)))
    throw new TypeError("governance list count is invalid");
  return {
    jsonUpperBytes: (
      2n +
      (kind === "rulesets" ? 197n : kind === "templates" ? 147n : 146n) * r +
      6n * s +
      n
    ).toString(),
    propertyCount: (25n + (kind === "rulesets" ? 12n : 9n) * r + p).toString(),
    objectOrArrayCount: (7n + 2n * r + o).toString()
  };
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function observation(input: GovernanceListInput, rows: readonly GovernanceListMetadata[]) {
  if (
    !validKind(input.kind) ||
    !uuid.test(input.boardId) ||
    !Number.isInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > 500 ||
    rows.length > input.limit + 1
  )
    throw new TypeError("governance list selector is invalid");
  const ids = new Set<string>();
  let s = 0n,
    n = 0n,
    p = 0n,
    o = 0n;
  const tuples = rows.map((row) => {
    if (
      typeof row.id !== "string" ||
      !uuid.test(row.id) ||
      ids.has(row.id) ||
      (row.cursor_at !== null && typeof row.cursor_at !== "string") ||
      typeof row.raw_order_key !== "string" ||
      !row.raw_order_key ||
      typeof row.observation_sha256 !== "string" ||
      !/^[0-9a-f]{64}$/u.test(row.observation_sha256)
    )
      throw new TypeError("governance list metadata identity is invalid");
    ids.add(row.id);
    s += scalar(row.scalar_utf8);
    n += scalar(row.normalized_json_utf8);
    p += scalar(row.json_property_count);
    o += scalar(row.json_container_count);
    return Object.freeze({
      id: row.id,
      cursor_at: row.cursor_at,
      raw_order_key: row.raw_order_key,
      observation_sha256: row.observation_sha256,
      scalar_utf8: row.scalar_utf8,
      normalized_json_utf8: row.normalized_json_utf8,
      json_property_count: row.json_property_count,
      json_container_count: row.json_container_count
    });
  });
  return {
    tuples: Object.freeze(tuples),
    scalars: {
      row_count: String(rows.length),
      scalar_utf8: s.toString(),
      normalized_json_utf8: n.toString(),
      json_property_count: p.toString(),
      json_container_count: o.toString()
    }
  };
}
function plan(
  input: GovernanceListInput,
  observed: ReturnType<typeof observation>
): ResponseAllocationPlan {
  return responseAllocationPlan({
    kind: "governance_list_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: input.boardId,
    sourceVersion: `${input.kind}:${input.limit}`,
    sha256: createHash("sha256")
      .update(JSON.stringify([input, observed.tuples]))
      .digest("hex"),
    listProjection: governanceListProjectionCost(input.kind, observed.scalars)
  });
}
export function governanceListProjectionPlan(
  input: GovernanceListInput,
  rows: readonly GovernanceListMetadata[]
): ResponseAllocationPlan {
  return plan(input, observation(input, rows));
}
export async function loadAdmittedGovernanceList(
  client: PoolClient,
  input: GovernanceListInput
): Promise<readonly GovernanceListPageRow[]> {
  observation(input, []);
  const parameters = [input.boardId, input.cursorAt, input.cursorId, input.limit + 1];
  const inspected = await client.query<GovernanceListMetadata>(
    GOVERNANCE_LIST_PREFLIGHT_SQL[input.kind],
    parameters
  );
  const observed = observation(input, inspected.rows);
  const loaded = await loadWithResponseAllocation(plan(input, observed), () =>
    client.query<{
      fits: boolean;
      item: JsonValue;
      cursor_at: string | null;
      cursor_id: string | null;
    }>(GOVERNANCE_LIST_CONTENT_SQL[input.kind], [...parameters, JSON.stringify(observed.tuples)])
  );
  if (loaded.rows.length === 1 && loaded.rows[0]?.fits === false)
    throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > observed.tuples.length)
    throw new TypeError("governance list returned extra rows");
  let previous = -1;
  const idField =
    input.kind === "rulesets"
      ? "ruleset_id"
      : input.kind === "templates"
        ? "template_id"
        : "matter_type_id";
  for (const row of loaded.rows) {
    const index = observed.tuples.findIndex((tuple) => tuple.id === row.cursor_id),
      expected = observed.tuples[index];
    if (
      row.fits !== true ||
      !expected ||
      index <= previous ||
      row.cursor_at !== expected.cursor_at ||
      row.item === null ||
      typeof row.item !== "object" ||
      Array.isArray(row.item) ||
      (row.item as Readonly<Record<string, JsonValue>>)[idField] !== expected.id
    )
      throw new TypeError("governance list returned tuple mismatch");
    previous = index;
  }
  return loaded.rows as readonly GovernanceListPageRow[];
}
