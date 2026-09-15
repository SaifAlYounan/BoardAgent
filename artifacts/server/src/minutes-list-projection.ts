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

export type MinutesListKind = "versions" | "reviews";
export interface MinutesListInput {
  readonly kind: MinutesListKind;
  readonly minutesId: string;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface MinutesListMetadata {
  readonly id: string;
  readonly cursor_at: string | null;
  readonly raw_created_at: string;
  readonly observation_sha256: string;
  readonly withdrawal_count: string;
  readonly disposition_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface MinutesListScalars {
  readonly row_count: string;
  readonly withdrawal_count: string;
  readonly disposition_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface MinutesListPageRow {
  readonly item: JsonValue;
  // Keep the existing PageRow static contract. PostgreSQL to_char can return
  // NULL; runtime validation below deliberately preserves that original value
  // for the unchanged page()/cursor logic instead of inventing a finite bound.
  readonly cursor_at: string;
  readonly cursor_id: string;
}
const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const versions = [
  ["version_id", "id"],
  ["minutes_id", "minutes_id"],
  ["version", "version"],
  ["canonical_schema", "canonical_schema"],
  ["sha256", "sha256"],
  ["package_base_sha256", "package_base_sha256"],
  ["transcript_version_id", "transcript_version_id"],
  ["supersedes_id", "supersedes_id"],
  ["created_at", "cursor_at"]
] as const;
const reviews = [
  ["review_item_id", "id"],
  ["minutes_id", "minutes_id"],
  ["item_kind", "item_kind"],
  ["schema_version", "schema_version"],
  ["author_member_id", "author_member_id"],
  ["author_seat_role", "author_seat_role"],
  ["base_version_id", "base_version_id"],
  ["base_sha256", "base_sha256"],
  ["payload_sha256", "payload_sha256"],
  ["created_at", "cursor_at"]
] as const;
const withdrawal = [
  ["withdrawal_id", "withdrawal_id"],
  ["author_member_id", "withdrawal_author_member_id"],
  ["withdrawn_at", "withdrawn_at"]
] as const;
const disposition = [
  ["disposition_id", "disposition_id"],
  ["decision", "decision"],
  ["reason", "reason"],
  ["resulting_minutes_version_id", "resulting_minutes_version_id"],
  ["created_at", "disposition_created_at"]
] as const;
type Fields = ReadonlyArray<readonly [string, string]>;
const values = (fields: Fields, alias: string) => fields.map(([, column]) => `${alias}.${column}`);
const pairs = (fields: Fields, alias: string) =>
  fields.map(([key, column]) => `'${key}',${alias}.${column}`).join(",\n");
const scalarKeys = [
  "withdrawal_count",
  "disposition_count",
  "scalar_utf8",
  "json_utf8",
  "json_properties",
  "json_containers"
] as const;
const metadataColumns =
  "id::text,cursor_at,raw_created_at,observation_sha256,withdrawal_count,disposition_count,scalar_utf8,json_utf8,json_properties,json_containers";
const selectedVersions = `select version_row.id,version_row.minutes_id,version_row.version,version_row.canonical_schema,
  encode(version_row.canonical_sha256,'hex') as sha256,
  encode(version_row.package_base_sha256,'hex') as package_base_sha256,
  version_row.transcript_version_id,version_row.supersedes_id,
  version_row.created_at as sort_created_at,version_row.created_at::text as raw_created_at,
  ${utc("version_row.created_at")} as cursor_at,version_row.id::text as cursor_id
  from minutes_versions as version_row where version_row.minutes_id=$1
    and ($2::timestamptz is null or (version_row.created_at,version_row.id)<($2::timestamptz,$3::uuid))
  order by version_row.created_at desc,version_row.id desc limit $4`;
const selectedReviews = `select item.id,item.minutes_id,item.item_kind,item.schema_version,item.author_member_id,item.author_seat_role,
  item.base_version_id,encode(item.base_sha256,'hex') as base_sha256,item.exact_anchor as anchor,
  item.canonical_payload as raw_payload,encode(item.payload_sha256,'hex') as payload_sha256,
  withdrawal.id as withdrawal_id,withdrawal.author_member_id as withdrawal_author_member_id,
  ${utc("withdrawal.withdrawn_at")} as withdrawn_at,
  disposition.id as disposition_id,disposition.decision,disposition.reason,disposition.resulting_minutes_version_id,
  ${utc("disposition.created_at")} as disposition_created_at,
  item.created_at as sort_created_at,item.created_at::text as raw_created_at,
  ${utc("item.created_at")} as cursor_at,item.id::text as cursor_id
  from minutes_review_items as item
  left join minutes_review_withdrawals as withdrawal on withdrawal.review_item_id=item.id
  left join minutes_review_dispositions as disposition on disposition.review_item_id=item.id
  where item.minutes_id=$1 and ($2::timestamptz is null or (item.created_at,item.id)<($2::timestamptz,$3::uuid))
  order by item.created_at desc,item.id desc limit $4`;

function statements(kind: MinutesListKind) {
  const review = kind === "reviews";
  const flat = review ? [...reviews, ...withdrawal, ...disposition] : versions;
  const fields = values(flat, "chosen");
  const privateValues = fields.map((value) => (value === "chosen.reason" ? hash(value) : value));
  const json = review
    ? `, normalized as materialized (
    select frontier.*,convert_from(raw_payload,'UTF8')::jsonb as payload from frontier
  )`
    : "";
  const graph = review
    ? `cross join lateral (
    with recursive roots(value) as (values(chosen.anchor),(chosen.payload)), nodes(value,member) as (
      select value,false from roots where value is not null
      union all
      select child.value,child.member from nodes as node cross join lateral (
        select entry.value,true as member from jsonb_each(
          case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
        union all
        select entry.value,false as member from jsonb_array_elements(
          case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
      ) as child
    ) select (select coalesce(sum(${utf8("value")}),0)::text from roots) as json_utf8,
      (select count(*) filter(where member)::text from nodes) as json_properties,
      (select count(*) filter(where jsonb_typeof(value) in ('object','array'))::text from nodes) as json_containers
  ) as graph`
    : "";
  // First materialize the exact joined, ordered limit+1 frontier. Only selected
  // review rows are parsed/measured; versions never select canonical_text.
  // PostgreSQL parsing/detoast/recursive workspace is outside this Node policy.
  const measured = `with frontier as materialized (${review ? selectedReviews : selectedVersions})${json}, measured as materialized (
    select chosen.*,${review ? "case when withdrawal_id is null then '0' else '1' end" : "'0'::text"} as withdrawal_count,
      ${review ? "case when disposition_id is null then '0' else '1' end" : "'0'::text"} as disposition_count,
      (${[...fields, "chosen.cursor_at", "chosen.cursor_id"].map(utf8).join("+")})::text as scalar_utf8,
      ${review ? "graph.json_utf8,graph.json_properties,graph.json_containers" : "'0'::text as json_utf8,'0'::text as json_properties,'0'::text as json_containers"},
      ${hash(`jsonb_build_array(${privateValues.join(",")},chosen.raw_created_at${review ? `,${hash("chosen.anchor")},${hash("chosen.payload")},encode(sha256(chosen.raw_payload),'hex'),octet_length(chosen.raw_payload)` : ""})`)} as observation_sha256
    from ${review ? "normalized" : "frontier"} as chosen ${graph}
  )`;
  const constructor = review
    ? `jsonb_build_object(${pairs(reviews, "chosen")},'anchor',chosen.anchor,'payload',chosen.payload,
    'withdrawal',case when chosen.withdrawal_id is null then null else jsonb_build_object(${pairs(withdrawal, "chosen")}) end,
    'disposition',case when chosen.disposition_id is null then null else jsonb_build_object(${pairs(disposition, "chosen")}) end)`
    : `jsonb_build_object(${pairs(versions, "chosen")})`;
  return {
    preflight: `${measured} select ${metadataColumns} from measured order by sort_created_at desc,id desc`,
    content: `${measured}, expected as materialized (
      select * from jsonb_to_recordset($5::jsonb) as bound(id uuid,cursor_at text,raw_created_at text,observation_sha256 text,
        withdrawal_count text,disposition_count text,scalar_utf8 numeric,json_utf8 numeric,json_properties numeric,json_containers numeric)
    ), matched as materialized (
      select fresh.*,(bound.id is not null and fresh.cursor_at is not distinct from bound.cursor_at
        and fresh.withdrawal_count=bound.withdrawal_count and fresh.disposition_count=bound.disposition_count
        and fresh.scalar_utf8::numeric<=bound.scalar_utf8 and fresh.json_utf8::numeric<=bound.json_utf8
        and fresh.json_properties::numeric<=bound.json_properties and fresh.json_containers::numeric<=bound.json_containers) as fits
      from measured as fresh left join expected as bound on bound.id=fresh.id
        and fresh.sort_created_at=bound.raw_created_at::timestamptz and fresh.observation_sha256=bound.observation_sha256
    ), global_gate as materialized (select coalesce(bool_and(fits),true) as fits from matched)
    select fits,item,cursor_at,cursor_id from (
      select gate.fits,case when gate.fits then (select ${constructor}) else null end as item,
        chosen.cursor_at,chosen.cursor_id,chosen.sort_created_at,chosen.id as sort_id
      from matched as chosen cross join global_gate as gate where gate.fits
      union all
      select gate.fits,null::jsonb,null::text,null::text,null::timestamptz,null::uuid
      from global_gate as gate where not gate.fits
    ) as projected order by sort_created_at desc,sort_id desc`
  };
}
export const MINUTES_LIST_PREFLIGHT_SQL = {
  versions: statements("versions").preflight,
  reviews: statements("reviews").preflight
};
export const MINUTES_LIST_CONTENT_SQL = {
  versions: statements("versions").content,
  reviews: statements("reviews").content
};
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("minutes list scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("minutes list scalar is invalid");
  return BigInt(value);
}
export function minutesListProjectionCost(
  kind: MinutesListKind,
  input: MinutesListScalars
): ListProjectionScalars {
  if (kind !== "versions" && kind !== "reviews")
    throw new TypeError("unknown minutes list projection");
  const r = scalar(input.row_count),
    w = scalar(input.withdrawal_count),
    d = scalar(input.disposition_count),
    s = scalar(input.scalar_utf8),
    n = scalar(input.json_utf8),
    p = scalar(input.json_properties),
    o = scalar(input.json_containers);
  if (
    r > 501n ||
    w > r ||
    d > r ||
    (kind === "versions" && (w !== 0n || d !== 0n || n !== 0n || p !== 0n || o !== 0n))
  )
    throw new TypeError("minutes list counts are invalid");
  return {
    jsonUpperBytes: (
      2n +
      (kind === "versions" ? 274n * r : 377n * r + 73n * w + 118n * d + n) +
      6n * s
    ).toString(),
    propertyCount: (
      25n + (kind === "versions" ? 13n * r : 18n * r + 3n * w + 5n * d + p)
    ).toString(),
    objectOrArrayCount: (7n + 2n * r + (kind === "versions" ? 0n : w + d + o)).toString()
  };
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function observation(input: MinutesListInput, rows: readonly MinutesListMetadata[]) {
  if (
    (input.kind !== "versions" && input.kind !== "reviews") ||
    !uuid.test(input.minutesId) ||
    !Number.isInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > 500 ||
    rows.length > input.limit + 1
  )
    throw new TypeError("minutes list selector is invalid");
  const ids = new Set<string>(),
    totals = Object.fromEntries(scalarKeys.map((key) => [key, 0n])) as Record<
      (typeof scalarKeys)[number],
      bigint
    >;
  const tuples = rows.map((row) => {
    if (
      typeof row.id !== "string" ||
      !uuid.test(row.id) ||
      ids.has(row.id) ||
      (row.cursor_at !== null && typeof row.cursor_at !== "string") ||
      typeof row.raw_created_at !== "string" ||
      !row.raw_created_at ||
      typeof row.observation_sha256 !== "string" ||
      !/^[0-9a-f]{64}$/u.test(row.observation_sha256)
    )
      throw new TypeError("minutes list metadata identity is invalid");
    ids.add(row.id);
    for (const key of scalarKeys) totals[key] += scalar(row[key]);
    if (scalar(row.withdrawal_count) > 1n || scalar(row.disposition_count) > 1n)
      throw new TypeError("minutes list child cardinality is invalid");
    return Object.freeze({ ...row });
  });
  const scalars = {
    row_count: String(rows.length),
    ...Object.fromEntries(scalarKeys.map((key) => [key, totals[key].toString()]))
  } as unknown as MinutesListScalars;
  return { tuples: Object.freeze(tuples), scalars };
}
function plan(
  input: MinutesListInput,
  observed: ReturnType<typeof observation>
): ResponseAllocationPlan {
  return responseAllocationPlan({
    kind: "minutes_list_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: input.minutesId,
    sourceVersion: `${input.kind}:${input.limit}`,
    sha256: createHash("sha256")
      .update(JSON.stringify([input, observed.tuples]))
      .digest("hex"),
    listProjection: minutesListProjectionCost(input.kind, observed.scalars)
  });
}
export function minutesListProjectionPlan(
  input: MinutesListInput,
  rows: readonly MinutesListMetadata[]
): ResponseAllocationPlan {
  return plan(input, observation(input, rows));
}
export async function loadAdmittedMinutesList(
  client: PoolClient,
  input: MinutesListInput
): Promise<readonly MinutesListPageRow[]> {
  // Validate even an empty selection before choosing a statement. All contents
  // still wait for an owner/lease, including the original empty page envelope.
  observation(input, []);
  const parameters = [input.minutesId, input.cursorAt, input.cursorId, input.limit + 1];
  const inspected = await client.query<MinutesListMetadata>(
    MINUTES_LIST_PREFLIGHT_SQL[input.kind],
    parameters
  );
  const observed = observation(input, inspected.rows);
  const loaded = await loadWithResponseAllocation(plan(input, observed), () =>
    client.query<{
      fits: boolean;
      item: JsonValue;
      cursor_at: string | null;
      cursor_id: string | null;
    }>(MINUTES_LIST_CONTENT_SQL[input.kind], [...parameters, JSON.stringify(observed.tuples)])
  );
  if (loaded.rows.length === 1 && loaded.rows[0]?.fits === false)
    throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > observed.tuples.length)
    throw new TypeError("minutes list returned extra rows");
  let previous = -1;
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
      Array.isArray(row.item)
    )
      throw new TypeError("minutes list returned tuple mismatch");
    const item = row.item as Readonly<Record<string, JsonValue>>;
    if (
      item[input.kind === "versions" ? "version_id" : "review_item_id"] !== expected.id ||
      item["minutes_id"] !== input.minutesId
    )
      throw new TypeError("minutes list returned item identity mismatch");
    previous = index;
  }
  return loaded.rows as readonly MinutesListPageRow[];
}
