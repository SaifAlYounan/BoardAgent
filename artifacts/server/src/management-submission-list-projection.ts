import { createHash } from "node:crypto";
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

import { MANAGEMENT_SUBMISSION_READ_ACCESS } from "./management-submission-projection.js";
export interface SubmissionListInput {
  readonly memberId: string;
  readonly boardId: string;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface SubmissionListMetadata {
  readonly id: string;
  readonly cursor_at: string | null;
  readonly raw_order_key: string;
  readonly observation_sha256: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
}
export interface SubmissionListScalars {
  readonly row_count: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
}
export interface SubmissionListPageRow {
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
const fields = [
  ["submission_id", "id"],
  ["board_id", "board_id"],
  ["management_owner_ids", "json_payload"],
  ["assigned_secretary_id", "assigned_secretary_id"],
  ["state", "state"],
  ["current_version_id", "current_version_id"],
  ["row_version", "row_version"],
  ["queue_entered_at", "cursor_at"],
  ["current_version", "current_version"],
  ["current_payload_sha256", "current_payload_sha256"]
] as const;
const selected = `select thread.id,thread.board_id,to_jsonb(thread.management_owner_ids) as json_payload,
  thread.assigned_secretary_id,thread.state,thread.current_version_id,thread.row_version::text as row_version,
  version_row.version as current_version,encode(version_row.payload_sha256,'hex') as current_payload_sha256,
  thread.queue_entered_at as sort_key,thread.queue_entered_at::text as raw_order_key,
  ${utc("thread.queue_entered_at")} as cursor_at,thread.id::text as cursor_id
  from management_submission_threads as thread
  join management_submission_versions as version_row on version_row.id=thread.current_version_id
  where thread.board_id=$1 and ${MANAGEMENT_SUBMISSION_READ_ACCESS}
    and ($3::timestamptz is null or (thread.queue_entered_at,thread.id)<($3::timestamptz,$4::uuid))
  order by thread.queue_entered_at desc,thread.id desc limit $5`;
function statements() {
  const columns = fields.map(([, column]) => column);
  const flat = columns
    .filter((column) => column !== "json_payload")
    .map((column) => `chosen.${column}`);
  const privateValues = columns.map((column) =>
    column === "json_payload" ? hash(`chosen.${column}`) : `chosen.${column}`
  );
  const order = "sort_key desc,id desc";
  const sortType = "timestamptz";
  // The original selected frontier precedes all recursive JSON work. PostgreSQL
  // normalization/traversal/hash workspace is separate from retained Node output.
  const measured = `with recursive frontier as materialized (${selected}),
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
  const constructor = `jsonb_build_object(${fields.map(([key, column]) => `'${key}',chosen.${column}`).join(",")})`;
  return {
    preflight: `${measured} select id::text,cursor_at,raw_order_key,observation_sha256,
      scalar_utf8,normalized_json_utf8,json_property_count,json_container_count
      from measured order by ${order}`,
    content: `${measured}, expected as materialized (
      select * from jsonb_to_recordset($6::jsonb) as bound(
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
const sql = statements();
export const SUBMISSION_LIST_PREFLIGHT_SQL = sql.preflight;
export const SUBMISSION_LIST_CONTENT_SQL = sql.content;
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("submission list scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("submission list scalar is invalid");
  return BigInt(value);
}
export function submissionListProjectionCost(input: SubmissionListScalars): ListProjectionScalars {
  const r = scalar(input.row_count),
    s = scalar(input.scalar_utf8),
    n = scalar(input.normalized_json_utf8),
    p = scalar(input.json_property_count),
    o = scalar(input.json_container_count);
  if (r > 501n) throw new TypeError("submission list count is invalid");
  return {
    jsonUpperBytes: (2n + 289n * r + 6n * s + n).toString(),
    propertyCount: (25n + 14n * r + p).toString(),
    objectOrArrayCount: (7n + 2n * r + o).toString()
  };
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function observation(input: SubmissionListInput, rows: readonly SubmissionListMetadata[]) {
  if (
    !uuid.test(input.memberId) ||
    !uuid.test(input.boardId) ||
    !Number.isInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > 500 ||
    rows.length > input.limit + 1
  )
    throw new TypeError("submission list selector is invalid");
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
      throw new TypeError("submission list metadata identity is invalid");
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
  input: SubmissionListInput,
  observed: ReturnType<typeof observation>
): ResponseAllocationPlan {
  return responseAllocationPlan({
    kind: "management_read_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: input.boardId,
    sourceVersion: `submissions:${input.limit}`,
    sha256: createHash("sha256")
      .update(JSON.stringify([input, observed.tuples]))
      .digest("hex"),
    listProjection: submissionListProjectionCost(observed.scalars)
  });
}
export function submissionListProjectionPlan(
  input: SubmissionListInput,
  rows: readonly SubmissionListMetadata[]
): ResponseAllocationPlan {
  return plan(input, observation(input, rows));
}
export async function loadAdmittedSubmissionList(
  client: PoolClient,
  input: SubmissionListInput
): Promise<readonly SubmissionListPageRow[]> {
  observation(input, []);
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new TypeError("submission list requires a native request owner");
  owner.assertLive();
  const parameters = [
    input.boardId,
    input.memberId,
    input.cursorAt,
    input.cursorId,
    input.limit + 1
  ];
  const inspected = await client.query<SubmissionListMetadata>(
    SUBMISSION_LIST_PREFLIGHT_SQL,
    parameters
  );
  owner.assertLive();
  const observed = observation(input, inspected.rows);
  const loaded = await loadWithResponseAllocation(plan(input, observed), () =>
    client.query<{
      fits: boolean;
      item: JsonValue;
      cursor_at: string | null;
      cursor_id: string | null;
    }>(SUBMISSION_LIST_CONTENT_SQL, [...parameters, JSON.stringify(observed.tuples)])
  );
  if (loaded.rows.length === 1 && loaded.rows[0]?.fits === false)
    throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > observed.tuples.length)
    throw new TypeError("submission list returned extra rows");
  let previous = -1;
  const idField = "submission_id";
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
      throw new TypeError("submission list returned tuple mismatch");
    previous = index;
  }
  return loaded.rows as readonly SubmissionListPageRow[];
}
