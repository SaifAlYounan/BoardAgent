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

export interface MinutesLineageMetadata {
  readonly correction_cycle_id: string;
  readonly original_minutes_id: string;
  readonly replacement_minutes_id: string;
  readonly secretary_member_id: string;
  readonly reason_utf8: string;
  readonly reason_sha256: string;
  readonly created_at: string | null;
  readonly raw_created_at: string;
  readonly cycle_count: string;
}
export interface MinutesLineageScalars {
  readonly cycle_count: string;
  readonly scalar_utf8: string;
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digest = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const selected = `with visible as materialized (
  select cycle.id as correction_cycle_id,cycle.original_minutes_id,cycle.replacement_minutes_id,
    cycle.reason,cycle.secretary_member_id,cycle.created_at as sort_created_at,
    cycle.created_at::text as raw_created_at,
    to_char(cycle.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as created_at
  from minutes_correction_cycles as cycle
  where cycle.original_minutes_id=$1 or cycle.replacement_minutes_id=$1
), measured as materialized (
  select visible.*,${utf8("reason")}::text as reason_utf8,
    encode(sha256(convert_to(reason,'UTF8')),'hex') as reason_sha256,
    (${["correction_cycle_id", "original_minutes_id", "replacement_minutes_id", "reason", "secretary_member_id", "created_at"].map(utf8).join("+")}) as scalar_utf8
  from visible
)`;
// Only scalar metadata crosses before reserve. Two distinct uniqueness constraints
// bound valid rows to two; LIMIT3 detects inconsistent cardinality without truncating output.
export const MINUTES_LINEAGE_PREFLIGHT_SQL = `${selected}
select correction_cycle_id,original_minutes_id,replacement_minutes_id,secretary_member_id,
  reason_utf8,reason_sha256,created_at,raw_created_at,count(*) over()::text as cycle_count
from measured order by sort_created_at,correction_cycle_id limit 3`;
export const MINUTES_LINEAGE_CONTENT_SQL = `${selected}, expected as materialized (
  select * from jsonb_to_recordset($2::jsonb) as bound(
    correction_cycle_id uuid,original_minutes_id uuid,replacement_minutes_id uuid,
    secretary_member_id uuid,reason_utf8 text,reason_sha256 text,created_at text,raw_created_at text)
), metrics as materialized (
  select count(*)::text as cycle_count,
    (${utf8("$1::uuid")}+coalesce(sum(scalar_utf8),0))::text as scalar_utf8 from measured
), gated as materialized (
  select metrics.*,cycle_count::numeric<=$3::numeric and cycle_count::numeric<=2
    and scalar_utf8::numeric<=$4::numeric and not exists(
      select 1 from measured as fresh where not exists(
        select 1 from expected as bound
        where fresh.correction_cycle_id=bound.correction_cycle_id
          and fresh.original_minutes_id=bound.original_minutes_id
          and fresh.replacement_minutes_id=bound.replacement_minutes_id
          and fresh.secretary_member_id=bound.secretary_member_id
          and fresh.reason_utf8=bound.reason_utf8 and fresh.reason_sha256=bound.reason_sha256
          and fresh.created_at is not distinct from bound.created_at
          and fresh.sort_created_at=bound.raw_created_at::timestamptz
      )
    ) as fits from metrics
)
select cycle_count,scalar_utf8,fits,case when fits then (
  select coalesce(jsonb_agg(jsonb_build_object(
    'correction_cycle_id',cycle.correction_cycle_id,'original_minutes_id',cycle.original_minutes_id,
    'replacement_minutes_id',cycle.replacement_minutes_id,'reason',cycle.reason,
    'secretary_member_id',cycle.secretary_member_id,'created_at',cycle.created_at
  ) order by cycle.sort_created_at,cycle.correction_cycle_id),'[]'::jsonb) from visible as cycle
) else null end as items from gated`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("minutes lineage scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("minutes lineage scalar is invalid");
  return BigInt(value);
}
export function minutesLineageProjectionCost(input: MinutesLineageScalars): ListProjectionScalars {
  const r = scalar(input.cycle_count),
    s = scalar(input.scalar_utf8);
  if (r > 2n) throw new ResponseAllocationUnavailable();
  return {
    jsonUpperBytes: (49n + 159n * r + 6n * s).toString(),
    propertyCount: (25n + 6n * r).toString(),
    objectOrArrayCount: (7n + r).toString()
  };
}
function observation(minutesId: string, rows: readonly MinutesLineageMetadata[]) {
  if (!uuid.test(minutesId)) throw new TypeError("minutes lineage identity is invalid");
  if (rows.length > 2) throw new ResponseAllocationUnavailable();
  const ids = new Set<string>();
  let bytes = BigInt(Buffer.byteLength(minutesId));
  const tuples = rows.map((row) => {
    const values = [
      row.correction_cycle_id,
      row.original_minutes_id,
      row.replacement_minutes_id,
      row.secretary_member_id
    ];
    if (
      values.some((value) => typeof value !== "string" || !uuid.test(value)) ||
      ids.has(row.correction_cycle_id) ||
      row.original_minutes_id === row.replacement_minutes_id ||
      (row.original_minutes_id !== minutesId && row.replacement_minutes_id !== minutesId) ||
      scalar(row.cycle_count) !== BigInt(rows.length) ||
      typeof row.reason_sha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(row.reason_sha256) ||
      (row.created_at !== null && typeof row.created_at !== "string") ||
      typeof row.raw_created_at !== "string" ||
      !row.raw_created_at
    )
      throw new TypeError("minutes lineage metadata identity is invalid");
    const reason = scalar(row.reason_utf8);
    if (reason < 1n || reason > 262_144n) throw new ResponseAllocationUnavailable();
    ids.add(row.correction_cycle_id);
    bytes +=
      144n + reason + BigInt(row.created_at === null ? 0 : Buffer.byteLength(row.created_at));
    return Object.freeze({
      correction_cycle_id: row.correction_cycle_id,
      original_minutes_id: row.original_minutes_id,
      replacement_minutes_id: row.replacement_minutes_id,
      secretary_member_id: row.secretary_member_id,
      reason_utf8: row.reason_utf8,
      reason_sha256: row.reason_sha256,
      created_at: row.created_at,
      raw_created_at: row.raw_created_at
    });
  });
  return {
    tuples: Object.freeze(tuples),
    scalars: { cycle_count: String(rows.length), scalar_utf8: bytes.toString() }
  };
}
function plan(minutesId: string, observed: ReturnType<typeof observation>): ResponseAllocationPlan {
  return responseAllocationPlan({
    kind: "minutes_lineage_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: minutesId,
    sourceVersion: "1",
    sha256: digest(JSON.stringify([minutesId, observed.tuples])),
    listProjection: minutesLineageProjectionCost(observed.scalars)
  });
}
export function minutesLineageProjectionPlan(
  minutesId: string,
  rows: readonly MinutesLineageMetadata[]
): ResponseAllocationPlan {
  return plan(minutesId, observation(minutesId, rows));
}
export async function loadAdmittedMinutesLineage(
  client: PoolClient,
  minutesId: string
): Promise<JsonValue[]> {
  const metadata = await client.query<MinutesLineageMetadata>(MINUTES_LINEAGE_PREFLIGHT_SQL, [
    minutesId
  ]);
  const observed = observation(minutesId, metadata.rows);
  const loaded = await loadWithResponseAllocation(plan(minutesId, observed), () =>
    client.query<
      MinutesLineageScalars & {
        fits: boolean;
        items: JsonValue;
      }
    >(MINUTES_LINEAGE_CONTENT_SQL, [
      minutesId,
      JSON.stringify(observed.tuples),
      observed.scalars.cycle_count,
      observed.scalars.scalar_utf8
    ])
  );
  const row = loaded.rows[0];
  if (loaded.rows.length !== 1 || !row)
    throw new TypeError("minutes lineage content row is invalid");
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    !Array.isArray(row.items) ||
    scalar(row.cycle_count) !== BigInt(row.items.length) ||
    row.items.length > observed.tuples.length ||
    scalar(row.scalar_utf8) > BigInt(observed.scalars.scalar_utf8)
  )
    throw new TypeError("minutes lineage content bound is invalid");
  const keys = [
    "correction_cycle_id",
    "original_minutes_id",
    "replacement_minutes_id",
    "reason",
    "secretary_member_id",
    "created_at"
  ];
  let previous = -1,
    bytes = BigInt(Buffer.byteLength(minutesId));
  for (const item of row.items) {
    if (item === null || typeof item !== "object" || Array.isArray(item))
      throw new TypeError("minutes lineage item is invalid");
    const value = item as Readonly<Record<string, JsonValue>>;
    const index = observed.tuples.findIndex(
      (tuple) => tuple.correction_cycle_id === value["correction_cycle_id"]
    );
    const expected = observed.tuples[index];
    if (
      !expected ||
      index <= previous ||
      Object.keys(value).length !== 6 ||
      keys.some((key) => !Object.hasOwn(value, key)) ||
      value["original_minutes_id"] !== expected.original_minutes_id ||
      value["replacement_minutes_id"] !== expected.replacement_minutes_id ||
      value["secretary_member_id"] !== expected.secretary_member_id ||
      value["created_at"] !== expected.created_at ||
      typeof value["reason"] !== "string" ||
      String(Buffer.byteLength(value["reason"])) !== expected.reason_utf8 ||
      digest(value["reason"]) !== expected.reason_sha256
    )
      throw new TypeError("minutes lineage returned tuple mismatch");
    previous = index;
    bytes +=
      144n +
      BigInt(expected.reason_utf8) +
      BigInt(expected.created_at === null ? 0 : Buffer.byteLength(expected.created_at));
  }
  if (bytes !== scalar(row.scalar_utf8))
    throw new TypeError("minutes lineage returned scalar mismatch");
  return row.items;
}
