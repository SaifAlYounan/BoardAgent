import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface AgendaProjectionMetadata {
  readonly meeting_id: string;
  readonly agenda_version_id: string;
  readonly version: string;
  readonly observation_sha256: string;
  readonly item_count: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
}
export interface AttendanceProjectionMetadata {
  readonly meeting_id: string;
  readonly record_count: string;
  readonly scalar_utf8: string;
  readonly observation_sha256: string;
}
export interface AgendaProjectionRow {
  readonly view: JsonValue;
}
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const agendaFlat = [
  ["meeting_id", "agenda.meeting_id"],
  ["agenda_version_id", "agenda.agenda_version_id"],
  ["version", "agenda.version"],
  ["schema_version", "agenda.schema_version"],
  ["sha256", "agenda.sha256"],
  ["created_at", "agenda.created_at"]
] as const;
const itemFlat = [
  ["item_id", "item.item_id"],
  ["ordinal", "item.ordinal"],
  ["title", "item.title"],
  ["source_document_version_id", "item.source_document_version_id"],
  ["source_document_sha256", "item.source_document_sha256"],
  ["sha256", "item.sha256"]
] as const;
const attendanceFlat = [
  ["attendance_id", "attendance.attendance_id"],
  ["member_id", "attendance.member_id"],
  ["status", "attendance.status"],
  ["source", "attendance.source"],
  ["recorder_member_id", "attendance.recorder_member_id"],
  ["corrects_id", "attendance.corrects_id"],
  ["correction_reason", "attendance.correction_reason"],
  ["recorded_at", "attendance.recorded_at_text"]
] as const;
const pairs = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([key, value]) => `'${key}',${value}`).join(",\n");
const tuple = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([, value]) => value).join(",");
const sum = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([, value]) => utf8(value)).join("+");

// Normalization, recursive JSON measurement and digest/sort workspace stay in
// PostgreSQL. Only fixed scalar metadata crosses into Node before reservation.
// Retain the original meeting join/current-or-explicit selector and LIMIT1.
const agendaMeasured = `with recursive selected_agenda as materialized (
  select meeting.id as meeting_id,agenda.id as agenda_version_id,agenda.version,
    agenda.schema_version,convert_from(agenda.canonical_payload,'UTF8')::jsonb as canonical_payload,
    encode(agenda.canonical_sha256,'hex') as sha256,${date("agenda.created_at")} as created_at
  from meetings as meeting join agenda_versions as agenda on agenda.meeting_id=meeting.id
  where meeting.id=$1 and (($2::integer is null and agenda.id=meeting.current_agenda_version_id)
    or agenda.version=$2)
  order by agenda.version desc limit 1
), selected_items as materialized (
  select item.id as item_id,item.ordinal,item.title,item.source_document_version_id,
    encode(item.source_document_sha256,'hex') as source_document_sha256,
    encode(item.item_sha256,'hex') as sha256
  from agenda_items as item
  where exists(select 1 from selected_agenda as agenda where agenda.agenda_version_id=item.agenda_version_id)
), json_nodes(value,member) as (
  select canonical_payload,false from selected_agenda
  union all
  select child.value,child.member from json_nodes as node
  cross join lateral (
    select entry.value,true as member
    from jsonb_each(case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member
    from jsonb_array_elements(case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), json_metrics as materialized (
  select (count(*) filter(where member))::text as json_property_count,
    (count(*) filter(where jsonb_typeof(value) in ('object','array')))::text as json_container_count
  from json_nodes
), item_metrics as materialized (
  select count(*)::text as item_count,coalesce(sum(${sum(itemFlat)}),0)::numeric as scalar_utf8,
    ${hash(`coalesce(string_agg(${hash(`jsonb_build_array(${tuple(itemFlat)})`)},'' order by item.ordinal,item.item_id),'')`)} as observation_sha256
  from selected_items as item
), measured as materialized (
  select agenda.meeting_id,agenda.agenda_version_id,agenda.version::text as version,
    item_metrics.item_count,(${sum(agendaFlat)}+item_metrics.scalar_utf8)::text as scalar_utf8,
    ${utf8("agenda.canonical_payload")}::text as normalized_json_utf8,
    json_metrics.json_property_count,json_metrics.json_container_count,
    ${hash(`jsonb_build_array(${tuple(agendaFlat)},${hash("agenda.canonical_payload")},item_metrics.observation_sha256)`)} as observation_sha256
  from selected_agenda as agenda cross join item_metrics cross join json_metrics
)`;
export const AGENDA_PREFLIGHT_SQL = `${agendaMeasured} select * from measured`;
export const AGENDA_CONTENT_SQL = `${agendaMeasured}, gated as materialized (
  select measured.*,agenda_version_id=$3::uuid and version=$4::text and observation_sha256=$5::text
    and item_count=$6::text and scalar_utf8::numeric<=$7::numeric
    and normalized_json_utf8::numeric<=$8::numeric
    and json_property_count=$9::text and json_container_count=$10::text as fits from measured
)
select gated.meeting_id,gated.agenda_version_id,gated.version,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${pairs(agendaFlat)},'canonical_payload',agenda.canonical_payload,
      'items',coalesce((select jsonb_agg(jsonb_build_object(${pairs(itemFlat)})
        order by item.ordinal,item.item_id) from selected_items as item),'[]'::jsonb))
    from selected_agenda as agenda
  ) else null end as view
from gated`;

const attendanceMeasured = `with selected_attendance as materialized (
  select attendance.id as attendance_id,attendance.member_id,attendance.attendance_status as status,
    attendance.source,attendance.recorder_member_id,attendance.corrects_id,attendance.correction_reason,
    attendance.recorded_at,${date("attendance.recorded_at")} as recorded_at_text
  from meeting_attendance as attendance where attendance.meeting_id=$1
), measured as materialized (
  select $1::uuid as meeting_id,count(*)::text as record_count,
    (${utf8("$1::uuid")}+coalesce(sum(${sum(attendanceFlat)}),0))::text as scalar_utf8,
    ${hash(
      `coalesce(string_agg(${hash(`jsonb_build_array(attendance.attendance_id,attendance.member_id,
      attendance.status,attendance.source,attendance.recorder_member_id,attendance.corrects_id,
      ${hash("attendance.correction_reason")},${utf8("attendance.correction_reason")},
      attendance.recorded_at_text,attendance.recorded_at::text)`)},'' order by attendance.recorded_at,attendance.attendance_id),'')`
    )} as observation_sha256
  from selected_attendance as attendance
)`;
export const ATTENDANCE_PREFLIGHT_SQL = `${attendanceMeasured} select * from measured`;
export const ATTENDANCE_CONTENT_SQL = `${attendanceMeasured}, gated as materialized (
  select measured.*,((record_count='0' and scalar_utf8='36' and observation_sha256=${hash("''::text")})
    or (record_count=$2::text and scalar_utf8::numeric<=$3::numeric and observation_sha256=$4::text)) as fits
  from measured
)
select gated.meeting_id,gated.record_count,gated.scalar_utf8,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select coalesce(jsonb_agg(jsonb_build_object(${pairs(attendanceFlat)})
      order by attendance.recorded_at,attendance.attendance_id),'[]'::jsonb)
    from selected_attendance as attendance
  ) else null end as items
from gated`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("meeting projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("meeting projection scalar is invalid");
  return BigInt(value);
}
function observation(value: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value))
    throw new TypeError("meeting projection observation is invalid");
}
function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("meeting projection payload is invalid");
  return value as Readonly<Record<string, JsonValue>>;
}
export function agendaProjectionCost(metadata: AgendaProjectionMetadata): ListProjectionScalars {
  const i = scalar(metadata.item_count),
    s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.normalized_json_utf8),
    p = scalar(metadata.json_property_count),
    o = scalar(metadata.json_container_count);
  if (n < 1n) throw new TypeError("normalized agenda JSON cannot be empty");
  // One arbitrary normalized JSON root includes an explicit numeric-carry byte.
  // Inherited23-property/5-container and4KiB allowances remain policy, not RSS.
  return {
    jsonUpperBytes: (169n + 137n * i + 6n * s + n).toString(),
    propertyCount: (31n + 6n * i + p).toString(),
    objectOrArrayCount: (7n + i + o).toString()
  };
}
export function attendanceProjectionCost(
  metadata: AttendanceProjectionMetadata
): ListProjectionScalars {
  const r = scalar(metadata.record_count),
    s = scalar(metadata.scalar_utf8);
  if (s < 36n || (r === 0n && s !== 36n))
    throw new TypeError("attendance selector bytes are invalid");
  return {
    jsonUpperBytes: (39n + 175n * r + 6n * s).toString(),
    propertyCount: (25n + 8n * r).toString(),
    objectOrArrayCount: (7n + r).toString()
  };
}
export function agendaProjectionPlan(metadata: AgendaProjectionMetadata): ResponseAllocationPlan {
  observation(metadata.observation_sha256);
  const version = scalar(metadata.version);
  if (version < 1n || version > 2_147_483_647n) throw new TypeError("agenda version is invalid");
  return responseAllocationPlan({
    kind: "meeting_tool_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.agenda_version_id,
    sourceVersion: metadata.version,
    sha256: metadata.observation_sha256,
    listProjection: agendaProjectionCost(metadata)
  });
}
export function attendanceProjectionPlan(
  metadata: AttendanceProjectionMetadata
): ResponseAllocationPlan {
  observation(metadata.observation_sha256);
  return responseAllocationPlan({
    kind: "meeting_tool_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.meeting_id,
    sourceVersion: "1",
    sha256: metadata.observation_sha256,
    listProjection: attendanceProjectionCost(metadata)
  });
}
export async function loadAdmittedAgenda(
  client: PoolClient,
  meetingId: string,
  version: number | null
): Promise<readonly AgendaProjectionRow[]> {
  const selected = await client.query<AgendaProjectionMetadata>(AGENDA_PREFLIGHT_SQL, [
    meetingId,
    version
  ]);
  if (selected.rows.length > 1) throw new TypeError("agenda preflight returned multiple parents");
  const metadata = selected.rows[0];
  if (!metadata) return [];
  if (
    metadata.meeting_id !== meetingId ||
    (version !== null && metadata.version !== String(version))
  )
    throw new TypeError("agenda preflight identity is invalid");
  const loaded = await loadWithResponseAllocation(agendaProjectionPlan(metadata), () =>
    client.query<
      Pick<
        AgendaProjectionMetadata,
        "meeting_id" | "agenda_version_id" | "version" | "observation_sha256"
      > & { fits: boolean; view: JsonValue }
    >(AGENDA_CONTENT_SQL, [
      meetingId,
      version,
      metadata.agenda_version_id,
      metadata.version,
      metadata.observation_sha256,
      metadata.item_count,
      metadata.scalar_utf8,
      metadata.normalized_json_utf8,
      metadata.json_property_count,
      metadata.json_container_count
    ])
  );
  if (loaded.rows.length === 0) return [];
  if (loaded.rows.length !== 1) throw new TypeError("agenda content returned multiple parents");
  const row = loaded.rows[0]!;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    row.meeting_id !== meetingId ||
    row.agenda_version_id !== metadata.agenda_version_id ||
    row.version !== metadata.version ||
    row.observation_sha256 !== metadata.observation_sha256
  )
    throw new TypeError("agenda content identity is invalid");
  const view = record(row.view);
  if (
    view["meeting_id"] !== meetingId ||
    view["agenda_version_id"] !== metadata.agenda_version_id ||
    view["version"] !== Number(metadata.version) ||
    !Array.isArray(view["items"]) ||
    BigInt(view["items"].length) !== scalar(metadata.item_count)
  )
    throw new TypeError("agenda payload identity is invalid");
  return loaded.rows;
}
export async function loadAdmittedAttendance(
  client: PoolClient,
  meetingId: string
): Promise<JsonValue[]> {
  const selected = await client.query<AttendanceProjectionMetadata>(ATTENDANCE_PREFLIGHT_SQL, [
    meetingId
  ]);
  if (selected.rows.length !== 1 || selected.rows[0]?.meeting_id !== meetingId)
    throw new TypeError("attendance preflight identity is invalid");
  const metadata = selected.rows[0]!;
  const loaded = await loadWithResponseAllocation(attendanceProjectionPlan(metadata), () =>
    client.query<AttendanceProjectionMetadata & { fits: boolean; items: JsonValue }>(
      ATTENDANCE_CONTENT_SQL,
      [meetingId, metadata.record_count, metadata.scalar_utf8, metadata.observation_sha256]
    )
  );
  if (loaded.rows.length !== 1) throw new TypeError("attendance content cardinality is invalid");
  const row = loaded.rows[0]!;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  const r = scalar(row.record_count),
    s = scalar(row.scalar_utf8);
  observation(row.observation_sha256);
  const empty =
    r === 0n &&
    s === 36n &&
    row.observation_sha256 === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  if (
    row.fits !== true ||
    row.meeting_id !== meetingId ||
    (!empty &&
      (row.record_count !== metadata.record_count ||
        s > scalar(metadata.scalar_utf8) ||
        row.observation_sha256 !== metadata.observation_sha256)) ||
    !Array.isArray(row.items) ||
    BigInt(row.items.length) !== r
  )
    throw new TypeError("attendance content identity is invalid");
  return row.items;
}
