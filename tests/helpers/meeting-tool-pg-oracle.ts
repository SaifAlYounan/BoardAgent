import { expect } from "vitest";
import type { PoolClient } from "pg";
import type { JsonValue } from "../../lib/contracts/src/index.js";
import type {
  AgendaProjectionMetadata,
  AttendanceProjectionMetadata
} from "../../artifacts/server/src/meeting-tool-projection.js";
import { ORIGINAL_AGENDA_SQL, ORIGINAL_ATTENDANCE_SQL } from "./meeting-tool-original-sql.js";

// Independent test-local lists from the verbatim original projection, never from
// runtime field descriptors. SQL hashes original PG values before JS numeric parsing.
const rootKeys = [
  "meeting_id",
  "agenda_version_id",
  "version",
  "schema_version",
  "sha256",
  "created_at"
] as const;
const itemKeys = [
  "item_id",
  "ordinal",
  "title",
  "source_document_version_id",
  "source_document_sha256",
  "sha256"
] as const;
const attendanceKeys = [
  "attendance_id",
  "member_id",
  "status",
  "source",
  "recorder_member_id",
  "corrects_id",
  "correction_reason",
  "recorded_at"
] as const;
function object(value: unknown): Record<string, JsonValue> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("expected original JSON object");
  return value as Record<string, JsonValue>;
}
function exactKeys(value: Record<string, JsonValue>, keys: readonly string[]) {
  expect(Object.keys(value).sort()).toEqual([...keys].sort());
}
const bytes = (value: JsonValue | undefined) =>
  value === null ? 0 : Buffer.byteLength(String(value));
export function meetingOracleShape(value: unknown) {
  let properties = 0,
    containers = 0;
  const stack = [value];
  while (stack.length) {
    const node = stack.pop();
    if (node !== null && typeof node === "object") {
      containers++;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      for (const child of Object.values(node)) stack.push(child);
    }
  }
  return { properties, containers };
}
const agendaObservation = `encode(sha256(convert_to(jsonb_build_array(
  original.view->'meeting_id',original.view->'agenda_version_id',original.view->'version',
  original.view->'schema_version',original.view->'sha256',original.view->'created_at',
  encode(sha256(convert_to((original.view->'canonical_payload')::text,'UTF8')),'hex'),
  encode(sha256(convert_to(coalesce((select string_agg(
    encode(sha256(convert_to(jsonb_build_array(
      item.value->'item_id',item.value->'ordinal',item.value->'title',
      item.value->'source_document_version_id',item.value->'source_document_sha256',item.value->'sha256'
    )::text,'UTF8')),'hex'),'' order by item.ordinality)
    from jsonb_array_elements(original.view->'items') with ordinality as item(value,ordinality)),''),'UTF8')),'hex')
)::text,'UTF8')),'hex')`;
export async function originalAgendaOracle(
  client: PoolClient,
  meetingId: string,
  version: number | null,
  originalSql = ORIGINAL_AGENDA_SQL
) {
  const found = await client.query<{
    view: JsonValue;
    normalized_json_text: string;
    observation_sha256: string;
  }>(
    `with original as materialized (${originalSql})
     select original.view,(original.view->'canonical_payload')::text as normalized_json_text,
       ${agendaObservation} as observation_sha256 from original`,
    [meetingId, version]
  );
  expect(found.rows.length).toBeLessThanOrEqual(1);
  const row = found.rows[0];
  if (!row) return null;
  const view = object(row.view);
  exactKeys(view, [...rootKeys, "canonical_payload", "items"]);
  if (!Array.isArray(view["items"])) throw new Error("expected original agenda items");
  const items = view["items"].map(object);
  let s = 0;
  for (const key of rootKeys) s += bytes(view[key]);
  for (const item of items) {
    exactKeys(item, itemKeys);
    for (const key of itemKeys) s += bytes(item[key]);
  }
  const graph = meetingOracleShape(view["canonical_payload"]);
  const metadata: AgendaProjectionMetadata = {
    meeting_id: String(view["meeting_id"]),
    agenda_version_id: String(view["agenda_version_id"]),
    version: String(view["version"]),
    observation_sha256: row.observation_sha256,
    item_count: String(items.length),
    scalar_utf8: String(s),
    normalized_json_utf8: String(Buffer.byteLength(row.normalized_json_text)),
    json_property_count: String(graph.properties),
    json_container_count: String(graph.containers)
  };
  return { view: row.view, metadata, normalizedJsonText: row.normalized_json_text };
}
const attendanceObservation = `encode(sha256(convert_to(coalesce((select string_agg(
  encode(sha256(convert_to(jsonb_build_array(
    item.value->'attendance_id',item.value->'member_id',item.value->'status',item.value->'source',
    item.value->'recorder_member_id',item.value->'corrects_id',
    encode(sha256(convert_to(item.value->>'correction_reason','UTF8')),'hex'),
    coalesce(octet_length(convert_to(item.value->>'correction_reason','UTF8')),0)::numeric,
    item.value->'recorded_at',
    (select attendance.recorded_at::text from meeting_attendance as attendance
      where attendance.id=(item.value->>'attendance_id')::uuid)
  )::text,'UTF8')),'hex'),'' order by item.ordinality)
  from jsonb_array_elements(original.items) with ordinality as item(value,ordinality)),''),'UTF8')),'hex')`;
export async function originalAttendanceOracle(
  client: PoolClient,
  meetingId: string,
  originalSql = ORIGINAL_ATTENDANCE_SQL
) {
  const found = await client.query<{ items: JsonValue; observation_sha256: string }>(
    `with original as materialized (${originalSql})
     select original.items,${attendanceObservation} as observation_sha256 from original`,
    [meetingId]
  );
  expect(found.rows).toHaveLength(1);
  const row = found.rows[0]!;
  if (!Array.isArray(row.items)) throw new Error("expected original attendance array");
  let s = Buffer.byteLength(meetingId);
  for (const value of row.items) {
    const item = object(value);
    exactKeys(item, attendanceKeys);
    for (const key of attendanceKeys) s += bytes(item[key]);
  }
  const metadata: AttendanceProjectionMetadata = {
    meeting_id: meetingId,
    record_count: String(row.items.length),
    scalar_utf8: String(s),
    observation_sha256: row.observation_sha256
  };
  return { items: row.items, metadata };
}
