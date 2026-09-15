import type { PoolClient } from "pg";
import { expect } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  ORIGINAL_MEETING_TRANSCRIPTS_SQL,
  ORIGINAL_MEETINGS_SQL
} from "./meeting-lists-original-sql.js";

// Independent test inventory and verbatim legacy SQL. No production projection
// descriptor, scalar function, observation builder or content SQL is imported.
export type OracleMeetingListKind = "transcripts" | "meetings";
export interface OracleMeetingListInput {
  readonly kind: OracleMeetingListKind;
  readonly selectorId: string;
  readonly memberId: string | null;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface OriginalMeetingPageRow {
  readonly item: Readonly<Record<string, JsonValue>>;
  readonly cursor_at: string | null;
  readonly cursor_id: string;
}
export interface OriginalMeetingMeasuredRow extends OriginalMeetingPageRow {
  readonly raw_created_at: string;
  readonly scalar_utf8: string;
  readonly observation_sha256: string;
}
export const ORIGINAL_MEETING_LIST_FIELDS = {
  transcripts: [
    "transcript_id",
    "meeting_id",
    "state",
    "row_version",
    "current_version_id",
    "version",
    "media_type",
    "verification_state",
    "sha256"
  ],
  meetings: [
    "meeting_id",
    "board_id",
    "title",
    "state",
    "scheduled_start_at",
    "scheduled_end_at",
    "current_version_id",
    "current_agenda_version_id",
    "current_minutes_id",
    "row_version",
    "my_rsvp",
    "created_at"
  ]
} as const;
export const ORIGINAL_MEETING_LIST_SQL = {
  transcripts: ORIGINAL_MEETING_TRANSCRIPTS_SQL,
  meetings: ORIGINAL_MEETINGS_SQL
};
export function originalMeetingListParameters(input: OracleMeetingListInput): readonly unknown[] {
  return input.kind === "transcripts"
    ? [input.selectorId, input.cursorAt, input.cursorId, input.limit + 1]
    : [input.selectorId, input.memberId, input.cursorAt, input.cursorId, input.limit + 1];
}
const scalarBytes = (expression: string) =>
  `coalesce(octet_length(convert_to((${expression})::text,'UTF8')),0)::numeric`;
const digest = (expression: string) =>
  `encode(sha256(convert_to((${expression})::text,'UTF8')),'hex')`;
export function originalMeetingListMeasuredSql(kind: OracleMeetingListKind): string {
  const fields = ORIGINAL_MEETING_LIST_FIELDS[kind];
  const sourceTable = kind === "transcripts" ? "meeting_transcripts" : "meetings";
  const scalar = [
    ...fields.map((key) => `legacy.item->>'${key}'`),
    "legacy.cursor_at",
    "legacy.cursor_id"
  ];
  // Using JSONB values preserves the visible numeric versus string distinctions.
  // Title alone is privately hashed; raw PG timestamp text remains a string.
  // No RSVP row ID/version appears: only the original response or JSON null.
  const tuple = fields.map((key) =>
    key === "title" ? digest("legacy.item->>'title'") : `legacy.item->'${key}'`
  );
  return `with original_rows as materialized (${ORIGINAL_MEETING_LIST_SQL[kind]})
    select legacy.item,legacy.cursor_at,legacy.cursor_id,source.created_at::text as raw_created_at,
      (${scalar.map(scalarBytes).join("+")})::text as scalar_utf8,
      ${digest(`jsonb_build_array(${tuple.join(",")},source.created_at::text)`)} as observation_sha256
    from original_rows as legacy join ${sourceTable} as source on source.id=legacy.cursor_id::uuid
    order by source.created_at desc,source.id desc`;
}
export async function readOriginalMeetingList(
  client: PoolClient,
  input: OracleMeetingListInput
): Promise<readonly OriginalMeetingPageRow[]> {
  return (
    await client.query<OriginalMeetingPageRow>(ORIGINAL_MEETING_LIST_SQL[input.kind], [
      ...originalMeetingListParameters(input)
    ])
  ).rows;
}
export async function readOriginalMeetingListMeasurement(
  client: PoolClient,
  input: OracleMeetingListInput
): Promise<readonly OriginalMeetingMeasuredRow[]> {
  return (
    await client.query<OriginalMeetingMeasuredRow>(originalMeetingListMeasuredSql(input.kind), [
      ...originalMeetingListParameters(input)
    ])
  ).rows;
}
export function originalMeetingMetadata(rows: readonly OriginalMeetingMeasuredRow[]) {
  return rows.map((row) => ({
    id: row.cursor_id,
    cursor_at: row.cursor_at,
    raw_created_at: row.raw_created_at,
    observation_sha256: row.observation_sha256,
    scalar_utf8: row.scalar_utf8
  }));
}
export function originalMeetingRows(
  rows: readonly OriginalMeetingMeasuredRow[]
): readonly OriginalMeetingPageRow[] {
  return rows.map(({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id }));
}
export function assertOriginalMeetingFlatScalars(
  kind: OracleMeetingListKind,
  rows: readonly OriginalMeetingMeasuredRow[]
): void {
  for (const row of rows) {
    expect(Object.keys(row.item).sort()).toEqual([...ORIGINAL_MEETING_LIST_FIELDS[kind]].sort());
    let bytes = 0n;
    for (const value of [
      ...ORIGINAL_MEETING_LIST_FIELDS[kind].map((key) => row.item[key]),
      row.cursor_at,
      row.cursor_id
    ]) {
      if (value === null) continue;
      if (typeof value !== "string" && typeof value !== "number")
        throw new Error("legacy meeting view has a non-flat field");
      // The only number in these views is transcript.version (an integer).
      // row_version is text; this is not a general PG JSON numeric-byte oracle.
      if (typeof value === "number") expect(Number.isSafeInteger(value)).toBe(true);
      bytes += BigInt(Buffer.byteLength(String(value), "utf8"));
    }
    expect(String(bytes)).toBe(row.scalar_utf8);
    expect(typeof row.item.row_version).toBe("string");
  }
}
export function originalMeetingAllocationBound(
  kind: OracleMeetingListKind,
  rows: readonly OriginalMeetingMeasuredRow[]
) {
  const rowCount = BigInt(rows.length),
    scalarUtf8 = rows.reduce((total, row) => total + BigInt(row.scalar_utf8), 0n);
  const jsonUpperBytes = 2n + (kind === "transcripts" ? 260n : 343n) * rowCount + 6n * scalarUtf8;
  const propertyCount = 25n + (kind === "transcripts" ? 13n : 16n) * rowCount;
  const objectOrArrayCount = 7n + 2n * rowCount;
  const allocationBytes =
    65536n + 8n * (jsonUpperBytes + 4096n) + 256n * propertyCount + 512n * objectOrArrayCount;
  const wireBytes = 65536n + 3n * (jsonUpperBytes + 4096n);
  return {
    rowCount,
    scalarUtf8,
    jsonUpperBytes,
    propertyCount,
    objectOrArrayCount,
    allocationBytes,
    wireBytes,
    units: Number((allocationBytes + 1048575n) / 1048576n)
  };
}
