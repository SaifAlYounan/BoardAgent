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

export type MeetingListKind = "transcripts" | "meetings";
export interface MeetingListInput {
  readonly kind: MeetingListKind;
  readonly selectorId: string;
  readonly memberId: string | null;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface MeetingListMetadata {
  readonly id: string;
  readonly cursor_at: string | null;
  readonly raw_created_at: string;
  readonly observation_sha256: string;
  readonly scalar_utf8: string;
}
export interface MeetingListScalars {
  readonly row_count: string;
  readonly scalar_utf8: string;
}
export interface MeetingListPageRow {
  readonly item: JsonValue;
  // Match the existing PageRow static contract without narrowing to_char's
  // possible runtime NULL or changing the existing page/cursor behavior.
  readonly cursor_at: string;
  readonly cursor_id: string;
}
const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const transcripts = [
  ["transcript_id", "id"],
  ["meeting_id", "meeting_id"],
  ["state", "state"],
  ["row_version", "row_version"],
  ["current_version_id", "current_version_id"],
  ["version", "version"],
  ["media_type", "media_type"],
  ["verification_state", "verification_state"],
  ["sha256", "sha256"]
] as const;
const meetings = [
  ["meeting_id", "id"],
  ["board_id", "board_id"],
  ["title", "title"],
  ["state", "state"],
  ["scheduled_start_at", "scheduled_start_at"],
  ["scheduled_end_at", "scheduled_end_at"],
  ["current_version_id", "current_version_id"],
  ["current_agenda_version_id", "current_agenda_version_id"],
  ["current_minutes_id", "current_minutes_id"],
  ["row_version", "row_version"],
  ["my_rsvp", "my_rsvp"],
  ["created_at", "cursor_at"]
] as const;
const selectedTranscripts = `select transcript.id,transcript.meeting_id,transcript.state,transcript.row_version::text as row_version,
  version_row.id as current_version_id,version_row.version,version_row.media_type,version_row.verification_state,
  encode(version_row.canonical_sha256,'hex') as sha256,
  transcript.created_at as sort_created_at,transcript.created_at::text as raw_created_at,
  ${utc("transcript.created_at")} as cursor_at,transcript.id::text as cursor_id
  from meeting_transcripts as transcript
  join meeting_transcript_versions as version_row on version_row.id=transcript.current_version_id
  where transcript.meeting_id=$1
    and ($2::timestamptz is null or (transcript.created_at,transcript.id)<($2::timestamptz,$3::uuid))
  order by transcript.created_at desc,transcript.id desc limit $4`;
const selectedMeetings = `select meeting.id,meeting.board_id,meeting.title,meeting.state,
  ${utc("meeting.scheduled_start")} as scheduled_start_at,${utc("meeting.scheduled_end")} as scheduled_end_at,
  meeting.current_version_id,meeting.current_agenda_version_id,meeting.current_minutes_id,meeting.row_version::text as row_version,
  (select rsvp.response from meeting_rsvps as rsvp
    where rsvp.meeting_id=meeting.id and rsvp.member_id=$2 and rsvp.is_current limit 1) as my_rsvp,
  meeting.created_at as sort_created_at,meeting.created_at::text as raw_created_at,
  ${utc("meeting.created_at")} as cursor_at,meeting.id::text as cursor_id
  from meetings as meeting where meeting.board_id=$1
    and ($3::timestamptz is null or (meeting.created_at,meeting.id)<($3::timestamptz,$4::uuid))
  order by meeting.created_at desc,meeting.id desc limit $5`;

function statements(kind: MeetingListKind) {
  const fields = kind === "transcripts" ? transcripts : meetings;
  const flat = fields.map(([, column]) => `chosen.${column}`);
  // Bind actual visible values. The only RSVP identity is its original scalar
  // response/NULL; an unreturned RSVP ID/version is deliberately not selected.
  const privateFlat = flat.map((value) => (value === "chosen.title" ? hash(value) : value));
  const measured = `with frontier as materialized (${kind === "transcripts" ? selectedTranscripts : selectedMeetings}),
    measured as materialized (
      select chosen.*,(${[...flat, "chosen.cursor_at", "chosen.cursor_id"].map(utf8).join("+")})::text as scalar_utf8,
        ${hash(`jsonb_build_array(${privateFlat.join(",")},chosen.raw_created_at)`)} as observation_sha256
      from frontier as chosen
    )`;
  const constructor = `jsonb_build_object(${fields.map(([key, column]) => `'${key}',chosen.${column}`).join(",\n")})`;
  return {
    preflight: `${measured} select id::text,cursor_at,raw_created_at,observation_sha256,scalar_utf8
      from measured order by sort_created_at desc,id desc`,
    content: `${measured}, expected as materialized (
      select * from jsonb_to_recordset($${kind === "transcripts" ? 5 : 6}::jsonb)
        as bound(id uuid,cursor_at text,raw_created_at text,observation_sha256 text,scalar_utf8 numeric)
    ), matched as materialized (
      select fresh.*,(bound.id is not null and fresh.cursor_at is not distinct from bound.cursor_at
        and fresh.scalar_utf8::numeric<=bound.scalar_utf8) as fits
      from measured as fresh left join expected as bound on bound.id=fresh.id
        and fresh.sort_created_at=bound.raw_created_at::timestamptz
        and fresh.observation_sha256=bound.observation_sha256
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
export const MEETING_LIST_PREFLIGHT_SQL = {
  transcripts: statements("transcripts").preflight,
  meetings: statements("meetings").preflight
};
export const MEETING_LIST_CONTENT_SQL = {
  transcripts: statements("transcripts").content,
  meetings: statements("meetings").content
};
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("meeting list scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("meeting list scalar is invalid");
  return BigInt(value);
}
export function meetingListProjectionCost(
  kind: MeetingListKind,
  input: MeetingListScalars
): ListProjectionScalars {
  if (kind !== "transcripts" && kind !== "meetings")
    throw new TypeError("unknown meeting list projection");
  const r = scalar(input.row_count),
    s = scalar(input.scalar_utf8);
  if (r > 501n) throw new TypeError("meeting list count is invalid");
  return {
    jsonUpperBytes: (2n + (kind === "transcripts" ? 260n : 343n) * r + 6n * s).toString(),
    propertyCount: (25n + (kind === "transcripts" ? 13n : 16n) * r).toString(),
    objectOrArrayCount: (7n + 2n * r).toString()
  };
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function observation(input: MeetingListInput, rows: readonly MeetingListMetadata[]) {
  if (
    (input.kind !== "transcripts" && input.kind !== "meetings") ||
    !uuid.test(input.selectorId) ||
    (input.kind === "meetings"
      ? typeof input.memberId !== "string" || !uuid.test(input.memberId)
      : input.memberId !== null) ||
    !Number.isInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > 500 ||
    rows.length > input.limit + 1
  )
    throw new TypeError("meeting list selector is invalid");
  const ids = new Set<string>();
  let total = 0n;
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
      throw new TypeError("meeting list metadata identity is invalid");
    ids.add(row.id);
    total += scalar(row.scalar_utf8);
    return Object.freeze({
      id: row.id,
      cursor_at: row.cursor_at,
      raw_created_at: row.raw_created_at,
      observation_sha256: row.observation_sha256,
      scalar_utf8: row.scalar_utf8
    });
  });
  return {
    tuples: Object.freeze(tuples),
    scalars: { row_count: String(rows.length), scalar_utf8: total.toString() }
  };
}
function plan(
  input: MeetingListInput,
  observed: ReturnType<typeof observation>
): ResponseAllocationPlan {
  return responseAllocationPlan({
    kind: "meeting_list_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: input.selectorId,
    sourceVersion: `${input.kind}:${input.limit}`,
    sha256: createHash("sha256")
      .update(JSON.stringify([input, observed.tuples]))
      .digest("hex"),
    listProjection: meetingListProjectionCost(input.kind, observed.scalars)
  });
}
export function meetingListProjectionPlan(
  input: MeetingListInput,
  rows: readonly MeetingListMetadata[]
): ResponseAllocationPlan {
  return plan(input, observation(input, rows));
}
export async function loadAdmittedMeetingList(
  client: PoolClient,
  input: MeetingListInput
): Promise<readonly MeetingListPageRow[]> {
  observation(input, []);
  const parameters =
    input.kind === "transcripts"
      ? [input.selectorId, input.cursorAt, input.cursorId, input.limit + 1]
      : [input.selectorId, input.memberId, input.cursorAt, input.cursorId, input.limit + 1];
  const inspected = await client.query<MeetingListMetadata>(
    MEETING_LIST_PREFLIGHT_SQL[input.kind],
    parameters
  );
  const observed = observation(input, inspected.rows);
  const loaded = await loadWithResponseAllocation(plan(input, observed), () =>
    client.query<{
      fits: boolean;
      item: JsonValue;
      cursor_at: string | null;
      cursor_id: string | null;
    }>(MEETING_LIST_CONTENT_SQL[input.kind], [...parameters, JSON.stringify(observed.tuples)])
  );
  if (loaded.rows.length === 1 && loaded.rows[0]?.fits === false)
    throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > observed.tuples.length)
    throw new TypeError("meeting list returned extra rows");
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
      throw new TypeError("meeting list returned tuple mismatch");
    const item = row.item as Readonly<Record<string, JsonValue>>;
    if (
      item[input.kind === "transcripts" ? "transcript_id" : "meeting_id"] !== expected.id ||
      item[input.kind === "transcripts" ? "meeting_id" : "board_id"] !== input.selectorId
    )
      throw new TypeError("meeting list returned item identity mismatch");
    previous = index;
  }
  return loaded.rows as readonly MeetingListPageRow[];
}
