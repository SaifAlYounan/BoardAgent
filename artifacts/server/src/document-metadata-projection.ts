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

export type DocumentMetadataKind = "hash" | "validation" | "versions" | "documents";
export interface DocumentMetadataInput {
  readonly kind: DocumentMetadataKind;
  readonly selectorId: string;
  readonly versionId: string | null;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface DocumentMetadataObservation {
  readonly id: string;
  readonly cursor_at: string | null;
  readonly raw_created_at: string | null;
  readonly observation_sha256: string;
  readonly scalar_utf8: string;
}
export interface DocumentMetadataScalars {
  readonly row_count: string;
  readonly scalar_utf8: string;
}
export interface DocumentMetadataRow {
  readonly item: JsonValue;
  // Preserve the existing PageRow static contract and its possible runtime NULL.
  // Point callers never expose these private cursor fields.
  readonly cursor_at: string;
  readonly cursor_id: string;
}
const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const common = [
  ["version_id", "version_row.id"],
  ["version", "version_row.version"],
  ["media_type", "version_row.media_type"],
  ["document_schema", "version_row.document_schema"],
  ["byte_length", "version_row.byte_length"],
  ["sha256", "encode(version_row.sha256,'hex')"]
] as const;
const fields = {
  hash: [["document_id", "document.id"], ...common],
  validation: [
    ["validation_attempt_id", "attempt.id"],
    ["board_id", "attempt.board_id"],
    ["offered_media_type", "attempt.offered_media_type"],
    ["offered_name", "attempt.offered_name"],
    ["offered_length", "attempt.offered_length::text"],
    ["offered_sha256", "encode(attempt.offered_sha256,'hex')"],
    ["result", "attempt.result"],
    ["result_code", "attempt.result_code"],
    ["remediation", "attempt.remediation"],
    ["accepted_document_version_id", "attempt.accepted_document_version_id"],
    ["attempted_at", utc("attempt.attempted_at")]
  ],
  versions: [
    ["document_id", "version_row.document_id"],
    ...common,
    ["created_by", "version_row.created_by"],
    ["created_at", utc("version_row.created_at")]
  ],
  documents: [
    ["document_id", "document.id"],
    ["board_id", "document.board_id"],
    ["title", "document.title"],
    ["state", "document.state"],
    ...common,
    ["row_version", "document.row_version::text"],
    [
      "resource_uri",
      "'board://' || document.board_id::text || '/documents/' || document.id::text || '/versions/' || version_row.version::text"
    ],
    ["created_at", utc("document.created_at")]
  ]
} as const;
const list = (kind: DocumentMetadataKind) => kind === "versions" || kind === "documents";
function source(kind: DocumentMetadataKind) {
  if (kind === "validation")
    return {
      from: "document_validation_attempts as attempt",
      where: "attempt.id=$1",
      id: "attempt.id",
      time: null
    };
  const from =
    kind === "versions"
      ? "document_versions as version_row join documents as document on document.id=version_row.document_id"
      : `documents as document join document_versions as version_row on ${kind === "hash" ? "version_row.document_id=document.id" : "version_row.id=document.current_version_id"}`;
  const id = kind === "documents" ? "document.id" : "version_row.id";
  const time =
    kind === "hash"
      ? null
      : kind === "documents"
        ? "document.created_at"
        : "version_row.created_at";
  const where =
    kind === "hash"
      ? "document.id=$1 and version_row.id=$2"
      : `${kind === "documents" ? "document.board_id=$1 and document.state='active'" : "document.id=$1"}
      and ($2::timestamptz is null or (${time},${id})<($2::timestamptz,$3::uuid))`;
  return { from, where, id, time };
}
function statements(kind: DocumentMetadataKind) {
  const selected = source(kind);
  // One RLS-filtered pass per statement: the frontier carries every projected leaf
  // as a typed column (f_<key>) at the statement snapshot, and measurement, drift
  // comparison and construction all read that carried row. Re-joining the source
  // per phase evaluated boardagent_document_permission about five times per row and
  // page, pushing warm_list_documents past its 500 ms target on a small host; within
  // one statement the carried values and a re-read are
  // the same snapshot, so nothing observable changes except the evaluation count.
  const carried = fields[kind].map(([key, value]) => `${value} as f_${key}`).join(",");
  const leaf = (key: string) => `chosen.f_${key}`;
  const flat = fields[kind].map(([key]) => leaf(key));
  const ordered = list(kind),
    time = selected.time ?? "null::timestamptz";
  const cursor = selected.time ? utc(selected.time) : "null::text";
  const measured = `with frontier as materialized (
      select ${selected.id} as id,${time} as sort_created_at,(${time})::text as raw_created_at,
        ${cursor} as cursor_at,${selected.id}::text as cursor_id,${carried}
      from ${selected.from} where ${selected.where}
      ${ordered ? `order by ${time} desc,${selected.id} desc limit $4` : "limit 2"}
    ), measured as materialized (
      select chosen.*,(${[...flat, "chosen.cursor_at", "chosen.cursor_id"].map(utf8).join("+")})::text as scalar_utf8,
        ${hash(`jsonb_build_array(${fields[kind].map(([key]) => (key === "version" || key === "byte_length" ? leaf(key) : hash(leaf(key)))).join(",")},chosen.raw_created_at)`)} as observation_sha256
      from frontier as chosen
    )`;
  const constructor = `jsonb_build_object(${fields[kind].map(([key]) => `'${key}',${leaf(key)}`).join(",\n")})`;
  return {
    preflight: `${measured} select id::text,cursor_at,raw_created_at,observation_sha256,scalar_utf8
      from measured${ordered ? " order by sort_created_at desc,id desc" : ""}`,
    content: `${measured}, expected as materialized (
      select * from jsonb_to_recordset($${ordered ? 5 : kind === "hash" ? 3 : 2}::jsonb)
        as bound(id uuid,cursor_at text,raw_created_at text,observation_sha256 text,scalar_utf8 numeric)
    ), matched as materialized (
      select fresh.*,(bound.id is not null and fresh.cursor_at is not distinct from bound.cursor_at
        and fresh.scalar_utf8::numeric<=bound.scalar_utf8) as fits
      from measured as fresh left join expected as bound on bound.id=fresh.id
        and fresh.sort_created_at is not distinct from bound.raw_created_at::timestamptz
        and fresh.observation_sha256=bound.observation_sha256
    ), global_gate as materialized (select coalesce(bool_and(fits),true) as fits from matched)
    select fits,item,cursor_at,cursor_id from (
      select gate.fits,case when gate.fits then (${constructor}) else null end as item,
        chosen.cursor_at,chosen.cursor_id,chosen.sort_created_at,chosen.id as sort_id
      from matched as chosen cross join global_gate as gate where gate.fits
      union all
      select gate.fits,null::jsonb,null::text,null::text,null::timestamptz,null::uuid
      from global_gate as gate where not gate.fits
    ) as projected${ordered ? " order by sort_created_at desc,sort_id desc" : ""}`
  };
}
export const DOCUMENT_METADATA_PREFLIGHT_SQL = {
  hash: statements("hash").preflight,
  validation: statements("validation").preflight,
  versions: statements("versions").preflight,
  documents: statements("documents").preflight
};
export const DOCUMENT_METADATA_CONTENT_SQL = {
  hash: statements("hash").content,
  validation: statements("validation").content,
  versions: statements("versions").content,
  documents: statements("documents").content
};
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("document metadata scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("document metadata scalar is invalid");
  return BigInt(value);
}
const coefficients = {
  hash: [212n, 11n],
  validation: [337n, 15n],
  versions: [252n, 13n],
  documents: [323n, 17n]
} as const;
export function documentMetadataProjectionCost(
  kind: DocumentMetadataKind,
  input: DocumentMetadataScalars
): ListProjectionScalars {
  if (!Object.hasOwn(coefficients, kind))
    throw new TypeError("unknown document metadata projection");
  const r = scalar(input.row_count),
    s = scalar(input.scalar_utf8),
    [j, p] = coefficients[kind];
  if (r > (list(kind) ? 501n : 1n)) throw new TypeError("document metadata count is invalid");
  return {
    jsonUpperBytes: (2n + j * r + 6n * s).toString(),
    propertyCount: (25n + p * r).toString(),
    objectOrArrayCount: (7n + 2n * r).toString()
  };
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function observation(input: DocumentMetadataInput, rows: readonly DocumentMetadataObservation[]) {
  if (
    !Object.hasOwn(coefficients, input.kind) ||
    !uuid.test(input.selectorId) ||
    (input.kind === "hash"
      ? typeof input.versionId !== "string" || !uuid.test(input.versionId)
      : input.versionId !== null) ||
    !Number.isInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > 500 ||
    (!list(input.kind) &&
      (input.limit !== 1 || input.cursorAt !== null || input.cursorId !== null)) ||
    rows.length > (list(input.kind) ? input.limit + 1 : 1)
  )
    throw new TypeError("document metadata selector is invalid");
  const ids = new Set<string>();
  let total = 0n;
  const tuples = rows.map((row) => {
    if (
      typeof row.id !== "string" ||
      !uuid.test(row.id) ||
      ids.has(row.id) ||
      (row.cursor_at !== null && typeof row.cursor_at !== "string") ||
      (list(input.kind)
        ? typeof row.raw_created_at !== "string" || !row.raw_created_at
        : row.raw_created_at !== null || row.cursor_at !== null) ||
      typeof row.observation_sha256 !== "string" ||
      !/^[0-9a-f]{64}$/u.test(row.observation_sha256)
    )
      throw new TypeError("document metadata identity is invalid");
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
  input: DocumentMetadataInput,
  observed: ReturnType<typeof observation>
): ResponseAllocationPlan {
  return responseAllocationPlan({
    kind: "document_metadata_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: input.selectorId,
    sourceVersion: `${input.kind}:${input.versionId ?? input.limit}`,
    sha256: createHash("sha256")
      .update(JSON.stringify([input, observed.tuples]))
      .digest("hex"),
    listProjection: documentMetadataProjectionCost(input.kind, observed.scalars)
  });
}
export function documentMetadataProjectionPlan(
  input: DocumentMetadataInput,
  rows: readonly DocumentMetadataObservation[]
): ResponseAllocationPlan {
  return plan(input, observation(input, rows));
}
export async function loadAdmittedDocumentMetadata(
  client: PoolClient,
  input: DocumentMetadataInput
): Promise<readonly DocumentMetadataRow[]> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new Error("native response allocation owner is required");
  owner.assertLive();
  observation(input, []);
  const parameters = list(input.kind)
    ? [input.selectorId, input.cursorAt, input.cursorId, input.limit + 1]
    : input.kind === "hash"
      ? [input.selectorId, input.versionId]
      : [input.selectorId];
  const inspected = await client.query<DocumentMetadataObservation>(
    DOCUMENT_METADATA_PREFLIGHT_SQL[input.kind],
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
    }>(DOCUMENT_METADATA_CONTENT_SQL[input.kind], [...parameters, JSON.stringify(observed.tuples)])
  );
  owner.assertLive();
  if (loaded.rows.length === 1 && loaded.rows[0]?.fits === false)
    throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > observed.tuples.length)
    throw new TypeError("document metadata returned extra rows");
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
      throw new TypeError("document metadata returned tuple mismatch");
    const item = row.item as Readonly<Record<string, JsonValue>>;
    const itemId =
      input.kind === "validation"
        ? "validation_attempt_id"
        : input.kind === "documents"
          ? "document_id"
          : "version_id";
    if (
      item[itemId] !== expected.id ||
      (input.kind === "validation"
        ? expected.id !== input.selectorId
        : input.kind === "hash"
          ? item.document_id !== input.selectorId || expected.id !== input.versionId
          : item[input.kind === "versions" ? "document_id" : "board_id"] !== input.selectorId)
    )
      throw new TypeError("document metadata returned item identity mismatch");
    previous = index;
  }
  return loaded.rows as readonly DocumentMetadataRow[];
}
