import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  currentResponseAllocationOwner,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface SearchProjectionInput {
  readonly boardId: string;
  readonly query: string;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface SearchProjectionMetadata {
  readonly id: string;
  readonly row_version: string;
  readonly version_id: string;
  readonly version: string;
  readonly sha256: string;
  readonly search_version_id: string;
  readonly search_sha256: string;
  readonly cursor_at: string;
  readonly scalar_utf8: string;
  readonly snippet_utf8: string;
  readonly rank_json_bytes: string;
}
export interface SearchPageRow {
  readonly item: JsonValue;
  readonly cursor_at: string;
  readonly cursor_id: string;
}
interface ContentRow {
  readonly fits: boolean;
  readonly item: JsonValue;
  readonly cursor_at: string | null;
  readonly cursor_id: string | null;
}

const utc = (expression: string) =>
  `to_char(${expression} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const bytes = (expression: string) => `coalesce(octet_length(${expression}),0)::numeric`;
const uri = `('board://' || $1::text || '/documents/' || projected.id::text ||
  '/versions/' || projected.version::text)`;
const scalarUtf8 = [
  "projected.id::text",
  "projected.current_version_id::text",
  "projected.title",
  "projected.media_type",
  "projected.document_schema",
  "projected.byte_length::text",
  "encode(projected.sha256,'hex')",
  uri,
  utc("projected.created_at"),
  "projected.id::text"
]
  .map(bytes)
  .join("+");

// PostgreSQL computes selected snippets before the reservation. Only scalar
// lengths/identities cross that first boundary; no headline/RLS/FTS workspace
// or RSS guarantee follows from the later Node response-allocation plan.
// Keep both visibility barriers, then select the original limit+1 frontier
// before rank/headline work. Ranking never determines the current page order.
const measured = `matched as materialized (
  select document_id from document_search
   where board_id=$1 and search_vector @@ plainto_tsquery('simple',$2)
), entitled as materialized (
  select document.id,document.current_version_id,version_row.created_at
    from documents as document
    join document_versions as version_row on version_row.id=document.current_version_id
    join matched as search on search.document_id=document.id
   where document.board_id=$1 and document.state='active'
), selected as materialized (
  select * from entitled
   where ($3::timestamptz is null or (created_at,id)<($3::timestamptz,$4::uuid))
   order by created_at desc,id desc limit $5
), projected as materialized (
  select document.id,document.row_version,document.title,document.current_version_id,
    version_row.version,version_row.media_type,version_row.document_schema,
    version_row.byte_length,version_row.sha256,version_row.created_at,
    search.current_version_id as search_version_id,
    search.canonical_text_sha256 as search_sha256,
    ts_rank_cd(search.search_vector,plainto_tsquery('simple',$2)) as rank,
    ts_headline('simple',search.search_text,plainto_tsquery('simple',$2),
      'MaxFragments=2,MaxWords=30,MinWords=10,StartSel="",StopSel=""') as snippet
  from selected
  join documents as document on document.id=selected.id
  join document_versions as version_row on version_row.id=selected.current_version_id
  join document_search as search on search.document_id=selected.id
), metadata as materialized (
  select projected.id,projected.row_version,
    projected.current_version_id as version_id,projected.version,
    encode(projected.sha256,'hex') as sha256,projected.search_version_id,
    encode(projected.search_sha256,'hex') as search_sha256,projected.created_at,
    (${scalarUtf8}) as scalar_utf8,
    octet_length(projected.snippet)::numeric as snippet_utf8,
    octet_length(to_jsonb(projected.rank)::text)::numeric as rank_json_bytes
  from projected
)`;

export const SEARCH_PREFLIGHT_SQL = `with ${measured}
  select id::text,row_version::text,version_id::text,version::text,sha256,
    search_version_id::text,search_sha256,${utc("created_at")} as cursor_at,
    scalar_utf8::text,snippet_utf8::text,rank_json_bytes::text
  from metadata order by created_at desc,id desc`;

// One global gate precedes EVERY full item construction. The same fresh
// MATERIALIZED projected rows feed both scalar measurement and the conditional
// subquery, so equal identities cannot hide growing snippets/metadata lengths.
export const SEARCH_CONTENT_SQL = `with ${measured}, expected as materialized (
  select * from jsonb_to_recordset($6::jsonb) as bound(
    id uuid,row_version bigint,version_id uuid,version integer,sha256 text,
    search_version_id uuid,search_sha256 text,cursor_at text,
    scalar_utf8 numeric,snippet_utf8 numeric,rank_json_bytes numeric)
), checked as materialized (
  select current.*,(bound.id is not null
    and current.scalar_utf8<=bound.scalar_utf8
    and current.snippet_utf8<=bound.snippet_utf8
    and current.rank_json_bytes<=bound.rank_json_bytes) as fits
  from metadata as current left join expected as bound
    on bound.id=current.id and bound.row_version=current.row_version
    and bound.version_id=current.version_id and bound.version=current.version
    and bound.sha256=current.sha256
    and bound.search_version_id=current.search_version_id
    and bound.search_sha256=current.search_sha256
    and bound.cursor_at=${utc("current.created_at")}
), global_gate as materialized (
  select coalesce(bool_and(fits),true) as fits from checked
)
select global_gate.fits,checked.id::text as cursor_id,
  ${utc("checked.created_at")} as cursor_at,
  case when global_gate.fits and checked.id is not null then (
    select jsonb_build_object(
      'document_id',projected.id,'version_id',projected.current_version_id,'title',projected.title,
      'media_type',projected.media_type,'document_schema',projected.document_schema,
      'byte_length',projected.byte_length,'sha256',encode(projected.sha256,'hex'),
      'rank',projected.rank,'snippet',projected.snippet,'resource_uri',${uri}
    ) from projected where projected.id=checked.id
  ) else null end as item
from global_gate left join checked on true
order by checked.created_at desc,checked.id desc`;

function integer(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("invalid search projection scalar");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("invalid search projection scalar");
  return BigInt(value);
}

export function searchProjectionPlan(
  input: SearchProjectionInput,
  frontier: readonly SearchProjectionMetadata[]
): ResponseAllocationPlan {
  if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 500)
    throw new TypeError("invalid search page limit");
  if (
    frontier.length > input.limit + 1 ||
    new Set(frontier.map((row) => row.id)).size !== frontier.length
  )
    throw new TypeError("invalid search frontier");
  let json = 2n;
  for (const row of frontier) {
    for (const identity of [row.id, row.version_id, row.search_version_id])
      if (
        typeof identity !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(identity)
      )
        throw new TypeError("invalid search identity");
    for (const digest of [row.sha256, row.search_sha256])
      if (typeof digest !== "string" || !/^[a-f0-9]{64}$/u.test(digest))
        throw new TypeError("invalid search digest");
    if (
      integer(row.row_version) < 1n ||
      integer(row.row_version) > 9_223_372_036_854_775_807n ||
      integer(row.version) < 1n ||
      integer(row.version) > 2_147_483_647n ||
      typeof row.cursor_at !== "string" ||
      row.cursor_at.length < 1 ||
      row.cursor_at.length > 64
    )
      throw new TypeError("invalid search version or cursor");
    // 193 item bytes (10 keys, sum lengths 91) + 54 pg row wrapper
    // bytes (3 keys, sum 22) + 2 array separator bytes. The rank's
    // actual scalar JSON includes any PostgreSQL numeric exponent expansion.
    json +=
      249n +
      6n * (integer(row.scalar_utf8) + integer(row.snippet_utf8)) +
      integer(row.rank_json_bytes);
  }
  const count = BigInt(frontier.length);
  const digest = createHash("sha256").update(JSON.stringify({ input, frontier })).digest("hex");
  return responseAllocationPlan({
    kind: "search_projection",
    representation: "tool",
    sourceId: digest,
    sourceVersion: "1",
    sha256: digest,
    canonicalBytes: 0,
    listProjection: {
      jsonUpperBytes: json.toString(),
      propertyCount: (8n + 13n * count).toString(),
      objectOrArrayCount: (5n + 2n * count).toString()
    }
  });
}

// executeRead's liveActor/authorizeRead and unchanged page/result remain in the
// caller. All database statements keep the original request transaction/RLS role.
export async function loadAdmittedSearchProjection(
  client: PoolClient,
  input: SearchProjectionInput
): Promise<readonly SearchPageRow[]> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new Error("native response allocation owner is required");
  owner.assertLive();
  if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 500)
    throw new TypeError("invalid search page limit");
  const parameters = [input.boardId, input.query, input.cursorAt, input.cursorId, input.limit + 1];
  const selected = await client.query<SearchProjectionMetadata>(SEARCH_PREFLIGHT_SQL, parameters);
  owner.assertLive();
  owner.reserve(searchProjectionPlan(input, selected.rows));
  const expected = new Map(selected.rows.map((row) => [row.id, row]));
  owner.assertLive();
  const loaded = await client.query<ContentRow>(SEARCH_CONTENT_SQL, [
    ...parameters,
    JSON.stringify(selected.rows)
  ]);
  owner.assertLive();
  if (loaded.rows.some((row) => !row.fits)) throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > input.limit + 1) throw new TypeError("invalid search row count");
  const result: SearchPageRow[] = [];
  const seen = new Set<string>();
  for (const row of loaded.rows) {
    if (row.cursor_id === null) {
      if (loaded.rows.length !== 1 || row.item !== null || row.cursor_at !== null)
        throw new TypeError("invalid empty search row");
      continue;
    }
    const bound = expected.get(row.cursor_id);
    // Keep the runtime object/array guard below; Array.isArray does not narrow
    // the readonly array member of JsonValue for TypeScript property access.
    const item = row.item as Readonly<Record<string, JsonValue>>;
    if (
      !bound ||
      seen.has(row.cursor_id) ||
      row.cursor_at !== bound.cursor_at ||
      typeof row.item !== "object" ||
      row.item === null ||
      Array.isArray(row.item) ||
      item["document_id"] !== bound.id ||
      item["version_id"] !== bound.version_id ||
      item["sha256"] !== bound.sha256 ||
      item["resource_uri"] !==
        `board://${input.boardId}/documents/${bound.id}/versions/${bound.version}`
    )
      throw new TypeError("loaded search identity does not match the admitted frontier");
    seen.add(row.cursor_id);
    result.push({ item: row.item, cursor_at: row.cursor_at, cursor_id: row.cursor_id });
  }
  return result;
}
