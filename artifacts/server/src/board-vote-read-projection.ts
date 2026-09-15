import type { PoolClient } from "pg";
import { sha256Hex, type JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
type Fields = ReadonlyArray<readonly [string, string]>;
const pairs = (fields: Fields) => fields.map(([key, value]) => `'${key}',${value}`).join(",");
const values = (fields: Fields) => fields.map(([, value]) => value).join(",");
const sum = (fields: Fields) => fields.map(([, value]) => utf8(value)).join("+");
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("board/vote scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("board/vote scalar is invalid");
  return BigInt(value);
}
function digest(value: string): void {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value))
    throw new TypeError("board/vote observation is invalid");
}
function id(value: string): void {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)
  )
    throw new TypeError("board/vote identity is invalid");
}
function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("board/vote payload is invalid");
  return value as Readonly<Record<string, JsonValue>>;
}
function plan(
  sourceId: string,
  observation: string,
  cost: ListProjectionScalars
): ResponseAllocationPlan {
  digest(observation);
  return responseAllocationPlan({
    kind: "board_vote_read_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId,
    sourceVersion: "1",
    sha256: observation,
    listProjection: cost
  });
}

export type BoardVotePageKind = "boards" | "votes";
export interface BoardVotePageInput {
  readonly kind: BoardVotePageKind;
  readonly selectorId: string;
  readonly at: string | null;
  readonly cursorId: string | null;
  readonly take: number;
}
export interface BoardVotePageMetadata {
  readonly id: string;
  readonly join_id: string | null;
  readonly outcome_id: string | null;
  readonly raw_at: string;
  readonly cursor_at: string | null;
  readonly cursor_id: string;
  readonly scalar_utf8: string;
  readonly observation_sha256: string;
}
// Match the existing PageRow static interface. SQL/runtime can still return null
// cursor_at; validation below preserves that value and the unchanged page encoder.
export interface BoardVotePageRow {
  readonly item: JsonValue;
  readonly cursor_at: string;
  readonly cursor_id: string;
}
interface LoadedPageRow {
  readonly item: JsonValue;
  readonly cursor_at: string | null;
  readonly cursor_id: string;
  readonly fits: boolean;
}
const boardFields: Fields = [
  ["board_id", "source.row_id"],
  ["slug", "source.slug"],
  ["name", "source.name"],
  ["timezone", "source.timezone"],
  ["state", "source.state"],
  ["row_version", "source.row_version"],
  ["seat_role", "source.seat_role"],
  ["is_chair", "source.is_chair"],
  ["is_secretary", "source.is_secretary"],
  ["voting_weight", "source.voting_weight"],
  ["entitlement_generation", "source.entitlement_generation"]
];
const voteFields: Fields = [
  ["vote_id", "source.row_id"],
  ["board_id", "source.board_id"],
  ["title", "source.title"],
  ["state", "source.state"],
  ["resolution_version_id", "source.resolution_version_id"],
  ["decision_package_id", "source.decision_package_id"],
  ["package_sha256", "source.package_sha256"],
  ["close_mode", "source.close_mode"],
  ["deadline_at", "source.deadline_at"],
  ["row_version", "source.row_version"],
  ["opened_at", "source.opened_at"],
  ["closed_outcome", "source.closed_outcome"]
];
const pageSources: Record<BoardVotePageKind, string> = {
  boards: `select board.id as row_id,membership.id as join_id,null::uuid as outcome_id,
  board.slug,board.name,board.timezone,board.state,board.row_version::text,
  membership.seat_role,membership.is_chair,membership.is_secretary,membership.voting_weight::text,membership.entitlement_generation::text,
  board.created_at as raw_created_at,${date("board.created_at")} as cursor_at,board.id::text as cursor_id
  from boards as board join board_memberships as membership on membership.board_id=board.id and membership.member_id=$1
  where membership.state='active' and membership.active_from<=transaction_timestamp()
    and (membership.active_until is null or membership.active_until>transaction_timestamp())
    and ($2::timestamptz is null or (board.created_at,board.id)<($2::timestamptz,$3::uuid))
  order by board.created_at desc,board.id desc limit $4`,
  votes: `select vote.id as row_id,package.id as join_id,outcome.id as outcome_id,
  vote.board_id,vote.title,vote.state,vote.current_resolution_version_id as resolution_version_id,
  vote.current_decision_package_id as decision_package_id,encode(package.package_sha256,'hex') as package_sha256,
  vote.close_mode,${date("vote.deadline_at")} as deadline_at,vote.row_version::text,
  case when vote.opened_at is null then null else ${date("vote.opened_at")} end as opened_at,
  case when outcome.id is null then null else outcome.outcome end as closed_outcome,
  vote.created_at as raw_created_at,${date("vote.created_at")} as cursor_at,vote.id::text as cursor_id
  from votes as vote left join decision_packages as package on package.id=vote.current_decision_package_id
  left join vote_outcomes as outcome on outcome.vote_id=vote.id
  where vote.board_id=$1 and not boardagent_member_vote_recused(vote.id,boardagent_context_uuid('boardagent.member_id'))
    and ($2::timestamptz is null or (vote.created_at,vote.id)<($2::timestamptz,$3::uuid))
  order by vote.created_at desc,vote.id desc limit $4`
};
function pageMeasured(kind: BoardVotePageKind) {
  const fields = kind === "boards" ? boardFields : voteFields;
  return `with selected as materialized (${pageSources[kind]}), measured as materialized (
    select source.row_id as id,source.join_id,source.outcome_id,source.raw_created_at::text as raw_at,source.cursor_at,source.cursor_id,
      (${sum(fields)}+${utf8("source.cursor_at")}+${utf8("source.cursor_id")})::text as scalar_utf8,
      ${hash(`jsonb_build_array(${values(fields)},source.cursor_at,source.cursor_id,source.raw_created_at::text,source.join_id,source.outcome_id)`)} as observation_sha256
    from selected as source)`;
}
export const BOARD_VOTE_PAGE_PREFLIGHT_SQL: Record<BoardVotePageKind, string> = {
  boards: `${pageMeasured("boards")} select * from measured order by raw_at::timestamptz desc,id desc`,
  votes: `${pageMeasured("votes")} select * from measured order by raw_at::timestamptz desc,id desc`
};
function pageContent(kind: BoardVotePageKind) {
  const fields = kind === "boards" ? boardFields : voteFields;
  return `${pageMeasured(kind)}, admitted as materialized (
    select * from jsonb_to_recordset($5::jsonb) as bound(id uuid,join_id uuid,outcome_id uuid,raw_at text,cursor_at text,cursor_id text,scalar_utf8 text,observation_sha256 text)
  ), gate as materialized (
    select count(*)<=jsonb_array_length($5::jsonb) and coalesce(bool_and(exists(select 1 from admitted as bound
      where bound.id=fresh.id and bound.join_id is not distinct from fresh.join_id and bound.outcome_id is not distinct from fresh.outcome_id
      and bound.raw_at::timestamptz=fresh.raw_at::timestamptz and bound.cursor_at is not distinct from fresh.cursor_at
      and bound.cursor_id=fresh.cursor_id and bound.observation_sha256=fresh.observation_sha256
      and fresh.scalar_utf8::numeric<=bound.scalar_utf8::numeric)),true) as fits from measured as fresh
  ), constructed as materialized (
    select gate.fits,case when gate.fits then (
      select coalesce(jsonb_agg(jsonb_build_object('fits',true,'item',jsonb_build_object(${pairs(fields)}),
        'cursor_at',source.cursor_at,'cursor_id',source.cursor_id) order by source.raw_created_at desc,source.row_id desc),'[]'::jsonb)
      from selected as source
    ) else null end as payload from gate
  ), ordered as (
    select false as fits,null::jsonb as item,null::text as cursor_at,null::text as cursor_id,0::bigint as position from constructed where not fits
    union all
    select true,entry.value->'item',entry.value->>'cursor_at',entry.value->>'cursor_id',entry.ordinality
      from constructed cross join lateral jsonb_array_elements(constructed.payload) with ordinality as entry(value,ordinality)
      where constructed.fits
  ) select fits,item,cursor_at,cursor_id from ordered order by position`;
}
export const BOARD_VOTE_PAGE_CONTENT_SQL: Record<BoardVotePageKind, string> = {
  boards: pageContent("boards"),
  votes: pageContent("votes")
};
export function boardVotePageCost(
  kind: BoardVotePageKind,
  metadata: readonly BoardVotePageMetadata[]
): ListProjectionScalars {
  if (kind !== "boards" && kind !== "votes") throw new TypeError("board/vote page kind is invalid");
  if (metadata.length > 501) throw new ResponseAllocationUnavailable();
  const r = BigInt(metadata.length),
    s = metadata.reduce((total, row) => total + scalar(row.scalar_utf8), 0n);
  return {
    jsonUpperBytes: (2n + (kind === "boards" ? 286n : 326n) * r + 6n * s).toString(),
    propertyCount: (25n + (kind === "boards" ? 15n : 16n) * r).toString(),
    objectOrArrayCount: (7n + 2n * r).toString()
  };
}
function pageMetadata(
  input: BoardVotePageInput,
  rows: readonly BoardVotePageMetadata[]
): readonly BoardVotePageMetadata[] {
  if (rows.length > input.take) throw new TypeError("board/vote page cardinality is invalid");
  const seen = new Set<string>();
  return rows.map((row) => {
    id(row.id);
    if (row.join_id !== null) id(row.join_id);
    if (row.outcome_id !== null) id(row.outcome_id);
    digest(row.observation_sha256);
    scalar(row.scalar_utf8);
    if (
      typeof row.raw_at !== "string" ||
      (row.cursor_at !== null && typeof row.cursor_at !== "string") ||
      row.cursor_id !== row.id ||
      (input.kind === "boards" && (row.join_id === null || row.outcome_id !== null))
    )
      throw new TypeError("board/vote page identity is invalid");
    const key = JSON.stringify([row.id, row.join_id, row.outcome_id]);
    if (seen.has(key)) throw new TypeError("duplicate board/vote joined row");
    seen.add(key);
    return Object.freeze({
      id: row.id,
      join_id: row.join_id,
      outcome_id: row.outcome_id,
      raw_at: row.raw_at,
      cursor_at: row.cursor_at,
      cursor_id: row.cursor_id,
      scalar_utf8: row.scalar_utf8,
      observation_sha256: row.observation_sha256
    });
  });
}
export function boardVotePagePlan(
  input: BoardVotePageInput,
  metadata: readonly BoardVotePageMetadata[]
): ResponseAllocationPlan {
  id(input.selectorId);
  if (input.cursorId !== null) id(input.cursorId);
  if (
    (input.kind !== "boards" && input.kind !== "votes") ||
    !Number.isInteger(input.take) ||
    input.take < 1 ||
    input.take > 501 ||
    (input.at !== null && typeof input.at !== "string")
  )
    throw new TypeError("board/vote page selector is invalid");
  return plan(
    sha256Hex(JSON.stringify(input)),
    sha256Hex(JSON.stringify(metadata)),
    boardVotePageCost(input.kind, metadata)
  );
}
export async function loadAdmittedBoardVotePage(
  client: PoolClient,
  input: BoardVotePageInput
): Promise<readonly BoardVotePageRow[]> {
  // Validate the bounded selector before using its SQL map; no public field is changed.
  boardVotePagePlan(input, []);
  const parameters = [input.selectorId, input.at, input.cursorId, input.take];
  const selected = await client.query<BoardVotePageMetadata>(
    BOARD_VOTE_PAGE_PREFLIGHT_SQL[input.kind],
    parameters
  );
  const metadata = pageMetadata(input, selected.rows),
    allocation = boardVotePagePlan(input, metadata);
  const loaded = await loadWithResponseAllocation(allocation, () =>
    client.query<LoadedPageRow>(BOARD_VOTE_PAGE_CONTENT_SQL[input.kind], [
      ...parameters,
      JSON.stringify(metadata)
    ])
  );
  if (loaded.rows.some((row) => row.fits === false)) throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > metadata.length)
    throw new TypeError("board/vote content cardinality is invalid");
  for (const row of loaded.rows) {
    const item = record(row.item);
    if (
      row.fits !== true ||
      typeof row.cursor_id !== "string" ||
      (row.cursor_at !== null && typeof row.cursor_at !== "string") ||
      item[input.kind === "boards" ? "board_id" : "vote_id"] !== row.cursor_id ||
      !metadata.some((bound) => bound.id === row.cursor_id && bound.cursor_at === row.cursor_at)
    )
      throw new TypeError("board/vote content identity is invalid");
  }
  return loaded.rows as readonly BoardVotePageRow[];
}

export interface ProxyStatusMetadata {
  readonly vote_id: string;
  readonly member_id: string;
  readonly principal_id: string;
  readonly grant_count: string;
  readonly revocation_count: string;
  readonly scalar_utf8: string;
  readonly observation_sha256: string;
}
const grantFields: Fields = [
  ["grant_id", "source.grant_id"],
  ["vote_id", "source.vote_id"],
  ["principal_member_id", "source.principal_member_id"],
  ["holder_member_id", "source.holder_member_id"],
  ["policy", "source.policy"],
  ["active", "source.active"],
  ["granted_at", "source.granted_at_text"],
  ["expires_at", "source.expires_at_text"]
];
const revocationFields: Fields = [
  ["revocation_id", "source.revocation_id"],
  ["reason", "source.reason"],
  ["effect", "source.effect"],
  ["revoked_at", "source.revoked_at_text"]
];
const proxyMeasured = `with selected as materialized (
  select grant_row.id as grant_id,grant_row.vote_id,grant_row.principal_member_id,grant_row.holder_member_id,grant_row.policy,
    revocation.id is null and (grant_row.expires_at is null or grant_row.expires_at>transaction_timestamp()) as active,
    grant_row.granted_at,${date("grant_row.granted_at")} as granted_at_text,${date("grant_row.expires_at")} as expires_at_text,
    revocation.id as revocation_id,revocation.reason,revocation.effect,${date("revocation.revoked_at")} as revoked_at_text
  from proxy_grants as grant_row left join proxy_revocations as revocation on revocation.grant_id=grant_row.id
  where grant_row.vote_id=$1 and not boardagent_member_vote_recused(grant_row.vote_id,$3)
    and (grant_row.principal_member_id=$2 or grant_row.holder_member_id=$2)
    and ($2=$3 or grant_row.principal_member_id=$3 or grant_row.holder_member_id=$3 or exists(
      select 1 from board_memberships as membership where membership.board_id=grant_row.board_id and membership.member_id=$3
        and membership.state='active' and membership.is_secretary and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())))
), measured as materialized (
  select $1::uuid as vote_id,$2::uuid as member_id,$3::uuid as principal_id,count(*)::text as grant_count,
    count(source.revocation_id)::text as revocation_count,
    (${utf8("$1::uuid")}+${utf8("$2::uuid")}+coalesce(sum(${sum(grantFields)}+case when source.revocation_id is null then 0 else ${sum(revocationFields)} end),0))::text as scalar_utf8,
    ${hash(`coalesce(string_agg(${hash(`jsonb_build_array(${values(grantFields)},${values(revocationFields)},source.granted_at::text)`)},'' order by source.granted_at,source.grant_id),'')`)} as observation_sha256
  from selected as source
)`;
export const PROXY_STATUS_PREFLIGHT_SQL = `${proxyMeasured} select * from measured`;
export const PROXY_STATUS_CONTENT_SQL = `${proxyMeasured}, gate as materialized (
  select measured.*,((grant_count='0' and revocation_count='0' and scalar_utf8='72' and observation_sha256=${hash("''::text")}) or
    (grant_count=$4::text and revocation_count=$5::text and scalar_utf8::numeric<=$6::numeric and observation_sha256=$7::text)) as fits from measured
) select gate.*,case when gate.fits then (
  select coalesce(jsonb_agg(jsonb_build_object(${pairs(grantFields)},'revocation',case when source.revocation_id is null then null else
    jsonb_build_object(${pairs(revocationFields)}) end) order by source.granted_at,source.grant_id),'[]'::jsonb) from selected as source
) else null end as items from gate`;
export function proxyStatusCost(metadata: ProxyStatusMetadata): ListProjectionScalars {
  const r = scalar(metadata.grant_count),
    v = scalar(metadata.revocation_count),
    s = scalar(metadata.scalar_utf8);
  if (v > r || s < 72n || (r === 0n && (v !== 0n || s !== 72n)))
    throw new TypeError("proxy scalar relationship is invalid");
  return {
    jsonUpperBytes: (54n + 186n * r + 77n * v + 6n * s).toString(),
    propertyCount: (26n + 9n * r + 4n * v).toString(),
    objectOrArrayCount: (8n + r + v).toString()
  };
}
export function proxyStatusPlan(metadata: ProxyStatusMetadata): ResponseAllocationPlan {
  id(metadata.vote_id);
  id(metadata.member_id);
  id(metadata.principal_id);
  return plan(
    `${metadata.vote_id}:${metadata.member_id}:${metadata.principal_id}`,
    metadata.observation_sha256,
    proxyStatusCost(metadata)
  );
}
export async function loadAdmittedProxyStatus(
  client: PoolClient,
  voteId: string,
  memberId: string,
  principalId: string
): Promise<JsonValue[]> {
  const selected = await client.query<ProxyStatusMetadata>(PROXY_STATUS_PREFLIGHT_SQL, [
    voteId,
    memberId,
    principalId
  ]);
  if (selected.rows.length !== 1) throw new TypeError("proxy preflight cardinality is invalid");
  const m = Object.freeze({ ...selected.rows[0]! });
  if (m.vote_id !== voteId || m.member_id !== memberId || m.principal_id !== principalId)
    throw new TypeError("proxy preflight identity is invalid");
  const loaded = await loadWithResponseAllocation(proxyStatusPlan(m), () =>
    client.query<ProxyStatusMetadata & { fits: boolean; items: JsonValue }>(
      PROXY_STATUS_CONTENT_SQL,
      [
        voteId,
        memberId,
        principalId,
        m.grant_count,
        m.revocation_count,
        m.scalar_utf8,
        m.observation_sha256
      ]
    )
  );
  if (loaded.rows.length !== 1) throw new TypeError("proxy content cardinality is invalid");
  const row = loaded.rows[0]!;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  proxyStatusCost(row);
  digest(row.observation_sha256);
  const empty =
    row.grant_count === "0" &&
    row.revocation_count === "0" &&
    row.scalar_utf8 === "72" &&
    row.observation_sha256 === sha256Hex("");
  if (
    row.fits !== true ||
    row.vote_id !== voteId ||
    row.member_id !== memberId ||
    row.principal_id !== principalId ||
    (!empty &&
      (row.grant_count !== m.grant_count ||
        row.revocation_count !== m.revocation_count ||
        scalar(row.scalar_utf8) > scalar(m.scalar_utf8) ||
        row.observation_sha256 !== m.observation_sha256)) ||
    !Array.isArray(row.items) ||
    BigInt(row.items.length) !== scalar(row.grant_count)
  )
    throw new TypeError("proxy content identity is invalid");
  const grants = new Set<string>();
  for (const value of row.items) {
    const item = record(value);
    if (
      typeof item["grant_id"] !== "string" ||
      grants.has(item["grant_id"]) ||
      item["vote_id"] !== voteId ||
      (item["principal_member_id"] !== memberId && item["holder_member_id"] !== memberId)
    )
      throw new TypeError("proxy grant identity is invalid");
    grants.add(item["grant_id"]);
    if (item["revocation"] !== null) {
      const revocation = record(item["revocation"]!);
      if (typeof revocation["revocation_id"] !== "string")
        throw new TypeError("proxy revocation identity is invalid");
    }
  }
  return row.items;
}

export interface VoteLineageMetadata {
  readonly supersession_id: string;
  readonly old_vote_id: string;
  readonly new_vote_id: string;
  readonly raw_at: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_containers: string;
  readonly observation_sha256: string;
}
const lineageFields: Fields = [
  ["supersession_id", "source.supersession_id"],
  ["old_vote_id", "source.old_vote_id"],
  ["new_vote_id", "source.new_vote_id"],
  ["old_package_sha256", "source.old_package_sha256"],
  ["new_package_sha256", "source.new_package_sha256"],
  ["secretary_member_id", "source.secretary_member_id"],
  ["reason", "source.reason"],
  ["created_at", "source.created_at_text"]
];
const lineageMeasured = `with recursive selected as materialized (
  select supersession.id as supersession_id,supersession.old_vote_id,supersession.new_vote_id,
    to_jsonb(supersession.changed_component_classes) as changed_component_classes,
    encode(supersession.old_package_sha256,'hex') as old_package_sha256,encode(supersession.new_package_sha256,'hex') as new_package_sha256,
    supersession.secretary_member_id,supersession.reason,supersession.created_at,${date("supersession.created_at")} as created_at_text
  from vote_supersessions as supersession where (supersession.old_vote_id=$1 or supersession.new_vote_id=$1)
    and not boardagent_member_vote_recused(supersession.old_vote_id,boardagent_context_uuid('boardagent.member_id'))
    and not boardagent_member_vote_recused(supersession.new_vote_id,boardagent_context_uuid('boardagent.member_id'))
), nodes(supersession_id,value) as (
  select supersession_id,changed_component_classes from selected union all
  select node.supersession_id,entry.value from nodes as node cross join lateral
    jsonb_array_elements(case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry(value)
), measured as materialized (
  select source.supersession_id,source.old_vote_id,source.new_vote_id,source.created_at::text as raw_at,
    (${sum(lineageFields)})::text as scalar_utf8,${utf8("source.changed_component_classes")}::text as json_utf8,
    (select count(*)::text from nodes where nodes.supersession_id=source.supersession_id and jsonb_typeof(nodes.value)='array') as json_containers,
    ${hash(`jsonb_build_array(${values(lineageFields)},${hash("source.changed_component_classes")},source.created_at::text)`)} as observation_sha256
  from selected as source
)`;
// Installed unique old_vote_id/new_vote_id means at most two edges. LIMIT3 is
// only a bounded inconsistency detector; the fresh complete set is never filtered.
export const VOTE_LINEAGE_PREFLIGHT_SQL = `${lineageMeasured} select * from measured order by raw_at::timestamptz,supersession_id limit 3`;
export const VOTE_LINEAGE_CONTENT_SQL = `${lineageMeasured}, admitted as materialized (
  select * from jsonb_to_recordset($2::jsonb) as bound(supersession_id uuid,old_vote_id uuid,new_vote_id uuid,raw_at text,
    scalar_utf8 text,json_utf8 text,json_containers text,observation_sha256 text)
), gate as materialized (
  select count(*)<=jsonb_array_length($2::jsonb) and coalesce(bool_and(exists(select 1 from admitted as bound
    where fresh.supersession_id=bound.supersession_id and fresh.old_vote_id=bound.old_vote_id and fresh.new_vote_id=bound.new_vote_id
      and fresh.raw_at::timestamptz=bound.raw_at::timestamptz and fresh.scalar_utf8::numeric<=bound.scalar_utf8::numeric
      and fresh.json_utf8::numeric<=bound.json_utf8::numeric and fresh.json_containers=bound.json_containers
      and fresh.observation_sha256=bound.observation_sha256)),true) as fits,count(*)::text as row_count from measured as fresh
) select gate.fits,gate.row_count,case when gate.fits then (
  select coalesce(jsonb_agg(jsonb_build_object(${pairs(lineageFields)},'changed_component_classes',source.changed_component_classes)
    order by source.created_at,source.supersession_id),'[]'::jsonb) from selected as source
) else null end as items from gate`;
export function voteLineageCost(metadata: readonly VoteLineageMetadata[]): ListProjectionScalars {
  if (metadata.length > 2) throw new ResponseAllocationUnavailable();
  let s = 36n,
    n = 0n,
    o = 0n;
  for (const row of metadata) {
    s += scalar(row.scalar_utf8);
    n += scalar(row.json_utf8);
    o += scalar(row.json_containers);
    if (scalar(row.json_utf8) < 1n || scalar(row.json_containers) < 1n)
      throw new TypeError("lineage array metric is invalid");
  }
  const r = BigInt(metadata.length);
  return {
    jsonUpperBytes: (36n + 227n * r + 6n * s + n).toString(),
    propertyCount: (25n + 9n * r).toString(),
    objectOrArrayCount: (8n + r + o).toString()
  };
}
export function voteLineagePlan(
  voteId: string,
  metadata: readonly VoteLineageMetadata[]
): ResponseAllocationPlan {
  id(voteId);
  return plan(voteId, sha256Hex(JSON.stringify(metadata)), voteLineageCost(metadata));
}
export async function loadAdmittedVoteLineage(
  client: PoolClient,
  voteId: string
): Promise<JsonValue[]> {
  const selected = await client.query<VoteLineageMetadata>(VOTE_LINEAGE_PREFLIGHT_SQL, [voteId]);
  if (selected.rows.length > 2) throw new ResponseAllocationUnavailable();
  const seen = new Set<string>();
  const metadata = selected.rows.map((row) => {
    id(row.supersession_id);
    id(row.old_vote_id);
    id(row.new_vote_id);
    digest(row.observation_sha256);
    if (
      (row.old_vote_id !== voteId && row.new_vote_id !== voteId) ||
      typeof row.raw_at !== "string" ||
      seen.has(row.supersession_id)
    )
      throw new TypeError("lineage preflight identity is invalid");
    seen.add(row.supersession_id);
    return Object.freeze({
      supersession_id: row.supersession_id,
      old_vote_id: row.old_vote_id,
      new_vote_id: row.new_vote_id,
      raw_at: row.raw_at,
      scalar_utf8: row.scalar_utf8,
      json_utf8: row.json_utf8,
      json_containers: row.json_containers,
      observation_sha256: row.observation_sha256
    });
  });
  const loaded = await loadWithResponseAllocation(voteLineagePlan(voteId, metadata), () =>
    client.query<{ fits: boolean; row_count: string; items: JsonValue }>(VOTE_LINEAGE_CONTENT_SQL, [
      voteId,
      JSON.stringify(metadata)
    ])
  );
  if (loaded.rows.length !== 1) throw new TypeError("lineage content cardinality is invalid");
  const row = loaded.rows[0]!;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    !Array.isArray(row.items) ||
    BigInt(row.items.length) !== scalar(row.row_count) ||
    row.items.length > metadata.length
  )
    throw new TypeError("lineage content shape is invalid");
  const returned = new Set<string>();
  for (const value of row.items) {
    const item = record(value),
      match = metadata.find((bound) => bound.supersession_id === item["supersession_id"]);
    if (
      !match ||
      returned.has(match.supersession_id) ||
      item["old_vote_id"] !== match.old_vote_id ||
      item["new_vote_id"] !== match.new_vote_id ||
      !Array.isArray(item["changed_component_classes"])
    )
      throw new TypeError("lineage payload identity is invalid");
    returned.add(match.supersession_id);
  }
  return row.items;
}
