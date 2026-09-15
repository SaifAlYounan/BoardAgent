import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface CertificateToolProjectionMetadata {
  readonly id: string;
  readonly board_id: string;
  readonly vote_id: string;
  readonly observation_sha256: string;
  readonly raw_payload_bytes: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface CertificateToolProjectionRow {
  readonly board_id: string;
  readonly view: JsonValue;
}
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const base64url = (value: string) =>
  `translate(encode(${value},'base64'),'+/=' || chr(10) || chr(13),'-_')`;
const fields = [
  ["certificate_id", "certificate.id"],
  ["vote_id", "certificate.vote_id"],
  ["outcome_id", "certificate.outcome_id"],
  ["public_id", "certificate.public_id"],
  ["schema_version", "certificate.schema_version"],
  ["payload_sha256", "certificate.payload_sha256"],
  ["signature_base64url", "certificate.signature_base64url"],
  ["signing_key_id", "certificate.signing_key_id"],
  ["state", "certificate.state"],
  ["supersedes_id", "certificate.supersedes_id"],
  ["issued_at", "certificate.issued_at"]
] as const;
const scalarSum = fields.map(([, value]) => utf8(value)).join("+");
const pairs = fields.map(([key, value]) => `'${key}',${value}`).join(",\n");

// This is the original TOOL selection, including historical explicit IDs and
// its issued_at DESC LIMIT1 behavior. There is deliberately no key-table join.
// Original bytea→UTF8→JSONB conversion remains in PostgreSQL. Its parse, hash,
// detoast, recursive JSON traversal and RLS workspace are not a Node RSS bound.
const measured = `with recursive selected_certificate as materialized (
  select certificate.id,certificate.board_id,certificate.vote_id,certificate.outcome_id,
    ${base64url("certificate.public_id")} as public_id,certificate.schema_version,
    convert_from(certificate.canonical_payload,'UTF8')::jsonb as canonical_payload,
    encode(certificate.payload_sha256,'hex') as payload_sha256,
    ${base64url("certificate.signature")} as signature_base64url,
    certificate.signing_key_id,certificate.state,certificate.supersedes_id,
    to_char(certificate.issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as issued_at,
    octet_length(certificate.canonical_payload)::text as raw_payload_bytes,
    encode(sha256(certificate.canonical_payload),'hex') as actual_payload_sha256
  from vote_certificates as certificate where certificate.vote_id=$1
    and not boardagent_member_vote_recused(certificate.vote_id,boardagent_context_uuid('boardagent.member_id'))
    and (($2::uuid is null and certificate.state='current') or certificate.id=$2)
  order by certificate.issued_at desc limit 1
), json_nodes(value,member) as (
  select canonical_payload,false from selected_certificate
  union all
  select child.value,child.member from json_nodes as node cross join lateral (
    select entry.value,true as member from jsonb_each(
      case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member from jsonb_array_elements(
      case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), measured as materialized (
  select certificate.id,certificate.board_id,certificate.vote_id,certificate.raw_payload_bytes,
    encode(sha256(convert_to(jsonb_build_array(certificate.id,certificate.board_id,certificate.vote_id,
      certificate.outcome_id,certificate.public_id,certificate.schema_version,certificate.payload_sha256,
      certificate.signature_base64url,certificate.signing_key_id,certificate.state,certificate.supersedes_id,
      certificate.issued_at,certificate.raw_payload_bytes,certificate.actual_payload_sha256)::text,'UTF8')),'hex') as observation_sha256,
    (${scalarSum})::text as scalar_utf8,
    (${utf8("certificate.canonical_payload")})::text as json_utf8,
    (select count(*) filter (where member)::text from json_nodes) as json_properties,
    (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text from json_nodes) as json_containers
  from selected_certificate as certificate
)`;
export const CERTIFICATE_TOOL_PREFLIGHT_SQL = `${measured} select * from measured`;
// If a previously current row stops matching that selector, an authorized
// scalar-only presence recheck distinguishes a changed row from disappearance.
export const CERTIFICATE_TOOL_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,id=$3::uuid and board_id=$4::uuid and observation_sha256=$5::text
    and raw_payload_bytes=$6::text and scalar_utf8::numeric<=$7::numeric
    and json_utf8::numeric<=$8::numeric and json_properties::numeric<=$9::numeric
    and json_containers::numeric<=$10::numeric as fits from measured
)
select gated.id,gated.board_id,gated.vote_id,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${pairs},'canonical_payload',certificate.canonical_payload)
    from selected_certificate as certificate
  ) else null end as view from gated
union all
select certificate.id,certificate.board_id,certificate.vote_id,null::text as observation_sha256,
  false as fits,null::jsonb as view
from vote_certificates as certificate
where not exists (select 1 from gated) and certificate.vote_id=$1 and certificate.id=$3
  and not boardagent_member_vote_recused(certificate.vote_id,boardagent_context_uuid('boardagent.member_id'))`;

function scalar(value: string): bigint {
  if (typeof value !== "string")
    throw new TypeError("certificate tool projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("certificate tool projection scalar is invalid");
  return BigInt(value);
}
export function certificateToolProjectionCost(
  metadata: CertificateToolProjectionMetadata
): ListProjectionScalars {
  const raw = scalar(metadata.raw_payload_bytes);
  if (raw < 2n || raw > 10485760n)
    throw new TypeError("certificate tool storage length is invalid");
  const s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  // Twelve keys sum145 bytes. The twelve-field object allowance is267; the
  // generic envelope/object allowances remain included in P/O and J+4096.
  return {
    jsonUpperBytes: (267n + 6n * s + n).toString(),
    propertyCount: (35n + p).toString(),
    objectOrArrayCount: (6n + o).toString()
  };
}
export function certificateToolProjectionPlan(
  metadata: CertificateToolProjectionMetadata
): ResponseAllocationPlan {
  if (!/^[0-9a-f]{64}$/u.test(metadata.observation_sha256))
    throw new TypeError("certificate tool observation hash is invalid");
  return responseAllocationPlan({
    kind: "certificate_tool_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.id,
    sourceVersion: "1",
    sha256: metadata.observation_sha256,
    listProjection: certificateToolProjectionCost(metadata)
  });
}
export async function loadAdmittedCertificateToolProjection(
  client: PoolClient,
  voteId: string,
  certificateId: string | null
): Promise<CertificateToolProjectionRow | null> {
  const observed = await client.query<CertificateToolProjectionMetadata>(
    CERTIFICATE_TOOL_PREFLIGHT_SQL,
    [voteId, certificateId]
  );
  if (observed.rows.length > 1)
    throw new TypeError("certificate tool preflight returned multiple rows");
  const metadata = observed.rows[0];
  if (!metadata) return null;
  if (metadata.vote_id !== voteId || (certificateId !== null && metadata.id !== certificateId))
    throw new TypeError("certificate tool preflight identity is invalid");
  const loaded = await loadWithResponseAllocation(certificateToolProjectionPlan(metadata), () =>
    client.query<{
      id: string;
      board_id: string;
      vote_id: string;
      observation_sha256: string;
      fits: boolean;
      view: JsonValue;
    }>(CERTIFICATE_TOOL_CONTENT_SQL, [
      voteId,
      certificateId,
      metadata.id,
      metadata.board_id,
      metadata.observation_sha256,
      metadata.raw_payload_bytes,
      metadata.scalar_utf8,
      metadata.json_utf8,
      metadata.json_properties,
      metadata.json_containers
    ])
  );
  if (loaded.rows.length > 1)
    throw new TypeError("certificate tool projection returned multiple rows");
  const row = loaded.rows[0];
  if (!row) return null;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    row.id !== metadata.id ||
    row.board_id !== metadata.board_id ||
    row.vote_id !== voteId ||
    row.observation_sha256 !== metadata.observation_sha256 ||
    row.view === null ||
    typeof row.view !== "object" ||
    Array.isArray(row.view)
  )
    throw new TypeError("certificate tool projection identity is invalid");
  const view = row.view as Readonly<Record<string, JsonValue>>;
  if (view["certificate_id"] !== metadata.id || view["vote_id"] !== voteId)
    throw new TypeError("certificate tool payload identity is invalid");
  return { board_id: row.board_id, view: row.view };
}
