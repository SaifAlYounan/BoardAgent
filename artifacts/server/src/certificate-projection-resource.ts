import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface CertificateProjectionMetadata {
  readonly id: string;
  readonly board_id: string;
  readonly vote_id: string;
  readonly signing_key_id: string;
  readonly observation_sha256: string;
  readonly raw_payload_bytes: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
export interface CertificateProjectionRow {
  readonly id: string;
  readonly payload: JsonValue;
}
const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const base64url = (value: string) =>
  `translate(encode(${value},'base64'),'+/=' || chr(10) || chr(13),'-_')`;
const rootFields = [
  ["schema_version", "'boardagent.vote-certificate-bundle.v1'"],
  ["certificate_id", "certificate.id"],
  ["vote_id", "certificate.vote_id"],
  ["outcome_id", "certificate.outcome_id"],
  ["public_id", "certificate.public_id"],
  ["payload_sha256", "certificate.payload_sha256"],
  ["signature_base64url", "certificate.signature_base64url"],
  ["issued_at", "certificate.issued_at"]
] as const;
const keyFields = [
  ["id", "certificate.signing_key_id"],
  ["kid", "certificate.kid"],
  ["algorithm", "certificate.algorithm"]
] as const;
const scalarSum = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([, v]) => utf8(v)).join("+");
const jsonPairs = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([k, v]) => `'${k}',${v}`).join(",\n");

// PostgreSQL keeps the original bytea -> UTF8 -> JSONB conversion. Raw certificate
// material never crosses the preflight into Node. PG parsing, hashing, traversal,
// RLS and query workspace are not covered by this response allocation policy.
const measured = `with recursive visible_certificate as materialized (
  select certificate.id,certificate.board_id,certificate.vote_id,certificate.outcome_id,
    ${base64url("certificate.public_id")} as public_id,
    convert_from(certificate.canonical_payload,'UTF8')::jsonb as canonical_payload,
    encode(certificate.payload_sha256,'hex') as payload_sha256,
    ${base64url("certificate.signature")} as signature_base64url,
    certificate.signing_key_id,key.kid,key.algorithm,key.public_jwk,
    ${utc("certificate.issued_at")} as issued_at,
    octet_length(certificate.canonical_payload)::text as raw_payload_bytes,
    encode(sha256(certificate.canonical_payload),'hex') as actual_payload_sha256,
    encode(sha256(convert_to(key.public_jwk::text,'UTF8')),'hex') as key_json_sha256
  from vote_certificates as certificate join crypto_key_registry as key on key.id=certificate.signing_key_id
  where certificate.board_id=$1 and certificate.vote_id=$2 and certificate.id=$3
    and not boardagent_member_vote_recused(certificate.vote_id,boardagent_context_uuid('boardagent.member_id'))
), json_roots(value) as materialized (
  select canonical_payload from visible_certificate
  union all select public_jwk from visible_certificate
), json_nodes(value,member) as (
  select value,false from json_roots
  union all
  select child.value,child.member from json_nodes as node cross join lateral (
    select entry.value,true as member from jsonb_each(
      case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member from jsonb_array_elements(
      case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), measured as materialized (
  select certificate.id,certificate.board_id,certificate.vote_id,certificate.signing_key_id,
    certificate.raw_payload_bytes,
    encode(sha256(convert_to(jsonb_build_array(certificate.id,certificate.board_id,certificate.vote_id,
      certificate.outcome_id,certificate.public_id,certificate.payload_sha256,certificate.signature_base64url,
      certificate.signing_key_id,certificate.kid,certificate.algorithm,certificate.issued_at,
      certificate.raw_payload_bytes,certificate.actual_payload_sha256,certificate.key_json_sha256)::text,'UTF8')),'hex')
      as observation_sha256,
    ((${scalarSum(rootFields)})+(${scalarSum(keyFields)}))::text as scalar_utf8,
    (select coalesce(sum(${utf8("value")}),0)::text from json_roots) as json_utf8,
    (select count(*) filter (where member)::text from json_nodes) as json_properties,
    (select count(*) filter (where jsonb_typeof(value) in ('object','array'))::text from json_nodes) as json_containers
  from visible_certificate as certificate
)`;
export const CERTIFICATE_PROJECTION_PREFLIGHT_SQL = `${measured} select * from measured`;
export const CERTIFICATE_PROJECTION_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,signing_key_id=$4::uuid and observation_sha256=$5::text
    and raw_payload_bytes=$6::text and scalar_utf8::numeric<=$7::numeric
    and json_utf8::numeric<=$8::numeric and json_properties::numeric<=$9::numeric
    and json_containers::numeric<=$10::numeric as fits from measured
)
select gated.id,gated.signing_key_id,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${jsonPairs(rootFields)},'canonical_payload',certificate.canonical_payload,
      'signing_key',jsonb_build_object(${jsonPairs(keyFields)},'public_jwk',certificate.public_jwk))
    from visible_certificate as certificate
  ) else null end as payload from gated`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("certificate projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("certificate projection scalar is invalid");
  return BigInt(value);
}
export function certificateProjectionCost(
  metadata: CertificateProjectionMetadata
): ListProjectionScalars {
  const raw = scalar(metadata.raw_payload_bytes);
  if (raw < 2n || raw > 10485760n) throw new TypeError("certificate storage length is invalid");
  const s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  return {
    jsonUpperBytes: (292n + 6n * s + n).toString(),
    propertyCount: (37n + p).toString(),
    objectOrArrayCount: (7n + o).toString()
  };
}
export function certificateProjectionPlan(
  metadata: CertificateProjectionMetadata
): ResponseAllocationPlan {
  if (!/^[0-9a-f]{64}$/u.test(metadata.observation_sha256))
    throw new TypeError("certificate observation hash is invalid");
  return responseAllocationPlan({
    kind: "certificate_projection",
    representation: "resource",
    canonicalBytes: 0,
    sourceId: metadata.id,
    sourceVersion: "1",
    sha256: metadata.observation_sha256,
    listProjection: certificateProjectionCost(metadata)
  });
}
export async function loadAdmittedCertificateProjection(
  client: PoolClient,
  boardId: string,
  voteId: string,
  certificateId: string
): Promise<CertificateProjectionRow | null> {
  const observed = await client.query<CertificateProjectionMetadata>(
    CERTIFICATE_PROJECTION_PREFLIGHT_SQL,
    [boardId, voteId, certificateId]
  );
  if (observed.rows.length > 1)
    throw new TypeError("certificate preflight returned multiple roots");
  const metadata = observed.rows[0];
  if (!metadata) return null;
  if (metadata.id !== certificateId || metadata.board_id !== boardId || metadata.vote_id !== voteId)
    throw new TypeError("certificate preflight identity is invalid");
  const loaded = await loadWithResponseAllocation(certificateProjectionPlan(metadata), () =>
    client.query<
      CertificateProjectionRow & {
        signing_key_id: string;
        observation_sha256: string;
        fits: boolean;
      }
    >(CERTIFICATE_PROJECTION_CONTENT_SQL, [
      boardId,
      voteId,
      certificateId,
      metadata.signing_key_id,
      metadata.observation_sha256,
      metadata.raw_payload_bytes,
      metadata.scalar_utf8,
      metadata.json_utf8,
      metadata.json_properties,
      metadata.json_containers
    ])
  );
  if (loaded.rows.length > 1) throw new TypeError("certificate projection returned multiple roots");
  const row = loaded.rows[0];
  if (!row) return null;
  if (row.fits === false) throw new ResponseAllocationUnavailable();
  if (
    row.fits !== true ||
    row.id !== metadata.id ||
    row.signing_key_id !== metadata.signing_key_id ||
    row.observation_sha256 !== metadata.observation_sha256 ||
    row.payload === null ||
    typeof row.payload !== "object" ||
    Array.isArray(row.payload)
  )
    throw new TypeError("certificate projection identity is invalid");
  const payload = row.payload as Readonly<Record<string, JsonValue>>;
  const key = payload["signing_key"];
  if (
    payload["certificate_id"] !== certificateId ||
    payload["vote_id"] !== voteId ||
    key === null ||
    typeof key !== "object" ||
    Array.isArray(key) ||
    (key as Readonly<Record<string, JsonValue>>)["id"] !== metadata.signing_key_id
  )
    throw new TypeError("certificate projection payload identity is invalid");
  return { id: row.id, payload: row.payload };
}
