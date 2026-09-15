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

type Fields = ReadonlyArray<readonly [string, string]>;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const rawHash = (value: string) => `encode(sha256(${value}),'hex')`;
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const pairs = (fields: Fields) => fields.map(([key, value]) => `'${key}',${value}`).join(",");
const sum = (fields: Fields) => fields.map(([, value]) => utf8(value)).join("+");
const leaves = (fields: Fields) => fields.map(([, value]) => hash(value)).join(",");
export interface ExportStatusMetadata {
  readonly row_count: string;
  readonly artifact_count: string;
  readonly scalar_utf8: string;
  readonly request_id: string | null;
  readonly artifact_id: string | null;
  readonly row_version: string | null;
  readonly observation_sha256: string;
}
export interface ExportStatusRow {
  readonly fits: boolean;
  readonly view: JsonValue;
}
const rootFlat: Fields = [
  ["export_id", "$2::text"],
  ["request_id", "source.request_id"],
  ["board_id", "source.board_id"],
  ["export_type", "source.export_type"],
  ["state", "source.state"],
  ["row_version", "source.row_version"],
  ["expires_at", "source.expires_at_text"],
  ["failure_class", "source.failure_class"],
  ["created_at", "source.created_at_text"],
  ["completed_at", "source.completed_at_text"]
];
const artifactFlat: Fields = [
  ["artifact_id", "source.artifact_id"],
  ["byte_length", "source.byte_length"],
  ["state", "source.artifact_state"],
  ["created_at", "source.artifact_created_at_text"],
  ["deleted_at", "source.deleted_at_text"]
];
const rootHex: Fields = [
  ["scope_sha256", "source.scope_sha256"],
  ["snapshot_sha256", "source.snapshot_sha256"]
];
const artifactHex: Fields = [
  ["manifest_sha256", "source.manifest_sha256"],
  ["content_set_sha256", "source.content_set_sha256"]
];
const hexPairs = (fields: Fields) =>
  fields.map(([key, value]) => `'${key}',encode(${value},'hex')`).join(",");
const hexSize = (fields: Fields) =>
  fields.map(([, value]) => `2*coalesce(octet_length(${value}),0)::numeric`).join("+");
const rawLeaves = (fields: Fields) => fields.map(([, value]) => rawHash(value)).join(",");

const measured = `with selected as materialized (
  select request.id as request_id,request.board_id,request.export_type,request.scope_sha256,
    request.state,request.row_version::text,request.expires_at,request.snapshot_sha256,request.failure_class,
    request.created_at,request.completed_at,artifact.id as artifact_id,artifact.manifest_sha256,
    artifact.content_set_sha256,artifact.byte_length::text,artifact.state as artifact_state,
    artifact.created_at as artifact_created_at,artifact.deleted_at,
    ${date("request.expires_at")} as expires_at_text,${date("request.created_at")} as created_at_text,
    case when request.completed_at is null then null else ${date("request.completed_at")} end as completed_at_text,
    ${date("artifact.created_at")} as artifact_created_at_text,
    case when artifact.deleted_at is null then null else ${date("artifact.deleted_at")} end as deleted_at_text
  from export_requests as request
  left join export_artifacts as artifact on artifact.export_request_id=request.id
  where request.public_id=$1 and request.requester_member_id=$3 limit 1
), observed as materialized (
  select ${hash(`jsonb_build_array(${leaves(rootFlat)},${rawLeaves(rootHex)},${leaves(artifactFlat)},${rawLeaves(artifactHex)},${hash("source.expires_at")},${hash("source.created_at")},${hash("source.completed_at")},${hash("source.artifact_created_at")},${hash("source.deleted_at")})`)} as row_hash from selected as source
), measured as materialized (
  select (select count(*)::text from selected) as row_count,
    (select count(artifact_id)::text from selected) as artifact_count,
    (${utf8("$2::text")}+(select coalesce(sum(${sum(rootFlat)}+${hexSize(rootHex)}+
      case when source.artifact_id is null then 0 else ${sum(artifactFlat)}+${hexSize(artifactHex)} end),0) from selected as source))::text as scalar_utf8,
    (select request_id::text from selected) as request_id,(select artifact_id::text from selected) as artifact_id,
    (select row_version from selected) as row_version,
    (select ${hash(`jsonb_build_array(${rawHash("$1::bytea")},${hash("$2::text")},${hash("$3::uuid")},coalesce(string_agg(row_hash,'' order by row_hash),''))`)} from observed) as observation_sha256
)`;
export const EXPORT_STATUS_PREFLIGHT_SQL = `${measured} select * from measured`;
export const EXPORT_STATUS_CONTENT_SQL = `${measured}, gate as materialized (
  select (scalar_utf8::numeric<=$6::numeric and (row_count='0' or
    (row_count=$4::text and artifact_count=$5::text and request_id is not distinct from $7::text
      and artifact_id is not distinct from $8::text and row_version is not distinct from $9::text
      and observation_sha256=$10::text))) as fits from measured
) select gate.fits,case when gate.fits then (select jsonb_build_object(
  ${pairs(rootFlat)},${hexPairs(rootHex)},'artifact',case when source.artifact_id is null then null else
    jsonb_build_object(${pairs(artifactFlat)},${hexPairs(artifactHex)}) end)) else null end as view
  from selected as source cross join gate where gate.fits
  union all select false,null::jsonb from gate where not gate.fits`;
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("export status scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("export status scalar is invalid");
  return BigInt(value);
}
export function exportStatusProjectionCost(metadata: ExportStatusMetadata): ListProjectionScalars {
  const r = scalar(metadata.row_count),
    a = scalar(metadata.artifact_count),
    s = scalar(metadata.scalar_utf8);
  if (r > 1n || a > r) throw new TypeError("export status scalar relationship is invalid");
  return {
    jsonUpperBytes: (2n + 298n * r + 152n * a + 6n * s).toString(),
    propertyCount: (32n + 15n * r + 7n * a).toString(),
    objectOrArrayCount: (12n + 2n * r + a).toString()
  };
}
export function exportStatusProjectionPlan(
  sourceId: string,
  metadata: ExportStatusMetadata
): ResponseAllocationPlan {
  const r = scalar(metadata.row_count),
    a = scalar(metadata.artifact_count);
  const uuid = (value: unknown) =>
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value);
  if (
    (r === 0n &&
      (metadata.request_id !== null ||
        metadata.row_version !== null ||
        metadata.artifact_id !== null)) ||
    (r === 1n && (!uuid(metadata.request_id) || metadata.row_version === null)) ||
    (a === 0n ? metadata.artifact_id !== null : !uuid(metadata.artifact_id)) ||
    typeof metadata.observation_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(metadata.observation_sha256)
  )
    throw new TypeError("export status observation is invalid");
  if (metadata.row_version !== null) scalar(metadata.row_version);
  return responseAllocationPlan({
    kind: "export_status_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId,
    sourceVersion: metadata.row_version ?? "0",
    sha256: metadata.observation_sha256,
    listProjection: exportStatusProjectionCost(metadata)
  });
}
export async function loadAdmittedExportStatus(
  client: PoolClient,
  publicId: Buffer,
  exportId: string,
  memberId: string
): Promise<readonly ExportStatusRow[]> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new TypeError("native export status allocation owner is required");
  owner.assertLive();
  const parameters = Object.freeze([Buffer.from(publicId), exportId, memberId]);
  const found = await client.query<ExportStatusMetadata>(EXPORT_STATUS_PREFLIGHT_SQL, [
    ...parameters
  ]);
  if (found.rows.length !== 1)
    throw new TypeError("export status preflight cardinality is invalid");
  const m = Object.freeze({ ...found.rows[0]! }),
    plan = exportStatusProjectionPlan(`export:${memberId}:${m.observation_sha256}`, m);
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<ExportStatusRow>(EXPORT_STATUS_CONTENT_SQL, [
      ...parameters,
      m.row_count,
      m.artifact_count,
      m.scalar_utf8,
      m.request_id,
      m.artifact_id,
      m.row_version,
      m.observation_sha256
    ])
  );
  if (loaded.rows.some((row) => row.fits === false)) throw new ResponseAllocationUnavailable();
  if (loaded.rows.length !== 0 && BigInt(loaded.rows.length) !== scalar(m.row_count))
    throw new TypeError("export status content cardinality is invalid");
  for (const row of loaded.rows) {
    if (
      row.fits !== true ||
      row.view === null ||
      typeof row.view !== "object" ||
      Array.isArray(row.view)
    )
      throw new TypeError("export status content is invalid");
    const view = row.view as Readonly<Record<string, JsonValue>>;
    if (
      view.export_id !== exportId ||
      view.request_id !== m.request_id ||
      view.row_version !== m.row_version
    )
      throw new TypeError("export status content identity is invalid");
    const artifact = view.artifact;
    if (
      m.artifact_id === null
        ? artifact !== null
        : artifact === null ||
          typeof artifact !== "object" ||
          Array.isArray(artifact) ||
          (artifact as Readonly<Record<string, JsonValue>>).artifact_id !== m.artifact_id
    )
      throw new TypeError("export status artifact identity is invalid");
  }
  return loaded.rows;
}
