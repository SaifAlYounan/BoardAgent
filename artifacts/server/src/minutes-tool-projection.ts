import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface MinutesToolProjectionMetadata {
  readonly minutes_id: string;
  readonly board_id: string;
  readonly row_version: string;
  readonly observation_sha256: string;
  readonly row_count: string;
  readonly version_count: string;
  readonly package_count: string;
  readonly declaration_count: string;
  readonly requirement_count: string;
  readonly signature_count: string;
  readonly scalar_utf8: string;
}
export interface MinutesToolProjectionRow {
  readonly view: JsonValue;
}
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hashText = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const root = [
  ["minutes_id", "minutes.minutes_id"],
  ["board_id", "minutes.board_id"],
  ["meeting_id", "minutes.meeting_id"],
  ["state", "minutes.state"],
  ["row_version", "minutes.row_version"],
  ["correction_of_minutes_id", "minutes.correction_of_minutes_id"],
  ["finalized_at", "minutes.finalized_at"],
  ["cancelled_at", "minutes.cancelled_at"]
] as const;
const version = [
  ["version_id", "minutes.version_id"],
  ["version", "minutes.version_number"],
  ["canonical_schema", "minutes.canonical_schema"],
  ["canonical_text", "minutes.canonical_text"],
  ["sha256", "minutes.version_sha256"],
  ["package_base_sha256", "minutes.package_base_sha256"],
  ["transcript_version_id", "minutes.transcript_version_id"],
  ["transcript_sha256", "minutes.transcript_sha256"],
  ["supersedes_id", "minutes.version_supersedes_id"],
  ["created_at", "minutes.version_created_at"]
] as const;
const pkg = [
  ["package_id", "minutes.package_id"],
  ["version", "minutes.package_version"],
  ["minutes_version_id", "minutes.package_minutes_version_id"],
  ["minutes_sha256", "minutes.minutes_sha256"],
  ["package_sha256", "minutes.package_sha256"],
  ["state", "minutes.package_state"]
] as const;
const requirement = [
  ["member_id", "requirement.member_id"],
  ["seat_role", "requirement.seat_role"],
  ["requirement", "requirement.requirement"],
  ["snapshot_sha256", "requirement.snapshot_sha256"]
] as const;
const signature = [
  ["signature_id", "signature.id"],
  ["signer_member_id", "signature.signer_member_id"],
  ["signer_seat_role", "signature.signer_seat_role"],
  ["record_sha256", "signature.record_sha256"],
  ["signed_at", "signature.signed_at_text"]
] as const;
const declaration = [
  ["declaration_id", "minutes.declaration_id"],
  ["minutes_version_id", "minutes.declaration_version_id"],
  ["declaration", "minutes.declaration"],
  ["manifest_sha256", "minutes.manifest_sha256"],
  ["declared_at", "minutes.declared_at"]
] as const;
const pairs = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([key, value]) => `'${key}',${value}`).join(",\n");
const flat = [...root, ...version, ...pkg, ...declaration];
const scalarSum = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields.map(([, value]) => utf8(value)).join("+");
const tuple = (fields: ReadonlyArray<readonly [string, string]>) =>
  fields
    .map(([, value]) => (value === "minutes.canonical_text" ? hashText(value) : value))
    .join(",");

// No outer LIMIT/order or extra parent/state predicate is introduced. Declaration
// selection retains the original visible-version dependency and latest LIMIT1.
// Text detoast/hash and aggregate workspace are PostgreSQL work, not qualified
// Node/process RSS. Preflight transfers only one fixed scalar metadata object.
const measured = `with selected_minutes as materialized (
  select minutes.id as minutes_id,minutes.board_id,minutes.meeting_id,minutes.state,
    minutes.row_version::text as row_version,minutes.correction_of_minutes_id,
    minutes.current_version_id,minutes.current_signature_package_id,
    ${date("minutes.finalized_at")} as finalized_at,${date("minutes.cancelled_at")} as cancelled_at,
    version_row.id as version_id,version_row.version as version_number,
    version_row.canonical_schema,version_row.canonical_text,
    encode(version_row.canonical_sha256,'hex') as version_sha256,
    encode(version_row.package_base_sha256,'hex') as package_base_sha256,
    version_row.transcript_version_id,encode(version_row.transcript_sha256,'hex') as transcript_sha256,
    version_row.supersedes_id as version_supersedes_id,
    ${date("version_row.created_at")} as version_created_at,
    package.id as package_id,package.version as package_version,
    package.minutes_version_id as package_minutes_version_id,
    encode(package.minutes_sha256,'hex') as minutes_sha256,
    encode(package.package_sha256,'hex') as package_sha256,package.state as package_state,
    declaration.id as declaration_id,declaration.minutes_version_id as declaration_version_id,
    declaration.declaration,encode(declaration.manifest_sha256,'hex') as manifest_sha256,
    ${date("declaration.declared_at")} as declared_at
  from minutes
  left join minutes_versions as version_row on version_row.id=minutes.current_version_id
  left join minutes_signature_packages as package on package.id=minutes.current_signature_package_id
  left join lateral (
    select declaration.id,declaration.minutes_version_id,declaration.declaration,
      declaration.manifest_sha256,declaration.declared_at
    from minutes_action_declarations as declaration
    where declaration.minutes_id=minutes.id and declaration.minutes_version_id=version_row.id
    order by declaration.declared_at desc limit 1
  ) as declaration on true
  where minutes.id=$1
), selected_requirements as materialized (
  select requirement.package_id,requirement.member_id,requirement.seat_role,requirement.requirement,
    encode(requirement.member_snapshot_sha256,'hex') as snapshot_sha256
  from minutes_signature_requirements as requirement
  where exists (select 1 from selected_minutes as minutes where minutes.package_id=requirement.package_id)
), selected_signatures as materialized (
  select signature.package_id,signature.id,signature.signer_member_id,signature.signer_seat_role,
    encode(signature.signature_record_sha256,'hex') as record_sha256,
    signature.signed_at,${date("signature.signed_at")} as signed_at_text
  from minutes_signatures as signature
  where exists (select 1 from selected_minutes as minutes where minutes.package_id=signature.package_id)
), requirement_metrics as materialized (
  select requirement.package_id,count(*)::numeric as child_count,
    coalesce(sum(${scalarSum(requirement)}),0)::numeric as scalar_utf8,
    ${hashText(`string_agg(${hashText(`jsonb_build_array(${tuple(requirement)})`)},'' order by requirement.member_id)`)} as observation_sha256
  from selected_requirements as requirement group by requirement.package_id
), signature_metrics as materialized (
  select signature.package_id,count(*)::numeric as child_count,
    coalesce(sum(${scalarSum(signature)}),0)::numeric as scalar_utf8,
    ${hashText(`string_agg(${hashText(`jsonb_build_array(${tuple(signature)})`)},'' order by signature.signed_at,signature.id)`)} as observation_sha256
  from selected_signatures as signature group by signature.package_id
), row_metrics as materialized (
  select minutes.board_id,minutes.row_version,minutes.version_id,minutes.package_id,minutes.declaration_id,
    coalesce(requirements.child_count,0)::numeric as requirement_count,
    coalesce(signatures.child_count,0)::numeric as signature_count,
    (${scalarSum(flat)}+coalesce(requirements.scalar_utf8,0)+coalesce(signatures.scalar_utf8,0))::numeric as scalar_utf8,
    ${hashText(`jsonb_build_array(${tuple(flat)},minutes.current_version_id,minutes.current_signature_package_id,
      coalesce(requirements.observation_sha256,${hashText("''::text")}),
      coalesce(signatures.observation_sha256,${hashText("''::text")}))`)} as observation_sha256
  from selected_minutes as minutes
  left join requirement_metrics as requirements on requirements.package_id=minutes.package_id
  left join signature_metrics as signatures on signatures.package_id=minutes.package_id
), measured as materialized (
  select $1::uuid as minutes_id,min(board_id::text)::uuid as board_id,min(row_version) as row_version,
    count(*)::text as row_count,
    (count(*) filter (where version_id is not null))::text as version_count,
    (count(*) filter (where package_id is not null))::text as package_count,
    (count(*) filter (where declaration_id is not null))::text as declaration_count,
    sum(requirement_count)::text as requirement_count,sum(signature_count)::text as signature_count,
    sum(scalar_utf8)::text as scalar_utf8,
    ${hashText(`string_agg(observation_sha256,'' order by observation_sha256)`)} as observation_sha256
  from row_metrics having count(*)>0
)`;
export const MINUTES_TOOL_PREFLIGHT_SQL = `${measured} select * from measured`;
export const MINUTES_TOOL_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,board_id=$2::uuid and row_version=$3::text and observation_sha256=$4::text
    and row_count=$5::text and version_count=$6::text and package_count=$7::text
    and declaration_count=$8::text and requirement_count=$9::text and signature_count=$10::text
    and scalar_utf8::numeric<=$11::numeric as fits from measured
)
select gated.minutes_id,gated.board_id,gated.row_version,gated.observation_sha256,gated.fits,
  case when gated.fits then (
    select jsonb_build_object(${pairs(root)},
      'version',case when minutes.version_id is null then null else jsonb_build_object(${pairs(version)}) end,
      'signature_package',case when minutes.package_id is null then null else jsonb_build_object(${pairs(pkg)},
        'required_signers',coalesce((select jsonb_agg(jsonb_build_object(${pairs(requirement)})
          order by requirement.member_id) from selected_requirements as requirement
          where requirement.package_id=minutes.package_id),'[]'::jsonb),
        'signatures',coalesce((select jsonb_agg(jsonb_build_object(${pairs(signature)})
          order by signature.signed_at,signature.id) from selected_signatures as signature
          where signature.package_id=minutes.package_id),'[]'::jsonb)) end,
      'action_declaration',case when minutes.declaration_id is null then null else jsonb_build_object(${pairs(declaration)}) end)
  ) else null end as view
from selected_minutes as minutes cross join gated where gated.fits
union all
select gated.minutes_id,gated.board_id,gated.row_version,gated.observation_sha256,gated.fits,null::jsonb as view
from gated where not gated.fits`;

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("minutes tool projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("minutes tool projection scalar is invalid");
  return BigInt(value);
}
export function minutesToolProjectionCost(
  metadata: MinutesToolProjectionMetadata
): ListProjectionScalars {
  const r = scalar(metadata.row_count),
    v = scalar(metadata.version_count),
    p = scalar(metadata.package_count),
    d = scalar(metadata.declaration_count),
    q = scalar(metadata.requirement_count),
    t = scalar(metadata.signature_count),
    s = scalar(metadata.scalar_utf8);
  if (r < 1n || v > r || p > r || d > v || (p === 0n && (q !== 0n || t !== 0n)))
    throw new TypeError("minutes tool projection count is invalid");
  // Complete scalar-only11/10/8/4/5/5-field output. Counts repeat child
  // occurrences per outer row; +23 properties/+5 containers and4KiB repeat
  // the inherited plain-tool policy. These are accounting bounds, not RSS.
  return {
    jsonUpperBytes: (
      223n * r +
      214n * v +
      159n * p +
      78n * q +
      108n * t +
      110n * d +
      6n * s +
      4096n * (r - 1n)
    ).toString(),
    propertyCount: (34n * r + 10n * v + 8n * p + 4n * q + 5n * t + 5n * d).toString(),
    objectOrArrayCount: (6n * r + v + 3n * p + q + t + d).toString()
  };
}
export function minutesToolProjectionPlan(
  metadata: MinutesToolProjectionMetadata
): ResponseAllocationPlan {
  if (!/^[0-9a-f]{64}$/u.test(metadata.observation_sha256))
    throw new TypeError("minutes tool observation hash is invalid");
  const version = scalar(metadata.row_version);
  if (version < 1n || version > 9_223_372_036_854_775_807n)
    throw new TypeError("minutes tool row version is invalid");
  return responseAllocationPlan({
    kind: "minutes_tool_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.minutes_id,
    sourceVersion: metadata.row_version,
    sha256: metadata.observation_sha256,
    listProjection: minutesToolProjectionCost(metadata)
  });
}
export async function loadAdmittedMinutesToolProjection(
  client: PoolClient,
  minutesId: string
): Promise<readonly MinutesToolProjectionRow[]> {
  const observed = await client.query<MinutesToolProjectionMetadata>(MINUTES_TOOL_PREFLIGHT_SQL, [
    minutesId
  ]);
  if (observed.rows.length > 1)
    throw new TypeError("minutes tool preflight returned multiple rows");
  const metadata = observed.rows[0];
  if (!metadata) return [];
  if (metadata.minutes_id !== minutesId || !metadata.board_id)
    throw new TypeError("minutes tool preflight identity is invalid");
  const loaded = await loadWithResponseAllocation(minutesToolProjectionPlan(metadata), () =>
    client.query<{
      minutes_id: string;
      board_id: string;
      row_version: string;
      observation_sha256: string;
      fits: boolean;
      view: JsonValue;
    }>(MINUTES_TOOL_CONTENT_SQL, [
      minutesId,
      metadata.board_id,
      metadata.row_version,
      metadata.observation_sha256,
      metadata.row_count,
      metadata.version_count,
      metadata.package_count,
      metadata.declaration_count,
      metadata.requirement_count,
      metadata.signature_count,
      metadata.scalar_utf8
    ])
  );
  if (loaded.rows.length === 0) return [];
  if (loaded.rows.length === 1 && loaded.rows[0]?.fits === false)
    throw new ResponseAllocationUnavailable();
  if (BigInt(loaded.rows.length) !== scalar(metadata.row_count))
    throw new TypeError("minutes tool projection row count is invalid");
  for (const row of loaded.rows) {
    if (
      row.fits !== true ||
      row.minutes_id !== minutesId ||
      row.board_id !== metadata.board_id ||
      row.row_version !== metadata.row_version ||
      row.observation_sha256 !== metadata.observation_sha256 ||
      row.view === null ||
      typeof row.view !== "object" ||
      Array.isArray(row.view)
    )
      throw new TypeError("minutes tool projection identity is invalid");
    const view = row.view as Readonly<Record<string, JsonValue>>;
    if (
      view["minutes_id"] !== minutesId ||
      view["board_id"] !== metadata.board_id ||
      view["row_version"] !== metadata.row_version
    )
      throw new TypeError("minutes tool payload identity is invalid");
  }
  return loaded.rows;
}
