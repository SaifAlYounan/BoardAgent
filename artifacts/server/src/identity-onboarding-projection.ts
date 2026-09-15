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
const date = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const pairs = (fields: Fields) => fields.map(([key, value]) => `'${key}',${value}`).join(",");
const sum = (fields: Fields) => fields.map(([, value]) => utf8(value)).join("+");
const leaves = (fields: Fields) => fields.map(([, value]) => hash(value)).join(",");
export type IdentityOnboardingKind = "whoami" | "onboarding";
export interface WhoamiProjectionInput {
  readonly memberId: string;
  readonly roles: readonly string[];
  readonly scopes: readonly string[];
  readonly boardIds: readonly string[];
  readonly protocolClientId: string;
  readonly accessTokenRecordId: string;
}
export interface IdentityOnboardingMetadata {
  readonly row_count: string;
  readonly recent_auth_count: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
  readonly observation_sha256: string;
}
export interface IdentityOnboardingRow {
  readonly fits: boolean;
  readonly view: JsonValue;
}

const whoamiFlat: Fields = [
  ["member_id", "source.member_id"],
  ["member_kind", "source.member_kind"],
  ["display_name", "source.display_name"],
  ["state", "source.state"],
  ["accountable_principal_id", "source.accountable_principal_id"],
  ["identity_generation", "source.identity_generation"],
  ["onboarding_generation", "source.onboarding_generation"],
  ["protocol_client_id", "source.protocol_client_id"],
  ["session_token_record_id", "source.session_token_record_id"]
];
const authFlat: Fields = [
  ["proof", "source.auth_proof"],
  ["session_id", "source.auth_session_id"],
  ["authenticated_at", "source.authenticated_at_text"],
  ["expires_at", "source.expires_at_text"]
];
const onboardingFlat: Fields = [
  ["board_id", "source.board_id"],
  ["seat_role", "source.seat_role"],
  ["attested", "source.attested"],
  ["attested_at", "source.attested_at_text"],
  ["presentation_choice", "source.presentation_choice"],
  ["local_memory_choice", "source.local_memory_choice"]
];
const termsFlat: Fields = [
  ["version_id", "source.terms_id"],
  ["version", "source.terms_version"],
  ["schema_version", "source.terms_schema_version"],
  ["canonical_text", "source.canonical_text"],
  ["sha256", "source.terms_sha256"],
  ["material_change", "source.material_change"],
  ["effective_at", "source.effective_at_text"]
];
const supportFlat: Fields = [
  ["version_id", "source.support_id"],
  ["version", "source.support_version"],
  ["name", "source.support_name"],
  ["sha256", "source.support_sha256"]
];

const whoamiSelected = `selected_member as materialized (
  select member.id as member_id,member.member_kind,member.display_name,member.state,member.accountable_principal_id,
    member.identity_generation::text,member.onboarding_generation::text
  from members as member where member.id=$1 and member.state='active'
), auth_rows as materialized (
  select auth.session_id,auth.proof_reference,auth.authenticated_at,auth.expires_at
  from public.boardagent_recent_auth_context() as auth
  where (select member_id from selected_member) is not null
), auth_scalar as materialized (
  select (select auth.session_id from auth_rows as auth) as auth_session_id,
    (select auth.proof_reference from auth_rows as auth) as auth_proof,
    (select auth.authenticated_at from auth_rows as auth) as authenticated_at,
    (select auth.expires_at from auth_rows as auth) as expires_at,
    (select count(*) from auth_rows)::numeric as auth_count
  where exists(select 1 from selected_member)
), selected as materialized (
  select member.*,to_jsonb($2::text[]) as roles,to_jsonb($3::text[]) as scopes,to_jsonb($4::uuid[]) as board_ids,
    $5::text as protocol_client_id,$6::uuid as session_token_record_id,auth.*,
    ${date("auth.authenticated_at")} as authenticated_at_text,${date("auth.expires_at")} as expires_at_text
  from selected_member as member cross join auth_scalar as auth
)`;
const onboardingSelected = `membership as (
  select * from board_memberships where board_id=$1 and member_id=$2 and state='active'
    and active_from<=transaction_timestamp() and (active_until is null or active_until>transaction_timestamp())
), current_terms as (
  select terms.* from onboarding_terms_versions as terms,membership
  where terms.organization_id=membership.organization_id and terms.seat_role=membership.seat_role
    and terms.effective_at<=transaction_timestamp() order by terms.version desc limit 1
), current_support as (
  select support.* from secretary_support_versions as support
  where support.board_id=$1 and support.effective_at<=transaction_timestamp() order by support.version desc limit 1
), selected as materialized (
  select $1::uuid as board_id,membership.id as membership_id,membership.member_id,membership.organization_id,
    membership.seat_role,membership.active_from,membership.active_until,
    terms.id as terms_id,terms.version as terms_version,terms.schema_version as terms_schema_version,
    terms.canonical_text,encode(terms.canonical_sha256,'hex') as terms_sha256,terms.material_change,
    terms.effective_at,${date("terms.effective_at")} as effective_at_text,
    support.id as support_id,support.version as support_version,support.support_name,support.contact_methods,
    encode(support.canonical_sha256,'hex') as support_sha256,support.effective_at as support_effective_at,
    attestation.id as attestation_id,attestation.id is not null as attested,attestation.attested_at,
    case when attestation.attested_at is null then null else ${date("attestation.attested_at")} end as attested_at_text,
    attestation.presentation_choice,attestation.local_memory_choice
  from membership join current_terms as terms on true join current_support as support on true
  left join onboarding_attestations as attestation on attestation.member_id=$2 and attestation.board_id=$1
    and attestation.terms_version_id=terms.id and attestation.support_version_id=support.id
)`;
function measured(kind: IdentityOnboardingKind): string {
  const whoami = kind === "whoami";
  const flat = whoami ? whoamiFlat : [...onboardingFlat, ...termsFlat, ...supportFlat];
  const jsonValues = whoami
    ? "select roles as value from selected union all select scopes from selected union all select board_ids from selected"
    : "select contact_methods as value from selected";
  const tuple = whoami
    ? `${leaves(flat)},${leaves(authFlat)},source.auth_count,${hash("source.roles")},${hash("source.scopes")},${hash("source.board_ids")},${hash("source.authenticated_at")},${hash("source.expires_at")}`
    : `${leaves(flat)},${hash("source.contact_methods")},source.membership_id,source.member_id,source.organization_id,source.terms_id,source.support_id,source.attestation_id,${hash("source.active_from")},${hash("source.active_until")},${hash("source.effective_at")},${hash("source.support_effective_at")},${hash("source.attested_at")}`;
  return `with recursive ${whoami ? whoamiSelected : onboardingSelected}, json_values as materialized (${jsonValues}),
  nodes(value,member) as (
    select value,false from json_values union all
    select child.value,child.member from nodes as node cross join lateral (
      select entry.value,true as member from jsonb_each(case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
      union all select element.value,false from jsonb_array_elements(case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as element
    ) as child
  ), observed as materialized (
    select ${hash(`jsonb_build_array(${tuple})`)} as row_hash from selected as source
  ), measured as materialized (
    select (select count(*)::text from selected) as row_count,
      ${whoami ? "(select coalesce(sum(auth_count),0)::text from selected)" : "'0'::text"} as recent_auth_count,
      (select coalesce(sum(${sum(flat)}${whoami ? `+case when source.auth_count=0 then 0 else ${sum(authFlat)} end` : ""}),0)::text from selected as source) as scalar_utf8,
      (select coalesce(sum(${utf8("value")}),0)::text from json_values) as normalized_json_utf8,
      (select count(*) filter(where member)::text from nodes) as json_property_count,
      (select count(*) filter(where jsonb_typeof(value) in ('object','array'))::text from nodes) as json_container_count,
      (select ${hash("coalesce(string_agg(row_hash,'' order by row_hash),'')")} from observed) as observation_sha256
  )`;
}
export const IDENTITY_ONBOARDING_PREFLIGHT_SQL: Readonly<Record<IdentityOnboardingKind, string>> = {
  whoami: `${measured("whoami")} select * from measured`,
  onboarding: `${measured("onboarding")} select * from measured`
};
function content(kind: IdentityOnboardingKind): string {
  const start = kind === "whoami" ? 7 : 3;
  const root =
    kind === "whoami"
      ? `jsonb_build_object(${pairs(whoamiFlat)},'roles',source.roles,'scopes',source.scopes,'board_ids',source.board_ids,
      'recent_auth',case when source.auth_count=0 then null else jsonb_build_object(${pairs(authFlat)}) end)`
      : `jsonb_build_object(${pairs(onboardingFlat)},'terms',jsonb_build_object(${pairs(termsFlat)}),
      'secretary_support',jsonb_build_object(${pairs(supportFlat)},'contact_methods',source.contact_methods))`;
  return `${measured(kind)}, gate as materialized (
    select (row_count='0' or (row_count=$${start}::text and recent_auth_count=$${start + 1}::text
      and scalar_utf8::numeric<=$${start + 2}::numeric and normalized_json_utf8::numeric<=$${start + 3}::numeric
      and json_property_count::numeric<=$${start + 4}::numeric and json_container_count::numeric<=$${start + 5}::numeric
      and observation_sha256=$${start + 6}::text)) as fits from measured
  ) select gate.fits,case when gate.fits then (select ${root}) else null end as view
    from selected as source cross join gate where gate.fits
    union all select false,null::jsonb from gate where not gate.fits`;
}
export const IDENTITY_ONBOARDING_CONTENT_SQL: Readonly<Record<IdentityOnboardingKind, string>> = {
  whoami: content("whoami"),
  onboarding: content("onboarding")
};
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("identity/onboarding scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("identity/onboarding scalar is invalid");
  return BigInt(value);
}
export function identityOnboardingProjectionCost(
  kind: IdentityOnboardingKind,
  metadata: IdentityOnboardingMetadata
): ListProjectionScalars {
  const r = scalar(metadata.row_count),
    a = scalar(metadata.recent_auth_count),
    s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.normalized_json_utf8),
    p = scalar(metadata.json_property_count),
    o = scalar(metadata.json_container_count);
  if (
    (kind === "whoami" && (r > 1n || a > r || o < 3n * r || n < 6n * r)) ||
    (kind === "onboarding" && (a !== 0n || o < r || n < 2n * r)) ||
    (r === 0n && (a !== 0n || s !== 0n || n !== 0n || p !== 0n || o !== 0n))
  )
    throw new TypeError("identity/onboarding scalar relationship is invalid");
  return {
    jsonUpperBytes: (2n + 1000n * r + 6n * s + n).toString(),
    propertyCount: (32n + (kind === "whoami" ? 15n * r + 4n * a : 22n * r) + p).toString(),
    objectOrArrayCount: (12n + (kind === "whoami" ? 2n * r + a : 4n * r) + o).toString()
  };
}
export function identityOnboardingProjectionPlan(
  kind: IdentityOnboardingKind,
  sourceId: string,
  metadata: IdentityOnboardingMetadata
): ResponseAllocationPlan {
  if (!/^[a-f0-9]{64}$/u.test(metadata.observation_sha256))
    throw new TypeError("identity/onboarding observation is invalid");
  return responseAllocationPlan({
    kind: "identity_onboarding_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId,
    sourceVersion: "1",
    sha256: metadata.observation_sha256,
    listProjection: identityOnboardingProjectionCost(kind, metadata)
  });
}
async function load(
  client: PoolClient,
  kind: IdentityOnboardingKind,
  parameters: readonly unknown[],
  sourceId: string,
  expectedId: string
): Promise<readonly IdentityOnboardingRow[]> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new TypeError("native identity/onboarding allocation owner is required");
  owner.assertLive();
  const selected = await client.query<IdentityOnboardingMetadata>(
    IDENTITY_ONBOARDING_PREFLIGHT_SQL[kind],
    [...parameters]
  );
  if (selected.rows.length !== 1)
    throw new TypeError("identity/onboarding preflight cardinality is invalid");
  const m = Object.freeze({ ...selected.rows[0]! });
  const bound = identityOnboardingProjectionPlan(kind, sourceId, m);
  const loaded = await loadWithResponseAllocation(bound, () =>
    client.query<IdentityOnboardingRow>(IDENTITY_ONBOARDING_CONTENT_SQL[kind], [
      ...parameters,
      m.row_count,
      m.recent_auth_count,
      m.scalar_utf8,
      m.normalized_json_utf8,
      m.json_property_count,
      m.json_container_count,
      m.observation_sha256
    ])
  );
  if (loaded.rows.some((row) => row.fits === false)) throw new ResponseAllocationUnavailable();
  if (loaded.rows.length !== 0 && BigInt(loaded.rows.length) !== scalar(m.row_count))
    throw new TypeError("identity/onboarding content cardinality is invalid");
  for (const row of loaded.rows) {
    if (
      row.fits !== true ||
      row.view === null ||
      typeof row.view !== "object" ||
      Array.isArray(row.view)
    )
      throw new TypeError("identity/onboarding content is invalid");
    const view = row.view as Readonly<Record<string, JsonValue>>;
    if (view[kind === "whoami" ? "member_id" : "board_id"] !== expectedId)
      throw new TypeError("identity/onboarding content identity is invalid");
  }
  return loaded.rows;
}
export function loadAdmittedWhoami(
  client: PoolClient,
  input: WhoamiProjectionInput
): Promise<readonly IdentityOnboardingRow[]> {
  return load(
    client,
    "whoami",
    Object.freeze([
      input.memberId,
      input.roles,
      input.scopes,
      input.boardIds,
      input.protocolClientId,
      input.accessTokenRecordId
    ]),
    `whoami:${input.memberId}:${input.accessTokenRecordId}`,
    input.memberId
  );
}
export function loadAdmittedOnboarding(
  client: PoolClient,
  boardId: string,
  memberId: string
): Promise<readonly IdentityOnboardingRow[]> {
  return load(
    client,
    "onboarding",
    Object.freeze([boardId, memberId]),
    `onboarding:${boardId}:${memberId}`,
    boardId
  );
}
