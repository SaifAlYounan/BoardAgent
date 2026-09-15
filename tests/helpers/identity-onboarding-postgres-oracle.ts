import type { PoolClient } from "pg";
import { expect } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  ORIGINAL_WHOAMI_SQL,
  ORIGINAL_ONBOARDING_SQL
} from "./identity-onboarding-original-sql.js";

export type IdentityOracleKind = "whoami" | "onboarding";
export type IdentitySqlTransform = (sql: string) => string;
export const identitySqlUnchanged: IdentitySqlTransform = (sql) => sql;
export const WHOAMI_FLAT = [
  "member_id",
  "member_kind",
  "display_name",
  "state",
  "accountable_principal_id",
  "identity_generation",
  "onboarding_generation",
  "protocol_client_id",
  "session_token_record_id"
] as const;
export const AUTH_FLAT = ["proof", "session_id", "authenticated_at", "expires_at"] as const;
export const ONBOARDING_FLAT = [
  "board_id",
  "seat_role",
  "attested",
  "attested_at",
  "presentation_choice",
  "local_memory_choice"
] as const;
export const TERMS_FLAT = [
  "version_id",
  "version",
  "schema_version",
  "canonical_text",
  "sha256",
  "material_change",
  "effective_at"
] as const;
export const SUPPORT_FLAT = ["version_id", "version", "name", "sha256"] as const;
export function identityObject(value: unknown): Readonly<Record<string, JsonValue>> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("expected original identity/onboarding object");
  return value as Readonly<Record<string, JsonValue>>;
}
export function identityGraph(roots: readonly unknown[]) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (!Array.isArray(value)) properties += Object.keys(value).length;
    for (const child of Object.values(value)) pending.push(child);
  }
  return { properties, containers };
}
const hash = (sql: string) => `encode(sha256(convert_to((${sql})::text,'UTF8')),'hex')`;
const textLeaf = (prefix: string, key: string) => `${prefix}->>'${key}'`;
const leafHashes = (prefix: string, fields: readonly string[]) =>
  fields.map((key) => hash(textLeaf(prefix, key)));
const originalSql = { whoami: ORIGINAL_WHOAMI_SQL, onboarding: ORIGINAL_ONBOARDING_SQL };
function checkedKeys(value: unknown, fields: readonly string[]) {
  const object = identityObject(value);
  expect(Object.keys(object).sort()).toEqual([...fields].sort());
  return object;
}
function flatBytes(value: Readonly<Record<string, JsonValue>>, fields: readonly string[]): number {
  return fields.reduce((sum, key) => {
    const leaf = value[key];
    if (leaf === null) return sum;
    if (leaf === undefined || typeof leaf === "object")
      throw new Error(`original flat leaf ${key} is absent or composite`);
    // SQL boolean text is true/false; integral version values and all bigint
    // values projected as strings preserve their exact text in this fixture.
    return sum + Buffer.byteLength(String(leaf));
  }, 0);
}
const onboardingPrivate = `jsonb_build_object(
  'membership_id',membership.id,'member_id',membership.member_id,'organization_id',membership.organization_id,
  'terms_id',terms.id,'support_id',support.id,'attestation_id',attestation.id,
  'active_from',membership.active_from::text,'active_until',membership.active_until::text,
  'effective_at',terms.effective_at::text,'support_effective_at',support.effective_at::text,
  'attested_at',attestation.attested_at::text) as private_bits, `;

/** Test-only oracle: original SQL constructs the complete view first. Normalized
 * PG text is retained as text; numeric JSON is never reserialized through JS
 * before private hashing or UTF8 measurement. No admitted helper is imported. */
export async function originalIdentityOnboarding(
  client: PoolClient,
  kind: IdentityOracleKind,
  parameters: readonly unknown[],
  transform: IdentitySqlTransform = identitySqlUnchanged
) {
  const sql = transform(originalSql[kind]);
  const original = await client.query<{ view: JsonValue }>(sql, [...parameters]);
  let augmented = originalSql[kind];
  if (kind === "onboarding") {
    expect(augmented.split("select jsonb_build_object(")).toHaveLength(2);
    augmented = augmented.replace(
      "select jsonb_build_object(",
      `select ${onboardingPrivate}jsonb_build_object(`
    );
  }
  const copied = await client.query<{
    view: JsonValue;
    normalized: string;
    private_bits?: JsonValue;
  }>(`select picked.*,picked.view::text as normalized from (${transform(augmented)}) as picked`, [
    ...parameters
  ]);
  expect(copied.rows.map((row) => canonicalJson(row.view)).sort()).toEqual(
    original.rows.map((row) => canonicalJson(row.view)).sort()
  );
  if (kind === "onboarding") for (const row of copied.rows) identityObject(row.private_bits);
  let authRaw: Readonly<Record<string, JsonValue>> = {};
  if (kind === "whoami" && original.rows.length !== 0) {
    const selected = await client.query<{
      authenticated_at: string | null;
      expires_at: string | null;
    }>(
      transform(
        `select auth.authenticated_at::text as authenticated_at,auth.expires_at::text as expires_at
       from public.boardagent_recent_auth_context() as auth
       cross join (select $1::uuid,$2::text[],$3::text[],$4::uuid[],$5::text,$6::uuid) as parameters`
      ),
      [...parameters]
    );
    const visible = identityObject(original.rows[0]!.view).recent_auth !== null;
    expect(selected.rows).toHaveLength(visible ? 1 : 0);
    authRaw = selected.rows[0] ?? {};
  }
  let scalar = 0,
    authCount = 0;
  for (const row of copied.rows) {
    if (kind === "whoami") {
      const view = checkedKeys(row.view, [
        ...WHOAMI_FLAT,
        "roles",
        "scopes",
        "board_ids",
        "recent_auth"
      ]);
      scalar += flatBytes(view, WHOAMI_FLAT);
      if (view.recent_auth !== null) {
        authCount++;
        scalar += flatBytes(checkedKeys(view.recent_auth, AUTH_FLAT), AUTH_FLAT);
      }
    } else {
      const view = checkedKeys(row.view, [...ONBOARDING_FLAT, "terms", "secretary_support"]);
      scalar +=
        flatBytes(view, ONBOARDING_FLAT) +
        flatBytes(checkedKeys(view.terms, TERMS_FLAT), TERMS_FLAT) +
        flatBytes(
          checkedKeys(view.secretary_support, [...SUPPORT_FLAT, "contact_methods"]),
          SUPPORT_FLAT
        );
    }
  }
  const flat =
    kind === "whoami"
      ? leafHashes("view", WHOAMI_FLAT)
      : [
          ...leafHashes("view", ONBOARDING_FLAT),
          ...leafHashes("(view->'terms')", TERMS_FLAT),
          ...leafHashes("(view->'secretary_support')", SUPPORT_FLAT)
        ];
  const tuple =
    kind === "whoami"
      ? [
          ...flat,
          ...leafHashes("(view->'recent_auth')", AUTH_FLAT),
          "case when view->'recent_auth'='null'::jsonb then 0 else 1 end",
          hash("view->'roles'"),
          hash("view->'scopes'"),
          hash("view->'board_ids'"),
          hash("private_bits->>'authenticated_at'"),
          hash("private_bits->>'expires_at'")
        ]
      : [
          ...flat,
          hash("view->'secretary_support'->'contact_methods'"),
          ...[
            "membership_id",
            "member_id",
            "organization_id",
            "terms_id",
            "support_id",
            "attestation_id"
          ].map((key) => `private_bits->>'${key}'`),
          ...[
            "active_from",
            "active_until",
            "effective_at",
            "support_effective_at",
            "attested_at"
          ].map((key) => hash(`private_bits->>'${key}'`))
        ];
  const roots =
    kind === "whoami"
      ? "select view->'roles' as value from source union all select view->'scopes' from source union all select view->'board_ids' from source"
      : "select view->'secretary_support'->'contact_methods' as value from source";
  const measured = await client.query<{ observation_sha256: string; normalized_roots: string[] }>(
    `
    with source as materialized (
      select views.value::jsonb as view,extras.value::jsonb as private_bits
      from unnest($1::text[]) with ordinality as views(value,n)
      join unnest($2::text[]) with ordinality as extras(value,n) using(n)
    ), observed as (select ${hash(`jsonb_build_array(${tuple.join(",")})`)} as row_hash from source),
    roots as (${roots})
    select (select ${hash("coalesce(string_agg(row_hash,'' order by row_hash),'')")} from observed) as observation_sha256,
      array(select value::text from roots) as normalized_roots`,
    [
      copied.rows.map((row) => row.normalized),
      copied.rows.map((row) => JSON.stringify(kind === "whoami" ? authRaw : row.private_bits))
    ]
  );
  expect(measured.rows).toHaveLength(1);
  const measuredRow = measured.rows[0]!;
  const graph = identityGraph(measuredRow.normalized_roots.map((root) => JSON.parse(root)));
  const metadata = {
    row_count: String(copied.rows.length),
    recent_auth_count: String(authCount),
    scalar_utf8: String(scalar),
    normalized_json_utf8: String(
      measuredRow.normalized_roots.reduce((sum, root) => sum + Buffer.byteLength(root), 0)
    ),
    json_property_count: String(graph.properties),
    json_container_count: String(graph.containers),
    observation_sha256: measuredRow.observation_sha256
  };
  return {
    views: original.rows.map((row) => row.view),
    metadata,
    normalizedRoots: measuredRow.normalized_roots,
    privateRows: copied.rows.map((row) => row.private_bits ?? authRaw)
  };
}
export interface OriginalIdentityMetadata {
  readonly row_count: string;
  readonly recent_auth_count: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
  readonly observation_sha256: string;
}
export function originalIdentityBound(kind: IdentityOracleKind, m: OriginalIdentityMetadata) {
  const r = BigInt(m.row_count),
    a = BigInt(m.recent_auth_count),
    s = BigInt(m.scalar_utf8),
    n = BigInt(m.normalized_json_utf8),
    p = BigInt(m.json_property_count),
    o = BigInt(m.json_container_count);
  const j = 2n + 1000n * r + 6n * s + n,
    properties = 32n + (kind === "whoami" ? 15n * r + 4n * a : 22n * r) + p,
    containers = 12n + (kind === "whoami" ? 2n * r + a : 4n * r) + o;
  const allocationBytes = 65536n + 8n * (j + 4096n) + 256n * properties + 512n * containers;
  return {
    jsonUpperBytes: j,
    propertyCount: properties,
    objectOrArrayCount: containers,
    allocationBytes,
    wireUpperBytes: 65536n + 3n * (j + 4096n),
    units: Number((allocationBytes + 1048575n) / 1048576n)
  };
}
