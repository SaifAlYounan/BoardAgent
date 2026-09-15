import { createHmac } from "node:crypto";
import type { PoolClient } from "pg";
import { expect } from "vitest";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import type {
  MinutesListKind,
  MinutesListMetadata,
  MinutesListScalars
} from "../../artifacts/server/src/minutes-list-projection.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";

// Independent literal field order, not imported from production SQL generation.
const versionKeys = [
  "version_id",
  "minutes_id",
  "version",
  "canonical_schema",
  "sha256",
  "package_base_sha256",
  "transcript_version_id",
  "supersedes_id",
  "created_at"
];
const reviewFlat = [
  "review_item_id",
  "minutes_id",
  "item_kind",
  "schema_version",
  "author_member_id",
  "author_seat_role",
  "base_version_id",
  "base_sha256",
  "payload_sha256",
  "created_at"
];
const withdrawalKeys = ["withdrawal_id", "author_member_id", "withdrawn_at"];
const dispositionKeys = [
  "disposition_id",
  "decision",
  "reason",
  "resulting_minutes_version_id",
  "created_at"
];
export interface MinutesOracleRow {
  item: Record<string, JsonValue>;
  cursor_at: string | null;
  cursor_id: string;
}
export const minutesListTools = {
  versions: "list_minutes_versions",
  reviews: "list_minutes_review_items"
} as const;
export const minutesListCursorKey = Buffer.alloc(32, 0x4c);
export function originalObject(value: unknown): Record<string, JsonValue> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("expected original object");
  return value as Record<string, JsonValue>;
}
export function listGraph(roots: readonly unknown[], deduplicate = false) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0n,
    containers = 0n;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object") continue;
    if (deduplicate && seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (Array.isArray(value)) pending.push(...value);
    else {
      properties += BigInt(Object.keys(value).length);
      pending.push(...Object.values(value));
    }
  }
  return { properties, containers };
}
const values = (value: Record<string, JsonValue> | null, keys: readonly string[]) =>
  keys.map((key) => value?.[key] ?? null);
const exactKeys = (value: Record<string, JsonValue>, expected: readonly string[]) =>
  expect(Object.keys(value).sort()).toEqual([...expected].sort());
export interface ListRawOracle {
  raw_created_at: string;
  anchor_text: string | null;
  payload_text: string | null;
  raw_sha256: string | null;
  raw_length: number | null;
}
export async function independentListMetadata(
  client: PoolClient,
  kind: MinutesListKind,
  row: MinutesOracleRow,
  raw: ListRawOracle
): Promise<MinutesListMetadata> {
  const item = row.item,
    review = kind === "reviews";
  exactKeys(
    item,
    review ? [...reviewFlat, "anchor", "payload", "withdrawal", "disposition"] : versionKeys
  );
  const w = review && item["withdrawal"] !== null ? originalObject(item["withdrawal"]) : null;
  const d = review && item["disposition"] !== null ? originalObject(item["disposition"]) : null;
  if (w) exactKeys(w, withdrawalKeys);
  if (d) exactKeys(d, dispositionKeys);
  const flat = review
    ? [...values(item, reviewFlat), ...values(w, withdrawalKeys), ...values(d, dispositionKeys)]
    : values(item, versionKeys);
  let s = 0n;
  for (const value of [...flat, row.cursor_at, row.cursor_id]) {
    if (value === null) continue;
    if (typeof value !== "string" && typeof value !== "number")
      throw new Error("nonflat original scalar");
    s += BigInt(Buffer.byteLength(String(value)));
  }
  const hashes = async (text: string | null) => (text === null ? null : sha256Hex(text));
  const privateFlat = [...flat];
  if (review) privateFlat[15] = d === null ? null : sha256Hex(String(d["reason"]));
  // PostgreSQL normalized JSON text remains an independent scalar input; JS
  // numeric rounding must never be fed back into the private digest oracle.
  const tuple = [...privateFlat, raw.raw_created_at];
  if (review)
    tuple.push(
      await hashes(raw.anchor_text),
      await hashes(raw.payload_text),
      raw.raw_sha256,
      raw.raw_length
    );
  const digest = (
    await client.query<{ digest: string }>(
      "select encode(sha256(convert_to(($1::jsonb)::text,'UTF8')),'hex') as digest",
      [JSON.stringify(tuple)]
    )
  ).rows[0]!.digest;
  const roots = review ? [raw.anchor_text, raw.payload_text] : [];
  const graph = listGraph(
    roots.filter((value): value is string => value !== null).map((value) => JSON.parse(value))
  );
  return {
    id: row.cursor_id,
    cursor_at: row.cursor_at,
    raw_created_at: raw.raw_created_at,
    observation_sha256: digest,
    withdrawal_count: w ? "1" : "0",
    disposition_count: d ? "1" : "0",
    scalar_utf8: String(s),
    json_utf8: String(
      roots.reduce((sum, value) => sum + (value === null ? 0 : Buffer.byteLength(value)), 0)
    ),
    json_properties: String(graph.properties),
    json_containers: String(graph.containers)
  };
}
export function listTotals(rows: readonly MinutesListMetadata[]): MinutesListScalars {
  const keys = [
    "withdrawal_count",
    "disposition_count",
    "scalar_utf8",
    "json_utf8",
    "json_properties",
    "json_containers"
  ] as const;
  return {
    row_count: String(rows.length),
    ...Object.fromEntries(
      keys.map((key) => [key, String(rows.reduce((sum, row) => sum + BigInt(row[key]), 0n))])
    )
  } as unknown as MinutesListScalars;
}
export function originalListEnvelope(
  kind: MinutesListKind,
  minutesId: string,
  rows: readonly MinutesOracleRow[],
  limit: number,
  principal: Pick<SurfacePrincipal, "organizationId" | "memberId">,
  actualCursor: unknown,
  beforeSeconds: number,
  afterSeconds: number
) {
  const selected = rows.slice(0, limit),
    last = selected.at(-1);
  let expectedCursor: string | null = null;
  if (rows.length > limit && last) {
    if (typeof actualCursor !== "string") throw new Error("expected native cursor");
    const encoded = actualCursor.split(".")[0];
    if (!encoded) throw new Error("cursor payload absent");
    const observed = originalObject(JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")));
    const expiry = observed["expires_at"];
    if (typeof expiry !== "number") throw new Error("expected cursor expiry");
    expect(expiry).toBeGreaterThanOrEqual(beforeSeconds + 86400);
    expect(expiry).toBeLessThanOrEqual(afterSeconds + 86400);
    const payload = canonicalJson({
      schema_version: "boardagent.cursor.v1",
      organization_id: principal.organizationId,
      member_id: principal.memberId,
      tool: minutesListTools[kind],
      board_id: null,
      after: canonicalJson({ at: last.cursor_at, id: last.cursor_id }),
      expires_at: expiry
    });
    const mac = createHmac("sha256", minutesListCursorKey)
      .update("boardagent.cursor.v1\0")
      .update(payload)
      .digest("base64url");
    expectedCursor = Buffer.from(payload).toString("base64url") + "." + mac;
  } else expect(actualCursor).toBeNull();
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: minutesListTools[kind],
    status: "ok",
    reference: minutesId,
    resource_uri: null,
    data: { items: selected.map((row) => row.item), next_cursor: expectedCursor }
  };
}
