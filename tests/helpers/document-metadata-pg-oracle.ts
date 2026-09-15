import type { JsonValue } from "../../lib/contracts/src/index.js";
import {
  ORIGINAL_DOCUMENT_HASH_SQL,
  ORIGINAL_DOCUMENT_VALIDATION_SQL,
  ORIGINAL_DOCUMENT_VERSIONS_SQL,
  ORIGINAL_DOCUMENT_DOCUMENTS_SQL
} from "./document-metadata-original-sql.js";

// Independent test oracle derived from the exact original four SQL statements.
// It imports no runtime field descriptors, metadata helper, or cost function.
export type DocumentOracleKind = "hash" | "validation" | "versions" | "documents";
export interface DocumentOriginalRow {
  readonly item: JsonValue;
  readonly cursor_at: string | null;
  readonly cursor_id: string;
}
export interface DocumentOracleRow {
  readonly id: string;
  readonly cursor_at: string | null;
  readonly raw_created_at: string | null;
  readonly observation_sha256: string;
  readonly scalar_utf8: string;
}
export const documentOriginalSql = {
  hash: ORIGINAL_DOCUMENT_HASH_SQL,
  validation: ORIGINAL_DOCUMENT_VALIDATION_SQL,
  versions: ORIGINAL_DOCUMENT_VERSIONS_SQL,
  documents: ORIGINAL_DOCUMENT_DOCUMENTS_SQL
};
const fields = {
  hash: [
    "document_id",
    "version_id",
    "version",
    "media_type",
    "document_schema",
    "byte_length",
    "sha256"
  ],
  validation: [
    "validation_attempt_id",
    "board_id",
    "offered_media_type",
    "offered_name",
    "offered_length",
    "offered_sha256",
    "result",
    "result_code",
    "remediation",
    "accepted_document_version_id",
    "attempted_at"
  ],
  versions: [
    "document_id",
    "version_id",
    "version",
    "media_type",
    "document_schema",
    "byte_length",
    "sha256",
    "created_by",
    "created_at"
  ],
  documents: [
    "document_id",
    "board_id",
    "title",
    "state",
    "version_id",
    "version",
    "media_type",
    "document_schema",
    "byte_length",
    "sha256",
    "row_version",
    "resource_uri",
    "created_at"
  ]
} as const;
const h = (text: string) => `encode(sha256(convert_to((${text})::text,'UTF8')),'hex')`;
const n = (text: string) => `coalesce(octet_length(convert_to((${text})::text,'UTF8')),0)::numeric`;
function oracleSql(kind: DocumentOracleKind): string {
  const point = kind === "hash" || kind === "validation";
  const pointId = kind === "hash" ? "version_id" : "validation_attempt_id";
  const normalized = point
    ? `select view as item,null::text as cursor_at,view->>'${pointId}' as cursor_id,null::text as raw_created_at from original`
    : `select original.item,original.cursor_at,original.cursor_id,stored.created_at::text as raw_created_at
       from original join ${kind === "versions" ? "document_versions" : "documents"} as stored on stored.id=original.cursor_id::uuid`;
  const scalarValues = [
    ...fields[kind].map((key) => `selected.item->>'${key}'`),
    "selected.cursor_at",
    "selected.cursor_id"
  ];
  const identityValues = fields[kind].map((key) =>
    key === "version" || key === "byte_length"
      ? `selected.item->'${key}'`
      : h(`selected.item->>'${key}'`)
  );
  return `with original as materialized (${documentOriginalSql[kind]}), selected as materialized (${normalized})
    select selected.cursor_id as id,selected.cursor_at,selected.raw_created_at,
      ${h(`jsonb_build_array(${identityValues.join(",")},selected.raw_created_at)`)} as observation_sha256,
      (${scalarValues.map(n).join("+")})::text as scalar_utf8
    from selected${point ? "" : " order by selected.raw_created_at::timestamptz desc,selected.cursor_id::uuid desc"}`;
}
export const documentMetadataOracleSql = {
  hash: oracleSql("hash"),
  validation: oracleSql("validation"),
  versions: oracleSql("versions"),
  documents: oracleSql("documents")
};

export function normalizedOriginalRows(
  kind: DocumentOracleKind,
  rows: readonly unknown[]
): readonly DocumentOriginalRow[] {
  if (kind === "versions" || kind === "documents") return rows as readonly DocumentOriginalRow[];
  return rows.map((value) => {
    const item = (value as { view: JsonValue }).view;
    if (item === null || typeof item !== "object" || Array.isArray(item))
      throw new Error("original point row has an invalid object");
    const record = item as Readonly<Record<string, JsonValue>>;
    const id = record[kind === "hash" ? "version_id" : "validation_attempt_id"];
    if (typeof id !== "string") throw new Error("original point row lacks its selected ID");
    return { item, cursor_at: null, cursor_id: id };
  });
}
export function independentDocumentCost(
  kind: DocumentOracleKind,
  rows: readonly DocumentOracleRow[]
) {
  const r = BigInt(rows.length),
    s = rows.reduce((sum, row) => sum + BigInt(row.scalar_utf8), 0n);
  const keyBytes = fields[kind].reduce((sum, key) => sum + Buffer.byteLength(key), 0);
  const fieldCount = fields[kind].length;
  const j = 2n + BigInt(keyBytes + 10 * fieldCount + 72) * r + 6n * s;
  const p = 25n + BigInt(fieldCount + 4) * r,
    o = 7n + 2n * r;
  const allocation = 65536n + 8n * (j + 4096n) + 256n * p + 512n * o;
  return {
    row_count: r.toString(),
    scalar_utf8: s.toString(),
    jsonUpperBytes: j.toString(),
    propertyCount: p.toString(),
    objectOrArrayCount: o.toString(),
    allocationBytes: Number(allocation),
    wireUpperBytes: Number(65536n + 3n * (j + 4096n)),
    units: Number((allocation + 1048575n) / 1048576n)
  };
}
