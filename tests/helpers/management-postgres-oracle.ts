import type { PoolClient } from "pg";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  ORIGINAL_SUBMISSION_POINT_SQL,
  ORIGINAL_SUBMISSION_LIST_SQL,
  ORIGINAL_QUESTION_LIST_SQL
} from "./management-read-original-sql.js";

export type ManagementObject = Readonly<Record<string, JsonValue>>;
export function managementObject(value: JsonValue | undefined): ManagementObject {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected management oracle object");
  return value as ManagementObject;
}
export function managementArray(value: JsonValue | undefined): readonly JsonValue[] {
  if (!Array.isArray(value)) throw new TypeError("expected management oracle array");
  return value;
}
export function managementGraph(roots: readonly unknown[]) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers += 1;
    if (!Array.isArray(value)) properties += Object.keys(value).length;
    pending.push(...Object.values(value));
  }
  return { properties, containers };
}
export const SUBMISSION_ROOT_FLAT = [
  "submission_id",
  "board_id",
  "assigned_secretary_id",
  "state",
  "current_version_id",
  "row_version",
  "queue_entered_at",
  "created_by",
  "created_at"
] as const;
export const SUBMISSION_VERSION_FLAT = [
  "version_id",
  "version",
  "schema_version",
  "payload_sha256",
  "author_member_id",
  "change_reason",
  "supersedes_id",
  "created_at"
] as const;
export const SUBMISSION_REQUEST_FLAT = [
  "request_id",
  "submission_version_id",
  "secretary_member_id",
  "request_text",
  "request_sha256",
  "created_at"
] as const;
export const SUBMISSION_REPLY_FLAT = [
  "reply_id",
  "submission_version_id",
  "management_author_id",
  "canonical_reply",
  "reply_sha256",
  "created_at"
] as const;
export const SUBMISSION_DISPOSITION_FLAT = [
  "disposition_id",
  "submission_version_id",
  "disposition",
  "secretary_member_id",
  "reason",
  "resulting_draft_id",
  "created_at"
] as const;
export const SUBMISSION_LIST_KEYS = [
  "submission_id",
  "board_id",
  "management_owner_ids",
  "assigned_secretary_id",
  "state",
  "current_version_id",
  "row_version",
  "queue_entered_at",
  "current_version",
  "current_payload_sha256"
] as const;
export const QUESTION_LIST_FLAT = [
  "questionId",
  "boardId",
  "askerMemberId",
  "dueAt",
  "state",
  "currentTurnId",
  "rowVersion",
  "turnCount",
  "answerCount",
  "createdAt"
] as const;
const utf8 = (value: string | null) => BigInt(value === null ? 0 : Buffer.byteLength(value));
function scalar(value: ManagementObject, keys: readonly string[]) {
  let total = 0n;
  for (const key of keys) {
    const item = value[key];
    if (item === null) continue;
    if (typeof item !== "string" && typeof item !== "number" && typeof item !== "boolean")
      throw new TypeError(`invalid management original scalar ${key}`);
    total += utf8(String(item));
  }
  return total;
}
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const tupleHash = (values: readonly string[]) => hash(`jsonb_build_array(${values.join(",")})`);
function values(keys: readonly string[], object = "item", hashedText?: string) {
  return keys.map((key) =>
    key === hashedText ? hash(`${object}->>'${key}'`) : `${object}->'${key}'`
  );
}
const aggregateHash = (table: string, predicate = "true") =>
  `(select case when count(*)=0 then '' else ${hash("string_agg(row_hash,'' order by position)")} end from ${table} where ${predicate})`;
function spliceOnce(source: string, old: string, next: string) {
  if (source.split(old).length !== 2) throw new Error("management original splice is not unique");
  return source.replace(old, next);
}

// This oracle deliberately constructs the complete original tiny fixture before
// admission/saturation. It imports no admitted helper, estimator or private SQL.
// Private raw-time lookups are restricted to IDs in that original authorized view.
export async function originalManagementSubmission(
  client: PoolClient,
  submissionId: string,
  memberId: string,
  originalSql = ORIGINAL_SUBMISSION_POINT_SQL
) {
  const base = spliceOnce(
    originalSql,
    "select jsonb_build_object(",
    "select thread.queue_entered_at::text as raw_queue,thread.created_at::text as raw_created,jsonb_build_object("
  );
  const sql = `with original as materialized (${base}),
    versions as materialized (
      select entry.value as item,entry.ordinality as position,stored.created_at::text as raw_at
      from original cross join lateral jsonb_array_elements(original.view->'versions') with ordinality as entry(value,ordinality)
      join management_submission_versions as stored on stored.id=(entry.value->>'version_id')::uuid
    ), requests as materialized (
      select entry.value as item,entry.ordinality as position,stored.created_at::text as raw_at
      from original cross join lateral jsonb_array_elements(original.view->'revision_requests') with ordinality as entry(value,ordinality)
      join management_revision_requests as stored on stored.id=(entry.value->>'request_id')::uuid
    ), replies as materialized (
      select request.item->>'request_id' as request_id,entry.value as item,entry.ordinality as position,stored.created_at::text as raw_at
      from requests as request cross join lateral jsonb_array_elements(request.item->'replies') with ordinality as entry(value,ordinality)
      join management_revision_replies as stored on stored.id=(entry.value->>'reply_id')::uuid
    ), dispositions as materialized (
      select entry.value as item,entry.ordinality as position,stored.created_at::text as raw_at
      from original cross join lateral jsonb_array_elements(original.view->'dispositions') with ordinality as entry(value,ordinality)
      join management_submission_dispositions as stored on stored.id=(entry.value->>'disposition_id')::uuid
    ), version_hashes as (
      select position,${tupleHash([...values(SUBMISSION_VERSION_FLAT, "item", "change_reason"), hash("item->'document_references'"), "raw_at"])} as row_hash from versions
    ), reply_hashes as (
      select request_id,position,${tupleHash([...values(SUBMISSION_REPLY_FLAT, "item", "canonical_reply"), "raw_at"])} as row_hash from replies
    ), request_hashes as (
      select request.position,${tupleHash([...values(SUBMISSION_REQUEST_FLAT, "request.item", "request_text"), "request.raw_at", aggregateHash("reply_hashes", "request_id=request.item->>'request_id'")])} as row_hash from requests as request
    ), disposition_hashes as (
      select position,${tupleHash([...values(SUBMISSION_DISPOSITION_FLAT, "item", "reason"), "raw_at"])} as row_hash from dispositions
    ) select original.*,
      ${tupleHash([...values(SUBMISSION_ROOT_FLAT, "original.view"), hash("original.view->'management_owner_ids'"), "original.raw_queue", "original.raw_created", aggregateHash("version_hashes"), aggregateHash("request_hashes"), aggregateHash("disposition_hashes")])} as private_hash,
      array[(original.view->'management_owner_ids')::text]||array(select (item->'document_references')::text from versions order by position) as normalized_roots,
      (select count(*)::text from versions) as version_lookup_count,(select count(*)::text from requests) as request_lookup_count,
      (select count(*)::text from replies) as reply_lookup_count,(select count(*)::text from dispositions) as disposition_lookup_count
      from original`;
  const rows = (
    await client.query<{
      view: JsonValue;
      raw_queue: string;
      raw_created: string;
      private_hash: string;
      normalized_roots: string[];
      version_lookup_count: string;
      request_lookup_count: string;
      reply_lookup_count: string;
      disposition_lookup_count: string;
    }>(sql, [submissionId, memberId])
  ).rows;
  if (rows.length > 1)
    throw new Error("normal fixture returned multiple original submission roots");
  const row = rows[0];
  if (!row) return { value: null, metadata: [], normalizedRoots: [] };
  const root = managementObject(row.view),
    versions = managementArray(root.versions),
    requests = managementArray(root.revision_requests),
    dispositions = managementArray(root.dispositions);
  const replies = requests.flatMap((value) => [
    ...managementArray(managementObject(value).replies)
  ]);
  if (
    row.version_lookup_count !== String(versions.length) ||
    row.request_lookup_count !== String(requests.length) ||
    row.reply_lookup_count !== String(replies.length) ||
    row.disposition_lookup_count !== String(dispositions.length)
  )
    throw new Error("original management private lookup lost a visible child");
  let s = scalar(root, SUBMISSION_ROOT_FLAT);
  for (const [rows, keys] of [
    [versions, SUBMISSION_VERSION_FLAT],
    [requests, SUBMISSION_REQUEST_FLAT],
    [replies, SUBMISSION_REPLY_FLAT],
    [dispositions, SUBMISSION_DISPOSITION_FLAT]
  ] as const)
    for (const item of rows) s += scalar(managementObject(item), keys);
  const graph = managementGraph(row.normalized_roots.map((text) => JSON.parse(text) as JsonValue));
  const metadata = {
    submission_id: String(root.submission_id),
    board_id: String(root.board_id),
    row_version: String(root.row_version),
    current_version_id: root.current_version_id === null ? null : String(root.current_version_id),
    observation_sha256: row.private_hash,
    version_count: String(versions.length),
    request_count: String(requests.length),
    reply_count: String(replies.length),
    disposition_count: String(dispositions.length),
    scalar_utf8: s.toString(),
    json_utf8: row.normalized_roots.reduce((n, value) => n + utf8(value), 0n).toString(),
    json_properties: String(graph.properties),
    json_containers: String(graph.containers)
  };
  return { value: row.view, metadata: [metadata], normalizedRoots: row.normalized_roots };
}

export async function originalManagementSubmissionList(
  client: PoolClient,
  parameters: readonly unknown[],
  originalSql = ORIGINAL_SUBMISSION_LIST_SQL
) {
  const base = spliceOnce(
    originalSql,
    "select jsonb_build_object(",
    "select thread.queue_entered_at::text as raw_order_key,jsonb_build_object("
  );
  const sql = `with original as materialized (${base}) select original.*,
    (original.item->'management_owner_ids')::text as normalized_owners,
    ${tupleHash([...SUBMISSION_LIST_KEYS.map((key) => (key === "management_owner_ids" ? hash(`original.item->'${key}'`) : `original.item->'${key}'`)), "original.raw_order_key"])} as private_hash
    from original order by raw_order_key::timestamptz desc,cursor_id::uuid desc`;
  const rows = (
    await client.query<{
      item: JsonValue;
      cursor_at: string | null;
      cursor_id: string;
      raw_order_key: string;
      normalized_owners: string;
      private_hash: string;
    }>(sql, [...parameters])
  ).rows;
  const metadata = rows.map((row) => {
    const graph = managementGraph([JSON.parse(row.normalized_owners) as JsonValue]);
    return {
      id: row.cursor_id,
      cursor_at: row.cursor_at,
      raw_order_key: row.raw_order_key,
      observation_sha256: row.private_hash,
      scalar_utf8: (
        scalar(
          managementObject(row.item),
          SUBMISSION_LIST_KEYS.filter((key) => key !== "management_owner_ids")
        ) +
        utf8(row.cursor_at) +
        utf8(row.cursor_id)
      ).toString(),
      normalized_json_utf8: String(Buffer.byteLength(row.normalized_owners)),
      json_property_count: String(graph.properties),
      json_container_count: String(graph.containers)
    };
  });
  return {
    value: rows.map(({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id })),
    metadata,
    normalizedOwners: rows.map((row) => row.normalized_owners)
  };
}

export async function originalManagementQuestionList(
  client: PoolClient,
  parameters: readonly unknown[],
  originalSql = ORIGINAL_QUESTION_LIST_SQL
) {
  const sql = `with original as materialized (${originalSql}), ordered as (
    select original.total_visible,entry.value as item,entry.ordinality as position from original
    cross join lateral jsonb_array_elements(original.items) with ordinality as entry(value,ordinality)
  ), observed as (
    select ordered.*,stored.created_at::text as raw_created_at,(item->'assignedOwnerIds')::text as normalized_owners,
      ${tupleHash([...values(QUESTION_LIST_FLAT), hash("item->'assignedOwnerIds'"), "stored.created_at::text"])} as private_hash
    from ordered join management_questions as stored on stored.id=(item->>'questionId')::uuid
  ) select original.total_visible,original.items,
    coalesce((select jsonb_agg(jsonb_build_object('question_id',item->>'questionId','created_at',item->'createdAt',
      'raw_created_at',raw_created_at,'normalized_owners',normalized_owners,'private_hash',private_hash) order by position) from observed),'[]'::jsonb) as private_rows
    from original`;
  const rows = (
    await client.query<{
      total_visible: string;
      items: JsonValue[];
      private_rows: Array<{
        question_id: string;
        created_at: string | null;
        raw_created_at: string;
        normalized_owners: string;
        private_hash: string;
      }>;
    }>(sql, [...parameters])
  ).rows;
  if (rows.length !== 1) throw new Error("original question aggregate did not return one header");
  const result = rows[0]!;
  if (result.items.length !== result.private_rows.length)
    throw new Error("original question private lookup lost a visible row");
  const metadata = result.items.map((item, index) => {
    const value = managementObject(item),
      row = result.private_rows[index]!;
    if (value.questionId !== row.question_id)
      throw new Error("original question private order changed");
    const graph = managementGraph([JSON.parse(row.normalized_owners) as JsonValue]);
    return {
      question_id: row.question_id,
      created_at: row.created_at,
      raw_created_at: row.raw_created_at,
      observation_sha256: row.private_hash,
      scalar_utf8: scalar(value, QUESTION_LIST_FLAT).toString(),
      json_utf8: String(Buffer.byteLength(row.normalized_owners)),
      json_properties: String(graph.properties),
      json_containers: String(graph.containers)
    };
  });
  const observation = {
    rows: metadata,
    total_visible: result.total_visible,
    row_count: String(metadata.length),
    scalar_utf8: metadata.reduce((sum, row) => sum + BigInt(row.scalar_utf8), 0n).toString(),
    json_utf8: metadata.reduce((sum, row) => sum + BigInt(row.json_utf8), 0n).toString(),
    json_properties: metadata
      .reduce((sum, row) => sum + BigInt(row.json_properties), 0n)
      .toString(),
    json_containers: metadata.reduce((sum, row) => sum + BigInt(row.json_containers), 0n).toString()
  };
  const preflight = metadata.length
    ? metadata.map((row) => ({ total_visible: result.total_visible, ...row }))
    : [
        {
          total_visible: result.total_visible,
          question_id: null,
          created_at: null,
          raw_created_at: null,
          observation_sha256: null,
          scalar_utf8: "0",
          json_utf8: "0",
          json_properties: "0",
          json_containers: "0"
        }
      ];
  return {
    value: { total_visible: result.total_visible, items: result.items },
    metadata,
    observation,
    preflight,
    normalizedOwners: result.private_rows.map((row) => row.normalized_owners)
  };
}
