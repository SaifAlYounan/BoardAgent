import type { PoolClient } from "pg";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  ORIGINAL_BOARDS_SQL,
  ORIGINAL_PROXY_SQL,
  ORIGINAL_VOTE_LINEAGE_SQL,
  ORIGINAL_VOTES_SQL
} from "./board-vote-read-original-sql.js";

export type BoardVoteObject = Readonly<Record<string, JsonValue>>;
export function boardVoteObject(value: JsonValue | undefined): BoardVoteObject {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected board/vote oracle object");
  return value as BoardVoteObject;
}
export function boardVoteGraph(roots: readonly unknown[]) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const node = pending.pop();
    if (node === null || typeof node !== "object" || seen.has(node)) continue;
    seen.add(node);
    containers += 1;
    if (!Array.isArray(node)) properties += Object.keys(node).length;
    for (const value of Object.values(node)) pending.push(value);
  }
  return { properties, containers };
}
export const BOARD_KEYS = [
  "board_id",
  "slug",
  "name",
  "timezone",
  "state",
  "row_version",
  "seat_role",
  "is_chair",
  "is_secretary",
  "voting_weight",
  "entitlement_generation"
] as const;
export const VOTE_KEYS = [
  "vote_id",
  "board_id",
  "title",
  "state",
  "resolution_version_id",
  "decision_package_id",
  "package_sha256",
  "close_mode",
  "deadline_at",
  "row_version",
  "opened_at",
  "closed_outcome"
] as const;
export const GRANT_FLAT_KEYS = [
  "grant_id",
  "vote_id",
  "principal_member_id",
  "holder_member_id",
  "policy",
  "active",
  "granted_at",
  "expires_at"
] as const;
export const REVOCATION_KEYS = ["revocation_id", "reason", "effect", "revoked_at"] as const;
export const LINEAGE_FLAT_KEYS = [
  "supersession_id",
  "old_vote_id",
  "new_vote_id",
  "old_package_sha256",
  "new_package_sha256",
  "secretary_member_id",
  "reason",
  "created_at"
] as const;
function scalar(object: BoardVoteObject, keys: readonly string[]) {
  let result = 0n;
  for (const key of keys) {
    const value = object[key];
    if (value === null) continue;
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean")
      throw new TypeError(`invalid original scalar ${key}`);
    result += BigInt(Buffer.byteLength(String(value)));
  }
  return result;
}
function once(source: string, before: string, after: string) {
  if (source.split(before).length !== 2)
    throw new Error("original oracle source splice is not unique");
  return source.replace(before, after);
}
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const entries = (keys: readonly string[], source = "original.item") =>
  keys.map((key) => `${source}->'${key}'`).join(",");

// Full original constructors execute BEFORE any deliberate occupancy. We add
// only private join/raw-time columns to the exact original selected frontier.
// This module imports no proposed estimator or admitted SQL.
export async function originalBoardVotePage(
  client: PoolClient,
  kind: "boards" | "votes",
  parameters: readonly unknown[]
) {
  const base = kind === "boards" ? ORIGINAL_BOARDS_SQL : ORIGINAL_VOTES_SQL;
  const extra =
    kind === "boards"
      ? "membership.id::text as join_id,null::text as outcome_id,board.created_at::text as raw_at,"
      : "package.id::text as join_id,outcome.id::text as outcome_id,vote.created_at::text as raw_at,";
  const sql = `with original as materialized (${once(base, "select jsonb_build_object(", `select ${extra}jsonb_build_object(`)})
    select original.*,${hash(`jsonb_build_array(${entries(kind === "boards" ? BOARD_KEYS : VOTE_KEYS)},original.cursor_at,original.cursor_id,original.raw_at,original.join_id,original.outcome_id)`)} as private_hash
    from original order by raw_at::timestamptz desc,cursor_id::uuid desc`;
  const rows = (
    await client.query<{
      item: JsonValue;
      cursor_at: string | null;
      cursor_id: string;
      raw_at: string;
      join_id: string | null;
      outcome_id: string | null;
      private_hash: string;
    }>(sql, [...parameters])
  ).rows;
  const metadata = rows.map((row) => ({
    id: row.cursor_id,
    join_id: row.join_id,
    outcome_id: row.outcome_id,
    raw_at: row.raw_at,
    cursor_at: row.cursor_at,
    cursor_id: row.cursor_id,
    scalar_utf8: (
      scalar(boardVoteObject(row.item), kind === "boards" ? BOARD_KEYS : VOTE_KEYS) +
      BigInt(Buffer.byteLength(row.cursor_id)) +
      BigInt(row.cursor_at === null ? 0 : Buffer.byteLength(row.cursor_at))
    ).toString(),
    observation_sha256: row.private_hash
  }));
  return {
    rows: rows.map((row) => ({
      item: row.item,
      cursor_at: row.cursor_at,
      cursor_id: row.cursor_id
    })),
    metadata
  };
}

export async function originalProxyStatus(
  client: PoolClient,
  voteId: string,
  memberId: string,
  principalId: string
) {
  const original = (
    await client.query<{ items: JsonValue[] }>(ORIGINAL_PROXY_SQL, [voteId, memberId, principalId])
  ).rows[0];
  if (!original) throw new Error("original proxy aggregate is absent");
  // The raw-time lookup is restricted to the exact original authorized grant IDs.
  const sql = `with original as materialized (${ORIGINAL_PROXY_SQL}), ordered as (
    select entry.value as item,entry.ordinality from original cross join lateral jsonb_array_elements(original.items) with ordinality as entry(value,ordinality)
  ), hashes as (
    select ordered.ordinality,${hash(`jsonb_build_array(${entries(GRANT_FLAT_KEYS, "ordered.item")},${REVOCATION_KEYS.map((key) => `ordered.item->'revocation'->'${key}'`).join(",")},grant_row.granted_at::text)`)} as row_hash
    from ordered join proxy_grants as grant_row on grant_row.id=(ordered.item->>'grant_id')::uuid
  ) select count(*)::text as count,${hash("coalesce(string_agg(row_hash,'' order by ordinality),'')")} as observation_sha256 from hashes`;
  const observed = (
    await client.query<{ count: string; observation_sha256: string }>(sql, [
      voteId,
      memberId,
      principalId
    ])
  ).rows[0];
  if (!observed || BigInt(observed.count) !== BigInt(original.items.length))
    throw new Error("original proxy private lookup mismatch");
  let s = BigInt(Buffer.byteLength(voteId) + Buffer.byteLength(memberId)),
    revocations = 0;
  for (const value of original.items) {
    const item = boardVoteObject(value);
    s += scalar(item, GRANT_FLAT_KEYS);
    if (item.revocation !== null) {
      revocations += 1;
      s += scalar(boardVoteObject(item.revocation), REVOCATION_KEYS);
    }
  }
  return {
    items: original.items,
    metadata: {
      vote_id: voteId,
      member_id: memberId,
      principal_id: principalId,
      grant_count: String(original.items.length),
      revocation_count: String(revocations),
      scalar_utf8: s.toString(),
      observation_sha256: observed.observation_sha256
    }
  };
}

export async function originalVoteLineage(client: PoolClient, voteId: string) {
  const sql = `with original as materialized (${ORIGINAL_VOTE_LINEAGE_SQL}), ordered as (
    select entry.value as item,entry.ordinality from original cross join lateral jsonb_array_elements(original.items) with ordinality as entry(value,ordinality)
  ) select ordered.item,supersession.created_at::text as raw_at,
    octet_length(convert_to((ordered.item->'changed_component_classes')::text,'UTF8'))::text as json_utf8,
    (ordered.item->'changed_component_classes')::text as normalized_array,
    ${hash(`jsonb_build_array(${entries(LINEAGE_FLAT_KEYS, "ordered.item")},${hash("ordered.item->'changed_component_classes'")},supersession.created_at::text)`)} as private_hash
    from ordered join vote_supersessions as supersession on supersession.id=(ordered.item->>'supersession_id')::uuid order by ordered.ordinality`;
  const rows = (
    await client.query<{
      item: JsonValue;
      raw_at: string;
      json_utf8: string;
      normalized_array: string;
      private_hash: string;
    }>(sql, [voteId])
  ).rows;
  const metadata = rows.map((row) => {
    const item = boardVoteObject(row.item),
      value = item.changed_component_classes;
    if (!Array.isArray(value) || Buffer.byteLength(row.normalized_array) !== Number(row.json_utf8))
      throw new Error("original lineage array mismatch");
    return {
      supersession_id: String(item.supersession_id),
      old_vote_id: String(item.old_vote_id),
      new_vote_id: String(item.new_vote_id),
      raw_at: row.raw_at,
      scalar_utf8: scalar(item, LINEAGE_FLAT_KEYS).toString(),
      json_utf8: row.json_utf8,
      json_containers: String(boardVoteGraph([value]).containers),
      observation_sha256: row.private_hash
    };
  });
  return {
    items: rows.map((row) => row.item),
    metadata,
    normalizedArrays: rows.map((row) => row.normalized_array)
  };
}
