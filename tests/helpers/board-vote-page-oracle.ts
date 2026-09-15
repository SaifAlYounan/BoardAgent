import { createHmac } from "node:crypto";
import { expect } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import type { BoardVoteNativeKind, BoardVoteNativePageRow } from "./board-vote-native-oracle.js";

// Independent literal cursor wire format, not the production page/cursor codec.
// Canonical JSON is the public contract serializer; original rows are supplied
// by verbatim legacy SQL, never by the admitted projection loader.
export const boardVoteCursorKey = Buffer.alloc(32, 1);
export const boardVoteTools = {
  boards: "list_my_boards",
  votes: "list_votes",
  proxy: "get_proxy_status",
  lineage: "get_vote_lineage"
} as const;
type CursorPrincipal = { readonly organizationId: string; readonly memberId: string };
export function signBoardVoteCursor(
  kind: Extract<BoardVoteNativeKind, "boards" | "votes">,
  selectorId: string,
  lastOriginalRow: BoardVoteNativePageRow,
  principal: CursorPrincipal,
  expiresAt: number
): string {
  if (
    typeof lastOriginalRow.cursor_at !== "string" ||
    typeof lastOriginalRow.cursor_id !== "string"
  )
    throw new Error("original cursor anchor requires its actual ordering value and ID");
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0)
    throw new Error("invalid fixture cursor expiry");
  const payload = canonicalJson({
    schema_version: "boardagent.cursor.v1",
    organization_id: principal.organizationId,
    member_id: principal.memberId,
    tool: boardVoteTools[kind],
    board_id: kind === "boards" ? null : selectorId,
    after: canonicalJson({ at: lastOriginalRow.cursor_at, id: lastOriginalRow.cursor_id }),
    expires_at: expiresAt
  });
  return (
    Buffer.from(payload).toString("base64url") +
    "." +
    createHmac("sha256", boardVoteCursorKey)
      .update("boardagent.cursor.v1\0")
      .update(payload)
      .digest("base64url")
  );
}
export function verifyBoardVoteCursor(
  kind: Extract<BoardVoteNativeKind, "boards" | "votes">,
  selectorId: string,
  anchor: BoardVoteNativePageRow,
  principal: CursorPrincipal,
  actualCursor: unknown,
  beforeSeconds: number,
  afterSeconds: number
): string {
  if (typeof actualCursor !== "string" || actualCursor.split(".").length !== 2)
    throw new Error("expected complete original cursor");
  const encoded = actualCursor.split(".")[0];
  if (!encoded) throw new Error("cursor payload absent");
  const payload: unknown = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  if (payload === null || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("expected original cursor payload");
  const expiry = (payload as Record<string, unknown>)["expires_at"];
  if (typeof expiry !== "number") throw new Error("expected original cursor expiry");
  expect(expiry).toBeGreaterThanOrEqual(beforeSeconds + 86400);
  expect(expiry).toBeLessThanOrEqual(afterSeconds + 86400);
  expect(expiry).toBeGreaterThan(Math.floor(Date.now() / 1000));
  const expected = signBoardVoteCursor(kind, selectorId, anchor, principal, expiry);
  expect(actualCursor).toBe(expected);
  return expected;
}
export function originalBoardVotePageEnvelope(
  kind: Extract<BoardVoteNativeKind, "boards" | "votes">,
  selectorId: string,
  originalRows: readonly BoardVoteNativePageRow[],
  limit: number,
  principal: CursorPrincipal,
  nextCursorFromActual: unknown,
  beforeSeconds: number,
  afterSeconds: number
) {
  const selected = originalRows.slice(0, limit),
    last = selected.at(-1);
  let nextCursor: string | null = null;
  if (originalRows.length > limit && last)
    nextCursor = verifyBoardVoteCursor(
      kind,
      selectorId,
      last,
      principal,
      nextCursorFromActual,
      beforeSeconds,
      afterSeconds
    );
  else expect(nextCursorFromActual).toBeNull();
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: boardVoteTools[kind],
    status: "ok",
    reference: null,
    resource_uri: null,
    data: { items: selected.map((row) => row.item), next_cursor: nextCursor }
  };
}

export function originalBoardVoteAggregateEnvelope(
  kind: Extract<BoardVoteNativeKind, "proxy" | "lineage">,
  voteId: string,
  memberId: string | null,
  items: readonly import("../../lib/contracts/src/canonical.js").JsonValue[]
) {
  if (kind === "proxy" && memberId === null)
    throw new Error("proxy result requires selected member");
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: boardVoteTools[kind],
    status: "ok",
    reference: voteId,
    resource_uri: null,
    data:
      kind === "proxy"
        ? { vote_id: voteId, member_id: memberId, grants: items }
        : { vote_id: voteId, lineage: items }
  };
}
