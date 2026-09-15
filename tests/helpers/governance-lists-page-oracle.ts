import { createHmac } from "node:crypto";
import { expect } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import type {
  OracleGovernanceListKind,
  OriginalGovernancePageRow
} from "./governance-lists-native-oracle.js";

// Independent literal cursor wire format, not the production page/cursor codec.
// Canonical JSON is the public contract serializer; original rows are supplied
// by verbatim legacy SQL, never by the admitted projection loader.
export const governanceListCursorKey = Buffer.alloc(32, 1);
export const governanceListTools = {
  rulesets: "list_ruleset_versions",
  templates: "list_approval_rule_templates",
  matter_types: "list_matter_types"
} as const;
type CursorPrincipal = { readonly organizationId: string; readonly memberId: string };
export function signGovernanceListTailCursor(
  kind: OracleGovernanceListKind,
  selectorId: string,
  lastOriginalRow: OriginalGovernancePageRow,
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
    tool: governanceListTools[kind],
    board_id: selectorId,
    after: canonicalJson({ at: lastOriginalRow.cursor_at, id: lastOriginalRow.cursor_id }),
    expires_at: expiresAt
  });
  return (
    Buffer.from(payload).toString("base64url") +
    "." +
    createHmac("sha256", governanceListCursorKey)
      .update("boardagent.cursor.v1\0")
      .update(payload)
      .digest("base64url")
  );
}
export function verifyGovernanceListCursor(
  kind: OracleGovernanceListKind,
  selectorId: string,
  anchor: OriginalGovernancePageRow,
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
  const expected = signGovernanceListTailCursor(kind, selectorId, anchor, principal, expiry);
  expect(actualCursor).toBe(expected);
  return expected;
}
export function originalGovernanceListEnvelope(
  kind: OracleGovernanceListKind,
  selectorId: string,
  originalRows: readonly OriginalGovernancePageRow[],
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
    nextCursor = verifyGovernanceListCursor(
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
    tool: governanceListTools[kind],
    status: "ok",
    reference: null,
    resource_uri: null,
    data: { items: selected.map((row) => row.item), next_cursor: nextCursor }
  };
}
