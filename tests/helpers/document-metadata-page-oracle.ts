import { createHmac } from "node:crypto";
import { expect } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import type { DocumentOracleKind, DocumentOriginalRow } from "./document-metadata-pg-oracle.js";

// Independent literal cursor wire format, not the production page/cursor codec.
// Canonical JSON is the public contract serializer; original rows are supplied
// by verbatim legacy SQL, never by the admitted projection loader.
export const documentCursorKey = Buffer.alloc(32, 0x4d);
export const documentTools = {
  hash: "get_document_hash",
  validation: "get_document_validation_status",
  versions: "list_document_versions",
  documents: "list_documents"
} as const;
type CursorPrincipal = { readonly organizationId: string; readonly memberId: string };
export function signDocumentTailCursor(
  kind: Extract<DocumentOracleKind, "versions" | "documents">,
  selectorId: string,
  lastOriginalRow: DocumentOriginalRow,
  principal: CursorPrincipal,
  expiresAt: number
): string {
  if (
    typeof lastOriginalRow.cursor_at !== "string" ||
    typeof lastOriginalRow.cursor_id !== "string"
  )
    throw new Error("original cursor anchor requires its actual timestamp and ID");
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0)
    throw new Error("invalid fixture cursor expiry");
  const payload = canonicalJson({
    schema_version: "boardagent.cursor.v1",
    organization_id: principal.organizationId,
    member_id: principal.memberId,
    tool: documentTools[kind],
    board_id: kind === "documents" ? selectorId : null,
    after: canonicalJson({ at: lastOriginalRow.cursor_at, id: lastOriginalRow.cursor_id }),
    expires_at: expiresAt
  });
  return (
    Buffer.from(payload).toString("base64url") +
    "." +
    createHmac("sha256", documentCursorKey)
      .update("boardagent.cursor.v1\0")
      .update(payload)
      .digest("base64url")
  );
}
export function verifyDocumentCursor(
  kind: Extract<DocumentOracleKind, "versions" | "documents">,
  selectorId: string,
  anchor: DocumentOriginalRow,
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
  const expected = signDocumentTailCursor(kind, selectorId, anchor, principal, expiry);
  expect(actualCursor).toBe(expected);
  return expected;
}
export function originalDocumentListEnvelope(
  kind: Extract<DocumentOracleKind, "versions" | "documents">,
  selectorId: string,
  originalRows: readonly DocumentOriginalRow[],
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
    nextCursor = verifyDocumentCursor(
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
    tool: documentTools[kind],
    status: "ok",
    reference: kind === "versions" ? selectorId : null,
    resource_uri: null,
    data: { items: selected.map((row) => row.item), next_cursor: nextCursor }
  };
}

export function originalDocumentPointEnvelope(
  kind: Extract<DocumentOracleKind, "hash" | "validation">,
  reference: string,
  originalRows: readonly DocumentOriginalRow[]
) {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: documentTools[kind],
    status: "ok",
    reference,
    resource_uri: null,
    data:
      kind === "hash"
        ? { document_hash: originalRows[0]?.item ?? null }
        : { validation: originalRows[0]?.item ?? null }
  };
}
