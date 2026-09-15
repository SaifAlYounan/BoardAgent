import { createHmac, timingSafeEqual } from "node:crypto";

import {
  FeedCursorPayloadSchema,
  PendingActionDeltaSchema,
  canonicalJson,
  canonicalJsonFromText,
  type FeedCursorPayload,
  type PendingActionDelta
} from "@boardagent/contracts";

function assertCursorKey(key: Uint8Array): void {
  if (key.byteLength < 32) throw new RangeError("feed cursor key must contain at least 32 bytes");
}

export function encodeFeedCursor(payloadInput: FeedCursorPayload, key: Uint8Array): string {
  assertCursorKey(key);
  const payload = FeedCursorPayloadSchema.parse(payloadInput);
  const body = Buffer.from(canonicalJson(payload)).toString("base64url");
  const signature = createHmac("sha256", key).update(body).digest("base64url");
  return `${body}.${signature}`;
}

export function decodeFeedCursor(cursor: string, key: Uint8Array): FeedCursorPayload {
  assertCursorKey(key);
  const parts = cursor.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error("invalid feed cursor framing");
  const [body, suppliedEncoded] = parts as [string, string];
  const supplied = Buffer.from(suppliedEncoded, "base64url");
  if (supplied.toString("base64url") !== suppliedEncoded) {
    throw new Error("invalid feed cursor signature encoding");
  }
  const expected = createHmac("sha256", key).update(body).digest();
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new Error("invalid feed cursor signature");
  }
  const raw = Buffer.from(body, "base64url");
  if (raw.toString("base64url") !== body) throw new Error("invalid feed cursor body encoding");
  const canonical = canonicalJsonFromText(raw);
  if (canonical !== raw.toString("utf8")) throw new Error("feed cursor body is not canonical");
  return FeedCursorPayloadSchema.parse(JSON.parse(canonical) as unknown);
}

export interface EntitledPendingDelta {
  readonly memberId: string;
  readonly boardId: string;
  readonly delta: PendingActionDelta;
}

export interface FeedReadContext {
  readonly memberId: string;
  readonly boardId: string | null;
  readonly entitlementGeneration: number;
  readonly limit: number;
}

export function listEntitledDeltas(
  rows: readonly EntitledPendingDelta[],
  cursorInput: FeedCursorPayload,
  context: FeedReadContext
): readonly PendingActionDelta[] {
  const cursor = FeedCursorPayloadSchema.parse(cursorInput);
  if (cursor.memberId !== context.memberId) throw new Error("feed cursor member mismatch");
  if (cursor.boardId !== context.boardId) throw new Error("feed cursor board mismatch");
  if (cursor.entitlementGeneration !== context.entitlementGeneration) {
    throw new Error("feed cursor entitlement generation mismatch");
  }
  if (!Number.isSafeInteger(context.limit) || context.limit < 1 || context.limit > 1_000) {
    throw new RangeError("feed limit must be between 1 and 1000");
  }

  const seen = new Set<string>();
  const validated = rows.map((row) => {
    const delta = PendingActionDeltaSchema.parse(row.delta);
    const key = `${row.memberId}:${delta.sequence}`;
    if (seen.has(key)) throw new Error(`duplicate feed sequence: ${delta.sequence}`);
    seen.add(key);
    return { ...row, delta };
  });
  const after = BigInt(cursor.afterSequence);
  return validated
    .filter(
      (row) =>
        row.memberId === context.memberId &&
        (context.boardId === null || row.boardId === context.boardId) &&
        row.delta.entitlementGeneration === context.entitlementGeneration &&
        BigInt(row.delta.sequence) > after
    )
    .toSorted((left, right) => {
      const lengthOrder = left.delta.sequence.length - right.delta.sequence.length;
      return lengthOrder || left.delta.sequence.localeCompare(right.delta.sequence);
    })
    .slice(0, context.limit)
    .map((row) => row.delta);
}
