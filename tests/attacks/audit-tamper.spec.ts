import { describe, expect, it } from "vitest";

import { appendEvent, verifyChain, type AuditEventBody } from "../../lib/audit/src/event.js";

function body(index: number): AuditEventBody {
  return {
    eventId: `018f0000-0000-7000-8000-${String(index).padStart(12, "0")}`,
    eventType: "context_read",
    actorMemberId: null,
    actorClientId: null,
    tokenJti: null,
    entityType: "attack_test",
    entityId: `object-${String(index)}`,
    boardId: null,
    occurredAt: "2026-09-04T00:00:00Z",
    origin: "mcp",
    details: { index },
    schemaVersion: 1
  };
}

describe("TH-13 audit tamper detection", () => {
  it("reports the exact first break for edit, reorder, truncation, and head substitution", () => {
    const first = appendEvent(undefined, body(1));
    const second = appendEvent(first, body(2));
    const third = appendEvent(second, body(3));
    const expected = { count: 3n, headHash: third.eventHash };
    expect(verifyChain([first, second, third], expected)).toEqual({
      valid: true,
      count: 3n,
      headHash: third.eventHash
    });
    expect(verifyChain([{ ...first, entityId: "edited" }, second, third], expected)).toMatchObject({
      valid: false,
      firstBreakSequence: 1n,
      reason: "event_hash_mismatch"
    });
    expect(verifyChain([second, first, third], expected)).toMatchObject({
      valid: false,
      firstBreakSequence: 1n,
      reason: "sequence_gap_or_reorder"
    });
    expect(verifyChain([first, second], expected)).toMatchObject({
      valid: false,
      firstBreakSequence: 3n,
      reason: "truncation_or_extension"
    });
    expect(
      verifyChain([first, second, third], { count: 3n, headHash: "f".repeat(64) })
    ).toMatchObject({ valid: false, firstBreakSequence: 3n, reason: "head_hash_mismatch" });
  });
});
