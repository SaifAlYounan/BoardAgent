import { beforeAll, describe, expect, it } from "vitest";

import {
  AUDIT_DOMAIN,
  AuditChainVerifier,
  AuditEventBodySchema,
  GENESIS_HASH,
  appendEvent,
  eventHash,
  verifyChain,
  type AuditEventBody
} from "../../lib/audit/src/event.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;

function body(index: number): AuditEventBody {
  return {
    eventId: id(index),
    eventType: "context_read",
    actorMemberId: null,
    actorClientId: null,
    tokenJti: null,
    entityType: "test",
    entityId: id(10_000 + index),
    boardId: null,
    occurredAt: "2026-08-28T00:00:00Z",
    origin: "mcp",
    details: {
      booleanValue: true,
      nullValue: null,
      numberValue: 1,
      stringValue: "value",
      arrayValue: [true, null, 1, "value"],
      objectValue: { nested: "value" }
    },
    schemaVersion: 1
  };
}

// z.lazy caches its first schema. Initialize outside a test so mutation coverage
// treats that shared initializer as static and checks every subsequent consumer.
beforeAll(() => {
  AuditEventBodySchema.safeParse(body(1));
});

describe("audit event boundary", () => {
  it("retains the first break while consuming later stream rows and supports an empty stream", () => {
    const verifier = new AuditChainVerifier();
    expect(verifier.finish()).toEqual({ valid: true, count: 0n, headHash: GENESIS_HASH });
    const first = appendEvent(undefined, body(1));
    const second = appendEvent(first, body(2));
    expect(verifier.add(first)).toBeUndefined();
    expect(verifier.finish({ count: 1n, headHash: first.eventHash })).toEqual({
      valid: true,
      count: 1n,
      headHash: first.eventHash
    });
    const expected = { valid: false, firstBreakSequence: 2n, reason: "event_hash_mismatch" };
    expect(verifier.add({ ...second, eventHash: "f".repeat(64) })).toEqual(expected);
    expect(verifier.add({ ...first, sequence: 99n })).toEqual(expected);
    expect(verifier.finish({ count: 100n, headHash: GENESIS_HASH })).toEqual(expected);
  });

  it("enforces exact event-body strings, origins, detail keys and JSON values", () => {
    expect(AuditEventBodySchema.parse(body(1))).toEqual(body(1));
    for (const origin of [
      "mcp",
      "oauth",
      "browser",
      "worker",
      "scheduler",
      "migration",
      "restore",
      "cli"
    ]) {
      expect(AuditEventBodySchema.parse({ ...body(1), origin }).origin).toBe(origin);
    }
    expect(
      AuditEventBodySchema.parse({
        ...body(1),
        entityType: `a${"b".repeat(63)}`,
        entityId: "x".repeat(2_048),
        details: { [`a${"B".repeat(127)}`]: "value" }
      }).entityId
    ).toHaveLength(2_048);

    for (const entityType of ["a", "!ab", "ab!", `a${"b".repeat(64)}`]) {
      expect(AuditEventBodySchema.safeParse({ ...body(1), entityType }).success).toBe(false);
    }
    for (const entityId of ["", "x".repeat(2_049)]) {
      expect(AuditEventBodySchema.safeParse({ ...body(1), entityId }).success).toBe(false);
    }
    for (const key of ["!a", "a!", `a${"B".repeat(128)}`]) {
      expect(AuditEventBodySchema.safeParse({ ...body(1), details: { [key]: true } }).success).toBe(
        false
      );
    }
    expect(
      AuditEventBodySchema.safeParse({ ...body(1), details: { value: Number.POSITIVE_INFINITY } })
        .success
    ).toBe(false);
    expect(
      AuditEventBodySchema.safeParse({ ...body(1), details: { value: undefined } }).success
    ).toBe(false);
  });

  it("hashes only positive sequences and canonical previous hashes", () => {
    expect(AUDIT_DOMAIN).toBe("boardagent.audit.event.v1");
    expect(GENESIS_HASH).toBe("0".repeat(64));
    const independentVector: AuditEventBody = {
      eventId: "018f0000-0000-7000-8000-000000000001",
      eventType: "context_read",
      actorMemberId: null,
      actorClientId: null,
      tokenJti: null,
      entityType: "context",
      entityId: "018f0000-0000-7000-8000-000000000002",
      boardId: null,
      occurredAt: "2026-08-28T00:00:00Z",
      origin: "mcp",
      details: {
        requestId: "018f0000-0000-7000-8000-000000000003",
        result: "authorized"
      },
      schemaVersion: 1
    };
    expect(appendEvent(undefined, independentVector).eventHash).toBe(
      "c487a2c6444f605d9981818f7e753147e9e6a8f0f75f42ff689faaeecff59e54"
    );
    const first = appendEvent(undefined, body(1));
    expect(first.sequence).toBe(1n);
    expect(first.previousHash).toBe(GENESIS_HASH);
    expect(first.eventHash).toBe(eventHash(1n, GENESIS_HASH, body(1)));
    expect(() => eventHash(0n, GENESIS_HASH, body(1))).toThrow("audit sequence must be positive");
    expect(() => eventHash(-1n, GENESIS_HASH, body(1))).toThrow("audit sequence must be positive");
    expect(() => eventHash(1n, "not-a-hash", body(1))).toThrow();
  });

  it("returns the exact first chain break for every failure mode", () => {
    const first = appendEvent(undefined, body(1));
    const second = appendEvent(first, body(2));
    expect(verifyChain([first, second])).toEqual({
      valid: true,
      count: 2n,
      headHash: second.eventHash
    });
    expect(verifyChain([])).toEqual({ valid: true, count: 0n, headHash: GENESIS_HASH });
    expect(verifyChain([{ ...first, sequence: 2n }])).toEqual({
      valid: false,
      firstBreakSequence: 1n,
      reason: "sequence_gap_or_reorder"
    });
    expect(verifyChain([{ ...first, previousHash: "f".repeat(64) }])).toEqual({
      valid: false,
      firstBreakSequence: 1n,
      reason: "previous_hash_mismatch"
    });
    expect(verifyChain([{ ...first, origin: "invalid" }])).toEqual({
      valid: false,
      firstBreakSequence: 1n,
      reason: "event_schema_invalid"
    });
    expect(verifyChain([{ ...first, eventHash: "f".repeat(64) }])).toEqual({
      valid: false,
      firstBreakSequence: 1n,
      reason: "event_hash_mismatch"
    });
    expect(verifyChain([first], { count: 2n, headHash: first.eventHash })).toEqual({
      valid: false,
      firstBreakSequence: 2n,
      reason: "truncation_or_extension"
    });
    expect(verifyChain([first], { count: 1n, headHash: "f".repeat(64) })).toEqual({
      valid: false,
      firstBreakSequence: 1n,
      reason: "head_hash_mismatch"
    });
  });
});

// Once a broken link is established, later rows need not be read or decoded.
it("stops reading a chain at the first failure", () => {
  const first = { ...appendEvent(undefined, body(1)), eventHash: "f".repeat(64) };
  const rows = [first, first];
  Object.defineProperty(rows, "1", {
    get() {
      throw new Error("later row must not be read");
    }
  });
  expect(verifyChain(rows)).toEqual({
    valid: false,
    firstBreakSequence: 1n,
    reason: "event_hash_mismatch"
  });
});
