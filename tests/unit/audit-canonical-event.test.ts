import fc from "fast-check";
import { expect, it } from "vitest";
import {
  AuditChainVerifier,
  AuditEventBodySchema,
  appendEvent,
  type AuditEvent,
  type AuditEventBody
} from "../../lib/audit/src/index.js";
import { canonicalJson } from "../../lib/contracts/src/index.js";

const body: AuditEventBody = {
  eventId: "018f0000-0000-7000-8000-000000000001",
  eventType: "context_read",
  actorMemberId: null,
  actorClientId: null,
  tokenJti: null,
  entityType: "context",
  entityId: "canonical-case",
  boardId: null,
  occurredAt: "2026-09-09T08:00:00Z",
  origin: "worker",
  details: {},
  schemaVersion: 1
};
function input(event: AuditEvent, payload: unknown = body) {
  return {
    canonicalPayload: Buffer.from(canonicalJson(payload)),
    sequence: event.sequence,
    previousHash: event.previousHash,
    eventHash: event.eventHash
  };
}

it("matches the existing chain oracle for 1000 nested event bodies and their hashes", () => {
  fc.assert(
    fc.property(fc.jsonValue(), (value) => {
      const changed = AuditEventBodySchema.parse({ ...body, details: { value } });
      const event = appendEvent(undefined, changed);
      const original = new AuditChainVerifier();
      original.add(event);
      const canonical = new AuditChainVerifier();
      expect(canonical.addCanonicalEvent(input(event, changed))).toEqual({ event });
      expect(canonical.finish({ count: 1n, headHash: event.eventHash })).toEqual(
        original.finish({ count: 1n, headHash: event.eventHash })
      );
    }),
    { seed: 0x41554341, numRuns: 1000, endOnFailure: true }
  );
});

it("retains sequence, link, event-hash and truncation failures without an unchecked intake", () => {
  const event = appendEvent(undefined, body);
  for (const changed of [
    event,
    { ...event, sequence: 0n },
    { ...event, sequence: 2n },
    { ...event, previousHash: "a".repeat(64) },
    { ...event, previousHash: "not-hex" },
    { ...event, eventHash: "f".repeat(64) },
    { ...event, eventHash: "not-hex" }
  ]) {
    const original = new AuditChainVerifier();
    original.add(changed);
    const canonical = new AuditChainVerifier();
    canonical.addCanonicalEvent(input(changed));
    expect(canonical.finish({ count: 1n, headHash: event.eventHash })).toEqual(
      original.finish({ count: 1n, headHash: event.eventHash })
    );
    expect(canonical.finish({ count: 2n, headHash: event.eventHash })).toEqual(
      original.finish({ count: 2n, headHash: event.eventHash })
    );
  }
});

it("refuses malformed, noncanonical and invalid-schema bytes and keeps finish failed", () => {
  const event = appendEvent(undefined, body);
  const encoded = canonicalJson(body);
  const cases = [
    ["{", "event_schema_invalid"],
    [canonicalJson({ ...body, unknown: true }), "event_schema_invalid"],
    [canonicalJson({ ...body, eventId: "wrong-id" }), "event_schema_invalid"],
    [canonicalJson({ ...body, eventType: "key_lifecycle_changed" }), "event_schema_invalid"],
    [" " + encoded, "event_manifest_not_canonical"],
    [
      encoded.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'),
      "event_manifest_not_canonical"
    ]
  ];
  for (const [payload, reason] of cases) {
    const verifier = new AuditChainVerifier();
    expect(
      verifier.addCanonicalEvent({ ...input(event), canonicalPayload: Buffer.from(payload!) })
    ).toEqual({ reason });
    expect(verifier.finish()).toMatchObject({ valid: false, reason });
  }
  const unicode = new AuditChainVerifier();
  expect(() =>
    unicode.addCanonicalEvent({
      ...input(event),
      canonicalPayload: Buffer.from(JSON.stringify({ ...body, details: { text: "e\u0301" } }))
    })
  ).toThrow("Unicode NFC");
  expect(unicode.finish()).toMatchObject({ valid: false, reason: "event_manifest_not_canonical" });
});

it("continues canonical decoding after a chain failure and retains its first chain break", () => {
  const first = appendEvent(undefined, body);
  const nextBody = { ...body, eventId: "018f0000-0000-7000-8000-000000000002" };
  const second = appendEvent(first, nextBody);
  const verifier = new AuditChainVerifier();
  expect(verifier.addCanonicalEvent({ ...input(first), eventHash: "f".repeat(64) })).toHaveProperty(
    "event"
  );
  expect(verifier.addCanonicalEvent(input(second, nextBody))).toEqual({ event: second });
  expect(
    verifier.addCanonicalEvent({
      ...input(second, nextBody),
      canonicalPayload: Buffer.from(" " + canonicalJson(nextBody))
    })
  ).toEqual({ reason: "event_manifest_not_canonical" });
  expect(verifier.finish()).toEqual({
    valid: false,
    firstBreakSequence: 1n,
    reason: "event_hash_mismatch"
  });
});
