import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  appendEvent,
  eventHash,
  verifyChain,
  type AuditEventBody
} from "../../lib/audit/src/index.js";
import {
  canonicalJson,
  canonicalJsonFromText,
  canonicalSha256
} from "../../lib/contracts/src/index.js";

describe("canonical and audit-event properties", () => {
  it("preserves canonical bytes and event identity across 100,000 seeded key orders", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 1_000_000_000 }),
        fc.stringMatching(/^[A-Za-z0-9 _-]{0,32}$/u),
        fc.boolean(),
        (value, label, flag) => {
          const forward = { value, label, flag };
          const reverse = { flag, label, value };
          const canonical = canonicalJson(forward);
          expect(canonicalJson(reverse)).toBe(canonical);
          expect(canonicalJsonFromText(canonical)).toBe(canonical);
          expect(canonicalSha256(reverse)).toBe(canonicalSha256(forward));

          const body: AuditEventBody = {
            eventId: "018f0000-0000-7000-8000-000000000001",
            eventType: "context_read",
            actorMemberId: null,
            actorClientId: null,
            tokenJti: null,
            entityType: "property_case",
            entityId: "canonical-event",
            boardId: null,
            occurredAt: "2026-08-28T00:00:00Z",
            origin: "mcp",
            details: forward,
            schemaVersion: 1
          };
          const reordered: AuditEventBody = { ...body, details: reverse };
          const event = appendEvent(undefined, body);
          expect(eventHash(1n, event.previousHash, reordered)).toBe(event.eventHash);
          expect(verifyChain([event], { count: 1n, headHash: event.eventHash })).toEqual({
            valid: true,
            count: 1n,
            headHash: event.eventHash
          });
        }
      ),
      { seed: 0x43414e4f, numRuns: 100_000, endOnFailure: true }
    );
  }, 30_000);
});
