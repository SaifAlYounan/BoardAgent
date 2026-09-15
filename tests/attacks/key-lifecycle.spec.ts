import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  signCheckpoint,
  verifyCheckpoint,
  type AuditCheckpointPayload
} from "../../lib/audit/src/checkpoint.js";

const payload: AuditCheckpointPayload = {
  schema: "boardagent.audit.checkpoint.v1",
  checkpointId: "018f0000-0000-7000-8000-000000000001",
  instanceId: "018f0000-0000-7000-8000-000000000002",
  organizationId: "018f0000-0000-7000-8000-000000000003",
  auditSchema: "boardagent.audit-event.v1",
  firstSequence: "1",
  lastSequence: "1000",
  firstEventSha256: "a".repeat(64),
  lastEventSha256: "b".repeat(64),
  issuedAt: "2026-09-04T00:00:00Z",
  signingKeyId: "018f0000-0000-7000-8000-000000000004",
  keyId: "evidence-2026-09"
};

describe("TH-40 evidence-key lifecycle", () => {
  it("accepts only the trusted historical key and fails closed on key or payload drift", () => {
    const active = generateKeyPairSync("ed25519");
    const attacker = generateKeyPairSync("ed25519");
    const checkpoint = signCheckpoint(payload, active.privateKey);
    expect(verifyCheckpoint(checkpoint, active.publicKey)).toBe(true);
    expect(verifyCheckpoint(checkpoint, attacker.publicKey)).toBe(false);
    expect(
      verifyCheckpoint(
        { ...checkpoint, payload: { ...checkpoint.payload, keyId: "compromised-key" } },
        active.publicKey
      )
    ).toBe(false);
    expect(
      verifyCheckpoint(
        { ...checkpoint, payload: { ...checkpoint.payload, lastEventSha256: "c".repeat(64) } },
        active.publicKey
      )
    ).toBe(false);
  });
});
