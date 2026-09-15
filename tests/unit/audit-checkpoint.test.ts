import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";
import type { ZodType } from "zod";

import {
  AuditCheckpointPayloadSchema,
  signCheckpoint,
  verifyCheckpoint,
  type AuditCheckpointPayload,
  type PublicJsonWebKey
} from "../../lib/audit/src/index.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;

const payload: AuditCheckpointPayload = {
  schema: "boardagent.audit.checkpoint.v1",
  checkpointId: id(1),
  instanceId: id(2),
  organizationId: id(3),
  auditSchema: "boardagent.audit-event.v1",
  firstSequence: "1",
  lastSequence: "1",
  firstEventSha256: "a".repeat(64),
  lastEventSha256: "b".repeat(64),
  issuedAt: "2026-08-28T00:00:00Z",
  signingKeyId: id(4),
  keyId: "evidence-1"
};

function expectCustomIssue(schema: ZodType, input: unknown, message: string): void {
  const result = schema.safeParse(input);
  expect(result.success).toBe(false);
  if (result.success) throw new Error("expected schema rejection");
  expect(
    result.error.issues.map((issue) => ({
      code: issue.code,
      path: issue.path,
      message: issue.message
    }))
  ).toEqual([{ code: "custom", path: [], message }]);
}

describe("audit checkpoint boundary", () => {
  it("enforces canonical sequence, key-id and exact 1,000-event bounds", () => {
    expect(AuditCheckpointPayloadSchema.parse(payload)).toEqual(payload);
    expect(
      AuditCheckpointPayloadSchema.parse({
        ...payload,
        firstSequence: "1",
        lastSequence: "1000",
        keyId: "k".repeat(128)
      }).lastSequence
    ).toBe("1000");
    expect(
      AuditCheckpointPayloadSchema.parse({
        ...payload,
        firstSequence: "2",
        lastSequence: "1000"
      }).firstSequence
    ).toBe("2");

    for (const firstSequence of ["0", "01", "x1", "1x", "1.0", "-1"]) {
      expect(AuditCheckpointPayloadSchema.safeParse({ ...payload, firstSequence }).success).toBe(
        false
      );
    }
    expect(() =>
      AuditCheckpointPayloadSchema.safeParse({ ...payload, lastSequence: "x1" })
    ).not.toThrow();
    expect(AuditCheckpointPayloadSchema.safeParse({ ...payload, lastSequence: "x1" }).success).toBe(
      false
    );
    for (const keyId of ["", `!${payload.keyId}`, `${payload.keyId}!`, "k".repeat(129)]) {
      expect(AuditCheckpointPayloadSchema.safeParse({ ...payload, keyId }).success).toBe(false);
    }
    expectCustomIssue(
      AuditCheckpointPayloadSchema,
      { ...payload, firstSequence: "2", lastSequence: "1" },
      "checkpoint sequence range is inverted"
    );
    expectCustomIssue(
      AuditCheckpointPayloadSchema,
      { ...payload, firstSequence: "1", lastSequence: "1001" },
      "checkpoint may cover at most 1,000 audit events"
    );
  });

  it("signs and verifies key objects, PEM and JWK while failing closed", () => {
    const evidence = generateKeyPairSync("ed25519");
    const privatePem = evidence.privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString("utf8");
    const publicPem = evidence.publicKey.export({ format: "pem", type: "spki" }).toString("utf8");
    const publicJwk = evidence.publicKey.export({ format: "jwk" }) as PublicJsonWebKey;

    const checkpoint = signCheckpoint(payload, evidence.privateKey);
    const pemCheckpoint = signCheckpoint(payload, privatePem);
    expect(pemCheckpoint).toEqual(checkpoint);
    expect(verifyCheckpoint(checkpoint, evidence.publicKey)).toBe(true);
    expect(verifyCheckpoint(checkpoint, publicPem)).toBe(true);
    expect(verifyCheckpoint(checkpoint, publicJwk)).toBe(true);

    expect(
      verifyCheckpoint(
        { ...checkpoint, signatureBase64Url: Buffer.alloc(63).toString("base64url") },
        evidence.publicKey
      )
    ).toBe(false);
    expect(
      verifyCheckpoint(
        { ...checkpoint, signatureBase64Url: Buffer.alloc(64).toString("base64url") },
        evidence.publicKey
      )
    ).toBe(false);
    expect(
      verifyCheckpoint(
        { ...checkpoint, payload: { ...payload, firstSequence: "0" } },
        evidence.publicKey
      )
    ).toBe(false);
    expect(verifyCheckpoint(checkpoint, "not a public key")).toBe(false);
  });
});
