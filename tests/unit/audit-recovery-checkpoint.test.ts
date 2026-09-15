import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { AuditCheckpointPayloadSchema } from "../../lib/audit/src/checkpoint.js";
import {
  AuditRecoveryRequestSchema,
  AuditRecoveryEvidenceSetSchema,
  SignedAuditRecoveryCheckpointSchema,
  AuditRecoveryCheckpointPayloadSchema,
  signRecoveryCheckpoint,
  verifyRecoveryCheckpoint
} from "../../lib/audit/src/recovery-checkpoint.js";

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, "0")}`;
const request = {
  schemaVersion: "boardagent.audit-recovery-request.v1" as const,
  recoveryId: id(1),
  instanceId: id(2),
  organizationId: id(3),
  firstSequence: "101",
  lastSequence: "1100",
  firstEventSha256: "a".repeat(64),
  headSha256: "b".repeat(64),
  signingKeyId: id(4),
  keyId: "evidence-recovery-1",
  firstUncoveredEventAt: "2026-09-08T09:00:00.000001Z",
  preparedAt: "2026-09-08T10:00:00.000001Z",
  expiresAt: "2026-09-08T10:30:00.000001Z",
  operatorReference: "Synthetic operator / incident 17",
  reason: "The signing worker stopped during a power outage."
};
const payload = {
  schema: "boardagent.audit.recovery-checkpoint.v1" as const,
  checkpointId: id(5),
  instanceId: id(2),
  organizationId: id(3),
  auditSchema: "boardagent.audit-event.v1" as const,
  firstSequence: "101",
  lastSequence: "1100",
  firstEventSha256: "a".repeat(64),
  lastEventSha256: "b".repeat(64),
  issuedAt: "2026-09-08T10:00:01.000002Z",
  signingKeyId: id(4),
  keyId: "evidence-recovery-1",
  recovery: {
    request,
    requestSha256: canonicalSha256(request),
    firstCoveredEventAt: request.firstUncoveredEventAt,
    missedByMicroseconds: "2701000001"
  }
};

describe("explicit audit recovery checkpoint format", () => {
  it("signs the exact operator request and truthful microsecond deadline miss, while v1 refuses it", () => {
    expect(AuditRecoveryRequestSchema.parse(request)).toEqual(request);
    expect(AuditRecoveryCheckpointPayloadSchema.parse(payload)).toEqual(payload);
    const keys = generateKeyPairSync("ed25519");
    const signed = signRecoveryCheckpoint(payload, keys.privateKey);
    expect(verifyRecoveryCheckpoint(signed, keys.publicKey)).toBe(true);
    expect(AuditCheckpointPayloadSchema.safeParse(payload).success).toBe(false);
    expect(
      verifyRecoveryCheckpoint(
        {
          ...signed,
          payload: {
            ...payload,
            recovery: {
              ...payload.recovery,
              request: { ...request, reason: "Changed after signing" }
            }
          }
        },
        keys.publicKey
      )
    ).toBe(false);
    expect(verifyRecoveryCheckpoint(signed, generateKeyPairSync("ed25519").publicKey)).toBe(false);
  });

  it("refuses forged bindings, omitted findings, changed request hashes and unsupported ranges", () => {
    const invalid = [
      { ...payload, instanceId: id(6) },
      { ...payload, organizationId: id(6) },
      { ...payload, signingKeyId: id(6) },
      { ...payload, keyId: "another-key" },
      { ...payload, firstSequence: "100" },
      { ...payload, lastSequence: "1101" },
      { ...payload, firstEventSha256: "c".repeat(64) },
      { ...payload, lastEventSha256: "c".repeat(64) },
      { ...payload, issuedAt: "2026-09-08T09:59:59Z" },
      { ...payload, issuedAt: request.expiresAt },
      { ...payload, issuedAt: "2026-09-08T10:30:00.000002Z" },
      { ...payload, recovery: { ...payload.recovery, missedByMicroseconds: "2701000000" } },
      { ...payload, recovery: { ...payload.recovery, missedByMicroseconds: "0" } },
      { ...payload, recovery: { ...payload.recovery, requestSha256: "d".repeat(64) } },
      {
        ...payload,
        recovery: { ...payload.recovery, firstCoveredEventAt: "2026-09-08T09:00:00.000002Z" }
      },
      { ...payload, recovery: { request, requestSha256: canonicalSha256(request) } },
      { ...payload, silentlyCompliant: true }
    ];
    for (const value of invalid)
      expect(AuditRecoveryCheckpointPayloadSchema.safeParse(value).success).toBe(false);
    const expandedRequest = { ...request, lastSequence: "1101" };
    expect(
      AuditRecoveryCheckpointPayloadSchema.safeParse({
        ...payload,
        lastSequence: "1101",
        recovery: {
          ...payload.recovery,
          request: expandedRequest,
          requestSha256: canonicalSha256(expandedRequest)
        }
      }).success
    ).toBe(false);
    for (const value of [
      { ...request, firstSequence: "0" },
      { ...request, lastSequence: "1000101" },
      { ...request, reason: " " },
      { ...request, operatorReference: "" },
      { ...request, preparedAt: "2026-02-30T10:00:00Z" },
      { ...request, expiresAt: "2026-09-08T10:30:00.000002Z" },
      { ...request, firstUncoveredEventAt: "2026-09-08T09:45:00.000001Z" },
      { ...request, operatorReference: "Pretend\u0000operator" }
    ])
      expect(AuditRecoveryRequestSchema.safeParse(value).success).toBe(false);
  });

  it("allows bounded interior segments and refuses noncanonical signatures and inappropriate keys", () => {
    const tail = {
      ...payload,
      firstSequence: "201",
      firstEventSha256: "c".repeat(64),
      recovery: {
        ...payload.recovery,
        firstCoveredEventAt: "2026-09-08T09:30:00.000002Z",
        missedByMicroseconds: "901000000"
      }
    };
    expect(AuditRecoveryCheckpointPayloadSchema.parse(tail)).toEqual(tail);
    const keys = generateKeyPairSync("ed25519");
    const signed = signRecoveryCheckpoint(tail, keys.privateKey);
    for (const signature of [
      signed.signatureBase64Url + "=",
      "!" + signed.signatureBase64Url,
      Buffer.alloc(63).toString("base64url")
    ]) {
      expect(
        verifyRecoveryCheckpoint({ ...signed, signatureBase64Url: signature }, keys.publicKey)
      ).toBe(false);
    }
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    expect(() => signRecoveryCheckpoint(payload, other.privateKey)).toThrow();
    expect(() => signRecoveryCheckpoint(payload, keys.publicKey)).toThrow();
    expect(verifyRecoveryCheckpoint(signed, keys.privateKey)).toBe(false);
  });
});

describe("recovery request and evidence boundaries", () => {
  it("allows singleton ranges, the bigint endpoint and timestamps without fractions", () => {
    for (const firstSequence of ["101", "9223372036854775807"]) {
      const value = { ...request, firstSequence, lastSequence: firstSequence };
      expect(AuditRecoveryRequestSchema.parse(value)).toEqual(value);
    }
    const whole = {
      ...request,
      firstUncoveredEventAt: "2026-09-08T09:00:00Z",
      preparedAt: "2026-09-08T10:00:00Z",
      expiresAt: "2026-09-08T10:30:00Z"
    };
    expect(AuditRecoveryRequestSchema.parse(whole)).toEqual(whole);
    for (const fraction of ["1", "12", "123", "1234", "12345", "123456"]) {
      const value = {
        ...whole,
        firstUncoveredEventAt: `2026-09-08T09:00:00.${fraction}Z`,
        preparedAt: `2026-09-08T10:00:00.${fraction}Z`,
        expiresAt: `2026-09-08T10:30:00.${fraction}Z`
      };
      expect(AuditRecoveryRequestSchema.parse(value)).toEqual(value);
    }
    for (const bad of ["9223372036854775808", "0101", "101\n", " 101"]) {
      const result = AuditRecoveryRequestSchema.safeParse({
        ...request,
        firstSequence: bad,
        lastSequence: bad
      });
      expect(result.success).toBe(false);
      if (!result.success)
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({ message: "expected a positive PostgreSQL bigint sequence" })
        );
    }
    expect(AuditRecoveryRequestSchema.safeParse({ ...request, lastSequence: "100" }).success).toBe(
      false
    );
  });
  it("rejects impossible calendar dates, malformed timestamp bytes and noncanonical operator text", () => {
    for (const firstUncoveredEventAt of ["2026-02-30T09:00:00Z", "2026-99-01T09:00:00Z"]) {
      const result = AuditRecoveryRequestSchema.safeParse({ ...request, firstUncoveredEventAt });
      expect(result.success).toBe(false);
      if (!result.success)
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({
            message: "timestamp must identify a real UTC calendar instant"
          })
        );
    }
    for (const firstUncoveredEventAt of [
      " " + request.firstUncoveredEventAt,
      request.firstUncoveredEventAt + "!",
      "not-a-date"
    ]) {
      const result = AuditRecoveryRequestSchema.safeParse({ ...request, firstUncoveredEventAt });
      expect(result.success).toBe(false);
    }
    for (const text of [" leading", "trailing ", "e\u0301", "x\u007fy", "x\u001fy"])
      for (const field of ["reason", "operatorReference"] as const)
        expect(AuditRecoveryRequestSchema.safeParse({ ...request, [field]: text }).success).toBe(
          false
        );
    for (const keyId of ["!key", "key!"])
      expect(AuditRecoveryRequestSchema.safeParse({ ...request, keyId }).success).toBe(false);
  });
  it("isolates segment bounds and the inclusive prepared / exclusive expiry instants", () => {
    const interior = { ...payload, lastSequence: "500" };
    expect(AuditRecoveryCheckpointPayloadSchema.parse(interior)).toEqual(interior);
    expect(
      AuditRecoveryCheckpointPayloadSchema.safeParse({ ...interior, firstSequence: "100" }).success
    ).toBe(false);
    const tail = { ...payload, firstSequence: "501" };
    expect(AuditRecoveryCheckpointPayloadSchema.parse(tail)).toEqual(tail);
    expect(
      AuditRecoveryCheckpointPayloadSchema.safeParse({ ...tail, lastSequence: "1101" }).success
    ).toBe(false);
    for (const [issuedAt, missedByMicroseconds, valid] of [
      [request.preparedAt, "2700000000", true],
      ["2026-09-08T10:30:00.000000Z", "4499999999", true],
      ["2026-09-08T10:00:00.000000Z", "2699999999", false],
      [request.expiresAt, "4500000000", false]
    ] as const) {
      expect(
        AuditRecoveryCheckpointPayloadSchema.safeParse({
          ...payload,
          issuedAt,
          recovery: { ...payload.recovery, missedByMicroseconds }
        }).success
      ).toBe(valid);
    }
    for (const missedByMicroseconds of ["02701000001", "2701000001\n"])
      expect(
        AuditRecoveryCheckpointPayloadSchema.safeParse({
          ...payload,
          recovery: { ...payload.recovery, missedByMicroseconds }
        }).success
      ).toBe(false);
    const result = AuditRecoveryCheckpointPayloadSchema.safeParse({
      ...payload,
      recovery: { ...payload.recovery, firstCoveredEventAt: "not-a-date" }
    });
    expect(result.success).toBe(false);
  });
  it("requires one original signed first segment per recovery in strict sequence order", () => {
    const keys = generateKeyPairSync("ed25519");
    const first = signRecoveryCheckpoint(payload, keys.privateKey);
    const nextRequest = {
      ...request,
      recoveryId: id(11),
      firstSequence: "1101",
      lastSequence: "2100"
    };
    const next = signRecoveryCheckpoint(
      {
        ...payload,
        checkpointId: id(12),
        firstSequence: "1101",
        lastSequence: "2100",
        recovery: {
          ...payload.recovery,
          request: nextRequest,
          requestSha256: canonicalSha256(nextRequest)
        }
      },
      keys.privateKey
    );
    expect(AuditRecoveryEvidenceSetSchema.parse([first, next])).toEqual([first, next]);
    const interior = signRecoveryCheckpoint({ ...payload, firstSequence: "201" }, keys.privateKey);
    const equalRequest = { ...request, recoveryId: id(13) };
    const equal = signRecoveryCheckpoint(
      {
        ...payload,
        checkpointId: id(14),
        recovery: {
          ...payload.recovery,
          request: equalRequest,
          requestSha256: canonicalSha256(equalRequest)
        }
      },
      keys.privateKey
    );
    const duplicateRequest = { ...nextRequest, recoveryId: request.recoveryId };
    const duplicateId = signRecoveryCheckpoint(
      {
        ...next.payload,
        recovery: {
          ...next.payload.recovery,
          request: duplicateRequest,
          requestSha256: canonicalSha256(duplicateRequest)
        }
      },
      keys.privateKey
    );
    expect(AuditRecoveryEvidenceSetSchema.safeParse([]).success).toBe(false);
    for (const values of [[interior], [first, duplicateId], [first, equal], [next, first]]) {
      const result = AuditRecoveryEvidenceSetSchema.safeParse(values);
      expect(result.success).toBe(false);
      if (!result.success)
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({
            message:
              "recovery evidence must contain one first signed checkpoint per recovery, in audit order"
          })
        );
    }
  });
  it("rejects wrong key metadata and alternate encodings of the same signature bytes", () => {
    const keys = generateKeyPairSync("ed25519"),
      signed = signRecoveryCheckpoint(payload, keys.privateKey);
    expect(() => signRecoveryCheckpoint(payload, keys.publicKey)).toThrow(
      "audit recovery checkpoint requires an Ed25519 private key"
    );
    const label = createPublicKey(keys.privateKey);
    Object.defineProperty(label, "asymmetricKeyType", { value: "ec" });
    expect(verifyRecoveryCheckpoint(signed, label)).toBe(false);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const alteredPadding =
      signed.signatureBase64Url.slice(0, -1) +
      alphabet[alphabet.indexOf(signed.signatureBase64Url.at(-1)!) + 1];
    expect(Buffer.from(alteredPadding, "base64url")).toEqual(
      Buffer.from(signed.signatureBase64Url, "base64url")
    );
    expect(
      verifyRecoveryCheckpoint({ ...signed, signatureBase64Url: alteredPadding }, keys.publicKey)
    ).toBe(false);
    for (const signatureBase64Url of [
      "!" + signed.signatureBase64Url,
      signed.signatureBase64Url + "!"
    ])
      expect(
        SignedAuditRecoveryCheckpointSchema.safeParse({ ...signed, signatureBase64Url }).success
      ).toBe(false);
  });
});

it("treats fractional timestamp spellings as the same instant but binds the original first-event time", () => {
  expect(
    AuditRecoveryRequestSchema.safeParse({
      ...request,
      preparedAt: "2026-09-08T10:00:00.1Z",
      expiresAt: "2026-09-08T10:30:00.100000Z"
    }).success
  ).toBe(true);
  const changed = {
    ...payload,
    recovery: {
      ...payload.recovery,
      firstCoveredEventAt: "2026-09-08T09:00:00.000002Z",
      missedByMicroseconds: "2701000000"
    }
  };
  const result = AuditRecoveryCheckpointPayloadSchema.safeParse(changed);
  expect(result.success).toBe(false);
  if (!result.success)
    expect(result.error.issues).toContainEqual(
      expect.objectContaining({
        code: "custom",
        message:
          "recovery checkpoint must bind its exact request, interval, key and truthful deadline miss"
      })
    );
  const text = AuditRecoveryRequestSchema.safeParse({ ...request, reason: " trailing " });
  expect(text.success).toBe(false);
  if (!text.success)
    expect(text.error.issues).toContainEqual(
      expect.objectContaining({
        message: "operator text must be nonempty canonical text without control characters"
      })
    );
});

it("reports an interval error after otherwise valid request fields", () => {
  const result = AuditRecoveryRequestSchema.safeParse({ ...request, firstSequence: "1101" });
  expect(result.success).toBe(false);
  if (!result.success)
    expect(result.error.issues).toContainEqual(
      expect.objectContaining({
        code: "custom",
        message:
          "recovery requires an overdue bounded range and an exact thirty-minute request lifetime"
      })
    );
});
