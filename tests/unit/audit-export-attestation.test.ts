import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AuditExportAttestationPayloadSchema,
  SignedAuditExportAttestationSchema,
  signAuditExportAttestation,
  verifyAuditExportAttestation
} from "../../lib/audit/src/export-attestation.js";
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, "0")}`;
const payload = {
  schemaVersion: "boardagent.audit-export-attestation.v1" as const,
  instanceId: id(1),
  exportRequestId: id(2),
  organizationId: id(3),
  boardId: null,
  scopeSha256: "a".repeat(64),
  snapshotSha256: "b".repeat(64),
  firstSequence: "10",
  lastSequence: "20",
  auditHeadSequence: "30",
  auditHeadSha256: "c".repeat(64),
  latestCheckpointSha256: "d".repeat(64),
  eventComponentSha256: "e".repeat(64),
  checkpointComponentSha256: "f".repeat(64),
  issuedAt: "2026-09-09T00:00:00Z",
  signingKeyId: id(4),
  keyId: "evidence-1"
};

describe("audit export attestation boundary", () => {
  it("requires an ordered range inside the frozen head including equal endpoints", () => {
    expect(AuditExportAttestationPayloadSchema.parse(payload)).toEqual(payload);
    expect(
      AuditExportAttestationPayloadSchema.parse({
        ...payload,
        lastSequence: "10",
        auditHeadSequence: "10"
      }).lastSequence
    ).toBe("10");
    for (const change of [{ firstSequence: "21" }, { lastSequence: "31" }]) {
      const result = AuditExportAttestationPayloadSchema.safeParse({ ...payload, ...change });
      expect(result.success).toBe(false);
      if (!result.success)
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({
            code: "custom",
            message: "export attestation range must be within its frozen head"
          })
        );
    }
    for (const field of ["firstSequence", "lastSequence", "auditHeadSequence"] as const) {
      for (const value of ["01", "10\n", " 10", "1e2", "-1"]) {
        expect(() =>
          AuditExportAttestationPayloadSchema.parse({ ...payload, [field]: value })
        ).toThrow();
      }
    }
    for (const keyId of ["!key", "key!", "", "a".repeat(129)])
      expect(AuditExportAttestationPayloadSchema.safeParse({ ...payload, keyId }).success).toBe(
        false
      );
    expect(
      AuditExportAttestationPayloadSchema.safeParse({
        ...payload,
        schemaVersion: "",
        auditRecoveryEvidence: []
      }).success
    ).toBe(false);
    expect(
      AuditExportAttestationPayloadSchema.safeParse({
        ...payload,
        schemaVersion: "boardagent.audit-export-attestation.v2",
        auditRecoveryEvidence: []
      }).success
    ).toBe(false);
  });

  it("requires Ed25519 key roles, exact signatures and valid signed structure", () => {
    const keys = generateKeyPairSync("ed25519");
    const signed = signAuditExportAttestation(payload, keys.privateKey);
    expect(verifyAuditExportAttestation(signed, keys.publicKey)).toBe(true);
    for (const key of [
      keys.publicKey,
      generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey
    ])
      expect(() => signAuditExportAttestation(payload, key)).toThrow(
        "audit export attestation requires an Ed25519 private key"
      );
    expect(verifyAuditExportAttestation(signed, keys.privateKey)).toBe(false);
    // Reject an explicitly inconsistent key descriptor before invoking the crypto backend.
    const wronglyLabelled = createPublicKey(keys.privateKey);
    Object.defineProperty(wronglyLabelled, "asymmetricKeyType", { value: "ec" });
    expect(verifyAuditExportAttestation(signed, wronglyLabelled)).toBe(false);
    expect(verifyAuditExportAttestation({ ...signed, unexpected: true }, keys.publicKey)).toBe(
      false
    );
    expect(verifyAuditExportAttestation(null, keys.publicKey)).toBe(false);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const alteredPadding =
      signed.signatureBase64Url.slice(0, -1) +
      alphabet[alphabet.indexOf(signed.signatureBase64Url.at(-1)!) + 1];
    expect(Buffer.from(alteredPadding, "base64url")).toEqual(
      Buffer.from(signed.signatureBase64Url, "base64url")
    );
    expect(
      verifyAuditExportAttestation(
        { ...signed, signatureBase64Url: alteredPadding },
        keys.publicKey
      )
    ).toBe(false);
    for (const signatureBase64Url of [
      "!" + signed.signatureBase64Url,
      signed.signatureBase64Url + "!",
      signed.signatureBase64Url + "=",
      "x".repeat(85)
    ]) {
      expect(
        SignedAuditExportAttestationSchema.safeParse({ ...signed, signatureBase64Url }).success
      ).toBe(false);
      expect(verifyAuditExportAttestation({ ...signed, signatureBase64Url }, keys.publicKey)).toBe(
        false
      );
    }
  });
});
