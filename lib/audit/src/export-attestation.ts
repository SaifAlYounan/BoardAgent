import { sign, verify, type KeyObject } from "node:crypto";
import { z } from "zod";
import { AuditRecoveryEvidenceSetSchema } from "./recovery-checkpoint.js";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson
} from "@boardagent/contracts";

const PositiveSequenceSchema = z.string().regex(/^[1-9]\d*$/u);

/** This binds an exact exported projection; it is not a cadence checkpoint. */
const AuditExportAttestationV1Schema = z
  .object({
    schemaVersion: z.literal("boardagent.audit-export-attestation.v1"),
    instanceId: UuidV7Schema,
    exportRequestId: UuidV7Schema,
    organizationId: UuidV7Schema,
    boardId: UuidV7Schema.nullable(),
    scopeSha256: Sha256HexSchema,
    snapshotSha256: Sha256HexSchema,
    firstSequence: PositiveSequenceSchema,
    lastSequence: PositiveSequenceSchema,
    auditHeadSequence: PositiveSequenceSchema,
    auditHeadSha256: Sha256HexSchema,
    latestCheckpointSha256: Sha256HexSchema,
    eventComponentSha256: Sha256HexSchema,
    checkpointComponentSha256: Sha256HexSchema,
    issuedAt: Rfc3339UtcSchema,
    signingKeyId: UuidV7Schema,
    keyId: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u)
  })
  .strict();

export const AuditExportAttestationPayloadSchema = z
  .discriminatedUnion("schemaVersion", [
    AuditExportAttestationV1Schema,
    AuditExportAttestationV1Schema.extend({
      schemaVersion: z.literal("boardagent.audit-export-attestation.v2"),
      auditRecoveryEvidence: AuditRecoveryEvidenceSetSchema
    })
  ])
  .refine(
    (value) =>
      BigInt(value.firstSequence) <= BigInt(value.lastSequence) &&
      BigInt(value.lastSequence) <= BigInt(value.auditHeadSequence),
    "export attestation range must be within its frozen head"
  );

export const SignedAuditExportAttestationSchema = z
  .object({
    payload: AuditExportAttestationPayloadSchema,
    signatureBase64Url: z.string().regex(/^[A-Za-z0-9_-]{86}$/u)
  })
  .strict();

export type AuditExportAttestationPayload = z.infer<typeof AuditExportAttestationPayloadSchema>;
export type SignedAuditExportAttestation = z.infer<typeof SignedAuditExportAttestationSchema>;

export function signAuditExportAttestation(
  payloadValue: z.input<typeof AuditExportAttestationPayloadSchema>,
  privateKey: KeyObject
): SignedAuditExportAttestation {
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("audit export attestation requires an Ed25519 private key");
  }
  const payload = AuditExportAttestationPayloadSchema.parse(payloadValue);
  return {
    payload,
    signatureBase64Url: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString(
      "base64url"
    )
  };
}

export function verifyAuditExportAttestation(value: unknown, publicKey: KeyObject): boolean {
  try {
    if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") return false;
    const signed = SignedAuditExportAttestationSchema.parse(value);
    const signature = Buffer.from(signed.signatureBase64Url, "base64url");
    return (
      signature.toString("base64url") === signed.signatureBase64Url &&
      verify(null, Buffer.from(canonicalJson(signed.payload)), publicKey, signature)
    );
  } catch {
    return false;
  }
}
