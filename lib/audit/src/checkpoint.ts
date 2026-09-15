import { createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { z } from "zod";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson
} from "@boardagent/contracts";

function createPositiveBigintStringSchema() {
  return z.string().regex(/^[1-9]\d*$/u);
}

function createKeyIdSchema() {
  return z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u);
}

const PositiveBigintStringSchema = z.lazy(createPositiveBigintStringSchema);
const KeyIdSchema = z.lazy(createKeyIdSchema);

function parseBigInt(value: string): bigint | null {
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

export interface AuditCheckpointPayload {
  readonly schema: "boardagent.audit.checkpoint.v1";
  readonly checkpointId: string;
  readonly instanceId: string;
  readonly organizationId: string;
  readonly auditSchema: "boardagent.audit-event.v1";
  readonly firstSequence: string;
  readonly lastSequence: string;
  readonly firstEventSha256: string;
  readonly lastEventSha256: string;
  readonly issuedAt: string;
  readonly signingKeyId: string;
  readonly keyId: string;
}

export type PublicJsonWebKey = Readonly<Record<string, unknown>> & { readonly kty: string };

function createAuditCheckpointPayloadSchema(): z.ZodType<AuditCheckpointPayload> {
  return z
    .object({
      schema: z.literal("boardagent.audit.checkpoint.v1"),
      checkpointId: UuidV7Schema,
      instanceId: UuidV7Schema,
      organizationId: UuidV7Schema,
      auditSchema: z.literal("boardagent.audit-event.v1"),
      firstSequence: PositiveBigintStringSchema,
      lastSequence: PositiveBigintStringSchema,
      firstEventSha256: Sha256HexSchema,
      lastEventSha256: Sha256HexSchema,
      issuedAt: Rfc3339UtcSchema,
      signingKeyId: UuidV7Schema,
      keyId: KeyIdSchema
    })
    .strict()
    .superRefine((payload, context) => {
      const firstSequence = parseBigInt(payload.firstSequence);
      const lastSequence = parseBigInt(payload.lastSequence);
      if (firstSequence === null || lastSequence === null) return;
      if (lastSequence < firstSequence) {
        context.addIssue({ code: "custom", message: "checkpoint sequence range is inverted" });
      }
      if (lastSequence - firstSequence >= 1_000n) {
        context.addIssue({
          code: "custom",
          message: "checkpoint may cover at most 1,000 audit events"
        });
      }
    });
}

export const AuditCheckpointPayloadSchema: z.ZodType<AuditCheckpointPayload> = z.lazy(
  createAuditCheckpointPayloadSchema
);

export interface SignedAuditCheckpoint {
  readonly payload: AuditCheckpointPayload;
  readonly signatureBase64Url: string;
}

function asPublicKey(key: KeyObject | string | PublicJsonWebKey): KeyObject {
  if (typeof key === "string") return createPublicKey(key);
  if ("kty" in key) {
    return createPublicKey({
      key: key as import("node:crypto").JsonWebKey,
      format: "jwk"
    });
  }
  return key as KeyObject;
}

export function signCheckpoint(
  rawPayload: AuditCheckpointPayload,
  privateKey: KeyObject | string
): SignedAuditCheckpoint {
  const payload = AuditCheckpointPayloadSchema.parse(rawPayload);
  const signature = sign(null, Buffer.from(canonicalJson(payload)), privateKey);
  return { payload, signatureBase64Url: signature.toString("base64url") };
}

export function verifyCheckpoint(
  checkpoint: SignedAuditCheckpoint,
  publicKey: KeyObject | string | PublicJsonWebKey
): boolean {
  try {
    const payload = AuditCheckpointPayloadSchema.parse(checkpoint.payload);
    const signature = Buffer.from(checkpoint.signatureBase64Url, "base64url");
    return verify(null, Buffer.from(canonicalJson(payload)), asPublicKey(publicKey), signature);
  } catch {
    return false;
  }
}
