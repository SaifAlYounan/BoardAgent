import { sign, verify, type KeyObject } from "node:crypto";
import { z } from "zod";
import {
  canonicalJson,
  canonicalSha256,
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";
import { AuditCheckpointPayloadSchema } from "./checkpoint.js";

const DEADLINE_MICROSECONDS = 900_000_000n;
const REQUEST_LIFETIME_MICROSECONDS = 1_800_000_000n;
const PositiveSequence = z
  .string()
  .refine(
    (value) => /^[1-9]\d{0,18}$/u.test(value) && BigInt(value) <= 9_223_372_036_854_775_807n,
    "expected a positive PostgreSQL bigint sequence"
  );
const ExactTimestamp = Rfc3339UtcSchema.refine((value) => {
  const date = new Date(value);
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
}, "timestamp must identify a real UTC calendar instant");
const KeyId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u);

function exactOperatorText(maximum: number) {
  return z
    .string()
    .min(1)
    .max(maximum)
    .refine(
      (value) =>
        value === value.trim() &&
        value === value.normalize("NFC") &&
        Array.from(value).every(
          (character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127
        ),
      "operator text must be nonempty canonical text without control characters"
    );
}

/** Input schemas validate the calendar and six-digit precision before this calculation. */
function microseconds(value: string): bigint {
  const wholeSeconds = value.slice(0, 19);
  const fraction = value.slice(20, -1);
  return BigInt(Date.parse(`${wholeSeconds}Z`)) * 1000n + BigInt(fraction.padEnd(6, "0"));
}

/** This is signed request data, not database authority or evidence of operator execution. */
export const AuditRecoveryRequestSchema = z
  .object({
    schemaVersion: z.literal("boardagent.audit-recovery-request.v1"),
    recoveryId: UuidV7Schema,
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    firstSequence: PositiveSequence,
    lastSequence: PositiveSequence,
    firstEventSha256: Sha256HexSchema,
    headSha256: Sha256HexSchema,
    signingKeyId: UuidV7Schema,
    keyId: KeyId,
    firstUncoveredEventAt: ExactTimestamp,
    preparedAt: ExactTimestamp,
    expiresAt: ExactTimestamp,
    operatorReference: exactOperatorText(256),
    reason: exactOperatorText(2048)
  })
  .strict()
  .transform((request, context) => {
    // This stage runs only after every strict field schema has succeeded.
    const first = BigInt(request.firstSequence);
    const last = BigInt(request.lastSequence);
    if (!(
      last >= first &&
      last - first < 1_000_000n &&
      microseconds(request.preparedAt) - microseconds(request.firstUncoveredEventAt) >
        DEADLINE_MICROSECONDS &&
      microseconds(request.expiresAt) - microseconds(request.preparedAt) ===
        REQUEST_LIFETIME_MICROSECONDS
    ))
      context.addIssue({
        code: "custom",
        message:
          "recovery requires an overdue bounded range and an exact thirty-minute request lifetime"
      });
    return request;
  });

export type AuditRecoveryRequest = z.infer<typeof AuditRecoveryRequestSchema>;

/** Ordinary checkpoint readers reject this distinct recovery format. Recovery-aware
 * consumers additionally verify the operator request and propagate its historical warning.
 */
export const AuditRecoveryCheckpointPayloadSchema = z
  .object({
    schema: z.literal("boardagent.audit.recovery-checkpoint.v1"),
    checkpointId: UuidV7Schema,
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    auditSchema: z.literal("boardagent.audit-event.v1"),
    firstSequence: PositiveSequence,
    lastSequence: PositiveSequence,
    firstEventSha256: Sha256HexSchema,
    lastEventSha256: Sha256HexSchema,
    issuedAt: ExactTimestamp,
    signingKeyId: UuidV7Schema,
    keyId: KeyId,
    recovery: z
      .object({
        request: AuditRecoveryRequestSchema,
        requestSha256: Sha256HexSchema,
        firstCoveredEventAt: ExactTimestamp,
        missedByMicroseconds: z.string().regex(/^[1-9]\d{0,19}$/u)
      })
      .strict()
  })
  .strict()
  .transform((payload, context) => {
    // Dependent checks consume validated fields, without swallowing parser exceptions.
    const { recovery, ...base } = payload;
    const request = recovery.request;
    const first = BigInt(payload.firstSequence);
    const last = BigInt(payload.lastSequence);
    const issuedAt = microseconds(payload.issuedAt);
    if (!(
      AuditCheckpointPayloadSchema.safeParse({ ...base, schema: "boardagent.audit.checkpoint.v1" })
        .success &&
      recovery.requestSha256 === canonicalSha256(request) &&
      payload.instanceId === request.instanceId &&
      payload.organizationId === request.organizationId &&
      payload.signingKeyId === request.signingKeyId &&
      payload.keyId === request.keyId &&
      first >= BigInt(request.firstSequence) &&
      last <= BigInt(request.lastSequence) &&
      (first !== BigInt(request.firstSequence) ||
        (payload.firstEventSha256 === request.firstEventSha256 &&
          recovery.firstCoveredEventAt === request.firstUncoveredEventAt)) &&
      (last !== BigInt(request.lastSequence) || payload.lastEventSha256 === request.headSha256) &&
      issuedAt >= microseconds(request.preparedAt) &&
      issuedAt < microseconds(request.expiresAt) &&
      issuedAt - microseconds(recovery.firstCoveredEventAt) - DEADLINE_MICROSECONDS ===
        BigInt(recovery.missedByMicroseconds)
    ))
      context.addIssue({
        code: "custom",
        message:
          "recovery checkpoint must bind its exact request, interval, key and truthful deadline miss"
      });
    return payload;
  });

export const SignedAuditRecoveryCheckpointSchema = z
  .object({
    payload: AuditRecoveryCheckpointPayloadSchema,
    signatureBase64Url: z.string().regex(/^[A-Za-z0-9_-]{86}$/u)
  })
  .strict();
export type AuditRecoveryCheckpointPayload = z.infer<typeof AuditRecoveryCheckpointPayloadSchema>;
export type SignedAuditRecoveryCheckpoint = z.infer<typeof SignedAuditRecoveryCheckpointSchema>;

/** One original signed finding per completed recovery, in audit order. An empty set
 * stays on legacy receipt formats; v2 receipts require at least one explicit finding.
 * The signatures are verified against independently trusted keys by each consumer.
 */
export const AuditRecoveryEvidenceSetSchema = z
  .array(SignedAuditRecoveryCheckpointSchema)
  .min(1)
  .max(1_000_000)
  .refine((evidence) => {
    const ids = new Set<string>();
    return evidence.every((entry, index) => {
      const request = entry.payload.recovery.request;
      if (
        ids.has(request.recoveryId) ||
        entry.payload.firstSequence !== request.firstSequence ||
        (index > 0 &&
          BigInt(evidence[index - 1]!.payload.firstSequence) >= BigInt(entry.payload.firstSequence))
      )
        return false;
      ids.add(request.recoveryId);
      return true;
    });
  }, "recovery evidence must contain one first signed checkpoint per recovery, in audit order");

export function signRecoveryCheckpoint(
  rawPayload: z.input<typeof AuditRecoveryCheckpointPayloadSchema>,
  privateKey: KeyObject
): SignedAuditRecoveryCheckpoint {
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("audit recovery checkpoint requires an Ed25519 private key");
  }
  const payload = AuditRecoveryCheckpointPayloadSchema.parse(rawPayload);
  return {
    payload,
    signatureBase64Url: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString(
      "base64url"
    )
  };
}

export function verifyRecoveryCheckpoint(value: unknown, publicKey: KeyObject): boolean {
  try {
    if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") return false;
    const signed = SignedAuditRecoveryCheckpointSchema.parse(value);
    const signature = Buffer.from(signed.signatureBase64Url, "base64url");
    return (
      signature.toString("base64url") === signed.signatureBase64Url &&
      verify(null, Buffer.from(canonicalJson(signed.payload)), publicKey, signature)
    );
  } catch {
    return false;
  }
}
