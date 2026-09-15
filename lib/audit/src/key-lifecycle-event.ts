import { z } from "zod";
import {
  canonicalJson,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";

/** Identity of validated public material, independent of labels and usage metadata. */
export function keyLifecyclePublicMaterialSha256(
  key:
    | { readonly kty: "EC"; readonly crv: "P-256"; readonly x: string; readonly y: string }
    | { readonly kty: "OKP"; readonly crv: "Ed25519"; readonly x: string }
) {
  return canonicalSha256(
    key.kty === "EC"
      ? { kty: key.kty, crv: key.crv, x: key.x, y: key.y }
      : { kty: key.kty, crv: key.crv, x: key.x }
  );
}

export const KeyLifecyclePurposeSchema = z.enum([
  "oauth_signing",
  "evidence_signing",
  "browser_session",
  "data_kek",
  "backup_kek"
]);
export const KeyLifecycleOperationSchema = z.enum(["replace", "retire", "mark_compromised"]);
const Time = z.iso.datetime({ precision: 6 });
const Kid = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u);
const Count = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,6})$/u)
  .refine((v) => BigInt(v) <= 1_000_000n);
const text = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .refine(
      (v) =>
        v.isWellFormed() &&
        v === v.normalize("NFC") &&
        v.trim() === v &&
        Array.from(v).every((character) => {
          const point = character.codePointAt(0)!;
          return point >= 32 && (point < 127 || point > 159);
        })
    );

export const KeyLifecycleStateSchema = z
  .object({
    keyId: UuidV7Schema,
    kid: Kid,
    algorithm: z.enum(["ES256", "EdDSA", "HMAC-SHA256", "A256GCM"]),
    publicMaterialSha256: Sha256HexSchema.nullable(),
    activatedAt: Time,
    retiredAt: Time.nullable(),
    compromisedAt: Time.nullable()
  })
  .strict()
  .superRefine((state, context) => {
    if (
      (state.retiredAt !== null && state.retiredAt.localeCompare(state.activatedAt) < 0) ||
      (state.compromisedAt !== null && state.compromisedAt.localeCompare(state.activatedAt) < 0)
    )
      context.addIssue({ code: "custom", message: "invalid key-state time ordering" });
  });

/** Public, attributable facts only. SQL must independently bind these to the actual transition. */
export const KeyLifecycleChangedSchema = z
  .object({
    schemaVersion: z.literal("boardagent.key-lifecycle-changed.v1"),
    operationId: UuidV7Schema,
    requestSha256: Sha256HexSchema,
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    purpose: KeyLifecyclePurposeSchema,
    operation: KeyLifecycleOperationSchema,
    before: KeyLifecycleStateSchema,
    after: KeyLifecycleStateSchema,
    replacement: KeyLifecycleStateSchema.nullable(),
    recordedAt: Time,
    declaredCompromisedAt: Time.nullable(),
    dependencyStateSha256: Sha256HexSchema,
    retainedMaterialSha256: Sha256HexSchema,
    operatorReference: text(512),
    reason: text(4096),
    effects: z
      .object({
        revokedSessions: Count,
        revokedRefreshFamilies: Count,
        cancelledStages: Count,
        affectedTotp: Count,
        disabledWebhooks: Count,
        rewrappedWebhooks: Count
      })
      .strict()
  })
  .strict()
  .superRefine((event, context) => {
    const invalid = () =>
      context.addIssue({ code: "custom", message: "inconsistent key lifecycle evidence" });
    const algorithm = {
      oauth_signing: "ES256",
      evidence_signing: "EdDSA",
      browser_session: "HMAC-SHA256",
      data_kek: "A256GCM",
      backup_kek: "A256GCM"
    }[event.purpose];
    const publicMaterial =
      event.purpose === "oauth_signing" || event.purpose === "evidence_signing";
    for (const state of [
      event.before,
      event.after,
      ...(event.replacement ? [event.replacement] : [])
    ]) {
      if (
        state.algorithm !== algorithm ||
        publicMaterial !== (state.publicMaterialSha256 !== null) ||
        (state.retiredAt !== null && state.retiredAt.localeCompare(event.recordedAt) > 0) ||
        (state.compromisedAt !== null && state.compromisedAt.localeCompare(event.recordedAt) > 0)
      )
        invalid();
    }
    // Each state's chronology and the exact after-state below also bound activation
    // and declared compromise times; keep those facts under their owning checks.
    const expected = { ...event.before };
    if (event.operation === "replace" || event.operation === "retire") {
      if (
        (event.operation === "retire" && event.before.retiredAt !== null) ||
        event.declaredCompromisedAt !== null
      )
        invalid();
      expected.retiredAt = event.before.retiredAt ?? event.recordedAt;
      if (event.operation === "replace") {
        const next = event.replacement;
        if (
          next === null ||
          next.keyId === event.before.keyId ||
          next.kid === event.before.kid ||
          next.activatedAt !== event.recordedAt ||
          next.retiredAt !== null ||
          next.compromisedAt !== null ||
          (publicMaterial && next.publicMaterialSha256 === event.before.publicMaterialSha256)
        )
          invalid();
      } else if (event.replacement !== null) invalid();
    } else {
      if (
        event.replacement !== null ||
        event.declaredCompromisedAt === null ||
        (event.before.compromisedAt !== null &&
          event.before.compromisedAt.localeCompare(event.declaredCompromisedAt) <= 0)
      )
        invalid();
      expected.compromisedAt = event.declaredCompromisedAt;
    }
    if (canonicalJson(event.after) !== canonicalJson(expected)) invalid();
    if (
      event.purpose !== "data_kek" &&
      (event.effects.affectedTotp !== "0" ||
        event.effects.disabledWebhooks !== "0" ||
        event.effects.rewrappedWebhooks !== "0")
    )
      invalid();
    if (event.operation !== "replace" && event.effects.rewrappedWebhooks !== "0") invalid();
  });

export type KeyLifecycleChanged = z.infer<typeof KeyLifecycleChangedSchema>;
