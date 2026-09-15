import { createPublicKey } from "node:crypto";
import path from "node:path";
import type { PoolClient } from "pg";
import { z } from "zod";
import { canonicalSha256, UuidV7Schema, Sha256HexSchema } from "@boardagent/contracts";
import {
  KeyLifecycleChangedSchema,
  KeyLifecycleOperationSchema,
  KeyLifecyclePurposeSchema,
  KeyLifecycleStateSchema,
  keyLifecyclePublicMaterialSha256
} from "@boardagent/audit";
import {
  KeyMaintenanceWorkSchema,
  inspectKeyMaintenanceWorkInTransaction
} from "./key-maintenance-work.js";

const Time = z.iso.datetime({ precision: 6 });
const Kid = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u);
const Coordinate = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/u)
  .refine((v) => Buffer.from(v, "base64url").toString("base64url") === v);
const PublicJwk = z
  .union([
    z
      .object({
        kty: z.literal("EC"),
        crv: z.literal("P-256"),
        x: Coordinate,
        y: Coordinate,
        kid: Kid,
        use: z.literal("sig"),
        alg: z.literal("ES256")
      })
      .strict(),
    z.object({ kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: Coordinate }).strict()
  ])
  .superRefine((jwk, context) => {
    try {
      const key = createPublicKey({ key: jwk, format: "jwk" });
      if (
        jwk.kty === "EC"
          ? key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
          : key.asymmetricKeyType !== "ed25519"
      )
        throw new Error("invalid key");
    } catch {
      context.addIssue({ code: "custom", message: "invalid public key projection" });
    }
  });
const Replacement = z
  .object({
    keyId: UuidV7Schema,
    kid: Kid,
    algorithm: KeyLifecycleStateSchema.shape.algorithm,
    publicJwk: PublicJwk.nullable(),
    nonsecretLocator: z.string().min(1).max(2048),
    materialSha256: Sha256HexSchema
  })
  .strict();

export const KeyLifecyclePreparationSchema = z
  .object({
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    keyId: UuidV7Schema,
    operationId: UuidV7Schema,
    operation: KeyLifecycleOperationSchema,
    replacement: Replacement.nullable(),
    declaredCompromisedAt: Time.nullable(),
    retainedMaterialSha256: Sha256HexSchema,
    operatorReference: KeyLifecycleChangedSchema.shape.operatorReference,
    reason: KeyLifecycleChangedSchema.shape.reason
  })
  .strict();

export const KeyLifecycleRequestSchema = KeyLifecyclePreparationSchema.extend({
  schemaVersion: z.literal("boardagent.key-lifecycle-request.v1"),
  purpose: KeyLifecyclePurposeSchema,
  expectedKey: KeyLifecycleStateSchema,
  expectedInventory: KeyMaintenanceWorkSchema,
  preparedAt: Time,
  expiresAt: Time
})
  .strict()
  .superRefine((request, context) => {
    const invalid = () =>
      context.addIssue({ code: "custom", message: "inconsistent key lifecycle request" });
    const dependencies = request.expectedInventory.keyDependencies;
    const algorithm = (
      {
        oauth_signing: "ES256",
        evidence_signing: "EdDSA",
        browser_session: "HMAC-SHA256",
        data_kek: "A256GCM",
        backup_kek: "A256GCM"
      } as const
    )[request.purpose];
    const asymmetric =
      request.purpose === "oauth_signing" || request.purpose === "evidence_signing";
    if (
      request.instanceId !== dependencies.instanceId ||
      request.organizationId !== dependencies.organizationId ||
      request.keyId !== dependencies.keyId ||
      request.purpose !== dependencies.keyPurpose ||
      request.expectedKey.keyId !== request.keyId ||
      request.expectedKey.algorithm !== algorithm ||
      asymmetric !== (request.expectedKey.publicMaterialSha256 !== null) ||
      request.preparedAt !== dependencies.observedAt ||
      request.expectedKey.activatedAt > request.preparedAt ||
      (request.expectedKey.retiredAt !== null &&
        request.expectedKey.retiredAt > request.preparedAt) ||
      (request.expectedKey.compromisedAt !== null &&
        request.expectedKey.compromisedAt > request.preparedAt) ||
      Date.parse(request.expiresAt) - Date.parse(request.preparedAt) !== 1_800_000 ||
      request.expiresAt.slice(-4) !== request.preparedAt.slice(-4)
    )
      invalid();
    if (request.operation === "mark_compromised") {
      if (
        request.declaredCompromisedAt === null ||
        request.declaredCompromisedAt < request.expectedKey.activatedAt ||
        request.declaredCompromisedAt > request.preparedAt ||
        (request.expectedKey.compromisedAt !== null &&
          request.declaredCompromisedAt >= request.expectedKey.compromisedAt)
      )
        invalid();
    } else if (request.declaredCompromisedAt !== null) invalid();
    if (request.operation === "retire" && request.expectedKey.retiredAt !== null) invalid();
    const next = request.replacement;
    if (request.operation !== "replace") {
      if (next !== null) invalid();
      return;
    }
    if (next === null) {
      invalid();
      return;
    }
    if (
      next.keyId === request.keyId ||
      next.kid === request.expectedKey.kid ||
      next.algorithm !== algorithm ||
      asymmetric !== (next.publicJwk !== null)
    )
      invalid();
    if (next.publicJwk !== null) {
      if (
        (request.purpose === "oauth_signing" &&
          (next.publicJwk.kty !== "EC" || next.publicJwk.kid !== next.kid)) ||
        (request.purpose === "evidence_signing" &&
          (next.publicJwk.kty !== "OKP" ||
            next.kid !== `evidence-${canonicalSha256(next.publicJwk).slice(0, 24)}`)) ||
        next.materialSha256 !== keyLifecyclePublicMaterialSha256(next.publicJwk) ||
        next.materialSha256 === request.expectedKey.publicMaterialSha256
      )
        invalid();
    }
    if (request.purpose === "backup_kek") {
      if (
        next.kid !== `backup-${next.keyId}` ||
        next.nonsecretLocator !== `sha256:${next.materialSha256}`
      )
        invalid();
    } else {
      const filename = next.nonsecretLocator.slice(5);
      if (
        !next.nonsecretLocator.startsWith("file:") ||
        !path.posix.isAbsolute(filename) ||
        path.posix.normalize(filename) !== filename ||
        filename === "/" ||
        Array.from(filename).some((c) => c.codePointAt(0)! < 32 || c.codePointAt(0) === 127)
      )
        invalid();
      if (request.purpose === "data_kek" && !/^data-[0-9a-f]{24}$/u.test(next.kid)) invalid();
      if (request.purpose === "browser_session" && !/^browser-[0-9a-f]{24}$/u.test(next.kid))
        invalid();
    }
  });

export type KeyLifecycleRequest = z.infer<typeof KeyLifecycleRequestSchema>;

/** Database-only preparation. The CLI must separately inspect actual protected material. */
export async function prepareKeyLifecycleInTransaction(
  client: PoolClient,
  input: z.input<typeof KeyLifecyclePreparationSchema>
) {
  const proposal = KeyLifecyclePreparationSchema.parse(input);
  const { inventory } = await inspectKeyMaintenanceWorkInTransaction(client, {
    instanceId: proposal.instanceId,
    organizationId: proposal.organizationId,
    keyId: proposal.keyId
  });
  const rows = await client.query<{ identity: unknown; public_jwk: unknown }>(
    `select jsonb_build_object('keyId',id,'kid',kid,'algorithm',algorithm,
      'activatedAt',to_char(activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'retiredAt',to_char(retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'compromisedAt',to_char(compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) as identity,
      public_jwk from public.crypto_key_registry where id=$1 and organization_id=$2`,
    [proposal.keyId, proposal.organizationId]
  );
  const row = rows.rows[0];
  if (!row || rows.rows.length !== 1 || typeof row.identity !== "object" || row.identity === null)
    throw new Error("key lifecycle identity unavailable");
  const publicJwk = row.public_jwk === null ? null : PublicJwk.parse(row.public_jwk);
  const expectedKey = KeyLifecycleStateSchema.parse({
    ...row.identity,
    publicMaterialSha256: publicJwk === null ? null : keyLifecyclePublicMaterialSha256(publicJwk)
  });
  if (
    (publicJwk?.kty === "EC" &&
      (inventory.keyDependencies.keyPurpose !== "oauth_signing" ||
        publicJwk.kid !== expectedKey.kid)) ||
    (publicJwk?.kty === "OKP" && inventory.keyDependencies.keyPurpose !== "evidence_signing")
  )
    throw new Error("key lifecycle public identity mismatch");
  const preparedAt = inventory.keyDependencies.observedAt;
  const expiresAt = new Date(Date.parse(preparedAt) + 1_800_000)
    .toISOString()
    .replace("Z", preparedAt.slice(-4));
  const request = KeyLifecycleRequestSchema.parse({
    ...proposal,
    schemaVersion: "boardagent.key-lifecycle-request.v1",
    purpose: inventory.keyDependencies.keyPurpose,
    expectedKey,
    expectedInventory: inventory,
    preparedAt,
    expiresAt
  });
  return { request, requestSha256: canonicalSha256(request) };
}
