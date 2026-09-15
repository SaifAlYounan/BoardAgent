import type { PoolClient } from "pg";
import { z } from "zod";

import { UuidV7Schema, canonicalJson } from "@boardagent/contracts";

const PublicJwkSchema = z
  .object({
    kty: z.string().min(1).max(16),
    kid: z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,128}$/u)
      .optional()
  })
  .passthrough();

export const RuntimeKeyPurposeSchema = z.enum([
  "oauth_signing",
  "evidence_signing",
  "browser_session",
  "data_kek"
]);

export type RuntimeKeyPurpose = z.infer<typeof RuntimeKeyPurposeSchema>;

export interface RuntimeKeyRegistration {
  readonly keyId: string;
  readonly kid: string;
  readonly purpose: RuntimeKeyPurpose;
  readonly algorithm: "ES256" | "EdDSA" | "HMAC-SHA256" | "A256GCM";
  readonly publicJwk: Readonly<Record<string, unknown>> | null;
  readonly nonsecretLocator: string;
}

const RuntimeKeyRegistrationSchema = z
  .object({
    keyId: UuidV7Schema,
    kid: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u),
    purpose: RuntimeKeyPurposeSchema,
    algorithm: z.enum(["ES256", "EdDSA", "HMAC-SHA256", "A256GCM"]),
    publicJwk: PublicJwkSchema.nullable(),
    nonsecretLocator: z.string().min(1).max(2048)
  })
  .strict()
  .superRefine((value, context) => {
    const expected = {
      oauth_signing: "ES256",
      evidence_signing: "EdDSA",
      browser_session: "HMAC-SHA256",
      data_kek: "A256GCM"
    }[value.purpose];
    if (value.algorithm !== expected) {
      context.addIssue({ code: "custom", message: "runtime key algorithm/purpose mismatch" });
    }
    const asymmetric = value.purpose === "oauth_signing" || value.purpose === "evidence_signing";
    if (asymmetric !== (value.publicJwk !== null)) {
      context.addIssue({ code: "custom", message: "runtime key public-JWK projection mismatch" });
    }
    if (value.publicJwk && "d" in value.publicJwk) {
      context.addIssue({
        code: "custom",
        message: "runtime key registry cannot contain private JWK"
      });
    }
  });

export async function registerRuntimeKeysInTransaction(
  client: PoolClient,
  organizationIdValue: string,
  registrationsValue: readonly RuntimeKeyRegistration[]
): Promise<readonly { readonly keyId: string; readonly replayed: boolean }[]> {
  const organizationId = UuidV7Schema.parse(organizationIdValue);
  const registrations = z.array(RuntimeKeyRegistrationSchema).length(4).parse(registrationsValue);
  if (new Set(registrations.map(({ purpose }) => purpose)).size !== registrations.length) {
    throw new Error("runtime key set must contain each purpose exactly once");
  }
  const results: { keyId: string; replayed: boolean }[] = [];
  for (const registration of registrations.toSorted((left, right) =>
    left.purpose.localeCompare(right.purpose)
  )) {
    const result = await client.query<{ result_key_id: string; replayed: boolean }>(
      `select result_key_id,replayed
         from boardagent_register_runtime_key($1,$2,$3,$4,$5,$6::jsonb,$7)`,
      [
        organizationId,
        registration.keyId,
        registration.kid,
        registration.purpose,
        registration.algorithm,
        registration.publicJwk === null ? null : canonicalJson(registration.publicJwk as never),
        registration.nonsecretLocator
      ]
    );
    const row = result.rows[0];
    if (!row || result.rows.length !== 1 || row.result_key_id !== registration.keyId) {
      throw new Error("runtime key authority returned an invalid result");
    }
    results.push({ keyId: row.result_key_id, replayed: row.replayed });
  }
  return results;
}
