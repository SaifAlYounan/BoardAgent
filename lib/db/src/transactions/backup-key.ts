import type { PoolClient } from "pg";
import { z } from "zod";

import { Rfc3339UtcSchema, Sha256HexSchema, UuidV7Schema } from "@boardagent/contracts";

export const BackupKeyIdentitySchema = z
  .object({
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    keyId: UuidV7Schema,
    kid: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u),
    purpose: z.literal("backup_kek"),
    algorithm: z.literal("A256GCM"),
    activatedAt: Rfc3339UtcSchema,
    fingerprintSha256: Sha256HexSchema
  })
  .strict();
export type BackupKeyIdentity = z.infer<typeof BackupKeyIdentitySchema>;

/** Existing bootstrap/backup RLS remains the authority; no new database grant. */
export async function readActiveBackupKeyInTransaction(
  client: PoolClient,
  keyIdValue: string
): Promise<BackupKeyIdentity> {
  const keyId = UuidV7Schema.parse(keyIdValue);
  const result = await client.query(
    `select instance.instance_id as "instanceId",key.organization_id as "organizationId",
            key.id as "keyId",key.kid,key.purpose,key.algorithm,
            to_char(key.activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "activatedAt",
            substring(key.nonsecret_locator from 8) as "fingerprintSha256"
       from public.crypto_key_registry key join public.system_instance instance
         on instance.singleton_key and instance.organization_id=key.organization_id
      where current_setting('boardagent.transaction_scope',true) in ('bootstrap','backup')
        and key.id=$1 and key.purpose='backup_kek' and key.algorithm='A256GCM'
        and key.public_jwk is null and key.nonsecret_locator ~ '^sha256:[0-9a-f]{64}$'
        and key.activated_at<=transaction_timestamp()
        and (key.retired_at is null or key.retired_at>transaction_timestamp())
        and (key.compromised_at is null or key.compromised_at>transaction_timestamp())`,
    [keyId]
  );
  if (result.rows.length !== 1) throw new Error("backup key has no active registered fingerprint");
  return BackupKeyIdentitySchema.parse(result.rows[0]);
}

export async function registerBackupKeyInTransaction(
  client: PoolClient,
  organizationIdValue: string,
  keyIdValue: string,
  fingerprintValue: string
): Promise<{ readonly keyId: string; readonly replayed: boolean }> {
  const organizationId = UuidV7Schema.parse(organizationIdValue);
  const keyId = UuidV7Schema.parse(keyIdValue);
  const fingerprint = z
    .string()
    .regex(/^[0-9a-f]{64}$/u)
    .parse(fingerprintValue);
  const result = await client.query<{ result_key_id: string; replayed: boolean }>(
    "select result_key_id,replayed from boardagent_register_backup_key($1,$2,$3)",
    [organizationId, keyId, fingerprint]
  );
  const row = result.rows[0];
  if (
    result.rows.length !== 1 ||
    row?.result_key_id !== keyId ||
    typeof row.replayed !== "boolean"
  ) {
    throw new Error("backup-key authority returned an invalid result");
  }
  return { keyId, replayed: row.replayed };
}
