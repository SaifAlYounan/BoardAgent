import {
  canonicalJsonFromText,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";
import { z } from "zod";
import {
  loadOperatorKeyMaterial,
  OperatorFilePathSchema,
  readOperatorProtectedFile
} from "./operator-key-files.js";
import { verifyBackupKeyBytes } from "./backup-key-binding.js";

const KeyringSchema = z
  .object({
    schemaVersion: z.literal("boardagent.backup-recovery-keys.v1"),
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    keys: z
      .array(
        z
          .object({
            keyId: UuidV7Schema,
            keyFile: OperatorFilePathSchema,
            fingerprintSha256: Sha256HexSchema
          })
          .strict()
      )
      .min(1)
      .max(4096)
  })
  .strict();

export class RecoveryKeyringError extends Error {
  constructor(readonly reasonCode: string) {
    super(reasonCode);
  }
}

/** Explicit operator-owned historical custody input; never authorizes a new write or registers a key. */
export async function loadRecoveryKeyring(
  file: string,
  base: {
    keyId: string;
    key: Uint8Array;
    instanceId?: string | undefined;
    organizationId?: string | undefined;
  }
) {
  const raw = await readOperatorProtectedFile(file, 1_048_576);
  let manifest: z.infer<typeof KeyringSchema>;
  try {
    manifest = KeyringSchema.parse(JSON.parse(canonicalJsonFromText(raw)));
  } finally {
    raw.fill(0);
  }
  if (
    new Set(manifest.keys.map((k) => k.keyId)).size !== manifest.keys.length ||
    new Set(manifest.keys.map((k) => k.keyFile)).size !== manifest.keys.length ||
    new Set(manifest.keys.map((k) => k.fingerprintSha256)).size !== manifest.keys.length
  )
    throw new RecoveryKeyringError("recovery_key_list_has_duplicates");
  if (
    (base.instanceId !== undefined && manifest.instanceId !== base.instanceId) ||
    (base.organizationId !== undefined && manifest.organizationId !== base.organizationId)
  )
    throw new RecoveryKeyringError("recovery_key_target_mismatch");
  const selected = manifest.keys.find((k) => k.keyId === base.keyId);
  if (!selected) throw new RecoveryKeyringError("recovery_base_key_missing");
  try {
    verifyBackupKeyBytes(base.key, selected.fingerprintSha256);
  } catch {
    throw new RecoveryKeyringError("recovery_base_key_mismatch");
  }
  const keys = new Map<string, Buffer>();
  try {
    for (const entry of manifest.keys) {
      const material = await loadOperatorKeyMaterial("backup_kek", entry.keyFile);
      try {
        if (material.materialSha256 !== entry.fingerprintSha256)
          throw new RecoveryKeyringError("recovery_private_key_mismatch");
        keys.set(entry.keyId, material.symmetricBytes());
      } finally {
        material.destroy();
      }
    }
    return {
      instanceId: manifest.instanceId,
      organizationId: manifest.organizationId,
      manifestSha256: canonicalSha256(manifest),
      keys,
      destroy: () => {
        for (const key of keys.values()) key.fill(0);
      }
    };
  } catch (error) {
    for (const key of keys.values()) key.fill(0);
    throw error;
  }
}
