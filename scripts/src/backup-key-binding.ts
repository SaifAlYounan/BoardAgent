import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, open, unlink } from "node:fs/promises";
import path from "node:path";

import {
  canonicalJson,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";
import { BackupKeyIdentitySchema, type BackupKeyIdentity } from "@boardagent/db";
import { z } from "zod";

const ReceiptBodySchema = BackupKeyIdentitySchema.extend({
  schemaVersion: z.literal("boardagent.backup-key-registration.v1")
}).strict();
export const BackupKeyReceiptSchema = ReceiptBodySchema.extend({
  receiptSha256: Sha256HexSchema
}).strict();
export type BackupKeyReceipt = z.infer<typeof BackupKeyReceiptSchema>;

export const RecoveryManifestKeyFields = {
  instanceId: UuidV7Schema.optional(),
  organizationId: UuidV7Schema.optional(),
  encryptionKeyFingerprintSha256: Sha256HexSchema.optional(),
  encryptionKeyActivatedAt: ReceiptBodySchema.shape.activatedAt.optional(),
  encryptionKeyKid: ReceiptBodySchema.shape.kid.optional()
} as const;

export function manifestBackupKeyIdentity(receipt: BackupKeyReceipt) {
  return {
    instanceId: receipt.instanceId,
    organizationId: receipt.organizationId,
    encryptionKeyFingerprintSha256: receipt.fingerprintSha256,
    encryptionKeyActivatedAt: receipt.activatedAt,
    encryptionKeyKid: receipt.kid
  };
}

export function completeRecoveryKeyIdentity(value: object): boolean {
  const object = value as Record<string, unknown>;
  const count = Object.keys(RecoveryManifestKeyFields).filter(
    (key) => object[key] !== undefined
  ).length;
  return count === 0 || count === Object.keys(RecoveryManifestKeyFields).length;
}

export function verifyRecoveryManifestKey(
  manifest: { readonly encryptionKeyFingerprintSha256?: string | undefined } & object,
  key: Uint8Array,
  expected?: BackupKeyReceipt
): number {
  if (!completeRecoveryKeyIdentity(manifest))
    throw new Error("recovery manifest key identity is incomplete");
  if (manifest.encryptionKeyFingerprintSha256 === undefined) return 1;
  verifyBackupKeyBytes(key, manifest.encryptionKeyFingerprintSha256);
  if (expected) {
    const fields = manifestBackupKeyIdentity(expected);
    const object = manifest as Record<string, unknown>;
    if (Object.entries(fields).some(([field, value]) => object[field] !== value)) {
      throw new Error("recovery manifest key identity differs from its registration receipt");
    }
  }
  return 0;
}

export function assertReceiptMatchesRegistry(
  receipt: BackupKeyReceipt,
  identity: BackupKeyIdentity
): void {
  const { receiptSha256: _hash, schemaVersion: _version, ...registeredIdentity } = receipt;
  if (canonicalJson(registeredIdentity) !== canonicalJson(identity)) {
    throw new Error("backup key receipt does not match the active registry identity");
  }
}

function receiptFromIdentity(identity: BackupKeyIdentity): BackupKeyReceipt {
  const body = ReceiptBodySchema.parse({
    ...identity,
    schemaVersion: "boardagent.backup-key-registration.v1"
  });
  return BackupKeyReceiptSchema.parse({ ...body, receiptSha256: canonicalSha256(body) });
}

export function verifyBackupKeyBytes(key: Uint8Array, expectedFingerprint: string): void {
  const fingerprint = Sha256HexSchema.parse(expectedFingerprint);
  if (key.byteLength !== 32 || createHash("sha256").update(key).digest("hex") !== fingerprint) {
    throw new Error("backup key bytes do not match the registered fingerprint");
  }
}

export async function readBackupKeyReceipt(filePath: string): Promise<BackupKeyReceipt> {
  const handle = await open(
    path.resolve(filePath),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size < 2 || stat.size > 8192) {
      throw new Error("backup key receipt must be a bounded owner-only regular file");
    }
    const bytes = Buffer.alloc(8193);
    let length = 0;
    while (length < bytes.length) {
      const read = await handle.read(bytes, length, bytes.length - length, null);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    const after = await handle.stat();
    if (
      length !== stat.size ||
      length > 8192 ||
      after.size !== stat.size ||
      after.mtimeMs !== stat.mtimeMs ||
      (after.mode & 0o077) !== 0
    ) {
      throw new Error("backup key receipt changed or exceeded its byte limit while being read");
    }
    const receipt = BackupKeyReceiptSchema.parse(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, length)))
    );
    const { receiptSha256, ...body } = receipt;
    if (canonicalSha256(body) !== receiptSha256)
      throw new Error("backup key receipt hash mismatch");
    return receipt;
  } finally {
    await handle.close();
  }
}

export async function verifyBackupKeyReceipt(input: {
  receiptFile: string;
  organizationId: string;
  keyId: string;
  key: Uint8Array;
}): Promise<BackupKeyReceipt> {
  const receipt = await readBackupKeyReceipt(input.receiptFile);
  if (
    receipt.organizationId !== UuidV7Schema.parse(input.organizationId) ||
    receipt.keyId !== UuidV7Schema.parse(input.keyId)
  ) {
    throw new Error("backup key receipt identity does not match the configured instance");
  }
  verifyBackupKeyBytes(input.key, receipt.fingerprintSha256);
  return receipt;
}

/** Publish immutable metadata, never a secret. Exact replay preserves identical bytes. */
export async function writeBackupKeyReceipt(
  directoryValue: string,
  identity: BackupKeyIdentity
): Promise<{
  readonly receipt: BackupKeyReceipt;
  readonly receiptFile: string;
}> {
  const directory = path.resolve(directoryValue);
  const stat = await lstat(directory);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o077) !== 0 ||
    stat.uid !== process.getuid?.()
  ) {
    throw new Error("backup key receipt directory must be private and owned by its writer");
  }
  const receipt = receiptFromIdentity(identity);
  const receiptFile = path.join(directory, `${receipt.keyId}.json`);
  const bytes = `${canonicalJson(receipt)}\n`;
  const temporary = path.join(directory, `.receipt-${randomBytes(16).toString("hex")}`);
  const handle = await open(temporary, "wx", 0o400);
  try {
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  } finally {
    await handle.close();
  }
  try {
    await link(temporary, receiptFile).catch(async (error: unknown) => {
      if (
        typeof error !== "object" ||
        error === null ||
        !("code" in error) ||
        error.code !== "EEXIST"
      )
        throw error;
      const existing = await readBackupKeyReceipt(receiptFile);
      if (canonicalJson(existing) !== canonicalJson(receipt))
        throw new Error("backup key receipt already exists with different metadata");
    });
    const directoryHandle = await open(directory, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } finally {
    await unlink(temporary);
  }
  return { receipt, receiptFile };
}
