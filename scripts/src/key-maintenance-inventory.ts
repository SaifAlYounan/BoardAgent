import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, open, opendir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BackupManifestSchema, ExportArtifactManifestSchema } from "@boardagent/db";
import { canonicalJsonFromText, canonicalSha256 } from "@boardagent/contracts";
import { BaseBackupManifestSchema } from "./base-backup.js";
import { WalArchiveManifestSchema } from "./wal-archive.js";
import {
  OperatorFilePathSchema,
  assertOperatorFileParents,
  readOperatorProtectedFile
} from "./operator-key-files.js";

// Local inventory is bounded independently of the database dependency count. No deletion occurs.
export const KEY_INVENTORY_LIMITS = {
  roots: 64,
  files: 20_000,
  depth: 32,
  bytes: 8 * 1024 ** 4,
  milliseconds: 600_000
} as const;
interface RetainedFile {
  readonly file: string;
  readonly bytes: string;
  readonly sha256: string;
}
interface KeyBinding {
  readonly keyId: string;
  readonly purpose: string;
  readonly materialSha256: string | null;
}
interface ManifestBinding {
  readonly file: string;
  readonly keyId: string;
  readonly kind: "logical" | "base" | "wal" | "export";
  readonly keyBinding: "full_fingerprint" | "legacy_id_only";
  readonly payload: "present_hash_verified" | "retired_metadata_only";
}

function safeStat(stat: Stats): boolean {
  return (
    stat.isFile() &&
    stat.nlink === 1 &&
    (stat.mode & 0o137) === 0 &&
    (stat.uid === 0 || stat.uid === process.getuid?.())
  );
}
function unchanged(a: Stats, b: Stats): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.size === b.size &&
    a.mtimeMs === b.mtimeMs &&
    a.ctimeMs === b.ctimeMs
  );
}
async function hashFile(
  file: string,
  remainingBytes: number,
  checkTime: () => void
): Promise<RetainedFile> {
  await assertOperatorFileParents(file);
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const buffer = Buffer.alloc(1_048_576);
  try {
    const before = await handle.stat();
    if (!safeStat(before) || before.size > remainingBytes)
      throw new Error("unsafe or oversized retained artifact");
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < before.size) {
      checkTime();
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, before.size - offset),
        offset
      );
      if (bytesRead === 0) throw new Error("retained artifact shortened");
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    if (!unchanged(before, await handle.stat()) || !unchanged(before, await lstat(file)))
      throw new Error("retained artifact changed");
    return { file, bytes: String(offset), sha256: hash.digest("hex") };
  } finally {
    buffer.fill(0);
    await handle.close();
  }
}
function adjacentFile(manifestFile: string, locator: string): string {
  const url = new URL(locator);
  if (
    url.protocol !== "file:" ||
    url.search ||
    url.hash ||
    (url.hostname && url.hostname !== "localhost")
  )
    throw new Error("unsupported recovery artifact locator");
  return path.join(path.dirname(manifestFile), path.basename(fileURLToPath(url)));
}

/** Hash every local file under explicit non-overlapping recovery roots; never infer off-host custody. */
export async function inspectRetainedRecoveryFiles(
  roots: readonly string[],
  keys: readonly KeyBinding[],
  target: { instanceId: string; organizationId: string }
) {
  if (roots.length > KEY_INVENTORY_LIMITS.roots || new Set(roots).size !== roots.length)
    throw new Error("invalid recovery roots");
  for (const root of roots) {
    OperatorFilePathSchema.parse(root);
    if (roots.some((other) => other !== root && root.startsWith(`${other}/`)))
      throw new Error("overlapping recovery roots");
  }
  const deadline = Date.now() + KEY_INVENTORY_LIMITS.milliseconds;
  const checkTime = () => {
    if (Date.now() > deadline) throw new Error("recovery inventory time limit reached");
  };
  const files: RetainedFile[] = [];
  let totalBytes = 0;
  const walk = async (directory: string, depth: number): Promise<void> => {
    checkTime();
    if (depth > KEY_INVENTORY_LIMITS.depth)
      throw new Error("recovery inventory depth limit reached");
    await assertOperatorFileParents(path.join(directory, ".inventory-path-check"));
    const before = await lstat(directory),
      stream = await opendir(directory);
    for await (const entry of stream) {
      checkTime();
      const file = path.join(directory, entry.name),
        stat = await lstat(file);
      if (stat.isDirectory()) await walk(file, depth + 1);
      else {
        if (files.length >= KEY_INVENTORY_LIMITS.files || !safeStat(stat))
          throw new Error("unsafe or excessive recovery inventory");
        const observed = await hashFile(file, KEY_INVENTORY_LIMITS.bytes - totalBytes, checkTime);
        files.push(observed);
        totalBytes += Number(observed.bytes);
      }
    }
    const after = await lstat(directory);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      throw new Error("recovery directory changed during inventory");
  };
  for (const root of roots.toSorted()) await walk(root, 0);
  files.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  const fileMap = new Map(files.map((file) => [file.file, file]));
  const keyMap = new Map(keys.map((key) => [key.keyId, key]));
  if (keyMap.size !== keys.length) throw new Error("duplicate retained key identity");
  const manifests: ManifestBinding[] = [];
  const checkArtifact = (file: string, sha256: string, bytes: string) => {
    const actual = fileMap.get(file);
    if (!actual || actual.sha256 !== sha256 || actual.bytes !== bytes)
      throw new Error("retained manifest artifact missing or mismatched");
  };
  for (const record of files) {
    checkTime();
    if (!record.file.endsWith(".json") && !record.file.endsWith(".manifest.json.retired")) continue;
    const raw = await readOperatorProtectedFile(record.file, 16_777_216);
    let value: unknown;
    try {
      if (createHash("sha256").update(raw).digest("hex") !== record.sha256)
        throw new Error("recovery manifest changed");
      value = JSON.parse(canonicalJsonFromText(raw));
    } finally {
      raw.fill(0);
    }
    const version =
      typeof value === "object" && value !== null && "schemaVersion" in value
        ? value.schemaVersion
        : undefined;
    let kind: ManifestBinding["kind"],
      binding: {
        encryptionKeyId: string;
        encryptionKeyFingerprintSha256?: string | undefined;
        instanceId?: string | undefined;
        organizationId?: string | undefined;
        encryptionKeyKid?: string | undefined;
      };
    if (version === "boardagent.backup-receipt.v1" || version === "boardagent.backup-receipt.v2") {
      const m = BackupManifestSchema.parse(value);
      kind = "logical";
      binding = m;
      checkArtifact(
        adjacentFile(record.file, m.artifact.encryptedStorageLocator),
        m.artifact.artifactSha256,
        m.artifact.byteLength
      );
    } else if (version === "boardagent.base-backup.v1") {
      const m = BaseBackupManifestSchema.parse(value);
      kind = "base";
      binding = m;
      if (!record.file.endsWith(".retired"))
        checkArtifact(
          adjacentFile(record.file, m.encryptedStorageLocator),
          m.artifactSha256,
          m.artifactBytes
        );
    } else if (version === "boardagent.wal-archive.v1") {
      const m = WalArchiveManifestSchema.parse(value);
      kind = "wal";
      binding = m;
      checkArtifact(
        path.join(path.dirname(record.file), `${m.walFile}.aes256gcm`),
        m.artifactSha256,
        m.artifactBytes
      );
    } else if (version === "boardagent.export-artifact.v1") {
      const m = ExportArtifactManifestSchema.parse(value);
      kind = "export";
      binding = m;
      if (!m.complete) throw new Error("unfinished retained export");
      const locator = `boardagent-export:v1/${m.exportRequestId}/${m.artifactId}`;
      if (
        m.encryptedStorageLocator !== locator ||
        m.encryptedContentSetSha256 !==
          canonicalSha256({
            schemaVersion: "boardagent.export-encrypted-content-set.v1",
            chunks: m.chunks.map(({ ordinal, byteOffset, byteLength, chunkSha256 }) => ({
              ordinal,
              byteOffset,
              byteLength,
              chunkSha256
            }))
          })
      )
        throw new Error("retained export content identity mismatch");
      for (const chunk of m.chunks) {
        if (chunk.storageLocator !== `${locator}/${chunk.ordinal}`)
          throw new Error("unsupported retained export locator");
        checkArtifact(
          path.join(path.dirname(record.file), `${chunk.ordinal}.bin`),
          chunk.chunkSha256,
          String(chunk.byteLength)
        );
      }
    } else {
      if (
        record.file.endsWith(".manifest.json") ||
        record.file.endsWith(".manifest.json.retired") ||
        path.basename(record.file) === "manifest.json"
      )
        throw new Error("unknown retained manifest schema");
      continue;
    }
    const key = keyMap.get(binding.encryptionKeyId);
    if (
      !key ||
      key.purpose !== (kind === "export" ? "data_kek" : "backup_kek") ||
      (binding.instanceId !== undefined && binding.instanceId !== target.instanceId) ||
      (binding.organizationId !== undefined && binding.organizationId !== target.organizationId) ||
      (binding.encryptionKeyFingerprintSha256 !== undefined &&
        binding.encryptionKeyFingerprintSha256 !== key.materialSha256) ||
      (binding.encryptionKeyKid !== undefined && binding.encryptionKeyKid !== `backup-${key.keyId}`)
    )
      throw new Error("retained manifest key or installation mismatch");
    manifests.push({
      file: record.file,
      kind,
      keyId: key.keyId,
      keyBinding:
        binding.encryptionKeyFingerprintSha256 === undefined
          ? "legacy_id_only"
          : "full_fingerprint",
      payload: record.file.endsWith(".retired") ? "retired_metadata_only" : "present_hash_verified"
    });
  }
  const result = {
    schemaVersion: "boardagent.local-key-recovery-inventory.v1" as const,
    roots: roots.toSorted(),
    files,
    manifests,
    totalBytes: String(totalBytes),
    offHostCustody: "not_verified" as const
  };
  return { ...result, inventorySha256: canonicalSha256(result) };
}
