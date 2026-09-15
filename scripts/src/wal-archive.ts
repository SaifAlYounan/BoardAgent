import { createHash, randomBytes } from "node:crypto";
import { link, lstat, open, readFile, readdir, rm, unlink } from "node:fs/promises";
import path from "node:path";

import { type JsonValue } from "@boardagent/contracts";
import { z } from "zod";
import { loadRecoveryKeyring, RecoveryKeyringError } from "./recovery-keyring.js";

import {
  decryptBackupArtifact,
  encryptBackupArtifact,
  loadBackupEncryptionKey,
  verifyBackupArtifact
} from "./recovery-artifact.js";
import {
  completeRecoveryKeyIdentity,
  manifestBackupKeyIdentity,
  RecoveryManifestKeyFields,
  verifyBackupKeyBytes,
  verifyBackupKeyReceipt,
  verifyRecoveryManifestKey,
  type BackupKeyReceipt
} from "./backup-key-binding.js";
import {
  isRecoveryTemporaryFile,
  publishRecoveryJson,
  recoveryTemporaryReport,
  syncRecoveryDirectory,
  type RecoveryTemporaryReport
} from "./recovery-publication.js";

const WalNameSchema = z
  .string()
  .regex(/^(?:[0-9A-F]{24}|[0-9A-F]{8}\.history|[0-9A-F]{24}\.[0-9A-F]{8}\.backup)$/u);
const UuidV7TextSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);
const DecimalCountSchema = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);

function missingPath(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

export const WalArchiveManifestSchema = z
  .object({
    schemaVersion: z.literal("boardagent.wal-archive.v1"),
    walFile: WalNameSchema,
    archivedAt: z.iso.datetime({ offset: true }),
    encryptionKeyId: UuidV7TextSchema,
    ...RecoveryManifestKeyFields,
    format: z.literal("postgresql-wal-aes256gcm-v1"),
    artifactSha256: Sha256Schema,
    artifactBytes: DecimalCountSchema,
    plaintextSha256: Sha256Schema,
    plaintextBytes: DecimalCountSchema
  })
  .strict()
  .refine(completeRecoveryKeyIdentity, { message: "WAL archive key identity is incomplete" });
export type WalArchiveManifest = z.infer<typeof WalArchiveManifestSchema>;

export interface ArchiveWalOnceInput {
  readonly organizationId: string;
  readonly keyRegistrationFile: string;
  readonly stagingDirectory: string;
  readonly destinationDirectory: string;
  readonly encryptionKeyFile: string;
  readonly encryptionKeyId: string;
  readonly archivedAt?: string;
  /** Explicit one-shot replay recovery; historical keys never encrypt new WAL. */
  readonly recoveryKeyringFile?: string;
  /** Continuous mode observes the growing destination at most once per minute. */
  readonly inspectDestinationTemporaries?: boolean;
}

type ArchiveStage =
  "paths" | "staging" | "key_material" | "key_registration" | "recovery_keys" | "archive";
const ArchiveStorageReason = {
  ENOSPC: "storage_full",
  EDQUOT: "storage_quota_exceeded",
  EACCES: "file_permission_denied",
  EPERM: "file_permission_denied",
  ENOENT: "file_missing",
  EIO: "storage_io_failure",
  EROFS: "storage_read_only",
  EEXIST: "publication_conflict",
  ELOOP: "symlink_refused",
  "28P01": "database_authentication_failed",
  "42501": "database_permission_denied"
} as const;

class ArchiveWalError extends Error {
  constructor(
    readonly stage: ArchiveStage,
    cause: unknown
  ) {
    super("WAL archive operation failed", { cause });
  }
}

class ArchivePairsError extends Error {
  constructor(
    readonly artifactNames: readonly string[],
    readonly manifestNames: readonly string[],
    readonly unknownFileCount: number
  ) {
    super("encrypted WAL archive must contain exact artifact/manifest pairs");
  }
}

class ArchiveEmptyError extends Error {
  constructor() {
    super("encrypted WAL archive has no published pairs");
  }
}

/** Only fixed enums cross the operational log boundary; never paths, input or error text. */
export function archiveWalFailureDetails(error: unknown): {
  readonly stage: ArchiveStage | "unknown";
  readonly reasonCode: string;
  readonly unpairedArtifactCount?: number;
  readonly unpairedArtifacts?: readonly string[];
  readonly unpairedManifestCount?: number;
  readonly unpairedManifests?: readonly string[];
  readonly unknownFileCount?: number;
} {
  if (error instanceof ArchiveEmptyError) return { stage: "archive", reasonCode: "archive_empty" };
  if (error instanceof ArchivePairsError)
    return {
      stage: "archive",
      reasonCode: "archive_pairs_incomplete",
      unpairedArtifactCount: error.artifactNames.length,
      unpairedArtifacts: error.artifactNames.slice(0, 20),
      unpairedManifestCount: error.manifestNames.length,
      unpairedManifests: error.manifestNames.slice(0, 20),
      unknownFileCount: error.unknownFileCount
    };
  const cause = error instanceof ArchiveWalError ? error.cause : error;
  if (cause instanceof RecoveryKeyringError)
    return { stage: "recovery_keys", reasonCode: cause.reasonCode };
  const code =
    typeof cause === "object" && cause !== null && "code" in cause ? cause.code : undefined;
  if (
    typeof code === "string" &&
    (/^08[0-9A-Z]{3}$/u.test(code) ||
      ["57P01", "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT"].includes(code))
  ) {
    return {
      stage: error instanceof ArchiveWalError ? error.stage : "unknown",
      reasonCode: "connection_unavailable"
    };
  }
  return {
    stage: error instanceof ArchiveWalError ? error.stage : "unknown",
    reasonCode:
      typeof code === "string" && Object.hasOwn(ArchiveStorageReason, code)
        ? ArchiveStorageReason[code as keyof typeof ArchiveStorageReason]
        : "validation_or_operation_failed"
  };
}

async function realDirectory(rawPath: string, label: string): Promise<string> {
  const directory = path.resolve(rawPath);
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory`);
  }
  return directory;
}

async function regularFile(filePath: string, label: string): Promise<void> {
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1) {
    throw new Error(`${label} must be a nonempty regular file`);
  }
}

async function writeManifest(filePath: string, manifest: WalArchiveManifest): Promise<void> {
  await publishRecoveryJson(filePath, manifest as JsonValue);
}

async function acknowledgeStagedWal(sourcePath: string, destination: string): Promise<void> {
  await syncRecoveryDirectory(destination);
  await unlink(sourcePath);
  await syncRecoveryDirectory(path.dirname(sourcePath));
}

async function plaintextIdentity(
  artifactPath: string,
  key: Uint8Array
): Promise<{ readonly sha256: string; readonly byteLength: number }> {
  const hash = createHash("sha256");
  let byteLength = 0;
  for await (const chunk of decryptBackupArtifact(artifactPath, key)) {
    hash.update(chunk);
    byteLength += chunk.length;
  }
  return { sha256: hash.digest("hex"), byteLength };
}

async function sourceIdentity(
  sourcePath: string
): Promise<{ readonly sha256: string; readonly byteLength: number }> {
  const hash = createHash("sha256");
  let byteLength = 0;
  const handle = await open(sourcePath, "r");
  try {
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk);
      byteLength += chunk.length;
    }
  } finally {
    await handle.close();
  }
  return { sha256: hash.digest("hex"), byteLength };
}

export async function readWalArchiveManifest(filePath: string): Promise<WalArchiveManifest> {
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 65_536) {
    throw new Error("WAL archive manifest must be a bounded regular file");
  }
  return WalArchiveManifestSchema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readFile(filePath)))
  );
}

async function validatePublishedWal(
  sourcePath: string,
  artifactPath: string,
  manifest: WalArchiveManifest,
  key: Uint8Array
): Promise<void> {
  await verifyBackupArtifact(artifactPath, manifest.artifactSha256, Number(manifest.artifactBytes));
  const [source, decrypted] = await Promise.all([
    sourceIdentity(sourcePath),
    plaintextIdentity(artifactPath, key)
  ]);
  if (
    source.sha256 !== manifest.plaintextSha256 ||
    String(source.byteLength) !== manifest.plaintextBytes ||
    decrypted.sha256 !== manifest.plaintextSha256 ||
    String(decrypted.byteLength) !== manifest.plaintextBytes
  ) {
    throw new Error("published WAL archive does not match its staged source and manifest");
  }
}

async function archiveOne(
  sourcePath: string,
  destination: string,
  walFile: string,
  key: Uint8Array,
  encryptionKeyId: string,
  archivedAt: string,
  registration: BackupKeyReceipt,
  historicalKeys?: ReadonlyMap<string, Buffer>
): Promise<"archived" | "replayed" | "previous_generation_replayed"> {
  const artifactPath = path.join(destination, `${walFile}.aes256gcm`);
  const manifestPath = path.join(destination, `${walFile}.manifest.json`);
  const [artifactExists, manifestExists] = await Promise.all([
    lstat(artifactPath).then(
      () => true,
      (error) => {
        if (missingPath(error)) return false;
        throw error;
      }
    ),
    lstat(manifestPath).then(
      () => true,
      (error) => {
        if (missingPath(error)) return false;
        throw error;
      }
    )
  ]);
  if (manifestExists && !artifactExists) {
    throw new Error("WAL archive manifest exists without its encrypted artifact");
  }
  if (manifestExists) {
    const manifest = await readWalArchiveManifest(manifestPath);
    if (manifest.walFile !== walFile)
      throw new Error("published WAL archive identity does not match this operation");
    const previousGeneration = manifest.encryptionKeyId !== encryptionKeyId;
    const selectedKey = previousGeneration ? historicalKeys?.get(manifest.encryptionKeyId) : key;
    if (!selectedKey) throw new RecoveryKeyringError("recovery_wal_key_missing");
    if (previousGeneration) {
      // Retained material can authenticate a published historical artifact only.
      // Current registration remains mandatory for the command and all new writes.
      if (
        manifest.instanceId !== undefined &&
        (manifest.instanceId !== registration.instanceId ||
          manifest.organizationId !== registration.organizationId)
      )
        throw new RecoveryKeyringError("recovery_key_target_mismatch");
      verifyRecoveryManifestKey(manifest, selectedKey);
    } else verifyRecoveryManifestKey(manifest, selectedKey, registration);
    await validatePublishedWal(sourcePath, artifactPath, manifest, selectedKey);
    await acknowledgeStagedWal(sourcePath, destination);
    return previousGeneration ? "previous_generation_replayed" : "replayed";
  }

  let encrypted: Awaited<ReturnType<typeof encryptBackupArtifact>> | undefined;
  if (!artifactExists) {
    const sourceHandle = await open(sourcePath, "r");
    try {
      encrypted = await encryptBackupArtifact(
        sourceHandle.createReadStream({ autoClose: false }),
        artifactPath,
        key
      );
    } finally {
      await sourceHandle.close();
    }
  } else {
    const stat = await lstat(artifactPath);
    const plaintext = await plaintextIdentity(artifactPath, key);
    const cipherHash = createHash("sha256")
      .update(await readFile(artifactPath))
      .digest("hex");
    encrypted = {
      sha256: cipherHash,
      byteLength: stat.size,
      plaintextSha256: plaintext.sha256,
      plaintextByteLength: plaintext.byteLength
    };
  }
  const manifest = WalArchiveManifestSchema.parse({
    schemaVersion: "boardagent.wal-archive.v1",
    walFile,
    archivedAt,
    encryptionKeyId,
    ...manifestBackupKeyIdentity(registration),
    format: "postgresql-wal-aes256gcm-v1",
    artifactSha256: encrypted.sha256,
    artifactBytes: String(encrypted.byteLength),
    plaintextSha256: encrypted.plaintextSha256,
    plaintextBytes: String(encrypted.plaintextByteLength)
  });
  await writeManifest(manifestPath, manifest);
  await validatePublishedWal(sourcePath, artifactPath, manifest, key);
  await acknowledgeStagedWal(sourcePath, destination);
  return "archived";
}

async function writeDecryptedWal(
  artifactPath: string,
  targetPath: string,
  key: Uint8Array,
  expectedSha256: string,
  expectedBytes: string
): Promise<void> {
  const temporary = `${targetPath}.partial-${String(process.pid)}-${randomBytes(8).toString("hex")}`;
  const handle = await open(temporary, "wx", 0o600);
  const hash = createHash("sha256");
  let byteLength = 0;
  let closed = false;
  try {
    for await (const chunk of decryptBackupArtifact(artifactPath, key, path.dirname(targetPath))) {
      hash.update(chunk);
      byteLength += chunk.length;
      let offset = 0;
      while (offset < chunk.length) {
        const result = await handle.write(chunk, offset, chunk.length - offset, null);
        if (result.bytesWritten < 1) throw new Error("WAL recovery write made no progress");
        offset += result.bytesWritten;
      }
    }
    if (hash.digest("hex") !== expectedSha256 || String(byteLength) !== expectedBytes) {
      throw new Error("decrypted WAL does not match its archive manifest");
    }
    await handle.sync();
    await handle.close();
    closed = true;
    await link(temporary, targetPath);
    await unlink(temporary);
  } catch (error) {
    if (!closed) await handle.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function materializeWalArchive(input: {
  readonly archiveDirectory: string;
  readonly targetDirectory: string;
  readonly encryptionKeyFile: string;
  readonly encryptionKeyId: string;
  readonly expectedKeyFingerprintSha256?: string | undefined;
  readonly expectedInstanceId?: string | undefined;
  readonly expectedOrganizationId?: string | undefined;
  readonly recoveryKeyringFile?: string | undefined;
}): Promise<
  {
    readonly walFiles: readonly string[];
    readonly legacyIdOnlyCount: number;
    readonly recoveryKeyringSha256?: string;
    readonly recoveryKeyIds?: readonly string[];
  } & RecoveryTemporaryReport
> {
  const archive = await realDirectory(input.archiveDirectory, "encrypted WAL archive directory");
  const target = await realDirectory(input.targetDirectory, "WAL recovery target directory");
  if ((await readdir(target)).length !== 0) {
    throw new Error("WAL recovery target directory must be empty");
  }
  const encryptionKeyId = UuidV7TextSchema.parse(input.encryptionKeyId);
  const observedEntries = (await readdir(archive, { withFileTypes: true })).toSorted(
    (left, right) => left.name.localeCompare(right.name)
  );
  if (observedEntries.some((entry) => !entry.isFile())) {
    throw new Error("encrypted WAL archive contains a non-file entry");
  }
  const temporaryNames = observedEntries
    .filter(({ name }) => isRecoveryTemporaryFile(name, "wal"))
    .map(({ name }) => name);
  const entries = observedEntries.filter(({ name }) => !isRecoveryTemporaryFile(name, "wal"));
  const isManifestName = (name: string) =>
    name.endsWith(".manifest.json") &&
    WalNameSchema.safeParse(name.slice(0, -".manifest.json".length)).success;
  const isArtifactName = (name: string) =>
    name.endsWith(".aes256gcm") &&
    WalNameSchema.safeParse(name.slice(0, -".aes256gcm".length)).success;
  const manifestNames = entries.map(({ name }) => name).filter(isManifestName);
  const artifactNames = entries.map(({ name }) => name).filter(isArtifactName);
  const names = new Set(entries.map(({ name }) => name));
  const unpairedArtifacts = artifactNames.filter(
    (name) => !names.has(name.slice(0, -".aes256gcm".length) + ".manifest.json")
  );
  const unpairedManifests = manifestNames.filter(
    (name) => !names.has(name.slice(0, -".manifest.json".length) + ".aes256gcm")
  );
  const unknownFileCount = entries.length - manifestNames.length - artifactNames.length;
  if (entries.length === 0) throw new ArchiveEmptyError();
  if (
    manifestNames.length < 1 ||
    unpairedArtifacts.length > 0 ||
    unpairedManifests.length > 0 ||
    unknownFileCount > 0
  ) {
    throw new ArchivePairsError(unpairedArtifacts, unpairedManifests, unknownFileCount);
  }
  const key = await loadBackupEncryptionKey(path.resolve(input.encryptionKeyFile));
  let keyring: Awaited<ReturnType<typeof loadRecoveryKeyring>> | undefined;
  const walFiles: string[] = [];
  let recoveryKeyIds: string[] = [];
  let legacyIdOnlyCount = 0;
  try {
    if (input.recoveryKeyringFile !== undefined)
      keyring = await loadRecoveryKeyring(path.resolve(input.recoveryKeyringFile), {
        keyId: encryptionKeyId,
        key,
        instanceId: input.expectedInstanceId,
        organizationId: input.expectedOrganizationId
      });
    if (input.expectedKeyFingerprintSha256 !== undefined) {
      // Cross-bind to the selected base backup even when some WAL manifests are legacy.
      verifyBackupKeyBytes(key, input.expectedKeyFingerprintSha256);
    }
    // Refuse an inconsistent key set before writing any decrypted segment.
    const manifests: WalArchiveManifest[] = [];
    for (const name of manifestNames)
      manifests.push(await readWalArchiveManifest(path.join(archive, name)));
    recoveryKeyIds = [
      ...new Set([encryptionKeyId, ...manifests.map((m) => m.encryptionKeyId)])
    ].sort();
    let observedInstance = input.expectedInstanceId ?? keyring?.instanceId;
    let observedOrganization = input.expectedOrganizationId ?? keyring?.organizationId;
    for (const manifest of manifests) {
      const selectedKey = keyring
        ? keyring.keys.get(manifest.encryptionKeyId)
        : manifest.encryptionKeyId === encryptionKeyId
          ? key
          : undefined;
      if (!selectedKey) {
        if (keyring) throw new RecoveryKeyringError("recovery_wal_key_missing");
        throw new Error("WAL key identity does not match recovery");
      }
      legacyIdOnlyCount += verifyRecoveryManifestKey(manifest, selectedKey);
      if (manifest.instanceId !== undefined) {
        if (
          (observedInstance !== undefined && manifest.instanceId !== observedInstance) ||
          (observedOrganization !== undefined && manifest.organizationId !== observedOrganization)
        ) {
          throw new Error("WAL archive contains a different instance identity");
        }
        observedInstance = manifest.instanceId;
        observedOrganization = manifest.organizationId;
      }
    }
    for (const [index, manifestName] of manifestNames.entries()) {
      const manifest = manifests[index]!;
      if (manifestName !== `${manifest.walFile}.manifest.json`) {
        throw new Error("WAL archive pair identity does not match this recovery operation");
      }
      const artifactName = `${manifest.walFile}.aes256gcm`;
      if (!entries.some(({ name }) => name === artifactName)) {
        throw new Error("WAL archive manifest is missing its encrypted artifact");
      }
      const artifactBytes = Number(manifest.artifactBytes);
      if (!Number.isSafeInteger(artifactBytes) || artifactBytes < 1) {
        throw new Error("WAL archive length exceeds the local verifier limit");
      }
      const artifactPath = path.join(archive, artifactName);
      await verifyBackupArtifact(artifactPath, manifest.artifactSha256, artifactBytes);
      await writeDecryptedWal(
        artifactPath,
        path.join(target, manifest.walFile),
        keyring ? keyring.keys.get(manifest.encryptionKeyId)! : key,
        manifest.plaintextSha256,
        manifest.plaintextBytes
      );
      walFiles.push(manifest.walFile);
    }
  } finally {
    key.fill(0);
    keyring?.destroy();
  }
  return {
    walFiles,
    legacyIdOnlyCount,
    ...recoveryTemporaryReport(temporaryNames),
    ...(keyring
      ? {
          recoveryKeyringSha256: keyring.manifestSha256,
          recoveryKeyIds
        }
      : {})
  };
}

export async function archiveWalOnce(input: ArchiveWalOnceInput): Promise<
  {
    readonly archived: number;
    readonly replayed: number;
    readonly previousGenerationReplayed?: number;
    readonly recoveryKeyringSha256?: string;
  } & RecoveryTemporaryReport
> {
  let stage: ArchiveStage = "paths";
  try {
    const staging = await realDirectory(input.stagingDirectory, "WAL staging directory");
    const destination = await realDirectory(
      input.destinationDirectory,
      "WAL archive destination directory"
    );
    const encryptionKeyId = UuidV7TextSchema.parse(input.encryptionKeyId);
    const archivedAt = z.iso
      .datetime({ offset: true })
      .parse(input.archivedAt ?? new Date().toISOString());
    stage = "staging";
    const entries = (await readdir(staging, { withFileTypes: true })).toSorted((left, right) =>
      left.name.localeCompare(right.name)
    );
    const isHookTemporary = (name: string): boolean => {
      const match = /^(.*)\.partial\.[1-9][0-9]{0,9}$/u.exec(name);
      return match !== null && WalNameSchema.safeParse(match[1]).success;
    };
    const unexpected = entries.find(
      (entry) =>
        !entry.isFile() ||
        (!WalNameSchema.safeParse(entry.name).success && !isHookTemporary(entry.name))
    );
    if (unexpected) throw new Error(`unexpected WAL staging entry: ${unexpected.name}`);
    const destinationTemporaries: string[] = [];
    if (input.inspectDestinationTemporaries !== false) {
      stage = "archive";
      for (const entry of await readdir(destination, { withFileTypes: true })) {
        if (!isRecoveryTemporaryFile(entry.name, "wal")) continue;
        if (!entry.isFile()) throw new Error("WAL archive temporary must be a regular file");
        destinationTemporaries.push(entry.name);
      }
    }

    stage = "key_material";
    const key = await loadBackupEncryptionKey(path.resolve(input.encryptionKeyFile));
    let archived = 0;
    let replayed = 0;
    let previousGenerationReplayed = 0;
    let keyring: Awaited<ReturnType<typeof loadRecoveryKeyring>> | undefined;
    try {
      stage = "key_registration";
      const registration = await verifyBackupKeyReceipt({
        receiptFile: input.keyRegistrationFile,
        organizationId: input.organizationId,
        keyId: encryptionKeyId,
        key
      });
      if (input.recoveryKeyringFile !== undefined) {
        stage = "recovery_keys";
        keyring = await loadRecoveryKeyring(path.resolve(input.recoveryKeyringFile), {
          keyId: encryptionKeyId,
          key,
          instanceId: registration.instanceId,
          organizationId: registration.organizationId
        });
      }
      stage = "archive";
      for (const entry of entries.filter(({ name }) => !isHookTemporary(name))) {
        const sourcePath = path.join(staging, entry.name);
        await regularFile(sourcePath, "staged WAL segment");
        const outcome = await archiveOne(
          sourcePath,
          destination,
          entry.name,
          key,
          encryptionKeyId,
          archivedAt,
          registration,
          keyring?.keys
        );
        if (outcome === "archived") archived += 1;
        else {
          replayed += 1;
          if (outcome === "previous_generation_replayed") previousGenerationReplayed += 1;
        }
      }
    } finally {
      key.fill(0);
      keyring?.destroy();
    }
    return {
      archived,
      replayed,
      ...(keyring
        ? { previousGenerationReplayed, recoveryKeyringSha256: keyring.manifestSha256 }
        : {}),
      ...recoveryTemporaryReport([
        ...entries.filter(({ name }) => isHookTemporary(name)).map(({ name }) => name),
        ...destinationTemporaries
      ])
    };
  } catch (error) {
    throw new ArchiveWalError(stage, error);
  }
}
