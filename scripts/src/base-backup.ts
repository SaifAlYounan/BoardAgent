import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { lstat, readFile, readdir, rename, rm } from "node:fs/promises";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { finished, pipeline } from "node:stream/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

import { canonicalSha256, type JsonValue } from "@boardagent/contracts";
import { uuidV7 } from "@boardagent/domain";
import { readActiveBackupKeyInTransaction, withBackupTransaction } from "@boardagent/db";
import { Pool } from "pg";
import { z } from "zod";

import {
  postgresBaseBackupSystemIdentifier,
  recoveryDatabaseName,
  runEncryptedPgBaseBackup,
  verifyPostgresBaseBackup
} from "./postgres-recovery.js";
import {
  decryptBackupArtifact,
  loadBackupEncryptionKey,
  verifyBackupArtifact
} from "./recovery-artifact.js";
import {
  assertReceiptMatchesRegistry,
  completeRecoveryKeyIdentity,
  manifestBackupKeyIdentity,
  RecoveryManifestKeyFields,
  verifyBackupKeyReceipt,
  verifyRecoveryManifestKey
} from "./backup-key-binding.js";
import {
  isRecoveryTemporaryFile,
  publishRecoveryJson,
  recoveryTemporaryReport,
  type RecoveryTemporaryReport
} from "./recovery-publication.js";

const UuidV7TextSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const PgLsnSchema = z.string().regex(/^[0-9A-F]+\/[0-9A-F]+$/u);
const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);
const ImageDigestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const DecimalCountSchema = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);

export const BaseBackupManifestSchema = z
  .object({
    schemaVersion: z.literal("boardagent.base-backup.v1"),
    backupId: UuidV7TextSchema,
    format: z.literal("postgresql-base-tar-encrypted-v1"),
    sourceDatabase: z.string().regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$/u),
    systemIdentifier: DecimalCountSchema,
    startedAt: z.iso.datetime({ offset: true }),
    completedAt: z.iso.datetime({ offset: true }),
    observedStartLsn: PgLsnSchema,
    observedEndLsn: PgLsnSchema,
    walMethod: z.literal("fetch"),
    manifestChecksums: z.literal("SHA256"),
    encryptionKeyId: UuidV7TextSchema,
    ...RecoveryManifestKeyFields,
    sourceImageDigest: ImageDigestSchema,
    pgBasebackupVersion: z.string().min(1).max(256),
    encryptedStorageLocator: z.url().startsWith("file:"),
    artifactSha256: Sha256Schema,
    artifactBytes: DecimalCountSchema,
    plaintextTarSha256: Sha256Schema,
    plaintextTarBytes: DecimalCountSchema,
    retention: z
      .object({ daily: z.literal(7), weekly: z.literal(4), monthly: z.literal(12) })
      .strict()
  })
  .strict()
  .refine(completeRecoveryKeyIdentity, { message: "base backup key identity is incomplete" })
  .refine((manifest) => Date.parse(manifest.completedAt) >= Date.parse(manifest.startedAt), {
    message: "base backup completion precedes its start"
  });
export type BaseBackupManifest = z.infer<typeof BaseBackupManifestSchema>;

export const BaseRestoreVerificationSchema = z
  .object({
    schemaVersion: z.literal("boardagent.base-restore-verification.v1"),
    backupId: UuidV7TextSchema,
    baseBackupManifestSha256: Sha256Schema,
    verifiedAt: z.iso.datetime({ offset: true }),
    pgVerifybackupVersion: z.string().min(1).max(256),
    systemIdentifier: DecimalCountSchema
  })
  .strict();

export interface CreateBaseBackupInput {
  readonly organizationId: string;
  readonly keyRegistrationFile: string;
  readonly databaseUrl: string;
  readonly destinationDirectory: string;
  readonly encryptionKeyFile: string;
  readonly encryptionKeyId: string;
  readonly sourceImageDigest: string;
  readonly now?: () => Date;
}

export interface VerifyBaseBackupInput {
  readonly manifestFile: string;
  readonly targetDirectory: string;
  readonly encryptionKeyFile: string;
  readonly encryptionKeyId: string;
}

export interface BaseBackupRetentionResult extends RecoveryTemporaryReport {
  readonly keptBackupIds: readonly string[];
  readonly prunedBackupIds: readonly string[];
  readonly resumedRetirements: number;
}

/** The backup is durable; retention is a separate, retryable operation. */
export class PublishedBaseBackupRetentionError extends Error {
  constructor(
    readonly backupId: string,
    readonly manifestFile: string,
    cause: unknown
  ) {
    super("base backup published but retention refused", { cause });
  }
}

interface RecoveryBoundary {
  readonly system_identifier: string;
  readonly current_lsn: string;
  readonly observed_at: string;
}

async function recoveryDirectory(rawPath: string): Promise<string> {
  const directory = path.resolve(rawPath);
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("base backup destination must be a real mounted directory");
  }
  return directory;
}

async function boundary(pool: Pool): Promise<RecoveryBoundary> {
  const result = await pool.query<RecoveryBoundary>(
    `select system_identifier::text,
            pg_current_wal_lsn()::text as current_lsn,
            to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') as observed_at
       from pg_control_system()`
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new Error("PostgreSQL recovery boundary was unavailable");
  }
  return row;
}

async function writeManifest(filePath: string, manifest: BaseBackupManifest): Promise<void> {
  await writeJsonFile(filePath, manifest as JsonValue);
}

async function writeJsonFile(filePath: string, value: JsonValue): Promise<void> {
  await publishRecoveryJson(filePath, value);
}

export async function readBaseBackupManifest(filePath: string): Promise<BaseBackupManifest> {
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 1_048_576) {
    throw new Error("base backup manifest must be a bounded regular file");
  }
  return BaseBackupManifestSchema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readFile(filePath)))
  );
}

function artifactPath(manifest: BaseBackupManifest): string {
  const locator = new URL(manifest.encryptedStorageLocator);
  if (
    locator.protocol !== "file:" ||
    locator.username ||
    locator.password ||
    locator.search ||
    locator.hash
  ) {
    throw new Error("base backup requires a mounted file artifact locator");
  }
  return fileURLToPath(locator);
}

function missingPath(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

async function exists(filePath: string): Promise<boolean> {
  return lstat(filePath).then(
    () => true,
    (error) => {
      if (missingPath(error)) return false;
      throw error;
    }
  );
}

function utcDay(timestamp: string): string {
  return timestamp.slice(0, 10);
}

function utcMonth(timestamp: string): string {
  return timestamp.slice(0, 7);
}

function utcWeek(timestamp: string): string {
  const instant = new Date(timestamp);
  const daysAfterMonday = (instant.getUTCDay() + 6) % 7;
  const monday = new Date(
    Date.UTC(
      instant.getUTCFullYear(),
      instant.getUTCMonth(),
      instant.getUTCDate() - daysAfterMonday
    )
  );
  return monday.toISOString().slice(0, 10);
}

async function resumeRetirements(directory: string): Promise<number> {
  const retiredNames = (await readdir(directory))
    .filter((name) => name.endsWith(".base.manifest.json.retired"))
    .toSorted();
  for (const retiredName of retiredNames) {
    const retiredPath = path.join(directory, retiredName);
    const manifest = await readBaseBackupManifest(retiredPath);
    if (retiredName !== `boardagent-${manifest.backupId}.base.manifest.json.retired`) {
      throw new Error("retired base backup manifest filename does not match its identity");
    }
    const expectedArtifact = path.join(
      directory,
      `boardagent-${manifest.backupId}.base.tar.aes256gcm`
    );
    if (path.resolve(artifactPath(manifest)) !== expectedArtifact) {
      throw new Error("retired base backup artifact locator escapes its generation directory");
    }
    if (await exists(expectedArtifact)) {
      const artifactStat = await lstat(expectedArtifact);
      if (!artifactStat.isFile() || artifactStat.isSymbolicLink()) {
        throw new Error("retired base backup artifact is not a regular file");
      }
      await rm(expectedArtifact);
    }
    await rm(retiredPath);
  }
  return retiredNames.length;
}

function chooseRetentionIds(manifests: readonly BaseBackupManifest[]): ReadonlySet<string> {
  const ordered = [...manifests].toSorted(
    (left, right) =>
      Date.parse(right.completedAt) - Date.parse(left.completedAt) ||
      right.backupId.localeCompare(left.backupId)
  );
  const kept = new Set<string>();
  const keepBuckets = (limit: number, bucket: (manifest: BaseBackupManifest) => string): void => {
    const observed = new Set<string>();
    for (const manifest of ordered) {
      const key = bucket(manifest);
      if (observed.has(key)) continue;
      if (observed.size >= limit) break;
      observed.add(key);
      kept.add(manifest.backupId);
    }
  };
  keepBuckets(7, ({ completedAt }) => utcDay(completedAt));
  keepBuckets(4, ({ completedAt }) => utcWeek(completedAt));
  keepBuckets(12, ({ completedAt }) => utcMonth(completedAt));
  if (ordered[0]) kept.add(ordered[0].backupId);
  return kept;
}

/**
 * Enforces the frozen GFS generation policy. A manifest is atomically renamed first so
 * a crash can only leave a resumable retirement marker, never a live manifest pointing
 * at a deleted artifact. Unknown/orphaned entries fail closed before any new pruning.
 */
export async function pruneBaseBackupGenerations(
  rawDirectory: string
): Promise<BaseBackupRetentionResult> {
  const directory = await recoveryDirectory(rawDirectory);
  const resumedRetirements = await resumeRetirements(directory);
  const observedEntries = await readdir(directory, { withFileTypes: true });
  if (observedEntries.some((entry) => !entry.isFile()))
    throw new Error("base backup directory contains a non-file entry");
  const temporaryReport = recoveryTemporaryReport(
    observedEntries
      .filter(({ name }) => isRecoveryTemporaryFile(name, "base"))
      .map(({ name }) => name)
  );
  const entries = observedEntries.filter(({ name }) => !isRecoveryTemporaryFile(name, "base"));
  const manifestPattern = /^boardagent-([0-9a-f-]{36})\.base\.manifest\.json$/u;
  const artifactPattern = /^boardagent-([0-9a-f-]{36})\.base\.tar\.aes256gcm$/u;
  const unexpected = entries.find(
    (entry) =>
      !entry.isFile() || (!manifestPattern.test(entry.name) && !artifactPattern.test(entry.name))
  );
  if (unexpected) throw new Error(`unexpected base backup entry: ${unexpected.name}`);

  const manifests: BaseBackupManifest[] = [];
  const artifactNames = new Set(
    entries.filter(({ name }) => artifactPattern.test(name)).map(({ name }) => name)
  );
  for (const entry of entries.filter(({ name }) => manifestPattern.test(name))) {
    const manifestPath = path.join(directory, entry.name);
    const manifest = await readBaseBackupManifest(manifestPath);
    if (entry.name !== `boardagent-${manifest.backupId}.base.manifest.json`) {
      throw new Error("base backup manifest filename does not match its identity");
    }
    const expectedArtifactName = `boardagent-${manifest.backupId}.base.tar.aes256gcm`;
    const expectedArtifactPath = path.join(directory, expectedArtifactName);
    if (
      !artifactNames.delete(expectedArtifactName) ||
      path.resolve(artifactPath(manifest)) !== expectedArtifactPath
    ) {
      throw new Error("base backup generation is missing or misbinds its encrypted artifact");
    }
    const artifactStat = await lstat(expectedArtifactPath);
    if (
      !artifactStat.isFile() ||
      artifactStat.isSymbolicLink() ||
      String(artifactStat.size) !== manifest.artifactBytes
    ) {
      throw new Error("base backup artifact does not match its manifest boundary");
    }
    manifests.push(manifest);
  }
  if (artifactNames.size > 0) throw new Error("base backup artifact exists without its manifest");
  if (manifests.length === 0) {
    return { keptBackupIds: [], prunedBackupIds: [], resumedRetirements, ...temporaryReport };
  }
  if (
    new Set(manifests.map(({ sourceDatabase }) => sourceDatabase)).size !== 1 ||
    new Set(manifests.map(({ systemIdentifier }) => systemIdentifier)).size !== 1
  ) {
    throw new Error("base backup generation directory mixes database identities");
  }

  const kept = chooseRetentionIds(manifests);
  const pruned = manifests
    .filter(({ backupId }) => !kept.has(backupId))
    .toSorted((left, right) => left.completedAt.localeCompare(right.completedAt));
  for (const manifest of pruned) {
    const manifestPath = path.join(directory, `boardagent-${manifest.backupId}.base.manifest.json`);
    const retiredPath = `${manifestPath}.retired`;
    const encryptedArtifact = path.join(
      directory,
      `boardagent-${manifest.backupId}.base.tar.aes256gcm`
    );
    await rename(manifestPath, retiredPath);
    await rm(encryptedArtifact);
    await rm(retiredPath);
  }
  return {
    keptBackupIds: manifests
      .filter(({ backupId }) => kept.has(backupId))
      .map(({ backupId }) => backupId)
      .toSorted(),
    prunedBackupIds: pruned.map(({ backupId }) => backupId),
    resumedRetirements,
    ...temporaryReport
  };
}

async function emptyTargetDirectory(rawPath: string): Promise<string> {
  const directory = await recoveryDirectory(rawPath);
  if ((await readdir(directory)).length !== 0) {
    throw new Error("base backup verification target must be empty");
  }
  return directory;
}

async function extractAuthenticatedTar(
  encryptedArtifact: string,
  targetDirectory: string,
  key: Uint8Array,
  expectedPlaintextSha256: string,
  expectedPlaintextBytes: string
): Promise<void> {
  const child = spawn(
    "tar",
    [
      "--extract",
      "--file=-",
      `--directory=${targetDirectory}`,
      "--no-same-owner",
      "--no-same-permissions",
      "--delay-directory-restore"
    ],
    { stdio: ["pipe", "ignore", "pipe"] }
  );
  if (!child.stdin) throw new Error("tar stdin was unavailable");
  let diagnostic = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    if (diagnostic.length < 65_536) diagnostic += chunk.slice(0, 65_536 - diagnostic.length);
  });
  const completion = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (signal) reject(new Error("tar extraction was interrupted"));
      else resolve(code ?? 1);
    });
  });
  const hash = createHash("sha256");
  let byteLength = 0;
  const identity = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      hash.update(chunk);
      byteLength += chunk.length;
      callback(null, chunk);
    }
  });
  const controller = new AbortController();
  const source = Readable.from(
    decryptBackupArtifact(encryptedArtifact, key, targetDirectory, controller.signal),
    {
      objectMode: false
    }
  );
  const consumerCompletion = completion.finally(() => {
    if (!source.readableEnded)
      controller.abort(new Error("tar stopped before consuming the authenticated backup"));
  });
  try {
    const [, code] = await Promise.all([
      pipeline(source, identity, child.stdin),
      consumerCompletion
    ]);
    if (code !== 0)
      throw new Error(`tar extraction failed (${diagnostic.trim() || "no diagnostic"})`);
    if (
      hash.digest("hex") !== expectedPlaintextSha256 ||
      String(byteLength) !== expectedPlaintextBytes
    ) {
      throw new Error("decrypted base backup tar does not match its manifest");
    }
  } catch (error) {
    controller.abort(error);
    source.destroy();
    if (!child.killed) child.kill("SIGTERM");
    await consumerCompletion.catch(() => undefined);
    await finished(source, { cleanup: true }).catch(() => undefined);
    throw error;
  }
}

export async function createEncryptedBaseBackup(input: CreateBaseBackupInput): Promise<{
  readonly manifest: BaseBackupManifest;
  readonly manifestFile: string;
  readonly retention: BaseBackupRetentionResult;
}> {
  const destination = await recoveryDirectory(input.destinationDirectory);
  const encryptionKeyId = UuidV7TextSchema.parse(input.encryptionKeyId);
  const sourceImageDigest = ImageDigestSchema.parse(input.sourceImageDigest);
  const now = input.now ?? (() => new Date());
  const backupId = uuidV7(now().getTime(), randomBytes(10));
  const artifactPath = path.join(destination, `boardagent-${backupId}.base.tar.aes256gcm`);
  const manifestPath = path.join(destination, `boardagent-${backupId}.base.manifest.json`);
  const key = await loadBackupEncryptionKey(path.resolve(input.encryptionKeyFile));
  const pool = new Pool({ connectionString: input.databaseUrl, max: 1 });
  let published = false;
  try {
    const registration = await verifyBackupKeyReceipt({
      receiptFile: input.keyRegistrationFile,
      organizationId: input.organizationId,
      keyId: encryptionKeyId,
      key
    });
    const activeKey = await withBackupTransaction(
      pool,
      (client) => readActiveBackupKeyInTransaction(client, encryptionKeyId),
      { assumeRole: "boardagent_backup" }
    );
    assertReceiptMatchesRegistry(registration, activeKey);
    const started = await boundary(pool);
    const artifact = await runEncryptedPgBaseBackup({
      databaseUrl: input.databaseUrl,
      artifactPath,
      encryptionKey: key,
      label: `boardagent:${backupId}`
    });
    const completed = await boundary(pool);
    if (completed.system_identifier !== started.system_identifier) {
      throw new Error("PostgreSQL system identifier changed during base backup");
    }
    const manifest = BaseBackupManifestSchema.parse({
      schemaVersion: "boardagent.base-backup.v1",
      backupId,
      format: "postgresql-base-tar-encrypted-v1",
      sourceDatabase: recoveryDatabaseName(input.databaseUrl),
      systemIdentifier: started.system_identifier,
      startedAt: started.observed_at,
      completedAt: completed.observed_at,
      observedStartLsn: started.current_lsn,
      observedEndLsn: completed.current_lsn,
      walMethod: "fetch",
      manifestChecksums: "SHA256",
      encryptionKeyId,
      ...manifestBackupKeyIdentity(registration),
      sourceImageDigest,
      pgBasebackupVersion: artifact.pgBasebackupVersion,
      encryptedStorageLocator: pathToFileURL(artifactPath).href,
      artifactSha256: artifact.sha256,
      artifactBytes: String(artifact.byteLength),
      plaintextTarSha256: artifact.plaintextSha256,
      plaintextTarBytes: String(artifact.plaintextByteLength),
      retention: { daily: 7, weekly: 4, monthly: 12 }
    });
    await verifyBackupArtifact(artifactPath, artifact.sha256, artifact.byteLength);
    await writeManifest(manifestPath, manifest);
    published = true;
    const retention = await pruneBaseBackupGenerations(destination).catch((error: unknown) => {
      throw new PublishedBaseBackupRetentionError(backupId, manifestPath, error);
    });
    return { manifest, manifestFile: manifestPath, retention };
  } catch (error) {
    if (!published) {
      await rm(manifestPath, { force: true }).catch(() => undefined);
      await rm(artifactPath, { force: true }).catch(() => undefined);
    }
    throw error;
  } finally {
    key.fill(0);
    await pool.end().catch(() => undefined);
  }
}

export async function verifyAndExtractBaseBackup(input: VerifyBaseBackupInput): Promise<{
  readonly manifest: BaseBackupManifest;
  readonly pgVerifybackupVersion: string;
  readonly verificationFile: string;
  readonly legacyIdOnlyCount: number;
}> {
  const manifestFile = path.resolve(input.manifestFile);
  const manifest = await readBaseBackupManifest(manifestFile);
  if (UuidV7TextSchema.parse(input.encryptionKeyId) !== manifest.encryptionKeyId) {
    throw new Error("base backup key identifier does not match the manifest");
  }
  const encryptedArtifact = artifactPath(manifest);
  const artifactBytes = Number(manifest.artifactBytes);
  if (!Number.isSafeInteger(artifactBytes) || artifactBytes < 1) {
    throw new Error("base backup artifact length exceeds the local verifier limit");
  }
  await verifyBackupArtifact(encryptedArtifact, manifest.artifactSha256, artifactBytes);
  const target = await emptyTargetDirectory(input.targetDirectory);
  const key = await loadBackupEncryptionKey(path.resolve(input.encryptionKeyFile));
  let legacyIdOnlyCount = 0;
  try {
    legacyIdOnlyCount = verifyRecoveryManifestKey(manifest, key);
    await extractAuthenticatedTar(
      encryptedArtifact,
      target,
      key,
      manifest.plaintextTarSha256,
      manifest.plaintextTarBytes
    );
  } finally {
    key.fill(0);
  }
  const backupManifestStat = await lstat(path.join(target, "backup_manifest"));
  if (!backupManifestStat.isFile() || backupManifestStat.isSymbolicLink()) {
    throw new Error("extracted PostgreSQL backup manifest is unavailable");
  }
  const verification = await verifyPostgresBaseBackup(target);
  if ((await postgresBaseBackupSystemIdentifier(target)) !== manifest.systemIdentifier) {
    throw new Error("extracted base backup system identifier does not match the manifest");
  }
  const verificationFile = path.join(target, ".boardagent-base-restore-verified.json");
  const receipt = BaseRestoreVerificationSchema.parse({
    schemaVersion: "boardagent.base-restore-verification.v1",
    backupId: manifest.backupId,
    baseBackupManifestSha256: canonicalSha256(manifest),
    verifiedAt: new Date().toISOString(),
    pgVerifybackupVersion: verification.pgVerifybackupVersion,
    systemIdentifier: manifest.systemIdentifier
  });
  await writeJsonFile(verificationFile, receipt as JsonValue);
  return { manifest, ...verification, verificationFile, legacyIdOnlyCount };
}
