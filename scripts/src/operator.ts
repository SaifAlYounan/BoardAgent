import { runKeyLifecycleOperator } from "./key-lifecycle-operator.js";
import { runAuditRecoveryOperator } from "./audit-recovery-operator.js";
import { RecoveryKeyringError } from "./recovery-keyring.js";
import { createHash, randomBytes } from "node:crypto";
import { lstat, readFile, readdir, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parseConfig, resolveDatabaseUrl, type BoardAgentConfig } from "@boardagent/config";
import { canonicalJsonFromText, canonicalSha256, type JsonValue } from "@boardagent/contracts";
import { verifyOfflineAuditExport, verifyOfflineCertificateBundle } from "@boardagent/audit";
import {
  BackupManifestSchema,
  captureBackupBoundaryInTransaction,
  finalizeBackupManifest,
  migrate,
  recordBackupCompletedInTransaction,
  recordRestoreVerifiedInTransaction,
  registerRuntimeKeysInTransaction,
  registerBackupKeyInTransaction,
  readActiveBackupKeyInTransaction,
  verifyRestoredBackupInTransaction,
  withBackupTransaction,
  withBootstrapTransaction,
  withRestoreTransaction,
  withWorkerTransaction,
  type BackupManifest,
  type RestoreReceiptManifest
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import {
  decryptExportEnvelope,
  loadBoardAgentKeyMaterial,
  runtimeKeyRegistrations,
  acquireKernelMaintenanceLease,
  PRODUCTION_MAINTENANCE_LOCK_FILE,
  KernelMaintenanceLeaseError,
  type BoardAgentKeyMaterial
} from "@boardagent/server";
import { Pool, type PoolClient } from "pg";
import { z } from "zod";

import {
  BoardAgentBootstrapOperator,
  BootstrapActivationInputSchema,
  type FirstSecretaryBootstrapResult
} from "./bootstrap.js";
import {
  provisionDatabasePrincipals,
  type DatabasePrincipalPasswordFiles
} from "./database-principals.js";
import {
  createEncryptedBaseBackup,
  verifyAndExtractBaseBackup,
  pruneBaseBackupGenerations,
  PublishedBaseBackupRetentionError
} from "./base-backup.js";
import {
  publishRecoveryJson,
  recoveryTemporaryReport,
  PublishedRecoveryRecordError
} from "./recovery-publication.js";
import {
  recoveryDatabaseName,
  runEncryptedPgDump,
  runEncryptedPgRestore
} from "./postgres-recovery.js";
import { loadBackupEncryptionKey, verifyBackupArtifact } from "./recovery-artifact.js";
import { preparePointInTimeRecovery } from "./pitr.js";
import { readPilotStateInTransaction } from "./pilot-state.js";
import { archiveWalOnce, archiveWalFailureDetails } from "./wal-archive.js";
import {
  verifyBackupKeyBytes,
  assertReceiptMatchesRegistry,
  verifyBackupKeyReceipt,
  writeBackupKeyReceipt
} from "./backup-key-binding.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const APP_BUILD = "boardagent-0.0.0-private-beta";
const PURPOSES = ["oauth_signing", "evidence_signing", "browser_session", "data_kek"] as const;
const UuidV7TextSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const ImageDigestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);

const BootstrapSetupSchema = z
  .object({
    organizationLegalName: z.string().min(1).max(512),
    organizationDisplayName: z.string().min(1).max(512),
    organizationSlug: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u),
    timezone: z.string().min(1).max(128),
    boardSlug: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u),
    boardName: z.string().min(1).max(512),
    boardCanonicalPayload: z.record(z.string(), JsonValueSchema),
    firstSecretaryLegalName: z.string().min(1).max(512),
    firstSecretaryDisplayName: z.string().min(1).max(512),
    votingWeight: z.number().int().min(1).max(1_000_000),
    supportName: z.string().min(1).max(512),
    supportContactMethods: z.array(JsonValueSchema).max(16),
    onboardingTermsText: z.string().min(1).max(65_536),
    invitationHandoffMethod: z.string().min(1).max(256)
  })
  .strict();

type BootstrapSetup = z.infer<typeof BootstrapSetupSchema>;

export interface OperatorIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly stdin?: AsyncIterable<Uint8Array>;
}

async function firstActivationCommand(env: NodeJS.ProcessEnv, io: OperatorIo): Promise<number> {
  const canonicalResourceUri = configuredResource(env);
  const chunks: Buffer[] = [];
  let byteLength = 0;
  for await (const chunk of io.stdin ?? process.stdin) {
    byteLength += chunk.byteLength;
    if (byteLength > 1024) throw new Error("activation input exceeds its byte limit");
    chunks.push(Buffer.from(chunk));
  }
  const bytes = Buffer.concat(chunks);
  let input: z.infer<typeof BootstrapActivationInputSchema>;
  try {
    input = BootstrapActivationInputSchema.parse(JSON.parse(canonicalJsonFromText(bytes)));
  } finally {
    bytes.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
  const pool = new Pool({ connectionString: resolveDatabaseUrl(env), max: 1 });
  try {
    const result = await new BoardAgentBootstrapOperator(pool, {
      assumeRole: "boardagent_migrator",
      expectedCanonicalResourceUri: canonicalResourceUri
    }).activateFirstSecretary(input);
    write(io, {
      schemaVersion: 1,
      command: "bootstrap",
      mode: "activate-first",
      status: result.activated ? "succeeded" : "refused",
      ...result,
      ...(result.activated ? { nextHumanStep: "complete_onboarding" } : {})
    });
    return result.activated ? 0 : 1;
  } finally {
    await pool.end();
  }
}

async function firstInvitationRenewalCommand(
  filePath: string,
  env: NodeJS.ProcessEnv,
  io: OperatorIo
): Promise<number> {
  const canonicalResourceUri = configuredResource(env);
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 16_384) {
    throw new Error("first invitation renewal requires a bounded regular JSON request file");
  }
  const input: unknown = JSON.parse(canonicalJsonFromText(await readFile(filePath)));
  const pool = new Pool({ connectionString: resolveDatabaseUrl(env), max: 2 });
  try {
    const operator = new BoardAgentBootstrapOperator(pool, {
      assumeRole: "boardagent_migrator",
      expectedCanonicalResourceUri: canonicalResourceUri
    });
    const result = await operator.renewFirstInvitation(input);
    write(io, {
      schemaVersion: 1,
      command: "bootstrap",
      mode: "renew-first-invitation",
      ...result
    });
    return 0;
  } finally {
    await pool.end();
  }
}

async function firstActivationRestartCommand(
  filePath: string,
  env: NodeJS.ProcessEnv,
  io: OperatorIo
): Promise<number> {
  const canonicalResourceUri = configuredResource(env);
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 16_384) {
    throw new Error("first activation restart requires a bounded regular JSON request file");
  }
  const input: unknown = JSON.parse(canonicalJsonFromText(await readFile(filePath)));
  const pool = new Pool({ connectionString: resolveDatabaseUrl(env), max: 2 });
  try {
    const operator = new BoardAgentBootstrapOperator(pool, {
      assumeRole: "boardagent_migrator",
      expectedCanonicalResourceUri: canonicalResourceUri
    });
    const result = await operator.reissueFirstActivation(input);
    write(io, {
      schemaVersion: 1,
      command: "bootstrap",
      mode: "reissue-first-activation",
      ...result
    });
    return 0;
  } finally {
    await pool.end();
  }
}

function requiredEnvironment(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function databasePrincipalPasswordFiles(
  env: NodeJS.ProcessEnv
): DatabasePrincipalPasswordFiles | null {
  const names = [
    "DATABASE_MIGRATOR_PASSWORD_FILE",
    "DATABASE_SERVER_PASSWORD_FILE",
    "DATABASE_WORKER_PASSWORD_FILE",
    "DATABASE_BACKUP_PASSWORD_FILE"
  ] as const;
  const configured = names.filter((name) => Boolean(env[name]));
  if (configured.length === 0) return null;
  if (configured.length !== names.length) {
    throw new Error("database principal password files must be configured together");
  }
  return {
    migrator: env.DATABASE_MIGRATOR_PASSWORD_FILE!,
    server: env.DATABASE_SERVER_PASSWORD_FILE!,
    worker: env.DATABASE_WORKER_PASSWORD_FILE!,
    backup: env.DATABASE_BACKUP_PASSWORD_FILE!
  };
}

function configuredResource(env: NodeJS.ProcessEnv): string {
  const base = new URL(requiredEnvironment(env, "BOARDAGENT_PUBLIC_BASE_URL"));
  if (
    base.protocol !== "https:" ||
    base.username !== "" ||
    base.password !== "" ||
    base.search !== "" ||
    base.hash !== "" ||
    (base.pathname !== "" && base.pathname !== "/")
  ) {
    throw new Error("bootstrap requires one exact HTTPS public base URL");
  }
  base.pathname = "/mcp";
  return base.href;
}

async function setupFile(filePath: string): Promise<BootstrapSetup> {
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 1_048_576) {
    throw new Error("bootstrap input must be a bounded regular JSON file");
  }
  return BootstrapSetupSchema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readFile(filePath)))
  );
}

async function boundedJsonFile(
  rawPath: string,
  label: string,
  maximumBytes = 16_777_216
): Promise<unknown> {
  const filePath = path.resolve(rawPath);
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > maximumBytes) {
    throw new Error(`${label} must be a bounded regular JSON file`);
  }
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(await readFile(filePath))
  ) as unknown;
}

async function verifyCertificateCommand(
  bundleArgument: string,
  trustedKeysArgument: string,
  io: OperatorIo
): Promise<number> {
  const valid = verifyOfflineCertificateBundle(
    await boundedJsonFile(bundleArgument, "certificate bundle", 2_097_152),
    await boundedJsonFile(trustedKeysArgument, "trusted evidence key set", 2_097_152)
  );
  write(io, {
    schemaVersion: "boardagent.operator-certificate-verification.v1",
    command: "verify-certificate",
    valid
  });
  return valid ? 0 : 1;
}

async function boundedBinaryFile(
  rawPath: string,
  label: string,
  maximumBytes = 536_870_912
): Promise<Buffer> {
  const filePath = path.resolve(rawPath);
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > maximumBytes) {
    throw new Error(`${label} must be a bounded regular file`);
  }
  return readFile(filePath);
}

async function verifyChainCommand(
  exportArgument: string,
  encryptionKeyArgument: string,
  trustedKeysArgument: string,
  io: OperatorIo
): Promise<number> {
  const encrypted = await boundedBinaryFile(exportArgument, "encrypted export");
  const key = await loadBackupEncryptionKey(path.resolve(encryptionKeyArgument));
  let decrypted;
  try {
    decrypted = decryptExportEnvelope(encrypted, key);
  } finally {
    key.fill(0);
    encrypted.fill(0);
  }
  const events = decrypted.components.find(({ name }) => name === "audit:events");
  const checkpoints = decrypted.components.find(({ name }) => name === "audit:checkpoints");
  const trustedKeys = await boundedJsonFile(
    trustedKeysArgument,
    "trusted evidence key set",
    2_097_152
  );
  const verification =
    events &&
    checkpoints &&
    decrypted.scope.exportType === "audit_chain" &&
    decrypted.auditAttestation !== undefined
      ? verifyOfflineAuditExport(
          events.bytes,
          checkpoints.bytes,
          {
            organizationId: decrypted.snapshot.organizationId,
            boardId: decrypted.snapshot.boardId,
            rangeFirstSequence: decrypted.scope.firstSequence,
            rangeLastSequence: decrypted.scope.lastSequence,
            auditHeadSequence: decrypted.snapshot.auditHeadSequence,
            auditHeadSha256: decrypted.snapshot.auditHeadSha256,
            latestCheckpointSha256: decrypted.snapshot.latestCheckpointSha256
          },
          trustedKeys,
          decrypted.auditAttestation === undefined
            ? undefined
            : {
                signed: decrypted.auditAttestation,
                exportRequestId: decrypted.snapshot.exportRequestId,
                scopeSha256: decrypted.snapshot.scopeSha256,
                snapshotSha256: decrypted.header.snapshotSha256,
                ...(decrypted.snapshot.schemaVersion === "boardagent.export-snapshot.v2"
                  ? { auditRecoveryEvidence: decrypted.snapshot.auditRecoveryEvidence }
                  : {})
              }
        )
      : ({
          valid: false,
          firstBreakSequence: null,
          reason:
            decrypted.scope.exportType === "audit_chain"
              ? decrypted.auditAttestation === undefined
                ? "legacy_export_attestation_required"
                : "audit_components_missing"
              : "audit_scope_missing"
        } as const);
  write(io, {
    schemaVersion:
      verification.valid && verification.recoveryEvidence !== undefined
        ? "boardagent.operator-chain-verification.v2"
        : "boardagent.operator-chain-verification.v1",
    command: "verify-chain",
    ...verification
  });
  return verification.valid ? 0 : 1;
}

function recoveryEnvironment(env: NodeJS.ProcessEnv): "development" | "test" | "production" {
  return z
    .enum(["development", "test", "production"])
    .parse(requiredEnvironment(env, "BOARDAGENT_ENV"));
}

type RecoveryDatabaseEnvironmentName =
  | "BOARDAGENT_BACKUP_DATABASE_URL"
  | "BOARDAGENT_RECEIPT_DATABASE_URL"
  | "BOARDAGENT_RESTORE_DATABASE_URL";

const RECOVERY_DATABASE_PASSWORD_FILES = {
  BOARDAGENT_BACKUP_DATABASE_URL: "BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE",
  BOARDAGENT_RECEIPT_DATABASE_URL: "BOARDAGENT_RECEIPT_DATABASE_PASSWORD_FILE",
  BOARDAGENT_RESTORE_DATABASE_URL: "BOARDAGENT_RESTORE_DATABASE_PASSWORD_FILE"
} as const satisfies Record<RecoveryDatabaseEnvironmentName, string>;

export function recoveryDatabaseUrl(
  env: NodeJS.ProcessEnv,
  environment: "development" | "test" | "production",
  name: RecoveryDatabaseEnvironmentName,
  allowNonproductionDefault = true
): string {
  const configured = env[name];
  const value =
    configured ??
    (environment !== "production" && allowNonproductionDefault
      ? requiredEnvironment(env, "BOARDAGENT_DATABASE_URL")
      : undefined);
  if (!value) throw new Error(`${name} is required`);
  if (environment !== "production") return value;
  return resolveDatabaseUrl({
    BOARDAGENT_ENV: environment,
    BOARDAGENT_DATABASE_URL: value,
    BOARDAGENT_DATABASE_PASSWORD_FILE: requiredEnvironment(
      env,
      RECOVERY_DATABASE_PASSWORD_FILES[name]
    )
  });
}

function assertDistinctProductionRecoveryAuthorities(
  environment: "development" | "test" | "production",
  backupDatabaseUrl: string,
  receiptDatabaseUrl: string
): void {
  if (environment !== "production") return;
  const backup = new URL(backupDatabaseUrl);
  const receipt = new URL(receiptDatabaseUrl);
  if (!backup.username || !receipt.username || backup.username === receipt.username) {
    throw new Error(
      "production backup and receipt connections require distinct database principals"
    );
  }
}

async function recoveryDirectory(rawPath: string): Promise<string> {
  const directory = path.resolve(rawPath);
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("recovery destination must be a real mounted directory");
  }
  return directory;
}

async function writeEvidenceFile(filePath: string, value: unknown): Promise<void> {
  await publishRecoveryJson(filePath, value as JsonValue);
}

async function backupManifestFile(rawPath: string): Promise<BackupManifest> {
  const filePath = path.resolve(rawPath);
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 16_777_216) {
    throw new Error("backup manifest must be a bounded regular JSON file");
  }
  return BackupManifestSchema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readFile(filePath)))
  );
}

function backupArtifactPath(manifest: BackupManifest): string {
  const locator = new URL(manifest.artifact.encryptedStorageLocator);
  if (
    locator.protocol !== "file:" ||
    locator.username ||
    locator.password ||
    locator.search ||
    locator.hash
  ) {
    throw new Error("restore-check requires a mounted file backup artifact locator");
  }
  return fileURLToPath(locator);
}

function safeArtifactByteLength(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("backup artifact byte length exceeds the local verifier limit");
  }
  return parsed;
}

async function assertEmptyRestoreDatabase(databaseUrl: string): Promise<void> {
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  try {
    const result = await pool.query<{ count: string }>(
      `select count(*)::text as count
         from pg_class as class
         join pg_namespace as namespace on namespace.oid=class.relnamespace
        where namespace.nspname='public' and class.relkind in ('r','p','v','m','S')`
    );
    if (result.rows[0]?.count !== "0") {
      throw new Error("restore-check target database is not empty");
    }
  } finally {
    await pool.end();
  }
}

async function backupCommand(
  destinationArgument: string,
  env: NodeJS.ProcessEnv,
  io: OperatorIo
): Promise<number> {
  const environment = recoveryEnvironment(env);
  const backupDatabaseUrl = recoveryDatabaseUrl(env, environment, "BOARDAGENT_BACKUP_DATABASE_URL");
  const receiptDatabaseUrl = recoveryDatabaseUrl(
    env,
    environment,
    "BOARDAGENT_RECEIPT_DATABASE_URL"
  );
  assertDistinctProductionRecoveryAuthorities(environment, backupDatabaseUrl, receiptDatabaseUrl);
  const encryptionKeyId = UuidV7TextSchema.parse(
    requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID")
  );
  const sourceImageDigest = ImageDigestSchema.parse(
    requiredEnvironment(env, "BOARDAGENT_SOURCE_IMAGE_DIGEST")
  );
  const directory = await recoveryDirectory(destinationArgument);
  const receiptId = uuidV7(Date.now(), randomBytes(10));
  const artifactPath = path.join(directory, `boardagent-${receiptId}.dump.aes256gcm`);
  const manifestPath = path.join(directory, `boardagent-${receiptId}.manifest.json`);
  const key = await loadBackupEncryptionKey(
    path.resolve(requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"))
  );
  const backupPool = new Pool({ connectionString: backupDatabaseUrl, max: 2 });
  const receiptPool = new Pool({ connectionString: receiptDatabaseUrl, max: 2 });
  try {
    const captured = await withBackupTransaction(
      backupPool,
      async (client) => {
        const boundary = await captureBackupBoundaryInTransaction(client, {
          receiptId,
          encryptionKeyId,
          encryptionKeyFingerprintSha256: createHash("sha256").update(key).digest("hex")
        });
        const artifact = await runEncryptedPgDump({
          databaseUrl: backupDatabaseUrl,
          snapshotId: boundary.snapshotId,
          artifactPath,
          encryptionKey: key
        });
        return { boundary, artifact };
      },
      {
        assumeRole: "boardagent_backup",
        statementTimeoutMs: 60_000
      }
    );
    const manifest = finalizeBackupManifest(captured.boundary, {
      format: "postgresql-custom-encrypted-v1",
      encryptedStorageLocator: pathToFileURL(artifactPath).href,
      artifactSha256: captured.artifact.sha256,
      byteLength: String(captured.artifact.byteLength),
      pgDumpVersion: captured.artifact.pgDumpVersion,
      encryptionTool: "node:crypto AES-256-GCM boardagent.v1",
      sourceImageDigest
    });
    await writeEvidenceFile(manifestPath, manifest);
    const persisted = await withWorkerTransaction(
      receiptPool,
      (client) =>
        recordBackupCompletedInTransaction(client, {
          manifest,
          auditEventId: uuidV7(Date.now(), randomBytes(10))
        }),
      { assumeRole: "boardagent_worker" }
    ).catch((error: unknown) => {
      throw new PublishedRecoveryRecordError("backup", receiptId, manifestPath, error);
    });
    write(io, {
      ...(manifest.schemaVersion === "boardagent.backup-receipt.v2"
        ? {
            schemaVersion: "boardagent.operator-backup.v2",
            warnings: manifest.auditRecoveryEvidence.map(
              (entry) =>
                `recovery:${entry.payload.recovery.request.recoveryId}:historical_checkpoint_deadline_missed`
            )
          }
        : { schemaVersion: "boardagent.operator-backup.v1" }),
      command: "backup",
      status: "succeeded",
      receiptId,
      manifestSha256: persisted.manifestSha256,
      contentSetSha256: manifest.contentSetSha256,
      artifactSha256: manifest.artifact.artifactSha256,
      artifactBytes: manifest.artifact.byteLength,
      snapshotLsn: manifest.snapshotLsn,
      sourceImageDigest,
      manifestFile: manifestPath,
      artifactFile: artifactPath,
      replayed: persisted.replayed
    });
    return 0;
  } finally {
    key.fill(0);
    await backupPool.end().catch(() => undefined);
    await receiptPool.end().catch(() => undefined);
  }
}

async function restoreCheckCommand(
  manifestArgument: string,
  env: NodeJS.ProcessEnv,
  io: OperatorIo
): Promise<number> {
  const environment = recoveryEnvironment(env);
  const manifestPath = path.resolve(manifestArgument);
  const manifest = await backupManifestFile(manifestPath);
  const configuredKeyId = UuidV7TextSchema.parse(
    requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID")
  );
  if (configuredKeyId !== manifest.encryptionKeyId) {
    throw new Error("restore-check backup key identifier does not match the manifest");
  }
  const artifactPath = backupArtifactPath(manifest);
  await verifyBackupArtifact(
    artifactPath,
    manifest.artifact.artifactSha256,
    safeArtifactByteLength(manifest.artifact.byteLength)
  );
  const targetDatabaseUrl = recoveryDatabaseUrl(
    env,
    environment,
    "BOARDAGENT_RESTORE_DATABASE_URL",
    false
  );
  if (recoveryDatabaseName(targetDatabaseUrl) === manifest.sourceDatabase) {
    throw new Error("restore-check target database must differ from the source database");
  }
  await assertEmptyRestoreDatabase(targetDatabaseUrl);
  const receiptDatabaseUrl = recoveryDatabaseUrl(
    env,
    environment,
    "BOARDAGENT_RECEIPT_DATABASE_URL"
  );
  const key = await loadBackupEncryptionKey(
    path.resolve(requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"))
  );
  let targetPool: Pool | undefined;
  const receiptPool = new Pool({ connectionString: receiptDatabaseUrl, max: 2 });
  try {
    if (manifest.encryptionKeyFingerprintSha256 !== undefined) {
      verifyBackupKeyBytes(key, manifest.encryptionKeyFingerprintSha256);
    }
    const restoreTool = await runEncryptedPgRestore({
      databaseUrl: targetDatabaseUrl,
      artifactPath,
      encryptionKey: key,
      scratchDirectory: path.dirname(manifestPath)
    });
    targetPool = new Pool({ connectionString: targetDatabaseUrl, max: 2 });
    const restoreReceiptId = uuidV7(Date.now(), randomBytes(10));
    const verification = await withRestoreTransaction(
      targetPool,
      (client) =>
        verifyRestoredBackupInTransaction(client, {
          sourceManifest: manifest,
          sourceBackupReceiptId: manifest.receiptId,
          sourceBackupManifestSha256: canonicalSha256(manifest),
          restoreReceiptId
        }),
      {
        assumeRole: "boardagent_backup",
        statementTimeoutMs: 60_000
      }
    );
    if (!verification.valid) {
      write(io, {
        schemaVersion: "boardagent.operator-restore-check.v1",
        command: "restore-check",
        status: "refused",
        ready: false,
        failures: verification.failures
      });
      return 1;
    }
    const restoreManifest: RestoreReceiptManifest = verification.receiptManifest;
    const restoreManifestPath = path.join(
      path.dirname(manifestPath),
      `boardagent-${restoreReceiptId}.restore-receipt.json`
    );
    await writeEvidenceFile(restoreManifestPath, restoreManifest);
    const persisted = await withWorkerTransaction(
      receiptPool,
      (client) =>
        recordRestoreVerifiedInTransaction(client, {
          manifest: restoreManifest,
          auditEventId: uuidV7(Date.now(), randomBytes(10))
        }),
      { assumeRole: "boardagent_worker" }
    ).catch((error: unknown) => {
      throw new PublishedRecoveryRecordError(
        "restore-check",
        restoreReceiptId,
        restoreManifestPath,
        error
      );
    });
    write(io, {
      ...(restoreManifest.schemaVersion === "boardagent.restore-receipt.v2"
        ? {
            schemaVersion: "boardagent.operator-restore-check.v2",
            warnings: restoreManifest.auditRecoveryEvidence.map(
              (entry) =>
                `recovery:${entry.payload.recovery.request.recoveryId}:historical_checkpoint_deadline_missed`
            )
          }
        : { schemaVersion: "boardagent.operator-restore-check.v1" }),
      command: "restore-check",
      status: "succeeded",
      ready: true,
      restoreReceiptId,
      sourceBackupReceiptId: manifest.receiptId,
      manifestSha256: persisted.manifestSha256,
      contentSetSha256: restoreManifest.contentSetSha256,
      restoredDatabase: restoreManifest.restoredDatabase,
      legacyIdOnlyCount: manifest.encryptionKeyFingerprintSha256 === undefined ? 1 : 0,
      pgRestoreVersion: restoreTool.pgRestoreVersion,
      restoreReceiptFile: restoreManifestPath,
      replayed: persisted.replayed
    });
    return 0;
  } finally {
    key.fill(0);
    await targetPool?.end().catch(() => undefined);
    await receiptPool.end().catch(() => undefined);
  }
}

async function instanceOrganization(client: PoolClient): Promise<string> {
  const result = await client.query<{ organization_id: string }>(
    "select organization_id from system_instance where singleton_key"
  );
  const organizationId = result.rows[0]?.organization_id;
  if (!organizationId || result.rows.length !== 1) {
    throw new Error("BoardAgent instance is not bootstrapped");
  }
  return organizationId;
}

async function registerKeys(
  pool: Pool,
  organizationId: string,
  config: BoardAgentConfig,
  keys: BoardAgentKeyMaterial
): Promise<{ readonly created: number; readonly replayed: number }> {
  return withBootstrapTransaction(
    pool,
    async (client) => {
      const active = await client.query<{ id: string; purpose: (typeof PURPOSES)[number] }>(
        `select id,purpose from crypto_key_registry
          where organization_id=$1 and retired_at is null and compromised_at is null
          order by purpose`,
        [organizationId]
      );
      const existing = new Map(active.rows.map(({ purpose, id }) => [purpose, id]));
      let index = 0;
      const registrations = runtimeKeyRegistrations(config, keys, () => {
        const purpose = PURPOSES[index++];
        if (!purpose) throw new Error("runtime-key registration order changed");
        return existing.get(purpose) ?? uuidV7(Date.now(), randomBytes(10));
      });
      const results = await registerRuntimeKeysInTransaction(client, organizationId, registrations);
      return {
        created: results.filter(({ replayed }) => !replayed).length,
        replayed: results.filter(({ replayed }) => replayed).length
      };
    },
    { assumeRole: "boardagent_migrator" }
  );
}

async function registerConfiguredKeys(
  pool: Pool,
  env: NodeJS.ProcessEnv,
  organizationId: string
): Promise<{ readonly created: number; readonly replayed: number }> {
  const config = parseConfig({ ...env, BOARDAGENT_ORGANIZATION_ID: organizationId });
  const keys = await loadBoardAgentKeyMaterial(config);
  return registerKeys(pool, organizationId, config, keys);
}

async function bootstrap(
  pool: Pool,
  env: NodeJS.ProcessEnv,
  setup: BootstrapSetup
): Promise<{
  readonly result: FirstSecretaryBootstrapResult;
  readonly keyRegistration: { readonly created: number; readonly replayed: number } | null;
}> {
  const result = await new BoardAgentBootstrapOperator(pool, {
    assumeRole: "boardagent_migrator"
  }).initialize({ ...setup, canonicalResourceUri: configuredResource(env) });
  const organizationId =
    result.status === "created"
      ? result.organizationId
      : await withBootstrapTransaction(pool, instanceOrganization, {
          assumeRole: "boardagent_migrator"
        });
  let keyRegistration = null;
  try {
    keyRegistration = await registerConfiguredKeys(pool, env, organizationId);
  } catch {
    if (result.status === "created") return { result, keyRegistration: null };
    throw new Error("runtime-key registration failed");
  }
  return { result, keyRegistration };
}

function write(io: OperatorIo, value: object): void {
  io.stdout(`${JSON.stringify(value)}\n`);
}

export async function runOperator(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  io: OperatorIo = {
    stdout: (line) => process.stdout.write(line),
    stderr: (line) => process.stderr.write(line)
  }
): Promise<number> {
  const keyApply = args[0] === "key-lifecycle" && args[1] === "apply" && args.length === 5;
  const keyInstall = args[0] === "key-lifecycle" && args[1] === "install" && args.length === 3;
  const backupWriter = (args[0] === "backup" || args[0] === "base-backup") && args.length === 2;
  const walWriter =
    (args[0] === "archive-wal" || args[0] === "archive-wal-once") && args.length === 3;
  const recoverySigner = args[0] === "audit-recovery" && args[1] === "apply" && args.length === 5;
  if (
    env["BOARDAGENT_ENV"] !== "production" ||
    !(keyApply || keyInstall || backupWriter || walWriter || recoverySigner)
  )
    return runOperatorCommand(args, env, io);
  const lease = await acquireKernelMaintenanceLease(
    PRODUCTION_MAINTENANCE_LOCK_FILE,
    keyApply || keyInstall ? "exclusive" : "shared"
  );
  try {
    if (walWriter) await assertCurrentArchiveKey(env);
    return await runOperatorCommand(args, env, io);
  } finally {
    await lease.close();
  }
}

class ArchiveKeyRegistrationError extends Error {
  readonly reasonCode: string;
  constructor(cause: unknown) {
    super("backup key registry check failed", { cause });
    const reason = archiveWalFailureDetails(cause).reasonCode;
    this.reasonCode =
      reason === "validation_or_operation_failed" ? "backup_key_registry_check_failed" : reason;
  }
}

/** A running WAL writer retains the kernel lease; database outages cannot release it. */
async function assertCurrentArchiveKey(env: NodeJS.ProcessEnv): Promise<void> {
  const connectionString = recoveryDatabaseUrl(env, "production", "BOARDAGENT_BACKUP_DATABASE_URL");
  const key = await loadBackupEncryptionKey(requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"));
  const pool = new Pool({ connectionString, max: 1 });
  try {
    const receipt = await verifyBackupKeyReceipt({
      receiptFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE"),
      organizationId: requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID"),
      keyId: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID"),
      key
    });
    const registered = await withBackupTransaction(
      pool,
      (client) => readActiveBackupKeyInTransaction(client, receipt.keyId),
      { assumeRole: "boardagent_backup" }
    ).catch((error: unknown) => {
      throw new ArchiveKeyRegistrationError(error);
    });
    assertReceiptMatchesRegistry(receipt, registered);
  } finally {
    key.fill(0);
    await pool.end();
  }
}

async function runOperatorCommand(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  io: OperatorIo
): Promise<number> {
  const command = args[0];
  if (command === "audit-recovery") return runAuditRecoveryOperator(args.slice(1), env, io);
  if (command === "key-lifecycle") return runKeyLifecycleOperator(args.slice(1), env, io);
  if (command === "check-backup-key" && args.length === 1) {
    const key = await loadBackupEncryptionKey(
      requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE")
    );
    try {
      const receipt = await verifyBackupKeyReceipt({
        receiptFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE"),
        organizationId: requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID"),
        keyId: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID"),
        key
      });
      write(io, {
        schemaVersion: "boardagent.operator-backup-key-check.v1",
        command,
        status: "valid",
        instanceId: receipt.instanceId,
        organizationId: receipt.organizationId,
        keyId: receipt.keyId,
        receiptSha256: receipt.receiptSha256
      });
      return 0;
    } finally {
      key.fill(0);
    }
  }
  if (command === "bootstrap" && args[1] === "activate-first") {
    if (args.length !== 2) throw new Error("activation accepts JSON on stdin only");
    return firstActivationCommand(env, io);
  }
  if (command === "bootstrap" && args[1] === "renew-first-invitation") {
    if (args.length !== 3) throw new Error("renew-first-invitation requires one JSON request file");
    return firstInvitationRenewalCommand(path.resolve(args[2]!), env, io);
  }
  if (command === "bootstrap" && args[1] === "reissue-first-activation") {
    if (args.length !== 3)
      throw new Error("reissue-first-activation requires one JSON request file");
    return firstActivationRestartCommand(path.resolve(args[2]!), env, io);
  }
  if (command === "verify-certificate" && args.length === 3) {
    return verifyCertificateCommand(args[1]!, args[2]!, io);
  }
  if (command === "verify-chain" && args.length === 4) {
    return verifyChainCommand(args[1]!, args[2]!, args[3]!, io);
  }
  if (command === "backup" && args.length === 2) {
    return backupCommand(args[1]!, env, io);
  }
  if (command === "inspect-pilot-state" && args.length === 1) {
    const environment = recoveryEnvironment(env);
    const inventoryPool = new Pool({
      connectionString: recoveryDatabaseUrl(env, environment, "BOARDAGENT_BACKUP_DATABASE_URL"),
      max: 1
    });
    try {
      const result = await withBackupTransaction(
        inventoryPool,
        (client) =>
          readPilotStateInTransaction(
            client,
            requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID")
          ),
        { assumeRole: "boardagent_backup" }
      );
      write(io, {
        schemaVersion: "boardagent.operator-pilot-state.v1",
        command,
        status: "observed",
        ...result
      });
      return 0;
    } finally {
      await inventoryPool.end();
    }
  }
  if (command === "restore-check" && args.length === 2) {
    return restoreCheckCommand(args[1]!, env, io);
  }
  if (command === "base-backup" && args.length === 2) {
    const environment = recoveryEnvironment(env);
    const result = await createEncryptedBaseBackup({
      organizationId: requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID"),
      keyRegistrationFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE"),
      databaseUrl: recoveryDatabaseUrl(env, environment, "BOARDAGENT_BACKUP_DATABASE_URL"),
      destinationDirectory: args[1]!,
      encryptionKeyFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"),
      encryptionKeyId: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID"),
      sourceImageDigest: requiredEnvironment(env, "BOARDAGENT_SOURCE_IMAGE_DIGEST")
    });
    write(io, {
      schemaVersion: "boardagent.operator-base-backup.v1",
      command,
      status: "succeeded",
      backupId: result.manifest.backupId,
      artifactSha256: result.manifest.artifactSha256,
      observedStartLsn: result.manifest.observedStartLsn,
      observedEndLsn: result.manifest.observedEndLsn,
      manifestFile: result.manifestFile,
      retainedGenerations: result.retention.keptBackupIds.length,
      prunedGenerations: result.retention.prunedBackupIds.length,
      resumedRetirements: result.retention.resumedRetirements,
      ...recoveryTemporaryReport(result.retention.ignoredTemporaryFiles ?? []),
      ...(result.retention.ignoredTemporaryFileCount === undefined
        ? {}
        : {
            ignoredTemporaryFileCount: result.retention.ignoredTemporaryFileCount
          })
    });
    return 0;
  }
  if (command === "prune-base-backups" && args.length === 2) {
    const result = await pruneBaseBackupGenerations(args[1]!);
    write(io, {
      schemaVersion: "boardagent.operator-base-retention.v1",
      command,
      status: "succeeded",
      ...result
    });
    return 0;
  }
  if (command === "base-restore-check" && args.length === 3) {
    const result = await verifyAndExtractBaseBackup({
      manifestFile: args[1]!,
      targetDirectory: args[2]!,
      encryptionKeyFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"),
      encryptionKeyId: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID")
    });
    write(io, {
      schemaVersion: "boardagent.operator-base-restore-check.v1",
      command,
      status: "succeeded",
      ready: false,
      reason: "isolated_start_and_replay_required",
      backupId: result.manifest.backupId,
      pgVerifybackupVersion: result.pgVerifybackupVersion,
      legacyIdOnlyCount: result.legacyIdOnlyCount,
      verificationFile: result.verificationFile
    });
    return 0;
  }
  if (command === "prepare-pitr" && args.length === 5) {
    const result = await preparePointInTimeRecovery({
      baseManifestFile: args[1]!,
      archiveDirectory: args[2]!,
      pgdataDirectory: args[3]!,
      walTargetDirectory: args[4]!,
      encryptionKeyFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"),
      encryptionKeyId: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID"),
      recoveryKeyringFile: env["BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE"]
    });
    write(io, {
      schemaVersion: "boardagent.operator-prepare-pitr.v1",
      command,
      status: "succeeded",
      ready: false,
      ...result
    });
    return 0;
  }
  if (command === "archive-wal-once" && args.length === 3) {
    const outcome = await archiveWalOnce({
      organizationId: requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID"),
      keyRegistrationFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE"),
      stagingDirectory: args[1]!,
      destinationDirectory: args[2]!,
      encryptionKeyFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"),
      encryptionKeyId: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID"),
      ...(env["BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE"]
        ? { recoveryKeyringFile: env["BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE"] }
        : {})
    });
    write(io, {
      schemaVersion: "boardagent.operator-wal-archive.v1",
      command,
      status: "succeeded",
      ...outcome
    });
    return 0;
  }
  if (command === "archive-wal" && args.length === 3) {
    const abort = new AbortController();
    const stop = (): void => abort.abort();
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    let blockedSince: number | undefined;
    let lastBlockedLog = 0;
    let lastTemporaryLog = 0;
    let lastDestinationInspection = 0;
    const publishStatus = async (status: object): Promise<void> => {
      const temporary = `/tmp/.boardagent-wal-status-${randomBytes(16).toString("hex")}`;
      try {
        await writeFile(temporary, JSON.stringify(status), { flag: "wx", mode: 0o600 });
        await rename(temporary, "/tmp/boardagent-wal-status.json");
      } finally {
        await unlink(temporary).catch(() => undefined);
      }
    };
    try {
      while (!abort.signal.aborted) {
        const inspectDestinationTemporaries =
          lastDestinationInspection === 0 || Date.now() - lastDestinationInspection >= 60_000;
        if (inspectDestinationTemporaries) lastDestinationInspection = Date.now();
        const outcome = await archiveWalOnce({
          inspectDestinationTemporaries,
          organizationId: requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID"),
          keyRegistrationFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE"),
          stagingDirectory: args[1]!,
          destinationDirectory: args[2]!,
          encryptionKeyFile: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE"),
          encryptionKeyId: requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID")
        }).catch(async (error: unknown) => {
          const now = Date.now();
          blockedSince ??= now;
          const stagedFileCount = await readdir(args[1]!).then(
            (files) => files.length,
            () => null
          );
          const details = archiveWalFailureDetails(error);
          await publishStatus({ status: "blocked", updatedAt: now, stagedFileCount, ...details });
          if (lastBlockedLog === 0 || now - lastBlockedLog >= 60_000) {
            io.stderr(
              `${JSON.stringify({ event: "wal_archive_blocked", severity: "error", ...details, stagedFileCount, stagingRetained: true })}\n`
            );
            lastBlockedLog = now;
          }
          return null;
        });
        if (outcome !== null) {
          const now = Date.now();
          await publishStatus({
            status: "healthy",
            updatedAt: now,
            ...(inspectDestinationTemporaries
              ? {
                  ignoredTemporaryFileCount: outcome.ignoredTemporaryFileCount ?? 0,
                  temporaryObservationAt: now
                }
              : {})
          });
          if (
            (outcome.ignoredTemporaryFileCount ?? 0) > 0 &&
            (lastTemporaryLog === 0 || now - lastTemporaryLog >= 60_000)
          ) {
            io.stderr(
              `${JSON.stringify({
                event: "wal_archive_temporary_files_retained",
                severity: "warning",
                ignoredTemporaryFileCount: outcome.ignoredTemporaryFileCount,
                ignoredTemporaryFiles: outcome.ignoredTemporaryFiles
              })}\n`
            );
            lastTemporaryLog = now;
          } else if ((outcome.ignoredTemporaryFileCount ?? 0) === 0) lastTemporaryLog = 0;
          if (blockedSince !== undefined) {
            io.stdout(
              `${JSON.stringify({ event: "wal_archive_resumed", blockedForMs: Date.now() - blockedSince })}\n`
            );
            blockedSince = undefined;
            lastBlockedLog = 0;
          }
        }
        if (outcome !== null && (outcome.archived > 0 || outcome.replayed > 0)) {
          write(io, {
            schemaVersion: "boardagent.operator-wal-archive.v1",
            command,
            status: "succeeded",
            ...outcome
          });
        }
        await new Promise<void>((resolve) => {
          const stopped = (): void => {
            clearTimeout(timer);
            resolve();
          };
          const timer = setTimeout(() => {
            abort.signal.removeEventListener("abort", stopped);
            resolve();
          }, 1_000);
          abort.signal.addEventListener("abort", stopped, { once: true });
        });
      }
      return 0;
    } finally {
      process.removeListener("SIGTERM", stop);
      process.removeListener("SIGINT", stop);
    }
  }
  const principalPasswordFiles =
    command === "migrate" && args.length === 1 ? databasePrincipalPasswordFiles(env) : null;
  const databaseUrl = principalPasswordFiles
    ? resolveDatabaseUrl({
        BOARDAGENT_ENV: "production",
        BOARDAGENT_DATABASE_URL: requiredEnvironment(env, "BOARDAGENT_DATABASE_URL"),
        BOARDAGENT_DATABASE_PASSWORD_FILE: requiredEnvironment(env, "DATABASE_OWNER_PASSWORD_FILE")
      })
    : resolveDatabaseUrl(env);
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  try {
    if (command === "check-bootstrap" && args.length === 1) {
      const organizationId = UuidV7TextSchema.parse(
        requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID")
      );
      const inventory = await withBootstrapTransaction(
        pool,
        async (client) => {
          const instance = await client.query<{ instance_id: string }>(
            "select instance_id from system_instance where singleton_key and organization_id=$1",
            [organizationId]
          );
          if (instance.rows.length !== 1)
            throw new Error("bootstrap check does not match the configured instance");
          const terms = await client.query<{
            seatRole: string;
            availableVersions: number;
            version: number | null;
            versionId: string | null;
            sha256: string | null;
          }>(
            `select requested.role as "seatRole", counts.total as "availableVersions",
                  latest.version, latest.id as "versionId", encode(latest.canonical_sha256,'hex') as sha256
             from unnest($2::text[]) with ordinality requested(role,ordinal)
             cross join lateral (select count(*)::int as total from onboarding_terms_versions t
               where t.organization_id=$1 and t.seat_role=requested.role and t.effective_at<=transaction_timestamp()) counts
             left join lateral (select t.id,t.version,t.canonical_sha256 from onboarding_terms_versions t
               where t.organization_id=$1 and t.seat_role=requested.role and t.effective_at<=transaction_timestamp()
               order by t.version desc limit 1) latest on true
            order by requested.ordinal`,
            [organizationId, ["voting_member", "management", "observer"]]
          );
          return {
            instanceId: UuidV7TextSchema.parse(instance.rows[0]!.instance_id),
            terms: terms.rows
          };
        },
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const allSeatRolesCovered =
        inventory.terms.length === 3 &&
        inventory.terms.every((term) => term.availableVersions > 0 && term.version !== null);
      write(io, {
        schemaVersion: "boardagent.operator-bootstrap-check.v1",
        command,
        checks: "onboarding_terms",
        status: allSeatRolesCovered ? "complete" : "incomplete",
        allSeatRolesCovered,
        organizationId,
        ...inventory
      });
      return allSeatRolesCovered ? 0 : 1;
    }
    if (command === "migrate" && args.length === 1) {
      const applied = await migrate(
        pool,
        MIGRATIONS,
        APP_BUILD,
        env["BOARDAGENT_ENV"] === "production" && principalPasswordFiles === null
          ? { assumeRole: "boardagent_migrator" as const }
          : {}
      );
      const databasePrincipals = principalPasswordFiles
        ? await provisionDatabasePrincipals(pool, principalPasswordFiles)
        : null;
      write(io, {
        schemaVersion: 1,
        command,
        status: "succeeded",
        migrationsApplied: applied,
        databasePrincipals
      });
      return 0;
    }
    if (command === "bootstrap" && args.length === 2) {
      await migrate(
        pool,
        MIGRATIONS,
        APP_BUILD,
        env["BOARDAGENT_ENV"] === "production" ? { assumeRole: "boardagent_migrator" as const } : {}
      );
      const outcome = await bootstrap(pool, env, await setupFile(path.resolve(args[1]!)));
      write(io, {
        schemaVersion: 1,
        command,
        operatorStatus: outcome.keyRegistration === null ? "partial" : "succeeded",
        ...outcome.result,
        runtimeKeysRegistered: outcome.keyRegistration !== null,
        keyRegistration: outcome.keyRegistration
      });
      return outcome.keyRegistration === null ? 1 : 0;
    }
    if (command === "register-runtime-keys" && args.length === 1) {
      const config = parseConfig(env);
      const keyRegistration = await registerConfiguredKeys(pool, env, config.organizationId);
      write(io, {
        schemaVersion: 1,
        command,
        status: "succeeded",
        keyRegistration
      });
      return 0;
    }
    if (command === "register-backup-key" && args.length === 1) {
      const receiptDirectory = requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY");
      const organizationId = UuidV7TextSchema.parse(
        requiredEnvironment(env, "BOARDAGENT_ORGANIZATION_ID")
      );
      const keyId = UuidV7TextSchema.parse(requiredEnvironment(env, "BOARDAGENT_BACKUP_KEY_ID"));
      const key = await loadBackupEncryptionKey(
        requiredEnvironment(env, "BOARDAGENT_BACKUP_KEK_FILE")
      );
      let fingerprintSha256: string;
      try {
        fingerprintSha256 = createHash("sha256").update(key).digest("hex");
      } finally {
        key.fill(0);
      }
      const { registration, identity } = await withBootstrapTransaction(
        pool,
        async (client) => {
          const registration = await registerBackupKeyInTransaction(
            client,
            organizationId,
            keyId,
            fingerprintSha256
          );
          return { registration, identity: await readActiveBackupKeyInTransaction(client, keyId) };
        },
        { assumeRole: "boardagent_migrator" }
      );
      const published = await writeBackupKeyReceipt(receiptDirectory, identity);
      write(io, {
        schemaVersion: "boardagent.operator-backup-key-registration.v1",
        command,
        status: "succeeded",
        organizationId,
        keyRegistration: { ...registration, purpose: "backup_kek", fingerprintSha256 },
        receiptFile: published.receiptFile,
        receiptSha256: published.receipt.receiptSha256
      });
      return 0;
    }
    io.stderr(
      "usage: operator <key-lifecycle inspect [OPERATION_ID RECEIPT.json]|key-lifecycle prepare PLAN.json REQUEST.json|key-lifecycle apply REQUEST.json SHA256 RECEIPT.json|key-lifecycle install INSTALL.json|audit-recovery inspect [RECOVERY_ID RECEIPT.json]|audit-recovery prepare INCIDENT.json REQUEST.json|audit-recovery apply REQUEST.json SHA256 RECEIPT.json|migrate|bootstrap SETUP.json|bootstrap activate-first (JSON stdin)|bootstrap renew-first-invitation REQUEST.json|bootstrap reissue-first-activation REQUEST.json|check-bootstrap|inspect-pilot-state|register-runtime-keys|register-backup-key|check-backup-key|verify-certificate BUNDLE.json TRUSTED_KEYS.json|verify-chain ENCRYPTED_EXPORT DATA_KEK_FILE TRUSTED_KEYS.json|backup DIRECTORY|base-backup DIRECTORY|prune-base-backups DIRECTORY|base-restore-check MANIFEST.json EMPTY_PGDATA|prepare-pitr BASE_MANIFEST.json WAL_ARCHIVE PGDATA EMPTY_WAL_TARGET|restore-check MANIFEST.json|archive-wal STAGING DIRECTORY|archive-wal-once STAGING DIRECTORY>\n"
    );
    return 64;
  } finally {
    await pool.end();
  }
}

export async function runOperatorWithDiagnostics(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  io: OperatorIo
): Promise<number> {
  try {
    return await runOperator(args, env, io);
  } catch (error: unknown) {
    if (error instanceof KernelMaintenanceLeaseError) {
      write(io, {
        status: "refused",
        command: args[0],
        stage: "maintenance_exclusion",
        reasonCode: error.code
      });
      return 1;
    }
    if (error instanceof RecoveryKeyringError) {
      write(io, {
        status: "refused",
        command: "prepare-pitr",
        stage: "recovery_keys",
        reasonCode: error.reasonCode
      });
      return 1;
    }

    if (error instanceof ArchiveKeyRegistrationError) {
      write(io, {
        schemaVersion: "boardagent.operator-wal-archive.v1",
        status: "refused",
        command: args[0],
        stage: "key_registration",
        reasonCode: error.reasonCode
      });
      return 1;
    }
    if (error instanceof PublishedRecoveryRecordError) {
      write(io, {
        schemaVersion: "boardagent.operator-recovery-outcome.v1",
        command: error.command,
        status: "published_recording_unconfirmed",
        ready: false,
        receiptId: error.receiptId,
        manifestFile: error.manifestFile,
        stage: "receipt_recording",
        reasonCode: archiveWalFailureDetails(error.cause).reasonCode
      });
      return 1;
    }
    if (error instanceof PublishedBaseBackupRetentionError) {
      write(io, {
        schemaVersion: "boardagent.operator-base-backup.v1",
        command: "base-backup",
        status: "published_retention_refused",
        backupId: error.backupId,
        manifestFile: error.manifestFile,
        stage: "retention",
        reasonCode: archiveWalFailureDetails(error.cause).reasonCode
      });
      return 1;
    }
    const details = archiveWalFailureDetails(error);
    const knownCommands = [
      "audit-recovery",
      "key-lifecycle",
      "migrate",
      "bootstrap",
      "check-bootstrap",
      "inspect-pilot-state",
      "register-runtime-keys",
      "register-backup-key",
      "check-backup-key",
      "verify-certificate",
      "verify-chain",
      "backup",
      "base-backup",
      "prune-base-backups",
      "base-restore-check",
      "prepare-pitr",
      "restore-check",
      "archive-wal",
      "archive-wal-once"
    ];
    const command = knownCommands.includes(args[0] ?? "") ? args[0]! : "unknown";
    io.stderr(
      `${JSON.stringify({ status: "failed", command, ...details, stage: details.stage === "unknown" ? command : details.stage })}\n`
    );
    return 1;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runOperatorWithDiagnostics(process.argv.slice(2), process.env, {
    stdout: (line) => process.stdout.write(line),
    stderr: (line) => process.stderr.write(line)
  });
}
