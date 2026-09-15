import { lstat, open, readFile } from "node:fs/promises";
import path from "node:path";

import { canonicalSha256, type JsonValue } from "@boardagent/contracts";
import { z } from "zod";

import { BaseRestoreVerificationSchema, readBaseBackupManifest } from "./base-backup.js";
import { materializeWalArchive } from "./wal-archive.js";
import {
  publishRecoveryJson,
  syncRecoveryDirectory,
  type RecoveryTemporaryReport
} from "./recovery-publication.js";

async function boundedJsonFile(filePath: string, label: string): Promise<unknown> {
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 1_048_576) {
    throw new Error(`${label} must be a bounded regular JSON file`);
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readFile(filePath)));
}

async function appendRecoveryConfiguration(pgdata: string): Promise<void> {
  const configurationPath = path.join(pgdata, "postgresql.auto.conf");
  const stat = await lstat(configurationPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1_048_576) {
    throw new Error("restored PostgreSQL auto-configuration is unavailable");
  }
  const existing = new TextDecoder("utf-8", { fatal: true }).decode(
    await readFile(configurationPath)
  );
  if (/^\s*(?:restore_command|recovery_target[^=]*)\s*=/mu.test(existing)) {
    throw new Error("restored PostgreSQL data already contains recovery settings");
  }
  const handle = await open(configurationPath, "a", 0o600);
  try {
    await handle.writeFile(
      "\n# BoardAgent isolated PITR preparation v1\n" +
        "restore_command = 'cp /wal-restore/%f %p'\n" +
        "recovery_target_timeline = 'latest'\n",
      "utf8"
    );
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function exclusiveFile(filePath: string, value: string): Promise<void> {
  const handle = await open(filePath, "wx", 0o600);
  try {
    await handle.writeFile(value, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function preparePointInTimeRecovery(input: {
  readonly baseManifestFile: string;
  readonly archiveDirectory: string;
  readonly pgdataDirectory: string;
  readonly walTargetDirectory: string;
  readonly encryptionKeyFile: string;
  readonly encryptionKeyId: string;
  readonly recoveryKeyringFile?: string | undefined;
}): Promise<
  {
    readonly backupId: string;
    readonly walFileCount: number;
    readonly includesWalFile: string;
    readonly preparationFile: string;
    readonly legacyIdOnlyCount: number;
  } & RecoveryTemporaryReport
> {
  const baseManifest = await readBaseBackupManifest(path.resolve(input.baseManifestFile));
  if (baseManifest.encryptionKeyId !== input.encryptionKeyId) {
    throw new Error("PITR key identifier does not match the base backup manifest");
  }
  const pgdata = path.resolve(input.pgdataDirectory);
  const verificationPath = path.join(pgdata, ".boardagent-base-restore-verified.json");
  const verification = BaseRestoreVerificationSchema.parse(
    await boundedJsonFile(verificationPath, "base restore verification receipt")
  );
  if (
    verification.backupId !== baseManifest.backupId ||
    verification.baseBackupManifestSha256 !== canonicalSha256(baseManifest) ||
    verification.systemIdentifier !== baseManifest.systemIdentifier
  ) {
    throw new Error("base restore verification receipt does not match the selected backup");
  }
  const {
    walFiles,
    legacyIdOnlyCount: legacyWalCount,
    ...temporaryReport
  } = await materializeWalArchive({
    archiveDirectory: input.archiveDirectory,
    targetDirectory: input.walTargetDirectory,
    encryptionKeyFile: input.encryptionKeyFile,
    encryptionKeyId: input.encryptionKeyId,
    expectedKeyFingerprintSha256: baseManifest.encryptionKeyFingerprintSha256,
    expectedInstanceId: baseManifest.instanceId,
    expectedOrganizationId: baseManifest.organizationId,
    recoveryKeyringFile: input.recoveryKeyringFile
  });
  const legacyIdOnlyCount =
    legacyWalCount + (baseManifest.encryptionKeyFingerprintSha256 === undefined ? 1 : 0);
  const segmentFiles = walFiles.filter((name) => /^[0-9A-F]{24}$/u.test(name));
  const includesWalFile = segmentFiles.at(-1);
  if (!includesWalFile) throw new Error("PITR preparation requires at least one WAL segment");
  await appendRecoveryConfiguration(pgdata);
  await exclusiveFile(path.join(pgdata, "recovery.signal"), "");
  const preparationFile = path.join(pgdata, ".boardagent-pitr-prepared.json");
  const receipt = z
    .object({
      schemaVersion: z.literal("boardagent.pitr-preparation.v1"),
      backupId: z.string().uuid(),
      baseBackupManifestSha256: z.string().regex(/^[0-9a-f]{64}$/u),
      preparedAt: z.iso.datetime({ offset: true }),
      walFileCount: z.number().int().positive(),
      legacyIdOnlyCount: z.number().int().nonnegative(),
      recoveryKeyringSha256: z
        .string()
        .regex(/^[0-9a-f]{64}$/u)
        .optional(),
      recoveryKeyIds: z.array(z.string().uuid()).min(1).max(4096).optional(),
      ignoredTemporaryFileCount: z.number().int().positive().optional(),
      ignoredTemporaryFiles: z.array(z.string().max(256)).max(20).optional(),
      includesWalFile: z.string().regex(/^[0-9A-F]{24}$/u),
      ready: z.literal(false),
      reason: z.literal("isolated_postgresql_start_and_application_verification_required")
    })
    .strict()
    .parse({
      schemaVersion: "boardagent.pitr-preparation.v1",
      backupId: baseManifest.backupId,
      baseBackupManifestSha256: canonicalSha256(baseManifest),
      preparedAt: new Date().toISOString(),
      walFileCount: walFiles.length,
      legacyIdOnlyCount,
      ...temporaryReport,
      includesWalFile,
      ready: false,
      reason: "isolated_postgresql_start_and_application_verification_required"
    });
  await syncRecoveryDirectory(pgdata);
  await publishRecoveryJson(preparationFile, receipt as JsonValue);
  return {
    backupId: baseManifest.backupId,
    walFileCount: walFiles.length,
    includesWalFile,
    preparationFile,
    legacyIdOnlyCount,
    ...temporaryReport
  };
}
