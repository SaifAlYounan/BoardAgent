import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { BaseBackupManifestSchema } from "../../scripts/src/base-backup.js";
import {
  DEFAULT_POSTGRES_IMAGE,
  DEFAULT_RELEASE_IMAGE
} from "../../scripts/src/build-release-image.js";
import { WalArchiveManifestSchema } from "../../scripts/src/wal-archive.js";

interface Invocation {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

async function command(
  executable: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env
): Promise<Invocation> {
  const child = spawn(executable, [...args], {
    cwd: path.resolve("."),
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { code, stdout, stderr };
}

async function waitFor(
  predicate: () => Promise<boolean>,
  description: string,
  timeoutMilliseconds = 45_000
): Promise<void> {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${description}`);
}

describe("T9 continuous WAL and encrypted PostgreSQL base backup", () => {
  it("archives a real switched segment and verifies an encrypted tar base backup without plaintext persistence", async () => {
    const suffix = `${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    const project = `boardagent_recovery_${suffix}`.toLowerCase();
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-compose-recovery-"));
    const configurationRoot = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-config-"));
    const hostOwner = await lstat(root);
    const wal = path.join(root, "wal");
    const base = path.join(root, "base");
    const restore = path.join(root, "restore");
    const walRestore = path.join(root, "wal-restore");
    const keyFile = path.join(root, "backup.key");
    const databasePasswordFile = path.join(root, "backup-database.password");
    await Promise.all([mkdir(wal), mkdir(base), mkdir(restore), mkdir(walRestore)]);
    await writeFile(keyFile, randomBytes(32), { mode: 0o600 });

    const image = process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE;
    const postgresImage = process.env["BOARDAGENT_POSTGRES_IMAGE"] ?? DEFAULT_POSTGRES_IMAGE;
    const recoveryCommand = async (args: readonly string[]): Promise<Invocation> =>
      command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--mount",
        `type=bind,source=${root},target=/recovery,readonly`,
        "--entrypoint",
        "node",
        image,
        ...args
      ]);
    const containerPath = (file: string): string => `/recovery/${path.relative(root, file)}`;
    const readdir = async (directory: string): Promise<string[]> => {
      const result = await recoveryCommand([
        "-e",
        "process.stdout.write(JSON.stringify(require('node:fs').readdirSync(process.argv[1])))",
        containerPath(directory)
      ]);
      expect(result.code, result.stderr).toBe(0);
      return JSON.parse(result.stdout) as string[];
    };
    const readFile = async (file: string, _encoding: "utf8"): Promise<string> => {
      const result = await recoveryCommand([
        "-e",
        "process.stdout.write(require('node:fs').readFileSync(process.argv[1]))",
        containerPath(file)
      ]);
      expect(result.code, result.stderr).toBe(0);
      return result.stdout;
    };
    const inspect = await command("docker", [
      "image",
      "inspect",
      image,
      "--format",
      '{{.Id}} {{index .Config.Labels "org.boardagent.source-tree-sha256"}}'
    ]);
    expect(inspect.code, inspect.stderr).toBe(0);
    const [imageId, sourceTreeSha256] = inspect.stdout.trim().split(/\s+/u);
    expect(imageId).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(sourceTreeSha256).toMatch(/^[0-9a-f]{64}$/u);

    const keyId = "018f0000-0000-7000-8000-000000000099";
    const password = `recovery-${randomBytes(18).toString("base64url")}`;
    const backupPassword = randomBytes(32).toString("base64url");
    await writeFile(databasePasswordFile, backupPassword, { mode: 0o600 });
    const compose: string[] = [
      "compose",
      "-p",
      project,
      "-f",
      "compose.yaml",
      "-f",
      "compose.recovery.yaml"
    ];
    const restoredContainer = `${project}-restored`;
    const env = {
      ...process.env,
      RELEASE_IMAGE: image,
      POSTGRES_IMAGE: postgresImage,
      RECOVERY_ROOT: root,
      BACKUP_KEK_HOST_FILE: keyFile,
      RECOVERY_DATABASE_PASSWORD_HOST_FILE: databasePasswordFile,
      BACKUP_KEY_ID: keyId,
      BOARDAGENT_ORGANIZATION_ID: "",
      POSTGRES_PASSWORD: password
    };
    try {
      // Commission identity before enabling archiving; no registry/archiver boot cycle.
      const initial = await command(
        "docker",
        ["compose", "-p", project, "-f", "compose.yaml", "up", "-d", "--wait", "postgres"],
        env
      );
      expect(initial.code, initial.stderr).toBe(0);
      const bootstrap = await command("docker", [
        "run",
        "--rm",
        "--network",
        `${project}_backend`,
        "-e",
        `BOARDAGENT_TEST_DATABASE_URL=postgresql://boardagent:${password}@postgres:5432/boardagent`,
        "-e",
        `BOARDAGENT_TEST_BACKUP_PASSWORD=${backupPassword}`,
        "--entrypoint",
        "node",
        image,
        "--input-type=module",
        "-e",
        `import path from 'node:path';import pg from 'pg';import fs from 'node:fs/promises';import {randomBytes} from 'node:crypto';
         import {migrate} from './lib/db/dist/index.js';
         import {BoardAgentBootstrapOperator} from './scripts/dist/bootstrap.js';
         import {provisionDatabasePrincipals} from './scripts/dist/database-principals.js';
         const pool=new pg.Pool({connectionString:process.env.BOARDAGENT_TEST_DATABASE_URL});
         try {
           await migrate(pool,path.resolve('lib/db/migrations'),'wal-recovery-fixture');
           const secrets=await fs.mkdtemp('/tmp/base-principals-');const files={};
           for(const purpose of ['migrator','server','worker','backup']) {
             files[purpose]=path.join(secrets,purpose+'.password');
             await fs.writeFile(files[purpose],purpose==='backup'?process.env.BOARDAGENT_TEST_BACKUP_PASSWORD:randomBytes(32).toString('base64url'),{mode:0o600});
           }
           await provisionDatabasePrincipals(pool,files);
           await fs.rm(secrets,{recursive:true,force:true});
           const result=await new BoardAgentBootstrapOperator(pool,{assumeRole:'boardagent_migrator'}).initialize({
             organizationLegalName:'Recovery Test Ltd',organizationDisplayName:'Recovery Test',organizationSlug:'recovery-test',
             timezone:'UTC',canonicalResourceUri:'https://recovery.boardagent.test/mcp',boardSlug:'main',boardName:'Main',
             boardCanonicalPayload:{schemaVersion:'boardagent.board.v1',name:'Main'},firstSecretaryLegalName:'Setup',
             firstSecretaryDisplayName:'Setup',votingWeight:1,supportName:'Support',supportContactMethods:[],
             onboardingTermsText:'Synthetic recovery terms.',invitationHandoffMethod:'in person'});
           if(result.status!=='created')throw new Error('fixture already exists');
           process.stdout.write(JSON.stringify({organizationId:result.organizationId}));
         } finally {await pool.end();}`
      ]);
      expect(bootstrap.code, bootstrap.stderr).toBe(0);
      env.BOARDAGENT_ORGANIZATION_ID = String(
        (JSON.parse(bootstrap.stdout) as { organizationId: string }).organizationId
      );
      const receiptVolume = await command("docker", [
        "volume",
        "create",
        `${project}_backup-key-receipts`
      ]);
      expect(receiptVolume.code, receiptVolume.stderr).toBe(0);
      const receiptCustody = await command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "FOWNER",
        "--cap-add",
        "DAC_OVERRIDE",
        "--mount",
        `type=volume,source=${project}_backup-key-receipts,target=/receipts`,
        "--entrypoint",
        "sh",
        image,
        "-ec",
        "install -d -o 10001 -g 10001 -m 0700 /receipts"
      ]);
      expect(receiptCustody.code, receiptCustody.stderr).toBe(0);
      // Native bind mounts preserve UID/mode. Recovery is private to its actual writer;
      // test inspection uses that principal rather than making recovery material public.
      // DAC_OVERRIDE is limited to this networkless, exact-root custody one-shot: after
      // chown of the 0700 root, uid 0 must still traverse it to finish its children.
      // The archiver and every content inspection retain uid 10001 and zero capabilities.
      const custody = await command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "FOWNER",
        "--cap-add",
        "DAC_OVERRIDE",
        "--security-opt",
        "no-new-privileges:true",
        "--mount",
        `type=bind,source=${root},target=/recovery`,
        "--entrypoint",
        "sh",
        image,
        "-ec",
        "chown 10001:10001 /recovery /recovery/wal /recovery/base /recovery/restore /recovery/wal-restore && chmod 0700 /recovery /recovery/wal /recovery/base /recovery/restore /recovery/wal-restore"
      ]);
      expect(custody.code, custody.stderr).toBe(0);
      const keySources = await command(
        "docker",
        [...compose, "run", "--rm", "recovery-secret-init"],
        env
      );
      expect(keySources.code, keySources.stderr).toBe(0);
      const registered = await command("docker", [
        "run",
        "--rm",
        "--network",
        `${project}_backend`,
        "--mount",
        `type=volume,source=${project}_recovery-secrets,target=/run/recovery,readonly`,
        "--mount",
        `type=volume,source=${project}_backup-key-receipts,target=/receipts`,
        "-e",
        "BOARDAGENT_ENV=test",
        "-e",
        `BOARDAGENT_DATABASE_URL=postgresql://boardagent:${password}@postgres:5432/boardagent`,
        "-e",
        `BOARDAGENT_ORGANIZATION_ID=${env.BOARDAGENT_ORGANIZATION_ID}`,
        "-e",
        `BOARDAGENT_BACKUP_KEY_ID=${keyId}`,
        "-e",
        "BOARDAGENT_BACKUP_KEK_FILE=/run/recovery/backup_kek",
        "-e",
        "BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY=/receipts",
        "--entrypoint",
        "node",
        image,
        "scripts/dist/operator.js",
        "register-backup-key"
      ]);
      expect(registered.code, registered.stderr).toBe(0);
      expect(JSON.parse(registered.stdout)).toMatchObject({
        status: "succeeded",
        keyRegistration: { keyId, replayed: false }
      });
      const beforeCheck = await command("docker", [...compose, "ps", "-q", "postgres"], env);
      const tampered = await command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--mount",
        `type=volume,source=${project}_backup-key-receipts,target=/receipts`,
        "--entrypoint",
        "node",
        image,
        "-e",
        `const fs=require('node:fs'),p='/receipts/${keyId}.json';fs.copyFileSync(p,p+'.original');fs.chmodSync(p,0o600);const r=JSON.parse(fs.readFileSync(p,'utf8'));r.fingerprintSha256='a'.repeat(64);fs.writeFileSync(p,JSON.stringify(r));`
      ]);
      expect(tampered.code, tampered.stderr).toBe(0);
      const refused = await command("docker", [...compose, "run", "--rm", "backup-key-check"], env);
      expect(refused.code).not.toBe(0);
      const afterCheck = await command("docker", [...compose, "ps", "-q", "postgres"], env);
      expect(afterCheck.stdout).toBe(beforeCheck.stdout);
      const repairedReceipt = await command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--mount",
        `type=volume,source=${project}_backup-key-receipts,target=/receipts`,
        "--entrypoint",
        "node",
        image,
        "-e",
        `const fs=require('node:fs'),p='/receipts/${keyId}.json';fs.writeFileSync(p,fs.readFileSync(p+'.original'));fs.chmodSync(p,0o400);fs.unlinkSync(p+'.original');`
      ]);
      expect(repairedReceipt.code, repairedReceipt.stderr).toBe(0);
      const checked = await command("docker", [...compose, "run", "--rm", "backup-key-check"], env);
      expect(checked.code, checked.stderr).toBe(0);
      const up = await command("docker", [...compose, "up", "-d", "wal-archiver"], env);
      expect(up.code, `${up.stdout}\n${up.stderr}`).toBe(0);
      try {
        await waitFor(async () => {
          const ready = await command(
            "docker",
            [
              ...compose,
              "exec",
              "-T",
              "postgres",
              "pg_isready",
              "-h",
              "127.0.0.1",
              "-U",
              "boardagent"
            ],
            env
          );
          return ready.code === 0;
        }, "recovery-overlay PostgreSQL readiness");
      } catch (error) {
        const logs = await command(
          "docker",
          [...compose, "logs", "--no-color", "postgres", "wal-archiver"],
          env
        );
        throw new Error(`${String(error)}\n${logs.stdout}\n${logs.stderr}`);
      }

      await waitFor(async () => {
        const ready = await command(
          "docker",
          [
            ...compose,
            "exec",
            "-T",
            "wal-archiver",
            "node",
            "-e",
            "const s=JSON.parse(require('node:fs').readFileSync('/tmp/boardagent-wal-status.json'));process.exit(s.status==='healthy'?0:1)"
          ],
          env
        );
        return ready.code === 0;
      }, "active WAL writer before receipt fault");

      const breakActiveReceipt = await command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--mount",
        `type=volume,source=${project}_backup-key-receipts,target=/receipts`,
        "--entrypoint",
        "node",
        image,
        "-e",
        `const fs=require('node:fs'),p='/receipts/${keyId}.json';fs.copyFileSync(p,p+'.original');fs.chmodSync(p,0o600);const r=JSON.parse(fs.readFileSync(p,'utf8'));r.fingerprintSha256='a'.repeat(64);fs.writeFileSync(p,JSON.stringify(r));`
      ]);
      expect(breakActiveReceipt.code, breakActiveReceipt.stderr).toBe(0);
      const archiverId = await command("docker", [...compose, "ps", "-q", "wal-archiver"], env);
      expect(archiverId.code, archiverId.stderr).toBe(0);
      await waitFor(async () => {
        const health = await command("docker", [
          "inspect",
          archiverId.stdout.trim(),
          "--format",
          "{{.State.Health.Status}}"
        ]);
        return health.code === 0 && health.stdout.trim() === "unhealthy";
      }, "archiver unhealthy status after receipt validation fails");
      const blockedLogs = await command(
        "docker",
        [...compose, "logs", "--no-color", "wal-archiver"],
        env
      );
      expect(`${blockedLogs.stdout}${blockedLogs.stderr}`).toContain(
        '"event":"wal_archive_blocked"'
      );
      expect(`${blockedLogs.stdout}${blockedLogs.stderr}`).toContain('"stage":"key_registration"');
      expect(`${blockedLogs.stdout}${blockedLogs.stderr}`).toContain(
        '"reasonCode":"validation_or_operation_failed"'
      );
      const archivedBefore = await readdir(wal);
      const settings = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "-e",
          `PGPASSWORD=${password}`,
          "postgres",
          "psql",
          "-U",
          "boardagent",
          "-d",
          "boardagent",
          "-Atc",
          "show archive_mode; show archive_timeout; create table recovery_probe(value text primary key); grant select on recovery_probe to boardagent_backup; insert into recovery_probe values ('before-base'); select pg_switch_wal();"
        ],
        env
      );
      expect(settings.code, settings.stderr).toBe(0);
      expect(settings.stdout).toContain("on\n");
      expect(settings.stdout).toContain("15min\n");
      await waitFor(async () => {
        const staging = await command(
          "docker",
          [
            ...compose,
            "exec",
            "-T",
            "wal-archiver",
            "node",
            "-e",
            "process.stdout.write(JSON.stringify(require('node:fs').readdirSync('/wal-staging')))"
          ],
          env
        );
        return (
          staging.code === 0 &&
          (JSON.parse(staging.stdout) as string[]).some((name) => /^[0-9A-F]{24}$/u.test(name))
        );
      }, "WAL retained in staging while registration is invalid");
      expect(await readdir(wal)).toEqual(archivedBefore);
      const restoreActiveReceipt = await command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--mount",
        `type=volume,source=${project}_backup-key-receipts,target=/receipts`,
        "--entrypoint",
        "node",
        image,
        "-e",
        `const fs=require('node:fs'),p='/receipts/${keyId}.json';fs.writeFileSync(p,fs.readFileSync(p+'.original'));fs.chmodSync(p,0o400);fs.unlinkSync(p+'.original');`
      ]);
      expect(restoreActiveReceipt.code, restoreActiveReceipt.stderr).toBe(0);
      await waitFor(async () => {
        const health = await command("docker", [
          "inspect",
          archiverId.stdout.trim(),
          "--format",
          "{{.State.Health.Status}}"
        ]);
        return health.code === 0 && health.stdout.trim() === "healthy";
      }, "archiver resumes after exact registration is restored");
      const resumedLogs = await command(
        "docker",
        [...compose, "logs", "--no-color", "wal-archiver"],
        env
      );
      expect(`${resumedLogs.stdout}${resumedLogs.stderr}`).toContain(
        '"event":"wal_archive_resumed"'
      );
      const hookTemporary = "000000010000000000FFFFFE.partial.999999";
      const retainedTemporary = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "wal-archiver",
          "node",
          "-e",
          `require('node:fs').writeFileSync('/wal-staging/${hookTemporary}','unfinished hook copy',{mode:0o600});`
        ],
        env
      );
      expect(retainedTemporary.code, retainedTemporary.stderr).toBe(0);
      await waitFor(async () => {
        const logs = await command(
          "docker",
          [...compose, "logs", "--no-color", "wal-archiver"],
          env
        );
        return `${logs.stdout}${logs.stderr}`.includes(
          '"event":"wal_archive_temporary_files_retained"'
        );
      }, "bounded retained-temporary warning");

      await waitFor(
        async () => (await readdir(wal)).some((name) => name.endsWith(".manifest.json")),
        "encrypted WAL archive"
      );
      const walManifestName = (await readdir(wal)).find((name) => name.endsWith(".manifest.json"));
      expect(walManifestName).toBeDefined();
      const walManifest = WalArchiveManifestSchema.parse(
        JSON.parse(await readFile(path.join(wal, walManifestName!), "utf8"))
      );
      expect(walManifest.format).toBe("postgresql-wal-aes256gcm-v1");
      expect(walManifest.plaintextBytes).toBe("16777216");

      const backupUrl = "postgresql://boardagent_backup_login@postgres:5432/boardagent";
      const inventory = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_BACKUP_DATABASE_URL=${backupUrl}`,
          "wal-archiver",
          "node",
          "scripts/dist/operator.js",
          "inspect-pilot-state"
        ],
        env
      );
      expect(inventory.code, inventory.stderr).toBe(0);
      expect(JSON.parse(inventory.stdout)).toMatchObject({
        command: "inspect-pilot-state",
        status: "observed",
        readOnly: true,
        tableRowCounts: {
          members: "1",
          documents: "0",
          webauthn_credentials: "0",
          recovery_probe: "1"
        }
      });
      const wrongBaseKey = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_BACKUP_DATABASE_URL=${backupUrl}`,
          "-e",
          `BOARDAGENT_SOURCE_IMAGE_DIGEST=${imageId!}`,
          "wal-archiver",
          "node",
          "--input-type=module",
          "-e",
          `import fs from 'node:fs/promises';import {runOperator} from './scripts/dist/operator.js';
         await fs.writeFile('/tmp/wrong-backup.key',Buffer.alloc(32,0x61),{mode:0o600});
         process.env.BOARDAGENT_BACKUP_KEK_FILE='/tmp/wrong-backup.key';
         process.exitCode=await runOperator(['base-backup','/recovery/base'],process.env);`
        ],
        env
      );
      expect(wrongBaseKey.code).not.toBe(0);
      expect(wrongBaseKey.stderr).toContain("registered fingerprint");
      expect(await readdir(base)).toEqual([]);
      const retentionBlocker = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "wal-archiver",
          "node",
          "-e",
          "require('node:fs').writeFileSync('/recovery/base/unrecognized-entry','preserve this diagnostic evidence',{mode:0o600})"
        ],
        env
      );
      expect(retentionBlocker.code, retentionBlocker.stderr).toBe(0);
      const backup = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_BACKUP_DATABASE_URL=${backupUrl}`,
          "-e",
          `BOARDAGENT_SOURCE_IMAGE_DIGEST=${imageId!}`,
          "wal-archiver",
          "node",
          "scripts/dist/operator.js",
          "base-backup",
          "/recovery/base"
        ],
        env
      );
      expect(backup.code, `${backup.stdout}\n${backup.stderr}`).toBe(1);
      expect(
        (await readdir(base)).filter((name) => name.endsWith(".base.manifest.json"))
      ).toHaveLength(1);
      const backupReceipt = JSON.parse(backup.stdout) as Record<string, unknown>;
      expect(backupReceipt).toMatchObject({
        schemaVersion: "boardagent.operator-base-backup.v1",
        command: "base-backup",
        status: "published_retention_refused",
        reasonCode: "validation_or_operation_failed"
      });
      expect(backupReceipt.backupId).toEqual(expect.any(String));
      expect(backupReceipt.manifestFile).toEqual(expect.stringContaining(".base.manifest.json"));
      const preserveBlocker = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "wal-archiver",
          "node",
          "-e",
          "require('node:fs').renameSync('/recovery/base/unrecognized-entry','/recovery/retention-blocker-preserved')"
        ],
        env
      );
      expect(preserveBlocker.code, preserveBlocker.stderr).toBe(0);
      const retentionRetry = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "wal-archiver",
          "node",
          "scripts/dist/operator.js",
          "prune-base-backups",
          "/recovery/base"
        ],
        env
      );
      expect(retentionRetry.code, retentionRetry.stderr).toBe(0);
      expect(JSON.parse(retentionRetry.stdout)).toMatchObject({
        status: "succeeded",
        command: "prune-base-backups",
        keptBackupIds: [backupReceipt.backupId]
      });
      expect(
        (await readdir(base)).filter((name) => name.endsWith(".base.manifest.json"))
      ).toHaveLength(1);
      const baseManifestName = (await readdir(base)).find((name) =>
        name.endsWith(".base.manifest.json")
      );
      expect(baseManifestName).toBeDefined();
      const baseManifest = BaseBackupManifestSchema.parse(
        JSON.parse(await readFile(path.join(base, baseManifestName!), "utf8"))
      );
      expect(baseManifest).toMatchObject({
        sourceDatabase: "boardagent",
        sourceImageDigest: imageId,
        walMethod: "fetch",
        manifestChecksums: "SHA256",
        organizationId: env.BOARDAGENT_ORGANIZATION_ID,
        encryptionKeyFingerprintSha256: walManifest.encryptionKeyFingerprintSha256,
        instanceId: walManifest.instanceId
      });
      expect((await readdir(base)).some((name) => name.endsWith(".tar"))).toBe(false);

      // Preserve the first base/WAL generation, replace the actual registered writer key,
      // then recover through WAL encrypted on both sides of the replacement.
      const stoppedForReplacement = await command(
        "docker",
        [...compose, "stop", "wal-archiver"],
        env
      );
      expect(stoppedForReplacement.code, stoppedForReplacement.stderr).toBe(0);
      const nextKeyId = "018f0000-0000-7000-8000-000000000100";
      const replaced = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_TEST_DATABASE_URL=postgresql://boardagent:${password}@postgres:5432/boardagent`,
          "wal-archiver",
          "node",
          "--input-type=module",
          "-e",
          `import fs from 'node:fs/promises';import {randomBytes,createHash} from 'node:crypto';import pg from 'pg';
         import {withBootstrapTransaction,prepareKeyLifecycleInTransaction,applyKeyLifecycleInTransaction,readActiveBackupKeyInTransaction} from './lib/db/dist/index.js';
         import {writeBackupKeyReceipt} from './scripts/dist/backup-key-binding.js';
         import {acquireKernelMaintenanceLease,PRODUCTION_MAINTENANCE_LOCK_FILE} from './artifacts/server/dist/index.js';
         const lease=await acquireKernelMaintenanceLease(PRODUCTION_MAINTENANCE_LOCK_FILE,'exclusive');
         const pool=new pg.Pool({connectionString:process.env.BOARDAGENT_TEST_DATABASE_URL});
         try {
           const old=await fs.readFile(process.env.BOARDAGENT_BACKUP_KEK_FILE),next=randomBytes(32),digest=b=>createHash('sha256').update(b).digest('hex');
           await fs.writeFile('/recovery/backup-old.key',old,{mode:0o400,flag:'wx'});
           await fs.writeFile('/recovery/backup-next.key',next,{mode:0o400,flag:'wx'});
           const target=(await pool.query('select instance_id,organization_id from system_instance')).rows[0];
           const inventory=[];for(const dir of ['/recovery/base','/recovery/wal'])for(const name of (await fs.readdir(dir)).sort())if(name.endsWith('.manifest.json'))inventory.push({name,sha256:digest(await fs.readFile(dir+'/'+name))});
           const proposed=await withBootstrapTransaction(pool,c=>prepareKeyLifecycleInTransaction(c,{
             instanceId:target.instance_id,organizationId:target.organization_id,keyId:'${keyId}',operationId:'018f0000-0000-7000-8000-000000000101',operation:'replace',declaredCompromisedAt:null,
             replacement:{keyId:'${nextKeyId}',kid:'backup-${nextKeyId}',algorithm:'A256GCM',publicJwk:null,materialSha256:digest(next),nonsecretLocator:'sha256:'+digest(next)},
             retainedMaterialSha256:digest(Buffer.from(JSON.stringify(inventory))),operatorReference:'synthetic cross-generation PITR test',reason:'Preserve old backup and prove journal replay across actual key replacement'
           }),{assumeRole:'boardagent_migrator',readOnly:true});
           const receipt=await withBootstrapTransaction(pool,c=>applyKeyLifecycleInTransaction(c,proposed),{assumeRole:'boardagent_migrator'});
           const identity=await withBootstrapTransaction(pool,c=>readActiveBackupKeyInTransaction(c,'${nextKeyId}'),{assumeRole:'boardagent_migrator',readOnly:true});
           await writeBackupKeyReceipt('/recovery',identity);
           await fs.writeFile('/recovery/recovery-keys.json',JSON.stringify({schemaVersion:'boardagent.backup-recovery-keys.v1',instanceId:target.instance_id,organizationId:target.organization_id,keys:[
             {keyId:'${keyId}',keyFile:'/recovery/backup-old.key',fingerprintSha256:digest(old)},
             {keyId:'${nextKeyId}',keyFile:'/recovery/backup-next.key',fingerprintSha256:digest(next)}]}),{mode:0o400,flag:'wx'});
           for(const dir of ['base-next','restore-next','wal-restore-next'])await fs.mkdir('/recovery/'+dir,{mode:0o700});
           process.stdout.write(JSON.stringify({operationId:receipt.operationId,replacementKeyId:identity.keyId}));old.fill(0);next.fill(0);
         } finally {await pool.end();await lease.close();}`
        ],
        env
      );
      expect(replaced.code, replaced.stdout + replaced.stderr).toBe(0);
      expect(JSON.parse(replaced.stdout)).toMatchObject({ replacementKeyId: nextKeyId });
      const rotationOverride = path.join(configurationRoot, "replacement.json");
      await writeFile(
        rotationOverride,
        JSON.stringify({
          services: {
            "wal-archiver": {
              environment: {
                BOARDAGENT_BACKUP_KEY_ID: nextKeyId,
                BOARDAGENT_BACKUP_KEK_FILE: "/recovery/backup-next.key",
                BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE: `/recovery/${nextKeyId}.json`
              }
            }
          }
        }),
        { mode: 0o600 }
      );
      compose.push("-f", rotationOverride);
      const restartedWriter = await command(
        "docker",
        [...compose, "up", "-d", "--no-deps", "--force-recreate", "wal-archiver"],
        env
      );
      expect(restartedWriter.code, restartedWriter.stderr).toBe(0);
      const nextBase = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_SOURCE_IMAGE_DIGEST=${imageId!}`,
          "wal-archiver",
          "node",
          "scripts/dist/operator.js",
          "base-backup",
          "/recovery/base-next"
        ],
        env
      );
      expect(nextBase.code, nextBase.stdout + nextBase.stderr).toBe(0);
      const nextBaseManifest = JSON.parse(nextBase.stdout).manifestFile as string;

      const afterBaseInsert = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "-e",
          `PGPASSWORD=${password}`,
          "postgres",
          "psql",
          "-U",
          "boardagent",
          "-d",
          "boardagent",
          "-Atc",
          "insert into recovery_probe values ('after-base')"
        ],
        env
      );
      expect(afterBaseInsert.code, afterBaseInsert.stderr).toBe(0);
      const afterBase = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "-e",
          `PGPASSWORD=${password}`,
          "postgres",
          "psql",
          "-U",
          "boardagent",
          "-d",
          "boardagent",
          "-Atc",
          "select pg_walfile_name(pg_current_wal_lsn()); select pg_switch_wal();"
        ],
        env
      );
      expect(afterBase.code, afterBase.stderr).toBe(0);
      const postBaseWalName = /(?:^|\n)([0-9A-F]{24})(?:\n|$)/u.exec(afterBase.stdout)?.[1];
      expect(postBaseWalName).toBeDefined();
      await waitFor(
        async () => (await readdir(wal)).includes(`${postBaseWalName!}.manifest.json`),
        "post-base-backup WAL archive"
      );
      expect(
        JSON.parse(await readFile(path.join(wal, `${postBaseWalName!}.manifest.json`), "utf8"))
      ).toMatchObject({ encryptionKeyId: nextKeyId });

      const recoveryVariants = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "wal-archiver",
          "node",
          "-e",
          `const fs=require('node:fs'),p='/recovery/base/${baseManifestName!}',m=JSON.parse(fs.readFileSync(p,'utf8'));
         fs.writeFileSync('/recovery/wrong-fingerprint.manifest.json',JSON.stringify({...m,encryptionKeyFingerprintSha256:'a'.repeat(64)}),{mode:0o600});
         for(const k of ['instanceId','organizationId','encryptionKeyFingerprintSha256','encryptionKeyActivatedAt','encryptionKeyKid'])delete m[k];
         fs.writeFileSync('/recovery/legacy-base.manifest.json',JSON.stringify(m),{mode:0o600});`
        ],
        env
      );
      expect(recoveryVariants.code, recoveryVariants.stderr).toBe(0);
      const wrongFingerprintRestore = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_BACKUP_KEY_ID=${keyId}`,
          "-e",
          "BOARDAGENT_BACKUP_KEK_FILE=/recovery/backup-old.key",
          "wal-archiver",
          "node",
          "scripts/dist/operator.js",
          "base-restore-check",
          "/recovery/wrong-fingerprint.manifest.json",
          "/recovery/restore"
        ],
        env
      );
      expect(wrongFingerprintRestore.code).not.toBe(0);
      // The public CLI deliberately redacts exception messages. Only the manifest
      // fingerprint differs from the valid generation used by the next restore.
      expect(wrongFingerprintRestore.stderr).toContain(
        '"reasonCode":"validation_or_operation_failed"'
      );
      expect(wrongFingerprintRestore.stderr).toContain('"stage":"base-restore-check"');
      expect(await readdir(restore)).toEqual([]);

      const restoreCheck = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_BACKUP_KEY_ID=${keyId}`,
          "-e",
          "BOARDAGENT_BACKUP_KEK_FILE=/recovery/backup-old.key",
          "wal-archiver",
          "node",
          "scripts/dist/operator.js",
          "base-restore-check",
          "/recovery/legacy-base.manifest.json",
          "/recovery/restore"
        ],
        env
      );
      expect(restoreCheck.code, `${restoreCheck.stdout}\n${restoreCheck.stderr}`).toBe(0);
      expect(JSON.parse(restoreCheck.stdout)).toMatchObject({
        schemaVersion: "boardagent.operator-base-restore-check.v1",
        status: "succeeded",
        ready: false,
        reason: "isolated_start_and_replay_required",
        legacyIdOnlyCount: 1
      });
      expect(await readFile(path.join(restore, "PG_VERSION"), "utf8")).toBe("18\n");
      const postgresManifest = await readFile(path.join(restore, "backup_manifest"), "utf8");
      expect(postgresManifest).toContain('"Checksum-Algorithm": "SHA256"');
      expect(postgresManifest).toMatch(/"Manifest-Checksum": "[0-9a-f]{64}"/u);

      const preparePitr = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_BACKUP_KEY_ID=${keyId}`,
          "-e",
          "BOARDAGENT_BACKUP_KEK_FILE=/recovery/backup-old.key",
          "-e",
          "BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE=/recovery/recovery-keys.json",
          "wal-archiver",
          "node",
          "scripts/dist/operator.js",
          "prepare-pitr",
          "/recovery/legacy-base.manifest.json",
          "/recovery/wal",
          "/recovery/restore",
          "/recovery/wal-restore"
        ],
        env
      );
      expect(preparePitr.code, `${preparePitr.stdout}\n${preparePitr.stderr}`).toBe(0);
      expect(JSON.parse(preparePitr.stdout)).toMatchObject({
        schemaVersion: "boardagent.operator-prepare-pitr.v1",
        status: "succeeded",
        ready: false,
        includesWalFile: postBaseWalName,
        legacyIdOnlyCount: 1,
        recoveryKeyIds: [keyId, nextKeyId]
      });

      const restoredArguments = (dataDirectory: string, walDirectory: string) => [
        "run",
        "--detach",
        "--name",
        restoredContainer,
        "--user",
        "10001:10001",
        "-e",
        "PGDATA=/var/lib/postgresql/data",
        "--read-only",
        "--tmpfs",
        "/tmp:size=32m,mode=1777",
        "--tmpfs",
        "/var/run/postgresql:size=16m,mode=0775,uid=10001,gid=10001",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--mount",
        `type=bind,source=${dataDirectory},target=/var/lib/postgresql/data`,
        "--mount",
        `type=bind,source=${walDirectory},target=/wal-restore,readonly`,
        postgresImage,
        "postgres",
        "-D",
        "/var/lib/postgresql/data",
        "-c",
        "listen_addresses=",
        "-c",
        "unix_socket_directories=/var/run/postgresql"
      ];
      const restored = await command("docker", restoredArguments(restore, walRestore));
      expect(restored.code, restored.stderr).toBe(0);
      try {
        await waitFor(async () => {
          const ready = await command("docker", [
            "exec",
            restoredContainer,
            "pg_isready",
            "-U",
            "boardagent",
            "-d",
            "boardagent"
          ]);
          return ready.code === 0;
        }, "isolated PITR PostgreSQL readiness");
      } catch (error) {
        const logs = await command("docker", ["logs", restoredContainer]);
        throw new Error(`${String(error)}\n${logs.stdout}\n${logs.stderr}`);
      }
      const recovered = await command("docker", [
        "exec",
        restoredContainer,
        "psql",
        "-U",
        "boardagent",
        "-d",
        "boardagent",
        "-Atc",
        "select value from recovery_probe order by value; select pg_is_in_recovery();"
      ]);
      expect(recovered.code, recovered.stderr).toBe(0);
      expect(recovered.stdout).toBe("after-base\nbefore-base\nf\n");
      const removedOldRestore = await command("docker", ["rm", "-f", restoredContainer]);
      expect(removedOldRestore.code, removedOldRestore.stderr).toBe(0);
      for (const args of [
        ["base-restore-check", nextBaseManifest, "/recovery/restore-next"],
        [
          "prepare-pitr",
          nextBaseManifest,
          "/recovery/wal",
          "/recovery/restore-next",
          "/recovery/wal-restore-next"
        ]
      ]) {
        const prepared = await command(
          "docker",
          [
            ...compose,
            "run",
            "--rm",
            "--no-deps",
            "-e",
            "BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE=/recovery/recovery-keys.json",
            "wal-archiver",
            "node",
            "scripts/dist/operator.js",
            ...args
          ],
          env
        );
        expect(prepared.code, prepared.stdout + prepared.stderr).toBe(0);
      }
      const restoredNext = await command(
        "docker",
        restoredArguments(path.join(root, "restore-next"), path.join(root, "wal-restore-next"))
      );
      expect(restoredNext.code, restoredNext.stderr).toBe(0);
      await waitFor(
        async () =>
          (
            await command("docker", [
              "exec",
              restoredContainer,
              "pg_isready",
              "-U",
              "boardagent",
              "-d",
              "boardagent"
            ])
          ).code === 0,
        "new key base PostgreSQL readiness"
      );
      const recoveredNext = await command("docker", [
        "exec",
        restoredContainer,
        "psql",
        "-U",
        "boardagent",
        "-d",
        "boardagent",
        "-Atc",
        "select value from recovery_probe order by value; select pg_is_in_recovery();"
      ]);
      expect(recoveredNext.code, recoveredNext.stderr).toBe(0);
      expect(recoveredNext.stdout).toBe("after-base\nbefore-base\nf\n");
    } finally {
      await command("docker", ["rm", "-f", restoredContainer]).catch(() => undefined);
      await command("docker", [...compose, "down", "--volumes", "--remove-orphans"], env).catch(
        () => undefined
      );
      const returned = await command("docker", [
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--security-opt",
        "no-new-privileges:true",
        "--mount",
        `type=bind,source=${root},target=/recovery`,
        "--entrypoint",
        "chown",
        image,
        "-R",
        `${String(hostOwner.uid)}:${String(hostOwner.gid)}`,
        "/recovery"
      ]);
      expect(returned.code, returned.stderr).toBe(0);
      await rm(root, { recursive: true, force: true });
      await rm(configurationRoot, { recursive: true, force: true });
    }
  }, 300_000);
});
