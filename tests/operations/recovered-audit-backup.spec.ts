import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { signCheckpoint } from "../../lib/audit/src/index.js";
import {
  migrate,
  withBootstrapTransaction,
  prepareKeyLifecycleInTransaction,
  applyKeyLifecycleInTransaction,
  withWorkerTransaction,
  prepareAuditCheckpointInTransaction,
  commitAuditCheckpointInTransaction
} from "../../lib/db/src/index.js";
import { DEFAULT_RELEASE_IMAGE } from "../../scripts/src/build-release-image.js";
import { provisionDatabasePrincipals } from "../../scripts/src/database-principals.js";
import { seedRecoveredAudit } from "../helpers/recovered-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  command,
  databaseConnection,
  withIsolatedRecoveryDatabase
} from "../helpers/physical-recovery.js";

const IMAGE = process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE;
const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");

describe("encrypted PostgreSQL backup/restore after a signing recovery", () => {
  it("restores old and new encrypted database generations after key replacement with permanent findings intact", async () => {
    await withIsolatedRecoveryDatabase(async (baseUrl, route) => {
      const suffix = `${String(process.pid)}_${randomBytes(4).toString("hex")}`;
      const sourceName = `boardagent_recovered_source_${suffix}`,
        restoredName = `boardagent_recovered_restore_${suffix}`;
      const retainedRestoreName = `boardagent_retained_restore_${suffix}`,
        nextRestoreName = `boardagent_next_restore_${suffix}`;
      const extraPools: Pool[] = [];
      const volume = `boardagent-recovered-backup-${suffix.replaceAll("_", "-")}`;
      const writerName = `${volume}-wal`;
      let writerCreated = false;
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovered-backup-"));
      const admin = new Pool({
        connectionString: databaseConnection(baseUrl, "postgres", false),
        max: 1
      });
      let source: Pool | undefined,
        restored: Pool | undefined,
        volumeCreated = false;
      try {
        await admin.query(`create database "${sourceName}"`);
        await admin.query(`create database "${restoredName}"`);
        await admin.query(`create database "${retainedRestoreName}"`);
        await admin.query(`create database "${nextRestoreName}"`);
        source = new Pool({
          connectionString: databaseConnection(baseUrl, sourceName, false),
          max: 4
        });
        await migrate(source, MIGRATIONS, "recovered-backup-operations");
        const fixture = await seedRecoveredAudit(source);
        const principalFiles = {
          migrator: path.join(directory, "migrator.password"),
          server: path.join(directory, "server.password"),
          worker: path.join(directory, "worker.password"),
          backup: path.join(directory, "backup.password")
        };
        for (const file of Object.values(principalFiles))
          await writeFile(file, randomBytes(32).toString("base64url"), { mode: 0o600 });
        await provisionDatabasePrincipals(source, principalFiles);
        await writeFile(
          path.join(directory, "restore.password"),
          decodeURIComponent(new URL(baseUrl).password),
          { mode: 0o600 }
        );
        await writeFile(path.join(directory, "backup.key"), Buffer.alloc(32, 119), { mode: 0o600 });
        const image = await command("docker", ["image", "inspect", "--format", "{{.Id}}", IMAGE]);
        expect(image.code, image.stderr).toBe(0);
        const imageDigest = image.stdout.trim();
        expect(imageDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
        const made = await command("docker", ["volume", "create", volume]);
        expect(made.code, made.stderr).toBe(0);
        volumeCreated = true;
        const seeded = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--read-only",
          "--user",
          "0:0",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--mount",
          `type=bind,source=${directory},target=/input,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "const fs=require('node:fs');fs.chownSync('/recovery',10001,10001);fs.chmodSync('/recovery',0o700);for(const name of ['migrator.password','worker.password','backup.password','restore.password','backup.key']){fs.copyFileSync('/input/'+name,'/recovery/'+name);fs.chownSync('/recovery/'+name,10001,10001);fs.chmodSync('/recovery/'+name,0o400);}"
        ]);
        expect(seeded.code, seeded.stderr).toBe(0);
        const principal = (database: string, username: string) => {
          const url = new URL(databaseConnection(baseUrl, database, route));
          url.username = username;
          url.password = "";
          return url.toString();
        };
        const envFile = path.join(directory, "operator.env");
        await writeFile(
          envFile,
          [
            "BOARDAGENT_ENV=production",
            `BOARDAGENT_INSTANCE_ID=${testId(15)}`,
            `BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE=/recovery/${testId(117_000)}.json`,
            `BOARDAGENT_DATABASE_URL=${principal(sourceName, "boardagent_migrator_login")}`,
            "BOARDAGENT_DATABASE_PASSWORD_FILE=/recovery/migrator.password",
            `BOARDAGENT_BACKUP_DATABASE_URL=${principal(sourceName, "boardagent_backup_login")}`,
            "BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE=/recovery/backup.password",
            `BOARDAGENT_RECEIPT_DATABASE_URL=${principal(sourceName, "boardagent_worker_login")}`,
            "BOARDAGENT_RECEIPT_DATABASE_PASSWORD_FILE=/recovery/worker.password",
            `BOARDAGENT_RESTORE_DATABASE_URL=${principal(restoredName, "boardagent")}`,
            "BOARDAGENT_RESTORE_DATABASE_PASSWORD_FILE=/recovery/restore.password",
            `BOARDAGENT_ORGANIZATION_ID=${fixture.actor.organizationId}`,
            `BOARDAGENT_BACKUP_KEY_ID=${testId(117_000)}`,
            "BOARDAGENT_BACKUP_KEK_FILE=/recovery/backup.key",
            "BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY=/recovery",
            `BOARDAGENT_SOURCE_IMAGE_DIGEST=${imageDigest}`
          ].join("\n") + "\n",
          { mode: 0o600 }
        );
        const operatorArgs = (args: string[]) => [
          "run",
          "--rm",
          "--read-only",
          "--network",
          route.network,
          "--env-file",
          envFile,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          ...args
        ];
        const operator = (args: string[], overrides: Record<string, string> = {}) => {
          const invocation = operatorArgs(args);
          invocation.splice(
            1,
            0,
            ...Object.entries(overrides).flatMap(([key, value]) => ["--env", `${key}=${value}`])
          );
          return command("docker", invocation);
        };
        const readRecord = async (filename: string) => {
          const result = await command("docker", [
            "run",
            "--rm",
            "--read-only",
            "--network",
            "none",
            "--mount",
            `type=volume,source=${volume},target=/recovery,readonly`,
            "--entrypoint",
            "node",
            IMAGE,
            "-e",
            "process.stdout.write(require('node:fs').readFileSync(process.argv[1],'utf8'))",
            filename
          ]);
          expect(result.code, result.stderr).toBe(0);
          return JSON.parse(result.stdout);
        };
        const registered = await operator(["register-backup-key"]);
        expect(registered.code, registered.stderr).toBe(0);
        const before = (
          await source.query(
            "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
          )
        ).rows;
        const backup = await operator(["backup", "/recovery"]);
        expect(backup.code, backup.stderr).toBe(0);
        const backupOutput = JSON.parse(backup.stdout),
          manifest = await readRecord(backupOutput.manifestFile);
        const warning = `recovery:${fixture.receipt.recoveryId}:historical_checkpoint_deadline_missed`;
        expect(manifest).toMatchObject({
          schemaVersion: "boardagent.backup-receipt.v2",
          auditRecoveryEvidence: [
            {
              payload: { recovery: { requestSha256: fixture.proposal.requestSha256 } }
            }
          ]
        });
        expect(backupOutput).toMatchObject({
          schemaVersion: "boardagent.operator-backup.v2",
          warnings: [warning]
        });
        const restore = await operator(["restore-check", backupOutput.manifestFile]);
        expect(restore.code, restore.stderr).toBe(0);
        const restoreOutput = JSON.parse(restore.stdout),
          restoreManifest = await readRecord(restoreOutput.restoreReceiptFile);
        expect(restoreOutput).toMatchObject({
          schemaVersion: "boardagent.operator-restore-check.v2",
          ready: true,
          warnings: [warning],
          pgRestoreVersion: expect.stringContaining("18.6")
        });
        expect(restoreManifest).toMatchObject({
          schemaVersion: "boardagent.restore-receipt.v2",
          auditRecoveryEvidence: manifest.auditRecoveryEvidence
        });
        restored = new Pool({
          connectionString: databaseConnection(baseUrl, restoredName, false),
          max: 2
        });
        expect(
          (
            await restored.query(
              "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
            )
          ).rows
        ).toEqual(before);
        const receipts = (
          await source.query(
            "select receipt_kind,schema_version from backup_receipts order by created_at,id"
          )
        ).rows;
        expect(receipts).toEqual([
          { receipt_kind: "backup", schema_version: "boardagent.backup-receipt.v2" },
          { receipt_kind: "restore", schema_version: "boardagent.restore-receipt.v2" }
        ]);

        // This is a real production WAL process, using the same root-owned inode as maintenance.
        const paths = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "const f=require('node:fs');for(const p of ['/recovery/staging','/recovery/wal'])f.mkdirSync(p,{mode:0o700});"
        ]);
        expect(paths.code, paths.stderr).toBe(0);
        const continuousArgs = operatorArgs(["archive-wal", "/recovery/staging", "/recovery/wal"]);
        continuousArgs.splice(
          1,
          1,
          "-d",
          "--name",
          writerName,
          "--tmpfs",
          "/tmp:size=16m,mode=1777"
        );
        const started = await command("docker", continuousArgs);
        expect(started.code, started.stderr).toBe(0);
        writerCreated = true;
        const deadline = Date.now() + 15_000;
        let healthy = false;
        while (Date.now() < deadline && !healthy) {
          const health = await command("docker", [
            "exec",
            writerName,
            "node",
            "-e",
            "const s=JSON.parse(require('node:fs').readFileSync('/tmp/boardagent-wal-status.json'));process.exit(s.status==='healthy'?0:1)"
          ]);
          healthy = health.code === 0;
          if (!healthy) await new Promise((resolve) => setTimeout(resolve, 100));
        }
        expect(healthy, "production WAL writer did not become healthy").toBe(true);
        const disconnected = await command("docker", [
          "network",
          "disconnect",
          route.network,
          writerName
        ]);
        expect(disconnected.code, disconnected.stderr).toBe(0);
        // Network/database loss cannot release the process's kernel lease.
        const blocked = await operator([
          "key-lifecycle",
          "apply",
          "/recovery/no-request.json",
          "0".repeat(64),
          "/recovery/no-receipt.json"
        ]);
        expect(blocked.code).toBe(1);
        expect(JSON.parse(blocked.stdout)).toMatchObject({
          status: "refused",
          stage: "maintenance_exclusion",
          reasonCode: "maintenance_lock_busy"
        });
        const stopped = await command("docker", ["stop", "--time", "10", writerName]);
        expect(stopped.code, stopped.stderr).toBe(0);
        const stoppedInspection = await command("docker", [
          "inspect",
          "--format",
          "{{.State.ExitCode}}",
          writerName
        ]);
        expect(stoppedInspection.stdout.trim()).toBe("0");
        const nextKeyId = testId(117_020);
        const nextMaterial = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "const f=require('node:fs'),c=require('node:crypto'),b=c.randomBytes(32);f.writeFileSync('/recovery/backup-next.key',b,{mode:0o400,flag:'wx'});process.stdout.write(c.createHash('sha256').update(b).digest('hex'));b.fill(0);"
        ]);
        expect(nextMaterial.code, nextMaterial.stderr).toBe(0);
        expect(nextMaterial.stdout).toMatch(/^[0-9a-f]{64}$/u);
        const proposal = await withBootstrapTransaction(
          source,
          (c) =>
            prepareKeyLifecycleInTransaction(c, {
              instanceId: testId(15),
              organizationId: fixture.actor.organizationId,
              keyId: testId(117_000),
              operationId: testId(117_010),
              operation: "replace",
              replacement: {
                keyId: nextKeyId,
                kid: `backup-${nextKeyId}`,
                algorithm: "A256GCM",
                publicJwk: null,
                materialSha256: nextMaterial.stdout,
                nonsecretLocator: `sha256:${nextMaterial.stdout}`
              },
              declaredCompromisedAt: null,
              retainedMaterialSha256: canonicalSha256(manifest),
              operatorReference: "synthetic WAL key test",
              reason: "Verify production startup refuses a retired backup key"
            }),
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
        await withBootstrapTransaction(source, (c) => applyKeyLifecycleInTransaction(c, proposal), {
          assumeRole: "boardagent_migrator"
        });
        const staleReceipt = await operator(["check-backup-key"]);
        expect(staleReceipt.code, staleReceipt.stderr).toBe(0);
        const refused = await operator(["archive-wal-once", "/recovery/staging", "/recovery/wal"]);
        expect(refused.code).toBe(1);
        expect(JSON.parse(refused.stdout)).toMatchObject({
          status: "refused",
          command: "archive-wal-once",
          stage: "key_registration",
          reasonCode: "backup_key_registry_check_failed"
        });
        const remaining = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--mount",
          `type=volume,source=${volume},target=/recovery,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "process.stdout.write(JSON.stringify(require('node:fs').readdirSync('/recovery/wal')))"
        ]);
        expect(remaining.code, remaining.stderr).toBe(0);
        expect(JSON.parse(remaining.stdout)).toEqual([]);
        await withWorkerTransaction(
          source,
          async (client) => {
            const prepared = await prepareAuditCheckpointInTransaction(client, {
              checkpointId: testId(117_021),
              signingKeyId: fixture.keyId
            });
            return commitAuditCheckpointInTransaction(client, {
              checkpoint: signCheckpoint(prepared.payload, fixture.evidence.privateKey),
              auditEventId: testId(117_022)
            });
          },
          { assumeRole: "boardagent_worker" }
        );
        const nextEnvironment = {
          BOARDAGENT_BACKUP_KEY_ID: nextKeyId,
          BOARDAGENT_BACKUP_KEK_FILE: "/recovery/backup-next.key",
          BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE: `/recovery/${nextKeyId}.json`
        };
        const nextRegistered = await operator(["register-backup-key"], nextEnvironment);
        expect(nextRegistered.code, nextRegistered.stdout + nextRegistered.stderr).toBe(0);
        const nextAudit = (
          await source.query(
            "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
          )
        ).rows;
        const nextBackup = await operator(["backup", "/recovery"], nextEnvironment);
        expect(nextBackup.code, nextBackup.stdout + nextBackup.stderr).toBe(0);
        const nextBackupOutput = JSON.parse(nextBackup.stdout);
        expect(await readRecord(nextBackupOutput.manifestFile)).toMatchObject({
          encryptionKeyId: nextKeyId
        });
        for (const selected of [
          {
            manifestFile: backupOutput.manifestFile as string,
            database: retainedRestoreName,
            environment: {},
            rows: before
          },
          {
            manifestFile: nextBackupOutput.manifestFile as string,
            database: nextRestoreName,
            environment: nextEnvironment,
            rows: nextAudit
          }
        ]) {
          const restoredGeneration = await operator(["restore-check", selected.manifestFile], {
            ...selected.environment,
            BOARDAGENT_RESTORE_DATABASE_URL: principal(selected.database, "boardagent")
          });
          expect(
            restoredGeneration.code,
            restoredGeneration.stdout + restoredGeneration.stderr
          ).toBe(0);
          const output = JSON.parse(restoredGeneration.stdout);
          expect(output.ready).toBe(true);
          expect(output.warnings).toContain(warning);
          const checked = new Pool({
            connectionString: databaseConnection(baseUrl, selected.database, false),
            max: 1
          });
          extraPools.push(checked);
          expect(
            (
              await checked.query(
                "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
              )
            ).rows
          ).toEqual(selected.rows);
        }
        expect(await readRecord(backupOutput.manifestFile)).toEqual(manifest);
      } finally {
        if (writerCreated) {
          const removedWriter = await command("docker", ["rm", "-f", writerName]);
          expect(removedWriter.code, removedWriter.stderr).toBe(0);
        }
        await Promise.all([
          source?.end(),
          restored?.end(),
          ...extraPools.map((p) => p.end()),
          admin.end()
        ]);
        if (volumeCreated) {
          const removed = await command("docker", ["volume", "rm", volume]);
          expect(removed.code, removed.stderr).toBe(0);
        }
        await rm(directory, { recursive: true, force: true });
      }
    });
  }, 180_000);
});
