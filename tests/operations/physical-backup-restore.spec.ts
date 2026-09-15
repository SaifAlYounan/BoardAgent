import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { signCheckpoint } from "../../lib/audit/src/index.js";
import {
  appendAuditEventsInTransaction,
  commitAuditCheckpointInTransaction,
  migrate,
  prepareAuditCheckpointInTransaction,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { DEFAULT_RELEASE_IMAGE } from "../../scripts/src/build-release-image.js";
import {
  command,
  databaseConnection,
  withIsolatedRecoveryDatabase
} from "../helpers/physical-recovery.js";
import { testId } from "../helpers/authorized-actor.js";
import { administrativeHistory } from "../helpers/administrative-history.js";
import {
  freshAdministrativeTestCredential,
  stageAdministrativeAction
} from "../helpers/administrative-service.js";
import { provisionDatabasePrincipals } from "../../scripts/src/database-principals.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const IMAGE = process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE;

async function relationCount(pool: Pool): Promise<string> {
  const result = await pool.query<{ count: string }>(
    `select count(*)::text as count
       from pg_class as class
       join pg_namespace as namespace on namespace.oid=class.relnamespace
      where namespace.nspname='public' and class.relkind in ('r','p','v','m','S')`
  );
  return result.rows[0]?.count ?? "missing";
}

describe("T9 encrypted physical PostgreSQL backup and restore-check", () => {
  it("dumps one exported snapshot, restores an empty database, verifies every invariant, and rejects ciphertext tamper", async () => {
    await withIsolatedRecoveryDatabase(async (baseUrl, route) => {
      const databaseUrl = (
        database: string,
        container: false | { readonly hostname: string; readonly port: string }
      ) => databaseConnection(baseUrl, database, container);
      const suffix = `${String(process.pid)}_${randomBytes(4).toString("hex")}`;
      const sourceDatabase = `boardagent_backup_physical_${suffix}`;
      const restoredDatabase = `boardagent_restore_physical_${suffix}`;
      const corruptDatabase = `boardagent_restore_tamper_${suffix}`;
      const volume = `boardagent-recovery-${suffix.replaceAll("_", "-")}`;
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-ops-"));
      const envPath = path.join(directory, "recovery.env");
      const corruptEnvPath = path.join(directory, "recovery-corrupt.env");
      const adminUrl = new URL(baseUrl);
      adminUrl.pathname = "/postgres";
      const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
      let source: Pool | undefined;
      let restored: Pool | undefined;
      let corrupt: Pool | undefined;
      try {
        await admin.query(`create database "${sourceDatabase}"`);
        await admin.query(`create database "${restoredDatabase}"`);
        await admin.query(`create database "${corruptDatabase}"`);
        source = new Pool({ connectionString: databaseUrl(sourceDatabase, false), max: 6 });
        await migrate(source, MIGRATIONS, "physical-backup-restore-test");
        const principalFiles = {
          migrator: path.join(directory, "migrator.password"),
          server: path.join(directory, "server.password"),
          worker: path.join(directory, "worker.password"),
          backup: path.join(directory, "backup.password")
        };
        const principalPasswords = {
          migrator: randomBytes(32).toString("base64url"),
          server: randomBytes(32).toString("base64url"),
          worker: randomBytes(32).toString("base64url"),
          backup: randomBytes(32).toString("base64url")
        };
        for (const purpose of ["migrator", "server", "worker", "backup"] as const)
          await writeFile(principalFiles[purpose], principalPasswords[purpose], { mode: 0o600 });
        await provisionDatabasePrincipals(source, principalFiles);
        const principalUrl = (database: string, user: string) => {
          const url = new URL(databaseUrl(database, route));
          url.username = user;
          url.password = "";
          return url.toString();
        };
        const history = await administrativeHistory(source);
        const actor = history.issuer;
        const recipient = await freshAdministrativeTestCredential(source, history.target, 95_000);
        expect(
          (
            await (
              await stageAdministrativeAction(source, recipient, "manage_company_admin", {
                schema_version: "boardagent.tool-input.v1",
                idempotency_key: "restored-admin-acceptance-0001",
                change: {
                  operation: "accept",
                  proposal_id: testId(94_100),
                  expected_proposal_version: 1,
                  reason: "Accept the administrator appointment before its later revocation"
                }
              })
            ).confirm()
          ).confirmed
        ).toBe(true);
        const activeAdmin = await freshAdministrativeTestCredential(source, history.target, 95_010);
        expect(
          (
            await (
              await stageAdministrativeAction(source, actor, "manage_company_admin", {
                schema_version: "boardagent.tool-input.v1",
                idempotency_key: "restored-admin-revocation-0001",
                change: {
                  operation: "revoke",
                  assignment_id: testId(94_100),
                  member_id: history.target.memberId,
                  expected_member_version: 4,
                  reason: "Retain this ended administrator appointment in the backup"
                }
              })
            ).confirm()
          ).confirmed
        ).toBe(true);
        const retainedTables = [
          "organization_role_assignments",
          "company_admin_proposals",
          "member_admin_delegations",
          "administrative_authority_changes",
          "members",
          "board_memberships",
          "membership_versions",
          "consent_records",
          "access_token_records",
          "auth_sessions",
          "refresh_families",
          "oauth_authorization_codes"
        ];
        const oauthKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
        await source.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
          oauthKey.publicKey.export({ format: "jwk" }),
          testId(8)
        ]);
        const evidenceKey = generateKeyPairSync("ed25519");
        const evidenceKeyId = testId(91_000);
        const backupKeyId = testId(91_001);
        await source.query(
          `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
         ) values
           ($1,$2,'physical-evidence-1','evidence_signing','EdDSA',$3,
             'operator-evidence-test',transaction_timestamp()-interval '1 minute')`,
          [evidenceKeyId, actor.organizationId, evidenceKey.publicKey.export({ format: "jwk" })]
        );
        await withRequestTransaction(
          source,
          actor.context,
          (client) =>
            appendAuditEventsInTransaction(client, [
              {
                organizationId: actor.organizationId,
                event: {
                  eventId: testId(91_010),
                  eventType: "context_read",
                  actorMemberId: actor.memberId,
                  actorClientId: actor.clientId,
                  tokenJti: actor.tokenJti,
                  entityType: "context",
                  entityId: testId(91_011),
                  boardId: actor.boardId,
                  origin: "mcp",
                  details: { purpose: "physical-backup-restore-fixture" },
                  schemaVersion: 1
                }
              }
            ]),
          { assumeRole: "boardagent_server" }
        );
        const checkpoint = await withWorkerTransaction(
          source,
          (client) =>
            prepareAuditCheckpointInTransaction(client, {
              checkpointId: testId(91_020),
              signingKeyId: evidenceKeyId
            }),
          { assumeRole: "boardagent_worker" }
        );
        await withWorkerTransaction(
          source,
          (client) =>
            commitAuditCheckpointInTransaction(client, {
              checkpoint: signCheckpoint(checkpoint.payload, evidenceKey.privateKey),
              auditEventId: testId(91_021)
            }),
          { assumeRole: "boardagent_worker" }
        );

        const imageInspection = await command("docker", [
          "image",
          "inspect",
          "--format",
          "{{.Id}}",
          IMAGE
        ]);
        expect(imageInspection.code, imageInspection.stderr).toBe(0);
        const imageDigest = imageInspection.stdout.trim();
        expect(imageDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
        const createdVolume = await command("docker", ["volume", "create", volume]);
        expect(createdVolume.code, createdVolume.stderr).toBe(0);
        const initialized = await command("docker", [
          "run",
          "--rm",
          "--user",
          "0:0",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "/bin/sh",
          IMAGE,
          "-c",
          "chown 10001:10001 /recovery && chmod 700 /recovery"
        ]);
        expect(initialized.code, initialized.stderr).toBe(0);
        const keyCreated = await command("docker", [
          "run",
          "--rm",
          "-e",
          `TEST_PASSWORD_MIGRATOR=${principalPasswords.migrator}`,
          "-e",
          `TEST_PASSWORD_BACKUP=${principalPasswords.backup}`,
          "-e",
          `TEST_PASSWORD_WORKER=${principalPasswords.worker}`,
          "-e",
          `TEST_PASSWORD_RESTORE=${decodeURIComponent(new URL(baseUrl).password)}`,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "const fs=require('node:fs');fs.writeFileSync('/recovery/backup.key',Buffer.alloc(32,109),{mode:0o600});for(const [name,env] of [['migrator','MIGRATOR'],['backup','BACKUP'],['worker','WORKER'],['restore','RESTORE']])fs.writeFileSync('/recovery/'+name+'.password',process.env['TEST_PASSWORD_'+env],{mode:0o600});"
        ]);
        expect(keyCreated.code, keyCreated.stderr).toBe(0);

        const envLines = (target: string): string =>
          [
            "BOARDAGENT_ENV=production",
            `BOARDAGENT_DATABASE_URL=${principalUrl(sourceDatabase, "boardagent_migrator_login")}`,
            "BOARDAGENT_DATABASE_PASSWORD_FILE=/recovery/migrator.password",
            `BOARDAGENT_BACKUP_DATABASE_URL=${principalUrl(sourceDatabase, "boardagent_backup_login")}`,
            "BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE=/recovery/backup.password",
            `BOARDAGENT_RECEIPT_DATABASE_URL=${principalUrl(sourceDatabase, "boardagent_worker_login")}`,
            "BOARDAGENT_RECEIPT_DATABASE_PASSWORD_FILE=/recovery/worker.password",
            `BOARDAGENT_ORGANIZATION_ID=${actor.organizationId}`,
            `BOARDAGENT_BACKUP_KEY_ID=${backupKeyId}`,
            "BOARDAGENT_BACKUP_KEK_FILE=/recovery/backup.key",
            "BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY=/recovery",
            `BOARDAGENT_SOURCE_IMAGE_DIGEST=${imageDigest}`,
            `BOARDAGENT_RESTORE_DATABASE_URL=${principalUrl(target, "boardagent")}`,
            "BOARDAGENT_RESTORE_DATABASE_PASSWORD_FILE=/recovery/restore.password"
          ].join("\n") + "\n";
        await writeFile(envPath, envLines(restoredDatabase), { mode: 0o600 });
        await writeFile(corruptEnvPath, envLines(corruptDatabase), { mode: 0o600 });

        const registered = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          envPath,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "register-backup-key"
        ]);
        expect(registered.code, registered.stderr).toBe(0);
        expect(JSON.parse(registered.stdout)).toMatchObject({
          status: "succeeded",
          keyRegistration: { keyId: backupKeyId, purpose: "backup_kek", replayed: false }
        });
        const refusedDirectory = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "require('node:fs').mkdirSync('/recovery/refused-backup',{mode:0o700})"
        ]);
        expect(refusedDirectory.code, refusedDirectory.stderr).toBe(0);
        const wrongIdBackup = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          envPath,
          "-e",
          `BOARDAGENT_BACKUP_KEY_ID=${testId(91_099)}`,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "backup",
          "/recovery/refused-backup"
        ]);
        expect(wrongIdBackup.code, "right key under an unregistered ID must fail").not.toBe(0);
        const afterWrongId = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "process.stdout.write(JSON.stringify(require('node:fs').readdirSync('/recovery/refused-backup')))"
        ]);
        expect(afterWrongId.code, afterWrongId.stderr).toBe(0);
        expect(JSON.parse(afterWrongId.stdout)).toEqual([]);

        const authorityBeforeBackup = new Map<string, unknown>();
        for (const table of retainedTables)
          authorityBeforeBackup.set(
            table,
            (await source.query(`select to_jsonb(r) as record from ${table} r order by id`)).rows
          );
        const auditBeforeBackup = (
          await source.query(
            "select id,encode(sha256(canonical_payload),'hex') as digest from audit_events order by sequence"
          )
        ).rows;

        const wrongKeyFixture = await command("docker", [
          "run",
          "--rm",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "const fs=require('node:fs');fs.writeFileSync('/recovery/backup.key',Buffer.alloc(32,110));"
        ]);
        expect(wrongKeyFixture.code, wrongKeyFixture.stderr).toBe(0);
        const wrongKeyBackup = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          envPath,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "backup",
          "/recovery/refused-backup"
        ]);
        expect(
          wrongKeyBackup.code,
          "wrong key bytes must fail before publishing a backup"
        ).not.toBe(0);
        const refusedFiles = await command("docker", [
          "run",
          "--rm",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "const fs=require('node:fs');process.stdout.write(JSON.stringify(fs.readdirSync('/recovery/refused-backup')));fs.writeFileSync('/recovery/backup.key',Buffer.alloc(32,109));"
        ]);
        expect(refusedFiles.code, refusedFiles.stderr).toBe(0);
        expect(JSON.parse(refusedFiles.stdout)).toEqual([]);

        const unrecordedBackup = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          envPath,
          "-e",
          "BOARDAGENT_RECEIPT_DATABASE_PASSWORD_FILE=/recovery/backup.password",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "backup",
          "/recovery/refused-backup"
        ]);
        expect(unrecordedBackup.code).toBe(1);
        const unrecordedFiles = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          "process.stdout.write(JSON.stringify(require('node:fs').readdirSync('/recovery/refused-backup')))"
        ]);
        expect(unrecordedFiles.code, unrecordedFiles.stderr).toBe(0);
        expect(JSON.parse(unrecordedFiles.stdout)).toHaveLength(2);
        expect(JSON.parse(unrecordedBackup.stdout)).toMatchObject({
          command: "backup",
          status: "published_recording_unconfirmed",
          stage: "receipt_recording",
          receiptId: expect.any(String),
          manifestFile: expect.stringContaining(".manifest.json")
        });

        const backup = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          envPath,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "backup",
          "/recovery"
        ]);
        expect(backup.code, backup.stderr).toBe(0);
        const backupReceipt = JSON.parse(backup.stdout) as Record<string, unknown>;
        expect(backupReceipt).toMatchObject({
          schemaVersion: "boardagent.operator-backup.v1",
          command: "backup",
          status: "succeeded",
          sourceImageDigest: imageDigest,
          replayed: false
        });
        expect(backupReceipt["artifactSha256"]).toMatch(/^[0-9a-f]{64}$/u);
        expect(backupReceipt["manifestSha256"]).toMatch(/^[0-9a-f]{64}$/u);
        const manifestFile = String(backupReceipt["manifestFile"]);
        expect(manifestFile).toMatch(/^\/recovery\/boardagent-.*\.manifest\.json$/u);

        const alteredManifest = await command("docker", [
          "run",
          "--rm",
          "--network",
          "none",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          `const fs=require('node:fs'),m=JSON.parse(fs.readFileSync(${JSON.stringify(manifestFile)},'utf8'));m.encryptionKeyFingerprintSha256='a'.repeat(64);fs.writeFileSync('/recovery/wrong-fingerprint.manifest.json',JSON.stringify(m),{mode:0o600});`
        ]);
        expect(alteredManifest.code, alteredManifest.stderr).toBe(0);
        const wrongFingerprintRestore = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          envPath,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "restore-check",
          "/recovery/wrong-fingerprint.manifest.json"
        ]);
        expect(wrongFingerprintRestore.code).toBe(1);
        const untouchedTarget = new Pool({
          connectionString: databaseUrl(restoredDatabase, false),
          max: 1
        });
        try {
          expect(await relationCount(untouchedTarget)).toBe("0");
        } finally {
          await untouchedTarget.end();
        }

        const restore = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          envPath,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "restore-check",
          manifestFile
        ]);
        expect(restore.code, restore.stderr).toBe(0);
        expect(JSON.parse(restore.stdout)).toMatchObject({
          schemaVersion: "boardagent.operator-restore-check.v1",
          command: "restore-check",
          status: "succeeded",
          ready: true,
          sourceBackupReceiptId: backupReceipt["receiptId"],
          restoredDatabase,
          replayed: false
        });

        restored = new Pool({ connectionString: databaseUrl(restoredDatabase, false), max: 2 });
        expect(await relationCount(restored)).not.toBe("0");
        expect(
          (
            await restored.query(
              "select state,row_version::text from member_admin_delegations where id=$1",
              [history.input.change.delegation_id]
            )
          ).rows
        ).toEqual([{ state: "revoked", row_version: "2" }]);
        expect(
          (await restored.query("select count(*)::int as n from company_admin_proposals")).rows[0]
            ?.n
        ).toBe(2);
        expect(
          (await restored.query("select count(*)::int as n from administrative_authority_changes"))
            .rows[0]?.n
        ).toBe(6);
        for (const table of retainedTables) {
          const restoredRows = await restored.query(
            `select to_jsonb(r) as record from ${table} r order by id`
          );
          expect(restoredRows.rows).toEqual(authorityBeforeBackup.get(table));
        }
        expect(
          (
            await restored.query(
              "select id,encode(sha256(canonical_payload),'hex') as digest from audit_events where id=any($1::uuid[]) order by sequence",
              [auditBeforeBackup.map((row) => row.id)]
            )
          ).rows
        ).toEqual(auditBeforeBackup);
        expect(
          (
            await restored.query(
              "select active_until is not null as ended from organization_role_assignments where id=$1",
              [testId(94_100)]
            )
          ).rows[0]
        ).toEqual({ ended: true });
        expect(
          (
            await restored.query(
              "select revoked_at is not null as revoked from access_token_records where id=$1",
              [activeAdmin.accessTokenRecordId]
            )
          ).rows[0]
        ).toEqual({ revoked: true });
        await expect(
          stageAdministrativeAction(restored, activeAdmin, "manage_company_admin", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "restored-revoked-admin-attempt-0001",
            change: {
              operation: "grant",
              proposal_id: testId(95_100),
              member_id: history.other.memberId,
              expected_member_version: 1,
              reason: "An old restored credential must not recover ended authority"
            }
          })
        ).rejects.toThrow("synthetic actor has no live token");
        const reconnected = await freshAdministrativeTestCredential(
          restored,
          history.target,
          95_020
        );
        await expect(
          stageAdministrativeAction(restored, reconnected, "manage_member", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "restored-ended-delegation-attempt-0001",
            authority_evidence: history.input.change.authority_evidence,
            change: {
              operation: "suspend",
              member_id: history.other.memberId,
              board_id: actor.boardId,
              reason: "A new connection must not revive ended delegation"
            }
          })
        ).rejects.toMatchObject({ code: "42501" });
        expect(
          (await restored.query("select count(*)::int as n from administrative_authority_changes"))
            .rows[0]
        ).toEqual({ n: 6 });
        expect(await restored.query("select display_name from organizations")).toMatchObject({
          rows: [{ display_name: "Org" }]
        });
        expect(
          await source.query(
            "select receipt_kind,state,count(*)::integer as count from backup_receipts group by receipt_kind,state order by receipt_kind"
          )
        ).toMatchObject({
          rows: [
            { receipt_kind: "backup", state: "created", count: 1 },
            { receipt_kind: "restore", state: "verified", count: 1 }
          ]
        });

        const artifactFile = String(backupReceipt["artifactFile"]);
        const tampered = await command("docker", [
          "run",
          "--rm",
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "-e",
          `const fs=require('node:fs');const p=${JSON.stringify(artifactFile)};const f=fs.openSync(p,'r+');const s=fs.fstatSync(f).size;const b=Buffer.alloc(1);fs.readSync(f,b,0,1,Math.floor(s/2));b[0]^=1;fs.writeSync(f,b,0,1,Math.floor(s/2));fs.fsyncSync(f);fs.closeSync(f);`
        ]);
        expect(tampered.code, tampered.stderr).toBe(0);
        const refused = await command("docker", [
          "run",
          "--rm",
          "--network",
          route.network,
          "--env-file",
          corruptEnvPath,
          "--mount",
          `type=volume,source=${volume},target=/recovery`,
          "--mount",
          `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
          "--entrypoint",
          "node",
          IMAGE,
          "scripts/dist/operator.js",
          "restore-check",
          manifestFile
        ]);
        expect(refused.code).toBe(1);
        expect(refused.stderr).toContain('"reasonCode":"validation_or_operation_failed"');
        expect(refused.stderr).toContain('"stage":"restore-check"');
        expect(`${refused.stdout}${refused.stderr}`).not.toContain("boardagent-local-only");
        corrupt = new Pool({ connectionString: databaseUrl(corruptDatabase, false), max: 1 });
        expect(await relationCount(corrupt)).toBe("0");
      } finally {
        await source?.end().catch(() => undefined);
        await restored?.end().catch(() => undefined);
        await corrupt?.end().catch(() => undefined);
        await admin.query(`drop database if exists "${corruptDatabase}" with (force)`);
        await admin.query(`drop database if exists "${restoredDatabase}" with (force)`);
        await admin.query(`drop database if exists "${sourceDatabase}" with (force)`);
        await admin.end();
        await command("docker", ["volume", "rm", "--force", volume]);
        await rm(directory, { recursive: true, force: true });
      }
    });
  }, 300_000);
});
