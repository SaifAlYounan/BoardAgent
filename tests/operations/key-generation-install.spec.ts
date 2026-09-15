import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  migrate,
  withWorkerTransaction,
  prepareAuditCheckpointInTransaction,
  commitAuditCheckpointInTransaction,
  withBootstrapTransaction,
  registerRuntimeKeysInTransaction,
  registerBackupKeyInTransaction,
  prepareKeyLifecycleInTransaction,
  applyKeyLifecycleInTransaction
} from "../../lib/db/src/index.js";
import { loadBoardAgentKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { runtimeKeyRegistrations } from "../../artifacts/server/src/runtime-binding.js";
import {
  PgTotpService,
  PgRateLimiter,
  generateTotpCodeFromBase32
} from "../../artifacts/server/src/index.js";
import { generateOperatorKeyFile } from "../../scripts/src/operator-key-files.js";
import { signCheckpoint } from "../../lib/audit/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { DEFAULT_RELEASE_IMAGE } from "../../scripts/src/build-release-image.js";
import { provisionDatabasePrincipals } from "../../scripts/src/database-principals.js";
import { productionKeyFiles } from "../helpers/production-key-files.js";
import { newWorkerTestId } from "../helpers/unseeded-worker.js";
import {
  command,
  databaseConnection,
  withIsolatedRecoveryDatabase
} from "../helpers/physical-recovery.js";

const IMAGE = process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE;

describe("production versioned key installation", () => {
  it.each([
    "oauth_signing",
    "evidence_signing",
    "browser_session",
    "data_kek",
    "backup_kek"
  ] as const)(
    "installs %s replacement, preserves old keys and starts isolated production roles",
    async (purpose) => {
      await withIsolatedRecoveryDatabase(async (url, route) => {
        const directory = await mkdtemp(
          path.join(await realpath(tmpdir()), "boardagent-key-generation-")
        );
        const suffix = `${process.pid}-${randomBytes(5).toString("hex")}`;
        const inputVolume = `boardagent-generation-input-${suffix}`;
        const outputVolume = `boardagent-generation-output-${suffix}`;
        const createdVolumes: string[] = [];
        const startedContainers: string[] = [];
        const pool = new Pool({ connectionString: url, max: 4 });
        try {
          await migrate(pool, path.resolve("lib/db/migrations"), "key-generation-test");
          const bootstrap = await new BoardAgentBootstrapOperator(pool, {
            assumeRole: "boardagent_migrator"
          }).initialize({
            organizationLegalName: "Synthetic Key Installation",
            organizationDisplayName: "Synthetic Key Installation",
            organizationSlug: "synthetic-key-installation",
            timezone: "UTC",
            canonicalResourceUri: "https://generation.boardagent.test/mcp",
            boardSlug: "main",
            boardName: "Synthetic Board",
            boardCanonicalPayload: { synthetic: true },
            firstSecretaryLegalName: "Unenrolled Synthetic Secretary",
            firstSecretaryDisplayName: "Unenrolled",
            votingWeight: 1,
            supportName: "Synthetic Operator",
            supportContactMethods: [{ kind: "operator_reference", value: "test" }],
            onboardingTermsText: "No human ceremony performed",
            invitationHandoffMethod: "not delivered"
          });
          if (bootstrap.status !== "created") throw new Error("fresh bootstrap required");
          const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
            .instance_id as string;
          const keys = await productionKeyFiles(directory, bootstrap.organizationId);
          const material = await loadBoardAgentKeyMaterial(parseConfig(keys.environment));
          const runtimeFiles = {
            oauth: "/run/boardagent-secrets/oauth.jwk",
            evidence: "/run/boardagent-secrets/evidence.pem",
            browserSession: "/run/boardagent-secrets/browser.key",
            dataEncryption: "/run/boardagent-secrets/data.key"
          };
          const registrations = runtimeKeyRegistrations(
            { ...parseConfig(keys.environment), keySources: runtimeFiles },
            material,
            newWorkerTestId
          );
          const backupId = newWorkerTestId(),
            backupBytes = randomBytes(32),
            replacementId = newWorkerTestId();
          const replacement = await generateOperatorKeyFile(
            purpose,
            path.join(directory, "replacement.key")
          );
          const replacementRelative = `versioned/${purpose}-next.key`;
          await writeFile(path.join(directory, "backup.key"), backupBytes, { mode: 0o600 });

          await withBootstrapTransaction(
            pool,
            async (c) => {
              await registerRuntimeKeysInTransaction(c, bootstrap.organizationId, registrations);
              await registerBackupKeyInTransaction(
                c,
                bootstrap.organizationId,
                backupId,
                createHash("sha256").update(backupBytes).digest("hex")
              );
            },
            { assumeRole: "boardagent_migrator" }
          );
          let factor:
            { memberId: string; secretBase32: string; fallbackHandle: string } | undefined;
          const originalDataId = registrations.find((k) => k.purpose === "data_kek")!.keyId;
          if (purpose === "data_kek") {
            const memberId = newWorkerTestId();
            await pool.query(
              "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Synthetic factor only','Synthetic factor','active')",
              [memberId, bootstrap.organizationId]
            );
            await pool.query(
              "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'secretariat','Synthetic factor test; no human activation')",
              [newWorkerTestId(), bootstrap.organizationId, memberId]
            );
            const policy = { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 };
            const service = new PgTotpService(pool, {
              issuer: "Synthetic generation test",
              activeKeyId: originalDataId,
              keys: new Map([[originalDataId, material.dataEncryptionKey]]),
              rateLimiter: new PgRateLimiter(pool, {
                hmacKey: material.browserSessionKey,
                assumeRole: "boardagent_server"
              }),
              rateLimits: { ip: policy, client: policy, member: policy, token: policy },
              maxFailedAttempts: 5,
              lockoutSeconds: 300,
              assumeRole: "boardagent_server"
            });
            const enrolled = await service.beginEnrollment({
              organizationId: bootstrap.organizationId,
              memberId,
              authorizedByMemberId: memberId
            });
            const now = Number(
              (await pool.query("select floor(extract(epoch from clock_timestamp())) as now"))
                .rows[0].now
            );
            await service.completeEnrollment({
              organizationId: bootstrap.organizationId,
              credentialId: enrolled.credentialId,
              authorizedByMemberId: memberId,
              code: generateTotpCodeFromBase32(enrolled.secretBase32, now)
            });
            factor = {
              memberId,
              secretBase32: enrolled.secretBase32,
              fallbackHandle: enrolled.fallbackHandle
            };
          }
          await withWorkerTransaction(
            pool,
            async (c) => {
              const staged = await prepareAuditCheckpointInTransaction(c, {
                checkpointId: newWorkerTestId(),
                signingKeyId: registrations.find((k) => k.purpose === "evidence_signing")!.keyId
              });
              await commitAuditCheckpointInTransaction(c, {
                checkpoint: signCheckpoint(staged.payload, material.evidencePrivateKey),
                auditEventId: newWorkerTestId()
              });
            },
            { assumeRole: "boardagent_worker" }
          );
          const proposal = await withBootstrapTransaction(
            pool,
            (c) =>
              prepareKeyLifecycleInTransaction(c, {
                instanceId,
                organizationId: bootstrap.organizationId,
                keyId:
                  purpose === "backup_kek"
                    ? backupId
                    : registrations.find((k) => k.purpose === purpose)!.keyId,
                operationId: newWorkerTestId(),
                operation: "replace",
                declaredCompromisedAt: null,
                replacement: {
                  keyId: replacementId,
                  kid: purpose === "backup_kek" ? `backup-${replacementId}` : replacement.kid!,
                  algorithm: replacement.algorithm,
                  publicJwk: replacement.publicJwk,
                  nonsecretLocator:
                    purpose === "backup_kek"
                      ? `sha256:${replacement.materialSha256}`
                      : `file:/run/boardagent-secrets/${replacementRelative}`,
                  materialSha256: replacement.materialSha256
                },
                retainedMaterialSha256: "a".repeat(64),
                operatorReference: "synthetic key installation",
                reason: "Verify actual protected generation installation"
              }),
            { assumeRole: "boardagent_migrator", readOnly: true }
          );
          const operation = await withBootstrapTransaction(
            pool,
            (c) => applyKeyLifecycleInTransaction(c, proposal),
            { assumeRole: "boardagent_migrator" }
          );
          const passwords = {
            migrator: path.join(directory, "migrator.password"),
            server: path.join(directory, "server.password"),
            worker: path.join(directory, "worker.password"),
            backup: path.join(directory, "backup.password")
          };
          for (const file of Object.values(passwords))
            await writeFile(file, randomBytes(32).toString("base64url"), { mode: 0o600 });
          await provisionDatabasePrincipals(pool, passwords);
          const purposeFiles = {
            oauth_signing: "oauth.jwk",
            evidence_signing: "evidence.pem",
            data_kek: "data.key",
            browser_session: "browser.key"
          };
          const plan = {
            schemaVersion: "boardagent.key-generation-plan.v1",
            operationId: operation.operationId,
            requestSha256: operation.requestSha256,
            generationRoot: "/generations/one",
            keyFiles: [
              ...registrations.map((k) => ({
                keyId: k.purpose === purpose ? replacementId : k.keyId,
                file: `/private-input/${k.purpose === purpose ? "replacement.key" : purposeFiles[k.purpose]}`
              })),
              ...(purpose === "data_kek"
                ? [{ keyId: originalDataId, file: "/private-input/data.key" }]
                : []),
              {
                keyId: purpose === "backup_kek" ? replacementId : backupId,
                file:
                  purpose === "backup_kek"
                    ? "/private-input/replacement.key"
                    : "/private-input/backup.key"
              }
            ],
            retainedDataKeyIds: purpose === "data_kek" ? [originalDataId] : [],
            passwordFiles: {
              migrator: "/private-input/migrator.password",
              server: "/private-input/server.password",
              worker: "/private-input/worker.password",
              backup: "/private-input/backup.password"
            }
          };
          await writeFile(path.join(directory, "install.json"), JSON.stringify(plan), {
            mode: 0o600
          });
          await writeFile(
            path.join(directory, "reused.password"),
            Buffer.concat([
              await readFile(path.join(directory, "server.password")),
              Buffer.from("\n")
            ]),
            { mode: 0o600 }
          );
          await writeFile(
            path.join(directory, "wrong.password"),
            randomBytes(32).toString("base64url"),
            {
              mode: 0o600
            }
          );
          for (const [name, change] of Object.entries({
            wrongReceipt: { requestSha256: "0".repeat(64) },
            missingKey: { keyFiles: plan.keyFiles.slice(1) },
            wrongMaterial: {
              keyFiles: plan.keyFiles.map((k) =>
                k.keyId === replacementId ? { ...k, file: "/private-input/data.key" } : k
              )
            },
            wrongPassword: {
              passwordFiles: { ...plan.passwordFiles, worker: "/private-input/wrong.password" }
            },
            swappedPrincipals: {
              passwordFiles: {
                ...plan.passwordFiles,
                worker: plan.passwordFiles.server,
                server: plan.passwordFiles.worker
              }
            },
            reusedPassword: {
              passwordFiles: { ...plan.passwordFiles, worker: "/private-input/reused.password" }
            }
          })) {
            await writeFile(
              path.join(directory, `${name}.json`),
              JSON.stringify({ ...plan, ...change, generationRoot: `/generations/${name}` }),
              { mode: 0o600 }
            );
          }
          for (const volume of [inputVolume, outputVolume]) {
            const made = await command("docker", ["volume", "create", volume]);
            expect(made.code, made.stderr).toBe(0);
            createdVolumes.push(volume);
          }
          const copied = await command("docker", [
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--user",
            "0:0",
            "--mount",
            `type=bind,source=${directory},target=/source,readonly`,
            "--mount",
            `type=volume,source=${inputVolume},target=/private-input`,
            "--entrypoint",
            "node",
            IMAGE,
            "-e",
            "const f=require('node:fs');f.chmodSync('/private-input',0o700);for(const n of f.readdirSync('/source')){f.copyFileSync('/source/'+n,'/private-input/'+n);f.chmodSync('/private-input/'+n,0o600);}"
          ]);
          expect(copied.code, copied.stderr).toBe(0);
          const connection = new URL(databaseConnection(url, "boardagent", route));
          connection.username = "boardagent_migrator_login";
          connection.password = "";
          const environment = path.join(directory, "operator.env");
          await writeFile(
            environment,
            [
              "BOARDAGENT_ENV=production",
              `BOARDAGENT_INSTANCE_ID=${instanceId}`,
              `BOARDAGENT_ORGANIZATION_ID=${bootstrap.organizationId}`,
              `BOARDAGENT_DATABASE_URL=${connection}`,
              "BOARDAGENT_DATABASE_PASSWORD_FILE=/private-input/migrator.password"
            ].join("\n") + "\n",
            { mode: 0o600 }
          );
          const invocationArgs = (file: string, user = "0:0", action = "install") => [
            "run",
            "--rm",
            "--read-only",
            "--network",
            route.network,
            "--user",
            user,
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--env-file",
            environment,
            "--mount",
            `type=volume,source=${inputVolume},target=/private-input,readonly`,
            "--mount",
            `type=volume,source=${outputVolume},target=/generations`,
            "--mount",
            `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
            "--entrypoint",
            "node",
            IMAGE,
            "scripts/dist/operator.js",
            "key-lifecycle",
            action,
            ...(action === "install" ? [`/private-input/${file}.json`] : [])
          ];
          const invoke = (file: string, user = "0:0", action = "install") =>
            command("docker", invocationArgs(file, user, action));
          for (const file of ["wrongReceipt", "missingKey", "wrongMaterial"]) {
            const refused = await invoke(file);
            expect(refused.code).toBe(1);
            expect(JSON.parse(refused.stdout)).toMatchObject({
              status: "refused",
              action: "install"
            });
          }
          if (purpose === "browser_session") {
            const reused = await invoke("reusedPassword");
            expect(reused.code, reused.stdout + reused.stderr).toBe(1);
            expect(JSON.parse(reused.stdout)).toMatchObject({
              status: "refused",
              reasonCode: "database_passwords_must_be_distinct"
            });
            for (const file of ["wrongPassword", "swappedPrincipals"]) {
              const refused = await invoke(file);
              expect(refused.code, refused.stdout + refused.stderr).toBe(1);
              expect(JSON.parse(refused.stdout)).toMatchObject({
                status: "refused",
                reasonCode: "database_password_check_failed"
              });
            }
          }
          const unprivileged = await invoke("install", "10001:10001");
          expect(unprivileged.code).toBe(1);
          expect(JSON.parse(unprivileged.stdout)).toMatchObject({
            status: "refused",
            reasonCode: "installation_requires_linux_root_operator"
          });
          const requirements = await invoke("unused", "0:0", "inspect");
          expect(requirements.code, requirements.stdout + requirements.stderr).toBe(0);
          expect(JSON.parse(requirements.stdout)).toMatchObject({
            installationRequirements: {
              retainedDataKeyIds: plan.retainedDataKeyIds,
              workerRetainedDataKeyIds: []
            }
          });
          if (purpose === "browser_session") {
            const limited = invocationArgs("install");
            const outputMount = limited.indexOf(
              `type=volume,source=${outputVolume},target=/generations`
            );
            expect(outputMount).toBeGreaterThan(0);
            limited.splice(outputMount - 1, 2, "--tmpfs", "/generations:size=4096,mode=0700");
            const commandIndex = limited.indexOf("scripts/dist/operator.js");
            limited.splice(
              commandIndex,
              limited.length - commandIndex,
              "--input-type=module",
              "-e",
              "import {runOperatorWithDiagnostics} from './scripts/dist/operator.js';import fs from 'node:fs';const lines=[];const code=await runOperatorWithDiagnostics(['key-lifecycle','install','/private-input/install.json'],process.env,{stdout:l=>lines.push(JSON.parse(l)),stderr:l=>lines.push(JSON.parse(l))});process.stdout.write(JSON.stringify({code,result:lines.at(-1),incomplete:fs.existsSync('/generations/one/server/.initialization-incomplete'),manifest:fs.existsSync('/generations/one/generation.json'),compose:fs.existsSync('/generations/one/compose.yaml')}));"
            );
            const failed = await command("docker", limited);
            expect(failed.code, failed.stderr).toBe(0);
            expect(JSON.parse(failed.stdout)).toMatchObject({
              code: 1,
              incomplete: true,
              manifest: false,
              compose: false,
              result: { status: "refused", reasonCode: "storage_full" }
            });
          }
          const installed = await invoke("install");
          expect(installed.code, installed.stdout + installed.stderr).toBe(0);
          expect(JSON.parse(installed.stdout)).toMatchObject({
            status: "generation_prepared",
            action: "install",
            operationId: operation.operationId,
            runtimeInstallation: "restart_and_verify_required"
          });
          const retry = await invoke("install");
          expect(retry.code).toBe(1);
          expect(JSON.parse(retry.stdout)).toMatchObject({
            status: "refused",
            reasonCode: "generation_directory_already_exists"
          });
          const inspect = await command("docker", [
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--read-only",
            "--mount",
            `type=volume,source=${outputVolume},target=/generations,readonly`,
            "--entrypoint",
            "node",
            IMAGE,
            "-e",
            "const f=require('node:fs');function walk(p){return f.readdirSync(p).sort().flatMap(n=>{const s=f.lstatSync(p+'/'+n);return s.isDirectory()?walk(p+'/'+n):[{path:p+'/'+n,uid:s.uid,gid:s.gid,mode:s.mode&511,sha:require('node:crypto').createHash('sha256').update(f.readFileSync(p+'/'+n)).digest('hex')}];});}process.stdout.write(JSON.stringify({root:f.readdirSync('/generations').sort(),files:walk('/generations/one'),manifest:JSON.parse(f.readFileSync('/generations/one/generation.json')),compose:f.readFileSync('/generations/one/compose.yaml','utf8')}));"
          ]);
          expect(inspect.code, inspect.stderr).toBe(0);
          const inventory = JSON.parse(inspect.stdout) as {
            root: string[];
            files: { path: string; uid: number; mode: number }[];
            manifest: Record<string, unknown>;
            compose: string;
          };
          expect(inventory.root).toEqual(["one"]);
          expect(inventory.manifest).toMatchObject({
            schemaVersion: "boardagent.key-generation.v1",
            instanceId,
            organizationId: bootstrap.organizationId,
            operationId: operation.operationId
          });
          const serverFiles = inventory.files.filter((f) =>
            f.path.startsWith("/generations/one/server/")
          );
          const workerFiles = inventory.files.filter((f) =>
            f.path.startsWith("/generations/one/worker/")
          );
          const relative = (keyPurpose: keyof typeof purposeFiles) =>
            keyPurpose === purpose ? replacementRelative : purposeFiles[keyPurpose];
          expect(
            serverFiles.map((f) => f.path.replace("/generations/one/server/", "")).sort()
          ).toEqual(
            [
              relative("data_kek"),
              "database_server_password",
              relative("evidence_signing"),
              relative("oauth_signing"),
              "retained-data-keys.json",
              ...(purpose === "data_kek" ? [`retained/${originalDataId}.key`] : []),
              relative("browser_session")
            ].sort()
          );
          expect(
            workerFiles.map((f) => f.path.replace("/generations/one/worker/", "")).sort()
          ).toEqual(
            [
              relative("data_kek"),
              "database_worker_password",
              relative("evidence_signing"),
              "retained-data-keys.json"
            ].sort()
          );
          for (const f of [...serverFiles, ...workerFiles])
            expect({ uid: f.uid, mode: f.mode }).toEqual({ uid: 10001, mode: 0o400 });
          for (const role of ["server", "worker"]) {
            const access = await command("docker", [
              "run",
              "--rm",
              "--network",
              "none",
              "--read-only",
              "--user",
              "10001:10001",
              "--cap-drop",
              "ALL",
              "--mount",
              `type=volume,source=${outputVolume},volume-subpath=one/${role},target=/run/boardagent-secrets,readonly`,
              "--entrypoint",
              "node",
              IMAGE,
              "-e",
              `const f=require('node:fs');for(const p of ['database_migrator_password','database_backup_password','backup_kek']){try{f.readFileSync('/run/boardagent-secrets/'+p);throw Error('unexpected access')}catch(e){if(!['ENOENT','EACCES'].includes(e.code))throw e}}f.readFileSync('/run/boardagent-secrets/${relative("data_kek")}');f.readFileSync('/run/boardagent-secrets/${relative("evidence_signing")}');process.stdout.write('isolated');`
            ]);
            expect(access.code, access.stderr).toBe(0);
            expect(access.stdout).toBe("isolated");
          }
          // Parse the generated deployment file with the real Compose engine.
          const generatedCompose = path.join(directory, "generation.yaml"),
            appEnv = path.join(directory, "application.env"),
            composeEnv = path.join(directory, "compose.env");
          await writeFile(generatedCompose, inventory.compose, { mode: 0o600 });
          await writeFile(
            appEnv,
            [
              "BOARDAGENT_ENV=production",
              `BOARDAGENT_ORGANIZATION_ID=${bootstrap.organizationId}`,
              "BOARDAGENT_PUBLIC_BASE_URL=https://generation.boardagent.test",
              "BOARDAGENT_AUTHORIZATION_MODE=builtin",
              "BOARDAGENT_BLOB_ROOT=/tmp/blobs",
              "BOARDAGENT_TRUSTED_PROXY_HOPS=1",
              "BOARDAGENT_WEBHOOKS_ENABLED=false",
              "BOARDAGENT_OAUTH_SIGNING_KEY_FILE=/run/boardagent-secrets/oauth.jwk",
              "BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE=/run/boardagent-secrets/evidence.pem",
              "BOARDAGENT_BROWSER_SESSION_KEY_FILE=/run/boardagent-secrets/browser.key",
              "BOARDAGENT_DATA_KEK_FILE=/run/boardagent-secrets/data.key"
            ].join("\n") + "\n",
            { mode: 0o600 }
          );
          const composeVariables = {
            APP_ENV_FILE: appEnv,
            RELEASE_IMAGE: IMAGE,
            BOARDAGENT_ORGANIZATION_ID: bootstrap.organizationId,
            BACKUP_KEY_ID: backupId,
            RECOVERY_ROOT: directory,
            DATABASE_OWNER_PASSWORD_HOST_FILE: keys.files.database,
            DATABASE_MIGRATOR_PASSWORD_HOST_FILE: passwords.migrator,
            DATABASE_SERVER_PASSWORD_HOST_FILE: passwords.server,
            DATABASE_WORKER_PASSWORD_HOST_FILE: passwords.worker,
            DATABASE_BACKUP_PASSWORD_HOST_FILE: passwords.backup,
            OAUTH_SIGNING_KEY_HOST_FILE: keys.files.oauth,
            EVIDENCE_SIGNING_KEY_HOST_FILE: keys.files.evidence,
            BROWSER_SESSION_KEY_HOST_FILE: keys.files.browser,
            DATA_KEK_HOST_FILE: keys.files.data,
            BACKUP_KEK_HOST_FILE: path.join(directory, "backup.key"),
            RECOVERY_DATABASE_PASSWORD_HOST_FILE: passwords.backup
          };
          await writeFile(
            composeEnv,
            Object.entries(composeVariables)
              .map(([k, v]) => `${k}=${v}`)
              .join("\n") + "\n",
            { mode: 0o600 }
          );
          const rendered = await command("docker", [
            "compose",
            "--env-file",
            composeEnv,
            "--profile",
            "operator",
            "--profile",
            "backup-key",
            "-f",
            path.resolve("compose.yaml"),
            "-f",
            path.resolve("compose.production.yaml"),
            "-f",
            path.resolve("compose.recovery.yaml"),
            "-f",
            generatedCompose,
            "config",
            "--format",
            "json"
          ]);
          expect(rendered.code, rendered.stderr).toBe(0);
          const composition = JSON.parse(rendered.stdout) as {
            services: Record<
              string,
              {
                environment: Record<string, string>;
                depends_on: Record<string, unknown>;
                volumes: { type: string; source: string; target: string; read_only?: boolean }[];
                profiles?: string[];
              }
            >;
          };
          for (const [service, role] of Object.entries({
            server: "server",
            worker: "worker",
            operator: "operator",
            "wal-archiver": "recovery",
            "backup-key-check": "recovery"
          })) {
            expect(
              composition.services[service]!.volumes.find(
                (v) => v.target === "/run/boardagent-secrets"
              )
            ).toMatchObject({ type: "bind", source: `/generations/one/${role}`, read_only: true });
            for (const initializer of [
              "application-secret-init",
              "recovery-secret-init",
              "backup-registration-secret-init"
            ])
              expect(composition.services[service]!.depends_on ?? {}).not.toHaveProperty(
                initializer
              );
          }
          expect(Object.keys(composition.services["postgres"]!.depends_on).sort()).toEqual([
            "backup-key-check",
            "wal-staging-init"
          ]);
          for (const initializer of [
            "application-secret-init",
            "recovery-secret-init",
            "backup-registration-secret-init",
            "backup-key-registrar"
          ])
            expect(composition.services).not.toHaveProperty(initializer);
          // Start the actual production entrypoints from the new, isolated directories.
          for (const role of ["server", "worker"] as const) {
            const env = { ...composition.services[role]!.environment };
            const roleConnection = new URL(env["BOARDAGENT_DATABASE_URL"]!);
            expect(roleConnection.username).toBe(`boardagent_${role}_login`);
            roleConnection.hostname = route.hostname;
            roleConnection.port = route.port;
            env["BOARDAGENT_DATABASE_URL"] = roleConnection.toString();
            const runtimeEnvironment = path.join(directory, `${role}.env`);
            await writeFile(
              runtimeEnvironment,
              Object.entries(env)
                .map(([k, v]) => `${k}=${v}`)
                .join("\n") + "\n",
              { mode: 0o600 }
            );
            const name = `boardagent-generation-${role}-${suffix}`;
            const started = await command("docker", [
              "run",
              "-d",
              "--name",
              name,
              "--read-only",
              "--network",
              route.network,
              "--user",
              "10001:10001",
              "--cap-drop",
              "ALL",
              "--tmpfs",
              "/tmp:size=128m,mode=1777",
              "--env-file",
              runtimeEnvironment,
              "--mount",
              `type=volume,source=${outputVolume},volume-subpath=one/${role},target=/run/boardagent-secrets,readonly`,
              "--mount",
              `type=volume,source=${route.maintenanceVolume},target=/run/boardagent-maintenance,readonly`,
              "--entrypoint",
              "node",
              IMAGE,
              "artifacts/server/dist/main.js",
              role
            ]);
            expect(started.code, started.stderr).toBe(0);
            startedContainers.push(name);
          }
          for (const [index, role] of ["server", "worker"].entries()) {
            const deadline = Date.now() + 20_000;
            let healthy = false;
            while (Date.now() < deadline && !healthy) {
              const health = await command("docker", [
                "exec",
                startedContainers[index]!,
                "node",
                "artifacts/server/dist/main.js",
                "healthcheck",
                ...(role === "worker" ? ["worker"] : [])
              ]);
              healthy = health.code === 0;
              if (!healthy) await new Promise((resolve) => setTimeout(resolve, 100));
            }
            const logs = await command("docker", ["logs", startedContainers[index]!]);
            expect(healthy, logs.stdout + logs.stderr).toBe(true);
          }
          if (factor) {
            const now = Number(
              (await pool.query("select floor(extract(epoch from clock_timestamp())) as now"))
                .rows[0].now
            );
            const authenticated = await command(
              "docker",
              [
                "exec",
                "-i",
                startedContainers[0]!,
                "node",
                "--input-type=module",
                "-e",
                "import {Pool} from 'pg';import {parseConfig} from './lib/config/dist/index.js';import {loadBoardAgentKeyMaterial,loadBoardAgentRuntimeBinding,PgTotpService,PgRateLimiter} from './artifacts/server/dist/index.js';import {dataDecryptionKeyring} from './artifacts/server/dist/retained-data-keys.js';let input='';for await(const c of process.stdin)input+=c;const request=JSON.parse(input),config=parseConfig(process.env),keys=await loadBoardAgentKeyMaterial(config),pool=new Pool({connectionString:config.databaseUrl,max:2});try{const binding=await loadBoardAgentRuntimeBinding(pool,config,keys,{assumeRole:'boardagent_server'});const policy={windowSeconds:60,maxRequests:100,blockSeconds:60};const service=new PgTotpService(pool,{issuer:'Synthetic generation test',activeKeyId:binding.keyIds.data_kek,keys:dataDecryptionKeyring(binding.keyIds.data_kek,keys.dataEncryptionKey,keys.retainedDataKeys),rateLimiter:new PgRateLimiter(pool,{hmacKey:keys.browserSessionKey,assumeRole:'boardagent_server'}),rateLimits:{ip:policy,client:policy,member:policy,token:policy},maxFailedAttempts:5,lockoutSeconds:300,assumeRole:'boardagent_server'});const result=await service.authenticate(request);process.stdout.write(JSON.stringify({memberId:result.memberId,retainedKeys:keys.retainedDataKeys.entries.map(k=>k.keyId)}));}finally{await pool.end();}"
              ],
              JSON.stringify({
                organizationId: bootstrap.organizationId,
                sessionId: newWorkerTestId(),
                clientId: newWorkerTestId(),
                clientIpClass: "ipv4:127.0.0.0/24",
                fallbackHandle: factor.fallbackHandle,
                code: generateTotpCodeFromBase32(factor.secretBase32, now + 30)
              })
            );
            expect(authenticated.code, authenticated.stderr).toBe(0);
            expect(JSON.parse(authenticated.stdout)).toEqual({
              memberId: factor.memberId,
              retainedKeys: [originalDataId]
            });
          }
          const busyInstall = await invoke("install");
          expect(busyInstall.code).toBe(1);
          expect(JSON.parse(busyInstall.stdout)).toMatchObject({
            reasonCode: "maintenance_lock_busy"
          });
          const unchanged = await command("docker", [
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--user",
            "0:0",
            "--mount",
            `type=volume,source=${inputVolume},target=/private-input,readonly`,
            "--entrypoint",
            "node",
            IMAGE,
            "-e",
            "process.stdout.write(require('node:crypto').createHash('sha256').update(require('node:fs').readFileSync('/private-input/browser.key')).digest('hex'))"
          ]);
          expect(unchanged.stdout).toBe(
            createHash("sha256")
              .update(await readFile(keys.files.browser))
              .digest("hex")
          );
        } finally {
          for (const name of startedContainers.reverse()) {
            const stopped = await command("docker", ["stop", "--time", "15", name]);
            expect(stopped.code, stopped.stderr).toBe(0);
            const removed = await command("docker", ["rm", name]);
            expect(removed.code, removed.stderr).toBe(0);
          }
          await pool.end();
          for (const volume of createdVolumes.reverse()) {
            const removed = await command("docker", ["volume", "rm", volume]);
            expect(removed.code, removed.stderr).toBe(0);
          }
          await rm(directory, { recursive: true, force: true });
        }
      });
    },
    180_000
  );
});
