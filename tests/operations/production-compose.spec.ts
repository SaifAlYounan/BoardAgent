import { generateKeyPairSync, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_POSTGRES_IMAGE,
  SOURCE_TREE_LABEL
} from "../../scripts/src/build-release-image.js";
import { sourceTreeSha256 } from "../../scripts/src/verify-release.js";
import { ownPrivateContainerInput } from "../helpers/container-custody.js";

import { proxyHttpRequest } from "../helpers/proxy-http.js";

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
  timeoutMilliseconds = 90_000
): Promise<void> {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${description}`);
}

async function ready(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const outbound = request(
      {
        hostname: "127.0.0.1",
        port,
        path: "/health/ready",
        headers: {
          host: "production-compose.boardagent.test",
          "x-forwarded-for": "198.51.100.55",
          "x-forwarded-proto": "https"
        }
      },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode === 200));
      }
    );
    outbound.once("error", () => resolve(false));
    outbound.end();
  });
}

function jsonReceipt(output: string): Readonly<Record<string, unknown>> {
  const line = output
    .split("\n")
    .map((candidate) => candidate.trim())
    .findLast((candidate) => candidate.startsWith("{") && candidate.endsWith("}"));
  if (!line) throw new Error(`operator JSON receipt missing from: ${output}`);
  return JSON.parse(line) as Readonly<Record<string, unknown>>;
}

async function secret(file: string, value: string | Uint8Array): Promise<void> {
  await writeFile(file, value, { mode: 0o600 });
}

describe("T9 production Compose cold start", () => {
  it("provisions separated principals and starts server/worker without an environment secret", async () => {
    const suffix = `${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    const project = `boardagent_prod_${suffix}`.toLowerCase();
    const working = await mkdtemp(path.join(tmpdir(), "boardagent-production-compose-"));
    const image = process.env["BOARDAGENT_RELEASE_IMAGE"] ?? "boardagent:verification-current";
    const postgresImage = process.env["BOARDAGENT_POSTGRES_IMAGE"] ?? DEFAULT_POSTGRES_IMAGE;
    const passwords = {
      owner: randomBytes(32).toString("base64url"),
      migrator: randomBytes(32).toString("base64url"),
      server: randomBytes(32).toString("base64url"),
      worker: randomBytes(32).toString("base64url"),
      backup: randomBytes(32).toString("base64url")
    } as const;
    const files = {
      owner: path.join(working, "owner.password"),
      migrator: path.join(working, "migrator.password"),
      server: path.join(working, "server.password"),
      worker: path.join(working, "worker.password"),
      backup: path.join(working, "backup.password"),
      oauth: path.join(working, "oauth.jwk"),
      evidence: path.join(working, "evidence.pem"),
      browser: path.join(working, "browser.key"),
      data: path.join(working, "data.key"),
      backupKek: path.join(working, "backup.key"),
      environment: path.join(working, "application.env"),
      setup: path.join(working, "bootstrap.json")
    } as const;
    const oauth = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
      format: "jwk"
    });
    const evidence = generateKeyPairSync("ed25519").privateKey.export({
      format: "pem",
      type: "pkcs8"
    });
    await Promise.all([
      ...Object.entries(passwords).map(([purpose, password]) =>
        secret(files[purpose as keyof typeof passwords], `${password}\n`)
      ),
      secret(
        files.oauth,
        `${JSON.stringify({ ...oauth, kid: "production-compose-oauth", use: "sig", alg: "ES256" })}\n`
      ),
      secret(files.evidence, evidence),
      secret(files.browser, randomBytes(32)),
      secret(files.data, randomBytes(32)),
      secret(files.backupKek, randomBytes(32))
    ]);
    const applicationEnvironment = (organizationId?: string): string =>
      [
        "BOARDAGENT_ENV=production",
        ...(organizationId ? [`BOARDAGENT_ORGANIZATION_ID=${organizationId}`] : []),
        "BOARDAGENT_PUBLIC_BASE_URL=https://production-compose.boardagent.test",
        "BOARDAGENT_AUTHORIZATION_MODE=builtin",
        "BOARDAGENT_BLOB_ROOT=/var/lib/boardagent/blobs",
        "BOARDAGENT_OAUTH_SIGNING_KEY_FILE=/run/boardagent-secrets/oauth_signing_key",
        "BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE=/run/boardagent-secrets/evidence_signing_key",
        "BOARDAGENT_BROWSER_SESSION_KEY_FILE=/run/boardagent-secrets/browser_session_key",
        "BOARDAGENT_DATA_KEK_FILE=/run/boardagent-secrets/data_kek",
        "BOARDAGENT_TRUSTED_PROXY_HOPS=1",
        "BOARDAGENT_WEBHOOKS_ENABLED=false"
      ].join("\n") + "\n";
    await secret(files.environment, applicationEnvironment());
    await secret(
      files.setup,
      `${JSON.stringify({
        organizationLegalName: "Production Compose Test Ltd",
        organizationDisplayName: "Production Compose Test",
        organizationSlug: "production-compose-test",
        timezone: "UTC",
        boardSlug: "main",
        boardName: "Main",
        boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
        firstSecretaryLegalName: "Production Secretary",
        firstSecretaryDisplayName: "Secretary",
        votingWeight: 1,
        supportName: "Secretary",
        supportContactMethods: [{ kind: "operator_reference", value: "production-compose-test" }],
        onboardingTermsText: "Review every canonical record before confirming.",
        invitationHandoffMethod: "in person"
      })}\n`
    );

    const compose = [
      "compose",
      "-p",
      project,
      "-f",
      "compose.yaml",
      "-f",
      "compose.production.yaml",
      "--profile",
      "initialize",
      "--profile",
      "operator",
      "--profile",
      "backup-key"
    ] as const;
    const env = {
      ...process.env,
      APP_ENV_FILE: files.environment,
      RELEASE_IMAGE: image,
      POSTGRES_IMAGE: postgresImage,
      PUBLISHED_PORT: "0",
      DATABASE_OWNER_PASSWORD_HOST_FILE: files.owner,
      DATABASE_MIGRATOR_PASSWORD_HOST_FILE: files.migrator,
      DATABASE_SERVER_PASSWORD_HOST_FILE: files.server,
      DATABASE_WORKER_PASSWORD_HOST_FILE: files.worker,
      DATABASE_BACKUP_PASSWORD_HOST_FILE: files.backup,
      OAUTH_SIGNING_KEY_HOST_FILE: files.oauth,
      EVIDENCE_SIGNING_KEY_HOST_FILE: files.evidence,
      BROWSER_SESSION_KEY_HOST_FILE: files.browser,
      DATA_KEK_HOST_FILE: files.data,
      BACKUP_KEK_HOST_FILE: files.backupKek
    };

    try {
      const inspection = await command("docker", [
        "image",
        "inspect",
        image,
        "--format",
        `{{index .Config.Labels "${SOURCE_TREE_LABEL}"}}`
      ]);
      expect(inspection.code, inspection.stderr).toBe(0);
      expect(inspection.stdout.trim()).toBe(await sourceTreeSha256());

      const initialized = await command(
        "docker",
        [...compose, "run", "--rm", "database-initializer"],
        env
      );
      expect(initialized.code, `${initialized.stdout}\n${initialized.stderr}`).toBe(0);
      expect(jsonReceipt(initialized.stdout)).toMatchObject({
        command: "migrate",
        status: "succeeded",
        migrationsApplied: 172,
        databasePrincipals: {
          schemaVersion: "boardagent.database-principal-provision.v1"
        }
      });

      for (const service of ["server", "worker"] as const) {
        const custody = await command(
          "docker",
          [
            ...compose,
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "node",
            service,
            "--input-type=module",
            "-e",
            `
            import { readFile, readdir } from 'node:fs/promises';
            import pg from 'pg';
            const directory = '/run/boardagent-secrets';
            const readable = [];
            for (const name of await readdir(directory)) {
              await readFile(directory + '/' + name);
              readable.push(name);
            }
            const denied = [];
            const forbidden = ['database_owner_password', 'database_migrator_password', 'database_backup_password', 'database_${service === "server" ? "worker" : "server"}_password', 'backup_kek'${service === "worker" ? ", 'oauth_signing_key', 'browser_session_key'" : ""}];
            for (const name of forbidden) {
              for (const path of [directory + '/' + name, '/run/secrets/' + name]) {
                try { await readFile(path); throw new Error('unexpected readable secret path: ' + path); }
                catch (error) { if (error.code !== 'ENOENT' && error.code !== 'EACCES') throw error; }
              }
              denied.push(name);
            }
            const password = (await readFile(process.env.BOARDAGENT_DATABASE_PASSWORD_FILE, 'utf8')).trim();
            const rejected = [];
            for (const principal of ['boardagent_owner', 'boardagent_migrator_login', 'boardagent_backup_login', 'boardagent_${service === "server" ? "worker" : "server"}_login']) {
              const url = new URL(process.env.BOARDAGENT_DATABASE_URL);
              url.username = principal;
              url.password = password;
              const client = new pg.Client({connectionString:url.toString()});
              try { await client.connect(); }
              catch (error) { if (error.code === '28P01') rejected.push(principal); else throw error; }
              finally { await client.end(); }
            }
            process.stdout.write(JSON.stringify({uid:process.getuid(), readable:readable.sort(), denied, rejected}));
          `
          ],
          env
        );
        expect(custody.code, custody.stderr).toBe(0);
        expect(jsonReceipt(custody.stdout)).toEqual({
          uid: 10001,
          readable: (service === "server"
            ? [
                "database_server_password",
                "oauth_signing_key",
                "evidence_signing_key",
                "browser_session_key",
                "data_kek"
              ]
            : ["database_worker_password", "evidence_signing_key", "data_kek"]
          ).sort(),
          denied: [
            "database_owner_password",
            "database_migrator_password",
            "database_backup_password",
            `database_${service === "server" ? "worker" : "server"}_password`,
            "backup_kek",
            ...(service === "worker" ? ["oauth_signing_key", "browser_session_key"] : [])
          ],
          rejected: [
            "boardagent_owner",
            "boardagent_migrator_login",
            "boardagent_backup_login",
            `boardagent_${service === "server" ? "worker" : "server"}_login`
          ]
        });
      }

      await ownPrivateContainerInput(image, files.setup);
      const bootstrapped = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "--volume",
          `${files.setup}:/tmp/bootstrap.json:ro`,
          "operator",
          "bootstrap",
          "/tmp/bootstrap.json"
        ],
        env
      );
      expect(bootstrapped.code, `${bootstrapped.stdout}\n${bootstrapped.stderr}`).toBe(0);
      const bootstrapReceipt = jsonReceipt(bootstrapped.stdout);
      expect(bootstrapReceipt).toMatchObject({
        command: "bootstrap",
        operatorStatus: "succeeded",
        status: "created",
        runtimeKeysRegistered: true
      });
      const organizationId = String(bootstrapReceipt["organizationId"]);
      expect(organizationId).toMatch(/^[0-9a-f-]{36}$/u);
      const bootstrapInventory = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "-e",
          `BOARDAGENT_ORGANIZATION_ID=${organizationId}`,
          "operator",
          "check-bootstrap"
        ],
        env
      );
      expect(bootstrapInventory.code, bootstrapInventory.stderr).toBe(0);
      expect(jsonReceipt(bootstrapInventory.stdout)).toMatchObject({
        command: "check-bootstrap",
        checks: "onboarding_terms",
        status: "complete",
        allSeatRolesCovered: true,
        organizationId,
        terms: ["voting_member", "management", "observer"].map((seatRole) => ({
          seatRole,
          availableVersions: 1,
          version: 1
        }))
      });
      await secret(files.environment, applicationEnvironment(organizationId));

      const registrationEnv = {
        ...env,
        BOARDAGENT_ORGANIZATION_ID: organizationId,
        BACKUP_KEY_ID: "0198c000-0000-7000-8000-000000085001"
      };
      const registered = await command(
        "docker",
        [...compose, "run", "--rm", "backup-key-registrar"],
        registrationEnv
      );
      expect(registered.code, registered.stderr).toBe(0);
      expect(jsonReceipt(registered.stdout)).toMatchObject({
        command: "register-backup-key",
        status: "succeeded",
        organizationId,
        keyRegistration: {
          keyId: registrationEnv.BACKUP_KEY_ID,
          purpose: "backup_kek",
          replayed: false
        }
      });
      const registeredAgain = await command(
        "docker",
        [...compose, "run", "--rm", "backup-key-registrar"],
        registrationEnv
      );
      expect(registeredAgain.code, registeredAgain.stderr).toBe(0);
      expect(jsonReceipt(registeredAgain.stdout)).toMatchObject({
        receiptSha256: jsonReceipt(registered.stdout)["receiptSha256"],
        keyRegistration: { keyId: registrationEnv.BACKUP_KEY_ID, replayed: true }
      });
      const registrarCustody = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "--entrypoint",
          "node",
          "backup-key-registrar",
          "--input-type=module",
          "-e",
          `import { readFile, readdir, stat } from 'node:fs/promises';
         const names = (await readdir('/run/boardagent-registration')).sort();
         for (const name of names) await readFile('/run/boardagent-registration/' + name);
         const forbidden = ['database_owner_password','database_server_password','database_worker_password','database_backup_password','oauth_signing_key','evidence_signing_key','browser_session_key','data_kek'];
         for (const name of forbidden) for (const directory of ['/run/boardagent-registration','/run/boardagent-secrets','/run/secrets']) {
           try { await readFile(directory + '/' + name); throw new Error('unexpected secret access'); }
           catch (error) { if (error.code !== 'ENOENT' && error.code !== 'EACCES') throw error; }
         }
         const receiptFile='/var/lib/boardagent/backup-key-receipts/${registrationEnv.BACKUP_KEY_ID}.json';
         const receiptStat=await stat(receiptFile),receipt=JSON.parse(await readFile(receiptFile,'utf8'));
         process.stdout.write(JSON.stringify({uid:process.getuid(),readable:names,denied:forbidden,receiptMode:receiptStat.mode&0o777,receiptOwner:receiptStat.uid,receiptSha256:receipt.receiptSha256}));`
        ],
        registrationEnv
      );
      expect(registrarCustody.code, registrarCustody.stderr).toBe(0);
      expect(jsonReceipt(registrarCustody.stdout)).toMatchObject({
        uid: 10001,
        readable: ["backup_kek", "database_migrator_password"],
        receiptMode: 0o400,
        receiptOwner: 10001,
        receiptSha256: jsonReceipt(registered.stdout)["receiptSha256"],
        denied: [
          "database_owner_password",
          "database_server_password",
          "database_worker_password",
          "database_backup_password",
          "oauth_signing_key",
          "evidence_signing_key",
          "browser_session_key",
          "data_kek"
        ]
      });

      const started = await command(
        "docker",
        [...compose, "up", "-d", "--no-build", "server", "worker"],
        env
      );
      expect(started.code, `${started.stdout}\n${started.stderr}`).toBe(0);
      const portResult = await command("docker", [...compose, "port", "server", "8787"], env);
      expect(portResult.code, portResult.stderr).toBe(0);
      const port = Number(portResult.stdout.trim().split(":").at(-1));
      expect(Number.isSafeInteger(port) && port > 0).toBe(true);
      await waitFor(() => ready(port), "production server readiness");
      // Exercise the production image's real HTTP upstream, as reached after
      // Caddy terminates TLS. Readiness alone cannot prove OAuth is usable.
      const issuer = "https://production-compose.boardagent.test";
      const discoveryUrl = `http://127.0.0.1:${String(port)}/.well-known/openid-configuration`;
      const proxyHeaders = {
        host: "production-compose.boardagent.test",
        "x-forwarded-for": "198.51.100.55",
        "x-forwarded-proto": "https",
        "x-forwarded-host": "production-compose.boardagent.test"
      };
      const discovery = await proxyHttpRequest(discoveryUrl, proxyHeaders);
      expect(discovery.status).toBe(200);
      const metadata = (await discovery.json()) as Record<string, unknown>;
      expect(metadata).toMatchObject({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`
      });
      for (const [key, value] of Object.entries(metadata)) {
        if (key.endsWith("_endpoint") || key === "jwks_uri") {
          expect(new URL(String(value)).origin).toBe(issuer);
        }
      }
      for (const invalidHeaders of [
        { "x-forwarded-proto": "http" },
        { "x-forwarded-host": "attacker.test" }
      ]) {
        const refused = await proxyHttpRequest(discoveryUrl, {
          ...proxyHeaders,
          ...invalidHeaders
        });
        expect(refused.status).toBe(400);
        expect(refused.headers.get("location")).toBeNull();
        await refused.arrayBuffer();
      }
      await waitFor(async () => {
        const logs = await command("docker", [...compose, "logs", "--no-color", "worker"], env);
        return (
          logs.code === 0 && `${logs.stdout}${logs.stderr}`.includes('"event":"worker.started"')
        );
      }, "production worker readiness");
      await waitFor(async () => {
        const probe = await command(
          "docker",
          [
            ...compose,
            "exec",
            "-T",
            "worker",
            "node",
            "artifacts/server/dist/main.js",
            "healthcheck",
            "worker"
          ],
          env
        );
        return probe.code === 0;
      }, "production worker progress health check under its separated identity");
      await waitFor(async () => {
        const container = await command("docker", [...compose, "ps", "-q", "worker"], env);
        if (container.code !== 0 || !container.stdout.trim()) return false;
        const health = await command(
          "docker",
          ["inspect", "--format", "{{.State.Health.Status}}", container.stdout.trim()],
          env
        );
        return health.code === 0 && health.stdout.trim() === "healthy";
      }, "configured Docker worker health check");

      const sessions = await command(
        "docker",
        [
          ...compose,
          "exec",
          "-T",
          "postgres",
          "psql",
          "-U",
          "boardagent_owner",
          "-d",
          "boardagent",
          "-Atc",
          "select usename from pg_stat_activity where datname='boardagent' and usename in ('boardagent_server_login','boardagent_worker_login') group by usename order by usename"
        ],
        env
      );
      expect(sessions.code, sessions.stderr).toBe(0);
      expect(sessions.stdout).toBe("boardagent_server_login\nboardagent_worker_login\n");

      const logs = await command(
        "docker",
        [...compose, "logs", "--no-color", "server", "worker"],
        env
      );
      expect(logs.code, logs.stderr).toBe(0);
      const allLogs = `${initialized.stdout}${initialized.stderr}${bootstrapped.stdout}${bootstrapped.stderr}${logs.stdout}${logs.stderr}`;
      for (const password of Object.values(passwords)) expect(allLogs).not.toContain(password);

      const blockedMaintenance = () =>
        command(
          "docker",
          [
            ...compose,
            "run",
            "--rm",
            "--no-deps",
            "operator",
            "key-lifecycle",
            "apply",
            "/tmp/not-a-request.json",
            "0".repeat(64),
            "/tmp/not-a-receipt.json"
          ],
          env
        );
      const whileRunning = await blockedMaintenance();
      expect(whileRunning.code).toBe(1);
      expect(jsonReceipt(whileRunning.stdout)).toMatchObject({
        status: "refused",
        stage: "maintenance_exclusion",
        reasonCode: "maintenance_lock_busy"
      });
      const stoppedWorker = await command("docker", [...compose, "stop", "worker"], env);
      expect(stoppedWorker.code, stoppedWorker.stderr).toBe(0);
      expect(jsonReceipt((await blockedMaintenance()).stdout)).toMatchObject({
        reasonCode: "maintenance_lock_busy"
      });
      const stoppedServer = await command("docker", [...compose, "stop", "server"], env);
      expect(stoppedServer.code, stoppedServer.stderr).toBe(0);
      const exclusive = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "--entrypoint",
          "node",
          "operator",
          "--input-type=module",
          "-e",
          "import {acquireKernelMaintenanceLease,PRODUCTION_MAINTENANCE_LOCK_FILE} from './artifacts/server/dist/kernel-maintenance-lease.js';const lease=await acquireKernelMaintenanceLease(PRODUCTION_MAINTENANCE_LOCK_FILE,'exclusive');await lease.close();process.stdout.write(JSON.stringify({exclusiveAfterShutdown:true}));"
        ],
        env
      );
      expect(exclusive.code, exclusive.stderr).toBe(0);
      expect(jsonReceipt(exclusive.stdout)).toEqual({ exclusiveAfterShutdown: true });
    } finally {
      await command("docker", [...compose, "down", "--volumes", "--remove-orphans"], env).catch(
        () => undefined
      );
      await rm(working, { recursive: true, force: true });
    }
  }, 240_000);
});
