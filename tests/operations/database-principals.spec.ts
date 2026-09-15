import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { DATABASE_PRINCIPALS } from "../../scripts/src/database-principals.js";
import { DEFAULT_POSTGRES_IMAGE } from "../../scripts/src/build-release-image.js";

const POSTGRES_IMAGE = process.env["BOARDAGENT_POSTGRES_IMAGE"] ?? DEFAULT_POSTGRES_IMAGE;
const TSX = path.resolve("node_modules/.bin/tsx");

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
    env: { ...process.env, ...env },
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

async function waitForPostgres(databaseUrl: string): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const pool = new Pool({ connectionString: databaseUrl, max: 1 });
    try {
      await pool.query("select 1");
      await pool.end();
      return;
    } catch {
      await pool.end().catch(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error("timed out waiting for isolated PostgreSQL");
}

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test port allocation failed");
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  );
  return address.port;
}

describe("T9 production database principals", () => {
  it("provisions four SCRAM login wrappers with no authority before their exact SET ROLE", async () => {
    const suffix = `${String(process.pid)}-${randomBytes(4).toString("hex")}`;
    const container = `boardagent-principals-${suffix}`;
    const ownerPassword = randomBytes(32).toString("base64url");
    const port = await availablePort();
    const working = await mkdtemp(path.join(tmpdir(), "boardagent-database-principals-"));
    const passwords = Object.fromEntries(
      DATABASE_PRINCIPALS.map(({ purpose }) => [purpose, randomBytes(32).toString("base64url")])
    ) as Record<(typeof DATABASE_PRINCIPALS)[number]["purpose"], string>;
    const files = Object.fromEntries(
      await Promise.all(
        DATABASE_PRINCIPALS.map(async ({ purpose }) => {
          const file = path.join(working, `${purpose}.password`);
          await writeFile(file, `${passwords[purpose]}\n`, { mode: 0o600 });
          return [purpose, file] as const;
        })
      )
    ) as Record<(typeof DATABASE_PRINCIPALS)[number]["purpose"], string>;
    const ownerPasswordFile = path.join(working, "owner.password");
    await writeFile(ownerPasswordFile, `${ownerPassword}\n`, { mode: 0o600 });

    try {
      const started = await command("docker", [
        "run",
        "--detach",
        "--name",
        container,
        "--publish",
        `127.0.0.1:${String(port)}:5432`,
        "--tmpfs",
        "/var/lib/postgresql:rw,uid=70,gid=70,mode=0700",
        "--env",
        "POSTGRES_DB=boardagent",
        "--env",
        "POSTGRES_USER=boardagent_owner",
        "--env",
        `POSTGRES_PASSWORD=${ownerPassword}`,
        POSTGRES_IMAGE
      ]);
      expect(started.code, started.stderr).toBe(0);
      const ownerUrl = new URL(`postgresql://boardagent_owner@127.0.0.1/boardagent`);
      ownerUrl.port = String(port);
      ownerUrl.password = ownerPassword;
      await waitForPostgres(ownerUrl.toString());

      const owner = new Pool({ connectionString: ownerUrl.toString(), max: 2 });
      try {
        const migrated = await command(
          TSX,
          ["--tsconfig", "scripts/tsconfig.json", "scripts/src/operator.ts", "migrate"],
          {
            BOARDAGENT_ENV: "production",
            BOARDAGENT_DATABASE_URL: `postgresql://boardagent_owner@127.0.0.1:${String(port)}/boardagent`,
            DATABASE_OWNER_PASSWORD_FILE: ownerPasswordFile,
            DATABASE_MIGRATOR_PASSWORD_FILE: files.migrator,
            DATABASE_SERVER_PASSWORD_FILE: files.server,
            DATABASE_WORKER_PASSWORD_FILE: files.worker,
            DATABASE_BACKUP_PASSWORD_FILE: files.backup
          }
        );
        expect(migrated.code, migrated.stderr).toBe(0);
        const migrationReceipt = JSON.parse(migrated.stdout) as Record<string, unknown>;
        expect(migrationReceipt).toMatchObject({
          schemaVersion: 1,
          command: "migrate",
          status: "succeeded",
          migrationsApplied: 172
        });
        const receipt = migrationReceipt["databasePrincipals"];
        expect(receipt).toMatchObject({
          schemaVersion: "boardagent.database-principal-provision.v1",
          database: "boardagent"
        });
        expect((receipt as { principals: unknown[] }).principals).toHaveLength(4);

        const migratorUrl = new URL(ownerUrl);
        migratorUrl.username = "boardagent_migrator_login";
        migratorUrl.password = "";
        const replay = await command(
          TSX,
          ["--tsconfig", "scripts/tsconfig.json", "scripts/src/operator.ts", "migrate"],
          {
            BOARDAGENT_ENV: "production",
            BOARDAGENT_DATABASE_URL: migratorUrl.toString(),
            BOARDAGENT_DATABASE_PASSWORD_FILE: files.migrator
          }
        );
        expect(replay.code, replay.stderr).toBe(0);
        expect(JSON.parse(replay.stdout)).toMatchObject({
          status: "succeeded",
          migrationsApplied: 0,
          databasePrincipals: null
        });

        const roleState = await owner.query<{
          rolbypassrls: boolean;
          rolcanlogin: boolean;
          rolcreatedb: boolean;
          rolcreaterole: boolean;
          rolinherit: boolean;
          rolname: string;
          rolreplication: boolean;
          rolsuper: boolean;
        }>(
          `select rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,
                  rolreplication,rolbypassrls
             from pg_roles where rolname=any($1) order by rolname`,
          [DATABASE_PRINCIPALS.map(({ loginRole }) => loginRole)]
        );
        expect(roleState.rows).toHaveLength(4);
        for (const role of roleState.rows) {
          const specification = DATABASE_PRINCIPALS.find(
            ({ loginRole }) => loginRole === role.rolname
          );
          expect(specification).toBeDefined();
          expect(role).toMatchObject({
            rolbypassrls: false,
            rolcanlogin: true,
            rolcreatedb: false,
            rolcreaterole: false,
            rolinherit: false,
            rolreplication: specification!.replication,
            rolsuper: false
          });
        }

        for (const principal of DATABASE_PRINCIPALS) {
          const loginUrl = new URL(ownerUrl);
          loginUrl.username = principal.loginRole;
          loginUrl.password = passwords[principal.purpose];
          const login = new Pool({ connectionString: loginUrl.toString(), max: 1 });
          try {
            await expect(login.query("select count(*) from system_instance")).rejects.toThrow(
              /permission denied/u
            );
            const client = await login.connect();
            try {
              expect(
                (await client.query<{ role_name: string }>("select current_user as role_name"))
                  .rows[0]
              ).toEqual({ role_name: principal.loginRole });
              await client.query(`set role ${principal.capabilityRole}`);
              expect(
                (await client.query<{ role_name: string }>("select current_user as role_name"))
                  .rows[0]
              ).toEqual({ role_name: principal.capabilityRole });
              expect((await client.query("select count(*) from system_instance")).rowCount).toBe(1);
            } finally {
              client.release();
            }
          } finally {
            await login.end();
          }
        }

        const deniedUrl = new URL(ownerUrl);
        deniedUrl.username = "boardagent_server_login";
        deniedUrl.password = randomBytes(32).toString("base64url");
        const denied = new Pool({ connectionString: deniedUrl.toString(), max: 1 });
        try {
          await expect(denied.query("select 1")).rejects.toThrow(/password authentication failed/u);
        } finally {
          await denied.end().catch(() => undefined);
        }
      } finally {
        await owner.end();
      }
    } finally {
      await command("docker", ["rm", "--force", container]).catch(() => undefined);
      await rm(working, { recursive: true, force: true });
    }
  }, 180_000);
});
