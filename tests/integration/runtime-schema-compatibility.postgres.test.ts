import { randomBytes } from "node:crypto";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import type { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  loadBoardAgentKeyMaterial,
  runtimeKeyRegistrations,
  startBoardAgentServer,
  startBoardAgentWorker
} from "../../artifacts/server/src/index.js";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  loadMigrations,
  migrate,
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { uuidV7 } from "../../lib/domain/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

async function fixture(pool: Pool, blobRoot: string) {
  const origin = "https://boardagent.schema.test";
  const created = await new BoardAgentBootstrapOperator(pool, {
    assumeRole: "boardagent_migrator"
  }).initialize({
    organizationLegalName: "Schema Test Ltd",
    organizationDisplayName: "Schema Test",
    organizationSlug: "schema-test",
    timezone: "UTC",
    canonicalResourceUri: `${origin}/mcp`,
    boardSlug: "main",
    boardName: "Main",
    boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
    firstSecretaryLegalName: "Secretary",
    firstSecretaryDisplayName: "Secretary",
    votingWeight: 1,
    supportName: "Secretary",
    supportContactMethods: [{ kind: "operator_reference", value: "local" }],
    onboardingTermsText: "Review canonical records.",
    invitationHandoffMethod: "in person"
  });
  if (created.status !== "created") throw new Error("schema fixture bootstrap failed");
  const config = parseConfig({
    BOARDAGENT_ENV: "test",
    BOARDAGENT_DATABASE_URL: "postgresql://unused",
    BOARDAGENT_ORGANIZATION_ID: created.organizationId,
    BOARDAGENT_PUBLIC_BASE_URL: origin,
    BOARDAGENT_AUTHORIZATION_MODE: "builtin",
    BOARDAGENT_BLOB_ROOT: blobRoot,
    BOARDAGENT_DEV_MASTER_SECRET: "schema-test-synthetic-secret-material-is-long-enough"
  });
  const keys = await loadBoardAgentKeyMaterial(config);
  await withBootstrapTransaction(
    pool,
    (client) =>
      registerRuntimeKeysInTransaction(
        client,
        created.organizationId,
        runtimeKeyRegistrations(config, keys, () => uuidV7(Date.now(), randomBytes(10)))
      ),
    { assumeRole: "boardagent_migrator" }
  );
  return config;
}

async function retainedRows(pool: Pool) {
  const result: Record<string, unknown> = {};
  for (const table of [
    "schema_migrations",
    "members",
    "organization_role_assignments",
    "audit_events",
    "jobs"
  ])
    result[table] = (
      await pool.query(
        `select encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') as digest from ${table} r order by digest`
      )
    ).rows;
  return result;
}

const incompatible = [
  {
    name: "future migration",
    sql: "insert into schema_migrations(version,name,sha256,app_build) select max(version)+1,'future_schema.sql',repeat('f',64),'synthetic-future' from schema_migrations"
  },
  { name: "missing migration", sql: "delete from schema_migrations where version=2" },
  {
    name: "altered migration hash",
    sql: "update schema_migrations set sha256=repeat('f',64) where version=1"
  },
  {
    name: "altered migration name",
    sql: "update schema_migrations set name='0001_unrecognized.sql' where version=1"
  }
] as const;

async function applyIncompatibleHistory(pool: Pool, sql: string, directory: string): Promise<void> {
  if (sql !== incompatible[0].sql) {
    // Owner-only corruption of this disposable fixture; no runtime mutation authority.
    await pool.query(sql);
    return;
  }
  // A future candidate must now use the real migration/receipt path. Direct insertion
  // cannot construct valid post-bootstrap ledger history after SQL0126.
  const sourceDirectory = path.resolve(import.meta.dirname, "../../lib/db/migrations");
  const migrations = await loadMigrations(sourceDirectory);
  const futureDirectory = path.join(directory, "synthetic-future-migrations");
  await mkdir(futureDirectory);
  for (const migration of migrations)
    await copyFile(
      path.join(sourceDirectory, migration.name),
      path.join(futureDirectory, migration.name)
    );
  const nextVersion = migrations.at(-1)!.version + 1;
  await writeFile(
    path.join(futureDirectory, `${String(nextVersion).padStart(4, "0")}_synthetic_future.sql`),
    "select 1;\n"
  );
  await migrate(pool, futureDirectory, "synthetic-future");
}

describe("AC22 runtime schema compatibility", () => {
  it("runtime principals can read migration metadata but cannot insert, update, delete or truncate it", async () => {
    await withMigratedDatabase("schema-grants", async (pool) => {
      const before = await retainedRows(pool);
      const client = await pool.connect();
      try {
        for (const role of ["boardagent_server", "boardagent_worker"] as const) {
          for (const sql of [
            incompatible[0].sql,
            "update public.schema_migrations set sha256=sha256 where version=1",
            "delete from public.schema_migrations where version=1",
            "truncate public.schema_migrations"
          ]) {
            await client.query("begin");
            try {
              await client.query(`set local role ${role}`);
              expect(
                (await client.query("select count(*)::int as n from public.schema_migrations"))
                  .rows[0].n
              ).toBeGreaterThan(98);
              await expect(client.query(sql)).rejects.toMatchObject({ code: "42501" });
            } finally {
              await client.query("rollback");
            }
          }
        }
      } finally {
        client.release();
      }
      expect(await retainedRows(pool)).toEqual(before);
    });
  });
  for (const component of ["server", "worker"] as const)
    it.each(incompatible)(
      `${component} refuses $name before serving or claiming jobs, preserving all stored rows`,
      async ({ sql }) => {
        await withMigratedDatabase("runtime-schema", async (pool) => {
          const directory = await mkdtemp(path.join(tmpdir(), "ba-schema-runtime-"));
          try {
            const config = await fixture(pool, directory);
            await applyIncompatibleHistory(pool, sql, directory);
            const before = await retainedRows(pool);
            const started =
              component === "server"
                ? startBoardAgentServer(config, {
                    pool,
                    host: "127.0.0.1",
                    port: 0,
                    assumeRole: "boardagent_server"
                  })
                : startBoardAgentWorker(config, { pool, assumeRole: "boardagent_worker" });
            const [result] = await Promise.allSettled([started]);
            if (result!.status === "fulfilled") await result!.value.close();
            expect(result!.status).toBe("rejected");
            if (result!.status === "rejected")
              expect(result!.reason.message).toBe(
                "database schema does not match the application bundle"
              );
            expect(await retainedRows(pool)).toEqual(before);
          } finally {
            await rm(directory, { recursive: true, force: true });
          }
        });
      }
    );

  it("a running server withdraws readiness after incompatible history appears", async () => {
    await withMigratedDatabase("schema-readiness", async (pool) => {
      const directory = await mkdtemp(path.join(tmpdir(), "ba-schema-readiness-"));
      try {
        const config = await fixture(pool, directory);
        const running = await startBoardAgentServer(config, {
          pool,
          host: "127.0.0.1",
          port: 0,
          assumeRole: "boardagent_server"
        });
        try {
          const ready = () =>
            new Promise<{ status: number; body: string }>((resolve, reject) => {
              const req = request(
                {
                  hostname: "127.0.0.1",
                  port: running.port,
                  path: "/health/ready",
                  headers: {
                    host: "boardagent.schema.test",
                    "x-forwarded-proto": "https",
                    "x-forwarded-for": "198.51.100.17"
                  }
                },
                (response) => {
                  let body = "";
                  response.setEncoding("utf8");
                  response.on("data", (chunk: string) => {
                    body += chunk;
                  });
                  response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
                  response.on("error", reject);
                }
              );
              req.on("error", reject);
              req.end();
            });
          expect((await ready()).status).toBe(200);
          await applyIncompatibleHistory(pool, incompatible[0].sql, directory);
          const before = await retainedRows(pool);
          const refused = await ready();
          expect(refused.status).toBe(503);
          expect(refused.body).not.toContain("future_schema");
          expect(await retainedRows(pool)).toEqual(before);
        } finally {
          await running.close();
        }
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
  });
});
