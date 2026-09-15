import { randomBytes } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";

import { migrate } from "../../lib/db/src/migrate.js";
import { dropClosedTestDatabase } from "./drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";

export async function withMigratedDatabase<T>(
  label: string,
  run: (pool: Pool) => Promise<T>,
  maximumConnections = 8
): Promise<T> {
  const safeLabel = label
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/gu, "_")
    .slice(0, 20);
  const database = `boardagent_${safeLabel}_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);

  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: maximumConnections });
  let passed = false;
  try {
    await migrate(pool, MIGRATIONS, `${safeLabel}-test`);
    const result = await run(pool);
    passed = true;
    return result;
  } finally {
    if (!passed) process.stderr.write(`Preserved failed migrated fixture: ${database}\n`);
    try {
      await pool.end();
      if (passed) await dropClosedTestDatabase(admin, database);
    } finally {
      await admin.end();
    }
  }
}
