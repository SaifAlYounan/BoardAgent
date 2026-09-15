import { mkdtemp, mkdir, copyFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Pool } from "pg";
import { sha256Hex } from "../../lib/contracts/src/index.js";
import { describe, expect, it } from "vitest";
import { loadMigrations, migrate } from "../../lib/db/src/migrate.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";
import { assertAdministrativeCatalog } from "../helpers/administrative-catalog.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const TABLES = [
  "administrative_authority_changes",
  "company_admin_proposals",
  "member_admin_delegations",
  "recovery_registration_grants"
];

describe("AC19/AC21 administrative authority schema and upgrade", () => {
  it("preserves exact committed baseline and additive migration bytes", async () => {
    const migrations = await loadMigrations(MIGRATIONS);
    const digest = (n: number) =>
      sha256Hex(
        migrations
          .slice(0, n)
          .map((m) => `${m.name}\t${m.sha256}\n`)
          .join("")
      );
    // Independently read from Git objects, not generated from the working tree:
    // ae1d163a8e186b77832aadff23404652837b951e (original86),
    // 636c47893805cbf24e944f49e86420b79146525c (committed97).
    expect(digest(86)).toBe("cb29b87204b67d659a4681a4ce4eb81ca110097ac44d8a40e73c503646c456d7");
    expect(digest(97)).toBe("000c5fc00fda094f36763d3def364be1e8a64254e45bed7dca1a57c3ea7b7bac");
  });
  it("upgrades the exact original migration set without rewriting it and isolates new authority tables", async () => {
    const database = `boardagent_admin_upgrade_${String(process.pid)}`;
    const adminUrl = new URL(BASE_URL);
    adminUrl.pathname = "/postgres";
    const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
    await admin.query(`create database "${database}"`);
    const url = new URL(BASE_URL);
    url.pathname = `/${database}`;
    const pool = new Pool({ connectionString: url.toString(), max: 2 });
    const directory = await mkdtemp(path.join(os.tmpdir(), "ba-admin-upgrade-"));
    try {
      const old = path.join(directory, "original");
      await mkdir(old);
      const migrations = await loadMigrations(MIGRATIONS);
      for (const migration of migrations.slice(0, 86)) {
        await copyFile(path.join(MIGRATIONS, migration.name), path.join(old, migration.name));
      }
      expect(await migrate(pool, old, "administrative-original-fixture")).toBe(86);
      const before = await pool.query(
        "select version,name,sha256 from schema_migrations order by version"
      );
      await migrate(pool, MIGRATIONS, "administrative-upgrade-fixture");
      const after = await pool.query(
        "select version,name,sha256 from schema_migrations where version<=86 order by version"
      );
      expect(after.rows).toEqual(before.rows);
      await assertAdministrativeCatalog(pool);
      const tables = await pool.query<{
        relname: string;
        relrowsecurity: boolean;
        relforcerowsecurity: boolean;
      }>(
        "select relname,relrowsecurity,relforcerowsecurity from pg_class where relnamespace='public'::regnamespace and relname=any($1) order by relname",
        [TABLES]
      );
      expect(tables.rows.map((row) => row.relname)).toEqual(TABLES);
      for (const table of tables.rows) {
        expect(table.relrowsecurity).toBe(true);
        expect(table.relforcerowsecurity).toBe(true);
        for (const role of ["boardagent_server", "boardagent_worker"]) {
          const privileges = await pool.query<{ allowed: boolean }>(
            "select has_table_privilege($1,$2,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') as allowed",
            [role, table.relname]
          );
          expect(privileges.rows[0]?.allowed, `${role} direct ${table.relname}`).toBe(false);
        }
        const backup = await pool.query<{ allowed: boolean }>(
          "select has_table_privilege('boardagent_backup',$1,'SELECT') as allowed",
          [table.relname]
        );
        expect(backup.rows[0]?.allowed).toBe(true);
      }
    } finally {
      await pool.end();
      await dropClosedTestDatabase(admin, database);
      await admin.end();
      await rm(directory, { recursive: true, force: true });
    }
  });
});
