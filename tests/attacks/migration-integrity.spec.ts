import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { loadMigrations, migrate } from "../../lib/db/src/migrate.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const MIGRATION_LOCK = "4242486065882889";

describe("TH-38 migration history integrity", () => {
  it("refuses gaps, checksum edits, incompatible targets, and a contended advisory lock", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-migration-attack-"));
    try {
      await writeFile(path.join(directory, "0001_first.sql"), "select 1;\n", "utf8");
      await writeFile(path.join(directory, "0003_gap.sql"), "select 3;\n", "utf8");
      await expect(loadMigrations(directory)).rejects.toThrow("contiguous from 0001");
    } finally {
      await rm(directory, { recursive: true });
    }

    await withMigratedDatabase("migration_integrity", async (pool) => {
      const last = await pool.query<{ sha256: string; version: number }>(
        "select version,sha256 from schema_migrations order by version desc limit 1"
      );
      const row = last.rows[0];
      if (!row) throw new Error("migration fixture has no ledger row");
      await pool.query("update schema_migrations set sha256=$1 where version=$2", [
        "0".repeat(64),
        row.version
      ]);
      await expect(migrate(pool, MIGRATIONS, "tampered-history-check")).rejects.toThrow(
        `migration history mismatch at ${String(row.version)}`
      );
      await pool.query("update schema_migrations set sha256=$1 where version=$2", [
        row.sha256,
        row.version
      ]);
      await expect(
        migrate(pool, MIGRATIONS, "incompatible-binary", {
          supportedSchemaRange: { minimum: 1, maximum: row.version - 1 }
        })
      ).rejects.toThrow("does not support bundled target schema");

      const holder = await pool.connect();
      try {
        await holder.query("select pg_advisory_lock($1)", [MIGRATION_LOCK]);
        await expect(
          migrate(pool, MIGRATIONS, "contended-migration", { lockTimeoutMs: 20 })
        ).rejects.toThrow("timed out acquiring migration advisory lock");
      } finally {
        await holder.query("select pg_advisory_unlock($1)", [MIGRATION_LOCK]);
        holder.release();
      }
    });
  });
});
