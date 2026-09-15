import path from "node:path";
import type { PoolClient } from "pg";
import { loadMigrations, type MigrationFile } from "./migrate.js";

// The immutable application bundle is read once per process. Database history is
// checked anew on every binding/readiness call; configuration cannot widen it.
let bundledMigrations: Promise<readonly MigrationFile[]> | undefined;

/** Read-only compatibility gate. Never migrate, repair history, or grant authority. */
export async function assertBundledSchemaInTransaction(client: PoolClient): Promise<void> {
  bundledMigrations ??= loadMigrations(path.resolve(import.meta.dirname, "../migrations"));
  const expected = await bundledMigrations;
  const applied = await client.query<{ version: number; name: string; sha256: string }>(
    "select version,name,sha256 from public.schema_migrations order by version"
  );
  if (
    expected.length === 0 ||
    applied.rows.length !== expected.length ||
    expected.some((migration, index) => {
      const row = applied.rows[index];
      return (
        row?.version !== migration.version ||
        row.name !== migration.name ||
        row.sha256 !== migration.sha256
      );
    })
  ) {
    throw new Error("database schema does not match the application bundle");
  }
}
