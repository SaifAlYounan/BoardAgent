import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";

import { migrate } from "../../lib/db/src/migrate.js";

describe("migration connection cleanup", () => {
  it.each(["none", "unlock", "reset-role"] as const)(
    "releases its checked-out connection after %s cleanup outcome",
    async (failure) => {
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-migration-cleanup-"));
      try {
        await writeFile(path.join(directory, "0001_synthetic.sql"), "select 1;\n");
        const cleanupError = new Error(`synthetic ${failure} failure`);
        const release = vi.fn();
        const query = vi.fn(async (sql: string) => {
          if (sql.includes("pg_try_advisory_lock")) return { rows: [{ acquired: true }] };
          if (
            (failure === "unlock" && sql.includes("pg_advisory_unlock")) ||
            (failure === "reset-role" && sql === "reset role")
          ) {
            throw cleanupError;
          }
          return { rows: [], rowCount: 0 };
        });
        const client = { query, release } as unknown as PoolClient;
        const pool = { connect: async () => client } as unknown as Pool;
        const result = migrate(pool, directory, "synthetic-cleanup-test", {
          assumeRole: "boardagent_migrator"
        });
        if (failure === "none") {
          await expect(result).resolves.toBe(1);
          expect(release).toHaveBeenCalledExactlyOnceWith();
        } else {
          await expect(result).rejects.toBe(cleanupError);
          expect(release).toHaveBeenCalledExactlyOnceWith(true);
        }
        expect(query.mock.calls.some(([sql]) => sql === "commit")).toBe(true);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  );
});
