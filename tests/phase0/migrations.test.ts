import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { loadMigrations } from "../../lib/db/src/index.js";

describe("migration ledger inputs", () => {
  it("loads contiguous migrations with exact SHA-256", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-migrations-"));
    await writeFile(path.join(directory, "0001_baseline.sql"), "select 1;\n");
    await writeFile(path.join(directory, "0002_next.sql"), "select 2;\n");
    const migrations = await loadMigrations(directory);
    expect(migrations.map((entry) => entry.version)).toEqual([1, 2]);
    expect(migrations.every((entry) => /^[0-9a-f]{64}$/u.test(entry.sha256))).toBe(true);
  });

  it("refuses gaps and reordered history", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-migrations-gap-"));
    await writeFile(path.join(directory, "0002_not_first.sql"), "select 2;\n");
    await expect(loadMigrations(directory)).rejects.toThrow("contiguous");
  });
});
