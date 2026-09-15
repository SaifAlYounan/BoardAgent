import type { Pool } from "pg";
import { afterEach, describe, expect, it, vi } from "vitest";

import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

afterEach(() => vi.useRealTimers());

function fixture(backends: () => readonly (string | null)[]) {
  const commands: string[] = [];
  const pool = {
    query: vi.fn(async (sql: string) => {
      commands.push(sql);
      if (/^select/iu.test(sql)) {
        const types = backends();
        // Both representations describe the same PostgreSQL activity snapshot, so
        // this also exercises the pre-fix count-based cleanup implementation.
        return /count\(\*\)/iu.test(sql)
          ? { rows: [{ count: String(types.length) }] }
          : { rows: types.map((backend_type) => ({ backend_type })) };
      }
      return { rows: [] };
    })
  } as unknown as Pool;
  return { pool, commands };
}

describe("owned test database cleanup", () => {
  it("leaves autovacuum shutdown to ordinary PostgreSQL DROP without forcing clients", async () => {
    vi.useFakeTimers();
    const { pool, commands } = fixture(() => ["autovacuum worker"]);
    const result = dropClosedTestDatabase(pool, "boardagent_cleanup_vacuum").then(
      () => ({ success: true }),
      (error: unknown) => ({ error })
    );
    await vi.advanceTimersByTimeAsync(5_020);
    expect(await result).toEqual({ success: true });
    expect(commands.filter((sql) => /^drop/iu.test(sql))).toEqual([
      'drop database "boardagent_cleanup_vacuum"'
    ]);
    expect(commands.join("\n")).not.toMatch(/force|terminate_backend/iu);
  });

  it.each(["client backend", "walsender", "unknown worker", null])(
    "refuses deletion while a %s remains, even alongside autovacuum",
    async (backend) => {
      vi.useFakeTimers();
      const { pool, commands } = fixture(() => ["autovacuum worker", backend]);
      const result = expect(
        dropClosedTestDatabase(pool, "boardagent_cleanup_busy")
      ).rejects.toThrow(/test database still has connections after pool shutdown/u);
      await vi.advanceTimersByTimeAsync(5_020);
      await result;
      expect(commands.some((sql) => /^drop/iu.test(sql))).toBe(false);
      expect(commands.join("\n")).not.toMatch(/force|terminate_backend/iu);
    }
  );

  it("waits for a closing client before dropping its owned database", async () => {
    vi.useFakeTimers();
    let connected = true;
    const { pool, commands } = fixture(() => (connected ? ["client backend"] : []));
    const pending = dropClosedTestDatabase(pool, "boardagent_cleanup_closing");
    await vi.advanceTimersByTimeAsync(40);
    expect(commands.some((sql) => /^drop/iu.test(sql))).toBe(false);
    connected = false;
    await vi.advanceTimersByTimeAsync(20);
    await pending;
    expect(commands.filter((sql) => /^drop/iu.test(sql))).toEqual([
      'drop database "boardagent_cleanup_closing"'
    ]);
  });

  it("rejects names outside the fixture namespace before querying", async () => {
    const { pool, commands } = fixture(() => []);
    await expect(dropClosedTestDatabase(pool, "production")).rejects.toThrow(
      "refusing non-fixture database"
    );
    expect(commands).toEqual([]);
  });
});
