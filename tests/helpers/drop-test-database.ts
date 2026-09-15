import type { Pool } from "pg";

/** Wait for client sockets; ordinary DROP handles autovacuum. Never force live clients. */
export async function dropClosedTestDatabase(admin: Pool, database: string): Promise<void> {
  if (!/^boardagent_[a-z0-9_]+$/u.test(database)) throw new Error("refusing non-fixture database");
  const deadline = Date.now() + 5_000;
  while (true) {
    const sessions = await admin.query<{ backend_type: string | null }>(
      "select backend_type from pg_stat_activity where datname=$1",
      [database]
    );
    const blocking = sessions.rows.filter(
      ({ backend_type }) => backend_type !== "autovacuum worker"
    );
    if (blocking.length === 0) break;
    if (Date.now() >= deadline)
      throw new Error(
        `test database still has connections after pool shutdown: ${blocking
          .map(({ backend_type }) => backend_type ?? "unknown")
          .toSorted()
          .join(", ")}`
      );
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  await admin.query(`drop database "${database}"`);
}
