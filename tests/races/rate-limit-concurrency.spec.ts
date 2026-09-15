import { createHash } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { PgRateLimiter } from "../../artifacts/server/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_rate_limit_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 24 });
  try {
    await migrate(pool, MIGRATIONS, "rate-limit-race-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}"`);
    await admin.end();
  }
}

describe("trusted persistent rate-limit buckets", () => {
  it("atomically caps concurrent attempts without storing the trusted subject", async () => {
    await withDatabase(async (pool) => {
      const organizationId = testId(63_001);
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
        [organizationId]
      );
      const trustedSubject = "198.51.100.0/24";
      const limiter = new PgRateLimiter(pool, {
        hmacKey: Buffer.alloc(32, 0x63),
        assumeRole: "boardagent_server"
      });
      const attempts = await Promise.all(
        Array.from({ length: 20 }, () =>
          limiter.consumeIdentity(organizationId, [
            {
              bucketClass: "ip",
              trustedSubject,
              windowSeconds: 60,
              maxRequests: 5,
              blockSeconds: 60
            }
          ])
        )
      );
      expect(attempts.filter(({ allowed }) => allowed)).toHaveLength(5);
      expect(attempts.filter(({ allowed }) => !allowed)).toHaveLength(15);
      expect(
        attempts
          .filter(({ allowed }) => !allowed)
          .every(({ retryAfterSeconds }) => retryAfterSeconds > 0)
      ).toBe(true);

      const persisted = await pool.query<{
        request_count: number;
        subject_sha256: Buffer;
      }>("select request_count,subject_sha256 from rate_limit_buckets");
      expect(persisted.rows).toHaveLength(1);
      expect(persisted.rows[0]?.request_count).toBe(6);
      expect(persisted.rows[0]?.subject_sha256).toHaveLength(32);
      expect(
        persisted.rows[0]?.subject_sha256.equals(
          createHash("sha256").update(trustedSubject).digest()
        )
      ).toBe(false);

      const client = await pool.connect();
      try {
        await client.query("begin");
        await client.query("set local role boardagent_server");
        await client.query("select set_config('boardagent.transaction_scope','identity',true)");
        await expect(
          client.query(
            `insert into rate_limit_buckets(
               bucket_class,subject_sha256,window_started_at,window_seconds,request_count
             ) values ('ip',$1,transaction_timestamp(),60,1)`,
            [Buffer.alloc(32, 1)]
          )
        ).rejects.toMatchObject({ code: "42501" });
        await client.query("rollback");
      } finally {
        client.release();
      }
    });
  });
});
