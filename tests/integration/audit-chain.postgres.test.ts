import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { EVENT_IDS } from "../../lib/contracts/src/index.js";
import { migrate } from "../../lib/db/src/index.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
const hash = (byte: number): Buffer => Buffer.alloc(32, byte);

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_audit_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "audit-chain-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function insertEvent(
  pool: Pool,
  organizationId: string,
  eventId: string,
  sequence: number,
  previousHash: Buffer,
  eventHash: Buffer,
  eventType = "context_read"
): Promise<void> {
  await pool.query(
    `insert into audit_events(
       id,sequence,organization_id,event_type,schema_version,object_type,object_id,
       canonical_payload,previous_event_sha256,event_sha256
     ) values ($1,$2,$3,$4,'boardagent.audit-event.v1','context',$1,$5,$6,$7)`,
    [eventId, sequence, organizationId, eventType, Buffer.from("{}"), previousHash, eventHash]
  );
}

describe("PostgreSQL audit registry and chain serialization", () => {
  it("contains exactly the registry's 141 event names in registry order", async () => {
    await withDatabase(async (pool) => {
      const result = await pool.query<{ definition: string }>(
        `select pg_get_constraintdef(oid) as definition
           from pg_constraint
          where conrelid = 'audit_events'::regclass and contype = 'c'
            and pg_get_constraintdef(oid) like '%event_type%'`
      );
      expect(result.rows).toHaveLength(1);
      const names = [
        ...(result.rows[0]?.definition.matchAll(/'([a-z][a-z0-9_]+)'::text/gu) ?? [])
      ].map((match) => match[1]);
      expect(names).toEqual([...EVENT_IDS]);
    });
  });

  it("serializes concurrent appends and refuses gaps, wrong links, unknown events, and mutation", async () => {
    await withDatabase(async (pool) => {
      const organizationId = id(1);
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
        [organizationId]
      );
      await insertEvent(pool, organizationId, id(2), 1, hash(0), hash(1));
      await expect(insertEvent(pool, organizationId, id(3), 3, hash(1), hash(3))).rejects.toThrow(
        /sequence must be contiguous/u
      );
      await expect(insertEvent(pool, organizationId, id(3), 2, hash(9), hash(3))).rejects.toThrow(
        /previous hash mismatch/u
      );

      const race = await Promise.allSettled([
        insertEvent(pool, organizationId, id(3), 2, hash(1), hash(2)),
        insertEvent(pool, organizationId, id(4), 2, hash(1), hash(4))
      ]);
      expect(race.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(race.filter(({ status }) => status === "rejected")).toHaveLength(1);
      const head = await pool.query<{ last_event_sha256: Buffer; last_sequence: string }>(
        "select last_sequence,last_event_sha256 from audit_chain_head where singleton_key"
      );
      expect(head.rows[0]?.last_sequence).toBe("2");
      expect([hash(2).toString("hex"), hash(4).toString("hex")]).toContain(
        head.rows[0]?.last_event_sha256.toString("hex")
      );

      await expect(
        insertEvent(
          pool,
          organizationId,
          id(5),
          3,
          head.rows[0]!.last_event_sha256,
          hash(5),
          "not_registered"
        )
      ).rejects.toThrow();
      const unchanged = await pool.query<{ last_sequence: string }>(
        "select last_sequence from audit_chain_head where singleton_key"
      );
      expect(unchanged.rows[0]?.last_sequence).toBe("2");
      await expect(
        pool.query("update audit_events set object_type='tampered' where sequence=1")
      ).rejects.toThrow(/immutable evidence/u);
    });
  });
});
