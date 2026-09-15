import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { verifyChain } from "../../lib/audit/src/index.js";
import {
  appendAuditEventsInTransaction,
  migrate,
  withRequestTransaction,
  type AuditAppendInput
} from "../../lib/db/src/index.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_audit_repository_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "audit-repository-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

describe("serialized audit transaction repository", () => {
  it("allocates canonical contiguous events and rolls failed transactions back for retry", async () => {
    await withDatabase(async (pool) => {
      const organizationId = id(1);
      const boardId = id(2);
      const memberId = id(3);
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
        [organizationId]
      );
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Member','Member','active')",
        [memberId, organizationId]
      );
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'board','Board','UTC')",
        [boardId, organizationId]
      );

      const context = {
        organizationId,
        memberId,
        clientId: id(4),
        tokenJti: id(5),
        boardIds: [boardId]
      };
      const input = (suffix: number): AuditAppendInput => ({
        organizationId,
        event: {
          eventId: id(suffix),
          eventType: "context_read",
          actorMemberId: memberId,
          actorClientId: null,
          tokenJti: context.tokenJti,
          entityType: "context",
          entityId: id(100 + suffix),
          boardId,
          origin: "mcp",
          details: { requestId: id(200 + suffix), result: "authorized" },
          schemaVersion: 1
        }
      });

      const unmanaged = await pool.connect();
      try {
        await expect(appendAuditEventsInTransaction(unmanaged, [input(9)])).rejects.toThrow(
          "managed request transaction"
        );
      } finally {
        unmanaged.release();
      }

      const first = await withRequestTransaction(
        pool,
        context,
        (client) => appendAuditEventsInTransaction(client, [input(10), input(11)]),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(first.map(({ sequence }) => sequence)).toEqual([1n, 2n]);
      expect(verifyChain(first)).toEqual({
        valid: true,
        count: 2n,
        headHash: first[1]?.eventHash
      });

      const raced = await Promise.all([
        withRequestTransaction(
          pool,
          context,
          (client) => appendAuditEventsInTransaction(client, [input(12)]),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        ),
        withRequestTransaction(
          pool,
          context,
          (client) => appendAuditEventsInTransaction(client, [input(13)]),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ]);
      expect(
        raced
          .flat()
          .map(({ sequence }) => sequence)
          .toSorted()
      ).toEqual([3n, 4n]);

      await expect(
        withRequestTransaction(
          pool,
          context,
          async (client) => {
            await appendAuditEventsInTransaction(client, [input(14)]);
            throw new Error("synthetic crash after append");
          },
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toThrow("synthetic crash");
      const afterCrash = await pool.query<{ count: string; last_sequence: string }>(
        `select count(*)::text as count,
                (select last_sequence::text from audit_chain_head where singleton_key) as last_sequence
           from audit_events`
      );
      expect(afterCrash.rows[0]).toEqual({ count: "4", last_sequence: "4" });

      const retried = await withRequestTransaction(
        pool,
        context,
        (client) => appendAuditEventsInTransaction(client, [input(14)]),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(retried[0]?.sequence).toBe(5n);

      const stored = await pool.query<{
        canonical_payload: Buffer;
        event_sha256: Buffer;
        previous_event_sha256: Buffer;
        sequence: string;
      }>(
        `select sequence::text, canonical_payload, previous_event_sha256, event_sha256
           from audit_events
          order by sequence`
      );
      expect(stored.rows).toHaveLength(5);
      for (const [index, row] of stored.rows.entries()) {
        const returned = [...first, ...raced.flat(), ...retried].find(
          ({ sequence }) => sequence === BigInt(row.sequence)
        );
        expect(returned).toBeDefined();
        expect(JSON.parse(row.canonical_payload.toString("utf8"))).toEqual(
          expect.objectContaining({ eventId: returned?.eventId })
        );
        expect(row.previous_event_sha256.toString("hex")).toBe(returned?.previousHash);
        expect(row.event_sha256.toString("hex")).toBe(returned?.eventHash);
        if (index === 0) expect(row.previous_event_sha256.equals(Buffer.alloc(32))).toBe(true);
      }
    });
  });
});
