import { describe, expect, it } from "vitest";

import { appendAuditEventsInTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("serializable request retries at the supported concurrency envelope", () => {
  it("does not replay privilege failures or read-committed serialization errors", async () => {
    await withMigratedDatabase("serialization-denial", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      for (const [isolation, code] of [
        ["serializable", "42501"],
        ["read committed", "40001"]
      ] as const) {
        let attempts = 0;
        await expect(
          withRequestTransaction(
            pool,
            actor.context,
            async (client) => {
              attempts += 1;
              await client.query(
                `do $$ begin raise exception using errcode='${code}', message='synthetic nonretryable abort'; end $$`
              );
            },
            { assumeRole: "boardagent_server", isolation }
          )
        ).rejects.toMatchObject({ code });
        expect(attempts).toBe(1);
      }
    });
  });

  it("replays a read-committed conflict only when the caller opts in, committing one event", async () => {
    // The resource-fetch outcome audit runs read committed after the response, beside
    // serializable writes that replay on conflict; without `retryConflicts` it was
    // always the deadlock victim under the 100-way T9 burst.
    await withMigratedDatabase("conflict-retry-opt-in", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      const before = await pool.query<{ count: string }>(
        "select count(*)::text as count from audit_events"
      );
      let attempts = 0;
      await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          attempts += 1;
          const isolation = await client.query<{ isolation: string }>(
            "select current_setting('transaction_isolation') as isolation"
          );
          expect(isolation.rows).toEqual([{ isolation: "read committed" }]);
          await appendAuditEventsInTransaction(client, [
            {
              organizationId: actor.organizationId,
              event: {
                eventId: testId(99_002),
                eventType: "context_read",
                actorMemberId: actor.memberId,
                actorClientId: actor.clientId,
                tokenJti: actor.tokenJti,
                entityType: "context",
                entityId: actor.memberId,
                boardId: actor.boardId,
                origin: "mcp",
                details: { purpose: "deadlock-victim-regression" },
                schemaVersion: 1
              }
            }
          ]);
          if (attempts <= 2) {
            await client.query(
              "do $$ begin raise exception using errcode='40P01', message='synthetic deadlock'; end $$"
            );
          }
        },
        { assumeRole: "boardagent_server", isolation: "read committed", retryConflicts: true }
      );
      expect(attempts).toBe(3);
      const after = await pool.query<{ count: string }>(
        "select count(*)::text as count from audit_events"
      );
      expect(BigInt(after.rows[0]!.count) - BigInt(before.rows[0]!.count)).toBe(1n);

      // Without the opt-in, a read-committed deadlock is not replayed.
      let plainAttempts = 0;
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            plainAttempts += 1;
            await client.query(
              "do $$ begin raise exception using errcode='40P01', message='synthetic deadlock'; end $$"
            );
          },
          { assumeRole: "boardagent_server", isolation: "read committed" }
        )
      ).rejects.toMatchObject({ code: "40P01" });
      expect(plainAttempts).toBe(1);
    });
  }, 30_000);

  it("survives thirteen PostgreSQL serialization aborts with one committed event and fresh local context", async () => {
    await withMigratedDatabase("serialization-retry", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      const before = await pool.query<{ count: string }>(
        "select count(*)::text as count from audit_events"
      );
      let attempts = 0;
      await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          attempts += 1;
          const context = await client.query<{ member: string; isolation: string }>(
            "select current_setting('boardagent.member_id') as member, current_setting('transaction_isolation') as isolation"
          );
          expect(context.rows).toEqual([{ member: actor.memberId, isolation: "serializable" }]);
          await appendAuditEventsInTransaction(client, [
            {
              organizationId: actor.organizationId,
              event: {
                eventId: testId(99_001),
                eventType: "context_read",
                actorMemberId: actor.memberId,
                actorClientId: actor.clientId,
                tokenJti: actor.tokenJti,
                entityType: "context",
                entityId: actor.memberId,
                boardId: actor.boardId,
                origin: "mcp",
                details: { purpose: "serialization-regression" },
                schemaVersion: 1
              }
            }
          ]);
          if (attempts <= 13) {
            await client.query(
              "do $$ begin raise exception using errcode='40001', message='synthetic serialization abort'; end $$"
            );
          }
        },
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(attempts).toBe(14);
      const after = await pool.query<{ count: string }>(
        "select count(*)::text as count from audit_events"
      );
      expect(BigInt(after.rows[0]!.count) - BigInt(before.rows[0]!.count)).toBe(1n);
    });
  }, 30_000);
});
