import type { Query } from "pg";
import { describe, expect, it } from "vitest";
import {
  appendAuditEventsInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("coherent audit verification during a concurrent append", () => {
  it("reports the first tampered link and drains the stream before another transaction query", async () => {
    await withUnseededWorker("audit-stream-tamper", async ({ pool, organizationId }) => {
      for (let index = 0; index < 3; index++)
        await withWorkerTransaction(
          pool,
          (client) =>
            appendAuditEventsInTransaction(client, [
              {
                organizationId,
                event: {
                  eventId: newWorkerTestId(),
                  eventType: "context_read",
                  actorMemberId: null,
                  actorClientId: null,
                  tokenJti: null,
                  entityType: "context",
                  entityId: newWorkerTestId(),
                  boardId: null,
                  origin: "worker",
                  details: { synthetic: true, purpose: "stream-drain-fixture" },
                  schemaVersion: 1
                }
              }
            ]),
          { assumeRole: "boardagent_worker" }
        );
      const setup = await pool.connect();
      try {
        await setup.query("begin");
        await setup.query("set local session_replication_role=replica");
        const changed = await setup.query(
          "update public.audit_events set previous_event_sha256=decode(repeat('ab',32),'hex') where sequence=2"
        );
        expect(changed.rowCount).toBe(1);
        await setup.query("commit");
      } finally {
        await setup.query("rollback");
        setup.release();
      }
      await withWorkerTransaction(
        pool,
        async (client) => {
          expect(await verifyPersistedAuditEvidence(client)).toEqual({
            valid: false,
            ready: false,
            reason: "previous_hash_mismatch",
            firstBreakSequence: "2"
          });
          expect((await client.query("select 1 as usable")).rows).toEqual([{ usable: 1 }]);
        },
        { assumeRole: "boardagent_worker" }
      );
    });
  }, 20_000);

  it("verifies one captured head instead of mixing it with later committed events", async () => {
    await withUnseededWorker("audit-snapshot", async ({ pool, organizationId }) => {
      const before = (await pool.query("select last_sequence::text from public.audit_chain_head"))
        .rows[0]!.last_sequence as string;
      const concurrent: { pending?: Promise<unknown> } = {};
      const append = () => {
        concurrent.pending ??= withWorkerTransaction(
          pool,
          (client) =>
            appendAuditEventsInTransaction(client, [
              {
                organizationId,
                event: {
                  eventId: newWorkerTestId(),
                  eventType: "context_read",
                  actorMemberId: null,
                  actorClientId: null,
                  tokenJti: null,
                  entityType: "context",
                  entityId: newWorkerTestId(),
                  boardId: null,
                  origin: "worker",
                  details: { synthetic: true, purpose: "verification-snapshot-concurrency" },
                  schemaVersion: 1
                }
              }
            ]),
          { assumeRole: "boardagent_worker" }
        );
        void concurrent.pending.catch(() => undefined);
        return concurrent.pending;
      };
      const result = await withWorkerTransaction(
        pool,
        async (client) => {
          const observed = new Proxy(client, {
            get(target, key) {
              if (key === "query")
                return (...args: unknown[]) => {
                  const query = args[0];
                  // Deterministically expose the old multi-query race immediately after
                  // its head read. For streaming queries, append once the first row arrives.
                  if (
                    typeof query === "string" &&
                    query.includes(
                      "select last_sequence::text,last_event_sha256 from public.audit_chain_head"
                    )
                  ) {
                    return Promise.resolve(Reflect.apply(target.query, target, args)).then(
                      async (rows) => {
                        await append();
                        return rows;
                      }
                    );
                  }
                  if (
                    typeof query === "object" &&
                    query !== null &&
                    "once" in query &&
                    typeof query.once === "function"
                  ) {
                    (query as Query).once("row", () => {
                      void append();
                    });
                  }
                  return Reflect.apply(target.query, target, args);
                };
              const value: unknown = Reflect.get(target, key);
              return typeof value === "function" ? value.bind(target) : value;
            }
          });
          return verifyPersistedAuditEvidence(observed);
        },
        { assumeRole: "boardagent_worker" }
      );
      expect(concurrent.pending).toBeDefined();
      await concurrent.pending;
      expect(result).toMatchObject({ valid: true, ready: true, eventCount: before });
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({ valid: true, ready: true, eventCount: (BigInt(before) + 1n).toString(10) });
    });
  }, 20_000);
});
