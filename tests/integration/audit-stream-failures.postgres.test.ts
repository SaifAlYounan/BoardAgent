import { Pool, Query, type QueryResult } from "pg";
import { describe, expect, it } from "vitest";
import { AuditEventBodySchema, eventHash } from "../../lib/audit/src/index.js";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";
import { seedValidAuditEnvelope } from "../helpers/valid-audit-envelope.js";

import { streamAuditEvidence } from "../../lib/db/src/transactions/audit-evidence-stream.js";

describe("audit stream failure boundaries", () => {
  it("keeps one snapshot across batches while a real append commits between fetches", async () => {
    await withUnseededWorker("audit-batch-snapshot", async ({ pool, config, organizationId }) => {
      await seedValidAuditEnvelope(pool, config, 3000);
      const batches: number[] = [];
      let appended = false;
      const result = await withWorkerTransaction(
        pool,
        async (client) => {
          const observed = new Proxy(client, {
            get(target, key) {
              if (key === "query")
                return (...args: unknown[]) => {
                  const query = args[0];
                  if (query instanceof Query) {
                    let count = 0;
                    query.on("row", () => {
                      count++;
                    });
                    query.on("end", (result: QueryResult) => {
                      batches.push(count);
                      expect(result.rows).toEqual([]);
                    });
                    if (batches.length === 1 && !appended) {
                      appended = true;
                      // This is a real, committed worker append, deliberately completed
                      // before the next page is submitted on the verification connection.
                      void withWorkerTransaction(
                        pool,
                        (writer) =>
                          appendAuditEventsInTransaction(writer, [
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
                                details: { synthetic: true, purpose: "between-audit-batches" },
                                schemaVersion: 1
                              }
                            }
                          ]),
                        { assumeRole: "boardagent_worker" }
                      ).then(
                        () => Reflect.apply(target.query, target, args),
                        (error: unknown) => query.emit("error", error)
                      );
                      return query;
                    }
                  }
                  return Reflect.apply(target.query, target, args);
                };
              const value: unknown = Reflect.get(target, key);
              return typeof value === "function" ? value.bind(target) : value;
            }
          });
          const verified = await verifyPersistedAuditEvidence(observed);
          expect(
            (await client.query("select name from pg_cursors where name like 'audit_evidence_%'"))
              .rows
          ).toEqual([]);
          expect((await client.query("show statement_timeout")).rows).toEqual([
            { statement_timeout: "30s" }
          ]);
          return verified;
        },
        { assumeRole: "boardagent_worker" }
      );
      expect(appended).toBe(true);
      expect(batches.length).toBeGreaterThan(3);
      expect(batches.every((count) => count <= 1000)).toBe(true);
      expect(result).toMatchObject({ valid: true, ready: true, eventCount: "3000" });
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({ valid: true, ready: true, eventCount: "3001" });
    });
  }, 20_000);

  it("drains and closes every batch after a consumer throws, preserving even a falsy first failure", async () => {
    await withUnseededWorker("audit-consumer-failure", async ({ pool, config }) => {
      await seedValidAuditEnvelope(pool, config, 3000);
      await withWorkerTransaction(
        pool,
        async (client) => {
          let calls = 0;
          const outcome = await streamAuditEvidence(client, () => {
            calls++;
            throw null; // A rejected value need not be an Error or truthy.
          }).then(
            () => ({ resolved: true }),
            (error: unknown) => ({ error })
          );
          expect(outcome).toEqual({ error: null });
          expect(calls).toBe(1);
          expect(
            (await client.query("select name from pg_cursors where name like 'audit_evidence_%'"))
              .rows
          ).toEqual([]);
          expect(await verifyPersistedAuditEvidence(client)).toMatchObject({
            valid: true,
            eventCount: "3000"
          });
        },
        { assumeRole: "boardagent_worker" }
      );
    });
  }, 20_000);

  it("refuses driver query_timeout before it can enable accumulating callbacks", async () => {
    await withUnseededWorker("audit-driver-timeout", async ({ pool, config }) => {
      await seedValidAuditEnvelope(pool, config, 1000);
      const timed = new Pool({ ...pool.options, max: 1, query_timeout: 10_000 });
      try {
        await expect(
          withWorkerTransaction(timed, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).rejects.toThrow("audit evidence streaming does not support driver query_timeout");
        expect((await timed.query("select 1 as usable")).rows).toEqual([{ usable: 1 }]);
      } finally {
        await timed.end();
      }
    });
  }, 20_000);

  it("drains all rows after an early malformed payload and retains its first failure", async () => {
    await withUnseededWorker("audit-payload-drain", async ({ pool, config }) => {
      await seedValidAuditEnvelope(pool, config, 1000);
      const fixture = await pool.connect();
      try {
        await fixture.query("begin");
        await fixture.query("set local session_replication_role=replica");
        await fixture.query(
          "update public.audit_events set canonical_payload=convert_to('{broken','UTF8') where sequence=2"
        );
        await fixture.query(
          "update public.audit_events set previous_event_sha256=decode(repeat('ab',32),'hex') where sequence=3"
        );
        await fixture.query("commit");
      } finally {
        await fixture.query("rollback");
        fixture.release();
      }
      let eventsSeen = 0;
      await withWorkerTransaction(
        pool,
        async (client) => {
          const observed = new Proxy(client, {
            get(target, key) {
              if (key === "query")
                return (...args: unknown[]) => {
                  const query = args[0];
                  if (typeof query === "object" && query !== null && "on" in query)
                    (query as Query).on("row", (row: { stream_kind: number }) => {
                      if (row.stream_kind === 3) eventsSeen++;
                    });
                  return Reflect.apply(target.query, target, args);
                };
              const value: unknown = Reflect.get(target, key);
              return typeof value === "function" ? value.bind(target) : value;
            }
          });
          expect(await verifyPersistedAuditEvidence(observed)).toEqual({
            valid: false,
            ready: false,
            reason: "event_schema_invalid",
            firstBreakSequence: "2"
          });
          expect(eventsSeen).toBe(1000);
          expect((await client.query("select 1 as usable")).rows).toEqual([{ usable: 1 }]);
        },
        { assumeRole: "boardagent_worker" }
      );
    });
  }, 20_000);

  it("rolls back a timeout after a cursor page was delivered and removes its pooled cursor", async () => {
    await withUnseededWorker("audit-page-timeout", async ({ pool, config }) => {
      await seedValidAuditEnvelope(pool, config, 3000);
      const single = new Pool({ ...pool.options, max: 1 });
      let pages = 0;
      try {
        const pid = (await single.query("select pg_backend_pid() as pid")).rows[0]?.pid;
        await expect(
          withWorkerTransaction(
            single,
            (client) => {
              const observed = new Proxy(client, {
                get(target, key) {
                  if (key === "query")
                    return (...args: unknown[]) => {
                      const query = args[0];
                      if (query instanceof Query) {
                        if (pages === 1) {
                          void target.query("set local statement_timeout='1ms'").then(
                            () => Reflect.apply(target.query, target, args),
                            (error: unknown) => query.emit("error", error)
                          );
                          return query;
                        }
                        query.once("end", () => {
                          pages++;
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
          )
        ).rejects.toMatchObject({ code: "57014" });
        expect(pages).toBe(1);
        expect((await single.query("select pg_backend_pid() as pid")).rows).toEqual([{ pid }]);
        expect(
          (await single.query("select name from pg_cursors where name like 'audit_evidence_%'"))
            .rows
        ).toEqual([]);
        expect(
          await withWorkerTransaction(single, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({ valid: true, ready: true, eventCount: "3000" });
      } finally {
        await single.end();
      }
    });
  }, 20_000);

  it("rolls back an actual SQL timeout and safely reuses the same pooled connection", async () => {
    await withUnseededWorker("audit-sql-timeout", async ({ pool, config }) => {
      await seedValidAuditEnvelope(pool, config, 1000);
      const single = new Pool({ ...pool.options, max: 1 });
      let entered = false;
      try {
        const before = (await single.query("select pg_backend_pid() as pid")).rows[0]?.pid;
        await expect(
          withWorkerTransaction(
            single,
            (client) => {
              entered = true;
              return verifyPersistedAuditEvidence(client);
            },
            { assumeRole: "boardagent_worker", statementTimeoutMs: 1 }
          )
        ).rejects.toMatchObject({ code: "57014" });
        expect(entered).toBe(true);
        expect(
          (
            await single.query(
              "select pg_backend_pid() as pid, txid_current_if_assigned() as transaction, current_setting('boardagent.transaction_scope',true) as scope"
            )
          ).rows
        ).toEqual([{ pid: before, transaction: null, scope: "" }]);
        expect(
          await withWorkerTransaction(single, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({ valid: true, ready: true, eventCount: "1000" });
      } finally {
        await single.end();
      }
    });
  }, 20_000);

  it("rejects a wrong signed-event reference even when the event chain and checkpoint signature are valid", async () => {
    await withUnseededWorker("audit-signed-reference", async ({ pool, config }) => {
      await seedValidAuditEnvelope(pool, config, 1000);
      const fixture = await pool.connect();
      try {
        await fixture.query("begin");
        await fixture.query("set local session_replication_role=replica");
        const row = (
          await fixture.query(
            "select canonical_payload,previous_event_sha256 from public.audit_events where sequence=1000"
          )
        ).rows[0]!;
        const body = AuditEventBodySchema.parse(
          JSON.parse((row.canonical_payload as Buffer).toString("utf8"))
        );
        const changed = { ...body, details: { ...body.details, manifestSha256: "a".repeat(64) } };
        const hash = Buffer.from(
          eventHash(1000n, (row.previous_event_sha256 as Buffer).toString("hex"), changed),
          "hex"
        );
        // Explicit hostile fixture: change only the uncovered signed-reference event,
        // rebuild its link/head, and retain the real checkpoint/signature over1..999.
        await fixture.query(
          "update public.audit_events set canonical_payload=$1,event_sha256=$2 where sequence=1000",
          [Buffer.from(canonicalJson(changed)), hash]
        );
        await fixture.query(
          "update public.audit_chain_head set last_event_sha256=$1 where singleton_key",
          [hash]
        );
        await fixture.query("commit");
      } finally {
        await fixture.query("rollback");
        fixture.release();
      }
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({ valid: false, ready: false, reason: "checkpoint_audit_event_missing" });
    });
  }, 20_000);
});
