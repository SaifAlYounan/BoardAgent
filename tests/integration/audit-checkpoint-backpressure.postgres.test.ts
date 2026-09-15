import { describe, expect, it } from "vitest";
import { appendAuditEventsInTransaction, withWorkerTransaction } from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("audit checkpoint capacity admission", () => {
  it("serializes concurrent appends at the same remaining capacity", async () => {
    await withUnseededWorker("checkpoint-cap-race", async ({ pool, organizationId }) => {
      const event = () => ({
        organizationId,
        event: {
          eventId: newWorkerTestId(),
          eventType: "context_read" as const,
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "context",
          entityId: newWorkerTestId(),
          boardId: null,
          origin: "worker" as const,
          details: { synthetic: true, purpose: "concurrent capacity admission" },
          schemaVersion: 1 as const
        }
      });
      const initial = await pool.query("select last_sequence::text from audit_chain_head");
      await withWorkerTransaction(
        pool,
        (client) =>
          appendAuditEventsInTransaction(
            client,
            Array.from({ length: 998 - Number(initial.rows[0]!.last_sequence) }, event)
          ),
        { assumeRole: "boardagent_worker" }
      );
      const attempts = await Promise.allSettled(
        Array.from({ length: 4 }, () =>
          withWorkerTransaction(
            pool,
            async (client) => {
              await appendAuditEventsInTransaction(client, [event()]);
            },
            { assumeRole: "boardagent_worker" }
          )
        )
      );
      expect(attempts.filter(({ status }) => status === "fulfilled")).toHaveLength(2);
      const failures = attempts.filter((result) => result.status === "rejected");
      expect(failures).toHaveLength(2);
      for (const result of failures) expect(result.reason).toMatchObject({ code: "55000" });
      expect((await pool.query("select last_sequence::text from audit_chain_head")).rows).toEqual([
        { last_sequence: "1000" }
      ]);
      expect(
        (await pool.query("select count(*)::int as count from audit_events")).rows[0]?.count
      ).toBe(1000);
    });
  }, 20_000);

  it("rolls back overflow atomically, then accepts work after the real worker signs", async () => {
    await withUnseededWorker(
      "checkpoint-admission",
      async ({ pool, organizationId, start, assertRunning }) => {
        const event = () => ({
          organizationId,
          event: {
            eventId: newWorkerTestId(),
            eventType: "context_read" as const,
            actorMemberId: null,
            actorClientId: null,
            tokenJti: null,
            entityType: "context",
            entityId: newWorkerTestId(),
            boardId: null,
            origin: "worker" as const,
            details: { synthetic: true, purpose: "checkpoint capacity admission" },
            schemaVersion: 1 as const
          }
        });
        const initial = await pool.query(
          "select last_sequence::text,last_event_sha256 from audit_chain_head"
        );
        const available = 1000 - Number(initial.rows[0]!.last_sequence);
        await expect(
          withWorkerTransaction(
            pool,
            async (client) => {
              await appendAuditEventsInTransaction(client, Array.from({ length: 10001 }, event));
            },
            { assumeRole: "boardagent_worker" }
          )
        ).rejects.toMatchObject({
          code: "54000",
          constraint: "boardagent_audit_transaction_capacity"
        });
        expect(
          (await pool.query("select last_sequence::text,last_event_sha256 from audit_chain_head"))
            .rows
        ).toEqual(initial.rows);
        await withWorkerTransaction(
          pool,
          (client) =>
            appendAuditEventsInTransaction(client, Array.from({ length: available }, event)),
          { assumeRole: "boardagent_worker" }
        );
        expect((await pool.query("select last_sequence::text from audit_chain_head")).rows).toEqual(
          [{ last_sequence: "1000" }]
        );
        await expect(
          withWorkerTransaction(
            pool,
            (client) => appendAuditEventsInTransaction(client, [event()]),
            { assumeRole: "boardagent_worker" }
          )
        ).rejects.toMatchObject({ code: "55000" });
        await start();
        await expect
          .poll(
            async () => {
              assertRunning();
              return (await pool.query("select count(*)::int as count from audit_checkpoints"))
                .rows[0]?.count;
            },
            { timeout: 5_000, interval: 50 }
          )
          .toBe(1);
        await expect(
          withWorkerTransaction(
            pool,
            (client) => appendAuditEventsInTransaction(client, [event()]),
            { assumeRole: "boardagent_worker" }
          )
        ).resolves.toHaveLength(1);
      }
    );
  }, 20_000);
});
