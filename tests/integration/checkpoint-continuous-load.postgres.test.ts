import { describe, expect, it } from "vitest";
import {
  appendAuditEventsInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction,
  type AuditAppendInput
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("checkpoint progress during continuous concurrent audit batches", () => {
  it("continues past four thousand events with whole-transaction retries and bounded windows", async () => {
    await withUnseededWorker(
      "checkpoint-continuous",
      async ({ pool, organizationId, start, assertRunning }) => {
        await Promise.all([start(), start()]);
        await expect
          .poll(
            async () =>
              (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]
                ?.count,
            { timeout: 3_000, interval: 50 }
          )
          .toBeGreaterThan(0);
        const deadline = Date.now() + 15_000;
        const writers = await Promise.allSettled(
          Array.from({ length: 4 }, async (_, writer) => {
            for (let batch = 0; batch < 100; batch++) {
              const inputs: AuditAppendInput[] = Array.from({ length: 11 }, () => ({
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
                  details: {
                    synthetic: true,
                    writer,
                    batch,
                    purpose: "continuous-checkpoint-capacity"
                  },
                  schemaVersion: 1
                }
              }));
              for (;;) {
                assertRunning();
                if (Date.now() > deadline)
                  throw new Error(
                    "checkpoint production did not release capacity for the next whole batch"
                  );
                try {
                  await withWorkerTransaction(
                    pool,
                    (client) => appendAuditEventsInTransaction(client, inputs),
                    { assumeRole: "boardagent_worker" }
                  );
                  break;
                } catch (error) {
                  if (!(
                    typeof error === "object" &&
                    error !== null &&
                    "code" in error &&
                    error.code === "55000"
                  ))
                    throw error;
                  await new Promise((resolve) => setTimeout(resolve, 10));
                }
              }
            }
          })
        );
        for (const writer of writers) if (writer.status === "rejected") throw writer.reason;
        expect(
          (
            await pool.query(
              "select count(*)::int as count from audit_events where convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'purpose'='continuous-checkpoint-capacity'"
            )
          ).rows[0]?.count
        ).toBe(4400);
        expect(
          await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({ valid: true, ready: true });
        const windows = await pool.query(
          "select count(*)::int as count,max(last_sequence-first_sequence+1)::int as maximum from audit_checkpoints"
        );
        expect(windows.rows[0]?.count).toBeGreaterThanOrEqual(5);
        expect(windows.rows[0]?.maximum).toBeLessThanOrEqual(1000);
        expect(
          (
            await pool.query(
              "select count(*)::int as count from jobs where job_type='audit_checkpoint' and state='dead'"
            )
          ).rows[0]?.count
        ).toBe(0);
      }
    );
  }, 25_000);
});
