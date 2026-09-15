import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import {
  claimTypedJobInTransaction,
  completeTypedJobInTransaction,
  enqueueRequestJobInTransaction,
  scheduleAuditCheckpointInTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

// Less-trusted database capability, not a fabricated human authentication ceremony.
async function backlog(pool: Pool, organizationId: string) {
  const client = await pool.connect();
  const ids: string[] = [];
  try {
    await client.query("begin");
    await client.query("set local role boardagent_server");
    await client.query("select set_config('boardagent.transaction_scope','request',true)");
    await client.query("select set_config('boardagent.organization_id',$1,true)", [organizationId]);
    for (let index = 0; index < 32; index++) {
      const jobType = index === 1 ? "audit_checkpoint" : "clock_health";
      const queued = await enqueueRequestJobInTransaction(client, {
        jobId: newWorkerTestId(),
        envelope: {
          schemaVersion: `boardagent.job.${jobType}.v1`,
          organizationId,
          boardId: null,
          jobType,
          subjectType: "organization",
          subjectId: organizationId,
          parameters: jobType === "audit_checkpoint" ? { throughSequence: "1" } : {}
        },
        idempotencyKey: `request-backlog:${index}`
      });
      ids.push(queued.jobId);
    }
    await client.query("commit");
    return ids;
  } finally {
    await client.query("rollback");
    client.release();
  }
}

const claim = (pool: Pool, leaseOwner: string) =>
  withWorkerTransaction(
    pool,
    (client) => claimTypedJobInTransaction(client, { leaseOwner, leaseSeconds: 30 }),
    { assumeRole: "boardagent_worker" }
  );

describe("checkpoint priority under an existing request queue", () => {
  it("claims the due protected producer before older request jobs, then retains FIFO order", async () => {
    await withUnseededWorker("checkpoint-priority", async ({ pool, organizationId }) => {
      const queued = await backlog(pool, organizationId);
      const scheduled = await withWorkerTransaction(
        pool,
        (client) => scheduleAuditCheckpointInTransaction(client, newWorkerTestId()),
        { assumeRole: "boardagent_worker" }
      );
      expect(scheduled.scheduling_status).toBe("scheduled");
      const first = await claim(pool, "priority-worker");
      expect(first).toMatchObject({ claimed: true, job: { jobId: scheduled.result_job_id } });
      // Holding the checkpoint lease does not prevent other workers from claiming work.
      const second = await claim(pool, "ordinary-worker");
      const third = await claim(pool, "ordinary-worker-two");
      expect(second).toMatchObject({ claimed: true, job: { jobId: queued[0] } });
      expect(third).toMatchObject({ claimed: true, job: { jobId: queued[1] } });
    });
  }, 20_000);

  it("keeps concurrent claims exclusive and honors checkpoint retry availability", async () => {
    await withUnseededWorker("checkpoint-priority-retry", async ({ pool, organizationId }) => {
      await backlog(pool, organizationId);
      const scheduled = await withWorkerTransaction(
        pool,
        (client) => scheduleAuditCheckpointInTransaction(client, newWorkerTestId()),
        { assumeRole: "boardagent_worker" }
      );
      const results = await Promise.all([claim(pool, "priority-a"), claim(pool, "priority-b")]);
      const index = results.findIndex(
        (result) => result.claimed && result.job.jobId === scheduled.result_job_id
      );
      expect(index).toBeGreaterThanOrEqual(0);
      const checkpoint = results[index];
      if (!checkpoint?.claimed) throw new Error("expected protected checkpoint claim");
      expect(new Set(results.map((result) => result.claimed && result.job.jobId)).size).toBe(2);
      await withWorkerTransaction(
        pool,
        (client) =>
          completeTypedJobInTransaction(client, {
            jobId: checkpoint.job.jobId,
            leaseOwner: index === 0 ? "priority-a" : "priority-b",
            attempt: checkpoint.job.attempt,
            leaseToken: checkpoint.job.leaseToken,
            result: "retryable_failure",
            resultSha256: "a".repeat(64),
            errorClass: "synthetic_retry"
          }),
        { assumeRole: "boardagent_worker" }
      );
      const next = await claim(pool, "after-retry");
      expect(next.claimed).toBe(true);
      if (next.claimed) expect(next.job.jobId).not.toBe(checkpoint.job.jobId);
      expect(
        (
          await pool.query(
            "select state,attempts,available_at>clock_timestamp() as future from public.jobs where id=$1",
            [checkpoint.job.jobId]
          )
        ).rows
      ).toEqual([{ state: "retry", attempts: 1, future: true }]);
    });
  }, 20_000);
});
