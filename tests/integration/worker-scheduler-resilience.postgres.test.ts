import type { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { startBoardAgentWorker } from "../../artifacts/server/src/worker-process.js";
import {
  claimTypedJobInTransaction,
  completeTypedJobInTransaction,
  enqueueRequestJobInTransaction,
  scheduleAuditCheckpointInTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

// Exercise the less-trusted application database capability directly. This is not a
// human enrollment or authentication fixture, and does not assert anonymous reachability.
async function requestJob(
  pool: Pool,
  organizationId: string,
  jobType: "clock_health" | "audit_checkpoint",
  key: string
) {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("set local role boardagent_server");
    await client.query("select set_config('boardagent.transaction_scope','request',true)");
    await client.query("select set_config('boardagent.organization_id',$1,true)", [organizationId]);
    const result = await enqueueRequestJobInTransaction(client, {
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
      idempotencyKey: key,
      availableAt: new Date(Date.now() + 86_400_000).toISOString()
    });
    await client.query("commit");
    return result;
  } finally {
    await client.query("rollback");
    client.release();
  }
}

describe("worker scheduler failure isolation", () => {
  it("preserves a dead checkpoint and alerts while unrelated jobs continue", async () => {
    await withUnseededWorker("scheduler-dead", async ({ pool, config }) => {
      const dead = await withWorkerTransaction(
        pool,
        async (client) => {
          await scheduleAuditCheckpointInTransaction(client, newWorkerTestId());
          const claimed = await claimTypedJobInTransaction(client, {
            leaseOwner: "fault-test",
            leaseSeconds: 30
          });
          if (!claimed.claimed) throw new Error("expected checkpoint lease");
          await completeTypedJobInTransaction(client, {
            jobId: claimed.job.jobId,
            leaseOwner: "fault-test",
            attempt: claimed.job.attempt,
            leaseToken: claimed.job.leaseToken,
            result: "permanent_failure",
            resultSha256: "a".repeat(64),
            errorClass: "synthetic_checkpoint_failure"
          });
          return claimed.job.jobId;
        },
        { assumeRole: "boardagent_worker" }
      );
      const alerts: string[] = [];
      const runtime = await startBoardAgentWorker(config, {
        pool,
        assumeRole: "boardagent_worker",
        pollMilliseconds: 25,
        onOperationalAlert: (alertClass) => {
          alerts.push(alertClass);
        }
      });
      const abort = new AbortController();
      let failure: unknown;
      const loop = runtime.run(abort.signal).catch((error: unknown) => {
        failure = error;
      });
      try {
        await expect
          .poll(
            async () => {
              if (failure) throw failure;
              return (
                await pool.query(
                  "select count(*)::int as count from jobs where job_type='clock_health' and state='succeeded'"
                )
              ).rows[0]?.count;
            },
            { timeout: 3_000, interval: 50 }
          )
          .toBeGreaterThan(0);
        expect(alerts.filter((value) => value === "audit_checkpoint_blocked")).toHaveLength(1);
        expect(
          (await pool.query("select state,attempts from jobs where id=$1", [dead])).rows
        ).toEqual([{ state: "dead", attempts: 1 }]);
        expect(
          (
            await pool.query("select resulting_state from job_attempt_results where job_id=$1", [
              dead
            ])
          ).rows
        ).toEqual([{ resulting_state: "dead" }]);
        expect(
          (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]?.count
        ).toBe(0);
      } finally {
        abort.abort();
        await loop;
        await runtime.close();
      }
    });
  }, 20_000);

  it("does not let future request jobs, including old worker-like keys, suppress production", async () => {
    await withUnseededWorker(
      "scheduler-future",
      async ({ pool, organizationId, start, assertRunning }) => {
        const future = await Promise.all([
          requestJob(pool, organizationId, "audit_checkpoint", "worker-audit-checkpoint:1"),
          requestJob(pool, organizationId, "clock_health", "worker-periodic:clock_health:forged")
        ]);
        await start();
        await expect
          .poll(
            async () => {
              assertRunning();
              return (
                await pool.query(
                  "select distinct job_type from jobs where job_type in ('clock_health','audit_checkpoint') and state='succeeded' order by job_type"
                )
              ).rows.map(({ job_type }) => job_type);
            },
            { timeout: 3_000, interval: 50 }
          )
          .toEqual(["audit_checkpoint", "clock_health"]);
        expect(
          (
            await pool.query(
              "select state,available_at>clock_timestamp() as future from jobs where id=any($1::uuid[])",
              [future.map((job) => job.jobId)]
            )
          ).rows
        ).toEqual([
          { state: "queued", future: true },
          { state: "queued", future: true }
        ]);
      }
    );
  }, 20_000);

  it.each(["worker-v2:checkpoint:1", "worker-v2:periodic:clock_health:forged"])(
    "refuses request impersonation of reserved producer identity %s",
    async (key) => {
      await withUnseededWorker("scheduler-identity", async ({ pool, organizationId }) => {
        await expect(requestJob(pool, organizationId, "clock_health", key)).rejects.toMatchObject({
          code: "job_invalid"
        });
        expect((await pool.query("select count(*)::int as count from jobs")).rows[0]?.count).toBe(
          0
        );
      });
    },
    20_000
  );
});
