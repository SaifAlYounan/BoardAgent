import { describe, expect, it } from "vitest";
import { startBoardAgentWorker } from "../../artifacts/server/src/worker-process.js";
import {
  claimTypedJobInTransaction,
  completeTypedJobInTransaction,
  scheduleAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("real elapsed checkpoint retry headroom", () => {
  it(
    "schedules within six minutes and recovers one actual thirty-second retry before the fifteen-minute ceiling",
    async () => {
      await withUnseededWorker(
        "checkpoint-headroom",
        async ({ pool, config, start, assertRunning }) => {
          const initialWorker = await startBoardAgentWorker(config, {
            pool,
            assumeRole: "boardagent_worker",
            onOperationalAlert: () => undefined
          });
          try {
            // Drain the genuinely produced initial work; no job/time/evidence is injected.
            for (let i = 0; i < 50; i++) await initialWorker.worker.runOnce();
          } finally {
            await initialWorker.close();
          }
          expect(
            (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]
              ?.count
          ).toBe(1);
          let scheduledId: string | null = null;
          await expect
            .poll(
              async () => {
                const result = await withWorkerTransaction(
                  pool,
                  (client) => scheduleAuditCheckpointInTransaction(client, newWorkerTestId()),
                  { assumeRole: "boardagent_worker" }
                );
                scheduledId = result.result_job_id;
                return result.scheduling_status;
              },
              { timeout: 6 * 60_000, interval: 1000 }
            )
            .toBe("scheduled");
          const olderJob = new Error("older genuine work precedes the checkpoint");
          const drain = await startBoardAgentWorker(config, {
            pool,
            assumeRole: "boardagent_worker",
            onOperationalAlert: () => undefined
          });
          let faultedJobId: string | undefined;
          try {
            for (let attempt = 0; attempt < 100 && faultedJobId === undefined; attempt++) {
              try {
                faultedJobId = await withWorkerTransaction(
                  pool,
                  async (client) => {
                    const claim = await claimTypedJobInTransaction(client, {
                      leaseOwner: "transient-signing-fault",
                      leaseSeconds: 30
                    });
                    if (!claim.claimed) throw new Error("scheduled checkpoint was not claimable");
                    // Roll back this inspection when an earlier retry precedes it. Execute
                    // that work through its real handler; never fabricate its completion.
                    if (claim.job.jobId !== scheduledId) throw olderJob;
                    await completeTypedJobInTransaction(client, {
                      jobId: claim.job.jobId,
                      leaseOwner: "transient-signing-fault",
                      attempt: claim.job.attempt,
                      leaseToken: claim.job.leaseToken,
                      result: "retryable_failure",
                      resultSha256: "b".repeat(64),
                      errorClass: "synthetic_transient_signing_failure"
                    });
                    return claim.job.jobId;
                  },
                  { assumeRole: "boardagent_worker" }
                );
              } catch (error) {
                if (error !== olderJob) throw error;
                await drain.worker.runOnce();
              }
            }
          } finally {
            await drain.close();
          }
          expect(faultedJobId).toBe(scheduledId);
          await start(1000);
          await expect
            .poll(
              async () => {
                assertRunning();
                return (
                  await pool.query("select state,attempts from jobs where id=$1", [faultedJobId])
                ).rows[0];
              },
              { timeout: 45_000, interval: 250 }
            )
            .toEqual({ state: "succeeded", attempts: 2 });
          expect(
            await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
              assumeRole: "boardagent_worker"
            })
          ).toMatchObject({ valid: true, ready: true, checkpointCount: 2 });
          expect(
            (
              await pool.query(
                "select bool_and(checkpoint.created_at-event.occurred_at<=interval '15 minutes') as valid from audit_checkpoints as checkpoint join audit_events as event on event.sequence=checkpoint.first_sequence"
              )
            ).rows
          ).toEqual([{ valid: true }]);
        }
      );
    },
    8 * 60_000
  );
});
