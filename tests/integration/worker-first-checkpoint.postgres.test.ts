import { describe, expect, it } from "vitest";

import {
  appendAuditEventsInTransaction,
  captureBackupBoundaryInTransaction,
  claimTypedJobInTransaction,
  scheduleAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withBackupTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("unseeded production worker lifecycle", () => {
  it("creates its first signed checkpoint through a succeeded job and permits a real backup boundary", async () => {
    await withUnseededWorker(
      "worker-first-checkpoint",
      async ({ pool, start, assertRunning, backupKeyId }) => {
        await start();
        await expect
          .poll(
            async () => {
              assertRunning();
              return (
                await pool.query(
                  "select count(*)::int as count from jobs where job_type='audit_checkpoint' and state='succeeded'"
                )
              ).rows[0]?.count;
            },
            { timeout: 5_000, interval: 50 }
          )
          .toBe(1);
        const verified = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        });
        expect(verified).toMatchObject({ valid: true, ready: true, checkpointCount: 1 });
        const boundary = await withBackupTransaction(
          pool,
          (client) =>
            captureBackupBoundaryInTransaction(client, {
              receiptId: newWorkerTestId(),
              encryptionKeyId: backupKeyId,
              encryptionKeyFingerprintSha256: "a".repeat(64)
            }),
          { assumeRole: "boardagent_backup" }
        );
        expect(boundary.auditBoundary.latestCheckpoint).not.toBeNull();
        expect(
          (await pool.query("select count(*)::int as count from webauthn_credentials")).rows[0]
            ?.count
        ).toBe(0);
      }
    );
  }, 20_000);

  it("produces a fresh healthy clock sample without a test-injected periodic job", async () => {
    await withUnseededWorker("worker-first-clock", async ({ pool, start, assertRunning }) => {
      await start();
      await expect
        .poll(
          async () => {
            assertRunning();
            return (
              await pool.query(
                "select count(*)::int as count from clock_health_samples where healthy and valid_until>clock_timestamp()"
              )
            ).rows[0]?.count;
          },
          { timeout: 3_000, interval: 50 }
        )
        .toBeGreaterThan(0);
    });
  }, 20_000);
});

describe("continuous runtime scheduling", () => {
  it("runs two workers against the same empty queue without duplicate cadence work", async () => {
    await withUnseededWorker("worker-two-runtimes", async ({ pool, start, assertRunning }) => {
      await Promise.all([start(), start()]);
      const expected = [
        "audit_checkpoint",
        "clock_health",
        "job_lease_reaper",
        "notification_lease_reaper",
        "vote_deadline_scan",
        "question_due_scan",
        "task_due_scan",
        "action_due_scan",
        "oauth_ephemera_expiry",
        "refresh_session_revocation",
        "wizard_expiry",
        "action_stage_expiry",
        "feed_reconcile",
        "feed_consistency_check",
        "export_reconcile",
        "export_artifact_expiry"
      ];
      await expect
        .poll(
          async () => {
            assertRunning();
            const result = await pool.query(
              "select distinct job_type from jobs where state='succeeded' and job_type=any($1)",
              [expected]
            );
            return result.rows.map(({ job_type }) => job_type).sort();
          },
          { timeout: 10_000, interval: 50 }
        )
        .toEqual(expected.sort());
      expect(
        (
          await pool.query(
            "select job_type,idempotency_key from jobs group by job_type,idempotency_key having count(*)>1"
          )
        ).rows
      ).toEqual([]);
      expect(
        (
          await pool.query(
            "select count(*)::int as count from jobs where job_type='audit_checkpoint' and state='succeeded'"
          )
        ).rows[0]?.count
      ).toBe(1);
    });
  }, 60_000);
});

describe("production worker restart recovery", () => {
  it("reaps a crashed worker lease and finishes the real scheduled checkpoint", async () => {
    await withUnseededWorker("worker-crash-recovery", async ({ pool, start, assertRunning }) => {
      const claimed = await withWorkerTransaction(
        pool,
        async (client) => {
          await scheduleAuditCheckpointInTransaction(client, newWorkerTestId());
          return claimTypedJobInTransaction(client, { leaseOwner: "dead-worker", leaseSeconds: 5 });
        },
        { assumeRole: "boardagent_worker" }
      );
      if (!claimed.claimed) throw new Error("expected a real leased checkpoint job");
      // Let the actual database lease expire; no job row/state/timestamp is rewritten.
      await new Promise((resolve) => setTimeout(resolve, 5_100));
      await start();
      await expect
        .poll(
          async () => {
            assertRunning();
            return (
              await pool.query("select state,attempts from jobs where id=$1", [claimed.job.jobId])
            ).rows[0];
          },
          { timeout: 40_000, interval: 50 }
        )
        .toEqual({ state: "succeeded", attempts: 2 });
      const verified = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
        assumeRole: "boardagent_worker"
      });
      expect(verified).toMatchObject({ valid: true, ready: true, checkpointCount: 1 });
    });
  }, 60_000);
});

describe("event-count checkpoint cadence", () => {
  it("signs the thousand-event boundary before the time cadence without an injected job", async () => {
    await withUnseededWorker(
      "worker-count-cadence",
      async ({ pool, start, assertRunning, organizationId }) => {
        await start();
        await expect
          .poll(
            async () => {
              assertRunning();
              return (
                await pool.query(
                  "select count(*)::int as count from jobs where job_type='audit_checkpoint' and state='succeeded'"
                )
              ).rows[0]?.count;
            },
            { timeout: 5_000, interval: 50 }
          )
          .toBe(1);
        await withWorkerTransaction(
          pool,
          async (client) => {
            await client.query("select last_sequence from boardagent_lock_audit_head()");
            const gap = (
              await client.query(
                "select head.last_sequence-coalesce((select max(last_sequence) from audit_checkpoints),0) as count from audit_chain_head as head"
              )
            ).rows[0]!;
            const count = 1000 - Number(gap.count);
            if (count < 1) throw new Error("fresh worker already has an unexpected audit backlog");
            await appendAuditEventsInTransaction(
              client,
              Array.from({ length: count }, () => ({
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
                  origin: "worker" as const,
                  details: { synthetic: true, purpose: "event-count cadence load" },
                  schemaVersion: 1
                }
              }))
            );
          },
          { assumeRole: "boardagent_worker" }
        );
        await expect
          .poll(
            async () => {
              assertRunning();
              return (await pool.query("select count(*)::int as count from audit_checkpoints"))
                .rows[0]?.count;
            },
            { timeout: 5_000, interval: 50 }
          )
          .toBe(2);
        const window = await pool.query(
          "select last_sequence-first_sequence+1 as count from audit_checkpoints order by last_sequence desc limit 1"
        );
        expect(window.rows).toEqual([{ count: "1000" }]);
        const verified = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        });
        expect(verified).toMatchObject({ valid: true, ready: true, checkpointCount: 2 });
      }
    );
  }, 20_000);
});
