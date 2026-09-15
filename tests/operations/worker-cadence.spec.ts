import { describe, expect, it } from "vitest";

import { verifyPersistedAuditEvidence, withWorkerTransaction } from "../../lib/db/src/index.js";
import { withUnseededWorker } from "../helpers/unseeded-worker.js";

/** Real elapsed time: no injected job, clock override, backdated row or accelerated cadence. */
describe("continuous worker cadence under the real database clock", () => {
  it(
    "renews signed evidence within fifteen minutes and clock health before expiry",
    async () => {
      await withUnseededWorker("worker-real-cadence", async ({ pool, start, assertRunning }) => {
        await start(1000);
        await expect
          .poll(
            async () => {
              assertRunning();
              return (await pool.query("select count(*)::int as count from audit_checkpoints"))
                .rows[0]?.count;
            },
            { timeout: 10_000, interval: 100 }
          )
          .toBe(1);
        const initial = await pool.query(
          "select id,last_sequence::text from audit_checkpoints order by last_sequence desc limit 1"
        );
        await expect
          .poll(
            async () => {
              assertRunning();
              const evidence = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
                assumeRole: "boardagent_worker"
              });
              expect(evidence).toMatchObject({ valid: true, ready: true });
              return (await pool.query("select count(*)::int as count from audit_checkpoints"))
                .rows[0]?.count;
            },
            { timeout: 15 * 60_000, interval: 1000 }
          )
          .toBeGreaterThan(1);
        const latest = await pool.query(
          "select id,last_sequence::text from audit_checkpoints order by last_sequence desc limit 1"
        );
        expect(latest.rows[0]?.id).not.toBe(initial.rows[0]?.id);
        expect(BigInt(latest.rows[0]!.last_sequence)).toBeGreaterThan(
          BigInt(initial.rows[0]!.last_sequence)
        );
        const windows =
          await pool.query(`select bool_and(checkpoint.created_at-event.occurred_at<=interval '15 minutes') as valid
        from audit_checkpoints as checkpoint join audit_events as event on event.sequence=checkpoint.first_sequence`);
        expect(windows.rows).toEqual([{ valid: true }]);
        const clock = await pool.query(`select count(*)::int as count,
        coalesce(bool_and(healthy),false) as healthy,
        coalesce(bool_and(prior_valid_until is null or measured_at<prior_valid_until),false) as continuous,
        max(valid_until)>clock_timestamp() as fresh
        from (select healthy,measured_at,valid_until,lag(valid_until) over(order by measured_at,id) as prior_valid_until
          from clock_health_samples) as samples`);
        expect(clock.rows[0]).toMatchObject({ healthy: true, continuous: true, fresh: true });
        expect(clock.rows[0]?.count).toBeGreaterThan(1);
        expect(
          (await pool.query("select count(*)::int as count from webauthn_credentials")).rows[0]
            ?.count
        ).toBe(0);
      });
    },
    16 * 60_000
  );
});
