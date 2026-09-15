import { describe, expect, it } from "vitest";
import { startBoardAgentWorker } from "../../artifacts/server/src/worker-process.js";
import {
  schedulePeriodicJobsInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("scheduler transaction failure isolation", () => {
  it.each(["40001", "40P01", "57014"] as const)(
    "rolls back a PostgreSQL-injected %s after scheduling, claims existing work and recovers",
    async (sqlstate) => {
      await withUnseededWorker(`scheduler-injected-${sqlstate}`, async ({ pool, config }) => {
        await withWorkerTransaction(pool, schedulePeriodicJobsInTransaction, {
          assumeRole: "boardagent_worker"
        });
        const alerts: { name: string; details: unknown }[] = [];
        const runtime = await startBoardAgentWorker(config, {
          pool,
          assumeRole: "boardagent_worker",
          onOperationalAlert: (name, details) => {
            alerts.push({ name, details });
          }
        });
        let renamed = false;
        try {
          // Disposable database fault injector: execute the real producer first, then
          // raise in PostgreSQL after it has written the new checkpoint job. This
          // proves transaction-abort/rollback isolation, not a natural deadlock or SSI race.
          await pool.query(`alter function public.boardagent_schedule_audit_checkpoint(uuid)
            rename to boardagent_fixture_original_checkpoint_scheduler`);
          renamed = true;
          await pool.query(`create function public.boardagent_schedule_audit_checkpoint(candidate uuid)
            returns table(result_job_id uuid,scheduling_status text)
            language plpgsql volatile security definer
            set search_path=pg_catalog,public,pg_temp as $inject$
            declare produced record;
            begin
              select * into strict produced
                from public.boardagent_fixture_original_checkpoint_scheduler(candidate);
              if produced.scheduling_status<>'scheduled' then
                raise exception 'fault fixture did not write a checkpoint job' using errcode='XX000';
              end if;
              raise exception 'synthetic scheduler database failure' using errcode='${sqlstate}';
            end
            $inject$;
            alter function public.boardagent_schedule_audit_checkpoint(uuid) owner to boardagent_migrator;
            revoke all on function public.boardagent_schedule_audit_checkpoint(uuid) from public;
            grant execute on function public.boardagent_schedule_audit_checkpoint(uuid) to boardagent_worker;`);
          expect(await runtime.worker.runOnce()).toMatchObject({ status: "succeeded" });
          expect(alerts).toContainEqual({
            name: "worker_scheduler_deferred",
            details: {
              reason: sqlstate === "57014" ? "database_statement_cancelled" : "database_contention",
              sqlstate
            }
          });
          expect(
            (
              await pool.query(
                "select count(*)::int as count from public.jobs where job_type='audit_checkpoint'"
              )
            ).rows[0]?.count
          ).toBe(0);
          expect(
            (await pool.query("select count(*)::int as count from public.audit_checkpoints"))
              .rows[0]?.count
          ).toBe(0);
          await pool.query(`drop function public.boardagent_schedule_audit_checkpoint(uuid);
            alter function public.boardagent_fixture_original_checkpoint_scheduler(uuid)
              rename to boardagent_schedule_audit_checkpoint`);
          renamed = false;
          expect(await runtime.worker.runOnce()).toMatchObject({
            status: "succeeded",
            jobType: "audit_checkpoint"
          });
          expect(
            await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
              assumeRole: "boardagent_worker"
            })
          ).toMatchObject({ valid: true, ready: true, checkpointCount: 1 });
          expect(alerts.filter(({ name }) => name === "worker_scheduler_deferred")).toHaveLength(1);
        } finally {
          if (renamed) {
            await pool.query(`drop function if exists public.boardagent_schedule_audit_checkpoint(uuid);
              alter function public.boardagent_fixture_original_checkpoint_scheduler(uuid)
                rename to boardagent_schedule_audit_checkpoint`);
          }
          await runtime.close();
        }
      });
    },
    20_000
  );

  it("reports actual producer lock timeout, executes queued work and resumes signing after release", async () => {
    await withUnseededWorker("scheduler-contention", async ({ pool, config, organizationId }) => {
      await withWorkerTransaction(pool, schedulePeriodicJobsInTransaction, {
        assumeRole: "boardagent_worker"
      });
      const holder = await pool.connect();
      const alerts: { name: string; details: unknown }[] = [];
      const runtime = await startBoardAgentWorker(config, {
        pool,
        assumeRole: "boardagent_worker",
        onOperationalAlert: (name, details) => {
          alerts.push({ name, details });
        }
      });
      try {
        await holder.query("begin");
        await holder.query("select pg_advisory_xact_lock(hashtextextended($1,103041))", [
          organizationId
        ]);
        // Real production10-second lock timeout, with no time/lease/threshold override.
        const result = await runtime.worker.runOnce();
        expect(result.status).toBe("succeeded");
        expect(alerts).toContainEqual({
          name: "worker_scheduler_deferred",
          details: { reason: "database_contention", sqlstate: "55P03" }
        });
        expect(
          (await pool.query("select count(*)::int as count from public.audit_checkpoints")).rows[0]
            ?.count
        ).toBe(0);
        await holder.query("rollback");
        expect(await runtime.worker.runOnce()).toMatchObject({
          status: "succeeded",
          jobType: "audit_checkpoint"
        });
        expect(
          await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({ valid: true, ready: true, checkpointCount: 1 });
      } finally {
        await holder.query("rollback");
        holder.release();
        await runtime.close();
      }
    });
  }, 30_000);

  it("keeps permission failures fatal instead of reporting a scheduler retry", async () => {
    await withUnseededWorker("scheduler-permission", async ({ pool, config }) => {
      const alerts: string[] = [];
      const runtime = await startBoardAgentWorker(config, {
        pool,
        assumeRole: "boardagent_worker",
        onOperationalAlert: (name) => {
          alerts.push(name);
        }
      });
      try {
        await pool.query(
          "revoke execute on function public.boardagent_schedule_audit_checkpoint(uuid) from boardagent_worker"
        );
        await expect(runtime.worker.runOnce()).rejects.toMatchObject({ code: "42501" });
        expect(alerts).not.toContain("worker_scheduler_deferred");
        expect(
          (await pool.query("select count(*)::int as count from public.jobs")).rows[0]?.count
        ).toBe(0);
      } finally {
        await runtime.close();
      }
    });
  }, 20_000);
});
