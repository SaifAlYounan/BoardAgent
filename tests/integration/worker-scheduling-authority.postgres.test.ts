import type { Pool, PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import {
  scheduleAuditCheckpointInTransaction,
  schedulePeriodicJobsInTransaction,
  TypedJobEnvelopeSchema,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

async function scoped<T>(
  pool: Pool,
  role: "boardagent_server" | "boardagent_worker" | "boardagent_backup",
  scope: string | null,
  run: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query(`set local role ${role}`);
    if (scope !== null)
      await client.query("select set_config('boardagent.transaction_scope',$1,true)", [scope]);
    return await run(client);
  } finally {
    await client.query("rollback");
    client.release();
  }
}

describe("database-derived worker scheduling authority", () => {
  it("coalesces concurrent ticks and derives canonical exact instance/board jobs", async () => {
    await withUnseededWorker("scheduler-concurrency", async ({ pool, organizationId, boardId }) => {
      const tick = () =>
        withWorkerTransaction(
          pool,
          async (client) => {
            const checkpoint = await scheduleAuditCheckpointInTransaction(
              client,
              newWorkerTestId()
            );
            const periodic = await schedulePeriodicJobsInTransaction(client);
            return { checkpoint, periodic };
          },
          { assumeRole: "boardagent_worker" }
        );
      const [left, right] = await Promise.all([tick(), tick()]);
      expect(
        [left.checkpoint.scheduling_status, right.checkpoint.scheduling_status].sort()
      ).toEqual(["pending", "scheduled"]);
      expect(left.checkpoint.result_job_id).toBe(right.checkpoint.result_job_id);
      const before = await pool.query("select id,canonical_payload from jobs order by id");
      expect(before.rows.length).toBeGreaterThan(20);
      for (const row of before.rows) {
        const bytes = row.canonical_payload as Buffer;
        const envelope = TypedJobEnvelopeSchema.parse(JSON.parse(bytes.toString("utf8")));
        expect(Buffer.from(canonicalJson(envelope))).toEqual(bytes);
        expect(envelope.organizationId).toBe(organizationId);
        expect([null, boardId]).toContain(envelope.boardId);
      }
      expect(
        (await pool.query("select count(*)::int as count from jobs where job_type='clock_health'"))
          .rows[0]?.count
      ).toBe(1);
      expect(
        (
          await pool.query(
            "select count(*)::int as count from jobs where job_type='vote_deadline_scan'"
          )
        ).rows[0]?.count
      ).toBe(1);
      await tick();
      expect((await pool.query("select id from jobs order by id")).rows).toEqual(
        before.rows.map(({ id }) => ({ id }))
      );
      expect(
        (await pool.query("select count(*)::int as count from webauthn_credentials")).rows[0]?.count
      ).toBe(0);
    });
  }, 20_000);

  it.each(["boardagent_server", "boardagent_backup"] as const)(
    "refuses scheduler execution by %s even with a forged worker scope",
    async (role) => {
      await withUnseededWorker("scheduler-denied-role", async ({ pool }) => {
        for (const operation of [
          (client: PoolClient) =>
            client.query("select boardagent_schedule_audit_checkpoint($1)", [newWorkerTestId()]),
          (client: PoolClient) => client.query("select boardagent_schedule_periodic_jobs()")
        ])
          await expect(scoped(pool, role, "worker", operation)).rejects.toMatchObject({
            code: "42501"
          });
        expect((await pool.query("select count(*)::int as count from jobs")).rows[0]?.count).toBe(
          0
        );
      });
    },
    20_000
  );

  it.each([null, "request", "bootstrap", "restore"])(
    "refuses the worker outside its managed scope: %s",
    async (scope) => {
      await withUnseededWorker("scheduler-wrong-scope", async ({ pool }) => {
        for (const operation of [
          (client: PoolClient) =>
            client.query("select boardagent_schedule_audit_checkpoint($1)", [newWorkerTestId()]),
          (client: PoolClient) => client.query("select boardagent_schedule_periodic_jobs()")
        ])
          await expect(scoped(pool, "boardagent_worker", scope, operation)).rejects.toMatchObject({
            code: "25000"
          });
      });
    },
    20_000
  );

  it("rejects invalid identity, extra caller authority, and raw worker queue writes", async () => {
    await withUnseededWorker("scheduler-closed-input", async ({ pool }) => {
      for (const id of [null, "00000000-0000-4000-8000-000000000000"]) {
        await expect(
          scoped(pool, "boardagent_worker", "worker", (client) =>
            client.query("select boardagent_schedule_audit_checkpoint($1)", [id])
          )
        ).rejects.toMatchObject({ code: "22023" });
      }
      await expect(
        scoped(pool, "boardagent_worker", "worker", (client) =>
          client.query("select boardagent_schedule_periodic_jobs($1::uuid)", [newWorkerTestId()])
        )
      ).rejects.toMatchObject({ code: "42883" });
      await expect(
        scoped(pool, "boardagent_worker", "worker", (client) =>
          client.query("insert into jobs default values")
        )
      ).rejects.toMatchObject({ code: "42501" });
      const permissions = await pool.query(
        "select has_function_privilege('boardagent_worker',oid,'EXECUTE') as allowed from pg_proc where proname='boardagent_enqueue_request_job'"
      );
      expect(permissions.rows).toEqual([{ allowed: false }]);
      expect((await pool.query("select count(*)::int as count from jobs")).rows[0]?.count).toBe(0);
    });
  }, 20_000);
});
