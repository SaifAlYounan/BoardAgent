import { describe, expect, it } from "vitest";
import * as db from "../../lib/db/src/index.js";
import { createBoardAgentServerApplication } from "../../artifacts/server/src/server-application.js";
import { startBoardAgentWorker } from "../../artifacts/server/src/worker-process.js";
import { withUnseededWorker, newWorkerTestId } from "../helpers/unseeded-worker.js";

describe("runtime exclusion during operator key maintenance", () => {
  it.each(["server", "worker"] as const)(
    "refuses maintenance while the real %s is open and permits it after close",
    async (component) => {
      await withUnseededWorker(`runtime-fence-${component}`, async (f) => {
        const target = (
          await f.pool.query(
            "select instance_id,(select id from crypto_key_registry where purpose='data_kek') as key_id from system_instance"
          )
        ).rows[0];
        const prepared = await db.withBootstrapTransaction(
          f.pool,
          (c) =>
            db.prepareKeyLifecycleInTransaction(c, {
              instanceId: target.instance_id,
              organizationId: f.organizationId,
              keyId: target.key_id,
              operationId: newWorkerTestId(),
              operation: "retire",
              replacement: null,
              declaredCompromisedAt: null,
              retainedMaterialSha256: "a".repeat(64),
              operatorReference: "Synthetic operator",
              reason: "Real process must close before key transition"
            }),
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
        const process =
          component === "server"
            ? await createBoardAgentServerApplication(f.pool, f.config, {
                assumeRole: "boardagent_server"
              })
            : await startBoardAgentWorker(f.config, {
                pool: f.pool,
                assumeRole: "boardagent_worker"
              });
        try {
          await expect(
            db.withBootstrapTransaction(
              f.pool,
              (c) => db.applyKeyLifecycleInTransaction(c, prepared),
              { assumeRole: "boardagent_migrator" }
            )
          ).rejects.toMatchObject({
            code: "55000",
            message: "stop server and worker before key maintenance"
          });
          expect(
            (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0]
              .n
          ).toBe(0);
        } finally {
          await process.close();
        }
        expect(
          (
            await db.withBootstrapTransaction(
              f.pool,
              (c) => db.applyKeyLifecycleInTransaction(c, prepared),
              { assumeRole: "boardagent_migrator" }
            )
          ).replayed
        ).toBe(false);
      });
    }
  );
});

describe("lease loss and in-flight database work", () => {
  it("keeps maintenance excluded until an in-flight transaction ends and refuses stale follow-up work", async () => {
    await withUnseededWorker("runtime-fence-connection-loss", async (f) => {
      const { acquireRuntimeMaintenanceLease } =
        await import("../../artifacts/server/src/runtime-maintenance-lease.js");
      const lease = await acquireRuntimeMaintenanceLease(f.pool, "worker", "boardagent_worker");
      let entered!: () => void;
      const before = new Promise<void>((resolve) => {
        entered = resolve;
      });
      let finish!: () => void;
      const gate = new Promise<void>((resolve) => {
        finish = resolve;
      });
      const work = db.withRuntimeDatabaseLease(lease, () =>
        db.withWorkerTransaction(
          f.pool,
          async (c) => {
            await c.query("select 1");
            entered();
            await gate;
          },
          { assumeRole: "boardagent_worker" }
        )
      );
      const control = await f.pool.connect();
      try {
        await before;
        await f.pool.query("select pg_terminate_backend($1)", [lease.backendPid]);
        await expect.poll(() => lease.available).toBe(false);
        await control.query("begin");
        expect(
          (
            await control.query("select pg_try_advisory_xact_lock($1,$2) as locked", [
              ...db.RUNTIME_MAINTENANCE_LOCK
            ])
          ).rows[0].locked
        ).toBe(false);
        await control.query("rollback");
        // Deliberately ignore the local loss notification: the SQL lock identity must
        // independently reject this stale context before its callback can run.
        let callbackRan = false;
        const stale = {
          backendPid: lease.backendPid,
          markerKeys: lease.markerKeys,
          assertAvailable() {}
        };
        await expect(
          db.withRuntimeDatabaseLease(stale, () =>
            db.withWorkerTransaction(
              f.pool,
              async () => {
                callbackRan = true;
              },
              { assumeRole: "boardagent_worker" }
            )
          )
        ).rejects.toMatchObject({ code: "runtime_lease_unavailable" });
        expect(callbackRan).toBe(false);
        finish();
        await work;
        await control.query("begin");
        expect(
          (
            await control.query("select pg_try_advisory_xact_lock($1,$2) as locked", [
              ...db.RUNTIME_MAINTENANCE_LOCK
            ])
          ).rows[0].locked
        ).toBe(true);
        await control.query("rollback");
      } finally {
        finish();
        await work.catch(() => undefined);
        await control.query("rollback");
        control.release();
        await lease.close();
      }
    });
  });
  it.each(["server", "worker"] as const)(
    "refuses %s startup while an exclusive maintenance transaction is active",
    async (component) => {
      await withUnseededWorker(`runtime-fence-start-${component}`, async (f) => {
        const c = await f.pool.connect();
        try {
          await c.query("begin");
          await c.query("select pg_advisory_xact_lock($1,$2)", [...db.RUNTIME_MAINTENANCE_LOCK]);
          const start = () =>
            component === "server"
              ? createBoardAgentServerApplication(f.pool, f.config, {
                  assumeRole: "boardagent_server"
                })
              : startBoardAgentWorker(f.config, { pool: f.pool, assumeRole: "boardagent_worker" });
          await expect(start()).rejects.toThrow("key maintenance is active");
          await c.query("rollback");
          const active = await start();
          await active.close();
        } finally {
          await c.query("rollback");
          c.release();
        }
      });
    }
  );
  it("stops accepting work and drains the worker before releasing maintenance exclusion", async () => {
    await withUnseededWorker("runtime-fence-drain", async (f) => {
      const { acquireRuntimeMaintenanceLease } =
        await import("../../artifacts/server/src/runtime-maintenance-lease.js");
      const { BoardAgentTypedWorker } = await import("../../artifacts/server/src/worker.js");
      const lease = await acquireRuntimeMaintenanceLease(f.pool, "worker", "boardagent_worker");
      let entered!: () => void, finish!: () => void;
      const before = new Promise<void>((resolve) => {
          entered = resolve;
        }),
        gate = new Promise<void>((resolve) => {
          finish = resolve;
        });
      let calls = 0;
      const worker = new BoardAgentTypedWorker(f.pool, {
        handlers: new Map(),
        runtimeDatabaseLease: lease,
        assumeRole: "boardagent_worker",
        beforeClaim: async () => {
          calls++;
          entered();
          await gate;
        }
      });
      const work = worker.runOnce();
      try {
        await before;
        let drained = false;
        const draining = worker.drain().then(() => {
          drained = true;
        });
        expect(await worker.runOnce()).toEqual({ status: "idle" });
        expect(calls).toBe(1);
        expect(drained).toBe(false);
        finish();
        await work;
        await draining;
        expect(drained).toBe(true);
      } finally {
        finish();
        await work.catch(() => undefined);
        await lease.close();
      }
    });
  });
});

describe("real process behavior after maintenance lease loss", () => {
  it("makes the running HTTP service unavailable until restarted", async () => {
    await withUnseededWorker("runtime-fence-http-loss", async (f) => {
      const { startBoardAgentServer } =
        await import("../../artifacts/server/src/process-runtime.js");
      let service = await startBoardAgentServer(f.config, {
        pool: f.pool,
        assumeRole: "boardagent_server",
        host: "127.0.0.1",
        port: 0
      });
      const { request } = await import("node:http");
      const check = () =>
        new Promise<{ status: number }>((resolve, reject) => {
          const outbound = request(
            {
              hostname: "127.0.0.1",
              port: service.port,
              path: "/health/ready",
              headers: {
                host: f.config.publicBaseUrl.host,
                "x-forwarded-for": "198.51.100.17",
                "x-forwarded-proto": "https"
              }
            },
            (response) => {
              response.resume();
              response.on("end", () => resolve({ status: response.statusCode ?? 0 }));
            }
          );
          outbound.on("error", reject);
          outbound.end();
        });
      try {
        expect((await check()).status).toBe(200);
        const leases = (
          await f.pool.query(
            "select pid from pg_stat_activity where datname=current_database() and application_name='boardagent-runtime-server'"
          )
        ).rows;
        expect(leases).toHaveLength(1);
        await f.pool.query("select pg_terminate_backend($1)", [leases[0].pid]);
        await expect.poll(async () => (await check()).status).toBe(503);
        await service.close();
        service = await startBoardAgentServer(f.config, {
          pool: f.pool,
          assumeRole: "boardagent_server",
          host: "127.0.0.1",
          port: 0
        });
        expect((await check()).status).toBe(200);
      } finally {
        await service.close();
      }
    });
  });
  it("refuses another production worker claim after its lease is lost", async () => {
    await withUnseededWorker("runtime-fence-worker-loss", async (f) => {
      const worker = await startBoardAgentWorker(f.config, {
        pool: f.pool,
        assumeRole: "boardagent_worker"
      });
      try {
        const leases = (
          await f.pool.query(
            "select pid from pg_stat_activity where datname=current_database() and application_name='boardagent-runtime-worker'"
          )
        ).rows;
        expect(leases).toHaveLength(1);
        await f.pool.query("select pg_terminate_backend($1)", [leases[0].pid]);
        await expect(worker.worker.runOnce()).rejects.toMatchObject({
          code: "runtime_lease_unavailable"
        });
        expect((await f.pool.query("select count(*)::int as n from jobs")).rows[0].n).toBe(0);
      } finally {
        await worker.close();
      }
    });
  });
});
