import { describe, expect, it } from "vitest";
import * as db from "../../lib/db/src/index.js";
import { withUnseededWorker, newWorkerTestId } from "../helpers/unseeded-worker.js";

async function operation(f: Parameters<Parameters<typeof withUnseededWorker>[1]>[0]) {
  const row = (
    await f.pool.query(
      "select instance_id,(select id from crypto_key_registry where purpose='data_kek') as key_id from system_instance"
    )
  ).rows[0];
  const input = await db.withBootstrapTransaction(
    f.pool,
    (c) =>
      db.prepareKeyLifecycleInTransaction(c, {
        instanceId: row.instance_id,
        organizationId: f.organizationId,
        keyId: row.key_id,
        operationId: newWorkerTestId(),
        operation: "retire",
        replacement: null,
        declaredCompromisedAt: null,
        retainedMaterialSha256: "a".repeat(64),
        operatorReference: "Synthetic operator",
        reason: "Lost response inspection test"
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
  const applied = await db.withBootstrapTransaction(
    f.pool,
    (c) => db.applyKeyLifecycleInTransaction(c, input),
    { assumeRole: "boardagent_migrator" }
  );
  return {
    applied,
    input,
    target: {
      instanceId: row.instance_id,
      organizationId: f.organizationId,
      operationId: input.request.operationId
    }
  };
}
describe("operator inspection of committed key-maintenance receipts", () => {
  it("recovers the original receipt without private keys or repeating a write after later lifecycle changes", async () => {
    await withUnseededWorker("key-receipt-history", async (f) => {
      const first = await operation(f);
      const read = () =>
        db.withBootstrapTransaction(
          f.pool,
          (c) => db.readKeyLifecycleReceiptInTransaction(c, first.target),
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
      const { replayed: _replayed, ...expected } = first.applied;
      expect(await read()).toEqual(expected);
      const key = (
        await f.pool.query(
          "select to_char(activated_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as activated from crypto_key_registry where id=$1",
          [first.input.request.keyId]
        )
      ).rows[0];
      const second = await db.withBootstrapTransaction(
        f.pool,
        (c) =>
          db.prepareKeyLifecycleInTransaction(c, {
            instanceId: first.target.instanceId,
            organizationId: f.organizationId,
            keyId: first.input.request.keyId,
            operationId: newWorkerTestId(),
            operation: "mark_compromised",
            replacement: null,
            declaredCompromisedAt: key.activated,
            retainedMaterialSha256: "b".repeat(64),
            operatorReference: "Synthetic operator",
            reason: "Later incident does not rewrite original receipt"
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      await db.withBootstrapTransaction(
        f.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, second),
        { assumeRole: "boardagent_migrator" }
      );
      const count = (await f.pool.query("select count(*)::int as n from audit_events")).rows[0].n;
      expect(await read()).toEqual(expected);
      expect((await f.pool.query("select count(*)::int as n from audit_events")).rows[0].n).toBe(
        count
      );
    });
  });
  it("requires read-only operator scope and the exact installation and completed operation", async () => {
    await withUnseededWorker("key-receipt-target", async (f) => {
      const first = await operation(f);
      for (const target of [
        { ...first.target, instanceId: newWorkerTestId() },
        { ...first.target, organizationId: newWorkerTestId() },
        { ...first.target, operationId: newWorkerTestId() }
      ])
        await expect(
          db.withBootstrapTransaction(
            f.pool,
            (c) => db.readKeyLifecycleReceiptInTransaction(c, target),
            { assumeRole: "boardagent_migrator", readOnly: true }
          )
        ).rejects.toThrow("key lifecycle completion unavailable");
      await expect(
        db.withBootstrapTransaction(
          f.pool,
          (c) => db.readKeyLifecycleReceiptInTransaction(c, first.target),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toThrow("read-only operator transaction");
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
        const c = await f.pool.connect();
        try {
          await c.query("begin isolation level serializable read only");
          await c.query(`set local role ${role}`);
          await c.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(db.readKeyLifecycleReceiptInTransaction(c, first.target)).rejects.toThrow(
            "read-only operator transaction"
          );
        } finally {
          await c.query("rollback");
          c.release();
        }
      }
    });
  });
});
