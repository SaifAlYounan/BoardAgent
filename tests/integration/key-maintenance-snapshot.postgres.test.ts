import { describe, expect, it } from "vitest";
import {
  withBootstrapTransaction,
  inspectKeyMaintenanceWorkInTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("shared operator maintenance snapshot", () => {
  it("revalidates the same facts inside the future writing transaction while keeping the read-only API restricted", async () => {
    await withUnseededWorker("key-work-writing-snapshot", async ({ pool, organizationId }) => {
      const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
        .instance_id as string;
      const keyId = (
        await pool.query("select id from crypto_key_registry where purpose='data_kek'")
      ).rows[0].id as string;
      const target = { instanceId, organizationId, keyId };
      const prepared = await withBootstrapTransaction(
        pool,
        (client) => inspectKeyMaintenanceWorkInTransaction(client, target),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      await withBootstrapTransaction(
        pool,
        async (client) => {
          const current = (
            await client.query(
              "select boardagent_snapshot_key_maintenance_work($1,$2,$3) as inventory",
              [instanceId, organizationId, keyId]
            )
          ).rows[0].inventory;
          expect(current.groups).toEqual(prepared.inventory.groups);
          expect(current.keyDependencies.keyStateSha256).toBe(
            prepared.inventory.keyDependencies.keyStateSha256
          );
        },
        { assumeRole: "boardagent_migrator" }
      );
      await expect(
        withBootstrapTransaction(
          pool,
          (client) => inspectKeyMaintenanceWorkInTransaction(client, target),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "25000" });
    });
  });

  it("denies the shared snapshot helpers to runtime roles even with claimed bootstrap scope", async () => {
    await withUnseededWorker("key-shared-snapshot-authority", async ({ pool, organizationId }) => {
      const target = (
        await pool.query(
          "select instance_id,(select id from crypto_key_registry where purpose='data_kek') as key_id from system_instance"
        )
      ).rows[0];
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"] as const) {
        for (const name of [
          "boardagent_snapshot_key_dependencies",
          "boardagent_snapshot_key_maintenance_work"
        ]) {
          const client = await pool.connect();
          try {
            await client.query("begin isolation level serializable");
            await client.query(`set local role ${role}`);
            await client.query(
              "select set_config('boardagent.transaction_scope','bootstrap',true)"
            );
            await expect(
              client.query(`select ${name}($1,$2,$3)`, [
                target.instance_id,
                organizationId,
                target.key_id
              ])
            ).rejects.toMatchObject({ code: "42501" });
          } finally {
            await client.query("rollback");
            client.release();
          }
        }
      }
      const client = await pool.connect();
      try {
        await client.query("begin isolation level read committed");
        await client.query("set local role boardagent_migrator");
        await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
        await expect(
          client.query("select boardagent_snapshot_key_maintenance_work($1,$2,$3)", [
            target.instance_id,
            organizationId,
            target.key_id
          ])
        ).rejects.toMatchObject({ code: "25000" });
      } finally {
        await client.query("rollback");
        client.release();
      }
      await expect(
        withBootstrapTransaction(
          pool,
          (c) =>
            c.query("select boardagent_snapshot_key_maintenance_work($1,$2,$3)", [
              newWorkerTestId(),
              organizationId,
              target.key_id
            ]),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23503" });
    });
  });
});
