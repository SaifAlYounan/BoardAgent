import { describe, expect, it } from "vitest";
import type { Pool, PoolClient } from "pg";
import {
  inspectKeyMaintenanceWorkInTransaction,
  withBootstrapTransaction,
  withWorkerTransaction,
  scheduleAuditCheckpointInTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

const lockSql = "select boardagent_lock_key_maintenance_snapshot($1,$2,$3,$4,$5,$6) as inventory";
async function prepared(pool: Pool, organizationId: string, purpose = "evidence_signing") {
  const target = (
    await pool.query(
      "select instance_id,(select id from crypto_key_registry where purpose=$1) as key_id from system_instance",
      [purpose]
    )
  ).rows[0];
  const { inventory } = await withBootstrapTransaction(
    pool,
    (c) =>
      inspectKeyMaintenanceWorkInTransaction(c, {
        instanceId: target.instance_id,
        organizationId,
        keyId: target.key_id
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
  const preparedAt = inventory.keyDependencies.observedAt;
  const expiresAt = new Date(Date.parse(preparedAt) + 1_800_000)
    .toISOString()
    .replace("Z", preparedAt.slice(-4));
  return {
    keyId: target.key_id as string,
    inventory,
    preparedAt,
    expiresAt,
    args: [
      target.instance_id,
      organizationId,
      target.key_id,
      inventory,
      preparedAt,
      expiresAt
    ] as unknown[]
  };
}
const validate = (pool: Pool, args: unknown[]) =>
  withBootstrapTransaction(pool, (c) => c.query(lockSql, args), {
    assumeRole: "boardagent_migrator"
  });

async function awaitDatabaseLock(pool: Pool, pid: number) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const row = (
      await pool.query("select wait_event_type from pg_stat_activity where pid=$1", [pid])
    ).rows[0];
    if (row?.wait_event_type === "Lock") return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("validator did not reach the expected database lock");
}

async function beginOperator(client: PoolClient, isolation = "serializable") {
  if (isolation !== "serializable" && isolation !== "read committed")
    throw new Error("invalid test isolation");
  await client.query(`begin isolation level ${isolation}`);
  await client.query("set local role boardagent_migrator");
  await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
}

describe("key maintenance revalidation under locks", () => {
  it("accepts unchanged prepared facts in the writing transaction without changing keys or audit", async () => {
    await withUnseededWorker("key-locked-snapshot", async ({ pool, organizationId }) => {
      const target = (
        await pool.query(
          "select instance_id,(select id from crypto_key_registry where purpose='evidence_signing') as key_id from system_instance"
        )
      ).rows[0];
      const { inventory } = await withBootstrapTransaction(
        pool,
        (c) =>
          inspectKeyMaintenanceWorkInTransaction(c, {
            instanceId: target.instance_id,
            organizationId,
            keyId: target.key_id
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const preparedAt = inventory.keyDependencies.observedAt;
      const expiresAt = new Date(Date.parse(preparedAt) + 1_800_000)
        .toISOString()
        .replace("Z", preparedAt.slice(-4));
      const before = (
        await pool.query("select to_jsonb(k) as value from crypto_key_registry k order by id")
      ).rows;
      const head = (await pool.query("select * from audit_chain_head")).rows;
      const result = await withBootstrapTransaction(
        pool,
        (c) =>
          c.query(
            "select boardagent_lock_key_maintenance_snapshot($1,$2,$3,$4,$5,$6) as inventory",
            [target.instance_id, organizationId, target.key_id, inventory, preparedAt, expiresAt]
          ),
        { assumeRole: "boardagent_migrator" }
      );
      expect(result.rows[0].inventory.groups).toEqual(inventory.groups);
      expect(
        (await pool.query("select to_jsonb(k) as value from crypto_key_registry k order by id"))
          .rows
      ).toEqual(before);
      expect((await pool.query("select * from audit_chain_head")).rows).toEqual(head);
    });
  });

  it("requires exact complete facts for all purposes and rejects omitted, added or altered facts", async () => {
    await withUnseededWorker("key-locked-facts", async ({ pool, organizationId }) => {
      for (const purpose of [
        "oauth_signing",
        "evidence_signing",
        "browser_session",
        "data_kek",
        "backup_kek"
      ]) {
        const input = await prepared(pool, organizationId, purpose);
        await expect(validate(pool, input.args)).resolves.toMatchObject({ rowCount: 1 });
        for (const change of [
          (v: typeof input.inventory) => {
            v.groups.pop();
          },
          (v: typeof input.inventory) => {
            v.groups[0]!.rowCount = "1";
          },
          (v: typeof input.inventory) => {
            v.keyDependencies.keyStateSha256 = "0".repeat(64);
          },
          (v: typeof input.inventory) => {
            v.keyDependencies.auditHead.sha256 = "0".repeat(64);
          },
          (v: typeof input.inventory) => {
            v.keyDependencies.foreignKeyDependencies.pop();
          },
          (v: typeof input.inventory) => {
            Object.assign(v, { ignoreChanges: true });
          }
        ]) {
          const inventory = structuredClone(input.inventory);
          change(inventory);
          const args = [...input.args];
          args[3] = inventory;
          await expect(validate(pool, args)).rejects.toMatchObject({ code: "55000" });
        }
      }
    });
  });

  it("refuses earlier preparation when actual queued work or key state changes", async () => {
    await withUnseededWorker("key-locked-stale", async ({ pool, organizationId }) => {
      const initial = await prepared(pool, organizationId);
      await withWorkerTransaction(
        pool,
        (c) => scheduleAuditCheckpointInTransaction(c, newWorkerTestId()),
        { assumeRole: "boardagent_worker" }
      );
      await expect(validate(pool, initial.args)).rejects.toMatchObject({ code: "55000" });
      const current = await prepared(pool, organizationId);
      await expect(validate(pool, current.args)).resolves.toMatchObject({ rowCount: 1 });
      await pool.query("update crypto_key_registry set retired_at=clock_timestamp() where id=$1", [
        current.keyId
      ]);
      await expect(validate(pool, current.args)).rejects.toMatchObject({ code: "55000" });
      await expect(
        validate(pool, (await prepared(pool, organizationId)).args)
      ).resolves.toMatchObject({ rowCount: 1 });
    });
  });

  it("refuses expired, future, noncanonical and mismatched preparation times", async () => {
    await withUnseededWorker("key-locked-expiry", async ({ pool, organizationId }) => {
      const input = await prepared(pool, organizationId);
      const invalid: unknown[][] = [
        [...input.args.slice(0, 4), null, input.expiresAt],
        [...input.args.slice(0, 4), input.preparedAt, input.preparedAt],
        [...input.args.slice(0, 4), input.preparedAt.replace("Z", "+00:00"), input.expiresAt],
        [...input.args.slice(0, 4), input.preparedAt.slice(0, -4) + "Z", input.expiresAt]
      ];
      for (const shift of [-3_600_000, 3_600_000]) {
        const first = new Date(Date.parse(input.preparedAt) + shift)
          .toISOString()
          .replace("Z", "000Z");
        const last = new Date(Date.parse(first) + 1_800_000).toISOString().replace("Z", "000Z");
        const inventory = structuredClone(input.inventory);
        inventory.keyDependencies.observedAt = first;
        invalid.push([...input.args.slice(0, 3), inventory, first, last]);
      }
      for (const args of invalid)
        await expect(validate(pool, args)).rejects.toMatchObject({ code: "55000" });
    });
  });

  it("denies runtime roles and inappropriate transaction modes even with a claimed operator scope", async () => {
    await withUnseededWorker("key-locked-permissions", async ({ pool, organizationId }) => {
      const input = await prepared(pool, organizationId);
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
        const c = await pool.connect();
        try {
          await c.query("begin isolation level serializable");
          await c.query(`set local role ${role}`);
          await c.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(c.query(lockSql, input.args)).rejects.toMatchObject({ code: "42501" });
        } finally {
          await c.query("rollback");
          c.release();
        }
      }
      const c = await pool.connect();
      try {
        await beginOperator(c, "read committed");
        await expect(c.query(lockSql, input.args)).rejects.toMatchObject({ code: "25000" });
      } finally {
        await c.query("rollback");
        c.release();
      }
      await expect(
        withBootstrapTransaction(pool, (c) => c.query(lockSql, input.args), {
          assumeRole: "boardagent_migrator",
          readOnly: true
        })
      ).rejects.toMatchObject({ code: "25000" });
      await expect(
        validate(pool, [newWorkerTestId(), ...input.args.slice(1)])
      ).rejects.toMatchObject({ code: "23503" });
    });
  });

  it("takes the audit head first and refuses a key changed while waiting for that lock", async () => {
    await withUnseededWorker("key-locked-race", async ({ pool, organizationId }) => {
      const input = await prepared(pool, organizationId);
      const blocker = await pool.connect(),
        validator = await pool.connect(),
        modifier = await pool.connect();
      let pending: Promise<unknown> | undefined;
      try {
        await blocker.query("begin");
        await blocker.query("select * from audit_chain_head for update");
        await beginOperator(validator);
        const pid = (await validator.query("select pg_backend_pid() as pid")).rows[0].pid as number;
        pending = validator.query(lockSql, input.args).catch((error: unknown) => error);
        await awaitDatabaseLock(pool, pid);
        await modifier.query("begin");
        // This succeeds only if the waiting validator has not taken the key lock first.
        await modifier.query("select id from crypto_key_registry where id=$1 for update nowait", [
          input.keyId
        ]);
        await modifier.query(
          "update crypto_key_registry set retired_at=clock_timestamp() where id=$1",
          [input.keyId]
        );
        await modifier.query("commit");
        await blocker.query("commit");
        expect(await pending).toMatchObject({ code: "40001" });
      } finally {
        await modifier.query("rollback");
        await blocker.query("rollback");
        if (pending) await pending;
        await validator.query("rollback");
        modifier.release();
        blocker.release();
        validator.release();
      }
      await expect(validate(pool, input.args)).rejects.toMatchObject({ code: "55000" });
      await expect(
        validate(pool, (await prepared(pool, organizationId)).args)
      ).resolves.toMatchObject({ rowCount: 1 });
    });
  });
});
