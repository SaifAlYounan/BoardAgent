import { describe, expect, it } from "vitest";
import * as db from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";
import { randomBytes } from "node:crypto";
import type { Pool } from "pg";
import { canonicalJson } from "../../lib/contracts/src/index.js";

async function prepare(pool: Pool, organizationId: string) {
  const target = (
    await pool.query(
      "select instance_id,(select id from crypto_key_registry where purpose='browser_session') as key_id from system_instance"
    )
  ).rows[0];
  return db.withBootstrapTransaction(
    pool,
    (c) =>
      db.prepareKeyLifecycleInTransaction(c, {
        instanceId: target.instance_id,
        organizationId,
        keyId: target.key_id,
        operationId: newWorkerTestId(),
        operation: "retire",
        replacement: null,
        declaredCompromisedAt: null,
        retainedMaterialSha256: "a".repeat(64),
        operatorReference: "Synthetic operator",
        reason: "Browser lifecycle rollback regression"
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
}
async function session(pool: Pool, organizationId: string) {
  const id = newWorkerTestId();
  await pool.query(
    "insert into auth_sessions(id,organization_id,opaque_session_sha256,state,exact_origin,expires_at) values($1,$2,$3,'anonymous','https://boardagent.test',transaction_timestamp()+interval '1 hour')",
    [id, organizationId, randomBytes(32)]
  );
  return id;
}

describe("browser key lifecycle", () => {
  it("retires the browser key through an audited operator transaction", async () => {
    await withUnseededWorker("browser-key-retire", async ({ pool, organizationId }) => {
      const target = (
        await pool.query(
          "select instance_id,(select id from crypto_key_registry where purpose='browser_session') as key_id from system_instance"
        )
      ).rows[0];
      const input = await db.withBootstrapTransaction(
        pool,
        (c) =>
          db.prepareKeyLifecycleInTransaction(c, {
            instanceId: target.instance_id,
            organizationId,
            keyId: target.key_id,
            operationId: newWorkerTestId(),
            operation: "retire",
            replacement: null,
            declaredCompromisedAt: null,
            retainedMaterialSha256: "a".repeat(64),
            operatorReference: "Synthetic operator",
            reason: "Browser key database test"
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const receipt = await db.withBootstrapTransaction(
        pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(receipt.replayed).toBe(false);
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            target.key_id
          ])
        ).rows[0].retired_at
      ).not.toBeNull();
    });
  });

  it("rolls back browser revocation when the real operation lacks its audit and completion", async () => {
    await withUnseededWorker("browser-key-incomplete", async ({ pool, organizationId }) => {
      const sessionId = await session(pool, organizationId);
      const input = await prepare(pool, organizationId);
      const { observedAt: _observedAt, ...dependencies } =
        input.request.expectedInventory.keyDependencies;
      let reachedRevocation = false;
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            await c.query("select * from boardagent_begin_key_lifecycle($1,$2,$3)", [
              Buffer.from(canonicalJson(input.request)),
              Buffer.from(input.requestSha256, "hex"),
              Buffer.from(
                canonicalJson({ ...input.request.expectedInventory, keyDependencies: dependencies })
              )
            ]);
            expect(
              (await c.query("select state from auth_sessions where id=$1", [sessionId])).rows[0]
                .state
            ).toBe("revoked");
            reachedRevocation = true;
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(reachedRevocation).toBe(true);
      expect(
        (await pool.query("select state from auth_sessions where id=$1", [sessionId])).rows[0].state
      ).toBe("anonymous");
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_browser_effects")).rows[0].n
      ).toBe(0);
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            input.request.keyId
          ])
        ).rows[0].retired_at
      ).toBeNull();
    });
  });

  it("checks complete session rows at commit even after a receipt was created", async () => {
    await withUnseededWorker("browser-key-row-integrity", async ({ pool, organizationId }) => {
      const sessionId = await session(pool, organizationId);
      const before = (await pool.query("select * from auth_sessions where id=$1", [sessionId]))
        .rows[0];
      const input = await prepare(pool, organizationId);
      let reachedReceipt = false;
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            await db.applyKeyLifecycleInTransaction(c, input);
            reachedReceipt = true;
            // Deliberate owner-level fault injection, not a runtime permission claim.
            await c.query("reset role");
            await c.query(
              "update auth_sessions set exact_origin='https://altered.test' where id=$1",
              [sessionId]
            );
            await c.query("set local role boardagent_migrator");
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(reachedReceipt).toBe(true);
      expect(
        (await pool.query("select * from auth_sessions where id=$1", [sessionId])).rows[0]
      ).toEqual(before);
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_browser_effects")).rows[0].n
      ).toBe(0);
    });
  });

  it("denies runtime effect writes and operator claims without the actual operation", async () => {
    await withUnseededWorker("browser-key-effect-authority", async ({ pool, organizationId }) => {
      const sessionId = await session(pool, organizationId);
      const insert = (c: import("pg").PoolClient) =>
        c.query(
          "insert into key_lifecycle_browser_effects(operation_id,target_type,target_id,session_id) values($1,'session',$2,$2)",
          [newWorkerTestId(), sessionId]
        );
      for (const assumeRole of [
        "boardagent_server",
        "boardagent_worker",
        "boardagent_backup"
      ] as const) {
        const c = await pool.connect();
        try {
          await c.query("begin isolation level serializable");
          await c.query(`set local role ${assumeRole}`);
          await c.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(insert(c)).rejects.toMatchObject({ code: "42501" });
        } finally {
          await c.query("rollback");
          c.release();
        }
      }
      await expect(
        db.withBootstrapTransaction(pool, insert, { assumeRole: "boardagent_migrator" })
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (await pool.query("select state from auth_sessions where id=$1", [sessionId])).rows[0].state
      ).toBe("anonymous");
    });
  });
});
