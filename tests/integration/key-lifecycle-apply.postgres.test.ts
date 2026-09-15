import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import type { Pool } from "pg";
import * as db from "../../lib/db/src/index.js";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import { KeyLifecycleChangedSchema } from "../../lib/audit/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

async function prepare(
  pool: Pool,
  organizationId: string,
  operation: "retire" | "mark_compromised" = "retire",
  declaredCompromisedAt: string | null = null,
  purpose = "evidence_signing"
) {
  const row = (
    await pool.query(
      "select instance_id,(select id from crypto_key_registry where purpose=$1) as key_id from system_instance",
      [purpose]
    )
  ).rows[0];
  return db.withBootstrapTransaction(
    pool,
    (c) =>
      db.prepareKeyLifecycleInTransaction(c, {
        instanceId: row.instance_id,
        organizationId,
        keyId: row.key_id,
        operationId: newWorkerTestId(),
        operation,
        replacement: null,
        declaredCompromisedAt,
        retainedMaterialSha256: "a".repeat(64),
        operatorReference: "Synthetic operator",
        reason: "Database-only test; no custody assertion"
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
}
function beginArguments(input: Awaited<ReturnType<typeof prepare>>) {
  const { observedAt: _observedAt, ...dependencies } =
    input.request.expectedInventory.keyDependencies;
  return [
    Buffer.from(canonicalJson(input.request)),
    Buffer.from(input.requestSha256, "hex"),
    Buffer.from(
      canonicalJson({ ...input.request.expectedInventory, keyDependencies: dependencies })
    )
  ];
}
const beginSql = "select * from boardagent_begin_key_lifecycle($1,$2,$3)";

describe("atomic operator key lifecycle", () => {
  it("retires an evidence key with an immutable operation and audit receipt, then replays exactly", async () => {
    await withUnseededWorker("key-lifecycle-retire", async ({ pool, organizationId }) => {
      const target = (
        await pool.query(
          "select instance_id,(select id from crypto_key_registry where purpose='evidence_signing') as key_id from system_instance"
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
            operatorReference: "Synthetic maintenance",
            reason: "Database retirement test; no file custody claim"
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const run = () =>
        db.withBootstrapTransaction(pool, (c) => db.applyKeyLifecycleInTransaction(c, input), {
          assumeRole: "boardagent_migrator"
        });
      const first = await run();
      expect(first.replayed).toBe(false);
      expect(first.operationId).toBe(input.request.operationId);
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            target.key_id
          ])
        ).rows[0].retired_at
      ).not.toBeNull();
      const replay = await run();
      expect(replay).toEqual({ ...first, replayed: true });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='key_lifecycle_changed'"
          )
        ).rows[0].n
      ).toBe(1);
    });
  });

  it("rolls back the key change if its audit or completion is missing", async () => {
    await withUnseededWorker("key-lifecycle-incomplete", async ({ pool, organizationId }) => {
      const input = await prepare(pool, organizationId);
      const before = (
        await pool.query("select * from crypto_key_registry where id=$1", [input.request.keyId])
      ).rows;
      await expect(
        db.withBootstrapTransaction(pool, (c) => c.query(beginSql, beginArguments(input)), {
          assumeRole: "boardagent_migrator"
        })
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (await pool.query("select * from crypto_key_registry where id=$1", [input.request.keyId]))
          .rows
      ).toEqual(before);
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
      const result = await db.withBootstrapTransaction(
        pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(result.replayed).toBe(false);
    });
  });

  it("refuses altered audit facts and rolls back both the operation and key change", async () => {
    await withUnseededWorker("key-lifecycle-audit-failure", async ({ pool, organizationId }) => {
      const input = await prepare(pool, organizationId);
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            const begun = (await c.query(beginSql, beginArguments(input))).rows[0];
            const details = KeyLifecycleChangedSchema.parse(begun.details);
            await db.appendAuditEventsInTransaction(c, [
              {
                organizationId,
                event: {
                  eventId: input.request.operationId,
                  eventType: "key_lifecycle_changed",
                  actorMemberId: null,
                  actorClientId: null,
                  tokenJti: null,
                  boardId: null,
                  entityType: "key_lifecycle_operation",
                  entityId: input.request.operationId,
                  origin: "cli",
                  schemaVersion: 1,
                  details: { ...details, reason: "Different audit facts" }
                }
              }
            ]);
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            input.request.keyId
          ])
        ).rows[0].retired_at
      ).toBeNull();
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='key_lifecycle_changed'"
          )
        ).rows[0].n
      ).toBe(0);
    });
  });

  it("preserves compromise history and returns the original receipt even after a later earlier-time report", async () => {
    await withUnseededWorker("key-lifecycle-compromise", async ({ pool, organizationId }) => {
      await pool.query(
        "update crypto_key_registry set activated_at=clock_timestamp()-interval '1 hour' where purpose='evidence_signing'"
      );
      const times = (
        await pool.query(`select to_char((clock_timestamp()-interval '20 minutes') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as first,
        to_char((clock_timestamp()-interval '30 minutes') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as earlier`)
      ).rows[0];
      const firstInput = await prepare(pool, organizationId, "mark_compromised", times.first);
      const run = (input: typeof firstInput) =>
        db.withBootstrapTransaction(pool, (c) => db.applyKeyLifecycleInTransaction(c, input), {
          assumeRole: "boardagent_migrator"
        });
      const first = await run(firstInput);
      const earlierInput = await prepare(pool, organizationId, "mark_compromised", times.earlier);
      const earlier = await run(earlierInput);
      expect(first.details.after.compromisedAt).toBe(times.first);
      expect(earlier.details.before.compromisedAt).toBe(times.first);
      expect(earlier.details.after.compromisedAt).toBe(times.earlier);
      expect(await run(firstInput)).toEqual({ ...first, replayed: true });
      await expect(
        prepare(pool, organizationId, "mark_compromised", times.first)
      ).rejects.toThrow();
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(2);
    });
  });

  it("refuses changed retries and leaves immutable operation and receipt records intact", async () => {
    await withUnseededWorker("key-lifecycle-retry", async ({ pool, organizationId }) => {
      const input = await prepare(pool, organizationId);
      const first = await db.withBootstrapTransaction(
        pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      const request = { ...input.request, reason: "Changed retry" };
      await expect(
        db.withBootstrapTransaction(
          pool,
          (c) =>
            db.applyKeyLifecycleInTransaction(c, {
              request,
              requestSha256: canonicalSha256(request)
            }),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "55000" });
      // Even the fixture's superuser cannot accidentally update/delete these rows through normal DML.
      for (const sql of [
        "update key_lifecycle_operations set authorizing_principal='changed'",
        "delete from key_lifecycle_operations",
        "update key_lifecycle_completions set completed_at=clock_timestamp()",
        "delete from key_lifecycle_completions"
      ])
        await expect(pool.query(sql)).rejects.toThrow();
      expect(
        await db.withBootstrapTransaction(
          pool,
          (c) => db.applyKeyLifecycleInTransaction(c, input),
          { assumeRole: "boardagent_migrator" }
        )
      ).toEqual({ ...first, replayed: true });
    });
  });

  it("denies runtime roles even with a claimed bootstrap scope and denies forged completion", async () => {
    await withUnseededWorker("key-lifecycle-authority", async ({ pool, organizationId }) => {
      const input = await prepare(pool, organizationId);
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
        const c = await pool.connect();
        try {
          await c.query("begin isolation level serializable");
          await c.query(`set local role ${role}`);
          await c.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(c.query(beginSql, beginArguments(input))).rejects.toMatchObject({
            code: "42501"
          });
        } finally {
          await c.query("rollback");
          c.release();
        }
      }
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            await c.query(beginSql, beginArguments(input));
            await c.query(
              "insert into key_lifecycle_completions(operation_id,audit_event_id) values($1,$2)",
              [input.request.operationId, newWorkerTestId()]
            );
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            input.request.keyId
          ])
        ).rows[0].retired_at
      ).toBeNull();
    });
  });

  it("refuses duplicate-key request bytes before any key is changed", async () => {
    await withUnseededWorker("key-lifecycle-duplicate", async ({ pool, organizationId }) => {
      const input = await prepare(pool, organizationId);
      const args = beginArguments(input);
      const raw = Buffer.from(
        '{"reason":"hidden extra value",' + args[0]!.toString("utf8").slice(1)
      );
      args[0] = raw;
      args[1] = createHash("sha256").update(raw).digest();
      const c = await pool.connect();
      try {
        await c.query("begin isolation level serializable");
        await c.query("set local role boardagent_migrator");
        await c.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
        await expect(c.query(beginSql, args)).rejects.toMatchObject({ code: "55000" });
      } finally {
        await c.query("rollback");
        c.release();
      }
    });
  });

  it("refuses unrelated key metadata changes after the audit receipt and rolls back the transaction", async () => {
    await withUnseededWorker(
      "key-lifecycle-post-receipt-change",
      async ({ pool, organizationId }) => {
        const input = await prepare(pool, organizationId);
        const before = (
          await pool.query("select * from crypto_key_registry where id=$1", [input.request.keyId])
        ).rows;
        await expect(
          db.withBootstrapTransaction(
            pool,
            async (c) => {
              await db.applyKeyLifecycleInTransaction(c, input);
              await c.query(
                "update crypto_key_registry set nonsecret_locator='file:/unexpected/key.pem' where id=$1",
                [input.request.keyId]
              );
            },
            { assumeRole: "boardagent_migrator" }
          )
        ).rejects.toMatchObject({ code: "23514" });
        expect(
          (await pool.query("select * from crypto_key_registry where id=$1", [input.request.keyId]))
            .rows
        ).toEqual(before);
      }
    );
  });

  it("serializes simultaneous exact retries into one change and one event", async () => {
    await withUnseededWorker("key-lifecycle-concurrent-retry", async ({ pool, organizationId }) => {
      const input = await prepare(pool, organizationId);
      const run = () =>
        db.withBootstrapTransaction(pool, (c) => db.applyKeyLifecycleInTransaction(c, input), {
          assumeRole: "boardagent_migrator"
        });
      const receipts = await Promise.all([run(), run()]);
      expect(receipts.map((r) => r.replayed).sort()).toEqual([false, true]);
      expect({ ...receipts[0], replayed: false }).toEqual({ ...receipts[1], replayed: false });
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(1);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='key_lifecycle_changed'"
          )
        ).rows[0].n
      ).toBe(1);
    });
  });

  it("refuses unsupported purpose claims without changing any key", async () => {
    await withUnseededWorker("key-lifecycle-unsupported", async ({ pool, organizationId }) => {
      const before = (
        await pool.query("select to_jsonb(k) as key from crypto_key_registry k order by id")
      ).rows;
      const input = await prepare(pool, organizationId);
      const invalid = { ...input.request, purpose: "unknown_key_purpose" };
      const args = beginArguments(input);
      args[0] = Buffer.from(canonicalJson(invalid));
      args[1] = Buffer.from(canonicalSha256(invalid), "hex");
      await expect(
        db.withBootstrapTransaction(pool, (c) => c.query(beginSql, args), {
          assumeRole: "boardagent_migrator"
        })
      ).rejects.toMatchObject({ code: "55000" });

      expect(
        (await pool.query("select to_jsonb(k) as key from crypto_key_registry k order by id")).rows
      ).toEqual(before);
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
    });
  });

  it("refuses a matching-looking event without its real operation and requires completion after a real event", async () => {
    await withUnseededWorker("key-lifecycle-forged-audit", async ({ pool, organizationId }) => {
      const input = await prepare(pool, organizationId);
      let saved: ReturnType<typeof KeyLifecycleChangedSchema.parse> | undefined;
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            const begun = (await c.query(beginSql, beginArguments(input))).rows[0];
            const details = KeyLifecycleChangedSchema.parse(begun.details);
            saved = details;
            await db.appendAuditEventsInTransaction(c, [
              {
                organizationId,
                event: {
                  eventId: input.request.operationId,
                  eventType: "key_lifecycle_changed",
                  actorMemberId: null,
                  actorClientId: null,
                  tokenJti: null,
                  boardId: null,
                  entityType: "key_lifecycle_operation",
                  entityId: input.request.operationId,
                  origin: "cli",
                  schemaVersion: 1,
                  details
                }
              }
            ]);
            // A genuine audit append alone is insufficient: the operation must also complete.
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(saved).toBeDefined();
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            const time = (await c.query("select occurred_at from boardagent_lock_audit_head()"))
              .rows[0].occurred_at as string;
            const details = KeyLifecycleChangedSchema.parse({
              ...saved,
              recordedAt: time,
              after: { ...saved!.after, retiredAt: time }
            });
            await db.appendAuditEventsInTransaction(c, [
              {
                organizationId,
                event: {
                  eventId: input.request.operationId,
                  eventType: "key_lifecycle_changed",
                  actorMemberId: null,
                  actorClientId: null,
                  tokenJti: null,
                  boardId: null,
                  entityType: "key_lifecycle_operation",
                  entityId: input.request.operationId,
                  origin: "cli",
                  schemaVersion: 1,
                  details
                }
              }
            ]);
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            input.request.keyId
          ])
        ).rows[0].retired_at
      ).toBeNull();
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='key_lifecycle_changed'"
          )
        ).rows[0].n
      ).toBe(0);
    });
  });
});
