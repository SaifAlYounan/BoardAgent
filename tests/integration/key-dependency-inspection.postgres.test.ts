import { describe, expect, it } from "vitest";
import {
  inspectKeyDependenciesInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { withUnseededWorker } from "../helpers/unseeded-worker.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedRecoveredAudit } from "../helpers/recovered-audit.js";

describe("operator key dependency inspection", () => {
  it("reports every declared key foreign-key dependency for all five purposes without changing records", async () => {
    await withUnseededWorker("key-dependency-inspection", async ({ pool, organizationId }) => {
      const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
        .instance_id;
      const before = (
        await pool.query("select to_jsonb(k) as key from crypto_key_registry k order by id")
      ).rows;
      for (const { key } of before) {
        const inspection = await withBootstrapTransaction(
          pool,
          async (client) => {
            return (
              await client.query(
                "select boardagent_inspect_key_dependencies($1,$2,$3) as inspection",
                [instanceId, organizationId, key.id]
              )
            ).rows[0].inspection;
          },
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
        expect(inspection).toMatchObject({
          schemaVersion: "boardagent.key-dependency-inspection.v1",
          instanceId,
          organizationId,
          keyId: key.id
        });
        expect(inspection.foreignKeyDependencies).toHaveLength(15);
        expect(
          inspection.foreignKeyDependencies.map(
            (entry: { table: string; column: string }) => `${entry.table}.${entry.column}`
          )
        ).toContain("totp_credentials.key_id");
        expect(inspection.foreignKeyDependencies).toContainEqual({
          table: "key_lifecycle_operations",
          column: "key_id",
          rowCount: "0",
          rowsSha256: "0".repeat(64)
        });
        expect(inspection.foreignKeyDependencies).toContainEqual({
          table: "key_lifecycle_operations",
          column: "replacement_key_id",
          rowCount: "0",
          rowsSha256: "0".repeat(64)
        });
        expect(inspection.totalReferences).toBe("0");
      }
      expect(
        (await pool.query("select to_jsonb(k) as key from crypto_key_registry k order by id")).rows
      ).toEqual(before);
    });
  });
});

describe("key inspection snapshot invariants", () => {
  it("keeps state digests identical across operator display settings", async () => {
    await withUnseededWorker("key-dependency-settings", async ({ pool, organizationId }) => {
      const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
        .instance_id;
      const keyId = (
        await pool.query("select id from crypto_key_registry where purpose='data_kek'")
      ).rows[0].id;
      await withBootstrapTransaction(
        pool,
        async (client) => {
          await client.query("set local timezone='UTC'");
          await client.query("set local bytea_output='hex'");
          const first = (
            await client.query(
              "select boardagent_inspect_key_dependencies($1,$2,$3) as inspection",
              [instanceId, organizationId, keyId]
            )
          ).rows[0].inspection;
          await client.query("set local timezone='Pacific/Honolulu'");
          await client.query("set local bytea_output='escape'");
          const second = (
            await client.query(
              "select boardagent_inspect_key_dependencies($1,$2,$3) as inspection",
              [instanceId, organizationId, keyId]
            )
          ).rows[0].inspection;
          expect(second.keyStateSha256).toBe(first.keyStateSha256);
          expect(second.foreignKeyDependencies).toEqual(first.foreignKeyDependencies);
        },
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
    });
  });
});

async function inspectionTarget(
  pool: import("pg").Pool,
  organizationId: string,
  purpose = "data_kek"
) {
  return {
    organizationId,
    instanceId: (await pool.query("select instance_id from system_instance")).rows[0]
      .instance_id as string,
    keyId: (
      await pool.query("select id from crypto_key_registry where purpose=$1 order by id limit 1", [
        purpose
      ])
    ).rows[0].id as string
  };
}

describe("protected key dependency facts", () => {
  it("keeps revoked rows, detects ciphertext/state changes and omits their private contents", async () => {
    await withUnseededWorker("key-dependency-content", async ({ pool, organizationId }) => {
      const target = await inspectionTarget(pool, organizationId);
      const memberId = (await pool.query("select id from members order by id limit 1")).rows[0].id;
      const read = () =>
        withBootstrapTransaction(
          pool,
          (client) => inspectKeyDependenciesInTransaction(client, target),
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
      const empty = await read();
      await pool.query(
        "insert into member_contact_points(id,organization_id,member_id,kind,protected_value,key_id,verified_at,state) values($1,$2,$3,'operator_reference',$4,$5,transaction_timestamp(),'active')",
        [
          testId(124_000),
          organizationId,
          memberId,
          Buffer.from("private-synthetic-contact-value"),
          target.keyId
        ]
      );
      const active = await read();
      expect(active.inspection.totalReferences).toBe("1");
      expect(
        active.inspection.foreignKeyDependencies.find(
          (entry) => entry.table === "member_contact_points"
        )
      ).toMatchObject({ rowCount: "1" });
      expect(JSON.stringify(active)).not.toContain("private-synthetic-contact-value");
      expect(JSON.stringify(active)).not.toContain(
        Buffer.from("private-synthetic-contact-value").toString("hex")
      );
      expect(active.stateSha256).not.toBe(empty.stateSha256);
      expect((await read()).stateSha256).toBe(active.stateSha256);
      await pool.query(
        "update member_contact_points set protected_value=$1,state='revoked' where id=$2",
        [Buffer.from("changed-synthetic-contact-value"), testId(124_000)]
      );
      const revoked = await read();
      expect(revoked.inspection.totalReferences).toBe("1");
      expect(revoked.stateSha256).not.toBe(active.stateSha256);
    });
  });
  it("uses a stable transaction snapshot while later writes become visible to the next inspection", async () => {
    await withUnseededWorker("key-dependency-snapshot", async ({ pool, organizationId }) => {
      const target = await inspectionTarget(pool, organizationId);
      const memberId = (await pool.query("select id from members order by id limit 1")).rows[0].id;
      const earlier = await withBootstrapTransaction(
        pool,
        async (client) => {
          const first = await inspectKeyDependenciesInTransaction(client, target);
          await pool.query(
            "insert into member_contact_points(id,organization_id,member_id,kind,protected_value,key_id,verified_at,state) values($1,$2,$3,'operator_reference',$4,$5,transaction_timestamp(),'revoked')",
            [testId(124_100), organizationId, memberId, Buffer.alloc(32, 177), target.keyId]
          );
          expect((await inspectKeyDependenciesInTransaction(client, target)).stateSha256).toBe(
            first.stateSha256
          );
          return first;
        },
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const later = await withBootstrapTransaction(
        pool,
        (client) => inspectKeyDependenciesInTransaction(client, target),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      expect(later.inspection.totalReferences).toBe("1");
      expect(later.stateSha256).not.toBe(earlier.stateSha256);
    });
  });
  it("discovers a new reference column and refuses an unreviewed table instead of reporting it empty", async () => {
    await withUnseededWorker("key-dependency-catalog", async ({ pool, organizationId }) => {
      const target = await inspectionTarget(pool, organizationId);
      const read = () =>
        withBootstrapTransaction(
          pool,
          (client) => inspectKeyDependenciesInTransaction(client, target),
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
      const before = await read();
      await pool.query(
        "alter table member_contact_points add column prior_key_id uuid references crypto_key_registry(id)"
      );
      const expanded = await read();
      expect(expanded.inspection.foreignKeyDependencies).toHaveLength(16);
      expect(expanded.inspection.foreignKeyDependencies).toContainEqual({
        table: "member_contact_points",
        column: "prior_key_id",
        rowCount: "0",
        rowsSha256: "0".repeat(64)
      });
      expect(expanded.stateSha256).not.toBe(before.stateSha256);
      await pool.query(
        "create table future_key_references(id uuid primary key,key_id uuid references crypto_key_registry(id))"
      );
      await pool.query("alter table future_key_references enable row level security");
      await pool.query("alter table future_key_references force row level security");
      await pool.query("insert into future_key_references values($1,$2)", [
        testId(124_200),
        target.keyId
      ]);
      await expect(read()).rejects.toMatchObject({
        code: "55000",
        message: "key dependency lacks an explicit operator inventory policy"
      });
    });
  });
  it("includes immutable audit-recovery authority as a real evidence-key dependency", async () => {
    await withMigratedDatabase("key-recovery-dependencies", async (pool) => {
      const fixture = await seedRecoveredAudit(pool),
        target = await inspectionTarget(pool, fixture.actor.organizationId, "evidence_signing");
      const result = await withBootstrapTransaction(
        pool,
        (client) => inspectKeyDependenciesInTransaction(client, target),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      expect(
        result.inspection.foreignKeyDependencies.find((entry) => entry.table === "audit_recoveries")
      ).toMatchObject({ rowCount: "1" });
      expect(BigInt(result.inspection.totalReferences)).toBeGreaterThan(1n);
    });
  });
  it("refuses runtime roles even when they claim bootstrap scope", async () => {
    await withUnseededWorker("key-dependency-authority", async ({ pool, organizationId }) => {
      const target = await inspectionTarget(pool, organizationId);
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"] as const) {
        const client = await pool.connect();
        try {
          await client.query("begin isolation level serializable read only");
          await client.query(`set local role ${role}`);
          await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(inspectKeyDependenciesInTransaction(client, target)).rejects.toMatchObject({
            code: "42501"
          });
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
    });
  });
  it("refuses writing or inconsistent transactions and wrong installation/key targets", async () => {
    await withUnseededWorker("key-dependency-target", async ({ pool, organizationId }) => {
      const target = await inspectionTarget(pool, organizationId);
      await expect(
        withBootstrapTransaction(
          pool,
          (client) => inspectKeyDependenciesInTransaction(client, target),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "25000" });
      const client = await pool.connect();
      try {
        await client.query("begin isolation level read committed read only");
        await client.query("set local role boardagent_migrator");
        await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
        await expect(inspectKeyDependenciesInTransaction(client, target)).rejects.toMatchObject({
          code: "25000"
        });
      } finally {
        await client.query("rollback");
        client.release();
      }
      for (const field of ["instanceId", "organizationId", "keyId"] as const) {
        await expect(
          withBootstrapTransaction(
            pool,
            (client) =>
              inspectKeyDependenciesInTransaction(client, { ...target, [field]: testId(124_300) }),
            { assumeRole: "boardagent_migrator", readOnly: true }
          )
        ).rejects.toMatchObject({ code: "23503" });
      }
    });
  });
});
