import { copyFile, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { signCheckpoint, signRecoveryCheckpoint } from "../../lib/audit/src/index.js";
import {
  loadMigrations,
  migrate,
  appendAuditEventsInTransaction,
  applyAuditRecoveryInTransaction,
  prepareAuditRecoveryInTransaction,
  verifyPersistedAuditEvidence,
  withBootstrapTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAgedAudit } from "../helpers/aged-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
async function withOldFullAudit(
  run: (
    pool: Pool,
    directory: string,
    fixture: Awaited<ReturnType<typeof seedAgedAudit>>
  ) => Promise<void>
) {
  const base = new URL(
    process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
      "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent"
  );
  const database = `boardagent_full_upgrade_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
  const adminUrl = new URL(base);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  base.pathname = `/${database}`;
  const pool = new Pool({ connectionString: base.toString(), max: 4 });
  const directory = await mkdtemp(path.join(tmpdir(), "boardagent-full-upgrade-"));
  try {
    const old = path.join(directory, "old");
    await mkdir(old);
    for (const migration of (await loadMigrations(MIGRATIONS)).slice(0, 121))
      await copyFile(path.join(MIGRATIONS, migration.name), path.join(old, migration.name));
    expect(await migrate(pool, old, "old-audit-full-fixture")).toBe(121);
    const fixture = await seedAgedAudit(pool, { eventCount: 1000 });
    await run(pool, directory, fixture);
  } finally {
    await pool.end();
    await dropClosedTestDatabase(admin, database);
    await admin.end();
    await rm(directory, { recursive: true, force: true });
  }
}

describe("installing recovery support with an old full audit backlog", () => {
  it("serializes competing full-backlog upgrades without duplicate audit receipts", async () => {
    await withOldFullAudit(async (pool) => {
      const pending = (await loadMigrations(MIGRATIONS)).length - 121;
      const results = await Promise.all([
        migrate(pool, MIGRATIONS, "concurrent-upgrade-a"),
        migrate(pool, MIGRATIONS, "concurrent-upgrade-b")
      ]);
      expect(results.toSorted((a, b) => a - b)).toEqual([0, pending]);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='migration_applied'"
          )
        ).rows
      ).toEqual([{ n: pending }]);
    });
  });

  it("refuses unreceipted migration commit and runtime ledger writes despite forged scope", async () => {
    await withOldFullAudit(async (pool) => {
      await migrate(pool, MIGRATIONS, "migration-receipt-guard");
      const next = (await loadMigrations(MIGRATIONS)).length + 1;
      const name = `${String(next).padStart(4, "0")}_synthetic_unreceipted.sql`;
      const client = await pool.connect();
      try {
        await client.query("begin");
        await client.query("set local role boardagent_migrator");
        await client.query("select set_config('boardagent.transaction_scope','migration',true)");
        await client.query(
          "insert into schema_migrations(version,name,sha256,app_build) values($1,$2,$3,$4)",
          [next, name, "ab".repeat(32), "synthetic-unreceipted"]
        );
        await expect(client.query("commit")).rejects.toMatchObject({ code: "23514" });
        await client.query("rollback");
        for (const role of [
          "boardagent_server",
          "boardagent_worker",
          "boardagent_backup"
        ] as const) {
          await client.query("begin");
          await client.query(`set local role ${role}`);
          await client.query("select set_config('boardagent.transaction_scope','migration',true)");
          await expect(
            client.query(
              "insert into schema_migrations(version,name,sha256,app_build) values($1,$2,$3,$4)",
              [next, name, "ab".repeat(32), "synthetic-runtime"]
            )
          ).rejects.toMatchObject({ code: "42501" });
          await client.query("rollback");
          await client.query("begin");
          await client.query(`set local role ${role}`);
          await expect(
            client.query(
              "update schema_migrations set audit_transaction_id=pg_current_xact_id() where version=126"
            )
          ).rejects.toMatchObject({ code: "42501" });
          await client.query("rollback");
        }
      } finally {
        await client.query("rollback");
        client.release();
      }
      expect(
        (await pool.query("select max(version)::int as version from schema_migrations")).rows
      ).toEqual([{ version: next - 1 }]);
    });
  });

  it("installs and audits the exact pending upgrade without ordinary admission, then recovers intact history", async () => {
    await withOldFullAudit(async (pool, _directory, fixture) => {
      const migrations = await loadMigrations(MIGRATIONS);
      const before = (
        await pool.query(
          "select canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
        )
      ).rows;
      const ledger = (
        await pool.query(
          "select version,name,sha256,applied_at,app_build from schema_migrations order by version"
        )
      ).rows;
      await expect(
        migrate(pool, MIGRATIONS, "recovery-upgrade-test", { assumeRole: "boardagent_migrator" })
      ).resolves.toBe(migrations.length - 121);
      expect(
        (
          await pool.query(
            "select canonical_payload,event_sha256,occurred_at from audit_events where sequence<=1000 order by sequence"
          )
        ).rows
      ).toEqual(before);
      expect(
        (
          await pool.query(
            "select version,name,sha256,applied_at,app_build from schema_migrations where version<=121 order by version"
          )
        ).rows
      ).toEqual(ledger);
      const receipts = (
        await pool.query(
          "select canonical_payload from audit_events where sequence>1000 order by sequence"
        )
      ).rows;
      expect(receipts.map((r) => JSON.parse(r.canonical_payload.toString("utf8")).details)).toEqual(
        migrations.slice(121).map((m) => ({
          version: m.version,
          name: m.name,
          sha256: m.sha256,
          appBuild: "recovery-upgrade-test"
        }))
      );
      const copied = JSON.parse(receipts[0]!.canonical_payload.toString("utf8"));
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            appendAuditEventsInTransaction(client, [
              {
                organizationId: fixture.actor.organizationId,
                event: { ...copied, eventId: testId(115_001) }
              }
            ]),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({
        code: "55000",
        constraint: "boardagent_audit_checkpoint_capacity"
      });
      const input = {
        recoveryId: testId(115_010),
        instanceId: testId(15),
        organizationId: fixture.actor.organizationId,
        signingKeyId: fixture.keyId,
        operatorReference: "synthetic-upgrade-incident",
        reason: "Recover retained evidence after installing the signing outage repair."
      };
      const prepared = await withBootstrapTransaction(
        pool,
        (client) => prepareAuditRecoveryInTransaction(client, input),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      let nextId = 115_100;
      await withBootstrapTransaction(
        pool,
        (client) =>
          applyAuditRecoveryInTransaction(
            client,
            {
              request: prepared.request,
              requestSha256: prepared.requestSha256,
              instanceId: input.instanceId,
              organizationId: input.organizationId
            },
            {
              createId: () => testId(nextId++),
              sign: async (payload) =>
                payload.schema === "boardagent.audit.recovery-checkpoint.v1"
                  ? signRecoveryCheckpoint(payload, fixture.evidence.privateKey)
                  : signCheckpoint(payload, fixture.evidence.privateKey)
            }
          ),
        { assumeRole: "boardagent_migrator" }
      );
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({
        valid: true,
        ready: true,
        warnings: [`recovery:${input.recoveryId}:historical_checkpoint_deadline_missed`]
      });
    });
  });

  it("rolls back the pending upgrade as one unit if later DDL fails", async () => {
    await withOldFullAudit(async (pool, directory) => {
      const candidate = path.join(directory, "candidate");
      await mkdir(candidate);
      const migrations = await loadMigrations(MIGRATIONS);
      for (const migration of migrations)
        await copyFile(path.join(MIGRATIONS, migration.name), path.join(candidate, migration.name));
      await writeFile(
        path.join(
          candidate,
          `${String(migrations.length + 1).padStart(4, "0")}_synthetic_failure.sql`
        ),
        "create table synthetic_recovery_upgrade_partial(id integer); select missing_recovery_upgrade_function();"
      );
      await expect(
        migrate(pool, candidate, "failed-recovery-upgrade", { assumeRole: "boardagent_migrator" })
      ).rejects.toThrow(/missing_recovery_upgrade_function/u);
      expect(
        (await pool.query("select max(version)::int as version from schema_migrations")).rows
      ).toEqual([{ version: 121 }]);
      expect((await pool.query("select count(*)::int as n from audit_events")).rows).toEqual([
        { n: 1000 }
      ]);
      expect(
        (
          await pool.query(
            "select to_regclass('public.audit_recoveries') as recovery,to_regclass('public.synthetic_recovery_upgrade_partial') as partial"
          )
        ).rows
      ).toEqual([{ recovery: null, partial: null }]);
    });
  });
});
