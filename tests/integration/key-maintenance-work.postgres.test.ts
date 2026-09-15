import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import type { Pool } from "pg";
import {
  withBootstrapTransaction,
  withWorkerTransaction,
  inspectKeyMaintenanceWorkInTransaction,
  scheduleAuditCheckpointInTransaction,
  claimTypedJobInTransaction,
  completeTypedJobInTransaction,
  KEY_MAINTENANCE_WORK_GROUPS
} from "../../lib/db/src/index.js";
import {
  PgTotpService,
  PgRateLimiter,
  generateTotpCodeFromBase32,
  loadBoardAgentKeyMaterial
} from "../../artifacts/server/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

async function targetFor(pool: Pool, organizationId: string, purpose = "data_kek") {
  return {
    instanceId: (await pool.query("select instance_id from system_instance")).rows[0]
      .instance_id as string,
    keyId: (await pool.query("select id from crypto_key_registry where purpose=$1", [purpose]))
      .rows[0].id as string,
    organizationId
  };
}
function inspect(pool: Pool, target: Awaited<ReturnType<typeof targetFor>>) {
  return withBootstrapTransaction(
    pool,
    (client) => inspectKeyMaintenanceWorkInTransaction(client, target),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
}
function group(
  result: Awaited<ReturnType<typeof inspect>>,
  name: (typeof KEY_MAINTENANCE_WORK_GROUPS)[number]
) {
  return result.inventory.groups.find((g) => g.name === name)!;
}

describe("operator key maintenance work inventory", () => {
  it("identifies unfinished work independently of direct key foreign keys", async () => {
    await withUnseededWorker("key-maintenance-work", async ({ pool, organizationId }) => {
      const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
        .instance_id;
      const keyId = (
        await pool.query("select id from crypto_key_registry where purpose='data_kek'")
      ).rows[0].id;
      const result = await withBootstrapTransaction(
        pool,
        async (client) => {
          return (
            await client.query(
              "select boardagent_inspect_key_maintenance_work($1,$2,$3) as inventory",
              [instanceId, organizationId, keyId]
            )
          ).rows[0].inventory;
        },
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      expect(result.schemaVersion).toBe("boardagent.key-maintenance-work.v1");
      expect(
        result.groups.find((entry: { name: string }) => entry.name === "leased_jobs")
      ).toMatchObject({ rowCount: "0" });
      expect(
        result.groups.find((entry: { name: string }) => entry.name === "pending_totp")
      ).toMatchObject({ rowCount: "0" });
    });
  });

  it("tracks real queued, leased and retry work even when it has no key-ID foreign key", async () => {
    await withUnseededWorker("key-work-lease", async ({ pool, organizationId }) => {
      const target = await targetFor(pool, organizationId);
      const empty = await inspect(pool, target);
      const scheduled = await withWorkerTransaction(
        pool,
        (client) => scheduleAuditCheckpointInTransaction(client, newWorkerTestId()),
        { assumeRole: "boardagent_worker" }
      );
      expect(scheduled.scheduling_status).toBe("scheduled");
      const queued = await inspect(pool, target);
      expect(group(queued, "unfinished_jobs").rowCount).toBe("1");
      expect(group(queued, "leased_jobs").rowCount).toBe("0");
      expect(queued.inventory.keyDependencies.totalReferences).toBe("0");
      expect(queued.stateSha256).not.toBe(empty.stateSha256);
      const lease = await withWorkerTransaction(
        pool,
        (client) =>
          claimTypedJobInTransaction(client, { leaseOwner: "key-work-test", leaseSeconds: 30 }),
        { assumeRole: "boardagent_worker" }
      );
      expect(lease.claimed).toBe(true);
      if (!lease.claimed) throw new Error("expected actual protected job lease");
      const leased = await inspect(pool, target);
      expect(group(leased, "leased_jobs").rowCount).toBe("1");
      expect(group(leased, "unfinished_jobs").rowCount).toBe("0");
      expect(leased.stateSha256).not.toBe(queued.stateSha256);
      expect((await inspect(pool, target)).stateSha256).toBe(leased.stateSha256);
      await withWorkerTransaction(
        pool,
        (client) =>
          completeTypedJobInTransaction(client, {
            jobId: lease.job.jobId,
            attempt: lease.job.attempt,
            leaseToken: lease.job.leaseToken,
            leaseOwner: "key-work-test",
            result: "retryable_failure",
            resultSha256: "a".repeat(64),
            errorClass: "synthetic_retry"
          }),
        { assumeRole: "boardagent_worker" }
      );
      const retry = await inspect(pool, target);
      expect(group(retry, "leased_jobs").rowCount).toBe("0");
      expect(group(retry, "unfinished_jobs").rowCount).toBe("1");
      expect(group(retry, "unfinished_jobs").rowsSha256).not.toBe(
        group(queued, "unfinished_jobs").rowsSha256
      );
      expect(JSON.stringify(retry)).not.toContain(lease.job.leaseToken);
    });
  });

  it("distinguishes actual unfinished TOTP enrollment from an activated factor without exposing secrets", async () => {
    await withUnseededWorker("key-work-totp", async ({ pool, organizationId, config }) => {
      const target = await targetFor(pool, organizationId);
      const memberId = newWorkerTestId();
      // Synthetic appointment fixture; no human identity or custody ceremony is claimed.
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Synthetic secretary','Synthetic secretary','active')",
        [memberId, organizationId]
      );
      await pool.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'secretariat','Synthetic key work test')",
        [newWorkerTestId(), organizationId, memberId]
      );
      const keys = await loadBoardAgentKeyMaterial(config);
      const rateLimiter = new PgRateLimiter(pool, {
        hmacKey: randomBytes(32),
        assumeRole: "boardagent_server"
      });
      const policy = { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 };
      const totp = new PgTotpService(pool, {
        issuer: "Synthetic maintenance",
        activeKeyId: target.keyId,
        keys: new Map([[target.keyId, keys.dataEncryptionKey]]),
        rateLimiter,
        rateLimits: { ip: policy, client: policy, member: policy, token: policy },
        maxFailedAttempts: 5,
        lockoutSeconds: 300,
        assumeRole: "boardagent_server"
      });
      const pending = await totp.beginEnrollment({
        organizationId,
        memberId,
        authorizedByMemberId: memberId
      });
      const pendingWork = await inspect(pool, target);
      expect(group(pendingWork, "pending_totp").rowCount).toBe("1");
      expect(group(pendingWork, "active_totp").rowCount).toBe("0");
      expect(JSON.stringify(pendingWork)).not.toContain(pending.secretBase32);
      const now = Number(
        (await pool.query("select floor(extract(epoch from clock_timestamp())) as now")).rows[0].now
      );
      await totp.completeEnrollment({
        organizationId,
        credentialId: pending.credentialId,
        authorizedByMemberId: memberId,
        code: generateTotpCodeFromBase32(pending.secretBase32, now)
      });
      const active = await inspect(pool, target);
      expect(group(active, "pending_totp").rowCount).toBe("0");
      expect(group(active, "active_totp").rowCount).toBe("1");
      const unrelated = await inspect(
        pool,
        await targetFor(pool, organizationId, "browser_session")
      );
      expect(group(unrelated, "active_totp").rowCount).toBe("0");
    });
  });

  it("keeps typed snapshot groups complete and stable across all purposes and display settings", async () => {
    await withUnseededWorker("key-work-snapshot", async ({ pool, organizationId }) => {
      for (const purpose of [
        "oauth_signing",
        "evidence_signing",
        "browser_session",
        "data_kek",
        "backup_kek"
      ]) {
        const target = await targetFor(pool, organizationId, purpose);
        await withBootstrapTransaction(
          pool,
          async (client) => {
            const first = await inspectKeyMaintenanceWorkInTransaction(client, target);
            await client.query("set local timezone='Pacific/Honolulu'");
            await client.query("set local bytea_output='escape'");
            const next = await inspectKeyMaintenanceWorkInTransaction(client, target);
            expect(next.stateSha256).toBe(first.stateSha256);
            expect(first.inventory.groups.map((g) => g.name)).toEqual(KEY_MAINTENANCE_WORK_GROUPS);
          },
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
      }
    });
  });

  it("refuses runtime callers, writable transactions and wrong installation targets", async () => {
    await withUnseededWorker("key-work-authority", async ({ pool, organizationId }) => {
      const target = await targetFor(pool, organizationId);
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"] as const) {
        const client = await pool.connect();
        try {
          await client.query("begin isolation level serializable read only");
          await client.query(`set local role ${role}`);
          await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(
            inspectKeyMaintenanceWorkInTransaction(client, target)
          ).rejects.toMatchObject({ code: "42501" });
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
      await expect(
        withBootstrapTransaction(
          pool,
          (client) => inspectKeyMaintenanceWorkInTransaction(client, target),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "25000" });
      for (const field of ["instanceId", "organizationId", "keyId"] as const)
        await expect(
          inspect(pool, { ...target, [field]: newWorkerTestId() })
        ).rejects.toMatchObject({ code: "23503" });
    });
  });
});
