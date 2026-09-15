import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Pool } from "pg";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  BackupManifestSchema,
  RestoreReceiptManifestSchema,
  migrate,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");

async function withLegacyDatabase(run: (pool: Pool) => Promise<void>) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-receipt-schema-"));
  const database = `boardagent_receipt_legacy_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
  const databaseUrl = new URL(
    process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
      "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent"
  );
  databaseUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: databaseUrl.toString(), max: 1 });
  let pool: Pool | undefined;
  let created = false;
  try {
    // Byte-identical historical migrations exercise an actual forward upgrade.
    // No receipt guards, evidence immutability or RLS controls are disabled.
    for (const name of await readdir(MIGRATIONS)) {
      if (/^\d{4}_[a-z0-9_]+\.sql$/u.test(name) && Number(name.slice(0, 4)) <= 157) {
        await copyFile(path.join(MIGRATIONS, name), path.join(directory, name));
      }
    }
    await admin.query(`create database "${database}"`);
    created = true;
    databaseUrl.pathname = `/${database}`;
    pool = new Pool({ connectionString: databaseUrl.toString(), max: 2 });
    await migrate(pool, directory, "receipt-legacy-test");
    await run(pool);
  } finally {
    await pool?.end();
    if (created) await dropClosedTestDatabase(admin, database);
    await admin.end();
    await rm(directory, { recursive: true, force: true });
  }
}

function health(pool: Pool, organizationId: string) {
  return withWorkerTransaction(
    pool,
    (client) =>
      client.query("select * from boardagent_backup_receipt_health($1)", [organizationId]),
    { assumeRole: "boardagent_worker" }
  );
}

async function fixture(pool: Pool) {
  const organizationId = testId(770001);
  const instanceId = testId(770002);
  const encryptionKeyId = testId(770003);
  await pool.query(
    "insert into organizations(id,legal_name,display_name,slug,timezone) values($1,'Synthetic receipt test','Synthetic receipt test','receipt-test','UTC')",
    [organizationId]
  );
  await pool.query(
    "insert into system_instance(instance_id,organization_id,canonical_resource_uri) values($1,$2,'https://receipt.test/mcp')",
    [instanceId, organizationId]
  );
  await pool.query(
    `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,nonsecret_locator,activated_at)
     values($1,$2,'synthetic-receipt-backup','backup_kek','A256GCM',$3,transaction_timestamp()-interval '1 minute')`,
    [encryptionKeyId, organizationId, "sha256:" + "a".repeat(64)]
  );
  const time = (
    await pool.query<{ at: string }>(
      `select to_char(transaction_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as at`
    )
  ).rows[0]!.at;
  // Complete schema-valid synthetic metadata isolates the SQL receipt boundary.
  // No backup artifact was created or restored, and these are not operational receipts.
  const manifest = BackupManifestSchema.parse({
    schemaVersion: "boardagent.backup-receipt.v1",
    receiptKind: "backup",
    receiptId: testId(770004),
    instanceId,
    organizationId,
    sourceDatabase: "synthetic_source",
    snapshotId: "synthetic-snapshot",
    snapshotLsn: "0/1",
    snapshotAt: time,
    migrationLedger: [
      {
        version: 1,
        name: "0001_synthetic.sql",
        sha256: "a".repeat(64),
        appBuild: "synthetic",
        appliedAt: time
      }
    ],
    migrationLedgerSha256: "a".repeat(64),
    publicSigningKeys: [],
    publicKeyRegistrySha256: "a".repeat(64),
    auditBoundary: { eventCount: "0", headSha256: "0".repeat(64), latestCheckpoint: null },
    tableInventory: [{ table: "organizations", rowCount: "1", rowsSha256: "a".repeat(64) }],
    schemaAuthoritySha256: "a".repeat(64),
    contentSetSha256: "a".repeat(64),
    encryptionKeyId,
    secretContinuity: "operator-custodied-secrets-not-contained-in-database-backup",
    retention: { daily: 7, weekly: 4, monthly: 12 },
    artifact: {
      format: "postgresql-custom-encrypted-v1",
      encryptedStorageLocator: "synthetic-unwritten-artifact",
      artifactSha256: "a".repeat(64),
      byteLength: "1",
      pgDumpVersion: "synthetic",
      encryptionTool: "synthetic",
      sourceImageDigest: "sha256:" + "a".repeat(64)
    }
  });
  return {
    manifest,
    insert: (candidate: Record<string, unknown>) =>
      withWorkerTransaction(
        pool,
        (client) =>
          client.query(
            `insert into backup_receipts(id,organization_id,receipt_kind,schema_version,canonical_manifest,
         manifest_sha256,snapshot_lsn,snapshot_at,content_set_sha256,encryption_key_id,state)
         values($1,$2,'backup',$3,$4,$5,$6::pg_lsn,$7::timestamptz,$8,$9,'created')`,
            [
              manifest.receiptId,
              organizationId,
              manifest.schemaVersion,
              Buffer.from(canonicalJson(candidate)),
              Buffer.from(canonicalSha256(candidate), "hex"),
              manifest.snapshotLsn,
              manifest.snapshotAt,
              Buffer.from(manifest.contentSetSha256, "hex"),
              encryptionKeyId
            ]
          ),
        { assumeRole: "boardagent_worker" }
      ),
    restore: (patch: Record<string, unknown> = {}) => {
      const validReceipt = RestoreReceiptManifestSchema.parse({
        schemaVersion: "boardagent.restore-receipt.v1",
        receiptKind: "restore",
        receiptId: testId(770005),
        instanceId,
        organizationId,
        snapshotLsn: manifest.snapshotLsn,
        snapshotAt: manifest.snapshotAt,
        contentSetSha256: manifest.contentSetSha256,
        encryptionKeyId,
        sourceBackupReceiptId: manifest.receiptId,
        sourceBackupManifestSha256: canonicalSha256(manifest),
        sourceDatabase: "synthetic_source",
        restoredDatabase: "synthetic_restore",
        sourceArtifactSha256: "a".repeat(64),
        verifiedAt: time,
        verification: {
          tableCount: 1,
          rowCount: "1",
          certificateCount: 0,
          auditEventCount: "0",
          auditHeadSha256: "0".repeat(64),
          auditCheckpointCount: 0,
          schemaAuthoritySha256: "a".repeat(64),
          transactionReadOnly: true,
          evidenceRepaired: false,
          failures: []
        }
      });
      const receipt = { ...validReceipt, ...patch };
      return withWorkerTransaction(
        pool,
        (client) =>
          client.query(
            `insert into backup_receipts(id,organization_id,receipt_kind,schema_version,canonical_manifest,
         manifest_sha256,snapshot_lsn,snapshot_at,content_set_sha256,encryption_key_id,state,
         source_backup_receipt_id,verified_restore_at)
         values($1,$2,'restore','boardagent.restore-receipt.v1',$3,$4,$5::pg_lsn,$6::timestamptz,$7,$8,
         'verified',$9,$6::timestamptz)`,
            [
              testId(770005),
              organizationId,
              Buffer.from(canonicalJson(receipt)),
              Buffer.from(canonicalSha256(receipt), "hex"),
              manifest.snapshotLsn,
              time,
              Buffer.from(manifest.contentSetSha256, "hex"),
              encryptionKeyId,
              manifest.receiptId
            ]
          ),
        { assumeRole: "boardagent_worker" }
      );
    }
  };
}

describe("backup receipt exact SQL field binding", () => {
  it("accepts matching schema-valid synthetic receipt fields", async () => {
    await withMigratedDatabase("receipt-binding-control", async (pool) => {
      const f = await fixture(pool);
      await expect(f.insert(f.manifest)).resolves.toMatchObject({ rowCount: 1 });
      await expect(f.restore()).resolves.toMatchObject({ rowCount: 1 });
      expect((await health(pool, f.manifest.organizationId)).rows[0]).toMatchObject({
        checked_receipts: "2",
        manifest_schema_mismatches: "0",
        manifest_binding_mismatches: "0"
      });
    });
  });

  it.each([
    "instanceId",
    "receiptId",
    "organizationId",
    "encryptionKeyId",
    "snapshotLsn",
    "snapshotAt",
    "contentSetSha256",
    "receiptKind"
  ])("refuses null %s even when the row values and raw manifest hash agree", async (field) => {
    await withMigratedDatabase("receipt-binding-null", async (pool) => {
      const f = await fixture(pool);
      const candidate = { ...f.manifest, [field]: null };
      expect(BackupManifestSchema.safeParse(candidate).success).toBe(false);
      const outcome = await f.insert(candidate).then(
        () => "inserted",
        () => "rejected"
      );
      expect(outcome).toBe("rejected");
    });
  });

  it("refuses a missing bound identity field", async () => {
    await withMigratedDatabase("receipt-binding-missing", async (pool) => {
      const f = await fixture(pool);
      const candidate: Record<string, unknown> = { ...f.manifest };
      delete candidate["instanceId"];
      await expect(f.insert(candidate)).rejects.toMatchObject({ code: "23514" });
    });
  });

  it.each(["sourceBackupReceiptId", "sourceBackupManifestSha256", "verifiedAt"])(
    "refuses null restore %s",
    async (field) => {
      await withMigratedDatabase("restore-binding-null", async (pool) => {
        const f = await fixture(pool);
        await f.insert(f.manifest);
        await expect(f.restore({ [field]: null })).rejects.toMatchObject({ code: "23514" });
      });
    }
  );

  it("detects a previously admitted null instance identity after forward migration", async () => {
    await withLegacyDatabase(async (pool) => {
      const f = await fixture(pool);
      expect(
        (await pool.query("select max(version) as version from schema_migrations")).rows[0]?.version
      ).toBe(157);
      const candidate = { ...f.manifest, instanceId: null };
      await f.insert(candidate);
      const before = (
        await pool.query("select canonical_manifest,manifest_sha256 from backup_receipts")
      ).rows;
      expect(await migrate(pool, MIGRATIONS, "receipt-health-upgrade-test")).toBeGreaterThanOrEqual(
        1
      );
      expect(
        (await pool.query("select name from schema_migrations where version=158")).rows
      ).toEqual([{ name: "0158_backup_receipt_null_binding.sql" }]);
      expect(
        (
          await pool.query(`select count(*)::int as count from audit_events
        where event_type='migration_applied'
        and convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'name'='0158_backup_receipt_null_binding.sql'`)
        ).rows[0]?.count
      ).toBe(1);
      expect((await health(pool, f.manifest.organizationId)).rows[0]).toMatchObject({
        checked_receipts: "1",
        manifest_schema_mismatches: "1",
        manifest_binding_mismatches: "1"
      });
      expect(
        (await pool.query("select canonical_manifest,manifest_sha256 from backup_receipts")).rows
      ).toEqual(before);
    });
  });
});
