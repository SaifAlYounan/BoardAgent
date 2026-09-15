import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { Pool } from "pg";
import {
  captureBackupBoundaryInTransaction,
  verifyPersistedAuditEvidence,
  withBackupTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

// The parent supplies only a disposable local database and synthetic public key identity.
const pool = new Pool({ connectionString: process.env["BOARDAGENT_TEST_DATABASE_URL"], max: 2 });
try {
  const started = performance.now();
  const verified = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
    assumeRole: "boardagent_worker"
  });
  assert.equal(verified.valid, true);
  if (!verified.valid) throw new Error("invalid audit fixture");
  assert.equal(verified.ready, true);
  assert.equal(verified.eventCount, process.env["BOARDAGENT_AUDIT_FIXTURE_COUNT"]);
  const verifyMilliseconds = performance.now() - started;
  process.stdout.write(
    JSON.stringify({
      status: "audit_verification_passed",
      eventCount: verified.eventCount,
      verifyMilliseconds,
      memory: process.memoryUsage()
    }) + "\n"
  );
  const backupStarted = performance.now();
  const boundary = await withBackupTransaction(
    pool,
    (client) =>
      captureBackupBoundaryInTransaction(client, {
        receiptId: testId(30_000_001),
        encryptionKeyId: process.env["BOARDAGENT_TEST_BACKUP_KEY_ID"]!,
        encryptionKeyFingerprintSha256: "a".repeat(64)
      }),
    { assumeRole: "boardagent_backup" }
  );
  assert.equal(boundary.auditBoundary.eventCount, verified.eventCount);
  process.stdout.write(
    JSON.stringify({
      status: "passed",
      eventCount: verified.eventCount,
      checkpointCount: verified.checkpointCount,
      verifyMilliseconds,
      backupMilliseconds: performance.now() - backupStarted,
      memory: process.memoryUsage(),
      maximumRssKiB: process.resourceUsage().maxRSS
    }) + "\n"
  );
} catch (error) {
  process.stdout.write(
    JSON.stringify({
      status: "failed",
      errorClass: error instanceof Error ? error.name : "unknown"
    }) + "\n"
  );
  process.exitCode = 1;
} finally {
  await pool.end();
}
