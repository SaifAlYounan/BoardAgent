import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { expect } from "vitest";

import { loadBoardAgentKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { runtimeKeyRegistrations } from "../../artifacts/server/src/runtime-binding.js";
import { startBoardAgentWorker } from "../../artifacts/server/src/worker-process.js";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  registerBackupKeyInTransaction,
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { uuidV7 } from "../../lib/domain/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withMigratedDatabase } from "./postgres-fixture.js";

export const newWorkerTestId = (): string => uuidV7(Date.now(), randomBytes(10));

/** Real bootstrap and runtime key binding, with no enrolled human and no injected jobs. */
export async function withUnseededWorker<T>(
  label: string,
  run: (fixture: {
    pool: import("pg").Pool;
    organizationId: string;
    boardId: string;
    backupKeyId: string;
    config: ReturnType<typeof parseConfig>;
    start: (pollMilliseconds?: number) => Promise<void>;
    assertRunning: () => void;
  }) => Promise<T>
): Promise<T> {
  return withMigratedDatabase(label, async (pool) => {
    const artifactRoot = await mkdtemp(path.join(tmpdir(), "boardagent-unseeded-worker-"));
    const running: { abort: AbortController; loop: Promise<void>; close: () => Promise<void> }[] =
      [];
    let runError: unknown;
    try {
      const initialized = await new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator"
      }).initialize({
        organizationLegalName: "Synthetic Worker Checkpoint Ltd",
        organizationDisplayName: "Synthetic Worker Checkpoint",
        organizationSlug: "synthetic-checkpoint",
        timezone: "UTC",
        canonicalResourceUri: "https://checkpoint.boardagent.test/mcp",
        boardSlug: "main-board",
        boardName: "Synthetic Board",
        boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", synthetic: true },
        firstSecretaryLegalName: "Unenrolled synthetic setup person",
        firstSecretaryDisplayName: "Unenrolled setup",
        votingWeight: 1,
        supportName: "Synthetic operator",
        supportContactMethods: [{ kind: "operator_reference", value: "local-test" }],
        onboardingTermsText: "Synthetic test only; no human ceremony is performed.",
        invitationHandoffMethod: "not delivered in this automated test"
      });
      if (initialized.status !== "created") throw new Error("fresh bootstrap expected");
      const config = parseConfig({
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: "postgresql://unused",
        BOARDAGENT_ORGANIZATION_ID: initialized.organizationId,
        BOARDAGENT_PUBLIC_BASE_URL: "https://checkpoint.boardagent.test",
        BOARDAGENT_AUTHORIZATION_MODE: "builtin",
        BOARDAGENT_BLOB_ROOT: artifactRoot,
        BOARDAGENT_DEV_MASTER_SECRET: "first-checkpoint-test-secret-material-is-long-enough",
        BOARDAGENT_TRUSTED_PROXY_HOPS: "1",
        BOARDAGENT_WEBHOOKS_ENABLED: "false"
      });
      const keys = await loadBoardAgentKeyMaterial(config);
      const backupKeyId = newWorkerTestId();
      await withBootstrapTransaction(
        pool,
        async (client) => {
          await registerRuntimeKeysInTransaction(
            client,
            initialized.organizationId,
            runtimeKeyRegistrations(config, keys, newWorkerTestId)
          );
          await registerBackupKeyInTransaction(
            client,
            initialized.organizationId,
            backupKeyId,
            "a".repeat(64)
          );
        },
        { assumeRole: "boardagent_migrator" }
      );
      expect((await pool.query("select count(*)::int as count from jobs")).rows[0]?.count).toBe(0);
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]?.count
      ).toBe(0);
      expect(
        (await pool.query("select count(*)::int as count from clock_health_samples")).rows[0]?.count
      ).toBe(0);
      return await run({
        pool,
        organizationId: initialized.organizationId,
        boardId: initialized.boardId,
        backupKeyId,
        config,
        assertRunning: () => {
          if (runError) throw runError;
        },
        start: async (pollMilliseconds = 25) => {
          const worker = await startBoardAgentWorker(config, {
            pool,
            assumeRole: "boardagent_worker",
            pollMilliseconds,
            // The test records no successful delivery to an external operator.
            onOperationalAlert: () => undefined
          });
          const abort = new AbortController();
          const loop = worker.run(abort.signal).catch((error: unknown) => {
            runError = error;
          });
          running.push({ abort, loop, close: () => worker.close() });
        }
      });
    } finally {
      for (const worker of running) worker.abort.abort();
      await Promise.all(
        running.map(async (worker) => {
          await worker.loop;
          await worker.close();
        })
      );
      await rm(artifactRoot, { recursive: true, force: true });
    }
  });
}
