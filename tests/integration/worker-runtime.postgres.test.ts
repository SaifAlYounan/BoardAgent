import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  BoardAgentTypedWorker,
  TypedJobExecutionError,
  type TypedJobHandler
} from "../../artifacts/server/src/worker.js";
import { loadBoardAgentKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { runtimeKeyRegistrations } from "../../artifacts/server/src/runtime-binding.js";
import { probeWorkerHealth } from "../../artifacts/server/src/worker-health.js";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  enqueueRequestJobInTransaction,
  migrate,
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { uuidV7 } from "../../lib/domain/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";

async function withDatabase<T>(run: (pool: Pool, databaseUrl: string) => Promise<T>): Promise<T> {
  const database = `boardagent_worker_runtime_${String(process.pid)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`drop database if exists "${database}" with (force)`);
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "worker-runtime-test");
    return await run(pool, testUrl.toString());
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

describe("executable typed worker coordinator", () => {
  it("runs external handlers outside the claim transaction and commits bounded outcomes", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      let behavior: "succeed" | "retry" | "dead" = "succeed";
      const handler: TypedJobHandler = async ({ job, signal }) => {
        expect(signal.aborted).toBe(false);
        expect(job.envelope.jobType).toBe("question_due_scan");
        // A fresh connection can be used while this handler runs: the worker is not
        // holding its claim transaction open around external or long-running work.
        expect((await pool.query("select 1 as alive")).rows[0]).toEqual({ alive: 1 });
        if (behavior === "retry") {
          throw new TypedJobExecutionError("temporary_dependency", false);
        }
        if (behavior === "dead") {
          throw new TypedJobExecutionError("invalid_job_target", true);
        }
        return { processed: true };
      };
      const worker = new BoardAgentTypedWorker(pool, {
        handlers: new Map([["question_due_scan", handler]]),
        workerId: "worker-runtime-test",
        assumeRole: "boardagent_worker",
        pollMilliseconds: 25
      });
      expect(() => worker.assertCompleteRegistry()).toThrow(
        "worker handler registry is incomplete"
      );

      const enqueue = async (jobId: string, key: string): Promise<void> => {
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId,
              idempotencyKey: key,
              envelope: {
                schemaVersion: "boardagent.job.question_due_scan.v1",
                organizationId: actor.organizationId,
                boardId: actor.boardId,
                jobType: "question_due_scan",
                subjectType: "board",
                subjectId: actor.boardId,
                parameters: { through: "2026-09-03T00:00:00Z" }
              }
            }),
          { assumeRole: "boardagent_server" }
        );
      };

      const succeededId = testId(37_000);
      await enqueue(succeededId, "worker-runtime-success");
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: succeededId,
        jobType: "question_due_scan",
        attempt: 1
      });

      behavior = "retry";
      const retriedId = testId(37_001);
      await enqueue(retriedId, "worker-runtime-retry");
      expect(await worker.runOnce()).toMatchObject({
        status: "retry_scheduled",
        jobId: retriedId,
        errorClass: "temporary_dependency"
      });

      behavior = "dead";
      const deadId = testId(37_002);
      await enqueue(deadId, "worker-runtime-permanent-failure");
      expect(await worker.runOnce()).toMatchObject({
        status: "dead",
        jobId: deadId,
        errorClass: "invalid_job_target"
      });

      const states = await pool.query<{
        id: string;
        state: string;
        last_error_class: string | null;
      }>(
        `select id,state,last_error_class from jobs
          where id=any($1::uuid[]) order by id`,
        [[succeededId, retriedId, deadId]]
      );
      expect(states.rows).toEqual([
        { id: succeededId, state: "succeeded", last_error_class: null },
        { id: retriedId, state: "retry", last_error_class: "temporary_dependency" },
        { id: deadId, state: "dead", last_error_class: "invalid_job_target" }
      ]);
      expect(await worker.runOnce()).toEqual({ status: "idle" });
    });
  });

  it("starts the complete production worker command and exits cleanly on SIGTERM", async () => {
    await withDatabase(async (pool, databaseUrl) => {
      const organizationId = testId(37_100);
      const instanceId = testId(37_101);
      const artifactRoot = await mkdtemp(path.join(tmpdir(), "boardagent-worker-process-"));
      const secret = "worker-process-test-secret-material-is-long-enough";
      const configured = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: databaseUrl,
        BOARDAGENT_ORGANIZATION_ID: organizationId,
        BOARDAGENT_PUBLIC_BASE_URL: "https://worker.boardagent.test",
        BOARDAGENT_AUTHORIZATION_MODE: "builtin",
        BOARDAGENT_BLOB_ROOT: artifactRoot,
        BOARDAGENT_DEV_MASTER_SECRET: secret,
        BOARDAGENT_TRUSTED_PROXY_HOPS: "1",
        BOARDAGENT_WEBHOOKS_ENABLED: "false"
      } satisfies NodeJS.ProcessEnv;
      const config = parseConfig(configured);
      const keys = await loadBoardAgentKeyMaterial(config);
      const registrations = runtimeKeyRegistrations(config, keys, () =>
        uuidV7(Date.now(), randomBytes(10))
      );
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Worker Process Ltd','Worker Process','worker-process','UTC')",
        [organizationId]
      );
      await pool.query(
        "insert into system_instance(instance_id,organization_id,canonical_resource_uri) values ($1,$2,$3)",
        [instanceId, organizationId, config.canonicalResourceUri]
      );
      await withBootstrapTransaction(
        pool,
        (client) => registerRuntimeKeysInTransaction(client, organizationId, registrations),
        { assumeRole: "boardagent_migrator" }
      );

      const inherited = Object.fromEntries(
        Object.entries(process.env).filter(([name]) => !name.startsWith("BOARDAGENT_"))
      );
      const child = spawn(
        path.resolve("node_modules/.bin/tsx"),
        ["--tsconfig", "artifacts/server/tsconfig.json", "artifacts/server/src/main.ts", "worker"],
        {
          cwd: path.resolve("."),
          env: { ...inherited, ...configured },
          stdio: ["ignore", "pipe", "pipe"]
        }
      );
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => (stdout += chunk));
      child.stderr.on("data", (chunk: string) => (stderr += chunk));
      const closed = new Promise<number | null>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", resolve);
      });
      try {
        await new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(
            () => reject(new Error(`worker did not start: ${stderr}`)),
            15_000
          );
          const inspect = (): void => {
            if (!stderr.includes('"event":"worker.started"')) return;
            clearTimeout(timeout);
            resolve();
          };
          child.stderr.on("data", inspect);
          child.once("exit", (code) => {
            clearTimeout(timeout);
            reject(new Error(`worker exited before startup (${String(code)}): ${stderr}`));
          });
          inspect();
        });
        await expect.poll(() => probeWorkerHealth(), { timeout: 10_000 }).toBe(true);
        child.kill("SIGTERM");
        const code = await closed;
        expect(code, `${stdout}\n${stderr}`).toBe(0);
        expect(await probeWorkerHealth()).toBe(false);
        expect(stderr).toContain('"event":"worker.started"');
        expect(stderr).toContain('"event":"worker.stopped"');
        expect(stderr).not.toContain(secret);
      } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
        await rm(artifactRoot, { recursive: true, force: true });
      }
    });
  }, 60_000);
});
