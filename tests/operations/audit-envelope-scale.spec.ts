import { spawn } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { withUnseededWorker } from "../helpers/unseeded-worker.js";
import { seedValidAuditEnvelope } from "../helpers/valid-audit-envelope.js";

describe("valid signed audit history verification envelope", () => {
  it.each([1000, 1_000_000])(
    "verifies %i real hash-chain events and captures the backup boundary in a bounded subprocess",
    async (total) => {
      await withUnseededWorker("audit-envelope", async ({ pool, config, backupKeyId }) => {
        const start = Date.now();
        const seeded = await seedValidAuditEnvelope(pool, config, total);
        // This is a conservative diagnostic heap budget, not a changed frozen release target.
        // Parent ownership keeps fixture cleanup alive if the child exhausts its heap.
        const result = await new Promise<{
          code: number | null;
          signal: string | null;
          stdout: string;
          stderr: string;
          timedOut: boolean;
        }>((resolve, reject) => {
          const child = spawn(
            process.execPath,
            [
              "--max-old-space-size=512",
              "--import",
              "tsx",
              path.resolve(import.meta.dirname, "verify-audit-envelope-child.ts")
            ],
            {
              cwd: path.resolve(import.meta.dirname, "../.."),
              env: {
                ...process.env,
                BOARDAGENT_TEST_DATABASE_URL: pool.options.connectionString,
                BOARDAGENT_AUDIT_FIXTURE_COUNT: String(total),
                BOARDAGENT_TEST_BACKUP_KEY_ID: backupKeyId
              },
              stdio: ["ignore", "pipe", "pipe"]
            }
          );
          let stdout = "",
            stderr = "";
          let timedOut = false;
          child.stdout.on("data", (value: Buffer) => {
            stdout = (stdout + value.toString()).slice(-16_000);
          });
          child.stderr.on("data", (value: Buffer) => {
            stderr = (stderr + value.toString()).slice(-16_000);
          });
          // Share the existing five-minute case budget, reserving 30 seconds for cleanup.
          const timeout = setTimeout(
            () => {
              timedOut = true;
              child.kill("SIGKILL");
            },
            Math.max(1, 270_000 - (Date.now() - start))
          );
          child.once("error", (error) => {
            clearTimeout(timeout);
            reject(error);
          });
          child.once("close", (code, signal) => {
            clearTimeout(timeout);
            resolve({ code, signal, stdout, stderr, timedOut });
          });
        });
        process.stdout.write(
          JSON.stringify({
            kind: "signed-audit-envelope-diagnostic",
            fixture: seeded,
            elapsedMilliseconds: Date.now() - start,
            ...result
          }) + "\n"
        );
        expect(result.timedOut).toBe(false);
        expect(result.signal).toBeNull();
        expect(result.code).toBe(0);
        expect(JSON.parse(result.stdout.trim().split("\n").at(-1)!)).toMatchObject({
          status: "passed",
          eventCount: String(total)
        });
      });
    },
    300_000
  );
});
