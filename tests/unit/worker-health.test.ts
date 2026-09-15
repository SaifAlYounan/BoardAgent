import { mkdtemp, rm, symlink, writeFile, chmod } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { startWorkerHealth, probeWorkerHealth } from "../../artifacts/server/src/worker-health.js";

describe("worker container readiness", () => {
  it("requires recent successful work, detects stalled progress, recovers and refuses after shutdown", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "ba-worker-health-"));
    const socketPath = path.join(directory, "status.sock");
    let now = 100_000;
    const health = await startWorkerHealth({ socketPath, now: () => now });
    try {
      expect(await probeWorkerHealth(socketPath)).toBe(false);
      health.progress();
      expect(await probeWorkerHealth(socketPath)).toBe(true);
      now += 30_001;
      expect(await probeWorkerHealth(socketPath)).toBe(false);
      health.progress();
      expect(await probeWorkerHealth(socketPath)).toBe(true);
      now -= 1;
      expect(await probeWorkerHealth(socketPath)).toBe(false);
    } finally {
      await health.close();
      expect(await probeWorkerHealth(socketPath)).toBe(false);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("does not overwrite a regular file, follow a symlink or accept a shared socket directory", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "ba-worker-health-"));
    const socketPath = path.join(directory, "status.sock");
    const target = path.join(directory, "preserved");
    try {
      await writeFile(socketPath, "unrelated");
      await expect(startWorkerHealth({ socketPath })).rejects.toThrow(
        "unsafe worker health socket"
      );
      await rm(socketPath);
      await writeFile(target, "preserved");
      await symlink(target, socketPath);
      await expect(startWorkerHealth({ socketPath })).rejects.toThrow(
        "unsafe worker health socket"
      );
      await rm(socketPath);
      await chmod(directory, 0o755);
      await expect(startWorkerHealth({ socketPath })).rejects.toThrow("private and owned");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
