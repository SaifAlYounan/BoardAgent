import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import {
  appendFile,
  chmod,
  mkdtemp,
  open,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import { BackupKeyIdentitySchema } from "../../lib/db/src/index.js";
import {
  readBackupKeyReceipt,
  verifyBackupKeyReceipt,
  writeBackupKeyReceipt
} from "../../scripts/src/backup-key-binding.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, open: vi.fn(actual.open) };
});

afterEach(() => vi.restoreAllMocks());

const key = Buffer.alloc(32, 0x51);
const identity = BackupKeyIdentitySchema.parse({
  instanceId: "018f0000-0000-7000-8000-000000000001",
  organizationId: "018f0000-0000-7000-8000-000000000002",
  keyId: "018f0000-0000-7000-8000-000000000099",
  kid: "backup-test",
  purpose: "backup_kek",
  algorithm: "A256GCM",
  activatedAt: "2026-09-07T00:00:00.123456Z",
  fingerprintSha256: createHash("sha256").update(key).digest("hex")
});

describe("offline backup-key identity receipt", () => {
  it("accepts a stable receipt at the byte limit and refuses one byte beyond it", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-key-receipt-limit-"));
    try {
      const published = await writeBackupKeyReceipt(directory, identity);
      await chmod(published.receiptFile, 0o600);
      const original = await readFile(published.receiptFile);
      await appendFile(published.receiptFile, " ".repeat(8192 - original.byteLength));
      await expect(readBackupKeyReceipt(published.receiptFile)).resolves.toEqual(published.receipt);
      await appendFile(published.receiptFile, " ");
      await expect(readBackupKeyReceipt(published.receiptFile)).rejects.toThrow("bounded");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses a named pipe without waiting for a writer", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-key-receipt-pipe-"));
    const fifo = path.join(directory, "receipt.json");
    let release: Awaited<ReturnType<typeof open>> | undefined;
    let pending: Promise<string> | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      expect(spawnSync("mkfifo", ["-m", "600", fifo], { encoding: "utf8" }).status).toBe(0);
      pending = readBackupKeyReceipt(fifo).then(
        () => "accepted",
        () => "refused"
      );
      const outcome = await Promise.race([
        pending,
        new Promise<string>((resolve) => {
          timer = setTimeout(() => resolve("blocked awaiting writer"), 1000);
        })
      ]);
      expect(outcome).toBe("refused");
    } finally {
      if (timer) clearTimeout(timer);
      // Release an old blocking open before cleanup, so a failing-before run cannot hang.
      if (pending) {
        release = await open(fifo, constants.O_RDWR | constants.O_NONBLOCK);
        await pending;
      }
      await release?.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses a receipt that grows beyond the byte limit after its first stat", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-key-receipt-growth-"));
    try {
      const published = await writeBackupKeyReceipt(directory, identity);
      await chmod(published.receiptFile, 0o600);
      const handle = await open(published.receiptFile, constants.O_RDONLY);
      const originalStat = handle.stat.bind(handle);
      vi.spyOn(handle, "stat").mockImplementationOnce(async () => {
        const before = await originalStat();
        // Valid JSON with excessive trailing whitespace models growth between stat and read.
        await appendFile(published.receiptFile, " ".repeat(8193));
        return before;
      });
      vi.mocked(open).mockResolvedValueOnce(handle);
      await expect(readBackupKeyReceipt(published.receiptFile)).rejects.toThrow();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("publishes once under concurrent retry and refuses to overwrite different metadata", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-key-receipt-"));
    try {
      const [a, b] = await Promise.all([
        writeBackupKeyReceipt(directory, identity),
        writeBackupKeyReceipt(directory, identity)
      ]);
      expect(a).toEqual(b);
      const original = await readFile(a.receiptFile, "utf8");
      await expect(
        writeBackupKeyReceipt(directory, { ...identity, kid: "different" })
      ).rejects.toThrow("different metadata");
      expect(await readFile(a.receiptFile, "utf8")).toBe(original);
      expect(await readdir(directory)).toEqual([`${identity.keyId}.json`]);
      expect(
        await verifyBackupKeyReceipt({
          receiptFile: a.receiptFile,
          organizationId: identity.organizationId,
          keyId: identity.keyId,
          key
        })
      ).toEqual(a.receipt);
      for (const mismatch of [
        { organizationId: identity.instanceId, keyId: identity.keyId, key },
        { organizationId: identity.organizationId, keyId: identity.instanceId, key },
        {
          organizationId: identity.organizationId,
          keyId: identity.keyId,
          key: Buffer.alloc(32, 0x52)
        }
      ])
        await expect(
          verifyBackupKeyReceipt({ receiptFile: a.receiptFile, ...mismatch })
        ).rejects.toThrow();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects tampered, exposed and symlinked receipts without accepting their metadata", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-key-receipt-refusal-"));
    try {
      const published = await writeBackupKeyReceipt(directory, identity);
      const alias = path.join(directory, "alias.json");
      await symlink(published.receiptFile, alias);
      await expect(readBackupKeyReceipt(alias)).rejects.toThrow();
      await chmod(published.receiptFile, 0o644);
      await expect(readBackupKeyReceipt(published.receiptFile)).rejects.toThrow("owner-only");
      await chmod(published.receiptFile, 0o600);
      await writeFile(
        published.receiptFile,
        JSON.stringify({ ...published.receipt, fingerprintSha256: "a".repeat(64) })
      );
      await expect(readBackupKeyReceipt(published.receiptFile)).rejects.toThrow("hash mismatch");
      await expect(writeBackupKeyReceipt(directory, identity)).rejects.toThrow("hash mismatch");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
