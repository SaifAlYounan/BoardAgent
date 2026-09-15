import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

import { decryptBackupArtifact } from "../../scripts/src/recovery-artifact.js";
import {
  archiveWalOnce,
  materializeWalArchive,
  WalArchiveManifestSchema
} from "../../scripts/src/wal-archive.js";
import {
  RecoveryManifestKeyFields,
  writeBackupKeyReceipt
} from "../../scripts/src/backup-key-binding.js";
import { BackupKeyIdentitySchema } from "../../lib/db/src/index.js";

const organizationId = "018f0000-0000-7000-8000-000000000002";
async function registrationFile(root: string, key: Uint8Array): Promise<string> {
  // Synthetic operator metadata fixture; real registry publication is tested separately.
  return (
    await writeBackupKeyReceipt(
      root,
      BackupKeyIdentitySchema.parse({
        instanceId: "018f0000-0000-7000-8000-000000000001",
        organizationId,
        keyId: "018f0000-0000-7000-8000-000000000099",
        kid: "wal-test",
        purpose: "backup_kek",
        algorithm: "A256GCM",
        activatedAt: "2026-09-04T00:00:00Z",
        fingerprintSha256: createHash("sha256").update(key).digest("hex")
      })
    )
  ).receiptFile;
}

async function collect(source: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of source) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

describe("encrypted continuous-WAL archive", () => {
  it("recovers around an actual killed encryption writer and preserves hook temporaries", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-wal-interrupted-"));
    const staging = path.join(root, "staging"),
      archive = path.join(root, "archive"),
      target = path.join(root, "target");
    const key = Buffer.alloc(32, 0x41),
      keyFile = path.join(root, "backup.key");
    const walName = "00000001000000000000000C";
    await Promise.all([
      mkdir(staging),
      mkdir(archive),
      mkdir(target),
      writeFile(keyFile, key, { mode: 0o600 })
    ]);
    const child = spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import {Readable} from 'node:stream';import {encryptBackupArtifact} from ${JSON.stringify(pathToFileURL(path.resolve("scripts/dist/recovery-artifact.js")).href)};
       const timer=setInterval(()=>{},1000);
       await encryptBackupArtifact(Readable.from((async function*(){yield Buffer.alloc(8192,0x55);process.stdout.write('partial-ready');await new Promise(()=>{});})()),process.argv[1],Buffer.alloc(32,0x41));clearInterval(timer);`,
        path.join(archive, `${walName}.aes256gcm`)
      ],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("encryption writer did not reach interruption point")),
          10_000
        );
        child.once("error", (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.stdout.once("data", () => {
          clearTimeout(timer);
          resolve();
        });
      });
      const stopped = once(child, "close");
      child.kill("SIGKILL");
      expect((await stopped)[1]).toBe("SIGKILL");
      const incomplete = (await readdir(archive)).filter((name) => name.includes(".partial-"));
      expect(incomplete).toHaveLength(1);
      expect(await readdir(archive)).toEqual(incomplete);
      const hookTemporary = `${walName}.partial.999999`;
      await writeFile(path.join(staging, hookTemporary), "unfinished copy", { mode: 0o600 });
      await writeFile(path.join(staging, walName), "complete staged WAL", { mode: 0o600 });
      const keyRegistrationFile = await registrationFile(root, key);
      const encryptionKeyId = "018f0000-0000-7000-8000-000000000099";
      expect(
        await archiveWalOnce({
          organizationId,
          keyRegistrationFile,
          stagingDirectory: staging,
          destinationDirectory: archive,
          encryptionKeyFile: keyFile,
          encryptionKeyId
        })
      ).toEqual({
        archived: 1,
        replayed: 0,
        ignoredTemporaryFileCount: 2,
        ignoredTemporaryFiles: [...incomplete, hookTemporary].toSorted()
      });
      expect(await readdir(staging)).toEqual([hookTemporary]);
      expect(
        await materializeWalArchive({
          archiveDirectory: archive,
          targetDirectory: target,
          encryptionKeyFile: keyFile,
          encryptionKeyId
        })
      ).toEqual({
        walFiles: [walName],
        legacyIdOnlyCount: 0,
        ignoredTemporaryFileCount: 1,
        ignoredTemporaryFiles: incomplete
      });
      expect(await readFile(path.join(target, walName), "utf8")).toBe("complete staged WAL");
      expect((await readdir(archive)).filter((name) => name.includes(".partial-"))).toEqual(
        incomplete
      );
      const refusedTarget = path.join(root, "refused-target");
      await mkdir(refusedTarget);
      await rm(path.join(archive, incomplete[0]!));
      await symlink(path.join(root, "unrelated"), path.join(archive, incomplete[0]!));
      await expect(
        materializeWalArchive({
          archiveDirectory: archive,
          targetDirectory: refusedTarget,
          encryptionKeyFile: keyFile,
          encryptionKeyId
        })
      ).rejects.toThrow("non-file entry");
      expect(await readdir(refusedTarget)).toEqual([]);
      await rm(path.join(archive, incomplete[0]!));
      await writeFile(
        path.join(archive, "unknown.partial-12-0123456789abcdef"),
        "not an owned temporary"
      );
      await expect(
        materializeWalArchive({
          archiveDirectory: archive,
          targetDirectory: refusedTarget,
          encryptionKeyFile: keyFile,
          encryptionKeyId
        })
      ).rejects.toThrow("exact artifact/manifest pairs");
      expect(await readdir(refusedTarget)).toEqual([]);
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        const stopped = once(child, "close");
        child.kill("SIGKILL");
        await stopped;
      }
      await rm(root, { recursive: true, force: true });
    }
  });

  it("reads mixed legacy/new archives offline and rejects an inconsistent fingerprint before extracting any segment", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-wal-mixed-"));
    const staging = path.join(root, "staging"),
      archive = path.join(root, "archive"),
      target = path.join(root, "target");
    const key = Buffer.alloc(32, 0x51),
      keyFile = path.join(root, "backup.key");
    const names = ["00000001000000000000000A", "00000001000000000000000B"];
    try {
      await Promise.all([
        mkdir(staging),
        mkdir(archive),
        mkdir(target),
        writeFile(keyFile, key, { mode: 0o600 })
      ]);
      const keyRegistrationFile = await registrationFile(root, key);
      for (const name of names)
        await writeFile(path.join(staging, name), `synthetic-${name}`, { mode: 0o600 });
      const encryptionKeyId = "018f0000-0000-7000-8000-000000000099";
      await archiveWalOnce({
        organizationId,
        keyRegistrationFile,
        stagingDirectory: staging,
        destinationDirectory: archive,
        encryptionKeyFile: keyFile,
        encryptionKeyId
      });
      const manifestFiles = names.map((name) => path.join(archive, `${name}.manifest.json`));
      const manifests = await Promise.all(
        manifestFiles.map(
          async (file) => JSON.parse(await readFile(file, "utf8")) as Record<string, unknown>
        )
      );
      const materialize = () =>
        materializeWalArchive({
          archiveDirectory: archive,
          targetDirectory: target,
          encryptionKeyFile: keyFile,
          encryptionKeyId
        });
      await writeFile(
        manifestFiles[1]!,
        JSON.stringify({ ...manifests[1], encryptionKeyFingerprintSha256: "a".repeat(64) })
      );
      await expect(materialize()).rejects.toThrow("registered fingerprint");
      expect(await readdir(target)).toEqual([]);
      await writeFile(
        manifestFiles[1]!,
        JSON.stringify({ ...manifests[1], organizationId: "018f0000-0000-7000-8000-000000000003" })
      );
      await expect(materialize()).rejects.toThrow("different instance identity");
      expect(await readdir(target)).toEqual([]);
      await writeFile(manifestFiles[1]!, JSON.stringify(manifests[1]));
      const legacy = { ...manifests[0] };
      for (const field of Object.keys(RecoveryManifestKeyFields)) delete legacy[field];
      await writeFile(manifestFiles[0]!, JSON.stringify(legacy));
      // Removal of new metadata retains GCM authentication for older backups.
      await writeFile(keyFile, Buffer.alloc(32, 0x52));
      await expect(materialize()).rejects.toThrow("registered fingerprint");
      expect(await readdir(target)).toEqual([]);
      await writeFile(keyFile, key);
      expect(await materialize()).toEqual({ walFiles: names, legacyIdOnlyCount: 1 });
      for (const name of names)
        expect(await readFile(path.join(target, name), "utf8")).toBe(`synthetic-${name}`);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("publishes authenticated WAL plus a strict manifest before removing staging bytes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-wal-archive-"));
    const staging = path.join(root, "staging");
    const destination = path.join(root, "destination");
    const keyFile = path.join(root, "backup.key");
    const walName = "00000001000000000000000A";
    const wal = Buffer.concat([Buffer.from("synthetic-wal\0"), Buffer.alloc(8192, 0x5a)]);
    await Promise.all([
      import("node:fs/promises").then(({ mkdir }) => mkdir(staging)),
      import("node:fs/promises").then(({ mkdir }) => mkdir(destination)),
      writeFile(keyFile, Buffer.alloc(32, 0x41), { mode: 0o600 })
    ]);
    await writeFile(path.join(staging, walName), wal, { mode: 0o600 });
    const keyRegistrationFile = await registrationFile(root, Buffer.alloc(32, 0x41));
    try {
      const result = await archiveWalOnce({
        organizationId,
        keyRegistrationFile,
        stagingDirectory: staging,
        destinationDirectory: destination,
        encryptionKeyFile: keyFile,
        encryptionKeyId: "018f0000-0000-7000-8000-000000000099",
        archivedAt: "2026-09-04T12:00:00.000Z"
      });
      expect(result).toEqual({ archived: 1, replayed: 0 });
      await expect(readFile(path.join(staging, walName))).rejects.toMatchObject({ code: "ENOENT" });

      const manifest = WalArchiveManifestSchema.parse(
        JSON.parse(await readFile(path.join(destination, `${walName}.manifest.json`), "utf8"))
      );
      expect(manifest).toMatchObject({
        schemaVersion: "boardagent.wal-archive.v1",
        walFile: walName,
        plaintextBytes: String(wal.length),
        encryptionKeyId: "018f0000-0000-7000-8000-000000000099"
      });
      const decrypted = await collect(
        decryptBackupArtifact(
          path.join(destination, `${walName}.aes256gcm`),
          Buffer.alloc(32, 0x41)
        )
      );
      expect(decrypted).toEqual(wal);
      expect((await readFile(path.join(destination, `${walName}.aes256gcm`))).includes(wal)).toBe(
        false
      );
      expect(manifest.encryptionKeyFingerprintSha256).toBe(
        createHash("sha256").update(Buffer.alloc(32, 0x41)).digest("hex")
      );
      const nextWalName = "00000001000000000000000B";
      await writeFile(path.join(staging, nextWalName), wal, { mode: 0o600 });
      await writeFile(keyFile, Buffer.alloc(32, 0x42));
      await expect(
        archiveWalOnce({
          organizationId,
          keyRegistrationFile,
          stagingDirectory: staging,
          destinationDirectory: destination,
          encryptionKeyFile: keyFile,
          encryptionKeyId: "018f0000-0000-7000-8000-000000000099"
        })
      ).rejects.toMatchObject({
        cause: { message: expect.stringContaining("registered fingerprint") }
      });
      expect(await readFile(path.join(staging, nextWalName))).toEqual(wal);
      expect(await readdir(destination)).toHaveLength(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("refuses unknown staging names and a key exposed to other users", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-wal-refusal-"));
    const staging = path.join(root, "staging");
    const destination = path.join(root, "destination");
    const keyFile = path.join(root, "backup.key");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(staging);
    await mkdir(destination);
    await writeFile(keyFile, Buffer.alloc(32, 0x42), { mode: 0o600 });
    const keyRegistrationFile = await registrationFile(root, Buffer.alloc(32, 0x42));
    try {
      await writeFile(path.join(staging, "unexpected"), "do not archive");
      await expect(
        archiveWalOnce({
          organizationId,
          keyRegistrationFile,
          stagingDirectory: staging,
          destinationDirectory: destination,
          encryptionKeyFile: keyFile,
          encryptionKeyId: "018f0000-0000-7000-8000-000000000099"
        })
      ).rejects.toMatchObject({
        cause: { message: expect.stringContaining("unexpected WAL staging entry") }
      });
      await rm(path.join(staging, "unexpected"));
      await writeFile(path.join(staging, "00000001000000000000000B"), "wal");
      await chmod(keyFile, 0o604);
      await expect(
        archiveWalOnce({
          organizationId,
          keyRegistrationFile,
          stagingDirectory: staging,
          destinationDirectory: destination,
          encryptionKeyFile: keyFile,
          encryptionKeyId: "018f0000-0000-7000-8000-000000000099"
        })
      ).rejects.toMatchObject({
        cause: { message: expect.stringContaining("must not be accessible to other users") }
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
