import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { describe, expect, it } from "vitest";

import {
  decryptBackupArtifact,
  encryptBackupArtifact,
  loadBackupEncryptionKey,
  verifyBackupArtifact
} from "../../scripts/src/recovery-artifact.js";

async function collect(source: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of source) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

describe("encrypted recovery artifact", () => {
  it("authenticates before releasing bytes into an actual child process pipe", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-child-"));
    const artifact = path.join(directory, "backup.dump.aes256gcm");
    const plaintext = Buffer.alloc(196_615, 0x41);
    const key = Buffer.alloc(32, 0x6a);
    try {
      await encryptBackupArtifact(Readable.from([plaintext]), artifact, key);
      for (const corrupt of [false, true]) {
        if (corrupt) {
          const changed = await readFile(artifact);
          changed[changed.length - 1]! ^= 0x01;
          await writeFile(artifact, changed);
          await verifyBackupArtifact(
            artifact,
            createHash("sha256").update(changed).digest("hex"),
            changed.length
          );
        }
        // This harmless consumer counts/hashes stdin and reports even after EOF
        // caused by a source error. It never interprets data or touches a database.
        const child = spawn(
          process.execPath,
          [
            "--input-type=module",
            "-e",
            `
          import { createHash } from 'node:crypto';
          let bytes = 0; const hash = createHash('sha256');
          process.stdin.on('data', chunk => { bytes += chunk.length; hash.update(chunk); });
          process.stdin.on('end', () => process.stdout.write(JSON.stringify({ bytes, sha256: hash.digest('hex') })));
        `
          ],
          { stdio: ["pipe", "pipe", "pipe"] }
        );
        let receipt = "";
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", (value: string) => {
          receipt += value;
        });
        const completion = new Promise<number | null>((resolve, reject) => {
          child.once("error", reject);
          child.once("close", resolve);
        });
        const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
        try {
          const [streamResult, code] = await Promise.all([
            pipeline(
              Readable.from(decryptBackupArtifact(artifact, key), { objectMode: false }),
              child.stdin
            ).then(
              () => undefined,
              (error: unknown) => error
            ),
            completion
          ]);
          expect(code).toBe(0);
          const parsed = JSON.parse(receipt) as { bytes: number; sha256: string };
          expect(parsed.bytes).toBe(corrupt ? 0 : plaintext.length);
          expect(parsed.sha256).toBe(
            createHash("sha256")
              .update(corrupt ? Buffer.alloc(0) : plaintext)
              .digest("hex")
          );
          if (corrupt)
            expect(streamResult).toEqual(new Error("backup artifact authentication failed"));
          else expect(streamResult).toBeUndefined();
        } finally {
          clearTimeout(timer);
          if (child.exitCode === null) child.kill("SIGKILL");
          await completion.catch(() => undefined);
        }
      }
    } finally {
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("MR-OPS-003 releases zero consumer bytes for a corrupt tag even when the manifest hash matches", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-auth-"));
    const artifact = path.join(directory, "backup.dump.aes256gcm");
    const plaintext = Buffer.alloc(3 * 65_536 + 7, 0x51);
    const key = Buffer.alloc(32, 0x6a);
    let consumedBytes = 0;
    try {
      await encryptBackupArtifact(Readable.from([plaintext]), artifact, key);
      const changed = await readFile(artifact);
      changed[changed.length - 1]! ^= 0x01;
      await writeFile(artifact, changed);
      // The local manifest is mutable. Its unkeyed digest does not authenticate a tag.
      const matchingManifest = {
        artifactSha256: createHash("sha256").update(changed).digest("hex"),
        byteLength: changed.length
      };
      await expect(
        verifyBackupArtifact(artifact, matchingManifest.artifactSha256, matchingManifest.byteLength)
      ).resolves.toBeUndefined();
      const sink = new Writable({
        write(chunk: Buffer, _encoding, callback) {
          consumedBytes += chunk.length;
          callback();
        }
      });
      await expect(
        pipeline(Readable.from(decryptBackupArtifact(artifact, key), { objectMode: false }), sink)
      ).rejects.toThrow("backup artifact authentication failed");
      expect(consumedBytes).toBe(0);
    } finally {
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("round-trips binary PostgreSQL bytes, binds the ciphertext hash, and rejects tamper", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-unit-"));
    const artifact = path.join(directory, "backup.dump.aes256gcm");
    const plaintext = Buffer.concat([
      Buffer.from("PGDMP\0synthetic BoardAgent backup bytes\0", "utf8"),
      Buffer.from(Array.from({ length: 8192 }, (_unused, index) => index % 251))
    ]);
    const key = Buffer.alloc(32, 0x5a);
    try {
      const encrypted = await encryptBackupArtifact(Readable.from([plaintext]), artifact, key);
      expect(encrypted.byteLength).toBeGreaterThan(plaintext.length);
      expect((await readFile(artifact)).includes(plaintext.subarray(0, 32))).toBe(false);
      await expect(
        verifyBackupArtifact(artifact, encrypted.sha256, encrypted.byteLength)
      ).resolves.toBeUndefined();
      await expect(collect(decryptBackupArtifact(artifact, key))).resolves.toEqual(plaintext);

      const changed = await readFile(artifact);
      changed[Math.floor(changed.length / 2)]! ^= 0x01;
      await writeFile(artifact, changed);
      await expect(
        verifyBackupArtifact(artifact, encrypted.sha256, encrypted.byteLength)
      ).rejects.toThrow("backup artifact hash mismatch");
    } finally {
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("streams a large authenticated artifact from isolated ciphertext despite source mutation", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-snapshot-"));
    const artifact = path.join(directory, "backup.dump.aes256gcm");
    const key = Buffer.alloc(32, 0x3d);
    const plaintextChunk = Buffer.alloc(65_536, 0x35);
    const expectedHash = createHash("sha256");
    const actualHash = createHash("sha256");
    let consumedBytes = 0;
    let chunks = 0;
    try {
      await encryptBackupArtifact(
        Readable.from(
          (async function* () {
            for (let index = 0; index < 65; index += 1) {
              expectedHash.update(plaintextChunk);
              yield plaintextChunk;
            }
          })()
        ),
        artifact,
        key
      );
      for await (const chunk of decryptBackupArtifact(artifact, key)) {
        expect(chunk.length).toBeLessThanOrEqual(65_536);
        actualHash.update(chunk);
        consumedBytes += chunk.length;
        chunks += 1;
        if (chunks === 1) {
          // A producer can replace/truncate the original after authentication. The
          // consumer must keep receiving only the exact authenticated snapshot.
          await writeFile(artifact, "synthetic changed original");
          expect(await readdir(directory)).toEqual([path.basename(artifact)]);
        }
      }
      expect(consumedBytes).toBe(65 * plaintextChunk.length);
      expect(chunks).toBeGreaterThan(1);
      expect(actualHash.digest("hex")).toBe(expectedHash.digest("hex"));
      expect(await readdir(directory)).toEqual([path.basename(artifact)]);
    } finally {
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("releases zero bytes for a wrong key and cleans up after authentication failure and cancellation", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-cleanup-"));
    const artifact = path.join(directory, "backup.dump.aes256gcm");
    const key = Buffer.alloc(32, 0x29);
    let consumedBytes = 0;
    try {
      await encryptBackupArtifact(Readable.from([Buffer.alloc(131_073, 0x41)]), artifact, key);
      const consumeWrongKey = async () => {
        for await (const chunk of decryptBackupArtifact(artifact, Buffer.alloc(32, 0x2a))) {
          consumedBytes += chunk.length;
        }
      };
      await expect(consumeWrongKey()).rejects.toThrow("backup artifact authentication failed");
      expect(consumedBytes).toBe(0);
      expect(await readdir(directory)).toEqual([path.basename(artifact)]);
      for await (const chunk of decryptBackupArtifact(artifact, key)) {
        expect(chunk.length).toBeGreaterThan(0);
        break;
      }
      expect(await readdir(directory)).toEqual([path.basename(artifact)]);
      await expect(collect(decryptBackupArtifact(artifact, key))).resolves.toHaveLength(131_073);
    } finally {
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses symlink and non-file artifacts before yielding any bytes", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-path-"));
    const artifact = path.join(directory, "backup.dump.aes256gcm");
    const linked = path.join(directory, "linked.aes256gcm");
    const nonFile = path.join(directory, "not-a-file");
    const key = Buffer.alloc(32, 0x3b);
    try {
      await encryptBackupArtifact(Readable.from([Buffer.alloc(128, 0x51)]), artifact, key);
      await symlink(artifact, linked);
      await mkdir(nonFile);
      await expect(collect(decryptBackupArtifact(linked, key))).rejects.toThrow();
      await expect(collect(decryptBackupArtifact(nonFile, key))).rejects.toThrow(
        "backup artifact must be a regular file"
      );
    } finally {
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("uses explicit private scratch storage for a read-only archive and rejects unsafe scratch paths", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-scratch-"));
    const archive = path.join(directory, "archive");
    const scratch = path.join(directory, "scratch");
    const linkedScratch = path.join(directory, "linked-scratch");
    const artifact = path.join(archive, "backup.dump.aes256gcm");
    const key = Buffer.alloc(32, 0x1d);
    try {
      await mkdir(archive, { mode: 0o700 });
      await mkdir(scratch, { mode: 0o700 });
      await encryptBackupArtifact(Readable.from([Buffer.alloc(131_073, 0x21)]), artifact, key);
      await chmod(artifact, 0o400);
      await chmod(archive, 0o500);
      await expect(collect(decryptBackupArtifact(artifact, key, scratch))).resolves.toHaveLength(
        131_073
      );
      expect(await readdir(scratch)).toEqual([]);
      await symlink(scratch, linkedScratch);
      await expect(collect(decryptBackupArtifact(artifact, key, linkedScratch))).rejects.toThrow();
      await chmod(scratch, 0o770);
      await expect(collect(decryptBackupArtifact(artifact, key, scratch))).rejects.toThrow(
        "backup authentication scratch directory must not be writable by other users"
      );
      expect(await readdir(scratch)).toEqual([]);
    } finally {
      key.fill(0);
      await chmod(archive, 0o700);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("loads only an exact private 32-byte or canonical base64url backup key", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-key-"));
    const keyFile = path.join(directory, "backup.key");
    try {
      await writeFile(keyFile, Buffer.alloc(32, 0x33), { mode: 0o600 });
      const raw = await loadBackupEncryptionKey(keyFile);
      expect(raw).toEqual(Buffer.alloc(32, 0x33));
      raw.fill(0);

      await writeFile(keyFile, Buffer.alloc(32, 0x44).toString("base64url"), { mode: 0o600 });
      const encoded = await loadBackupEncryptionKey(keyFile);
      expect(encoded).toEqual(Buffer.alloc(32, 0x44));
      encoded.fill(0);

      await chmod(keyFile, 0o604);
      await expect(loadBackupEncryptionKey(keyFile)).rejects.toThrow(
        "backup encryption key must not be accessible to other users"
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
