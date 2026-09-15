import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import * as inventory from "../../scripts/src/key-maintenance-inventory.js";
const id = "019f11a2-1234-7000-8000-000000000001";
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
async function fixture(run: (directory: string) => Promise<void>) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), "boardagent-key-inventory-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
async function wal(directory: string) {
  const name = "000000010000000000000001";
  const artifact = path.join(directory, `${name}.aes256gcm`),
    manifest = path.join(directory, `${name}.manifest.json`);
  const metadata = {
    schemaVersion: "boardagent.wal-archive.v1",
    walFile: name,
    archivedAt: "2026-09-09T00:00:00Z",
    encryptionKeyId: id,
    format: "postgresql-wal-aes256gcm-v1",
    artifactSha256: hash("retained ciphertext"),
    artifactBytes: "19",
    plaintextSha256: hash("plaintext"),
    plaintextBytes: "9"
  };
  await writeFile(artifact, "retained ciphertext", { mode: 0o600 });
  await writeFile(manifest, JSON.stringify(metadata), { mode: 0o600 });
  return { artifact, manifest, metadata };
}
const keys = [{ keyId: id, purpose: "backup_kek" as const, materialSha256: "a".repeat(64) }];
const target = { instanceId: id, organizationId: id };

describe("local retained key-maintenance inventory", () => {
  it("hashes actual nested files and WAL manifests, preserves bytes and labels off-host custody unknown", async () => {
    await fixture(async (directory) => {
      const f = await wal(directory);
      await mkdir(path.join(directory, "nested"), { mode: 0o700 });
      await writeFile(path.join(directory, "nested", "preserved-note"), "retained", {
        mode: 0o600
      });
      const first = await inventory.inspectRetainedRecoveryFiles([directory], keys, target);
      const second = await inventory.inspectRetainedRecoveryFiles([directory], keys, target);
      expect(second).toEqual(first);
      expect(first.files).toHaveLength(3);
      expect(first.manifests).toEqual([
        expect.objectContaining({
          file: f.manifest,
          keyId: id,
          kind: "wal",
          keyBinding: "legacy_id_only"
        })
      ]);
      expect(first.offHostCustody).toBe("not_verified");
      expect(await readFile(f.artifact, "utf8")).toBe("retained ciphertext");
      await writeFile(path.join(directory, "new-file"), "new", { mode: 0o600 });
      expect(await inventory.inspectRetainedRecoveryFiles([directory], keys, target)).not.toEqual(
        first
      );
    });
  });
  it("refuses missing or changed manifest payloads, unknown keys, wrong targets and false full fingerprints", async () => {
    await fixture(async (directory) => {
      const f = await wal(directory);
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], [], target)
      ).rejects.toThrow();
      await writeFile(f.artifact, "different");
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], keys, target)
      ).rejects.toThrow();
      await rm(f.artifact);
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], keys, target)
      ).rejects.toThrow();
      await writeFile(f.artifact, "retained ciphertext", { mode: 0o600 });
      const full = {
        ...f.metadata,
        instanceId: id,
        organizationId: id,
        encryptionKeyFingerprintSha256: "b".repeat(64),
        encryptionKeyActivatedAt: "2026-01-01T00:00:00Z",
        encryptionKeyKid: `backup-${id}`
      };
      await writeFile(f.manifest, JSON.stringify(full));
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], keys, target)
      ).rejects.toThrow();
      await writeFile(
        f.manifest,
        JSON.stringify({ ...full, encryptionKeyFingerprintSha256: keys[0]!.materialSha256 })
      );
      expect(
        (await inventory.inspectRetainedRecoveryFiles([directory], keys, target)).manifests[0]
          ?.keyBinding
      ).toBe("full_fingerprint");
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], keys, {
          ...target,
          instanceId: "019f11a2-1234-7000-8000-000000000002"
        })
      ).rejects.toThrow();
    });
  });
  it("refuses hidden symlinks, overlapping roots, unsafe files and unknown manifest schemas", async () => {
    await fixture(async (directory) => {
      const f = await wal(directory);
      await symlink(f.artifact, path.join(directory, ".hidden-link"));
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], keys, target)
      ).rejects.toThrow();
      await rm(path.join(directory, ".hidden-link"));
      await mkdir(path.join(directory, "nested"), { mode: 0o700 });
      await expect(
        inventory.inspectRetainedRecoveryFiles(
          [directory, path.join(directory, "nested")],
          keys,
          target
        )
      ).rejects.toThrow();
      await chmod(f.artifact, 0o666);
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], keys, target)
      ).rejects.toThrow();
      await chmod(f.artifact, 0o600);
      await writeFile(
        path.join(directory, "future.manifest.json"),
        JSON.stringify({ schemaVersion: "future.v1" }),
        { mode: 0o600 }
      );
      await expect(
        inventory.inspectRetainedRecoveryFiles([directory], keys, target)
      ).rejects.toThrow();
    });
  });
});
