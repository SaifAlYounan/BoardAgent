import { createHash } from "node:crypto";
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";
import { inspectRetainedRecoveryFiles } from "../../scripts/src/key-maintenance-inventory.js";

import {
  BaseBackupManifestSchema,
  pruneBaseBackupGenerations
} from "../../scripts/src/base-backup.js";

const roots: string[] = [];

function backupId(index: number): string {
  return `018f0000-0000-7000-8000-${index.toString(16).padStart(12, "0")}`;
}

async function generation(directory: string, index: number, completedAt: string): Promise<string> {
  const id = backupId(index);
  const artifact = path.join(directory, `boardagent-${id}.base.tar.aes256gcm`);
  const manifest = path.join(directory, `boardagent-${id}.base.manifest.json`);
  const bytes = Buffer.from(`encrypted-${String(index)}`, "utf8");
  await writeFile(artifact, bytes, { mode: 0o600 });
  const record = BaseBackupManifestSchema.parse({
    schemaVersion: "boardagent.base-backup.v1",
    backupId: id,
    format: "postgresql-base-tar-encrypted-v1",
    sourceDatabase: "boardagent",
    systemIdentifier: "7623456789012345678",
    startedAt: completedAt,
    completedAt,
    observedStartLsn: "0/1000000",
    observedEndLsn: "0/2000000",
    walMethod: "fetch",
    manifestChecksums: "SHA256",
    encryptionKeyId: "018f0000-0000-7000-8000-000000000099",
    sourceImageDigest: `sha256:${"a".repeat(64)}`,
    pgBasebackupVersion: "pg_basebackup (PostgreSQL) 18.6",
    encryptedStorageLocator: pathToFileURL(artifact).href,
    artifactSha256: createHash("sha256").update(bytes).digest("hex"),
    artifactBytes: String(bytes.length),
    plaintextTarSha256: "b".repeat(64),
    plaintextTarBytes: "1",
    retention: { daily: 7, weekly: 4, monthly: 12 }
  });
  await writeFile(manifest, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return id;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("base-backup generation retention", () => {
  it("distinguishes present retained artifacts from permanent retirement metadata during key inventory", async () => {
    const directory = await mkdtemp(
      path.join(await realpath(tmpdir()), "boardagent-retained-base-key-")
    );
    roots.push(directory);
    const id = await generation(directory, 1, "2026-05-01T12:00:00.000Z");
    const keyId = "018f0000-0000-7000-8000-000000000099";
    const keys = [{ keyId, purpose: "backup_kek", materialSha256: "a".repeat(64) }];
    const target = { instanceId: backupId(97), organizationId: backupId(98) };
    const first = await inspectRetainedRecoveryFiles([directory], keys, target);
    expect(first.manifests).toEqual([
      expect.objectContaining({ kind: "base", keyId, payload: "present_hash_verified" })
    ]);
    const manifest = path.join(directory, `boardagent-${id}.base.manifest.json`);
    await rename(manifest, `${manifest}.retired`);
    await rm(path.join(directory, `boardagent-${id}.base.tar.aes256gcm`));
    const retired = await inspectRetainedRecoveryFiles([directory], keys, target);
    expect(retired.manifests).toEqual([
      expect.objectContaining({ kind: "base", keyId, payload: "retired_metadata_only" })
    ]);
    expect(retired.files).toHaveLength(1);
  });
  it("retains recognized uncommitted temporaries while processing complete generations", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-retention-interrupted-"));
    roots.push(directory);
    const id = await generation(directory, 1, "2026-05-01T12:00:00.000Z");
    const partial = `boardagent-${backupId(2)}.base.tar.aes256gcm.partial-999999-0123456789abcdef`;
    await writeFile(path.join(directory, partial), "incomplete", { mode: 0o600 });
    expect(await pruneBaseBackupGenerations(directory)).toEqual({
      keptBackupIds: [id],
      prunedBackupIds: [],
      resumedRetirements: 0,
      ignoredTemporaryFileCount: 1,
      ignoredTemporaryFiles: [partial]
    });
    expect(await readFile(path.join(directory, partial), "utf8")).toBe("incomplete");
    await rm(path.join(directory, partial));
    await symlink(path.join(directory, "unrelated"), path.join(directory, partial));
    await expect(pruneBaseBackupGenerations(directory)).rejects.toThrow("non-file entry");
    await rm(path.join(directory, partial));
    await writeFile(path.join(directory, "unknown.partial-12-0123456789abcdef"), "unknown");
    await expect(pruneBaseBackupGenerations(directory)).rejects.toThrow(
      "unexpected base backup entry"
    );
  });

  it("keeps the newest generation from each of twelve UTC months", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-retention-monthly-"));
    roots.push(directory);
    const ids: string[] = [];
    for (let index = 0; index < 20; index += 1) {
      ids.push(
        await generation(
          directory,
          index + 1,
          new Date(Date.UTC(2024, index, 15, 12)).toISOString()
        )
      );
    }

    const result = await pruneBaseBackupGenerations(directory);
    expect(result.resumedRetirements).toBe(0);
    expect(result.keptBackupIds).toEqual(ids.slice(-12).toSorted());
    expect(result.prunedBackupIds).toEqual(ids.slice(0, 8));
    expect(await readdir(directory)).toHaveLength(24);
  });

  it("adds weekly recovery points outside the newest seven UTC days", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-retention-daily-"));
    roots.push(directory);
    const ids: string[] = [];
    for (let day = 1; day <= 20; day += 1) {
      ids.push(
        await generation(directory, day, new Date(Date.UTC(2026, 4, day, 12)).toISOString())
      );
    }

    const result = await pruneBaseBackupGenerations(directory);
    expect(result.keptBackupIds).toEqual(
      [ids[2], ids[9], ...ids.slice(13)].filter((id): id is string => id !== undefined).toSorted()
    );
    expect(result.prunedBackupIds).toHaveLength(11);
  });

  it("resumes a manifest-first retirement after a simulated crash", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-retention-resume-"));
    roots.push(directory);
    const id = await generation(directory, 1, "2026-05-01T12:00:00.000Z");
    const manifest = path.join(directory, `boardagent-${id}.base.manifest.json`);
    await rename(manifest, `${manifest}.retired`);

    expect(await pruneBaseBackupGenerations(directory)).toEqual({
      keptBackupIds: [],
      prunedBackupIds: [],
      resumedRetirements: 1
    });
    expect(await readdir(directory)).toEqual([]);
  });

  it("fails closed on an orphan without deleting it", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-retention-orphan-"));
    roots.push(directory);
    const id = backupId(1);
    const artifact = path.join(directory, `boardagent-${id}.base.tar.aes256gcm`);
    await writeFile(artifact, "orphan", { mode: 0o600 });

    await expect(pruneBaseBackupGenerations(directory)).rejects.toThrow(
      "artifact exists without its manifest"
    );
    expect(await readFile(artifact, "utf8")).toBe("orphan");
  });
});
