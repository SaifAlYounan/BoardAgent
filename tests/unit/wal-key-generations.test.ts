import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { archiveWalOnce, materializeWalArchive } from "../../scripts/src/wal-archive.js";
import { writeBackupKeyReceipt } from "../../scripts/src/backup-key-binding.js";
import { BackupKeyIdentitySchema } from "../../lib/db/src/index.js";

const instanceId = "018f0000-0000-7000-8000-000000000001";
const organizationId = "018f0000-0000-7000-8000-000000000002";
const ids = ["018f0000-0000-7000-8000-000000000099", "018f0000-0000-7000-8000-000000000100"];
const names = ["00000001000000000000000A", "00000001000000000000000B"];
const fingerprint = (key: Uint8Array) => createHash("sha256").update(key).digest("hex");

describe("offline WAL recovery across backup key replacement", () => {
  it("requires explicit protected old/new keys and verifies the complete key set before writing plaintext", async () => {
    const root = await mkdtemp(path.join(await realpath(tmpdir()), "boardagent-wal-generations-"));
    const staging = path.join(root, "staging"),
      archive = path.join(root, "archive"),
      target = path.join(root, "target");
    const keyFiles = ids.map((id) => path.join(root, `${id}.key`));
    const keyBytes = [Buffer.alloc(32, 0x61), Buffer.alloc(32, 0x62)];
    const ringFile = path.join(root, "recovery-keys.json");
    const ring = {
      schemaVersion: "boardagent.backup-recovery-keys.v1",
      instanceId,
      organizationId,
      keys: ids.map((keyId, i) => ({
        keyId,
        keyFile: keyFiles[i]!,
        fingerprintSha256: fingerprint(keyBytes[i]!)
      }))
    };
    try {
      await Promise.all([mkdir(staging), mkdir(archive), mkdir(target)]);
      for (const [i, keyId] of ids.entries()) {
        await writeFile(keyFiles[i]!, keyBytes[i]!, { mode: 0o600 });
        const receipt = await writeBackupKeyReceipt(
          root,
          BackupKeyIdentitySchema.parse({
            instanceId,
            organizationId,
            keyId,
            kid: `backup-${keyId}`,
            purpose: "backup_kek",
            algorithm: "A256GCM",
            activatedAt: "2026-09-09T00:00:00Z",
            fingerprintSha256: fingerprint(keyBytes[i]!)
          })
        );
        await writeFile(path.join(staging, names[i]!), `synthetic WAL generation ${i}`, {
          mode: 0o600
        });
        await archiveWalOnce({
          organizationId,
          keyRegistrationFile: receipt.receiptFile,
          stagingDirectory: staging,
          destinationDirectory: archive,
          encryptionKeyId: keyId,
          encryptionKeyFile: keyFiles[i]!
        });
      }
      const input = {
        archiveDirectory: archive,
        targetDirectory: target,
        encryptionKeyId: ids[0]!,
        encryptionKeyFile: keyFiles[0]!,
        expectedInstanceId: instanceId,
        expectedOrganizationId: organizationId,
        expectedKeyFingerprintSha256: fingerprint(keyBytes[0]!)
      };
      await expect(materializeWalArchive(input)).rejects.toThrow("key identity");
      expect(await readdir(target)).toEqual([]);
      const withRing = { ...input, recoveryKeyringFile: ringFile };
      for (const [changed, reason] of [
        [{ ...ring, keys: [ring.keys[0]!] }, "recovery_wal_key_missing"],
        [{ ...ring, keys: [ring.keys[1]!] }, "recovery_base_key_missing"],
        [{ ...ring, keys: [ring.keys[0]!, ring.keys[0]!] }, "recovery_key_list_has_duplicates"],
        [{ ...ring, organizationId: instanceId }, "recovery_key_target_mismatch"],
        [
          {
            ...ring,
            keys: [ring.keys[0]!, { ...ring.keys[1]!, fingerprintSha256: "a".repeat(64) }]
          },
          "recovery_private_key_mismatch"
        ],
        [
          {
            ...ring,
            keys: [{ ...ring.keys[0]!, fingerprintSha256: "b".repeat(64) }, ring.keys[1]!]
          },
          "recovery_base_key_mismatch"
        ]
      ] as const) {
        await writeFile(ringFile, JSON.stringify(changed), { mode: 0o600 });
        await expect(materializeWalArchive(withRing)).rejects.toThrow(reason);
        expect(await readdir(target)).toEqual([]);
      }
      await writeFile(ringFile, JSON.stringify(ring), { mode: 0o600 });
      const result = await materializeWalArchive(withRing);
      expect(result.walFiles).toEqual(names);
      expect(result.recoveryKeyIds).toEqual(ids);
      expect(result.recoveryKeyringSha256).toMatch(/^[a-f0-9]{64}$/u);
      for (const [i, name] of names.entries())
        expect(await readFile(path.join(target, name), "utf8")).toBe(
          `synthetic WAL generation ${i}`
        );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

it("authenticates an interrupted published WAL replay with retained keys after rotation", async () => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), "boardagent-wal-replay-"));
  const staging = path.join(root, "staging"),
    archive = path.join(root, "archive"),
    ringFile = path.join(root, "recovery-keys.json");
  const keyBytes = [Buffer.alloc(32, 0x71), Buffer.alloc(32, 0x72)];
  const keyFiles = ids.map((id) => path.join(root, `${id}.key`));
  const receipts: string[] = [];
  const ring = {
    schemaVersion: "boardagent.backup-recovery-keys.v1",
    instanceId,
    organizationId,
    keys: ids.map((keyId, i) => ({
      keyId,
      keyFile: keyFiles[i]!,
      fingerprintSha256: fingerprint(keyBytes[i]!)
    }))
  };
  const stagedFile = path.join(staging, names[0]!);
  const artifactFile = path.join(archive, `${names[0]}.aes256gcm`),
    manifestFile = path.join(archive, `${names[0]}.manifest.json`);
  const wal = Buffer.from(
    "Synthetic complete segment retained after publish before acknowledgement"
  );
  try {
    await Promise.all([mkdir(staging), mkdir(archive)]);
    for (const [i, keyId] of ids.entries()) {
      await writeFile(keyFiles[i]!, keyBytes[i]!, { mode: 0o600 });
      const receipt = await writeBackupKeyReceipt(
        root,
        BackupKeyIdentitySchema.parse({
          instanceId,
          organizationId,
          keyId,
          kid: `backup-${keyId}`,
          purpose: "backup_kek",
          algorithm: "A256GCM",
          activatedAt: "2026-09-09T00:00:00Z",
          fingerprintSha256: fingerprint(keyBytes[i]!)
        })
      );
      receipts.push(receipt.receiptFile);
    }
    const input = {
      organizationId,
      keyRegistrationFile: receipts[0]!,
      stagingDirectory: staging,
      destinationDirectory: archive,
      encryptionKeyFile: keyFiles[0]!,
      encryptionKeyId: ids[0]!
    };
    await writeFile(stagedFile, wal, { mode: 0o600 });
    expect(await archiveWalOnce(input)).toEqual({ archived: 1, replayed: 0 });
    const artifact = await readFile(artifactFile),
      manifestBytes = await readFile(manifestFile),
      manifest = JSON.parse(manifestBytes.toString("utf8"));
    await writeFile(stagedFile, wal, { mode: 0o600 });
    const next = {
      ...input,
      keyRegistrationFile: receipts[1]!,
      encryptionKeyFile: keyFiles[1]!,
      encryptionKeyId: ids[1]!
    };
    await expect(archiveWalOnce(next)).rejects.toThrow();
    expect(await readFile(stagedFile)).toEqual(wal);
    const explicit = { ...next, recoveryKeyringFile: ringFile };
    await writeFile(ringFile, JSON.stringify({ ...ring, keys: [ring.keys[1]] }), { mode: 0o600 });
    await expect(archiveWalOnce(explicit)).rejects.toThrow();
    expect(await readFile(stagedFile)).toEqual(wal);
    await writeFile(ringFile, JSON.stringify(ring));
    await writeFile(manifestFile, JSON.stringify({ ...manifest, instanceId: organizationId }));
    await expect(archiveWalOnce(explicit)).rejects.toThrow();
    expect(await readFile(stagedFile)).toEqual(wal);
    // Matching public hashes cannot substitute for authentication with the retained key.
    const corrupted = Buffer.from(artifact);
    corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
    await writeFile(artifactFile, corrupted);
    await writeFile(
      manifestFile,
      JSON.stringify({ ...manifest, artifactSha256: fingerprint(corrupted) })
    );
    await expect(archiveWalOnce(explicit)).rejects.toThrow();
    expect(await readFile(stagedFile)).toEqual(wal);
    await writeFile(artifactFile, artifact);
    await writeFile(manifestFile, manifestBytes);
    await writeFile(stagedFile, "different WAL source");
    await expect(archiveWalOnce(explicit)).rejects.toThrow();
    expect(await readFile(stagedFile, "utf8")).toBe("different WAL source");
    await writeFile(stagedFile, wal);
    const { runOperatorWithDiagnostics } = await import("../../scripts/src/operator.js");
    const lines: string[] = [];
    const code = await runOperatorWithDiagnostics(
      ["archive-wal-once", staging, archive],
      {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_ORGANIZATION_ID: organizationId,
        BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE: receipts[1],
        BOARDAGENT_BACKUP_KEK_FILE: keyFiles[1],
        BOARDAGENT_BACKUP_KEY_ID: ids[1],
        BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE: ringFile
      },
      { stdout: (s) => lines.push(s), stderr: (s) => lines.push(s) }
    );
    expect({ code, output: lines.join("") }).toMatchObject({ code: 0 });
    expect(JSON.parse(lines.at(-1)!)).toMatchObject({
      archived: 0,
      replayed: 1,
      previousGenerationReplayed: 1,
      recoveryKeyringSha256: expect.stringMatching(/^[a-f0-9]{64}$/u)
    });
    expect(await readdir(staging)).toEqual([]);
    expect(await readFile(artifactFile)).toEqual(artifact);
    expect(await readFile(manifestFile)).toEqual(manifestBytes);
    await writeFile(path.join(staging, names[1]!), "new generation WAL", { mode: 0o600 });
    expect(await archiveWalOnce(next)).toEqual({ archived: 1, replayed: 0 });
    expect(
      JSON.parse(await readFile(path.join(archive, `${names[1]}.manifest.json`), "utf8"))
        .encryptionKeyId
    ).toBe(ids[1]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
