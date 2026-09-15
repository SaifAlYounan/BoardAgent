import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  archiveWalOnce,
  archiveWalFailureDetails,
  materializeWalArchive
} from "../../scripts/src/wal-archive.js";
import { runOperatorWithDiagnostics } from "../../scripts/src/operator.js";

describe("safe WAL failure diagnostics", () => {
  it("reports bounded valid orphan names and never prints unknown input names or raw CLI error text", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-diagnostic-"));
    try {
      const archive = path.join(root, "archive"),
        target = path.join(root, "target");
      await mkdir(archive);
      await mkdir(target);
      const names = Array.from(
        { length: 25 },
        (_, i) => `${(i + 1).toString(16).toUpperCase().padStart(24, "0")}.aes256gcm`
      );
      for (const name of names) await writeFile(path.join(archive, name), "orphan bytes");
      await writeFile(path.join(archive, "private-unknown-input-name"), "x");
      try {
        await materializeWalArchive({
          archiveDirectory: archive,
          targetDirectory: target,
          encryptionKeyFile: path.join(root, "unused-key"),
          encryptionKeyId: "018f0000-0000-7000-8000-000000000099"
        });
        throw new Error("expected orphan refusal");
      } catch (error) {
        const details = archiveWalFailureDetails(error);
        expect(details).toEqual({
          stage: "archive",
          reasonCode: "archive_pairs_incomplete",
          unpairedArtifactCount: 25,
          unpairedArtifacts: names.slice(0, 20),
          unpairedManifestCount: 0,
          unpairedManifests: [],
          unknownFileCount: 1
        });
        expect(JSON.stringify(details)).not.toContain("private-unknown");
      }
      const stdout: string[] = [],
        stderr: string[] = [];
      expect(
        await runOperatorWithDiagnostics(
          ["base-restore-check", path.join(root, "private-missing-manifest"), target],
          {
            BOARDAGENT_BACKUP_KEK_FILE: path.join(root, "private-key-file"),
            BOARDAGENT_BACKUP_KEY_ID: "018f0000-0000-7000-8000-000000000099"
          },
          { stdout: (line) => stdout.push(line), stderr: (line) => stderr.push(line) }
        )
      ).toBe(1);
      expect(stdout).toEqual([]);
      expect(JSON.parse(stderr.join(""))).toEqual({
        status: "failed",
        command: "base-restore-check",
        stage: "base-restore-check",
        reasonCode: "file_missing"
      });
      expect(stderr.join("")).not.toContain(root);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("distinguishes missing key material, invalid registration and unexpected staging while retaining WAL", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-wal-diagnostic-"));
    try {
      const staging = path.join(root, "staging"),
        archive = path.join(root, "archive"),
        key = path.join(root, "key"),
        receipt = path.join(root, "receipt");
      await mkdir(staging);
      await mkdir(archive);
      const wal = path.join(staging, "000000010000000000000001");
      await writeFile(wal, "staged source", { mode: 0o600 });
      const input = {
        organizationId: "018f0000-0000-7000-8000-000000000001",
        encryptionKeyId: "018f0000-0000-7000-8000-000000000099",
        stagingDirectory: staging,
        destinationDirectory: archive,
        encryptionKeyFile: key,
        keyRegistrationFile: receipt
      };
      const failure = async () => {
        try {
          await archiveWalOnce(input);
          throw new Error("expected refusal");
        } catch (error) {
          return archiveWalFailureDetails(error);
        }
      };
      expect(await failure()).toEqual({ stage: "key_material", reasonCode: "file_missing" });
      await writeFile(key, Buffer.alloc(32, 1), { mode: 0o600 });
      await writeFile(receipt, '{"private":"do-not-log-this"}', { mode: 0o600 });
      expect(await failure()).toEqual({
        stage: "key_registration",
        reasonCode: "validation_or_operation_failed"
      });
      await writeFile(path.join(staging, "unexpected-private-name"), "x");
      expect(await failure()).toEqual({
        stage: "staging",
        reasonCode: "validation_or_operation_failed"
      });
      expect(await readFile(wal, "utf8")).toBe("staged source");
      const details = archiveWalFailureDetails(new Error("secret in arbitrary failure"));
      expect(details).toEqual({ stage: "unknown", reasonCode: "validation_or_operation_failed" });
      expect(JSON.stringify(details)).not.toContain("secret");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
