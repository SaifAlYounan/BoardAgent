import { mkdtemp, mkdir, readFile, readdir, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  isRecoveryTemporaryFile,
  publishRecoveryJson,
  recoveryTemporaryReport
} from "../../scripts/src/recovery-publication.js";

describe("exclusive durable recovery metadata publication", () => {
  it("publishes one complete private winner under concurrent writers and preserves it on retry", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-publication-"));
    try {
      const target = path.join(root, "manifest.json");
      const bodies = Array.from({ length: 8 }, (_, writer) => ({
        writer,
        records: "x".repeat(65536)
      }));
      const results = await Promise.allSettled(
        bodies.map((body) => publishRecoveryJson(target, body))
      );
      expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(results.filter(({ status }) => status === "rejected")).toHaveLength(7);
      for (const result of results)
        if (result.status === "rejected") expect(result.reason).toMatchObject({ code: "EEXIST" });
      const original = await readFile(target);
      expect(bodies).toContainEqual(JSON.parse(original.toString("utf8")));
      expect((await stat(target)).mode & 0o777).toBe(0o600);
      await expect(publishRecoveryJson(target, { replacement: true })).rejects.toMatchObject({
        code: "EEXIST"
      });
      expect(await readFile(target)).toEqual(original);
      expect(await readdir(root)).toEqual(["manifest.json"]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("refuses a symlink parent or target without writing through either", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-publication-path-"));
    try {
      const destination = path.join(root, "destination");
      await mkdir(destination);
      await symlink(destination, path.join(root, "alias"));
      await expect(
        publishRecoveryJson(path.join(root, "alias", "manifest.json"), { value: 1 })
      ).rejects.toThrow();
      expect(await readdir(destination)).toEqual([]);
      await symlink(path.join(destination, "untouched.json"), path.join(root, "manifest.json"));
      await expect(
        publishRecoveryJson(path.join(root, "manifest.json"), { value: 1 })
      ).rejects.toMatchObject({ code: "EEXIST" });
      expect(await readdir(destination)).toEqual([]);
      expect((await readdir(root)).toSorted()).toEqual(["alias", "destination", "manifest.json"]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("recognizes only owned incomplete names and bounds the report without claiming staleness", () => {
    const wal = "000000010000000000000001.manifest.json.partial-999999-0123456789abcdef";
    const base =
      "boardagent-018f0000-0000-7000-8000-000000000001.base.manifest.json.partial-42-0123456789abcdef";
    expect(isRecoveryTemporaryFile(wal, "wal")).toBe(true);
    expect(isRecoveryTemporaryFile(base, "base")).toBe(true);
    for (const name of [
      wal + "x",
      "../" + wal,
      wal.replace("999999", "0"),
      wal.replace("0123456789abcdef", "bad"),
      "unexpected.partial-12-0123456789abcdef"
    ]) {
      expect(isRecoveryTemporaryFile(name, "wal")).toBe(false);
    }
    expect(isRecoveryTemporaryFile(base.replace("7000", "4000"), "base")).toBe(false);
    const names = Array.from({ length: 25 }, (_, i) => wal.replace("999999", String(i + 1)));
    expect(recoveryTemporaryReport(names)).toEqual({
      ignoredTemporaryFileCount: 25,
      ignoredTemporaryFiles: names.toSorted().slice(0, 20)
    });
    expect(recoveryTemporaryReport([])).toEqual({});
  });
});
