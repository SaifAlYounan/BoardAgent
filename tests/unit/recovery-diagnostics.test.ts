import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { archiveWalFailureDetails, materializeWalArchive } from "../../scripts/src/wal-archive.js";

describe("recovery failure diagnostics", () => {
  it.each(["08000", "08003", "08006", "08P01", "57P01", "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT"])(
    "classifies connection failure %s without exposing its message or connection data",
    (code) => {
      const error = Object.assign(new Error("synthetic private connection details"), {
        code,
        connectionString: "synthetic-private-dsn"
      });
      expect(archiveWalFailureDetails(error)).toEqual({
        stage: "unknown",
        reasonCode: "connection_unavailable"
      });
    }
  );

  it.each(["080", "080000", "08p01", "08SECRET", "57014", "unknown"])(
    "keeps unrecognized code %s generic",
    (code) => {
      expect(archiveWalFailureDetails({ code, message: "synthetic private details" })).toEqual({
        stage: "unknown",
        reasonCode: "validation_or_operation_failed"
      });
    }
  );

  it.each([false, true])(
    "reports an archive without published pairs as empty, with retained temporary=%s",
    async (temporary) => {
      const root = await mkdtemp(path.join(tmpdir(), "boardagent-empty-wal-diagnostic-"));
      const archive = path.join(root, "archive");
      const target = path.join(root, "target");
      try {
        await Promise.all([mkdir(archive), mkdir(target)]);
        const filename = "00000001000000000000000C.aes256gcm.partial-123-0123456789abcdef";
        if (temporary) await writeFile(path.join(archive, filename), "unfinished synthetic writer");
        const result = await materializeWalArchive({
          archiveDirectory: archive,
          targetDirectory: target,
          encryptionKeyFile: path.join(root, "missing-private-key"),
          encryptionKeyId: "018f0000-0000-7000-8000-000000000099"
        }).then(
          () => ({ unexpectedlySucceeded: true }),
          (error: unknown) => archiveWalFailureDetails(error)
        );
        expect(result).toEqual({ stage: "archive", reasonCode: "archive_empty" });
        expect(await readdir(target)).toEqual([]);
        expect(await readdir(archive)).toEqual(temporary ? [filename] : []);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );
});
