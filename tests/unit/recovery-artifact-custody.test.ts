import { mkdtemp, open, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import {
  decryptBackupArtifact,
  encryptBackupArtifact
} from "../../scripts/src/recovery-artifact.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, open: vi.fn(actual.open), unlink: vi.fn(actual.unlink) };
});

describe("recovery authentication snapshot custody", () => {
  it("refuses a pathname substitution that leaves the actual snapshot linked and empty", async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-custody-"));
    const artifact = path.join(directory, "backup.aes256gcm");
    const moved = path.join(directory, "retained-empty-snapshot");
    const key = Buffer.alloc(32, 0x31);
    let consumedBytes = 0;
    try {
      await encryptBackupArtifact(Readable.from([Buffer.alloc(131_073, 0x51)]), artifact, key);
      vi.mocked(unlink).mockImplementation(async (file) => {
        if (typeof file === "string" && path.basename(file).startsWith(".boardagent-auth-")) {
          await rename(file, moved);
          await writeFile(file, Buffer.alloc(0), { mode: 0o600, flag: "wx" });
        }
        await actual.unlink(file);
      });
      const consume = async () => {
        for await (const chunk of decryptBackupArtifact(artifact, key))
          consumedBytes += chunk.length;
      };
      await expect(consume()).rejects.toThrow(
        "backup authentication snapshot must be private and unlinked"
      );
      expect(consumedBytes).toBe(0);
      expect(await readFile(moved)).toHaveLength(0);
    } finally {
      vi.mocked(unlink).mockImplementation(actual.unlink);
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("stops a canceled first pass at the next chunk and closes its anonymous snapshot", async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-abort-"));
    const artifact = path.join(directory, "backup.aes256gcm");
    const key = Buffer.alloc(32, 0x61);
    const controller = new AbortController();
    let snapshot: Awaited<ReturnType<typeof open>> | undefined;
    let writtenChunks = 0;
    let consumedBytes = 0;
    try {
      await encryptBackupArtifact(Readable.from([Buffer.alloc(16 * 65_536, 0x41)]), artifact, key);
      vi.mocked(open).mockImplementation(async (...args) => {
        const handle = await actual.open(...args);
        if (typeof args[0] === "string" && path.basename(args[0]).startsWith(".boardagent-auth-")) {
          snapshot = handle;
          const write = handle.write.bind(handle);
          vi.spyOn(handle, "write").mockImplementation(async (...writeArgs) => {
            const result = (await Reflect.apply(write, undefined, writeArgs)) as Awaited<
              ReturnType<typeof handle.write>
            >;
            writtenChunks += 1;
            if (writtenChunks === 2) controller.abort(new Error("synthetic consumer cancellation"));
            return result;
          });
        }
        return handle;
      });
      const consume = async () => {
        for await (const chunk of decryptBackupArtifact(
          artifact,
          key,
          directory,
          controller.signal
        ))
          consumedBytes += chunk.length;
      };
      await expect(consume()).rejects.toThrow("synthetic consumer cancellation");
      expect(writtenChunks).toBe(2);
      expect(consumedBytes).toBe(0);
      expect(snapshot?.fd).toBe(-1);
    } finally {
      vi.mocked(open).mockImplementation(actual.open);
      key.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  });
});
