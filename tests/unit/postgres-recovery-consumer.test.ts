import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { encryptBackupArtifact } from "../../scripts/src/recovery-artifact.js";
import { runEncryptedPgRestore } from "../../scripts/src/postgres-recovery.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, open: vi.fn(actual.open) };
});

describe("encrypted PostgreSQL restore consumer boundary", () => {
  it.each(["valid", "invalid_tag", "consumer_exit"] as const)(
    "handles %s with an actual harmless child consumer and closed snapshot",
    async (scenario) => {
      const actualProcess =
        await vi.importActual<typeof import("node:child_process")>("node:child_process");
      const actualFs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-consumer-"));
      const artifact = path.join(directory, "backup.aes256gcm");
      const receipt = path.join(directory, "consumer-count.json");
      const key = Buffer.alloc(32, 0x32);
      let consumer: ReturnType<typeof spawn> | undefined;
      let ready: Promise<unknown> | undefined;
      let snapshot: Awaited<ReturnType<typeof open>> | undefined;
      let writtenChunks = 0;
      try {
        const encrypted = await encryptBackupArtifact(
          Readable.from([Buffer.alloc(16 * 65_536, 0x51)]),
          artifact,
          key
        );
        if (scenario === "invalid_tag") {
          const changed = await readFile(artifact);
          changed[changed.length - 1]! ^= 1;
          await writeFile(artifact, changed);
        }
        vi.mocked(spawn).mockImplementation((executable, args) => {
          if (executable !== "pg_restore" || !Array.isArray(args))
            throw new Error("unexpected recovery fixture executable");
          if (args.includes("--version"))
            return actualProcess.spawn(
              process.execPath,
              ["-e", "process.stdout.write('pg_restore (PostgreSQL) 18.6')"],
              { stdio: ["ignore", "pipe", "pipe"] }
            );
          expect(args).toContain("--single-transaction");
          expect(args).toContain("--exit-on-error");
          // Substitute only the external executable. The real wrapper, pipe,
          // authentication, child lifecycle and file I/O remain in use; no DB runs.
          consumer = actualProcess.spawn(
            process.execPath,
            [
              "--input-type=module",
              "-e",
              `
            import { writeFileSync } from 'node:fs';
            let bytes = 0; const report = () => writeFileSync(process.argv[1], JSON.stringify({ bytes }));
            process.stdin.on('data', chunk => { bytes += chunk.length; });
            process.stdin.on('end', () => { report(); process.exit(0); });
            process.on('SIGTERM', () => { report(); process.exit(1); });
            process.stdout.write('ready');
          `,
              receipt
            ],
            { stdio: ["pipe", "pipe", "pipe"] }
          );
          ready = once(consumer.stdout!, "data");
          return consumer;
        });
        vi.mocked(open).mockImplementation(async (...args) => {
          const handle = await actualFs.open(...args);
          if (
            typeof args[0] === "string" &&
            path.basename(args[0]).startsWith(".boardagent-auth-")
          ) {
            snapshot = handle;
            const write = handle.write.bind(handle);
            vi.spyOn(handle, "write").mockImplementation(async (...writeArgs) => {
              await ready;
              const result = (await Reflect.apply(write, undefined, writeArgs)) as Awaited<
                ReturnType<typeof handle.write>
              >;
              writtenChunks += 1;
              if (scenario === "consumer_exit" && writtenChunks === 2) {
                const closed = once(consumer!, "close");
                consumer!.kill("SIGTERM");
                await closed;
              }
              return result;
            });
          }
          return handle;
        });
        const restoration = runEncryptedPgRestore({
          databaseUrl: "postgresql://synthetic@127.0.0.1:1/synthetic_fixture",
          artifactPath: artifact,
          encryptionKey: key,
          scratchDirectory: directory
        });
        if (scenario === "valid")
          await expect(restoration).resolves.toEqual({
            pgRestoreVersion: "pg_restore (PostgreSQL) 18.6"
          });
        else if (scenario === "invalid_tag")
          await expect(restoration).rejects.toThrow("backup artifact authentication failed");
        else await expect(restoration).rejects.toThrow();
        expect(JSON.parse(await readFile(receipt, "utf8"))).toEqual({
          bytes: scenario === "valid" ? encrypted.plaintextByteLength : 0
        });
        expect(snapshot?.fd).toBe(-1);
        if (scenario === "consumer_exit") expect(writtenChunks).toBe(2);
      } finally {
        vi.mocked(open).mockImplementation(actualFs.open);
        vi.mocked(spawn).mockImplementation(actualProcess.spawn);
        if (consumer && consumer.exitCode === null && consumer.signalCode === null) {
          const closed = once(consumer, "close");
          consumer.kill("SIGKILL");
          await closed;
        }
        key.fill(0);
        await rm(directory, { recursive: true, force: true });
      }
    }
  );
});
