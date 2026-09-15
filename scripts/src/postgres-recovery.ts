import { spawn } from "node:child_process";
import { rm } from "node:fs/promises";
import { Readable } from "node:stream";
import { finished, pipeline } from "node:stream/promises";

import { z } from "zod";

import {
  decryptBackupArtifact,
  encryptBackupArtifact,
  type EncryptedBackupArtifact
} from "./recovery-artifact.js";

const SnapshotSchema = z.string().min(1).max(256);
const ToolSchema = z.enum([
  "pg_dump",
  "pg_restore",
  "pg_basebackup",
  "pg_verifybackup",
  "pg_controldata"
]);
const MAXIMUM_DIAGNOSTIC_BYTES = 64 * 1024;

interface PostgresConnection {
  readonly argument: string;
  readonly databaseName: string;
  readonly env: NodeJS.ProcessEnv;
}

interface SpawnedTool {
  readonly child: ReturnType<typeof spawn>;
  readonly completion: Promise<number>;
  readonly diagnostic: () => string;
}

function postgresConnection(databaseUrl: string): PostgresConnection {
  const parsed = new URL(databaseUrl);
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    throw new Error("recovery database URL must use PostgreSQL");
  }
  if (!parsed.username || parsed.pathname.length < 2 || parsed.hash) {
    throw new Error("recovery database URL must identify a user and database without a fragment");
  }
  const databaseName = decodeURIComponent(parsed.pathname.slice(1));
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$/u.test(databaseName)) {
    throw new Error("recovery database name is invalid");
  }
  const password = decodeURIComponent(parsed.password);
  parsed.password = "";
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PGAPPNAME: "boardagent-recovery-v1",
    PGCONNECT_TIMEOUT: "10"
  };
  if (password) env["PGPASSWORD"] = password;
  else delete env["PGPASSWORD"];
  return { argument: parsed.toString(), databaseName, env };
}

function spawnTool(
  executable: z.infer<typeof ToolSchema>,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  stdin: "ignore" | "pipe",
  stdout: "ignore" | "pipe"
): SpawnedTool {
  const child = spawn(executable, [...args], {
    env,
    stdio: [stdin, stdout, "pipe"]
  });
  let diagnostic = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    if (diagnostic.length < MAXIMUM_DIAGNOSTIC_BYTES) {
      diagnostic += chunk.slice(0, MAXIMUM_DIAGNOSTIC_BYTES - diagnostic.length);
    }
  });
  const completion = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (signal) reject(new Error(`${executable} was interrupted`));
      else resolve(code ?? 1);
    });
  });
  return { child, completion, diagnostic: () => diagnostic };
}

export async function postgresToolVersion(
  rawTool: "pg_dump" | "pg_restore" | "pg_basebackup" | "pg_verifybackup" | "pg_controldata"
): Promise<string> {
  const tool = ToolSchema.parse(rawTool);
  const invocation = spawnTool(tool, ["--version"], process.env, "ignore", "pipe");
  let stdout = "";
  invocation.child.stdout?.setEncoding("utf8");
  invocation.child.stdout?.on("data", (chunk: string) => (stdout += chunk));
  const code = await invocation.completion;
  if (code !== 0) throw new Error(`${tool} version check failed`);
  const version = stdout.trim();
  if (
    !new RegExp(`^${tool.replace("_", "_")} \\(PostgreSQL\\) 18\\.6(?:[ .-]|$)`, "u").test(version)
  ) {
    throw new Error(`${tool} must be the pinned PostgreSQL 18.6 client`);
  }
  return version;
}

export async function verifyPostgresBaseBackup(
  directory: string
): Promise<{ readonly pgVerifybackupVersion: string }> {
  const pgVerifybackupVersion = await postgresToolVersion("pg_verifybackup");
  const invocation = spawnTool(
    "pg_verifybackup",
    ["--no-parse-wal", directory],
    process.env,
    "ignore",
    "ignore"
  );
  const code = await invocation.completion;
  if (code !== 0) {
    throw new Error(
      `pg_verifybackup failed (${invocation.diagnostic().trim() || "no diagnostic"})`
    );
  }
  return { pgVerifybackupVersion };
}

export async function postgresBaseBackupSystemIdentifier(directory: string): Promise<string> {
  await postgresToolVersion("pg_controldata");
  const invocation = spawnTool("pg_controldata", [directory], process.env, "ignore", "pipe");
  let stdout = "";
  invocation.child.stdout?.setEncoding("utf8");
  invocation.child.stdout?.on("data", (chunk: string) => (stdout += chunk));
  const code = await invocation.completion;
  if (code !== 0) {
    throw new Error(`pg_controldata failed (${invocation.diagnostic().trim() || "no diagnostic"})`);
  }
  const match = /^Database system identifier:\s*([0-9]+)$/mu.exec(stdout);
  if (!match?.[1]) throw new Error("pg_controldata did not report a system identifier");
  return match[1];
}

export async function runEncryptedPgDump(input: {
  readonly databaseUrl: string;
  readonly snapshotId: string;
  readonly artifactPath: string;
  readonly encryptionKey: Uint8Array;
}): Promise<EncryptedBackupArtifact & { readonly pgDumpVersion: string }> {
  const connection = postgresConnection(input.databaseUrl);
  const snapshotId = SnapshotSchema.parse(input.snapshotId);
  const pgDumpVersion = await postgresToolVersion("pg_dump");
  const process = spawnTool(
    "pg_dump",
    [
      "--dbname",
      connection.argument,
      "--format=custom",
      "--role=boardagent_backup",
      "--enable-row-security",
      "--snapshot",
      snapshotId,
      "--lock-wait-timeout=30s",
      "--no-password"
    ],
    connection.env,
    "ignore",
    "pipe"
  );
  if (!process.child.stdout) throw new Error("pg_dump stdout was unavailable");
  try {
    const [artifact, code] = await Promise.all([
      encryptBackupArtifact(process.child.stdout, input.artifactPath, input.encryptionKey),
      process.completion
    ]);
    if (code !== 0) {
      await rm(input.artifactPath, { force: true });
      throw new Error(`pg_dump failed (${process.diagnostic().trim() || "no diagnostic"})`);
    }
    return { ...artifact, pgDumpVersion };
  } catch (error) {
    if (!process.child.killed) process.child.kill("SIGTERM");
    await process.completion.catch(() => undefined);
    await rm(input.artifactPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function runEncryptedPgRestore(input: {
  readonly databaseUrl: string;
  readonly artifactPath: string;
  readonly encryptionKey: Uint8Array;
  readonly scratchDirectory?: string;
}): Promise<{ readonly pgRestoreVersion: string }> {
  const connection = postgresConnection(input.databaseUrl);
  const pgRestoreVersion = await postgresToolVersion("pg_restore");
  const process = spawnTool(
    "pg_restore",
    ["--dbname", connection.argument, "--exit-on-error", "--single-transaction", "--no-password"],
    connection.env,
    "pipe",
    "ignore"
  );
  if (!process.child.stdin) throw new Error("pg_restore stdin was unavailable");
  const controller = new AbortController();
  const source = Readable.from(
    decryptBackupArtifact(
      input.artifactPath,
      input.encryptionKey,
      input.scratchDirectory,
      controller.signal
    ),
    { objectMode: false }
  );
  const completion = process.completion.finally(() => {
    if (!source.readableEnded)
      controller.abort(new Error("pg_restore stopped before consuming the authenticated backup"));
  });
  try {
    const [, code] = await Promise.all([pipeline(source, process.child.stdin), completion]);
    if (code !== 0) {
      throw new Error(`pg_restore failed (${process.diagnostic().trim() || "no diagnostic"})`);
    }
    return { pgRestoreVersion };
  } catch (error) {
    controller.abort(error);
    source.destroy();
    if (!process.child.killed) process.child.kill("SIGTERM");
    await completion.catch(() => undefined);
    await finished(source, { cleanup: true }).catch(() => undefined);
    throw error;
  }
}

export async function runEncryptedPgBaseBackup(input: {
  readonly databaseUrl: string;
  readonly artifactPath: string;
  readonly encryptionKey: Uint8Array;
  readonly label: string;
}): Promise<
  EncryptedBackupArtifact & {
    readonly pgBasebackupVersion: string;
  }
> {
  const connection = postgresConnection(input.databaseUrl);
  const label = z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_.:-]+$/u)
    .parse(input.label);
  const pgBasebackupVersion = await postgresToolVersion("pg_basebackup");
  const process = spawnTool(
    "pg_basebackup",
    [
      "--dbname",
      connection.argument,
      "--pgdata=-",
      "--format=tar",
      "--wal-method=fetch",
      "--checkpoint=fast",
      "--manifest-checksums=SHA256",
      "--label",
      label,
      "--no-password"
    ],
    connection.env,
    "ignore",
    "pipe"
  );
  if (!process.child.stdout) throw new Error("pg_basebackup stdout was unavailable");
  try {
    const [artifact, code] = await Promise.all([
      encryptBackupArtifact(process.child.stdout, input.artifactPath, input.encryptionKey),
      process.completion
    ]);
    if (code !== 0) {
      await rm(input.artifactPath, { force: true });
      throw new Error(`pg_basebackup failed (${process.diagnostic().trim() || "no diagnostic"})`);
    }
    return { ...artifact, pgBasebackupVersion };
  } catch (error) {
    if (!process.child.killed) process.child.kill("SIGTERM");
    await process.completion.catch(() => undefined);
    await rm(input.artifactPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

export function recoveryDatabaseName(databaseUrl: string): string {
  return postgresConnection(databaseUrl).databaseName;
}
