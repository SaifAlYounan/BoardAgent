import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const TSX = path.resolve("node_modules/.bin/tsx");

interface Invocation {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

async function invoke(args: readonly string[], env: NodeJS.ProcessEnv): Promise<Invocation> {
  const child = spawn(
    TSX,
    ["--tsconfig", "scripts/tsconfig.json", "scripts/src/operator.ts", ...args],
    { cwd: path.resolve("."), env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] }
  );
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { code, stdout, stderr };
}

describe("T9 operator CLI", () => {
  it("migrates, bootstraps once, registers exact runtime keys and never replays the invite", async () => {
    const database = `boardagent_operator_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    const adminUrl = new URL(BASE_URL);
    adminUrl.pathname = "/postgres";
    const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
    await admin.query(`create database "${database}"`);
    const databaseUrl = new URL(BASE_URL);
    databaseUrl.pathname = `/${database}`;
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-operator-"));
    const setupPath = path.join(directory, "bootstrap.json");
    await writeFile(
      setupPath,
      `${JSON.stringify({
        organizationLegalName: "Operator Test Ltd",
        organizationDisplayName: "Operator Test",
        organizationSlug: "operator-test",
        timezone: "UTC",
        boardSlug: "main",
        boardName: "Main",
        boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
        firstSecretaryLegalName: "Secretary",
        firstSecretaryDisplayName: "Secretary",
        votingWeight: 1,
        supportName: "Secretary",
        supportContactMethods: [{ kind: "operator_reference", value: "local" }],
        onboardingTermsText: "Review every canonical record.",
        invitationHandoffMethod: "in person"
      })}\n`,
      { mode: 0o600 }
    );
    const env = {
      BOARDAGENT_ENV: "test",
      BOARDAGENT_DATABASE_URL: databaseUrl.toString(),
      BOARDAGENT_PUBLIC_BASE_URL: "https://operator.boardagent.test",
      BOARDAGENT_AUTHORIZATION_MODE: "builtin",
      BOARDAGENT_BLOB_ROOT: directory,
      BOARDAGENT_DEV_MASTER_SECRET: "operator-test-secret-material-is-long-enough"
    };
    try {
      const first = await invoke(["bootstrap", setupPath], env);
      expect(first.code, first.stderr).toBe(0);
      const firstReceipt = JSON.parse(first.stdout) as Record<string, unknown>;
      expect(firstReceipt).toMatchObject({
        schemaVersion: 1,
        command: "bootstrap",
        operatorStatus: "succeeded",
        status: "created",
        secretOnce: true,
        runtimeKeysRegistered: true,
        keyRegistration: { created: 4, replayed: 0 }
      });
      expect(firstReceipt["enrollmentUrl"]).toMatch(
        /^https:\/\/operator\.boardagent\.test\/enroll#/u
      );
      const organizationId = String(firstReceipt["organizationId"]);

      const verification = new Pool({ connectionString: databaseUrl.toString(), max: 1 });
      try {
        expect(
          await verification.query(
            "select purpose,count(*)::integer as count from crypto_key_registry group by purpose order by purpose"
          )
        ).toMatchObject({
          rows: [
            { purpose: "browser_session", count: 1 },
            { purpose: "data_kek", count: 1 },
            { purpose: "evidence_signing", count: 1 },
            { purpose: "oauth_signing", count: 1 }
          ]
        });
      } finally {
        await verification.end();
      }

      const replay = await invoke(["bootstrap", setupPath], env);
      expect(replay.code, replay.stderr).toBe(0);
      const replayReceipt = JSON.parse(replay.stdout) as Record<string, unknown>;
      expect(replayReceipt).toMatchObject({
        operatorStatus: "succeeded",
        status: "already_initialized",
        secretOnce: true,
        runtimeKeysRegistered: true,
        keyRegistration: { created: 0, replayed: 4 }
      });
      expect(replayReceipt).not.toHaveProperty("enrollmentUrl");

      const keys = await invoke(["register-runtime-keys"], {
        ...env,
        BOARDAGENT_ORGANIZATION_ID: organizationId
      });
      expect(keys.code, keys.stderr).toBe(0);
      expect(JSON.parse(keys.stdout)).toMatchObject({
        status: "succeeded",
        keyRegistration: { created: 0, replayed: 4 }
      });
      const backupKeyFile = path.join(directory, "backup.key");
      await writeFile(backupKeyFile, randomBytes(32), { mode: 0o600 });
      const backupEnv = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: databaseUrl.toString(),
        BOARDAGENT_ORGANIZATION_ID: organizationId,
        BOARDAGENT_BACKUP_KEY_ID: "0198c000-0000-7000-8000-000000085001",
        BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY: directory,
        BOARDAGENT_BACKUP_KEK_FILE: backupKeyFile
      };
      const backupKey = await invoke(["register-backup-key"], backupEnv);
      expect(backupKey.code, backupKey.stderr).toBe(0);
      expect(JSON.parse(backupKey.stdout)).toMatchObject({
        command: "register-backup-key",
        status: "succeeded",
        keyRegistration: { purpose: "backup_kek", replayed: false }
      });
      const backupReplay = await invoke(["register-backup-key"], backupEnv);
      expect(backupReplay.code, backupReplay.stderr).toBe(0);
      expect(JSON.parse(backupReplay.stdout)).toMatchObject({
        keyRegistration: { replayed: true }
      });
    } finally {
      await admin.query(`drop database "${database}" with (force)`);
      await admin.end();
      await rm(directory, { recursive: true, force: true });
    }
  }, 120_000);
});
