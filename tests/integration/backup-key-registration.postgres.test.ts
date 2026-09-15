import { createHash } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { migrate, withBootstrapTransaction } from "../../lib/db/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { runOperator } from "../../scripts/src/operator.js";
import { testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withFixture(
  run: (fixture: {
    pool: Pool;
    databaseUrl: string;
    organizationId: string;
    keyFile: string;
    key: Buffer;
  }) => Promise<void>
): Promise<void> {
  const database = `boardagent_backup_key_${String(process.pid)}_${String(++databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const databaseUrl = new URL(BASE_URL);
  databaseUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: databaseUrl.toString(), max: 3 });
  const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-backup-key-"));
  try {
    await migrate(pool, MIGRATIONS, "backup-key-registration-test");
    let id = 84_000;
    const initialized = await new BoardAgentBootstrapOperator(pool, {
      assumeRole: "boardagent_migrator",
      newId: () => testId(id++)
    }).initialize({
      organizationLegalName: "Backup Test Ltd",
      organizationDisplayName: "Backup Test",
      organizationSlug: "backup-test",
      timezone: "UTC",
      canonicalResourceUri: "https://boardagent.test/mcp",
      boardSlug: "main",
      boardName: "Main",
      boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
      firstSecretaryLegalName: "Secretary",
      firstSecretaryDisplayName: "Secretary",
      votingWeight: 1,
      supportName: "Secretary",
      supportContactMethods: [],
      onboardingTermsText: "Synthetic terms.",
      invitationHandoffMethod: "in person"
    });
    if (initialized.status !== "created") throw new Error("fixture bootstrap failed");
    const keyFile = path.join(directory, "backup.key");
    const key = Buffer.alloc(32, 0x64);
    await writeFile(keyFile, key, { mode: 0o600 });
    await run({
      pool,
      databaseUrl: databaseUrl.toString(),
      organizationId: initialized.organizationId,
      keyFile,
      key
    });
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
    await rm(directory, { recursive: true, force: true });
  }
}

describe("operator backup-key commissioning", () => {
  it("registers and replays one exact key without application secrets and refuses replacement", async () => {
    await withFixture(async ({ pool, databaseUrl, organizationId, keyFile, key }) => {
      const keyId = testId(85_001);
      const env = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: databaseUrl,
        BOARDAGENT_ORGANIZATION_ID: organizationId,
        BOARDAGENT_BACKUP_KEY_ID: keyId,
        BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY: path.dirname(keyFile),
        BOARDAGENT_BACKUP_KEK_FILE: keyFile
      };
      const output: string[] = [];
      const io = {
        stdout: (line: string) => output.push(line),
        stderr: (line: string) => output.push(line)
      };
      expect(await runOperator(["register-backup-key"], env, io)).toBe(0);
      const fingerprint = createHash("sha256").update(key).digest("hex");
      expect(JSON.parse(output[0]!)).toMatchObject({
        command: "register-backup-key",
        status: "succeeded",
        organizationId,
        keyRegistration: {
          keyId,
          purpose: "backup_kek",
          fingerprintSha256: fingerprint,
          replayed: false
        }
      });
      const receiptFile = path.join(path.dirname(keyFile), `${keyId}.json`);
      const originalReceipt = await readFile(receiptFile, "utf8");
      expect((await lstat(receiptFile)).mode & 0o777).toBe(0o400);
      expect(JSON.parse(originalReceipt)).toMatchObject({
        schemaVersion: "boardagent.backup-key-registration.v1",
        organizationId,
        keyId,
        fingerprintSha256: fingerprint,
        purpose: "backup_kek"
      });
      expect(await runOperator(["register-backup-key"], env, io)).toBe(0);
      expect(JSON.parse(output[1]!)).toMatchObject({ keyRegistration: { replayed: true } });
      expect(await readFile(receiptFile, "utf8")).toBe(originalReceipt);
      const rows = await pool.query(
        "select id,purpose,algorithm,public_jwk,nonsecret_locator from crypto_key_registry"
      );
      expect(rows.rows).toEqual([
        {
          id: keyId,
          purpose: "backup_kek",
          algorithm: "A256GCM",
          public_jwk: null,
          nonsecret_locator: `sha256:${fingerprint}`
        }
      ]);
      expect(output.join("")).not.toContain(key.toString("base64url"));
      expect(output.join("")).not.toContain(keyFile);
      await expect(
        runOperator(
          ["register-backup-key"],
          { ...env, BOARDAGENT_BACKUP_KEY_ID: testId(85_002) },
          io
        )
      ).rejects.toMatchObject({ code: "23505" });
      await writeFile(keyFile, Buffer.alloc(32, 0x65));
      await expect(runOperator(["register-backup-key"], env, io)).rejects.toMatchObject({
        code: "23505"
      });
      expect(
        (await pool.query("select count(*)::int as count from crypto_key_registry")).rows[0]?.count
      ).toBe(1);
    });
  });

  it("refuses wrong organization and unsafe key files before registration", async () => {
    await withFixture(async ({ pool, databaseUrl, organizationId, keyFile }) => {
      const env = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: databaseUrl,
        BOARDAGENT_ORGANIZATION_ID: organizationId,
        BOARDAGENT_BACKUP_KEY_ID: testId(85_001),
        BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY: path.dirname(keyFile),
        BOARDAGENT_BACKUP_KEK_FILE: keyFile
      };
      const output: string[] = [];
      const io = {
        stdout: (line: string) => output.push(line),
        stderr: (line: string) => output.push(line)
      };
      await expect(
        runOperator(
          ["register-backup-key"],
          { ...env, BOARDAGENT_ORGANIZATION_ID: testId(85_003) },
          io
        )
      ).rejects.toThrow();
      await chmod(keyFile, 0o644);
      await expect(runOperator(["register-backup-key"], env, io)).rejects.toThrow();
      await chmod(keyFile, 0o600);
      await writeFile(keyFile, Buffer.alloc(31, 0x64));
      await expect(runOperator(["register-backup-key"], env, io)).rejects.toThrow();
      expect(output).toEqual([]);
      expect(
        (await pool.query("select count(*)::int as count from crypto_key_registry")).rows[0]?.count
      ).toBe(0);
    });
  });

  it("restricts SQL registration to bootstrap migrator authority and validates exact metadata", async () => {
    await withFixture(async ({ pool, organizationId }) => {
      const args = [organizationId, testId(85_001), "a".repeat(64)];
      const sql = "select * from boardagent_register_backup_key($1,$2,$3)";
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"] as const) {
        const client = await pool.connect();
        try {
          await client.query("begin");
          await client.query(`set local role ${role}`);
          await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(client.query(sql, args)).rejects.toMatchObject({ code: "42501" });
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
      await expect(pool.query(sql, args)).rejects.toMatchObject({ code: "22023" });
      for (const invalid of [
        [organizationId, testId(85_001), null],
        [organizationId, testId(85_001), "not-a-hash"],
        [null, testId(85_001), args[2]]
      ]) {
        await expect(
          withBootstrapTransaction(pool, (client) => client.query(sql, invalid), {
            assumeRole: "boardagent_migrator"
          })
        ).rejects.toMatchObject({ code: "22023" });
      }
      await expect(
        withBootstrapTransaction(
          pool,
          (client) => client.query(sql, [testId(85_003), args[1], args[2]]),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23503" });
      expect(
        (await pool.query("select count(*)::int as count from crypto_key_registry")).rows[0]?.count
      ).toBe(0);
    });
  });
});
