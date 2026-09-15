import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { recoveryDatabaseUrl } from "../../scripts/src/operator.js";

describe("production operator recovery database credentials", () => {
  it("loads each production password from its owner-only file and keeps it out of input URLs", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-recovery-config-"));
    const passwordFile = path.join(directory, "backup.password");
    const password = "b".repeat(43);
    await writeFile(passwordFile, `${password}\n`, { mode: 0o600 });
    try {
      const cases = [
        [
          "BOARDAGENT_BACKUP_DATABASE_URL",
          "BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE",
          "boardagent_backup_login"
        ],
        [
          "BOARDAGENT_RECEIPT_DATABASE_URL",
          "BOARDAGENT_RECEIPT_DATABASE_PASSWORD_FILE",
          "boardagent_worker_login"
        ],
        [
          "BOARDAGENT_RESTORE_DATABASE_URL",
          "BOARDAGENT_RESTORE_DATABASE_PASSWORD_FILE",
          "boardagent_backup_login"
        ]
      ] as const;
      for (const [urlName, passwordName, username] of cases) {
        const resolved = recoveryDatabaseUrl(
          {
            [urlName]: `postgresql://${username}@postgres:5432/boardagent`,
            [passwordName]: passwordFile
          },
          "production",
          urlName
        );
        const parsed = new URL(resolved);
        expect(parsed.username).toBe(username);
        expect(parsed.password).toBe(password);
        expect(parsed.hostname).toBe("postgres");
      }

      expect(() =>
        recoveryDatabaseUrl(
          {
            BOARDAGENT_BACKUP_DATABASE_URL:
              "postgresql://boardagent_backup_login:embedded-secret@postgres:5432/boardagent",
            BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE: passwordFile
          },
          "production",
          "BOARDAGENT_BACKUP_DATABASE_URL"
        )
      ).toThrow("password must come from its secret file");
      expect(() =>
        recoveryDatabaseUrl(
          {
            BOARDAGENT_BACKUP_DATABASE_URL:
              "postgresql://boardagent_backup_login@postgres:5432/boardagent"
          },
          "production",
          "BOARDAGENT_BACKUP_DATABASE_URL"
        )
      ).toThrow("BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE is required");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("requires an explicit restore target even outside production", () => {
    expect(() =>
      recoveryDatabaseUrl(
        { BOARDAGENT_DATABASE_URL: "postgresql://local@127.0.0.1/boardagent" },
        "test",
        "BOARDAGENT_RESTORE_DATABASE_URL",
        false
      )
    ).toThrow("BOARDAGENT_RESTORE_DATABASE_URL is required");
  });
});
