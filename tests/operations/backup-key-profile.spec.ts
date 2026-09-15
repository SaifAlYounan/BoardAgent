import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const invoke = promisify(execFile);

describe("production backup-key registration profile", () => {
  it("gives only the one-shot registrar the migrator password and backup KEK", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-registration-profile-"));
    const input = path.join(directory, "unused-private-input");
    await writeFile(input, "", { mode: 0o600 });
    try {
      const env = {
        ...process.env,
        APP_ENV_FILE: input,
        RELEASE_IMAGE: "boardagent:profile-test",
        DATABASE_OWNER_PASSWORD_HOST_FILE: input,
        DATABASE_MIGRATOR_PASSWORD_HOST_FILE: input,
        DATABASE_SERVER_PASSWORD_HOST_FILE: input,
        DATABASE_WORKER_PASSWORD_HOST_FILE: input,
        DATABASE_BACKUP_PASSWORD_HOST_FILE: input,
        OAUTH_SIGNING_KEY_HOST_FILE: input,
        EVIDENCE_SIGNING_KEY_HOST_FILE: input,
        BROWSER_SESSION_KEY_HOST_FILE: input,
        DATA_KEK_HOST_FILE: input,
        BACKUP_KEK_HOST_FILE: input
      };
      const { stdout } = await invoke(
        "docker",
        [
          "compose",
          "-f",
          "compose.yaml",
          "-f",
          "compose.production.yaml",
          "--profile",
          "backup-key",
          "config",
          "--format",
          "json"
        ],
        { env }
      );
      const config = JSON.parse(stdout) as {
        services: Record<
          string,
          {
            user: string;
            command: string[];
            entrypoint: string[];
            profiles: string[];
            cap_drop: string[];
            read_only: boolean;
            restart: string;
            volumes: { source: string; target: string; read_only?: boolean }[];
            secrets?: { source: string; target: string }[];
            environment: Record<string, string>;
          }
        >;
      };
      const registrar = config.services["backup-key-registrar"];
      expect(registrar).toBeDefined();
      expect(registrar).toMatchObject({
        user: "10001:10001",
        read_only: true,
        cap_drop: ["ALL"],
        restart: "no",
        profiles: ["backup-key"],
        command: ["register-backup-key"],
        environment: {
          BOARDAGENT_DATABASE_URL:
            "postgresql://boardagent_migrator_login@postgres:5432/boardagent",
          BOARDAGENT_DATABASE_PASSWORD_FILE:
            "/run/boardagent-registration/database_migrator_password",
          BOARDAGENT_BACKUP_KEK_FILE: "/run/boardagent-registration/backup_kek"
        }
      });
      expect(registrar!.volumes).toEqual([
        {
          type: "volume",
          source: "backup-registration-secrets",
          target: "/run/boardagent-registration",
          read_only: true,
          volume: {}
        },
        {
          type: "volume",
          source: "backup-key-receipts",
          target: "/var/lib/boardagent/backup-key-receipts",
          volume: {}
        }
      ]);
      const initializer = config.services["backup-registration-secret-init"];
      expect(initializer).toMatchObject({
        user: "0:0",
        profiles: ["backup-key"],
        restart: "no",
        read_only: true
      });
      expect(initializer!.secrets?.map(({ source }) => source).sort()).toEqual([
        "backup_registration_kek",
        "database_migrator_password"
      ]);
      for (const [name, service] of Object.entries(config.services)) {
        if (["backup-key-registrar", "backup-registration-secret-init"].includes(name)) continue;
        expect(
          service.volumes?.some(({ source }) => source === "backup-registration-secrets"),
          name
        ).not.toBe(true);
        expect(
          service.volumes?.some(({ source }) => source === "backup-key-receipts"),
          name
        ).not.toBe(true);
        expect(
          service.secrets?.some(({ source }) => source === "backup_registration_kek"),
          name
        ).not.toBe(true);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
