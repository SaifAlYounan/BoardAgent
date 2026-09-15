import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  loadBoardAgentKeyMaterial,
  loadBoardAgentWorkerKeyMaterial
} from "../../artifacts/server/src/key-material.js";
import { parseConfig, resolveDatabaseUrl } from "../../lib/config/src/index.js";

describe("runtime secret initialization readiness", () => {
  it.each(["file", "dangling-symlink"])(
    "refuses database and application credentials while a %s marker exists",
    async (kind) => {
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-secret-ready-"));
      try {
        const database = path.join(directory, "database_server_password");
        const oauth = path.join(directory, "oauth_signing_key");
        const evidence = path.join(directory, "evidence_signing_key");
        const browser = path.join(directory, "browser_session_key");
        const data = path.join(directory, "data_kek");
        const marker = path.join(directory, ".initialization-incomplete");
        await writeFile(database, randomBytes(32).toString("base64url"), { mode: 0o600 });
        await writeFile(
          oauth,
          JSON.stringify({
            ...generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
              format: "jwk"
            }),
            kid: "synthetic-readiness-test",
            use: "sig",
            alg: "ES256"
          }),
          { mode: 0o600 }
        );
        await writeFile(
          evidence,
          generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }),
          { mode: 0o600 }
        );
        await writeFile(browser, randomBytes(32), { mode: 0o600 });
        await writeFile(data, randomBytes(32), { mode: 0o600 });
        const environment = {
          BOARDAGENT_ENV: "production",
          BOARDAGENT_DATABASE_URL: "postgresql://boardagent_server_login@localhost/boardagent",
          BOARDAGENT_DATABASE_PASSWORD_FILE: database,
          BOARDAGENT_ORGANIZATION_ID: "018f0000-0000-7000-8000-000000000001",
          BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
          BOARDAGENT_AUTHORIZATION_MODE: "builtin",
          BOARDAGENT_BLOB_ROOT: directory,
          BOARDAGENT_OAUTH_SIGNING_KEY_FILE: oauth,
          BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: evidence,
          BOARDAGENT_BROWSER_SESSION_KEY_FILE: browser,
          BOARDAGENT_DATA_KEK_FILE: data
        };
        const config = parseConfig(environment);
        await expect(loadBoardAgentKeyMaterial(config)).resolves.toHaveProperty("oauthKid");
        await expect(loadBoardAgentWorkerKeyMaterial(config)).resolves.toHaveProperty(
          "evidenceKid"
        );
        if (kind === "file") await writeFile(marker, "", { mode: 0o600 });
        else await symlink(path.join(directory, "absent"), marker);

        expect(() => resolveDatabaseUrl(environment)).toThrow("secret initialization incomplete");
        await expect(loadBoardAgentKeyMaterial(config)).rejects.toThrow(
          "secret initialization incomplete"
        );
        await expect(loadBoardAgentWorkerKeyMaterial(config)).rejects.toThrow(
          "secret initialization incomplete"
        );

        await rm(marker);
        expect(() => resolveDatabaseUrl(environment)).not.toThrow();
        await expect(loadBoardAgentKeyMaterial(config)).resolves.toHaveProperty("oauthKid");
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  );
});
