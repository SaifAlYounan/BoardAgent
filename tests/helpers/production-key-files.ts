import { generateKeyPairSync, randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";

/** Disposable real-format keys only. Callers own/remove the private temporary directory. */
export async function productionKeyFiles(directory: string, organizationId: string) {
  const files = {
    database: path.join(directory, "database.password"),
    oauth: path.join(directory, "oauth.jwk"),
    evidence: path.join(directory, "evidence.pem"),
    browser: path.join(directory, "browser.key"),
    data: path.join(directory, "data.key")
  };
  await writeFile(files.database, randomBytes(32).toString("base64url"), { mode: 0o600 });
  await writeFile(
    files.oauth,
    JSON.stringify({
      ...generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
        format: "jwk"
      }),
      kid: "synthetic-retained-key-test",
      use: "sig",
      alg: "ES256"
    }),
    { mode: 0o600 }
  );
  await writeFile(
    files.evidence,
    generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }),
    { mode: 0o600 }
  );
  await writeFile(files.browser, randomBytes(32), { mode: 0o600 });
  await writeFile(files.data, randomBytes(32), { mode: 0o600 });
  return {
    files,
    environment: {
      BOARDAGENT_ENV: "production",
      BOARDAGENT_DATABASE_URL: "postgresql://boardagent_server_login@localhost/boardagent",
      BOARDAGENT_DATABASE_PASSWORD_FILE: files.database,
      BOARDAGENT_ORGANIZATION_ID: organizationId,
      BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
      BOARDAGENT_AUTHORIZATION_MODE: "builtin",
      BOARDAGENT_BLOB_ROOT: directory,
      BOARDAGENT_OAUTH_SIGNING_KEY_FILE: files.oauth,
      BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: files.evidence,
      BOARDAGENT_BROWSER_SESSION_KEY_FILE: files.browser,
      BOARDAGENT_DATA_KEK_FILE: files.data
    }
  };
}
