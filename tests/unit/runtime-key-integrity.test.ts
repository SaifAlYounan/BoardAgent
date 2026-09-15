import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { describe, expect, it } from "vitest";

import {
  loadBoardAgentKeyMaterial,
  loadBoardAgentWorkerKeyMaterial
} from "../../artifacts/server/src/key-material.js";
import { parseConfig, type BoardAgentConfig } from "../../lib/config/src/index.js";

async function withProductionKeys(
  run: (fixture: { config: BoardAgentConfig; oauthFile: string; jwk: JWK }) => Promise<void>
) {
  const directory = await mkdtemp(path.join(tmpdir(), "boardagent-runtime-key-integrity-"));
  try {
    const files = {
      database: path.join(directory, "database-password"),
      oauth: path.join(directory, "oauth-key"),
      evidence: path.join(directory, "evidence-key"),
      browser: path.join(directory, "browser-key"),
      data: path.join(directory, "data-key")
    };
    const jwk: JWK = {
      ...generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
        format: "jwk"
      }),
      kid: "synthetic-runtime-integrity",
      use: "sig",
      alg: "ES256"
    };
    await writeFile(files.database, randomBytes(32).toString("base64url"), { mode: 0o600 });
    await writeFile(files.oauth, JSON.stringify(jwk), { mode: 0o600 });
    await writeFile(
      files.evidence,
      generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }),
      { mode: 0o600 }
    );
    await writeFile(files.browser, randomBytes(32), { mode: 0o600 });
    await writeFile(files.data, randomBytes(32), { mode: 0o600 });
    const config = parseConfig({
      BOARDAGENT_ENV: "production",
      BOARDAGENT_DATABASE_URL: "postgresql://boardagent_server_login@localhost/boardagent",
      BOARDAGENT_DATABASE_PASSWORD_FILE: files.database,
      BOARDAGENT_ORGANIZATION_ID: "018f0000-0000-7000-8000-000000000001",
      BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
      BOARDAGENT_AUTHORIZATION_MODE: "builtin",
      BOARDAGENT_BLOB_ROOT: directory,
      BOARDAGENT_OAUTH_SIGNING_KEY_FILE: files.oauth,
      BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: files.evidence,
      BOARDAGENT_BROWSER_SESSION_KEY_FILE: files.browser,
      BOARDAGENT_DATA_KEK_FILE: files.data
    });
    await run({ config, oauthFile: files.oauth, jwk });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("production runtime OAuth key integrity", () => {
  it("loads a matching retained key whose signatures verify with the loaded public identity", async () => {
    await withProductionKeys(async ({ config }) => {
      const keys = await loadBoardAgentKeyMaterial(config);
      const token = await new SignJWT({ synthetic: true })
        .setProtectedHeader({ alg: "ES256", kid: keys.oauthKid })
        .sign(await importJWK(keys.oauthPrivateJwk as JWK, "ES256"));
      const verified = await jwtVerify(token, keys.oauthPublicKey, { algorithms: ["ES256"] });
      expect(verified.payload.synthetic).toBe(true);
      expect(keys.oauthPublicJwk).not.toHaveProperty("d");
    });
  });

  it.each(["different-private-scalar", "zero-private-scalar", "alias-x", "alias-y", "alias-d"])(
    "refuses a retained OAuth key with %s before runtime binding",
    async (kind) => {
      await withProductionKeys(async ({ config, oauthFile, jwk }) => {
        const changed = { ...jwk };
        if (kind === "different-private-scalar") {
          changed.d = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
            format: "jwk"
          }).d!;
        } else if (kind === "zero-private-scalar") {
          changed.d = Buffer.alloc(32).toString("base64url");
        } else {
          const field = kind.slice(-1) as "x" | "y" | "d";
          const value = changed[field]!;
          const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
          const alias = value.slice(0, -1) + alphabet[alphabet.indexOf(value.at(-1)!) + 1];
          expect(Buffer.from(alias, "base64url")).toEqual(Buffer.from(value, "base64url"));
          expect(alias).not.toBe(value);
          changed[field] = alias;
        }
        await writeFile(oauthFile, JSON.stringify(changed), { mode: 0o600 });
        const outcome = await loadBoardAgentKeyMaterial(config).then(
          () => "loaded",
          () => "rejected"
        );
        expect(outcome).toBe("rejected");
      });
    }
  );

  it("loads worker keys without access to the server OAuth private file", async () => {
    await withProductionKeys(async ({ config, oauthFile }) => {
      await rm(oauthFile);
      const keys = await loadBoardAgentWorkerKeyMaterial(config);
      expect(keys.evidencePrivateKey.asymmetricKeyType).toBe("ed25519");
      expect(keys).not.toHaveProperty("oauthPrivateJwk");
      expect(keys).not.toHaveProperty("browserSessionKey");
    });
  });
});
