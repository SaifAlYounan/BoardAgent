import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import * as files from "../../scripts/src/operator-key-files.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";

async function fixture(run: (directory: string) => Promise<void>) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), "boardagent-key-files-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
const keyPath = (directory: string) => path.join(directory, "key");

describe("operator private key file boundary", () => {
  it("publishes once with private durable bytes and refuses overwriting or partial substitution", async () => {
    await fixture(async (directory) => {
      const file = keyPath(directory),
        bytes = randomBytes(32);
      await files.publishOperatorKeyFile(file, bytes);
      expect(await readFile(file)).toEqual(bytes);
      expect((await lstat(file)).mode & 0o777).toBe(0o600);
      expect((await lstat(file)).nlink).toBe(1);
      await expect(files.publishOperatorKeyFile(file, randomBytes(32))).rejects.toThrow();
      expect(await readFile(file)).toEqual(bytes);
      const observed = await files.readOperatorProtectedFile(file, 32);
      expect(observed).toEqual(bytes);
      observed.fill(0);
    });
  });
  it("refuses links, hardlinks, unsafe modes, writable ancestors and oversized files", async () => {
    await fixture(async (directory) => {
      const file = keyPath(directory);
      await writeFile(file, randomBytes(32), { mode: 0o600 });
      await symlink(file, path.join(directory, "symlink"));
      await expect(
        files.readOperatorProtectedFile(path.join(directory, "symlink"), 32)
      ).rejects.toThrow();
      await link(file, path.join(directory, "hardlink"));
      await expect(files.readOperatorProtectedFile(file, 32)).rejects.toThrow();
      await rm(path.join(directory, "hardlink"));
      for (const mode of [0o644, 0o660, 0o700]) {
        await chmod(file, mode);
        await expect(files.readOperatorProtectedFile(file, 32)).rejects.toThrow();
      }
      await chmod(file, 0o600);
      await expect(files.readOperatorProtectedFile(file, 31)).rejects.toThrow();
      await chmod(directory, 0o777);
      await expect(files.readOperatorProtectedFile(file, 32)).rejects.toThrow();
      await expect(
        files.publishOperatorKeyFile(path.join(directory, "new"), randomBytes(32))
      ).rejects.toThrow();
      await chmod(directory, 0o700);
      const actual = path.join(directory, "actual");
      await mkdir(actual, { mode: 0o700 });
      await symlink(actual, path.join(directory, "alias"));
      await expect(
        files.publishOperatorKeyFile(path.join(directory, "alias", "new"), randomBytes(32))
      ).rejects.toThrow();
    });
  });
  it("normalizes symmetric encodings and detects reuse across purpose names", async () => {
    await fixture(async (directory) => {
      const raw = randomBytes(32),
        file = keyPath(directory);
      await writeFile(file, raw, { mode: 0o600 });
      const data = await files.loadOperatorKeyMaterial("data_kek", file);
      const browser = await files.loadOperatorKeyMaterial("browser_session", file);
      expect(data.materialSha256).toBe(createHash("sha256").update(raw).digest("hex"));
      expect(data.materialSha256).toBe(browser.materialSha256);
      expect(data.kid).not.toBe(browser.kid);
      await expect(files.assertDistinctOperatorKeyMaterial([data, browser])).rejects.toThrow();
      await writeFile(file, `${raw.toString("base64url")}\n`);
      const encoded = await files.loadOperatorKeyMaterial("data_kek", file);
      expect(encoded.materialSha256).toBe(data.materialSha256);
      expect(encoded.kid).toBe(data.kid);
      expect(encoded.fileSha256).not.toBe(data.fileSha256);
      for (const invalid of [
        ` ${raw.toString("base64url")}`,
        `${raw.toString("base64url")}\n\n`,
        "a".repeat(43)
      ]) {
        await writeFile(file, invalid);
        await expect(files.loadOperatorKeyMaterial("data_kek", file)).rejects.toThrow();
      }
      for (const material of [data, browser, encoded]) material.destroy();
    });
  });
  it("derives OAuth public identity from the private scalar and refuses mismatched or extra fields", async () => {
    await fixture(async (directory) => {
      const file = keyPath(directory);
      const privateJwk = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
        format: "jwk"
      });
      const jwk = { ...privateJwk, kid: "oauth-test", use: "sig", alg: "ES256" };
      await writeFile(file, JSON.stringify(jwk), { mode: 0o600 });
      const material = await files.loadOperatorKeyMaterial("oauth_signing", file);
      expect(material.materialSha256).toBe(
        canonicalSha256({ kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! })
      );
      expect(material.publicJwk).not.toHaveProperty("d");
      material.destroy();
      const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
        format: "jwk"
      });
      for (const invalid of [
        { ...jwk, d: other.d },
        { ...jwk, extra: true },
        { ...jwk, d: "A".repeat(43) }
      ]) {
        await writeFile(file, JSON.stringify(invalid));
        await expect(files.loadOperatorKeyMaterial("oauth_signing", file)).rejects.toThrow();
      }
    });
  });
  it("generates distinct correctly bound material for all five purposes without printing private bytes", async () => {
    await fixture(async (directory) => {
      for (const purpose of [
        "oauth_signing",
        "evidence_signing",
        "browser_session",
        "data_kek",
        "backup_kek"
      ] as const) {
        const file = path.join(directory, purpose);
        const generated = await files.generateOperatorKeyFile(purpose, file);
        const loaded = await files.loadOperatorKeyMaterial(purpose, file);
        expect(loaded.materialSha256).toBe(generated.materialSha256);
        expect(loaded.kid).toBe(generated.kid);
        expect(loaded.algorithm).toBe(generated.algorithm);
        expect(JSON.stringify(generated)).not.toContain("PRIVATE KEY");
        expect(JSON.stringify(generated)).not.toContain('"d":');
        loaded.destroy();
        await expect(files.generateOperatorKeyFile(purpose, file)).rejects.toThrow();
      }
    });
  });
});
