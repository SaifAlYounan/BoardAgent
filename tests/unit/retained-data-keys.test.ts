import { createHash, randomBytes } from "node:crypto";
import { chmod, link, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  loadBoardAgentKeyMaterial,
  loadBoardAgentWorkerKeyMaterial
} from "../../artifacts/server/src/key-material.js";
import { productionKeyFiles } from "../helpers/production-key-files.js";
import { testId } from "../helpers/authorized-actor.js";

async function fixture<T>(
  run: (input: Awaited<ReturnType<typeof prepare>>) => Promise<T>
): Promise<T> {
  const directory = await mkdtemp(path.join(tmpdir(), "boardagent-retained-data-"));
  try {
    return await run(await prepare(directory));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
async function prepare(directory: string) {
  const production = await productionKeyFiles(directory, testId(120_000));
  const key = randomBytes(32),
    keyFile = path.join(directory, "previous-data.key"),
    manifestFile = path.join(directory, "retained.json");
  await writeFile(keyFile, key, { mode: 0o600 });
  const entry = {
    keyId: testId(120_002),
    kid: `data-${createHash("sha256").update("boardagent/data/key-id/v1\0").update(key).digest("hex").slice(0, 24)}`,
    fingerprintSha256: createHash("sha256").update(key).digest("hex"),
    keyFile
  };
  const manifest = {
    schemaVersion: "boardagent.retained-data-keys.v1",
    instanceId: testId(120_001),
    organizationId: testId(120_000),
    keys: [entry]
  };
  const save = (value: unknown = manifest) =>
    writeFile(manifestFile, JSON.stringify(value), { mode: 0o600 });
  await save();
  const config = parseConfig({
    ...production.environment,
    BOARDAGENT_RETAINED_DATA_KEYS_FILE: manifestFile
  });
  return { ...production, directory, key, keyFile, manifestFile, entry, manifest, config, save };
}
const INVALID = "retained data-key manifest or protected key file is invalid";

describe("retained data-key configuration and protected material", () => {
  it("loads historical keys for both processes and never gives the worker OAuth/browser material", async () => {
    await fixture(async ({ config, manifestFile, manifest, entry, key }) => {
      expect(config).toHaveProperty("retainedDataKeysFile", manifestFile);
      const server = await loadBoardAgentKeyMaterial(config),
        worker = await loadBoardAgentWorkerKeyMaterial(config);
      for (const keys of [server, worker]) {
        expect(keys.retainedDataKeys).toEqual({
          instanceId: manifest.instanceId,
          organizationId: manifest.organizationId,
          entries: [{ ...entry, key }]
        });
        expect(Buffer.from(keys.dataEncryptionKey)).not.toEqual(key);
      }
      expect(worker).not.toHaveProperty("oauthPrivateJwk");
      expect(worker).not.toHaveProperty("browserSessionKey");
    });
  });
  it("accepts canonical base64url and explicitly permitted group-read files", async () => {
    await fixture(async ({ config, keyFile, key, manifestFile }) => {
      await writeFile(keyFile, key.toString("base64url") + "\n");
      await chmod(keyFile, 0o640);
      await chmod(manifestFile, 0o640);
      expect(
        (await loadBoardAgentWorkerKeyMaterial(config)).retainedDataKeys!.entries[0]!.key
      ).toEqual(key);
    });
  });
  it.each([
    "world-readable",
    "group-writable",
    "executable",
    "symlink",
    "hardlink",
    "missing",
    "wrong-bytes",
    "oversize",
    "noncanonical-base64"
  ])("refuses a %s retained key", async (kind) => {
    await fixture(async ({ config, keyFile, key }) => {
      if (kind === "world-readable") await chmod(keyFile, 0o604);
      if (kind === "group-writable") await chmod(keyFile, 0o620);
      if (kind === "executable") await chmod(keyFile, 0o700);
      if (kind === "symlink") {
        const target = keyFile + ".real";
        await writeFile(target, key, { mode: 0o600 });
        await rm(keyFile);
        await symlink(target, keyFile);
      }
      if (kind === "hardlink") await link(keyFile, keyFile + ".alias");
      if (kind === "missing") await rm(keyFile);
      if (kind === "wrong-bytes") await writeFile(keyFile, randomBytes(32));
      if (kind === "oversize") await writeFile(keyFile, Buffer.alloc(45));
      if (kind === "noncanonical-base64") await writeFile(keyFile, key.toString("base64url") + "=");
      await expect(loadBoardAgentWorkerKeyMaterial(config)).rejects.toThrow(INVALID);
    });
  });
  it.each([
    "unknown-field",
    "duplicate-key",
    "wrong-fingerprint",
    "wrong-kid",
    "wrong-organization",
    "active-file",
    "active-bytes",
    "relative-path",
    "duplicate-json",
    "too-many",
    "too-large",
    "manifest-symlink",
    "manifest-permissions",
    "incomplete"
  ])("refuses %s manifest input without exposing supplied content", async (kind) => {
    await fixture(
      async ({ config, files, keyFile, manifestFile, manifest, entry, save, directory }) => {
        if (kind === "unknown-field")
          await save({ ...manifest, privateKey: "sensitive-synthetic-marker" });
        if (kind === "duplicate-key") await save({ ...manifest, keys: [entry, entry] });
        if (kind === "wrong-fingerprint")
          await save({ ...manifest, keys: [{ ...entry, fingerprintSha256: "0".repeat(64) }] });
        if (kind === "wrong-kid")
          await save({ ...manifest, keys: [{ ...entry, kid: "data-" + "0".repeat(24) }] });
        if (kind === "wrong-organization")
          await save({ ...manifest, organizationId: testId(120_003) });
        if (kind === "active-file")
          await save({ ...manifest, keys: [{ ...entry, keyFile: files.data }] });
        if (kind === "active-bytes") {
          const active = await readFile(files.data);
          await writeFile(keyFile, active);
          await save({
            ...manifest,
            keys: [
              {
                ...entry,
                fingerprintSha256: createHash("sha256").update(active).digest("hex"),
                kid: `data-${createHash("sha256").update("boardagent/data/key-id/v1\0").update(active).digest("hex").slice(0, 24)}`
              }
            ]
          });
        }
        if (kind === "relative-path")
          await save({ ...manifest, keys: [{ ...entry, keyFile: "relative.key" }] });
        if (kind === "duplicate-json")
          await writeFile(
            manifestFile,
            JSON.stringify(manifest).replace('"keys":', '"keys":[],"keys":')
          );
        if (kind === "too-many")
          await save({ ...manifest, keys: Array.from({ length: 4097 }, () => entry) });
        if (kind === "too-large") await writeFile(manifestFile, " ".repeat(1_048_577));
        if (kind === "manifest-symlink") {
          await save();
          await writeFile(manifestFile + ".real", await readFile(manifestFile), { mode: 0o600 });
          await rm(manifestFile);
          await symlink(manifestFile + ".real", manifestFile);
        }
        if (kind === "manifest-permissions") await chmod(manifestFile, 0o644);
        if (kind === "incomplete")
          await writeFile(path.join(directory, ".initialization-incomplete"), "", { mode: 0o600 });
        await expect(loadBoardAgentWorkerKeyMaterial(config)).rejects.toThrow(
          kind === "incomplete" ? "secret initialization incomplete" : INVALID
        );
      }
    );
  });
  it("rejects local-profile, nonabsolute, alias and empty configuration", async () => {
    await fixture(async ({ environment, files }) => {
      for (const file of ["retained.json", "", files.data, "/run/secrets/../retained.json"]) {
        expect(() =>
          parseConfig({ ...environment, BOARDAGENT_RETAINED_DATA_KEYS_FILE: file })
        ).toThrow();
      }
      expect(() =>
        parseConfig({
          ...environment,
          BOARDAGENT_ENV: "test",
          BOARDAGENT_DATABASE_PASSWORD_FILE: undefined,
          BOARDAGENT_DEV_MASTER_SECRET: "retained-key-local-refusal-synthetic-only",
          BOARDAGENT_RETAINED_DATA_KEYS_FILE: "/run/retained.json"
        })
      ).toThrow("production-only");
    });
  });
});
