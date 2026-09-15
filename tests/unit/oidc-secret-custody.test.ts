import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { Pool } from "pg";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { parseConfig } from "../../lib/config/src/index.js";
import { loadBoardAgentKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { createBoardAgentServerApplication } from "../../artifacts/server/src/server-application.js";

const seams = vi.hoisted(() => ({
  closeLease: vi.fn(async () => undefined),
  discover: vi.fn(async () => {
    throw new Error("synthetic discovery boundary reached");
  })
}));

vi.mock("../../artifacts/server/src/runtime-maintenance-lease.js", () => ({
  acquireRuntimeMaintenanceLease: async () => ({ available: true, close: seams.closeLease })
}));
vi.mock("../../artifacts/server/src/runtime-binding.js", () => ({
  loadBoardAgentRuntimeBinding: async () => ({
    keyIds: {
      oauth_signing: "018f0000-0000-7000-8000-000000000002",
      data_kek: "018f0000-0000-7000-8000-000000000003"
    }
  })
}));
vi.mock("../../artifacts/server/src/oauth-authorization-server.js", () => ({
  createBoardAgentOAuthProvider: () => ({})
}));
vi.mock("../../artifacts/server/src/oidc-federation.js", () => ({
  discoverUpstreamOidcProfile: seams.discover
}));

async function withSecret(
  run: (fixture: { directory: string; file: string; start: () => Promise<string> }) => Promise<void>
) {
  const directory = await mkdtemp(path.join(tmpdir(), "boardagent-oidc-secret-"));
  const file = path.join(directory, "client-secret");
  const query = vi.fn(() => {
    throw new Error("unexpected database query");
  });
  try {
    await writeFile(file, "synthetic-client-secret-material-32", { mode: 0o600 });
    const config = parseConfig({
      BOARDAGENT_ENV: "test",
      BOARDAGENT_DATABASE_URL: "postgresql://unused",
      BOARDAGENT_ORGANIZATION_ID: "018f0000-0000-7000-8000-000000000001",
      BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.secret.test",
      BOARDAGENT_AUTHORIZATION_MODE: "oidc",
      BOARDAGENT_OIDC_ISSUER: "https://identity.secret.test",
      BOARDAGENT_OIDC_CLIENT_ID: "synthetic-client",
      BOARDAGENT_OIDC_CLIENT_SECRET_FILE: file,
      BOARDAGENT_BLOB_ROOT: directory,
      BOARDAGENT_DEV_MASTER_SECRET: "synthetic-dev-master-secret-long-enough"
    });
    const keys = await loadBoardAgentKeyMaterial(config);
    await run({
      directory,
      file,
      start: () =>
        createBoardAgentServerApplication({ query } as unknown as Pool, config, { keys }).then(
          () => "unexpected startup success",
          (error: unknown) => (error instanceof Error ? error.message : "unknown error")
        )
    });
    expect(query).not.toHaveBeenCalled();
    expect(seams.closeLease).toHaveBeenCalledTimes(1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("OIDC client secret startup custody", () => {
  beforeEach(() => vi.clearAllMocks());

  it.each(["file", "dangling-symlink"])(
    "refuses the secret while a %s initialization marker exists",
    async (kind) => {
      await withSecret(async ({ directory, start }) => {
        const marker = path.join(directory, ".initialization-incomplete");
        if (kind === "file") await writeFile(marker, "", { mode: 0o600 });
        else await symlink(path.join(directory, "absent"), marker);
        expect(await start()).toContain("secret initialization incomplete");
        expect(seams.discover).not.toHaveBeenCalled();
      });
    }
  );

  it("refuses an oversized raw file even when trimming would yield a valid secret", async () => {
    await withSecret(async ({ file, start }) => {
      await writeFile(file, "synthetic-client-secret-material-32" + "\n".repeat(8192));
      expect(await start()).toContain("OIDC client secret file has invalid length");
      expect(seams.discover).not.toHaveBeenCalled();
    });
  });

  it.each([0o600, 0o640])("accepts the supported runtime read permissions %i", async (mode) => {
    await withSecret(async ({ file, start }) => {
      await writeFile(file, "s".repeat(4096) + "\r\n");
      await chmod(file, mode);
      expect(await start()).toBe("synthetic discovery boundary reached");
      expect(seams.discover).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({ clientSecret: "s".repeat(4096) })
      );
    });
  });

  it("refuses a world-readable secret before discovery", async () => {
    await withSecret(async ({ file, start }) => {
      await chmod(file, 0o644);
      expect(await start()).toContain("OIDC client secret must be a private regular file");
      expect(seams.discover).not.toHaveBeenCalled();
    });
  });
});
