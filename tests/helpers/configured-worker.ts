import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Pool } from "pg";

import { loadBoardAgentKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { runtimeKeyRegistrations } from "../../artifacts/server/src/runtime-binding.js";
import { startBoardAgentWorker } from "../../artifacts/server/src/worker-process.js";
import { parseConfig } from "../../lib/config/src/index.js";
import { newWorkerTestId } from "./unseeded-worker.js";

/** Bind the existing synthetic actor fixture to actual runtime keys, then use production startup.
 * This is test fixture construction, not an operator key-rotation or human enrollment path.
 */
export async function withConfiguredFixtureWorker<T>(
  pool: Pool,
  organizationId: string,
  run: (worker: Awaited<ReturnType<typeof startBoardAgentWorker>>) => Promise<T>
): Promise<T> {
  const artifactRoot = await mkdtemp(path.join(tmpdir(), "boardagent-configured-fixture-worker-"));
  let worker: Awaited<ReturnType<typeof startBoardAgentWorker>> | undefined;
  try {
    const config = parseConfig({
      BOARDAGENT_ENV: "test",
      BOARDAGENT_DATABASE_URL: "postgresql://unused",
      BOARDAGENT_ORGANIZATION_ID: organizationId,
      BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
      BOARDAGENT_AUTHORIZATION_MODE: "builtin",
      BOARDAGENT_BLOB_ROOT: artifactRoot,
      BOARDAGENT_DEV_MASTER_SECRET: "configured-worker-synthetic-test-only-secret-material",
      BOARDAGENT_WEBHOOKS_ENABLED: "false"
    });
    const keys = await loadBoardAgentKeyMaterial(config);
    const existing = await pool.query("select id,purpose from crypto_key_registry order by id");
    if (
      existing.rows.length === 0 ||
      existing.rows.some(({ purpose }) => purpose !== "oauth_signing")
    ) {
      throw new Error("configured worker requires an untouched synthetic actor key fixture");
    }
    // Additional synthetic actors use their own placeholder OAuth keys. Retain them as
    // history while the worker binds one active fixture key per purpose.
    await pool.query(
      "update crypto_key_registry set retired_at=transaction_timestamp() where id<>$1",
      [existing.rows[0]!.id]
    );
    for (const registration of runtimeKeyRegistrations(config, keys, newWorkerTestId)) {
      if (registration.purpose === "oauth_signing") {
        await pool.query(
          "update crypto_key_registry set kid=$1,public_jwk=$2,nonsecret_locator=$3 where id=$4",
          [
            registration.kid,
            registration.publicJwk,
            registration.nonsecretLocator,
            existing.rows[0]!.id
          ]
        );
      } else {
        await pool.query(
          "insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at) values($1,$2,$3,$4,$5,$6,$7,transaction_timestamp())",
          [
            registration.keyId,
            organizationId,
            registration.kid,
            registration.purpose,
            registration.algorithm,
            registration.publicJwk,
            registration.nonsecretLocator
          ]
        );
      }
    }
    worker = await startBoardAgentWorker(config, {
      pool,
      assumeRole: "boardagent_worker",
      pollMilliseconds: 25,
      onOperationalAlert: () => undefined
    });
    return await run(worker);
  } finally {
    await worker?.close();
    await rm(artifactRoot, { recursive: true, force: true });
  }
}
