import { generateKeyPairSync, randomBytes } from "node:crypto";
import { request } from "node:http";

import { describe, expect, it } from "vitest";

import {
  loadBoardAgentKeyMaterial,
  loadBoardAgentRuntimeBinding,
  startBoardAgentServer,
  startBoardAgentWorker,
  runtimeKeyRegistrations
} from "../../artifacts/server/src/index.js";
import { OAUTH_VERIFICATION_CACHE_MILLISECONDS } from "../../artifacts/server/src/oauth-public-keys.js";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  registerBackupKeyInTransaction,
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { uuidV7 } from "../../lib/domain/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const ORIGIN = "https://boardagent.runtime.test";

async function proxyRequest(
  port: number,
  path: string,
  options: { readonly method?: string; readonly body?: string } = {}
): Promise<{ readonly status: number; readonly body: string }> {
  return new Promise((resolve, reject) => {
    const outbound = request(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: options.method ?? "GET",
        headers: {
          host: new URL(ORIGIN).host,
          "x-forwarded-for": "198.51.100.17",
          "x-forwarded-proto": "https",
          ...(options.body === undefined
            ? {}
            : {
                "content-type": "application/json",
                "content-length": String(Buffer.byteLength(options.body))
              })
        }
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.once("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8")
          })
        );
      }
    );
    outbound.once("error", reject);
    if (options.body !== undefined) outbound.write(options.body);
    outbound.end();
  });
}

describe("executable application runtime binding", () => {
  it("binds exactly the four runtime purposes after backup registration, and recovers server and worker idle connections", async () => {
    await withMigratedDatabase("application-runtime", async (pool) => {
      const initialized = await new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator"
      }).initialize({
        organizationLegalName: "Runtime Test Ltd",
        organizationDisplayName: "Runtime Test",
        organizationSlug: "runtime-test",
        timezone: "UTC",
        canonicalResourceUri: `${ORIGIN}/mcp`,
        boardSlug: "main",
        boardName: "Main",
        boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
        firstSecretaryLegalName: "Secretary",
        firstSecretaryDisplayName: "Secretary",
        votingWeight: 1,
        supportName: "Secretary",
        supportContactMethods: [{ kind: "operator_reference", value: "local" }],
        onboardingTermsText: "Review every canonical record.",
        invitationHandoffMethod: "in person"
      });
      if (initialized.status !== "created") throw new Error("runtime test bootstrap failed");

      const config = parseConfig({
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: "postgresql://unused",
        BOARDAGENT_ORGANIZATION_ID: initialized.organizationId,
        BOARDAGENT_PUBLIC_BASE_URL: ORIGIN,
        BOARDAGENT_AUTHORIZATION_MODE: "builtin",
        BOARDAGENT_BLOB_ROOT: "/tmp/boardagent-runtime-test",
        BOARDAGENT_DEV_MASTER_SECRET: "runtime-test-secret-material-is-long-enough"
      });
      const keys = await loadBoardAgentKeyMaterial(config);
      const registrations = runtimeKeyRegistrations(config, keys, () =>
        uuidV7(Date.now(), randomBytes(10))
      );
      await withBootstrapTransaction(
        pool,
        (client) =>
          registerRuntimeKeysInTransaction(client, initialized.organizationId, registrations),
        { assumeRole: "boardagent_migrator" }
      );
      // Recovery custody is a fifth registry purpose, never a fifth application key.
      await withBootstrapTransaction(
        pool,
        (client) =>
          registerBackupKeyInTransaction(
            client,
            initialized.organizationId,
            uuidV7(Date.now(), randomBytes(10)),
            "a".repeat(64)
          ),
        { assumeRole: "boardagent_migrator" }
      );

      const binding = await loadBoardAgentRuntimeBinding(pool, config, keys, {
        assumeRole: "boardagent_server"
      });
      expect(binding).toMatchObject({
        instanceId: initialized.instanceId,
        organizationId: initialized.organizationId,
        canonicalResourceUri: `${ORIGIN}/mcp`,
        keyIds: Object.fromEntries(registrations.map(({ purpose, keyId }) => [purpose, keyId]))
      });

      const runtimeErrors: string[] = [];
      const originalErrorListeners = pool.listenerCount("error");
      const loseIdleConnection = async () => {
        const control = await pool.connect();
        const idle = await pool.connect();
        const pid = Number((await idle.query("select pg_backend_pid() as pid")).rows[0].pid);
        const removed = new Promise<void>((resolve) => {
          const observe = (client: unknown) => {
            if (client === idle) {
              pool.removeListener("remove", observe);
              resolve();
            }
          };
          pool.on("remove", observe);
        });
        idle.release();
        try {
          expect(pool.idleCount).toBeGreaterThan(0);
          expect(
            (
              await control.query(
                "select pg_terminate_backend(pid) as terminated from pg_stat_activity where pid=$1 and datname=current_database()",
                [pid]
              )
            ).rows[0]
          ).toEqual({ terminated: true });
          await removed;
          await new Promise<void>((resolve) => setImmediate(resolve));
        } finally {
          control.release();
        }
      };
      const running = await startBoardAgentServer(config, {
        pool,
        port: 0,
        assumeRole: "boardagent_server",
        onError: (error) => runtimeErrors.push(error.message)
      });
      try {
        const live = await proxyRequest(running.port, "/health/live");
        expect(live.status, runtimeErrors.join("; ")).toBe(200);
        expect(JSON.parse(live.body)).toEqual({ status: "live" });
        const ready = await proxyRequest(running.port, "/health/ready");
        expect(ready.status).toBe(200);
        expect(JSON.parse(ready.body)).toEqual({ status: "ready" });
        const metadata = await proxyRequest(
          running.port,
          "/.well-known/oauth-protected-resource/mcp"
        );
        expect(metadata.status).toBe(200);
        expect(JSON.parse(metadata.body)).toMatchObject({
          resource: `${ORIGIN}/mcp`,
          authorization_servers: [ORIGIN]
        });
        // Historical registry fixture, not a supported rotation ceremony: JWKS
        // retains ordinary retired verification keys and refreshes compromise metadata
        // after its bounded publication interval. MCP authorization stays live.
        const retiredKeyId = uuidV7(Date.now(), randomBytes(10));
        const retiredPublicKey = {
          ...generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
            format: "jwk"
          }),
          kid: "oauth-retired-test",
          use: "sig",
          alg: "ES256"
        };
        await pool.query(
          `insert into crypto_key_registry(
          id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at,retired_at
        ) values ($1,$2,$3,'oauth_signing','ES256',$4,'fixture:retained-public-key',
          transaction_timestamp()-interval '1 minute',transaction_timestamp())`,
          [retiredKeyId, initialized.organizationId, retiredPublicKey.kid, retiredPublicKey]
        );
        const historicalJwks = await proxyRequest(running.port, "/jwks");
        expect(historicalJwks.status).toBe(200);
        expect(JSON.parse(historicalJwks.body)).toEqual({
          keys: expect.arrayContaining([keys.oauthPublicJwk, retiredPublicKey])
        });
        expect(JSON.parse(historicalJwks.body).keys).toHaveLength(2);
        expect(historicalJwks.body).not.toContain("nonsecret_locator");
        await pool.query(
          "update crypto_key_registry set compromised_at=transaction_timestamp() where id=$1",
          [retiredKeyId]
        );
        await new Promise<void>((resolve) =>
          setTimeout(resolve, OAUTH_VERIFICATION_CACHE_MILLISECONDS + 100)
        );
        const compromisedJwks = await proxyRequest(running.port, "/jwks");
        expect(compromisedJwks.status).toBe(200);
        expect(JSON.parse(compromisedJwks.body)).toEqual({ keys: [keys.oauthPublicJwk] });
        expect(
          (
            await pool.query("select count(*)::int as count from crypto_key_registry where id=$1", [
              retiredKeyId
            ])
          ).rows[0]?.count
        ).toBe(1);
        const oauthRegistration = registrations.find(({ purpose }) => purpose === "oauth_signing")!;
        await pool.query("update crypto_key_registry set public_jwk=$2 where id=$1", [
          oauthRegistration.keyId,
          { ...keys.oauthPublicJwk, d: "private-field-canary" }
        ]);
        await new Promise<void>((resolve) =>
          setTimeout(resolve, OAUTH_VERIFICATION_CACHE_MILLISECONDS + 100)
        );
        const invalidJwks = await proxyRequest(running.port, "/jwks");
        expect(invalidJwks.status).toBe(500);
        expect(invalidJwks.body).not.toContain("private-field-canary");
        await pool.query("update crypto_key_registry set public_jwk=$2 where id=$1", [
          oauthRegistration.keyId,
          keys.oauthPublicJwk
        ]);
        const unauthorized = await proxyRequest(running.port, "/mcp", {
          method: "POST",
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" })
        });
        expect(unauthorized.status).toBe(401);
        await loseIdleConnection();
        expect(runtimeErrors).toEqual(["database pool connection lost"]);
        expect((await proxyRequest(running.port, "/health/ready")).status).toBe(200);
      } finally {
        await running.close();
        await running.close();
      }
      expect(pool.listenerCount("error")).toBe(originalErrorListeners);
      const alerts: string[] = [];
      const worker = await startBoardAgentWorker(config, {
        pool,
        assumeRole: "boardagent_worker",
        onOperationalAlert: (alertClass) => {
          alerts.push(alertClass);
        }
      });
      try {
        await loseIdleConnection();
        expect(alerts).toEqual(["database_connection_lost"]);
        // The scheduler now discovers the bootstrap's first checkpoint; connection
        // recovery must permit that actual job to complete, not merely return idle.
        await expect(worker.worker.runOnce()).resolves.toMatchObject({
          status: "succeeded",
          jobType: "audit_checkpoint"
        });
        expect(
          (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]?.count
        ).toBe(1);
      } finally {
        await worker.close();
      }
      expect(pool.listenerCount("error")).toBe(originalErrorListeners);

      await expect(
        loadBoardAgentRuntimeBinding(
          pool,
          config,
          { ...keys, oauthKid: "wrong-loaded-key" },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("does not match loaded key material");
      await pool.query(
        "update crypto_key_registry set retired_at=clock_timestamp() where organization_id=$1 and purpose='evidence_signing'",
        [config.organizationId]
      );
      await expect(
        loadBoardAgentRuntimeBinding(pool, config, keys, { assumeRole: "boardagent_server" })
      ).rejects.toThrow("exactly four");
      await pool.query(
        "update crypto_key_registry set retired_at=null where organization_id=$1 and purpose='evidence_signing'",
        [config.organizationId]
      );

      await expect(
        loadBoardAgentRuntimeBinding(
          pool,
          { ...config, canonicalResourceUri: "https://other.runtime.test/mcp" },
          keys,
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("canonical resource");
    });
  });
});
