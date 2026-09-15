import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  loadBoardAgentKeyMaterial,
  runtimeKeyRegistrations,
  startBoardAgentServer,
  startBoardAgentWorker
} from "../../artifacts/server/src/index.js";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { uuidV7 } from "../../lib/domain/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const PURPOSES = ["oauth_signing", "evidence_signing", "browser_session", "data_kek"] as const;
const STATES = ["future", "retired", "compromised"] as const;

/** Close an unexpectedly successful process too, so failing-first runs leave no listener. */
async function startupResult(start: () => Promise<{ close(): Promise<void> }>): Promise<string> {
  let running;
  try {
    running = await start();
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    return error.message;
  }
  await running.close();
  return "started";
}

describe("runtime key validity before process startup", () => {
  it.each(PURPOSES.flatMap((purpose) => STATES.map((state) => ({ purpose, state }))))(
    "refuses both processes with a $state $purpose key and can start with valid keys",
    async ({ purpose, state }) => {
      const blobRoot = await mkdtemp(path.join(tmpdir(), "boardagent-key-validity-"));
      try {
        await withMigratedDatabase("runtime-key-validity", async (pool) => {
          const initialized = await new BoardAgentBootstrapOperator(pool, {
            assumeRole: "boardagent_migrator"
          }).initialize({
            organizationLegalName: "Key Validity Test Ltd",
            organizationDisplayName: "Key Validity Test",
            organizationSlug: "key-validity-test",
            timezone: "UTC",
            canonicalResourceUri: "https://boardagent.test/mcp",
            boardSlug: "main",
            boardName: "Main",
            boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
            firstSecretaryLegalName: "Synthetic Secretary",
            firstSecretaryDisplayName: "Synthetic Secretary",
            votingWeight: 1,
            supportName: "Synthetic Support",
            supportContactMethods: [{ kind: "operator_reference", value: "local" }],
            onboardingTermsText: "Review every canonical record.",
            invitationHandoffMethod: "in person"
          });
          if (initialized.status !== "created") throw new Error("fixture bootstrap failed");
          const config = parseConfig({
            BOARDAGENT_ENV: "test",
            BOARDAGENT_DATABASE_URL: "postgresql://unused",
            BOARDAGENT_ORGANIZATION_ID: initialized.organizationId,
            BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
            BOARDAGENT_AUTHORIZATION_MODE: "builtin",
            BOARDAGENT_BLOB_ROOT: blobRoot,
            BOARDAGENT_DEV_MASTER_SECRET: "key-validity-fixture-only-secret-material"
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
          const keyId = registrations.find((entry) => entry.purpose === purpose)!.keyId;
          const original = await pool.query(
            `select to_char(activated_at at time zone 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as activated_at
             from crypto_key_registry where id=$1`,
            [keyId]
          );
          // Owner-only corruption of disposable fixture state, not a supported rotation
          // or a claim that an application principal can change key authority.
          await pool.query(
            `update crypto_key_registry set
               activated_at=case when $2='future' then transaction_timestamp()+interval '1 day'
                 else activated_at end,
               retired_at=case when $2='retired' then transaction_timestamp() else null end,
               compromised_at=case when $2='compromised' then transaction_timestamp() else null end
             where id=$1`,
            [keyId, state]
          );
          const startServer = () =>
            startBoardAgentServer(config, {
              pool,
              assumeRole: "boardagent_server",
              host: "127.0.0.1",
              port: 0
            });
          const startWorker = () =>
            startBoardAgentWorker(config, { pool, assumeRole: "boardagent_worker" });
          const errorListeners = pool.listenerCount("error");
          const refused = {
            server: await startupResult(startServer),
            worker: await startupResult(startWorker)
          };
          expect(pool.listenerCount("error")).toBe(errorListeners);
          expect(refused).toEqual({
            server: "runtime requires exactly four active purpose-separated keys",
            worker: "runtime requires exactly four active purpose-separated keys"
          });
          await pool.query(
            `update crypto_key_registry set activated_at=$2::timestamptz,
               retired_at=null,compromised_at=null where id=$1`,
            [keyId, original.rows[0]!.activated_at]
          );
          expect(await startupResult(startServer)).toBe("started");
          expect(await startupResult(startWorker)).toBe("started");
          expect(pool.listenerCount("error")).toBe(errorListeners);
        });
      } finally {
        await rm(blobRoot, { recursive: true, force: true });
      }
    }
  );
});
