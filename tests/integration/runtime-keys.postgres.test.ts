import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  migrate,
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_runtime_keys_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "runtime-key-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function registrations(offset = 0) {
  return [
    {
      keyId: testId(81_001 + offset),
      kid: `oauth-${String(offset)}key`,
      purpose: "oauth_signing",
      algorithm: "ES256",
      publicJwk: {
        alg: "ES256",
        crv: "P-256",
        kid: `oauth-${String(offset)}key`,
        kty: "EC",
        use: "sig",
        x: "A".repeat(43),
        y: "B".repeat(43)
      },
      nonsecretLocator: "file:/run/secrets/oauth-signing.jwk"
    },
    {
      keyId: testId(81_002 + offset),
      kid: `evidence-${String(offset)}key`,
      purpose: "evidence_signing",
      algorithm: "EdDSA",
      publicJwk: { crv: "Ed25519", kty: "OKP", x: "C".repeat(43) },
      nonsecretLocator: "file:/run/secrets/evidence-signing.pem"
    },
    {
      keyId: testId(81_003 + offset),
      kid: `browser-${String(offset)}key`,
      purpose: "browser_session",
      algorithm: "HMAC-SHA256",
      publicJwk: null,
      nonsecretLocator: "file:/run/secrets/browser-session.key"
    },
    {
      keyId: testId(81_004 + offset),
      kid: `data-${String(offset)}key`,
      purpose: "data_kek",
      algorithm: "A256GCM",
      publicJwk: null,
      nonsecretLocator: "file:/run/secrets/data-kek.key"
    }
  ] as const;
}

describe("runtime key registration authority", () => {
  it("registers the four external key identities exactly once and refuses silent replacement", async () => {
    await withDatabase(async (pool) => {
      const operator = new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator",
        newId: (() => {
          let value = 82_000;
          return () => testId(value++);
        })(),
        entropy: () => Buffer.alloc(32, 0x42)
      });
      const initialized = await operator.initialize({
        organizationLegalName: "Runtime Key Test Ltd",
        organizationDisplayName: "Runtime Key Test",
        organizationSlug: "runtime-key-test",
        timezone: "UTC",
        canonicalResourceUri: "https://boardagent.test/mcp",
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
      if (initialized.status !== "created") throw new Error("test bootstrap failed");

      const first = await withBootstrapTransaction(
        pool,
        (client) =>
          registerRuntimeKeysInTransaction(client, initialized.organizationId, registrations()),
        { assumeRole: "boardagent_migrator" }
      );
      expect(first).toHaveLength(4);
      expect(first.every(({ replayed }) => !replayed)).toBe(true);

      const replay = await withBootstrapTransaction(
        pool,
        (client) =>
          registerRuntimeKeysInTransaction(client, initialized.organizationId, registrations()),
        { assumeRole: "boardagent_migrator" }
      );
      expect(replay.every(({ replayed }) => replayed)).toBe(true);
      expect(
        await pool.query(
          "select purpose,algorithm,public_jwk ? 'd' as has_private from crypto_key_registry order by purpose"
        )
      ).toMatchObject({
        rows: [
          { purpose: "browser_session", algorithm: "HMAC-SHA256", has_private: null },
          { purpose: "data_kek", algorithm: "A256GCM", has_private: null },
          { purpose: "evidence_signing", algorithm: "EdDSA", has_private: false },
          { purpose: "oauth_signing", algorithm: "ES256", has_private: false }
        ]
      });

      await expect(
        withBootstrapTransaction(
          pool,
          (client) =>
            registerRuntimeKeysInTransaction(
              client,
              initialized.organizationId,
              registrations(100)
            ),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23505" });
    });
  });
});
