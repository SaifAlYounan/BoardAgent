import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseConfig } from "../../lib/config/src/index.js";
import {
  registerRuntimeKeysInTransaction,
  prepareKeyLifecycleInTransaction,
  applyKeyLifecycleInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import {
  loadBoardAgentKeyMaterial,
  loadBoardAgentRuntimeBinding,
  loadBoardAgentWorkerRuntimeBinding,
  runtimeKeyRegistrations,
  startBoardAgentServer,
  startBoardAgentWorker,
  PgTotpService,
  PgRateLimiter,
  generateTotpCodeFromBase32
} from "../../artifacts/server/src/index.js";
import { dataDecryptionKeyring } from "../../artifacts/server/src/retained-data-keys.js";
import { Aes256GcmWebhookSecurity } from "../../artifacts/server/src/webhook-security.js";
import { productionKeyFiles } from "../helpers/production-key-files.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { newWorkerTestId } from "../helpers/unseeded-worker.js";
import { testId } from "../helpers/authorized-actor.js";

async function withRuntime<T>(
  run: (fixture: Awaited<ReturnType<typeof setup>>) => Promise<T>
): Promise<T> {
  const directory = await mkdtemp(path.join(tmpdir(), "boardagent-retained-runtime-"));
  try {
    return await withMigratedDatabase("retained-data", async (pool) =>
      run(await setup(pool, directory))
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
async function setup(pool: import("pg").Pool, directory: string) {
  const initialized = await new BoardAgentBootstrapOperator(pool, {
    assumeRole: "boardagent_migrator"
  }).initialize({
    organizationLegalName: "Synthetic Key Retention Ltd",
    organizationDisplayName: "Synthetic Key Retention",
    organizationSlug: "key-retention",
    timezone: "UTC",
    canonicalResourceUri: "https://boardagent.test/mcp",
    boardSlug: "main",
    boardName: "Main",
    boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", synthetic: true },
    firstSecretaryLegalName: "Unenrolled setup fixture",
    firstSecretaryDisplayName: "Setup fixture",
    votingWeight: 1,
    supportName: "Synthetic operator",
    supportContactMethods: [{ kind: "operator_reference", value: "local-test" }],
    onboardingTermsText: "Synthetic tests only; no human enrollment performed.",
    invitationHandoffMethod: "not delivered"
  });
  if (initialized.status !== "created") throw new Error("fresh fixture required");
  const production = await productionKeyFiles(directory, initialized.organizationId);
  const config = parseConfig(production.environment),
    keys = await loadBoardAgentKeyMaterial(config);
  const registrations = runtimeKeyRegistrations(config, keys, newWorkerTestId);
  await withBootstrapTransaction(
    pool,
    (client) => registerRuntimeKeysInTransaction(client, config.organizationId, registrations),
    { assumeRole: "boardagent_migrator" }
  );
  const oldKeyId = registrations.find((entry) => entry.purpose === "data_kek")!.keyId;
  const rotateFixture = async () => {
    // Exercise the supported database replacement with real retained material.
    // This fixture does not assert human custody or operator handover acceptance.
    const keyFile = path.join(directory, "old-data.key"),
      manifestFile = path.join(directory, "retained.json");
    await writeFile(keyFile, keys.dataEncryptionKey, { mode: 0o600 });
    await writeFile(production.files.data, randomBytes(32), { mode: 0o600 });
    const manifest = {
      schemaVersion: "boardagent.retained-data-keys.v1",
      instanceId: initialized.instanceId,
      organizationId: initialized.organizationId,
      keys: [
        {
          keyId: oldKeyId,
          kid: keys.dataEncryptionKid,
          fingerprintSha256: createHash("sha256").update(keys.dataEncryptionKey).digest("hex"),
          keyFile
        }
      ]
    };
    await writeFile(manifestFile, JSON.stringify(manifest), { mode: 0o600 });
    const nextConfig = parseConfig({
      ...production.environment,
      BOARDAGENT_RETAINED_DATA_KEYS_FILE: manifestFile
    });
    const nextKeys = await loadBoardAgentKeyMaterial(nextConfig);
    const nextRegistrations = runtimeKeyRegistrations(nextConfig, nextKeys, newWorkerTestId).map(
      (entry) =>
        entry.purpose === "data_kek"
          ? entry
          : registrations.find((old) => old.purpose === entry.purpose)!
    );
    const replacement = nextRegistrations.find((entry) => entry.purpose === "data_kek")!;
    const request = await withBootstrapTransaction(
      pool,
      (client) =>
        prepareKeyLifecycleInTransaction(client, {
          instanceId: initialized.instanceId,
          organizationId: initialized.organizationId,
          keyId: oldKeyId,
          operationId: newWorkerTestId(),
          operation: "replace",
          declaredCompromisedAt: null,
          retainedMaterialSha256: createHash("sha256")
            .update(JSON.stringify(manifest))
            .digest("hex"),
          operatorReference: "Synthetic retained-key fixture",
          reason: "Verify runtime consumers across supported key replacement",
          replacement: {
            keyId: replacement.keyId,
            kid: replacement.kid,
            algorithm: "A256GCM",
            publicJwk: null,
            materialSha256: createHash("sha256").update(nextKeys.dataEncryptionKey).digest("hex"),
            nonsecretLocator: replacement.nonsecretLocator
          }
        }),
      { assumeRole: "boardagent_migrator", readOnly: true }
    );
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: replacement.keyId,
      keys: new Map([
        [oldKeyId, keys.dataEncryptionKey],
        [replacement.keyId, nextKeys.dataEncryptionKey]
      ])
    });
    await withBootstrapTransaction(
      pool,
      (client) => applyKeyLifecycleInTransaction(client, request, security),
      {
        assumeRole: "boardagent_migrator"
      }
    );
    const binding = await loadBoardAgentRuntimeBinding(pool, nextConfig, nextKeys, {
      assumeRole: "boardagent_server"
    });
    return { config: nextConfig, keys: nextKeys, binding, manifest, manifestFile, keyFile };
  };
  return { pool, directory, initialized, config, keys, registrations, oldKeyId, rotateFixture };
}

describe("retained data-key runtime registry and consumer binding", () => {
  it("starts both real processes with ordinary retired history, decrypts old webhook data and encrypts new material with the active key", async () => {
    await withRuntime(async ({ pool, keys, oldKeyId, initialized, rotateFixture }) => {
      const object = {
        organizationId: initialized.organizationId,
        memberId: initialized.firstMemberId,
        webhookId: testId(122_000)
      };
      const oldSecurity = new Aes256GcmWebhookSecurity({
        activeKeyId: oldKeyId,
        keys: new Map([[oldKeyId, keys.dataEncryptionKey]]),
        resolve: async () => [{ address: "8.8.8.8", family: 4 }]
      });
      const oldSecret = oldSecurity.createSecret(object),
        endpoint = await oldSecurity.protectEndpoint({
          ...object,
          endpoint: "https://synthetic-hook.example/notify"
        });
      const after = await rotateFixture();
      const ring = dataDecryptionKeyring(
        after.binding.keyIds.data_kek,
        after.keys.dataEncryptionKey,
        after.keys.retainedDataKeys
      );
      const current = new Aes256GcmWebhookSecurity({
        activeKeyId: after.binding.keyIds.data_kek,
        keys: ring
      });
      expect(current.openSecret({ ...object, ...oldSecret })).toBe(oldSecret.secret);
      expect(current.openEndpoint({ ...object, ...endpoint })).toBe(endpoint.endpoint);
      expect(current.createSecret(object).keyId).toBe(after.binding.keyIds.data_kek);
      expect(() =>
        current.openSecret({ ...object, ...oldSecret, memberId: testId(122_001) })
      ).toThrow();
      const missing = new Aes256GcmWebhookSecurity({
        activeKeyId: after.binding.keyIds.data_kek,
        keys: new Map([[after.binding.keyIds.data_kek, after.keys.dataEncryptionKey]])
      });
      expect(() => missing.openSecret({ ...object, ...oldSecret })).toThrow(
        "webhook ciphertext authentication failed"
      );
      const server = await startBoardAgentServer(after.config, {
        pool,
        assumeRole: "boardagent_server",
        host: "127.0.0.1",
        port: 0
      });
      try {
        const worker = await startBoardAgentWorker(after.config, {
          pool,
          assumeRole: "boardagent_worker"
        });
        await worker.close();
      } finally {
        await server.close();
      }
      expect(
        (
          await pool.query(
            "select count(*)::int as count from crypto_key_registry where purpose='data_kek'"
          )
        ).rows[0].count
      ).toBe(2);
    });
  });
  it.each([
    "wrong-instance",
    "unknown-id",
    "wrong-kid",
    "compromised",
    "future-retirement",
    "wrong-purpose"
  ])("refuses %s retained material through both database capability roles", async (kind) => {
    await withRuntime(async ({ pool, oldKeyId, rotateFixture }) => {
      const after = await rotateFixture();
      if (kind === "wrong-instance") after.manifest.instanceId = testId(122_004);
      if (kind === "unknown-id") after.manifest.keys[0]!.keyId = testId(122_004);
      if (kind === "wrong-kid")
        await pool.query(
          "update crypto_key_registry set kid='data-000000000000000000000000' where id=$1",
          [oldKeyId]
        );
      if (kind === "compromised")
        await pool.query("update crypto_key_registry set compromised_at=activated_at where id=$1", [
          oldKeyId
        ]);
      if (kind === "future-retirement")
        await pool.query(
          "update crypto_key_registry set retired_at=transaction_timestamp()+interval '1 day' where id=$1",
          [oldKeyId]
        );
      if (kind === "wrong-purpose")
        await pool.query(
          "update crypto_key_registry set purpose='browser_session',algorithm='HMAC-SHA256' where id=$1",
          [oldKeyId]
        );
      await writeFile(after.manifestFile, JSON.stringify(after.manifest), { mode: 0o600 });
      const supplied = await loadBoardAgentKeyMaterial(after.config);
      await expect(
        loadBoardAgentRuntimeBinding(pool, after.config, supplied, {
          assumeRole: "boardagent_server"
        })
      ).rejects.toThrow("retained data key");
      await expect(
        loadBoardAgentWorkerRuntimeBinding(pool, after.config, supplied, {
          assumeRole: "boardagent_worker"
        })
      ).rejects.toThrow("retained data key");
    });
  });
  it("retains active TOTP authentication across retirement but refuses old pending enrollment and compromised factors", async () => {
    await withRuntime(async ({ pool, initialized, keys, oldKeyId, rotateFixture }) => {
      const organizationId = initialized.organizationId,
        secretary = testId(123_000),
        pendingMember = testId(123_001),
        compromiseMember = testId(123_005);
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$3,'human','Synthetic credential fixture','Credential fixture','active'),($2,$3,'human','Synthetic pending fixture','Pending fixture','active'),($4,$3,'human','Synthetic compromise fixture','Compromise fixture','active')",
        [secretary, pendingMember, organizationId, compromiseMember]
      );
      await pool.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'secretariat','Synthetic key retention test')",
        [testId(123_002), organizationId, secretary]
      );
      const policy = { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 };
      const rateLimiter = new PgRateLimiter(pool, {
        hmacKey: randomBytes(32),
        assumeRole: "boardagent_server"
      });
      const service = (activeKeyId: string, ring: ReadonlyMap<string, Uint8Array>) =>
        new PgTotpService(pool, {
          issuer: "Synthetic retention",
          activeKeyId,
          keys: ring,
          rateLimiter,
          rateLimits: { ip: policy, client: policy, member: policy, token: policy },
          maxFailedAttempts: 5,
          lockoutSeconds: 300,
          assumeRole: "boardagent_server"
        });
      const original = service(oldKeyId, new Map([[oldKeyId, keys.dataEncryptionKey]]));
      const active = await original.beginEnrollment({
        organizationId,
        memberId: secretary,
        authorizedByMemberId: secretary
      });
      const now = Number(
        (await pool.query("select floor(extract(epoch from clock_timestamp())) as now")).rows[0].now
      );
      await original.completeEnrollment({
        organizationId,
        credentialId: active.credentialId,
        authorizedByMemberId: secretary,
        code: generateTotpCodeFromBase32(active.secretBase32, now)
      });
      const pending = await original.beginEnrollment({
        organizationId,
        memberId: pendingMember,
        authorizedByMemberId: secretary
      });
      const compromise = await original.beginEnrollment({
        organizationId,
        memberId: compromiseMember,
        authorizedByMemberId: secretary
      });
      await original.completeEnrollment({
        organizationId,
        credentialId: compromise.credentialId,
        authorizedByMemberId: secretary,
        code: generateTotpCodeFromBase32(compromise.secretBase32, now)
      });
      const before = (
        await pool.query("select id,key_id,encrypted_secret from totp_credentials order by id")
      ).rows;
      const after = await rotateFixture();
      const current = service(
        after.binding.keyIds.data_kek,
        dataDecryptionKeyring(
          after.binding.keyIds.data_kek,
          after.keys.dataEncryptionKey,
          after.keys.retainedDataKeys
        )
      );
      const login = {
        organizationId,
        sessionId: testId(123_003),
        clientId: testId(123_004),
        clientIpClass: "ipv4:127.0.0.0/24",
        fallbackHandle: active.fallbackHandle,
        code: generateTotpCodeFromBase32(active.secretBase32, now + 30)
      };
      expect(await current.authenticate(login)).toMatchObject({
        memberId: secretary,
        credentialId: active.credentialId
      });
      await expect(
        current.completeEnrollment({
          organizationId,
          credentialId: pending.credentialId,
          authorizedByMemberId: secretary,
          code: generateTotpCodeFromBase32(pending.secretBase32, now)
        })
      ).rejects.toMatchObject({ code: "invalid_enrollment" });
      expect(
        (
          await pool.query("select state,terminal_at from totp_credentials where id=$1", [
            pending.credentialId
          ])
        ).rows[0]
      ).toMatchObject({ state: "disabled", terminal_at: expect.any(Date) });
      expect(
        (
          await pool.query(
            "select credential_id from key_lifecycle_totp_effects where credential_id=$1",
            [pending.credentialId]
          )
        ).rows
      ).toHaveLength(1);
      expect(
        (await pool.query("select id,key_id,encrypted_secret from totp_credentials order by id"))
          .rows
      ).toEqual(before);
      await pool.query("update crypto_key_registry set compromised_at=activated_at where id=$1", [
        oldKeyId
      ]);
      await expect(
        current.authenticate({
          ...login,
          fallbackHandle: compromise.fallbackHandle,
          code: generateTotpCodeFromBase32(compromise.secretBase32, now + 30)
        })
      ).rejects.toMatchObject({ code: "invalid_totp" });
    });
  });
});
