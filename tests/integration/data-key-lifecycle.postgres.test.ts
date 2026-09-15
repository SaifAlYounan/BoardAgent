import { describe, expect, it } from "vitest";
import * as db from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("data encryption key lifecycle", () => {
  it("retires a data key with its immutable operation while retaining its identity", async () => {
    await withUnseededWorker("data-key-retire", async ({ pool, organizationId }) => {
      const target = (
        await pool.query(
          "select instance_id,(select id from crypto_key_registry where purpose='data_kek') as key_id from system_instance"
        )
      ).rows[0];
      const input = await db.withBootstrapTransaction(
        pool,
        (c) =>
          db.prepareKeyLifecycleInTransaction(c, {
            instanceId: target.instance_id,
            organizationId,
            keyId: target.key_id,
            operationId: newWorkerTestId(),
            operation: "retire",
            replacement: null,
            declaredCompromisedAt: null,
            retainedMaterialSha256: "a".repeat(64),
            operatorReference: "Synthetic operator",
            reason: "Data-key database retirement test"
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const receipt = await db.withBootstrapTransaction(
        pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(receipt.replayed).toBe(false);
      expect(
        (
          await pool.query("select retired_at from crypto_key_registry where id=$1", [
            target.key_id
          ])
        ).rows[0].retired_at
      ).not.toBeNull();
    });
  });
});

// Synthetic actors and actual TOTP enrollment; no human acceptance is implied.
async function factors(fixture: Parameters<Parameters<typeof withUnseededWorker>[1]>[0]) {
  const { pool, organizationId, config } = fixture;
  const { loadBoardAgentKeyMaterial, PgTotpService, PgRateLimiter, generateTotpCodeFromBase32 } =
    await import("../../artifacts/server/src/index.js");
  const keys = await loadBoardAgentKeyMaterial(config);
  const keyId = (await pool.query("select id from crypto_key_registry where purpose='data_kek'"))
    .rows[0].id as string;
  const memberId = newWorkerTestId(),
    pendingMemberId = newWorkerTestId(),
    unrelatedMemberId = newWorkerTestId();
  for (const id of [memberId, pendingMemberId, unrelatedMemberId])
    await pool.query(
      "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Synthetic factor fixture','Fixture','active')",
      [id, organizationId]
    );
  await pool.query(
    "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'secretariat','Synthetic factor test')",
    [newWorkerTestId(), organizationId, memberId]
  );
  const policy = { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 };
  const service = (activeKeyId: string, ring: ReadonlyMap<string, Uint8Array>) =>
    new PgTotpService(pool, {
      issuer: "Synthetic lifecycle",
      activeKeyId,
      keys: ring,
      rateLimiter: new PgRateLimiter(pool, {
        hmacKey: keys.browserSessionKey,
        assumeRole: "boardagent_server"
      }),
      rateLimits: { ip: policy, client: policy, member: policy, token: policy },
      maxFailedAttempts: 5,
      lockoutSeconds: 300,
      assumeRole: "boardagent_server"
    });
  const original = service(keyId, new Map([[keyId, keys.dataEncryptionKey]]));
  const active = await original.beginEnrollment({
    organizationId,
    memberId,
    authorizedByMemberId: memberId
  });
  const now = Number(
    (await pool.query("select floor(extract(epoch from clock_timestamp())) as now")).rows[0].now
  );
  await original.completeEnrollment({
    organizationId,
    credentialId: active.credentialId,
    authorizedByMemberId: memberId,
    code: generateTotpCodeFromBase32(active.secretBase32, now)
  });
  const pending = await original.beginEnrollment({
    organizationId,
    memberId: pendingMemberId,
    authorizedByMemberId: memberId
  });
  const sessions: string[] = [];
  for (const id of [memberId, pendingMemberId, unrelatedMemberId]) {
    const sessionId = newWorkerTestId();
    sessions.push(sessionId);
    await pool.query(
      "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,state,exact_origin,expires_at) values($1,$2,sha256(convert_to(($1::uuid)::text,'UTF8')),$3,'authenticated','https://checkpoint.boardagent.test',transaction_timestamp()+interval '1 hour')",
      [sessionId, organizationId, id]
    );
  }
  return {
    keys,
    keyId,
    memberId,
    pendingMemberId,
    unrelatedMemberId,
    active,
    pending,
    sessions,
    now,
    service
  };
}

async function prepared(
  fixture: Parameters<Parameters<typeof withUnseededWorker>[1]>[0],
  keyId: string,
  operation: "retire" | "mark_compromised" | "replace",
  replacement: Parameters<typeof db.prepareKeyLifecycleInTransaction>[1]["replacement"] = null
) {
  const target = (await fixture.pool.query("select instance_id from system_instance")).rows[0];
  const key = (
    await fixture.pool.query(
      "select to_char(activated_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as activated from crypto_key_registry where id=$1",
      [keyId]
    )
  ).rows[0];
  return db.withBootstrapTransaction(
    fixture.pool,
    (c) =>
      db.prepareKeyLifecycleInTransaction(c, {
        instanceId: target.instance_id,
        organizationId: fixture.organizationId,
        keyId,
        operationId: newWorkerTestId(),
        operation,
        replacement,
        declaredCompromisedAt: operation === "mark_compromised" ? key.activated : null,
        retainedMaterialSha256: "a".repeat(64),
        operatorReference: "Synthetic operator",
        reason: "Data dependent effects regression"
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
}

describe("data key credential effects", () => {
  it("retires with active TOTP unchanged, cancels pending enrollment and preserves current sessions", async () => {
    await withUnseededWorker("data-key-totp-retire", async (fixture) => {
      const f = await factors(fixture);
      const before = (
        await fixture.pool.query("select * from totp_credentials where id=$1", [
          f.active.credentialId
        ])
      ).rows[0];
      const input = await prepared(fixture, f.keyId, "retire");
      const receipt = await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(receipt.details.effects).toMatchObject({ affectedTotp: "1", revokedSessions: "0" });
      expect(
        (
          await fixture.pool.query("select * from totp_credentials where id=$1", [
            f.active.credentialId
          ])
        ).rows[0]
      ).toEqual(before);
      expect(
        (
          await fixture.pool.query("select state from totp_credentials where id=$1", [
            f.pending.credentialId
          ])
        ).rows[0].state
      ).toBe("disabled");
      expect(
        (
          await fixture.pool.query("select state from auth_sessions where id=any($1::uuid[])", [
            f.sessions
          ])
        ).rows.map((x) => x.state)
      ).toEqual(["authenticated", "authenticated", "authenticated"]);
    });
  });
  it("contains a compromised TOTP key, preserving unrelated sessions and exact retry history", async () => {
    await withUnseededWorker("data-key-totp-compromise", async (fixture) => {
      const f = await factors(fixture);
      const before = (
        await fixture.pool.query(
          "select id,key_id,encrypted_secret,last_accepted_step,activated_at from totp_credentials order by id"
        )
      ).rows;
      const input = await prepared(fixture, f.keyId, "mark_compromised");
      const receipt = await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(receipt.details.effects).toMatchObject({ affectedTotp: "2", revokedSessions: "2" });
      expect(
        (
          await fixture.pool.query(
            "select id,key_id,encrypted_secret,last_accepted_step,activated_at from totp_credentials order by id"
          )
        ).rows
      ).toEqual(before);
      expect(
        (
          await fixture.pool.query(
            "select state,failed_attempts,locked_until from totp_credentials"
          )
        ).rows
      ).toEqual([
        { state: "compromised", failed_attempts: 0, locked_until: null },
        { state: "compromised", failed_attempts: 0, locked_until: null }
      ]);
      for (const id of f.sessions.slice(0, 2))
        expect(
          (await fixture.pool.query("select state from auth_sessions where id=$1", [id])).rows[0]
            .state
        ).toBe("revoked");
      expect(
        (await fixture.pool.query("select state from auth_sessions where id=$1", [f.sessions[2]]))
          .rows[0].state
      ).toBe("authenticated");
      const fresh = newWorkerTestId();
      await fixture.pool.query(
        "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,state,exact_origin,expires_at) values($1,$2,sha256(convert_to(($1::uuid)::text,'UTF8')),$3,'authenticated','https://checkpoint.boardagent.test',transaction_timestamp()+interval '1 hour')",
        [fresh, fixture.organizationId, f.memberId]
      );
      const retry = await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(retry).toEqual({ ...receipt, replayed: true });
      expect(
        (await fixture.pool.query("select state from auth_sessions where id=$1", [fresh])).rows[0]
          .state
      ).toBe("authenticated");
    });
  });
});

async function replacementKey() {
  const { randomBytes, createHash } = await import("node:crypto");
  const { symmetricKeyId } = await import("../../artifacts/server/src/symmetric-key-id.js");
  const material = randomBytes(32),
    keyId = newWorkerTestId();
  return {
    material,
    replacement: {
      keyId,
      kid: symmetricKeyId("data", material),
      algorithm: "A256GCM" as const,
      publicJwk: null,
      nonsecretLocator: `file:/synthetic/keys/data-${keyId}.key`,
      materialSha256: createHash("sha256").update(material).digest("hex")
    }
  };
}
async function hook(
  fixture: Parameters<Parameters<typeof withUnseededWorker>[1]>[0],
  f: Awaited<ReturnType<typeof factors>>
) {
  const { Aes256GcmWebhookSecurity } =
    await import("../../artifacts/server/src/webhook-security.js");
  const security = new Aes256GcmWebhookSecurity({
    activeKeyId: f.keyId,
    keys: new Map([[f.keyId, f.keys.dataEncryptionKey]]),
    resolve: async () => [{ address: "8.8.8.8", family: 4 }]
  });
  const context = {
    organizationId: fixture.organizationId,
    memberId: f.memberId,
    webhookId: newWorkerTestId()
  };
  const endpoint = await security.protectEndpoint({
      ...context,
      endpoint: `https://synthetic-notifications.example/board/${context.webhookId}`
    }),
    secret = security.createSecret(context);
  await fixture.pool.query(
    `insert into member_webhooks(id,organization_id,member_id,endpoint_ciphertext,endpoint_sha256,
    secret_ciphertext,secret_sha256,key_id,ssrf_validation_receipt_sha256,state,generation,event_classes,verified_at)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',1,array['security'],transaction_timestamp())`,
    [
      context.webhookId,
      context.organizationId,
      context.memberId,
      endpoint.endpointCiphertext,
      Buffer.from(endpoint.endpointSha256, "hex"),
      secret.secretCiphertext,
      Buffer.from(secret.secretSha256, "hex"),
      f.keyId,
      Buffer.from(endpoint.validationReceiptSha256, "hex")
    ]
  );
  return { context, endpoint, secret };
}

describe("data key notification continuity", () => {
  it("rewraps live notifications across two replacements, preserves TOTP and contains historical secret exposure", async () => {
    await withUnseededWorker("data-key-rewrap-history", async (fixture) => {
      const f = await factors(fixture),
        first = await hook(fixture, f),
        second = await hook(fixture, f);
      const { Aes256GcmWebhookSecurity } =
        await import("../../artifacts/server/src/webhook-security.js");
      const { generateTotpCodeFromBase32 } = await import("../../artifacts/server/src/index.js");
      const next = await replacementKey(),
        ring = new Map([
          [f.keyId, f.keys.dataEncryptionKey],
          [next.replacement.keyId, next.material]
        ]);
      const security = new Aes256GcmWebhookSecurity({
        activeKeyId: next.replacement.keyId,
        keys: ring
      });
      const input = await prepared(fixture, f.keyId, "replace", next.replacement);
      const receipt = await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input, security),
        { assumeRole: "boardagent_migrator" }
      );
      expect(receipt.details.effects).toMatchObject({
        rewrappedWebhooks: "2",
        disabledWebhooks: "0",
        affectedTotp: "1",
        revokedSessions: "0"
      });
      for (const original of [first, second]) {
        const row = (
          await fixture.pool.query("select * from member_webhooks where id=$1", [
            original.context.webhookId
          ])
        ).rows[0];
        expect(row).toMatchObject({
          key_id: next.replacement.keyId,
          state: "active",
          generation: "2"
        });
        expect(
          security.openEndpoint({
            ...original.context,
            keyId: row.key_id,
            endpointCiphertext: row.endpoint_ciphertext
          })
        ).toBe(original.endpoint.endpoint);
        expect(
          security.openSecret({
            ...original.context,
            keyId: row.key_id,
            secretCiphertext: row.secret_ciphertext
          })
        ).toBe(original.secret.secret);
        expect(row.secret_sha256).toEqual(Buffer.from(original.secret.secretSha256, "hex"));
      }
      expect(
        await f.service(next.replacement.keyId, ring).authenticate({
          organizationId: fixture.organizationId,
          sessionId: newWorkerTestId(),
          clientId: newWorkerTestId(),
          clientIpClass: "ipv4:127.0.0.0/24",
          fallbackHandle: f.active.fallbackHandle,
          code: generateTotpCodeFromBase32(f.active.secretBase32, f.now + 30)
        })
      ).toMatchObject({ memberId: f.memberId });
      expect(
        await f.service(next.replacement.keyId, ring).beginEnrollment({
          organizationId: fixture.organizationId,
          memberId: f.pendingMemberId,
          authorizedByMemberId: f.memberId
        })
      ).toMatchObject({ credentialId: expect.any(String) });
      // Synthetic owner fixture for an actual distinct external-secret rotation, through
      // the ordinary guarded row transition; this does not claim a human confirmation.
      const rotated = security.createSecret(second.context);
      await fixture.pool.query(
        "update member_webhooks set secret_ciphertext=$2,secret_sha256=$3,generation=generation+1,updated_at=transaction_timestamp() where id=$1",
        [
          second.context.webhookId,
          rotated.secretCiphertext,
          Buffer.from(rotated.secretSha256, "hex")
        ]
      );
      const latest = await replacementKey();
      ring.set(latest.replacement.keyId, latest.material);
      const current = new Aes256GcmWebhookSecurity({
        activeKeyId: latest.replacement.keyId,
        keys: ring
      });
      const secondInput = await prepared(
        fixture,
        next.replacement.keyId,
        "replace",
        latest.replacement
      );
      await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, secondInput, current),
        { assumeRole: "boardagent_migrator" }
      );
      const incident = await prepared(fixture, f.keyId, "mark_compromised");
      const incidentReceipt = await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, incident),
        { assumeRole: "boardagent_migrator" }
      );
      expect(incidentReceipt.details.effects).toMatchObject({
        disabledWebhooks: "1",
        affectedTotp: "1",
        revokedSessions: "2"
      });
      expect(
        (
          await fixture.pool.query("select state from member_webhooks where id=$1", [
            first.context.webhookId
          ])
        ).rows[0].state
      ).toBe("disabled");
      expect(
        (
          await fixture.pool.query("select state from member_webhooks where id=$1", [
            second.context.webhookId
          ])
        ).rows[0].state
      ).toBe("active");
      expect(
        (await fixture.pool.query("select count(*)::int as n from key_lifecycle_webhook_rewraps"))
          .rows[0].n
      ).toBe(4);
      const replay = await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(replay).toEqual({ ...receipt, replayed: true });
    });
  });
  it("rolls back key replacement and pending-factor effects when private rewrapping is unavailable", async () => {
    await withUnseededWorker("data-key-rewrap-no-port", async (fixture) => {
      const f = await factors(fixture),
        webhook = await hook(fixture, f),
        next = await replacementKey();
      const input = await prepared(fixture, f.keyId, "replace", next.replacement);
      await expect(
        db.withBootstrapTransaction(
          fixture.pool,
          (c) => db.applyKeyLifecycleInTransaction(c, input),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toThrow("webhook rewrapping is required");
      expect(
        (
          await fixture.pool.query("select retired_at from crypto_key_registry where id=$1", [
            f.keyId
          ])
        ).rows[0].retired_at
      ).toBeNull();
      expect(
        (
          await fixture.pool.query("select state from totp_credentials where id=$1", [
            f.pending.credentialId
          ])
        ).rows[0].state
      ).toBe("pending_verification");
      expect(
        (
          await fixture.pool.query("select key_id from member_webhooks where id=$1", [
            webhook.context.webhookId
          ])
        ).rows[0].key_id
      ).toBe(f.keyId);
      expect(
        (await fixture.pool.query("select count(*)::int as n from key_lifecycle_operations"))
          .rows[0].n
      ).toBe(0);
    });
  });
});

describe("retained protected contact records", () => {
  it.each(["replace", "retire", "mark_compromised"] as const)(
    "preserves contact evidence and applies the %s disposition",
    async (operation) => {
      await withUnseededWorker(`data-key-contact-${operation}`, async (fixture) => {
        const target = (
          await fixture.pool.query("select id from crypto_key_registry where purpose='data_kek'")
        ).rows[0].id;
        const memberId = (await fixture.pool.query("select id from members order by id limit 1"))
          .rows[0].id;
        const id = newWorkerTestId();
        // Opaque retained ciphertext fixture. No new contact encryption format is invented.
        const { randomBytes } = await import("node:crypto");
        await fixture.pool.query(
          "insert into member_contact_points(id,organization_id,member_id,kind,protected_value,key_id,verified_at,state) values($1,$2,$3,'operator_reference',$4,$5,transaction_timestamp(),'active')",
          [id, fixture.organizationId, memberId, randomBytes(64), target]
        );
        const before = (
          await fixture.pool.query("select * from member_contact_points where id=$1", [id])
        ).rows[0];
        const input = await prepared(
          fixture,
          target,
          operation,
          operation === "replace" ? (await replacementKey()).replacement : null
        );
        await db.withBootstrapTransaction(
          fixture.pool,
          (c) => db.applyKeyLifecycleInTransaction(c, input),
          { assumeRole: "boardagent_migrator" }
        );
        expect(
          (await fixture.pool.query("select * from member_contact_points where id=$1", [id]))
            .rows[0]
        ).toEqual({ ...before, state: operation === "mark_compromised" ? "revoked" : "active" });
        expect(
          (await fixture.pool.query("select count(*)::int as n from key_lifecycle_contact_effects"))
            .rows[0].n
        ).toBe(operation === "mark_compromised" ? 1 : 0);
      });
    }
  );
});

describe("data key operation authority and failure boundaries", () => {
  it.each(["missing-completion", "unrelated-session", "changed-session-after-receipt"] as const)(
    "rolls back the complete incident after %s",
    async (fault) => {
      await withUnseededWorker(`data-key-rollback-${fault}`, async (fixture) => {
        const f = await factors(fixture),
          webhook = await hook(fixture, f),
          input = await prepared(fixture, f.keyId, "mark_compromised");
        const beforeTotp = (await fixture.pool.query("select * from totp_credentials order by id"))
          .rows;
        const beforeHook = (
          await fixture.pool.query("select * from member_webhooks where id=$1", [
            webhook.context.webhookId
          ])
        ).rows[0];
        let reached = false;
        const { canonicalJson } = await import("../../lib/contracts/src/index.js");
        const { observedAt: _observedAt, ...dependencies } =
          input.request.expectedInventory.keyDependencies;
        await expect(
          db.withBootstrapTransaction(
            fixture.pool,
            async (c) => {
              if (fault === "changed-session-after-receipt") {
                await db.applyKeyLifecycleInTransaction(c, input);
                reached = true;
                // Deliberate owner fault after an authentic receipt. This tests the deferred
                // full-row integrity check, not resistance to a PostgreSQL superuser.
                await c.query("reset role");
                await c.query(
                  "update auth_sessions set exact_origin='https://changed.test' where id=$1",
                  [f.sessions[0]]
                );
                await c.query("set local role boardagent_migrator");
              } else {
                await c.query("select * from boardagent_begin_key_lifecycle($1,$2,$3)", [
                  Buffer.from(canonicalJson(input.request)),
                  Buffer.from(input.requestSha256, "hex"),
                  Buffer.from(
                    canonicalJson({
                      ...input.request.expectedInventory,
                      keyDependencies: dependencies
                    })
                  )
                ]);
                expect(
                  (
                    await c.query("select state from member_webhooks where id=$1", [
                      webhook.context.webhookId
                    ])
                  ).rows[0].state
                ).toBe("disabled");
                expect(
                  (
                    await c.query("select state from totp_credentials where id=$1", [
                      f.active.credentialId
                    ])
                  ).rows[0].state
                ).toBe("compromised");
                reached = true;
                if (fault === "unrelated-session")
                  await c.query(
                    "insert into key_lifecycle_browser_effects(operation_id,target_type,target_id,session_id) values($1,'session',$2,$2)",
                    [input.request.operationId, f.sessions[2]]
                  );
              }
            },
            { assumeRole: "boardagent_migrator" }
          )
        ).rejects.toMatchObject({ code: "23514" });
        expect(reached).toBe(true);
        expect(
          (await fixture.pool.query("select * from totp_credentials order by id")).rows
        ).toEqual(beforeTotp);
        expect(
          (
            await fixture.pool.query("select * from member_webhooks where id=$1", [
              webhook.context.webhookId
            ])
          ).rows[0]
        ).toEqual(beforeHook);
        expect(
          (
            await fixture.pool.query("select state from auth_sessions where id=any($1::uuid[])", [
              f.sessions
            ])
          ).rows.map((x) => x.state)
        ).toEqual(["authenticated", "authenticated", "authenticated"]);
        expect(
          (await fixture.pool.query("select count(*)::int as n from key_lifecycle_operations"))
            .rows[0].n
        ).toBe(0);
        const receipt = await db.withBootstrapTransaction(
          fixture.pool,
          (c) => db.applyKeyLifecycleInTransaction(c, input),
          { assumeRole: "boardagent_migrator" }
        );
        expect(receipt.details.effects).toMatchObject({
          disabledWebhooks: "1",
          affectedTotp: "2",
          revokedSessions: "2"
        });
      });
    }
  );
  it("refuses runtime and backup roles that claim operator scope", async () => {
    await withUnseededWorker("data-key-runtime-boundary", async (fixture) => {
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"])
        for (const query of [
          "select * from boardagent_read_key_webhook_rewrap_batch($1)",
          "select boardagent_apply_key_webhook_rewrap($1,$1,decode(repeat('aa',65),'hex'),decode(repeat('bb',65),'hex'))",
          "insert into key_lifecycle_totp_effects(operation_id,credential_id) values($1,$1)",
          "insert into key_lifecycle_contact_effects(operation_id,contact_id) values($1,$1)",
          "insert into key_lifecycle_webhook_disables(operation_id,webhook_id) values($1,$1)"
        ]) {
          const c = await fixture.pool.connect();
          try {
            await c.query("begin isolation level serializable");
            await c.query(`set local role ${role}`);
            await c.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
            await expect(c.query(query, [newWorkerTestId()])).rejects.toMatchObject({
              code: "42501"
            });
          } finally {
            await c.query("rollback");
            c.release();
          }
        }
    });
  });
  it("refuses altered encrypted material and rolls back partial replacement", async () => {
    await withUnseededWorker("data-key-authenticated-rewrap-failure", async (fixture) => {
      const f = await factors(fixture),
        webhook = await hook(fixture, f),
        next = await replacementKey();
      const input = await prepared(fixture, f.keyId, "replace", next.replacement);
      const { Aes256GcmWebhookSecurity } =
        await import("../../artifacts/server/src/webhook-security.js");
      const security = new Aes256GcmWebhookSecurity({
        activeKeyId: next.replacement.keyId,
        keys: new Map([
          [f.keyId, f.keys.dataEncryptionKey],
          [next.replacement.keyId, next.material]
        ])
      });
      let reached = false;
      await expect(
        db.withBootstrapTransaction(
          fixture.pool,
          (c) =>
            db.applyKeyLifecycleInTransaction(c, input, {
              rewrapStoredMaterial(material) {
                reached = true;
                const damaged = Buffer.from(material.secretCiphertext);
                damaged[damaged.length - 1]! ^= 1;
                return security.rewrapStoredMaterial({ ...material, secretCiphertext: damaged });
              }
            }),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toThrow("webhook ciphertext authentication failed");
      expect(reached).toBe(true);
      expect(
        (
          await fixture.pool.query("select key_id from member_webhooks where id=$1", [
            webhook.context.webhookId
          ])
        ).rows[0].key_id
      ).toBe(f.keyId);
      expect(
        (
          await fixture.pool.query("select retired_at from crypto_key_registry where id=$1", [
            f.keyId
          ])
        ).rows[0].retired_at
      ).toBeNull();
      expect(
        (await fixture.pool.query("select count(*)::int as n from key_lifecycle_webhook_rewraps"))
          .rows[0].n
      ).toBe(0);
      expect(
        (
          await fixture.pool.query("select state from totp_credentials where id=$1", [
            f.pending.credentialId
          ])
        ).rows[0].state
      ).toBe("pending_verification");
      await db.withBootstrapTransaction(
        fixture.pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input, security),
        { assumeRole: "boardagent_migrator" }
      );
    });
  });
});
