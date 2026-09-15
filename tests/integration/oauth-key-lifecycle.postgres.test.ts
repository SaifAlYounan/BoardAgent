import { generateKeyPairSync, randomBytes, createHash } from "node:crypto";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import * as db from "../../lib/db/src/index.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { newWorkerTestId } from "../helpers/unseeded-worker.js";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import { PgTokenContextStore } from "../../artifacts/server/src/index.js";

async function fixture(pool: Pool) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["onboarding:read"]
  });
  const generated = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
    format: "jwk"
  });
  const publicJwk = {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: generated.x!,
    y: generated.y!,
    kid: "test-oauth",
    use: "sig" as const,
    alg: "ES256" as const
  };
  await pool.query(
    "update crypto_key_registry set public_jwk=$1,nonsecret_locator='file:/run/boardagent/oauth.jwk' where id=$2",
    [publicJwk, testId(8)]
  );
  await pool.query(
    "insert into oauth_client_grants(client_id,grant_type,scope) values($1,'refresh_token','onboarding:read')",
    [actor.clientId]
  );
  return {
    ...actor,
    publicJwk,
    instanceId: (await pool.query("select instance_id from system_instance")).rows[0]
      .instance_id as string,
    store: new PgTokenContextStore(pool, { assumeRole: "boardagent_server" })
  };
}
async function family(
  pool: Pool,
  actor: Awaited<ReturnType<typeof fixture>>,
  signingKeyId: string
) {
  const sessionId = newWorkerTestId(),
    familyId = newWorkerTestId(),
    tokenId = newWorkerTestId(),
    accessId = newWorkerTestId(),
    jti = newWorkerTestId();
  const refreshHash = createHash("sha256").update(randomBytes(32)).digest("hex");
  await pool.query(
    "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '8 hours',transaction_timestamp())",
    [sessionId, actor.organizationId, randomBytes(32), actor.memberId, actor.clientId]
  );
  await pool.query(
    "insert into refresh_families(id,organization_id,member_id,client_id,resource_uri,generation,state,idle_expires_at,absolute_expires_at) values($1,$2,$3,$4,'https://boardagent.test/mcp',1,'active',transaction_timestamp()+interval '30 days',transaction_timestamp()+interval '90 days')",
    [familyId, actor.organizationId, actor.memberId, actor.clientId]
  );
  await pool.query(
    "insert into refresh_tokens(id,family_id,generation,token_sha256) values($1,$2,1,$3)",
    [tokenId, familyId, Buffer.from(refreshHash, "hex")]
  );
  await pool.query(
    "insert into access_token_records(id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,refresh_family_id,signing_key_id,expires_at) values($1,$2,$3,$4,$5,'https://boardagent.test/mcp',array['onboarding:read'],$6,$7,$8,transaction_timestamp()+interval '10 minutes')",
    [
      accessId,
      actor.organizationId,
      jti,
      actor.memberId,
      actor.clientId,
      sessionId,
      familyId,
      signingKeyId
    ]
  );
  return { sessionId, familyId, jti, refreshHash };
}
async function request(
  pool: Pool,
  actor: Awaited<ReturnType<typeof fixture>>,
  keyId: string,
  operation: "replace" | "retire" | "mark_compromised"
) {
  let replacement: db.KeyLifecycleRequest["replacement"] = null;
  if (operation === "replace") {
    const generated = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
      format: "jwk"
    });
    const nextId = newWorkerTestId(),
      kid = `oauth-${nextId}`;
    const publicJwk = {
      kty: "EC" as const,
      crv: "P-256" as const,
      x: generated.x!,
      y: generated.y!,
      kid,
      use: "sig" as const,
      alg: "ES256" as const
    };
    replacement = {
      keyId: nextId as db.KeyLifecycleRequest["keyId"],
      kid,
      algorithm: "ES256",
      publicJwk,
      materialSha256: canonicalSha256({
        kty: "EC",
        crv: "P-256",
        x: generated.x!,
        y: generated.y!
      }) as db.KeyLifecycleRequest["retainedMaterialSha256"],
      nonsecretLocator: "file:/run/boardagent/next-oauth.jwk"
    };
  }
  const declaredCompromisedAt =
    operation === "mark_compromised"
      ? ((
          await pool.query(
            `select to_char(activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as time from crypto_key_registry where id=$1`,
            [keyId]
          )
        ).rows[0].time as string)
      : null;
  return db.withBootstrapTransaction(
    pool,
    (c) =>
      db.prepareKeyLifecycleInTransaction(c, {
        instanceId: actor.instanceId,
        organizationId: actor.organizationId,
        keyId,
        operationId: newWorkerTestId(),
        operation,
        replacement,
        declaredCompromisedAt,
        retainedMaterialSha256: "a".repeat(64),
        operatorReference: "Synthetic key operator",
        reason: "Database OAuth lifecycle test"
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
}
const apply = (pool: Pool, input: Awaited<ReturnType<typeof request>>) =>
  db.withBootstrapTransaction(pool, (c) => db.applyKeyLifecycleInTransaction(c, input), {
    assumeRole: "boardagent_migrator"
  });
const refresh = (
  pool: Pool,
  actor: Awaited<ReturnType<typeof fixture>>,
  refreshHash: string,
  signingKeyId: string
) =>
  db.withIdentityTransaction(
    pool,
    { organizationId: actor.organizationId },
    (c) =>
      db.rotateRefreshTokenInTransaction(c, {
        organizationId: actor.organizationId,
        clientId: actor.clientId,
        resourceUri: "https://boardagent.test/mcp",
        presentedRefreshTokenSha256: refreshHash,
        replacementRefreshTokenId: newWorkerTestId(),
        replacementRefreshTokenSha256: createHash("sha256").update(randomBytes(32)).digest("hex"),
        accessTokenRecordId: newWorkerTestId(),
        accessTokenJti: newWorkerTestId(),
        signingKeyId,
        auditEventId: newWorkerTestId()
      }),
    { assumeRole: "boardagent_server" }
  );

describe("OAuth key lifecycle", () => {
  it("retires an OAuth signing key with the protected operation while preserving its public identity", async () => {
    await withMigratedDatabase("oauth-key-retire", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["onboarding:read"]
      });
      const generated = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
        format: "jwk"
      });
      const publicJwk = {
        kty: "EC",
        crv: "P-256",
        x: generated.x!,
        y: generated.y!,
        kid: "test-oauth",
        use: "sig",
        alg: "ES256"
      };
      await pool.query(
        "update crypto_key_registry set public_jwk=$1,nonsecret_locator='file:/run/boardagent/oauth.jwk' where id=$2",
        [publicJwk, testId(8)]
      );
      const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
        .instance_id;
      const input = await db.withBootstrapTransaction(
        pool,
        (c) =>
          db.prepareKeyLifecycleInTransaction(c, {
            instanceId,
            organizationId: actor.organizationId,
            keyId: testId(8),
            operationId: newWorkerTestId(),
            operation: "retire",
            replacement: null,
            declaredCompromisedAt: null,
            retainedMaterialSha256: "a".repeat(64),
            operatorReference: "Synthetic operator",
            reason: "Database OAuth retirement test"
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      const result = await db.withBootstrapTransaction(
        pool,
        (c) => db.applyKeyLifecycleInTransaction(c, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(result.details.purpose).toBe("oauth_signing");
      const key = (
        await pool.query("select public_jwk,retired_at from crypto_key_registry where id=$1", [
          testId(8)
        ])
      ).rows[0];
      expect(key.public_jwk).toEqual(publicJwk);
      expect(key.retired_at).not.toBeNull();
    });
  });

  it("keeps ordinary access valid and rotates a live refresh grant using the replacement signer", async () => {
    await withMigratedDatabase("oauth-key-replace-refresh", async (pool) => {
      const actor = await fixture(pool),
        old = await family(pool, actor, testId(8));
      expect(await actor.store.findActiveByJti(old.jti)).not.toBeNull();
      const input = await request(pool, actor, testId(8), "replace");
      const receipt = await apply(pool, input);
      expect(receipt.details.effects.revokedRefreshFamilies).toBe("0");
      expect(await actor.store.findActiveByJti(old.jti)).not.toBeNull();
      await expect(refresh(pool, actor, old.refreshHash, testId(8))).rejects.toThrow();
      const result = await refresh(pool, actor, old.refreshHash, input.request.replacement!.keyId);
      expect(result.refreshed).toBe(true);
      if (!result.refreshed) throw new Error("new signer refresh failed");
      expect(result.claims.signingKeyId).toBe(input.request.replacement!.keyId);
      expect(await actor.store.findActiveByJti(result.claims.jti)).not.toBeNull();
      expect(await apply(pool, input)).toEqual({ ...receipt, replayed: true });
    });
  });

  it("revokes grants touched by a compromised old signer while preserving unrelated new-signer grants", async () => {
    await withMigratedDatabase("oauth-key-compromise-grants", async (pool) => {
      const actor = await fixture(pool),
        affected = await family(pool, actor, testId(8));
      const replacement = await request(pool, actor, testId(8), "replace");
      await apply(pool, replacement);
      const newKeyId = replacement.request.replacement!.keyId;
      const carried = await refresh(pool, actor, affected.refreshHash, newKeyId);
      if (!carried.refreshed) throw new Error("setup refresh failed");
      const unrelated = await family(pool, actor, newKeyId);
      const input = await request(pool, actor, testId(8), "mark_compromised");
      const receipt = await apply(pool, input);
      expect(receipt.details.effects).toMatchObject({
        revokedRefreshFamilies: "1",
        revokedSessions: "0"
      });
      expect(await actor.store.findActiveByJti(affected.jti)).toBeNull();
      expect(await actor.store.findActiveByJti(carried.claims.jti)).toBeNull();
      expect(await actor.store.findActiveByJti(unrelated.jti)).not.toBeNull();
      expect((await refresh(pool, actor, affected.refreshHash, newKeyId)).refreshed).toBe(false);
      expect((await refresh(pool, actor, unrelated.refreshHash, newKeyId)).refreshed).toBe(true);
      expect(
        (
          await pool.query(
            "select family_id from key_lifecycle_affected_families where operation_id=$1",
            [input.request.operationId]
          )
        ).rows
      ).toEqual([{ family_id: affected.familyId }]);
      expect(
        (await pool.query("select state from auth_sessions where id=$1", [affected.sessionId]))
          .rows[0].state
      ).toBe("authenticated");
      expect(await apply(pool, input)).toEqual({ ...receipt, replayed: true });
    });
  });

  it("rolls back the key and revocations if a recorded family changes after the receipt", async () => {
    await withMigratedDatabase("oauth-key-family-atomicity", async (pool) => {
      const actor = await fixture(pool),
        affected = await family(pool, actor, testId(8));
      const input = await request(pool, actor, testId(8), "mark_compromised");
      let reachedReceipt = false;
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            await db.applyKeyLifecycleInTransaction(c, input);
            reachedReceipt = true;
            await c.query(
              "update refresh_families set revoked_at=revoked_at+interval '1 second' where id=$1",
              [affected.familyId]
            );
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(reachedReceipt).toBe(true);
      expect(
        (
          await pool.query("select compromised_at from crypto_key_registry where id=$1", [
            testId(8)
          ])
        ).rows[0].compromised_at
      ).toBeNull();
      expect(
        (await pool.query("select state from refresh_families where id=$1", [affected.familyId]))
          .rows[0].state
      ).toBe("active");
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_affected_families")).rows[0]
          .n
      ).toBe(0);
    });
  });

  it("refuses an unchanged EC key renamed as a replacement at the database entry point", async () => {
    await withMigratedDatabase("oauth-key-renamed-db", async (pool) => {
      const actor = await fixture(pool),
        input = await request(pool, actor, testId(8), "replace");
      const replacement = {
        ...input.request.replacement!,
        publicJwk: { ...actor.publicJwk, kid: input.request.replacement!.kid },
        materialSha256: input.request.expectedKey.publicMaterialSha256
      };
      const changed = { ...input.request, replacement };
      const { observedAt: _observedAt, ...deps } = input.request.expectedInventory.keyDependencies;
      await expect(
        db.withBootstrapTransaction(
          pool,
          (c) =>
            c.query("select * from boardagent_begin_key_lifecycle($1,$2,$3)", [
              Buffer.from(canonicalJson(changed)),
              Buffer.from(canonicalSha256(changed), "hex"),
              Buffer.from(
                canonicalJson({ ...input.request.expectedInventory, keyDependencies: deps })
              )
            ]),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "55000" });
    });
  });

  it("refuses attaching an unrelated family to a completed-in-transaction compromise operation", async () => {
    await withMigratedDatabase("oauth-key-unrelated-effect", async (pool) => {
      const actor = await fixture(pool),
        affected = await family(pool, actor, testId(8));
      const replacement = await request(pool, actor, testId(8), "replace");
      await apply(pool, replacement);
      const unrelated = await family(pool, actor, replacement.request.replacement!.keyId);
      const input = await request(pool, actor, testId(8), "mark_compromised");
      let reachedReceipt = false;
      await expect(
        db.withBootstrapTransaction(
          pool,
          async (c) => {
            await db.applyKeyLifecycleInTransaction(c, input);
            reachedReceipt = true;
            await c.query(
              "insert into key_lifecycle_affected_families(operation_id,family_id,before_sha256,after_sha256) values($1,$2,$3,$3)",
              [input.request.operationId, unrelated.familyId, Buffer.alloc(32)]
            );
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(reachedReceipt).toBe(true);
      expect(
        (
          await pool.query("select compromised_at from crypto_key_registry where id=$1", [
            testId(8)
          ])
        ).rows[0].compromised_at
      ).toBeNull();
      expect(
        (
          await pool.query(
            "select state from refresh_families where id=any($1::uuid[]) order by id",
            [[affected.familyId, unrelated.familyId]]
          )
        ).rows
      ).toEqual([{ state: "active" }, { state: "active" }]);
      expect(
        (await pool.query("select count(*)::int as n from key_lifecycle_affected_families")).rows[0]
          .n
      ).toBe(0);
    });
  });

  it("denies runtime writes and unaffiliated operator claims to the revocation ledger", async () => {
    await withMigratedDatabase("oauth-key-effect-authority", async (pool) => {
      const actor = await fixture(pool),
        affected = await family(pool, actor, testId(8));
      const sql =
        "insert into key_lifecycle_affected_families(operation_id,family_id,before_sha256,after_sha256) values($1,$2,$3,$3)";
      const args = [newWorkerTestId(), affected.familyId, Buffer.alloc(32)];
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
        const c = await pool.connect();
        try {
          await c.query("begin isolation level serializable");
          await c.query(`set local role ${role}`);
          await c.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(c.query(sql, args)).rejects.toMatchObject({ code: "42501" });
        } finally {
          await c.query("rollback");
          c.release();
        }
      }
      await expect(
        db.withBootstrapTransaction(pool, (c) => c.query(sql, args), {
          assumeRole: "boardagent_migrator"
        })
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (await pool.query("select state from refresh_families where id=$1", [affected.familyId]))
          .rows[0].state
      ).toBe("active");
    });
  });
});
