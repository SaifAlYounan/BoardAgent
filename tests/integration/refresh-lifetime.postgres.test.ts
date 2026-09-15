import { createHash } from "node:crypto";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  createPgOidcProviderPersistence,
  PgTokenContextStore
} from "../../artifacts/server/src/index.js";
import {
  rotateRefreshTokenInTransaction,
  withIdentityTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const sessionId = testId(184_001);
const familyId = testId(184_002);
const priorId = testId(184_003);
const freshJti = testId(184_020);
const sessionCookie = Buffer.alloc(32, 73).toString("base64url");
const presentedHash = "51".repeat(32);

async function seed(pool: Pool) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["onboarding:read"]
  });
  await pool.query(
    `insert into oauth_client_grants(client_id,grant_type,scope)
    values ($1,'refresh_token','onboarding:read')`,
    [actor.clientId]
  );
  await pool.query(
    `insert into auth_sessions(
    id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
    created_at,expires_at,last_authenticated_at
  ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
    transaction_timestamp()-interval '9 hours',transaction_timestamp()-interval '1 hour',
    transaction_timestamp()-interval '9 hours')`,
    [
      sessionId,
      actor.organizationId,
      createHash("sha256").update(sessionCookie).digest(),
      actor.memberId,
      actor.clientId
    ]
  );
  await pool.query(
    `insert into refresh_families(
    id,organization_id,member_id,client_id,resource_uri,generation,state,idle_expires_at,absolute_expires_at
  ) values ($1,$2,$3,$4,'https://boardagent.test/mcp',1,'active',
    transaction_timestamp()+interval '30 days',transaction_timestamp()+interval '90 days')`,
    [familyId, actor.organizationId, actor.memberId, actor.clientId]
  );
  await pool.query(
    `insert into refresh_tokens(id,family_id,generation,token_sha256)
    values ($1,$2,1,$3)`,
    [testId(184_004), familyId, Buffer.from(presentedHash, "hex")]
  );
  await pool.query(
    `insert into access_token_records(
    id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,
    refresh_family_id,signing_key_id,issued_at,expires_at
  ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',array['onboarding:read'],$6,$7,$8,
    transaction_timestamp()-interval '75 minutes',transaction_timestamp()-interval '60 minutes')`,
    [
      priorId,
      actor.organizationId,
      testId(184_005),
      actor.memberId,
      actor.clientId,
      sessionId,
      familyId,
      testId(8)
    ]
  );
  const refresh = () =>
    withIdentityTransaction(
      pool,
      { organizationId: actor.organizationId },
      (client) =>
        rotateRefreshTokenInTransaction(client, {
          organizationId: actor.organizationId,
          clientId: actor.clientId,
          resourceUri: "https://boardagent.test/mcp",
          presentedRefreshTokenSha256: presentedHash,
          replacementRefreshTokenId: testId(184_021),
          replacementRefreshTokenSha256: "61".repeat(32),
          accessTokenRecordId: testId(184_022),
          accessTokenJti: freshJti,
          signingKeyId: testId(8),
          auditEventId: testId(184_023)
        }),
      { assumeRole: "boardagent_server" }
    );
  return {
    actor,
    refresh,
    store: new PgTokenContextStore(pool, { assumeRole: "boardagent_server" })
  };
}

describe("refresh authority independent from the browser session lifetime", () => {
  it("caps a newly rotated idle lease at the original absolute boundary", async () => {
    await withMigratedDatabase("refresh_absolute_cap", async (pool) => {
      const { refresh } = await seed(pool);
      await pool.query(
        "update refresh_families set absolute_expires_at=transaction_timestamp()+interval '1 hour' where id=$1",
        [familyId]
      );
      expect(await refresh()).toMatchObject({ refreshed: true });
      expect(
        (
          await pool.query<{ clamped: boolean; within_hour: boolean }>(
            `select idle_expires_at=absolute_expires_at as clamped,
          absolute_expires_at<=transaction_timestamp()+interval '1 hour' as within_hour
         from refresh_families where id=$1`,
            [familyId]
          )
        ).rows
      ).toEqual([{ clamped: true, within_hour: true }]);
    });
  });
  it.each(["member", "client", "resource"])(
    "refuses a prior access record bound to a different %s",
    async (subject) => {
      await withMigratedDatabase("refresh_prior_binding", async (pool) => {
        const { refresh, actor } = await seed(pool);
        if (subject === "resource")
          await pool.query(
            "update access_token_records set resource_uri='https://other.test/mcp' where id=$1",
            [priorId]
          );
        else if (subject === "member") {
          await pool.query(
            `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
          values ($1,$2,'human','Other','Other','active')`,
            [testId(184_030), actor.organizationId]
          );
          await pool.query(
            "update access_token_records set member_id=$2,session_id=null where id=$1",
            [priorId, testId(184_030)]
          );
        } else {
          await pool.query(
            `insert into oauth_clients(id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,state)
          select $1,organization_id,protocol_id_kind,'other-client','{}',metadata_sha256,'active'
          from oauth_clients where id=$2`,
            [testId(184_031), actor.clientId]
          );
          await pool.query(
            "update access_token_records set client_id=$2,session_id=null where id=$1",
            [priorId, testId(184_031)]
          );
        }
        await expect(refresh()).rejects.toThrow(/unavailable/u);
      });
    }
  );
  it.each([false, true])(
    "reconnects after nine hours without renewing browser authority (maintenance=%s)",
    async (maintenance) => {
      await withMigratedDatabase("refresh_lifetime", async (pool) => {
        const { actor, refresh, store } = await seed(pool);
        if (maintenance)
          await withWorkerTransaction(
            pool,
            (client) =>
              client.query(
                "select boardagent_run_worker_maintenance('oauth_ephemera_expiry',$1,100)",
                [actor.organizationId]
              ),
            { assumeRole: "boardagent_worker" }
          );
        expect(await refresh()).toMatchObject({ refreshed: true, generation: "2" });
        expect(await store.findActiveByJti(freshJti)).toMatchObject({ memberId: actor.memberId });
        const persistence = createPgOidcProviderPersistence({
          pool,
          organizationId: actor.organizationId,
          issuer: "https://boardagent.test",
          resourceUri: "https://boardagent.test/mcp",
          stateEncryptionKey: Buffer.alloc(32, 9),
          assumeRole: "boardagent_server"
        });
        expect(await new persistence.adapter("Session").find(sessionCookie)).toBeUndefined();
        const row = await pool.query<{ expired: boolean; old_auth: boolean; state: string }>(
          `select expires_at<transaction_timestamp() as expired,
          last_authenticated_at<transaction_timestamp()-interval '8 hours' as old_auth,state
         from auth_sessions where id=$1`,
          [sessionId]
        );
        expect(row.rows).toEqual([
          { expired: true, old_auth: true, state: maintenance ? "expired" : "authenticated" }
        ]);
      });
    }
  );
  it.each(["idle", "absolute"])(
    "refuses the %s boundary even before worker cleanup",
    async (boundary) => {
      await withMigratedDatabase("refresh_boundary", async (pool) => {
        const { refresh } = await seed(pool);
        await pool.query(
          boundary === "idle"
            ? "update refresh_families set idle_expires_at=transaction_timestamp() where id=$1"
            : "update refresh_families set absolute_expires_at=transaction_timestamp() where id=$1",
          [familyId]
        );
        expect(await refresh()).toMatchObject({ refreshed: false, state: "expired" });
        expect(
          (
            await pool.query<{ count: number }>(
              "select count(*)::int as count from access_token_records where refresh_family_id=$1 and revoked_at is null",
              [familyId]
            )
          ).rows
        ).toEqual([{ count: 0 }]);
      });
    }
  );
  it.each(["session", "member", "client"])("refuses an explicitly revoked %s", async (subject) => {
    await withMigratedDatabase("refresh_revoked", async (pool) => {
      const { actor, refresh } = await seed(pool);
      if (subject === "session")
        await pool.query("update auth_sessions set state='revoked' where id=$1", [sessionId]);
      if (subject === "member")
        await pool.query(
          "update members set state='suspended',row_version=row_version+1 where id=$1",
          [actor.memberId]
        );
      if (subject === "client")
        await pool.query("update oauth_clients set state='suspended' where id=$1", [
          actor.clientId
        ]);
      await expect(refresh()).rejects.toThrow(/unavailable/u);
      expect(
        (
          await pool.query<{ generation: string }>(
            "select generation::text from refresh_families where id=$1",
            [familyId]
          )
        ).rows
      ).toEqual([{ generation: "1" }]);
    });
  });
  it.each(["family", "idle", "absolute", "session", "member", "client", "access", "key"])(
    "removes an already-issued bearer when %s authority ends",
    async (subject) => {
      await withMigratedDatabase("refresh_live_context", async (pool) => {
        const { actor, refresh, store } = await seed(pool);
        expect(await refresh()).toMatchObject({ refreshed: true });
        expect(await store.findActiveByJti(freshJti)).not.toBeNull();
        if (subject === "family")
          await pool.query(
            "update refresh_families set state='revoked',revoked_at=transaction_timestamp() where id=$1",
            [familyId]
          );
        if (subject === "idle")
          await pool.query(
            "update refresh_families set idle_expires_at=transaction_timestamp() where id=$1",
            [familyId]
          );
        if (subject === "absolute")
          await pool.query(
            "update refresh_families set absolute_expires_at=transaction_timestamp() where id=$1",
            [familyId]
          );
        if (subject === "session")
          await pool.query("update auth_sessions set state='revoked' where id=$1", [sessionId]);
        if (subject === "member")
          await pool.query(
            "update members set state='suspended',row_version=row_version+1 where id=$1",
            [actor.memberId]
          );
        if (subject === "client")
          await pool.query("update oauth_clients set state='suspended' where id=$1", [
            actor.clientId
          ]);
        if (subject === "access")
          await pool.query(
            "update access_token_records set revoked_at=transaction_timestamp() where jti=$1",
            [freshJti]
          );
        if (subject === "key")
          await pool.query(
            "update crypto_key_registry set compromised_at=transaction_timestamp() where id=$1",
            [testId(8)]
          );
        expect(await store.findActiveByJti(freshJti)).toBeNull();
      });
    }
  );
});
