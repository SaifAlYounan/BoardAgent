import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { PgWebAuthnStore } from "../../artifacts/server/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
import { testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_webauthn_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "webauthn-store-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

describe("PostgreSQL WebAuthn authority", () => {
  it("persists challenge hashes, refuses unbound recovery and atomically consumes authentication", async () => {
    await withDatabase(async (pool) => {
      const organizationId = testId(62_001);
      const memberId = testId(62_002);
      const clientId = testId(62_003);
      const sessionId = testId(62_004);
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
        [organizationId]
      );
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Member','Member','active')",
        [memberId, organizationId]
      );
      await pool.query(
        `insert into oauth_clients(
           id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,state
         ) values ($1,$2,'preregistered','webauthn-test-client','{}',$3,'active')`,
        [clientId, organizationId, testHash(62)]
      );
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, organizationId, testHash(63), memberId, clientId]
      );

      const store = new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" });
      const registrationChallengeId = testId(62_010);
      const registrationHash = "41".repeat(32);
      await store.saveChallenge({
        id: registrationChallengeId,
        organizationId,
        sessionId,
        memberId,
        purpose: "recovery",
        challengeSha256: registrationHash,
        rpId: "boardagent.test",
        exactOrigin: "https://boardagent.test",
        expiresAt: new Date(Date.now() + 300_000),
        consumedAt: null
      });
      await expect(
        store.findChallengeBySha256(organizationId, registrationHash)
      ).resolves.toMatchObject({
        id: registrationChallengeId,
        consumedAt: null
      });

      const credential = {
        id: testId(62_011),
        organizationId,
        memberId,
        credentialId: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
        publicKey: Uint8Array.from({ length: 64 }, () => 7),
        counter: 0,
        transports: ["internal"] as const,
        backupEligible: false,
        backupState: false,
        state: "active" as const
      };
      await expect(
        store.completeRegistration({
          organizationId,
          challengeId: registrationChallengeId,
          expectedChallengeSha256: registrationHash,
          credential
        })
      ).resolves.toBe(false);
      await expect(
        store.completeRegistration({
          organizationId,
          challengeId: registrationChallengeId,
          expectedChallengeSha256: registrationHash,
          credential: { ...credential, id: testId(62_012) }
        })
      ).resolves.toBe(false);
      await expect(store.listActiveCredentials(organizationId, memberId)).resolves.toHaveLength(0);
      // Authentication fixture only: successful issuance is exercised through the
      // complete two-party enrollment/recovery protocol tests, never this raw store.
      await pool.query(
        `insert into webauthn_credentials(id,organization_id,member_id,credential_id,public_key,
        signature_counter,transports,backup_eligible,backup_state,state)
        values($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
        [
          credential.id,
          organizationId,
          memberId,
          Buffer.from(credential.credentialId),
          Buffer.from(credential.publicKey)
        ]
      );
      await expect(store.listActiveCredentials(organizationId, memberId)).resolves.toHaveLength(1);
      await expect(
        store.findActiveCredentialByRawId(organizationId, credential.credentialId)
      ).resolves.toMatchObject({ id: credential.id, counter: 0 });

      const authenticationChallengeId = testId(62_013);
      const authenticationHash = "42".repeat(32);
      await store.saveChallenge({
        id: authenticationChallengeId,
        organizationId,
        sessionId,
        memberId,
        purpose: "authentication",
        challengeSha256: authenticationHash,
        rpId: "boardagent.test",
        exactOrigin: "https://boardagent.test",
        expiresAt: new Date(Date.now() + 300_000),
        consumedAt: null
      });
      await expect(
        store.completeAuthentication({
          organizationId,
          challengeId: authenticationChallengeId,
          expectedChallengeSha256: authenticationHash,
          credentialId: credential.id,
          expectedCounter: 0,
          expectedBackupEligible: false,
          newCounter: 1,
          newBackupState: false
        })
      ).resolves.toBe(true);
      await expect(
        store.completeAuthentication({
          organizationId,
          challengeId: authenticationChallengeId,
          expectedChallengeSha256: authenticationHash,
          credentialId: credential.id,
          expectedCounter: 0,
          expectedBackupEligible: false,
          newCounter: 1,
          newBackupState: false
        })
      ).resolves.toBe(false);
      await expect(
        store.findActiveCredentialByRawId(organizationId, credential.credentialId)
      ).resolves.toMatchObject({ counter: 1 });

      const pendingChallengeId = testId(62_014);
      const pendingChallengeHash = "43".repeat(32);
      const pendingMemberId = testId(62_015);
      const pendingCredentialId = testId(62_016);
      const pendingRawCredentialId = Uint8Array.from({ length: 32 }, (_, index) => 0xff - index);
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Pending member','Pending member','pending_activation')",
        [pendingMemberId, organizationId]
      );
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,signature_counter,transports,
           backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,1,array['internal'],false,false,'active')`,
        [
          pendingCredentialId,
          organizationId,
          pendingMemberId,
          Buffer.from(pendingRawCredentialId),
          Buffer.alloc(64, 9)
        ]
      );
      await store.saveChallenge({
        id: pendingChallengeId,
        organizationId,
        sessionId,
        memberId: null,
        purpose: "authentication",
        challengeSha256: pendingChallengeHash,
        rpId: "boardagent.test",
        exactOrigin: "https://boardagent.test",
        expiresAt: new Date(Date.now() + 300_000),
        consumedAt: null
      });
      await expect(
        store.findActiveCredentialByRawId(organizationId, pendingRawCredentialId)
      ).resolves.toBeNull();
      await expect(
        store.completeAuthentication({
          organizationId,
          challengeId: pendingChallengeId,
          expectedChallengeSha256: pendingChallengeHash,
          credentialId: pendingCredentialId,
          expectedCounter: 1,
          expectedBackupEligible: false,
          newCounter: 2,
          newBackupState: false
        })
      ).resolves.toBe(false);
      expect(
        await pool.query(
          `select challenge.consumed_at,credential.signature_counter::text as counter
             from webauthn_challenges as challenge
             cross join webauthn_credentials as credential
            where challenge.id=$1 and credential.id=$2`,
          [pendingChallengeId, pendingCredentialId]
        )
      ).toMatchObject({ rows: [{ consumed_at: null, counter: "1" }] });
      await pool.query("update members set state='active',row_version=row_version+1 where id=$1", [
        pendingMemberId
      ]);
      await expect(
        store.completeAuthentication({
          organizationId,
          challengeId: pendingChallengeId,
          expectedChallengeSha256: pendingChallengeHash,
          credentialId: pendingCredentialId,
          expectedCounter: 1,
          expectedBackupEligible: false,
          newCounter: 2,
          newBackupState: false
        })
      ).resolves.toBe(true);

      const persisted = await pool.query<{
        challenge_sha256: Buffer;
        consumed_at: Date | null;
      }>(
        "select challenge_sha256,consumed_at from webauthn_challenges where id in ($1,$2,$3) order by id",
        [registrationChallengeId, authenticationChallengeId, pendingChallengeId]
      );
      expect(persisted.rows).toHaveLength(3);
      expect(persisted.rows.every((row) => row.challenge_sha256.length === 32)).toBe(true);
      expect(persisted.rows[0]?.consumed_at).toBeNull();
      expect(persisted.rows.slice(1).every((row) => row.consumed_at !== null)).toBe(true);

      const requestClient = await pool.connect();
      try {
        await requestClient.query("begin");
        await requestClient.query("set local role boardagent_server");
        await requestClient.query(
          `select set_config('boardagent.organization_id',$1,true),
                  set_config('boardagent.transaction_scope','request',true)`,
          [organizationId]
        );
        const hidden = await requestClient.query<{ count: string }>(
          "select count(*)::text as count from webauthn_challenges"
        );
        expect(hidden.rows).toEqual([{ count: "0" }]);
        await requestClient.query("rollback");
      } finally {
        requestClient.release();
      }
    });
  });
});
