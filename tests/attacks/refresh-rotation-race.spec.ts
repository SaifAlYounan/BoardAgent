import { describe, expect, it } from "vitest";

import {
  rotateRefreshTokenInTransaction,
  withIdentityTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("TH-18 refresh-token reuse race", () => {
  it("allows one successor then atomically compromises and revokes the whole family", async () => {
    await withMigratedDatabase("refresh_rotation", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["onboarding:read"]
      });
      const familyId = testId(18_100);
      const presentedHash = "51".repeat(32);
      await pool.query(
        `insert into oauth_client_grants(client_id,grant_type,scope)
         values ($1,'refresh_token','onboarding:read')`,
        [actor.clientId]
      );
      await pool.query(
        `insert into refresh_families(
           id,organization_id,member_id,client_id,resource_uri,generation,state,
           idle_expires_at,absolute_expires_at
         ) values ($1,$2,$3,$4,'https://boardagent.test/mcp',1,'active',
           transaction_timestamp()+interval '30 days',transaction_timestamp()+interval '90 days')`,
        [familyId, actor.organizationId, actor.memberId, actor.clientId]
      );
      await pool.query(
        `insert into refresh_tokens(id,family_id,generation,token_sha256)
         values ($1,$2,1,$3)`,
        [testId(18_101), familyId, Buffer.from(presentedHash, "hex")]
      );
      await pool.query(
        `insert into access_token_records(
           id,organization_id,jti,member_id,client_id,resource_uri,scope_set,
           refresh_family_id,signing_key_id,expires_at
         ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',array['onboarding:read'],
           $6,$7,transaction_timestamp()+interval '10 minutes')`,
        [
          testId(18_102),
          actor.organizationId,
          testId(18_103),
          actor.memberId,
          actor.clientId,
          familyId,
          testId(8)
        ]
      );

      const rotate = (base: number, replacementHash: string) =>
        withIdentityTransaction(
          pool,
          { organizationId: actor.organizationId },
          (client) =>
            rotateRefreshTokenInTransaction(client, {
              organizationId: actor.organizationId,
              clientId: actor.clientId,
              resourceUri: "https://boardagent.test/mcp",
              presentedRefreshTokenSha256: presentedHash,
              replacementRefreshTokenId: testId(base),
              replacementRefreshTokenSha256: replacementHash,
              accessTokenRecordId: testId(base + 1),
              accessTokenJti: testId(base + 2),
              signingKeyId: testId(8),
              auditEventId: testId(base + 3)
            }),
          { assumeRole: "boardagent_server" }
        );
      const results = await Promise.all([
        rotate(18_110, "61".repeat(32)),
        rotate(18_120, "71".repeat(32))
      ]);
      expect(results.filter((result) => result.refreshed)).toHaveLength(1);
      expect(results.filter((result) => !result.refreshed)).toEqual([
        expect.objectContaining({
          familyId,
          refreshed: false,
          state: "compromised",
          reuseDetected: true
        })
      ]);
      expect(
        (
          await pool.query<{ live_access: string; live_refresh: string; state: string }>(
            `select family.state,
                    (select count(*)::text from refresh_tokens
                      where family_id=family.id and used_at is null and revoked_at is null)
                      as live_refresh,
                    (select count(*)::text from access_token_records
                      where refresh_family_id=family.id and revoked_at is null) as live_access
               from refresh_families as family where family.id=$1`,
            [familyId]
          )
        ).rows
      ).toEqual([{ state: "compromised", live_refresh: "0", live_access: "0" }]);
      expect(
        (
          await pool.query<{ event_type: string }>(
            "select event_type from audit_events order by sequence"
          )
        ).rows.map(({ event_type: eventType }) => eventType)
      ).toEqual(["token_refreshed", "token_reuse_detected"]);
    });
  });
});
