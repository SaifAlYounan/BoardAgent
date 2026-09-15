import { describe, expect, it } from "vitest";

import { PgOidcFederationStore } from "../../artifacts/server/src/oidc-federation.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const ISSUER = "https://accounts.identity.example";
const RESOURCE = "https://boardagent.test/mcp";
const CALLBACK = "https://boardagent.test/auth/oidc/callback/google";
const CHALLENGE = "P".repeat(43);

describe("TH-19 OIDC identity linking", () => {
  it("maps only an exact active issuer+subject and never provisions an unknown collision", async () => {
    await withMigratedDatabase("oidc_linking", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["onboarding:read"]
      });
      await pool.query(
        `insert into external_identity_links(
           id,organization_id,member_id,issuer,subject,state,confirmed_by,confirmed_at
         ) values ($1,$2,$3,$4,'exact-prelinked-subject','active',$3,transaction_timestamp())`,
        [testId(19_100), actor.organizationId, actor.memberId, ISSUER]
      );
      let generatedId = 19_900;
      const store = new PgOidcFederationStore(pool, {
        organizationId: actor.organizationId,
        assumeRole: "boardagent_server",
        newId: () => testId((generatedId += 1))
      });
      const seedBrowserBinding = async (base: number) => {
        const sessionId = testId(base);
        const requestId = testId(base + 1);
        await pool.query(
          `insert into auth_sessions(
             id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at
           ) values ($1,$2,$3,null,$4,'anonymous','https://boardagent.test',
             transaction_timestamp()+interval '10 minutes')`,
          [sessionId, actor.organizationId, testHash(base % 255), actor.clientId]
        );
        await pool.query(
          `insert into oauth_authorization_requests(
             id,organization_id,client_id,resource_uri,redirect_uri,scope_set,member_id,session_id,
             state_hash,request_state,expires_at
           ) values ($1,$2,$3,$4,'https://portable-client.test/callback',
             array['onboarding:read'],null,$5,$6,'pending',
             transaction_timestamp()+interval '10 minutes')`,
          [
            requestId,
            actor.organizationId,
            actor.clientId,
            RESOURCE,
            sessionId,
            testHash((base + 1) % 255)
          ]
        );
        return { sessionId, requestId };
      };
      const attempt = async (base: number, subject: string) => {
        const browser = await seedBrowserBinding(base);
        const transactionId = testId(base + 2);
        const state = testHash((base + 2) % 255);
        const nonce = testHash((base + 3) % 255);
        await store.begin({
          transactionId,
          providerId: "google",
          providerKind: "generic",
          exactIssuer: ISSUER,
          interactionUid: `oidc-linking-${String(base).padStart(16, "0")}`,
          authorizationRequestId: browser.requestId,
          sessionId: browser.sessionId,
          clientId: actor.clientId,
          resourceUri: RESOURCE,
          callbackUri: CALLBACK,
          stateSha256: state,
          nonceSha256: nonce,
          pkceS256Challenge: CHALLENGE,
          invitationTokenSha256: null
        });
        return store.complete({
          transactionId,
          providerId: "google",
          providerKind: "generic",
          exactIssuer: ISSUER,
          stateSha256: state,
          nonceSha256: nonce,
          pkceS256Challenge: CHALLENGE,
          subject,
          completionSha256: testHash((base + 4) % 255),
          pendingLinkId: testId(base + 5)
        });
      };

      await expect(attempt(19_200, "unknown-subject-with-colliding-email-claim")).resolves.toEqual({
        status: "unknown_subject",
        interactionUid: expect.any(String),
        memberId: null
      });
      expect((await pool.query("select id from members")).rowCount).toBe(1);
      expect((await pool.query("select id from external_identity_links")).rowCount).toBe(1);

      await expect(attempt(19_300, "exact-prelinked-subject")).resolves.toMatchObject({
        status: "authenticated",
        memberId: actor.memberId
      });
      await expect(attempt(19_400, "EXACT-PRELINKED-SUBJECT")).resolves.toMatchObject({
        status: "unknown_subject",
        memberId: null
      });
    });
  });
});
