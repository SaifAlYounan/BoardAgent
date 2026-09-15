import { randomBytes } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import Provider from "oidc-provider";
import { describe, expect, it, vi } from "vitest";
import { createPgOidcProviderPersistence } from "../../artifacts/server/src/pg-oidc-adapter.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";

interface SavedInteraction {
  exp: number;
  iat: number;
  save(ttl: number): Promise<string>;
}

interface PendingRequest {
  id: string;
  session_id: string;
  expires_at: string;
}

describe("OAuth interaction persistence clock boundary", () => {
  it.each(["live", "expired_request", "revoked_session"] as const)(
    "preserves original expiry and current authority across a scheduling gap: %s",
    async (state) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await administrativeOAuthFixture(pool);
        const tokensBefore = (await pool.query("select id from access_token_records order by id"))
          .rows;
        const codesBefore = (
          await pool.query("select id from oauth_authorization_codes order by id")
        ).rows;
        const original = Provider.prototype.interactionResult;
        let delayed = false;
        let before: PendingRequest | undefined;
        let extendedProviderLifetime = 0;
        const spy = vi
          .spyOn(Provider.prototype, "interactionResult")
          .mockImplementation(async function (this: InstanceType<typeof Provider>, ...args) {
            const klass = (this as unknown as { Interaction: { prototype: SavedInteraction } })
              .Interaction;
            const save = klass.prototype.save;
            const saveSpy = vi.spyOn(klass.prototype, "save").mockImplementation(async function (
              this: SavedInteraction,
              ttl
            ) {
              if (!delayed) {
                delayed = true;
                const requests = await pool.query<PendingRequest>(
                  "select id,session_id,expires_at::text from oauth_authorization_requests where request_state='pending'"
                );
                expect(requests.rows).toHaveLength(1);
                before = requests.rows[0]!;
                // Real scheduling delay between the provider's relative TTL calculation
                // and its later epoch read in BaseModel.save. No fake time or auth.
                await delay(1100);
                if (state === "expired_request") {
                  const expired = await pool.query<PendingRequest>(
                    "update oauth_authorization_requests set expires_at=transaction_timestamp()-interval '0.1 second' where id=$1 returning id,session_id,expires_at::text",
                    [before.id]
                  );
                  before = expired.rows[0]!;
                } else if (state === "revoked_session") {
                  await pool.query("update auth_sessions set state='revoked' where id=$1", [
                    before.session_id
                  ]);
                }
              }
              try {
                return await save.call(this, ttl);
              } finally {
                extendedProviderLifetime = Math.max(extendedProviderLifetime, this.exp - this.iat);
              }
            });
            try {
              return await original.apply(this, args);
            } finally {
              saveSpy.mockRestore();
            }
          });
        try {
          if (state === "live") {
            const token = await f.login(f.target.memberId);
            expect(token.access_token).toBeTruthy();
          } else {
            await expect(f.login(f.target.memberId)).rejects.toThrow();
            expect(
              (await pool.query("select id from access_token_records order by id")).rows
            ).toEqual(tokensBefore);
            expect(
              (await pool.query("select id from oauth_authorization_codes order by id")).rows
            ).toEqual(codesBefore);
          }
          expect(delayed).toBe(true);
          expect(extendedProviderLifetime).toBeGreaterThan(600);
          expect(before).toBeDefined();
          expect(
            (
              await pool.query<{ expires_at: string }>(
                "select expires_at::text from oauth_authorization_requests where id=$1",
                [before!.id]
              )
            ).rows[0]!.expires_at
          ).toBe(before!.expires_at);
          if (state === "revoked_session") {
            expect(
              (
                await pool.query("select state from auth_sessions where id=$1", [
                  before!.session_id
                ])
              ).rows[0]!.state
            ).toBe("revoked");
          }
        } finally {
          spy.mockRestore();
          await f.close();
        }
      });
    },
    // Includes a fresh full-schema database, TLS login and the real scheduling gap.
    30_000
  );

  it("refuses a newly issued interaction longer than ten minutes without persisting it", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const requestsBefore = (
          await pool.query("select id from oauth_authorization_requests order by id")
        ).rows;
        const persistence = createPgOidcProviderPersistence({
          pool,
          organizationId: f.target.organizationId,
          issuer: f.origin,
          resourceUri: f.resource,
          stateEncryptionKey: randomBytes(32),
          assumeRole: "boardagent_server"
        });
        const client = (
          await pool.query("select protocol_id_value from oauth_clients where id=$1", [
            f.target.clientId
          ])
        ).rows[0]!;
        const now = Math.floor(Date.now() / 1000);
        const interactionId = randomBytes(24).toString("base64url");
        await expect(
          persistence.interactionStateStore.run({ headers: {} } as IncomingMessage, () =>
            new persistence.adapter("Interaction").upsert(
              interactionId,
              {
                iat: now,
                exp: now + 601,
                kind: "Interaction",
                jti: interactionId,
                cid: randomBytes(24).toString("base64url"),
                params: {
                  client_id: client.protocol_id_value,
                  code_challenge: "x".repeat(43),
                  code_challenge_method: "S256",
                  redirect_uri: "https://agent-callback.test/callback",
                  response_type: "code",
                  scope: "onboarding:read",
                  state: randomBytes(24).toString("base64url"),
                  resource: f.resource
                },
                prompt: { name: "login" }
              },
              601
            )
          )
        ).rejects.toThrow("OIDC interaction lifetime");
        expect(
          (await pool.query("select id from oauth_authorization_requests order by id")).rows
        ).toEqual(requestsBefore);
      } finally {
        await f.close();
      }
    });
  });
});
