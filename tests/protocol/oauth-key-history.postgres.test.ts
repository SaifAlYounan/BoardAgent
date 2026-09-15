import { SignJWT, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it, vi } from "vitest";
import { OAUTH_VERIFICATION_CACHE_MILLISECONDS } from "../../artifacts/server/src/oauth-public-keys.js";

import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import {
  administrativeOAuthFixture,
  bootstrapOAuthFixture
} from "../helpers/administrative-oauth.js";

const expireKeySnapshot = () =>
  new Promise<void>((resolve) => setTimeout(resolve, OAUTH_VERIFICATION_CACHE_MILLISECONDS + 100));

describe("OAuth signing-key history through the production HTTPS application", () => {
  it.each(["key-lookup", "token-ledger"] as const)(
    "reports a %s outage as a server failure without discarding valid credentials",
    async (stage) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await administrativeOAuthFixture(pool);
        try {
          const token = await f.login(f.target.memberId);
          if (stage === "token-ledger") {
            // Warm the actual resolver snapshot first. The next failed pool checkout
            // must come from the uncached live token ledger, after signature verification.
            await f.connect(token);
          }
          const checkout = vi
            .spyOn(pool, "connect")
            .mockRejectedValueOnce(new Error("synthetic-pool-checkout-failure-canary"));
          let response: Response;
          try {
            response = await f.trustedFetch(f.resource, {
              method: "POST",
              headers: {
                authorization: `Bearer ${token.access_token}`,
                "content-type": "application/json"
              },
              body: JSON.stringify({ jsonrpc: "2.0", id: "lookup-outage", method: "initialize" })
            });
          } finally {
            checkout.mockRestore();
          }
          expect(response.status).toBe(500);
          expect(response.headers.has("www-authenticate")).toBe(false);
          expect(await response.json()).toEqual({
            error: "server_error",
            error_description: "Internal Server Error"
          });
          expect(f.errors.map((error) => error.message)).toEqual([
            "token verification unavailable"
          ]);
          expect(f.errors[0]).toMatchObject({
            code:
              stage === "key-lookup"
                ? "oauth_signature_verification_unavailable"
                : "oauth_token_authority_unavailable"
          });
          expect(JSON.stringify(f.errors)).not.toContain("synthetic-pool-checkout-failure-canary");
          expect(f.errors[0]!.cause).toBeUndefined();
          expect(f.errors[0]!.stack).not.toContain("synthetic-pool-checkout-failure-canary");
          // Pool-checkout fault injection is complete. The issued credential and its
          // database authority remain usable after the bounded failure interval.
          await new Promise<void>((resolve) => setTimeout(resolve, 1100));
          const client = await f.connect(token);
          expect(
            (
              await client.callTool({
                name: "whoami",
                arguments: { schema_version: "boardagent.tool-input.v1" }
              })
            ).isError
          ).not.toBe(true);
        } finally {
          await f.close();
        }
      });
    }
  );

  it("bounds database checkouts during a burst of distinct forged key identifiers", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const signer = await generateKeyPair("ES256");
        const tokens = await Promise.all(
          Array.from({ length: 32 }, (_, i) =>
            new SignJWT({})
              .setProtectedHeader({ alg: "ES256", kid: `unknown-burst-${i}` })
              .sign(signer.privateKey)
          )
        );
        const checkout = vi.spyOn(pool, "connect");
        try {
          const responses = await Promise.all(
            tokens.map((token) =>
              f.trustedFetch(f.resource, {
                method: "POST",
                headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
                body: JSON.stringify({ jsonrpc: "2.0", id: "forged-burst", method: "initialize" })
              })
            )
          );
          expect(responses.map((response) => response.status)).toEqual(Array(32).fill(401));
          // Separate TLS handshakes can straddle one real cache expiry. This is a
          // bounded burst assertion, not a promise that every request starts together.
          expect(checkout.mock.calls.length).toBeLessThanOrEqual(2);
        } finally {
          checkout.mockRestore();
        }
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });

  it("coalesces public JWKS lookups and refreshes retained history after the cache interval", async () => {
    await withAdministrativeDatabase(async (pool) => {
      // Start from real bootstrap: administrative fixtures also retain placeholder
      // historical keys that deliberately are not valid public verification material.
      const f = await bootstrapOAuthFixture(pool);
      try {
        const checkout = vi.spyOn(pool, "connect");
        try {
          const responses = await Promise.all(
            Array.from({ length: 32 }, () => f.trustedFetch(new URL("/jwks", f.origin)))
          );
          expect(responses.map((response) => response.status)).toEqual(Array(32).fill(200));
          const bodies = await Promise.all(responses.map((response) => response.json()));
          expect(bodies.every((body) => JSON.stringify(body) === JSON.stringify(bodies[0]))).toBe(
            true
          );
          // As above, independently established TLS requests may cross one expiry.
          expect(checkout.mock.calls.length).toBeLessThanOrEqual(2);
        } finally {
          checkout.mockRestore();
        }
        const history = await f.installSyntheticOAuthReplacement();
        const current = await f.trustedFetch(new URL("/jwks", f.origin));
        expect(await current.json()).toMatchObject({
          keys: expect.arrayContaining([
            expect.objectContaining({ kid: history.oldKid }),
            expect.objectContaining({ kid: history.newKid })
          ])
        });
        // Only the advertised canonical /jwks route is supported. The provider
        // rejects trailing-slash aliases; it must not publish a different key set.
        for (const path of ["/jwks/", "/jwks/?refresh=1"]) {
          const alias = await f.trustedFetch(new URL(path, f.origin));
          expect(alias.status).toBe(404);
          const body = await alias.text();
          expect(body).not.toContain(history.oldKid);
          expect(body).not.toContain(history.newKid);
        }
        await pool.query(
          "update crypto_key_registry set compromised_at=transaction_timestamp() where id=$1",
          [history.oldKeyId]
        );
        await expireKeySnapshot();
        const refreshed = await f.trustedFetch(new URL("/jwks", f.origin));
        expect(await refreshed.json()).toEqual({
          keys: [expect.objectContaining({ kid: history.newKid })]
        });
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });

  it("refuses malformed historical trust and caller-supplied verification keys", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const token = await f.login(f.target.memberId);
        const client = await f.connect(token);
        const history = await f.installSyntheticOAuthReplacement();
        const original = (
          await pool.query<{
            public_jwk: Record<string, unknown>;
            activated_at: string;
            retired_at: string;
          }>(
            `select public_jwk,activated_at::text,retired_at::text
            from crypto_key_registry where id=$1`,
            [history.oldKeyId]
          )
        ).rows[0]!;
        const refused = async (accessToken: string) => {
          const response = await f.trustedFetch(f.resource, {
            method: "POST",
            headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", id: "untrusted-key", method: "initialize" })
          });
          expect(response.status).toBe(401);
          expect(await response.json()).toEqual({
            error: "invalid_token",
            error_description: "Bearer token is invalid"
          });
        };
        for (const altered of [
          { ...original.public_jwk, d: "private-key-field-canary" },
          { ...original.public_jwk, kid: "different-key-identity" },
          { ...original.public_jwk, x: "A".repeat(43), y: "A".repeat(43) }
        ]) {
          await pool.query("update crypto_key_registry set public_jwk=$2 where id=$1", [
            history.oldKeyId,
            altered
          ]);
          await expireKeySnapshot();
          await refused(token.access_token);
        }
        await pool.query(
          `update crypto_key_registry set public_jwk=$2,retired_at=null,
            activated_at=transaction_timestamp()+interval '1 day' where id=$1`,
          [history.oldKeyId, original.public_jwk]
        );
        await expireKeySnapshot();
        await refused(token.access_token);
        await pool.query(
          `update crypto_key_registry set activated_at=$2::timestamptz,retired_at=$3::timestamptz
            where id=$1`,
          [history.oldKeyId, original.activated_at, original.retired_at]
        );
        await expireKeySnapshot();
        const untrusted = await generateKeyPair("ES256", { extractable: true });
        const untrustedJwk = await exportJWK(untrusted.publicKey);
        for (const kid of [history.oldKid, "unknown-key", "bad/key", "x".repeat(129)]) {
          const forged = await new SignJWT(decodeJwt(token.access_token))
            .setProtectedHeader({
              alg: "ES256",
              kid,
              jwk: untrustedJwk,
              jku: "https://untrusted.invalid/jwks"
            })
            .sign(untrusted.privateKey);
          await refused(forged);
        }
        const stillValid = await client.callTool({
          name: "whoami",
          arguments: { schema_version: "boardagent.tool-input.v1" }
        });
        expect(stillValid.isError).not.toBe(true);
        expect(stillValid.structuredContent).toMatchObject({
          data: { member_id: f.target.memberId }
        });
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  }, 15_000);

  it("keeps live issued tokens usable after ordinary retirement and rejects a compromised key", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const first = await f.login(f.issuer.memberId);
        const second = await f.login(f.target.memberId);
        const oldClient = await f.connect(second);
        const who = () =>
          oldClient.callTool({
            name: "whoami",
            arguments: { schema_version: "boardagent.tool-input.v1" }
          });
        expect((await who()).isError).not.toBe(true);
        const history = await f.installSyntheticOAuthReplacement();
        expect(decodeProtectedHeader(second.access_token).kid).toBe(history.oldKid);
        expect(history.newKid).not.toBe(history.oldKid);

        // Same genuine issued bearer and real MCP client, after the application's
        // signing key changed. No fake token store or signature-verification seam.
        const afterRestart = await who();
        expect(afterRestart.isError).not.toBe(true);
        expect(afterRestart.structuredContent).toMatchObject({
          data: { member_id: f.target.memberId }
        });
        const refresh = await f.trustedFetch(new URL("/token", f.origin), {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: first.refresh_token,
            client_id: first.protocolId,
            resource: f.resource
          }).toString()
        });
        expect(refresh.status).toBe(200);
        const refreshed = (await refresh.json()) as { access_token: string; refresh_token: string };
        expect(decodeProtectedHeader(refreshed.access_token).kid).toBe(history.newKid);
        const newClient = await f.connect({ ...first, ...refreshed });
        expect(
          (
            await newClient.callTool({
              name: "whoami",
              arguments: { schema_version: "boardagent.tool-input.v1" }
            })
          ).isError
        ).not.toBe(true);

        // Disposable owner fixture marking, not an operator compromise-response command.
        await pool.query(
          "update crypto_key_registry set compromised_at=transaction_timestamp() where id=$1",
          [history.oldKeyId]
        );
        const refused = await f.trustedFetch(f.resource, {
          method: "POST",
          headers: {
            authorization: `Bearer ${second.access_token}`,
            "content-type": "application/json"
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: "compromised-key", method: "initialize" })
        });
        expect(refused.status).toBe(401);
        expect(
          (
            await newClient.callTool({
              name: "whoami",
              arguments: { schema_version: "boardagent.tool-input.v1" }
            })
          ).isError
        ).not.toBe(true);
        expect(
          (
            await pool.query(
              "select count(*)::int as count from crypto_key_registry where id=any($1::uuid[])",
              [[history.oldKeyId, history.newKeyId]]
            )
          ).rows[0]?.count
        ).toBe(2);
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });
});
