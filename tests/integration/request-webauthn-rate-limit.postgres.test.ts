import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import { AuthRequestBoundary } from "../../artifacts/server/src/auth-page.js";
import { PgRateLimiter } from "../../artifacts/server/src/pg-rate-limiter.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

const ORIGIN = "https://boardagent.test";
function request(
  ip: string,
  extra: Record<string, string> = {},
  encrypted = true
): IncomingMessage {
  const headers = {
    host: "boardagent.test",
    origin: ORIGIN,
    "sec-fetch-site": "same-origin",
    ...extra
  };
  return {
    method: "POST",
    headers,
    rawHeaders: Object.entries(headers).flat(),
    socket: { remoteAddress: ip, encrypted }
  } as unknown as IncomingMessage;
}
const policy = { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 };

describe("request-scoped browser passkey throttling", () => {
  for (const limitedAxis of ["ip", "client"] as const) {
    it(`isolates trusted ${limitedAxis} subjects across interleaved requests and preserves the cap`, async () => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool);
        const { RequestWebAuthnAttemptLimiter } =
          await import("../../artifacts/server/src/request-webauthn-rate-limiter.js");
        const limiter = new RequestWebAuthnAttemptLimiter(pool, {
          boundary: new AuthRequestBoundary({ origin: ORIGIN }),
          limiter: new PgRateLimiter(pool, {
            hmacKey: Buffer.alloc(32, 0x79),
            assumeRole: "boardagent_server"
          }),
          policies: {
            ip: { ...policy, maxRequests: limitedAxis === "ip" ? 1 : 100 },
            client: { ...policy, maxRequests: limitedAxis === "client" ? 1 : 100 },
            member: policy,
            token: policy
          },
          assumeRole: "boardagent_server"
        });
        const a = {
          organizationId: issuer.organizationId,
          memberId: issuer.memberId,
          sessionId: testId(72_010),
          purpose: "authentication" as const,
          operation: "authentication_begin" as const
        };
        const b = { ...a, memberId: target.memberId, sessionId: testId(72_011) };
        const first = await limiter.run(request("198.51.100.10"), () => limiter.consume(a));
        expect(first.allowed).toBe(true);
        const results = await Promise.all([
          limiter.run(request(limitedAxis === "ip" ? "198.51.100.20" : "192.0.2.10"), async () => {
            await new Promise<void>((resolve) => setImmediate(resolve));
            return limiter.consume(a);
          }),
          limiter.run(request("203.0.113.10"), async () => {
            await Promise.resolve();
            return limiter.consume(b);
          })
        ]);
        expect(results[0]?.allowed).toBe(false);
        expect(results[0]?.retryAfterSeconds).toBeGreaterThan(0);
        expect(results[1]?.allowed).toBe(true);
        const rows = (
          await pool.query(
            "select bucket_class,count(*)::int as n from rate_limit_buckets group by bucket_class"
          )
        ).rows;
        expect(rows.find((r) => r.bucket_class === "client")?.n).toBe(2);
        expect(rows.find((r) => r.bucket_class === "ip")?.n).toBe(limitedAxis === "ip" ? 2 : 3);
      });
    });
  }
  it("refuses missing request context, forged forwarding and mismatched session identity before consuming buckets", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const { RequestWebAuthnAttemptLimiter } =
        await import("../../artifacts/server/src/request-webauthn-rate-limiter.js");
      const limiter = new RequestWebAuthnAttemptLimiter(pool, {
        boundary: new AuthRequestBoundary({ origin: ORIGIN }),
        limiter: new PgRateLimiter(pool, {
          hmacKey: Buffer.alloc(32, 0x79),
          assumeRole: "boardagent_server"
        }),
        policies: { ip: policy, client: policy, member: policy, token: policy },
        assumeRole: "boardagent_server"
      });
      const context = {
        organizationId: issuer.organizationId,
        memberId: issuer.memberId,
        sessionId: testId(72_010),
        purpose: "authentication" as const,
        operation: "authentication_begin" as const
      };
      await expect(limiter.consume(context)).rejects.toThrow();
      await expect(
        limiter.run(request("198.51.100.10", { "x-forwarded-for": "203.0.113.10" }), () =>
          limiter.consume(context)
        )
      ).rejects.toThrow();
      for (const wrong of [
        { ...context, memberId: target.memberId },
        { ...context, organizationId: testId(108_000) },
        { ...context, sessionId: testId(108_001) },
        { ...context, sessionId: null }
      ])
        await expect(
          limiter.run(request("198.51.100.10"), () => limiter.consume(wrong))
        ).rejects.toThrow();
      expect(
        (await pool.query("select count(*)::int as n from rate_limit_buckets")).rows[0]?.n
      ).toBe(0);
      // Enrollment has no OAuth client yet; its built-in client class still uses the actual IP.
      expect(
        (
          await limiter.run(request("198.51.100.10"), () =>
            limiter.consume({
              ...context,
              sessionId: null,
              purpose: "enrollment",
              operation: "registration_begin"
            })
          )
        ).allowed
      ).toBe(true);
      const proxied = new RequestWebAuthnAttemptLimiter(pool, {
        boundary: new AuthRequestBoundary({ origin: ORIGIN, trustedProxyHops: 1 }),
        limiter: new PgRateLimiter(pool, {
          hmacKey: Buffer.alloc(32, 0x7a),
          assumeRole: "boardagent_server"
        }),
        policies: { ip: policy, client: policy, member: policy, token: policy },
        assumeRole: "boardagent_server"
      });
      const forwarding = { "x-forwarded-for": "203.0.113.10", "x-forwarded-proto": "https" };
      expect(
        (await proxied.run(request("127.0.0.1", forwarding, false), () => proxied.consume(context)))
          .allowed
      ).toBe(true);
      await expect(
        proxied.run(
          request(
            "127.0.0.1",
            {
              ...forwarding,
              "x-forwarded-for": "198.51.100.1, 203.0.113.10"
            },
            false
          ),
          () => proxied.consume(context)
        )
      ).rejects.toThrow();
      await pool.query("update auth_sessions set state='revoked' where id=$1", [context.sessionId]);
      await expect(
        limiter.run(request("192.0.2.10"), () => limiter.consume(context))
      ).rejects.toThrow();
    });
  });
});
