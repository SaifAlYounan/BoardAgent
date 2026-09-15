import { createPublicKey } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Pool } from "pg";
import { importJWK, type JWTVerifyGetKey } from "jose";
import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";
import { withIdentityTransaction } from "@boardagent/db";
import { OAuthVerificationKeyRejectedError } from "./auth.js";

export const OAUTH_VERIFICATION_CACHE_MILLISECONDS = 1000;
const MAX_RECENT_VERIFICATION_KEYS = 4096;

const PublicOAuthJwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
    y: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
    kid: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u),
    use: z.literal("sig"),
    alg: z.literal("ES256")
  })
  .strict();

function publicOAuthJwk(row: { readonly kid: string; readonly public_jwk: unknown }) {
  // The same public-only trust projection governs publication and local verification.
  const jwk = PublicOAuthJwkSchema.parse(row.public_jwk);
  if (jwk.kid !== row.kid) throw new Error("OAuth public key identity mismatch");
  const key = createPublicKey({ key: jwk, format: "jwk" });
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("OAuth public key curve mismatch");
  }
  return jwk;
}

/** Share in-flight work and a short success/failure snapshot across all callers. */
function coalescedVerificationSnapshot<T>(refresh: () => Promise<T>): () => Promise<T> {
  let cached: Promise<T> | undefined;
  let pending = false;
  let refreshAfter = 0;
  return () => {
    if (cached && (pending || performance.now() < refreshAfter)) return cached;
    pending = true;
    cached = refresh().finally(() => {
      pending = false;
      // Failed refreshes also cool down; never fall back to stale successful data.
      refreshAfter = performance.now() + OAUTH_VERIFICATION_CACHE_MILLISECONDS;
    });
    return cached;
  };
}

/**
 * Resolve only a local, configured-organization public key. Untrusted JWT key URLs and
 * embedded JWKs never select a trust source. No private historical keys are loaded.
 * Retirement preserves already-issued tokens until their existing ledger expiry;
 * compromise is checked here and again by the live token-context lookup.
 */
export function createPgOAuthVerificationKeyResolver(
  pool: Pool,
  organizationIdValue: string,
  options: { readonly assumeRole?: "boardagent_server" } = {}
): JWTVerifyGetKey {
  const organizationId = UuidV7Schema.parse(organizationIdValue);
  type Row = { kid: string; public_jwk: unknown };
  type Snapshot = {
    readonly rows: ReadonlyMap<string, Row>;
    readonly imported: Map<string, Promise<CryptoKey>>;
  };
  const snapshot = coalescedVerificationSnapshot<Snapshot>(() =>
    withIdentityTransaction(
      pool,
      { organizationId },
      async (client) => {
        // One coalesced read covers every kid, including arbitrary unknown-kid bursts.
        // Retired keys older than the maximum access-token lifetime cannot be needed
        // by a legitimately issued live token. Full public history stays in /jwks.
        const result = await client.query<Row>(
          `select kid,public_jwk from public.crypto_key_registry
          where organization_id=$1 and purpose='oauth_signing' and algorithm='ES256'
            and activated_at<=transaction_timestamp() and compromised_at is null
            and (retired_at is null or retired_at>transaction_timestamp()-interval '15 minutes')
          order by id limit $2`,
          [organizationId, MAX_RECENT_VERIFICATION_KEYS + 1]
        );
        if (result.rows.length > MAX_RECENT_VERIFICATION_KEYS) {
          throw new Error("recent OAuth verification key history exceeds runtime bound");
        }
        const rows = new Map(result.rows.map((row) => [row.kid, row]));
        if (rows.size !== result.rows.length)
          throw new Error("OAuth verification key identity is not unique");
        return { rows, imported: new Map<string, Promise<CryptoKey>>() };
      },
      {
        ...options,
        isolation: "read committed",
        readOnly: true,
        lockTimeoutMs: 250,
        statementTimeoutMs: 1000
      }
    )
  );
  return async (header) => {
    if (
      header.alg !== "ES256" ||
      typeof header.kid !== "string" ||
      !/^[A-Za-z0-9._-]{1,128}$/u.test(header.kid)
    ) {
      throw new OAuthVerificationKeyRejectedError("OAuth verification key metadata invalid");
    }
    const current = await snapshot();
    const row = current.rows.get(header.kid);
    if (!row) throw new OAuthVerificationKeyRejectedError("OAuth verification key unavailable");
    let imported = current.imported.get(header.kid);
    if (!imported) {
      imported = (async () => {
        try {
          const key = await importJWK(publicOAuthJwk(row), "ES256");
          if (!(key instanceof CryptoKey)) throw new Error("OAuth public key import invalid");
          return key;
        } catch {
          throw new OAuthVerificationKeyRejectedError("OAuth public key invalid");
        }
      })();
      current.imported.set(header.kid, imported);
    }
    return imported;
  };
}

/** Public verification history only. This endpoint cannot activate or replace keys. */
export function createPgOAuthPublicKeysEndpoint(
  pool: Pool,
  organizationIdValue: string,
  options: { readonly assumeRole?: "boardagent_server" } = {}
) {
  const organizationId = UuidV7Schema.parse(organizationIdValue);
  // Publication may lag a registry change by this one-second snapshot interval.
  // This is public trust discovery, not token authorization: MCP always checks the
  // live ledger after verifying a signature, including cached compromised keys.
  const snapshot = coalescedVerificationSnapshot(() =>
    withIdentityTransaction(
      pool,
      { organizationId },
      async (client) => {
        const result = await client.query<{ kid: string; public_jwk: unknown }>(
          `select kid,public_jwk from public.crypto_key_registry
            where organization_id=$1 and purpose='oauth_signing' and algorithm='ES256'
              and activated_at<=transaction_timestamp() and compromised_at is null
            order by activated_at,id`,
          [organizationId]
        );
        if (result.rows.length === 0) throw new Error("OAuth verification keys unavailable");
        return result.rows.map(publicOAuthJwk);
      },
      {
        ...options,
        isolation: "read committed",
        readOnly: true,
        lockTimeoutMs: 250,
        statementTimeoutMs: 1000
      }
    )
  );
  return {
    async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
      if (request.method !== "GET" && request.method !== "HEAD") {
        response.writeHead(405, { allow: "GET, HEAD", "cache-control": "no-store" });
        response.end();
        return;
      }
      const keys = await snapshot();
      response.writeHead(200, {
        "content-type": "application/jwk-set+json; charset=utf-8",
        "cache-control": "no-store",
        pragma: "no-cache"
      });
      response.end(request.method === "HEAD" ? undefined : JSON.stringify({ keys }));
    }
  };
}
