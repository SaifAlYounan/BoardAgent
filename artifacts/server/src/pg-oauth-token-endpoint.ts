import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import { SignJWT, importJWK, type CryptoKey, type JWK } from "jose";
import type { Pool, PoolClient } from "pg";
import { z } from "zod";

import { OAuthRedirectUriSchema, UuidV7Schema, sha256Bytes } from "@boardagent/contracts";
import {
  IdentityTransactionError,
  issueTokensFromAuthorizationCodeInTransaction,
  rotateRefreshTokenInTransaction,
  withIdentityTransaction,
  type TokenClaimsMaterial
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

import type { BoardAgentOAuthTokenEndpoint } from "./oauth-authorization-server.js";

const ProtocolClientIdSchema = z.string().min(1).max(2048);
const OpaqueTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const PkceVerifierSchema = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/u);
const ExactHttpsSchema = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.href === value &&
      url.username === "" &&
      url.password === "" &&
      url.hash === ""
    );
  });

const AuthorizationCodeFormSchema = z
  .object({
    grant_type: z.literal("authorization_code"),
    client_id: ProtocolClientIdSchema,
    redirect_uri: OAuthRedirectUriSchema,
    code: OpaqueTokenSchema,
    code_verifier: PkceVerifierSchema,
    resource: ExactHttpsSchema
  })
  .strict();

const RefreshTokenFormSchema = z
  .object({
    grant_type: z.literal("refresh_token"),
    client_id: ProtocolClientIdSchema,
    refresh_token: OpaqueTokenSchema,
    resource: ExactHttpsSchema
  })
  .strict();

type TokenEndpointForm =
  z.infer<typeof AuthorizationCodeFormSchema> | z.infer<typeof RefreshTokenFormSchema>;

class OAuthTokenEndpointError extends Error {
  public constructor(
    public readonly oauthError:
      | "invalid_client"
      | "invalid_grant"
      | "invalid_request"
      | "invalid_target"
      | "unsupported_grant_type",
    public readonly status = 400
  ) {
    super(oauthError);
    this.name = "OAuthTokenEndpointError";
  }
}

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

function newOpaqueToken(): string {
  return randomBytes(32).toString("base64url");
}

function sha256Hex(value: string): string {
  return Buffer.from(sha256Bytes(value)).toString("hex");
}

function writeJson(
  response: ServerResponse,
  status: number,
  body: Readonly<Record<string, unknown>>
): void {
  const encoded = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-length": String(encoded.length),
    "content-type": "application/json; charset=utf-8",
    pragma: "no-cache"
  });
  response.end(encoded);
}

function singleHeader(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (Array.isArray(value)) throw new OAuthTokenEndpointError("invalid_request");
  return value;
}

async function readForm(request: IncomingMessage): Promise<TokenEndpointForm> {
  if (request.method !== "POST" || request.url !== "/token") {
    throw new OAuthTokenEndpointError("invalid_request");
  }
  const contentType = singleHeader(request, "content-type")?.toLowerCase();
  if (
    contentType !== "application/x-www-form-urlencoded" &&
    contentType !== "application/x-www-form-urlencoded; charset=utf-8"
  ) {
    throw new OAuthTokenEndpointError("invalid_request");
  }
  const declaredLength = singleHeader(request, "content-length");
  if (
    declaredLength !== undefined &&
    (!/^(?:0|[1-9]\d*)$/u.test(declaredLength) || Number(declaredLength) > 8192)
  ) {
    throw new OAuthTokenEndpointError("invalid_request");
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunkValue of request) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    length += chunk.length;
    if (length > 8192) throw new OAuthTokenEndpointError("invalid_request");
    chunks.push(chunk);
  }
  let body: string;
  try {
    body = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    throw new OAuthTokenEndpointError("invalid_request");
  }
  const params = new URLSearchParams(body);
  const keys = [...params.keys()];
  if (keys.length !== new Set(keys).size) throw new OAuthTokenEndpointError("invalid_request");
  const record = Object.fromEntries(params.entries());
  const grantType = record["grant_type"];
  if (grantType === "authorization_code") {
    const parsed = AuthorizationCodeFormSchema.safeParse(record);
    if (!parsed.success) throw new OAuthTokenEndpointError("invalid_request");
    return parsed.data;
  }
  if (grantType === "refresh_token") {
    const parsed = RefreshTokenFormSchema.safeParse(record);
    if (!parsed.success) throw new OAuthTokenEndpointError("invalid_request");
    return parsed.data;
  }
  throw new OAuthTokenEndpointError("unsupported_grant_type");
}

function jwtEpoch(value: string): number {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error("database token time is invalid");
  return Math.floor(milliseconds / 1000);
}

async function signAccessToken(
  claims: TokenClaimsMaterial,
  privateKey: CryptoKey,
  configuredKid: string
): Promise<string> {
  if (claims.signingKeyKid !== configuredKid) {
    throw new Error("database and configured OAuth signing KID differ");
  }
  const issuedAt = jwtEpoch(claims.issuedAt);
  const expiresAt = jwtEpoch(claims.expiresAt);
  if (expiresAt - issuedAt !== 900) throw new Error("database access token lifetime drifted");
  return new SignJWT({
    resource: claims.resource,
    client_id: claims.clientId,
    scope: claims.scopes.join(" ")
  })
    .setProtectedHeader({ alg: "ES256", kid: configuredKid, typ: "at+jwt" })
    .setIssuer(claims.issuer)
    .setAudience(claims.audience)
    .setSubject(claims.subject)
    .setJti(claims.jti)
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .sign(privateKey);
}

async function resolveClient(
  client: PoolClient,
  organizationId: string,
  protocolClientId: string
): Promise<string> {
  const result = await client.query<{ id: string }>(
    `select id from oauth_clients
      where organization_id=$1 and protocol_id_value=$2 and state='active'`,
    [organizationId, protocolClientId]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) throw new OAuthTokenEndpointError("invalid_client");
  return UuidV7Schema.parse(row.id);
}

async function assertSigningKeyBinding(
  client: PoolClient,
  organizationId: string,
  signingKeyId: string,
  privateJwk: Readonly<Record<string, unknown>>
): Promise<void> {
  const result = await client.query<{ public_jwk: Record<string, unknown>; kid: string }>(
    `select public_jwk,kid from crypto_key_registry
      where id=$1 and organization_id=$2 and purpose='oauth_signing' and algorithm='ES256'
        and activated_at<=transaction_timestamp()
        and (retired_at is null or retired_at>transaction_timestamp())
        and (compromised_at is null or compromised_at>transaction_timestamp())`,
    [signingKeyId, organizationId]
  );
  const row = result.rows[0];
  const fields = ["kty", "crv", "x", "y", "kid", "use", "alg"] as const;
  if (
    !row ||
    result.rows.length !== 1 ||
    row.kid !== privateJwk["kid"] ||
    fields.some((field) => row.public_jwk[field] !== privateJwk[field])
  ) {
    throw new Error("configured OAuth private key does not match the active registry key");
  }
}

export interface PgOAuthTokenEndpointOptions {
  readonly pool: Pool;
  readonly organizationId: string;
  readonly resourceUri: string;
  readonly signingKeyId: string;
  readonly privateJwk: Readonly<Record<string, unknown>>;
  /** Test/bootstrap seam only. Production uses an already-scoped server pool. */
  readonly assumeRole?: "boardagent_server";
}

export function createPgOAuthTokenEndpoint(
  options: PgOAuthTokenEndpointOptions
): BoardAgentOAuthTokenEndpoint {
  const organizationId = UuidV7Schema.parse(options.organizationId);
  const signingKeyId = UuidV7Schema.parse(options.signingKeyId);
  const resourceUri = ExactHttpsSchema.parse(options.resourceUri);
  const privateJwk = z
    .object({
      kty: z.literal("EC"),
      crv: z.literal("P-256"),
      x: z.string().min(1),
      y: z.string().min(1),
      d: z.string().min(1),
      kid: z.string().min(1).max(128),
      alg: z.literal("ES256"),
      use: z.literal("sig")
    })
    .passthrough()
    .parse(options.privateJwk);
  const privateKey = importJWK(privateJwk as JWK & { readonly kty: "EC" }, "ES256");
  const transactionOptions = options.assumeRole ? { assumeRole: options.assumeRole } : {};

  const exchangeAuthorizationCode = async (
    form: z.infer<typeof AuthorizationCodeFormSchema>
  ): Promise<Readonly<Record<string, unknown>>> => {
    if (form.resource !== resourceUri) throw new OAuthTokenEndpointError("invalid_target");
    const refreshToken = newOpaqueToken();
    const key = await privateKey;
    return withIdentityTransaction(
      options.pool,
      { organizationId },
      async (client) => {
        const clientId = await resolveClient(client, organizationId, form.client_id);
        await assertSigningKeyBinding(client, organizationId, signingKeyId, privateJwk);
        const issued = await issueTokensFromAuthorizationCodeInTransaction(client, {
          organizationId,
          clientId,
          authorizationCodeSha256: sha256Hex(form.code),
          pkceVerifier: form.code_verifier,
          redirectUri: form.redirect_uri,
          resourceUri,
          refreshFamilyId: newId(),
          refreshTokenId: newId(),
          refreshTokenSha256: sha256Hex(refreshToken),
          accessTokenRecordId: newId(),
          accessTokenJti: newId(),
          signingKeyId,
          auditEventId: newId()
        });
        const accessToken = await signAccessToken(issued.claims, key, privateJwk.kid);
        return {
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 900,
          refresh_token: refreshToken,
          scope: issued.claims.scopes.join(" ")
        };
      },
      transactionOptions
    );
  };

  const exchangeRefreshToken = async (
    form: z.infer<typeof RefreshTokenFormSchema>
  ): Promise<Readonly<Record<string, unknown>>> => {
    if (form.resource !== resourceUri) throw new OAuthTokenEndpointError("invalid_target");
    const replacement = newOpaqueToken();
    const key = await privateKey;
    return withIdentityTransaction(
      options.pool,
      { organizationId },
      async (client) => {
        const clientId = await resolveClient(client, organizationId, form.client_id);
        await assertSigningKeyBinding(client, organizationId, signingKeyId, privateJwk);
        const refreshed = await rotateRefreshTokenInTransaction(client, {
          organizationId,
          clientId,
          resourceUri,
          presentedRefreshTokenSha256: sha256Hex(form.refresh_token),
          replacementRefreshTokenId: newId(),
          replacementRefreshTokenSha256: sha256Hex(replacement),
          accessTokenRecordId: newId(),
          accessTokenJti: newId(),
          signingKeyId,
          auditEventId: newId()
        });
        if (!refreshed.refreshed) {
          return { error: "invalid_grant" };
        }
        const accessToken = await signAccessToken(refreshed.claims, key, privateJwk.kid);
        return {
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 900,
          refresh_token: replacement,
          scope: refreshed.claims.scopes.join(" ")
        };
      },
      transactionOptions
    );
  };

  return {
    async handle(request, response): Promise<void> {
      try {
        const form = await readForm(request);
        const result =
          form.grant_type === "authorization_code"
            ? await exchangeAuthorizationCode(form)
            : await exchangeRefreshToken(form);
        if (result["error"] === "invalid_grant") {
          writeJson(response, 400, result);
          return;
        }
        writeJson(response, 200, result);
      } catch (error) {
        if (error instanceof OAuthTokenEndpointError) {
          writeJson(response, error.status, { error: error.oauthError });
          return;
        }
        if (error instanceof IdentityTransactionError) {
          if (
            error.code === "identity_context_invalid" ||
            error.code === "token_signing_key_invalid"
          ) {
            writeJson(response, 500, { error: "server_error" });
            return;
          }
          writeJson(response, 400, {
            error: error.code === "token_client_invalid" ? "invalid_client" : "invalid_grant"
          });
          return;
        }
        writeJson(response, 500, { error: "server_error" });
      }
    }
  };
}
