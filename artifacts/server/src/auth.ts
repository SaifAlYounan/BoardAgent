import { errors as joseErrors, jwtVerify, type JWTVerifyGetKey, type JWTVerifyOptions } from "jose";
import { OAuthError, OAuthErrorCode, type OAuthTokenVerifier } from "@modelcontextprotocol/server";

export interface ActiveTokenContext {
  readonly tokenRecordId: string;
  readonly organizationId: string;
  readonly memberId: string;
  readonly internalClientId: string;
  readonly protocolClientId: string;
  readonly resourceUri: string;
  readonly scopes: readonly string[];
  readonly expiresAt: number;
  readonly signingKeyKid: string;
  readonly roles: readonly string[];
  readonly boardIds: readonly string[];
}

/** Resolves only a currently active database token/client/member/session tuple. */
export interface TokenContextStore {
  findActiveByJti(jti: string): Promise<ActiveTokenContext | null>;
}

export interface TokenVerifierOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly publicKey: CryptoKey | JWTVerifyGetKey;
  readonly tokens: TokenContextStore;
  readonly clockToleranceSeconds?: number;
  readonly onError?: (error: Error) => void;
}

/** Expected rejection of untrusted key metadata, distinct from an unavailable database. */
export class OAuthVerificationKeyRejectedError extends Error {}

function stringClaim(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new OAuthError(OAuthErrorCode.InvalidToken, `missing ${name} claim`);
  }
  return value;
}

function scopesClaim(value: unknown): string[] {
  if (typeof value === "string") return value.split(" ").filter(Boolean);
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) return value;
  throw new OAuthError(OAuthErrorCode.InvalidToken, "invalid scope claim");
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  const normalizedLeft = [...new Set(left)].toSorted();
  const normalizedRight = [...new Set(right)].toSorted();
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

export function createTokenVerifier(
  options: TokenVerifierOptions
): OAuthTokenVerifier["verifyAccessToken"] {
  const verifyOptions: JWTVerifyOptions = {
    algorithms: ["ES256"],
    issuer: options.issuer,
    audience: options.audience,
    clockTolerance: options.clockToleranceSeconds ?? 30,
    requiredClaims: ["sub", "jti", "iat", "exp", "aud"]
  };
  // Normalize the static-key compatibility seam to jose's resolver overload once.
  const verificationKey = options.publicKey;
  const resolveKey: JWTVerifyGetKey =
    typeof verificationKey === "function" ? verificationKey : () => verificationKey;
  return async (token) => {
    // A request-local, allowlisted classification retains useful diagnostics without
    // copying arbitrary database exception messages, SQL or credentials to the sink.
    let failureCode = "oauth_signature_verification_unavailable";
    try {
      const verified = await jwtVerify(token, resolveKey, verifyOptions);
      const { payload, protectedHeader } = verified;
      if (
        protectedHeader.alg !== "ES256" ||
        typeof protectedHeader.kid !== "string" ||
        !protectedHeader.kid
      ) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "untrusted token key metadata");
      }
      const memberId = stringClaim(payload.sub, "sub");
      const jti = stringClaim(payload.jti, "jti");
      const internalClientId = stringClaim(payload.client_id, "client_id");
      const resource = stringClaim(payload.resource, "resource");
      if (typeof payload.exp !== "number") {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "missing exp claim");
      }
      if (resource !== options.audience) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "token resource mismatch");
      }
      const scopes = scopesClaim(payload.scope);
      failureCode = "oauth_token_authority_unavailable";
      const record = await options.tokens.findActiveByJti(jti);
      if (!record) {
        throw new OAuthError(
          OAuthErrorCode.InvalidToken,
          "token is not active in the BoardAgent ledger"
        );
      }
      if (
        record.memberId !== memberId ||
        record.internalClientId !== internalClientId ||
        record.resourceUri !== resource ||
        record.expiresAt !== payload.exp ||
        record.signingKeyKid !== protectedHeader.kid ||
        !sameStringSet(record.scopes, scopes)
      ) {
        throw new OAuthError(
          OAuthErrorCode.InvalidToken,
          "token claims do not match the BoardAgent ledger"
        );
      }
      return {
        token,
        clientId: record.protocolClientId,
        scopes: [...record.scopes].toSorted(),
        expiresAt: payload.exp,
        resource: new URL(resource),
        extra: {
          organizationId: record.organizationId,
          memberId,
          internalClientId,
          accessTokenRecordId: record.tokenRecordId,
          jti,
          keyId: protectedHeader.kid,
          roles: [...new Set(record.roles)].toSorted(),
          boardIds: [...new Set(record.boardIds)].toSorted()
        }
      };
    } catch (error) {
      if (error instanceof OAuthError) throw error;
      if (
        error instanceof joseErrors.JOSEError ||
        error instanceof OAuthVerificationKeyRejectedError
      ) {
        throw new OAuthError(
          OAuthErrorCode.InvalidToken,
          "access token cryptographic verification failed"
        );
      }
      // The bearer SDK converts non-OAuth errors to generic500. Report a bounded
      // operational error here because its gate consumes the exception internally.
      const unavailable = Object.assign(new Error("token verification unavailable"), {
        code: failureCode
      });
      try {
        options.onError?.(unavailable);
      } catch {
        /* An alert sink cannot change refusal. */
      }
      throw unavailable;
    }
  };
}

export function bearerToken(authorization: string | undefined): string {
  if (!authorization) throw new Error("missing bearer token");
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/u.exec(authorization);
  if (!match?.[1]) throw new Error("invalid bearer authorization header");
  return match[1];
}
