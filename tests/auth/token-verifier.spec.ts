import { SignJWT, generateKeyPair } from "jose";
import { describe, expect, it, vi } from "vitest";

import {
  bearerToken,
  createTokenVerifier,
  OAuthVerificationKeyRejectedError,
  type ActiveTokenContext,
  type TokenContextStore
} from "../../artifacts/server/src/auth.js";

const ISSUER = "https://boardagent.test";
const RESOURCE = "https://boardagent.test/mcp";
const MEMBER_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const INTERNAL_CLIENT_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const TOKEN_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
const JTI = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e04";
const ORGANIZATION_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e05";
const BOARD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e06";
const KID = "oauth-es256-current";
const EXP = 2_000_000_000;

class FakeStore implements TokenContextStore {
  public constructor(public current: ActiveTokenContext | null) {}

  public async findActiveByJti(jti: string): Promise<ActiveTokenContext | null> {
    return jti === JTI ? this.current : null;
  }
}

function context(overrides: Partial<ActiveTokenContext> = {}): ActiveTokenContext {
  return {
    tokenRecordId: TOKEN_ID,
    organizationId: ORGANIZATION_ID,
    memberId: MEMBER_ID,
    internalClientId: INTERNAL_CLIENT_ID,
    protocolClientId: "https://portable-client.test/client.json",
    resourceUri: RESOURCE,
    scopes: ["governance:read", "documents:read"],
    expiresAt: EXP,
    signingKeyKid: KID,
    roles: ["member"],
    boardIds: [BOARD_ID],
    ...overrides
  };
}

async function signedToken(
  privateKey: CryptoKey,
  overrides: Record<string, unknown> = {}
): Promise<string> {
  return new SignJWT({
    client_id: INTERNAL_CLIENT_ID,
    resource: RESOURCE,
    scope: "documents:read governance:read",
    ...overrides
  })
    .setProtectedHeader({ alg: "ES256", kid: KID })
    .setIssuer(ISSUER)
    .setAudience(RESOURCE)
    .setSubject(MEMBER_ID)
    .setJti(JTI)
    .setIssuedAt(1_999_999_100)
    .setExpirationTime(EXP)
    .sign(privateKey);
}

describe("database-bound MCP bearer verification", () => {
  it("distinguishes rejected resolver keys from operational failures", async () => {
    const { privateKey } = await generateKeyPair("ES256");
    const token = await signedToken(privateKey);
    const store = new FakeStore(context());
    const lookup = vi.spyOn(store, "findActiveByJti");
    const onError = vi.fn();
    let failure: Error = new OAuthVerificationKeyRejectedError("untrusted key");
    const verify = createTokenVerifier({
      issuer: ISSUER,
      audience: RESOURCE,
      publicKey: async () => {
        throw failure;
      },
      tokens: store,
      onError,
      clockToleranceSeconds: EXP - Math.floor(Date.now() / 1000) + 1
    });
    await expect(verify(token)).rejects.toThrow("cryptographic verification failed");
    expect(onError).not.toHaveBeenCalled();
    failure = new Error("database-detail-canary");
    await expect(verify(token)).rejects.toThrow("token verification unavailable");
    expect(onError).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        message: "token verification unavailable",
        code: "oauth_signature_verification_unavailable"
      })
    );
    expect(lookup).not.toHaveBeenCalled();
  });

  it("reports a failed live ledger lookup with a nonsecret operational classification", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const store = new FakeStore(context());
    vi.spyOn(store, "findActiveByJti").mockRejectedValueOnce(new Error("ledger-detail-canary"));
    const onError = vi.fn();
    const verify = createTokenVerifier({
      issuer: ISSUER,
      audience: RESOURCE,
      publicKey,
      tokens: store,
      onError,
      clockToleranceSeconds: EXP - Math.floor(Date.now() / 1000) + 1
    });
    await expect(verify(await signedToken(privateKey))).rejects.toMatchObject({
      message: "token verification unavailable",
      code: "oauth_token_authority_unavailable"
    });
    expect(onError).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        message: "token verification unavailable",
        code: "oauth_token_authority_unavailable"
      })
    );
    expect(JSON.stringify(onError.mock.calls)).not.toContain("ledger-detail-canary");
    const diagnostic = onError.mock.calls[0]![0] as Error;
    expect(diagnostic.cause).toBeUndefined();
    expect(diagnostic.stack).not.toContain("ledger-detail-canary");
  });

  it("rejects a resolver's wrong signature key and an independently mismatched ledger kid", async () => {
    const keys = await generateKeyPair("ES256");
    const other = await generateKeyPair("ES256");
    const store = new FakeStore(context());
    let selected = other.publicKey;
    const resolve = vi.fn(async () => selected);
    const verify = createTokenVerifier({
      issuer: ISSUER,
      audience: RESOURCE,
      publicKey: resolve,
      tokens: store,
      clockToleranceSeconds: EXP - Math.floor(Date.now() / 1000) + 1
    });
    const token = await signedToken(keys.privateKey);
    await expect(verify(token)).rejects.toThrow("cryptographic verification failed");
    selected = keys.publicKey;
    store.current = context({ signingKeyKid: "a-different-ledger-key" });
    await expect(verify(token)).rejects.toThrow("claims do not match");
    expect(resolve.mock.calls).toHaveLength(2);
  });

  it("rejects a non-string kid even when a permissive test resolver verifies its signature", async () => {
    const keys = await generateKeyPair("ES256");
    const store = new FakeStore(context());
    const lookup = vi.spyOn(store, "findActiveByJti");
    const verify = createTokenVerifier({
      issuer: ISSUER,
      audience: RESOURCE,
      publicKey: async () => keys.publicKey,
      tokens: store,
      clockToleranceSeconds: EXP - Math.floor(Date.now() / 1000) + 1
    });
    const malformed = await new SignJWT({
      client_id: INTERNAL_CLIENT_ID,
      resource: RESOURCE,
      scope: "governance:read"
    })
      .setProtectedHeader({ alg: "ES256", kid: 123 as unknown as string })
      .setIssuer(ISSUER)
      .setAudience(RESOURCE)
      .setSubject(MEMBER_ID)
      .setJti(JTI)
      .setIssuedAt(1_999_999_100)
      .setExpirationTime(EXP)
      .sign(keys.privateKey);
    await expect(verify(malformed)).rejects.toThrow("untrusted token key metadata");
    expect(lookup).not.toHaveBeenCalled();
  });

  it("hydrates protocol and internal identity only when every ledger binding matches", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const store = new FakeStore(context());
    const verify = createTokenVerifier({
      issuer: ISSUER,
      audience: RESOURCE,
      publicKey,
      tokens: store,
      clockToleranceSeconds: EXP - Math.floor(Date.now() / 1000) + 1
    });
    const auth = await verify(await signedToken(privateKey));
    expect(auth.clientId).toBe("https://portable-client.test/client.json");
    expect(auth.scopes).toEqual(["documents:read", "governance:read"]);
    expect(auth.extra).toEqual({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      internalClientId: INTERNAL_CLIENT_ID,
      accessTokenRecordId: TOKEN_ID,
      jti: JTI,
      keyId: KID,
      roles: ["member"],
      boardIds: [BOARD_ID]
    });
  });

  it("fails closed for a missing record or any claim/ledger mismatch", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const store = new FakeStore(null);
    const verify = createTokenVerifier({
      issuer: ISSUER,
      audience: RESOURCE,
      publicKey,
      tokens: store,
      clockToleranceSeconds: EXP - Math.floor(Date.now() / 1000) + 1
    });
    const token = await signedToken(privateKey);
    await expect(verify(token)).rejects.toThrow("not active");
    store.current = context({ scopes: ["governance:read"] });
    await expect(verify(token)).rejects.toThrow("claims do not match");
    store.current = context({ signingKeyKid: "retired-key" });
    await expect(verify(token)).rejects.toThrow("claims do not match");
  });

  it("accepts exactly one syntactically bounded Bearer credential", () => {
    expect(bearerToken("Bearer abc.DEF_123-~")).toBe("abc.DEF_123-~");
    expect(() => bearerToken(undefined)).toThrow("missing bearer token");
    expect(() => bearerToken("bearer abc")).toThrow("invalid bearer");
    expect(() => bearerToken("Bearer abc extra")).toThrow("invalid bearer");
  });
});
