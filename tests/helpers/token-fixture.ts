import { generateKeyPair, SignJWT } from "jose";

import {
  createTokenVerifier,
  type ActiveTokenContext,
  type TokenContextStore
} from "../../artifacts/server/src/auth.js";

export const TOKEN_ISSUER = "https://boardagent.test";
export const TOKEN_RESOURCE = "https://boardagent.test/mcp";
export const TOKEN_MEMBER_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
export const TOKEN_CLIENT_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
export const TOKEN_RECORD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
export const TOKEN_JTI = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e04";
export const TOKEN_ORGANIZATION_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e05";
export const TOKEN_BOARD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e06";
export const TOKEN_KEY_ID = "oauth-es256-current";
export const TOKEN_EXPIRY = 2_000_000_000;

export function activeTokenContext(
  overrides: Partial<ActiveTokenContext> = {}
): ActiveTokenContext {
  return {
    tokenRecordId: TOKEN_RECORD_ID,
    organizationId: TOKEN_ORGANIZATION_ID,
    memberId: TOKEN_MEMBER_ID,
    internalClientId: TOKEN_CLIENT_ID,
    protocolClientId: "https://portable-client.test/client.json",
    resourceUri: TOKEN_RESOURCE,
    scopes: ["governance:read", "documents:read"],
    expiresAt: TOKEN_EXPIRY,
    signingKeyKid: TOKEN_KEY_ID,
    roles: ["member"],
    boardIds: [TOKEN_BOARD_ID],
    ...overrides
  };
}

export class MemoryTokenStore implements TokenContextStore {
  public readonly lookups: string[] = [];

  public constructor(public current: ActiveTokenContext | null = activeTokenContext()) {}

  public async findActiveByJti(jti: string): Promise<ActiveTokenContext | null> {
    this.lookups.push(jti);
    return jti === TOKEN_JTI ? this.current : null;
  }
}

export interface TokenClaimsPatch {
  readonly audience?: string;
  readonly resource?: string;
  readonly scopes?: readonly string[];
  readonly subject?: string;
  readonly clientId?: string;
  readonly jti?: string;
  readonly keyId?: string;
}

export async function tokenFixture(store = new MemoryTokenStore()) {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const verify = createTokenVerifier({
    issuer: TOKEN_ISSUER,
    audience: TOKEN_RESOURCE,
    publicKey,
    tokens: store
  });
  const sign = async (patch: TokenClaimsPatch = {}): Promise<string> =>
    new SignJWT({
      client_id: patch.clientId ?? TOKEN_CLIENT_ID,
      resource: patch.resource ?? TOKEN_RESOURCE,
      scope: (patch.scopes ?? ["documents:read", "governance:read"]).join(" ")
    })
      .setProtectedHeader({ alg: "ES256", kid: patch.keyId ?? TOKEN_KEY_ID })
      .setIssuer(TOKEN_ISSUER)
      .setAudience(patch.audience ?? TOKEN_RESOURCE)
      .setSubject(patch.subject ?? TOKEN_MEMBER_ID)
      .setJti(patch.jti ?? TOKEN_JTI)
      .setIssuedAt()
      .setExpirationTime(TOKEN_EXPIRY)
      .sign(privateKey);
  return { sign, store, verify };
}
