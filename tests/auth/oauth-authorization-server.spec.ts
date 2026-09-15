import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { exportJWK, generateKeyPair } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  AuthRequestBoundary,
  createBoardAgentOAuthProvider,
  type BoardAgentOAuthProvider,
  type OidcProviderAdapter
} from "../../artifacts/server/src/index.js";

import { proxyHttpRequest } from "../helpers/proxy-http.js";

const ISSUER = "https://boardagent.test";
const RESOURCE = `${ISSUER}/mcp`;
const CLIENT_ID = "https://portable-client.test/client.json";
const REDIRECT_URI = "https://portable-client.test/callback";
const SCOPES = ["documents:read", "governance:read", "vote:act"] as const;
const PKCE_CHALLENGE = "A".repeat(43);
const PKCE_VERIFIER = "v".repeat(43);
const MEMBER_ID = "018f0000-0000-7000-8000-000000000003";

interface StoredArtifact {
  readonly payload: Readonly<Record<string, unknown>>;
  readonly expiresAt: number;
}

class DurableTestAdapter implements OidcProviderAdapter {
  public static readonly artifacts = new Map<string, StoredArtifact>();
  public static readonly models = new Set<string>();

  public constructor(private readonly model: string) {
    DurableTestAdapter.models.add(model);
  }

  private key(id: string): string {
    return `${this.model}\0${id}`;
  }

  public async upsert(
    id: string,
    payload: Readonly<Record<string, unknown>>,
    expiresIn: number
  ): Promise<void> {
    DurableTestAdapter.artifacts.set(this.key(id), {
      payload: structuredClone(payload),
      expiresAt: Date.now() + expiresIn * 1000
    });
  }

  public async find(id: string): Promise<Readonly<Record<string, unknown>> | undefined> {
    const stored = DurableTestAdapter.artifacts.get(this.key(id));
    if (!stored) return undefined;
    if (stored.expiresAt <= Date.now()) {
      DurableTestAdapter.artifacts.delete(this.key(id));
      return undefined;
    }
    return structuredClone(stored.payload);
  }

  public async destroy(id: string): Promise<void> {
    DurableTestAdapter.artifacts.delete(this.key(id));
  }

  public async consume(id: string): Promise<void> {
    const stored = DurableTestAdapter.artifacts.get(this.key(id));
    if (!stored) return;
    DurableTestAdapter.artifacts.set(this.key(id), {
      ...stored,
      payload: { ...stored.payload, consumed: Math.floor(Date.now() / 1000) }
    });
  }

  public async findByUid(uid: string): Promise<Readonly<Record<string, unknown>> | undefined> {
    for (const [key, stored] of DurableTestAdapter.artifacts) {
      if (key.startsWith(`${this.model}\0`) && stored.payload["uid"] === uid) {
        return structuredClone(stored.payload);
      }
    }
    return undefined;
  }

  public async findByUserCode(
    userCode: string
  ): Promise<Readonly<Record<string, unknown>> | undefined> {
    for (const [key, stored] of DurableTestAdapter.artifacts) {
      if (key.startsWith(`${this.model}\0`) && stored.payload["userCode"] === userCode) {
        return structuredClone(stored.payload);
      }
    }
    return undefined;
  }

  public async revokeByGrantId(grantId: string): Promise<void> {
    for (const [key, stored] of DurableTestAdapter.artifacts) {
      if (key.startsWith(`${this.model}\0`) && stored.payload["grantId"] === grantId) {
        DurableTestAdapter.artifacts.delete(key);
      }
    }
  }
}

let privateJwk: Readonly<Record<string, unknown>>;
const activeServers: Server[] = [];

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  privateJwk = {
    ...(await exportJWK(privateKey)),
    kid: "oauth-es256-1",
    use: "sig",
    alg: "ES256"
  };
});

beforeEach(() => {
  DurableTestAdapter.artifacts.clear();
  DurableTestAdapter.models.clear();
});

afterEach(async () => {
  await Promise.all(
    activeServers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve()))
          )
      )
  );
});

function provider(overrides: Partial<Parameters<typeof createBoardAgentOAuthProvider>[0]> = {}) {
  return createBoardAgentOAuthProvider({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    scopes: SCOPES,
    clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT_URI] }],
    privateJwk,
    cookieKeys: ["c".repeat(32), "d".repeat(32)],
    adapter: DurableTestAdapter,
    ...overrides
  });
}

async function listen(
  runtime: BoardAgentOAuthProvider,
  interactionHandler?: (request: IncomingMessage, response: ServerResponse) => Promise<void>,
  proxyBoundary?: AuthRequestBoundary
): Promise<URL> {
  const callback = runtime.callback();
  const server = createServer((request, response) => {
    if (proxyBoundary) {
      // Real unencrypted upstream transport: exactly the boundary the HTTP runtime
      // applies before OAuth. Do not rewrite headers or pretend this socket is TLS.
      try {
        proxyBoundary.inspect(request, { stateChanging: false });
      } catch {
        response.writeHead(400);
        response.end();
        return;
      }
    } else {
      // Existing direct-TLS unit fixture. The proxy cases below intentionally do
      // not use this simulation, since it hides TLS-offload integration defects.
      Object.defineProperty(request.socket, "encrypted", {
        configurable: true,
        value: true
      });
      request.headers.host = new URL(runtime.issuer).host;
    }
    if (request.url?.startsWith("/auth/interactions/") && interactionHandler) {
      void interactionHandler(request, response).catch((error: unknown) => {
        response.statusCode = 500;
        response.end(error instanceof Error ? error.message : "interaction failed");
      });
      return;
    }
    callback(request, response);
  });
  activeServers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("OAuth test server has no port");
  return new URL(`http://127.0.0.1:${String(address.port)}`);
}

class TestCookieJar {
  private readonly values = new Map<string, string>();

  public add(response: Response): void {
    const headers = response.headers as Headers & { getSetCookie?: () => string[] };
    const setCookies = headers.getSetCookie?.() ?? [response.headers.get("set-cookie") ?? ""];
    for (const setCookie of setCookies) {
      const pair = setCookie.split(";", 1)[0];
      const separator = pair?.indexOf("=") ?? -1;
      if (!pair || separator <= 0) continue;
      this.values.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
  }

  public header(): string {
    return [...this.values.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

async function fetchWithCookies(
  jar: TestCookieJar,
  url: URL,
  init: RequestInit = {},
  forwardedHeaders?: Readonly<Record<string, string>>
): Promise<Response> {
  const headers = new Headers(init.headers);
  const cookie = jar.header();
  if (cookie !== "") headers.set("cookie", cookie);
  const response = forwardedHeaders
    ? await proxyHttpRequest(url, { ...forwardedHeaders, ...Object.fromEntries(headers) })
    : await fetch(url, { ...init, headers, redirect: "manual" });
  jar.add(response);
  return response;
}

function authorizationUrl(base: URL, changes: Readonly<Record<string, string | null>> = {}): URL {
  const url = new URL("/authorize", base);
  const params: Record<string, string> = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "documents:read governance:read",
    state: "state-0123456789abcdef",
    code_challenge: PKCE_CHALLENGE,
    code_challenge_method: "S256",
    resource: RESOURCE
  };
  for (const [key, value] of Object.entries(changes)) {
    if (value === null) delete params[key];
    else params[key] = value;
  }
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url;
}

function oauthRedirectError(response: Response): URL {
  const location = response.headers.get("location");
  if (!location) throw new Error("OAuth response did not redirect");
  return new URL(location, REDIRECT_URI);
}

function oauthError(url: URL): string | null {
  return (
    url.searchParams.get("error") ??
    new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash).get("error")
  );
}

describe("BoardAgent OAuth authorization server", () => {
  const proxyHeaders = {
    host: "boardagent.test",
    "x-forwarded-for": "198.51.100.55",
    "x-forwarded-proto": "https",
    "x-forwarded-host": "boardagent.test"
  };

  it("publishes HTTPS endpoints over actual HTTP from the validated TLS-offload proxy", async () => {
    const base = await listen(
      provider(),
      undefined,
      new AuthRequestBoundary({ origin: ISSUER, trustedProxyHops: 1 })
    );
    const response = await proxyHttpRequest(
      new URL("/.well-known/openid-configuration", base),
      proxyHeaders
    );
    expect(response.status).toBe(200);
    const metadata = (await response.json()) as Record<string, unknown>;
    expect(metadata).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`
    });
    for (const [key, value] of Object.entries(metadata)) {
      if (key.endsWith("_endpoint") || key === "jwks_uri") {
        expect(new URL(String(value)).origin).toBe(ISSUER);
      }
    }
  });

  it("starts authorization with secure cookies through the validated TLS-offload proxy", async () => {
    const base = await listen(
      provider(),
      undefined,
      new AuthRequestBoundary({ origin: ISSUER, trustedProxyAddresses: ["127.0.0.1"] })
    );
    const response = await proxyHttpRequest(authorizationUrl(base), proxyHeaders);
    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).toMatch(/^\/auth\/interactions\/[A-Za-z0-9_-]+$/u);
    expect(new URL(location!, ISSUER).origin).toBe(ISSUER);
    const cookies = response.headers.getSetCookie();
    expect(cookies.length).toBeGreaterThan(0);
    for (const cookie of cookies) {
      expect(cookie.toLowerCase()).toContain("secure");
      expect(cookie.toLowerCase()).toContain("httponly");
      expect(cookie.toLowerCase()).toContain("samesite=lax");
    }
    expect([...DurableTestAdapter.artifacts.values()]).toContainEqual(
      expect.objectContaining({ payload: expect.objectContaining({ kind: "Interaction" }) })
    );
  });

  it.each([
    { "x-forwarded-proto": "http" },
    { "x-forwarded-proto": "https, http" },
    { "x-forwarded-host": "attacker.test" },
    { "x-forwarded-port": "80" },
    { "x-forwarded-for": "198.51.100.55, 198.51.100.56" },
    { host: "attacker.test" },
    { forwarded: "proto=https;host=attacker.test" }
  ])("refuses invalid forwarding before OAuth can create an interaction: %j", async (headers) => {
    const base = await listen(
      provider(),
      undefined,
      new AuthRequestBoundary({ origin: ISSUER, trustedProxyHops: 1 })
    );
    const response = await proxyHttpRequest(authorizationUrl(base), {
      ...proxyHeaders,
      ...headers
    });
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(DurableTestAdapter.artifacts.size).toBe(0);
  });

  it("refuses forwarded HTTPS when no proxy is trusted", async () => {
    const base = await listen(provider(), undefined, new AuthRequestBoundary({ origin: ISSUER }));
    const response = await proxyHttpRequest(authorizationUrl(base), proxyHeaders);
    expect(response.status).toBe(400);
    expect(DurableTestAdapter.artifacts.size).toBe(0);
  });

  it("publishes only the frozen authorization-code, refresh and S256 surface", async () => {
    const base = await listen(provider());
    const response = await fetch(new URL("/.well-known/openid-configuration", base));
    expect(response.status).toBe(200);
    const metadata = (await response.json()) as Record<string, unknown>;
    expect(metadata).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"]
    });
    expect(metadata).not.toHaveProperty("device_authorization_endpoint");
    expect(metadata).not.toHaveProperty("registration_endpoint");

    const keys = (await (await fetch(new URL("/jwks", base))).json()) as {
      keys: Array<Record<string, unknown>>;
    };
    expect(keys.keys).toEqual([
      expect.objectContaining({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig" })
    ]);
    expect(keys.keys[0]).not.toHaveProperty("d");
  });

  it("accepts one exact resource-bound S256 request into the custom interaction", async () => {
    const base = await listen(provider());
    const response = await fetch(authorizationUrl(base), { redirect: "manual" });
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toMatch(/^\/auth\/interactions\/[A-Za-z0-9_-]+$/u);
    const cookies = response.headers.get("set-cookie") ?? "";
    expect(cookies.toLowerCase()).toContain("secure");
    expect(cookies.toLowerCase()).toContain("httponly");
    expect(cookies.toLowerCase()).toContain("samesite=lax");
    expect(DurableTestAdapter.models).toContain("Interaction");
    const interaction = [...DurableTestAdapter.artifacts.values()].find(
      ({ payload }) => payload["kind"] === "Interaction"
    );
    expect(interaction?.payload).toMatchObject({
      params: {
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        code_challenge_method: "S256",
        resource: RESOURCE
      }
    });
    expect((interaction?.expiresAt ?? 0) - Date.now()).toBeLessThanOrEqual(600_000);
  });

  it.each([
    ["missing state", { state: null }, "invalid_request"],
    ["short state", { state: "short" }, "invalid_request"],
    ["missing resource", { resource: null }, "invalid_target"],
    ["other resource", { resource: "https://other.test/mcp" }, "invalid_target"],
    ["plain PKCE", { code_challenge_method: "plain" }, "invalid_request"],
    ["implicit response", { response_type: "token" }, "unsupported_response_type"]
  ])("rejects %s without opening an interaction", async (_label, changes, error) => {
    const base = await listen(provider());
    const response = await fetch(authorizationUrl(base, changes), { redirect: "manual" });
    expect(response.status).toBe(303);
    expect(oauthError(oauthRedirectError(response))).toBe(error);
    expect(DurableTestAdapter.artifacts.size).toBe(0);
  });

  it("never redirects a malformed request to an unregistered URI", async () => {
    const base = await listen(provider());
    const response = await fetch(
      authorizationUrl(base, { redirect_uri: "https://attacker.test/callback" }),
      { redirect: "manual" }
    );
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_redirect_uri" });
  });

  it.each(["direct TLS", "validated TLS-offload proxy"] as const)(
    "completes login, explicit consent and one-use S256 code exchange through %s",
    async (transport) => {
      const viaProxy = transport === "validated TLS-offload proxy";
      const runtime = provider();
      const base = await listen(
        runtime,
        async (request, response) => {
          await runtime.approveInteraction(request, response, { memberId: MEMBER_ID });
        },
        viaProxy ? new AuthRequestBoundary({ origin: ISSUER, trustedProxyHops: 1 }) : undefined
      );
      const jar = new TestCookieJar();
      const challenge = createHash("sha256").update(PKCE_VERIFIER).digest("base64url");
      let response = await fetchWithCookies(
        jar,
        authorizationUrl(base, { code_challenge: challenge }),
        {},
        viaProxy ? proxyHeaders : undefined
      );
      let callback: URL | undefined;
      for (let redirects = 0; redirects < 8; redirects += 1) {
        expect(response.status).toBe(303);
        const location = response.headers.get("location");
        if (!location) throw new Error("OAuth continuation has no location");
        const target = new URL(location, ISSUER);
        if (target.origin === new URL(REDIRECT_URI).origin) {
          callback = target;
          break;
        }
        expect(target.origin).toBe(ISSUER);
        response = await fetchWithCookies(
          jar,
          new URL(`${target.pathname}${target.search}`, base),
          {},
          viaProxy ? proxyHeaders : undefined
        );
      }
      expect(callback?.searchParams.get("state")).toBe("state-0123456789abcdef");
      const code = callback?.searchParams.get("code");
      expect(code).toBeTruthy();

      const exchange = async () => {
        const body = new URLSearchParams({
          grant_type: "authorization_code",
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          code: code!,
          code_verifier: PKCE_VERIFIER,
          resource: RESOURCE
        }).toString();
        const headers = { "content-type": "application/x-www-form-urlencoded" };
        return viaProxy
          ? proxyHttpRequest(
              new URL("/token", base),
              { ...proxyHeaders, ...headers },
              { method: "POST", body }
            )
          : fetch(new URL("/token", base), { method: "POST", headers, body });
      };
      const tokenResponse = await exchange();
      expect(tokenResponse.status).toBe(200);
      const tokenBody = await tokenResponse.json();
      expect(tokenBody).toMatchObject({
        token_type: "Bearer",
        expires_in: 900,
        scope: "documents:read governance:read"
      });
      expect(tokenBody).toMatchObject({
        access_token: expect.any(String),
        refresh_token: expect.any(String)
      });
      expect([...DurableTestAdapter.models]).toEqual(
        expect.arrayContaining(["Interaction", "Session", "Grant", "AuthorizationCode"])
      );

      const replay = await exchange();
      expect(replay.status).toBe(400);
      await expect(replay.json()).resolves.toMatchObject({ error: "invalid_grant" });
    }
  );

  it.each(["client_credentials", "password", "urn:ietf:params:oauth:grant-type:device_code"])(
    "rejects the disabled %s grant",
    async (grantType) => {
      const base = await listen(provider());
      const response = await fetch(new URL("/token", base), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: grantType,
          client_id: CLIENT_ID,
          resource: RESOURCE
        })
      });
      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toMatchObject({ error: "unsupported_grant_type" });
      expect(DurableTestAdapter.artifacts.size).toBe(0);
    }
  );

  it("fails closed on issuer/resource/key/cookie/client configuration drift", () => {
    expect(() => provider({ issuer: "http://boardagent.test" })).toThrow(/HTTPS origin/u);
    expect(() => provider({ resourceUri: `${ISSUER}/mcp/` })).toThrow(/canonical resource/u);
    expect(() => provider({ privateJwk: { ...privateJwk, alg: "RS256" } })).toThrow();
    expect(() => provider({ cookieKeys: ["x".repeat(32)] })).toThrow(/at least two/u);
    expect(() =>
      provider({
        clients: [
          { clientId: CLIENT_ID, redirectUris: [REDIRECT_URI] },
          { clientId: CLIENT_ID, redirectUris: [REDIRECT_URI] }
        ]
      })
    ).toThrow(/duplicates/u);
  });
});
