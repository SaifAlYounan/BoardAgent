import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";

import {
  createBoardAgentOAuthProvider,
  type BoardAgentOAuthProvider,
  type OidcProviderAdapter
} from "../../artifacts/server/src/oauth-authorization-server.js";

const ISSUER = "https://boardagent.test";
const RESOURCE = `${ISSUER}/mcp`;
const CLIENT_ID = "https://portable-client.test/client.json";
const REDIRECT_URI = "https://portable-client.test/callback";
const MEMBER_ID = "018f0000-0000-7000-8000-000000000701";
const VERIFIER = "v".repeat(43);

interface StoredArtifact {
  readonly payload: Readonly<Record<string, unknown>>;
  readonly expiresAt: number;
}

class AttackAdapter implements OidcProviderAdapter {
  private static readonly records = new Map<string, StoredArtifact>();

  public static reset(): void {
    AttackAdapter.records.clear();
  }

  public constructor(private readonly model: string) {}

  private key(id: string): string {
    return `${this.model}\u0000${id}`;
  }

  public async upsert(
    id: string,
    payload: Readonly<Record<string, unknown>>,
    expiresIn: number
  ): Promise<void> {
    AttackAdapter.records.set(this.key(id), {
      payload: structuredClone(payload),
      expiresAt: Date.now() + expiresIn * 1_000
    });
  }

  public async find(id: string): Promise<Readonly<Record<string, unknown>> | undefined> {
    const stored = AttackAdapter.records.get(this.key(id));
    if (!stored || stored.expiresAt <= Date.now()) return undefined;
    return structuredClone(stored.payload);
  }

  public async destroy(id: string): Promise<void> {
    AttackAdapter.records.delete(this.key(id));
  }

  public async consume(id: string): Promise<void> {
    const stored = AttackAdapter.records.get(this.key(id));
    if (stored) {
      AttackAdapter.records.set(this.key(id), {
        ...stored,
        payload: { ...stored.payload, consumed: Math.floor(Date.now() / 1_000) }
      });
    }
  }

  public async findByUid(uid: string): Promise<Readonly<Record<string, unknown>> | undefined> {
    for (const [key, stored] of AttackAdapter.records) {
      if (key.startsWith(`${this.model}\u0000`) && stored.payload["uid"] === uid) {
        return structuredClone(stored.payload);
      }
    }
    return undefined;
  }

  public async findByUserCode(
    userCode: string
  ): Promise<Readonly<Record<string, unknown>> | undefined> {
    for (const [key, stored] of AttackAdapter.records) {
      if (key.startsWith(`${this.model}\u0000`) && stored.payload["userCode"] === userCode) {
        return structuredClone(stored.payload);
      }
    }
    return undefined;
  }

  public async revokeByGrantId(grantId: string): Promise<void> {
    for (const [key, stored] of AttackAdapter.records) {
      if (key.startsWith(`${this.model}\u0000`) && stored.payload["grantId"] === grantId) {
        AttackAdapter.records.delete(key);
      }
    }
  }
}

class CookieJar {
  private readonly values = new Map<string, string>();

  public add(response: Response): void {
    const headers = response.headers as Headers & { getSetCookie?: () => string[] };
    for (const value of headers.getSetCookie?.() ?? [response.headers.get("set-cookie") ?? ""]) {
      const pair = value.split(";", 1)[0];
      const separator = pair?.indexOf("=") ?? -1;
      if (pair && separator > 0)
        this.values.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
  }

  public header(): string {
    return [...this.values].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

function authorizationUrl(base: URL, changes: Readonly<Record<string, string>> = {}): URL {
  const url = new URL("/authorize", base);
  const challenge = createHash("sha256").update(VERIFIER).digest("base64url");
  const values = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "documents:read governance:read",
    state: "oauth-attack-state-0123456789",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
    ...changes
  };
  for (const [name, value] of Object.entries(values)) url.searchParams.set(name, value);
  return url;
}

async function listen(runtime: BoardAgentOAuthProvider): Promise<{
  readonly base: URL;
  close(): Promise<void>;
}> {
  const callback = runtime.callback();
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    Object.defineProperty(request.socket, "encrypted", { configurable: true, value: true });
    request.headers.host = new URL(runtime.issuer).host;
    if (request.url?.startsWith("/auth/interactions/")) {
      void runtime
        .approveInteraction(request, response, { memberId: MEMBER_ID })
        .catch((error: unknown) => {
          response.statusCode = 500;
          response.end(error instanceof Error ? error.message : "interaction failed");
        });
      return;
    }
    callback(request, response);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("OAuth attack server has no port");
  return {
    base: new URL(`http://127.0.0.1:${String(address.port)}`),
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      )
  };
}

async function fetchWithJar(jar: CookieJar, url: URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const cookie = jar.header();
  if (cookie) headers.set("cookie", cookie);
  const response = await fetch(url, { ...init, headers, redirect: "manual" });
  jar.add(response);
  return response;
}

describe("TH-07 OAuth flow confusion", () => {
  it("binds redirect, resource, S256 and a one-use code while refusing alternate grants", async () => {
    AttackAdapter.reset();
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    const runtime = createBoardAgentOAuthProvider({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      scopes: ["documents:read", "governance:read", "vote:act"],
      clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT_URI] }],
      privateJwk: {
        ...(await exportJWK(privateKey)),
        kid: "oauth-attack-key",
        use: "sig",
        alg: "ES256"
      },
      cookieKeys: ["c".repeat(32), "d".repeat(32)],
      adapter: AttackAdapter
    });
    const server = await listen(runtime);
    try {
      const wrongRedirect = await fetch(
        authorizationUrl(server.base, { redirect_uri: "https://attacker.test/callback" }),
        { redirect: "manual" }
      );
      expect(wrongRedirect.status).toBe(400);
      expect(wrongRedirect.headers.get("location")).toBeNull();

      for (const changes of [
        { resource: "https://other.test/mcp" },
        { code_challenge_method: "plain" }
      ]) {
        const refused = await fetch(authorizationUrl(server.base, changes), { redirect: "manual" });
        expect(refused.status).toBe(303);
        const location = refused.headers.get("location");
        if (!location) throw new Error("OAuth refusal has no registered redirect");
        expect(new URL(location).origin).toBe(new URL(REDIRECT_URI).origin);
        expect(new URL(location).searchParams.get("error")).toMatch(/invalid_(?:request|target)/u);
      }

      const jar = new CookieJar();
      let response = await fetchWithJar(jar, authorizationUrl(server.base));
      let callback: URL | null = null;
      for (let redirects = 0; redirects < 8; redirects += 1) {
        expect(response.status).toBe(303);
        const location = response.headers.get("location");
        if (!location) throw new Error("OAuth continuation has no location");
        const target = new URL(location, ISSUER);
        if (target.origin === new URL(REDIRECT_URI).origin) {
          callback = target;
          break;
        }
        response = await fetchWithJar(
          jar,
          new URL(`${target.pathname}${target.search}`, server.base)
        );
      }
      const code = callback?.searchParams.get("code");
      expect(code).toBeTruthy();
      const exchange = () =>
        fetch(new URL("/token", server.base), {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            code: code!,
            code_verifier: VERIFIER,
            resource: RESOURCE
          })
        });
      expect((await exchange()).status).toBe(200);
      const replay = await exchange();
      expect(replay.status).toBe(400);
      await expect(replay.json()).resolves.toMatchObject({ error: "invalid_grant" });

      const disabled = await fetch(new URL("/token", server.base), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: CLIENT_ID,
          resource: RESOURCE
        })
      });
      expect(disabled.status).toBe(400);
      await expect(disabled.json()).resolves.toMatchObject({ error: "unsupported_grant_type" });
    } finally {
      await server.close();
    }
  });
});
