import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type McpHandlerRequestOptions,
  type McpHttpHandler,
  type OAuthTokenVerifier
} from "@modelcontextprotocol/server";
import { describe, expect, it, vi } from "vitest";

import { createProtectedMcpHandler } from "../../artifacts/server/src/protected-mcp.js";

const RESOURCE = "https://boardagent.test/mcp";
const MEMBER_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";

function activeAuthInfo(token = "active-token"): AuthInfo {
  return {
    token,
    clientId: "https://agent.test/client.json",
    scopes: ["governance:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 900,
    resource: new URL(RESOURCE),
    extra: { memberId: MEMBER_ID }
  };
}

function fixture(overrides: Partial<OAuthTokenVerifier> = {}) {
  const downstreamFetch = vi.fn<
    (request: Request, options?: McpHandlerRequestOptions) => Promise<Response>
  >(async () => Response.json({ accepted: true }));
  const verifier: OAuthTokenVerifier = {
    verifyAccessToken: vi.fn(async (token) => {
      if (token !== "active-token") {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "private ledger reason");
      }
      return activeAuthInfo(token);
    }),
    ...overrides
  };
  const downstream = {
    fetch: downstreamFetch,
    close: vi.fn(async () => undefined),
    notify: {} as McpHttpHandler["notify"],
    bus: {} as McpHttpHandler["bus"]
  } satisfies McpHttpHandler;
  const handler = createProtectedMcpHandler({
    handler: downstream,
    resourceUri: RESOURCE,
    verifier
  });
  return { downstream, downstreamFetch, handler, verifier };
}

async function rejection(
  handler: McpHttpHandler,
  request: Request
): Promise<{ readonly body: unknown; readonly challenge: string | null; readonly status: number }> {
  const response = await handler.fetch(request, { authInfo: activeAuthInfo("forged-bypass") });
  return {
    body: await response.json(),
    challenge: response.headers.get("www-authenticate"),
    status: response.status
  };
}

describe("protected MCP HTTP boundary", () => {
  it("makes missing, malformed, query-only, and invalid credentials indistinguishable", async () => {
    const { downstreamFetch, handler } = fixture();
    const attempts = [
      new Request(RESOURCE, { method: "POST" }),
      new Request(RESOURCE, { method: "POST", headers: { authorization: "Basic abc" } }),
      new Request(`${RESOURCE}?access_token=active-token`, { method: "POST" }),
      new Request(RESOURCE, {
        method: "POST",
        headers: { authorization: "Bearer unknown-token" }
      }),
      new Request(RESOURCE, {
        method: "POST",
        headers: { authorization: "Bearer active-token extra" }
      })
    ];

    const rejected = await Promise.all(attempts.map((request) => rejection(handler, request)));
    expect(rejected).toEqual(
      Array.from({ length: attempts.length }, () => ({
        body: { error: "invalid_token", error_description: "Bearer token is invalid" },
        challenge:
          'Bearer error="invalid_token", error_description="Bearer token is invalid", resource_metadata="https://boardagent.test/.well-known/oauth-protected-resource/mcp"',
        status: 401
      }))
    );
    expect(downstreamFetch).not.toHaveBeenCalled();
  });

  it("forwards only verifier-produced auth context and preserves the handler lifecycle", async () => {
    const { downstream, downstreamFetch, handler } = fixture();
    const request = new Request(RESOURCE, {
      method: "POST",
      headers: { authorization: "Bearer active-token" }
    });
    const response = await handler.fetch(request, { authInfo: activeAuthInfo("forged-bypass") });

    expect(response.status).toBe(200);
    expect(downstreamFetch).toHaveBeenCalledOnce();
    expect(downstreamFetch.mock.calls[0]?.[1]?.authInfo).toEqual(activeAuthInfo());
    expect(handler.notify).toBe(downstream.notify);
    expect(handler.bus).toBe(downstream.bus);
    await handler.close();
    expect(downstream.close).toHaveBeenCalledOnce();
  });

  it("rejects a valid token bound to another resource before MCP dispatch", async () => {
    const verifier: OAuthTokenVerifier = {
      verifyAccessToken: vi.fn(async (token) => ({
        ...activeAuthInfo(token),
        resource: new URL("https://boardagent.test/other")
      }))
    };
    const { downstreamFetch, handler } = fixture(verifier);
    const rejected = await rejection(
      handler,
      new Request(RESOURCE, {
        method: "POST",
        headers: { authorization: "Bearer active-token" }
      })
    );

    expect(rejected.status).toBe(401);
    expect(rejected.body).toEqual({
      error: "invalid_token",
      error_description: "Bearer token is invalid"
    });
    expect(downstreamFetch).not.toHaveBeenCalled();
  });

  it("rejects construction unless the canonical resource is an exact origin plus path", () => {
    const { downstream, verifier } = fixture();
    expect(() =>
      createProtectedMcpHandler({
        handler: downstream,
        resourceUri: `${RESOURCE}?tenant=guessable`,
        verifier
      })
    ).toThrow("canonical MCP resource URI");
  });
});
