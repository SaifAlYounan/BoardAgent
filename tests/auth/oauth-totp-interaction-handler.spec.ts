import { createServer, request, type IncomingMessage, type RequestListener } from "node:http";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AuthRequestBoundary,
  createBoardAgentOAuthInteractionHandler,
  type BoardAgentOAuthProvider,
  type OidcInteractionBinding,
  type OidcInteractionBindingStore
} from "../../artifacts/server/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

const INTERACTION_UID = Buffer.alloc(24, 0xe1).toString("base64url");
const CSRF_TOKEN = Buffer.alloc(32, 0xe2).toString("base64url");
const FALLBACK_HANDLE = Buffer.alloc(32, 0xe3).toString("base64url");
const ORGANIZATION_ID = testId(71_001);
const SESSION_ID = testId(71_002);
const CLIENT_ID = testId(71_003);
const MEMBER_ID = testId(71_004);
const RESOURCE = "https://boardagent.test/mcp";
const openServers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(
    openServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.closeAllConnections();
          server.close((error) => (error ? reject(error) : resolve()));
        })
    )
  );
});

async function send(
  port: number,
  path: string,
  body?: URLSearchParams
): Promise<{
  readonly body: string;
  readonly headers: IncomingMessage["headers"];
  readonly status: number;
}> {
  const serialized = body?.toString();
  return new Promise((resolve, reject) => {
    const outbound = request(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: serialized === undefined ? "GET" : "POST",
        headers: {
          host: "localhost",
          ...(serialized === undefined
            ? {}
            : {
                origin: "http://localhost",
                "sec-fetch-site": "same-origin",
                "content-type": "application/x-www-form-urlencoded",
                "content-length": String(Buffer.byteLength(serialized))
              })
        }
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.once("end", () =>
          resolve({
            body: Buffer.concat(chunks).toString("utf8"),
            headers: response.headers,
            status: response.statusCode ?? 0
          })
        );
      }
    );
    outbound.once("error", reject);
    if (serialized !== undefined) outbound.write(serialized);
    outbound.end();
  });
}

function fixture(includeTotp: boolean): {
  readonly port: Promise<number>;
  readonly authenticate: ReturnType<typeof vi.fn>;
  readonly approvals: string[];
} {
  const approvals: string[] = [];
  const binding: OidcInteractionBinding = {
    interactionUid: INTERACTION_UID,
    authorizationRequestId: testId(71_005),
    sessionId: SESSION_ID,
    clientId: CLIENT_ID,
    protocolClientId: "https://portable-client.test/client.json",
    clientDisplayName: "Portable client",
    resourceUri: RESOURCE,
    scopes: ["documents:read"],
    csrfToken: CSRF_TOKEN,
    expiresAt: new Date(Date.now() + 300_000)
  };
  const bindingStore: OidcInteractionBindingStore = {
    load: async () => binding,
    verifyCsrf: (candidate, token) => {
      if (candidate !== binding || token !== CSRF_TOKEN) throw new Error("CSRF rejected");
    }
  };
  const provider: BoardAgentOAuthProvider = {
    issuer: "https://boardagent.test",
    resourceUri: RESOURCE,
    callback: () => {
      throw new Error("provider callback is outside this fixture");
    },
    interactionDetails: async () =>
      ({
        uid: INTERACTION_UID,
        prompt: { name: "login", reasons: [], details: {} },
        params: {
          client_id: binding.protocolClientId,
          resource: RESOURCE,
          scope: "documents:read"
        }
      }) as never,
    approveInteraction: async (_request, responseValue, input) => {
      approvals.push(input.memberId);
      const response = responseValue as import("node:http").ServerResponse;
      response.writeHead(303, { location: "/approved" });
      response.end();
    },
    denyInteraction: async (_request, responseValue) => {
      const response = responseValue as import("node:http").ServerResponse;
      response.writeHead(303, { location: "/denied" });
      response.end();
    }
  };
  const authenticate = vi.fn(async () => ({
    memberId: MEMBER_ID,
    credentialId: testId(71_006),
    acceptedStep: 1
  }));
  const handler: RequestListener = createBoardAgentOAuthInteractionHandler({
    organizationId: ORGANIZATION_ID,
    boundary: new AuthRequestBoundary({
      origin: "http://localhost",
      allowInsecureLoopbackDevelopment: true
    }),
    provider,
    bindingStore,
    webauthn: {
      beginAuthentication: () => {
        throw new Error("passkey is outside this fixture");
      },
      completeAuthentication: () => {
        throw new Error("passkey is outside this fixture");
      }
    },
    ...(includeTotp ? { totp: { authenticate } } : {}),
    includeHsts: false
  });
  const server = createServer(handler);
  openServers.push(server);
  const port = new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") reject(new Error("test server has no port"));
      else resolve(address.port);
    });
  });
  return { port, authenticate, approvals };
}

describe("BoardAgent OAuth TOTP interaction controller", () => {
  it("renders fallback only when configured and binds the exact protected submission", async () => {
    const setup = fixture(true);
    const port = await setup.port;
    const basePath = `/auth/interactions/${INTERACTION_UID}`;
    const login = await send(port, basePath);
    expect(login.status).toBe(200);
    expect(login.body).toContain("data-passkey-button");
    expect(login.body).toContain("data-totp-fallback-link");
    expect(login.body).not.toContain('name="code"');

    const fallback = await send(port, `${basePath}/totp`);
    expect(fallback.status).toBe(200);
    expect(fallback.body).toContain('name="fallback_handle"');
    expect(fallback.body).toContain('name="code"');
    expect(fallback.body).not.toContain('type="password"');

    const malformed = await send(
      port,
      `${basePath}/totp/complete`,
      new URLSearchParams({
        csrf_token: CSRF_TOKEN,
        fallback_handle: FALLBACK_HANDLE,
        code: "123456",
        member_id: MEMBER_ID
      })
    );
    expect(malformed.status).toBe(400);
    expect(setup.authenticate).not.toHaveBeenCalled();

    const accepted = await send(
      port,
      `${basePath}/totp/complete`,
      new URLSearchParams({
        csrf_token: CSRF_TOKEN,
        fallback_handle: FALLBACK_HANDLE,
        code: "123456"
      })
    );
    expect(accepted.status).toBe(303);
    expect(accepted.headers.location).toBe("/approved");
    expect(setup.authenticate).toHaveBeenCalledWith({
      organizationId: ORGANIZATION_ID,
      sessionId: SESSION_ID,
      clientId: CLIENT_ID,
      clientIpClass: "ipv4:127.0.0.0/24",
      fallbackHandle: FALLBACK_HANDLE,
      code: "123456"
    });
    expect(setup.approvals).toEqual([MEMBER_ID]);
  });

  it("does not expose or accept the fallback route when TOTP is unavailable", async () => {
    const setup = fixture(false);
    const port = await setup.port;
    const basePath = `/auth/interactions/${INTERACTION_UID}`;
    const login = await send(port, basePath);
    expect(login.status).toBe(200);
    expect(login.body).not.toContain("data-totp-fallback-link");
    const fallback = await send(port, `${basePath}/totp`);
    expect(fallback.status).toBe(400);
    expect(fallback.body).toBe('{"error":"invalid_auth_request"}');
  });
});
