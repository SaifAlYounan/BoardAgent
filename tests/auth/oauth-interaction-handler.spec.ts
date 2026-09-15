import {
  createServer,
  request,
  type IncomingMessage,
  type RequestOptions,
  type Server
} from "node:http";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AuthRequestBoundary,
  createBoardAgentOAuthInteractionHandler,
  type BoardAgentOAuthProvider,
  type OidcInteractionBinding,
  type OidcInteractionBindingStore,
  WebAuthnCeremonyError
} from "../../artifacts/server/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

const INTERACTION_UID = Buffer.alloc(24, 0x91).toString("base64url");
const CSRF_TOKEN = Buffer.alloc(32, 0x92).toString("base64url");
const CREDENTIAL_ID = Buffer.alloc(32, 0x93).toString("base64url");
const ORGANIZATION_ID = testId(66_001);
const SESSION_ID = testId(66_002);
const CLIENT_ID = testId(66_003);
const MEMBER_ID = testId(66_004);
const RESOURCE = "https://boardagent.test/mcp";
const CLIENT_PROTOCOL_ID = "https://portable-client.test/client.json";
const openServers: Server[] = [];

const credential = {
  id: CREDENTIAL_ID,
  rawId: CREDENTIAL_ID,
  response: {
    clientDataJSON: Buffer.from("client-data").toString("base64url"),
    authenticatorData: Buffer.from("authenticator-data").toString("base64url"),
    signature: Buffer.from("signature").toString("base64url"),
    userHandle: null
  },
  type: "public-key",
  clientExtensionResults: {},
  authenticatorAttachment: "platform"
} as const;

afterEach(async () => {
  await Promise.all(
    openServers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve()))
          )
      )
  );
});

async function httpRequest(
  port: number,
  options: RequestOptions & { readonly body?: string }
): Promise<{
  readonly body: string;
  readonly headers: IncomingMessage["headers"];
  readonly status: number;
}> {
  return new Promise((resolve, reject) => {
    const outbound = request(
      {
        hostname: "127.0.0.1",
        port,
        method: options.method ?? "GET",
        path: options.path,
        headers: { host: "localhost", ...options.headers }
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
    if (options.body !== undefined) outbound.write(options.body);
    outbound.end();
  });
}

function postOptions(
  path: string,
  body: URLSearchParams
): RequestOptions & { readonly body: string } {
  const serialized = body.toString();
  return {
    method: "POST",
    path,
    headers: {
      origin: "http://localhost",
      "sec-fetch-site": "same-origin",
      "content-type": "application/x-www-form-urlencoded; charset=utf-8",
      "content-length": String(Buffer.byteLength(serialized))
    },
    body: serialized
  };
}

function fixture(): {
  readonly port: Promise<number>;
  readonly phase: { value: "login" | "consent" };
  readonly approvals: string[];
  readonly denials: number[];
  readonly beginAuthentication: ReturnType<typeof vi.fn>;
  readonly completeAuthentication: ReturnType<typeof vi.fn>;
  readonly oidcStart: ReturnType<typeof vi.fn>;
  readonly oidcCallback: ReturnType<typeof vi.fn>;
  readonly oidcConsumeCompletion: ReturnType<typeof vi.fn>;
  readonly onInteractionFailure: ReturnType<typeof vi.fn<(failure: Error) => void>>;
} {
  const phase: { value: "login" | "consent" } = { value: "login" };
  const approvals: string[] = [];
  const denials: number[] = [];
  const binding: OidcInteractionBinding = {
    interactionUid: INTERACTION_UID,
    authorizationRequestId: testId(66_005),
    sessionId: SESSION_ID,
    clientId: CLIENT_ID,
    protocolClientId: CLIENT_PROTOCOL_ID,
    clientDisplayName: `<img src=x onerror="pwned()"> Portable client`,
    resourceUri: RESOURCE,
    scopes: ["documents:read", "governance:read"],
    csrfToken: CSRF_TOKEN,
    expiresAt: new Date("2026-09-02T12:00:00Z")
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
        prompt: { name: phase.value, reasons: [], details: {} },
        params: {
          client_id: CLIENT_PROTOCOL_ID,
          resource: RESOURCE,
          scope: "documents:read governance:read"
        },
        ...(phase.value === "consent" ? { session: { accountId: MEMBER_ID } } : {})
      }) as never,
    approveInteraction: async (_incoming, responseValue, input) => {
      approvals.push(input.memberId);
      const response = responseValue as import("node:http").ServerResponse;
      response.writeHead(303, { location: "/authorize/continued" });
      response.end();
    },
    denyInteraction: async (_incoming, responseValue) => {
      denials.push(1);
      const response = responseValue as import("node:http").ServerResponse;
      response.writeHead(303, { location: "/authorize/denied" });
      response.end();
    }
  };
  const beginAuthentication = vi.fn(
    async () =>
      ({
        challenge: Buffer.alloc(32, 0x94).toString("base64url"),
        timeout: 60_000,
        rpId: "localhost",
        userVerification: "required"
      }) as const
  );
  const completeAuthentication = vi.fn(async () => ({
    memberId: MEMBER_ID,
    sessionId: SESSION_ID,
    credentialId: testId(66_006),
    newCounter: 2,
    backupState: false
  }));
  const oidcStart = vi.fn(async () => ({
    location: "https://accounts.identity.test/authorize?state=opaque",
    setCookie:
      "__Secure-boardagent_upstream_test=sealed; Path=/auth/oidc/callback/google; Max-Age=600; HttpOnly; Secure; SameSite=Lax"
  }));
  const oidcCallback = vi.fn(async () => ({
    status: "authenticated" as const,
    location: `${`/auth/interactions/${INTERACTION_UID}`}/oidc/complete`,
    setCookie:
      "__Secure-boardagent_finish_test=opaque; " +
      `Path=/auth/interactions/${INTERACTION_UID}/oidc/complete; ` +
      "Max-Age=600; HttpOnly; Secure; SameSite=Lax"
  }));
  const oidcConsumeCompletion = vi.fn(async () => ({ memberId: MEMBER_ID }));
  const onInteractionFailure = vi.fn<(failure: Error) => void>();
  const handler = createBoardAgentOAuthInteractionHandler({
    organizationId: ORGANIZATION_ID,
    boundary: new AuthRequestBoundary({
      origin: "http://localhost",
      allowInsecureLoopbackDevelopment: true
    }),
    provider,
    bindingStore,
    webauthn: { beginAuthentication, completeAuthentication },
    oidc: {
      providers: [{ id: "google", label: 'Google <script id="unsafe">' }],
      start: oidcStart,
      callback: oidcCallback,
      consumeCompletion: oidcConsumeCompletion
    },
    includeHsts: false,
    onInteractionFailure
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
  return {
    port,
    phase,
    approvals,
    denials,
    beginAuthentication,
    completeAuthentication,
    oidcStart,
    oidcCallback,
    oidcConsumeCompletion,
    onInteractionFailure
  };
}

describe("BoardAgent OAuth passkey interaction controller", () => {
  it("authenticates through discoverable WebAuthn before approving the OAuth principal", async () => {
    const setup = fixture();
    const port = await setup.port;
    const basePath = `/auth/interactions/${INTERACTION_UID}`;

    const page = await httpRequest(port, { path: basePath });
    expect(page.status).toBe(200);
    expect(page.body).toContain("/auth/webauthn.js");
    expect(page.body).toContain("&lt;img src=x onerror=&quot;pwned()&quot;&gt;");
    expect(page.body).not.toContain("<img");
    expect(page.headers["content-security-policy"]).not.toMatch(/unsafe-inline|unsafe-eval/u);

    const browserScript = await httpRequest(port, { path: "/auth/webauthn.js" });
    expect(browserScript.status).toBe(200);
    expect(browserScript.headers["content-type"]).toBe("text/javascript; charset=utf-8");
    expect(browserScript.body).toContain("navigator.credentials.get");
    expect(browserScript.body).not.toMatch(/https?:\/\//u);

    const begin = await httpRequest(
      port,
      postOptions(`${basePath}/passkey/begin`, new URLSearchParams({ csrf_token: CSRF_TOKEN }))
    );
    expect(begin.status).toBe(200);
    expect(JSON.parse(begin.body)).toMatchObject({
      rpId: "localhost",
      userVerification: "required"
    });
    expect(setup.beginAuthentication).toHaveBeenCalledWith({
      organizationId: ORGANIZATION_ID,
      memberId: null,
      sessionId: SESSION_ID,
      purpose: "authentication"
    });

    const complete = await httpRequest(
      port,
      postOptions(
        `${basePath}/passkey/complete`,
        new URLSearchParams({
          csrf_token: CSRF_TOKEN,
          credential: JSON.stringify(credential)
        })
      )
    );
    expect(complete.status).toBe(303);
    expect(complete.headers.location).toBe("/authorize/continued");
    expect(setup.completeAuthentication).toHaveBeenCalledWith({
      organizationId: ORGANIZATION_ID,
      sessionId: SESSION_ID,
      purpose: "authentication",
      response: credential
    });
    expect(setup.approvals).toEqual([MEMBER_ID]);
  });

  it("renders exact consent, accepts only the provider session principal and rejects request confusion", async () => {
    const setup = fixture();
    const port = await setup.port;
    const basePath = `/auth/interactions/${INTERACTION_UID}`;
    setup.phase.value = "consent";

    const page = await httpRequest(port, { path: basePath });
    expect(page.status).toBe(200);
    expect(page.body).toContain("documents:read");
    expect(page.body).toContain("governance:read");
    expect(page.body).toContain("https://boardagent.test/mcp");

    const consent = await httpRequest(
      port,
      postOptions(`${basePath}/consent`, new URLSearchParams({ csrf_token: CSRF_TOKEN }))
    );
    expect(consent.status).toBe(303);
    expect(setup.approvals).toEqual([MEMBER_ID]);

    setup.phase.value = "login";
    const wrongCsrf = await httpRequest(
      port,
      postOptions(
        `${basePath}/passkey/begin`,
        new URLSearchParams({ csrf_token: Buffer.alloc(32, 0xff).toString("base64url") })
      )
    );
    expect(wrongCsrf).toMatchObject({
      status: 400,
      body: '{"error":"invalid_auth_request"}'
    });
    expect(setup.onInteractionFailure).toHaveBeenLastCalledWith(
      expect.objectContaining({
        name: "OAuthInteractionFailure",
        routeKind: "passkey_begin",
        reasonCode: "csrf_invalid",
        status: 400
      })
    );

    const injectedMember = await httpRequest(
      port,
      postOptions(
        `${basePath}/passkey/complete`,
        new URLSearchParams({
          csrf_token: CSRF_TOKEN,
          credential: JSON.stringify(credential),
          member_id: testId(66_999)
        })
      )
    );
    expect(injectedMember.status).toBe(400);
    expect(setup.completeAuthentication).not.toHaveBeenCalled();

    // A refused assertion is reported by route and ceremony reason, never by content.
    setup.completeAuthentication.mockRejectedValueOnce(
      new WebAuthnCeremonyError("verification_failed", "refused for the test")
    );
    const refusedAssertion = await httpRequest(
      port,
      postOptions(
        `${basePath}/passkey/complete`,
        new URLSearchParams({ csrf_token: CSRF_TOKEN, credential: JSON.stringify(credential) })
      )
    );
    expect(refusedAssertion).toMatchObject({
      status: 400,
      body: '{"error":"invalid_auth_request"}'
    });
    expect(setup.onInteractionFailure).toHaveBeenLastCalledWith(
      expect.objectContaining({
        routeKind: "passkey_complete",
        reasonCode: "webauthn_verification_failed",
        status: 400
      })
    );
    const reported = setup.onInteractionFailure.mock.lastCall?.[0];
    expect(reported).toBeInstanceOf(Error);
    expect((reported as Error).message).not.toContain(credential.id);

    const crossOrigin = await httpRequest(port, {
      ...postOptions(`${basePath}/cancel`, new URLSearchParams({ csrf_token: CSRF_TOKEN })),
      headers: {
        origin: "https://attacker.test",
        "sec-fetch-site": "cross-site",
        "content-type": "application/x-www-form-urlencoded"
      }
    });
    expect(crossOrigin.status).toBe(400);

    const queryConfusion = await httpRequest(port, {
      path: `${basePath}?return=https://attacker.test`
    });
    expect(queryConfusion.status).toBe(400);

    const cancel = await httpRequest(
      port,
      postOptions(`${basePath}/cancel`, new URLSearchParams({ csrf_token: CSRF_TOKEN }))
    );
    expect(cancel.status).toBe(303);
    expect(setup.denials).toEqual([1]);
  });

  it("federates through an upstream provider and consumes a one-use local completion", async () => {
    const setup = fixture();
    const port = await setup.port;
    const basePath = `/auth/interactions/${INTERACTION_UID}`;

    const page = await httpRequest(port, { path: basePath });
    expect(page.status).toBe(200);
    expect(page.body).toContain(`${basePath}/oidc/google/start`);
    expect(page.body).toContain("Google &lt;script id=&quot;unsafe&quot;&gt;");
    expect(page.body).not.toContain('<script id="unsafe">');

    const started = await httpRequest(
      port,
      postOptions(`${basePath}/oidc/google/start`, new URLSearchParams({ csrf_token: CSRF_TOKEN }))
    );
    expect(started.status).toBe(303);
    expect(started.headers.location).toBe("https://accounts.identity.test/authorize?state=opaque");
    expect(started.headers["set-cookie"]?.[0]).toContain("HttpOnly; Secure; SameSite=Lax");
    expect(setup.oidcStart).toHaveBeenCalledWith({
      providerId: "google",
      binding: expect.anything()
    });

    const callback = await httpRequest(port, {
      path: "/auth/oidc/callback/google?code=one-use-code&state=opaque&iss=https%3A%2F%2Faccounts.identity.test",
      headers: { cookie: "__Secure-boardagent_upstream_test=sealed" }
    });
    expect(callback.status).toBe(303);
    expect(callback.headers.location).toBe(`${basePath}/oidc/complete`);
    expect(setup.oidcCallback).toHaveBeenCalledWith({
      providerId: "google",
      currentUrl: new URL(
        "http://localhost/auth/oidc/callback/google?code=one-use-code&state=opaque&iss=https%3A%2F%2Faccounts.identity.test"
      ),
      cookieHeader: "__Secure-boardagent_upstream_test=sealed"
    });

    const finishPage = await httpRequest(port, {
      path: `${basePath}/oidc/complete`,
      headers: { cookie: "__Secure-boardagent_finish_test=opaque" }
    });
    expect(finishPage.status).toBe(200);
    expect(finishPage.body).toContain("Finish secure sign-in");
    expect(setup.oidcConsumeCompletion).not.toHaveBeenCalled();

    const finished = await httpRequest(port, {
      ...postOptions(`${basePath}/oidc/complete`, new URLSearchParams({ csrf_token: CSRF_TOKEN })),
      headers: {
        ...postOptions(`${basePath}/oidc/complete`, new URLSearchParams({ csrf_token: CSRF_TOKEN }))
          .headers,
        cookie: "__Secure-boardagent_finish_test=opaque"
      }
    });
    expect(finished.status).toBe(303);
    expect(finished.headers.location).toBe("/authorize/continued");
    expect(setup.oidcConsumeCompletion).toHaveBeenCalledWith({
      interactionUid: INTERACTION_UID,
      cookieHeader: "__Secure-boardagent_finish_test=opaque"
    });
    expect(setup.approvals).toEqual([MEMBER_ID]);
  });
});
