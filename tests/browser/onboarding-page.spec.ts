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
  BuiltinOnboardingCsrf,
  createBuiltinOnboardingHandler,
  type BuiltinOnboardingService
} from "../../artifacts/server/src/index.js";
import { authenticationResponse } from "./webauthn-harness.js";

const STAGE_TOKEN = Buffer.alloc(32, 0xd1).toString("base64url");
const MEMBER_ID = "018f0000-0000-7000-8000-000000000002";
const BOARD_ID = "018f0000-0000-7000-8000-000000000003";
const TERMS_ID = "018f0000-0000-7000-8000-000000000004";
const SUPPORT_ID = "018f0000-0000-7000-8000-000000000005";
const FORM_AUTHENTICATION_RESPONSE = {
  ...authenticationResponse,
  response: {
    clientDataJSON: Buffer.from("client-data").toString("base64url"),
    authenticatorData: Buffer.from("authenticator-data").toString("base64url"),
    signature: Buffer.from("signature-data").toString("base64url")
  }
} as const;
const openServers: Server[] = [];

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
        path: options.path ?? "/onboarding",
        headers: options.headers
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

function postHeaders(origin: string, body: string): Readonly<Record<string, string>> {
  return {
    host: new URL(origin).host,
    origin,
    "sec-fetch-site": "same-origin",
    "content-type": "application/x-www-form-urlencoded",
    "content-length": String(Buffer.byteLength(body))
  };
}

async function start(
  onboarding: Pick<BuiltinOnboardingService, "begin" | "complete">,
  csrf: BuiltinOnboardingCsrf
): Promise<{ readonly origin: string; readonly port: number }> {
  const server = createServer();
  openServers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("onboarding server has no port");
  const origin = `http://localhost:${String(address.port)}`;
  server.on(
    "request",
    createBuiltinOnboardingHandler({
      boundary: new AuthRequestBoundary({
        origin,
        allowInsecureLoopbackDevelopment: true
      }),
      onboarding,
      csrf,
      includeHsts: false
    })
  );
  return { origin, port: address.port };
}

describe("builtin onboarding browser controller", () => {
  it("authenticates a bounded 10-minute CSRF token and rejects tamper, expiry and rewind", () => {
    let now = new Date("2026-09-02T18:00:00Z");
    const csrf = new BuiltinOnboardingCsrf({
      key: Buffer.alloc(32, 0xa1),
      entropy: (length) => Buffer.alloc(length, 0xa2),
      now: () => now
    });
    const token = csrf.issue();
    expect(token).toHaveLength(96);
    expect(() => csrf.verify(token)).not.toThrow();

    const tampered = Buffer.from(token, "base64url");
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    expect(() => csrf.verify(tampered.toString("base64url"))).toThrow("invalid onboarding request");
    now = new Date("2026-09-02T18:09:59Z");
    expect(() => csrf.verify(token)).not.toThrow();
    now = new Date("2026-09-02T18:10:00Z");
    expect(() => csrf.verify(token)).toThrow("invalid onboarding request");
    now = new Date("2026-09-02T17:59:59Z");
    expect(() => csrf.verify(token)).toThrow("invalid onboarding request");

    expect(() => new BuiltinOnboardingCsrf({ key: Buffer.alloc(31) })).toThrow("at least 256 bits");
    expect(() =>
      new BuiltinOnboardingCsrf({
        key: Buffer.alloc(32),
        entropy: () => Buffer.alloc(31)
      }).issue()
    ).toThrow("wrong length");
  });

  it("keeps the stage secret out of the page and shows only exact staged data before UV", async () => {
    const begin = vi.fn(async () => ({
      organizationDisplayName: `<img src=x onerror="pwned()"> Mining Co`,
      boardName: "Exploration <Board>",
      memberDisplayName: "Target Director & Chair",
      memberKind: "human" as const,
      accountablePrincipalId: null,
      seatRole: "voting_member" as const,
      terms: {
        versionId: TERMS_ID,
        version: 2,
        schemaVersion: "boardagent.onboarding-terms.v1",
        canonicalText: "Exact current director responsibilities",
        sha256: "12".repeat(32)
      },
      secretarySupport: {
        versionId: SUPPORT_ID,
        version: 1,
        name: "Board Secretary",
        contactMethods: [{ kind: "email", value: "secretary@example.test" }],
        sha256: "34".repeat(32)
      },
      presentationChoice: "structured summaries",
      localMemoryChoice: "encrypted local cache",
      expiresAt: "2026-09-02T18:10:00.000Z",
      publicKey: {
        challenge: Buffer.alloc(32, 0xd2).toString("base64url"),
        rpId: "localhost",
        timeout: 60_000,
        userVerification: "required" as const,
        allowCredentials: [
          {
            id: authenticationResponse.id,
            type: "public-key" as const,
            transports: ["internal" as const]
          }
        ]
      }
    }));
    const complete = vi.fn(async () => ({
      status: "current" as const,
      memberId: MEMBER_ID,
      boardId: BOARD_ID,
      termsVersionId: TERMS_ID,
      supportVersionId: SUPPORT_ID
    }));
    const csrf = new BuiltinOnboardingCsrf({
      key: Buffer.alloc(32, 0xd3),
      entropy: (length) => Buffer.alloc(length, 0xd4),
      now: () => new Date("2026-09-02T18:00:00Z")
    });
    const { origin, port } = await start({ begin, complete }, csrf);

    const page = await httpRequest(port, { headers: { host: new URL(origin).host } });
    expect(page.status).toBe(200);
    expect(page.body).toContain('type="password"');
    expect(page.body).toContain("does not claim that I understood");
    expect(page.body).not.toContain(STAGE_TOKEN);
    expect(page.headers["cache-control"]).toBe("no-store, max-age=0");
    expect(page.headers["referrer-policy"]).toBe("no-referrer");
    expect(page.headers["content-security-policy"]).not.toMatch(/unsafe-inline|unsafe-eval/u);
    const csrfToken = /name="csrf_token" value="([A-Za-z0-9_-]+)"/u.exec(page.body)?.[1];
    expect(csrfToken).toHaveLength(96);

    const script = await httpRequest(port, {
      path: "/onboarding/webauthn.js",
      headers: { host: new URL(origin).host }
    });
    expect(script.status).toBe(200);
    expect(script.body).toContain("navigator.credentials.get");
    expect(script.body).toContain("history.replaceState");
    expect(script.body).toContain("textContent");
    expect(script.body).not.toMatch(/localStorage|sessionStorage|console\.|https?:\/\//u);

    const beginBody = new URLSearchParams({
      csrf_token: csrfToken!,
      stage_token: STAGE_TOKEN
    }).toString();
    const inspected = await httpRequest(port, {
      method: "POST",
      path: "/onboarding/passkey/begin",
      headers: postHeaders(origin, beginBody),
      body: beginBody
    });
    expect(inspected.status).toBe(200);
    expect(JSON.parse(inspected.body)).toMatchObject({
      organizationDisplayName: `<img src=x onerror="pwned()"> Mining Co`,
      boardName: "Exploration <Board>",
      terms: { canonicalText: "Exact current director responsibilities" },
      publicKey: { userVerification: "required" }
    });
    expect(begin).toHaveBeenCalledWith({ stageToken: STAGE_TOKEN });

    const completeBody = new URLSearchParams({
      attest: "true",
      credential: JSON.stringify(FORM_AUTHENTICATION_RESPONSE),
      csrf_token: csrfToken!,
      stage_token: STAGE_TOKEN
    }).toString();
    const completed = await httpRequest(port, {
      method: "POST",
      path: "/onboarding/passkey/complete",
      headers: postHeaders(origin, completeBody),
      body: completeBody
    });
    expect(completed.status).toBe(200);
    expect(JSON.parse(completed.body)).toEqual({
      status: "current",
      memberId: MEMBER_ID,
      boardId: BOARD_ID,
      termsVersionId: TERMS_ID,
      supportVersionId: SUPPORT_ID
    });
    expect(completed.body).not.toContain(STAGE_TOKEN);
    expect(complete).toHaveBeenCalledWith({
      stageToken: STAGE_TOKEN,
      response: FORM_AUTHENTICATION_RESPONSE
    });
  });

  it("rejects route, origin, CSRF, field, attestation and credential confusion generically", async () => {
    const onboarding = {
      begin: vi.fn(),
      complete: vi.fn()
    } as unknown as Pick<BuiltinOnboardingService, "begin" | "complete">;
    const csrf = new BuiltinOnboardingCsrf({
      key: Buffer.alloc(32, 0xe1),
      entropy: (length) => Buffer.alloc(length, 0xe2),
      now: () => new Date("2026-09-02T18:00:00Z")
    });
    const { origin, port } = await start(onboarding, csrf);
    const page = await httpRequest(port, { headers: { host: new URL(origin).host } });
    const csrfToken = /name="csrf_token" value="([A-Za-z0-9_-]+)"/u.exec(page.body)?.[1];
    if (!csrfToken) throw new Error("test page has no CSRF token");
    const validBegin = new URLSearchParams({
      csrf_token: csrfToken,
      stage_token: STAGE_TOKEN
    }).toString();
    const extraField = new URLSearchParams({
      csrf_token: csrfToken,
      stage_token: STAGE_TOKEN,
      extra: "confusion"
    }).toString();
    const uncheckedComplete = new URLSearchParams({
      attest: "false",
      credential: JSON.stringify(FORM_AUTHENTICATION_RESPONSE),
      csrf_token: csrfToken,
      stage_token: STAGE_TOKEN
    }).toString();
    const malformedCredential = new URLSearchParams({
      attest: "true",
      credential: JSON.stringify({ ...FORM_AUTHENTICATION_RESPONSE, injected: true }),
      csrf_token: csrfToken,
      stage_token: STAGE_TOKEN
    }).toString();
    const badCsrf = new URLSearchParams({
      csrf_token: Buffer.alloc(72, 0xff).toString("base64url"),
      stage_token: STAGE_TOKEN
    }).toString();
    const attacks: Array<RequestOptions & { readonly body?: string }> = [
      { path: "/onboarding?stage=secret", headers: { host: new URL(origin).host } },
      {
        method: "POST",
        path: "/onboarding/passkey/begin",
        headers: postHeaders("http://attacker.test", validBegin),
        body: validBegin
      },
      {
        method: "POST",
        path: "/onboarding/passkey/begin",
        headers: postHeaders(origin, badCsrf),
        body: badCsrf
      },
      {
        method: "POST",
        path: "/onboarding/passkey/begin",
        headers: postHeaders(origin, extraField),
        body: extraField
      },
      {
        method: "POST",
        path: "/onboarding/passkey/complete",
        headers: postHeaders(origin, uncheckedComplete),
        body: uncheckedComplete
      },
      {
        method: "POST",
        path: "/onboarding/passkey/complete",
        headers: postHeaders(origin, malformedCredential),
        body: malformedCredential
      }
    ];
    for (const attack of attacks) {
      const rejected = await httpRequest(port, attack);
      expect(rejected).toMatchObject({
        status: 400,
        body: '{"error":"invalid_onboarding_request"}'
      });
    }
    expect(onboarding.begin).not.toHaveBeenCalled();
    expect(onboarding.complete).not.toHaveBeenCalled();
  });
});
