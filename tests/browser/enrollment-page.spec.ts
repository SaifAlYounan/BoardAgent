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
  BuiltinEnrollmentCsrf,
  createBuiltinEnrollmentHandler,
  type BuiltinEnrollmentService
} from "../../artifacts/server/src/index.js";
import { registrationResponse } from "./webauthn-harness.js";

const INVITATION_TOKEN = Buffer.alloc(32, 0xb1).toString("base64url");
const ACTIVATION_CODE = "ABC-2345";
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
        path: options.path ?? "/enroll",
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

describe("builtin enrollment browser controller", () => {
  it("authenticates a bounded 10-minute CSRF token and rejects tamper, expiry and clock rewind", () => {
    let now = new Date("2026-09-02T16:00:00Z");
    const csrf = new BuiltinEnrollmentCsrf({
      key: Buffer.alloc(32, 0xa1),
      entropy: (length) => Buffer.alloc(length, 0xa2),
      now: () => now
    });
    const token = csrf.issue();
    expect(token).toHaveLength(96);
    expect(() => csrf.verify(token)).not.toThrow();

    const tamperedBytes = Buffer.from(token, "base64url");
    tamperedBytes[tamperedBytes.length - 1] = tamperedBytes[tamperedBytes.length - 1]! ^ 1;
    expect(() => csrf.verify(tamperedBytes.toString("base64url"))).toThrow(
      "invalid enrollment request"
    );

    now = new Date("2026-09-02T16:09:59Z");
    expect(() => csrf.verify(token)).not.toThrow();
    now = new Date("2026-09-02T16:10:00Z");
    expect(() => csrf.verify(token)).toThrow("invalid enrollment request");
    now = new Date("2026-09-02T15:59:59Z");
    expect(() => csrf.verify(token)).toThrow("invalid enrollment request");

    expect(() => new BuiltinEnrollmentCsrf({ key: Buffer.alloc(31) })).toThrow("at least 256 bits");
    expect(() =>
      new BuiltinEnrollmentCsrf({
        key: Buffer.alloc(32),
        entropy: () => Buffer.alloc(31)
      }).issue()
    ).toThrow("wrong length");
  });

  it("keeps the invite out of URLs, shows the seat before UV creation, and returns only an activation code", async () => {
    const begin = vi.fn(async () => ({
      organizationDisplayName: `<img src=x onerror="pwned()"> Mining Co`,
      memberDisplayName: "Target Director & Chair",
      seats: [
        {
          boardId: "018f0000-0000-7000-8000-000000000001",
          boardName: "Exploration <Board>",
          seatRole: "voting_member" as const
        }
      ],
      publicKey: {
        challenge: Buffer.alloc(32, 0xb2).toString("base64url"),
        rp: { id: "localhost", name: "BoardAgent" },
        user: {
          id: Buffer.alloc(16, 0xb3).toString("base64url"),
          name: "member",
          displayName: "Target Director"
        },
        pubKeyCredParams: [{ alg: -7, type: "public-key" as const }],
        timeout: 60_000,
        attestation: "none" as const,
        authenticatorSelection: { userVerification: "required" as const }
      }
    }));
    const complete = vi.fn(async () => ({
      status: "pending_activation" as const,
      memberId: "018f0000-0000-7000-8000-000000000002",
      invitationId: "018f0000-0000-7000-8000-000000000003",
      activationChallengeId: "018f0000-0000-7000-8000-000000000004",
      activationCode: ACTIVATION_CODE,
      proofingMethod: "verified_number_call" as const,
      expiresInSeconds: 600 as const
    }));
    const enrollment = { begin, complete } as unknown as BuiltinEnrollmentService;
    const server = createServer();
    openServers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("enrollment server has no port");
    const origin = `http://localhost:${String(address.port)}`;
    server.on(
      "request",
      createBuiltinEnrollmentHandler({
        boundary: new AuthRequestBoundary({
          origin,
          allowInsecureLoopbackDevelopment: true
        }),
        enrollment,
        csrf: new BuiltinEnrollmentCsrf({
          key: Buffer.alloc(32, 0xb4),
          entropy: (length) => Buffer.alloc(length, 0xb5),
          now: () => new Date("2026-09-02T16:00:00Z")
        }),
        includeHsts: false
      })
    );

    const page = await httpRequest(address.port, {
      headers: { host: new URL(origin).host }
    });
    expect(page.status).toBe(200);
    expect(page.body).toContain('type="password"');
    expect(page.body).not.toContain(INVITATION_TOKEN);
    expect(page.headers["cache-control"]).toBe("no-store, max-age=0");
    expect(page.headers["content-security-policy"]).not.toMatch(/unsafe-inline|unsafe-eval/u);
    const csrfToken = /name="csrf_token" value="([A-Za-z0-9_-]+)"/u.exec(page.body)?.[1];
    expect(csrfToken).toHaveLength(96);

    const script = await httpRequest(address.port, {
      path: "/enroll/webauthn.js",
      headers: { host: new URL(origin).host }
    });
    expect(script.status).toBe(200);
    expect(script.body).toContain("navigator.credentials.create");
    expect(script.body).toContain("history.replaceState");
    expect(script.body).toContain("textContent");
    expect(script.body).not.toMatch(/localStorage|sessionStorage|console\.|https?:\/\//u);

    const beginBody = new URLSearchParams({
      csrf_token: csrfToken!,
      invitation_token: INVITATION_TOKEN
    }).toString();
    const inspected = await httpRequest(address.port, {
      method: "POST",
      path: "/enroll/passkey/begin",
      headers: postHeaders(origin, beginBody),
      body: beginBody
    });
    expect(inspected.status).toBe(200);
    expect(JSON.parse(inspected.body)).toMatchObject({
      organizationDisplayName: `<img src=x onerror="pwned()"> Mining Co`,
      memberDisplayName: "Target Director & Chair",
      seats: [{ boardName: "Exploration <Board>", seatRole: "voting_member" }],
      publicKey: { authenticatorSelection: { userVerification: "required" } }
    });
    expect(begin).toHaveBeenCalledWith({ invitationToken: INVITATION_TOKEN });

    const completeBody = new URLSearchParams({
      csrf_token: csrfToken!,
      invitation_token: INVITATION_TOKEN,
      proofing_method: "verified_number_call",
      credential: JSON.stringify(registrationResponse)
    }).toString();
    const completed = await httpRequest(address.port, {
      method: "POST",
      path: "/enroll/passkey/complete",
      headers: postHeaders(origin, completeBody),
      body: completeBody
    });
    expect(completed.status).toBe(200);
    expect(JSON.parse(completed.body)).toEqual({
      status: "pending_activation",
      memberId: "018f0000-0000-7000-8000-000000000002",
      invitationId: "018f0000-0000-7000-8000-000000000003",
      activationChallengeId: "018f0000-0000-7000-8000-000000000004",
      activationCode: ACTIVATION_CODE,
      expiresInSeconds: 600
    });
    expect(completed.body).not.toContain(INVITATION_TOKEN);
    expect(complete).toHaveBeenCalledWith({
      invitationToken: INVITATION_TOKEN,
      proofingMethod: "verified_number_call",
      response: registrationResponse
    });
  });

  it("rejects route, origin, CSRF, field and proof-method confusion before enrollment", async () => {
    const enrollment = {
      begin: vi.fn(),
      complete: vi.fn()
    } as unknown as BuiltinEnrollmentService;
    const server = createServer();
    openServers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("enrollment server has no port");
    const origin = `http://localhost:${String(address.port)}`;
    server.on(
      "request",
      createBuiltinEnrollmentHandler({
        boundary: new AuthRequestBoundary({
          origin,
          allowInsecureLoopbackDevelopment: true
        }),
        enrollment,
        csrf: new BuiltinEnrollmentCsrf({
          key: Buffer.alloc(32, 0xc1),
          entropy: (length) => Buffer.alloc(length, 0xc2),
          now: () => new Date("2026-09-02T16:00:00Z")
        }),
        includeHsts: false
      })
    );
    const page = await httpRequest(address.port, { headers: { host: new URL(origin).host } });
    const csrfToken = /name="csrf_token" value="([A-Za-z0-9_-]+)"/u.exec(page.body)?.[1];
    if (!csrfToken) throw new Error("test page has no CSRF token");

    const validBegin = new URLSearchParams({
      csrf_token: csrfToken,
      invitation_token: INVITATION_TOKEN
    }).toString();
    const malformedComplete = new URLSearchParams({
      csrf_token: csrfToken,
      invitation_token: INVITATION_TOKEN,
      proofing_method: "email",
      credential: JSON.stringify(registrationResponse)
    }).toString();
    const attacks: Array<RequestOptions & { readonly body?: string }> = [
      { path: "/enroll?token=secret", headers: { host: new URL(origin).host } },
      {
        method: "POST",
        path: "/enroll/passkey/begin",
        headers: postHeaders("http://attacker.test", validBegin),
        body: validBegin
      },
      {
        method: "POST",
        path: "/enroll/passkey/begin",
        headers: postHeaders(
          origin,
          new URLSearchParams({
            csrf_token: Buffer.alloc(72, 0xff).toString("base64url"),
            invitation_token: INVITATION_TOKEN
          }).toString()
        ),
        body: new URLSearchParams({
          csrf_token: Buffer.alloc(72, 0xff).toString("base64url"),
          invitation_token: INVITATION_TOKEN
        }).toString()
      },
      {
        method: "POST",
        path: "/enroll/passkey/begin",
        headers: postHeaders(
          origin,
          new URLSearchParams({
            csrf_token: csrfToken,
            invitation_token: INVITATION_TOKEN,
            extra: "confusion"
          }).toString()
        ),
        body: new URLSearchParams({
          csrf_token: csrfToken,
          invitation_token: INVITATION_TOKEN,
          extra: "confusion"
        }).toString()
      },
      {
        method: "POST",
        path: "/enroll/passkey/complete",
        headers: postHeaders(origin, malformedComplete),
        body: malformedComplete
      }
    ];
    for (const attack of attacks) {
      const rejected = await httpRequest(address.port, attack);
      expect(rejected).toMatchObject({
        status: 400,
        body: '{"error":"invalid_enrollment_request"}'
      });
    }
    expect(enrollment.begin).not.toHaveBeenCalled();
    expect(enrollment.complete).not.toHaveBeenCalled();
  });
});
