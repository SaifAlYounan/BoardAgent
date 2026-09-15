import { request, type IncomingMessage, type RequestOptions } from "node:http";
import { createServer } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  AuthRequestBoundary,
  authPageSecurityHeaders,
  createAuthInteractionBinding,
  parseAuthInteractionPath,
  readAuthInteractionSubmission,
  renderAuthInteractionPage,
  rotateAuthSession,
  verifyAuthInteractionBinding
} from "../../artifacts/server/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

const INTERACTION_UID = Buffer.alloc(24, 0x71).toString("base64url");
const CSRF_TOKEN = Buffer.alloc(32, 0x72).toString("base64url");
const STATE = Buffer.alloc(32, 0x73).toString("base64url");
const NONCE = Buffer.alloc(32, 0x74).toString("base64url");
const SESSION_ID = testId(65_001);
const CLIENT_ID = testId(65_002);
const MALICIOUS_CLIENT = `<img src=x onerror="globalThis.pwned=true"> & Outside Client`;
const openServers: Array<ReturnType<typeof createServer>> = [];

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
        path: options.path ?? `/auth/interactions/${INTERACTION_UID}`,
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

describe("BoardAgent hardened auth interaction page", () => {
  it("accepts exactly the configured proxy-hop chain and rejects added hops", async () => {
    const boundary = new AuthRequestBoundary({
      origin: "https://boardagent.test",
      trustedProxyHops: 1
    });
    const server = createServer((incoming, response) => {
      try {
        const inspection = boundary.inspect(incoming, { stateChanging: false });
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(inspection));
      } catch {
        response.writeHead(400).end();
      }
    });
    openServers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("proxy test server has no port");
    const exact = await httpRequest(address.port, {
      headers: {
        host: "boardagent.test",
        "x-forwarded-for": "198.51.100.22",
        "x-forwarded-proto": "https"
      }
    });
    expect(exact.status).toBe(200);
    expect(JSON.parse(exact.body)).toMatchObject({ clientIpClass: "ipv4:198.51.100.0/24" });
    const added = await httpRequest(address.port, {
      headers: {
        host: "boardagent.test",
        "x-forwarded-for": "198.51.100.22, 203.0.113.9",
        "x-forwarded-proto": "https"
      }
    });
    expect(added.status).toBe(400);
  });

  it("escapes external text and rejects Host, proxy, origin, CSRF and redirect confusion", async () => {
    const boundary = new AuthRequestBoundary({
      origin: "https://boardagent.test",
      trustedProxyAddresses: ["127.0.0.1"]
    });
    const binding = createAuthInteractionBinding({
      interactionUid: INTERACTION_UID,
      sessionId: SESSION_ID,
      clientId: CLIENT_ID,
      state: STATE,
      nonce: NONCE,
      csrfToken: CSRF_TOKEN,
      expiresAt: new Date("2026-09-02T05:10:00Z")
    });
    const server = createServer((incoming, response) => {
      void (async () => {
        try {
          boundary.inspect(incoming, { stateChanging: incoming.method === "POST" });
          const interactionUid = parseAuthInteractionPath(incoming.url ?? "");
          if (incoming.method === "GET") {
            const body = renderAuthInteractionPage({
              interactionUid,
              csrfToken: CSRF_TOKEN,
              clientDisplayName: MALICIOUS_CLIENT
            });
            response.writeHead(200, authPageSecurityHeaders({ includeHsts: true }));
            response.end(body);
            return;
          }
          const submission = await readAuthInteractionSubmission(incoming);
          verifyAuthInteractionBinding(binding, {
            interactionUid,
            sessionId: SESSION_ID,
            clientId: CLIENT_ID,
            state: STATE,
            nonce: NONCE,
            csrfToken: submission.csrfToken,
            now: new Date("2026-09-02T05:00:00Z")
          });
          response.writeHead(204, authPageSecurityHeaders({ includeHsts: true }));
          response.end();
        } catch {
          response.writeHead(400, {
            "cache-control": "no-store",
            "content-type": "application/json; charset=utf-8"
          });
          response.end('{"error":"invalid_auth_request"}');
        }
      })();
    });
    openServers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("auth test server has no port");
    const proxyHeaders = {
      host: "boardagent.test",
      "x-forwarded-for": "198.51.100.22",
      "x-forwarded-proto": "https"
    };

    const page = await httpRequest(address.port, { headers: proxyHeaders });
    expect(page.status).toBe(200);
    expect(page.body).toContain("&lt;img src=x onerror=&quot;globalThis.pwned=true&quot;&gt;");
    expect(page.body).not.toContain("<img");
    expect(page.body).not.toContain("https://");
    expect(page.headers["cache-control"]).toBe("no-store, max-age=0");
    expect(page.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(page.headers["content-security-policy"]).not.toMatch(/unsafe-inline|unsafe-eval/u);
    expect(page.headers["x-frame-options"]).toBe("DENY");
    expect(page.headers["strict-transport-security"]).toContain("max-age=");
    expect(page.headers["referrer-policy"]).toBe("same-origin");

    const validBody = new URLSearchParams({
      action: "passkey",
      csrf_token: CSRF_TOKEN
    }).toString();
    const valid = await httpRequest(address.port, {
      method: "POST",
      headers: {
        ...proxyHeaders,
        origin: "https://boardagent.test",
        "sec-fetch-site": "same-origin",
        "content-type": "application/x-www-form-urlencoded",
        "content-length": String(Buffer.byteLength(validBody))
      },
      body: validBody
    });
    expect(valid.status).toBe(204);

    const attacks: Array<RequestOptions & { readonly body?: string }> = [
      { headers: { ...proxyHeaders, host: "attacker.test" } },
      { headers: { ...proxyHeaders, "x-forwarded-host": "attacker.test" } },
      {
        headers: proxyHeaders,
        path: `/auth/interactions/${INTERACTION_UID}?return=https://attacker.test`
      },
      {
        method: "POST",
        headers: {
          ...proxyHeaders,
          origin: "https://attacker.test",
          "sec-fetch-site": "cross-site",
          "content-type": "application/x-www-form-urlencoded"
        },
        body: validBody
      },
      {
        method: "POST",
        headers: {
          ...proxyHeaders,
          origin: "https://boardagent.test",
          "sec-fetch-site": "same-origin",
          "content-type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          action: "passkey",
          csrf_token: Buffer.alloc(32, 0xff).toString("base64url")
        }).toString()
      }
    ];
    for (const attack of attacks) {
      const rejected = await httpRequest(address.port, attack);
      expect(rejected.status).toBe(400);
      expect(rejected.body).toBe('{"error":"invalid_auth_request"}');
    }
  });

  it("rotates opaque browser sessions and binds state, nonce and CSRF only by hash", () => {
    const first = rotateAuthSession({
      entropy: Buffer.alloc(64, 0x81),
      now: new Date("2026-09-02T05:00:00Z")
    });
    const second = rotateAuthSession({
      entropy: Buffer.alloc(64, 0x82),
      now: new Date("2026-09-02T05:01:00Z")
    });
    expect(first.opaqueSessionSha256.equals(second.opaqueSessionSha256)).toBe(false);
    expect(first.setCookie).not.toBe(second.setCookie);
    expect(first.setCookie).toMatch(
      /^__Host-boardagent_auth=[A-Za-z0-9_-]{43}; Path=\/; Max-Age=28800; Secure; HttpOnly; SameSite=Lax$/u
    );
    expect(first.csrfToken).toHaveLength(43);

    const binding = createAuthInteractionBinding({
      interactionUid: INTERACTION_UID,
      sessionId: SESSION_ID,
      clientId: CLIENT_ID,
      state: STATE,
      nonce: NONCE,
      csrfToken: first.csrfToken,
      expiresAt: new Date("2026-09-02T05:10:00Z")
    });
    expect(binding).not.toHaveProperty("state");
    expect(binding).not.toHaveProperty("nonce");
    expect(binding).not.toHaveProperty("csrfToken");
    expect(() =>
      verifyAuthInteractionBinding(binding, {
        interactionUid: INTERACTION_UID,
        sessionId: SESSION_ID,
        clientId: CLIENT_ID,
        state: STATE,
        nonce: `${NONCE}x`,
        csrfToken: first.csrfToken,
        now: new Date("2026-09-02T05:02:00Z")
      })
    ).toThrow(/invalid auth interaction/u);
  });
});
