import {
  createServer,
  request as nodeRequest,
  type IncomingMessage,
  type RequestListener
} from "node:http";
import { connect } from "node:net";

import type { McpHttpHandler } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import {
  AuthRequestBoundary,
  createBoardAgentHttpRuntime
} from "../../artifacts/server/src/index.js";

const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        })
    )
  );
});

async function listen(
  build: (origin: string) => RequestListener,
  observeRequest?: (request: IncomingMessage) => void
): Promise<{ readonly base: URL; readonly origin: string }> {
  let handler: RequestListener = (_request, response) => {
    response.writeHead(503).end();
  };
  const server = createServer((request, response) => {
    Object.defineProperty(request.socket, "encrypted", { configurable: true, value: true });
    observeRequest?.(request);
    handler(request, response);
  });
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind");
  const origin = `https://127.0.0.1:${String(address.port)}`;
  handler = build(origin);
  return { base: new URL(`http://127.0.0.1:${String(address.port)}`), origin };
}

async function rawHttpRequest(base: URL, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port: Number(base.port) });
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("error", reject);
    socket.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    socket.once("connect", () => socket.end(request));
  });
}

function nodeHandler(body: Readonly<Record<string, unknown>>, status = 200): RequestListener {
  return (_request, response) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  };
}

function invalidPublicCertificateVerifier() {
  return {
    verify: async () => ({ status: "complete" as const, valid: false })
  };
}

async function bodyEndpoint(
  fetch: (request: Request) => Promise<Response>,
  observeRequest?: (request: IncomingMessage) => void
) {
  return listen(
    (origin) =>
      createBoardAgentHttpRuntime({
        canonicalOrigin: origin,
        resourceUri: `${origin}/mcp`,
        boundary: new AuthRequestBoundary({ origin }),
        mcp: { fetch, close: async () => undefined },
        oauth: { callback: () => nodeHandler({ oauth: true }) },
        interaction: nodeHandler({ interaction: true }),
        enrollment: nodeHandler({ enrollment: true }),
        onboarding: nodeHandler({ onboarding: true }),
        readiness: { check: async () => ({ ready: true }) },
        publicCertificateVerifier: invalidPublicCertificateVerifier(),
        includeHsts: false
      }).handler,
    observeRequest
  );
}

async function chunkedBody(
  base: URL,
  origin: string,
  bytes: number
): Promise<{ status: number; retryAfter?: string }> {
  return new Promise((resolve, reject) => {
    const outbound = nodeRequest(
      new URL("/mcp", base),
      {
        method: "POST",
        headers: {
          host: new URL(origin).host,
          "content-type": "application/json",
          "transfer-encoding": "chunked"
        }
      },
      (response) => {
        response.resume();
        response.once("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            ...(response.headers["retry-after"]
              ? { retryAfter: response.headers["retry-after"] }
              : {})
          })
        );
      }
    );
    outbound.once("error", reject);
    const chunk = Buffer.alloc(65_536, 0x61);
    let remaining = bytes;
    const write = () => {
      while (remaining > 0 && !outbound.destroyed) {
        const size = Math.min(chunk.length, remaining);
        remaining -= size;
        if (!outbound.write(chunk.subarray(0, size))) {
          outbound.once("drain", write);
          return;
        }
      }
      if (!outbound.destroyed) outbound.end();
    };
    write();
  });
}

describe("native HTTP runtime boundary", () => {
  it("returns complete rejection responses for repeated oversized public uploads and remains available", async () => {
    let dispatches = 0;
    const running = await bodyEndpoint(async () => {
      dispatches += 1;
      return Response.json({ ok: true });
    });
    // Reuse one origin and real fetch uploads: the old early socket close races
    // ongoing writes, intermittently replacing the 413 with EPIPE/ECONNRESET.
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const response = await fetch(new URL("/verify/certificate", running.base), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "a".repeat(1024 * 1024 + 1),
        signal: AbortSignal.timeout(2_000)
      });
      expect(response.status).toBe(413);
      expect(response.headers.get("connection")).toBe("close");
      expect(await response.json()).toEqual({ error: "request_too_large" });
    }
    expect(dispatches).toBe(0);
    const subsequent = await fetch(new URL("/mcp", running.base), {
      method: "POST",
      body: "{}",
      signal: AbortSignal.timeout(2_000)
    });
    expect(subsequent.status).toBe(200);
    expect(await subsequent.json()).toEqual({ ok: true });
    expect(dispatches).toBe(1);
  }, 10_000);

  it.each(["stalled", "excess"] as const)(
    "bounds rejected-upload cleanup for a %s sender without dispatching its body",
    async (mode) => {
      let discardedBytes = 0,
        dispatches = 0;
      const running = await bodyEndpoint(
        async () => {
          dispatches += 1;
          return Response.json({ unexpected: true });
        },
        (request) => {
          // Observe actual application reads without putting the stream into flowing
          // mode or replacing the native read implementation.
          const nativeRead = request.read.bind(request);
          request.read = (size?: number) => {
            const chunk: unknown = nativeRead(size);
            if (Buffer.isBuffer(chunk)) discardedBytes += chunk.byteLength;
            return chunk;
          };
        }
      );
      const started = performance.now();
      const received = await new Promise<string>((resolve, reject) => {
        const socket = connect({ host: "127.0.0.1", port: Number(running.base.port) });
        const chunks: Buffer[] = [];
        const timeout = setTimeout(() => {
          socket.destroy();
          reject(new Error("rejected sender retained its connection"));
        }, 2_000);
        socket.on("data", (chunk: Buffer) => chunks.push(chunk));
        // A sender exceeding the cleanup budget may be disconnected; it must
        // already have received the rejection, and must never reach dispatch.
        socket.on("error", () => undefined);
        socket.once("close", () => {
          clearTimeout(timeout);
          resolve(Buffer.concat(chunks).toString("utf8"));
        });
        socket.once("connect", () => {
          socket.write(
            [
              "POST /verify/certificate HTTP/1.1",
              `Host: ${new URL(running.origin).host}`,
              "Content-Type: application/json",
              "Content-Length: 1073741824",
              "",
              ""
            ].join("\r\n")
          );
          socket.write(mode === "excess" ? Buffer.alloc(3 * 1024 * 1024, 0x61) : "a");
          // Deliberately leave the declared request unfinished.
        });
      });
      expect(received).toContain(" 413 ");
      expect(received).toContain('{"error":"request_too_large"}');
      expect(performance.now() - started).toBeLessThan(2_000);
      expect(discardedBytes).toBeLessThanOrEqual(2 * 1024 * 1024);
      expect(dispatches).toBe(0);
    }
  );

  it("bounds MCP wire bytes for declared and chunked bodies while public verification stays at 1 MiB", async () => {
    const wireMaximum = 6 * 10 * 1024 * 1024 + 1024 * 1024;
    let dispatches = 0;
    const running = await bodyEndpoint(async (request) => {
      await request.arrayBuffer();
      dispatches += 1;
      return Response.json({ ok: true });
    });
    const oversized = await rawHttpRequest(
      running.base,
      [
        "POST /mcp HTTP/1.1",
        `Host: ${new URL(running.origin).host}`,
        `Content-Length: ${wireMaximum + 1}`,
        "Connection: close",
        "",
        ""
      ].join("\r\n")
    );
    expect(oversized).toContain(" 413 ");
    expect((await chunkedBody(running.base, running.origin, wireMaximum)).status).toBe(200);
    expect((await chunkedBody(running.base, running.origin, wireMaximum + 1)).status).toBe(413);
    const publicResult = await fetch(new URL("/verify/certificate", running.base), {
      method: "POST",
      headers: { host: new URL(running.origin).host, "content-type": "application/json" },
      body: "a".repeat(1024 * 1024 + 1)
    });
    expect(publicResult.status).toBe(413);
    await publicResult.arrayBuffer();
    expect(dispatches).toBe(1);
  });

  it("bounds aggregate body buffering and releases capacity after a completed response", async () => {
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const running = await bodyEndpoint(async (request) => {
      await request.arrayBuffer();
      entered.resolve();
      await release.promise;
      return Response.json({ ok: true });
    });
    const body = '{"text":"' + "\\u0061".repeat(6 * 1024 * 1024) + '"}';
    const options = {
      method: "POST",
      headers: { host: new URL(running.origin).host, "content-type": "application/json" },
      body
    };
    const first = fetch(new URL("/mcp", running.base), options);
    try {
      await Promise.race([
        entered.promise,
        first.then((response) => {
          if (response.status !== 200) throw new Error("first body was not admitted");
        })
      ]);
      const second = await rawHttpRequest(
        running.base,
        [
          "POST /mcp HTTP/1.1",
          `Host: ${new URL(running.origin).host}`,
          `Content-Length: ${Buffer.byteLength(body)}`,
          "Connection: close",
          "",
          ""
        ].join("\r\n")
      );
      expect(second).toContain(" 503 ");
      expect(second).toContain("retry-after: 1");
    } finally {
      release.resolve();
    }
    const completed = await first;
    expect(completed.status).toBe(200);
    await completed.arrayBuffer();
    const next = await fetch(new URL("/mcp", running.base), options);
    expect(next.status).toBe(200);
    await next.arrayBuffer();
  });
  it.each([false, true])(
    "releases body capacity after dispatch failure or downstream disconnect (disconnect=%s)",
    async (disconnect) => {
      let dispatches = 0;
      const aborted = Promise.withResolvers<void>();
      const running = await bodyEndpoint(async (request) => {
        await request.arrayBuffer();
        dispatches += 1;
        if (dispatches > 1) return Response.json({ ok: true });
        if (!disconnect) throw new Error("synthetic dispatch failure");
        request.signal.addEventListener("abort", () => aborted.resolve(), { once: true });
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new Uint8Array(8 * 1024 * 1024));
            }
          })
        );
      });
      const body = "a".repeat(36 * 1024 * 1024);
      const options = { method: "POST", headers: { host: new URL(running.origin).host }, body };
      const first = await fetch(new URL("/mcp", running.base), options);
      if (disconnect) {
        expect(first.status).toBe(200);
        await first.body?.cancel();
        await aborted.promise;
        await new Promise<void>((resolve) => setImmediate(resolve));
      } else {
        expect(first.status).toBe(400);
        await first.arrayBuffer();
      }
      const next = await fetch(new URL("/mcp", running.base), options);
      expect(next.status).toBe(200);
      await next.arrayBuffer();
      expect(dispatches).toBe(2);
    }
  );

  it.each([false, true])(
    "accepts the frozen 10 MiB canonical source through JSON transport (escaped=%s)",
    async (escaped) => {
      const maximumContentBytes = 10 * 1024 * 1024;
      let receivedBytes = 0;
      const running = await listen(
        (origin) =>
          createBoardAgentHttpRuntime({
            canonicalOrigin: origin,
            resourceUri: `${origin}/mcp`,
            boundary: new AuthRequestBoundary({ origin }),
            mcp: {
              fetch: async (request) => {
                const body = (await request.json()) as {
                  params: { arguments: { canonical_body: string } };
                };
                receivedBytes = Buffer.byteLength(body.params.arguments.canonical_body, "utf8");
                return Response.json({ receivedBytes });
              },
              close: async () => undefined
            },
            oauth: { callback: () => nodeHandler({ oauth: true }) },
            interaction: nodeHandler({ interaction: true }),
            enrollment: nodeHandler({ enrollment: true }),
            onboarding: nodeHandler({ onboarding: true }),
            readiness: { check: async () => ({ ready: true }) },
            publicCertificateVerifier: invalidPublicCertificateVerifier(),
            includeHsts: false
          }).handler
      );
      const content = (escaped ? "\\u0061" : "a").repeat(maximumContentBytes);
      const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add_document","arguments":{"canonical_body":"${content}"}}}`;
      const response = await fetch(new URL("/mcp", running.base), {
        method: "POST",
        headers: { host: new URL(running.origin).host, "content-type": "application/json" },
        body
      });
      expect(response.status).toBe(200);
      expect(receivedBytes).toBe(maximumContentBytes);
      await response.arrayBuffer();
    }
  );

  it("publishes path-bound OAuth metadata and reconstructs MCP at the canonical HTTPS URL", async () => {
    const seen: Request[] = [];
    let closed = 0;
    const mcp: Pick<McpHttpHandler, "fetch" | "close"> = {
      fetch: async (request) => {
        seen.push(request);
        return Response.json({ ok: true, body: await request.json() });
      },
      close: async () => {
        closed += 1;
      }
    };
    const runtimeHolder: { close?: () => Promise<void> } = {};
    const running = await listen((origin) => {
      const runtime = createBoardAgentHttpRuntime({
        canonicalOrigin: origin,
        resourceUri: `${origin}/mcp`,
        boundary: new AuthRequestBoundary({ origin }),
        mcp,
        oauth: { callback: () => nodeHandler({ oauth: true }) },
        interaction: nodeHandler({ interaction: true }),
        enrollment: nodeHandler({ enrollment: true }),
        onboarding: nodeHandler({ onboarding: true }),
        readiness: { check: async () => ({ ready: true }) },
        publicCertificateVerifier: invalidPublicCertificateVerifier(),
        includeHsts: true
      });
      runtimeHolder.close = runtime.close;
      return runtime.handler;
    });

    const metadata = await fetch(
      new URL("/.well-known/oauth-protected-resource/mcp", running.base),
      { headers: { host: new URL(running.origin).host } }
    );
    expect(metadata.status).toBe(200);
    expect(await metadata.json()).toMatchObject({
      resource: `${running.origin}/mcp`,
      authorization_servers: [running.origin],
      bearer_methods_supported: ["header"]
    });

    const response = await fetch(new URL("/mcp", running.base), {
      method: "POST",
      headers: {
        authorization: "Bearer opaque",
        "content-type": "application/json",
        host: new URL(running.origin).host
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" })
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true });
    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toBe(`${running.origin}/mcp`);
    expect(seen[0]?.headers.get("authorization")).toBe("Bearer opaque");
    await runtimeHolder.close?.();
    expect(closed).toBe(1);
  });

  it("exposes live and fail-closed readiness separately and rejects non-POST MCP", async () => {
    const running = await listen(
      (origin) =>
        createBoardAgentHttpRuntime({
          canonicalOrigin: origin,
          resourceUri: `${origin}/mcp`,
          boundary: new AuthRequestBoundary({ origin }),
          mcp: {
            fetch: async () => Response.json({ unreachable: true }),
            close: async () => undefined
          },
          oauth: { callback: () => nodeHandler({ oauth: true }) },
          interaction: nodeHandler({ interaction: true }),
          enrollment: nodeHandler({ enrollment: true }),
          onboarding: nodeHandler({ onboarding: true }),
          readiness: { check: async () => ({ ready: false, reason: "secret detail" }) },
          publicCertificateVerifier: invalidPublicCertificateVerifier(),
          includeHsts: true
        }).handler
    );
    const host = new URL(running.origin).host;
    const live = await fetch(new URL("/health/live", running.base), { headers: { host } });
    expect(live.status).toBe(200);
    expect(await live.json()).toEqual({ status: "live" });
    expect(live.headers.get("strict-transport-security")).toBe(
      "max-age=63072000; includeSubDomains"
    );
    const ready = await fetch(new URL("/health/ready", running.base), { headers: { host } });
    expect(ready.status).toBe(503);
    const readyText = await ready.text();
    expect(JSON.parse(readyText)).toEqual({ status: "unavailable" });
    expect(readyText).not.toContain("secret detail");
    const mcpGet = await fetch(new URL("/mcp", running.base), { headers: { host } });
    expect(mcpGet.status).toBe(405);
    expect(mcpGet.headers.get("allow")).toBe("POST");
  });

  it("rejects ambiguous headers and oversized MCP bodies before dispatch", async () => {
    let dispatches = 0;
    const running = await listen(
      (origin) =>
        createBoardAgentHttpRuntime({
          canonicalOrigin: origin,
          resourceUri: `${origin}/mcp`,
          boundary: new AuthRequestBoundary({ origin }),
          mcp: {
            fetch: async () => {
              dispatches += 1;
              return Response.json({ unreachable: true });
            },
            close: async () => undefined
          },
          oauth: { callback: () => nodeHandler({ oauth: true }) },
          interaction: nodeHandler({ interaction: true }),
          enrollment: nodeHandler({ enrollment: true }),
          onboarding: nodeHandler({ onboarding: true }),
          readiness: { check: async () => ({ ready: true }) },
          publicCertificateVerifier: invalidPublicCertificateVerifier(),
          includeHsts: false
        }).handler
    );
    const host = new URL(running.origin).host;
    const ambiguous = await rawHttpRequest(
      running.base,
      [
        "POST /mcp HTTP/1.1",
        `Host: ${host}`,
        "Content-Encoding: identity",
        "Content-Encoding: identity",
        "Content-Length: 0",
        "Connection: close",
        "",
        ""
      ].join("\r\n")
    );
    expect(ambiguous).toMatch(/^HTTP\/1\.1 400 /u);

    const oversized = await rawHttpRequest(
      running.base,
      [
        "POST /mcp HTTP/1.1",
        `Host: ${host}`,
        `Content-Length: ${6 * 10_485_760 + 1_048_576 + 1}`,
        "Content-Type: application/octet-stream",
        "Connection: close",
        "",
        ""
      ].join("\r\n")
    );
    expect(oversized).toContain(" 413 ");
    expect(oversized).not.toContain("strict-transport-security");
    expect(dispatches).toBe(0);
  });

  it("routes only the frozen browser and OAuth path families", async () => {
    const running = await listen(
      (origin) =>
        createBoardAgentHttpRuntime({
          canonicalOrigin: origin,
          resourceUri: `${origin}/mcp`,
          boundary: new AuthRequestBoundary({ origin }),
          mcp: { fetch: async () => new Response(), close: async () => undefined },
          oauth: { callback: () => nodeHandler({ route: "oauth" }) },
          interaction: nodeHandler({ route: "interaction" }),
          enrollment: nodeHandler({ route: "enrollment" }),
          onboarding: nodeHandler({ route: "onboarding" }),
          readiness: { check: async () => ({ ready: true }) },
          publicCertificateVerifier: invalidPublicCertificateVerifier(),
          includeHsts: true
        }).handler
    );
    const headers = { host: new URL(running.origin).host };
    await expect(
      fetch(new URL("/enroll", running.base), { headers }).then((value) => value.json())
    ).resolves.toEqual({ route: "enrollment" });
    await expect(
      fetch(new URL("/onboarding", running.base), { headers }).then((value) => value.json())
    ).resolves.toEqual({ route: "onboarding" });
    await expect(
      fetch(new URL("/auth/interactions/example", running.base), { headers }).then((value) =>
        value.json()
      )
    ).resolves.toEqual({ route: "interaction" });
    await expect(
      fetch(new URL("/authorize", running.base), { headers }).then((value) => value.json())
    ).resolves.toEqual({ route: "oauth" });
    // oidc-provider resumes its authenticated interaction on authorization/:uid.
    await expect(
      fetch(new URL("/authorize/resume_012-abc", running.base), { headers }).then((value) =>
        value.json()
      )
    ).resolves.toEqual({ route: "oauth" });
    for (const pathname of [
      "/authorize/",
      "/authorize/resume/nested",
      "/authorize/%2f",
      "/authorize/" + "a".repeat(257)
    ]) {
      expect((await fetch(new URL(pathname, running.base), { headers })).status).toBe(404);
    }
    const unknown = await fetch(new URL("/admin", running.base), { headers });
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toEqual({ error: "not_found" });
  });

  it("exposes only a strict, rate-limited, generic public certificate verdict", async () => {
    const calls: Array<{
      candidatePublicId: string | null;
      candidateBundle: unknown | null;
      clientIpClass: string;
    }> = [];
    const publicId = Buffer.alloc(32, 0xa7).toString("base64url");
    const running = await listen(
      (origin) =>
        createBoardAgentHttpRuntime({
          canonicalOrigin: origin,
          resourceUri: `${origin}/mcp`,
          boundary: new AuthRequestBoundary({ origin }),
          mcp: { fetch: async () => new Response(), close: async () => undefined },
          oauth: { callback: () => nodeHandler({ route: "oauth" }) },
          interaction: nodeHandler({ route: "interaction" }),
          enrollment: nodeHandler({ route: "enrollment" }),
          onboarding: nodeHandler({ route: "onboarding" }),
          readiness: { check: async () => ({ ready: true }) },
          publicCertificateVerifier: {
            verify: async (input) => {
              calls.push(input);
              if (calls.length === 4) {
                return { status: "rate_limited", retryAfterSeconds: 17 } as const;
              }
              return {
                status: "complete",
                valid: input.candidatePublicId === publicId || input.candidateBundle !== null
              } as const;
            }
          },
          includeHsts: true
        }).handler
    );
    const headers = {
      host: new URL(running.origin).host,
      "content-type": "application/json"
    };
    const valid = await fetch(new URL("/verify/certificate", running.base), {
      method: "POST",
      headers,
      body: JSON.stringify({
        schema_version: "boardagent.public-certificate-verification.v1",
        public_id: publicId
      })
    });
    expect(valid.status).toBe(200);
    expect(await valid.json()).toEqual({
      schema_version: "boardagent.public-certificate-verification.v1",
      valid: true
    });
    expect(calls[0]).toEqual({
      candidatePublicId: publicId,
      candidateBundle: null,
      clientIpClass: "ipv4:127.0.0.0/24"
    });

    const candidateBundle = { public_id: publicId, candidate: "opaque-bundle" };
    const bundled = await fetch(new URL("/verify/certificate", running.base), {
      method: "POST",
      headers,
      body: JSON.stringify({
        schema_version: "boardagent.public-certificate-verification.v1",
        bundle: candidateBundle
      })
    });
    expect(bundled.status).toBe(200);
    expect(await bundled.json()).toEqual({
      schema_version: "boardagent.public-certificate-verification.v1",
      valid: true
    });
    expect(calls[1]).toEqual({
      candidatePublicId: null,
      candidateBundle,
      clientIpClass: "ipv4:127.0.0.0/24"
    });

    const malformed = await fetch(new URL("/verify/certificate", running.base), {
      method: "POST",
      headers,
      body: JSON.stringify({
        schema_version: "boardagent.public-certificate-verification.v1",
        public_id: publicId,
        enumerable_vote_id: "forbidden"
      })
    });
    expect(malformed.status).toBe(200);
    expect(await malformed.json()).toEqual({
      schema_version: "boardagent.public-certificate-verification.v1",
      valid: false
    });
    expect(calls[2]).toMatchObject({ candidatePublicId: null, candidateBundle: null });

    const limited = await fetch(new URL("/verify/certificate", running.base), {
      method: "POST",
      headers,
      body: JSON.stringify({
        schema_version: "boardagent.public-certificate-verification.v1",
        public_id: Buffer.alloc(32, 0xb8).toString("base64url")
      })
    });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("17");
    expect(await limited.json()).toEqual({
      schema_version: "boardagent.public-certificate-verification.v1",
      valid: false
    });

    const wrongMethod = await fetch(new URL("/verify/certificate", running.base), {
      headers: { host: headers.host }
    });
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("allow")).toBe("POST");
    expect(calls).toHaveLength(4);
  });
});
