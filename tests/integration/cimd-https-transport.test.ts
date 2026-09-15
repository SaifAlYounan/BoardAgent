import { readFileSync } from "node:fs";
import { createServer, type RequestOptions } from "node:https";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import type { TLSSocket } from "node:tls";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock("node:https", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:https")>()),
  request: mocked.request
}));

import {
  fetchPinnedCimdDocument,
  resolveCimdClientMetadata
} from "../../artifacts/server/src/client-registration.js";

const clientId = "https://cimd-fixture.test/metadata";
const pinnedAddresses = [{ address: "127.0.0.1", family: 4 as const }];
const tls = {
  key: readFileSync(new URL("../fixtures/tls/cimd-transport.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/cimd-transport.crt", import.meta.url))
};
const body = Buffer.from(
  JSON.stringify({
    client_id: clientId,
    client_name: "Synthetic CIMD transport fixture",
    redirect_uris: ["https://cimd-fixture.test/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  })
);
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  try {
    for (const result of await Promise.allSettled(cleanups.splice(0).map((close) => close())))
      if (result.status === "rejected") throw result.reason;
  } finally {
    mocked.request.mockReset();
  }
});

// Transport-only fixture: injected loopback pin, explicit fixture trust and an
// ephemeral destination port. The public-address resolver is not bypassed or
// relabelled as passing. The production lookup, TLS verification, URL hostname,
// agent setting, actual ClientRequest/IncomingMessage and stream lifecycle remain.
async function fixture(mode: "complete" | "abort" | "trickle", trusted = true) {
  const actual = await vi.importActual<typeof import("node:https")>("node:https");
  const sockets = new Set<Duplex>();
  const socketClosures: Array<Promise<void>> = [];
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const requests: Array<{ host: string | undefined; servername: string | false | null }> = [];
  const clients: Array<{ request: ClientRequest; closed: Promise<void> }> = [];
  const tlsErrors: Error[] = [];
  const responseErrors: Error[] = [];
  let responseSeen!: () => void;
  const responseStarted = new Promise<void>((resolve) => {
    responseSeen = resolve;
  });
  const observed = { chunks: 0, bytes: 0 };
  const server = createServer(tls, (request, response) => {
    requests.push({
      host: request.headers.host,
      servername: (request.socket as TLSSocket).servername
    });
    response.on("error", (error) => responseErrors.push(error));
    response.setHeader("content-type", "application/json");
    if (mode === "complete") {
      response.end(body);
      return;
    }
    response.setHeader("content-length", String(body.length));
    response.write("{");
    response.flushHeaders();
    const timer =
      mode === "abort"
        ? setTimeout(() => response.destroy(), 30)
        : setInterval(() => response.write(" "), 25);
    timers.add(timer);
    response.once("close", () => {
      clearTimeout(timer);
      timers.delete(timer);
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socketClosures.push(
      new Promise<void>((resolve) => {
        socket.once("close", () => {
          sockets.delete(socket);
          resolve();
        });
      })
    );
  });
  server.on("tlsClientError", (error) => tlsErrors.push(error));
  cleanups.push(async () => {
    for (const timer of timers) clearTimeout(timer);
    for (const { request } of clients) request.destroy();
    server.closeAllConnections();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
    await Promise.all([...clients.map(({ closed }) => closed), ...socketClosures]);
    expect(sockets.size).toBe(0);
    expect(responseErrors).toEqual([]);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string" || address.port === 3000)
    throw new Error("missing allowed local CIMD test listener");
  const port = address.port;
  mocked.request.mockImplementation(
    (url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void) => {
      expect(url.protocol).toBe("https:");
      expect(url.port).toBe("");
      expect(["cimd-fixture.test", "wrong-cimd-fixture.test"]).toContain(url.hostname);
      expect(options).toMatchObject({
        agent: false,
        method: "GET",
        minVersion: "TLSv1.2",
        rejectUnauthorized: true
      });
      expect(options).not.toHaveProperty("checkServerIdentity");
      expect(options).not.toHaveProperty("servername");
      expect(options.lookup).toEqual(expect.any(Function));
      // Only fixture trust and port differ. Do not replace production pinned lookup,
      // hostname, certificate validation, request/response objects or event order.
      const request = actual.request(
        url,
        { ...options, port, ...(trusted ? { ca: tls.cert } : {}) },
        callback
      );
      const closed = new Promise<void>((resolve) => request.once("close", resolve));
      clients.push({ request, closed });
      request.once("response", (response) => {
        response.on("data", (chunk: Buffer) => {
          observed.chunks += 1;
          observed.bytes += chunk.length;
        });
        responseSeen();
      });
      return request;
    }
  );
  return { port, requests, clients, tlsErrors, responseStarted, observed };
}

function attempt(options: { clientId?: string; signal?: AbortSignal; timeoutMs?: number } = {}) {
  return fetchPinnedCimdDocument({
    clientId: options.clientId ?? clientId,
    pinnedAddresses,
    maxBytes: 1024,
    timeoutMs: options.timeoutMs ?? 2_000,
    ...(options.signal === undefined ? {} : { signal: options.signal })
  });
}

describe("CIMD transport over actual local HTTPS with injected loopback pins", () => {
  it("accepts a trusted certificate for the exact URL hostname and preserves exact bytes", async () => {
    const f = await fixture("complete");
    const response = await attempt();
    expect(response).toEqual({ statusCode: 200, contentType: "application/json", body });
    expect(f.requests).toEqual([
      { host: `cimd-fixture.test:${f.port}`, servername: "cimd-fixture.test" }
    ]);
    expect(f.tlsErrors).toEqual([]);
    expect(f.observed.bytes).toBe(body.length);
    await Promise.all(f.clients.map(({ closed }) => closed));
  });

  it("refuses the same endpoint when the fixture certificate is not trusted", async () => {
    const f = await fixture("complete", false);
    await expect(attempt()).rejects.toMatchObject({
      code: expect.stringMatching(
        /SELF_SIGNED_CERT|UNABLE_TO_VERIFY_LEAF_SIGNATURE|CERT_UNTRUSTED/u
      )
    });
    await Promise.all(f.clients.map(({ closed }) => closed));
    expect(f.requests).toEqual([]);
  });

  it("refuses a trusted certificate whose hostname differs from the exact URL", async () => {
    const f = await fixture("complete");
    await expect(
      attempt({ clientId: "https://wrong-cimd-fixture.test/metadata" })
    ).rejects.toMatchObject({ code: "ERR_TLS_CERT_ALTNAME_INVALID" });
    await Promise.all(f.clients.map(({ closed }) => closed));
    expect(f.requests).toEqual([]);
  });

  it("refuses an actual peer-aborted response after receiving partial bytes", async () => {
    const f = await fixture("abort");
    await expect(attempt()).rejects.toMatchObject({ code: "cimd_response_refused" });
    expect(f.observed.bytes).toBeGreaterThan(0);
    expect(f.observed.bytes).toBeLessThan(body.length);
    await Promise.all(f.clients.map(({ closed }) => closed));
    expect(f.clients.every(({ request }) => request.destroyed)).toBe(true);
  });

  it("cancels the actual request and response on AbortSignal after headers", async () => {
    const f = await fixture("trickle");
    const controller = new AbortController();
    const pending = attempt({ signal: controller.signal }).catch((error: unknown) => error);
    await f.responseStarted;
    controller.abort();
    await expect(pending).resolves.toMatchObject({ code: "cimd_timeout" });
    await Promise.all(f.clients.map(({ closed }) => closed));
    expect(f.clients.every(({ request }) => request.destroyed)).toBe(true);
  });

  it("applies its wall-clock deadline while an actual response keeps sending bytes", async () => {
    const f = await fixture("trickle");
    const started = performance.now();
    await expect(attempt({ timeoutMs: 250 })).rejects.toMatchObject({ code: "cimd_timeout" });
    const elapsed = performance.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(200);
    expect(elapsed).toBeLessThan(1_500);
    expect(f.observed.chunks).toBeGreaterThan(1);
    await Promise.all(f.clients.map(({ closed }) => closed));
    expect(f.clients.every(({ request }) => request.destroyed)).toBe(true);
  });

  it("keeps the real metadata resolver's loopback refusal before the fetch boundary", async () => {
    const fetcher = vi.fn(fetchPinnedCimdDocument);
    await expect(
      resolveCimdClientMetadata(clientId, ["governance:read"], {
        resolver: async () => pinnedAddresses,
        fetcher,
        timeoutMs: 500
      })
    ).rejects.toMatchObject({ code: "cimd_address_refused" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(mocked.request).not.toHaveBeenCalled();
  });
});
