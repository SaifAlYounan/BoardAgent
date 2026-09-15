import { readFileSync } from "node:fs";
import { createServer, request as httpsRequest } from "node:https";
import type { ClientRequest, RequestListener } from "node:http";
import { Readable } from "node:stream";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpHandler, type AuthInfo, type Transport } from "@modelcontextprotocol/server";
import { z } from "zod";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthRequestBoundary } from "../../artifacts/server/src/auth-page.js";
import { createBoardAgentHttpRuntime } from "../../artifacts/server/src/http-runtime.js";
import { createProtectedMcpHandler } from "../../artifacts/server/src/protected-mcp.js";
import { ResourceObservedMcpServer } from "../../artifacts/server/src/resource-delivery-transport.js";
import {
  ResourceDeliveryCollector,
  attachPreparedResource,
  bindResourceDeliveryResponse,
  currentResourceDeliveryCollector,
  registerPreparedResource,
  registerResourceResponse,
  type ResourceDeliveryOutcome
} from "../../artifacts/server/src/resource-delivery.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  currentResponseAllocationOwner,
  loadWithResponseAllocation,
  responseAllocationPlan,
  type ResponseAllocationOwner
} from "../../artifacts/server/src/response-allocation.js";

// Real native HTTPS + pinned SDK. Only service/audit and explicit fault gates are
// synthetic. The maximum allocation charge uses a tiny body to test accounting,
// not to claim a maximum-payload memory or database qualification.
const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  const results = await Promise.allSettled(cleanup.splice(0).map((work) => work()));
  for (const result of results) if (result.status === "rejected") throw result.reason;
});
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
type ProtocolVersion = "2026-07-28" | "2025-11-25";
type Tag = "held" | "competing" | "later";
function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Delegate the complete current public interface. The real SDK still constructs,
// frames, serializes and correlates every message. Faults affect only its observed
// completion promise after the untouched actual send invocation.
function delegateTransport(transport: Transport, send: Transport["send"]): Transport {
  return {
    start: () => transport.start(),
    close: () => transport.close(),
    send,
    get onmessage() {
      return transport.onmessage;
    },
    set onmessage(value) {
      transport.onmessage = value;
    },
    get onclose() {
      return transport.onclose;
    },
    set onclose(value) {
      transport.onclose = value;
    },
    get onerror() {
      return transport.onerror;
    },
    set onerror(value) {
      transport.onerror = value;
    },
    get sessionId() {
      return transport.sessionId;
    },
    set sessionId(value) {
      transport.sessionId = value;
    },
    ...(transport.hasPerRequestStream === undefined
      ? {}
      : { hasPerRequestStream: transport.hasPerRequestStream }),
    ...(transport.setProtocolVersion === undefined
      ? {}
      : { setProtocolVersion: (version: string) => transport.setProtocolVersion!(version) }),
    ...(transport.setSupportedProtocolVersions === undefined
      ? {}
      : {
          setSupportedProtocolVersions: (versions: string[]) =>
            transport.setSupportedProtocolVersions!(versions)
        })
  };
}

async function fixture(
  version: ProtocolVersion,
  options: {
    validationGate?: boolean;
    validationFailure?: boolean;
    sendGate?: boolean;
    sendReject?: boolean;
    auditGate?: boolean;
    auditReject?: boolean;
  } = {}
) {
  const f = {
    manager: undefined as ResponseAllocationManager | undefined,
    contexts: new Map<
      Tag,
      {
        owner: ResponseAllocationOwner;
        collector: ResourceDeliveryCollector;
        requestId: string | number;
      }
    >(),
    callbacksReturned: new Set<Tag>(),
    loaded: [] as Tag[],
    nativeFinished: new Set<string>(),
    nativeClosed: new Set<string>(),
    sends: [] as Array<{ tag: Tag | undefined; id: unknown; hasCanonicalResult: boolean }>,
    recordCalls: [] as Array<{ tag: Tag; outcome: ResourceDeliveryOutcome }>,
    errors: [] as Error[],
    sdkErrors: [] as Error[],
    requests: new Map<string, ClientRequest>(),
    validationEntered: gate(),
    validationFinish: gate(),
    actualSendReturned: gate(),
    sendFinish: gate(),
    auditEntered: gate(),
    auditFinish: gate()
  };
  const clients: Client[] = [];
  let closeRuntime: (() => Promise<void>) | undefined;
  let closeHttps: (() => Promise<void>) | undefined;
  const originalOpen = ResponseAllocationManager.prototype.openRequest;
  const managerSpy = vi
    .spyOn(ResponseAllocationManager.prototype, "openRequest")
    .mockImplementation(function (this: ResponseAllocationManager, signal: AbortSignal) {
      f.manager = this;
      return originalOpen.call(this, signal);
    });
  cleanup.push(async () => {
    f.validationFinish.release();
    f.sendFinish.release();
    f.auditFinish.release();
    for (const request of f.requests.values()) request.destroy();
    const failures: unknown[] = [];
    for (const result of await Promise.allSettled(clients.map((client) => client.close())))
      if (result.status === "rejected") failures.push(result.reason);
    for (const close of [closeRuntime, closeHttps]) {
      try {
        await close?.();
      } catch (error) {
        failures.push(error);
      }
    }
    managerSpy.mockRestore();
    if (failures.length)
      throw new AggregateError(failures, "native allocation fixture cleanup failed");
  });
  const base = createMcpHandler(
    async () => {
      let servingTag: Tag | undefined;
      class FaultObservedServer extends ResourceObservedMcpServer {
        public override connect(transport: Transport): Promise<void> {
          const send: Transport["send"] = (message, sendOptions) => {
            const result = "result" in message ? message.result : undefined;
            const structured = isObject(result) ? result["structuredContent"] : undefined;
            const terminal = isObject(message) && ("result" in message || "error" in message);
            if (terminal)
              f.sends.push({
                tag: servingTag,
                id: message["id"],
                hasCanonicalResult: isObject(structured) && typeof structured["body"] === "string"
              });
            const actual = transport.send(message, sendOptions);
            if (servingTag !== "held" || !options.sendGate || !terminal) return actual;
            return actual.then(async () => {
              f.actualSendReturned.release();
              await f.sendFinish.promise;
              if (options.sendReject)
                throw new Error("synthetic delegated-send completion failure");
            });
          };
          return super.connect(delegateTransport(transport, send));
        }
      }
      const server = new FaultObservedServer(
        { name: "native-allocation-lifetime-fixture", version: "1" },
        {
          supportedProtocolVersions: ["2026-07-28", "2025-11-25"]
        }
      );
      server.server.onerror = (error) => f.sdkErrors.push(error);
      server.registerTool(
        "allocation_fixture",
        {
          inputSchema: z.object({ tag: z.enum(["held", "competing", "later"]) }),
          outputSchema: z
            .object({ tag: z.enum(["held", "competing", "later"]), body: z.string() })
            .superRefine(async (value, context) => {
              if (value.tag !== "held") return;
              if (options.validationGate) {
                f.validationEntered.release();
                await f.validationFinish.promise;
              }
              if (options.validationFailure)
                context.addIssue({
                  code: "custom",
                  message: "synthetic SDK output validation failure"
                });
            })
        },
        async ({ tag }, ctx) => {
          servingTag = tag;
          const owner = currentResponseAllocationOwner();
          const collector = currentResourceDeliveryCollector();
          if (!owner || !collector) throw new Error("native owner and collector required");
          f.contexts.set(tag, { owner, collector, requestId: ctx.mcpReq.id });
          try {
            const plan = responseAllocationPlan({
              kind: "document",
              representation: "tool",
              sourceId: `synthetic-${tag}`,
              sourceVersion: "1",
              sha256: "a".repeat(64),
              canonicalBytes: 10_485_760
            });
            await loadWithResponseAllocation(plan, async () => {
              f.loaded.push(tag);
            });
            const body = `synthetic canonical source: ${tag}`;
            const source = attachPreparedResource(
              { body },
              {
                preparedEventId: `synthetic-prepared-${tag}`,
                byteLength: Buffer.byteLength(body),
                record: async (outcome) => {
                  f.recordCalls.push({ tag, outcome });
                  if (tag === "held" && options.auditGate) {
                    f.auditEntered.release();
                    await f.auditFinish.promise;
                  }
                  if (tag === "held" && options.auditReject)
                    throw new Error("synthetic audit completion failure");
                }
              }
            );
            registerPreparedResource(source, ctx.mcpReq.id);
            const output = {
              content: [{ type: "text" as const, text: body }],
              structuredContent: { tag, body }
            };
            registerResourceResponse(source, ctx.mcpReq.id, output);
            f.callbacksReturned.add(tag);
            return output;
          } catch (error) {
            if (!(error instanceof ResponseAllocationUnavailable)) throw error;
            const value = {
              code: "response_capacity_busy",
              message: "Response capacity is busy. Retry this read shortly.",
              retryable: true
            };
            return {
              isError: true,
              content: [{ type: "text" as const, text: JSON.stringify(value) }],
              structuredContent: value
            };
          }
        }
      );
      return server;
    },
    { legacy: "stateless", responseMode: "json", maxSubscriptions: 0, keepAliveMs: 0 }
  );
  let handler: RequestListener = (_request, response) => response.writeHead(503).end();
  const https = createServer(tls, (request, response) => {
    const tag = String(request.headers["x-allocation-fixture-tag"] ?? "initialization");
    response.once("finish", () => f.nativeFinished.add(tag));
    response.once("close", () => f.nativeClosed.add(tag));
    handler(request, response);
  });
  closeHttps = async () => {
    https.closeAllConnections();
    await new Promise<void>((resolve) => https.close(() => resolve()));
  };
  https.on("clientError", () => undefined);
  await new Promise<void>((resolve, reject) => {
    https.once("error", reject);
    https.listen(0, "127.0.0.1", resolve);
  });
  const address = https.address();
  if (!address || typeof address === "string" || address.port === 3000)
    throw new Error("missing permitted ephemeral HTTPS address");
  const origin = `https://127.0.0.1:${address.port}`;
  const resource = new URL("/mcp", origin);
  const auth: AuthInfo = {
    token: "synthetic-allocation-token",
    clientId: "https://synthetic-client.test/client.json",
    scopes: ["documents:read"],
    resource,
    expiresAt: Math.floor(Date.now() / 1000) + 120
  };
  const protectedMcp = createProtectedMcpHandler({
    handler: {
      ...base,
      fetch: async (request, requestOptions) =>
        bindResourceDeliveryResponse(await base.fetch(request, requestOptions))
    },
    resourceUri: resource.href,
    verifier: { verifyAccessToken: async () => auth }
  });
  const unused: RequestListener = (_request, response) => response.writeHead(404).end();
  const runtime = createBoardAgentHttpRuntime({
    canonicalOrigin: origin,
    resourceUri: resource.href,
    boundary: new AuthRequestBoundary({ origin }),
    mcp: protectedMcp,
    oauth: { callback: () => unused },
    interaction: unused,
    enrollment: unused,
    onboarding: unused,
    readiness: { check: async () => ({ ready: true }) },
    publicCertificateVerifier: { verify: async () => ({ status: "complete", valid: false }) },
    includeHsts: false,
    onError: (error) => f.errors.push(error)
  });
  closeRuntime = () => runtime.close();
  handler = runtime.handler;
  const transportFetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    if (new URL(request.url).origin !== origin) throw new Error("nonlocal fixture request refused");
    const body = request.body ? Buffer.from(await request.arrayBuffer()) : undefined;
    const parsed: unknown = body ? JSON.parse(body.toString("utf8")) : undefined;
    const params = isObject(parsed) ? parsed["params"] : undefined;
    const args = isObject(params) ? params["arguments"] : undefined;
    const tag = isObject(args) && typeof args["tag"] === "string" ? args["tag"] : "initialization";
    return new Promise<Response>((resolve, reject) => {
      const outgoing = httpsRequest(
        request.url,
        {
          method: request.method,
          headers: {
            ...Object.fromEntries(request.headers),
            authorization: "Bearer synthetic-allocation-token",
            "x-allocation-fixture-tag": tag
          },
          ca: tls.cert,
          agent: false
        },
        (incoming) => {
          const headers = new Headers();
          for (const [name, value] of Object.entries(incoming.headers)) {
            if (typeof value === "string") headers.set(name, value);
            else if (Array.isArray(value)) for (const part of value) headers.append(name, part);
          }
          const status = incoming.statusCode ?? 500;
          resolve(
            new Response(
              [204, 205, 304].includes(status)
                ? null
                : (Readable.toWeb(incoming) as ReadableStream<Uint8Array>),
              {
                status,
                headers
              }
            )
          );
        }
      );
      f.requests.set(tag, outgoing);
      outgoing.once("error", reject);
      const abort = () => outgoing.destroy(new Error("synthetic client request cancelled"));
      request.signal.addEventListener("abort", abort, { once: true });
      outgoing.once("close", () => {
        if (f.requests.get(tag) === outgoing) f.requests.delete(tag);
        request.signal.removeEventListener("abort", abort);
      });
      if (request.signal.aborted) abort();
      else outgoing.end(body);
    });
  };
  async function connect() {
    const client = new Client(
      { name: "native-allocation-client", version: "1" },
      {
        capabilities: {},
        versionNegotiation: { mode: version === "2025-11-25" ? "legacy" : { pin: version } },
        cachePartition: "native-allocation-synthetic"
      }
    );
    clients.push(client);
    await client.connect(new StreamableHTTPClientTransport(resource, { fetch: transportFetch }));
    expect(client.getNegotiatedProtocolVersion()).toBe(version);
    expect(client.getProtocolEra()).toBe(version === "2025-11-25" ? "legacy" : "modern");
    return client;
  }
  const one = await connect();
  const two = await connect();
  const call = (client: Client, tag: Tag) =>
    client.callTool({ name: "allocation_fixture", arguments: { tag } });
  async function zero() {
    await expect.poll(() => f.manager?.accounting.usedUnits, { timeout: 3_000 }).toBe(0);
  }
  async function busy() {
    const response = await call(two, "competing");
    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({
      code: "response_capacity_busy",
      retryable: true
    });
    expect(f.loaded).not.toContain("competing");
  }
  async function later() {
    const response = await call(two, "later");
    expect(response.isError).not.toBe(true);
    await zero();
    expect(f.loaded).toContain("later");
  }
  return { f, one, two, call, zero, busy, later };
}

describe.sequential("native response allocation lifetime supplement", () => {
  it.each(["2026-07-28", "2025-11-25"] as const)(
    "retains allocation after real HTTPS cancellation while SDK output validation is blocked (%s)",
    async (version) => {
      const { f, one, call, busy, later, zero } = await fixture(version, { validationGate: true });
      const held = call(one, "held").then(
        (value) => ({ value }),
        (error: unknown) => ({ error })
      );
      await f.validationEntered.promise;
      expect(f.callbacksReturned.has("held")).toBe(true);
      expect(f.manager?.accounting.usedUnits).toBe(1_281);
      const outgoing = f.requests.get("held");
      expect(outgoing).toBeDefined();
      outgoing!.destroy(new Error("intentional real HTTPS client disconnect"));
      await expect.poll(() => f.contexts.get("held")?.owner.signal.aborted).toBe(true);
      await expect.poll(() => f.nativeClosed.has("held")).toBe(true);
      await busy();
      expect(f.manager?.accounting.usedUnits).toBe(1_281);
      expect(f.recordCalls.filter((entry) => entry.tag === "held")).toEqual([]);
      expect(f.sends.filter((entry) => entry.tag === "held" && entry.hasCanonicalResult)).toEqual(
        []
      );
      // No manual nativeTerminal, initial collector.settle or client.close supplies proof.
      f.validationFinish.release();
      expect(await held).toHaveProperty("error");
      await zero();
      const records = f.recordCalls.filter((entry) => entry.tag === "held");
      expect(records).toHaveLength(1);
      expect(records[0]!.outcome).toMatchObject({ outcome: "interrupted", bytesTransferred: 0 });
      expect(f.sends.filter((entry) => entry.tag === "held" && entry.hasCanonicalResult)).toEqual(
        []
      );
      await later();
    },
    15_000
  );

  it.each([false, true])(
    "retains allocation through a gated delegated actual-send promise, reject=%s",
    async (reject) => {
      const { f, one, call, busy, later, zero } = await fixture("2026-07-28", {
        sendGate: true,
        sendReject: reject
      });
      const held = call(one, "held").catch((error: unknown) => error);
      await f.actualSendReturned.promise;
      await expect.poll(() => f.nativeFinished.has("held")).toBe(true);
      await f.contexts.get("held")!.owner.whenProducersDone();
      expect(f.manager?.accounting.usedUnits).toBe(1_281);
      expect(f.recordCalls.filter((entry) => entry.tag === "held")).toEqual([]);
      await busy();
      f.sendFinish.release();
      await held;
      await zero();
      const records = f.recordCalls.filter((entry) => entry.tag === "held");
      expect(records).toHaveLength(1);
      expect(records[0]!.outcome.outcome).toBe(reject ? "interrupted" : "completed");
      if (reject) expect(records[0]!.outcome.observationBasis).toBe("response_not_associated");
      expect(
        f.sends.filter((entry) => entry.tag === "held" && entry.hasCanonicalResult)
      ).toHaveLength(1);
      await later();
    },
    15_000
  );

  it.each([false, true])(
    "retains allocation until gated audit settlement and reuses settlement once, reject=%s",
    async (reject) => {
      const { f, one, call, busy, later, zero } = await fixture("2026-07-28", {
        auditGate: true,
        auditReject: reject
      });
      const held = call(one, "held").catch((error: unknown) => error);
      await f.auditEntered.promise;
      await expect.poll(() => f.nativeFinished.has("held")).toBe(true);
      await f.contexts.get("held")!.owner.whenProducersDone();
      expect(f.manager?.accounting.usedUnits).toBe(1_281);
      await busy();
      const collector = f.contexts.get("held")!.collector;
      // Native settlement already entered record(). These are duplicate calls only.
      const repeatOne = collector.settle("interrupted", 0, false);
      const repeatTwo = collector.settle("completed", 9_999, true);
      expect(repeatTwo).toBe(repeatOne);
      expect(f.recordCalls.filter((entry) => entry.tag === "held")).toHaveLength(1);
      f.auditFinish.release();
      const failures = await repeatOne;
      await held;
      await zero();
      expect(failures).toHaveLength(reject ? 1 : 0);
      expect(await repeatTwo).toBe(failures);
      expect(f.recordCalls.filter((entry) => entry.tag === "held")).toHaveLength(1);
      expect(f.manager?.accounting).toEqual({ usedUnits: 0, largeUsedUnits: 0 });
      if (reject)
        await expect
          .poll(() =>
            f.errors.some(
              (error) =>
                (error as Error & { code?: string }).code ===
                "resource_delivery_outcome_audit_unavailable"
            )
          )
          .toBe(true);
      await later();
    },
    15_000
  );

  it.each(["2026-07-28", "2025-11-25"] as const)(
    "settles allocation after SDK output-validation failure without a completed delivery (%s)",
    async (version) => {
      const { f, one, call, later, zero } = await fixture(version, { validationFailure: true });
      const response = await call(one, "held");
      expect(response.isError).toBe(true);
      await zero();
      await expect.poll(() => f.nativeFinished.has("held")).toBe(true);
      const records = f.recordCalls.filter((entry) => entry.tag === "held");
      expect(records).toHaveLength(1);
      expect(records[0]!.outcome).toMatchObject({
        outcome: "interrupted",
        observationBasis: "response_not_associated"
      });
      expect(f.sends.filter((entry) => entry.tag === "held" && entry.hasCanonicalResult)).toEqual(
        []
      );
      await later();
    },
    15_000
  );
});
