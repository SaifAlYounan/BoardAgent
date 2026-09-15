import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, request as httpsRequest } from "node:https";
import type { ClientRequest, RequestListener } from "node:http";
import { Readable } from "node:stream";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo, StandardSchemaWithJSON } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AuthRequestBoundary,
  createBoardAgentHttpRuntime,
  createBoardAgentMcpHandler,
  type BoardAgentSurfaceService,
  type SurfaceResourceResult,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { createProtectedMcpHandler } from "../../artifacts/server/src/protected-mcp.js";
import { ResourceObservedMcpServer } from "../../artifacts/server/src/resource-delivery-transport.js";
import {
  attachPreparedResource,
  currentResourceDeliveryCollector,
  type ResourceDeliveryOutcome
} from "../../artifacts/server/src/resource-delivery.js";
import {
  ResponseAllocationManager,
  currentResponseAllocationOwner,
  loadWithResponseAllocation,
  responseAllocationPlan,
  type ResponseAllocationOwner,
  type TranscriptProjectionScalars
} from "../../artifacts/server/src/response-allocation.js";
import { TOOL_INPUT_SCHEMA_VERSION, canonicalJson } from "../../lib/contracts/src/index.js";

// Actual local HTTPS, the production BoardAgent factory, pinned SDK and native
// owner/collector. Service, token verification, metadata and audit storage are
// synthetic. Tiny exact-length plans test lifetime, not capacity or PostgreSQL.
const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  const results = await Promise.allSettled(cleanup.splice(0).map((work) => work()));
  for (const result of results) if (result.status === "rejected") throw result.reason;
});
const REQUEST_TIMEOUT_MS = 5_000;
const protocols = ["2026-07-28", "2025-11-25"] as const;
type Protocol = (typeof protocols)[number];
type Route = "resource" | "tool";
const cases = protocols.flatMap((protocol) =>
  (["resource", "tool"] as const).map((route) => ({ protocol, route }))
);
const id = (tail: number) => `018f47a1-1f5d-7c3a-8b22-${String(tail).padStart(12, "0")}`;
const digest = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function gate() {
  let release!: () => void;
  const state = {
    open: false,
    promise: new Promise<void>((resolve) => {
      release = resolve;
    })
  };
  return {
    get open() {
      return state.open;
    },
    promise: state.promise,
    release: () => {
      state.open = true;
      release();
    }
  };
}
const awaitGate = (value: ReturnType<typeof gate>) =>
  expect.poll(() => value.open, { timeout: 3_000 }).toBe(true);
const capture = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error })
  );

async function fixture(
  protocol: Protocol,
  options: {
    producerGate?: boolean;
    validationGate?: boolean;
    auditGate?: boolean;
  } = {}
) {
  const board = id(6),
    meeting = id(7),
    transcript = id(8),
    version = id(9);
  const uri = `board://${board}/meetings/${meeting}/transcripts/1`;
  const turn = {
    turn_id: id(10),
    speaker_member_id: null,
    speaker_label: "Synthetic secretary",
    starts_at_ms: null,
    ends_at_ms: null,
    canonical_text: 'Exact transcript "quotation", backslash \\ and Δ 😀\nSecond line.'
  };
  const canonical = canonicalJson({
    schema_version: "boardagent.transcript-turns.v1",
    values: { turns: [turn] }
  });
  const view = {
    transcript_id: transcript,
    meeting_id: meeting,
    state: "unverified",
    version_id: version,
    version: 1,
    canonical_schema: "boardagent.transcript-turns.v1",
    media_type: "application/json",
    canonical_body: canonical,
    sha256: digest(canonical),
    source_type: "agent_prepared",
    verification_state: "agent_prepared_unverified",
    supersedes_id: null,
    turns: [{ ...turn, ordinal: 1, sha256: digest(turn.canonical_text) }],
    challenges: [],
    verification: null
  };
  const flatBytes = (row: Record<string, unknown>, omit: ReadonlySet<string> = new Set()) =>
    Object.entries(row).reduce(
      (n, [key, value]) =>
        n +
        (omit.has(key) || value === null || typeof value === "object"
          ? 0
          : Buffer.byteLength(String(value), "utf8")),
      0
    );
  const projection: TranscriptProjectionScalars = {
    rootUtf8Bytes: String(flatBytes(view, new Set(["canonical_body"]))),
    turnCount: "1",
    turnUtf8Bytes: String(flatBytes(view.turns[0]!)),
    challengeCount: "0",
    challengeUtf8Bytes: "0",
    verificationCount: "0",
    verificationUtf8Bytes: "0"
  };
  const plans = {
    resource: responseAllocationPlan({
      kind: "transcript",
      representation: "resource",
      sourceId: version,
      sourceVersion: `${meeting}:1`,
      sha256: view.sha256,
      canonicalBytes: Buffer.byteLength(canonical)
    }),
    tool: responseAllocationPlan({
      kind: "transcript_tool",
      representation: "tool",
      sourceId: version,
      sourceVersion: `${transcript}:1`,
      sha256: view.sha256,
      canonicalBytes: Buffer.byteLength(canonical),
      transcriptProjection: projection
    })
  };
  expect(plans.resource.units).toBe(1);
  expect(plans.tool.units).toBe(1);
  const expectedTool: SurfaceToolResult = {
    schema_version: "boardagent.tool-result.v1",
    tool: "get_meeting_transcript",
    status: "ok",
    reference: version,
    resource_uri: null,
    data: { transcript: view }
  };
  const f = {
    manager: undefined as ResponseAllocationManager | undefined,
    owner: undefined as ResponseAllocationOwner | undefined,
    validationOwner: undefined as ResponseAllocationOwner | undefined,
    requests: new Map<Route, ClientRequest>(),
    nativeFinished: new Set<Route>(),
    nativeClosed: new Set<Route>(),
    wireBytes: 0,
    wireContentType: "",
    serviceReturned: false,
    loaded: false,
    prepared: [] as Array<{ id: string; uri: string; sha256: string; byteLength: number }>,
    recordCalls: [] as ResourceDeliveryOutcome[],
    outcomes: [] as ResourceDeliveryOutcome[],
    events: [] as string[],
    errors: [] as Error[],
    producerEntered: gate(),
    producerFinish: gate(),
    validationEntered: gate(),
    validationFinish: gate(),
    auditEntered: gate(),
    auditFinish: gate()
  };
  let client: Client | undefined;
  let closeRuntime: (() => Promise<void>) | undefined;
  let closeHttps: (() => Promise<void>) | undefined;
  const originalOpen = ResponseAllocationManager.prototype.openRequest;
  const managerSpy = vi
    .spyOn(ResponseAllocationManager.prototype, "openRequest")
    .mockImplementation(function (this: ResponseAllocationManager, signal: AbortSignal) {
      f.manager = this;
      return originalOpen.call(this, signal);
    });
  const originalRegister = ResourceObservedMcpServer.prototype.registerTool;
  const registerSpy = vi
    .spyOn(ResourceObservedMcpServer.prototype, "registerTool")
    .mockImplementation(function (
      this: ResourceObservedMcpServer,
      ...args: Parameters<typeof originalRegister>
    ) {
      const [name, config, callback] = args;
      if (name !== "get_meeting_transcript" || !options.validationGate)
        return Reflect.apply(originalRegister, this, args) as ReturnType<typeof originalRegister>;
      // Fresh per-registration Standard Schema decorator. JSON exports and the
      // original validator are delegated unchanged; no shared cache is mutated.
      const schema = config.outputSchema as StandardSchemaWithJSON;
      const standard = schema["~standard"];
      const gated: StandardSchemaWithJSON = {
        "~standard": {
          ...standard,
          validate: async (value, validationOptions) => {
            f.validationOwner = currentResponseAllocationOwner();
            f.validationEntered.release();
            await f.validationFinish.promise;
            return standard.validate(value, validationOptions);
          }
        }
      };
      return Reflect.apply(originalRegister, this, [
        name,
        { ...config, outputSchema: gated },
        callback
      ]) as ReturnType<typeof originalRegister>;
    });
  cleanup.push(async () => {
    f.producerFinish.release();
    f.validationFinish.release();
    f.auditFinish.release();
    for (const request of f.requests.values()) request.destroy();
    const failures: unknown[] = [];
    for (const close of [async () => client?.close(), closeRuntime, closeHttps]) {
      try {
        await close?.();
      } catch (error) {
        failures.push(error);
      }
    }
    registerSpy.mockRestore();
    managerSpy.mockRestore();
    if (failures.length)
      throw new AggregateError(failures, "transcript native fixture cleanup failed");
  });
  async function admitted<T extends object>(route: Route, result: T): Promise<T> {
    const owner = currentResponseAllocationOwner();
    if (!owner || !currentResourceDeliveryCollector())
      throw new Error("actual native owner/collector required");
    f.owner = owner;
    const loaded = await loadWithResponseAllocation(plans[route], async () => {
      f.producerEntered.release();
      if (options.producerGate) await f.producerFinish.promise;
      f.loaded = true;
      return result;
    });
    const preparedId = `synthetic-transcript-${route}`;
    f.prepared.push({
      id: preparedId,
      uri,
      sha256: view.sha256,
      byteLength: Buffer.byteLength(canonical)
    });
    f.serviceReturned = true;
    return attachPreparedResource(loaded, {
      preparedEventId: preparedId,
      byteLength: Buffer.byteLength(canonical),
      record: async (outcome) => {
        f.recordCalls.push(outcome);
        f.events.push("audit:entered");
        f.auditEntered.release();
        if (options.auditGate) await f.auditFinish.promise;
        f.outcomes.push(outcome);
        f.events.push("audit:settled");
      }
    });
  }
  function unsupported(): never {
    throw new Error("unsupported synthetic transcript action");
  }
  const service: BoardAgentSurfaceService = {
    executeRead: async (_principal, tool, input) => {
      expect(tool).toBe("get_meeting_transcript");
      expect(input).toEqual({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_id: transcript,
        version_id: version
      });
      return admitted("tool", expectedTool);
    },
    readResource: async (_principal, requested) => {
      expect(requested.href).toBe(uri);
      return admitted("resource", {
        uri,
        media_type: "application/json",
        text: canonical
      } satisfies SurfaceResourceResult);
    },
    executeDirect: async () => unsupported(),
    prepareHumanAction: async () => unsupported(),
    persistHumanStage: async () => unsupported(),
    resolveHumanAction: async () => unsupported()
  };
  let handler: RequestListener = (_request, response) => response.writeHead(503).end();
  const https = createServer(tls, (request, response) => {
    const tag = request.headers["x-transcript-fixture-route"];
    if (tag === "resource" || tag === "tool") {
      response.once("finish", () => {
        f.nativeFinished.add(tag);
        f.events.push("node:finish");
      });
      response.once("close", () => f.nativeClosed.add(tag));
    }
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
  const origin = `https://127.0.0.1:${address.port}`,
    resource = new URL("/mcp", origin);
  const auth: AuthInfo = {
    token: "synthetic-transcript-token",
    clientId: "https://synthetic-client.test/client.json",
    scopes: ["governance:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 600,
    resource,
    extra: {
      organizationId: id(1),
      memberId: id(2),
      internalClientId: id(3),
      accessTokenRecordId: id(4),
      jti: id(5),
      keyId: "synthetic-key",
      roles: ["member"],
      boardIds: [board]
    }
  };
  const protectedMcp = createProtectedMcpHandler({
    handler: createBoardAgentMcpHandler({
      service,
      requestStateKey: new Uint8Array(32).fill(0x47),
      requestStateTtlSeconds: 600
    }),
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
    if (new URL(request.url).origin !== origin)
      throw new Error("nonlocal transcript request refused");
    const body = request.body ? Buffer.from(await request.arrayBuffer()) : undefined;
    const parsed: unknown = body ? JSON.parse(body.toString("utf8")) : undefined;
    const params = object(parsed) ? parsed["params"] : undefined;
    const route: Route | undefined =
      object(parsed) && parsed["method"] === "resources/read"
        ? "resource"
        : object(params) && params["name"] === "get_meeting_transcript"
          ? "tool"
          : undefined;
    return new Promise<Response>((resolve, reject) => {
      const outgoing = httpsRequest(
        request.url,
        {
          method: request.method,
          headers: {
            ...Object.fromEntries(request.headers),
            authorization: "Bearer synthetic-transcript-token",
            ...(route ? { "x-transcript-fixture-route": route } : {})
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
          if (route) {
            f.wireContentType = headers.get("content-type") ?? "";
            incoming.on("data", (chunk: Buffer) => {
              f.wireBytes += chunk.length;
            });
          }
          const status = incoming.statusCode ?? 500;
          resolve(
            new Response(
              [204, 205, 304].includes(status)
                ? null
                : (Readable.toWeb(incoming) as ReadableStream<Uint8Array>),
              { status, headers }
            )
          );
        }
      );
      if (route) f.requests.set(route, outgoing);
      outgoing.once("error", reject);
      const abort = () => outgoing.destroy(new Error("synthetic transcript client cancelled"));
      request.signal.addEventListener("abort", abort, { once: true });
      outgoing.once("close", () => {
        if (route && f.requests.get(route) === outgoing) f.requests.delete(route);
        request.signal.removeEventListener("abort", abort);
      });
      if (request.signal.aborted) abort();
      else outgoing.end(body);
    });
  };
  client = new Client(
    { name: "transcript-native-client", version: "1" },
    {
      capabilities: {},
      versionNegotiation: { mode: protocol === "2025-11-25" ? "legacy" : { pin: protocol } },
      cachePartition: "synthetic-transcript-native"
    }
  );
  await client.connect(new StreamableHTTPClientTransport(resource, { fetch: transportFetch }), {
    timeout: REQUEST_TIMEOUT_MS
  });
  expect(client.getNegotiatedProtocolVersion()).toBe(protocol);
  expect(client.getProtocolEra()).toBe(protocol === "2025-11-25" ? "legacy" : "modern");
  const call = async (route: Route): Promise<unknown> =>
    route === "resource"
      ? client!.readResource(
          { uri },
          { timeout: REQUEST_TIMEOUT_MS, maxTotalTimeout: REQUEST_TIMEOUT_MS }
        )
      : client!.callTool(
          {
            name: "get_meeting_transcript",
            arguments: {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              transcript_id: transcript,
              version_id: version
            }
          },
          { timeout: REQUEST_TIMEOUT_MS, maxTotalTimeout: REQUEST_TIMEOUT_MS }
        );
  const zero = () => expect.poll(() => f.manager?.accounting.usedUnits, { timeout: 3_000 }).toBe(0);
  return { f, canonical, view, uri, expectedTool, call, zero };
}

describe.sequential("native transcript admission and delivery", () => {
  it.each(cases)(
    "preserves exact $route bytes and native completion through held audit ($protocol)",
    async ({ protocol, route }) => {
      const { f, canonical, view, uri, expectedTool, call, zero } = await fixture(protocol, {
        auditGate: true
      });
      const pending = capture(call(route));
      try {
        await awaitGate(f.auditEntered);
        await expect.poll(() => f.nativeFinished.has(route)).toBe(true);
        let producerDone = false;
        void f.owner!.whenProducersDone().then(() => {
          producerDone = true;
        });
        await expect.poll(() => producerDone, { timeout: 3_000 }).toBe(true);
        expect(f.manager?.accounting).toEqual({ usedUnits: 1, largeUsedUnits: 0 });
        expect(f.recordCalls).toHaveLength(1);
        expect(f.outcomes).toEqual([]);
        const reply = await pending;
        expect(reply.error).toBeUndefined();
        const value = reply.value!;
        if (route === "resource") {
          expect(value).toMatchObject({
            contents: [{ uri, mimeType: "application/json", text: canonical }]
          });
          const text = (value as { contents: Array<{ text: string }> }).contents[0]!.text;
          expect(digest(text)).toBe(view.sha256);
        } else {
          expect((value as { isError?: boolean }).isError).not.toBe(true);
          const result = value as {
            content: Array<{ type: string; text?: string }>;
            structuredContent: SurfaceToolResult;
          };
          expect(result.structuredContent).toEqual(expectedTool);
          expect(JSON.parse(result.content[0]!.text!)).toEqual(expectedTool);
          const returned = result.structuredContent.data as { transcript: typeof view };
          expect(returned.transcript).toEqual(view);
          expect(digest(returned.transcript.canonical_body)).toBe(returned.transcript.sha256);
          expect(returned.transcript.media_type).toBe("application/json");
        }
        expect(f.wireContentType).toContain(
          protocol === "2025-11-25" ? "text/event-stream" : "application/json"
        );
        expect(f.recordCalls[0]).toMatchObject({
          outcome: "completed",
          bytesTransferred: Buffer.byteLength(canonical),
          observationBasis: "node_response_finish"
        });
        expect(f.recordCalls[0]!.responseBytesQueued).toBe(f.wireBytes);
        expect(f.wireBytes).toBeGreaterThan(Buffer.byteLength(canonical));
        expect(f.events.indexOf("node:finish")).toBeLessThan(f.events.indexOf("audit:entered"));
        f.auditFinish.release();
        await zero();
        expect(f.outcomes).toEqual(f.recordCalls);
        expect(f.outcomes).toHaveLength(1);
        expect(f.errors).toEqual([]);
      } finally {
        f.auditFinish.release();
        await pending;
      }
    },
    15_000
  );

  it.each(cases)(
    "retains $route admission after HTTPS disconnect until the held producer settles ($protocol)",
    async ({ protocol, route }) => {
      const { f, call, zero } = await fixture(protocol, { producerGate: true });
      const pending = capture(call(route));
      try {
        await awaitGate(f.producerEntered);
        expect(f.manager?.accounting.usedUnits).toBe(1);
        expect(f.loaded).toBe(false);
        expect(f.prepared).toEqual([]);
        let producerDone = false;
        void f.owner!.whenProducersDone().then(() => {
          producerDone = true;
        });
        const outgoing = f.requests.get(route);
        expect(outgoing).toBeDefined();
        outgoing!.destroy(new Error("intentional real HTTPS transcript disconnect"));
        await expect.poll(() => f.owner?.signal.aborted).toBe(true);
        await expect.poll(() => f.nativeClosed.has(route)).toBe(true);
        expect(producerDone).toBe(false);
        expect(f.manager?.accounting.usedUnits).toBe(1);
        expect(f.recordCalls).toEqual([]);
        expect(f.wireBytes).toBe(0);
        f.producerFinish.release();
        await expect.poll(() => producerDone, { timeout: 3_000 }).toBe(true);
        expect((await pending).error).toBeDefined();
        await zero();
        expect(f.outcomes).toHaveLength(1);
        expect(f.outcomes[0]).toMatchObject({ outcome: "interrupted", bytesTransferred: 0 });
        expect(f.nativeFinished.has(route)).toBe(false);
      } finally {
        f.producerFinish.release();
        await pending;
      }
    },
    15_000
  );

  it.each(protocols)(
    "retains composite admission after HTTPS disconnect during actual SDK output validation (%s)",
    async (protocol) => {
      const { f, call, zero } = await fixture(protocol, { validationGate: true });
      const pending = capture(call("tool"));
      try {
        await awaitGate(f.validationEntered);
        expect(f.serviceReturned).toBe(true);
        expect(f.loaded).toBe(true);
        expect(f.validationOwner).toBe(f.owner);
        expect(f.manager?.accounting.usedUnits).toBe(1);
        const outgoing = f.requests.get("tool");
        expect(outgoing).toBeDefined();
        outgoing!.destroy(new Error("intentional HTTPS disconnect during transcript validation"));
        await expect.poll(() => f.owner?.signal.aborted).toBe(true);
        await expect.poll(() => f.nativeClosed.has("tool")).toBe(true);
        expect(f.manager?.accounting.usedUnits).toBe(1);
        expect(f.recordCalls).toEqual([]);
        expect(f.wireBytes).toBe(0);
        f.validationFinish.release();
        expect((await pending).error).toBeDefined();
        await zero();
        expect(f.outcomes).toHaveLength(1);
        expect(f.outcomes[0]).toMatchObject({ outcome: "interrupted", bytesTransferred: 0 });
        expect(f.nativeFinished.has("tool")).toBe(false);
      } finally {
        f.validationFinish.release();
        await pending;
      }
    },
    15_000
  );
});
