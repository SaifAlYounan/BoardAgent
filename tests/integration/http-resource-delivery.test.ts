import {
  loadWithResponseAllocation,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { readFileSync } from "node:fs";
import { createServer, request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import type { RequestListener, ServerResponse } from "node:http";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";
import {
  AuthRequestBoundary,
  createBoardAgentHttpRuntime,
  createBoardAgentMcpHandler,
  type BoardAgentSurfaceService,
  type SurfaceResourceResult,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { createProtectedMcpHandler } from "../../artifacts/server/src/protected-mcp.js";
import {
  attachPreparedResource,
  type ResourceDeliveryOutcome
} from "../../artifacts/server/src/resource-delivery.js";
import { TOOL_INPUT_SCHEMA_VERSION, type JsonValue } from "../../lib/contracts/src/index.js";

const ids = Array.from({ length: 8 }, (_value, i) => `018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e0${i + 1}`);
const board = ids[5]!;
const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  const results = await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup()));
  for (const result of results) if (result.status === "rejected") throw result.reason;
});

function unsupported(): never {
  throw new Error("unsupported synthetic service action");
}

async function fixture(protocol: "2026-07-28" | "2025-11-25" = "2026-07-28") {
  const f = {
    canonical: "canonical source with \\ and Δ\n",
    binary: false,
    invalidResult: false,
    failAudit: false,
    substituteResponse: false,
    abortOnData: false,
    endBeforeWrite: false,
    writeAfterEnd: false,
    nodeErrors: [] as Error[],
    outcomes: [] as Array<ResourceDeliveryOutcome & { preparedEventId: string }>,
    errors: [] as Error[],
    prepared: [] as string[],
    events: [] as string[],
    preparedBytes: new Map<string, number>(),
    preparedSources: new Map<string, string>(),
    documents: new Map<string, string>(),
    beforeRead: undefined as ((documentId: string) => Promise<void>) | undefined,
    readRequestIds: [] as Array<{ id: string | number; documentId: string }>,
    transferred: 0
  };
  function prepared<T extends object>(value: T, canonical = f.canonical): T {
    const preparedEventId = `synthetic-prepared-${f.prepared.length + 1}`;
    f.prepared.push(preparedEventId);
    f.events.push(`prepared:${preparedEventId}`);
    const byteLength = f.binary
      ? Buffer.from(canonical, "base64url").byteLength
      : Buffer.byteLength(canonical);
    f.preparedBytes.set(preparedEventId, byteLength);
    f.preparedSources.set(preparedEventId, canonical);
    return attachPreparedResource(value, {
      preparedEventId,
      byteLength,
      record: async (outcome) => {
        if (f.failAudit) throw new Error("synthetic outcome storage failure");
        f.events.push(`outcome:${outcome.outcome}:${preparedEventId}`);
        f.outcomes.push({ ...outcome, preparedEventId });
      }
    });
  }
  const service: BoardAgentSurfaceService = {
    executeRead: async (_principal, tool, input) => {
      const documentId = (input as { document_id?: string }).document_id ?? "";
      const canonical = f.documents.get(documentId) ?? f.canonical;
      await f.beforeRead?.(documentId);
      return prepared(
        {
          schema_version: "boardagent.tool-result.v1",
          tool,
          status: f.invalidResult ? "invalid" : "ok",
          reference: null,
          resource_uri: null,
          data: f.binary
            ? { bytes: canonical, encoding: "base64url" }
            : { canonical_body: canonical }
        } as SurfaceToolResult,
        canonical
      );
    },
    readResource: async (_principal, uri) =>
      prepared({
        uri: f.invalidResult ? "board://invalid-resource-binding" : uri.href,
        media_type: "text/plain; charset=utf-8",
        text: f.canonical
      } satisfies SurfaceResourceResult),
    executeDirect: async () => unsupported(),
    prepareHumanAction: async () => unsupported(),
    persistHumanStage: async () => unsupported(),
    resolveHumanAction: async () => unsupported()
  };
  let handler: RequestListener = (_request, response) => response.writeHead(503).end();
  let currentResponse: ServerResponse | undefined;
  const server = createServer(tls, (request, response) => {
    currentResponse = response;
    response.on("error", (error) => f.nodeErrors.push(error));
    if (f.writeAfterEnd) {
      // Controlled lifecycle fault on a real ServerResponse: Node itself emits
      // ERR_STREAM_WRITE_AFTER_END; no manually emitted error or fake sink.
      const write = response.write.bind(response);
      response.write = ((chunk: Uint8Array) => {
        response.end();
        return write(chunk);
      }) as typeof response.write;
    }
    response.once("finish", () => f.events.push("node:finish"));
    response.once("close", () => f.events.push("node:close"));
    handler(request, response);
  });
  server.on("clientError", () => undefined);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing local HTTPS listener");
  const origin = `https://127.0.0.1:${address.port}`;
  const resource = new URL(`${origin}/mcp`);
  const mcp = createBoardAgentMcpHandler({
    service,
    requestStateKey: new Uint8Array(32).fill(0x73),
    requestStateTtlSeconds: 600
  });
  const auth: AuthInfo = {
    token: "synthetic-token",
    clientId: "https://synthetic-client.test/client.json",
    scopes: ["governance:read", "documents:read", "audit:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 600,
    resource,
    extra: {
      organizationId: ids[0],
      memberId: ids[1],
      internalClientId: ids[2],
      accessTokenRecordId: ids[3],
      jti: ids[4],
      keyId: "synthetic-key",
      roles: ["member"],
      boardIds: [board]
    }
  };
  const protectedMcp = createProtectedMcpHandler({
    handler: mcp,
    resourceUri: resource.href,
    verifier: { verifyAccessToken: async () => auth }
  });
  const unused: RequestListener = (_request, response) => response.writeHead(404).end();
  const runtime = createBoardAgentHttpRuntime({
    canonicalOrigin: origin,
    resourceUri: resource.href,
    boundary: new AuthRequestBoundary({ origin }),
    mcp: {
      ...protectedMcp,
      fetch: async (request, options) => {
        const input = f.substituteResponse
          ? ((await request.clone().json()) as { id: number | string })
          : undefined;
        const response = await protectedMcp.fetch(request, options);
        if (f.endBeforeWrite && f.prepared.length > 0) currentResponse!.end();
        return f.substituteResponse && f.prepared.length > 0
          ? Response.json({
              jsonrpc: "2.0",
              id: input!.id,
              error: { code: -32603, message: "substituted response" }
            })
          : response;
      }
    },
    oauth: { callback: () => unused },
    interaction: unused,
    enrollment: unused,
    onboarding: unused,
    readiness: { check: async () => ({ ready: true }) },
    publicCertificateVerifier: { verify: async () => ({ status: "complete", valid: false }) },
    includeHsts: false,
    onError: (error) => f.errors.push(error)
  });
  handler = runtime.handler;
  // Actual HTTPS sockets, pinned fixture CA, and exact local target. The only
  // substituted boundary is authenticated service/audit storage, not SDK/HTTP.
  const transportFetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    if (new URL(request.url).origin !== origin) throw new Error("nonlocal test request refused");
    const body = request.body ? Buffer.from(await request.arrayBuffer()) : undefined;
    if (body) {
      const message = JSON.parse(body.toString("utf8")) as {
        id: string | number;
        params?: { name?: string; arguments?: { document_id?: string } };
      };
      if (message.params?.name === "read_document")
        f.readRequestIds.push({
          id: message.id,
          documentId: message.params.arguments!.document_id!
        });
    }
    return new Promise<Response>((resolve, reject) => {
      const outgoing = httpsRequest(
        request.url,
        {
          method: request.method,
          headers: {
            ...Object.fromEntries(request.headers),
            authorization: "Bearer synthetic-token"
          },
          ca: tls.cert,
          agent: false
        },
        (incoming) => {
          incoming.on("data", (chunk: Buffer) => {
            f.transferred += chunk.length;
            if (f.abortOnData && f.prepared.length > 0)
              incoming.destroy(new Error("synthetic client disconnect"));
          });
          const headers = new Headers();
          for (const [name, value] of Object.entries(incoming.headers)) {
            if (typeof value === "string") headers.set(name, value);
            else if (Array.isArray(value)) value.forEach((part) => headers.append(name, part));
          }
          resolve(
            new Response(Readable.toWeb(incoming) as ReadableStream<Uint8Array>, {
              status: incoming.statusCode ?? 500,
              headers
            })
          );
        }
      );
      outgoing.once("error", reject);
      const abort = () => outgoing.destroy(new Error("synthetic request cancelled"));
      request.signal.addEventListener("abort", abort, { once: true });
      outgoing.once("close", () => request.signal.removeEventListener("abort", abort));
      outgoing.end(body);
    });
  };
  const clients: Client[] = [];
  async function connectClient() {
    const client = new Client(
      { name: "delivery-integration-client", version: "1" },
      {
        capabilities: {},
        versionNegotiation: { mode: protocol === "2025-11-25" ? "legacy" : { pin: protocol } },
        cachePartition: ids[1]!
      }
    );
    clients.push(client);
    await client.connect(new StreamableHTTPClientTransport(resource, { fetch: transportFetch }));
    return client;
  }
  cleanups.push(async () => {
    await Promise.all(clients.map((client) => client.close()));
    await runtime.close();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  const client = await connectClient();
  f.events.length = 0;
  f.transferred = 0;
  async function outcome(count = 1) {
    await expect.poll(() => f.outcomes.length, { timeout: 3000 }).toBe(count);
    return f.outcomes.at(-1)!;
  }
  async function tool(binary = false) {
    return client.callTool({
      name: binary ? "read_export_chunk" : "read_document",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        ...(binary
          ? { export_id: "a".repeat(43), chunk_no: 0, recent_auth_proof: "b".repeat(43) }
          : { document_id: ids[6], version_id: null })
      } as Record<string, JsonValue>
    });
  }
  return { f, client, connectClient, outcome, tool };
}

describe("SR071 native HTTPS resource outcomes with the pinned SDK", () => {
  it.each(["2026-07-28", "2025-11-25"] as const)(
    "observes actual %s tool and resource completion after Node finish",
    async (protocol) => {
      const { f, client, outcome, tool } = await fixture(protocol);
      const response = await client.readResource({ uri: `board://${board}` });
      expect(response.contents[0]).toMatchObject({ text: f.canonical });
      const first = await outcome();
      expect(first).toMatchObject({
        outcome: "completed",
        bytesTransferred: Buffer.byteLength(f.canonical),
        observationBasis: "node_response_finish"
      });
      expect(f.events.indexOf("node:finish")).toBeLessThan(
        f.events.indexOf(`outcome:completed:${first.preparedEventId}`)
      );
      expect((await tool()).isError).not.toBe(true);
      const second = await outcome(2);
      expect(second).toMatchObject({
        outcome: "completed",
        bytesTransferred: Buffer.byteLength(f.canonical)
      });
      expect(f.errors).toEqual([]);
    }
  );

  it("does not complete a prepared result rejected by the actual SDK callback validation", async () => {
    const { f, tool, outcome } = await fixture();
    f.invalidResult = true;
    expect((await tool()).isError).toBe(true);
    expect(await outcome()).toMatchObject({
      outcome: "interrupted",
      observationBasis: "response_not_associated"
    });
  });

  it("does not complete a substituted response after the SDK produced a valid result", async () => {
    const { f, tool, outcome } = await fixture();
    f.substituteResponse = true;
    await tool().catch(() => undefined);
    expect(await outcome()).toMatchObject({
      outcome: "interrupted",
      observationBasis: "response_not_associated"
    });
  });

  it("reports a failed outcome append without rewriting a completed HTTP reply or replaying", async () => {
    const { f, tool } = await fixture();
    f.failAudit = true;
    expect((await tool()).isError).not.toBe(true);
    await expect.poll(() => f.errors.length).toBe(1);
    expect(f.errors[0]).toMatchObject({ code: "resource_delivery_outcome_audit_unavailable" });
    expect(f.outcomes).toEqual([]);
    expect(f.prepared).toHaveLength(1);
  });

  it("records interruption for an actual client socket abort during a large response", async () => {
    const { f, tool, outcome } = await fixture();
    f.canonical = "\\".repeat(10_485_760);
    f.abortOnData = true;
    await expect(tool()).rejects.toThrow();
    const observed = await outcome();
    expect(observed).toMatchObject({ outcome: "interrupted", bytesTransferred: null });
    expect(f.transferred).toBeGreaterThan(0);
    expect(f.transferred).toBeLessThan(observed.responseBytesQueued);
    expect(f.events).not.toContain("node:finish");
    expect(f.outcomes).toHaveLength(1);
  }, 30_000);

  it("rejects an actual response ended before the writer owns completion", async () => {
    const { f, tool, outcome } = await fixture();
    f.endBeforeWrite = true;
    await tool().catch(() => undefined);
    expect(await outcome()).toMatchObject({ outcome: "interrupted", bytesTransferred: 0 });
  });

  it("records an actual Node write-after-end failure as interruption", async () => {
    const { f, tool, outcome } = await fixture();
    f.writeAfterEnd = true;
    await tool().catch(() => undefined);
    expect(await outcome()).toMatchObject({ outcome: "interrupted", bytesTransferred: null });
    await expect.poll(() => f.nodeErrors.length).toBeGreaterThan(0);
    expect(f.nodeErrors[0]).toMatchObject({ code: "ERR_STREAM_WRITE_AFTER_END" });
  });

  it("isolates overlapping collectors even when SDK request IDs are reused by separate clients", async () => {
    const one = await fixture();
    const two = await fixture();
    one.f.canonical = "first request source";
    two.f.canonical = "second request source";
    await Promise.all([one.tool(), two.tool()]);
    expect(await one.outcome()).toMatchObject({
      outcome: "completed",
      bytesTransferred: Buffer.byteLength(one.f.canonical)
    });
    expect(await two.outcome()).toMatchObject({
      outcome: "completed",
      bytesTransferred: Buffer.byteLength(two.f.canonical)
    });
    expect(one.f.outcomes).toHaveLength(1);
    expect(two.f.outcomes).toHaveLength(1);
  });

  it.each(["2026-07-28", "2025-11-25"] as const)(
    "correlates a bounded admission refusal across overlapping same-ID SDK clients (%s)",
    async (protocol) => {
      const { f, tool, outcome, connectClient } = await fixture(protocol);
      const secondClient = await connectClient();
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let entered!: () => void;
      const arrived = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const loaded: string[] = [];
      f.beforeRead = async (documentId) => {
        const allocation = responseAllocationPlan({
          kind: "document",
          representation: "tool",
          sourceId: documentId,
          sourceVersion: "1",
          sha256: "a".repeat(64),
          canonicalBytes: 10_485_760
        });
        await loadWithResponseAllocation(allocation, async () => {
          if (documentId === ids[6]) {
            entered();
            await gate;
          }
          loaded.push(documentId);
        });
      };
      const first = tool().then(
        (value) => ({ value, error: undefined }),
        (error: unknown) => ({ value: undefined, error })
      );
      const second = () =>
        secondClient.callTool({
          name: "read_document",
          arguments: {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            document_id: ids[7]!,
            version_id: null
          }
        });
      try {
        await arrived;
        const refused = await second();
        expect(refused.isError).toBe(true);
        expect(refused.structuredContent).toEqual({
          code: "response_capacity_busy",
          message: "Response capacity is busy. Retry this read shortly.",
          retryable: true
        });
        expect(Buffer.byteLength(JSON.stringify(refused))).toBeLessThan(2_048);
        expect(f.readRequestIds).toHaveLength(2);
        expect(f.readRequestIds[0]!.id).toBe(f.readRequestIds[1]!.id);
        expect(loaded).toEqual([]);
        expect(f.prepared).toEqual([]);
        expect(f.outcomes).toEqual([]);
        release();
        const accepted = await first;
        expect(accepted.error).toBeUndefined();
        expect(accepted.value?.isError).not.toBe(true);
        expect(await outcome()).toMatchObject({ outcome: "completed" });
        expect((await second()).isError).not.toBe(true);
        expect(await outcome(2)).toMatchObject({ outcome: "completed" });
        expect(loaded).toEqual([ids[6], ids[7]]);
      } finally {
        release();
        await first;
      }
    }
  );

  it("forces two clients with reused request IDs to overlap on the same native runtime", async () => {
    const { f, tool, outcome, connectClient } = await fixture();
    const secondClient = await connectClient();
    const firstDocument = ids[6]!;
    const secondDocument = ids[7]!;
    const firstSource = "first request canonical source with Δ";
    const secondSource = "second, longer request canonical source with different bytes";
    f.documents.set(firstDocument, firstSource);
    f.documents.set(secondDocument, secondSource);
    const arrivals: string[] = [];
    const releases = new Map<string, () => void>();
    f.beforeRead = async (documentId) => {
      arrivals.push(documentId);
      await new Promise<void>((resolve) => releases.set(documentId, resolve));
    };
    // Handle rejections immediately even while the test deliberately holds both calls.
    const result = <T>(promise: Promise<T>) =>
      promise.then(
        (value) => ({ value, error: undefined }),
        (error: unknown) => ({ value: undefined, error })
      );
    const first = result(tool());
    const second = result(
      secondClient.callTool({
        name: "read_document",
        arguments: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          document_id: secondDocument,
          version_id: null
        }
      })
    );
    try {
      await expect.poll(() => arrivals.length).toBe(2);
      expect(new Set(arrivals)).toEqual(new Set([firstDocument, secondDocument]));
      expect(f.prepared).toEqual([]);
      expect(f.readRequestIds).toHaveLength(2);
      expect(f.readRequestIds[0]!.id).toBe(f.readRequestIds[1]!.id);
      releases.get(secondDocument)!();
      const secondResult = await second;
      expect(secondResult.error).toBeUndefined();
      expect(secondResult.value?.structuredContent).toMatchObject({
        data: { canonical_body: secondSource }
      });
      const secondOutcome = await outcome();
      expect(f.preparedSources.get(secondOutcome.preparedEventId)).toBe(secondSource);
      expect(secondOutcome).toMatchObject({
        outcome: "completed",
        bytesTransferred: Buffer.byteLength(secondSource)
      });
      // The first request is still live on this same runtime after the second completed.
      expect(f.prepared).toHaveLength(1);
      releases.get(firstDocument)!();
      const firstResult = await first;
      expect(firstResult.error).toBeUndefined();
      expect(firstResult.value?.structuredContent).toMatchObject({
        data: { canonical_body: firstSource }
      });
      const firstOutcome = await outcome(2);
      expect(f.preparedSources.get(firstOutcome.preparedEventId)).toBe(firstSource);
      expect(firstOutcome).toMatchObject({
        outcome: "completed",
        bytesTransferred: Buffer.byteLength(firstSource)
      });
      expect(new Set(f.outcomes.map((observed) => observed.preparedEventId)).size).toBe(2);
      expect(f.errors).toEqual([]);
    } finally {
      for (const release of releases.values()) release();
      await Promise.all([first, second]);
    }
  });

  it.each([false, true])(
    "preserves the existing 10 MiB boundary through actual HTTPS, binary=%s",
    async (binary) => {
      const { f, tool, outcome } = await fixture();
      const canonicalBytes = 10_485_760;
      f.binary = binary;
      f.canonical = binary
        ? Buffer.alloc(canonicalBytes, 0x71).toString("base64url")
        : "\\".repeat(canonicalBytes);
      const rssBefore = process.memoryUsage().rss;
      const response = await tool(binary);
      expect(response.isError).not.toBe(true);
      const structured = response.structuredContent as { data: Record<string, unknown> };
      expect(structured.data[binary ? "bytes" : "canonical_body"]).toBe(f.canonical);
      const observed = await outcome();
      expect(observed).toMatchObject({ outcome: "completed", bytesTransferred: canonicalBytes });
      expect(observed.responseBytesQueued).toBe(f.transferred);
      expect(f.errors).toEqual([]);
      console.info(
        JSON.stringify({
          probe: "native-https-resource-delivery",
          binary,
          canonicalBytes,
          responseBytesQueued: observed.responseBytesQueued,
          rssBefore,
          rssAfter: process.memoryUsage().rss,
          limitation: "combined server/client process RSS snapshot, not isolated server peak"
        })
      );
    },
    30_000
  );
});
