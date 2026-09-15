import {
  createServer,
  request as nodeRequest,
  type ClientRequest,
  type IncomingHttpHeaders,
  type RequestListener
} from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { AuthRequestBoundary } from "../../artifacts/server/src/auth-page.js";
import { createBoardAgentHttpRuntime } from "../../artifacts/server/src/http-runtime.js";
import {
  attachPreparedResource,
  bindResourceDeliveryResponse,
  registerPreparedResource,
  type ResourceDeliveryOutcome
} from "../../artifacts/server/src/resource-delivery.js";
import {
  currentResponseAllocationOwner,
  type ResponseAllocationOwner
} from "../../artifacts/server/src/response-allocation.js";

// Native loopback HTTP with the existing http-runtime.spec.ts mocked-TLS socket
// flag. This is NOT a TLS, SDK, real authentication, database, or RSS qualification.
// The service is synthetic; actual runtime routing/body/owner/collector code runs.
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  const results = await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup()));
  for (const result of results) if (result.status === "rejected") throw result.reason;
});
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
type Reply = { status: number; headers: IncomingHttpHeaders; body: string } | { error: Error };
type Exchange = {
  request: ClientRequest;
  result: Promise<Reply>;
  dataSeen: ReturnType<typeof gate>;
};

async function fixture(options: { auditReject?: boolean } = {}) {
  const f = {
    seen: new Set<string>(),
    fetchTags: [] as string[],
    closed: new Set<string>(),
    errors: [] as Error[],
    held: gate(),
    producerFinish: gate(),
    producerEntered: gate(),
    auditEntered: gate(),
    auditFinish: gate(),
    producerOwner: undefined as ResponseAllocationOwner | undefined,
    producerSettled: false,
    producerFailed: false,
    bodyCancelled: false,
    audits: [] as ResourceDeliveryOutcome[]
  };
  const requests = new Set<ClientRequest>();
  const exchanges: Exchange[] = [];
  let pendingProducer: Promise<void> | undefined;
  let handler: RequestListener = (_request, response) => response.writeHead(503).end();
  const server = createServer((request, response) => {
    Object.defineProperty(request.socket, "encrypted", { configurable: true, value: true });
    const tag = String(request.headers["x-dispatch-fixture-tag"] ?? "untagged");
    f.seen.add(tag);
    response.once("close", () => f.closed.add(tag));
    handler(request, response);
  });
  server.on("clientError", (_error, socket) => socket.destroy());
  let closeRuntime: (() => Promise<void>) | undefined;
  cleanups.push(async () => {
    f.held.release();
    f.producerFinish.release();
    f.auditFinish.release();
    for (const request of requests) request.destroy();
    await Promise.all(exchanges.map((exchange) => exchange.result));
    await pendingProducer;
    await closeRuntime?.();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string" || address.port === 3000)
    throw new Error("missing permitted ephemeral HTTP fixture address");
  const base = new URL(`http://127.0.0.1:${address.port}`);
  const origin = `https://127.0.0.1:${address.port}`;
  const unused: RequestListener = (_request, response) => response.writeHead(404).end();
  const runtime = createBoardAgentHttpRuntime({
    canonicalOrigin: origin,
    resourceUri: `${origin}/mcp`,
    boundary: new AuthRequestBoundary({ origin }),
    mcp: {
      close: async () => undefined,
      fetch: async (request) => {
        const tag = request.headers.get("x-dispatch-fixture-tag") ?? "untagged";
        f.fetchTags.push(tag);
        if (tag.startsWith("held-")) await f.held.promise;
        if (tag === "fetch-rejection") throw new Error("synthetic MCP fetch rejection");
        if (tag === "producer") {
          const owner = currentResponseAllocationOwner();
          if (!owner) throw new Error("native request owner is required");
          f.producerOwner = owner;
          // A real registered owner producer intentionally outlives fetch() and
          // the disconnected native exchange. No response allocation is reserved.
          pendingProducer = owner
            .produce(async () => {
              f.producerEntered.release();
              await f.producerFinish.promise;
            })
            .then(
              () => {
                f.producerSettled = true;
              },
              () => {
                f.producerSettled = true;
                f.producerFailed = true;
              }
            );
          const source = attachPreparedResource(
            {},
            {
              preparedEventId: "synthetic-dispatch-prepared",
              byteLength: 7,
              record: async (outcome) => {
                f.audits.push(outcome);
                f.auditEntered.release();
                await f.auditFinish.promise;
                if (options.auditReject) throw new Error("synthetic audit rejection");
              }
            }
          );
          registerPreparedResource(source, "producer");
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("partial"));
            },
            cancel() {
              f.bodyCancelled = true;
            }
          });
          // There is no SDK terminal association in this fixture. The recorded
          // audit is expected to be interrupted, never a completed MCP delivery.
          return bindResourceDeliveryResponse(
            new Response(stream, {
              headers: { "content-type": "text/plain" }
            })
          );
        }
        return Response.json({ ok: true, tag });
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
  closeRuntime = runtime.close;

  function request(
    tag: string,
    options: {
      path?: string;
      method?: string;
      body?: string | Buffer;
      headers?: Record<string, string>;
      sendBody?: boolean;
    } = {}
  ): Exchange {
    const body = options.body ?? "{}";
    const method = options.method ?? "POST";
    const dataSeen = gate();
    let outgoing!: ClientRequest;
    const result = new Promise<Reply>((resolve) => {
      let settled = false;
      const finish = (reply: Reply) => {
        if (!settled) {
          settled = true;
          resolve(reply);
        }
      };
      outgoing = nodeRequest(
        new URL(options.path ?? "/mcp", base),
        {
          method,
          agent: false,
          headers: {
            host: new URL(origin).host,
            "x-dispatch-fixture-tag": tag,
            ...(method === "POST"
              ? {
                  "content-type": "application/json",
                  "content-length": String(Buffer.byteLength(body))
                }
              : {}),
            ...options.headers
          }
        },
        (incoming) => {
          const chunks: Buffer[] = [];
          incoming.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
            dataSeen.release();
          });
          incoming.once("end", () =>
            finish({
              status: incoming.statusCode ?? 0,
              headers: incoming.headers,
              body: Buffer.concat(chunks).toString("utf8")
            })
          );
          incoming.once("aborted", () => finish({ error: new Error("fixture response aborted") }));
          incoming.once("error", (error) => finish({ error }));
        }
      );
      requests.add(outgoing);
      outgoing.once("error", (error) => finish({ error }));
      outgoing.once("close", () => requests.delete(outgoing));
      outgoing.setTimeout(10_000, () => outgoing.destroy(new Error("fixture request timeout")));
      if (options.sendBody === false) outgoing.flushHeaders();
      else outgoing.end(method === "POST" ? body : undefined);
    });
    const exchange = { request: outgoing, result, dataSeen };
    exchanges.push(exchange);
    return exchange;
  }
  async function hold(count: number) {
    const prior = f.fetchTags.filter((tag) => tag.startsWith("held-")).length;
    const held = Array.from({ length: count }, (_value, index) => request(`held-${prior + index}`));
    await expect
      .poll(() => f.fetchTags.filter((tag) => tag.startsWith("held-")).length, { timeout: 3_000 })
      .toBe(prior + count);
    return held;
  }
  async function busy(tag: string, options?: Parameters<typeof request>[1]) {
    const reply = await request(tag, options).result;
    expect(reply).toMatchObject({ status: 503, headers: { "retry-after": "1" } });
    if (!("body" in reply)) throw new Error("expected complete native capacity rejection");
    expect(JSON.parse(reply.body)).toEqual({ error: "temporarily_unavailable" });
    expect(f.fetchTags).not.toContain(tag);
  }
  return { f, request, hold, busy };
}

describe.sequential("native MCP dispatch admission", () => {
  it("refuses request 129 before body validation or fetch while 128 bodies are still pending", async () => {
    const { f, request, busy } = await fixture();
    const pending = Array.from({ length: 128 }, (_value, index) =>
      request(`body-pending-${index}`, { sendBody: false })
    );
    await expect.poll(() => f.seen.size, { timeout: 3_000 }).toBe(128);
    expect(f.fetchTags).toEqual([]);
    await busy("overflow-before-body", { headers: { "content-encoding": "gzip" } });
    expect(f.fetchTags).toEqual([]);
    for (const exchange of pending) exchange.request.end("{}");
    const replies = await Promise.all(pending.map((exchange) => exchange.result));
    expect(replies).toHaveLength(128);
    for (const reply of replies) expect(reply).toMatchObject({ status: 200 });
    expect(f.fetchTags).toHaveLength(128);
    expect(await request("after-pending-bodies").result).toMatchObject({ status: 200 });
  }, 15_000);

  it("keeps 100 concurrent calls plus one additional call eligible without consuming non-MCP routes", async () => {
    const { f, request, hold } = await fixture();
    const held = await hold(101);
    expect(f.fetchTags).toHaveLength(101);
    expect(await request("live", { path: "/health/live", method: "GET" }).result).toMatchObject({
      status: 200
    });
    expect(await request("mcp-get", { method: "GET" }).result).toMatchObject({
      status: 405,
      headers: { allow: "POST" }
    });
    f.held.release();
    for (const reply of await Promise.all(held.map((exchange) => exchange.result)))
      expect(reply).toMatchObject({ status: 200 });
  }, 15_000);

  it("refuses saturated dispatch before fetch and restores all slots after normal completion", async () => {
    const { f, request, hold, busy } = await fixture();
    const held = await hold(128);
    await busy("overflow-valid");
    expect(f.fetchTags).toHaveLength(128);
    // Trust-boundary and non-POST behavior remain prior to the new admission check.
    expect(
      await request("wrong-host", { headers: { host: "wrong.invalid" } }).result
    ).toMatchObject({ status: 400 });
    expect(await request("mcp-get", { method: "GET" }).result).toMatchObject({ status: 405 });
    f.held.release();
    for (const reply of await Promise.all(held.map((exchange) => exchange.result)))
      expect(reply).toMatchObject({ status: 200 });
    f.held = gate();
    const secondWave = await hold(128);
    await busy("overflow-second-wave");
    f.held.release();
    for (const reply of await Promise.all(secondWave.map((exchange) => exchange.result)))
      expect(reply).toMatchObject({ status: 200 });
    expect(await request("after-success").result).toMatchObject({ status: 200 });
  }, 15_000);

  it.each(["encoded-body", "invalid-utf8", "fetch-rejection"] as const)(
    "releases an admitted slot after %s while 127 other dispatches remain held",
    async (failure) => {
      const { f, request, hold } = await fixture();
      await hold(127);
      const options =
        failure === "encoded-body"
          ? { headers: { "content-encoding": "gzip" } }
          : failure === "invalid-utf8"
            ? { body: Buffer.from([0xc3, 0x28]) }
            : {};
      expect(await request(failure, options).result).toMatchObject({ status: 400 });
      if (failure !== "fetch-rejection") expect(f.fetchTags).not.toContain(failure);
      else expect(f.fetchTags).toContain(failure);
      expect(await request("after-error").result).toMatchObject({ status: 200 });
      expect(f.fetchTags.filter((tag) => tag.startsWith("held-"))).toHaveLength(127);
    },
    15_000
  );

  it.each([false, true])(
    "holds a disconnected producer slot through actual collector audit settlement, auditReject=%s",
    async (auditReject) => {
      const { f, request, hold, busy } = await fixture({ auditReject });
      await hold(127);
      const producer = request("producer");
      await f.producerEntered.promise;
      await producer.dataSeen.promise;
      producer.request.destroy(new Error("intentional native HTTP disconnect"));
      await expect.poll(() => f.producerOwner?.signal.aborted).toBe(true);
      await expect.poll(() => f.closed.has("producer") && f.bodyCancelled).toBe(true);
      expect(f.producerSettled).toBe(false);
      expect(f.audits).toEqual([]);
      await busy("overflow-after-disconnect");
      f.producerFinish.release();
      await f.auditEntered.promise;
      await expect.poll(() => f.producerSettled).toBe(true);
      expect(f.producerFailed).toBe(true);
      expect(f.audits).toHaveLength(1);
      expect(f.audits[0]).toMatchObject({ outcome: "interrupted" });
      await busy("overflow-during-audit");
      f.auditFinish.release();
      await expect
        .poll(
          async () => {
            const reply = await request("after-audit").result;
            return "status" in reply ? reply.status : 0;
          },
          { timeout: 3_000 }
        )
        .toBe(200);
      expect(f.audits).toHaveLength(1);
      if (auditReject)
        expect(
          f.errors.some(
            (error) =>
              (error as Error & { code?: string }).code ===
              "resource_delivery_outcome_audit_unavailable"
          )
        ).toBe(true);
      expect(await producer.result).toHaveProperty("error");
    },
    15_000
  );
});
