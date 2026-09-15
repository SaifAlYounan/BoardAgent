import { readFileSync } from "node:fs";
import { createServer, request as httpsRequest } from "node:https";
import type { ClientRequest, RequestListener } from "node:http";
import { Readable } from "node:stream";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo } from "@modelcontextprotocol/server";
import type { Pool } from "pg";
import { expect, it, vi } from "vitest";
import {
  AuthRequestBoundary,
  createBoardAgentHttpRuntime,
  createBoardAgentMcpHandler,
  type BoardAgentSurfaceService
} from "../../artifacts/server/src/index.js";
import { createProtectedMcpHandler } from "../../artifacts/server/src/protected-mcp.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResourceDeliveryCollector,
  currentResourceDeliveryCollector
} from "../../artifacts/server/src/resource-delivery.js";
import {
  ResponseAllocationManager,
  currentResponseAllocationOwner,
  type ResponseAllocationOwner
} from "../../artifacts/server/src/response-allocation.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor } from "../helpers/authorized-actor.js";
import { identityOnboardingProjectionPrincipal } from "../helpers/identity-onboarding-projection-principal.js";
import {
  identityNativeTools,
  originalIdentityNativeResult,
  type IdentityNativeTool
} from "../helpers/identity-onboarding-native-oracle.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-identity-onboarding-native-token";
const timeout = 10000;
const routes = identityNativeTools;
type Route = IdentityNativeTool;
type Selection = {
  tool: IdentityNativeTool;
  reference: string | null;
  input: Record<string, JsonValue>;
};
function isRoute(value: unknown): value is Route {
  return typeof value === "string" && (routes as readonly string[]).includes(value);
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function gate() {
  let release!: () => void,
    open = false;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    promise,
    get open() {
      return open;
    },
    release: () => {
      open = true;
      release();
    }
  };
}
const capture = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error })
  );
async function bounded<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} exceeded ${timeout}ms`)), timeout);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
function retainedGraph(roots: readonly unknown[]) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0n,
    containers = 0n;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (Array.isArray(value)) pending.push(...value);
    else {
      properties += BigInt(Object.keys(value).length);
      pending.push(...Object.values(value));
    }
  }
  return { properties, containers };
}
async function auditSnapshot(pool: Pool) {
  return (
    await pool.query<{ id: string; sequence: string; event_hash: string; canonical_hex: string }>(
      `select id,sequence::text,encode(event_sha256,'hex') as event_hash,
    encode(canonical_payload,'hex') as canonical_hex from audit_events order by sequence`
    )
  ).rows;
}

it("delivers exact identity and onboarding reads through native HTTPS SDK and real empty collector settlement", async () => {
  await withMigratedDatabase("identity_onboarding_native", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: [
        "documents:contribute",
        "documents:read",
        "governance:read",
        "meeting:act",
        "onboarding:read",
        "secretariat:admin"
      ]
    });
    // Reuse the dedicated six-scope WO session/resolver fixture. The session
    // storage is synthetic; provider/browser authentication is not exercised.
    const rawPrincipal = await identityOnboardingProjectionPrincipal(pool, actor);
    const principal = {
      ...rawPrincipal,
      scopes: [...rawPrincipal.scopes].toSorted(),
      roles: [...rawPrincipal.roles].toSorted(),
      boardIds: [...new Set(rawPrincipal.boardIds)].toSorted()
    };
    const selections: Record<Route, Selection> = {
      whoami: {
        tool: "whoami",
        reference: actor.memberId,
        input: { schema_version: TOOL_INPUT_SCHEMA_VERSION }
      },
      get_onboarding: {
        tool: "get_onboarding",
        reference: actor.boardId,
        input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: actor.boardId }
      },
      get_onboarding_status: {
        tool: "get_onboarding_status",
        reference: null,
        input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: actor.boardId }
      }
    };
    let activeRoute: Route | undefined;
    function routeFor(tool: unknown, input: Record<string, unknown>): Route {
      if (
        !activeRoute ||
        tool !== selections[activeRoute].tool ||
        canonicalJson(input) !== canonicalJson(selections[activeRoute].input)
      )
        throw new Error("unexpected identity/onboarding selector");
      return activeRoute;
    }
    async function expectedFor(route: Route) {
      return withRequestTransaction(
        pool,
        actor.context,
        async (connection) => {
          expect(
            (await connection.query<{ role: string }>("select current_user as role")).rows
          ).toEqual([{ role: "boardagent_server" }]);
          const original = await originalIdentityNativeResult(
            connection,
            route,
            actor.boardId,
            principal
          );
          expect(original.metadata.row_count).toBe("1");
          expect(original.bound.units).toBe(1);
          return original;
        },
        { assumeRole: "boardagent_server" }
      );
    }
    const auth: AuthInfo = {
      token,
      clientId: principal.protocolClientId,
      scopes: [...principal.scopes],
      expiresAt: Math.floor(Date.now() / 1000) + 300,
      resource,
      extra: {
        organizationId: principal.organizationId,
        memberId: principal.memberId,
        internalClientId: principal.clientId,
        accessTokenRecordId: principal.accessTokenRecordId,
        jti: principal.tokenJti,
        keyId: principal.keyId,
        roles: principal.roles,
        boardIds: principal.boardIds
      }
    };
    const entered = Object.fromEntries(routes.map((route) => [route, gate()])) as Record<
        Route,
        ReturnType<typeof gate>
      >,
      releaseSettlement = Object.fromEntries(routes.map((route) => [route, gate()])) as Record<
        Route,
        ReturnType<typeof gate>
      >;
    const owners = new Map<Route, ResponseAllocationOwner>(),
      collectors = new Map<Route, ResourceDeliveryCollector>();
    const ids = new Map<Route, string | number>(),
      nativeFinished = new Set<Route>(),
      nativeClosed = new Set<Route>();
    const wire = Object.fromEntries(routes.map((route) => [route, 0])) as Record<Route, number>,
      media = Object.fromEntries(routes.map((route) => [route, ""])) as Record<Route, string>;
    const observedSettlements = new Map<
      Route,
      { outcome: string; responseBytesQueued: number; responseWriteAttempted: boolean | undefined }
    >();
    const settled = new Map<Route, readonly Error[]>(),
      delegations = new Map<Route, number>();
    const requests = new Set<ClientRequest>(),
      seenManagers = new Set<ResponseAllocationManager>();
    const failures: unknown[] = [],
      serverErrors: Error[] = [],
      pending: Array<Promise<unknown>> = [],
      observations: unknown[] = [];
    let manager: ResponseAllocationManager | undefined,
      client: Client | undefined,
      closeRuntime: (() => Promise<void>) | undefined;
    let handler: RequestListener = (_request, response) => response.writeHead(503).end();
    const server = createServer(tls, (request, response) => {
      const route = request.headers["x-identity-onboarding-fixture"];
      if (isRoute(route)) {
        response.once("finish", () => nativeFinished.add(route));
        response.once("close", () => nativeClosed.add(route));
      }
      handler(request, response);
    });
    const originalOpen = ResponseAllocationManager.prototype.openRequest;
    const openSpy = vi
      .spyOn(ResponseAllocationManager.prototype, "openRequest")
      .mockImplementation(function (this: ResponseAllocationManager, signal) {
        seenManagers.add(this);
        return originalOpen.call(this, signal);
      });
    // Plain identity/onboardings return no prepared delivery handle. Delegate
    // actual runtime settlement only after the test gate; do not signal owners.
    const registerSpy = vi.spyOn(ResourceDeliveryCollector.prototype, "register");
    const originalSettle = ResourceDeliveryCollector.prototype.settle;
    const gatedSettlements = new WeakMap<ResourceDeliveryCollector, Promise<readonly Error[]>>();
    const settleSpy = vi
      .spyOn(ResourceDeliveryCollector.prototype, "settle")
      .mockImplementation(function (
        this: ResourceDeliveryCollector,
        outcome,
        responseBytesQueued,
        responseWriteAttempted
      ) {
        const route = routes.find((candidate) => collectors.get(candidate) === this);
        if (!route)
          return originalSettle.call(this, outcome, responseBytesQueued, responseWriteAttempted);
        let promise = gatedSettlements.get(this);
        if (!promise) {
          observedSettlements.set(route, { outcome, responseBytesQueued, responseWriteAttempted });
          entered[route].release();
          promise = releaseSettlement[route].promise.then(async () => {
            delegations.set(route, (delegations.get(route) ?? 0) + 1);
            const result = await originalSettle.call(
              this,
              outcome,
              responseBytesQueued,
              responseWriteAttempted
            );
            settled.set(route, result);
            return result;
          });
          gatedSettlements.set(this, promise);
        }
        return promise;
      });
    try {
      server.on("clientError", (error) => serverErrors.push(error));
      server.on("error", (error) => serverErrors.push(error));
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      if (!address || typeof address === "string" || address.port === 3000)
        throw new Error("missing permitted HTTPS address");
      const localOrigin = `https://127.0.0.1:${address.port}`;
      const repository = new PgSurfaceReadRepository(pool, {
        cursorKey: new Uint8Array(32).fill(1),
        transaction: { assumeRole: "boardagent_server" }
      });
      const unsupported = async (): Promise<never> => {
        throw new Error("unexpected native fixture action");
      };
      const service: BoardAgentSurfaceService = {
        executeDirect: unsupported,
        prepareHumanAction: unsupported,
        persistHumanStage: unsupported,
        resolveHumanAction: unsupported,
        readResource: unsupported,
        executeRead: async (requestPrincipal, tool, input) => {
          if (!(identityNativeTools as readonly string[]).includes(tool) || !object(input))
            throw new Error("unexpected native tool request");
          const route = routeFor(tool, input);
          const owner = currentResponseAllocationOwner(),
            collector = currentResourceDeliveryCollector();
          if (!owner || !collector)
            throw new Error("actual native allocation owner and collector required");
          expect(owners.has(route)).toBe(false);
          owners.set(route, owner);
          collectors.set(route, collector);
          expect(requestPrincipal).toEqual(principal);
          expect(requestPrincipal.serviceOrigin).toBe(origin);
          expect(requestPrincipal.tokenJti).toBe(actor.tokenJti);
          try {
            return await repository.executeRead(requestPrincipal, tool, input);
          } catch (error) {
            throw new Error(
              `native identity repository failed: ${error instanceof Error ? error.stack : String(error)}`,
              { cause: error }
            );
          }
        }
      };
      const protectedMcp = createProtectedMcpHandler({
        handler: createBoardAgentMcpHandler({
          service,
          requestStateKey: new Uint8Array(32).fill(0x47),
          requestStateTtlSeconds: 600
        }),
        resourceUri: resource.href,
        verifier: {
          verifyAccessToken: async (value) => {
            if (value !== token) throw new Error("unexpected synthetic bearer");
            return auth;
          }
        }
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
        onError: (error) => serverErrors.push(error)
      });
      closeRuntime = () => runtime.close();
      handler = runtime.handler;
      const transportFetch: typeof fetch = async (input, init) => {
        const request = new Request(input, init),
          canonical = new URL(request.url);
        if (
          canonical.origin !== origin ||
          canonical.pathname !== "/mcp" ||
          canonical.search ||
          canonical.hash
        )
          throw new Error("nonlocal or unexpected native SDK request refused");
        const body = request.body ? Buffer.from(await request.arrayBuffer()) : undefined;
        const parsed: unknown = body ? JSON.parse(body.toString("utf8")) : undefined;
        const params = object(parsed) ? parsed["params"] : undefined,
          args = object(params) ? params["arguments"] : undefined;
        let route: Route | undefined;
        if (object(parsed) && parsed["method"] === "tools/call") {
          if (
            !object(params) ||
            !(identityNativeTools as readonly unknown[]).includes(params["name"]) ||
            !object(args) ||
            !(typeof parsed["id"] === "string" || typeof parsed["id"] === "number")
          )
            throw new Error("uncorrelated identity/onboarding tool request");
          route = routeFor(params["name"], args);
          ids.set(route, parsed["id"]);
        }
        // The canonical authority remains boardagent.test. Only the test fetch
        // maps its exact endpoint to the CA-verified loopback TLS socket.
        return new Promise<Response>((resolve, reject) => {
          const outgoing = httpsRequest(
            new URL("/mcp", localOrigin),
            {
              method: request.method,
              headers: {
                ...Object.fromEntries(request.headers),
                host: canonical.host,
                authorization: `Bearer ${token}`,
                ...(route ? { "x-identity-onboarding-fixture": route } : {})
              },
              ca: tls.cert,
              // Verify the local TLS identity separately from the canonical HTTP Host.
              servername: "localhost",
              agent: false
            },
            (incoming) => {
              const headers = new Headers();
              for (const [name, value] of Object.entries(incoming.headers)) {
                if (typeof value === "string") headers.set(name, value);
                else if (Array.isArray(value)) for (const part of value) headers.append(name, part);
              }
              if (route) {
                media[route] = headers.get("content-type") ?? "";
                incoming.on("data", (chunk: Buffer) => {
                  wire[route] += chunk.length;
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
          requests.add(outgoing);
          outgoing.once("error", reject);
          const abort = () => outgoing.destroy(new Error("native fixture request cancelled"));
          request.signal.addEventListener("abort", abort, { once: true });
          outgoing.once("close", () => {
            requests.delete(outgoing);
            request.signal.removeEventListener("abort", abort);
          });
          if (request.signal.aborted) abort();
          else outgoing.end(body);
        });
      };
      client = new Client(
        { name: "identity-onboarding-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "identity-onboarding-native-fixture"
        }
      );
      await client.connect(new StreamableHTTPClientTransport(resource, { fetch: transportFetch }), {
        timeout
      });
      expect(seenManagers.size).toBe(1);
      manager = seenManagers.values().next().value;
      expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      expect(client.getProtocolEra()).toBe("modern");
      // Populate the actual SDK's output-schema cache before Client.callTool.
      // This lists metadata; it does not execute any other tool or diagnostic.
      const listed = await client.listTools();
      for (const name of identityNativeTools) {
        const declared = listed.tools.find((tool) => tool.name === name);
        expect(declared).toBeDefined();
        const schema = declared?.outputSchema;
        if (!object(schema)) throw new Error("missing tool result schema");
        expect(schema["required"]).toEqual(
          expect.arrayContaining([
            "schema_version",
            "tool",
            "status",
            "reference",
            "resource_uri",
            "data"
          ])
        );
        expect(schema["additionalProperties"]).toBe(false);
      }
      await expect.poll(() => manager?.accounting.usedUnits, { timeout }).toBe(0);
      let lastAudit: Awaited<ReturnType<typeof auditSnapshot>> | undefined;
      for (const route of routes) {
        const oracle = await expectedFor(route);
        const before = await auditSnapshot(pool);
        lastAudit = before;
        activeRoute = route;
        const received = capture(
          client.callTool(
            {
              name: selections[route].tool,
              arguments: selections[route].input
            },
            { timeout, maxTotalTimeout: timeout }
          )
        );
        pending.push(received);
        const routeFailures: unknown[] = [];
        try {
          const earlyFailure = received.then((reply) => {
            if (!reply.ok) throw reply.error;
            return new Promise<never>(() => undefined);
          });
          await Promise.race([
            expect.poll(() => entered[route].open, { timeout }).toBe(true),
            earlyFailure
          ]);
          await expect.poll(() => nativeFinished.has(route), { timeout }).toBe(true);
          let producerDone = false;
          void owners
            .get(route)!
            .whenProducersDone()
            .then(() => {
              producerDone = true;
            });
          await expect.poll(() => producerDone, { timeout }).toBe(true);
          // SDK collection/output validation is independent of native HTTP finish.
          const reply = await received;
          if (!reply.ok) throw reply.error;
          expect(reply.value.isError ?? false, JSON.stringify(reply.value)).toBe(false);
          const structured = reply.value.structuredContent;
          if (!object(structured) || !object(structured["data"]))
            throw new Error("expected original identity/onboarding result");
          const expected = oracle.envelope;
          const expectedBytes = Buffer.from(canonicalJson(expected)),
            expectedTextBytes = Buffer.from(JSON.stringify(expected));
          expect(structured).toEqual(expected);
          expect(reply.value.content).toHaveLength(1);
          const text = reply.value.content[0];
          if (!object(text) || text["type"] !== "text" || typeof text["text"] !== "string")
            throw new Error("expected identity/onboarding tool text result");
          // Existing MCP text uses JSON.stringify; canonical bytes are a separate oracle.
          expect(Buffer.from(text["text"])).toEqual(expectedTextBytes);
          expect(Buffer.from(canonicalJson(JSON.parse(text["text"])))).toEqual(expectedBytes);
          expect(Buffer.from(canonicalJson(reply.value.structuredContent))).toEqual(expectedBytes);
          const result = reply.value.structuredContent;
          if (!object(result)) throw new Error("expected structured result");
          expect(Object.keys(result).sort()).toEqual([
            "data",
            "reference",
            "resource_uri",
            "schema_version",
            "status",
            "tool"
          ]);
          expect(result["schema_version"]).toBe("boardagent.tool-result.v1");
          expect(result["tool"]).toBe(selections[route].tool);
          const data = result["data"];
          if (!object(data)) throw new Error("expected identity/onboarding result data");
          expect(data).toEqual(expected.data);
          if (route === "get_onboarding") expect(Object.keys(data)).toEqual(["onboarding"]);
          if (route === "get_onboarding_status")
            expect(Object.keys(data).sort()).toEqual(["board_id", "status", "terms_version_id"]);
          expect(result["reference"]).toBe(selections[route].reference);
          expect(result["resource_uri"]).toBe(oracle.envelope.resource_uri);
          expect(media[route]).toContain("application/json");
          expect(wire[route]).toBeGreaterThan(expectedBytes.length);
          const retained = oracle.retained;
          const nativeShape = {
            content: [{ type: "text", text: JSON.stringify(expected) }],
            structuredContent: expected
          };
          const graph = retainedGraph([retained, expected, nativeShape]);
          expect(graph.properties).toBeLessThanOrEqual(oracle.bound.propertyCount);
          expect(graph.containers).toBeLessThanOrEqual(oracle.bound.objectOrArrayCount);
          expect(BigInt(Buffer.byteLength(JSON.stringify(retained)))).toBeLessThanOrEqual(
            oracle.bound.jsonUpperBytes
          );
          expect(BigInt(expectedTextBytes.length)).toBeLessThanOrEqual(
            oracle.bound.jsonUpperBytes + 4096n
          );
          expect(BigInt(wire[route])).toBeLessThanOrEqual(oracle.bound.wireUpperBytes);
          expect(manager?.accounting.usedUnits).toBe(oracle.bound.units);
          expect(registerSpy).not.toHaveBeenCalled();
          expect(settled.has(route)).toBe(false);
          expect(delegations.get(route) ?? 0).toBe(0);
          expect(observedSettlements.get(route)).toMatchObject({
            outcome: "completed",
            responseBytesQueued: wire[route]
          });
          expect(await auditSnapshot(pool)).toEqual(before);
          releaseSettlement[route].release();
          await expect.poll(() => settled.has(route), { timeout }).toBe(true);
          expect(settled.get(route)).toEqual([]);
          expect(delegations.get(route)).toBe(1);
          await expect.poll(() => manager?.accounting.usedUnits, { timeout }).toBe(0);
          expect(await auditSnapshot(pool)).toEqual(before);
          observations.push({
            route,
            requestId: ids.get(route),
            resourceUri: oracle.envelope.resource_uri,
            reference: selections[route].reference,
            canonicalBytes: expectedBytes.length,
            canonicalSha256: sha256Hex(expectedBytes),
            textBytes: expectedTextBytes.length,
            textSha256: sha256Hex(expectedTextBytes),
            wireBytes: wire[route],
            heldUnits: oracle.bound.units,
            originalMetadata: oracle.metadata,
            retainedRowCount: retained.length,
            statusRetainsFullOnboardingView: route === "get_onboarding_status",
            allocationBoundBytes: String(oracle.bound.allocationBytes),
            wireBoundBytes: String(oracle.bound.wireUpperBytes),
            sdkReplyCollected: true,
            serverProducerCompleted: producerDone,
            nativeFinished: nativeFinished.has(route),
            collectorDelegations: delegations.get(route),
            collectorErrors: settled.get(route)?.length,
            finalAllocationUnits: manager?.accounting.usedUnits,
            preparedDeliveryRegistrations: 0,
            deliveryAuditAdded: false
          });
        } catch (error) {
          routeFailures.push(error);
        } finally {
          releaseSettlement[route].release();
          try {
            await bounded(received, "native call cleanup");
          } catch (error) {
            routeFailures.push(error);
          } finally {
            activeRoute = undefined;
          }
        }
        if (routeFailures.length)
          throw new AggregateError(
            routeFailures,
            `native route ${route} failed: ${routeFailures.map((error) => (error instanceof Error ? error.stack : String(error))).join("\n")}`
          );
      }
      expect(ids.size).toBe(routes.length);
      expect(new Set(ids.values()).size).toBe(routes.length);
      expect(nativeFinished.size).toBe(routes.length);
      await expect.poll(() => nativeClosed.size, { timeout }).toBe(routes.length);
      expect(await auditSnapshot(pool)).toEqual(lastAudit);
    } catch (error) {
      failures.push(error);
    } finally {
      for (const route of routes) releaseSettlement[route].release();
      for (const request of requests) request.destroy();
      for (const close of [
        async () => client?.close(),
        closeRuntime,
        async () => {
          server.closeAllConnections();
          if (server.listening)
            await new Promise<void>((resolve, reject) =>
              server.close((error) => (error ? reject(error) : resolve()))
            );
        }
      ]) {
        try {
          if (close) await bounded(Promise.resolve().then(close), "native transport cleanup");
        } catch (error) {
          failures.push(error);
        }
      }
      try {
        await bounded(Promise.all(pending), "pending native calls cleanup");
      } catch (error) {
        failures.push(error);
      }
      settleSpy.mockRestore();
      registerSpy.mockRestore();
      openSpy.mockRestore();
      if (serverErrors.length)
        failures.push(new AggregateError(serverErrors, "native server errors"));
    }
    if (failures.length)
      throw new AggregateError(
        failures,
        `native identity fixture failed: ${failures.map((error) => (error instanceof Error ? error.stack : String(error))).join("\n")}`
      );
    console.info(
      JSON.stringify({
        probe: "native-identity-onboarding-delivery",
        protocol: "2026-07-28",
        fixtureKind:
          "constrained synthetic six-scope secretary and authenticated session; actual resolver",
        publicCalls: routes.length,
        tools: observations,
        finalAllocationUnits: manager?.accounting.usedUnits,
        networkCleanupComplete: true
      })
    );
  });
}, 120000);
