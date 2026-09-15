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
import { seedManagementProjectionFixture } from "../helpers/management-projection-fixture.js";
import {
  originalManagementNative,
  originalManagementNativeEnvelope,
  originalManagementRetainedRoots,
  type ManagementNativeInput
} from "../helpers/management-native-oracle.js";
import {
  managementListCursorKey,
  managementListTools,
  signManagementListTailCursor,
  verifyManagementListCursor,
  type OriginalManagementPageRow
} from "../helpers/management-page-oracle.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin);
const timeout = 10000;
const routeNames = [
  "point-complete",
  "submissions-full",
  "submissions-page",
  "submissions-next",
  "submissions-empty",
  "questions-full",
  "questions-page",
  "questions-next",
  "questions-empty"
] as const;
type Route = (typeof routeNames)[number];
const nativeTools = { point: "get_management_submission", ...managementListTools } as const;
type Tool = (typeof nativeTools)[keyof typeof nativeTools];
type Selection = {
  tool: Tool;
  reference: string | null;
  selection: ManagementNativeInput;
  expectedRows: number;
  input: Record<string, JsonValue>;
  inputCursorAnchor?: OriginalManagementPageRow;
  cursorIssued?: { before: number; after: number };
};
function isRoute(value: unknown): value is Route {
  return typeof value === "string" && (routeNames as readonly string[]).includes(value);
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

type ManagementFixture = Awaited<ReturnType<typeof seedManagementProjectionFixture>>;
async function runActorGroup(
  pool: Pool,
  fixture: ManagementFixture,
  actorName: "secretary" | "asker"
) {
  // Each group owns a distinct runtime, fixed AuthInfo and SDK transport. No
  // request or verifier changes actor identity within a live runtime.
  const actor = fixture.actors[actorName],
    principal = fixture.principals[actorName];
  const token = `synthetic-management-native-${actorName}`;
  const routes = routeNames.filter((route) =>
    actorName === "secretary" ? !route.startsWith("questions-") : route.startsWith("questions-")
  );
  const selections = {} as Record<Route, Selection>;
  if (actorName === "secretary")
    selections["point-complete"] = {
      tool: "get_management_submission",
      reference: fixture.submissionIds[0],
      selection: {
        kind: "point",
        selectorId: fixture.submissionIds[0],
        limit: 100,
        cursorAt: null,
        cursorId: null
      },
      expectedRows: 0,
      input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, submission_id: fixture.submissionIds[0] }
    };
  const kind = actorName === "secretary" ? "submissions" : "questions";
  const original = await withRequestTransaction(
    pool,
    actor.context,
    async (connection) => {
      expect(
        (await connection.query<{ role: string }>("select current_user as role")).rows
      ).toEqual([{ role: "boardagent_server" }]);
      const read = await originalManagementNative(
        connection,
        { kind, selectorId: fixture.boardId, cursorAt: null, cursorId: null, limit: 100 },
        actor.memberId
      );
      expect(read.rows).toHaveLength(3);
      expect(new Set(read.rows.map((row) => row.cursor_id))).toEqual(
        new Set(kind === "submissions" ? fixture.submissionIds : fixture.questionIds)
      );
      if (kind === "questions") expect(read.totalVisible).toBe("3");
      return read.rows;
    },
    { assumeRole: "boardagent_server" }
  );
  for (const phase of ["full", "page", "next", "empty"] as const) {
    const anchor = phase === "next" ? original[0]! : phase === "empty" ? original.at(-1)! : null;
    const selection: ManagementNativeInput = {
      kind,
      selectorId: fixture.boardId,
      limit: phase === "page" ? 1 : 100,
      cursorAt: anchor?.cursor_at ?? null,
      cursorId: anchor?.cursor_id ?? null
    };
    let cursor: string | null = null,
      cursorIssued: Selection["cursorIssued"];
    if (phase === "empty") {
      // Independently signed input from the actual terminal original anchor;
      // no public cursor is emitted by a terminal page.
      const issued = Math.floor(Date.now() / 1000);
      cursor = signManagementListTailCursor(
        kind,
        fixture.boardId,
        anchor!,
        principal,
        issued + 86400
      );
      cursorIssued = { before: issued, after: issued };
    }
    selections[`${kind}-${phase}`] = {
      tool: managementListTools[kind],
      reference: null,
      selection,
      expectedRows: phase === "empty" ? 0 : phase === "page" ? 2 : phase === "next" ? 2 : 3,
      input: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: fixture.boardId,
        limit: selection.limit,
        cursor
      },
      ...(anchor ? { inputCursorAnchor: anchor } : {}),
      ...(cursorIssued ? { cursorIssued } : {})
    };
  }
  let activeRoute: Route | undefined;
  function routeFor(tool: unknown, input: Record<string, unknown>): Route {
    if (
      !activeRoute ||
      tool !== selections[activeRoute].tool ||
      canonicalJson(input) !== canonicalJson(selections[activeRoute].input)
    )
      throw new Error("unexpected management selector");
    return activeRoute;
  }
  async function expectedFor(route: Route) {
    const choice = selections[route];
    return withRequestTransaction(
      pool,
      actor.context,
      async (connection) => {
        const original = await originalManagementNative(
          connection,
          choice.selection,
          actor.memberId
        );
        expect(original.rows).toHaveLength(choice.expectedRows);
        expect(original.bound.units).toBe(1);
        if (choice.selection.kind === "point") {
          expect(original.point).not.toBeNull();
          expect(original.metadata[0]).toMatchObject({
            version_count: "2",
            request_count: "1",
            reply_count: "1",
            disposition_count: "1"
          });
        }
        if (choice.selection.kind === "questions") expect(original.totalVisible).toBe("3");
        return { ...original, units: original.bound.units, resourceUri: null };
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
    const route = request.headers["x-management-native-fixture"];
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
  // Plain management tools return no prepared delivery handle. Delegate
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
      cursorKey: managementListCursorKey,
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
      executeRead: async (actualPrincipal, tool, input) => {
        if (!(Object.values(nativeTools) as readonly string[]).includes(tool) || !object(input))
          throw new Error("unexpected native tool request");
        const route = routeFor(tool, input);
        const owner = currentResponseAllocationOwner(),
          collector = currentResourceDeliveryCollector();
        if (!owner || !collector)
          throw new Error("actual native allocation owner and collector required");
        expect(owners.has(route)).toBe(false);
        owners.set(route, owner);
        collectors.set(route, collector);
        expect(actualPrincipal).toEqual({
          ...principal,
          serviceOrigin: origin,
          scopes: [...principal.scopes].toSorted(),
          roles: [...principal.roles].toSorted(),
          boardIds: [...new Set(principal.boardIds)].toSorted()
        });
        return repository.executeRead(actualPrincipal, tool, input);
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
          !(Object.values(nativeTools) as readonly unknown[]).includes(params["name"]) ||
          !object(args) ||
          !(typeof parsed["id"] === "string" || typeof parsed["id"] === "number")
        )
          throw new Error("uncorrelated management tool request");
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
              ...(route ? { "x-management-native-fixture": route } : {})
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
      { name: "management-native-native-fixture", version: "1" },
      {
        capabilities: {},
        versionNegotiation: { mode: { pin: "2026-07-28" } },
        cachePartition: "management-native-native-fixture"
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
    for (const name of Object.values(nativeTools)) {
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
      const oracle = await expectedFor(route),
        choice = selections[route];
      if (choice.selection.kind !== "point" && choice.input["cursor"] !== null) {
        if (!choice.inputCursorAnchor || !choice.cursorIssued)
          throw new Error("cursor provenance missing");
        verifyManagementListCursor(
          choice.selection.kind,
          choice.selection.selectorId,
          choice.inputCursorAnchor,
          actor,
          choice.input["cursor"],
          choice.cursorIssued.before,
          choice.cursorIssued.after
        );
      } else if (route.endsWith("-next"))
        throw new Error("public first-page cursor was not consumed");
      const before = await auditSnapshot(pool);
      lastAudit = before;
      activeRoute = route;
      const beforeSeconds = Math.floor(Date.now() / 1000);
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
          throw new Error("expected original list result");
        const afterSeconds = Math.floor(Date.now() / 1000);
        const expected = originalManagementNativeEnvelope(
          choice.selection,
          oracle,
          principal,
          structured["data"]["next_cursor"],
          beforeSeconds,
          afterSeconds
        );
        const expectedBytes = Buffer.from(canonicalJson(expected)),
          expectedTextBytes = Buffer.from(JSON.stringify(expected));
        expect(structured).toEqual(expected);
        if (route.endsWith("-page")) {
          const nextRoute = `${choice.selection.kind}-next` as Route;
          const cursor = structured["data"]["next_cursor"];
          expect(typeof cursor).toBe("string");
          selections[nextRoute].input["cursor"] = cursor as string;
          selections[nextRoute].cursorIssued = {
            before: beforeSeconds,
            after: afterSeconds
          };
        }
        expect(reply.value.content).toHaveLength(1);
        const text = reply.value.content[0];
        if (!object(text) || text["type"] !== "text" || typeof text["text"] !== "string")
          throw new Error("expected management tool text result");
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
        if (!object(data)) throw new Error("expected governance result data");
        expect(data).toEqual(expected.data);
        expect(Object.keys(data).sort()).toEqual(
          choice.selection.kind === "point"
            ? ["submission"]
            : choice.selection.kind === "questions"
              ? ["items", "next_cursor", "total_visible"]
              : ["items", "next_cursor"]
        );
        expect(result["reference"]).toBe(selections[route].reference);
        expect(result["resource_uri"]).toBe(oracle.resourceUri);
        expect(media[route]).toContain("application/json");
        expect(wire[route]).toBeGreaterThan(expectedBytes.length);
        const retained = oracle.retained;
        const retainedRoots = originalManagementRetainedRoots(choice.selection, oracle);
        const nativeShape = {
          content: [{ type: "text", text: JSON.stringify(expected) }],
          structuredContent: expected
        };
        const graph = retainedGraph([...retainedRoots, expected, nativeShape]);
        expect(graph.properties).toBeLessThanOrEqual(oracle.bound.propertyCount);
        expect(graph.containers).toBeLessThanOrEqual(oracle.bound.objectOrArrayCount);
        expect(BigInt(Buffer.byteLength(JSON.stringify(retained)))).toBeLessThanOrEqual(
          oracle.bound.jsonUpperBytes
        );
        expect(BigInt(expectedTextBytes.length)).toBeLessThanOrEqual(
          oracle.bound.jsonUpperBytes + 4096n
        );
        expect(BigInt(wire[route])).toBeLessThanOrEqual(oracle.bound.wireBytes);
        expect(manager?.accounting.usedUnits).toBe(oracle.units);
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
          actor: actorName,
          metadata: oracle.metadata,
          originalRows: oracle.rows.length,
          originalTotalVisible: oracle.totalVisible,
          requestId: ids.get(route),
          resourceUri: oracle.resourceUri,
          reference: selections[route].reference,
          canonicalBytes: expectedBytes.length,
          canonicalSha256: sha256Hex(expectedBytes),
          textBytes: expectedTextBytes.length,
          textSha256: sha256Hex(expectedTextBytes),
          wireBytes: wire[route],
          heldUnits: oracle.units,
          emptyPageRetainsReservation: route.endsWith("-empty"),
          syntheticSignedTailInput: route.endsWith("-empty"),
          allocationBoundBytes: String(oracle.bound.allocationBytes),
          wireBoundBytes: String(oracle.bound.wireBytes),
          sdkReplyCollected: true,
          serverProducerCompleted: producerDone,
          nativeFinished: nativeFinished.has(route),
          collectorDelegations: delegations.get(route),
          collectorErrors: settled.get(route)?.length,
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
      `native management ${actorName} fixture failed: ${failures.map((error) => (error instanceof Error ? error.stack : String(error))).join("\n")}`
    );
  expect(manager?.accounting.usedUnits).toBe(0);
  return {
    actor: actorName,
    publicCalls: routes.length,
    tools: observations,
    finalAllocationUnits: manager?.accounting.usedUnits,
    networkCleanupComplete: true
  };
}

it("delivers exact management histories and pages through separate native HTTPS actor sessions and real collector settlement", async () => {
  await withMigratedDatabase("management_native", async (pool) => {
    const fixture = await seedManagementProjectionFixture(pool);
    expect(fixture.commands).toHaveLength(7);
    await fixture.requestMainRevision();
    await fixture.replyToMainRevision();
    await fixture.reviseSourceAndResubmitMain();
    await fixture.approveMain();
    expect(fixture.commands).toHaveLength(12);
    await fixture.answerFirstQuestion();
    await fixture.followUpFirstQuestion();
    await fixture.answerFirstQuestionAgain();
    expect(fixture.commands).toHaveLength(15);
    // The existing fixture supplies constrained synthetic authenticated sessions
    // and resolves all nine actual token fields. No duplicate session is seeded.
    const secretary = await runActorGroup(pool, fixture, "secretary");
    const asker = await runActorGroup(pool, fixture, "asker");
    expect(secretary.publicCalls + asker.publicCalls).toBe(9);
    console.info(
      JSON.stringify({
        probe: "native-management-delivery",
        protocol: "2026-07-28",
        fixtureKind:
          "15 normal document/submission/question actions with synthetic constrained sessions and two fixed-actor runtimes",
        commands: fixture.commands,
        publicCalls: 9,
        groups: [secretary, asker],
        tools: [...secretary.tools, ...asker.tools],
        finalAllocationUnits: 0,
        networkCleanupComplete: true,
        publicAbsentSubmissionTested: false
      })
    );
  });
}, 120000);
