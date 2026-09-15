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
import { meetingProjectionPrincipal } from "../helpers/meeting-projection-principal.js";
import { seedGovernanceListProjectionFixture } from "../helpers/governance-list-projection-fixture.js";
import {
  assertOriginalGovernanceScalars,
  originalGovernanceAllocationBound,
  originalGovernanceRows,
  readOriginalGovernanceList,
  readOriginalGovernanceListMeasurement,
  type OracleGovernanceListInput,
  type OracleGovernanceListKind,
  type OriginalGovernancePageRow
} from "../helpers/governance-lists-native-oracle.js";
import {
  governanceListCursorKey,
  governanceListTools,
  originalGovernanceListEnvelope,
  signGovernanceListTailCursor,
  verifyGovernanceListCursor
} from "../helpers/governance-lists-page-oracle.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-governance-lists-native-token";
const timeout = 10000;
const routes = [
  "rulesets-full",
  "rulesets-page",
  "rulesets-next",
  "rulesets-empty",
  "templates-full",
  "templates-page",
  "templates-next",
  "templates-empty",
  "matter_types-full",
  "matter_types-page",
  "matter_types-next",
  "matter_types-empty"
] as const;
type Route = (typeof routes)[number];
type Tool = (typeof governanceListTools)[keyof typeof governanceListTools];
type Selection = {
  tool: Tool;
  kind: OracleGovernanceListKind;
  reference: null;
  selection: OracleGovernanceListInput;
  expectedRows: number;
  input: Record<string, JsonValue>;
  inputCursorAnchor?: OriginalGovernancePageRow;
  cursorIssued?: { before: number; after: number };
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

it("delivers exact governance list pages through native HTTPS SDK and real empty collector settlement", async () => {
  await withMigratedDatabase("governance_lists_native", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: [
        "documents:contribute",
        "documents:read",
        "governance:read",
        "meeting:act",
        "secretariat:admin"
      ]
    });
    // Reuse the actually passed constrained catalog storage. This is not a
    // public governance activation ceremony or browser/provider authentication.
    const seed = await seedGovernanceListProjectionFixture(pool, actor);
    const principal = await meetingProjectionPrincipal(pool, actor);
    const selections = {} as Record<Route, Selection>;
    for (const kind of ["rulesets", "templates", "matter_types"] as const) {
      const original = await withRequestTransaction(
        pool,
        actor.context,
        async (connection) => {
          expect(
            (await connection.query<{ role: string }>("select current_user as role")).rows
          ).toEqual([{ role: "boardagent_server" }]);
          const rows = await readOriginalGovernanceList(connection, {
            kind,
            selectorId: actor.boardId,
            cursorAt: null,
            cursorId: null,
            limit: 100
          });
          const expectedIds =
            kind === "rulesets"
              ? [seed.rulesetId, seed.alternateRulesetId]
              : kind === "templates"
                ? seed.templateIds
                : seed.matterIds;
          expect(rows).toHaveLength(expectedIds.length);
          expect(new Set(rows.map((row) => row.cursor_id))).toEqual(new Set(expectedIds));
          return rows;
        },
        { assumeRole: "boardagent_server" }
      );
      for (const phase of ["full", "page", "next", "empty"] as const) {
        const anchor =
          phase === "next" ? original[0]! : phase === "empty" ? original.at(-1)! : null;
        const selection: OracleGovernanceListInput = {
          kind,
          selectorId: actor.boardId,
          limit: phase === "page" ? 1 : 100,
          cursorAt: anchor?.cursor_at ?? null,
          cursorId: anchor?.cursor_id ?? null
        };
        let cursor: string | null = null;
        let cursorIssued: Selection["cursorIssued"];
        if (phase === "empty") {
          // Terminal public pages emit no cursor. This explicitly synthetic
          // signed input uses the actual last original row's ordering tuple.
          const issued = Math.floor(Date.now() / 1000);
          cursor = signGovernanceListTailCursor(
            kind,
            actor.boardId,
            anchor!,
            actor,
            issued + 86400
          );
          cursorIssued = { before: issued, after: issued };
        }
        selections[`${kind}-${phase}`] = {
          kind,
          tool: governanceListTools[kind],
          reference: null,
          selection,
          expectedRows:
            phase === "empty"
              ? 0
              : phase === "page"
                ? 2
                : phase === "next"
                  ? original.length - 1
                  : original.length,
          input: {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: actor.boardId,
            limit: selection.limit,
            cursor
          },
          ...(anchor ? { inputCursorAnchor: anchor } : {}),
          ...(cursorIssued ? { cursorIssued } : {})
        };
      }
    }
    let activeRoute: Route | undefined;
    function routeFor(tool: unknown, input: Record<string, unknown>): Route {
      if (
        !activeRoute ||
        tool !== selections[activeRoute].tool ||
        canonicalJson(input) !== canonicalJson(selections[activeRoute].input)
      )
        throw new Error("unexpected governance list selector");
      return activeRoute;
    }
    async function expectedFor(route: Route) {
      const choice = selections[route];
      return withRequestTransaction(
        pool,
        actor.context,
        async (connection) => {
          const measured = await readOriginalGovernanceListMeasurement(
            connection,
            choice.selection
          );
          assertOriginalGovernanceScalars(choice.kind, measured);
          const rows = originalGovernanceRows(measured);
          expect(rows).toHaveLength(choice.expectedRows);
          const bound = originalGovernanceAllocationBound(choice.kind, measured);
          expect(bound.units).toBe(1);
          return { rows, bound, units: bound.units, resourceUri: null };
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
      const route = request.headers["x-governance-lists-fixture"];
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
    // Plain governance lists return no prepared delivery handle. Delegate
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
        cursorKey: governanceListCursorKey,
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
        executeRead: async (principal, tool, input) => {
          if (
            !(Object.values(governanceListTools) as readonly string[]).includes(tool) ||
            !object(input)
          )
            throw new Error("unexpected native tool request");
          const route = routeFor(tool, input);
          const owner = currentResponseAllocationOwner(),
            collector = currentResourceDeliveryCollector();
          if (!owner || !collector)
            throw new Error("actual native allocation owner and collector required");
          expect(owners.has(route)).toBe(false);
          owners.set(route, owner);
          collectors.set(route, collector);
          expect(principal.serviceOrigin).toBe(origin);
          expect(principal.tokenJti).toBe(actor.tokenJti);
          return repository.executeRead(principal, tool, input);
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
            !(Object.values(governanceListTools) as readonly unknown[]).includes(params["name"]) ||
            !object(args) ||
            !(typeof parsed["id"] === "string" || typeof parsed["id"] === "number")
          )
            throw new Error("uncorrelated governance tool request");
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
                ...(route ? { "x-governance-lists-fixture": route } : {})
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
        { name: "governance-lists-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "governance-lists-native-fixture"
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
      for (const name of Object.values(governanceListTools)) {
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
        if (choice.input["cursor"] !== null) {
          if (!choice.inputCursorAnchor || !choice.cursorIssued)
            throw new Error("cursor provenance missing");
          verifyGovernanceListCursor(
            choice.kind,
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
          expect(reply.value.isError ?? false).toBe(false);
          const structured = reply.value.structuredContent;
          if (!object(structured) || !object(structured["data"]))
            throw new Error("expected original list result");
          const afterSeconds = Math.floor(Date.now() / 1000);
          const expected = originalGovernanceListEnvelope(
            selections[route].kind,
            selections[route].selection.selectorId,
            oracle.rows,
            selections[route].selection.limit,
            actor,
            structured["data"]["next_cursor"],
            beforeSeconds,
            afterSeconds
          );
          const expectedBytes = Buffer.from(canonicalJson(expected)),
            expectedTextBytes = Buffer.from(JSON.stringify(expected));
          expect(structured).toEqual(expected);
          if (route.endsWith("-page")) {
            const nextRoute = `${choice.kind}-next` as Route;
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
            throw new Error("expected governance tool text result");
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
          expect(Object.keys(data).sort()).toEqual(["items", "next_cursor"]);
          expect(result["reference"]).toBe(selections[route].reference);
          expect(result["resource_uri"]).toBe(oracle.resourceUri);
          expect(media[route]).toContain("application/json");
          expect(wire[route]).toBeGreaterThan(expectedBytes.length);
          const retained = oracle.rows.map((row) => ({ fits: true, ...row }));
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
          throw new AggregateError(routeFailures, `native route ${route} failed`);
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
      throw new AggregateError(failures, "native governance tool fixture failed");
    console.info(
      JSON.stringify({
        probe: "native-governance-lists-delivery",
        protocol: "2026-07-28",
        fixtureKind: "constrained synthetic governance catalog storage",
        publicCalls: routes.length,
        tools: observations,
        finalAllocationUnits: manager?.accounting.usedUnits,
        networkCleanupComplete: true
      })
    );
  });
}, 120000);
