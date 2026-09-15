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
import {
  AGENDA_PREFLIGHT_SQL,
  ATTENDANCE_PREFLIGHT_SQL,
  agendaProjectionPlan,
  attendanceProjectionPlan,
  type AgendaProjectionMetadata,
  type AttendanceProjectionMetadata
} from "../../artifacts/server/src/meeting-tool-projection.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedMeetingToolProjectionFixture } from "../helpers/meeting-tool-projection-fixture.js";
import { meetingProjectionPrincipal } from "../helpers/meeting-projection-principal.js";
import {
  originalAgendaOracle,
  originalAttendanceOracle
} from "../helpers/meeting-tool-pg-oracle.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-meeting-tools-native-token";
const timeout = 10000;
const routes = [
  "agenda-current",
  "agenda-explicit",
  "agenda-absent",
  "attendance-history",
  "attendance-empty"
] as const;
type Route = (typeof routes)[number];
type Tool = "get_agenda" | "get_attendance";
type Selection = Readonly<{
  tool: Tool;
  kind: "agenda" | "attendance";
  meetingId: string;
  version: number | null;
  expectedCount: number;
  input: Record<string, string | number | null>;
}>;
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
function bounded<T>(promise: Promise<T>, label: string, milliseconds = timeout): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), milliseconds);
    })
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
const capture = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error })
  );
async function auditSnapshot(pool: Pool) {
  return (
    await pool.query<{ id: string; sequence: string; event_hash: string; canonical_hex: string }>(
      `select id,sequence::text,encode(event_sha256,'hex') as event_hash,
    encode(canonical_payload,'hex') as canonical_hex from audit_events order by sequence`
    )
  ).rows;
}

it("delivers exact agenda selectors and attendance histories through native HTTPS SDK and real empty collector settlement", async () => {
  await withMigratedDatabase("meeting_tools_native", async (pool) => {
    const fixture = await seedMeetingToolProjectionFixture(pool),
      actor = fixture.secretary;
    expect(fixture.commands).toHaveLength(6);
    expect(fixture.currentVersion()).toBe(2);
    // Constrained synthetic session plus the actual nine-field live resolver;
    // no browser/provider/OAuth cryptographic authentication is represented.
    const principal = await meetingProjectionPrincipal(pool, actor);
    const agendaSelection = (version: number | null): Selection => ({
      tool: "get_agenda",
      kind: "agenda",
      meetingId: fixture.meetingId,
      version,
      expectedCount: version === 2147483647 ? 0 : 3,
      input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, meeting_id: fixture.meetingId, version }
    });
    const attendanceSelection = (meetingId: string, expectedCount: number): Selection => ({
      tool: "get_attendance",
      kind: "attendance",
      meetingId,
      version: null,
      expectedCount,
      input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, meeting_id: meetingId }
    });
    const selections: Record<Route, Selection> = {
      "agenda-current": agendaSelection(null),
      "agenda-explicit": agendaSelection(1),
      "agenda-absent": agendaSelection(2147483647),
      "attendance-history": attendanceSelection(fixture.meetingId, 2),
      "attendance-empty": attendanceSelection(fixture.emptyMeetingId, 0)
    };
    function routeFor(tool: unknown, input: Record<string, unknown>): Route {
      const found = routes.find(
        (route) =>
          tool === selections[route].tool &&
          input["meeting_id"] === selections[route].meetingId &&
          (selections[route].kind === "attendance" ||
            input["version"] === selections[route].version)
      );
      if (!found) throw new Error("unexpected meeting tool selector");
      return found;
    }
    // Independent verbatim original SQL is evaluated before native calls. It is a
    // small test oracle, not a production path or an RSS/capacity measurement.
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (connection) => {
        const expected = {} as Record<
          Route,
          {
            view: JsonValue;
            data: JsonValue;
            result: JsonValue;
            bytes: Buffer;
            textBytes: Buffer;
            units: number;
            resourceUri: null;
          }
        >;
        for (const route of routes) {
          const selection = selections[route];
          let view: JsonValue, units: number, data: JsonValue;
          if (selection.kind === "agenda") {
            const old = await originalAgendaOracle(
              connection,
              selection.meetingId,
              selection.version
            );
            const metadata = (
              await connection.query<AgendaProjectionMetadata>(AGENDA_PREFLIGHT_SQL, [
                selection.meetingId,
                selection.version
              ])
            ).rows;
            expect(metadata).toEqual(old ? [old.metadata] : []);
            view = old?.view ?? null;
            units = old ? agendaProjectionPlan(old.metadata).units : 0;
            if (selection.expectedCount) {
              if (!object(view)) throw new Error("expected complete original agenda");
              expect(Object.keys(view)).toHaveLength(8);
              expect(view["meeting_id"]).toBe(selection.meetingId);
              expect(view["agenda_version_id"]).toBe(
                route === "agenda-current" ? fixture.amendedAgendaId : fixture.originalAgendaId
              );
              expect(view["version"]).toBe(route === "agenda-current" ? 2 : 1);
              expect(view["items"]).toHaveLength(selection.expectedCount);
            } else expect(view).toBeNull();
            data = { agenda: view };
          } else {
            const old = await originalAttendanceOracle(connection, selection.meetingId);
            const metadata = (
              await connection.query<AttendanceProjectionMetadata>(ATTENDANCE_PREFLIGHT_SQL, [
                selection.meetingId
              ])
            ).rows;
            expect(metadata).toEqual([old.metadata]);
            view = old.items;
            units = attendanceProjectionPlan(old.metadata).units;
            expect(view).toHaveLength(selection.expectedCount);
            if (selection.expectedCount)
              expect(view).toEqual([
                expect.objectContaining({
                  attendance_id: fixture.originalAttendanceId,
                  status: "present",
                  corrects_id: null
                }),
                expect.objectContaining({
                  attendance_id: fixture.currentAttendanceId(),
                  status: "excused",
                  corrects_id: fixture.originalAttendanceId
                })
              ]);
            data = { meeting_id: selection.meetingId, records: view };
          }
          const result = {
            schema_version: "boardagent.tool-result.v1",
            tool: selection.tool,
            status: "ok",
            reference: selection.meetingId,
            resource_uri: null,
            data
          } as JsonValue;
          expected[route] = {
            view,
            data,
            result,
            resourceUri: null,
            bytes: Buffer.from(canonicalJson(result)),
            textBytes: Buffer.from(JSON.stringify(result)),
            units
          };
          expect(units).toBe(route === "agenda-absent" ? 0 : 1);
        }
        return expected;
      },
      { assumeRole: "boardagent_server" }
    );
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
        roles: [...principal.roles],
        boardIds: [...principal.boardIds]
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
      const route = request.headers["x-meeting-tools-fixture"];
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
    // Plain meeting tools return no prepared delivery handle. Delegate
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
        cursorKey: Buffer.alloc(32, 0x47),
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
          if ((tool !== "get_agenda" && tool !== "get_attendance") || !object(input))
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
            (params["name"] !== "get_agenda" && params["name"] !== "get_attendance") ||
            !object(args) ||
            !(typeof parsed["id"] === "string" || typeof parsed["id"] === "number")
          )
            throw new Error("uncorrelated meeting tool request");
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
                ...(route ? { "x-meeting-tools-fixture": route } : {})
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
        { name: "meeting-tools-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "meeting-tools-native-fixture"
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
      for (const name of ["get_agenda", "get_attendance"] as const) {
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
      const before = await auditSnapshot(pool);
      for (const route of routes) {
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
          const reply = await bounded(received, "SDK result collection did not settle");
          if (!reply.ok) throw reply.error;
          expect(reply.value.isError ?? false).toBe(false);
          expect(reply.value.structuredContent).toEqual(oracle[route].result);
          expect(reply.value.content).toHaveLength(1);
          const text = reply.value.content[0];
          if (!object(text) || text["type"] !== "text" || typeof text["text"] !== "string")
            throw new Error("expected meeting tool text result");
          // Existing MCP text uses JSON.stringify; canonical bytes are a separate oracle.
          expect(Buffer.from(text["text"])).toEqual(oracle[route].textBytes);
          expect(Buffer.from(canonicalJson(JSON.parse(text["text"])))).toEqual(oracle[route].bytes);
          expect(Buffer.from(canonicalJson(reply.value.structuredContent))).toEqual(
            oracle[route].bytes
          );
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
          if (!object(data)) throw new Error("expected meeting result data");
          expect(data).toEqual(oracle[route].data);
          expect(Object.keys(data).sort()).toEqual(
            selections[route].kind === "agenda" ? ["agenda"] : ["meeting_id", "records"]
          );
          expect(result["reference"]).toBe(selections[route].meetingId);
          expect(result["resource_uri"]).toBe(oracle[route].resourceUri);
          expect(media[route]).toContain("application/json");
          expect(wire[route]).toBeGreaterThan(oracle[route].bytes.length);
          expect(manager?.accounting.usedUnits).toBe(oracle[route].units);
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
            resourceUri: oracle[route].resourceUri,
            reference: selections[route].meetingId,
            canonicalBytes: oracle[route].bytes.length,
            canonicalSha256: sha256Hex(oracle[route].bytes),
            textBytes: oracle[route].textBytes.length,
            textSha256: sha256Hex(oracle[route].textBytes),
            wireBytes: wire[route],
            heldUnits: oracle[route].units,
            absentProjectionHasNoReservation: route === "agenda-absent",
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
            await bounded(received, "SDK route cleanup did not settle");
          } catch (error) {
            routeFailures.push(error);
          }
        }
        if (routeFailures.length)
          throw new AggregateError(routeFailures, "native route body or cleanup failed");
      }
      expect(ids.size).toBe(routes.length);
      expect(new Set(ids.values()).size).toBe(routes.length);
      expect(nativeFinished.size).toBe(routes.length);
      await expect.poll(() => nativeClosed.size, { timeout }).toBe(routes.length);
      expect(await auditSnapshot(pool)).toEqual(before);
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
          await bounded(
            Promise.resolve().then(() => close?.()),
            "native network cleanup did not settle"
          );
        } catch (error) {
          failures.push(error);
        }
      }
      try {
        await bounded(Promise.all(pending), "pending native SDK calls did not settle");
      } catch (error) {
        failures.push(error);
      }
      settleSpy.mockRestore();
      registerSpy.mockRestore();
      openSpy.mockRestore();
      if (serverErrors.length)
        failures.push(new AggregateError(serverErrors, "native server errors"));
    }
    if (failures.length) throw new AggregateError(failures, "native meeting tool fixture failed");
    console.info(
      JSON.stringify({
        probe: "native-meeting-tools-delivery",
        protocol: "2026-07-28",
        normalMeetingCommands: fixture.commands,
        currentAgendaVersion: fixture.currentVersion(),
        tools: observations,
        finalAllocationUnits: manager?.accounting.usedUnits,
        networkCleanupComplete: true
      })
    );
  });
}, 120000);
