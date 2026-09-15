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
  MINUTES_TOOL_PREFLIGHT_SQL,
  minutesToolProjectionPlan,
  type MinutesToolProjectionMetadata
} from "../../artifacts/server/src/minutes-tool-projection.js";
import {
  MINUTES_LINEAGE_PREFLIGHT_SQL,
  minutesLineageProjectionPlan,
  type MinutesLineageMetadata
} from "../../artifacts/server/src/minutes-lineage-projection.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import { seedMinutesLineageFixture } from "../helpers/minutes-lineage-fixture.js";
import { ORIGINAL_MINUTES_TOOL_SQL } from "../helpers/minutes-tool-original-sql.js";
import { ORIGINAL_MINUTES_LINEAGE_SQL } from "../helpers/minutes-lineage-original-sql.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-minutes-tools-native-token";
const timeout = 10000;
const routes = [
  "minutes-A",
  "minutes-B",
  "minutes-C",
  "minutes-absent",
  "lineage-B",
  "lineage-C"
] as const;
type Route = (typeof routes)[number];
type Tool = "get_minutes" | "get_minutes_lineage";
type Selection = Readonly<{
  tool: Tool;
  kind: "minutes" | "lineage";
  minutesId: string;
  expectedState: "finalized" | "published_review" | null;
  expectedCycles: number;
  input: Record<string, string>;
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

it("delivers exact finalized published and lineage minutes tools through native HTTPS SDK and real empty collector settlement", async () => {
  await withMigratedDatabase("minutes_tools_native", async (pool) => {
    const fixture = await seedMinutesLineageFixture(pool),
      actor = fixture.secretary;
    expect(fixture.currentTip()).toEqual({ minutesId: fixture.middleId, state: "finalized" });
    await fixture.appendSuccessor();
    expect(fixture.commands).toHaveLength(12);
    expect(fixture.currentTip()).toEqual({
      minutesId: fixture.replacementId,
      state: "published_review"
    });
    // This ordinary repository test fixture has no browser session by default.
    // Add constrained synthetic authenticated-session storage for the real
    // live-token resolver; no browser or OAuth authentication is represented.
    const sessionId = testId(337002);
    await pool.query(
      `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,
        state,exact_origin,expires_at,last_authenticated_at)
       values($1,$2,$3,$4,$5,'authenticated',$6,transaction_timestamp()+interval '10 minutes',
        transaction_timestamp())`,
      [
        sessionId,
        actor.organizationId,
        Buffer.alloc(32, 0x92),
        actor.memberId,
        actor.clientId,
        origin
      ]
    );
    const linked = await pool.query(
      "update access_token_records set session_id=$2 where id=$1 and session_id is null returning id",
      [actor.accessTokenRecordId, sessionId]
    );
    expect(linked.rowCount).toBe(1);
    // The shared fixture ran only normal minutes no-actions/sign/finalize/
    // correction commands before this read-only transport. No native mutation port exists.
    const minutesSelection = (
      minutesId: string,
      expectedState: Selection["expectedState"]
    ): Selection => ({
      tool: "get_minutes",
      kind: "minutes",
      minutesId,
      expectedState,
      expectedCycles: 0,
      input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, minutes_id: minutesId }
    });
    const lineageSelection = (minutesId: string, expectedCycles: number): Selection => ({
      tool: "get_minutes_lineage",
      kind: "lineage",
      minutesId,
      expectedState: null,
      expectedCycles,
      input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, minutes_id: minutesId }
    });
    const selections: Record<Route, Selection> = {
      "minutes-A": minutesSelection(fixture.originalId, "finalized"),
      "minutes-B": minutesSelection(fixture.middleId, "finalized"),
      "minutes-C": minutesSelection(fixture.replacementId, "published_review"),
      "minutes-absent": minutesSelection(testId(337003), null),
      "lineage-B": lineageSelection(fixture.middleId, 2),
      "lineage-C": lineageSelection(fixture.replacementId, 1)
    };
    function routeFor(tool: unknown, input: Record<string, unknown>): Route {
      const found = routes.find(
        (route) =>
          tool === selections[route].tool && input["minutes_id"] === selections[route].minutesId
      );
      if (!found) throw new Error("unexpected minutes tool selector");
      return found;
    }
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
            resourceUri: string | null;
          }
        >;
        for (const route of routes) {
          const selection = selections[route];
          let view: JsonValue,
            units: number,
            resourceUri: string | null = null,
            data: JsonValue;
          if (selection.kind === "minutes") {
            const found = await connection.query<{ view: JsonValue }>(ORIGINAL_MINUTES_TOOL_SQL, [
              selection.minutesId
            ]);
            const measured = await connection.query<MinutesToolProjectionMetadata>(
              MINUTES_TOOL_PREFLIGHT_SQL,
              [selection.minutesId]
            );
            const visible = selection.expectedState !== null;
            expect(found.rows).toHaveLength(visible ? 1 : 0);
            expect(measured.rows).toHaveLength(visible ? 1 : 0);
            view = found.rows[0]?.view ?? null;
            if (visible) {
              if (!object(view)) throw new Error("expected complete original minutes");
              expect(Object.keys(view)).toHaveLength(11);
              expect(view["minutes_id"]).toBe(selection.minutesId);
              expect(view["board_id"]).toBe(actor.boardId);
              expect(view["state"]).toBe(selection.expectedState);
              const version = view["version"];
              if (!object(version)) throw new Error("expected visible original minutes version");
              expect(Object.keys(version)).toHaveLength(10);
              expect(version["transcript_version_id"]).toBeNull();
              expect(version["transcript_sha256"]).toBeNull();
              resourceUri = `board://${actor.boardId}/minutes/${selection.minutesId}/versions/${String(version["version"])}`;
              if (selection.expectedState === "finalized") {
                const pkg = view["signature_package"],
                  declaration = view["action_declaration"];
                if (!object(pkg) || !object(declaration))
                  throw new Error("expected finalized package and declaration");
                expect(Object.keys(pkg)).toHaveLength(8);
                expect(Object.keys(declaration)).toHaveLength(5);
                const requirements = pkg["required_signers"],
                  signatures = pkg["signatures"];
                if (!Array.isArray(requirements) || !Array.isArray(signatures))
                  throw new Error("expected original signature arrays");
                expect(requirements).toHaveLength(1);
                expect(signatures).toHaveLength(1);
                if (!object(requirements[0]) || !object(signatures[0]))
                  throw new Error("expected original signature records");
                expect(Object.keys(requirements[0])).toHaveLength(4);
                expect(Object.keys(signatures[0])).toHaveLength(5);
                expect(requirements[0]["member_id"]).toBe(fixture.signer.memberId);
                expect(signatures[0]["signer_member_id"]).toBe(fixture.signer.memberId);
              } else {
                expect(view["signature_package"]).toBeNull();
                expect(view["action_declaration"]).toBeNull();
              }
            } else expect(view).toBeNull();
            units = measured.rows[0] ? minutesToolProjectionPlan(measured.rows[0]).units : 0;
            data = { minutes: view };
          } else {
            const found = await connection.query<{ items: JsonValue[] }>(
              ORIGINAL_MINUTES_LINEAGE_SQL,
              [selection.minutesId]
            );
            const measured = await connection.query<MinutesLineageMetadata>(
              MINUTES_LINEAGE_PREFLIGHT_SQL,
              [selection.minutesId]
            );
            expect(found.rows).toHaveLength(1);
            view = found.rows[0]!.items;
            expect(view).toHaveLength(selection.expectedCycles);
            for (const item of view) {
              if (!object(item)) throw new Error("expected original cycle");
              expect(Object.keys(item)).toHaveLength(6);
            }
            expect(
              view.map((item) =>
                object(item) ? [item["original_minutes_id"], item["replacement_minutes_id"]] : null
              )
            ).toEqual(
              selection.expectedCycles === 2
                ? [
                    [fixture.originalId, fixture.middleId],
                    [fixture.middleId, fixture.replacementId]
                  ]
                : [[fixture.middleId, fixture.replacementId]]
            );
            units = minutesLineageProjectionPlan(selection.minutesId, measured.rows).units;
            data = { minutes_id: selection.minutesId, correction_cycles: view };
          }
          const result = {
            schema_version: "boardagent.tool-result.v1",
            tool: selection.tool,
            status: "ok",
            reference: selection.minutesId,
            resource_uri: resourceUri,
            data
          } as JsonValue;
          expected[route] = {
            view,
            data,
            result,
            resourceUri,
            bytes: Buffer.from(canonicalJson(result)),
            textBytes: Buffer.from(JSON.stringify(result)),
            units
          };
          if (route === "minutes-absent") expect(units).toBe(0);
          else expect(units).toBe(1);
        }
        return expected;
      },
      { assumeRole: "boardagent_server" }
    );
    const live = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const result = await client.query<{
          protocol_client_id: string;
          resource_uri: string;
          scope_set: string[];
          roles: string[];
          board_ids: string[];
        }>(
          "select protocol_client_id,resource_uri,scope_set,roles,board_ids from boardagent_resolve_access_token($1)",
          [actor.tokenJti]
        );
        expect(result.rows).toHaveLength(1);
        return result.rows[0]!;
      },
      { assumeRole: "boardagent_server" }
    );
    expect(live.resource_uri).toBe(resource.href);
    expect(live.scope_set).toEqual(
      expect.arrayContaining(["governance:read", "minutes:act", "secretariat:admin"])
    );
    expect(live.scope_set).toHaveLength(3);
    const auth: AuthInfo = {
      token,
      clientId: live.protocol_client_id,
      scopes: live.scope_set,
      expiresAt: Math.floor(Date.now() / 1000) + 300,
      resource,
      extra: {
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        internalClientId: actor.clientId,
        accessTokenRecordId: actor.accessTokenRecordId,
        jti: actor.tokenJti,
        keyId: "test-oauth",
        roles: live.roles,
        boardIds: live.board_ids
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
      const route = request.headers["x-minutes-tools-fixture"];
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
    // Plain minutes tools return no prepared delivery handle. Delegate
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
          if ((tool !== "get_minutes" && tool !== "get_minutes_lineage") || !object(input))
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
            (params["name"] !== "get_minutes" && params["name"] !== "get_minutes_lineage") ||
            !object(args) ||
            !(typeof parsed["id"] === "string" || typeof parsed["id"] === "number")
          )
            throw new Error("uncorrelated minutes tool request");
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
                ...(route ? { "x-minutes-tools-fixture": route } : {})
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
        { name: "minutes-tools-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "minutes-tools-native-fixture"
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
      for (const name of ["get_minutes", "get_minutes_lineage"] as const) {
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
          expect(reply.value.structuredContent).toEqual(oracle[route].result);
          expect(reply.value.content).toHaveLength(1);
          const text = reply.value.content[0];
          if (!object(text) || text["type"] !== "text" || typeof text["text"] !== "string")
            throw new Error("expected minutes tool text result");
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
          if (!object(data)) throw new Error("expected minutes result data");
          expect(data).toEqual(oracle[route].data);
          expect(Object.keys(data).sort()).toEqual(
            selections[route].kind === "minutes" ? ["minutes"] : ["correction_cycles", "minutes_id"]
          );
          expect(result["reference"]).toBe(selections[route].minutesId);
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
            reference: selections[route].minutesId,
            canonicalBytes: oracle[route].bytes.length,
            canonicalSha256: sha256Hex(oracle[route].bytes),
            textBytes: oracle[route].textBytes.length,
            textSha256: sha256Hex(oracle[route].textBytes),
            wireBytes: wire[route],
            heldUnits: oracle[route].units,
            absentProjectionHasNoReservation: route === "minutes-absent",
            sdkReplyCollected: true,
            serverProducerCompleted: producerDone,
            nativeFinished: nativeFinished.has(route),
            collectorDelegations: delegations.get(route),
            collectorErrors: settled.get(route)?.length,
            preparedDeliveryRegistrations: 0,
            deliveryAuditAdded: false
          });
        } finally {
          releaseSettlement[route].release();
          await received;
        }
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
          await close?.();
        } catch (error) {
          failures.push(error);
        }
      }
      await Promise.all(pending);
      settleSpy.mockRestore();
      registerSpy.mockRestore();
      openSpy.mockRestore();
      if (serverErrors.length)
        failures.push(new AggregateError(serverErrors, "native server errors"));
    }
    if (failures.length) throw new AggregateError(failures, "native minutes tool fixture failed");
    console.info(
      JSON.stringify({
        probe: "native-minutes-tools-delivery",
        protocol: "2026-07-28",
        normalMinutesCommands: fixture.commands,
        currentTip: fixture.currentTip(),
        tools: observations,
        finalAllocationUnits: manager?.accounting.usedUnits,
        networkCleanupComplete: true
      })
    );
  });
}, 120000);
