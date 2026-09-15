import { createHmac } from "node:crypto";
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
  MINUTES_LIST_PREFLIGHT_SQL,
  minutesListProjectionPlan,
  type MinutesListInput,
  type MinutesListKind,
  type MinutesListMetadata
} from "../../artifacts/server/src/minutes-list-projection.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import { seedMinutesLineageFixture } from "../helpers/minutes-lineage-fixture.js";
import {
  ORIGINAL_MINUTES_VERSIONS_SQL,
  ORIGINAL_MINUTES_REVIEWS_SQL
} from "../helpers/minutes-lists-original-sql.js";
import {
  minutesListCursorKey,
  minutesListTools,
  originalListEnvelope,
  type MinutesOracleRow
} from "../helpers/minutes-list-pg-oracle.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-minutes-lists-native-token";
const timeout = 10000;
const routes = [
  "versions-full",
  "versions-page",
  "versions-next",
  "versions-empty",
  "reviews-full",
  "reviews-page",
  "reviews-next",
  "reviews-empty"
] as const;
type Route = (typeof routes)[number];
type Tool = "list_minutes_versions" | "list_minutes_review_items";
type Selection = {
  tool: Tool;
  kind: MinutesListKind;
  minutesId: string;
  selection: MinutesListInput;
  expectedRows: number;
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
async function auditSnapshot(pool: Pool) {
  return (
    await pool.query<{ id: string; sequence: string; event_hash: string; canonical_hex: string }>(
      `select id,sequence::text,encode(event_sha256,'hex') as event_hash,
    encode(canonical_payload,'hex') as canonical_hex from audit_events order by sequence`
    )
  ).rows;
}

it("delivers exact minutes list pages through native HTTPS SDK and real empty collector settlement", async () => {
  await withMigratedDatabase("minutes_lists_native", async (pool) => {
    const fixture = await seedMinutesLineageFixture(pool),
      actor = fixture.secretary;
    expect(fixture.currentTip()).toEqual({ minutesId: fixture.middleId, state: "finalized" });
    await fixture.appendSuccessor();
    expect(fixture.commands).toHaveLength(12);
    await fixture.minutesLists.seedReviews();
    await fixture.minutesLists.withdrawFirstComment();
    await fixture.minutesLists.resolveRedline();
    await fixture.minutesLists.withdrawSecondComment();
    await fixture.minutesLists.appendVersion();
    await fixture.minutesLists.appendVersion();
    expect(fixture.commands).toHaveLength(20);
    expect(fixture.currentTip()).toEqual({
      minutesId: fixture.replacementId,
      state: "published_review"
    });
    // This ordinary repository test fixture has no browser session by default.
    // Add constrained synthetic authenticated-session storage for the real
    // live-token resolver; no browser or OAuth authentication is represented.
    const sessionId = testId(339002);
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
    // Only the named normal20-command setup precedes native reads; every
    // mutation/resource service is rejected once the real transport starts.
    const originalSql = {
      versions: ORIGINAL_MINUTES_VERSIONS_SQL,
      reviews: ORIGINAL_MINUTES_REVIEWS_SQL
    };
    const selections = {} as Record<Route, Selection>;
    const originalRows = await withRequestTransaction(
      pool,
      actor.context,
      async (connection) => {
        const rows = {} as Record<MinutesListKind, MinutesOracleRow[]>;
        for (const kind of ["versions", "reviews"] as const) {
          rows[kind] = (
            await connection.query<MinutesOracleRow>(originalSql[kind], [
              fixture.replacementId,
              null,
              null,
              101
            ])
          ).rows;
          expect(rows[kind]).toHaveLength(3);
        }
        expect(rows.versions.map((row) => row.item["version"])).toEqual([3, 2, 1]);
        expect(rows.reviews.filter((row) => row.item["withdrawal"] !== null)).toHaveLength(2);
        expect(rows.reviews.filter((row) => row.item["disposition"] !== null)).toHaveLength(1);
        return rows;
      },
      { assumeRole: "boardagent_server" }
    );
    for (const kind of ["versions", "reviews"] as const)
      for (const phase of ["full", "page", "next", "empty"] as const) {
        const first = originalRows[kind][0]!,
          last = originalRows[kind].at(-1)!;
        const anchor = phase === "next" ? first : phase === "empty" ? last : null;
        const selection: MinutesListInput = {
          kind,
          minutesId: fixture.replacementId,
          limit: phase === "page" ? 1 : 100,
          cursorAt: anchor?.cursor_at ?? null,
          cursorId: anchor?.cursor_id ?? null
        };
        let cursor: string | null = null;
        if (phase === "empty") {
          // Independently sign the final original-row anchor, making a real empty
          // page request without changing Date.now or using production cursor code.
          const payload = canonicalJson({
            schema_version: "boardagent.cursor.v1",
            organization_id: actor.organizationId,
            member_id: actor.memberId,
            tool: minutesListTools[kind],
            board_id: null,
            after: canonicalJson({ at: last.cursor_at, id: last.cursor_id }),
            expires_at: Math.floor(Date.now() / 1000) + 86400
          });
          cursor =
            Buffer.from(payload).toString("base64url") +
            "." +
            createHmac("sha256", minutesListCursorKey)
              .update("boardagent.cursor.v1\0")
              .update(payload)
              .digest("base64url");
        }
        selections[`${kind}-${phase}`] = {
          kind,
          tool: minutesListTools[kind],
          minutesId: fixture.replacementId,
          selection,
          expectedRows: phase === "full" ? 3 : phase === "empty" ? 0 : 2,
          input: {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: fixture.replacementId,
            limit: selection.limit,
            cursor
          }
        };
      }
    function routeFor(tool: unknown, input: Record<string, unknown>): Route {
      const found = routes.find(
        (route) =>
          tool === selections[route].tool &&
          canonicalJson(input) === canonicalJson(selections[route].input)
      );
      if (!found) throw new Error("unexpected minutes list selector");
      return found;
    }
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (connection) => {
        const expected = {} as Record<
          Route,
          { rows: MinutesOracleRow[]; units: number; resourceUri: null }
        >;
        for (const route of routes) {
          const selection = selections[route],
            chosen = selection.selection;
          const values = [chosen.minutesId, chosen.cursorAt, chosen.cursorId, chosen.limit + 1];
          const found = (
            await connection.query<MinutesOracleRow>(originalSql[selection.kind], values)
          ).rows;
          const measured = (
            await connection.query<MinutesListMetadata>(
              MINUTES_LIST_PREFLIGHT_SQL[selection.kind],
              values
            )
          ).rows;
          expect(found).toHaveLength(selection.expectedRows);
          expect(measured).toHaveLength(found.length);
          for (const row of found)
            expect(Object.keys(row.item)).toHaveLength(selection.kind === "versions" ? 9 : 14);
          const units = minutesListProjectionPlan(chosen, measured).units;
          expect(units).toBe(1);
          expected[route] = { rows: found, units, resourceUri: null };
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
      const route = request.headers["x-minutes-lists-fixture"];
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
    // Plain minutes lists return no prepared delivery handle. Delegate
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
        cursorKey: minutesListCursorKey,
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
            (tool !== "list_minutes_versions" && tool !== "list_minutes_review_items") ||
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
            (params["name"] !== "list_minutes_versions" &&
              params["name"] !== "list_minutes_review_items") ||
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
                ...(route ? { "x-minutes-lists-fixture": route } : {})
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
        { name: "minutes-lists-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "minutes-lists-native-fixture"
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
      for (const name of ["list_minutes_versions", "list_minutes_review_items"] as const) {
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
          const expected = originalListEnvelope(
            selections[route].kind,
            selections[route].minutesId,
            oracle[route].rows,
            selections[route].selection.limit,
            actor,
            structured["data"]["next_cursor"],
            beforeSeconds,
            Math.floor(Date.now() / 1000)
          );
          const expectedBytes = Buffer.from(canonicalJson(expected)),
            expectedTextBytes = Buffer.from(JSON.stringify(expected));
          expect(structured).toEqual(expected);
          if (route.endsWith("-page")) {
            const cursor = structured["data"]["next_cursor"];
            expect(typeof cursor).toBe("string");
            selections[`${selections[route].kind}-next`].input["cursor"] = cursor as string;
          }
          expect(reply.value.content).toHaveLength(1);
          const text = reply.value.content[0];
          if (!object(text) || text["type"] !== "text" || typeof text["text"] !== "string")
            throw new Error("expected minutes tool text result");
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
          if (!object(data)) throw new Error("expected minutes result data");
          expect(data).toEqual(expected.data);
          expect(Object.keys(data).sort()).toEqual(["items", "next_cursor"]);
          expect(result["reference"]).toBe(selections[route].minutesId);
          expect(result["resource_uri"]).toBe(oracle[route].resourceUri);
          expect(media[route]).toContain("application/json");
          expect(wire[route]).toBeGreaterThan(expectedBytes.length);
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
            canonicalBytes: expectedBytes.length,
            canonicalSha256: sha256Hex(expectedBytes),
            textBytes: expectedTextBytes.length,
            textSha256: sha256Hex(expectedTextBytes),
            wireBytes: wire[route],
            heldUnits: oracle[route].units,
            emptyPageRetainsReservation: route.endsWith("-empty"),
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
        probe: "native-minutes-lists-delivery",
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
