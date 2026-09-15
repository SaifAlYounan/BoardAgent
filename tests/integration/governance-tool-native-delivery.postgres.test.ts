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
  GOVERNANCE_PROFILE_TOOL_PREFLIGHT_SQL,
  RULESET_TOOL_PREFLIGHT_SQL,
  governanceToolProjectionPlan,
  type GovernanceToolProjectionMetadata
} from "../../artifacts/server/src/governance-tool-projection.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedGovernanceToolProjectionFixture } from "../helpers/governance-tool-projection-fixture.js";
import {
  ORIGINAL_PROFILE_TOOL_SQL,
  ORIGINAL_RULESET_TOOL_SQL
} from "../helpers/governance-tool-original-sql.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-governance-tool-native-token";
const timeout = 10000;
const routes = [
  "profile-current",
  "profile-explicit",
  "profile-absent",
  "ruleset-current",
  "ruleset-explicit",
  "ruleset-absent"
] as const;
type Route = (typeof routes)[number];
type Tool = "get_board_governance_profile" | "get_ruleset";
type Selection = Readonly<{
  tool: Tool;
  kind: "profile" | "ruleset";
  selector: string | number | null;
  dataKey: "profile" | "ruleset";
  reference: string | null;
  expectedId: string | null;
  expectedVersion: number | null;
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

it("delivers exact current explicit and absent governance tools through native HTTPS SDK and real empty collector settlement", async () => {
  await withMigratedDatabase("governance_tool_native", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["governance:read"]
    });
    // This ordinary repository test fixture has no browser session by default.
    // Add constrained synthetic authenticated-session storage for the real
    // live-token resolver; no browser or OAuth authentication is represented.
    const sessionId = testId(260002);
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
    // Ordinary constrained draft storage with current pointers, two versions,
    // four ordered rules and literal PostgreSQL numeric-carry values. This is
    // not a public governance activation or canonical-commitment ceremony.
    const fixture = await seedGovernanceToolProjectionFixture(pool, actor);
    const selections: Record<Route, Selection> = {
      "profile-current": {
        tool: "get_board_governance_profile",
        kind: "profile",
        selector: null,
        dataKey: "profile",
        reference: null,
        expectedId: fixture.profileId,
        expectedVersion: 1,
        input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: actor.boardId, version: null }
      },
      "profile-explicit": {
        tool: "get_board_governance_profile",
        kind: "profile",
        selector: 2,
        dataKey: "profile",
        reference: null,
        expectedId: fixture.alternateProfileId,
        expectedVersion: 2,
        input: { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: actor.boardId, version: 2 }
      },
      "profile-absent": {
        tool: "get_board_governance_profile",
        kind: "profile",
        selector: 2147483647,
        dataKey: "profile",
        reference: null,
        expectedId: null,
        expectedVersion: null,
        input: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId,
          version: 2147483647
        }
      },
      "ruleset-current": {
        tool: "get_ruleset",
        kind: "ruleset",
        selector: null,
        dataKey: "ruleset",
        reference: null,
        expectedId: fixture.rulesetId,
        expectedVersion: 1,
        input: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId,
          ruleset_id: null
        }
      },
      "ruleset-explicit": {
        tool: "get_ruleset",
        kind: "ruleset",
        selector: fixture.alternateRulesetId,
        dataKey: "ruleset",
        reference: fixture.alternateRulesetId,
        expectedId: fixture.alternateRulesetId,
        expectedVersion: 2,
        input: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId,
          ruleset_id: fixture.alternateRulesetId
        }
      },
      "ruleset-absent": {
        tool: "get_ruleset",
        kind: "ruleset",
        selector: testId(260003),
        dataKey: "ruleset",
        reference: testId(260003),
        expectedId: null,
        expectedVersion: null,
        input: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId,
          ruleset_id: testId(260003)
        }
      }
    };
    function routeFor(tool: unknown, input: Record<string, unknown>): Route {
      const found = routes.find((route) => {
        const selection = selections[route];
        return (
          tool === selection.tool &&
          input["board_id"] === actor.boardId &&
          input[selection.kind === "profile" ? "version" : "ruleset_id"] === selection.selector
        );
      });
      if (!found) throw new Error("unexpected governance tool selector");
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
            result: JsonValue;
            bytes: Buffer;
            textBytes: Buffer;
            units: number;
            resourceUri: string | null;
          }
        >;
        for (const route of routes) {
          const selection = selections[route],
            profile = selection.kind === "profile";
          const found = await connection.query<{ view: JsonValue }>(
            profile ? ORIGINAL_PROFILE_TOOL_SQL : ORIGINAL_RULESET_TOOL_SQL,
            [actor.boardId, selection.selector]
          );
          const measured = await connection.query<GovernanceToolProjectionMetadata>(
            profile ? GOVERNANCE_PROFILE_TOOL_PREFLIGHT_SQL : RULESET_TOOL_PREFLIGHT_SQL,
            [actor.boardId, selection.selector]
          );
          const visible = selection.expectedId !== null;
          expect(found.rows).toHaveLength(visible ? 1 : 0);
          expect(measured.rows).toHaveLength(visible ? 1 : 0);
          const view = found.rows[0]?.view ?? null;
          if (visible) {
            if (!object(view)) throw new Error("expected original complete governance view");
            expect(Object.keys(view)).toHaveLength(profile ? 11 : 12);
            expect(view[profile ? "profile_id" : "ruleset_id"]).toBe(selection.expectedId);
            expect(view["version"]).toBe(selection.expectedVersion);
            expect(view["board_id"]).toBe(actor.boardId);
            expect(view["state"]).toBe("draft");
            expect(view["supersedes_id"]).toBeNull();
            expect(view["activated_at"]).toBeNull();
            const payload = view["canonical_payload"];
            if (!object(payload)) throw new Error("expected governance payload");
            expect(payload["carry"]).toBe(10000000000000000);
            if (profile)
              expect(view["source_agreement_references"]).toEqual(
                route === "profile-current" ? [10000000000000000] : []
              );
            else {
              const rules = view["rules"];
              if (!Array.isArray(rules)) throw new Error("expected original rules array");
              expect(rules).toHaveLength(route === "ruleset-current" ? fixture.ruleIds.length : 0);
              if (route === "ruleset-current")
                expect(
                  rules.map((rule: unknown) => {
                    if (!object(rule)) throw new Error("expected complete rule");
                    expect(Object.keys(rule)).toHaveLength(7);
                    return rule["rule_id"];
                  })
                ).toEqual(fixture.ruleIds);
            }
          } else expect(view).toBeNull();
          const resourceUri = visible
            ? `board://${actor.boardId}/${profile ? "governance-profile" : "rulesets"}/${String(selection.expectedVersion)}`
            : null;
          const result = {
            schema_version: "boardagent.tool-result.v1",
            tool: selection.tool,
            status: "ok",
            reference: selection.reference,
            resource_uri: resourceUri,
            data: { [selection.dataKey]: view }
          } as JsonValue;
          expected[route] = {
            view,
            result,
            resourceUri,
            bytes: Buffer.from(canonicalJson(result)),
            textBytes: Buffer.from(JSON.stringify(result)),
            units: measured.rows[0]
              ? governanceToolProjectionPlan(selection.kind, measured.rows[0]).units
              : 0
          };
          if (visible) expect(expected[route].units).toBeGreaterThan(0);
          else expect(expected[route].units).toBe(0);
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
    expect(live.scope_set).toEqual(["governance:read"]);
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
      const route = request.headers["x-governance-tool-fixture"];
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
    // Plain governance tools return no prepared delivery handle. Delegate
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
          if ((tool !== "get_board_governance_profile" && tool !== "get_ruleset") || !object(input))
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
            (params["name"] !== "get_board_governance_profile" &&
              params["name"] !== "get_ruleset") ||
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
                ...(route ? { "x-governance-tool-fixture": route } : {})
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
        { name: "governance-tool-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "governance-tool-native-fixture"
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
      for (const name of ["get_board_governance_profile", "get_ruleset"] as const) {
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
            throw new Error("expected governance tool text result");
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
          if (!object(data)) throw new Error("expected governance result data");
          expect(Object.keys(data)).toEqual([selections[route].dataKey]);
          expect(data[selections[route].dataKey]).toEqual(oracle[route].view);
          expect(result["reference"]).toBe(selections[route].reference);
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
            reference: selections[route].reference,
            canonicalBytes: oracle[route].bytes.length,
            canonicalSha256: sha256Hex(oracle[route].bytes),
            textBytes: oracle[route].textBytes.length,
            textSha256: sha256Hex(oracle[route].textBytes),
            wireBytes: wire[route],
            heldUnits: oracle[route].units,
            absentProjectionHasNoReservation: selections[route].expectedId === null,
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
    if (failures.length)
      throw new AggregateError(failures, "native governance tool fixture failed");
    console.info(
      JSON.stringify({
        probe: "native-governance-tool-delivery",
        protocol: "2026-07-28",
        tools: observations,
        finalAllocationUnits: manager?.accounting.usedUnits,
        networkCleanupComplete: true
      })
    );
  });
}, 120000);
