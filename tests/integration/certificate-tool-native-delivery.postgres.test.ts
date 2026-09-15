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
  CERTIFICATE_TOOL_PREFLIGHT_SQL,
  certificateToolProjectionPlan,
  type CertificateToolProjectionMetadata
} from "../../artifacts/server/src/certificate-tool-projection.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { verifyOfflineCertificateBundle } from "../../lib/audit/src/offline.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedVoteProjectionFixture } from "../helpers/vote-projection-fixture.js";
import { seedCertificateProjectionFixture } from "../helpers/certificate-projection-fixture.js";
import { ORIGINAL_CERTIFICATE_TOOL_SQL } from "../helpers/certificate-tool-original-sql.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-certificate-tool-native-token";
const timeout = 10000;
type Route = "default" | "explicit";
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

it("delivers exact current and explicit certificate tools through native HTTPS SDK and real empty collector settlement", async () => {
  await withMigratedDatabase("cert_tool_native", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["governance:read"]
    });
    // This ordinary repository test fixture has no browser session by default.
    // Add constrained synthetic authenticated-session storage for the real
    // live-token resolver; no browser or OAuth authentication is represented.
    const sessionId = testId(225002);
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
    const vote = await seedVoteProjectionFixture(pool, actor),
      signed = await seedCertificateProjectionFixture(pool, actor, vote.voteId);
    const uri = `board://${actor.boardId}/votes/${vote.voteId}/certificates/${signed.certificateId}`;
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (connection) => {
        const expected = {} as Record<
          Route,
          { view: JsonValue; result: JsonValue; bytes: Buffer; textBytes: Buffer; units: number }
        >;
        for (const route of ["default", "explicit"] as const) {
          const selected = route === "default" ? null : signed.certificateId;
          const found = await connection.query<{ board_id: string; view: JsonValue }>(
            ORIGINAL_CERTIFICATE_TOOL_SQL,
            [vote.voteId, selected]
          );
          const measured = await connection.query<CertificateToolProjectionMetadata>(
            CERTIFICATE_TOOL_PREFLIGHT_SQL,
            [vote.voteId, selected]
          );
          expect(found.rows).toHaveLength(1);
          expect(measured.rows).toHaveLength(1);
          expect(found.rows[0]!.board_id).toBe(actor.boardId);
          const view = found.rows[0]!.view;
          if (!object(view))
            throw new Error("expected original twelve-field certificate tool view");
          expect(Object.keys(view)).toHaveLength(12);
          const result = {
            schema_version: "boardagent.tool-result.v1",
            tool: "get_vote_certificate",
            status: "ok",
            reference: selected ?? vote.voteId,
            resource_uri: uri,
            data: { certificate: view }
          } as JsonValue;
          expected[route] = {
            view,
            result,
            bytes: Buffer.from(canonicalJson(result)),
            textBytes: Buffer.from(JSON.stringify(result)),
            units: certificateToolProjectionPlan(measured.rows[0]!).units
          };
        }
        expect(expected.default.view).toEqual(expected.explicit.view);
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
    const entered = { default: gate(), explicit: gate() },
      releaseSettlement = { default: gate(), explicit: gate() };
    const owners = new Map<Route, ResponseAllocationOwner>(),
      collectors = new Map<Route, ResourceDeliveryCollector>();
    const ids = new Map<Route, string | number>(),
      nativeFinished = new Set<Route>(),
      nativeClosed = new Set<Route>();
    const wire = { default: 0, explicit: 0 },
      media = { default: "", explicit: "" };
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
      const route = request.headers["x-certificate-tool-fixture"];
      if (route === "default" || route === "explicit") {
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
    // Plain get_vote_certificate returns no prepared delivery handle. Delegate
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
        const route = (["default", "explicit"] as const).find(
          (candidate) => collectors.get(candidate) === this
        );
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
          if (tool !== "get_vote_certificate" || !object(input) || input["vote_id"] !== vote.voteId)
            throw new Error("unexpected native tool request");
          const route: Route = input["certificate_id"] === null ? "default" : "explicit";
          if (route === "explicit" && input["certificate_id"] !== signed.certificateId)
            throw new Error("unexpected certificate selector");
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
            params["name"] !== "get_vote_certificate" ||
            !object(args) ||
            args["vote_id"] !== vote.voteId ||
            !(typeof parsed["id"] === "string" || typeof parsed["id"] === "number")
          )
            throw new Error("uncorrelated certificate tool request");
          if (args["certificate_id"] !== null && args["certificate_id"] !== signed.certificateId)
            throw new Error("unexpected certificate selector");
          route = args["certificate_id"] === null ? "default" : "explicit";
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
                ...(route ? { "x-certificate-tool-fixture": route } : {})
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
        { name: "certificate-tool-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "certificate-tool-native-fixture"
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
      const declared = listed.tools.find((tool) => tool.name === "get_vote_certificate");
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
      await expect.poll(() => manager?.accounting.usedUnits, { timeout }).toBe(0);
      const before = await auditSnapshot(pool);
      for (const route of ["default", "explicit"] as const) {
        const received = capture(
          client.callTool(
            {
              name: "get_vote_certificate",
              arguments: {
                schema_version: TOOL_INPUT_SCHEMA_VERSION,
                vote_id: vote.voteId,
                certificate_id: route === "default" ? null : signed.certificateId
              }
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
            throw new Error("expected certificate tool text result");
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
          expect(result["tool"]).toBe("get_vote_certificate");
          const data = result["data"],
            view = object(data) ? data["certificate"] : undefined;
          if (!object(view)) throw new Error("expected original certificate view");
          expect(Object.keys(view)).toHaveLength(12);
          expect(view["signing_key"]).toBeUndefined();
          const bundle = {
            schema_version: "boardagent.vote-certificate-bundle.v1",
            certificate_id: view["certificate_id"],
            vote_id: view["vote_id"],
            outcome_id: view["outcome_id"],
            public_id: view["public_id"],
            canonical_payload: view["canonical_payload"],
            payload_sha256: view["payload_sha256"],
            signature_base64url: view["signature_base64url"],
            issued_at: view["issued_at"],
            signing_key: signed.trust.keys[0]
          };
          expect(verifyOfflineCertificateBundle(bundle, signed.trust)).toBe(true);
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
            resourceUri: uri,
            reference: route === "default" ? vote.voteId : signed.certificateId,
            canonicalBytes: oracle[route].bytes.length,
            canonicalSha256: sha256Hex(oracle[route].bytes),
            textBytes: oracle[route].textBytes.length,
            textSha256: sha256Hex(oracle[route].textBytes),
            wireBytes: wire[route],
            heldUnits: oracle[route].units,
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
      expect(ids.size).toBe(2);
      expect(new Set(ids.values()).size).toBe(2);
      expect(nativeFinished.size).toBe(2);
      await expect.poll(() => nativeClosed.size, { timeout }).toBe(2);
      expect(await auditSnapshot(pool)).toEqual(before);
    } catch (error) {
      failures.push(error);
    } finally {
      releaseSettlement.default.release();
      releaseSettlement.explicit.release();
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
      throw new AggregateError(failures, "native certificate tool fixture failed");
    console.info(
      JSON.stringify({
        probe: "native-certificate-tool-delivery",
        protocol: "2026-07-28",
        tools: observations,
        finalAllocationUnits: manager?.accounting.usedUnits,
        networkCleanupComplete: true
      })
    );
  });
}, 120000);
