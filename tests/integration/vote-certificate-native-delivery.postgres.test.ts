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
  currentResourceDeliveryCollector,
  type PreparedResourceDelivery,
  type ResourceDeliveryOutcome
} from "../../artifacts/server/src/resource-delivery.js";
import {
  ResponseAllocationManager,
  currentResponseAllocationOwner,
  type ResponseAllocationOwner
} from "../../artifacts/server/src/response-allocation.js";
import {
  VOTE_PROJECTION_PREFLIGHT_SQL,
  voteProjectionPlan,
  type VoteProjectionMetadata
} from "../../artifacts/server/src/vote-projection-resource.js";
import {
  CERTIFICATE_PROJECTION_PREFLIGHT_SQL,
  certificateProjectionPlan,
  type CertificateProjectionMetadata
} from "../../artifacts/server/src/certificate-projection-resource.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { eventHash, type AuditEventBody } from "../../lib/audit/src/event.js";
import { verifyOfflineCertificateBundle } from "../../lib/audit/src/offline.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedVoteProjectionFixture } from "../helpers/vote-projection-fixture.js";
import { seedCertificateProjectionFixture } from "../helpers/certificate-projection-fixture.js";
import { ORIGINAL_VOTE_RESOURCE_SQL } from "../helpers/vote-resource-original-sql.js";
import { ORIGINAL_CERTIFICATE_RESOURCE_SQL } from "../helpers/certificate-resource-original-sql.js";

const tls = {
  key: readFileSync(new URL("../fixtures/tls/released-client-matrix.key", import.meta.url)),
  cert: readFileSync(new URL("../fixtures/tls/released-client-matrix.crt", import.meta.url))
};
const origin = "https://boardagent.test",
  resource = new URL("/mcp", origin),
  token = "synthetic-vote-certificate-native-token";
const timeout = 10000;
type Route = "vote" | "certificate";
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function gate() {
  let release!: () => void;
  let open = false;
  const promise = new Promise<void>((r) => {
    release = r;
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
interface AuditRow {
  id: string;
  sequence: string;
  event_hash: string;
  previous_hash: string;
  canonical_hex: string;
  body: AuditEventBody;
}
async function auditSnapshot(pool: Pool): Promise<AuditRow[]> {
  return (
    await pool.query<AuditRow>(
      `select id,sequence::text,encode(event_sha256,'hex') as event_hash,encode(previous_event_sha256,'hex') as previous_hash,
    encode(canonical_payload,'hex') as canonical_hex,convert_from(canonical_payload,'UTF8')::jsonb as body
    from audit_events order by sequence`
    )
  ).rows;
}

it("delivers exact vote and signed certificate resources through native HTTPS SDK and settled PostgreSQL audits", async () => {
  await withMigratedDatabase("vote_cert_native", async (pool) => {
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
    const uris = {
      vote: `board://${actor.boardId}/votes/${vote.voteId}`,
      certificate: `board://${actor.boardId}/votes/${vote.voteId}/certificates/${signed.certificateId}`
    };
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const v = await client.query<{ payload: JsonValue }>(ORIGINAL_VOTE_RESOURCE_SQL, [
          actor.boardId,
          vote.voteId
        ]);
        const c = await client.query<{ payload: JsonValue }>(ORIGINAL_CERTIFICATE_RESOURCE_SQL, [
          actor.boardId,
          vote.voteId,
          signed.certificateId
        ]);
        const vm = await client.query<VoteProjectionMetadata>(VOTE_PROJECTION_PREFLIGHT_SQL, [
          actor.boardId,
          vote.voteId
        ]);
        const cm = await client.query<CertificateProjectionMetadata>(
          CERTIFICATE_PROJECTION_PREFLIGHT_SQL,
          [actor.boardId, vote.voteId, signed.certificateId]
        );
        expect(v.rows).toHaveLength(1);
        expect(c.rows).toHaveLength(1);
        expect(vm.rows).toHaveLength(1);
        expect(cm.rows).toHaveLength(1);
        return {
          bytes: {
            vote: Buffer.from(canonicalJson(v.rows[0]!.payload)),
            certificate: Buffer.from(canonicalJson(c.rows[0]!.payload))
          },
          units: {
            vote: voteProjectionPlan(vm.rows[0]!).units,
            certificate: certificateProjectionPlan(cm.rows[0]!).units
          },
          versions: { vote: vm.rows[0]!.row_version, certificate: "1" }
        };
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
    const entered = { vote: gate(), certificate: gate() },
      releaseAudit = { vote: gate(), certificate: gate() };
    const requests = new Set<ClientRequest>(),
      nativeFinished = new Set<Route>(),
      nativeClosed = new Set<Route>();
    const owners = new Map<Route, ResponseAllocationOwner>(),
      collectors = new Map<Route, ResourceDeliveryCollector>();
    const ids = new Map<Route, string | number>(),
      preparedIds = new Map<Route, string>();
    const registrationKinds = { vote: new Set<string>(), certificate: new Set<string>() };
    const calls = new Map<Route, ResourceDeliveryOutcome[]>(),
      committed = new Map<Route, ResourceDeliveryOutcome[]>();
    const wire = { vote: 0, certificate: 0 },
      media = { vote: "", certificate: "" },
      heldUnits = { vote: 0, certificate: 0 };
    const observations: unknown[] = [];
    const failures: unknown[] = [],
      serverErrors: Error[] = [],
      pending: Array<Promise<unknown>> = [];
    let manager: ResponseAllocationManager | undefined, client: Client | undefined;
    let closeRuntime: (() => Promise<void>) | undefined;
    let handler: RequestListener = (_request, response) => response.writeHead(503).end();
    const server = createServer(tls, (request, response) => {
      const route = request.headers["x-vote-certificate-fixture"];
      if (route === "vote" || route === "certificate") {
        response.once("finish", () => nativeFinished.add(route));
        response.once("close", () => nativeClosed.add(route));
      }
      handler(request, response);
    });
    const seenManagers = new Set<ResponseAllocationManager>();
    const originalOpen = ResponseAllocationManager.prototype.openRequest;
    const openSpy = vi
      .spyOn(ResponseAllocationManager.prototype, "openRequest")
      .mockImplementation(function (this: ResponseAllocationManager, signal) {
        seenManagers.add(this);
        return originalOpen.call(this, signal);
      });
    const originalRegister = ResourceDeliveryCollector.prototype.register;
    const wrapped = new WeakMap<PreparedResourceDelivery, PreparedResourceDelivery>();
    const registerSpy = vi
      .spyOn(ResourceDeliveryCollector.prototype, "register")
      .mockImplementation(function (
        this: ResourceDeliveryCollector,
        prepared,
        requestId,
        expectedResult
      ) {
        // The runtime first registers the prepared handle without a result,
        // then associates the validated response. Identify both phases by the
        // actual per-request collector and preserve the original handle.
        const route = (["vote", "certificate"] as const).find(
          (candidate) => collectors.get(candidate) === this
        );
        if (!route) throw new Error("unexpected native prepared resource collector");
        expect(requestId).toBe(ids.get(route));
        if (expectedResult === null) {
          registrationKinds[route].add("prepared");
        } else {
          const contents = expectedResult["contents"];
          const first = Array.isArray(contents) ? contents[0] : undefined;
          expect(object(first) ? first["uri"] : undefined).toBe(uris[route]);
          registrationKinds[route].add("response");
        }
        preparedIds.set(route, prepared.preparedEventId);
        let delegated = wrapped.get(prepared);
        if (!delegated) {
          delegated = {
            ...prepared,
            record: async (outcome) => {
              const seen = calls.get(route) ?? [];
              seen.push(outcome);
              calls.set(route, seen);
              entered[route].release();
              await releaseAudit[route].promise;
              await prepared.record(outcome);
              const done = committed.get(route) ?? [];
              done.push(outcome);
              committed.set(route, done);
            }
          };
          wrapped.set(prepared, delegated);
        }
        return originalRegister.call(this, delegated, requestId, expectedResult);
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
        executeRead: unsupported,
        executeDirect: unsupported,
        prepareHumanAction: unsupported,
        persistHumanStage: unsupported,
        resolveHumanAction: unsupported,
        readResource: async (principal, uri) => {
          const route: Route | undefined =
            uri.href === uris.vote
              ? "vote"
              : uri.href === uris.certificate
                ? "certificate"
                : undefined;
          if (!route) throw new Error("unexpected resource URI");
          const owner = currentResponseAllocationOwner(),
            collector = currentResourceDeliveryCollector();
          if (!owner || !collector)
            throw new Error("actual native allocation owner and collector required");
          owners.set(route, owner);
          collectors.set(route, collector);
          expect(principal.serviceOrigin).toBe(origin);
          expect(principal.tokenJti).toBe(actor.tokenJti);
          return repository.readResource(principal, uri);
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
          uri = object(params) ? params["uri"] : undefined;
        const route: Route | undefined =
          uri === uris.vote ? "vote" : uri === uris.certificate ? "certificate" : undefined;
        if (route) {
          if (
            !object(parsed) ||
            parsed["method"] !== "resources/read" ||
            !(typeof parsed["id"] === "string" || typeof parsed["id"] === "number")
          )
            throw new Error("uncorrelated resource request");
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
                ...(route ? { "x-vote-certificate-fixture": route } : {})
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
        { name: "vote-certificate-native-fixture", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: "vote-certificate-native-fixture"
        }
      );
      await client.connect(new StreamableHTTPClientTransport(resource, { fetch: transportFetch }), {
        timeout
      });
      expect(seenManagers.size).toBe(1);
      manager = seenManagers.values().next().value;
      expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      expect(client.getProtocolEra()).toBe("modern");
      await expect.poll(() => manager?.accounting.usedUnits, { timeout }).toBe(0);
      const before = await auditSnapshot(pool);
      for (const route of ["vote", "certificate"] as const) {
        const received = capture(
          client.readResource({ uri: uris[route] }, { timeout, maxTotalTimeout: timeout })
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
          // HTTP finish is not used as the SDK reply assertion: collect and
          // validate the actual Client.readResource result independently.
          const reply = await received;
          if (!reply.ok) throw reply.error;
          expect(reply.value?.contents).toHaveLength(1);
          const content = reply.value!.contents[0]!;
          expect(content).toMatchObject({
            uri: uris[route],
            mimeType: "application/json",
            text: oracle.bytes[route].toString("utf8")
          });
          expect("text" in content).toBe(true);
          if (!("text" in content) || typeof content.text !== "string")
            throw new Error("expected exact text resource");
          expect(Buffer.from(content.text, "utf8")).toEqual(oracle.bytes[route]);
          if (route === "certificate")
            expect(verifyOfflineCertificateBundle(JSON.parse(content.text), signed.trust)).toBe(
              true
            );
          expect(media[route]).toContain("application/json");
          expect(wire[route]).toBeGreaterThan(oracle.bytes[route].length);
          expect(manager?.accounting.usedUnits).toBe(oracle.units[route]);
          heldUnits[route] = manager!.accounting.usedUnits;
          expect(registrationKinds[route]).toEqual(new Set(["prepared", "response"]));
          expect(calls.get(route)).toHaveLength(1);
          expect(committed.get(route) ?? []).toEqual([]);
          expect(calls.get(route)![0]).toMatchObject({
            outcome: "completed",
            bytesTransferred: oracle.bytes[route].length,
            observationBasis: "node_response_finish",
            responseBytesQueued: wire[route]
          });
          const during = await auditSnapshot(pool),
            matching = during.filter(
              (row) =>
                row.body.eventType === "resource_fetch" &&
                row.body.entityId === (route === "vote" ? vote.voteId : signed.certificateId)
            );
          expect(matching).toHaveLength(1);
          expect(matching[0]!.id).toBe(preparedIds.get(route));
          expect(matching[0]!.body.details["phase"]).toBe("prepared");
          releaseAudit[route].release();
          await expect.poll(() => committed.get(route)?.length ?? 0, { timeout }).toBe(1);
          await expect.poll(() => manager?.accounting.usedUnits, { timeout }).toBe(0);
          expect(committed.get(route)).toEqual(calls.get(route));
        } finally {
          releaseAudit[route].release();
          await received;
        }
      }
      const after = await auditSnapshot(pool),
        byId = new Map(after.map((row) => [row.id, row]));
      for (const row of before) expect(byId.get(row.id)).toEqual(row);
      for (const route of ["vote", "certificate"] as const) {
        const rows = after.filter(
          (row) =>
            row.body.eventType === "resource_fetch" &&
            row.body.entityId === (route === "vote" ? vote.voteId : signed.certificateId)
        );
        expect(rows).toHaveLength(2);
        const prepared = rows.find((row) => row.body.details["phase"] === "prepared")!;
        const completed = rows.find((row) => row.body.details["phase"] === "completed")!;
        expect(prepared).toBeDefined();
        expect(completed).toBeDefined();
        for (const row of rows) {
          expect(eventHash(BigInt(row.sequence), row.previous_hash, row.body)).toBe(row.event_hash);
          expect(row.body).toMatchObject({
            actorMemberId: actor.memberId,
            actorClientId: actor.clientId,
            tokenJti: actor.tokenJti,
            boardId: actor.boardId,
            entityType: route === "vote" ? "vote" : "vote_certificate",
            origin: "mcp",
            details: {
              resourceUri: uris[route],
              sha256: sha256Hex(oracle.bytes[route]),
              byteLength: oracle.bytes[route].length,
              requestOrigin: origin,
              representation: "application/json",
              version: oracle.versions[route]
            }
          });
        }
        expect(completed.body.details).toMatchObject({
          preparedEventId: prepared.id,
          preparedEventHash: prepared.event_hash,
          observationBasis: "node_response_finish",
          bytesTransferred: oracle.bytes[route].length,
          responseBytesQueued: wire[route]
        });
        observations.push({
          route,
          uri: uris[route],
          requestId: ids.get(route),
          canonicalSha256: sha256Hex(oracle.bytes[route]),
          canonicalBytes: oracle.bytes[route].length,
          wireBytes: wire[route],
          heldUnits: heldUnits[route],
          sdkReplyCollected: true,
          nativeFinished: nativeFinished.has(route),
          preparedEventId: prepared.id,
          preparedEventHash: prepared.event_hash,
          completedEventId: completed.id,
          completedEventHash: completed.event_hash,
          outcome: completed.body.details
        });
      }
      expect(nativeFinished.size).toBe(2);
      await expect.poll(() => nativeClosed.size, { timeout }).toBe(2);
    } catch (error) {
      failures.push(error);
    } finally {
      releaseAudit.vote.release();
      releaseAudit.certificate.release();
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
      registerSpy.mockRestore();
      openSpy.mockRestore();
      if (serverErrors.length)
        failures.push(new AggregateError(serverErrors, "native server errors"));
    }
    if (failures.length)
      throw new AggregateError(failures, "native vote/certificate fixture failed");
    console.info(
      JSON.stringify({
        probe: "native-vote-certificate-delivery",
        protocol: "2026-07-28",
        resources: observations,
        finalAllocationUnits: manager?.accounting.usedUnits,
        networkCleanupComplete: true
      })
    );
  });
}, 120000);
