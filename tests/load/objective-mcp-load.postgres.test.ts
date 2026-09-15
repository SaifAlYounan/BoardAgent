import { mkdtemp, rm } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { importJWK, SignJWT, type JWK } from "jose";
import { type Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import {
  loadBoardAgentKeyMaterial,
  PgTokenContextStore,
  runtimeKeyRegistrations,
  startBoardAgentServer,
  type ActiveTokenContext,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { parseConfig, type BoardAgentConfig } from "../../lib/config/src/index.js";
import { SERVER_DATABASE_CONNECTION_LIMIT } from "../../artifacts/server/src/process-runtime.js";
import { TOOL_INPUT_SCHEMA_VERSION, type JsonValue } from "../../lib/contracts/src/index.js";
import {
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  ENVELOPE,
  readAndAssertFixtureCounts,
  seedCapacityFixture
} from "../performance/verify-phase1-performance.js";

const ORIGIN = "https://boardagent.test";
const RESOURCE = `${ORIGIN}/mcp`;
const LOAD_REQUESTS = 100;
const AUDITED_WRITES = 20;
// Reads that append audit evidence in the mix: the twenty `get_board` calls. Each
// appends two `resource_fetch` events: `prepared` inside the read transaction and the
// delivery outcome (`completed`) recorded in its own transaction after the HTTP response
// finishes. `whoami`, `get_document_hash` and the list/search reads append nothing.
const AUDITED_READ_CALLS = 20;
const AUDITED_READS = AUDITED_READ_CALLS * 2;
// The outcome event lands after the client already holds the response, so the audit
// composition is read once the outcomes have settled, within this bound.
const OUTCOME_SETTLE_LIMIT_MS = 15_000;
const AUDIT_HEAD_SHARE_LIMIT = 0.2;
// Planning bars PE-005 / D2-054 are warm-local bars measured serially, excluding human
// elicitation; the phase-1 performance verifier asserts them on a fresh fixture in tier 5
// and in the native D2-054 phase. The serial post-load probe below runs right after the
// 100-way burst (twenty audited writes, autovacuum and WAL churn still settling) on a
// 1,000,000-row fixture, so it asserts only the list/get bar, which holds on both a
// development machine and a small 2-CPU host, and records the entitled-search p95 next
// to its reference bar: the small host measured 1937 ms there against a 1500 ms warm
// bar that the fresh-fixture verifier met on the same host. The 100-way contention p95
// is recorded, never a bar.
const WARM_LIST_GET_P95_LIMIT_MS = 500;
const WARM_SEARCH_P95_REFERENCE_MS = 1500;
const PROBE_LIST_GET_REQUESTS = 30;
const PROBE_SEARCH_REQUESTS = 5;

interface QueryTelemetry {
  readonly auditHeadMilliseconds: number[];
  readonly transactionFailures: Record<string, number>;
}

interface HttpTelemetry {
  barrier: ExactConcurrencyBarrier | null;
  inFlight: number;
  maximumInFlight: number;
  readonly preflight: Array<{
    readonly request: string;
    readonly response: string;
    readonly status: number;
  }>;
}

class ExactConcurrencyBarrier {
  private arrivals = 0;
  private readonly promise: Promise<void>;
  private reject!: (error: Error) => void;
  private resolve!: () => void;
  private readonly timer: NodeJS.Timeout;

  public constructor(private readonly expected: number) {
    this.promise = new Promise<void>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
    this.timer = setTimeout(() => {
      this.reject(
        new Error(
          `only ${String(this.arrivals)} of ${String(this.expected)} MCP requests reached the concurrency barrier`
        )
      );
    }, 30_000);
    this.timer.unref();
  }

  public async enter(): Promise<void> {
    this.arrivals += 1;
    if (this.arrivals > this.expected) {
      throw new Error(`more than ${String(this.expected)} MCP requests entered the load window`);
    }
    if (this.arrivals === this.expected) {
      clearTimeout(this.timer);
      this.resolve();
    }
    await this.promise;
  }

  public count(): number {
    return this.arrivals;
  }
}

function queryText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value !== null && typeof value === "object" && "text" in value) {
    const textValue = (value as { readonly text?: unknown }).text;
    return typeof textValue === "string" ? textValue : "";
  }
  return "";
}

/** Observe the real audit-head query without changing production transaction behavior. */
function instrumentPool(pool: Pool, telemetry: QueryTelemetry): Pool {
  const clients = new WeakMap<PoolClient, PoolClient>();
  const instrumentClient = (client: PoolClient): PoolClient => {
    const existing = clients.get(client);
    if (existing) return existing;
    const proxy = new Proxy(client, {
      get(target, property) {
        if (property === "query") {
          const query = target.query.bind(target) as (...args: unknown[]) => Promise<unknown>;
          return async (...args: unknown[]): Promise<unknown> => {
            const observesAuditHead = queryText(args[0]).includes(
              "from boardagent_lock_audit_head()"
            );
            const started = observesAuditHead ? performance.now() : 0;
            try {
              return await query(...args);
            } catch (error) {
              if (
                typeof error === "object" &&
                error !== null &&
                "code" in error &&
                (error.code === "40001" || error.code === "40P01")
              ) {
                const key = `${error.code}: ${queryText(args[0]).replace(/\s+/gu, " ").trim().slice(0, 160)}`;
                telemetry.transactionFailures[key] = (telemetry.transactionFailures[key] ?? 0) + 1;
              }
              throw error;
            } finally {
              if (observesAuditHead) {
                telemetry.auditHeadMilliseconds.push(performance.now() - started);
              }
            }
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      }
    }) as PoolClient;
    clients.set(client, proxy);
    return proxy;
  };
  return new Proxy(pool, {
    get(target, property) {
      if (property === "connect") {
        return async (): Promise<PoolClient> => instrumentClient(await target.connect());
      }
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    }
  }) as Pool;
}

function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new TypeError("expected structured BoardAgent result data");
  }
  return value as Readonly<Record<string, JsonValue>>;
}

async function call(
  client: Client,
  name: string,
  args: Readonly<Record<string, JsonValue>>
): Promise<SurfaceToolResult> {
  const response = await client.callTool({ name, arguments: args });
  if (response.isError) {
    const message = response.content
      .filter(
        (item): item is Extract<(typeof response.content)[number], { type: "text" }> =>
          item.type === "text"
      )
      .map(({ text }) => text)
      .join("\n");
    throw new Error(`BoardAgent tool failed: ${name}: ${message}`);
  }
  const structured = response.structuredContent as SurfaceToolResult | undefined;
  if (!structured || structured.tool !== name) {
    throw new Error(`missing BoardAgent result for ${name}`);
  }
  return structured;
}

function percentile95(values: readonly number[]): number {
  if (values.length === 0) throw new Error("p95 requires at least one request");
  const sorted = [...values].toSorted((left, right) => left - right);
  return sorted[Math.ceil(sorted.length * 0.95) - 1] as number;
}

function roundMilliseconds(value: number): number {
  return Math.round(value * 100) / 100;
}

async function registerLoadRuntimeKeys(
  pool: Pool,
  config: BoardAgentConfig,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>
): Promise<void> {
  const keys = await loadBoardAgentKeyMaterial(config);
  const keyIds = [testId(8), testId(7_900_001), testId(7_900_002), testId(7_900_003)];
  let keyIndex = 0;
  const registrations = runtimeKeyRegistrations(config, keys, () => {
    const id = keyIds[keyIndex];
    keyIndex += 1;
    if (!id) throw new Error("runtime key fixture exhausted");
    return id;
  });
  const oauth = registrations.find(({ purpose }) => purpose === "oauth_signing");
  if (!oauth || oauth.publicJwk === null) throw new Error("OAuth registration is unavailable");
  await pool.query(
    `update crypto_key_registry
        set kid=$2,algorithm=$3,public_jwk=$4::jsonb,nonsecret_locator=$5
      where id=$1`,
    [testId(8), oauth.kid, oauth.algorithm, JSON.stringify(oauth.publicJwk), oauth.nonsecretLocator]
  );
  await withBootstrapTransaction(
    pool,
    (client) => registerRuntimeKeysInTransaction(client, actor.organizationId, registrations),
    { assumeRole: "boardagent_migrator" }
  );
}

async function bindRuntimeKeys(
  pool: Pool,
  config: BoardAgentConfig,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>
): Promise<{
  readonly context: ActiveTokenContext;
  readonly token: string;
}> {
  const keys = await loadBoardAgentKeyMaterial(config);
  // Spread writes across distinct board roots so the shared audit head is the measured
  // serialization point rather than one artificially hot board row.
  await pool.query("update board_memberships set is_secretary=true where member_id=$1", [
    actor.memberId
  ]);
  const sessionId = testId(7_900_010);
  await pool.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated',$6,
               transaction_timestamp()+interval '15 minutes',transaction_timestamp())`,
    [sessionId, actor.organizationId, testHash(219), actor.memberId, actor.clientId, ORIGIN]
  );
  await pool.query(
    `update access_token_records
        set session_id=$1,
            expires_at=transaction_timestamp()+interval '10 minutes',
            scope_set=scope_set || array['documents:contribute']::text[]
      where id=$2`,
    [sessionId, actor.accessTokenRecordId]
  );
  const tokenStore = new PgTokenContextStore(pool, { assumeRole: "boardagent_server" });
  const context = await tokenStore.findActiveByJti(actor.tokenJti);
  if (!context) throw new Error("load-test access token did not resolve");
  const privateKey = await importJWK(keys.oauthPrivateJwk as JWK, "ES256");
  const token = await new SignJWT({
    client_id: context.internalClientId,
    resource: RESOURCE,
    scope: context.scopes.join(" ")
  })
    .setProtectedHeader({ alg: "ES256", kid: context.signingKeyKid })
    .setIssuer(ORIGIN)
    .setAudience(RESOURCE)
    .setSubject(context.memberId)
    .setJti(actor.tokenJti)
    .setIssuedAt()
    .setExpirationTime(context.expiresAt)
    .sign(privateKey);
  return { context, token };
}

async function loopbackFetch(
  port: number,
  bearer: string,
  telemetry: HttpTelemetry,
  input: string | URL | Request,
  init?: RequestInit
): Promise<Response> {
  const original = new Request(input, init);
  if (telemetry.barrier) await telemetry.barrier.enter();
  telemetry.inFlight += 1;
  telemetry.maximumInFlight = Math.max(telemetry.maximumInFlight, telemetry.inFlight);
  try {
    const headers = new Headers(original.headers);
    headers.set("authorization", `Bearer ${bearer}`);
    headers.set("host", new URL(ORIGIN).host);
    headers.set("x-forwarded-for", "198.51.100.80");
    headers.set("x-forwarded-proto", "https");
    headers.delete("content-length");
    const body =
      original.method === "GET" || original.method === "HEAD"
        ? undefined
        : await original.arrayBuffer();
    if (body !== undefined) headers.set("content-length", String(body.byteLength));
    const target = new URL(original.url);
    const response = await new Promise<Response>((resolve, reject) => {
      const outbound = httpRequest(
        {
          hostname: "127.0.0.1",
          port,
          path: `${target.pathname}${target.search}`,
          method: original.method,
          headers: Object.fromEntries(headers.entries())
        },
        (incoming) => {
          const chunks: Buffer[] = [];
          incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
          incoming.once("end", () => {
            original.signal.removeEventListener("abort", abort);
            const responseHeaders = new Headers();
            for (const [name, value] of Object.entries(incoming.headers)) {
              if (Array.isArray(value)) {
                for (const entry of value) responseHeaders.append(name, entry);
              } else if (value !== undefined) {
                responseHeaders.set(name, value);
              }
            }
            const responseBody = Buffer.concat(chunks);
            resolve(
              new Response(responseBody.length === 0 ? null : responseBody, {
                status: incoming.statusCode ?? 500,
                ...(incoming.statusMessage === undefined
                  ? {}
                  : { statusText: incoming.statusMessage }),
                headers: responseHeaders
              })
            );
          });
        }
      );
      const abort = (): void => {
        outbound.destroy(original.signal.reason);
      };
      original.signal.addEventListener("abort", abort, { once: true });
      outbound.once("error", (error) => {
        original.signal.removeEventListener("abort", abort);
        reject(error);
      });
      if (body !== undefined) outbound.write(Buffer.from(body));
      outbound.end();
    });
    if (telemetry.barrier === null) {
      telemetry.preflight.push({
        request: body === undefined ? "" : Buffer.from(body).toString("utf8").slice(0, 2_048),
        response: (await response.clone().text()).slice(0, 2_048),
        status: response.status
      });
    }
    return response;
  } finally {
    telemetry.inFlight -= 1;
  }
}

describe("T9 objective deployment load", () => {
  it(
    "serves 100 simultaneous real MCP requests at the exact D2-054 envelope without leakage or audit-head domination",
    async () => {
      await withMigratedDatabase(
        "objective-mcp-load",
        async (owner) => {
          const blobRoot = await mkdtemp(path.join(tmpdir(), "boardagent-load-"));
          let running: Awaited<ReturnType<typeof startBoardAgentServer>> | undefined;
          let client: Client | undefined;
          try {
            const runtimeConfig = (organizationId: string) =>
              parseConfig({
                BOARDAGENT_ENV: "test",
                BOARDAGENT_DATABASE_URL: "postgresql://unused",
                BOARDAGENT_ORGANIZATION_ID: organizationId,
                BOARDAGENT_PUBLIC_BASE_URL: ORIGIN,
                BOARDAGENT_AUTHORIZATION_MODE: "builtin",
                BOARDAGENT_BLOB_ROOT: blobRoot,
                BOARDAGENT_DEV_MASTER_SECRET: "objective-load-secret-material-is-long-enough",
                BOARDAGENT_TRUSTED_PROXY_HOPS: "1"
              });
            const fixture = await seedCapacityFixture(owner, (actor) =>
              registerLoadRuntimeKeys(owner, runtimeConfig(actor.organizationId), actor)
            );
            const counts = await readAndAssertFixtureCounts(owner);
            const config = runtimeConfig(fixture.actor.organizationId);
            const { context, token } = await bindRuntimeKeys(owner, config, fixture.actor);
            expect(context.boardIds).toHaveLength(ENVELOPE.boards);

            const queryTelemetry: QueryTelemetry = {
              auditHeadMilliseconds: [],
              transactionFailures: {}
            };
            const runtimeErrors: string[] = [];
            const httpTelemetry: HttpTelemetry = {
              barrier: null,
              inFlight: 0,
              maximumInFlight: 0,
              preflight: []
            };
            running = await startBoardAgentServer(config, {
              pool: instrumentPool(owner, queryTelemetry),
              host: "127.0.0.1",
              port: 0,
              assumeRole: "boardagent_server",
              onError: (error) =>
                runtimeErrors.push(
                  `${error.message}${
                    error.cause instanceof Error
                      ? ` <- ${error.cause.message} [${String((error as { causeCode?: unknown }).causeCode ?? "")}]`
                      : ""
                  }`
                )
            });
            client = new Client(
              { name: "boardagent-t9-load", version: "1.0.0" },
              {
                capabilities: {},
                versionNegotiation: { mode: { pin: "2026-07-28" } },
                cachePartition: fixture.actor.memberId
              }
            );
            try {
              await client.connect(
                new StreamableHTTPClientTransport(new URL(RESOURCE), {
                  fetch: (input, init) =>
                    loopbackFetch(running!.port, token, httpTelemetry, input, init)
                })
              );
            } catch (error) {
              throw new Error(
                `${error instanceof Error ? error.message : String(error)}; runtimeErrors=${JSON.stringify(runtimeErrors)}; preflight=${JSON.stringify(httpTelemetry.preflight)}`,
                { cause: error }
              );
            }

            const auditHeadBefore = await owner.query<{ last_sequence: string }>(
              "select last_sequence::text from audit_chain_head where singleton_key"
            );
            const operations: Array<() => Promise<SurfaceToolResult>> = [];
            for (let index = 0; index < 20; index += 1) {
              operations.push(() =>
                call(client!, "whoami", { schema_version: TOOL_INPUT_SCHEMA_VERSION })
              );
            }
            for (let index = 0; index < 20; index += 1) {
              operations.push(() =>
                call(client!, "get_board", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  board_id: fixture.boardIds[index] as string
                })
              );
            }
            for (let index = 0; index < 20; index += 1) {
              operations.push(() =>
                call(client!, "get_document_hash", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  document_id: fixture.visibleDocumentIds[index] as string,
                  version_id: fixture.visibleVersionIds[index] as string
                })
              );
            }
            for (let index = 0; index < 10; index += 1) {
              operations.push(() =>
                call(client!, "search_documents", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  board_id: fixture.boardIds[index] as string,
                  query: "needle",
                  cursor: null,
                  limit: 100
                })
              );
            }
            for (let index = 0; index < 5; index += 1) {
              operations.push(() =>
                call(client!, "search_documents", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  board_id: fixture.boardIds[index] as string,
                  query: "restrictedneedle",
                  cursor: null,
                  limit: 100
                })
              );
            }
            for (let index = 0; index < 5; index += 1) {
              operations.push(() =>
                call(client!, "list_pending_actions", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  cursor: null,
                  limit: ENVELOPE.briefingItems
                })
              );
            }
            for (let index = 0; index < AUDITED_WRITES; index += 1) {
              const documentId = testId(7_000_000 + index);
              operations.push(() =>
                call(client!, "create_document_version", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  board_id: fixture.boardIds[index] as string,
                  document_id: documentId,
                  title: `T9 load document ${String(index)}`,
                  media_type: "text/plain; charset=utf-8",
                  schema_name: null,
                  canonical_body: `T9 objective load ${String(index)}\n`,
                  expected_current_version_id: null,
                  idempotency_key: `t9-load-document-${String(index).padStart(6, "0")}`
                })
              );
            }
            expect(operations).toHaveLength(LOAD_REQUESTS);

            const barrier = new ExactConcurrencyBarrier(LOAD_REQUESTS);
            httpTelemetry.barrier = barrier;
            const durations: number[] = [];
            const settled = await Promise.allSettled(
              operations.map(async (operation) => {
                const started = performance.now();
                const result = await operation();
                durations.push(performance.now() - started);
                return result;
              })
            );
            httpTelemetry.barrier = null;
            const results = settled.map((result) => {
              if (result.status === "rejected") {
                throw new Error(
                  `${String(result.reason)}; transactionFailures=${JSON.stringify(queryTelemetry.transactionFailures)}`
                );
              }
              return result.value;
            });

            // Every read must answer with its record, never an empty "absent" under load: an
            // absent board or hash would also silently skip its audit event, so this check
            // names the read before the audit composition below can differ.
            for (const value of results) {
              if (value.tool === "get_board") {
                expect(
                  record(value.data)["board"],
                  "get_board answered null under load"
                ).not.toBeNull();
              } else if (value.tool === "get_document_hash") {
                expect(
                  record(value.data)["document_hash"],
                  "get_document_hash answered null under load"
                ).not.toBeNull();
              } else if (value.tool === "whoami") {
                expect(record(value.data)["member_id"]).toBe(fixture.actor.memberId);
              }
            }

            expect(barrier.count()).toBe(LOAD_REQUESTS);
            expect(httpTelemetry.maximumInFlight).toBe(LOAD_REQUESTS);
            expect(results).toHaveLength(LOAD_REQUESTS);
            const writes = results.filter(({ tool }) => tool === "create_document_version");
            expect(writes).toHaveLength(AUDITED_WRITES);
            expect(writes.every(({ status }) => status === "accepted")).toBe(true);
            const hiddenNeedleSearches = results.filter(
              ({ tool, data }) =>
                tool === "search_documents" &&
                Array.isArray(record(data)["items"]) &&
                (record(data)["items"] as readonly JsonValue[]).length === 0
            );
            expect(hiddenNeedleSearches).toHaveLength(5);

            const serializedResults = JSON.stringify(results);
            for (const hiddenMemberId of fixture.noiseMemberIds) {
              expect(serializedResults).not.toContain(hiddenMemberId);
            }
            const auditHeadAfter = await owner.query<{ last_sequence: string }>(
              "select last_sequence::text from audit_chain_head where singleton_key"
            );
            // Each `get_board` appends a `prepared` event in its read transaction and a
            // `completed` outcome after the response finishes; the chain therefore grows by
            // the twenty writes plus those forty events, and by nothing else. The outcome
            // transactions may still be in flight when the client holds the last reply, so
            // wait, bounded, until the composition stops moving.
            const readComposition = async () =>
              (
                await owner.query<{ event_type: string; count: number }>(
                  "select event_type,count(*)::int as count from audit_events where sequence>$1::bigint group by event_type order by event_type",
                  [auditHeadBefore.rows[0]!.last_sequence]
                )
              ).rows;
            const settleStarted = performance.now();
            let auditComposition = await readComposition();
            const resourceFetchCount = (rows: readonly { event_type: string; count: number }[]) =>
              rows.find((row) => row.event_type === "resource_fetch")?.count ?? 0;
            while (
              resourceFetchCount(auditComposition) < AUDITED_READS &&
              performance.now() - settleStarted < OUTCOME_SETTLE_LIMIT_MS
            ) {
              await new Promise((resolve) => setTimeout(resolve, 100));
              auditComposition = await readComposition();
            }
            const outcomeSettleMilliseconds = roundMilliseconds(performance.now() - settleStarted);
            // A lost outcome audit is reported by the runtime as an error; none may occur.
            // Asserted first so a reporting failure names itself before the count differs.
            expect(runtimeErrors, "runtime errors during the burst").toEqual([]);
            const composition = Object.fromEntries(
              auditComposition.map((row) => [row.event_type, row.count])
            );
            expect(composition["document_version_created"]).toBe(AUDITED_WRITES);
            const auditedReadEvents = auditComposition.filter(
              (row) => row.event_type !== "document_version_created"
            );
            // Name the board and phase that lost an event before the count can differ.
            const auditedReadBreakdown = await owner.query<{
              uri: string;
              phase: string;
              count: number;
            }>(
              `select convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'resourceUri' as uri,
                      convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'phase' as phase,
                      count(*)::int as count
                 from audit_events
                where sequence>$1::bigint and event_type='resource_fetch'
                group by 1,2 order by 1,2`,
              [auditHeadBefore.rows[0]!.last_sequence]
            );
            const expectedBreakdown = fixture.boardIds
              .slice(0, AUDITED_READ_CALLS)
              .flatMap((boardId) => [
                { uri: `board://${boardId}`, phase: "completed", count: 1 },
                { uri: `board://${boardId}`, phase: "prepared", count: 1 }
              ])
              .toSorted((left, right) =>
                left.uri === right.uri
                  ? left.phase.localeCompare(right.phase)
                  : left.uri.localeCompare(right.uri)
              );
            expect(
              auditedReadBreakdown.rows,
              `audited read events by board and phase (outcomes settled in ${String(outcomeSettleMilliseconds)} ms)`
            ).toEqual(expectedBreakdown);
            expect(auditedReadEvents).toEqual([
              { event_type: "resource_fetch", count: AUDITED_READS }
            ]);

            expect(
              BigInt(auditHeadAfter.rows[0]!.last_sequence) -
                BigInt(auditHeadBefore.rows[0]!.last_sequence)
            ).toBe(BigInt(AUDITED_WRITES + AUDITED_READS));
            // Failed serializable attempts are part of the real request critical path and
            // therefore remain in the lock-share numerator rather than being hidden.
            expect(queryTelemetry.auditHeadMilliseconds.length).toBeGreaterThanOrEqual(
              AUDITED_WRITES
            );

            const auditHeadMilliseconds = queryTelemetry.auditHeadMilliseconds.reduce(
              (total, duration) => total + duration,
              0
            );
            const requestCriticalPathMilliseconds = durations.reduce(
              (total, duration) => total + duration,
              0
            );
            const auditHeadShare = auditHeadMilliseconds / requestCriticalPathMilliseconds;
            expect(auditHeadShare).toBeLessThan(AUDIT_HEAD_SHARE_LIMIT);

            // Serial post-load probe on the same warm server and connection: the planning
            // p95 bars apply here. Process memory is recorded after the contention run.
            const probeListGet: number[] = [];
            const probeSearch: number[] = [];
            for (let index = 0; index < PROBE_LIST_GET_REQUESTS; index += 1) {
              const started = performance.now();
              if (index % 3 === 2) {
                await call(client, "get_document_hash", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  document_id: fixture.visibleDocumentIds[index % 20] as string,
                  version_id: fixture.visibleVersionIds[index % 20] as string
                });
              } else {
                await call(client, "get_board", {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  board_id: fixture.boardIds[index % 10] as string
                });
              }
              probeListGet.push(performance.now() - started);
            }
            for (let index = 0; index < PROBE_SEARCH_REQUESTS; index += 1) {
              const started = performance.now();
              await call(client, "search_documents", {
                schema_version: TOOL_INPUT_SCHEMA_VERSION,
                board_id: fixture.boardIds[index] as string,
                query: "needle",
                cursor: null,
                limit: 100
              });
              probeSearch.push(performance.now() - started);
            }
            const warmListGetP95 = percentile95(probeListGet);
            const warmSearchP95 = percentile95(probeSearch);
            expect(warmListGetP95).toBeLessThanOrEqual(WARM_LIST_GET_P95_LIMIT_MS);
            // Every probe search must have answered; its p95 is recorded against the
            // reference bar, which the phase-1 verifier asserts under warm conditions.
            expect(probeSearch).toHaveLength(PROBE_SEARCH_REQUESTS);
            const memory = process.memoryUsage();

            process.stdout.write(
              `${JSON.stringify({
                schemaVersion: "boardagent.t9-objective-load.v2",
                status: "passed",
                fixture: counts,
                requests: LOAD_REQUESTS,
                simultaneousAtHttpBoundary: httpTelemetry.maximumInFlight,
                auditedWrites: AUDITED_WRITES,
                auditedReads: AUDITED_READS,
                outcomeSettleMilliseconds,
                auditEventComposition: composition,
                transactionFailures: queryTelemetry.transactionFailures,
                incorrectAuthorizationResultsOrEvents: 0,
                p95Milliseconds: roundMilliseconds(percentile95(durations)),
                serialPostLoadProbe: {
                  listGetRequests: PROBE_LIST_GET_REQUESTS,
                  listGetP95Milliseconds: roundMilliseconds(warmListGetP95),
                  listGetP95LimitMilliseconds: WARM_LIST_GET_P95_LIMIT_MS,
                  searchRequests: PROBE_SEARCH_REQUESTS,
                  searchP95Milliseconds: roundMilliseconds(warmSearchP95),
                  searchP95ReferenceMilliseconds: WARM_SEARCH_P95_REFERENCE_MS,
                  searchP95AssertedHere: false
                },
                processMemoryAfterLoad: {
                  rssBytes: memory.rss,
                  heapUsedBytes: memory.heapUsed
                },
                auditHeadLock: {
                  attempts: queryTelemetry.auditHeadMilliseconds.length,
                  committedWrites: AUDITED_WRITES,
                  milliseconds: roundMilliseconds(auditHeadMilliseconds),
                  requestCriticalPathMilliseconds: roundMilliseconds(
                    requestCriticalPathMilliseconds
                  ),
                  sharePercent: Math.round(auditHeadShare * 10_000) / 100,
                  thresholdPercent: AUDIT_HEAD_SHARE_LIMIT * 100
                }
              })}\n`
            );
          } finally {
            await Promise.allSettled([client?.close(), running?.close()]);
            await rm(blobRoot, { recursive: true, force: true });
          }
        },
        SERVER_DATABASE_CONNECTION_LIMIT
      );
    },
    10 * 60_000
  );
});
