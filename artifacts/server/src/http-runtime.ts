import { once } from "node:events";
import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";

import type { McpHttpHandler } from "@modelcontextprotocol/server";
import { z } from "zod";

import { ResourceDeliveryCollector } from "./resource-delivery.js";
import { ResponseAllocationManager } from "./response-allocation.js";
import { AuthRequestBoundary } from "./auth-page.js";
import type { BoardAgentOAuthProvider } from "./oauth-authorization-server.js";

// A canonical 10 MiB source may use six wire bytes per ASCII character (\\uXXXX).
// Keep one MiB for the JSON-RPC envelope; stored-content limits remain independent.
const MAX_MCP_REQUEST_BYTES = 6 * 10_485_760 + 1_048_576;
const MAX_PUBLIC_REQUEST_BYTES = 1_048_576;
// The budget covers retained wire bodies across reads and in-flight dispatches.
// It is not an RSS bound: JSON decoding and application objects also consume memory.
const MAX_IN_FLIGHT_BODY_BYTES = 64 * 1_048_576;
// Bound admitted native MCP dispatches before body decoding, authentication, and
// per-request SDK construction. This is independent of body/response allocation
// accounting and leaves room beyond the supported 100 concurrent requests.
const MAX_IN_FLIGHT_MCP_REQUESTS = 128;
// Reject before dispatch, then drain only a bounded amount of already arriving input.
// This is discarded stream data, not additional accepted or retained body capacity.
const MAX_REJECTED_BODY_DISCARD_BYTES = 2 * 1_048_576;
const REJECTED_BODY_DISCARD_MILLISECONDS = 250;
const HSTS_VALUE = "max-age=63072000; includeSubDomains";

class BodyCapacityError extends Error {}

export const PUBLIC_CERTIFICATE_VERIFICATION_SCHEMA_VERSION =
  "boardagent.public-certificate-verification.v1";

const PublicCertificateVerificationRequestSchema = z.union([
  z
    .object({
      schema_version: z.literal(PUBLIC_CERTIFICATE_VERIFICATION_SCHEMA_VERSION),
      public_id: z.string().regex(/^[A-Za-z0-9_-]{43}$/u)
    })
    .strict(),
  z
    .object({
      schema_version: z.literal(PUBLIC_CERTIFICATE_VERIFICATION_SCHEMA_VERSION),
      bundle: z.unknown()
    })
    .strict()
]);

export const BOARDAGENT_OAUTH_SCOPES = [
  "audit:read",
  "documents:contribute",
  "documents:read",
  "governance:read",
  "management:question",
  "meeting:act",
  "member:propose",
  "minutes:act",
  "notifications:manage",
  "onboarding:read",
  "proxy:manage",
  "secretariat:admin",
  "secretariat:message",
  "task:act",
  "vote:act"
] as const;

export interface BoardAgentReadiness {
  check(): Promise<{ readonly ready: true } | { readonly ready: false; readonly reason: string }>;
}

export interface BoardAgentPublicCertificateVerifier {
  verify(input: {
    readonly candidatePublicId: string | null;
    readonly candidateBundle: unknown | null;
    readonly clientIpClass: string;
  }): Promise<
    | { readonly status: "complete"; readonly valid: boolean }
    | { readonly status: "rate_limited"; readonly retryAfterSeconds: number }
  >;
}

export interface BoardAgentHttpRuntimeOptions {
  readonly canonicalOrigin: string;
  readonly resourceUri: string;
  readonly boundary: AuthRequestBoundary;
  readonly mcp: Pick<McpHttpHandler, "fetch" | "close">;
  readonly oauth: Pick<BoardAgentOAuthProvider, "callback">;
  readonly interaction: RequestListener;
  readonly enrollment: RequestListener;
  readonly recovery?: RequestListener;
  readonly onboarding: RequestListener;
  readonly readiness: BoardAgentReadiness;
  readonly publicCertificateVerifier: BoardAgentPublicCertificateVerifier;
  readonly includeHsts: boolean;
  readonly onError?: (error: Error) => void;
}

function singleHeader(request: IncomingMessage, name: string): string | undefined {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      values.push(request.rawHeaders[index + 1] ?? "");
    }
  }
  const header = request.headers[name];
  if (values.length > 1 || Array.isArray(header)) throw new Error("ambiguous HTTP header");
  return values[0] ?? header;
}

function pathOf(request: IncomingMessage): string {
  const raw = request.url ?? "";
  if (!raw.startsWith("/") || raw.startsWith("//")) throw new Error("invalid request target");
  return new URL(raw, "https://boardagent.invalid").pathname;
}

function writeJsonHeaders(
  response: ServerResponse,
  status: number,
  includeHsts: boolean,
  extraHeaders: Readonly<Record<string, string>>
): boolean {
  if (response.headersSent || response.destroyed) {
    response.destroy();
    return false;
  }
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    pragma: "no-cache",
    "x-content-type-options": "nosniff",
    ...(includeHsts ? { "strict-transport-security": HSTS_VALUE } : {}),
    ...extraHeaders
  });
  return true;
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: Readonly<Record<string, unknown>>,
  includeHsts: boolean,
  extraHeaders: Readonly<Record<string, string>> = {}
): void {
  if (writeJsonHeaders(response, status, includeHsts, extraHeaders))
    response.end(JSON.stringify(body));
}

async function discardRejectedBody(
  request: IncomingMessage,
  response: ServerResponse
): Promise<void> {
  if (request.readableEnded || request.destroyed || response.destroyed) return;
  await new Promise<void>((resolve) => {
    let remaining = MAX_REJECTED_BODY_DISCARD_BYTES;
    let finished = false;
    const finish = (): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      request.off("readable", read);
      request.off("end", finish);
      request.off("close", finish);
      request.off("error", finish);
      response.off("close", finish);
      request.pause();
      resolve();
    };
    const read = (): void => {
      try {
        while (!finished && remaining > 0) {
          // Pull only the remaining allowance; never retain chunks or resume an
          // unlimited flowing stream. IncomingMessage has its native byte encoding.
          const chunk: unknown = request.read(Math.min(65_536, remaining));
          if (chunk === null) break;
          if (!Buffer.isBuffer(chunk)) {
            finish();
            return;
          }
          remaining -= chunk.byteLength;
        }
        if (remaining === 0 || (request.complete && request.readableLength === 0)) finish();
      } catch {
        // This request is already rejected. A broken input ends cleanup, never dispatches.
        finish();
      }
    };
    const timer = setTimeout(finish, REJECTED_BODY_DISCARD_MILLISECONDS);
    timer.unref();
    request.on("readable", read);
    request.once("end", finish);
    request.once("close", finish);
    request.once("error", finish);
    response.once("close", finish);
    read();
  });
}

async function rejectJson(
  request: IncomingMessage,
  response: ServerResponse,
  status: number,
  body: Readonly<Record<string, unknown>>,
  includeHsts: boolean,
  extraHeaders: Readonly<Record<string, string>> = {}
): Promise<void> {
  const serialized = JSON.stringify(body);
  if (
    !writeJsonHeaders(response, status, includeHsts, {
      ...extraHeaders,
      connection: "close",
      "content-length": String(Buffer.byteLength(serialized))
    })
  )
    return;
  // Writing sends the complete length-delimited rejection immediately. Ending the
  // connection while a small rejected upload is still arriving races client writes.
  response.write(serialized);
  await discardRejectedBody(request, response);
  response.end();
}

async function boundedBody(
  request: IncomingMessage,
  maximumBytes: number,
  account: (bytes: number) => void
): Promise<Uint8Array | undefined> {
  if (request.method === "GET" || request.method === "HEAD") return undefined;
  if (singleHeader(request, "content-encoding") !== undefined) {
    throw new Error("encoded request bodies are unsupported");
  }
  const contentLength = singleHeader(request, "content-length");
  if (contentLength !== undefined) {
    if (!/^(?:0|[1-9]\d*)$/u.test(contentLength)) throw new Error("invalid content length");
    if (Number(contentLength) > maximumBytes) throw new RangeError("request too large");
    // Reserve declared bodies before reading. Chunked bodies reserve incrementally.
    account(Number(contentLength));
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunkValue of request.iterator({ destroyOnReturn: false })) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    length += chunk.length;
    if (length > maximumBytes) throw new RangeError("request too large");
    if (contentLength === undefined) account(chunk.length);
    chunks.push(chunk);
  }
  if (contentLength !== undefined && Number(contentLength) !== length) {
    throw new Error("content length mismatch");
  }
  return length === 0 ? undefined : Buffer.concat(chunks, length);
}

export async function writeWebResponse(
  response: ServerResponse,
  web: Response,
  includeHsts: boolean,
  observe?: (
    outcome: "completed" | "interrupted",
    responseBytesQueued: number,
    responseWriteAttempted: boolean
  ) => void
): Promise<void> {
  const headers: Record<string, string> = {};
  web.headers.forEach((value, name) => {
    headers[name] = value;
  });
  delete headers["strict-transport-security"];
  const setCookies = (web.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie?.();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const drainController = new AbortController();
  let responseBytesQueued = 0;
  let responseWriteAttempted = false;
  let endRequested = false;
  let failure: Error | undefined;
  let terminalOutcome: "completed" | "interrupted" | undefined;
  let resolveTerminal: () => void = () => undefined;
  const terminal = new Promise<void>((resolve) => {
    resolveTerminal = resolve;
  });
  const settle = (outcome: "completed" | "interrupted", error?: Error): void => {
    if (terminalOutcome !== undefined) return;
    terminalOutcome = outcome;
    failure = error;
    if (outcome === "interrupted") {
      drainController.abort(error);
      void reader?.cancel(error).catch(() => undefined);
    }
    resolveTerminal();
  };
  const finish = (): void =>
    endRequested
      ? settle("completed")
      : settle("interrupted", new Error("downstream response finished before source completion"));
  const close = (): void => settle("interrupted", new Error("downstream connection closed"));
  const error = (cause: Error): void => settle("interrupted", cause);
  response.once("finish", finish);
  response.once("close", close);
  response.once("error", error);
  try {
    reader = web.body?.getReader();
    if (response.destroyed) close();
    else if (response.writableEnded || response.writableFinished) finish();
    drainController.signal.throwIfAborted();
    response.writeHead(web.status, {
      ...headers,
      ...(includeHsts ? { "strict-transport-security": HSTS_VALUE } : {}),
      ...(setCookies && setCookies.length > 0 ? { "set-cookie": setCookies } : {})
    });
    if (reader) {
      for (;;) {
        const next = await reader.read();
        drainController.signal.throwIfAborted();
        if (next.done) break;
        responseWriteAttempted = true;
        const canContinue = response.write(next.value);
        responseBytesQueued += next.value.byteLength;
        drainController.signal.throwIfAborted();
        if (!canContinue) {
          await once(response, "drain", { signal: drainController.signal });
        }
      }
    }
    endRequested = true;
    response.end();
    await terminal;
    if (failure) throw failure;
  } catch (cause) {
    const observedFailure = failure;
    settle("interrupted", cause instanceof Error ? cause : new Error("response write failed"));
    throw observedFailure ?? cause;
  } finally {
    response.off("finish", finish);
    response.off("close", close);
    response.off("error", error);
    reader?.releaseLock();
    observe?.(terminalOutcome ?? "interrupted", responseBytesQueued, responseWriteAttempted);
  }
}

async function handleMcp(
  request: IncomingMessage,
  response: ServerResponse,
  options: BoardAgentHttpRuntimeOptions,
  admission: ResponseAllocationManager,
  account: (bytes: number) => void
): Promise<void> {
  if (request.method !== "POST") {
    sendJson(response, 405, { error: "method_not_allowed" }, options.includeHsts, {
      allow: "POST"
    });
    return;
  }
  const body = await boundedBody(request, MAX_MCP_REQUEST_BYTES, account);
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined || name.startsWith(":")) continue;
    if (Array.isArray(value)) value.forEach((entry) => headers.append(name, entry));
    else headers.set(name, value);
  }
  headers.delete("content-encoding");
  headers.delete("transfer-encoding");
  if (body === undefined) headers.delete("content-length");
  else headers.set("content-length", String(body.byteLength));
  const controller = new AbortController();
  const abort = (): void => controller.abort(new Error("MCP client disconnected"));
  request.once("aborted", abort);
  response.once("close", abort);
  const owner = admission.openRequest(controller.signal);
  const collector = new ResourceDeliveryCollector(owner);
  let deliveryOutcome: "completed" | "interrupted" = "interrupted";
  let responseBytesQueued = 0;
  let responseWriteAttempted = false;
  try {
    const target = new URL(request.url ?? "/mcp", `${options.canonicalOrigin}/`);
    const webRequest = new Request(target, {
      method: "POST",
      headers,
      signal: controller.signal,
      ...(body === undefined
        ? {}
        : { body: new TextDecoder("utf-8", { fatal: true }).decode(body) })
    });
    const web = await collector.run(() => owner.run(() => options.mcp.fetch(webRequest)));
    collector.acceptResponse(web);
    await writeWebResponse(response, web, options.includeHsts, (outcome, bytes, attempted) => {
      deliveryOutcome = outcome;
      responseBytesQueued = bytes;
      responseWriteAttempted = attempted;
    });
  } finally {
    request.off("aborted", abort);
    response.off("close", abort);
    owner.nativeTerminal();
    const failures = await collector.settle(
      deliveryOutcome,
      responseBytesQueued,
      responseWriteAttempted
    );
    for (const failure of failures) {
      try {
        // The cause names the database or transaction reason (a lock timeout, a pool
        // failure, a refused evidence match); it never carries request content.
        options.onError?.(
          Object.assign(
            new Error("resource delivery outcome audit unavailable", { cause: failure }),
            {
              code: "resource_delivery_outcome_audit_unavailable",
              causeCode:
                typeof failure === "object" && failure !== null && "code" in failure
                  ? String((failure as { code: unknown }).code)
                  : null
            }
          )
        );
      } catch {
        /* Reporting cannot replay an audit or alter a finished response. */
      }
    }
  }
}

async function handlePublicCertificateVerification(
  request: IncomingMessage,
  response: ServerResponse,
  options: BoardAgentHttpRuntimeOptions,
  clientIpClass: string,
  account: (bytes: number) => void
): Promise<void> {
  if (request.method !== "POST") {
    sendJson(response, 405, { error: "method_not_allowed" }, options.includeHsts, {
      allow: "POST"
    });
    return;
  }
  let candidatePublicId: string | null = null;
  let candidateBundle: unknown | null = null;
  try {
    const body = await boundedBody(request, MAX_PUBLIC_REQUEST_BYTES, account);
    if (singleHeader(request, "content-type") !== "application/json" || body === undefined) {
      throw new Error("invalid public certificate request");
    }
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(body);
    const parsed = PublicCertificateVerificationRequestSchema.parse(JSON.parse(decoded) as unknown);
    if ("public_id" in parsed) candidatePublicId = parsed.public_id;
    else candidateBundle = parsed.bundle;
  } catch (error) {
    if (error instanceof RangeError || error instanceof BodyCapacityError) throw error;
  }
  const verdict = await options.publicCertificateVerifier.verify({
    candidatePublicId,
    candidateBundle,
    clientIpClass
  });
  if (verdict.status === "rate_limited") {
    sendJson(
      response,
      429,
      { schema_version: PUBLIC_CERTIFICATE_VERIFICATION_SCHEMA_VERSION, valid: false },
      options.includeHsts,
      { "retry-after": String(verdict.retryAfterSeconds) }
    );
    return;
  }
  sendJson(
    response,
    200,
    { schema_version: PUBLIC_CERTIFICATE_VERIFICATION_SCHEMA_VERSION, valid: verdict.valid },
    options.includeHsts
  );
}

function metadata(options: BoardAgentHttpRuntimeOptions): Readonly<Record<string, unknown>> {
  return {
    resource: options.resourceUri,
    authorization_servers: [options.canonicalOrigin],
    scopes_supported: BOARDAGENT_OAUTH_SCOPES,
    bearer_methods_supported: ["header"]
  };
}

/**
 * One native-HTTP route boundary for the frozen public surface. It reconstructs MCP
 * requests against the configured HTTPS origin only after the proxy/Host boundary has
 * authenticated the edge, avoiding the stock adapter's `http://` reconstruction.
 */
export function createBoardAgentHttpRuntime(options: BoardAgentHttpRuntimeOptions): {
  readonly handler: RequestListener;
  readonly close: () => Promise<void>;
} {
  const origin = new URL(options.canonicalOrigin);
  if (origin.origin !== options.canonicalOrigin || origin.protocol !== "https:") {
    throw new Error("BoardAgent runtime requires one exact HTTPS canonical origin");
  }
  if (options.resourceUri !== `${options.canonicalOrigin}/mcp`) {
    throw new Error("BoardAgent runtime resource must be the canonical origin plus /mcp");
  }
  const oauth = options.oauth.callback();
  const responseAdmission = new ResponseAllocationManager();
  let bufferedBytes = 0;
  let inFlightMcpRequests = 0;
  const handler: RequestListener = (request, response) => {
    let heldBytes = 0;
    let heldMcpSlot = false;
    const account = (bytes: number): void => {
      if (bufferedBytes + bytes > MAX_IN_FLIGHT_BODY_BYTES) {
        throw new BodyCapacityError("HTTP body capacity unavailable");
      }
      bufferedBytes += bytes;
      heldBytes += bytes;
    };
    const run = async (): Promise<void> => {
      const inspection = options.boundary.inspect(request, { stateChanging: false });
      const path = pathOf(request);
      if (path === "/health/live") {
        if (request.method !== "GET") {
          sendJson(response, 405, { error: "method_not_allowed" }, options.includeHsts, {
            allow: "GET"
          });
          return;
        }
        sendJson(response, 200, { status: "live" }, options.includeHsts);
        return;
      }
      if (path === "/health/ready") {
        if (request.method !== "GET") {
          sendJson(response, 405, { error: "method_not_allowed" }, options.includeHsts, {
            allow: "GET"
          });
          return;
        }
        const readiness = await options.readiness.check();
        sendJson(
          response,
          readiness.ready ? 200 : 503,
          readiness.ready ? { status: "ready" } : { status: "unavailable" },
          options.includeHsts
        );
        return;
      }
      if (
        path === "/.well-known/oauth-protected-resource" ||
        path === "/.well-known/oauth-protected-resource/mcp"
      ) {
        if (request.method !== "GET") {
          sendJson(response, 405, { error: "method_not_allowed" }, options.includeHsts, {
            allow: "GET"
          });
          return;
        }
        sendJson(response, 200, metadata(options), options.includeHsts);
        return;
      }
      if (path === "/mcp") {
        if (request.method === "POST") {
          if (inFlightMcpRequests >= MAX_IN_FLIGHT_MCP_REQUESTS)
            throw new BodyCapacityError("HTTP MCP dispatch capacity unavailable");
          inFlightMcpRequests += 1;
          heldMcpSlot = true;
        }
        await handleMcp(request, response, options, responseAdmission, account);
        return;
      }
      if (path === "/verify/certificate") {
        await handlePublicCertificateVerification(
          request,
          response,
          options,
          inspection.clientIpClass,
          account
        );
        return;
      }
      if (path.startsWith("/recover") && options.recovery) {
        options.recovery(request, response);
        return;
      }
      if (path.startsWith("/enroll")) {
        options.enrollment(request, response);
        return;
      }
      if (path.startsWith("/onboarding")) {
        options.onboarding(request, response);
        return;
      }
      if (path.startsWith("/auth/")) {
        options.interaction(request, response);
        return;
      }
      if (
        path === "/authorize" ||
        /^\/authorize\/[A-Za-z0-9_-]{1,256}$/u.test(path) ||
        path === "/token" ||
        path === "/register" ||
        path === "/jwks" ||
        path.startsWith("/.well-known/") ||
        path.startsWith("/session/") ||
        path.startsWith("/me")
      ) {
        oauth(request, response);
        return;
      }
      sendJson(response, 404, { error: "not_found" }, options.includeHsts);
    };
    void run()
      .catch(async (error: unknown) => {
        const normalized = error instanceof Error ? error : new Error("unknown runtime failure");
        options.onError?.(normalized);
        if (error instanceof BodyCapacityError) {
          await rejectJson(
            request,
            response,
            503,
            { error: "temporarily_unavailable" },
            options.includeHsts,
            {
              "retry-after": "1"
            }
          );
        } else if (error instanceof RangeError) {
          await rejectJson(
            request,
            response,
            413,
            { error: "request_too_large" },
            options.includeHsts
          );
        } else {
          await rejectJson(
            request,
            response,
            400,
            { error: "invalid_request" },
            options.includeHsts
          );
        }
      })
      .finally(() => {
        bufferedBytes -= heldBytes;
        // handleMcp includes producer and delivery-audit settlement. A closed
        // downstream connection alone does not release this request's slot.
        if (heldMcpSlot) inFlightMcpRequests -= 1;
      });
  };
  return {
    handler,
    close: async () => {
      await options.mcp.close();
    }
  };
}
