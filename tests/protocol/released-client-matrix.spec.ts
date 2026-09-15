import { execFile } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile } from "node:fs/promises";
import { createServer, type Server as HttpsServer } from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type McpHttpHandler,
  type OAuthTokenVerifier
} from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";

import {
  createBoardAgentMcpHandler,
  createProtectedMcpHandler,
  type BoardAgentSurfaceService,
  type HumanActionResolution,
  type PersistHumanStageInput,
  type PreparedHumanAction,
  type ResolveHumanActionInput,
  type SurfacePrincipal,
  type SurfaceResourceResult,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { type JsonValue } from "../../lib/contracts/src/index.js";

const ROOT = path.resolve(import.meta.dirname, "../..");
const TLS_CERTIFICATE = path.join(ROOT, "tests", "fixtures", "tls", "released-client-matrix.crt");
const TLS_KEY = path.join(ROOT, "tests", "fixtures", "tls", "released-client-matrix.key");
const PROBE = path.join(ROOT, "tests", "helpers", "released-client-probe.ts");
const TSX = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
const BOARD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e06";
const ORGANIZATION_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const MEMBER_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const INTERNAL_CLIENT_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
const TOKEN_RECORD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e04";
const TOKEN_JTI = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e05";
const TOKENS = {
  mcporter: "mcporter-client-token",
  openclaw: "openclaw-client-token"
} as const;
const PROTOCOL_CLIENTS = {
  mcporter: "https://mcporter.test/client.json",
  openclaw: "https://openclaw.test/client.json"
} as const;
const ALL_SCOPES = [
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

const execFileAsync = promisify(execFile);
const openServers: HttpsServer[] = [];
const openHandlers: McpHttpHandler[] = [];

interface WireRequest {
  readonly client: keyof typeof TOKENS | "unknown";
  readonly method: string | null;
  readonly protocolHeader: string | null;
  readonly requestedProtocol: string | null;
}

const ProbeOutput = z
  .object({
    client: z.enum(["mcporter", "openclaw"]),
    version: z.string(),
    connection: z
      .object({ protocolVersion: z.string().optional(), era: z.string().optional() })
      .optional(),
    toolCount: z.number().int(),
    hasResources: z.boolean().optional(),
    hasPrompts: z.boolean().optional(),
    whoami: z
      .object({
        data: z.object({
          member_id: z.string(),
          protocol_client_id: z.string()
        })
      })
      .passthrough(),
    concreteResourceCount: z.number().int(),
    resourceTemplateCount: z.number().int().optional(),
    resourceText: z.string(),
    promptCount: z.number().int(),
    promptText: z.string()
  })
  .strict();

function toolResult(tool: string, data: JsonValue): SurfaceToolResult {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: null,
    resource_uri: null,
    data
  };
}

class ReleasedClientSurface implements BoardAgentSurfaceService {
  public async executeRead(
    principal: SurfacePrincipal,
    tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    return toolResult(tool, {
      member_id: principal.memberId,
      protocol_client_id: principal.protocolClientId
    });
  }

  public async executeDirect(
    _principal: SurfacePrincipal,
    _tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    throw new Error("released-client matrix may not execute direct acts");
  }

  public async prepareHumanAction(
    _principal: SurfacePrincipal,
    _tool: string,
    _input: JsonValue
  ): Promise<PreparedHumanAction> {
    throw new Error("released-client matrix may not prepare acts");
  }

  public async persistHumanStage(_input: PersistHumanStageInput): Promise<void> {
    throw new Error("released-client matrix may not persist acts");
  }

  public async resolveHumanAction(_input: ResolveHumanActionInput): Promise<HumanActionResolution> {
    throw new Error("released-client matrix may not resolve acts");
  }

  public async readResource(principal: SurfacePrincipal, uri: URL): Promise<SurfaceResourceResult> {
    return {
      uri: uri.href,
      media_type: "application/json",
      text: JSON.stringify({
        schema_version: "boardagent.released-client-resource.v1",
        member_id: principal.memberId,
        protocol_client_id: principal.protocolClientId,
        uri: uri.href
      })
    };
  }
}

function tokenClient(token: string | undefined): keyof typeof TOKENS | "unknown" {
  if (token === `Bearer ${TOKENS.mcporter}`) return "mcporter";
  if (token === `Bearer ${TOKENS.openclaw}`) return "openclaw";
  return "unknown";
}

function authInfo(client: keyof typeof TOKENS, resource: URL): AuthInfo {
  return {
    token: TOKENS[client],
    clientId: PROTOCOL_CLIENTS[client],
    scopes: [...ALL_SCOPES],
    expiresAt: Math.floor(Date.now() / 1_000) + 600,
    resource,
    extra: {
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      internalClientId: INTERNAL_CLIENT_ID,
      accessTokenRecordId: TOKEN_RECORD_ID,
      jti: TOKEN_JTI,
      keyId: "oauth-es256-released-client-test",
      roles: ["admin", "secretariat", "member"],
      boardIds: [BOARD_ID]
    }
  };
}

async function bodyOf(request: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8"));
  }
  return Buffer.concat(chunks);
}

async function startEndpoint(): Promise<{
  readonly endpoint: string;
  readonly requests: WireRequest[];
  readonly serverErrors: Error[];
}> {
  const [cert, key] = await Promise.all([readFile(TLS_CERTIFICATE), readFile(TLS_KEY)]);
  const requests: WireRequest[] = [];
  const serverErrors: Error[] = [];
  let handler: McpHttpHandler | undefined;
  const server = createServer({ cert, key }, (incoming, outgoing) => {
    void (async () => {
      const body = await bodyOf(incoming);
      let wire: Readonly<Record<string, unknown>> = {};
      try {
        const parsed = body.length === 0 ? {} : (JSON.parse(body.toString("utf8")) as unknown);
        if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
          wire = parsed as Readonly<Record<string, unknown>>;
        }
      } catch {
        // The product handler returns the canonical malformed-request response.
      }
      const params =
        wire["params"] !== null &&
        typeof wire["params"] === "object" &&
        !Array.isArray(wire["params"])
          ? (wire["params"] as Readonly<Record<string, unknown>>)
          : {};
      requests.push({
        client: tokenClient(incoming.headers.authorization),
        method: typeof wire["method"] === "string" ? wire["method"] : null,
        protocolHeader:
          typeof incoming.headers["mcp-protocol-version"] === "string"
            ? incoming.headers["mcp-protocol-version"]
            : null,
        requestedProtocol:
          typeof params["protocolVersion"] === "string" ? params["protocolVersion"] : null
      });
      const headers = new Headers();
      for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
        headers.append(incoming.rawHeaders[index] ?? "", incoming.rawHeaders[index + 1] ?? "");
      }
      const address = server.address();
      if (!address || typeof address === "string" || !handler) {
        throw new Error("released-client endpoint unavailable");
      }
      const target = new URL(incoming.url ?? "/", `https://127.0.0.1:${String(address.port)}`);
      const response = await handler.fetch(
        new Request(target, {
          method: incoming.method ?? "POST",
          headers,
          ...(body.length === 0 ? {} : { body: body.toString("utf8") })
        })
      );
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, name) => {
        responseHeaders[name] = value;
      });
      outgoing.writeHead(response.status, responseHeaders);
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    })().catch((error: unknown) => {
      const normalized = error instanceof Error ? error : new Error(String(error));
      serverErrors.push(normalized);
      if (!outgoing.headersSent) outgoing.writeHead(500, { "content-type": "application/json" });
      outgoing.end(JSON.stringify({ error: "test_endpoint_failure" }));
    });
  });
  openServers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("HTTPS test listener unavailable");
  const resource = new URL(`https://127.0.0.1:${String(address.port)}/mcp`);
  const raw = createBoardAgentMcpHandler({
    service: new ReleasedClientSurface(),
    requestStateKey: new Uint8Array(32).fill(0x63),
    requestStateTtlSeconds: 600
  });
  const verifier: OAuthTokenVerifier = {
    async verifyAccessToken(token) {
      const client =
        token === TOKENS.mcporter ? "mcporter" : token === TOKENS.openclaw ? "openclaw" : null;
      if (!client) throw new OAuthError(OAuthErrorCode.InvalidToken, "invalid token");
      return authInfo(client, resource);
    }
  };
  handler = createProtectedMcpHandler({
    handler: raw,
    resourceUri: resource.href,
    verifier
  });
  openHandlers.push(handler);
  return { endpoint: resource.href, requests, serverErrors };
}

async function runClient(
  client: keyof typeof TOKENS,
  endpoint: string
): Promise<z.infer<typeof ProbeOutput>> {
  const state = await mkdtemp(path.join(tmpdir(), `boardagent-${client}-`));
  const execution = await execFileAsync(process.execPath, [TSX, PROBE], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 4 * 1_024 * 1_024,
    timeout: 60_000,
    env: {
      ...process.env,
      BOARDAGENT_RELEASED_CLIENT: client,
      BOARDAGENT_RELEASED_CLIENT_BOARD_ID: BOARD_ID,
      BOARDAGENT_RELEASED_CLIENT_ENDPOINT: endpoint,
      BOARDAGENT_RELEASED_CLIENT_TOKEN: TOKENS[client],
      NODE_EXTRA_CA_CERTS: TLS_CERTIFICATE,
      OPENCLAW_CONFIG_PATH: path.join(state, "openclaw.json"),
      OPENCLAW_STATE_DIR: state,
      NO_COLOR: "1"
    }
  });
  expect(execution.stderr).toBe("");
  return ProbeOutput.parse(JSON.parse(execution.stdout) as unknown);
}

function methodsFor(requests: readonly WireRequest[], client: keyof typeof TOKENS): Set<string> {
  return new Set(
    requests
      .filter((request) => request.client === client && request.method !== null)
      .map((request) => request.method as string)
  );
}

afterEach(async () => {
  await Promise.allSettled(openHandlers.splice(0).map((handler) => handler.close()));
  await Promise.allSettled(
    openServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        })
    )
  );
});

describe("frozen released MCP client matrix", () => {
  it("runs exact mcporter and OpenClaw releases through HTTPS, bearer auth, reads, resources and prompts", async () => {
    const endpoint = await startEndpoint();
    const mcporter = await runClient("mcporter", endpoint.endpoint);
    const openclaw = await runClient("openclaw", endpoint.endpoint);

    expect(mcporter).toMatchObject({
      client: "mcporter",
      version: "0.13.7",
      connection: { protocolVersion: "2026-07-28", era: "modern" },
      toolCount: 154,
      concreteResourceCount: 0,
      resourceTemplateCount: 16,
      promptCount: 7
    });
    expect(openclaw).toMatchObject({
      client: "openclaw",
      version: "2026.7.1",
      toolCount: 58,
      hasResources: true,
      hasPrompts: true,
      concreteResourceCount: 0,
      promptCount: 7
    });
    for (const output of [mcporter, openclaw]) {
      expect(output.whoami.data).toEqual({
        member_id: MEMBER_ID,
        protocol_client_id: PROTOCOL_CLIENTS[output.client]
      });
      expect(JSON.parse(output.resourceText)).toEqual({
        schema_version: "boardagent.released-client-resource.v1",
        member_id: MEMBER_ID,
        protocol_client_id: PROTOCOL_CLIENTS[output.client],
        uri: `board://${BOARD_ID}`
      });
      expect(output.promptText).toContain("derived local memory");
      expect([...methodsFor(endpoint.requests, output.client)]).toEqual(
        expect.arrayContaining([
          output.client === "mcporter" ? "server/discover" : "initialize",
          "tools/list",
          "tools/call",
          "resources/list",
          "resources/read",
          "prompts/list",
          "prompts/get"
        ])
      );
    }

    const initialized = (client: keyof typeof TOKENS): WireRequest | undefined =>
      endpoint.requests.find(
        (request) => request.client === client && request.method === "initialize"
      );
    expect(initialized("openclaw")).toBeDefined();
    expect(methodsFor(endpoint.requests, "mcporter").has("server/discover")).toBe(true);
    expect(
      endpoint.requests
        .filter(
          (request) =>
            request.method !== null &&
            request.method !== "initialize" &&
            request.method !== "server/discover"
        )
        .every(
          (request) =>
            request.protocolHeader === (request.client === "mcporter" ? "2026-07-28" : "2025-11-25")
        )
    ).toBe(true);
    expect(endpoint.requests.some((request) => request.client === "unknown")).toBe(false);
    expect(endpoint.serverErrors).toEqual([]);
  });
});
