import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import {
  CLIENT_CAPABILITIES_META_KEY,
  PROTOCOL_VERSION_META_KEY,
  type AuthInfo
} from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import {
  LEGACY_PROTOCOL,
  MODERN_PROTOCOL,
  createBoardAgentMcpHandler,
  type BoardAgentSurfaceService,
  type HumanActionResolution,
  type PersistHumanStageInput,
  type PreparedHumanAction,
  type ResolveHumanActionInput,
  type SurfacePrincipal,
  type SurfaceResourceResult,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION, type JsonValue } from "../../lib/contracts/src/index.js";

const RESOURCE = new URL("https://boardagent.test/mcp");
const ORGANIZATION_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const MEMBER_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const CLIENT_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
const TOKEN_RECORD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e04";
const TOKEN_JTI = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e05";
const BOARD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e06";
const VOTE_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e07";
const STAGE_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e08";

interface Capture {
  readonly request: Request;
  readonly body: string;
  readonly response: Response;
}

const activeClients: Client[] = [];
const activeHandlers: Array<ReturnType<typeof createBoardAgentMcpHandler>> = [];

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

class CountingSurfaceService implements BoardAgentSurfaceService {
  public prepares = 0;
  public persists = 0;

  public async executeRead(
    principal: SurfacePrincipal,
    tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    return toolResult(tool, { member_id: principal.memberId, board_ids: principal.boardIds });
  }

  public async executeDirect(
    _principal: SurfacePrincipal,
    tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    return toolResult(tool, { direct: true });
  }

  public async prepareHumanAction(
    _principal: SurfacePrincipal,
    tool: string,
    _input: JsonValue
  ): Promise<PreparedHumanAction> {
    this.prepares += 1;
    return {
      schema_version: "boardagent.prepared-human-action.v1",
      stage_id: STAGE_ID,
      action_code: tool,
      board_id: BOARD_ID,
      target_type: "vote",
      target_id: VOTE_ID,
      package_sha256: "a".repeat(64),
      confirmation_code: "BRD7K2Q9",
      expires_at: "2026-09-02T12:10:00Z",
      confirmation_lines: ["BOARDAGENT CANONICAL CONFIRMATION", "Confirmation code: BRD7K2Q9"],
      canonical_payload: { vote_id: VOTE_ID, choice: "yes" }
    };
  }

  public async persistHumanStage(_input: PersistHumanStageInput): Promise<void> {
    this.persists += 1;
  }

  public async resolveHumanAction(input: ResolveHumanActionInput): Promise<HumanActionResolution> {
    return { confirmed: true, result: toolResult(input.tool, { ballot_id: VOTE_ID }) };
  }

  public async readResource(
    _principal: SurfacePrincipal,
    uri: URL
  ): Promise<SurfaceResourceResult> {
    return {
      uri: uri.href,
      media_type: "application/json",
      text: JSON.stringify({ schema_version: "boardagent.resource.v1", uri: uri.href })
    };
  }
}

function authInfo(): AuthInfo {
  return {
    token: "synthetic-test-token",
    clientId: "https://portable-client.test/client.json",
    scopes: [
      "governance:read",
      "documents:read",
      "vote:act",
      "proxy:manage",
      "minutes:act",
      "member:propose",
      "secretariat:admin",
      "audit:read",
      "meeting:act",
      "task:act",
      "documents:contribute",
      "secretariat:message",
      "management:question",
      "notifications:manage",
      "onboarding:read"
    ],
    expiresAt: Math.floor(Date.now() / 1000) + 600,
    resource: RESOURCE,
    extra: {
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      internalClientId: CLIENT_ID,
      accessTokenRecordId: TOKEN_RECORD_ID,
      jti: TOKEN_JTI,
      keyId: "oauth-es256-1",
      roles: ["admin", "secretariat", "member"],
      boardIds: [BOARD_ID]
    }
  };
}

function buildHarness(service = new CountingSurfaceService()) {
  const captures: Capture[] = [];
  const handler = createBoardAgentMcpHandler({
    service,
    requestStateKey: new Uint8Array(32).fill(0x64),
    requestStateTtlSeconds: 600
  });
  activeHandlers.push(handler);

  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const capturedRequest = request.clone();
    const body = request.method === "POST" ? await request.clone().text() : "";
    const response = await handler.fetch(request, { authInfo: authInfo() });
    captures.push({ request: capturedRequest, body, response: response.clone() });
    return response;
  };

  const connect = async (
    protocol: typeof MODERN_PROTOCOL | typeof LEGACY_PROTOCOL,
    capabilities: {
      elicitation?: { form?: Record<string, never>; url?: Record<string, never> };
    } = {},
    autoFulfill = true
  ): Promise<Client> => {
    const client = new Client(
      { name: `downgrade-proof-${protocol}`, version: "1.0.0" },
      {
        capabilities,
        versionNegotiation: { mode: protocol === LEGACY_PROTOCOL ? "legacy" : { pin: protocol } },
        inputRequired: { autoFulfill, maxRounds: 2 },
        cachePartition: `${MEMBER_ID}-${protocol}-${String(activeClients.length)}`
      }
    );
    await client.connect(new StreamableHTTPClientTransport(RESOURCE, { fetch }));
    activeClients.push(client);
    return client;
  };

  return { handler, service, captures, connect };
}

function stageBallotArguments(): Record<string, JsonValue> {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    vote_id: VOTE_ID,
    principal_member_id: null,
    choice: "yes",
    statement: null,
    idempotency_key: "protocol-downgrade-stage-0001"
  };
}

function capturedToolCall(captures: readonly Capture[], name: string): Capture {
  const capture = captures.find(({ request }) => request.headers.get("mcp-name") === name);
  if (!capture) throw new Error(`missing captured tool call: ${name}`);
  return capture;
}

async function jsonRpcError(response: Response): Promise<{
  readonly code?: number;
  readonly message?: string;
  readonly data?: unknown;
}> {
  const body = (await response.json()) as {
    error?: { code?: number; message?: string; data?: unknown };
  };
  return body.error ?? {};
}

afterEach(async () => {
  await Promise.allSettled(activeClients.splice(0).map((client) => client.close()));
  await Promise.allSettled(activeHandlers.splice(0).map((handler) => handler.close()));
});

describe("frozen MCP downgrade boundary", () => {
  it("uses the approved 151-tool registry while exposing only its 58 read tools to legacy clients", async () => {
    const harness = buildHarness();
    const modern = await harness.connect(MODERN_PROTOCOL);
    const legacy = await harness.connect(LEGACY_PROTOCOL);

    const modernTools = (await modern.listTools()).tools;
    const legacyTools = (await legacy.listTools()).tools;
    expect(modernTools).toHaveLength(154);
    expect(legacyTools).toHaveLength(58);
    expect(modernTools.map(({ name }) => name)).toEqual(
      expect.arrayContaining([
        "manage_company_admin",
        "manage_member_admin_delegation",
        "list_administrative_access"
      ])
    );
    expect(legacyTools.some(({ name }) => name === "list_administrative_access")).toBe(true);
    expect(
      legacyTools.some(
        ({ name }) => name === "manage_company_admin" || name === "manage_member_admin_delegation"
      )
    ).toBe(false);
    expect(legacyTools.every(({ annotations }) => annotations?.readOnlyHint === true)).toBe(true);
    expect(legacyTools.some(({ name }) => name === "stage_ballot")).toBe(false);

    const modernWho = await modern.callTool({
      name: "whoami",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION }
    });
    const legacyWho = await legacy.callTool({
      name: "whoami",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION }
    });
    expect(legacyWho.structuredContent).toEqual(modernWho.structuredContent);
  });

  it("returns the frozen legacy_read_only error before preparing or persisting an H act", async () => {
    const harness = buildHarness();
    const legacy = await harness.connect(LEGACY_PROTOCOL);

    await expect(
      legacy.callTool({ name: "stage_ballot", arguments: stageBallotArguments() })
    ).rejects.toMatchObject({ code: -32602, message: "legacy_read_only" });
    expect(harness.service.prepares).toBe(0);
    expect(harness.service.persists).toBe(0);
  });

  it.each(["manage_company_admin", "manage_member_admin_delegation"])(
    "refuses the approved %s action on a legacy connection before any preparation",
    async (name) => {
      const harness = buildHarness();
      const legacy = await harness.connect(LEGACY_PROTOCOL);
      await expect(
        legacy.callTool({ name, arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION } })
      ).rejects.toMatchObject({ code: -32602, message: "legacy_read_only" });
      expect(harness.service.prepares).toBe(0);
      expect(harness.service.persists).toBe(0);
    }
  );

  it("returns -32020 for every modern header/body/name/version disagreement", async () => {
    const harness = buildHarness();
    const modern = await harness.connect(MODERN_PROTOCOL);
    await modern.callTool({
      name: "whoami",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION }
    });
    const canonical = capturedToolCall(harness.captures, "whoami");

    const mutations: Array<(headers: Headers, body: Record<string, unknown>) => void> = [
      (headers) => headers.set("mcp-method", "resources/read"),
      (headers) => headers.set("mcp-name", "list_boards"),
      (headers) => headers.set("mcp-protocol-version", "2027-01-01"),
      (_headers, body) => {
        const params = body.params as { _meta: Record<string, unknown> };
        params._meta[PROTOCOL_VERSION_META_KEY] = "2027-01-01";
      }
    ];

    for (const mutate of mutations) {
      const headers = new Headers(canonical.request.headers);
      const body = JSON.parse(canonical.body) as Record<string, unknown>;
      mutate(headers, body);
      const response = await harness.handler.fetch(
        new Request(RESOURCE, { method: "POST", headers, body: JSON.stringify(body) }),
        { authInfo: authInfo() }
      );
      expect(response.status).toBe(400);
      expect(await jsonRpcError(response)).toMatchObject({ code: -32020 });
    }
  });

  it("returns -32022 rather than silently falling back for an unsupported version", async () => {
    const harness = buildHarness();
    const modern = await harness.connect(MODERN_PROTOCOL);
    await modern.callTool({
      name: "whoami",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION }
    });
    const canonical = capturedToolCall(harness.captures, "whoami");
    const headers = new Headers(canonical.request.headers);
    headers.set("mcp-protocol-version", "2027-01-01");
    const body = JSON.parse(canonical.body) as {
      params: { _meta: Record<string, unknown> };
    };
    body.params._meta[PROTOCOL_VERSION_META_KEY] = "2027-01-01";

    const response = await harness.handler.fetch(
      new Request(RESOURCE, { method: "POST", headers, body: JSON.stringify(body) }),
      { authInfo: authInfo() }
    );
    expect(response.status).toBe(400);
    expect(await jsonRpcError(response)).toMatchObject({
      code: -32022,
      data: { requested: "2027-01-01", supported: [MODERN_PROTOCOL] }
    });
  });

  it("returns -32021 before staging when form elicitation is absent", async () => {
    const harness = buildHarness();
    const modern = await harness.connect(MODERN_PROTOCOL, {});

    await expect(
      modern.callTool({ name: "stage_ballot", arguments: stageBallotArguments() })
    ).rejects.toMatchObject({
      code: -32021,
      message: "MISSING_REQUIRED_CLIENT_CAPABILITY",
      data: { requiredCapabilities: { elicitation: { form: {} } } }
    });
    expect(harness.service.prepares).toBe(0);
    expect(harness.service.persists).toBe(0);
  });

  it("accepts the spec's empty elicitation object as form support and stages the act", async () => {
    const harness = buildHarness();
    const modern = await harness.connect(MODERN_PROTOCOL, { elicitation: {} }, false);
    const pending = await modern.callTool(
      { name: "stage_ballot", arguments: stageBallotArguments() },
      { allowInputRequired: true }
    );
    expect(pending).toMatchObject({
      resultType: "input_required",
      inputRequests: { confirm_action: { method: "elicitation/create" } }
    });
    expect(harness.service.prepares).toBe(1);
    expect(harness.service.persists).toBe(1);
    const stage = capturedToolCall(harness.captures, "stage_ballot");
    const requestBody = JSON.parse(stage.body) as { params: { _meta: Record<string, unknown> } };
    expect(requestBody.params._meta[CLIENT_CAPABILITIES_META_KEY]).toEqual({ elicitation: {} });
  });

  it("returns -32021 before staging when the client declares URL-only elicitation", async () => {
    const harness = buildHarness();
    const modern = await harness.connect(MODERN_PROTOCOL, { elicitation: { url: {} } });
    await expect(
      modern.callTool({ name: "stage_ballot", arguments: stageBallotArguments() })
    ).rejects.toMatchObject({
      code: -32021,
      message: "MISSING_REQUIRED_CLIENT_CAPABILITY",
      data: { requiredCapabilities: { elicitation: { form: {} } } }
    });
    expect(harness.service.prepares).toBe(0);
    expect(harness.service.persists).toBe(0);
  });

  it("emits only complete or input_required modern result discriminators with the shim off", async () => {
    const harness = buildHarness();
    const modern = await harness.connect(MODERN_PROTOCOL, { elicitation: { form: {} } }, false);
    await modern.callTool({
      name: "whoami",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION }
    });
    const complete = capturedToolCall(harness.captures, "whoami");
    await expect(complete.response.json()).resolves.toMatchObject({
      result: { resultType: "complete" }
    });

    const pending = await modern.callTool(
      { name: "stage_ballot", arguments: stageBallotArguments() },
      { allowInputRequired: true }
    );
    expect(pending).toMatchObject({
      resultType: "input_required",
      requestState: expect.any(String),
      inputRequests: {
        confirm_action: { method: "elicitation/create" }
      }
    });
    const stage = capturedToolCall(harness.captures, "stage_ballot");
    await expect(stage.response.json()).resolves.toMatchObject({
      result: { resultType: "input_required" }
    });
    expect(harness.service.prepares).toBe(1);
    expect(harness.service.persists).toBe(1);

    const requestBody = JSON.parse(stage.body) as { params: { _meta: Record<string, unknown> } };
    expect(requestBody.params._meta[PROTOCOL_VERSION_META_KEY]).toBe(MODERN_PROTOCOL);
    expect(requestBody.params._meta[CLIENT_CAPABILITIES_META_KEY]).toEqual({
      elicitation: { form: {} }
    });
  });
});
