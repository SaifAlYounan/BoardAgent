import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import {
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
const ONBOARDING_TOKEN = Buffer.alloc(32, 0xa7).toString("base64url");

const activeClients: Client[] = [];
const activeHandlers: Array<ReturnType<typeof createBoardAgentMcpHandler>> = [];

function result(tool: string, data: JsonValue): SurfaceToolResult {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: null,
    resource_uri: null,
    data
  };
}

class FakeSurfaceService implements BoardAgentSurfaceService {
  public prepares = 0;
  public persists = 0;
  public confirms = 0;
  public rejects = 0;
  public directs = 0;
  private stage: PersistHumanStageInput | undefined;

  public async executeRead(
    principal: SurfacePrincipal,
    tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    return result(tool, {
      member_id: principal.memberId,
      board_ids: principal.boardIds,
      source: "fake_surface"
    });
  }

  public async executeDirect(
    _principal: SurfacePrincipal,
    tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    this.directs += 1;
    return result(
      tool,
      tool === "prepare_onboarding_attestation"
        ? {
            direct: true,
            onboarding_url: `https://boardagent.test/onboarding#${ONBOARDING_TOKEN}`,
            secret_once: true
          }
        : { direct: true }
    );
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
      expires_at: "2026-09-01T12:10:00Z",
      confirmation_lines: [
        "BOARDAGENT CANONICAL CONFIRMATION",
        `Vote: ${VOTE_ID}`,
        `Package SHA-256: ${"a".repeat(64)}`,
        "Confirmation code: BRD7K2Q9"
      ],
      canonical_payload: { vote_id: VOTE_ID, choice: "yes" }
    };
  }

  public async persistHumanStage(input: PersistHumanStageInput): Promise<void> {
    expect(input.request_state.length).toBeGreaterThan(40);
    expect(input.embedded_form).toMatchObject({
      schema_version: "boardagent.confirmation-form.v1"
    });
    this.persists += 1;
    this.stage = input;
  }

  public async resolveHumanAction(input: ResolveHumanActionInput): Promise<HumanActionResolution> {
    expect(this.stage?.prepared.stage_id).toBe(input.stage_id);
    expect(input.request_state).toBe(this.stage?.request_state);
    const response = input.input_response as {
      approve?: JsonValue;
      confirmation_code?: JsonValue;
    } | null;
    if (
      input.response_action !== "accept" ||
      response?.approve !== true ||
      response.confirmation_code !== "BRD7K2Q9"
    ) {
      this.rejects += 1;
      return { confirmed: false, reason: "consent_rejected" };
    }
    this.confirms += 1;
    return { confirmed: true, result: result(input.tool, { ballot_id: VOTE_ID }) };
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

class FractionalResultSurfaceService extends FakeSurfaceService {
  public override async executeRead(
    _principal: SurfacePrincipal,
    tool: string,
    _input: JsonValue
  ): Promise<SurfaceToolResult> {
    return result(tool, { rank: 0.125 });
  }
}

class DatabaseFailureSurfaceService extends FakeSurfaceService {
  public constructor(
    private readonly sqlstate: string,
    private readonly constraint?: string
  ) {
    super();
  }
  public override async executeRead(): Promise<SurfaceToolResult> {
    throw Object.assign(new Error("synthetic database diagnostic"), {
      code: this.sqlstate,
      constraint: this.constraint
    });
  }
  public override async readResource(): Promise<SurfaceResourceResult> {
    throw Object.assign(new Error("synthetic database diagnostic"), {
      code: this.sqlstate,
      constraint: this.constraint
    });
  }
}

afterEach(async () => {
  await Promise.allSettled(activeClients.splice(0).map((client) => client.close()));
  await Promise.allSettled(activeHandlers.splice(0).map((handler) => handler.close()));
});

async function connect(
  service: FakeSurfaceService,
  protocol: "2026-07-28" | "2025-11-25" = "2026-07-28",
  capabilities: { elicitation?: { form?: Record<string, never> } } = {
    elicitation: { form: {} }
  }
): Promise<Client> {
  const handler = createBoardAgentMcpHandler({
    service,
    requestStateKey: new Uint8Array(32).fill(0x73),
    requestStateTtlSeconds: 600
  });
  activeHandlers.push(handler);
  const authInfo: AuthInfo = {
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
  const client = new Client(
    { name: "portable-client", version: "1.0.0" },
    {
      capabilities,
      versionNegotiation: {
        mode: protocol === "2025-11-25" ? "legacy" : { pin: protocol }
      },
      inputRequired: { autoFulfill: true, maxRounds: 2 },
      cachePartition: MEMBER_ID
    }
  );
  const transportFetch = handler.fetch.bind(handler);
  await client.connect(
    new StreamableHTTPClientTransport(RESOURCE, {
      fetch: async (input, init) => transportFetch(new Request(input, init), { authInfo })
    })
  );
  activeClients.push(client);
  return client;
}

describe("generated frozen MCP surface", () => {
  it("reports audit capacity as retryable error data on a protected resource read", async () => {
    const client = await connect(
      new DatabaseFailureSurfaceService("55000", "boardagent_audit_checkpoint_capacity"),
      "2026-07-28",
      {}
    );
    await expect(client.readResource({ uri: `board://${BOARD_ID}` })).rejects.toMatchObject({
      code: -32603,
      data: { code: "audit_checkpoint_capacity", retryable: true }
    });
  });

  it.each(["2026-07-28", "2025-11-25"] as const)(
    "reports exact audit capacity failures to %s read clients",
    async (protocol) => {
      const client = await connect(
        new DatabaseFailureSurfaceService("55000", "boardagent_audit_checkpoint_capacity"),
        protocol,
        {}
      );
      const response = await client.callTool({
        name: "search_documents",
        arguments: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: BOARD_ID,
          query: "synthetic",
          cursor: null,
          limit: 10
        }
      });
      expect(response.isError).toBe(true);
      expect(response.structuredContent).toMatchObject({
        code: "audit_checkpoint_capacity",
        retryable: true
      });
      expect(JSON.stringify(response)).not.toContain("synthetic database diagnostic");
    }
  );

  it.each([
    ["55000", undefined],
    ["55000", "other_integrity_failure"],
    ["42501", "boardagent_audit_checkpoint_capacity"],
    ["54000", "other_size_failure"],
    ["55000", "boardagent_audit_transaction_capacity"]
  ])(
    "does not classify unrelated database failure %s / %s as retryable capacity",
    async (code, constraint) => {
      const client = await connect(
        new DatabaseFailureSurfaceService(code!, constraint),
        "2026-07-28",
        {}
      );
      const response = await client.callTool({
        name: "search_documents",
        arguments: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: BOARD_ID,
          query: "synthetic",
          cursor: null,
          limit: 10
        }
      });
      expect(response.isError).toBe(true);
      expect(response.structuredContent).toBeUndefined();
    }
  );

  it.each(["2026-07-28", "2025-11-25"] as const)(
    "tells %s clients that an oversized action must not be retried unchanged",
    async (protocol) => {
      const client = await connect(
        new DatabaseFailureSurfaceService("54000", "boardagent_audit_transaction_capacity"),
        protocol,
        {}
      );
      const response = await client.callTool({
        name: "search_documents",
        arguments: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: BOARD_ID,
          query: "synthetic",
          cursor: null,
          limit: 10
        }
      });
      expect(response.isError).toBe(true);
      expect(response.structuredContent).toMatchObject({
        code: "audit_transaction_capacity",
        retryable: false
      });
      expect(JSON.stringify(response)).not.toContain("synthetic database diagnostic");
    }
  );

  it("accepts finite fractional JSON values in structured tool results", async () => {
    const client = await connect(new FractionalResultSurfaceService(), "2026-07-28", {});
    const response = await client.callTool({
      name: "search_documents",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: BOARD_ID,
        query: "ranked result",
        cursor: null,
        limit: 10
      }
    });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    expect(response.structuredContent).toMatchObject({
      tool: "search_documents",
      data: { rank: 0.125 }
    });
  });

  it("advertises all 154 approved current tools, 16 resources and 7 thin prompts", async () => {
    const client = await connect(new FakeSurfaceService());
    expect((await client.listTools()).tools).toHaveLength(154);
    expect((await client.listResourceTemplates()).resourceTemplates).toHaveLength(16);
    expect((await client.listPrompts()).prompts).toHaveLength(7);

    const prompt = await client.getPrompt({
      name: "set-vote",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: BOARD_ID }
    });
    expect(prompt.messages[0]?.content).toMatchObject({
      type: "text",
      text: expect.stringContaining("Call create_vote")
    });
  });

  it("advertises exactly the 58 approved read tools to the frozen legacy profile", async () => {
    const client = await connect(new FakeSurfaceService(), "2025-11-25", {});
    const tools = (await client.listTools()).tools;
    expect(tools).toHaveLength(58);
    expect(tools.some(({ name }) => name === "stage_ballot")).toBe(false);
    expect(tools.every(({ annotations }) => annotations?.readOnlyHint === true)).toBe(true);
  });

  it("validates strict versioned arguments and serves an entitled resource", async () => {
    const client = await connect(new FakeSurfaceService());
    const identity = await client.callTool({
      name: "whoami",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION }
    });
    expect(identity.isError).not.toBe(true);

    const invalid = await client.callTool({
      name: "whoami",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION, injected: true }
    });
    expect(invalid.isError).toBe(true);

    const uri = `board://${BOARD_ID}`;
    const resource = await client.readResource({ uri });
    expect(resource.contents).toEqual([
      expect.objectContaining({ uri, mimeType: "application/json" })
    ]);
  });

  it("persists the exact protected state before returning and confirms once", async () => {
    const service = new FakeSurfaceService();
    const client = await connect(service);
    let rendered = "";
    client.setRequestHandler("elicitation/create", async (request) => {
      rendered = String(request.params.message);
      return { action: "accept", content: { approve: true, confirmation_code: "BRD7K2Q9" } };
    });

    const response = await client.callTool({
      name: "stage_ballot",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: VOTE_ID,
        principal_member_id: null,
        choice: "yes",
        statement: "Approved on the exact package.",
        idempotency_key: "stage-ballot-000001"
      }
    });
    expect(response.isError).not.toBe(true);
    expect(service.prepares).toBe(1);
    expect(service.persists).toBe(1);
    expect(service.confirms).toBe(1);
    expect(rendered).toContain("BOARDAGENT CANONICAL CONFIRMATION");
    expect(rendered).toContain("Confirmation code: BRD7K2Q9");
  });

  it("rejects an incapable client before preparation or persistence", async () => {
    const service = new FakeSurfaceService();
    const client = await connect(service, "2026-07-28", {});
    await expect(
      client.callTool({
        name: "stage_ballot",
        arguments: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: VOTE_ID,
          principal_member_id: null,
          choice: "no",
          statement: null,
          idempotency_key: "stage-ballot-000002"
        }
      })
    ).rejects.toMatchObject({ code: -32021 });
    expect(service.prepares).toBe(0);
    expect(service.persists).toBe(0);
  });

  it("lets an incapable modern client prepare only the passkey onboarding exception", async () => {
    const service = new FakeSurfaceService();
    const client = await connect(service, "2026-07-28", {});
    const response = await client.callTool({
      name: "prepare_onboarding_attestation",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: BOARD_ID,
        terms_version_id: ORGANIZATION_ID,
        support_version_id: MEMBER_ID,
        presentation_choice: "structured summaries",
        local_memory_choice: "encrypted local cache",
        idempotency_key: "prepare-onboarding-0001"
      }
    });
    expect(response.isError).not.toBe(true);
    expect(service.directs).toBe(1);
    expect(service.prepares).toBe(0);
    expect(JSON.stringify(response.content)).not.toContain(ONBOARDING_TOKEN);
    expect(response.structuredContent).toMatchObject({
      tool: "prepare_onboarding_attestation",
      data: {
        onboarding_url: `https://boardagent.test/onboarding#${ONBOARDING_TOKEN}`,
        secret_once: true
      }
    });
    const prompt = await client.getPrompt({
      name: "onboard-boardagent",
      arguments: { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: BOARD_ID }
    });
    const promptText = JSON.stringify(prompt.messages);
    expect(promptText).toMatch(/no governance portal/u);
    expect(promptText).toMatch(/secretary-support record/u);
    expect(promptText).toMatch(/information presented/u);
    expect(promptText).toMatch(/derived local memory/u);
  });

  it("routes a direct canonical document contribution without an elicitation prompt", async () => {
    const service = new FakeSurfaceService();
    const client = await connect(service, "2026-07-28", {});
    const response = await client.callTool({
      name: "create_document_version",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: BOARD_ID,
        document_id: VOTE_ID,
        title: "Exploration programme",
        media_type: "text/markdown; charset=utf-8",
        schema_name: null,
        canonical_body: "# Exploration programme\n",
        expected_current_version_id: null,
        idempotency_key: "document-contribution-0001"
      }
    });
    expect(response.isError).not.toBe(true);
    expect(response.structuredContent).toMatchObject({
      tool: "create_document_version",
      data: { direct: true }
    });
    expect(service.directs).toBe(1);
    expect(service.prepares).toBe(0);
    expect(service.persists).toBe(0);
  });

  it("records a decline without executing the act", async () => {
    const service = new FakeSurfaceService();
    const client = await connect(service);
    client.setRequestHandler("elicitation/create", async () => ({ action: "decline" }));
    const response = await client.callTool({
      name: "stage_ballot",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: VOTE_ID,
        principal_member_id: null,
        choice: "abstain",
        statement: null,
        idempotency_key: "stage-ballot-000003"
      }
    });
    expect(response.isError).toBe(true);
    expect(service.prepares).toBe(1);
    expect(service.persists).toBe(1);
    expect(service.rejects).toBe(1);
    expect(service.confirms).toBe(0);
  });
});
