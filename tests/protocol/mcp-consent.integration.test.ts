import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import { createBoardAgentPrototypeMcpHandler } from "../../artifacts/server/src/index.js";
import type {
  BallotConfirmationView,
  BallotStageView,
  BoardAgentService,
  DocumentView,
  PendingActionView,
  PrincipalView
} from "../../artifacts/server/src/ports.js";

const MCP_URL = new URL("https://boardagent.test/mcp");
const VOTE_ID = "11111111-1111-4111-8111-111111111111";
const activeClients: Client[] = [];
const activeHandlers: Array<ReturnType<typeof createBoardAgentPrototypeMcpHandler>> = [];

class FakeService implements BoardAgentService {
  public stageCount = 0;
  public confirmationCount = 0;
  public rejectionCount = 0;
  private readonly stages = new Map<string, BallotStageView>();

  public async whoami(memberId: string): Promise<PrincipalView> {
    return {
      memberId,
      displayName: "Director A",
      roles: ["member"],
      scopes: ["governance:read", "vote:act"],
      boardIds: ["22222222-2222-4222-8222-222222222222"],
      onboardingCurrent: true,
      secretaryContact: {
        name: "Secretary",
        contactText: "Use ask_secretariat through BoardAgent."
      }
    };
  }

  public async listPendingActions(
    _memberId: string,
    _afterSequence: string | null,
    _limit: number
  ): Promise<readonly PendingActionView[]> {
    return [];
  }

  public async listDocuments(
    _memberId: string,
    _boardId: string,
    _afterSequence: string | null,
    _limit: number
  ): Promise<readonly DocumentView[]> {
    return [];
  }

  public async stageBallot(input: {
    memberId: string;
    clientId: string;
    tokenJti: string;
    voteId: string;
    choice: "yes" | "no" | "abstain";
    statement: string | null;
    requestHash: string;
  }): Promise<BallotStageView> {
    this.stageCount += 1;
    const stage: BallotStageView = {
      stageId: `stage-${this.stageCount}`,
      voteId: input.voteId,
      voteTitle: "Approve deterministic private beta",
      memberName: "Director A",
      choice: input.choice,
      statement: input.statement,
      canonicalResolutionText: "RESOLVED: approve the exact BoardAgent decision package.",
      canonicalResolutionSha256: "a".repeat(64),
      confirmationCode: "BRD7K2Q9",
      requestHash: input.requestHash,
      expiresAt: "2026-08-29T12:10:00Z"
    };
    this.stages.set(stage.stageId, stage);
    return stage;
  }

  public async confirmBallot(input: {
    memberId: string;
    clientId: string;
    tokenJti: string;
    stageId: string;
    confirmationCode: string;
    requestHash: string;
    canonicalResolutionSha256: string;
  }): Promise<BallotConfirmationView> {
    const stage = this.stages.get(input.stageId);
    if (
      !stage ||
      input.confirmationCode !== stage.confirmationCode ||
      input.requestHash !== stage.requestHash ||
      input.canonicalResolutionSha256 !== stage.canonicalResolutionSha256
    ) {
      throw new Error("confirmation rejected");
    }
    this.confirmationCount += 1;
    return {
      ballotId: "33333333-3333-4333-8333-333333333333",
      voteId: stage.voteId,
      principalMemberId: input.memberId,
      casterMemberId: input.memberId,
      certificateResourceUri: `board://${stage.voteId}/certificate`,
      auditSequence: "42"
    };
  }

  public async rejectBallotStage(): Promise<void> {
    this.rejectionCount += 1;
  }
}

afterEach(async () => {
  await Promise.allSettled(activeClients.splice(0).map((client) => client.close()));
  await Promise.allSettled(activeHandlers.splice(0).map((handler) => handler.close()));
});

async function connect(
  service: FakeService,
  capabilities: { elicitation?: { form?: Record<string, never> } }
): Promise<Client> {
  const handler = createBoardAgentPrototypeMcpHandler({
    service,
    requestStateKey: new Uint8Array(32).fill(0x53),
    requestStateTtlSeconds: 600
  });
  activeHandlers.push(handler);
  const authInfo: AuthInfo = {
    token: "synthetic-test-token",
    clientId: "portable-client",
    scopes: ["governance:read", "vote:act"],
    expiresAt: Math.floor(Date.now() / 1000) + 600,
    resource: MCP_URL,
    extra: { memberId: "member-a", jti: "test-jti" }
  };
  const client = new Client(
    { name: "portable-client", version: "1.0.0" },
    {
      capabilities,
      versionNegotiation: { mode: { pin: "2026-07-28" } },
      inputRequired: { autoFulfill: true, maxRounds: 2 },
      cachePartition: "member-a"
    }
  );
  await client.connect(
    new StreamableHTTPClientTransport(MCP_URL, {
      fetch: async (input, init) => handler.fetch(new Request(input, init), { authInfo })
    })
  );
  activeClients.push(client);
  return client;
}

describe("BoardAgent MCP 2026 server-attested consent", () => {
  it("uses a real modular SDK client and records exactly one confirmed ballot", async () => {
    const service = new FakeService();
    const client = await connect(service, { elicitation: { form: {} } });
    let rendered = "";
    client.setRequestHandler("elicitation/create", async (request) => {
      rendered = String(request.params.message);
      return { action: "accept", content: { approve: true, confirmation_code: "BRD7K2Q9" } };
    });

    const identity = await client.callTool({ name: "whoami", arguments: {} });
    expect(identity.isError).not.toBe(true);
    const result = await client.callTool({
      name: "stage_ballot",
      arguments: { vote_id: VOTE_ID, choice: "yes", statement: "Approved on the complete package." }
    });
    expect(result.isError).not.toBe(true);
    expect(service.stageCount).toBe(1);
    expect(service.confirmationCount).toBe(1);
    expect(rendered).toContain("BoardAgent canonical vote confirmation");
    expect(rendered).toContain("RESOLVED: approve the exact BoardAgent decision package.");
    expect(rendered).toContain(`Resolution SHA-256: ${"a".repeat(64)}`);
    expect(rendered).toContain("Confirmation code: BRD7K2Q9");
  });

  it("rejects an incapable client before creating a stage", async () => {
    const service = new FakeService();
    const client = await connect(service, {});
    await expect(
      client.callTool({
        name: "stage_ballot",
        arguments: { vote_id: VOTE_ID, choice: "no", statement: null }
      })
    ).rejects.toMatchObject({ code: -32021 });
    expect(service.stageCount).toBe(0);
    expect(service.confirmationCount).toBe(0);
  });

  it("rejects decline without recording or restaging", async () => {
    const service = new FakeService();
    const client = await connect(service, { elicitation: { form: {} } });
    client.setRequestHandler("elicitation/create", async () => ({ action: "decline" }));
    const result = await client.callTool({
      name: "stage_ballot",
      arguments: { vote_id: VOTE_ID, choice: "abstain", statement: null }
    });
    expect(result.isError).toBe(true);
    expect(service.stageCount).toBe(1);
    expect(service.rejectionCount).toBe(1);
    expect(service.confirmationCount).toBe(0);
  });
});
