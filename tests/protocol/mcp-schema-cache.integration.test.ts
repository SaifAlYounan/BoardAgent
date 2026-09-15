import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type {
  AuthInfo,
  McpHttpHandler,
  StandardSchemaWithJSON
} from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BOARDAGENT_REGISTRY, TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import { createBoardAgentMcpHandler } from "../../artifacts/server/src/mcp-surface.js";
import * as schemaCache from "../../artifacts/server/src/mcp-schema-cache.js";
import { ResourceObservedMcpServer } from "../../artifacts/server/src/resource-delivery-transport.js";
import {
  ResponseAllocationManager,
  currentResponseAllocationOwner,
  loadWithResponseAllocation,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import type {
  BoardAgentSurfaceService,
  SurfaceToolResult
} from "../../artifacts/server/src/ports.js";

const RESOURCE = new URL("https://schema-cache.test/mcp");
const ids = Array.from({ length: 8 }, (_, i) => `018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e0${i + 1}`);
const versions = ["2026-07-28", "2025-11-25"] as const;
const clients: Client[] = [];
const handlers: McpHttpHandler[] = [];
const readArguments = {
  schema_version: TOOL_INPUT_SCHEMA_VERSION,
  document_id: ids[6],
  version_id: null
};

function response(tool: string, member: string): SurfaceToolResult {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: null,
    resource_uri: null,
    data: { member_id: member, canonical_body: "x" }
  };
}
function service(
  read: BoardAgentSurfaceService["executeRead"] = async (actor, tool) =>
    response(tool, actor.memberId)
): BoardAgentSurfaceService {
  const unsupported = async (): Promise<never> => {
    throw new Error("unexpected fixture operation");
  };
  return {
    executeRead: read,
    executeDirect: unsupported,
    readResource: unsupported,
    prepareHumanAction: unsupported,
    persistHumanStage: unsupported,
    resolveHumanAction: unsupported
  };
}
function handler(value = service()): McpHttpHandler {
  const created = createBoardAgentMcpHandler({
    service: value,
    requestStateKey: new Uint8Array(32).fill(0x73),
    requestStateTtlSeconds: 600
  });
  handlers.push(created);
  return created;
}
function auth(member = ids[1]!): AuthInfo {
  return {
    token: "synthetic-schema-token",
    clientId: "https://schema-client.test/client.json",
    scopes: ["documents:read", "governance:read", "meeting:act"],
    expiresAt: Math.floor(Date.now() / 1000) + 600,
    resource: RESOURCE,
    extra: {
      organizationId: ids[0],
      memberId: member,
      internalClientId: ids[2],
      accessTokenRecordId: ids[3],
      jti: ids[4],
      keyId: "schema-fixture",
      roles: ["member"],
      boardIds: [ids[5]]
    }
  };
}
async function connect(
  value: McpHttpHandler,
  version: (typeof versions)[number],
  member = ids[1]!,
  manager?: ResponseAllocationManager
): Promise<Client> {
  const client = new Client(
    { name: "schema-cache-client", version: "1" },
    {
      capabilities: {},
      versionNegotiation: { mode: version === "2025-11-25" ? "legacy" : { pin: version } }
    }
  );
  clients.push(client);
  await client.connect(
    new StreamableHTTPClientTransport(RESOURCE, {
      fetch: async (input, init) => {
        const request = new Request(input, init);
        if (!manager) return value.fetch(request, { authInfo: auth(member) });
        const owner = manager.openRequest(new AbortController().signal);
        try {
          return await owner.run(() => value.fetch(request, { authInfo: auth(member) }));
        } finally {
          // Synthetic direct-SDK ownership markers; no native delivery/audit claim.
          await owner.whenProducersDone();
          owner.nativeTerminal();
          owner.collectorSettled();
        }
      }
    })
  );
  expect(client.getNegotiatedProtocolVersion()).toBe(version);
  expect(client.getProtocolEra()).toBe(version === "2025-11-25" ? "legacy" : "modern");
  if (version === "2026-07-28") expect(client.getDiscoverResult()).toBeDefined();
  return client;
}
function uncached<Input, Output>(
  schema: StandardSchemaWithJSON<Input, Output>
): StandardSchemaWithJSON<Input, Output> {
  return schema;
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.allSettled(clients.splice(0).map((client) => client.close()));
  await Promise.allSettled(handlers.splice(0).map((value) => value.close()));
});

describe("request-independent MCP schema reuse", () => {
  it.each(versions)(
    "keeps the full uncached catalog and schemas exact across fresh requests (%s)",
    async (version) => {
      // Bypass only the adapter through its public module seam. The baseline uses
      // the original Zod exporters/validators and the same frozen registrations.
      const bypass = vi.spyOn(schemaCache, "memoizeSchemaExports").mockImplementation(uncached);
      let expected: {
        tools: Awaited<ReturnType<Client["listTools"]>>;
        resources: Awaited<ReturnType<Client["listResourceTemplates"]>>;
        prompts: Awaited<ReturnType<Client["listPrompts"]>>;
      };
      try {
        const baseline = await connect(handler(), version);
        expected = {
          tools: await baseline.listTools(),
          resources: await baseline.listResourceTemplates(),
          prompts: await baseline.listPrompts()
        };
        await baseline.close();
      } finally {
        bypass.mockRestore();
      }
      const registrations = vi.spyOn(ResourceObservedMcpServer.prototype, "registerTool");
      const cached = await connect(handler(), version);
      const first = await cached.listTools();
      const second = await cached.listTools();
      expect(first).toEqual(expected!.tools);
      expect(second).toEqual(expected!.tools);
      expect(await cached.listResourceTemplates()).toEqual(expected!.resources);
      expect(await cached.listPrompts()).toEqual(expected!.prompts);
      expect(first.tools.map((tool) => tool.name)).toEqual(
        BOARDAGENT_REGISTRY.tools
          .filter((tool) => version !== "2025-11-25" || tool.class === "R")
          .map((tool) => tool.name)
      );
      const selected = registrations.mock.calls
        .map((call, index) => ({ call, context: registrations.mock.contexts[index] }))
        .filter(({ call }) => call[0] === "read_document");
      expect(selected.length).toBeGreaterThanOrEqual(3);
      expect(new Set(selected.map(({ context }) => context)).size).toBe(selected.length);
      expect(new Set(selected.map(({ call }) => call[1].inputSchema)).size).toBe(1);
      expect(new Set(selected.map(({ call }) => call[1].outputSchema)).size).toBe(1);
    }
  );

  it.each(versions)(
    "preserves strict rejection and tool-result validation (%s)",
    async (version) => {
      const read = vi.fn<BoardAgentSurfaceService["executeRead"]>(async () =>
        response("wrong_tool", ids[1]!)
      );
      const client = await connect(handler(service(read)), version);
      expect(
        (
          await client.callTool({
            name: "read_document",
            arguments: { ...readArguments, injected: true }
          })
        ).isError
      ).toBe(true);
      expect(read).not.toHaveBeenCalled();
      expect(
        (await client.callTool({ name: "read_document", arguments: readArguments })).isError
      ).toBe(true);
      expect(read).toHaveBeenCalledTimes(1);
    }
  );

  it("retains the canonical transcript refinement that JSON Schema alone cannot express", async () => {
    const direct = vi.fn(async (): Promise<never> => {
      throw new Error("refinement was skipped");
    });
    const client = await connect(handler({ ...service(), executeDirect: direct }), "2026-07-28");
    const invalid = await client.callTool({
      name: "create_meeting_transcript_version",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "schema-cache-canonical-01",
        meeting_id: ids[5],
        transcript_id: ids[6],
        media_type: "application/json",
        canonical_body:
          '{ "schema_version": "boardagent.transcript-turns.v1", "values": { "turns": [] } }',
        coverage_statement: "Synthetic canonical-refinement fixture",
        supersedes_version_id: null
      }
    });
    expect(invalid.isError).toBe(true);
    expect(direct).not.toHaveBeenCalled();
    expect(JSON.stringify(invalid.content)).toContain("exact canonical encoding");
  });

  it("shares schemas while concurrent eras retain distinct actors, servers and owners", async () => {
    const manager = new ResponseAllocationManager();
    const entered = [gate(), gate()];
    const finish = [gate(), gate()];
    const owners: unknown[] = [];
    const read: BoardAgentSurfaceService["executeRead"] = async (actor, tool) => {
      const index = actor.memberId === ids[1] ? 0 : 1;
      owners[index] = currentResponseAllocationOwner();
      return loadWithResponseAllocation(
        responseAllocationPlan({
          kind: "document",
          representation: "tool",
          sourceId: `synthetic-${actor.memberId}`,
          sourceVersion: "1",
          sha256: "a".repeat(64),
          canonicalBytes: 1
        }),
        async () => {
          entered[index]!.release();
          await finish[index]!.promise;
          return response(tool, actor.memberId);
        }
      );
    };
    const shared = handler(service(read));
    const first = await connect(shared, "2026-07-28", ids[1], manager);
    const second = await connect(shared, "2025-11-25", ids[7], manager);
    const calls = [
      first.callTool({ name: "read_document", arguments: readArguments }),
      second.callTool({ name: "read_document", arguments: readArguments })
    ];
    let gateDeadline: ReturnType<typeof setTimeout> | undefined;
    try {
      const allEntered = Promise.all(
        entered.map((value, index) =>
          Promise.race([
            value.promise,
            calls[index]!.then(() => {
              throw new Error("request finished before its ownership gate");
            })
          ])
        )
      );
      await Promise.race([
        allEntered,
        new Promise<never>((_resolve, reject) => {
          gateDeadline = setTimeout(
            () => reject(new Error("both owner gates were not entered within two seconds")),
            2_000
          );
        })
      ]);
      expect(owners[0]).toBeDefined();
      expect(owners[1]).toBeDefined();
      expect(owners[0]).not.toBe(owners[1]);
      expect(manager.accounting.usedUnits).toBe(2);
      finish[0]!.release();
      expect((await calls[0]!).structuredContent).toMatchObject({ data: { member_id: ids[1] } });
      expect(manager.accounting.usedUnits).toBe(1);
      finish[1]!.release();
      expect((await calls[1]!).structuredContent).toMatchObject({ data: { member_id: ids[7] } });
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      if (gateDeadline !== undefined) clearTimeout(gateDeadline);
      for (const value of finish) value.release();
      await Promise.allSettled([first.close(), second.close()]);
      await Promise.allSettled(calls);
    }
  });
});
