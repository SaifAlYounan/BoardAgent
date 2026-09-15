import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { createRuntime } from "mcporter";

const TOOL_INPUT_SCHEMA_VERSION = "boardagent.tool-input.v1";

interface OpenClawRuntime {
  getCatalog(): Promise<{
    readonly diagnostics?: readonly unknown[];
    readonly servers: Readonly<
      Record<
        string,
        {
          readonly prompts?: Readonly<Record<string, unknown>>;
          readonly resources?: Readonly<Record<string, unknown>>;
          readonly toolCount: number;
        }
      >
    >;
    readonly tools: readonly unknown[];
  }>;
  callTool(serverName: string, toolName: string, input: unknown): Promise<unknown>;
  listResources?(serverName: string): Promise<unknown>;
  readResource?(serverName: string, uri: string): Promise<unknown>;
  listPrompts?(serverName: string): Promise<unknown>;
  getPrompt?(serverName: string, name: string, args?: Record<string, string>): Promise<unknown>;
  dispose(): Promise<void>;
}

interface OpenClawRuntimeModule {
  createSessionMcpRuntime(input: {
    readonly sessionId: string;
    readonly workspaceDir: string;
    readonly cfg: Readonly<Record<string, unknown>>;
  }): OpenClawRuntime;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Readonly<Record<string, unknown>>;
}

function arrayField(value: unknown, field: string): readonly unknown[] {
  if (Array.isArray(value)) return value;
  const candidate = record(value)[field];
  return Array.isArray(candidate) ? candidate : [];
}

function contentText(value: unknown): string | null {
  const first = arrayField(value, "contents")[0] ?? arrayField(value, "messages")[0];
  const firstRecord = record(first);
  const content = record(firstRecord["content"]);
  const direct = firstRecord["text"];
  if (typeof direct === "string") return direct;
  return typeof content["text"] === "string" ? content["text"] : null;
}

function structuredContent(value: unknown): Readonly<Record<string, unknown>> {
  const direct = record(record(value)["structuredContent"]);
  if (Object.keys(direct).length > 0) return direct;
  const text = record(arrayField(value, "content")[0])["text"];
  if (typeof text !== "string") return {};
  try {
    return record(JSON.parse(text) as unknown);
  } catch {
    return {};
  }
}

async function packageVersion(name: "mcporter" | "openclaw"): Promise<string> {
  const manifest = JSON.parse(
    await readFile(path.join(process.cwd(), "node_modules", name, "package.json"), "utf8")
  ) as { version?: unknown };
  if (typeof manifest.version !== "string") throw new Error(`${name} package version missing`);
  return manifest.version;
}

async function probeMcporter(endpoint: string, token: string, boardId: string): Promise<unknown> {
  const runtime = await createRuntime({
    clientInfo: { name: "boardagent-mcporter-acceptance", version: "1.0.0" },
    servers: [
      {
        name: "boardagent",
        command: {
          kind: "http",
          url: new URL(endpoint),
          headers: { Authorization: `Bearer ${token}` }
        },
        protocolVersion: "2026-07-28"
      }
    ]
  });
  try {
    const tools = await runtime.listTools("boardagent", {
      includeSchema: true,
      disableOAuth: true
    });
    const connection = await runtime.connect("boardagent", { disableOAuth: true });
    const whoami = await runtime.callTool("boardagent", "whoami", {
      args: { schema_version: TOOL_INPUT_SCHEMA_VERSION },
      disableOAuth: true
    });
    const resources = await runtime.listResources("boardagent", { disableOAuth: true });
    const resource = await runtime.readResource("boardagent", `board://${boardId}`, {
      disableOAuth: true
    });
    const resourceTemplates = await connection.client.listResourceTemplates();
    const prompts = await connection.client.listPrompts();
    const prompt = await connection.client.getPrompt({
      name: "onboard-boardagent",
      arguments: {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: boardId
      }
    });
    return {
      client: "mcporter",
      version: await packageVersion("mcporter"),
      connection: await runtime.getConnectionInfo?.("boardagent"),
      toolCount: tools.length,
      whoami: structuredContent(whoami),
      concreteResourceCount: arrayField(resources, "resources").length,
      resourceTemplateCount: arrayField(resourceTemplates, "resourceTemplates").length,
      resourceText: contentText(resource),
      promptCount: arrayField(prompts, "prompts").length,
      promptText: contentText(prompt)
    };
  } finally {
    await runtime.close();
  }
}

async function probeOpenClaw(endpoint: string, token: string, boardId: string): Promise<unknown> {
  const moduleUrl = pathToFileURL(
    path.join(
      process.cwd(),
      "node_modules",
      "openclaw",
      "dist",
      "agents",
      "agent-bundle-mcp-runtime.js"
    )
  ).href;
  const runtimeModule = (await import(moduleUrl)) as unknown as OpenClawRuntimeModule;
  const runtime = runtimeModule.createSessionMcpRuntime({
    sessionId: "boardagent-released-client-acceptance",
    workspaceDir: process.cwd(),
    cfg: {
      mcp: {
        sessionIdleTtlMs: 0,
        servers: {
          boardagent: {
            url: endpoint,
            transport: "streamable-http",
            headers: { Authorization: `Bearer ${token}` },
            sslVerify: true,
            timeout: 20,
            connectTimeout: 10
          }
        }
      }
    }
  });
  try {
    const catalog = await runtime.getCatalog();
    const server = catalog.servers["boardagent"];
    if (!server || (catalog.diagnostics?.length ?? 0) > 0) {
      throw new Error(`OpenClaw MCP catalog failed: ${JSON.stringify(catalog.diagnostics ?? [])}`);
    }
    const whoami = await runtime.callTool("boardagent", "whoami", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION
    });
    const resources = await runtime.listResources?.("boardagent");
    const resource = await runtime.readResource?.("boardagent", `board://${boardId}`);
    const prompts = await runtime.listPrompts?.("boardagent");
    const prompt = await runtime.getPrompt?.("boardagent", "onboard-boardagent", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      board_id: boardId
    });
    return {
      client: "openclaw",
      version: await packageVersion("openclaw"),
      toolCount: server.toolCount,
      hasResources: server.resources !== undefined,
      hasPrompts: server.prompts !== undefined,
      whoami: structuredContent(whoami),
      concreteResourceCount: arrayField(resources, "resources").length,
      resourceText: contentText(resource),
      promptCount: arrayField(prompts, "prompts").length,
      promptText: contentText(prompt)
    };
  } finally {
    await runtime.dispose();
  }
}

const kind = required("BOARDAGENT_RELEASED_CLIENT");
const endpoint = required("BOARDAGENT_RELEASED_CLIENT_ENDPOINT");
const token = required("BOARDAGENT_RELEASED_CLIENT_TOKEN");
const boardId = required("BOARDAGENT_RELEASED_CLIENT_BOARD_ID");
const output =
  kind === "mcporter"
    ? await probeMcporter(endpoint, token, boardId)
    : kind === "openclaw"
      ? await probeOpenClaw(endpoint, token, boardId)
      : (() => {
          throw new Error(`unknown released client ${kind}`);
        })();
process.stdout.write(`${JSON.stringify(output)}\n`);
