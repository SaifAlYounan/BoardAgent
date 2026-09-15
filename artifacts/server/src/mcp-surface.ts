import {
  BOARDAGENT_REGISTRY,
  BOARDAGENT_REGISTRY_DIGEST,
  Rfc3339UtcSchema,
  TOOL_INPUT_SCHEMA_VERSION,
  StructuredErrorSchema,
  UuidV7Schema,
  canonicalSha256,
  toolInputSchema,
  type JsonValue,
  type StructuredError
} from "@boardagent/contracts";
import {
  CLIENT_CAPABILITIES_META_KEY,
  type McpServer,
  MissingRequiredClientCapabilityError,
  ProtocolError,
  INTERNAL_ERROR,
  ResourceTemplate,
  acceptedContent,
  createMcpHandler,
  createRequestStateCodec,
  inputRequired,
  inputResponse,
  isLegacyRequest,
  type McpHttpHandler,
  type McpRequestContext,
  type ServerContext
} from "@modelcontextprotocol/server";
import { z } from "zod";

import { confirmationFormMessage } from "./confirmation-form-message.js";

import type { BoardAgentSurfaceService, SurfacePrincipal, SurfaceToolResult } from "./ports.js";
import { parseClientCapabilities, supportsFormElicitation } from "./client-capabilities.js";
import {
  bindResourceDeliveryResponse,
  registerPreparedResource,
  registerResourceResponse
} from "./resource-delivery.js";
import { ResourceObservedMcpServer } from "./resource-delivery-transport.js";
import { memoizeSchemaExports } from "./mcp-schema-cache.js";
import {
  ResponseAllocationUnavailable,
  currentResponseAllocationOwner
} from "./response-allocation.js";

export const MODERN_PROTOCOL = "2026-07-28" as const;

export const LEGACY_PROTOCOL = "2025-11-25" as const;

const RESULT_SCHEMA_VERSION = "boardagent.tool-result.v1" as const;
const HUMAN_STATE_SCHEMA_VERSION = "boardagent.mrtr-state.v1" as const;

const ConfirmationInput = z
  .object({ approve: z.boolean(), confirmation_code: z.string().length(8) })
  .strict();
const PromptInput = z
  .object({
    schema_version: z.literal(TOOL_INPUT_SCHEMA_VERSION),
    board_id: UuidV7Schema,
    draft_id: UuidV7Schema.nullable().default(null)
  })
  .strict();
const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);
const AuthExtraSchema = z
  .object({
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    internalClientId: UuidV7Schema,
    accessTokenRecordId: UuidV7Schema,
    jti: UuidV7Schema,
    keyId: z.string().min(1).max(255),
    roles: z.array(z.enum(["admin", "secretariat", "management", "member", "observer"])).max(8),
    boardIds: z.array(UuidV7Schema).max(25)
  })
  .strict();

interface HumanState {
  readonly schema_version: typeof HUMAN_STATE_SCHEMA_VERSION;
  readonly tool: string;
  readonly stage_id: string;
  readonly arguments_sha256: string;
}

interface VerifiedHumanState extends HumanState {
  readonly request_state: string;
}

function principal(ctx: ServerContext): SurfacePrincipal {
  const info = ctx.http?.authInfo;
  if (!info) throw new Error("authenticated BoardAgent context required");
  if (!info.resource) throw new Error("protected resource binding is required");
  const extra = AuthExtraSchema.parse(info.extra);
  return {
    organizationId: extra.organizationId,
    memberId: extra.memberId,
    serviceOrigin: info.resource.origin,
    clientId: extra.internalClientId,
    protocolClientId: info.clientId,
    accessTokenRecordId: extra.accessTokenRecordId,
    tokenJti: extra.jti,
    keyId: extra.keyId,
    scopes: [...info.scopes].toSorted(),
    roles: [...extra.roles].toSorted(),
    boardIds: [...new Set(extra.boardIds)].toSorted()
  };
}

function capabilities(ctx: ServerContext): JsonValue {
  const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined;
  const parsed = parseClientCapabilities(envelope?.[CLIENT_CAPABILITIES_META_KEY] ?? {});
  if (!parsed.success) throw parsed.error;
  return parsed.data;
}

function requestIdBytes(ctx: ServerContext): Uint8Array {
  return Buffer.from(String(ctx.mcpReq.id), "utf8");
}

// Names come only from the frozen registry; no request identity or data is cached.
const resultSchemas = new Map<string, z.ZodType<SurfaceToolResult>>();

function resultSchema(tool: string): z.ZodType<SurfaceToolResult> {
  const cached = resultSchemas.get(tool);
  if (cached) return cached;
  const schema = z
    .object({
      schema_version: z.literal(RESULT_SCHEMA_VERSION),
      tool: z.literal(tool),
      status: z.enum(["ok", "accepted", "already_applied"]),
      reference: z.string().min(1).max(4096).nullable(),
      resource_uri: z.string().min(1).max(4096).nullable(),
      data: JsonValueSchema
    })
    .strict() as z.ZodType<SurfaceToolResult>;
  resultSchemas.set(tool, schema);
  return schema;
}

function textAndStructured(value: SurfaceToolResult): {
  content: [{ type: "text"; text: string }];
  structuredContent: SurfaceToolResult;
} {
  const data =
    typeof value.data === "object" && value.data !== null && !Array.isArray(value.data)
      ? (value.data as Readonly<Record<string, JsonValue>>)
      : null;
  const containsOneTimeSecret =
    data?.["secret_once"] === true &&
    ((value.tool === "issue_enrollment" && typeof data["enrollment_link"] === "string") ||
      (value.tool === "prepare_onboarding_attestation" &&
        typeof data["onboarding_url"] === "string"));
  if (containsOneTimeSecret) {
    return {
      content: [
        {
          type: "text",
          text: "BoardAgent returned a one-time browser link only in structuredContent; do not log or replay it."
        }
      ],
      structuredContent: value
    };
  }
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value
  };
}

function responseCapacityError(error: unknown): StructuredError | undefined {
  if (!(error instanceof ResponseAllocationUnavailable)) return undefined;
  return StructuredErrorSchema.parse({
    code: "response_capacity_busy",
    message: "Response capacity is busy. Retry this read shortly.",
    retryable: true
  });
}

function checkpointCapacityError(error: unknown): StructuredError | undefined {
  if (typeof error !== "object" || error === null || !("code" in error) || !("constraint" in error))
    return undefined;
  if (error.code === "54000" && error.constraint === "boardagent_audit_transaction_capacity") {
    return StructuredErrorSchema.parse({
      code: "audit_transaction_capacity",
      message:
        "This action exceeds the supported size. Ask the administrator for help; repeating it unchanged will not resolve this.",
      retryable: false
    });
  }
  if (error.code !== "55000" || error.constraint !== "boardagent_audit_checkpoint_capacity")
    return undefined;
  return StructuredErrorSchema.parse({
    code: "audit_checkpoint_capacity",
    message:
      "Audit capacity is full. Retry this request after a signed checkpoint restores capacity.",
    retryable: true
  });
}

function title(name: string): string {
  return name
    .split("_")
    .map((word) => `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}

function toJson(value: unknown): JsonValue {
  return JsonValueSchema.parse(value);
}

function promptTarget(promptName: string): string {
  const targets: Readonly<Record<string, string>> = {
    "onboard-boardagent": "prepare_onboarding_attestation",
    "set-vote": "create_vote",
    "call-meeting": "create_meeting",
    "circulate-document": "circulate_document",
    "record-minutes": "create_minutes_version, then publish_minutes",
    "configure-ruleset": "validate_ruleset_draft, then manage_ruleset",
    "ask-management": "ask_management"
  };
  const target = targets[promptName];
  if (!target) throw new Error(`unregistered BoardAgent prompt target: ${promptName}`);
  return target;
}

function promptGuidance(promptName: string): readonly string[] {
  if (promptName !== "onboard-boardagent") return [];
  return [
    "Explain that BoardAgent has no governance portal: the agent presents entitled canonical records, while the browser page is only the passkey attestation ceremony.",
    "Read the exact current onboarding terms and secretary-support record to the person before proceeding.",
    "Ask how the person wants information presented and whether the agent may keep derived local memory, then explain the person's security, review, refetch, and tombstone responsibilities."
  ];
}

export interface FrozenMcpCompositionOptions {
  readonly service: BoardAgentSurfaceService;
  readonly requestStateKey: Uint8Array | string;
  readonly requestStateTtlSeconds: number;
}

export function createBoardAgentMcpHandler(options: FrozenMcpCompositionOptions): McpHttpHandler {
  const codec = createRequestStateCodec<HumanState>({
    key: options.requestStateKey,
    ttlSeconds: options.requestStateTtlSeconds,
    bind: (ctx) => {
      const actor = principal(ctx);
      return `${ctx.mcpReq.method}\0${actor.organizationId}\0${actor.memberId}\0${actor.clientId}`;
    }
  });

  const factory = async (requestContext: McpRequestContext): Promise<McpServer> => {
    const server = new ResourceObservedMcpServer(
      { name: "BoardAgent", version: "0.0.0-private-beta" },
      {
        supportedProtocolVersions: [MODERN_PROTOCOL, LEGACY_PROTOCOL],
        enforceStrictCapabilities: true,
        instructions:
          "BoardAgent is an MCP-native governance system of record with no governance portal and no server AI. Present entitled canonical information to the person, cite its URI/version/hash, and obtain fresh human confirmation for binding acts.",
        cacheHints: {
          "tools/list": { ttlMs: 0, cacheScope: "private" },
          "prompts/list": { ttlMs: 0, cacheScope: "private" },
          "resources/list": { ttlMs: 0, cacheScope: "private" },
          "resources/read": { ttlMs: 0, cacheScope: "private" },
          "server/discover": { ttlMs: 0, cacheScope: "private" }
        },
        inputRequired: { legacyShim: false, maxRounds: 2, roundTimeoutMs: 600_000 },
        requestState: {
          verify: async (wire, ctx): Promise<VerifiedHumanState> => ({
            ...(await codec.verify(wire, ctx)),
            request_state: wire
          })
        }
      }
    );

    for (const entry of BOARDAGENT_REGISTRY.tools) {
      if (requestContext.era === "legacy" && entry.class !== "R") continue;
      const directWithoutMrtr =
        entry.class === "D" || entry.name === "prepare_onboarding_attestation";
      const inputSchema = toolInputSchema(entry.name) as z.ZodType<JsonValue>;
      server.registerTool(
        entry.name,
        {
          title: title(entry.name),
          description: `${entry.section}. Authority: ${entry.requiredAuthority}. Object rule: ${entry.objectRule}.`,
          inputSchema: memoizeSchemaExports(inputSchema),
          outputSchema: memoizeSchemaExports(resultSchema(entry.name)),
          annotations: {
            readOnlyHint: entry.class === "R",
            destructiveHint: entry.class === "H",
            idempotentHint: true,
            openWorldHint: false
          },
          _meta: {
            "io.boardagent/action-class": entry.class,
            "io.boardagent/registry-digest": BOARDAGENT_REGISTRY_DIGEST
          }
        },
        async (rawInput, ctx) => {
          try {
            const actor = principal(ctx);
            const input = toJson(rawInput);
            if (entry.class === "R") {
              const read = await options.service.executeRead(actor, entry.name, input);
              registerPreparedResource(read, ctx.mcpReq.id);
              currentResponseAllocationOwner()?.assertLive();
              const output = textAndStructured(resultSchema(entry.name).parse(read));
              registerResourceResponse(read, ctx.mcpReq.id, output);
              return output;
            }
            // Onboarding is the frozen pre-governance H exception: MCP creates only a
            // one-use browser stage. The actual attestation requires recent passkey UV.
            if (directWithoutMrtr) {
              return textAndStructured(
                await options.service.executeDirect(actor, entry.name, input)
              );
            }

            const clientCapabilities = capabilities(ctx);
            if (!supportsFormElicitation(clientCapabilities)) {
              throw new MissingRequiredClientCapabilityError({
                requiredCapabilities: { elicitation: { form: {} } }
              });
            }
            const argumentsSha256 = canonicalSha256(input);
            const state = ctx.mcpReq.requestState<VerifiedHumanState>();
            const responseView = inputResponse(ctx.mcpReq.inputResponses, "confirm_action");
            const accepted = acceptedContent(
              ctx.mcpReq.inputResponses,
              "confirm_action",
              ConfirmationInput
            );
            if (state) {
              if (
                state.schema_version !== HUMAN_STATE_SCHEMA_VERSION ||
                state.tool !== entry.name ||
                state.arguments_sha256 !== argumentsSha256
              ) {
                throw new Error("MRTR request does not match the protected BoardAgent stage");
              }
              const responseAction =
                responseView.kind === "elicit" ? responseView.action : "cancel";
              const resolution = await options.service.resolveHumanAction({
                principal: actor,
                tool: entry.name,
                input,
                stage_id: state.stage_id,
                client_capabilities: clientCapabilities,
                request_state: state.request_state,
                retry_request_id: requestIdBytes(ctx),
                response_action: responseAction,
                input_response: accepted ? toJson(accepted) : null
              });
              if (!resolution.confirmed) {
                return {
                  isError: true,
                  content: [{ type: "text", text: resolution.reason }]
                };
              }
              return textAndStructured(resolution.result);
            }

            const completed = await options.service.replayHumanAction?.(actor, entry.name, input);
            if (completed) return textAndStructured(completed);

            const prepared = await options.service.prepareHumanAction(actor, entry.name, input);
            UuidV7Schema.parse(prepared.stage_id);
            Rfc3339UtcSchema.parse(prepared.expires_at);
            const statePayload: HumanState = {
              schema_version: HUMAN_STATE_SCHEMA_VERSION,
              tool: entry.name,
              stage_id: prepared.stage_id,
              arguments_sha256: argumentsSha256
            };
            const requestState = await codec.mint(statePayload, ctx);
            const requestedSchema = {
              type: "object" as const,
              properties: {
                approve: { type: "boolean" as const },
                confirmation_code: {
                  type: "string" as const,
                  minLength: 8,
                  maxLength: 8
                }
              },
              required: ["approve", "confirmation_code"],
              additionalProperties: false
            };
            const form = {
              schema_version: "boardagent.confirmation-form.v1",
              message: confirmationFormMessage(prepared.confirmation_lines),
              requested_schema: requestedSchema
            };
            const resultEnvelope = {
              schema_version: "boardagent.input-required.v1",
              tool: entry.name,
              stage_id: prepared.stage_id,
              form_id: "confirm_action",
              request_state_sha256: canonicalSha256(requestState)
            } as const;
            await options.service.persistHumanStage({
              principal: actor,
              tool: entry.name,
              input,
              prepared,
              client_capabilities: clientCapabilities,
              embedded_form: toJson(form),
              embedded_result: toJson(resultEnvelope),
              request_state: requestState,
              prepared_request_id: requestIdBytes(ctx)
            });
            return inputRequired({
              requestState,
              inputRequests: {
                confirm_action: inputRequired.elicit({
                  message: form.message,
                  requestedSchema: form.requested_schema
                })
              }
            });
          } catch (error) {
            const capacity = responseCapacityError(error) ?? checkpointCapacityError(error);
            if (!capacity) throw error;
            return {
              isError: true,
              content: [{ type: "text" as const, text: JSON.stringify(capacity) }],
              structuredContent: { ...capacity }
            };
          }
        }
      );
    }

    for (const [index, entry] of BOARDAGENT_REGISTRY.resourceTemplates.entries()) {
      server.registerResource(
        `boardagent-resource-${String(index + 1)}`,
        new ResourceTemplate(entry.uriTemplate, { list: undefined }),
        {
          title: entry.uriTemplate,
          description: `Entitlement root: ${entry.entitlementRoot}`,
          mimeType: "application/json",
          cacheHint: { ttlMs: 0, cacheScope: "private" }
        },
        async (uri, _variables, ctx) => {
          const resource = await options.service
            .readResource(principal(ctx), uri)
            .catch((error: unknown) => {
              const capacity = responseCapacityError(error) ?? checkpointCapacityError(error);
              if (capacity) throw new ProtocolError(INTERNAL_ERROR, capacity.message, capacity);
              throw error;
            });
          registerPreparedResource(resource, ctx.mcpReq.id);
          currentResponseAllocationOwner()?.assertLive();
          if (resource.uri !== uri.href) throw new Error("resource service URI binding mismatch");
          if (resource.blob_base64 !== undefined) {
            if (resource.text !== undefined) throw new Error("resource cannot be text and binary");
            const output = {
              contents: [
                { uri: resource.uri, mimeType: resource.media_type, blob: resource.blob_base64 }
              ]
            };
            registerResourceResponse(resource, ctx.mcpReq.id, output);
            return output;
          }
          if (resource.text === undefined) throw new Error("resource body is unavailable");
          const output = {
            contents: [{ uri: resource.uri, mimeType: resource.media_type, text: resource.text }]
          };
          registerResourceResponse(resource, ctx.mcpReq.id, output);
          return output;
        }
      );
    }

    for (const entry of BOARDAGENT_REGISTRY.prompts) {
      server.registerPrompt(
        entry.name,
        {
          title: title(entry.name.replaceAll("-", "_")),
          description: entry.intendedFlow,
          argsSchema: PromptInput
        },
        ({ board_id, draft_id }) => ({
          messages: [
            {
              role: "user",
              content: {
                type: "text",
                text: [
                  `Use BoardAgent's ${entry.name} flow for board ${board_id}.`,
                  `Call ${promptTarget(entry.name)} through the registered strict tools.`,
                  draft_id === null ? "Start a new guided draft." : `Resume draft ${draft_id}.`,
                  ...promptGuidance(entry.name),
                  "Treat BoardAgent canonical data as authoritative; any client-created presentation or memory is derived and must cite current URI/version/hash evidence."
                ].join("\n")
              }
            }
          ]
        })
      );
    }

    return server;
  };

  const base = createMcpHandler(factory, {
    legacy: "stateless",
    responseMode: "json",
    maxSubscriptions: 0,
    keepAliveMs: 0
  });
  const forward = base.fetch.bind(base);
  const humanTools = new Set(
    BOARDAGENT_REGISTRY.tools
      .filter(({ class: actionClass }) => actionClass === "H")
      .map(({ name }) => name)
  );
  const mrtrHumanTools = new Set(
    BOARDAGENT_REGISTRY.tools
      .filter(
        ({ class: actionClass, name }) =>
          actionClass === "H" && name !== "prepare_onboarding_attestation"
      )
      .map(({ name }) => name)
  );
  return {
    ...base,
    fetch: async (request, requestOptions) => {
      const body =
        request.method === "POST"
          ? ((await request
              .clone()
              .json()
              .catch(() => undefined)) as
              | {
                  id?: number | string;
                  method?: string;
                  params?: { name?: string; _meta?: Record<string, unknown> };
                }
              | undefined)
          : undefined;
      const toolName = request.headers.get("mcp-name") ?? body?.params?.name ?? null;
      if (
        body?.method === "tools/call" &&
        toolName !== null &&
        humanTools.has(toolName) &&
        (await isLegacyRequest(request, body))
      ) {
        return Response.json({
          jsonrpc: "2.0",
          id: body.id ?? null,
          error: {
            code: -32602,
            message: "legacy_read_only",
            data: { requiredProtocol: MODERN_PROTOCOL }
          }
        });
      }
      if (
        request.method === "POST" &&
        request.headers.get("mcp-method") === "tools/call" &&
        toolName !== null &&
        mrtrHumanTools.has(toolName)
      ) {
        const clientCapabilities = parseClientCapabilities(
          body?.params?._meta?.[CLIENT_CAPABILITIES_META_KEY] ?? {}
        );
        if (!clientCapabilities.success || !supportsFormElicitation(clientCapabilities.data)) {
          return Response.json(
            {
              jsonrpc: "2.0",
              id: body?.id ?? null,
              error: clientCapabilities.success
                ? {
                    code: -32021,
                    message: "MISSING_REQUIRED_CLIENT_CAPABILITY",
                    data: { requiredCapabilities: { elicitation: { form: {} } } }
                  }
                : { code: -32602, message: "invalid_client_capabilities" }
            },
            { status: 400 }
          );
        }
      }
      return bindResourceDeliveryResponse(await forward(request, requestOptions));
    }
  };
}
