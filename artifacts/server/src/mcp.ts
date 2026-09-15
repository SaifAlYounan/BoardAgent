import { canonicalSha256 } from "@boardagent/contracts";
import {
  McpServer,
  CLIENT_CAPABILITIES_META_KEY,
  MissingRequiredClientCapabilityError,
  acceptedContent,
  createMcpHandler,
  createRequestStateCodec,
  inputRequired,
  inputResponse,
  type AuthInfo,
  type McpHttpHandler,
  type McpRequestContext,
  type ServerContext
} from "@modelcontextprotocol/server";
import { z } from "zod";

import { confirmationFormMessage } from "./confirmation-form-message.js";

import { parseClientCapabilities, supportsFormElicitation } from "./client-capabilities.js";
import type { BoardAgentService } from "./ports.js";

const MODERN_PROTOCOL = "2026-07-28";
const LEGACY_PROTOCOL = "2025-11-25";

const EmptyInput = z.object({}).strict();
const CursorInput = z
  .object({
    updated_since: z.string().regex(/^\d+$/u).nullable().default(null),
    limit: z.number().int().min(1).max(500).default(100)
  })
  .strict();
const ListDocumentsInput = CursorInput.extend({ board_id: z.uuid() }).strict();
const StageBallotInput = z
  .object({
    vote_id: z.uuid(),
    choice: z.enum(["yes", "no", "abstain"]),
    statement: z.string().max(16_384).nullable().default(null)
  })
  .strict();
const ConfirmationInput = z
  .object({ approve: z.boolean(), confirmation_code: z.string().length(8) })
  .strict();

const WhoamiOutput = z
  .object({
    memberId: z.string(),
    displayName: z.string(),
    roles: z.array(z.string()),
    scopes: z.array(z.string()),
    boardIds: z.array(z.string()),
    onboardingCurrent: z.boolean(),
    secretaryContact: z.object({ name: z.string(), contactText: z.string() }).strict()
  })
  .strict();

interface ProtectedBallotState {
  readonly kind: "ballot";
  readonly stageId: string;
  readonly requestHash: string;
  readonly canonicalResolutionSha256: string;
}

function auth(ctx: ServerContext): { memberId: string; clientId: string; tokenJti: string } {
  const info = ctx.http?.authInfo;
  const memberId = info?.extra?.memberId;
  const tokenJti = info?.extra?.jti;
  if (!info || typeof memberId !== "string" || typeof tokenJti !== "string" || !info.clientId) {
    throw new Error("authenticated member context required");
  }
  return { memberId, clientId: info.clientId, tokenJti };
}

function textAndStructured<T>(value: T): {
  content: [{ type: "text"; text: string }];
  structuredContent: T;
} {
  return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value };
}

export interface McpCompositionOptions {
  readonly service: BoardAgentService;
  readonly requestStateKey: Uint8Array | string;
  readonly requestStateTtlSeconds: number;
}

/** @deprecated Historical four-tool spike retained only as a protocol regression fixture. */
export function createBoardAgentPrototypeMcpHandler(
  options: McpCompositionOptions
): McpHttpHandler {
  const codec = createRequestStateCodec<ProtectedBallotState>({
    key: options.requestStateKey,
    ttlSeconds: options.requestStateTtlSeconds,
    bind: (ctx) => {
      const info = ctx.http?.authInfo;
      const memberId = info?.extra?.memberId;
      if (!info || typeof memberId !== "string" || !info.clientId)
        throw new Error("missing MRTR identity binding");
      return `${ctx.mcpReq.method}\0${memberId}\0${info.clientId}`;
    }
  });

  const factory = async (requestContext: McpRequestContext): Promise<McpServer> => {
    const server = new McpServer(
      { name: "BoardAgent", version: "0.0.0-private-beta" },
      {
        supportedProtocolVersions: [MODERN_PROTOCOL, LEGACY_PROTOCOL],
        enforceStrictCapabilities: true,
        instructions:
          "BoardAgent is an agent-native governance system of record. Present entitled information to your principal in their preferred form. The principal and agent are responsible for review and agent security. No governance UI exists.",
        cacheHints: {
          "tools/list": { ttlMs: 0, cacheScope: "private" },
          "resources/list": { ttlMs: 0, cacheScope: "private" },
          "resources/read": { ttlMs: 0, cacheScope: "private" },
          "server/discover": { ttlMs: 0, cacheScope: "private" }
        },
        inputRequired: { legacyShim: false, maxRounds: 2, roundTimeoutMs: 600_000 },
        requestState: { verify: codec.verify }
      }
    );

    server.registerTool(
      "whoami",
      {
        title: "Who am I in BoardAgent?",
        description:
          "Return the authenticated person's role, boards, scopes, onboarding state, and secretary contact.",
        inputSchema: EmptyInput,
        outputSchema: WhoamiOutput,
        annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
      },
      async (_input, ctx) => {
        const principal = auth(ctx);
        return textAndStructured(await options.service.whoami(principal.memberId));
      }
    );

    server.registerTool(
      "list_pending_actions",
      {
        title: "List my pending BoardAgent actions",
        description: "One-call entitlement-filtered briefing with a monotonic delta cursor.",
        inputSchema: CursorInput,
        outputSchema: z.array(
          z
            .object({
              sequence: z.string(),
              kind: z.string(),
              objectId: z.string(),
              title: z.string(),
              occurredAt: z.string(),
              dueAt: z.string().nullable(),
              resourceUri: z.string()
            })
            .strict()
        ),
        annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
      },
      async (input, ctx) => {
        const principal = auth(ctx);
        return textAndStructured(
          await options.service.listPendingActions(
            principal.memberId,
            input.updated_since,
            input.limit
          )
        );
      }
    );

    server.registerTool(
      "list_documents",
      {
        title: "List entitled BoardAgent documents",
        description: "List only documents visible after ACL and live-recusal filtering.",
        inputSchema: ListDocumentsInput,
        outputSchema: z.array(
          z
            .object({
              documentId: z.string(),
              versionId: z.string(),
              boardId: z.string(),
              title: z.string(),
              mediaType: z.enum([
                "application/json",
                "text/markdown; charset=utf-8",
                "text/plain; charset=utf-8"
              ]),
              sha256: z.string().regex(/^[0-9a-f]{64}$/u),
              byteLength: z.number().int().nonnegative(),
              resourceUri: z.string()
            })
            .strict()
        ),
        annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
      },
      async (input, ctx) => {
        const principal = auth(ctx);
        return textAndStructured(
          await options.service.listDocuments(
            principal.memberId,
            input.board_id,
            input.updated_since,
            input.limit
          )
        );
      }
    );

    if (requestContext.era === "modern") {
      server.registerTool(
        "stage_ballot",
        {
          title: "Stage and confirm a ballot",
          description:
            "Stage a ballot, display server-canonical resolution text, and require exact fresh MRTR confirmation.",
          inputSchema: StageBallotInput,
          outputSchema: z
            .object({
              ballotId: z.string(),
              voteId: z.string(),
              principalMemberId: z.string(),
              casterMemberId: z.string(),
              certificateResourceUri: z.string(),
              auditSequence: z.string()
            })
            .strict(),
          annotations: { destructiveHint: true, idempotentHint: true, openWorldHint: false }
        },
        async (input, ctx) => {
          const principal = auth(ctx);
          const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined;
          // Form-mode elicitation per the MCP capability rules (shared predicate): `form`
          // declared, or the spec's backwards-compatible empty `elicitation` object.
          const capabilities = parseClientCapabilities(
            envelope?.[CLIENT_CAPABILITIES_META_KEY] ?? {}
          );
          if (!capabilities.success || !supportsFormElicitation(capabilities.data)) {
            throw new MissingRequiredClientCapabilityError({
              requiredCapabilities: { elicitation: { form: {} } }
            });
          }
          const requestHash = canonicalSha256(input);
          const state = ctx.mcpReq.requestState<ProtectedBallotState>();
          const response = inputResponse(ctx.mcpReq.inputResponses, "confirm_ballot");
          const accepted = acceptedContent(
            ctx.mcpReq.inputResponses,
            "confirm_ballot",
            ConfirmationInput
          );
          if (state) {
            if (state.kind !== "ballot" || state.requestHash !== requestHash)
              throw new Error("MRTR request mismatch");
            if (
              response.kind !== "elicit" ||
              response.action !== "accept" ||
              !accepted ||
              !accepted.approve
            ) {
              await options.service.rejectBallotStage({
                ...principal,
                stageId: state.stageId,
                reason:
                  response.kind === "elicit" && response.action === "decline"
                    ? "declined"
                    : response.kind === "elicit" && response.action === "cancel"
                      ? "cancelled"
                      : "invalid_response"
              });
              return {
                isError: true,
                content: [{ type: "text", text: "consent_rejected" }]
              };
            }
            const confirmed = await options.service.confirmBallot({
              ...principal,
              stageId: state.stageId,
              confirmationCode: accepted.confirmation_code,
              requestHash,
              canonicalResolutionSha256: state.canonicalResolutionSha256
            });
            return textAndStructured(confirmed);
          }
          const stage = await options.service.stageBallot({
            ...principal,
            voteId: input.vote_id,
            choice: input.choice,
            statement: input.statement,
            requestHash
          });
          const requestState = await codec.mint(
            {
              kind: "ballot",
              stageId: stage.stageId,
              requestHash,
              canonicalResolutionSha256: stage.canonicalResolutionSha256
            },
            ctx
          );
          return inputRequired({
            requestState,
            inputRequests: {
              confirm_ballot: inputRequired.elicit({
                message: confirmationFormMessage([
                  `BoardAgent canonical vote confirmation`,
                  `Vote: ${stage.voteTitle} (${stage.voteId})`,
                  `Member: ${stage.memberName}`,
                  `Choice: ${stage.choice}`,
                  `Statement: ${stage.statement ?? "(none)"}`,
                  `Resolution SHA-256: ${stage.canonicalResolutionSha256}`,
                  `Resolution text:`,
                  stage.canonicalResolutionText,
                  `Confirmation code: ${stage.confirmationCode}`,
                  `Expires: ${stage.expiresAt}`
                ]),
                requestedSchema: {
                  type: "object",
                  properties: {
                    approve: { type: "boolean" },
                    confirmation_code: { type: "string", minLength: 8, maxLength: 8 }
                  },
                  required: ["approve", "confirmation_code"]
                }
              })
            }
          });
        }
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
  return {
    ...base,
    fetch: async (request, requestOptions) => {
      if (
        request.method === "POST" &&
        request.headers.get("mcp-method") === "tools/call" &&
        request.headers.get("mcp-name") === "stage_ballot"
      ) {
        const body = (await request
          .clone()
          .json()
          .catch(() => undefined)) as
          { id?: number | string; params?: { _meta?: Record<string, unknown> } } | undefined;
        const capabilities = parseClientCapabilities(
          body?.params?._meta?.[CLIENT_CAPABILITIES_META_KEY] ?? {}
        );
        if (!capabilities.success || !supportsFormElicitation(capabilities.data)) {
          return Response.json(
            {
              jsonrpc: "2.0",
              id: body?.id ?? null,
              error: {
                code: -32021,
                message: "MISSING_REQUIRED_CLIENT_CAPABILITY",
                data: { requiredCapabilities: { elicitation: { form: {} } } }
              }
            },
            { status: 400 }
          );
        }
      }
      return base.fetch(request, requestOptions);
    }
  };
}

export function assertMcpAudience(authInfo: AuthInfo, canonicalResourceUri: string): void {
  if (authInfo.resource?.toString().replace(/\/$/u, "") !== canonicalResourceUri) {
    throw new Error("MCP token audience/resource mismatch");
  }
}
