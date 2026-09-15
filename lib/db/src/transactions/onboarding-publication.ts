import type { PoolClient } from "pg";
import { z } from "zod";
import {
  canonicalJson,
  canonicalSha256,
  sha256Hex,
  toolInputSchema,
  UuidV7Schema,
  Sha256HexSchema,
  type JsonValue
} from "@boardagent/contracts";
import {
  stageActionInTransaction,
  confirmStagedActionInTransaction,
  type StageActionInput,
  type ConfirmStagedActionInput
} from "./consent.js";
import { readRequestContext } from "./request-context.js";

export type OnboardingPublicationTool = "publish_secretary_support" | "publish_onboarding_terms";
export function isOnboardingPublicationTool(tool: string): tool is OnboardingPublicationTool {
  return tool === "publish_secretary_support" || tool === "publish_onboarding_terms";
}
const SnapshotSchema = z
  .object({
    schemaVersion: z.literal("boardagent.onboarding-publication.v1"),
    tool: z.enum(["publish_secretary_support", "publish_onboarding_terms"]),
    request: z.record(z.string(), z.json()),
    boardId: UuidV7Schema.nullable(),
    targetType: z.enum(["secretary_support_version", "onboarding_terms_version"]),
    version: z.number().int().positive(),
    initialAdministrativeSetup: z.boolean(),
    previousVersionId: UuidV7Schema.nullable(),
    previousSha256: Sha256HexSchema.nullable()
  })
  .strict();
export async function prepareOnboardingPublicationInTransaction(
  client: PoolClient,
  tool: OnboardingPublicationTool,
  input: unknown
) {
  const request = toolInputSchema(tool).parse(input) as Readonly<Record<string, JsonValue>>;
  const result = await client.query<{ snapshot: unknown }>(
    "select boardagent_prepare_onboarding_publication($1,$2::jsonb) as snapshot",
    [tool, request]
  );
  const snapshot = SnapshotSchema.parse(result.rows[0]?.snapshot);
  const targetId = UuidV7Schema.parse(request["version_id"]);
  if (
    snapshot.tool !== tool ||
    (tool === "publish_secretary_support") !== (snapshot.boardId !== null) ||
    (tool === "publish_secretary_support") !== (snapshot.targetType === "secretary_support_version")
  )
    throw new Error("onboarding publication snapshot mismatch");
  const canonicalContent =
    tool === "publish_secretary_support"
      ? canonicalJson({
          schemaVersion: "boardagent.secretary-support.v1",
          boardId: snapshot.boardId,
          version: snapshot.version,
          supportName: request["support_name"]!,
          contactMethods: request["contact_methods"]!
        })
      : z.string().parse(request["canonical_text"]);
  const contentSha256 = sha256Hex(canonicalContent);
  const canonicalPayload = { ...snapshot, canonicalContent, contentSha256 } satisfies JsonValue;
  return {
    actionCode: tool,
    boardId: snapshot.boardId,
    targetType: snapshot.targetType,
    targetId,
    canonicalSchema: snapshot.schemaVersion,
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    packageSha256: null,
    version: snapshot.version,
    contentSha256,
    request
  } as const;
}
export async function stageOnboardingPublicationInTransaction(
  client: PoolClient,
  input: {
    readonly tool: OnboardingPublicationTool;
    readonly request: JsonValue;
    readonly stage: Omit<
      StageActionInput,
      | "boardId"
      | "actingForMemberId"
      | "actionCode"
      | "targetType"
      | "targetId"
      | "canonicalSchema"
      | "canonicalPayload"
      | "packageSha256"
      | "originalName"
    >;
    readonly expectedPayloadSha256: string;
  }
) {
  const prepared = await prepareOnboardingPublicationInTransaction(
    client,
    input.tool,
    input.request
  );
  if (prepared.payloadSha256 !== input.expectedPayloadSha256)
    throw new Error("onboarding publication changed before presentation was persisted");
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: null,
      originalName: input.tool
    },
    async () => {}
  );
  return {
    ...staged,
    boardId: prepared.boardId,
    targetType: prepared.targetType,
    targetId: prepared.targetId
  };
}
export async function confirmOnboardingPublicationInTransaction(
  client: PoolClient,
  input: {
    readonly tool: OnboardingPublicationTool;
    readonly request: JsonValue;
    readonly confirmation: ConfirmStagedActionInput;
    readonly auditEventId: string;
  }
) {
  let prepared: Awaited<ReturnType<typeof prepareOnboardingPublicationInTransaction>> | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (c) => {
      prepared = await prepareOnboardingPublicationInTransaction(c, input.tool, input.request);
      return { payloadSha256: prepared.payloadSha256, packageSha256: null };
    },
    async (c, consentRecordId) => {
      if (!prepared) throw new Error("onboarding publication preparation unavailable");
      const p = prepared;
      const context = await readRequestContext(c);
      return {
        value: {
          versionId: p.targetId,
          version: p.version,
          contentSha256: p.contentSha256,
          boardId: p.boardId,
          reattestationRequired: true
        },
        auditEvents: [
          {
            organizationId: context.organizationId,
            consentRecordId,
            objectVersion: BigInt(p.version),
            event: {
              eventId: UuidV7Schema.parse(input.auditEventId),
              eventType:
                input.tool === "publish_secretary_support"
                  ? ("secretary_support_published" as const)
                  : ("onboarding_terms_published" as const),
              actorMemberId: context.memberId,
              actorClientId: context.clientId,
              tokenJti: context.tokenJti,
              boardId: p.boardId,
              entityType: p.targetType,
              entityId: p.targetId,
              origin: "mcp" as const,
              schemaVersion: 1 as const,
              details: {
                version: p.version,
                previousVersionId: p.canonicalPayload.previousVersionId,
                contentSha256: p.contentSha256,
                payloadSha256: p.payloadSha256,
                reason: p.request["reason"]!
              }
            }
          }
        ],
        finalizeAfterAudit: async (finalClient: PoolClient) => {
          await finalClient.query("select boardagent_apply_onboarding_publication($1,$2)", [
            consentRecordId,
            input.auditEventId
          ]);
        }
      };
    },
    { exposeConfirmedProjectionToAct: true, appendConsentBeforeAct: true }
  );
}
