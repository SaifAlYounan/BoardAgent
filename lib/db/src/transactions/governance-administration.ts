import type { PoolClient } from "pg";
import { z } from "zod";

import type { AuditEventType } from "@boardagent/audit";
import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  type JsonValue
} from "@boardagent/contracts";
import {
  GovernanceProfileSchema,
  RulesetVersionSchema,
  governanceProfileSha256,
  type GovernanceProfile,
  type RulesetVersion
} from "@boardagent/ruleset";

import type { AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext } from "./request-context.js";

const SnapshotSchema = z.record(z.string(), z.json());
const BoardSlugSchema = z
  .string()
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u)
  .max(80);
const PositiveRowVersionSchema = z.number().int().positive().safe();
const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.boolean(),
    z.null(),
    z.number().finite(),
    z.string(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);

const SurfaceCitationSchema = z
  .object({
    documentVersionId: UuidV7Schema,
    sourceDocumentSha256: Sha256HexSchema,
    clause: z.string().min(1).max(512),
    locator: z.string().min(1).max(1024)
  })
  .strict();
export type SurfaceGovernanceCitation = z.infer<typeof SurfaceCitationSchema>;

const SeatMaterialSchema = z
  .object({
    id: UuidV7Schema,
    seatClass: z.enum(["voting_member", "management", "observer"]),
    minimumWeight: z.string().regex(/^(?:0|[1-9]\d*)$/u),
    maximumWeight: z.string().regex(/^(?:0|[1-9]\d*)$/u),
    canonicalSha256: Sha256HexSchema
  })
  .strict();

const TemplateMaterialSchema = z
  .object({
    templateId: UuidV7Schema,
    approvalRuleId: UuidV7Schema,
    approvalRuleSha256: Sha256HexSchema,
    templateSha256: Sha256HexSchema
  })
  .strict();

const CitationMaterialSchema = z
  .object({
    id: UuidV7Schema,
    ruleTemplateId: UuidV7Schema.nullable(),
    citation: SurfaceCitationSchema
  })
  .strict();

const MatterTypeMaterialSchema = z
  .object({
    id: UuidV7Schema,
    code: z.string().regex(/^[a-z][a-z0-9_]{0,127}$/u),
    schemaSha256: Sha256HexSchema
  })
  .strict();

const RuleMaterialSchema = z
  .object({ ruleId: UuidV7Schema, canonicalSha256: Sha256HexSchema })
  .strict();

const RuleCitationMaterialSchema = z
  .object({ id: UuidV7Schema, ruleId: UuidV7Schema, citation: SurfaceCitationSchema })
  .strict();

const GovernanceRequestSchema = z.discriminatedUnion("actionCode", [
  z
    .object({
      actionCode: z.literal("create_board"),
      boardId: UuidV7Schema,
      slug: BoardSlugSchema,
      name: z.string().min(1).max(512),
      timezone: z.string().min(1).max(128),
      initialSettings: JsonValueSchema,
      secretaryMemberId: UuidV7Schema,
      boardVersionId: UuidV7Schema,
      boardVersionSha256: Sha256HexSchema
    })
    .strict(),
  z
    .object({
      actionCode: z.literal("update_board"),
      boardId: UuidV7Schema,
      expectedRowVersion: PositiveRowVersionSchema,
      name: z.string().min(1).max(512),
      timezone: z.string().min(1).max(128),
      settings: JsonValueSchema,
      reason: z.string().min(1).max(65_536),
      boardVersionId: UuidV7Schema,
      boardVersionSha256: Sha256HexSchema
    })
    .strict(),
  z
    .object({
      actionCode: z.literal("archive_board"),
      boardId: UuidV7Schema,
      reason: z.string().min(1).max(65_536)
    })
    .strict(),
  z
    .object({
      actionCode: z.literal("configure_board_governance"),
      boardId: UuidV7Schema,
      expectedProfileId: UuidV7Schema.nullable(),
      profile: GovernanceProfileSchema,
      profileSha256: Sha256HexSchema,
      citations: z.array(SurfaceCitationSchema).min(1).max(1024),
      seatMaterial: z.array(SeatMaterialSchema).min(1).max(3),
      templateMaterial: z.array(TemplateMaterialSchema).min(1).max(1_000),
      citationMaterial: z.array(CitationMaterialSchema).min(1).max(64_256),
      reason: z.string().min(1).max(65_536)
    })
    .strict(),
  z
    .object({
      actionCode: z.literal("manage_ruleset"),
      boardId: UuidV7Schema,
      expectedRulesetId: UuidV7Schema.nullable(),
      ruleset: RulesetVersionSchema,
      rulesetSha256: Sha256HexSchema,
      citations: z.array(SurfaceCitationSchema).min(1).max(10_240),
      matterTypeMaterial: z.array(MatterTypeMaterialSchema).min(1).max(1_000),
      ruleMaterial: z.array(RuleMaterialSchema).min(1).max(10_000),
      citationMaterial: z.array(RuleCitationMaterialSchema).min(1).max(640_000),
      reason: z.string().min(1).max(65_536)
    })
    .strict()
]);

export type GovernanceAdministrationRequest = z.infer<typeof GovernanceRequestSchema>;

const CanonicalPayloadSchema = z
  .object({
    schemaVersion: z.literal("boardagent.governance-administration.v1"),
    actionCode: z.enum([
      "create_board",
      "update_board",
      "archive_board",
      "configure_board_governance",
      "manage_ruleset"
    ]),
    targetType: z.enum(["board", "governance_profile", "ruleset"]),
    targetId: UuidV7Schema,
    boardId: UuidV7Schema,
    request: GovernanceRequestSchema,
    current: SnapshotSchema
  })
  .strict();

export interface PreparedGovernanceAdministrationAction {
  readonly actionCode: GovernanceAdministrationRequest["actionCode"];
  readonly boardId: string;
  readonly targetType: "board" | "governance_profile" | "ruleset";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.governance-administration.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string | null;
}

export interface GovernanceAdministrationStageInput {
  readonly prepared: PreparedGovernanceAdministrationAction;
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
}

export interface GovernanceAdministrationConfirmationInput {
  readonly confirmation: ConfirmStagedActionInput;
  readonly auditEventId: string;
}

export interface GovernanceAdministrationResult {
  readonly actionCode: GovernanceAdministrationRequest["actionCode"];
  readonly targetType: PreparedGovernanceAdministrationAction["targetType"];
  readonly targetId: string;
  readonly boardId: string;
  readonly data: JsonValue;
}

export class GovernanceAdministrationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "GovernanceAdministrationError";
  }
}

function bounded(value: string, label: string, maximum: number): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > maximum) {
    throw new RangeError(`${label} must contain 1 through ${String(maximum)} characters`);
  }
  return normalized;
}

function validTimezone(value: string): string {
  const timezone = bounded(value, "board timezone", 128);
  try {
    new Intl.DateTimeFormat("en", { timeZone: timezone }).format(new Date(0));
  } catch {
    throw new TypeError("board timezone must be an IANA time zone");
  }
  return timezone;
}

function uniqueIds(
  values: readonly string[],
  label: string
): readonly z.infer<typeof UuidV7Schema>[] {
  const ids = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(ids).size !== ids.length) {
    throw new GovernanceAdministrationError(`${label} must be globally unique`);
  }
  return ids;
}

function citationKey(citation: SurfaceGovernanceCitation): string {
  return canonicalSha256(citation);
}

function normalizeCitation(value: SurfaceGovernanceCitation): SurfaceGovernanceCitation {
  const citation = SurfaceCitationSchema.parse(value);
  return {
    ...citation,
    clause: bounded(citation.clause, "governance citation clause", 512),
    locator: bounded(citation.locator, "governance citation locator", 1024)
  };
}

function normalizeCitations(values: readonly SurfaceGovernanceCitation[]) {
  const citations = values.map(normalizeCitation);
  const keys = citations.map(citationKey);
  if (new Set(keys).size !== keys.length) {
    throw new GovernanceAdministrationError("governance citations must be unique");
  }
  return citations.toSorted((left, right) => citationKey(left).localeCompare(citationKey(right)));
}

function embeddedProfileCitations(profile: GovernanceProfile): SurfaceGovernanceCitation[] {
  return [
    ...profile.sourceAgreements.map((citation) => ({
      documentVersionId: citation.sourceDocumentVersionId,
      sourceDocumentSha256: citation.sourceDocumentSha256,
      clause: citation.clause,
      locator: citation.locator
    })),
    ...profile.templates.flatMap((template) =>
      template.citations.map((citation) => ({
        documentVersionId: citation.sourceDocumentVersionId,
        sourceDocumentSha256: citation.sourceDocumentSha256,
        clause: citation.clause,
        locator: citation.locator
      }))
    )
  ];
}

function embeddedRulesetCitations(ruleset: RulesetVersion): SurfaceGovernanceCitation[] {
  return ruleset.rules.flatMap((rule) =>
    rule.citations.map((citation) => ({
      documentVersionId: citation.sourceDocumentVersionId,
      sourceDocumentSha256: citation.sourceDocumentSha256,
      clause: citation.clause,
      locator: citation.locator
    }))
  );
}

function assertCitationClosure(
  submitted: readonly SurfaceGovernanceCitation[],
  embedded: readonly SurfaceGovernanceCitation[]
): void {
  const submittedKeys = normalizeCitations(submitted).map(citationKey);
  // One clause may support several templates/rules. The submitted evidence list
  // binds its distinct sources; the canonical payload retains every relationship.
  const embeddedKeys = [
    ...new Set(embedded.map((citation) => citationKey(normalizeCitation(citation))))
  ].toSorted();
  if (
    submittedKeys.length !== embeddedKeys.length ||
    submittedKeys.some((value, index) => value !== embeddedKeys[index])
  ) {
    throw new GovernanceAdministrationError(
      "submitted citations must exactly match the canonical governance payload"
    );
  }
}

function target(request: GovernanceAdministrationRequest): {
  readonly type: PreparedGovernanceAdministrationAction["targetType"];
  readonly id: string;
} {
  switch (request.actionCode) {
    case "create_board":
    case "update_board":
    case "archive_board":
      return { type: "board", id: request.boardId };
    case "configure_board_governance":
      return { type: "governance_profile", id: request.profile.id };
    case "manage_ruleset":
      return { type: "ruleset", id: request.ruleset.id };
  }
}

function boardVersionPayload(
  request: Extract<
    GovernanceAdministrationRequest,
    { readonly actionCode: "create_board" | "update_board" }
  >
): JsonValue {
  return {
    schemaVersion: "boardagent.board.v1",
    boardId: request.boardId,
    slug: request.actionCode === "create_board" ? request.slug : null,
    name: request.name,
    timezone: request.timezone,
    settings: request.actionCode === "create_board" ? request.initialSettings : request.settings,
    secretaryMemberId: request.actionCode === "create_board" ? request.secretaryMemberId : null
  };
}

export function normalizeGovernanceAdministrationRequest(
  rawRequest: GovernanceAdministrationRequest
): GovernanceAdministrationRequest {
  const request = GovernanceRequestSchema.parse(rawRequest);
  switch (request.actionCode) {
    case "create_board": {
      const created = {
        ...request,
        slug: BoardSlugSchema.parse(request.slug),
        name: bounded(request.name, "board name", 512),
        timezone: validTimezone(request.timezone)
      };
      if (
        !safeHashEqual(created.boardVersionSha256, canonicalSha256(boardVersionPayload(created)))
      ) {
        throw new GovernanceAdministrationError("initial board version hash is invalid");
      }
      return created;
    }
    case "update_board": {
      const updated = {
        ...request,
        name: bounded(request.name, "board name", 512),
        timezone: validTimezone(request.timezone),
        reason: bounded(request.reason, "board amendment reason", 65_536)
      };
      if (
        !safeHashEqual(updated.boardVersionSha256, canonicalSha256(boardVersionPayload(updated)))
      ) {
        throw new GovernanceAdministrationError("board amendment version hash is invalid");
      }
      return updated;
    }
    case "archive_board":
      return {
        ...request,
        reason: bounded(request.reason, "board archival reason", 65_536)
      };
    case "configure_board_governance": {
      const profile = GovernanceProfileSchema.parse(request.profile);
      if (profile.boardId !== request.boardId) {
        throw new GovernanceAdministrationError("governance profile board does not match target");
      }
      if (!safeHashEqual(governanceProfileSha256(profile), request.profileSha256)) {
        throw new GovernanceAdministrationError("governance profile hash is invalid");
      }
      assertCitationClosure(request.citations, embeddedProfileCitations(profile));
      const ids = uniqueIds(
        [
          profile.id,
          ...request.seatMaterial.map(({ id }) => id),
          ...request.templateMaterial.flatMap(({ templateId, approvalRuleId }) => [
            templateId,
            approvalRuleId
          ]),
          ...request.citationMaterial.map(({ id }) => id)
        ],
        "governance material IDs"
      );
      if (ids.length < 1) throw new Error("governance material is unavailable");
      return {
        ...request,
        reason: bounded(request.reason, "governance profile amendment reason", 65_536)
      };
    }
    case "manage_ruleset": {
      const ruleset = RulesetVersionSchema.parse(request.ruleset);
      if (ruleset.boardId !== request.boardId) {
        throw new GovernanceAdministrationError("ruleset board does not match target");
      }
      const { canonicalHash: suppliedHash, ...hashPayload } = ruleset;
      if (
        !safeHashEqual(canonicalSha256(hashPayload as JsonValue), request.rulesetSha256) ||
        !safeHashEqual(suppliedHash, request.rulesetSha256)
      ) {
        throw new GovernanceAdministrationError("ruleset canonical hash is invalid");
      }
      assertCitationClosure(request.citations, embeddedRulesetCitations(ruleset));
      uniqueIds(
        [
          ruleset.id,
          ...request.matterTypeMaterial.map(({ id }) => id),
          ...request.ruleMaterial.map(({ ruleId }) => ruleId),
          ...request.citationMaterial.map(({ id }) => id)
        ],
        "ruleset material IDs"
      );
      return {
        ...request,
        reason: bounded(request.reason, "ruleset amendment reason", 65_536)
      };
    }
  }
}

async function currentSnapshot(
  client: PoolClient,
  request: GovernanceAdministrationRequest
): Promise<JsonValue> {
  const result = await client.query<{ snapshot: unknown }>(
    "select boardagent_governance_admin_snapshot($1,$2,$3::jsonb) as snapshot",
    [request.actionCode, request.boardId, request]
  );
  return SnapshotSchema.parse(result.rows[0]?.snapshot) as JsonValue;
}

function preparedFromPayload(payloadInput: unknown): PreparedGovernanceAdministrationAction {
  const payload = CanonicalPayloadSchema.parse(payloadInput);
  const request = normalizeGovernanceAdministrationRequest(payload.request);
  const actionTarget = target(request);
  if (
    payload.actionCode !== request.actionCode ||
    payload.boardId !== request.boardId ||
    payload.targetType !== actionTarget.type ||
    payload.targetId !== actionTarget.id
  ) {
    throw new GovernanceAdministrationError("governance action target binding is invalid");
  }
  const canonicalPayload = payload as JsonValue;
  return {
    actionCode: request.actionCode,
    boardId: request.boardId,
    targetType: actionTarget.type,
    targetId: actionTarget.id,
    canonicalSchema: "boardagent.governance-administration.v1",
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    packageSha256:
      request.actionCode === "configure_board_governance"
        ? request.profileSha256
        : request.actionCode === "manage_ruleset"
          ? request.rulesetSha256
          : null
  };
}

export async function prepareGovernanceAdministrationActionInTransaction(
  client: PoolClient,
  rawRequest: GovernanceAdministrationRequest
): Promise<PreparedGovernanceAdministrationAction> {
  const request = normalizeGovernanceAdministrationRequest(rawRequest);
  const actionTarget = target(request);
  const current = await currentSnapshot(client, request);
  return preparedFromPayload({
    schemaVersion: "boardagent.governance-administration.v1",
    actionCode: request.actionCode,
    targetType: actionTarget.type,
    targetId: actionTarget.id,
    boardId: request.boardId,
    request,
    current
  });
}

async function revalidatePrepared(
  client: PoolClient,
  input: PreparedGovernanceAdministrationAction
): Promise<PreparedGovernanceAdministrationAction> {
  const prepared = preparedFromPayload(input.canonicalPayload);
  if (
    prepared.actionCode !== input.actionCode ||
    prepared.boardId !== input.boardId ||
    prepared.targetType !== input.targetType ||
    prepared.targetId !== input.targetId ||
    input.canonicalSchema !== prepared.canonicalSchema ||
    !safeHashEqual(prepared.payloadSha256, input.payloadSha256) ||
    input.packageSha256 !== prepared.packageSha256
  ) {
    throw new GovernanceAdministrationError("prepared governance action changed after rendering");
  }
  const payload = CanonicalPayloadSchema.parse(prepared.canonicalPayload);
  const live = await currentSnapshot(client, payload.request);
  if (!safeHashEqual(canonicalSha256(live), canonicalSha256(payload.current))) {
    throw new GovernanceAdministrationError("governance authority or aggregate changed");
  }
  return prepared;
}

export async function stageGovernanceAdministrationActionInTransaction(
  client: PoolClient,
  input: GovernanceAdministrationStageInput
): Promise<StagedAction & PreparedGovernanceAdministrationAction> {
  const prepared = await revalidatePrepared(client, input.prepared);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      // A board does not exist yet while create_board is staged, so the generic
      // stage row cannot satisfy its board foreign key or board-scoped RLS. The
      // exact future board remains bound in targetId and canonicalPayload; all
      // other governance acts retain their existing board scope on the stage.
      boardId: prepared.actionCode === "create_board" ? null : prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => undefined
  );
  return { ...prepared, ...staged, packageSha256: staged.packageSha256 };
}

function auditType(action: GovernanceAdministrationRequest["actionCode"]): AuditEventType {
  switch (action) {
    case "create_board":
      return "board_created";
    case "update_board":
      return "board_amended";
    case "archive_board":
      return "board_archived";
    case "configure_board_governance":
      return "governance_profile_activated";
    case "manage_ruleset":
      return "ruleset_amended";
  }
}

export async function confirmGovernanceAdministrationActionInTransaction(
  client: PoolClient,
  input: GovernanceAdministrationConfirmationInput
): Promise<StagedActionResolution<GovernanceAdministrationResult>> {
  let prepared: PreparedGovernanceAdministrationAction | undefined;
  let payload: z.infer<typeof CanonicalPayloadSchema> | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      const stage = await requestClient.query<{ canonical_payload: Buffer }>(
        "select canonical_payload from action_stages where id=$1",
        [input.confirmation.stageId]
      );
      const bytes = stage.rows[0]?.canonical_payload;
      if (!bytes) throw new GovernanceAdministrationError("governance stage is unavailable");
      let rawPayload: unknown;
      try {
        rawPayload = JSON.parse(bytes.toString("utf8"));
      } catch {
        throw new GovernanceAdministrationError("governance stage payload is invalid");
      }
      prepared = await revalidatePrepared(requestClient, preparedFromPayload(rawPayload));
      payload = CanonicalPayloadSchema.parse(prepared.canonicalPayload);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared || !payload) {
        throw new Error("governance administration preparation is unavailable");
      }
      const context = await readRequestContext(requestClient);
      const applied = await requestClient.query<{ result: unknown }>(
        `select boardagent_apply_governance_admin_action($1,$2,$3::jsonb,$4,$5) as result`,
        [
          prepared.actionCode,
          prepared.boardId,
          payload,
          Buffer.from(prepared.payloadSha256, "hex"),
          consentRecordId
        ]
      );
      const data = SnapshotSchema.parse(applied.rows[0]?.result) as JsonValue;
      const auditEvents: AuditAppendInput[] = [
        {
          organizationId: context.organizationId,
          consentRecordId,
          event: {
            eventId: UuidV7Schema.parse(input.auditEventId),
            eventType: auditType(prepared.actionCode),
            actorMemberId: context.memberId,
            actorClientId: context.clientId,
            tokenJti: context.tokenJti,
            entityType: prepared.targetType,
            entityId: prepared.targetId,
            // create_board is organization-scoped authority and creates no seat.
            // Keep its audit row organization-scoped as well; the immutable
            // entityId/details still identify the newly created board exactly.
            boardId: prepared.actionCode === "create_board" ? null : prepared.boardId,
            origin: "mcp",
            details: {
              actionCode: prepared.actionCode,
              payloadSha256: prepared.payloadSha256,
              packageSha256: prepared.packageSha256,
              resultSha256: canonicalSha256(data)
            },
            schemaVersion: 1
          }
        }
      ];
      return {
        value: {
          actionCode: prepared.actionCode,
          targetType: prepared.targetType,
          targetId: prepared.targetId,
          boardId: prepared.boardId,
          data
        },
        auditEvents
      };
    }
  );
}

export function buildGovernanceProfileRequest(input: {
  readonly boardId: string;
  readonly expectedProfileId: string | null;
  readonly profile: unknown;
  readonly citations: readonly SurfaceGovernanceCitation[];
  readonly generatedIds: readonly string[];
  readonly reason: string;
}): GovernanceAdministrationRequest {
  const profile = GovernanceProfileSchema.parse(input.profile);
  const roles = [...new Set(profile.seats.map(({ role }) => role))].toSorted();
  const requiredIds =
    roles.length + profile.templates.length + embeddedProfileCitations(profile).length;
  if (input.generatedIds.length !== requiredIds) {
    throw new GovernanceAdministrationError("governance profile material IDs are incomplete");
  }
  const generated = uniqueIds(input.generatedIds, "governance material IDs");
  let offset = 0;
  const seatMaterial = roles.map((seatClass) => {
    const weights = profile.seats
      .filter((seat) => seat.role === seatClass)
      .map((seat) => BigInt(seat.weight));
    const minimumWeight = weights.reduce((left, right) => (left < right ? left : right));
    const maximumWeight = weights.reduce((left, right) => (left > right ? left : right));
    const material = {
      id: generated[offset++]!,
      seatClass,
      minimumWeight: minimumWeight.toString(10),
      maximumWeight: maximumWeight.toString(10)
    };
    return {
      ...material,
      canonicalSha256: Sha256HexSchema.parse(canonicalSha256(material))
    };
  });
  const templateMaterial = profile.templates.map((template) => {
    const approvalRuleId = generated[offset++]!;
    const templateId = template.id;
    const approvalRule = {
      schemaVersion: "boardagent.approval-rule.v1",
      approval: template.approval,
      quorum: template.quorum,
      approvalDenominator: template.approvalDenominator,
      abstentionsCountForQuorum: template.abstentionsCountForQuorum,
      tieBehavior: template.tieBehavior,
      proxyPolicy: template.proxyPolicy,
      closeMode: template.closeMode
    } satisfies JsonValue;
    return {
      templateId,
      approvalRuleId,
      approvalRuleSha256: Sha256HexSchema.parse(canonicalSha256(approvalRule)),
      templateSha256: Sha256HexSchema.parse(canonicalSha256(template))
    };
  });
  const citationMaterial: z.infer<typeof CitationMaterialSchema>[] = [];
  for (const citation of profile.sourceAgreements) {
    citationMaterial.push({
      id: generated[offset++]!,
      ruleTemplateId: null,
      citation: {
        documentVersionId: citation.sourceDocumentVersionId,
        sourceDocumentSha256: citation.sourceDocumentSha256,
        clause: citation.clause,
        locator: citation.locator
      }
    });
  }
  for (const template of profile.templates) {
    for (const citation of template.citations) {
      citationMaterial.push({
        id: generated[offset++]!,
        ruleTemplateId: template.id,
        citation: {
          documentVersionId: citation.sourceDocumentVersionId,
          sourceDocumentSha256: citation.sourceDocumentSha256,
          clause: citation.clause,
          locator: citation.locator
        }
      });
    }
  }
  return normalizeGovernanceAdministrationRequest({
    actionCode: "configure_board_governance",
    boardId: UuidV7Schema.parse(input.boardId),
    expectedProfileId:
      input.expectedProfileId === null ? null : UuidV7Schema.parse(input.expectedProfileId),
    profile,
    profileSha256: Sha256HexSchema.parse(governanceProfileSha256(profile)),
    citations: normalizeCitations(input.citations),
    seatMaterial,
    templateMaterial,
    citationMaterial,
    reason: bounded(input.reason, "governance profile amendment reason", 65_536)
  });
}

export function buildBoardCreationRequest(input: {
  readonly boardId: string;
  readonly slug: string;
  readonly name: string;
  readonly timezone: string;
  readonly initialSettings: JsonValue;
  readonly secretaryMemberId: string;
  readonly boardVersionId: string;
}): GovernanceAdministrationRequest {
  const base = {
    actionCode: "create_board" as const,
    boardId: UuidV7Schema.parse(input.boardId),
    slug: BoardSlugSchema.parse(input.slug),
    name: bounded(input.name, "board name", 512),
    timezone: validTimezone(input.timezone),
    initialSettings: input.initialSettings,
    secretaryMemberId: UuidV7Schema.parse(input.secretaryMemberId),
    boardVersionId: UuidV7Schema.parse(input.boardVersionId)
  };
  return normalizeGovernanceAdministrationRequest({
    ...base,
    boardVersionSha256: Sha256HexSchema.parse(
      canonicalSha256(
        boardVersionPayload({
          ...base,
          boardVersionSha256: Sha256HexSchema.parse("0".repeat(64))
        })
      )
    )
  });
}

export function buildBoardUpdateRequest(input: {
  readonly boardId: string;
  readonly expectedRowVersion: number;
  readonly name: string;
  readonly timezone: string;
  readonly settings: JsonValue;
  readonly reason: string;
  readonly boardVersionId: string;
}): GovernanceAdministrationRequest {
  const base = {
    actionCode: "update_board" as const,
    boardId: UuidV7Schema.parse(input.boardId),
    expectedRowVersion: PositiveRowVersionSchema.parse(input.expectedRowVersion),
    name: bounded(input.name, "board name", 512),
    timezone: validTimezone(input.timezone),
    settings: input.settings,
    reason: bounded(input.reason, "board amendment reason", 65_536),
    boardVersionId: UuidV7Schema.parse(input.boardVersionId)
  };
  return normalizeGovernanceAdministrationRequest({
    ...base,
    boardVersionSha256: Sha256HexSchema.parse(
      canonicalSha256(
        boardVersionPayload({
          ...base,
          boardVersionSha256: Sha256HexSchema.parse("0".repeat(64))
        })
      )
    )
  });
}

export function buildBoardArchiveRequest(input: {
  readonly boardId: string;
  readonly reason: string;
}): GovernanceAdministrationRequest {
  return normalizeGovernanceAdministrationRequest({
    actionCode: "archive_board",
    boardId: UuidV7Schema.parse(input.boardId),
    reason: bounded(input.reason, "board archival reason", 65_536)
  });
}

export function buildRulesetRequest(input: {
  readonly boardId: string;
  readonly expectedRulesetId: string | null;
  readonly ruleset: unknown;
  readonly citations: readonly SurfaceGovernanceCitation[];
  readonly generatedMatterTypeIds: readonly string[];
  readonly generatedCitationIds: readonly string[];
  readonly reason: string;
}): GovernanceAdministrationRequest {
  const ruleset = RulesetVersionSchema.parse(input.ruleset);
  const hashPayload = { ...ruleset } as Record<string, unknown>;
  delete hashPayload["canonicalHash"];
  const rulesetSha256 = Sha256HexSchema.parse(canonicalSha256(hashPayload as JsonValue));
  if (!safeHashEqual(ruleset.canonicalHash, rulesetSha256)) {
    throw new GovernanceAdministrationError("ruleset canonicalHash does not match its content");
  }
  if (input.generatedMatterTypeIds.length !== ruleset.matterTypes.length) {
    throw new GovernanceAdministrationError("ruleset matter-type IDs are incomplete");
  }
  if (input.generatedCitationIds.length !== embeddedRulesetCitations(ruleset).length) {
    throw new GovernanceAdministrationError("ruleset citation IDs are incomplete");
  }
  const matterTypeIds = uniqueIds(input.generatedMatterTypeIds, "ruleset matter-type IDs");
  const citationIds = uniqueIds(input.generatedCitationIds, "ruleset citation IDs");
  const matterTypeMaterial = ruleset.matterTypes.map((matterType, index) => ({
    id: matterTypeIds[index]!,
    code: matterType.code,
    schemaSha256: Sha256HexSchema.parse(canonicalSha256(matterType))
  }));
  const ruleMaterial = ruleset.rules.map((rule) => ({
    ruleId: rule.id,
    canonicalSha256: Sha256HexSchema.parse(canonicalSha256(rule))
  }));
  let citationOffset = 0;
  const citationMaterial = ruleset.rules.flatMap((rule) =>
    rule.citations.map((citation) => ({
      id: citationIds[citationOffset++]!,
      ruleId: rule.id,
      citation: {
        documentVersionId: citation.sourceDocumentVersionId,
        sourceDocumentSha256: citation.sourceDocumentSha256,
        clause: citation.clause,
        locator: citation.locator
      }
    }))
  );
  return normalizeGovernanceAdministrationRequest({
    actionCode: "manage_ruleset",
    boardId: UuidV7Schema.parse(input.boardId),
    expectedRulesetId:
      input.expectedRulesetId === null ? null : UuidV7Schema.parse(input.expectedRulesetId),
    ruleset,
    rulesetSha256,
    citations: normalizeCitations(input.citations),
    matterTypeMaterial,
    ruleMaterial,
    citationMaterial,
    reason: bounded(input.reason, "ruleset amendment reason", 65_536)
  });
}
