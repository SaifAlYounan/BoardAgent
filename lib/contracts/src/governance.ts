import { z } from "zod";

import { canonicalText, CanonicalizationError } from "./canonical.js";
import { Rfc3339UtcSchema, Sha256HexSchema, UuidSchema } from "./schemas.js";

function canonicalString(minimum: number, maximum: number): z.ZodString {
  return z
    .string()
    .min(minimum)
    .max(maximum)
    .superRefine((value, context) => {
      try {
        canonicalText(value);
      } catch (error) {
        context.addIssue({
          code: "custom",
          message: error instanceof CanonicalizationError ? error.message : "invalid canonical text"
        });
      }
    }) as z.ZodString;
}

export const GovernanceCitationSchema = z
  .object({
    sourceDocumentVersionId: UuidSchema,
    sourceDocumentSha256: Sha256HexSchema,
    clause: canonicalString(1, 512),
    locator: canonicalString(1, 1024)
  })
  .strict();

export const GovernanceRuleTemplatePayloadSchema = z
  .object({
    schemaVersion: z.literal("boardagent.governance-rule-template.v1"),
    approvalRuleSha256: Sha256HexSchema,
    overridePolicy: z.enum(["forbidden", "reasoned_within_bounds"])
  })
  .strict();
export type GovernanceRuleTemplatePayload = z.infer<typeof GovernanceRuleTemplatePayloadSchema>;

const MinutesReviewBaseShape = {
  minutesId: UuidSchema,
  baseVersion: z.number().int().positive().safe(),
  baseSha256: Sha256HexSchema
};

export const MinutesCommentSchema = z
  .object({
    schemaVersion: z.literal("boardagent.minutes-comment.v1"),
    ...MinutesReviewBaseShape,
    comment: canonicalString(1, 262_144),
    citations: z.array(GovernanceCitationSchema).max(64)
  })
  .strict();
export type MinutesComment = z.infer<typeof MinutesCommentSchema>;

export const MinutesAnchorSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("section"),
      section: canonicalString(1, 512)
    })
    .strict(),
  z
    .object({
      kind: z.literal("lines"),
      startLine: z.number().int().positive().safe(),
      endLine: z.number().int().positive().safe()
    })
    .strict()
    .refine((anchor) => anchor.endLine >= anchor.startLine, {
      message: "line anchor end must not precede start"
    })
]);

export const MinutesRedlineSchema = z
  .object({
    schemaVersion: z.literal("boardagent.minutes-redline.v1"),
    ...MinutesReviewBaseShape,
    anchor: MinutesAnchorSchema,
    anchoredTextSha256: Sha256HexSchema,
    operation: z.enum(["replace", "insert_before", "insert_after", "delete"]),
    proposedText: canonicalString(0, 262_144),
    rationale: canonicalString(1, 65_536),
    citations: z.array(GovernanceCitationSchema).max(64)
  })
  .strict()
  .superRefine((redline, context) => {
    if (redline.operation === "delete" && redline.proposedText !== "") {
      context.addIssue({
        code: "custom",
        path: ["proposedText"],
        message: "delete redline proposed text must be empty"
      });
    }
    if (redline.operation !== "delete" && redline.proposedText.length === 0) {
      context.addIssue({
        code: "custom",
        path: ["proposedText"],
        message: "non-delete redline proposed text must be nonempty"
      });
    }
  });
export type MinutesRedline = z.infer<typeof MinutesRedlineSchema>;

export const MinutesActionItemSchema = z
  .object({
    itemId: UuidSchema,
    ownerMemberId: UuidSchema,
    dueAt: Rfc3339UtcSchema,
    sourceLocator: z
      .object({
        section: canonicalString(1, 512),
        line: z.number().int().positive().safe()
      })
      .strict(),
    description: canonicalString(1, 262_144),
    requiredEvidence: canonicalString(1, 262_144),
    visibility: z.enum(["board", "secretariat_management"])
  })
  .strict();
export type MinutesActionItem = z.infer<typeof MinutesActionItemSchema>;

const MinutesActionBaseShape = {
  schemaVersion: z.literal("boardagent.minutes-action-manifest.v1"),
  minutesId: UuidSchema,
  minutesVersion: z.number().int().positive().safe(),
  minutesSha256: Sha256HexSchema
};

const NoActionItemsSchema = z
  .object({
    ...MinutesActionBaseShape,
    declaration: z.literal("no_action_items")
  })
  .strict();

const LoggedActionItemsSchema = z
  .object({
    ...MinutesActionBaseShape,
    declaration: z.literal("items_logged"),
    items: z.array(MinutesActionItemSchema).min(1).max(1_000)
  })
  .strict()
  .superRefine((manifest, context) => {
    const ids = new Set<string>();
    for (const [index, item] of manifest.items.entries()) {
      if (ids.has(item.itemId)) {
        context.addIssue({
          code: "custom",
          path: ["items", index, "itemId"],
          message: `duplicate action item: ${item.itemId}`
        });
      }
      ids.add(item.itemId);
    }
  });

export const MinutesActionManifestSchema = z.union([NoActionItemsSchema, LoggedActionItemsSchema]);
export type MinutesActionManifest = z.infer<typeof MinutesActionManifestSchema>;

export const DecisionPackageComponentSchema = z
  .object({
    type: z.enum(["management_submission", "document", "question_cutoff"]),
    ordinal: z.number().int().positive().safe(),
    id: UuidSchema,
    version: z.number().int().positive().safe(),
    sha256: Sha256HexSchema
  })
  .strict();

export const DecisionPackageSchema = z
  .object({
    schemaVersion: z.literal("boardagent.decision-package.v1"),
    voteId: UuidSchema,
    packageVersion: z.number().int().positive().safe(),
    resolutionVersionId: UuidSchema,
    resolutionSha256: Sha256HexSchema,
    governanceProfileVersionId: UuidSchema,
    governanceProfileSha256: Sha256HexSchema,
    rulesetVersionId: UuidSchema,
    rulesetSha256: Sha256HexSchema,
    approvalRuleId: UuidSchema,
    approvalRuleSha256: Sha256HexSchema,
    matterEvaluationId: UuidSchema,
    matterEvaluationResultSha256: Sha256HexSchema,
    selectedRulesetRuleId: UuidSchema,
    selectedRulesetRuleSha256: Sha256HexSchema,
    ruleOverride: z
      .object({ id: UuidSchema, canonicalSha256: Sha256HexSchema })
      .strict()
      .nullable(),
    electorateSha256: Sha256HexSchema,
    closeMode: z.enum(["automatic", "secretariat_confirmed"]),
    deadlineAt: Rfc3339UtcSchema,
    components: z.array(DecisionPackageComponentSchema).max(10_000)
  })
  .strict()
  .superRefine((decisionPackage, context) => {
    const keys = new Set<string>();
    for (const [index, component] of decisionPackage.components.entries()) {
      if (component.ordinal !== index + 1) {
        context.addIssue({
          code: "custom",
          path: ["components", index, "ordinal"],
          message: "decision-package ordinals must be contiguous from one"
        });
      }
      const key = `${component.type}:${component.id}:${String(component.version)}`;
      if (keys.has(key)) {
        context.addIssue({
          code: "custom",
          path: ["components", index],
          message: `duplicate decision-package component: ${key}`
        });
      }
      keys.add(key);
    }
  });
export type DecisionPackage = z.infer<typeof DecisionPackageSchema>;

const SafeReferenceValueSchema = z.union([
  UuidSchema,
  Sha256HexSchema,
  Rfc3339UtcSchema,
  z.number().int().nonnegative().safe()
]);

export const PendingActionDeltaSchema = z
  .object({
    schemaVersion: z.literal("boardagent.pending-action.v1"),
    sequence: z.string().regex(/^[1-9]\d*$/u),
    deltaType: z.enum([
      "revote_required",
      "minutes_resign_required",
      "vote_replaced",
      "notice",
      "task_assigned",
      "task_due",
      "management_question_due",
      "submission_revision_requested",
      "action_required",
      "tombstone"
    ]),
    objectType: z.enum([
      "vote",
      "minutes",
      "task",
      "question",
      "submission",
      "document",
      "meeting"
    ]),
    objectId: UuidSchema,
    objectVersion: z.number().int().positive().safe(),
    entitlementGeneration: z.number().int().positive().safe(),
    actionState: z.enum(["pending", "resolved", "informational"]),
    changedComponentClasses: z
      .array(
        z.enum([
          "resolution",
          "governance_profile",
          "ruleset",
          "approval_rule",
          "electorate",
          "close_mode",
          "deadline",
          "management_submission",
          "document",
          "question_cutoff"
        ])
      )
      .min(1)
      .max(10)
      .optional(),
    safeRefs: z.record(z.string().regex(/^[a-z][a-zA-Z0-9]{0,63}$/u), SafeReferenceValueSchema),
    createdAt: Rfc3339UtcSchema
  })
  .strict();
export type PendingActionDelta = z.infer<typeof PendingActionDeltaSchema>;

export const FeedCursorPayloadSchema = z
  .object({
    schemaVersion: z.literal("boardagent.feed-cursor.v1"),
    memberId: UuidSchema,
    boardId: UuidSchema.nullable(),
    entitlementGeneration: z.number().int().positive().safe(),
    afterSequence: z.string().regex(/^(?:0|[1-9]\d*)$/u)
  })
  .strict();
export type FeedCursorPayload = z.infer<typeof FeedCursorPayloadSchema>;

export const BriefingFeedPositionSchema = z
  .object({
    sequence: z.string().regex(/^(?:0|[1-9]\d*)$/u),
    boardId: UuidSchema.nullable(),
    entryKind: z.enum(["feed", "tombstone"]).nullable(),
    entryId: UuidSchema.nullable()
  })
  .strict()
  .superRefine((position, context) => {
    const atGenesis = position.sequence === "0";
    const boundFields = [position.boardId, position.entryKind, position.entryId].filter(
      (value) => value !== null
    ).length;
    if ((atGenesis && boundFields !== 0) || (!atGenesis && boundFields !== 3)) {
      context.addIssue({
        code: "custom",
        message: "briefing position must be genesis or bind one complete feed entry"
      });
    }
  });
export type BriefingFeedPosition = z.infer<typeof BriefingFeedPositionSchema>;

export const BriefingCursorPayloadSchema = z
  .object({
    schemaVersion: z.enum(["boardagent.briefing-cursor.v1", "boardagent.briefing-cursor.v2"]),
    memberId: UuidSchema,
    entitlementSetSha256: Sha256HexSchema,
    position: BriefingFeedPositionSchema,
    mode: z.enum(["delta", "resync"])
  })
  .strict();
export type BriefingCursorPayload = z.infer<typeof BriefingCursorPayloadSchema>;

export const BriefingResyncInstructionSchema = z
  .object({
    schema_version: z.literal("boardagent.briefing-resync.v1"),
    reason: z.enum(["briefing_overflow", "entitlement_changed", "cursor_version_changed"]),
    resync_token: z.string().min(1).max(4096),
    steps: z.tuple([
      z.literal("list_my_boards"),
      z.literal("get_my_board_snapshot"),
      z.literal("list_my_updates")
    ])
  })
  .strict();
export type BriefingResyncInstruction = z.infer<typeof BriefingResyncInstructionSchema>;
