import { z } from "zod";

import {
  assertJsonStructure,
  CanonicalizationError,
  canonicalJson,
  canonicalText
} from "./canonical.js";
import { TOOL_IDS } from "./generated/registry.ids.js";
import {
  MinutesActionManifestSchema,
  MinutesCommentSchema,
  MinutesRedlineSchema
} from "./governance.js";
import { Rfc3339UtcSchema, Sha256HexSchema, UuidV7Schema } from "./schemas.js";
import { MAX_TRANSCRIPT_BYTES, parseTranscriptAnnex } from "./transcript.js";

export const TOOL_INPUT_SCHEMA_VERSION = "boardagent.tool-input.v1" as const;

export type ToolId = (typeof TOOL_IDS)[number];

const IdempotencyKeySchema = z
  .string()
  .min(16)
  .max(200)
  .regex(/^[A-Za-z0-9._~-]+$/u);
const CursorSchema = z.string().min(1).max(4096).nullable().default(null);
const PageLimitSchema = z.number().int().min(1).max(500).default(100);
const BriefingLimitSchema = z.literal(1_000).default(1_000);
const PositiveVersionSchema = z.number().int().positive().safe();
function canonicalString(minimum: number, maximum: number): z.ZodType<string> {
  return z
    .string()
    .min(minimum)
    .max(maximum)
    .superRefine((value, ctx) => {
      try {
        canonicalText(value);
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: error instanceof Error ? error.message : "text is not canonical"
        });
      }
    });
}

const ShortTextSchema = canonicalString(1, 1024);
const CanonicalTextSchema = canonicalString(1, 1_048_576);
const ReasonSchema = canonicalString(1, 65_536);
const PublicOpaqueIdSchema = z
  .string()
  .min(32)
  .max(512)
  .regex(/^[A-Za-z0-9_-]+$/u);
const UrlSchema = z
  .url()
  .max(2048)
  .refine((value) => {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && parsed.username === "" && parsed.password === "";
  }, "URL must use HTTPS without embedded credentials");

// JSON permits finite fractional numbers. `z.number().safe()` is a safe-integer schema
// in Zod 4 and incorrectly rejected PostgreSQL search ranks in structured MCP results.
const JsonScalarSchema = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
type JsonValue = z.infer<typeof JsonScalarSchema> | JsonValue[] | { [key: string]: JsonValue };
const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([JsonScalarSchema, z.array(JsonValueSchema), z.record(z.string(), JsonValueSchema)])
);
const DynamicFactsSchema = z
  .object({
    schema_version: z.string().regex(/^boardagent\.[a-z0-9_.-]+\.v[0-9]+$/u),
    values: z.record(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/u), JsonValueSchema)
  })
  .strict()
  .superRefine((value, ctx) => {
    try {
      canonicalJson(value);
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: error instanceof Error ? error.message : "facts are not canonical JSON"
      });
    }
  });

// Profiles and rulesets use the canonical domain's camelCase fields. They are
// documents, not dynamic fact maps. Preserve the strict envelope and canonical
// JSON refinement; the server also parses their values with the domain schema.
const GovernanceDocumentSchema = DynamicFactsSchema.safeExtend({
  values: z.record(z.string().regex(/^[a-z][a-zA-Z0-9_]{0,63}$/u), JsonValueSchema)
});

const MeetingAgendaItemSchema = z
  .object({
    title: ShortTextSchema,
    source_document_version_id: UuidV7Schema.nullable().default(null),
    source_document_sha256: Sha256HexSchema.nullable().default(null)
  })
  .strict()
  .superRefine((item, ctx) => {
    if ((item.source_document_version_id === null) !== (item.source_document_sha256 === null)) {
      ctx.addIssue({
        code: "custom",
        message: "agenda document version and SHA-256 must both be present or both be null"
      });
    }
  });

const MeetingAgendaSchema = z
  .object({
    schema_version: z.literal("boardagent.agenda.v1"),
    values: z.object({ items: z.array(MeetingAgendaItemSchema).min(1).max(1000) }).strict()
  })
  .strict()
  .superRefine((value, ctx) => {
    try {
      canonicalJson(value);
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: error instanceof Error ? error.message : "agenda is not canonical JSON"
      });
    }
  });

const MeetingAttendeeIdsSchema = z
  .array(UuidV7Schema)
  .min(1)
  .max(1000)
  .superRefine((memberIds, ctx) => {
    if (new Set(memberIds).size !== memberIds.length) {
      ctx.addIssue({ code: "custom", message: "meeting attendees must be unique" });
    }
  });

const TranscriptBodySchema = canonicalString(1, MAX_TRANSCRIPT_BYTES).superRefine(
  (value, context) => {
    if (Buffer.byteLength(value, "utf8") > MAX_TRANSCRIPT_BYTES) {
      context.addIssue({ code: "custom", message: "transcript annex exceeds 10 MiB" });
    }
  }
);

const TranscriptTurnIdsSchema = z
  .array(UuidV7Schema)
  .min(1)
  .max(10_000)
  .superRefine((turnIds, context) => {
    if (new Set(turnIds).size !== turnIds.length) {
      context.addIssue({ code: "custom", message: "transcript turn identifiers must be unique" });
    }
  });

const DocumentReferenceSchema = z
  .object({
    document_id: UuidV7Schema,
    version_id: UuidV7Schema,
    sha256: Sha256HexSchema
  })
  .strict();
const ResourceReferenceSchema = z
  .object({ uri: z.string().min(1).max(4096), sha256: Sha256HexSchema })
  .strict();
const CitationSchema = z
  .object({
    document_version_id: UuidV7Schema,
    sha256: Sha256HexSchema,
    clause: ShortTextSchema,
    locator: ShortTextSchema
  })
  .strict();
export const AdministrativeReasonSchema = canonicalString(1, 2000);
export const AdministrativeEvidenceSchema = z
  .array(CitationSchema)
  .min(1)
  .max(8)
  .superRefine((citations, ctx) => {
    if (new Set(citations.map((citation) => canonicalJson(citation))).size !== citations.length) {
      ctx.addIssue({ code: "custom", message: "administrative citations must be unique" });
    }
  });
const CompanyAdminChangeSchema = z.discriminatedUnion("operation", [
  z
    .object({
      operation: z.enum(["grant", "transfer"]),
      proposal_id: UuidV7Schema,
      member_id: UuidV7Schema,
      expected_member_version: PositiveVersionSchema,
      reason: AdministrativeReasonSchema
    })
    .strict(),
  z
    .object({
      operation: z.enum(["accept", "decline", "cancel"]),
      proposal_id: UuidV7Schema,
      expected_proposal_version: PositiveVersionSchema,
      reason: AdministrativeReasonSchema
    })
    .strict(),
  z
    .object({
      operation: z.literal("revoke"),
      assignment_id: UuidV7Schema,
      member_id: UuidV7Schema,
      expected_member_version: PositiveVersionSchema,
      reason: AdministrativeReasonSchema
    })
    .strict()
]);
const MemberAdminDelegationChangeSchema = z.discriminatedUnion("operation", [
  z
    .object({
      operation: z.literal("grant"),
      delegation_id: UuidV7Schema,
      member_id: UuidV7Schema,
      board_id: UuidV7Schema,
      expected_member_version: PositiveVersionSchema,
      expires_at: Rfc3339UtcSchema,
      reason: AdministrativeReasonSchema,
      authority_evidence: AdministrativeEvidenceSchema
    })
    .strict(),
  z
    .object({
      operation: z.literal("revoke"),
      delegation_id: UuidV7Schema,
      board_id: UuidV7Schema,
      expected_delegation_version: PositiveVersionSchema,
      reason: AdministrativeReasonSchema
    })
    .strict()
]);
const MemberChangeSchema = z.discriminatedUnion("operation", [
  z
    .object({
      operation: z.literal("invite"),
      member_id: UuidV7Schema,
      board_id: UuidV7Schema,
      member_kind: z.enum(["human", "ai_observer"]),
      seat_role: z.enum(["voting_member", "management", "observer"]),
      legal_name: ShortTextSchema,
      display_name: ShortTextSchema,
      voting_weight: z.number().int().min(0).max(1_000_000_000),
      accountable_principal_id: UuidV7Schema.nullable(),
      reason: AdministrativeReasonSchema.optional()
    })
    .strict(),
  z
    .object({
      operation: z.enum(["suspend", "remove", "reactivate"]),
      member_id: UuidV7Schema,
      board_id: UuidV7Schema.nullable(),
      reason: ReasonSchema
    })
    .strict(),
  z
    .object({
      operation: z.literal("change_seat"),
      member_id: UuidV7Schema,
      board_id: UuidV7Schema,
      seat_role: z.enum(["voting_member", "management", "observer"]),
      voting_weight: z.number().int().min(0).max(1_000_000_000),
      is_secretary: z.boolean(),
      // Explicit chair changes require company administration. Omission retains the
      // current chair when the member remains a voter; other roles cannot chair.
      is_chair: z.boolean().optional(),
      reason: ReasonSchema
    })
    .strict()
]);

type Shape = z.ZodRawShape;
function readInput<T extends Shape>(
  shape: T
): z.ZodObject<T & { schema_version: z.ZodLiteral<typeof TOOL_INPUT_SCHEMA_VERSION> }> {
  return z
    .object({ schema_version: z.literal(TOOL_INPUT_SCHEMA_VERSION), ...shape })
    .strict() as z.ZodObject<
    T & { schema_version: z.ZodLiteral<typeof TOOL_INPUT_SCHEMA_VERSION> }
  >;
}

function mutationInput<T extends Shape>(
  shape: T
): z.ZodObject<
  T & {
    schema_version: z.ZodLiteral<typeof TOOL_INPUT_SCHEMA_VERSION>;
    idempotency_key: typeof IdempotencyKeySchema;
  }
> {
  return z
    .object({
      schema_version: z.literal(TOOL_INPUT_SCHEMA_VERSION),
      ...shape,
      idempotency_key: IdempotencyKeySchema
    })
    .strict() as z.ZodObject<
    T & {
      schema_version: z.ZodLiteral<typeof TOOL_INPUT_SCHEMA_VERSION>;
      idempotency_key: typeof IdempotencyKeySchema;
    }
  >;
}

const Empty = readInput({});
const Page = readInput({ cursor: CursorSchema, limit: PageLimitSchema });
const Board = readInput({ board_id: UuidV7Schema });
const BoardPage = readInput({
  board_id: UuidV7Schema,
  cursor: CursorSchema,
  limit: PageLimitSchema
});
const Minutes = readInput({ minutes_id: UuidV7Schema });
const Vote = readInput({ vote_id: UuidV7Schema });
const Task = readInput({ task_id: UuidV7Schema });
const Member = readInput({ member_id: UuidV7Schema });
const Draft = readInput({ draft_id: UuidV7Schema });

const ToolInputSchemas = {
  whoami: Empty,
  list_my_boards: Page,
  get_board: Board,
  get_my_board_snapshot: Board,
  list_my_updates: readInput({ cursor: CursorSchema, limit: PageLimitSchema }),
  list_pending_actions: readInput({ cursor: CursorSchema, limit: BriefingLimitSchema }),
  get_onboarding: readInput({ board_id: UuidV7Schema }),
  get_onboarding_status: readInput({ board_id: UuidV7Schema }),
  publish_secretary_support: mutationInput({
    board_id: UuidV7Schema,
    version_id: UuidV7Schema,
    expected_version_id: UuidV7Schema.nullable().optional(),
    support_name: canonicalString(1, 512),
    contact_methods: z.array(z.json()).min(1).max(32),
    reason: ReasonSchema
  }),
  publish_onboarding_terms: mutationInput({
    seat_role: z.enum(["voting_member", "management", "observer"]),
    version_id: UuidV7Schema,
    expected_version_id: UuidV7Schema.nullable().optional(),
    canonical_text: CanonicalTextSchema,
    reason: ReasonSchema
  }),
  prepare_onboarding_attestation: mutationInput({
    board_id: UuidV7Schema,
    terms_version_id: UuidV7Schema,
    support_version_id: UuidV7Schema,
    presentation_choice: ShortTextSchema,
    local_memory_choice: ShortTextSchema
  }),
  create_board: mutationInput({
    board_id: UuidV7Schema,
    slug: z
      .string()
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u)
      .max(80),
    name: ShortTextSchema,
    timezone: ShortTextSchema,
    initial_settings: DynamicFactsSchema,
    secretary_member_id: UuidV7Schema
  }),
  update_board: mutationInput({
    board_id: UuidV7Schema,
    expected_row_version: PositiveVersionSchema,
    name: ShortTextSchema,
    timezone: ShortTextSchema,
    settings: DynamicFactsSchema,
    reason: ReasonSchema
  }),
  archive_board: mutationInput({ board_id: UuidV7Schema, reason: ReasonSchema }),
  get_board_governance_profile: readInput({
    board_id: UuidV7Schema,
    version: PositiveVersionSchema.nullable().default(null)
  }),
  list_approval_rule_templates: BoardPage,
  configure_board_governance: mutationInput({
    board_id: UuidV7Schema,
    expected_profile_id: UuidV7Schema.nullable(),
    profile: GovernanceDocumentSchema,
    citations: z.array(CitationSchema).min(1).max(256),
    reason: ReasonSchema
  }),
  list_matter_types: BoardPage,
  evaluate_matter: mutationInput({
    board_id: UuidV7Schema,
    matter_type_id: UuidV7Schema,
    facts: DynamicFactsSchema,
    expected_profile_id: UuidV7Schema,
    expected_ruleset_id: UuidV7Schema
  }),
  get_ruleset: readInput({
    board_id: UuidV7Schema,
    ruleset_id: UuidV7Schema.nullable().default(null)
  }),
  list_ruleset_versions: BoardPage,
  validate_ruleset_draft: readInput({
    board_id: UuidV7Schema,
    draft: GovernanceDocumentSchema,
    citations: z.array(CitationSchema).min(1).max(1024)
  }),
  manage_ruleset: mutationInput({
    board_id: UuidV7Schema,
    expected_ruleset_id: UuidV7Schema.nullable(),
    ruleset: GovernanceDocumentSchema,
    citations: z.array(CitationSchema).min(1).max(1024),
    reason: ReasonSchema
  }),
  list_documents: BoardPage,
  read_document: readInput({ document_id: UuidV7Schema, version_id: UuidV7Schema.nullable() }),
  search_documents: readInput({
    board_id: UuidV7Schema,
    query: z.string().min(1).max(4096),
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  get_document_hash: readInput({ document_id: UuidV7Schema, version_id: UuidV7Schema }),
  list_document_versions: readInput({
    document_id: UuidV7Schema,
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  get_document_validation_status: readInput({ validation_attempt_id: UuidV7Schema }),
  create_document_version: mutationInput({
    board_id: UuidV7Schema,
    document_id: UuidV7Schema,
    title: ShortTextSchema,
    media_type: z.enum([
      "application/json",
      "text/markdown; charset=utf-8",
      "text/plain; charset=utf-8"
    ]),
    schema_name: z
      .string()
      .regex(/^boardagent\.[a-z0-9_.-]+\.v[0-9]+$/u)
      .nullable(),
    canonical_body: z.string().max(10_485_760),
    expected_current_version_id: UuidV7Schema.nullable()
  }),
  circulate_document: mutationInput({
    board_id: UuidV7Schema,
    document_id: UuidV7Schema,
    version_id: UuidV7Schema,
    document_sha256: Sha256HexSchema,
    recipient_member_ids: z.array(UuidV7Schema).min(1).max(1000),
    completeness_statement: z.literal("canonical_version_stands_alone")
  }),
  manage_document_access: mutationInput({
    board_id: UuidV7Schema,
    document_id: UuidV7Schema,
    operation: z.enum(["grant", "exclude", "lift_exclusion"]),
    member_id: UuidV7Schema,
    permission: z.enum(["read", "contribute"]).nullable(),
    reason: ReasonSchema
  }),
  manage_recusal: mutationInput({
    board_id: UuidV7Schema,
    member_id: UuidV7Schema,
    object_type: z.enum(["board", "document", "meeting", "minutes", "question", "vote"]),
    object_id: UuidV7Schema,
    operation: z.enum(["add", "lift"]),
    reason: ReasonSchema
  }),
  archive_document: mutationInput({ document_id: UuidV7Schema, reason: ReasonSchema }),
  soft_delete_document: mutationInput({ document_id: UuidV7Schema, reason: ReasonSchema }),
  submit_document_to_secretariat: mutationInput({
    board_id: UuidV7Schema,
    submission_id: UuidV7Schema,
    document_references: z.array(DocumentReferenceSchema).min(1).max(1000),
    purpose: ShortTextSchema
  }),
  list_management_submissions: BoardPage,
  get_management_submission: readInput({ submission_id: UuidV7Schema }),
  request_management_revision: mutationInput({ submission_id: UuidV7Schema, reason: ReasonSchema }),
  reply_to_management_revision: mutationInput({
    submission_id: UuidV7Schema,
    revision_request_id: UuidV7Schema,
    reply: CanonicalTextSchema
  }),
  resubmit_management_materials: mutationInput({
    submission_id: UuidV7Schema,
    document_references: z.array(DocumentReferenceSchema).min(1).max(1000),
    reason: ReasonSchema
  }),
  approve_management_submission: mutationInput({
    submission_id: UuidV7Schema,
    version_id: UuidV7Schema
  }),
  reject_management_submission: mutationInput({
    submission_id: UuidV7Schema,
    version_id: UuidV7Schema,
    reason: ReasonSchema
  }),
  ask_management: mutationInput({
    board_id: UuidV7Schema,
    question_id: UuidV7Schema,
    owner_member_id: UuidV7Schema,
    due_at: Rfc3339UtcSchema,
    question: CanonicalTextSchema,
    citations: z.array(DocumentReferenceSchema).max(64)
  }),
  list_management_questions: BoardPage,
  get_management_question: readInput({ question_id: UuidV7Schema }),
  answer_management_question: mutationInput({
    question_id: UuidV7Schema,
    answer: CanonicalTextSchema
  }),
  follow_up_management_question: mutationInput({
    question_id: UuidV7Schema,
    follow_up: CanonicalTextSchema,
    due_at: Rfc3339UtcSchema
  }),
  list_meetings: BoardPage,
  get_agenda: readInput({ meeting_id: UuidV7Schema, version: PositiveVersionSchema.nullable() }),
  rsvp: mutationInput({
    meeting_id: UuidV7Schema,
    response: z.enum(["attending", "not_attending", "tentative"]),
    note: z.string().min(1).max(4096).nullable()
  }),
  get_attendance: readInput({ meeting_id: UuidV7Schema }),
  create_meeting: mutationInput({
    board_id: UuidV7Schema,
    meeting_id: UuidV7Schema,
    title: ShortTextSchema,
    scheduled_start_at: Rfc3339UtcSchema,
    scheduled_end_at: Rfc3339UtcSchema,
    timezone: ShortTextSchema,
    agenda: MeetingAgendaSchema,
    attendee_member_ids: MeetingAttendeeIdsSchema
  }),
  amend_meeting: mutationInput({
    meeting_id: UuidV7Schema,
    expected_row_version: PositiveVersionSchema,
    title: ShortTextSchema,
    scheduled_start_at: Rfc3339UtcSchema,
    scheduled_end_at: Rfc3339UtcSchema,
    timezone: ShortTextSchema,
    agenda: MeetingAgendaSchema,
    reason: ReasonSchema
  }),
  record_attendance: mutationInput({
    meeting_id: UuidV7Schema,
    member_id: UuidV7Schema,
    status: z.enum(["present", "absent", "excused"]),
    source: z.literal("secretary_record")
  }),
  correct_attendance: mutationInput({
    attendance_id: UuidV7Schema,
    status: z.enum(["present", "absent", "excused"]),
    reason: ReasonSchema
  }),
  cancel_meeting: mutationInput({ meeting_id: UuidV7Schema, reason: ReasonSchema }),
  complete_meeting: mutationInput({
    meeting_id: UuidV7Schema,
    completion_statement: z.literal("attendance_record_is_complete")
  }),
  list_meeting_transcripts: readInput({
    meeting_id: UuidV7Schema,
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  get_meeting_transcript: readInput({
    transcript_id: UuidV7Schema,
    version_id: UuidV7Schema.nullable()
  }),
  create_meeting_transcript_version: mutationInput({
    meeting_id: UuidV7Schema,
    transcript_id: UuidV7Schema,
    media_type: z.enum(["text/markdown; charset=utf-8", "application/json"]),
    canonical_body: TranscriptBodySchema,
    coverage_statement: ShortTextSchema,
    supersedes_version_id: UuidV7Schema.nullable()
  }).superRefine((input, context) => {
    try {
      parseTranscriptAnnex(input.media_type, input.canonical_body);
    } catch (error) {
      context.addIssue({
        code: "custom",
        message: error instanceof Error ? error.message : "transcript annex is invalid"
      });
    }
  }),
  verify_meeting_transcript: mutationInput({
    transcript_id: UuidV7Schema,
    version_id: UuidV7Schema,
    sha256: Sha256HexSchema,
    verification_statement: z.literal("secretary_verified_annex_hash")
  }),
  link_meeting_qna: mutationInput({
    transcript_version_id: UuidV7Schema,
    turn_ids: TranscriptTurnIdsSchema,
    question_id: UuidV7Schema
  }),
  challenge_transcript_turn: mutationInput({
    transcript_version_id: UuidV7Schema,
    turn_id: UuidV7Schema,
    comment: CanonicalTextSchema
  }),
  resolve_transcript_challenge: mutationInput({
    challenge_id: UuidV7Schema,
    disposition: z.enum(["accept", "reject"]),
    reason: ReasonSchema,
    corrected_version_id: UuidV7Schema.nullable()
  }).superRefine((input, context) => {
    if ((input.disposition === "accept") !== (input.corrected_version_id !== null)) {
      context.addIssue({
        code: "custom",
        message: "accepted challenges require a corrected version; rejected challenges forbid one"
      });
    }
  }),
  list_votes: BoardPage,
  get_vote: Vote,
  get_vote_lineage: Vote,
  stage_ballot: mutationInput({
    vote_id: UuidV7Schema,
    principal_member_id: UuidV7Schema.nullable().default(null),
    choice: z.enum(["yes", "no", "abstain"]),
    statement: z.string().max(16_384).nullable().default(null)
  }),
  grant_proxy: mutationInput({ vote_id: UuidV7Schema, holder_member_id: UuidV7Schema }),
  revoke_proxy: mutationInput({ grant_id: UuidV7Schema, reason: ReasonSchema }),
  get_proxy_status: readInput({ vote_id: UuidV7Schema, member_id: UuidV7Schema.nullable() }),
  get_vote_certificate: readInput({
    vote_id: UuidV7Schema,
    certificate_id: UuidV7Schema.nullable()
  }),
  verify_certificate: readInput({
    public_id: PublicOpaqueIdSchema.nullable(),
    bundle: z.string().max(2_097_152).nullable()
  }).refine(
    (value) => (value.public_id === null) !== (value.bundle === null),
    "supply exactly one certificate reference"
  ),
  create_vote: mutationInput({
    board_id: UuidV7Schema,
    vote_id: UuidV7Schema,
    title: ShortTextSchema,
    resolution_text: CanonicalTextSchema,
    decision_package: DynamicFactsSchema,
    approval_rule_id: UuidV7Schema,
    matter_evaluation_id: UuidV7Schema,
    selected_ruleset_rule_id: UuidV7Schema,
    override_reason: ReasonSchema.nullable(),
    close_mode: z.enum(["automatic", "secretariat_confirmed"]),
    deadline_at: Rfc3339UtcSchema
  }),
  amend_resolution_text: mutationInput({
    vote_id: UuidV7Schema,
    expected_resolution_version_id: UuidV7Schema,
    resolution_text: CanonicalTextSchema,
    reason: ReasonSchema
  }),
  replace_open_vote: mutationInput({
    vote_id: UuidV7Schema,
    replacement_vote_id: UuidV7Schema,
    changed_component_classes: z
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
      .max(10),
    replacement_package: DynamicFactsSchema,
    reason: ReasonSchema
  }),
  exclude_pending_vote_source: mutationInput({
    vote_id: UuidV7Schema,
    source_type: z.enum(["management_submission", "document", "question_cutoff"]),
    source_id: UuidV7Schema,
    source_version: PositiveVersionSchema,
    source_sha256: Sha256HexSchema,
    reason: ReasonSchema
  }),
  extend_vote_deadline: mutationInput({
    vote_id: UuidV7Schema,
    deadline_at: Rfc3339UtcSchema,
    reason: ReasonSchema
  }),
  close_vote: mutationInput({ vote_id: UuidV7Schema, expected_package_sha256: Sha256HexSchema }),
  cancel_vote: mutationInput({ vote_id: UuidV7Schema, reason: ReasonSchema }),
  get_minutes: Minutes,
  list_minutes_versions: readInput({
    minutes_id: UuidV7Schema,
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  get_minutes_lineage: Minutes,
  create_minutes_version: mutationInput({
    minutes_id: UuidV7Schema,
    meeting_id: UuidV7Schema,
    canonical_text: CanonicalTextSchema,
    transcript_version_id: UuidV7Schema.nullable(),
    expected_current_version_id: UuidV7Schema.nullable()
  }),
  publish_minutes: mutationInput({
    minutes_id: UuidV7Schema,
    version_id: UuidV7Schema,
    minutes_sha256: Sha256HexSchema,
    signer_member_ids: z.array(UuidV7Schema).min(1).max(1000)
  }),
  list_minutes_review_items: readInput({
    minutes_id: UuidV7Schema,
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  comment_minutes: mutationInput({ payload: MinutesCommentSchema }),
  withdraw_minutes_comment: mutationInput({
    minutes_id: UuidV7Schema,
    review_item_id: UuidV7Schema
  }),
  propose_minutes_redline: mutationInput({ payload: MinutesRedlineSchema }),
  resolve_minutes_review_item: mutationInput({
    minutes_id: UuidV7Schema,
    review_item_id: UuidV7Schema,
    disposition: z.enum(["accept", "reject"]),
    reason: ReasonSchema,
    replacement_text: CanonicalTextSchema.nullable()
  }),
  correct_minutes_package: mutationInput({
    minutes_id: UuidV7Schema,
    expected_version_id: UuidV7Schema,
    canonical_text: CanonicalTextSchema,
    reason: ReasonSchema
  }),
  prepare_minutes_for_signature: mutationInput({
    minutes_id: UuidV7Schema,
    expected_version_id: UuidV7Schema,
    signer_member_ids: z.array(UuidV7Schema).min(1).max(1000)
  }),
  stage_minutes_signature: mutationInput({
    minutes_id: UuidV7Schema,
    package_id: UuidV7Schema,
    reservation: z.string().max(65_536).nullable()
  }),
  finalize_minutes: mutationInput({ minutes_id: UuidV7Schema, package_id: UuidV7Schema }),
  create_minutes_correction_cycle: mutationInput({
    minutes_id: UuidV7Schema,
    replacement_minutes_id: UuidV7Schema,
    canonical_text: CanonicalTextSchema,
    reason: ReasonSchema
  }),
  cancel_minutes: mutationInput({ minutes_id: UuidV7Schema, reason: ReasonSchema }),
  list_my_tasks: Page,
  list_action_items: BoardPage,
  get_task: Task,
  get_action_item: Task,
  log_minutes_action_items: mutationInput({ manifest: MinutesActionManifestSchema }),
  declare_no_minutes_action_items: mutationInput({ manifest: MinutesActionManifestSchema }),
  create_task: mutationInput({
    task_id: UuidV7Schema,
    board_id: UuidV7Schema,
    owner_member_id: UuidV7Schema,
    due_at: Rfc3339UtcSchema,
    description: CanonicalTextSchema,
    required_evidence: z.array(ShortTextSchema).min(1).max(256),
    source_minutes_id: UuidV7Schema.nullable(),
    source_minutes_version_id: UuidV7Schema.nullable()
  }),
  start_task: mutationInput({ task_id: UuidV7Schema }),
  submit_task_evidence: mutationInput({
    task_id: UuidV7Schema,
    evidence_id: UuidV7Schema,
    canonical_text: CanonicalTextSchema.nullable(),
    document_references: z.array(DocumentReferenceSchema).max(256),
    resource_references: z.array(ResourceReferenceSchema).max(256)
  }),
  review_task_evidence: mutationInput({
    task_id: UuidV7Schema,
    evidence_id: UuidV7Schema,
    disposition: z.enum(["accept", "reject"]),
    reason: ReasonSchema
  }),
  complete_task: mutationInput({
    task_id: UuidV7Schema,
    evidence_ids: z.array(UuidV7Schema).min(1).max(1000)
  }),
  create_task_correction_cycle: mutationInput({
    task_id: UuidV7Schema,
    replacement_task_id: UuidV7Schema,
    owner_member_id: UuidV7Schema,
    due_at: Rfc3339UtcSchema,
    description: CanonicalTextSchema,
    required_evidence: z.array(ShortTextSchema).min(1).max(256),
    reason: ReasonSchema
  }),
  cancel_task: mutationInput({ task_id: UuidV7Schema, reason: ReasonSchema }),
  propose_action: mutationInput({
    proposal_id: UuidV7Schema,
    board_id: UuidV7Schema,
    proposal_type: z.enum(["meeting", "vote", "document", "minutes", "task", "other"]),
    title: ShortTextSchema,
    payload: DynamicFactsSchema,
    references: z.array(ResourceReferenceSchema).max(256)
  }),
  withdraw_proposal: mutationInput({ proposal_id: UuidV7Schema }),
  list_proposals: readInput({
    board_id: UuidV7Schema,
    state: z.enum(["pending", "withdrawn", "approved_to_draft", "rejected"]).nullable(),
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  approve_proposal: mutationInput({
    proposal_id: UuidV7Schema,
    resulting_draft_id: UuidV7Schema,
    draft_type: z.enum(["meeting", "vote", "minutes", "task", "proposal"])
  }),
  reject_proposal: mutationInput({ proposal_id: UuidV7Schema, reason: ReasonSchema }),
  ask_secretariat: mutationInput({
    request_id: UuidV7Schema,
    board_id: UuidV7Schema,
    topic: ShortTextSchema,
    message: CanonicalTextSchema,
    references: z.array(ResourceReferenceSchema).max(256)
  }),
  list_secretariat_requests: readInput({
    board_id: UuidV7Schema.nullable(),
    state: z.enum(["open", "answered", "closed"]).nullable(),
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  reply_secretariat_request: mutationInput({
    request_id: UuidV7Schema,
    reply: CanonicalTextSchema
  }),
  close_secretariat_request: mutationInput({ request_id: UuidV7Schema }),
  list_members: readInput({
    board_id: UuidV7Schema.nullable(),
    state: z
      .enum([
        "invited",
        "enrollment_pending",
        "pending_activation",
        "active",
        "suspended",
        "removed"
      ])
      .nullable(),
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  get_member: Member,
  manage_member: mutationInput({
    change: MemberChangeSchema,
    authority_evidence: AdministrativeEvidenceSchema.optional()
  }),
  manage_company_admin: mutationInput({ change: CompanyAdminChangeSchema }),
  manage_member_admin_delegation: mutationInput({ change: MemberAdminDelegationChangeSchema }),
  list_administrative_access: readInput({
    mode: z.enum(["mine", "organization"]).default("mine"),
    board_id: UuidV7Schema.nullable().default(null),
    limit: z.number().int().min(1).max(100).default(50),
    cursor: CursorSchema
  }),
  issue_enrollment: mutationInput({
    member_id: UuidV7Schema,
    handoff_method: z.enum(["operator_display", "operator_qr"]),
    expires_in_seconds: z.number().int().min(60).max(86_400)
  }),
  list_enrollments: readInput({
    state: z.enum(["issued", "consumed", "expired", "revoked"]).nullable(),
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  revoke_enrollment: mutationInput({ invitation_id: UuidV7Schema, reason: ReasonSchema }),
  confirm_enrollment_activation: mutationInput({
    member_id: UuidV7Schema,
    invitation_id: UuidV7Schema,
    challenge_id: UuidV7Schema,
    confirmation_code: z.string().length(8),
    proofing_method: ShortTextSchema
  }),
  reissue_activation: mutationInput({
    member_id: UuidV7Schema,
    challenge_id: UuidV7Schema,
    proofing_method: ShortTextSchema
  }),
  initiate_identity_recovery: mutationInput({
    member_id: UuidV7Schema,
    reason: ReasonSchema,
    proofing_method: ShortTextSchema,
    credential_disposition: z.enum(["revoke_all", "preserve_named"]),
    preserved_credential_ids: z.array(UuidV7Schema).max(32)
  }),
  list_my_sessions: Page,
  revoke_my_session: mutationInput({
    session_id: UuidV7Schema,
    recent_auth_proof: PublicOpaqueIdSchema
  }),
  list_oauth_clients: Page,
  block_oauth_client: mutationInput({ client_id: UuidV7Schema, reason: ReasonSchema }),
  unblock_oauth_client: mutationInput({ client_id: UuidV7Schema, reason: ReasonSchema }),
  link_external_identity: mutationInput({
    member_id: UuidV7Schema,
    issuer: UrlSchema,
    subject: z.string().min(1).max(1024),
    browser_proof: PublicOpaqueIdSchema
  }),
  unlink_external_identity: mutationInput({ identity_link_id: UuidV7Schema, reason: ReasonSchema }),
  export_audit_chain: mutationInput({
    board_id: UuidV7Schema.nullable(),
    from_sequence: z.string().regex(/^(?:0|[1-9]\d*)$/u),
    to_sequence: z
      .string()
      .regex(/^[1-9]\d*$/u)
      .nullable(),
    recent_auth_proof: PublicOpaqueIdSchema
  }),
  verify_audit_chain: readInput({
    export_id: PublicOpaqueIdSchema.nullable(),
    from_sequence: z
      .string()
      .regex(/^(?:0|[1-9]\d*)$/u)
      .nullable(),
    to_sequence: z
      .string()
      .regex(/^[1-9]\d*$/u)
      .nullable()
  }),
  export_system_data: mutationInput({
    board_id: UuidV7Schema.nullable(),
    scope: z.enum(["organization", "board", "member_portability"]),
    purpose: ReasonSchema,
    recent_auth_proof: PublicOpaqueIdSchema
  }),
  get_export_status: readInput({ export_id: PublicOpaqueIdSchema }),
  read_export_chunk: readInput({
    export_id: PublicOpaqueIdSchema,
    chunk_no: z.number().int().nonnegative().safe(),
    recent_auth_proof: PublicOpaqueIdSchema
  }),
  cancel_export: mutationInput({ export_id: PublicOpaqueIdSchema }),
  delete_export_artifact: mutationInput({ export_id: PublicOpaqueIdSchema }),
  get_retention_policy: Empty,
  list_my_webhooks: Page,
  configure_webhook: mutationInput({
    webhook_id: UuidV7Schema,
    endpoint: UrlSchema,
    event_classes: z
      .array(z.enum(["pending_action", "notice", "security"]))
      .min(1)
      .max(3),
    recent_auth_proof: PublicOpaqueIdSchema
  }),
  rotate_webhook_secret: mutationInput({
    webhook_id: UuidV7Schema,
    recent_auth_proof: PublicOpaqueIdSchema
  }),
  disable_webhook: mutationInput({ webhook_id: UuidV7Schema, reason: ReasonSchema }),
  test_webhook: mutationInput({ webhook_id: UuidV7Schema }),
  list_my_drafts: readInput({
    draft_type: z.enum(["meeting", "vote", "minutes", "task", "proposal"]).nullable(),
    cursor: CursorSchema,
    limit: PageLimitSchema
  }),
  resume_draft: Draft,
  cancel_draft: mutationInput({ draft_id: UuidV7Schema, reason: ReasonSchema })
} satisfies Record<ToolId, z.ZodType>;

// Guard the complete input before any recursive Zod JSON schema runs. A preprocess
// preserves the advertised JSON schemas and the underlying field semantics.
function guardToolInputs(schemas: Record<ToolId, z.ZodType>): Readonly<Record<ToolId, z.ZodType>> {
  const result = { ...schemas };
  for (const name of TOOL_IDS) {
    result[name] = z.preprocess((value, ctx) => {
      try {
        assertJsonStructure(value);
      } catch (error) {
        if (!(error instanceof CanonicalizationError)) throw error;
        ctx.addIssue({ code: "custom", message: error.message });
        return z.NEVER;
      }
      return value;
    }, schemas[name]);
  }
  return Object.freeze(result);
}

export const TOOL_INPUT_SCHEMAS = guardToolInputs(ToolInputSchemas);

export function toolInputSchema(toolName: string): z.ZodType {
  if (!Object.hasOwn(TOOL_INPUT_SCHEMAS, toolName)) {
    throw new Error(`unregistered BoardAgent tool input schema: ${toolName}`);
  }
  return TOOL_INPUT_SCHEMAS[toolName as ToolId];
}

export function assertToolInputSchemaClosure(): void {
  const schemaIds = Object.keys(TOOL_INPUT_SCHEMAS).toSorted();
  const registryIds = [...TOOL_IDS].toSorted();
  if (schemaIds.length !== registryIds.length) {
    throw new Error(
      `tool input schema count drift: expected ${String(registryIds.length)}, got ${String(schemaIds.length)}`
    );
  }
  for (let index = 0; index < registryIds.length; index += 1) {
    if (schemaIds[index] !== registryIds[index]) {
      throw new Error(
        `tool input schema drift: expected ${registryIds[index] ?? "end"}, got ${schemaIds[index] ?? "end"}`
      );
    }
  }
}
