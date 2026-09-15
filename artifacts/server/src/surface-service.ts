import { randomBytes } from "node:crypto";
import { z } from "zod";

import { canonicalVoteCertificatePayload } from "@boardagent/audit";
import {
  DecisionPackageComponentSchema,
  MinutesActionManifestSchema,
  Rfc3339UtcSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  sha256Hex,
  toolInputSchema,
  type JsonValue,
  type MinutesActionManifest
} from "@boardagent/contracts";
import {
  prepareBoardRecusalInTransaction,
  stageBoardRecusalInTransaction,
  confirmBoardRecusalInTransaction,
  type BoardRecusalAction,
  prepareRecordRecusalInTransaction,
  stageRecordRecusalInTransaction,
  confirmRecordRecusalInTransaction,
  type RecordRecusalAction,
  EnrollmentActivationAdministrationError,
  EnrollmentAdministrationError,
  MemberAdministrationError,
  OnboardingTransactionError,
  approveProposalInTransaction,
  answerManagementQuestionInTransaction,
  askManagementQuestionInTransaction,
  askSecretariatInTransaction,
  cancelWizardDraftInTransaction,
  closeSecretariatRequestInTransaction,
  confirmBallotLifecycleActionInTransaction,
  confirmDocumentLifecycleActionInTransaction,
  confirmMeetingLifecycleActionInTransaction,
  confirmMinutesLifecycleActionInTransaction,
  confirmTaskLifecycleActionInTransaction,
  confirmTaskCreationInTransaction,
  confirmTranscriptLifecycleActionInTransaction,
  confirmVoteCancellationLifecycleActionInTransaction,
  confirmVoteCloseLifecycleActionInTransaction,
  confirmVoteCreationLifecycleActionInTransaction,
  confirmVoteDeadlineExtensionLifecycleActionInTransaction,
  confirmVoteRecusalLifecycleActionInTransaction,
  confirmVoteReplacementLifecycleActionInTransaction,
  confirmVoteResolutionAmendmentLifecycleActionInTransaction,
  confirmVoteSourceExclusionLifecycleActionInTransaction,
  challengeTranscriptTurnInTransaction,
  approveManagementSubmissionInTransaction,
  confirmStagedActionInTransaction,
  contributeDocumentVersionInTransaction,
  createMeetingTranscriptVersionInTransaction,
  createMinutesVersionInTransaction,
  evaluateMatterInTransaction,
  finalizeEnrollmentActivationInTransaction,
  finalizeVoteCloseInTransaction,
  finalizeMemberInviteInTransaction,
  finalizeMemberLifecycleInTransaction,
  finalizeAdministrativeAuthorityInTransaction,
  prepareAdministrativeAuthorityInTransaction,
  planAdministrativeAuthorityInTransaction,
  type PreparedAdministrativeAuthority,
  isAdministrativeAuthorityTool,
  type AdministrativeAuthorityTool,
  prepareMemberLifecycleInTransaction,
  planMemberLifecycleInTransaction,
  isMemberLifecycleInput,
  type PreparedMemberLifecycle,
  followUpManagementQuestionInTransaction,
  issueActivationRestartInTransaction,
  issueEnrollmentInTransaction,
  planEnrollmentActivationInTransaction,
  planMemberInviteInTransaction,
  prepareEnrollmentActivationInTransaction,
  prepareActivationRestartInTransaction,
  prepareEnrollmentIssuanceInTransaction,
  prepareMemberInviteInTransaction,
  prepareDocumentLifecycleActionInTransaction,
  prepareMeetingLifecycleActionInTransaction,
  prepareMinutesLifecycleActionInTransaction,
  prepareTaskLifecycleActionInTransaction,
  prepareTaskCreationInTransaction,
  prepareTranscriptLifecycleActionInTransaction,
  prepareVoteCancellationLifecycleActionInTransaction,
  prepareVoteCloseLifecycleActionInTransaction,
  prepareVoteCreationLifecycleActionInTransaction,
  prepareVoteDeadlineExtensionLifecycleActionInTransaction,
  prepareVoteRecusalLifecycleActionInTransaction,
  prepareVoteReplacementLifecycleActionInTransaction,
  prepareVoteResolutionAmendmentLifecycleActionInTransaction,
  prepareVoteSourceExclusionLifecycleActionInTransaction,
  prepareOnboardingStageInTransaction,
  prepareBallotLifecycleActionInTransaction,
  replayCompletedBallotInTransaction,
  replayCompletedMemberInviteInTransaction,
  replayCompletedMemberLifecycleInTransaction,
  recordDocumentValidationRejectionInTransaction,
  recordMeetingAttendanceInTransaction,
  recordMeetingRsvpInTransaction,
  proposeActionInTransaction,
  rejectProposalInTransaction,
  rejectManagementSubmissionInTransaction,
  replyToManagementRevisionInTransaction,
  replySecretariatRequestInTransaction,
  requestManagementRevisionInTransaction,
  resubmitManagementMaterialsInTransaction,
  submitMinutesReviewInTransaction,
  submitDocumentToSecretariatInTransaction,
  stageActionInTransaction,
  stageBallotLifecycleActionInTransaction,
  stageDocumentLifecycleActionInTransaction,
  stageMeetingLifecycleActionInTransaction,
  stageMinutesLifecycleActionInTransaction,
  stageTaskLifecycleActionInTransaction,
  stageTaskCreationInTransaction,
  stageTranscriptLifecycleActionInTransaction,
  stageVoteCancellationLifecycleActionInTransaction,
  stageVoteCloseLifecycleActionInTransaction,
  stageVoteCreationLifecycleActionInTransaction,
  stageVoteRecusalLifecycleActionInTransaction,
  stageVoteReplacementLifecycleActionInTransaction,
  stageVoteSourceExclusionLifecycleActionInTransaction,
  startTaskInTransaction,
  submitTaskEvidenceInTransaction,
  withdrawMinutesCommentInTransaction,
  withdrawProposalInTransaction,
  withRequestTransaction,
  type BallotLifecycleAction,
  type BallotLifecycleResult,
  type CommunicationMutationResult,
  type PreparedBallotLifecycleAction,
  type PreparedEnrollmentActivation,
  type PreparedActivationRestart,
  type PreparedEnrollmentIssuance,
  type PreparedMemberInvite,
  type PreparedDocumentLifecycleAction,
  type DocumentLifecycleAction,
  type DocumentLifecycleResult,
  type MeetingAgenda,
  type MeetingLifecycleAction,
  type MeetingLifecycleResult,
  type PreparedMeetingLifecycleAction,
  type PreparedMinutesLifecycleAction,
  type MinutesLifecycleAction,
  type MinutesLifecycleResult,
  type PreparedTaskLifecycleAction,
  type TaskCreationAction,
  type TaskCreationResult,
  type TaskLifecycleAction,
  type TaskLifecycleResult,
  type TranscriptLifecycleAction,
  type TranscriptLifecycleResult,
  type PreparedTranscriptLifecycleAction,
  type PreparedVoteCancellationLifecycleAction,
  type PreparedVoteCloseLifecycleAction,
  type PreparedVoteCreationLifecycleAction,
  type PreparedVoteRecusalLifecycleAction,
  type PreparedVoteReplacementLifecycleAction,
  type PreparedVoteSourceExclusionLifecycleAction,
  type TransactionOptions,
  type VoteCancellationLifecycleAction,
  type VoteCancellationLifecycleResult,
  type VoteCloseLifecycleAction,
  type VoteCloseStageMaterial,
  type VoteCreationLifecycleAction,
  type VoteCreationStageMaterial,
  type VoteDeadlineExtensionLifecycleInput,
  type OpenVoteResult,
  type VoteRecusalLifecycleAction,
  type VoteReplacementLifecycleAction,
  type VoteReplacementStageMaterial,
  type VoteResolutionAmendmentLifecycleInput,
  type VoteSourceExclusionLifecycleAction,
  type ExcludePendingVoteSourceResult,
  type ManageVoteRecusalResult,
  type ReplaceVoteResult
} from "@boardagent/db";
import {
  DocumentValidationError,
  confirmationCode,
  prepareDocumentContribution,
  prepareManagementQuestion,
  prepareManagementQuestionTurn,
  uuidV7
} from "@boardagent/domain";
import type { Pool, PoolClient } from "pg";

import type {
  BoardAgentSurfaceService,
  HumanActionResolution,
  PersistHumanStageInput,
  PreparedHumanAction,
  ResolveHumanActionInput,
  SurfacePrincipal,
  SurfaceResourceResult,
  SurfaceToolResult,
  VoteCertificateSigningPort
} from "./ports.js";
import { ControlPlaneSurface } from "./control-plane-surface.js";
import type { WebhookSecurityPort } from "./webhook-security.js";

const ISSUE_ENROLLMENT = "issue_enrollment" as const;
const REISSUE_ACTIVATION = "reissue_activation" as const;
const MANAGE_MEMBER = "manage_member" as const;
const MANAGE_COMPANY_ADMIN = "manage_company_admin" as const;
const MANAGE_MEMBER_ADMIN_DELEGATION = "manage_member_admin_delegation" as const;
const CONFIRM_ENROLLMENT_ACTIVATION = "confirm_enrollment_activation" as const;
const PREPARE_ONBOARDING_ATTESTATION = "prepare_onboarding_attestation" as const;
const CREATE_DOCUMENT_VERSION = "create_document_version" as const;
const EVALUATE_MATTER = "evaluate_matter" as const;
const SUBMIT_DOCUMENT_TO_SECRETARIAT = "submit_document_to_secretariat" as const;
const REQUEST_MANAGEMENT_REVISION = "request_management_revision" as const;
const REPLY_TO_MANAGEMENT_REVISION = "reply_to_management_revision" as const;
const RESUBMIT_MANAGEMENT_MATERIALS = "resubmit_management_materials" as const;
const APPROVE_MANAGEMENT_SUBMISSION = "approve_management_submission" as const;
const REJECT_MANAGEMENT_SUBMISSION = "reject_management_submission" as const;
const ASK_MANAGEMENT = "ask_management" as const;
const ANSWER_MANAGEMENT_QUESTION = "answer_management_question" as const;
const FOLLOW_UP_MANAGEMENT_QUESTION = "follow_up_management_question" as const;
const CIRCULATE_DOCUMENT = "circulate_document" as const;
const MANAGE_DOCUMENT_ACCESS = "manage_document_access" as const;
const ARCHIVE_DOCUMENT = "archive_document" as const;
const SOFT_DELETE_DOCUMENT = "soft_delete_document" as const;
const RSVP = "rsvp" as const;
const CREATE_MEETING = "create_meeting" as const;
const AMEND_MEETING = "amend_meeting" as const;
const RECORD_ATTENDANCE = "record_attendance" as const;
const CORRECT_ATTENDANCE = "correct_attendance" as const;
const CANCEL_MEETING = "cancel_meeting" as const;
const COMPLETE_MEETING = "complete_meeting" as const;
const CREATE_MEETING_TRANSCRIPT_VERSION = "create_meeting_transcript_version" as const;
const VERIFY_MEETING_TRANSCRIPT = "verify_meeting_transcript" as const;
const LINK_MEETING_QNA = "link_meeting_qna" as const;
const CHALLENGE_TRANSCRIPT_TURN = "challenge_transcript_turn" as const;
const RESOLVE_TRANSCRIPT_CHALLENGE = "resolve_transcript_challenge" as const;
const CREATE_VOTE = "create_vote" as const;
const REPLACE_OPEN_VOTE = "replace_open_vote" as const;
const AMEND_RESOLUTION_TEXT = "amend_resolution_text" as const;
const EXTEND_VOTE_DEADLINE = "extend_vote_deadline" as const;
const STAGE_BALLOT = "stage_ballot" as const;
const GRANT_PROXY = "grant_proxy" as const;
const REVOKE_PROXY = "revoke_proxy" as const;
const MANAGE_RECUSAL = "manage_recusal" as const;
const EXCLUDE_PENDING_VOTE_SOURCE = "exclude_pending_vote_source" as const;
const CLOSE_VOTE = "close_vote" as const;
const CANCEL_VOTE = "cancel_vote" as const;
const COMMENT_MINUTES = "comment_minutes" as const;
const PROPOSE_MINUTES_REDLINE = "propose_minutes_redline" as const;
const WITHDRAW_MINUTES_COMMENT = "withdraw_minutes_comment" as const;
const CREATE_MINUTES_VERSION = "create_minutes_version" as const;
const PUBLISH_MINUTES = "publish_minutes" as const;
const RESOLVE_MINUTES_REVIEW_ITEM = "resolve_minutes_review_item" as const;
const CORRECT_MINUTES_PACKAGE = "correct_minutes_package" as const;
const PREPARE_MINUTES_FOR_SIGNATURE = "prepare_minutes_for_signature" as const;
const STAGE_MINUTES_SIGNATURE = "stage_minutes_signature" as const;
const FINALIZE_MINUTES = "finalize_minutes" as const;
const CREATE_MINUTES_CORRECTION_CYCLE = "create_minutes_correction_cycle" as const;
const CANCEL_MINUTES = "cancel_minutes" as const;
const LOG_MINUTES_ACTION_ITEMS = "log_minutes_action_items" as const;
const DECLARE_NO_MINUTES_ACTION_ITEMS = "declare_no_minutes_action_items" as const;
const CREATE_TASK = "create_task" as const;
const START_TASK = "start_task" as const;
const SUBMIT_TASK_EVIDENCE = "submit_task_evidence" as const;
const REVIEW_TASK_EVIDENCE = "review_task_evidence" as const;
const COMPLETE_TASK = "complete_task" as const;
const CREATE_TASK_CORRECTION_CYCLE = "create_task_correction_cycle" as const;
const CANCEL_TASK = "cancel_task" as const;
const PROPOSE_ACTION = "propose_action" as const;
const WITHDRAW_PROPOSAL = "withdraw_proposal" as const;
const APPROVE_PROPOSAL = "approve_proposal" as const;
const REJECT_PROPOSAL = "reject_proposal" as const;
const ASK_SECRETARIAT = "ask_secretariat" as const;
const REPLY_SECRETARIAT_REQUEST = "reply_secretariat_request" as const;
const CLOSE_SECRETARIAT_REQUEST = "close_secretariat_request" as const;
const CANCEL_DRAFT = "cancel_draft" as const;
const ENROLLMENT_UNAVAILABLE_BINDING_SCHEMA = "boardagent.enrollment-unavailable.v1" as const;
const MEMBER_UNAVAILABLE_BINDING_SCHEMA = "boardagent.member-invite-unavailable.v1" as const;
const ACTIVATION_UNAVAILABLE_BINDING_SCHEMA =
  "boardagent.enrollment-activation-unavailable.v1" as const;

type ReadSurface = Pick<BoardAgentSurfaceService, "executeRead" | "readResource">;
type ManagementWorkflowTool =
  | typeof SUBMIT_DOCUMENT_TO_SECRETARIAT
  | typeof REQUEST_MANAGEMENT_REVISION
  | typeof REPLY_TO_MANAGEMENT_REVISION
  | typeof RESUBMIT_MANAGEMENT_MATERIALS
  | typeof APPROVE_MANAGEMENT_SUBMISSION
  | typeof REJECT_MANAGEMENT_SUBMISSION;
type CommunicationTool =
  | typeof PROPOSE_ACTION
  | typeof WITHDRAW_PROPOSAL
  | typeof APPROVE_PROPOSAL
  | typeof REJECT_PROPOSAL
  | typeof ASK_SECRETARIAT
  | typeof REPLY_SECRETARIAT_REQUEST
  | typeof CLOSE_SECRETARIAT_REQUEST;
type ManagementQuestionTool =
  typeof ASK_MANAGEMENT | typeof ANSWER_MANAGEMENT_QUESTION | typeof FOLLOW_UP_MANAGEMENT_QUESTION;
type DocumentLifecycleTool =
  | typeof CIRCULATE_DOCUMENT
  | typeof MANAGE_DOCUMENT_ACCESS
  | typeof ARCHIVE_DOCUMENT
  | typeof SOFT_DELETE_DOCUMENT;
type MeetingLifecycleTool =
  | typeof CREATE_MEETING
  | typeof AMEND_MEETING
  | typeof CORRECT_ATTENDANCE
  | typeof CANCEL_MEETING
  | typeof COMPLETE_MEETING;
type TranscriptLifecycleTool =
  typeof VERIFY_MEETING_TRANSCRIPT | typeof LINK_MEETING_QNA | typeof RESOLVE_TRANSCRIPT_CHALLENGE;
type BallotLifecycleTool = typeof STAGE_BALLOT | typeof GRANT_PROXY | typeof REVOKE_PROXY;
type MinutesLifecycleTool =
  | typeof PUBLISH_MINUTES
  | typeof RESOLVE_MINUTES_REVIEW_ITEM
  | typeof CORRECT_MINUTES_PACKAGE
  | typeof PREPARE_MINUTES_FOR_SIGNATURE
  | typeof STAGE_MINUTES_SIGNATURE
  | typeof FINALIZE_MINUTES
  | typeof CREATE_MINUTES_CORRECTION_CYCLE
  | typeof CANCEL_MINUTES
  | typeof LOG_MINUTES_ACTION_ITEMS
  | typeof DECLARE_NO_MINUTES_ACTION_ITEMS;
type TaskLifecycleTool =
  | typeof REVIEW_TASK_EVIDENCE
  | typeof COMPLETE_TASK
  | typeof CREATE_TASK_CORRECTION_CYCLE
  | typeof CANCEL_TASK;

function isMinutesLifecycleTool(tool: string): tool is MinutesLifecycleTool {
  return (
    tool === PUBLISH_MINUTES ||
    tool === RESOLVE_MINUTES_REVIEW_ITEM ||
    tool === CORRECT_MINUTES_PACKAGE ||
    tool === PREPARE_MINUTES_FOR_SIGNATURE ||
    tool === STAGE_MINUTES_SIGNATURE ||
    tool === FINALIZE_MINUTES ||
    tool === CREATE_MINUTES_CORRECTION_CYCLE ||
    tool === CANCEL_MINUTES ||
    tool === LOG_MINUTES_ACTION_ITEMS ||
    tool === DECLARE_NO_MINUTES_ACTION_ITEMS
  );
}

function isTaskLifecycleTool(tool: string): tool is TaskLifecycleTool {
  return (
    tool === REVIEW_TASK_EVIDENCE ||
    tool === COMPLETE_TASK ||
    tool === CREATE_TASK_CORRECTION_CYCLE ||
    tool === CANCEL_TASK
  );
}

function isNamedRecusal(input: JsonValue, kind: string): boolean {
  return (
    input !== null &&
    typeof input === "object" &&
    "object_type" in input &&
    input["object_type"] === kind
  );
}

function isDocumentLifecycleTool(tool: string): tool is DocumentLifecycleTool {
  return (
    tool === CIRCULATE_DOCUMENT ||
    tool === MANAGE_DOCUMENT_ACCESS ||
    tool === ARCHIVE_DOCUMENT ||
    tool === SOFT_DELETE_DOCUMENT
  );
}

function isMeetingLifecycleTool(tool: string): tool is MeetingLifecycleTool {
  return (
    tool === CREATE_MEETING ||
    tool === AMEND_MEETING ||
    tool === CORRECT_ATTENDANCE ||
    tool === CANCEL_MEETING ||
    tool === COMPLETE_MEETING
  );
}

function isTranscriptLifecycleTool(tool: string): tool is TranscriptLifecycleTool {
  return (
    tool === VERIFY_MEETING_TRANSCRIPT ||
    tool === LINK_MEETING_QNA ||
    tool === RESOLVE_TRANSCRIPT_CHALLENGE
  );
}

function isBallotLifecycleTool(tool: string): tool is BallotLifecycleTool {
  return tool === STAGE_BALLOT || tool === GRANT_PROXY || tool === REVOKE_PROXY;
}

export interface PgBoardAgentSurfaceServiceOptions {
  readonly reads: ReadSurface;
  readonly transaction?: TransactionOptions;
  readonly now?: () => Date;
  readonly entropy?: (length: number) => Buffer;
  readonly newId?: () => string;
  readonly voteCertificateSigner?: VoteCertificateSigningPort;
  readonly webhookSecurity?: WebhookSecurityPort;
}

function secureBytes(entropy: (length: number) => Buffer, length: number): Buffer {
  const value = entropy(length);
  if (value.length !== length) throw new Error("secure entropy source returned the wrong length");
  return value;
}

function exactServiceOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("surface principal service origin is invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== value ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new TypeError("surface principal requires one canonical HTTPS service origin");
  }
  return value;
}

function requestContext(principal: SurfacePrincipal) {
  return {
    organizationId: UuidV7Schema.parse(principal.organizationId),
    memberId: UuidV7Schema.parse(principal.memberId),
    clientId: UuidV7Schema.parse(principal.clientId),
    tokenJti: UuidV7Schema.parse(principal.tokenJti),
    boardIds: principal.boardIds.map((boardId) => UuidV7Schema.parse(boardId))
  } as const;
}

function invitationLink(origin: string, token: string): string {
  const path = new URL("/enroll", `${exactServiceOrigin(origin)}/`).href;
  return `${path}#${token}`;
}

function restartLink(origin: string, token: string): string {
  const path = new URL("/enroll/restart", `${exactServiceOrigin(origin)}/`).href;
  return `${path}#${token}`;
}

function result(
  tool:
    | typeof ISSUE_ENROLLMENT
    | typeof REISSUE_ACTIVATION
    | typeof MANAGE_MEMBER
    | typeof MANAGE_COMPANY_ADMIN
    | typeof MANAGE_MEMBER_ADMIN_DELEGATION
    | typeof CONFIRM_ENROLLMENT_ACTIVATION
    | typeof PREPARE_ONBOARDING_ATTESTATION
    | typeof CREATE_DOCUMENT_VERSION
    | typeof EVALUATE_MATTER
    | ManagementWorkflowTool
    | CommunicationTool
    | ManagementQuestionTool
    | typeof CANCEL_DRAFT
    | DocumentLifecycleTool
    | typeof RSVP
    | typeof RECORD_ATTENDANCE
    | MeetingLifecycleTool
    | typeof CREATE_MEETING_TRANSCRIPT_VERSION
    | typeof CHALLENGE_TRANSCRIPT_TURN
    | TranscriptLifecycleTool
    | typeof CREATE_VOTE
    | typeof REPLACE_OPEN_VOTE
    | typeof AMEND_RESOLUTION_TEXT
    | typeof EXTEND_VOTE_DEADLINE
    | BallotLifecycleTool
    | typeof MANAGE_RECUSAL
    | typeof EXCLUDE_PENDING_VOTE_SOURCE
    | typeof CLOSE_VOTE
    | typeof CANCEL_VOTE
    | typeof COMMENT_MINUTES
    | typeof PROPOSE_MINUTES_REDLINE
    | typeof WITHDRAW_MINUTES_COMMENT
    | typeof CREATE_MINUTES_VERSION
    | typeof CREATE_TASK
    | typeof START_TASK
    | typeof SUBMIT_TASK_EVIDENCE
    | MinutesLifecycleTool
    | TaskLifecycleTool,
  status: SurfaceToolResult["status"],
  reference: string,
  data: JsonValue,
  resourceUri: string | null = null
): SurfaceToolResult {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status,
    reference,
    resource_uri: resourceUri,
    data
  };
}

/**
 * Incremental production surface composition. Reads delegate to the complete frozen
 * read repository; confirmed actions are added only after their own database proof.
 */
export class PgBoardAgentSurfaceService implements BoardAgentSurfaceService {
  private readonly reads: ReadSurface;
  private readonly transaction: TransactionOptions;
  private readonly now: () => Date;
  private readonly entropy: (length: number) => Buffer;
  private readonly newId: () => string;
  private readonly voteCertificateSigner: VoteCertificateSigningPort | undefined;
  private readonly controlPlane: ControlPlaneSurface;
  private readonly voteCreationMaterial = new WeakMap<
    PreparedHumanAction,
    VoteCreationStageMaterial
  >();
  private readonly voteReplacementMaterial = new WeakMap<
    PreparedHumanAction,
    VoteReplacementStageMaterial
  >();
  private readonly voteEditReplacement = new WeakMap<
    PreparedHumanAction,
    {
      readonly action: VoteReplacementLifecycleAction;
      readonly material: VoteReplacementStageMaterial;
    }
  >();
  private readonly voteCloseMaterial = new WeakMap<PreparedHumanAction, VoteCloseStageMaterial>();

  public constructor(
    private readonly pool: Pool,
    options: PgBoardAgentSurfaceServiceOptions
  ) {
    this.reads = options.reads;
    this.transaction = { ...options.transaction, isolation: "serializable" };
    this.now = options.now ?? (() => new Date());
    this.entropy = options.entropy ?? randomBytes;
    this.newId =
      options.newId ?? (() => uuidV7(this.now().getTime(), secureBytes(this.entropy, 10)));
    this.voteCertificateSigner = options.voteCertificateSigner;
    this.controlPlane = new ControlPlaneSurface(pool, {
      transaction: this.transaction,
      now: this.now,
      entropy: this.entropy,
      newId: this.newId,
      ...(options.webhookSecurity === undefined ? {} : { webhookSecurity: options.webhookSecurity })
    });
  }

  public executeRead(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    return this.reads.executeRead(principal, tool, input);
  }

  public async executeDirect(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    if (this.controlPlane.handlesDirectTool(tool)) {
      return this.controlPlane.executeDirect(principal, tool, input);
    }
    if (tool === EVALUATE_MATTER) {
      return this.evaluateMatter(principal, input);
    }
    if (tool === CREATE_DOCUMENT_VERSION) {
      return this.createDocumentVersion(principal, input);
    }
    if (tool === SUBMIT_DOCUMENT_TO_SECRETARIAT) {
      return this.submitDocumentToSecretariat(principal, input);
    }
    if (tool === REQUEST_MANAGEMENT_REVISION) {
      return this.requestManagementRevision(principal, input);
    }
    if (tool === REPLY_TO_MANAGEMENT_REVISION) {
      return this.replyToManagementRevision(principal, input);
    }
    if (tool === RESUBMIT_MANAGEMENT_MATERIALS) {
      return this.resubmitManagementMaterials(principal, input);
    }
    if (tool === APPROVE_MANAGEMENT_SUBMISSION || tool === REJECT_MANAGEMENT_SUBMISSION) {
      return this.disposeManagementSubmission(principal, tool, input);
    }
    if (
      tool === PROPOSE_ACTION ||
      tool === WITHDRAW_PROPOSAL ||
      tool === APPROVE_PROPOSAL ||
      tool === REJECT_PROPOSAL ||
      tool === ASK_SECRETARIAT ||
      tool === REPLY_SECRETARIAT_REQUEST ||
      tool === CLOSE_SECRETARIAT_REQUEST
    ) {
      return this.executeCommunication(principal, tool, input);
    }
    if (
      tool === ASK_MANAGEMENT ||
      tool === ANSWER_MANAGEMENT_QUESTION ||
      tool === FOLLOW_UP_MANAGEMENT_QUESTION
    ) {
      return this.executeManagementQuestion(principal, tool, input);
    }
    if (tool === CANCEL_DRAFT) {
      return this.cancelDraft(principal, input);
    }
    if (tool === CREATE_MINUTES_VERSION) {
      return this.createMinutesVersion(principal, input);
    }
    if (tool === COMMENT_MINUTES || tool === PROPOSE_MINUTES_REDLINE) {
      return this.submitMinutesReview(principal, tool, input);
    }
    if (tool === WITHDRAW_MINUTES_COMMENT) {
      return this.withdrawMinutesComment(principal, input);
    }
    if (tool === START_TASK) {
      return this.startTask(principal, input);
    }
    if (tool === SUBMIT_TASK_EVIDENCE) {
      return this.submitTaskEvidence(principal, input);
    }
    if (tool === RSVP) {
      return this.recordMeetingRsvp(principal, input);
    }
    if (tool === RECORD_ATTENDANCE) {
      return this.recordMeetingAttendance(principal, input);
    }
    if (tool === CREATE_MEETING_TRANSCRIPT_VERSION) {
      return this.createMeetingTranscriptVersion(principal, input);
    }
    if (tool === CHALLENGE_TRANSCRIPT_TURN) {
      return this.challengeTranscriptTurn(principal, input);
    }
    if (tool === PREPARE_ONBOARDING_ATTESTATION) {
      const stageToken = secureBytes(this.entropy, 32).toString("base64url");
      try {
        const prepared = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            prepareOnboardingStageInTransaction(client, {
              originalArguments: input,
              exactOrigin: exactServiceOrigin(principal.serviceOrigin),
              stageId: this.newId(),
              stageTokenSha256: sha256Hex(stageToken),
              idempotencyRecordId: this.newId(),
              auditEventId: this.newId()
            }),
          this.transaction
        );
        const target = new URL("/onboarding", `${exactServiceOrigin(principal.serviceOrigin)}/`);
        if (!prepared.replayed) target.hash = stageToken;
        return result(
          PREPARE_ONBOARDING_ATTESTATION,
          prepared.replayed ? "already_applied" : "accepted",
          prepared.stageId,
          {
            stage_id: prepared.stageId,
            board_id: prepared.boardId,
            terms_version_id: prepared.termsVersionId,
            support_version_id: prepared.supportVersionId,
            expires_at: prepared.expiresAt,
            onboarding_url: prepared.replayed ? null : target.href,
            secret_once: true,
            next_step: prepared.replayed
              ? "The one-time onboarding URL was already returned. Start a new ceremony after this stage expires if it was lost."
              : "Open the URL in a browser, review the exact terms and choices, then attest with your passkey."
          }
        );
      } catch (error) {
        if (
          error instanceof OnboardingTransactionError &&
          error.code === "onboarding_already_current"
        ) {
          return result(PREPARE_ONBOARDING_ATTESTATION, "already_applied", principal.memberId, {
            board_id:
              typeof input === "object" && input !== null && !Array.isArray(input)
                ? ((input as Readonly<Record<string, JsonValue>>)["board_id"] ?? null)
                : null,
            onboarding_current: true,
            onboarding_url: null,
            secret_once: true
          });
        }
        throw error;
      }
    }
    throw new Error(`direct surface action is not implemented yet: ${tool}`);
  }

  private async cancelDraft(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(CANCEL_DRAFT).parse(input) as {
      readonly draft_id: string;
      readonly idempotency_key: string;
      readonly reason: string;
    };
    const cancelled = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        cancelWizardDraftInTransaction(client, {
          organizationId: principal.organizationId,
          exactOrigin: principal.serviceOrigin,
          draftId: parsed.draft_id,
          reason: parsed.reason,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(
      CANCEL_DRAFT,
      cancelled.replayed ? "already_applied" : "accepted",
      cancelled.draftId,
      cancelled.replayed
        ? {
            schema_version: "boardagent.draft-cancel-result.v1",
            draft_id: cancelled.draftId,
            response_sha256: cancelled.responseSha256,
            replayed: true
          }
        : {
            schema_version: "boardagent.draft-cancel-result.v1",
            board_id: cancelled.boardId,
            draft_id: cancelled.draftId,
            state: cancelled.state,
            row_version: cancelled.rowVersion.toString(10),
            response_sha256: cancelled.responseSha256,
            replayed: false
          }
    );
  }

  private async evaluateMatter(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(EVALUATE_MATTER).parse(input) as {
      readonly board_id: string;
      readonly expected_profile_id: string;
      readonly expected_ruleset_id: string;
      readonly facts: {
        readonly values: Readonly<Record<string, string | number | boolean | null>>;
      };
      readonly idempotency_key: string;
      readonly matter_type_id: string;
    };
    const evaluated = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      async (client) => {
        const matterType = await client.query<{ code: string }>(
          "select boardagent_resolve_matter_type_code($1,$2,$3,$4) as code",
          [
            parsed.board_id,
            parsed.matter_type_id,
            parsed.expected_profile_id,
            parsed.expected_ruleset_id
          ]
        );
        const code = matterType.rows[0]?.code;
        if (!code || matterType.rows.length !== 1) {
          throw new Error("matter evaluation is unavailable");
        }
        return evaluateMatterInTransaction(client, {
          organizationId: principal.organizationId,
          boardId: parsed.board_id,
          matterTypeId: parsed.matter_type_id,
          matterTypeCode: code,
          facts: parsed.facts.values,
          expectedProfileId: parsed.expected_profile_id,
          expectedRulesetId: parsed.expected_ruleset_id,
          evaluationId: this.newId(),
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        });
      },
      this.transaction
    );
    return result(
      EVALUATE_MATTER,
      evaluated.replayed ? "already_applied" : "accepted",
      evaluated.evaluationId,
      {
        schema_version: "boardagent.matter-evaluation-result.v1",
        evaluation_id: evaluated.evaluationId,
        status: evaluated.status,
        matched_rule_id: evaluated.matchedRuleId,
        selected_approval_rule_id: evaluated.selectedApprovalRuleId,
        candidate_rule_ids: evaluated.candidateRuleIds,
        missing_fields: evaluated.missingFields,
        result_sha256: evaluated.resultSha256,
        replayed: evaluated.replayed
      },
      `board://${parsed.board_id}/matter-evaluations/${evaluated.evaluationId}`
    );
  }

  private async submitDocumentToSecretariat(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(SUBMIT_DOCUMENT_TO_SECRETARIAT).parse(input) as {
      readonly board_id: string;
      readonly document_references: readonly {
        readonly document_id: string;
        readonly version_id: string;
        readonly sha256: string;
      }[];
      readonly idempotency_key: string;
      readonly purpose: string;
      readonly submission_id: string;
    };
    const created = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      async (client) => {
        const secretaries = await client.query<{ member_id: string }>(
          `select membership.member_id
             from board_memberships as membership
            where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
              and membership.board_id=$1
              and membership.is_secretary
              and membership.state='active'
              and membership.active_from<=transaction_timestamp()
              and (membership.active_until is null
                   or membership.active_until>transaction_timestamp())
            order by membership.active_from,membership.id
            limit 2`,
          [parsed.board_id]
        );
        if (secretaries.rows.length !== 1 || !secretaries.rows[0]) {
          throw new Error(
            "management submission is unavailable: board requires exactly one active assigned secretary"
          );
        }
        return submitDocumentToSecretariatInTransaction(client, {
          organizationId: principal.organizationId,
          submissionId: parsed.submission_id,
          versionId: this.newId(),
          boardId: parsed.board_id,
          assignedSecretaryMemberId: secretaries.rows[0].member_id,
          documentReferences: parsed.document_references.map(
            ({ document_id, version_id, sha256 }) => ({
              documentId: document_id,
              versionId: version_id,
              sha256
            })
          ),
          purpose: parsed.purpose,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        });
      },
      this.transaction
    );
    const resourceUri = `board://${parsed.board_id}/management-submissions/${created.submissionId}`;
    return result(
      SUBMIT_DOCUMENT_TO_SECRETARIAT,
      created.replayed ? "already_applied" : "accepted",
      created.submissionId,
      created.replayed
        ? {
            schema_version: "boardagent.management-submission-result.v1",
            submission_id: created.submissionId,
            response_sha256: created.responseSha256,
            replayed: true
          }
        : {
            schema_version: "boardagent.management-submission-result.v1",
            board_id: created.boardId,
            submission_id: created.submissionId,
            version_id: created.versionId,
            version: 1,
            state: created.state,
            row_version: created.rowVersion.toString(10),
            response_sha256: created.responseSha256,
            replayed: false
          },
      resourceUri
    );
  }

  private async requestManagementRevision(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(REQUEST_MANAGEMENT_REVISION).parse(input) as {
      readonly idempotency_key: string;
      readonly reason: string;
      readonly submission_id: string;
    };
    const changed = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        requestManagementRevisionInTransaction(client, {
          organizationId: principal.organizationId,
          requestId: this.newId(),
          submissionId: parsed.submission_id,
          reason: parsed.reason,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(
      REQUEST_MANAGEMENT_REVISION,
      changed.replayed ? "already_applied" : "accepted",
      changed.submissionId,
      changed.replayed
        ? {
            schema_version: "boardagent.management-revision-request-result.v1",
            submission_id: changed.submissionId,
            response_sha256: changed.responseSha256,
            replayed: true
          }
        : {
            schema_version: "boardagent.management-revision-request-result.v1",
            board_id: changed.boardId,
            submission_id: changed.submissionId,
            version_id: changed.versionId,
            revision_request_id: changed.revisionRequestId ?? null,
            state: changed.state,
            row_version: changed.rowVersion.toString(10),
            response_sha256: changed.responseSha256,
            replayed: false
          }
    );
  }

  private async replyToManagementRevision(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(REPLY_TO_MANAGEMENT_REVISION).parse(input) as {
      readonly idempotency_key: string;
      readonly reply: string;
      readonly revision_request_id: string;
      readonly submission_id: string;
    };
    const changed = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        replyToManagementRevisionInTransaction(client, {
          organizationId: principal.organizationId,
          replyId: this.newId(),
          submissionId: parsed.submission_id,
          revisionRequestId: parsed.revision_request_id,
          reply: parsed.reply,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(
      REPLY_TO_MANAGEMENT_REVISION,
      changed.replayed ? "already_applied" : "accepted",
      changed.submissionId,
      changed.replayed
        ? {
            schema_version: "boardagent.management-revision-reply-result.v1",
            submission_id: changed.submissionId,
            response_sha256: changed.responseSha256,
            replayed: true
          }
        : {
            schema_version: "boardagent.management-revision-reply-result.v1",
            board_id: changed.boardId,
            submission_id: changed.submissionId,
            version_id: changed.versionId,
            revision_request_id: changed.revisionRequestId ?? parsed.revision_request_id,
            reply_id: changed.replyId ?? null,
            state: changed.state,
            row_version: changed.rowVersion.toString(10),
            response_sha256: changed.responseSha256,
            replayed: false
          }
    );
  }

  private async resubmitManagementMaterials(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(RESUBMIT_MANAGEMENT_MATERIALS).parse(input) as {
      readonly document_references: readonly {
        readonly document_id: string;
        readonly version_id: string;
        readonly sha256: string;
      }[];
      readonly idempotency_key: string;
      readonly reason: string;
      readonly submission_id: string;
    };
    const { changed, visibleVoteIds } = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      async (client) => {
        const submission = await client.query<{
          assigned_secretary_id: string;
          board_id: string;
          current_payload_sha256: Buffer;
          current_version: number;
          current_version_id: string;
        }>(
          `select thread.assigned_secretary_id,thread.board_id,thread.current_version_id,
                  version.version as current_version,version.payload_sha256 as current_payload_sha256
             from management_submission_threads as thread
             join management_submission_versions as version on version.id=thread.current_version_id
            where thread.id=$1`,
          [parsed.submission_id]
        );
        const current = submission.rows[0];
        if (!current || submission.rows.length !== 1) {
          throw new Error("management resubmission is unavailable");
        }
        const linkedVotes = await client.query<{ vote_id: string }>(
          `select vote.id as vote_id
             from votes as vote
             join decision_packages as package
               on package.vote_id=vote.id and package.id=vote.current_decision_package_id
            where vote.state in ('open','source_update_pending')
              and exists (
                select 1 from decision_package_components as component
                 where component.decision_package_id=package.id
                   and component.component_class='submission'
                   and component.object_type='management_submission_version'
                   and component.object_id=$1
                   and component.object_version=$2::bigint
                   and component.object_sha256=$3
              )
            order by vote.id`,
          [current.current_version_id, current.current_version, current.current_payload_sha256]
        );
        const primaryAuditEventId = this.newId();
        const changed = await resubmitManagementMaterialsInTransaction(client, {
          organizationId: principal.organizationId,
          submissionId: parsed.submission_id,
          versionId: this.newId(),
          documentReferences: parsed.document_references.map(
            ({ document_id, version_id, sha256 }) => ({
              documentId: document_id,
              versionId: version_id,
              sha256
            })
          ),
          reason: parsed.reason,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: primaryAuditEventId,
          secretaryDelivery: {
            secretaryMemberId: current.assigned_secretary_id,
            noticeId: this.newId(),
            feedId: this.newId()
          },
          sourceUpdateAuditEvents: linkedVotes.rows.map(({ vote_id }) => ({
            voteId: vote_id,
            causeId: this.newId(),
            auditEventId: this.newId()
          }))
        });
        return {
          changed,
          visibleVoteIds: changed.replayed
            ? []
            : await this.visibleSourceUpdateVoteIds(client, changed.sourceUpdateVoteIds)
        };
      },
      this.transaction
    );
    return result(
      RESUBMIT_MANAGEMENT_MATERIALS,
      changed.replayed ? "already_applied" : "accepted",
      changed.submissionId,
      {
        schema_version: "boardagent.management-resubmission-result.v1",
        submission_id: changed.submissionId,
        version_id: changed.versionId,
        version: changed.version,
        payload_sha256: changed.payloadSha256,
        state: "resubmitted",
        source_update_vote_ids: visibleVoteIds,
        response_sha256: changed.responseSha256,
        replayed: changed.replayed
      }
    );
  }

  private async disposeManagementSubmission(
    principal: SurfacePrincipal,
    tool: typeof APPROVE_MANAGEMENT_SUBMISSION | typeof REJECT_MANAGEMENT_SUBMISSION,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(tool).parse(input) as {
      readonly idempotency_key: string;
      readonly reason?: string;
      readonly submission_id: string;
      readonly version_id: string;
    };
    const resultingDraftId = tool === APPROVE_MANAGEMENT_SUBMISSION ? this.newId() : null;
    const draftContext =
      resultingDraftId === null
        ? null
        : {
            schemaVersion: "boardagent.management-draft-context.v1" as const,
            submissionId: parsed.submission_id,
            versionId: parsed.version_id,
            resultingDraftId
          };
    const signedContext =
      draftContext === null ? null : Buffer.from(canonicalJson(draftContext), "utf8");
    const changed = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        tool === APPROVE_MANAGEMENT_SUBMISSION
          ? approveManagementSubmissionInTransaction(client, {
              organizationId: principal.organizationId,
              dispositionId: this.newId(),
              submissionId: parsed.submission_id,
              versionId: parsed.version_id,
              resultingDraftId: resultingDraftId!,
              signedContext: signedContext!,
              contextSha256: sha256Hex(signedContext!),
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            })
          : rejectManagementSubmissionInTransaction(client, {
              organizationId: principal.organizationId,
              dispositionId: this.newId(),
              submissionId: parsed.submission_id,
              versionId: parsed.version_id,
              reason: parsed.reason!,
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
      this.transaction
    );
    return result(
      tool,
      changed.replayed ? "already_applied" : "accepted",
      changed.submissionId,
      changed.replayed
        ? {
            schema_version: "boardagent.management-disposition-result.v1",
            submission_id: changed.submissionId,
            response_sha256: changed.responseSha256,
            replayed: true
          }
        : {
            schema_version: "boardagent.management-disposition-result.v1",
            board_id: changed.boardId,
            submission_id: changed.submissionId,
            version_id: changed.versionId,
            state: changed.state,
            row_version: changed.rowVersion.toString(10),
            resulting_draft_id: changed.resultingDraftId ?? null,
            response_sha256: changed.responseSha256,
            replayed: false
          }
    );
  }

  private communicationResult(
    tool: CommunicationTool,
    changed: CommunicationMutationResult,
    details: Readonly<Record<string, JsonValue>> = {}
  ): SurfaceToolResult {
    return result(
      tool,
      changed.replayed ? "already_applied" : "accepted",
      changed.objectId,
      changed.replayed
        ? {
            schema_version: "boardagent.communication-result.v1",
            object_id: changed.objectId,
            response_sha256: changed.responseSha256,
            replayed: true,
            ...details
          }
        : {
            schema_version: "boardagent.communication-result.v1",
            object_id: changed.objectId,
            state: changed.state,
            row_version: changed.rowVersion.toString(10),
            resulting_draft_id: changed.resultingDraftId ?? null,
            response_sha256: changed.responseSha256,
            replayed: false,
            ...details
          }
    );
  }

  private async executeCommunication(
    principal: SurfacePrincipal,
    tool: CommunicationTool,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    switch (tool) {
      case PROPOSE_ACTION: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly board_id: string;
          readonly idempotency_key: string;
          readonly payload: JsonValue;
          readonly proposal_id: string;
          readonly proposal_type: "meeting" | "vote" | "document" | "minutes" | "task" | "other";
          readonly references: readonly { readonly sha256: string; readonly uri: string }[];
          readonly title: string;
        };
        const changed = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            proposeActionInTransaction(client, {
              organizationId: principal.organizationId,
              proposalId: parsed.proposal_id,
              boardId: parsed.board_id,
              proposalType: parsed.proposal_type,
              title: parsed.title,
              payload: parsed.payload,
              references: parsed.references,
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
          this.transaction
        );
        return this.communicationResult(tool, changed, {
          board_id: parsed.board_id,
          proposal_id: changed.objectId
        });
      }
      case WITHDRAW_PROPOSAL: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly idempotency_key: string;
          readonly proposal_id: string;
        };
        const changed = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            withdrawProposalInTransaction(client, {
              organizationId: principal.organizationId,
              proposalId: parsed.proposal_id,
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
          this.transaction
        );
        return this.communicationResult(tool, changed, { proposal_id: changed.objectId });
      }
      case APPROVE_PROPOSAL: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly draft_type: "meeting" | "vote" | "minutes" | "task" | "proposal";
          readonly idempotency_key: string;
          readonly proposal_id: string;
          readonly resulting_draft_id: string;
        };
        const draftContext = {
          schemaVersion: "boardagent.proposal-draft-context.v1" as const,
          proposalId: parsed.proposal_id,
          resultingDraftId: parsed.resulting_draft_id,
          draftType: parsed.draft_type
        };
        const signedContext = Buffer.from(canonicalJson(draftContext), "utf8");
        const changed = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            approveProposalInTransaction(client, {
              organizationId: principal.organizationId,
              dispositionId: this.newId(),
              proposalId: parsed.proposal_id,
              resultingDraftId: parsed.resulting_draft_id,
              draftType: parsed.draft_type,
              signedContext,
              contextSha256: sha256Hex(signedContext),
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
          this.transaction
        );
        return this.communicationResult(tool, changed, {
          proposal_id: changed.objectId,
          resulting_draft_id: parsed.resulting_draft_id,
          draft_type: parsed.draft_type
        });
      }
      case REJECT_PROPOSAL: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly idempotency_key: string;
          readonly proposal_id: string;
          readonly reason: string;
        };
        const changed = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            rejectProposalInTransaction(client, {
              organizationId: principal.organizationId,
              dispositionId: this.newId(),
              proposalId: parsed.proposal_id,
              reason: parsed.reason,
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
          this.transaction
        );
        return this.communicationResult(tool, changed, { proposal_id: changed.objectId });
      }
      case ASK_SECRETARIAT: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly board_id: string;
          readonly idempotency_key: string;
          readonly message: string;
          readonly references: readonly { readonly sha256: string; readonly uri: string }[];
          readonly request_id: string;
          readonly topic: string;
        };
        const changed = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            askSecretariatInTransaction(client, {
              organizationId: principal.organizationId,
              requestId: parsed.request_id,
              initialTurnId: this.newId(),
              boardId: parsed.board_id,
              topic: parsed.topic,
              message: parsed.message,
              references: parsed.references,
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
          this.transaction
        );
        return this.communicationResult(tool, changed, {
          board_id: parsed.board_id,
          request_id: changed.objectId
        });
      }
      case REPLY_SECRETARIAT_REQUEST: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly idempotency_key: string;
          readonly reply: string;
          readonly request_id: string;
        };
        const changed = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            replySecretariatRequestInTransaction(client, {
              organizationId: principal.organizationId,
              requestId: parsed.request_id,
              turnId: this.newId(),
              reply: parsed.reply,
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
          this.transaction
        );
        return this.communicationResult(tool, changed, { request_id: changed.objectId });
      }
      case CLOSE_SECRETARIAT_REQUEST: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly idempotency_key: string;
          readonly request_id: string;
        };
        const changed = await withRequestTransaction(
          this.pool,
          requestContext(principal),
          (client) =>
            closeSecretariatRequestInTransaction(client, {
              organizationId: principal.organizationId,
              requestId: parsed.request_id,
              idempotencyRecordId: this.newId(),
              idempotencyKey: parsed.idempotency_key,
              auditEventId: this.newId()
            }),
          this.transaction
        );
        return this.communicationResult(tool, changed, { request_id: changed.objectId });
      }
    }
  }

  private async assertDocumentVersionReferences(
    client: PoolClient,
    references: readonly {
      readonly document_id: string;
      readonly version_id: string;
      readonly sha256: string;
    }[],
    unavailableMessage: string
  ): Promise<void> {
    if (references.length === 0) return;
    const expected = references.toSorted((left, right) =>
      left.version_id.localeCompare(right.version_id)
    );
    const found = await client.query<{
      document_id: string;
      sha256: string;
      version_id: string;
    }>(
      `select version.document_id,version.id as version_id,encode(version.sha256,'hex') as sha256
         from document_versions as version
        where version.id=any($1::uuid[])
        order by version.id`,
      [expected.map(({ version_id }) => version_id)]
    );
    if (
      found.rows.length !== expected.length ||
      found.rows.some((row, index) => {
        const reference = expected[index];
        return (
          !reference ||
          row.version_id !== reference.version_id ||
          row.document_id !== reference.document_id ||
          !safeHashEqual(row.sha256, reference.sha256)
        );
      })
    ) {
      throw new Error(unavailableMessage);
    }
  }

  private async questionSurfaceContext(
    client: PoolClient,
    questionId: string
  ): Promise<{
    readonly assignedOwnerIds: readonly string[];
    readonly askerMemberId: string;
    readonly boardId: string;
    readonly currentOrdinal: number;
  }> {
    const result = await client.query<{
      asker_member_id: string;
      assigned_owner_ids: string[];
      board_id: string;
      current_ordinal: number;
    }>(
      `select question.board_id,question.asker_member_id,question.assigned_owner_ids,
              turn.ordinal as current_ordinal
         from management_questions as question
         join management_question_turns as turn on turn.id=question.current_turn_id
        where question.id=$1`,
      [questionId]
    );
    const row = result.rows[0];
    if (
      !row ||
      result.rows.length !== 1 ||
      !Number.isSafeInteger(row.current_ordinal) ||
      row.current_ordinal < 1
    ) {
      throw new Error("management question is unavailable");
    }
    return {
      boardId: row.board_id,
      askerMemberId: row.asker_member_id,
      assignedOwnerIds: row.assigned_owner_ids,
      currentOrdinal: row.current_ordinal
    };
  }

  private async visibleSourceUpdateVoteIds(
    client: PoolClient,
    voteIds: readonly string[]
  ): Promise<readonly string[]> {
    if (voteIds.length === 0) return [];
    // The mutation must invalidate every linked vote. Only its public response
    // is projected through the actor's current personal read authority.
    const visible = await client.query<{ id: string }>(
      `select vote.id from votes as vote
        where vote.id=any($1::uuid[])
          and not boardagent_member_vote_recused(vote.id,
            boardagent_context_uuid('boardagent.member_id'))
        order by array_position($1::uuid[],vote.id)`,
      [voteIds]
    );
    return visible.rows.map(({ id }) => id);
  }

  private async linkedQuestionVoteIds(
    client: PoolClient,
    questionId: string,
    nextOrdinal: number
  ): Promise<readonly string[]> {
    const result = await client.query<{ vote_id: string }>(
      `select vote.id as vote_id
         from question_decision_links as link
         join decision_packages as package on package.id=link.decision_package_id
         join votes as vote
           on vote.id=package.vote_id and vote.current_decision_package_id=package.id
        where link.question_id=$1
          and $2::integer>link.inclusive_turn_ordinal
          and vote.state in ('open','source_update_pending')
        order by vote.id`,
      [questionId, nextOrdinal]
    );
    return result.rows.map(({ vote_id }) => vote_id);
  }

  private questionResult(
    tool: ManagementQuestionTool,
    changed:
      | Awaited<ReturnType<typeof askManagementQuestionInTransaction>>
      | Awaited<ReturnType<typeof answerManagementQuestionInTransaction>>,
    details: Readonly<Record<string, JsonValue>>
  ): SurfaceToolResult {
    return result(
      tool,
      changed.replayed ? "already_applied" : "accepted",
      changed.questionId,
      changed.replayed
        ? {
            schema_version: "boardagent.management-question-result.v1",
            question_id: changed.questionId,
            response_sha256: changed.responseSha256,
            replayed: true,
            ...details
          }
        : {
            schema_version: "boardagent.management-question-result.v1",
            question_id: changed.questionId,
            response_sha256: changed.responseSha256,
            replayed: false,
            ...details
          }
    );
  }

  private async executeManagementQuestion(
    principal: SurfacePrincipal,
    tool: ManagementQuestionTool,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    if (tool === ASK_MANAGEMENT) {
      const parsed = toolInputSchema(tool).parse(input) as {
        readonly board_id: string;
        readonly citations: readonly {
          readonly document_id: string;
          readonly version_id: string;
          readonly sha256: string;
        }[];
        readonly due_at: string;
        readonly idempotency_key: string;
        readonly owner_member_id: string;
        readonly question: string;
        readonly question_id: string;
      };
      const prepared = prepareManagementQuestion({
        questionId: parsed.question_id,
        boardId: parsed.board_id,
        question: parsed.question,
        assignedOwnerIds: [parsed.owner_member_id],
        dueAt: parsed.due_at,
        citations: parsed.citations.map(({ document_id, version_id, sha256 }) => ({
          sourceDocumentVersionId: version_id,
          sourceDocumentSha256: sha256,
          clause: "entire_document",
          locator: document_id
        })),
        visibility: [
          { granteeType: "seat_role", seatRole: "voting_member" },
          { granteeType: "seat_role", seatRole: "management" },
          { granteeType: "seat_role", seatRole: "observer" }
        ]
      });
      const changed = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        async (client) => {
          await this.assertDocumentVersionReferences(
            client,
            parsed.citations,
            "management question citation is unavailable"
          );
          return askManagementQuestionInTransaction(client, {
            organizationId: principal.organizationId,
            prepared,
            initialTurnId: this.newId(),
            auditEventId: this.newId(),
            idempotencyRecordId: this.newId(),
            idempotencyKey: parsed.idempotency_key,
            visibilityRecordIds: prepared.visibility.map(() => this.newId()),
            ownerDeliveries: [
              {
                ownerMemberId: parsed.owner_member_id,
                noticeId: this.newId(),
                feedId: this.newId()
              }
            ]
          });
        },
        this.transaction
      );
      return this.questionResult(tool, changed, {
        board_id: parsed.board_id,
        state: "pending",
        turn_ordinal: 1,
        due_at: parsed.due_at
      });
    }

    if (tool === ANSWER_MANAGEMENT_QUESTION) {
      const parsed = toolInputSchema(tool).parse(input) as {
        readonly answer: string;
        readonly idempotency_key: string;
        readonly question_id: string;
      };
      const prepared = prepareManagementQuestionTurn({
        questionId: parsed.question_id,
        turnKind: "answer",
        text: parsed.answer,
        citations: []
      });
      const { changed, visibleVoteIds } = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        async (client) => {
          const context = await this.questionSurfaceContext(client, parsed.question_id);
          const linkedVoteIds = await this.linkedQuestionVoteIds(
            client,
            parsed.question_id,
            context.currentOrdinal + 1
          );
          const primaryAuditEventId = this.newId();
          const changed = await answerManagementQuestionInTransaction(client, {
            organizationId: principal.organizationId,
            prepared,
            turnId: this.newId(),
            answerRecordId: this.newId(),
            auditEventId: primaryAuditEventId,
            idempotencyRecordId: this.newId(),
            idempotencyKey: parsed.idempotency_key,
            askerDelivery: {
              recipientMemberId: context.askerMemberId,
              noticeId: this.newId(),
              feedId: this.newId()
            },
            ownerResolutions: context.assignedOwnerIds.map((ownerMemberId) => ({
              ownerMemberId,
              tombstoneId: this.newId()
            })),
            sourceUpdateAuditEvents: linkedVoteIds.map((voteId) => ({
              voteId,
              causeId: this.newId(),
              auditEventId: this.newId()
            }))
          });
          return {
            changed,
            visibleVoteIds: changed.replayed
              ? []
              : await this.visibleSourceUpdateVoteIds(client, changed.sourceUpdateVoteIds)
          };
        },
        this.transaction
      );
      return this.questionResult(tool, changed, {
        state: "answered",
        turn_id: changed.replayed ? changed.turnId : changed.turnId,
        turn_ordinal: changed.replayed ? null : changed.turnOrdinal,
        row_version: changed.replayed ? null : changed.questionRowVersion.toString(10),
        source_update_vote_ids: visibleVoteIds
      });
    }

    const parsed = toolInputSchema(tool).parse(input) as {
      readonly due_at: string;
      readonly follow_up: string;
      readonly idempotency_key: string;
      readonly question_id: string;
    };
    const prepared = prepareManagementQuestionTurn({
      questionId: parsed.question_id,
      turnKind: "follow_up",
      text: parsed.follow_up,
      citations: [],
      dueAt: parsed.due_at
    });
    const { changed, visibleVoteIds } = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      async (client) => {
        const context = await this.questionSurfaceContext(client, parsed.question_id);
        const linkedVoteIds = await this.linkedQuestionVoteIds(
          client,
          parsed.question_id,
          context.currentOrdinal + 1
        );
        const primaryAuditEventId = this.newId();
        const changed = await followUpManagementQuestionInTransaction(client, {
          organizationId: principal.organizationId,
          prepared,
          turnId: this.newId(),
          auditEventId: primaryAuditEventId,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          ownerDeliveries: context.assignedOwnerIds.map((ownerMemberId) => ({
            ownerMemberId,
            noticeId: this.newId(),
            feedId: this.newId()
          })),
          sourceUpdateAuditEvents: linkedVoteIds.map((voteId) => ({
            voteId,
            causeId: this.newId(),
            auditEventId: this.newId()
          }))
        });
        return {
          changed,
          visibleVoteIds: changed.replayed
            ? []
            : await this.visibleSourceUpdateVoteIds(client, changed.sourceUpdateVoteIds)
        };
      },
      this.transaction
    );
    return this.questionResult(tool, changed, {
      state: "pending",
      due_at: parsed.due_at,
      turn_id: changed.turnId,
      turn_ordinal: changed.replayed ? null : changed.turnOrdinal,
      row_version: changed.replayed ? null : changed.questionRowVersion.toString(10),
      source_update_vote_ids: visibleVoteIds
    });
  }

  private async createMinutesVersion(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(CREATE_MINUTES_VERSION).parse(input) as {
      readonly canonical_text: string;
      readonly expected_current_version_id: string | null;
      readonly idempotency_key: string;
      readonly meeting_id: string;
      readonly minutes_id: string;
      readonly transcript_version_id: string | null;
    };
    const created = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        createMinutesVersionInTransaction(client, {
          minutesId: parsed.minutes_id,
          meetingId: parsed.meeting_id,
          canonicalText: parsed.canonical_text,
          transcriptVersionId: parsed.transcript_version_id,
          expectedCurrentVersionId: parsed.expected_current_version_id,
          minutesVersionId: this.newId(),
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    if (created.replayed) {
      return result(CREATE_MINUTES_VERSION, "already_applied", created.minutesVersionId, {
        schema_version: "boardagent.minutes-version-result.v1",
        board_id: created.boardId,
        minutes_id: created.minutesId,
        minutes_version_id: created.minutesVersionId,
        response_sha256: created.responseSha256,
        replayed: true
      });
    }
    return result(
      CREATE_MINUTES_VERSION,
      "accepted",
      created.minutesVersionId,
      {
        schema_version: "boardagent.minutes-version-result.v1",
        board_id: created.boardId,
        minutes_id: created.minutesId,
        minutes_version_id: created.minutesVersionId,
        version: created.version,
        canonical_sha256: created.canonicalSha256,
        package_base_sha256: created.packageBaseSha256,
        response_sha256: created.responseSha256,
        replayed: false
      },
      `board://${created.boardId}/minutes/${created.minutesId}/versions/${String(created.version)}`
    );
  }

  private async submitMinutesReview(
    principal: SurfacePrincipal,
    tool: typeof COMMENT_MINUTES | typeof PROPOSE_MINUTES_REDLINE,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(tool).parse(input) as {
      readonly idempotency_key: string;
      readonly payload: JsonValue;
    };
    const payload = parsed.payload as Readonly<Record<string, JsonValue>>;
    const minutesId = UuidV7Schema.parse(payload["minutesId"]);
    const review = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        submitMinutesReviewInTransaction(client, {
          reviewItemId: this.newId(),
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          payload,
          deliveryFactory: () => ({ noticeId: this.newId(), feedId: this.newId() }),
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(tool, review.replayed ? "already_applied" : "accepted", review.reviewItemId, {
      schema_version: "boardagent.minutes-review-result.v1",
      minutes_id: minutesId,
      review_item_id: review.reviewItemId,
      review_kind: tool === COMMENT_MINUTES ? "comment" : "redline",
      response_sha256: review.responseSha256,
      replayed: review.replayed
    });
  }

  private async withdrawMinutesComment(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(WITHDRAW_MINUTES_COMMENT).parse(input) as {
      readonly idempotency_key: string;
      readonly minutes_id: string;
      readonly review_item_id: string;
    };
    const withdrawal = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        withdrawMinutesCommentInTransaction(client, {
          withdrawalId: this.newId(),
          minutesId: parsed.minutes_id,
          reviewItemId: parsed.review_item_id,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(
      WITHDRAW_MINUTES_COMMENT,
      withdrawal.replayed ? "already_applied" : "accepted",
      withdrawal.withdrawalId,
      {
        schema_version: "boardagent.minutes-review-withdrawal-result.v1",
        minutes_id: parsed.minutes_id,
        review_item_id: withdrawal.reviewItemId,
        withdrawal_id: withdrawal.withdrawalId,
        response_sha256: withdrawal.responseSha256,
        replayed: withdrawal.replayed
      }
    );
  }

  private async startTask(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(START_TASK).parse(input) as {
      readonly idempotency_key: string;
      readonly task_id: string;
    };
    const started = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        startTaskInTransaction(client, {
          taskId: parsed.task_id,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(START_TASK, started.replayed ? "already_applied" : "accepted", started.taskId, {
      schema_version: "boardagent.task-start-result.v1",
      task_id: started.taskId,
      response_sha256: started.responseSha256,
      replayed: started.replayed
    });
  }

  private async submitTaskEvidence(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(SUBMIT_TASK_EVIDENCE).parse(input) as {
      readonly canonical_text: string | null;
      readonly document_references: readonly {
        readonly document_id: string;
        readonly sha256: string;
        readonly version_id: string;
      }[];
      readonly evidence_id: string;
      readonly idempotency_key: string;
      readonly resource_references: readonly {
        readonly sha256: string;
        readonly uri: string;
      }[];
      readonly task_id: string;
    };
    const submitted = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      async (client) => {
        // Validate the public tuple before projecting it into the frozen evidence
        // payload. Version identity is immutable; historical payload hashes stay valid.
        await this.assertDocumentVersionReferences(
          client,
          parsed.document_references,
          "task evidence document reference is unavailable"
        );
        return submitTaskEvidenceInTransaction(client, {
          evidenceId: parsed.evidence_id,
          payload: {
            schemaVersion: "boardagent.task-evidence.v1",
            taskId: parsed.task_id,
            canonicalText: parsed.canonical_text,
            documentReferences: parsed.document_references.map(({ version_id, sha256 }) => ({
              documentVersionId: version_id,
              sha256
            })),
            resourceReferences: parsed.resource_references.map(({ uri, sha256 }) => ({
              resourceUri: uri,
              sha256
            }))
          },
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        });
      },
      this.transaction
    );
    return result(
      SUBMIT_TASK_EVIDENCE,
      submitted.replayed ? "already_applied" : "accepted",
      submitted.safeResponseId,
      {
        schema_version: "boardagent.task-evidence-result.v1",
        task_id: submitted.taskId,
        evidence_id: submitted.safeResponseId,
        response_sha256: submitted.responseSha256,
        replayed: submitted.replayed
      }
    );
  }

  private async createDocumentVersion(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(CREATE_DOCUMENT_VERSION).parse(input) as {
      readonly board_id: string;
      readonly canonical_body: string;
      readonly document_id: string;
      readonly expected_current_version_id: string | null;
      readonly idempotency_key: string;
      readonly media_type:
        "application/json" | "text/markdown; charset=utf-8" | "text/plain; charset=utf-8";
      readonly schema_name: string | null;
      readonly title: string;
    };
    const offered = Buffer.from(parsed.canonical_body, "utf8");
    let prepared;
    try {
      prepared = prepareDocumentContribution({
        organizationId: principal.organizationId,
        boardId: parsed.board_id,
        documentId: parsed.document_id,
        title: parsed.title,
        mediaType: parsed.media_type,
        documentSchema: parsed.schema_name,
        body: offered
      });
    } catch (error) {
      if (!(error instanceof DocumentValidationError)) throw error;
      const recorded = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          recordDocumentValidationRejectionInTransaction(client, {
            organizationId: principal.organizationId,
            boardId: parsed.board_id,
            validationAttemptId: this.newId(),
            idempotencyRecordId: this.newId(),
            idempotencyKey: parsed.idempotency_key,
            expectedCurrentVersionId: parsed.expected_current_version_id,
            offeredMediaType: parsed.media_type,
            offeredName: parsed.title,
            offeredLength: offered.byteLength,
            offeredSha256: sha256Hex(offered),
            rejection: error
          }),
        this.transaction
      );
      throw new DocumentValidationError(
        error.code,
        `${error.code}: ${error.message}; validation attempt ${recorded.validationAttemptId}`,
        error.remediation
      );
    }

    const validationAttemptId = this.newId();
    const contributed = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        contributeDocumentVersionInTransaction(client, {
          prepared,
          expectedCurrentVersionId: parsed.expected_current_version_id,
          documentVersionId: this.newId(),
          validationAttemptId,
          auditEventId: this.newId(),
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          offeredName: parsed.title
        }),
      this.transaction
    );
    if (contributed.replayed) {
      return result(CREATE_DOCUMENT_VERSION, "already_applied", contributed.documentVersionId, {
        schema_version: "boardagent.document-contribution-result.v1",
        document_version_id: contributed.documentVersionId,
        response_sha256: contributed.responseSha256,
        replayed: true
      });
    }
    const resourceUri =
      `board://${parsed.board_id}/documents/${contributed.documentId}/versions/` +
      String(contributed.version);
    return result(
      CREATE_DOCUMENT_VERSION,
      "accepted",
      contributed.documentVersionId,
      {
        schema_version: "boardagent.document-contribution-result.v1",
        document_id: contributed.documentId,
        document_version_id: contributed.documentVersionId,
        version: contributed.version,
        sha256: contributed.sha256,
        byte_length: contributed.byteLength,
        validation_attempt_id: validationAttemptId,
        validation_result: "accepted",
        replayed: false
      },
      resourceUri
    );
  }

  private async recordMeetingRsvp(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(RSVP).parse(input) as {
      readonly idempotency_key: string;
      readonly meeting_id: string;
      readonly note: string | null;
      readonly response: "attending" | "not_attending" | "tentative";
    };
    const recorded = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        recordMeetingRsvpInTransaction(client, {
          meetingId: parsed.meeting_id,
          response: parsed.response,
          note: parsed.note,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          rsvpId: this.newId(),
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(RSVP, recorded.replayed ? "already_applied" : "accepted", recorded.recordId, {
      schema_version: "boardagent.meeting-rsvp-result.v1",
      meeting_id: recorded.meetingId,
      rsvp_id: recorded.recordId,
      version: recorded.version,
      response_sha256: recorded.responseSha256,
      replayed: recorded.replayed
    });
  }

  private async recordMeetingAttendance(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(RECORD_ATTENDANCE).parse(input) as {
      readonly idempotency_key: string;
      readonly meeting_id: string;
      readonly member_id: string;
      readonly source: "secretary_record";
      readonly status: "present" | "absent" | "excused";
    };
    const recorded = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        recordMeetingAttendanceInTransaction(client, {
          meetingId: parsed.meeting_id,
          memberId: parsed.member_id,
          status: parsed.status,
          source: parsed.source,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          attendanceId: this.newId(),
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(
      RECORD_ATTENDANCE,
      recorded.replayed ? "already_applied" : "accepted",
      recorded.recordId,
      {
        schema_version: "boardagent.meeting-attendance-result.v1",
        meeting_id: recorded.meetingId,
        attendance_id: recorded.recordId,
        response_sha256: recorded.responseSha256,
        replayed: recorded.replayed
      }
    );
  }

  private async createMeetingTranscriptVersion(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(CREATE_MEETING_TRANSCRIPT_VERSION).parse(input) as {
      readonly canonical_body: string;
      readonly coverage_statement: string;
      readonly idempotency_key: string;
      readonly media_type: "application/json" | "text/markdown; charset=utf-8";
      readonly meeting_id: string;
      readonly supersedes_version_id: string | null;
      readonly transcript_id: string;
    };
    const created = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        createMeetingTranscriptVersionInTransaction(client, {
          meetingId: parsed.meeting_id,
          transcriptId: parsed.transcript_id,
          transcriptVersionId: this.newId(),
          mediaType: parsed.media_type,
          canonicalBody: parsed.canonical_body,
          coverageStatement: parsed.coverage_statement,
          supersedesVersionId: parsed.supersedes_version_id,
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    const minutesRefresh =
      created.minutesRefresh === null
        ? null
        : {
            minutes_id: created.minutesRefresh.minutesId,
            minutes_version_id: created.minutesRefresh.minutesVersionId,
            version: created.minutesRefresh.version,
            canonical_sha256: created.minutesRefresh.canonicalSha256,
            package_base_sha256: created.minutesRefresh.packageBaseSha256,
            state: created.minutesRefresh.state
          };
    const resourceUri =
      `board://${created.boardId}/meetings/${created.meetingId}/transcripts/` +
      String(created.version);
    return result(
      CREATE_MEETING_TRANSCRIPT_VERSION,
      created.replayed ? "already_applied" : "accepted",
      created.transcriptVersionId,
      {
        schema_version: "boardagent.meeting-transcript-version-result.v1",
        meeting_id: created.meetingId,
        transcript_id: created.transcriptId,
        transcript_version_id: created.transcriptVersionId,
        version: created.version,
        canonical_schema: created.canonicalSchema,
        media_type: created.mediaType,
        canonical_sha256: created.canonicalSha256,
        coverage_statement: created.coverageStatement,
        verification_state: "agent_prepared_unverified",
        turn_ids: created.turnIds,
        response_sha256: created.responseSha256,
        minutes_refresh: minutesRefresh,
        replayed: created.replayed
      },
      resourceUri
    );
  }

  private async challengeTranscriptTurn(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<SurfaceToolResult> {
    const parsed = toolInputSchema(CHALLENGE_TRANSCRIPT_TURN).parse(input) as {
      readonly comment: string;
      readonly idempotency_key: string;
      readonly transcript_version_id: string;
      readonly turn_id: string;
    };
    const challenged = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        challengeTranscriptTurnInTransaction(client, {
          transcriptVersionId: parsed.transcript_version_id,
          turnId: parsed.turn_id,
          comment: parsed.comment,
          challengeId: this.newId(),
          idempotencyRecordId: this.newId(),
          idempotencyKey: parsed.idempotency_key,
          auditEventId: this.newId()
        }),
      this.transaction
    );
    return result(
      CHALLENGE_TRANSCRIPT_TURN,
      challenged.replayed ? "already_applied" : "accepted",
      challenged.challengeId,
      {
        schema_version: "boardagent.transcript-turn-challenge-result.v1",
        transcript_id: challenged.transcriptId,
        transcript_version_id: challenged.transcriptVersionId,
        turn_id: challenged.turnId,
        challenge_id: challenged.challengeId,
        comment_sha256: challenged.commentSha256,
        state: "pending",
        response_sha256: challenged.responseSha256,
        replayed: challenged.replayed
      }
    );
  }

  private async prepareIssue(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<PreparedEnrollmentIssuance> {
    return withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) => prepareEnrollmentIssuanceInTransaction(client, input),
      this.transaction
    );
  }

  private async prepareMemberInvite(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<PreparedMemberInvite> {
    return withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) => prepareMemberInviteInTransaction(client, input),
      this.transaction
    );
  }

  private async prepareActivation(
    principal: SurfacePrincipal,
    input: JsonValue
  ): Promise<PreparedEnrollmentActivation> {
    return withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) => prepareEnrollmentActivationInTransaction(client, input),
      this.transaction
    );
  }

  private meetingLifecycleAction(
    tool: MeetingLifecycleTool,
    input: JsonValue
  ): MeetingLifecycleAction {
    switch (tool) {
      case CREATE_MEETING: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly agenda: MeetingAgenda;
          readonly attendee_member_ids: readonly string[];
          readonly board_id: string;
          readonly meeting_id: string;
          readonly scheduled_end_at: string;
          readonly scheduled_start_at: string;
          readonly timezone: string;
          readonly title: string;
        };
        new Intl.DateTimeFormat("en", { timeZone: parsed.timezone }).format(0);
        return {
          kind: "create",
          boardId: parsed.board_id,
          meetingId: parsed.meeting_id,
          title: parsed.title,
          scheduledStartAt: parsed.scheduled_start_at,
          scheduledEndAt: parsed.scheduled_end_at,
          timezone: parsed.timezone,
          agenda: parsed.agenda,
          attendeeMemberIds: parsed.attendee_member_ids
        };
      }
      case AMEND_MEETING: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly agenda: MeetingAgenda;
          readonly expected_row_version: number;
          readonly meeting_id: string;
          readonly reason: string;
          readonly scheduled_end_at: string;
          readonly scheduled_start_at: string;
          readonly timezone: string;
          readonly title: string;
        };
        new Intl.DateTimeFormat("en", { timeZone: parsed.timezone }).format(0);
        return {
          kind: "amend",
          meetingId: parsed.meeting_id,
          expectedRowVersion: parsed.expected_row_version,
          title: parsed.title,
          scheduledStartAt: parsed.scheduled_start_at,
          scheduledEndAt: parsed.scheduled_end_at,
          timezone: parsed.timezone,
          agenda: parsed.agenda,
          reason: parsed.reason
        };
      }
      case CORRECT_ATTENDANCE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly attendance_id: string;
          readonly reason: string;
          readonly status: "present" | "absent" | "excused";
        };
        return {
          kind: "attendance_correction",
          attendanceId: parsed.attendance_id,
          status: parsed.status,
          reason: parsed.reason
        };
      }
      case CANCEL_MEETING: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly meeting_id: string;
          readonly reason: string;
        };
        return { kind: "cancellation", meetingId: parsed.meeting_id, reason: parsed.reason };
      }
      case COMPLETE_MEETING: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly completion_statement: "attendance_record_is_complete";
          readonly meeting_id: string;
        };
        return {
          kind: "completion",
          meetingId: parsed.meeting_id,
          completionStatement: parsed.completion_statement
        };
      }
    }
  }

  private meetingConfirmationLines(
    tool: MeetingLifecycleTool,
    action: MeetingLifecycleAction,
    prepared: PreparedMeetingLifecycleAction,
    code: string
  ): readonly string[] {
    const common = [
      "BOARDAGENT MEETING ACTION CONFIRMATION",
      `Action: ${tool}`,
      `Target: ${prepared.targetId}`,
      `Board: ${prepared.boardId}`,
      `Canonical action SHA-256: ${prepared.payloadSha256}`,
      `Bound package SHA-256: ${prepared.packageSha256}`
    ];
    switch (action.kind) {
      case "create":
        return [
          ...common,
          `Title: ${action.title}`,
          `Schedule: ${action.scheduledStartAt} to ${action.scheduledEndAt} (${action.timezone})`,
          `Agenda items: ${String(action.agenda.values.items.length)}`,
          `Attendees: ${action.attendeeMemberIds.toSorted().join(", ")}`,
          "Result: call the meeting with immutable meeting/agenda version 1 and notify every exact attendee.",
          `Confirmation code: ${code}`
        ];
      case "amend":
        return [
          ...common,
          `Expected row version: ${String(action.expectedRowVersion)}`,
          `New title: ${action.title}`,
          `New schedule: ${action.scheduledStartAt} to ${action.scheduledEndAt} (${action.timezone})`,
          `New agenda items: ${String(action.agenda.values.items.length)}`,
          `Reason: ${action.reason}`,
          "Result: append immutable meeting and agenda versions, retain the prior versions, and re-notify current attendees.",
          `Confirmation code: ${code}`
        ];
      case "attendance_correction":
        return [
          ...common,
          `Corrected status: ${action.status}`,
          `Reason: ${action.reason}`,
          "Result: append one linked correction while permanently retaining the prior attendance record.",
          `Confirmation code: ${code}`
        ];
      case "cancellation":
        return [
          ...common,
          `Reason: ${action.reason}`,
          "Result: cancel this meeting permanently and notify every current attendee.",
          `Confirmation code: ${code}`
        ];
      case "completion":
        return [
          ...common,
          "Attendance statement: attendance_record_is_complete",
          "Result: complete the meeting permanently over the exact current attendance manifest.",
          `Confirmation code: ${code}`
        ];
    }
  }

  private meetingLifecycleResult(
    tool: MeetingLifecycleTool,
    lifecycle: MeetingLifecycleResult
  ): SurfaceToolResult {
    switch (lifecycle.kind) {
      case "create":
      case "amend":
        if (
          (lifecycle.kind === "create" && tool !== CREATE_MEETING) ||
          (lifecycle.kind === "amend" && tool !== AMEND_MEETING)
        ) {
          break;
        }
        return result(tool, "accepted", lifecycle.meetingId, {
          schema_version: "boardagent.meeting-version-result.v1",
          meeting_id: lifecycle.meetingId,
          meeting_version_id: lifecycle.meetingVersionId,
          agenda_version_id: lifecycle.agendaVersionId,
          version: lifecycle.version,
          package_sha256: lifecycle.packageSha256,
          recipient_member_ids: lifecycle.recipientMemberIds
        });
      case "attendance_correction":
        if (tool !== CORRECT_ATTENDANCE) break;
        return result(tool, "accepted", lifecycle.attendanceId, {
          schema_version: "boardagent.meeting-attendance-correction-result.v1",
          meeting_id: lifecycle.meetingId,
          prior_attendance_id: lifecycle.priorAttendanceId,
          attendance_id: lifecycle.attendanceId,
          status: lifecycle.status
        });
      case "cancellation":
      case "completion":
        if (
          (lifecycle.kind === "cancellation" && tool !== CANCEL_MEETING) ||
          (lifecycle.kind === "completion" && tool !== COMPLETE_MEETING)
        ) {
          break;
        }
        return result(tool, "accepted", lifecycle.meetingId, {
          schema_version: "boardagent.meeting-terminal-result.v1",
          meeting_id: lifecycle.meetingId,
          state: lifecycle.state,
          row_version: lifecycle.rowVersion
        });
    }
    throw new Error(`${tool} returned an unexpected meeting lifecycle result: ${lifecycle.kind}`);
  }

  private transcriptLifecycleAction(
    tool: TranscriptLifecycleTool,
    input: JsonValue
  ): TranscriptLifecycleAction {
    switch (tool) {
      case VERIFY_MEETING_TRANSCRIPT: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly sha256: string;
          readonly transcript_id: string;
          readonly verification_statement: "secretary_verified_annex_hash";
          readonly version_id: string;
        };
        return {
          kind: "verification",
          transcriptId: parsed.transcript_id,
          versionId: parsed.version_id,
          sha256: parsed.sha256,
          verificationStatement: parsed.verification_statement
        };
      }
      case LINK_MEETING_QNA: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly question_id: string;
          readonly transcript_version_id: string;
          readonly turn_ids: readonly string[];
        };
        return {
          kind: "qna_link",
          transcriptVersionId: parsed.transcript_version_id,
          turnIds: parsed.turn_ids,
          questionId: parsed.question_id
        };
      }
      case RESOLVE_TRANSCRIPT_CHALLENGE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly challenge_id: string;
          readonly corrected_version_id: string | null;
          readonly disposition: "accept" | "reject";
          readonly reason: string;
        };
        return {
          kind: "challenge_resolution",
          challengeId: parsed.challenge_id,
          decision: parsed.disposition === "accept" ? "accepted" : "rejected",
          reason: parsed.reason,
          correctedVersionId: parsed.corrected_version_id
        };
      }
    }
  }

  private transcriptConfirmationLines(
    tool: TranscriptLifecycleTool,
    action: TranscriptLifecycleAction,
    prepared: PreparedTranscriptLifecycleAction,
    code: string
  ): readonly string[] {
    const common = [
      "BOARDAGENT TRANSCRIPT ACTION CONFIRMATION",
      `Action: ${tool}`,
      `Target: ${prepared.targetId}`,
      `Board: ${prepared.boardId}`,
      `Canonical action SHA-256: ${prepared.payloadSha256}`,
      `Bound evidence SHA-256: ${prepared.packageSha256}`
    ];
    switch (action.kind) {
      case "verification":
        return [
          ...common,
          `Transcript version: ${action.versionId}`,
          `Stored annex SHA-256: ${action.sha256}`,
          "Boundary: verify the stored annex hash only; BoardAgent stores no recording and makes no comparison claim.",
          `Confirmation code: ${code}`
        ];
      case "qna_link":
        return [
          ...common,
          `Transcript version: ${action.transcriptVersionId}`,
          `Exact contiguous turns: ${action.turnIds.join(", ")}`,
          `Management question: ${action.questionId}`,
          "Result: bind this exact turn range to the question without clearing any unanswered management action.",
          `Confirmation code: ${code}`
        ];
      case "challenge_resolution":
        return [
          ...common,
          `Decision: ${action.decision}`,
          `Reason: ${action.reason}`,
          `Corrected transcript version: ${action.correctedVersionId ?? "none"}`,
          "Result: permanently record this disposition; acceptance is bound to the exact current direct successor annex.",
          `Confirmation code: ${code}`
        ];
    }
  }

  private transcriptLifecycleResult(
    tool: TranscriptLifecycleTool,
    lifecycle: TranscriptLifecycleResult
  ): SurfaceToolResult {
    switch (lifecycle.kind) {
      case "verification":
        if (tool !== VERIFY_MEETING_TRANSCRIPT) break;
        return result(tool, "accepted", lifecycle.verificationId, {
          schema_version: "boardagent.transcript-verification-result.v1",
          verification_id: lifecycle.verificationId,
          transcript_id: lifecycle.transcriptId,
          version_id: lifecycle.versionId,
          sha256: lifecycle.sha256,
          state: lifecycle.state,
          row_version: lifecycle.rowVersion
        });
      case "qna_link":
        if (tool !== LINK_MEETING_QNA) break;
        return result(tool, "accepted", lifecycle.linkId, {
          schema_version: "boardagent.transcript-qna-link-result.v1",
          link_id: lifecycle.linkId,
          transcript_id: lifecycle.transcriptId,
          transcript_version_id: lifecycle.transcriptVersionId,
          turn_ids: lifecycle.turnIds,
          turns_sha256: lifecycle.turnsSha256,
          question_id: lifecycle.questionId,
          management_question_sha256: lifecycle.managementQuestionSha256,
          management_action_preserved: lifecycle.managementActionPreserved
        });
      case "challenge_resolution":
        if (tool !== RESOLVE_TRANSCRIPT_CHALLENGE) break;
        return result(tool, "accepted", lifecycle.dispositionId, {
          schema_version: "boardagent.transcript-challenge-resolution-result.v1",
          disposition_id: lifecycle.dispositionId,
          challenge_id: lifecycle.challengeId,
          state: lifecycle.state,
          corrected_version_id: lifecycle.correctedVersionId
        });
    }
    throw new Error(`${tool} returned an unexpected transcript result: ${lifecycle.kind}`);
  }

  private ballotLifecycleAction(
    tool: BallotLifecycleTool,
    input: JsonValue
  ): BallotLifecycleAction {
    switch (tool) {
      case STAGE_BALLOT: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly choice: "yes" | "no" | "abstain";
          readonly idempotency_key: string;
          readonly principal_member_id: string | null;
          readonly statement: string | null;
          readonly vote_id: string;
        };
        return {
          kind: "ballot",
          voteId: parsed.vote_id,
          principalMemberId: parsed.principal_member_id,
          choice: parsed.choice,
          statement: parsed.statement,
          idempotencyKey: parsed.idempotency_key
        };
      }
      case GRANT_PROXY: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly holder_member_id: string;
          readonly idempotency_key: string;
          readonly vote_id: string;
        };
        return {
          kind: "grant_proxy",
          voteId: parsed.vote_id,
          holderMemberId: parsed.holder_member_id,
          idempotencyKey: parsed.idempotency_key
        };
      }
      case REVOKE_PROXY: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly grant_id: string;
          readonly idempotency_key: string;
          readonly reason: string;
        };
        return {
          kind: "revoke_proxy",
          proxyGrantId: parsed.grant_id,
          reason: parsed.reason,
          idempotencyKey: parsed.idempotency_key
        };
      }
    }
  }

  private ballotConfirmationLines(
    tool: BallotLifecycleTool,
    action: BallotLifecycleAction,
    prepared: PreparedBallotLifecycleAction,
    code: string
  ): readonly string[] {
    const common = [
      "BOARDAGENT VOTE ACTION CONFIRMATION",
      `Action: ${tool}`,
      `Vote: ${prepared.voteTitle} (${prepared.voteId})`,
      `Resolution SHA-256: ${prepared.resolutionSha256}`,
      "Canonical resolution text:",
      prepared.resolutionText,
      `Decision package SHA-256: ${prepared.packageSha256}`,
      `Canonical decision package: ${canonicalJson(prepared.decisionPackage)}`,
      `Canonical action SHA-256: ${prepared.payloadSha256}`
    ];
    switch (action.kind) {
      case "ballot":
        return [
          ...common,
          `Principal: ${prepared.principalDisplayName} (${prepared.principalMemberId})`,
          `Caster: ${prepared.actorDisplayName} (${prepared.actorMemberId})`,
          `Choice: ${action.choice}`,
          `Statement: ${action.statement ?? "(none)"}`,
          `Proxy grant: ${prepared.proxyGrantId ?? "none — direct ballot"}`,
          "Result: cast one attributable ballot over this exact package; a direct ballot may supersede a proxy ballot only under the frozen rule.",
          `Confirmation code: ${code}`
        ];
      case "grant_proxy":
        return [
          ...common,
          `Principal: ${prepared.principalDisplayName} (${prepared.principalMemberId})`,
          `Holder: ${prepared.holderDisplayName ?? "unavailable"} (${action.holderMemberId})`,
          `Frozen precedence policy: ${(prepared.canonicalPayload as Record<string, JsonValue>)["policy"] as string}`,
          "Result: grant proxy authority for this vote only; no chain or cycle is permitted.",
          `Confirmation code: ${code}`
        ];
      case "revoke_proxy":
        return [
          ...common,
          `Proxy grant: ${action.proxyGrantId}`,
          `Principal: ${prepared.principalDisplayName} (${prepared.principalMemberId})`,
          `Holder: ${prepared.holderDisplayName ?? "unavailable"} (${prepared.holderMemberId ?? "unavailable"})`,
          `Reason: ${action.reason}`,
          "Result: append a permanent revocation; prior grant evidence remains intact.",
          `Confirmation code: ${code}`
        ];
    }
  }

  private ballotLifecycleResult(
    tool: BallotLifecycleTool,
    lifecycle: BallotLifecycleResult
  ): SurfaceToolResult {
    switch (lifecycle.kind) {
      case "grant_proxy": {
        if (tool !== GRANT_PROXY) break;
        const granted = lifecycle.result;
        return result(
          tool,
          granted.replayed ? "already_applied" : "accepted",
          granted.proxyGrantId,
          {
            schema_version: "boardagent.proxy-grant-result.v1",
            vote_id: granted.voteId,
            proxy_grant_id: granted.proxyGrantId,
            principal_member_id: "principalMemberId" in granted ? granted.principalMemberId : null,
            holder_member_id: "holderMemberId" in granted ? granted.holderMemberId : null,
            policy: "policy" in granted ? granted.policy : null,
            response_sha256: granted.responseSha256,
            replayed: granted.replayed
          }
        );
      }
      case "revoke_proxy": {
        if (tool !== REVOKE_PROXY) break;
        const revoked = lifecycle.result;
        return result(
          tool,
          revoked.replayed ? "already_applied" : "accepted",
          revoked.proxyRevocationId,
          {
            schema_version: "boardagent.proxy-revocation-result.v1",
            vote_id: revoked.voteId,
            proxy_grant_id: revoked.proxyGrantId,
            proxy_revocation_id: revoked.proxyRevocationId,
            effect: revoked.effect,
            response_sha256: revoked.responseSha256,
            replayed: revoked.replayed
          }
        );
      }
      case "ballot": {
        if (tool !== STAGE_BALLOT) break;
        const ballot = lifecycle.result;
        return result(tool, ballot.replayed ? "already_applied" : "accepted", ballot.ballotId, {
          schema_version: "boardagent.ballot-result.v1",
          vote_id: ballot.voteId,
          ballot_id: ballot.ballotId,
          principal_member_id: ballot.principalMemberId,
          caster_member_id: "casterMemberId" in ballot ? ballot.casterMemberId : null,
          source: ballot.source,
          superseded_ballot_id: "supersededBallotId" in ballot ? ballot.supersededBallotId : null,
          response_sha256: ballot.responseSha256,
          replayed: ballot.replayed
        });
      }
    }
    throw new Error(`${tool} returned an unexpected ballot lifecycle result: ${lifecycle.kind}`);
  }

  private voteCreationAction(input: JsonValue): VoteCreationLifecycleAction {
    const parsed = toolInputSchema(CREATE_VOTE).parse(input) as {
      readonly approval_rule_id: string;
      readonly board_id: string;
      readonly close_mode: "automatic" | "secretariat_confirmed";
      readonly deadline_at: string;
      readonly decision_package: {
        readonly schema_version: string;
        readonly values: Readonly<Record<string, JsonValue>>;
      };
      readonly idempotency_key: string;
      readonly matter_evaluation_id: string;
      readonly override_reason: string | null;
      readonly resolution_text: string;
      readonly selected_ruleset_rule_id: string;
      readonly title: string;
      readonly vote_id: string;
    };
    if (
      parsed.decision_package.schema_version !== "boardagent.vote-package-components.v1" ||
      Object.keys(parsed.decision_package.values).length !== 1 ||
      !Object.hasOwn(parsed.decision_package.values, "components")
    ) {
      throw new TypeError(
        "create_vote decision_package must be boardagent.vote-package-components.v1 with only components"
      );
    }
    const components = DecisionPackageComponentSchema.array()
      .max(10_000)
      .parse(parsed.decision_package.values["components"]);
    return {
      boardId: parsed.board_id,
      voteId: parsed.vote_id,
      title: parsed.title,
      resolutionText: parsed.resolution_text,
      components,
      approvalRuleId: parsed.approval_rule_id,
      matterEvaluationId: parsed.matter_evaluation_id,
      selectedRulesetRuleId: parsed.selected_ruleset_rule_id,
      overrideReason: parsed.override_reason,
      closeMode: parsed.close_mode,
      deadlineAt: parsed.deadline_at,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteCreationConfirmationLines(
    prepared: PreparedVoteCreationLifecycleAction,
    code: string
  ): readonly string[] {
    return [
      "BOARDAGENT GUIDED VOTE CREATION CONFIRMATION",
      `Vote: ${prepared.title} (${prepared.voteId})`,
      `Board: ${prepared.boardId}`,
      `Canonical resolution SHA-256: ${prepared.resolutionSha256}`,
      "Canonical resolution text:",
      prepared.resolutionText,
      `Governance profile: ${prepared.decisionPackage.governanceProfileVersionId}`,
      `Governance profile SHA-256: ${prepared.decisionPackage.governanceProfileSha256}`,
      `Ruleset: ${prepared.decisionPackage.rulesetVersionId}`,
      `Ruleset SHA-256: ${prepared.decisionPackage.rulesetSha256}`,
      `Persisted matter evaluation: ${prepared.decisionPackage.matterEvaluationId}`,
      `Profile-permitted recommended rule: ${prepared.recommendedRuleId}`,
      `Selected rule: ${prepared.selectedRuleId}`,
      `Selected rule SHA-256: ${prepared.decisionPackage.selectedRulesetRuleSha256}`,
      `Reasoned rule override: ${prepared.overrideReason ?? "none"}`,
      ...prepared.ruleCitations.map(
        (citation) =>
          `Rule citation: ${citation.clause} — ${citation.locator} ` +
          `(document version ${citation.sourceDocumentVersionId}; ${citation.sourceDocumentSha256})`
      ),
      `Decision sources: ${String(prepared.decisionPackage.components.length)}`,
      ...prepared.decisionPackage.components.map(
        (component) =>
          `Source ${String(component.ordinal)}: ${component.type}/${component.id} ` +
          `version ${String(component.version)}; ${component.sha256}`
      ),
      `Frozen electorate members: ${String(prepared.electorate.entries.length)}`,
      `Entitled recipients notified: ${String(prepared.recipientMemberIds.length)}`,
      `Close mode: ${prepared.decisionPackage.closeMode}`,
      `Deadline: ${prepared.decisionPackage.deadlineAt}`,
      `Decision package SHA-256: ${prepared.packageSha256}`,
      `Canonical decision package: ${canonicalJson(prepared.decisionPackage)}`,
      "Result: atomically create the immutable resolution and package, freeze the current electorate, open the vote, and deliver one exact notice to every entitled recipient.",
      `Confirmation code: ${code}`
    ];
  }

  private voteCreationResult(opened: OpenVoteResult): SurfaceToolResult {
    return result(CREATE_VOTE, opened.replayed ? "already_applied" : "accepted", opened.voteId, {
      schema_version: "boardagent.vote-open-result.v1",
      vote_id: opened.voteId,
      decision_package_id: opened.decisionPackageId,
      state: opened.state,
      package_sha256: opened.replayed ? null : opened.packageSha256,
      electorate_sha256: opened.replayed ? null : opened.electorateSha256,
      response_sha256: opened.responseSha256,
      replayed: opened.replayed
    });
  }

  private voteReplacementAction(input: JsonValue): VoteReplacementLifecycleAction {
    const parsed = toolInputSchema(REPLACE_OPEN_VOTE).parse(input) as {
      readonly changed_component_classes: readonly (
        | "resolution"
        | "governance_profile"
        | "ruleset"
        | "approval_rule"
        | "electorate"
        | "close_mode"
        | "deadline"
        | "management_submission"
        | "document"
        | "question_cutoff"
      )[];
      readonly idempotency_key: string;
      readonly reason: string;
      readonly replacement_package: {
        readonly schema_version: string;
        readonly values: Readonly<Record<string, JsonValue>>;
      };
      readonly replacement_vote_id: string;
      readonly vote_id: string;
    };
    if (parsed.replacement_package.schema_version !== "boardagent.vote-replacement-draft.v1") {
      throw new TypeError(
        "replace_open_vote replacement_package must use boardagent.vote-replacement-draft.v1"
      );
    }
    const draft = z
      .object({
        title: z.string().min(1).max(512),
        resolution_text: z.string().min(1).max(1_048_576),
        components: DecisionPackageComponentSchema.array().max(10_000),
        approval_rule_id: UuidV7Schema,
        matter_evaluation_id: UuidV7Schema,
        selected_ruleset_rule_id: UuidV7Schema,
        override_reason: z.string().min(1).max(65_536).nullable(),
        close_mode: z.enum(["automatic", "secretariat_confirmed"]),
        deadline_at: Rfc3339UtcSchema
      })
      .strict()
      .parse(parsed.replacement_package.values);
    return {
      actionCode: REPLACE_OPEN_VOTE,
      oldVoteId: parsed.vote_id,
      newVoteId: parsed.replacement_vote_id,
      declaredChangedComponentClasses: parsed.changed_component_classes,
      newTitle: draft.title,
      newResolutionText: draft.resolution_text,
      components: draft.components,
      approvalRuleId: draft.approval_rule_id,
      matterEvaluationId: draft.matter_evaluation_id,
      selectedRulesetRuleId: draft.selected_ruleset_rule_id,
      overrideReason: draft.override_reason,
      closeMode: draft.close_mode,
      deadlineAt: draft.deadline_at,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteResolutionAmendmentInput(input: JsonValue): VoteResolutionAmendmentLifecycleInput {
    const parsed = toolInputSchema(AMEND_RESOLUTION_TEXT).parse(input) as {
      readonly expected_resolution_version_id: string;
      readonly idempotency_key: string;
      readonly reason: string;
      readonly resolution_text: string;
      readonly vote_id: string;
    };
    return {
      voteId: parsed.vote_id,
      expectedResolutionVersionId: parsed.expected_resolution_version_id,
      resolutionText: parsed.resolution_text,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteDeadlineExtensionInput(input: JsonValue): VoteDeadlineExtensionLifecycleInput {
    const parsed = toolInputSchema(EXTEND_VOTE_DEADLINE).parse(input) as {
      readonly deadline_at: string;
      readonly idempotency_key: string;
      readonly reason: string;
      readonly vote_id: string;
    };
    return {
      voteId: parsed.vote_id,
      deadlineAt: parsed.deadline_at,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteReplacementConfirmationLines(
    prepared: PreparedVoteReplacementLifecycleAction,
    code: string
  ): readonly string[] {
    return [
      `BOARDAGENT ${prepared.actionCode.toUpperCase()} REPLACEMENT CONFIRMATION`,
      `Old vote: ${prepared.oldVoteId}`,
      `Old decision package SHA-256: ${prepared.oldPackageSha256}`,
      `New vote: ${prepared.newTitle} (${prepared.newVoteId})`,
      `Changed component classes: ${prepared.changedComponentClasses.join(", ")}`,
      `Reason: ${prepared.reason}`,
      `Canonical replacement resolution SHA-256: ${prepared.newResolutionSha256}`,
      "Canonical replacement resolution text:",
      prepared.newResolutionText,
      `Replacement sources: ${String(prepared.decisionPackage.components.length)}`,
      ...prepared.decisionPackage.components.map(
        (component) =>
          `Source ${String(component.ordinal)}: ${component.type}/${component.id} ` +
          `version ${String(component.version)}; ${component.sha256}`
      ),
      `Replacement electorate members: ${String(prepared.electorate.entries.length)}`,
      `Entitled replacement notices: ${String(prepared.recipientMemberIds.length)}`,
      `Members explicitly required to revote: ${String(prepared.revoteMemberIds.length)}`,
      `New close mode: ${prepared.decisionPackage.closeMode}`,
      `New deadline: ${prepared.decisionPackage.deadlineAt}`,
      `New decision package SHA-256: ${prepared.packageSha256}`,
      `Canonical replacement package: ${canonicalJson(prepared.decisionPackage)}`,
      "Result: atomically supersede the old vote, preserve every prior act as noncounting history, dispose all old authority, open the linked empty replacement, and deliver exact replacement and revote duties.",
      `Confirmation code: ${code}`
    ];
  }

  private voteReplacementResult(
    tool: typeof REPLACE_OPEN_VOTE | typeof AMEND_RESOLUTION_TEXT | typeof EXTEND_VOTE_DEADLINE,
    replaced: ReplaceVoteResult
  ): SurfaceToolResult {
    return result(tool, replaced.replayed ? "already_applied" : "accepted", replaced.newVoteId, {
      schema_version: "boardagent.vote-replacement-result.v1",
      old_vote_id: replaced.oldVoteId,
      new_vote_id: replaced.newVoteId,
      decision_package_id: replaced.decisionPackageId,
      state: replaced.state,
      old_package_sha256: replaced.replayed ? null : replaced.oldPackageSha256,
      new_package_sha256: replaced.replayed ? null : replaced.newPackageSha256,
      changed_component_classes: replaced.replayed ? null : replaced.changedComponentClasses,
      response_sha256: replaced.responseSha256,
      replayed: replaced.replayed
    });
  }

  private recordRecusalAction(input: JsonValue): RecordRecusalAction {
    const parsed = toolInputSchema(MANAGE_RECUSAL).parse(input) as {
      board_id: string;
      object_id: string;
      object_type: string;
      member_id: string;
      operation: "add" | "lift";
      reason: string;
      idempotency_key: string;
    };
    if (
      parsed.object_type !== "question" &&
      parsed.object_type !== "meeting" &&
      parsed.object_type !== "minutes"
    )
      throw new Error("record recusal target is unavailable");
    return {
      boardId: parsed.board_id,
      objectType: parsed.object_type,
      objectId: parsed.object_id,
      memberId: parsed.member_id,
      operation: parsed.operation,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private boardRecusalAction(input: JsonValue): BoardRecusalAction {
    const parsed = toolInputSchema(MANAGE_RECUSAL).parse(input) as {
      board_id: string;
      object_id: string;
      object_type: string;
      member_id: string;
      operation: "add" | "lift";
      reason: string;
      idempotency_key: string;
    };
    if (parsed.object_type !== "board" || parsed.object_id !== parsed.board_id)
      throw new Error("board recusal target is unavailable");
    return {
      boardId: parsed.board_id,
      memberId: parsed.member_id,
      operation: parsed.operation,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteRecusalAction(input: JsonValue): VoteRecusalLifecycleAction {
    const parsed = toolInputSchema(MANAGE_RECUSAL).parse(input) as {
      readonly board_id: string;
      readonly idempotency_key: string;
      readonly member_id: string;
      readonly object_id: string;
      readonly object_type: "board" | "document" | "meeting" | "minutes" | "question" | "vote";
      readonly operation: "add" | "lift";
      readonly reason: string;
    };
    if (parsed.object_type !== "vote") {
      throw new Error("this confirmed manage_recusal path currently requires object_type=vote");
    }
    return {
      boardId: parsed.board_id,
      voteId: parsed.object_id,
      memberId: parsed.member_id,
      operation: parsed.operation,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteRecusalConfirmationLines(
    prepared: PreparedVoteRecusalLifecycleAction,
    code: string
  ): readonly string[] {
    return [
      "BOARDAGENT LIVE VOTE RECUSAL CONFIRMATION",
      `Vote: ${prepared.voteTitle} (${prepared.voteId})`,
      `Member: ${prepared.memberDisplayName} (${prepared.memberId})`,
      `New recusal state: ${prepared.state}`,
      `Canonical resolution SHA-256: ${prepared.resolutionSha256}`,
      "Canonical resolution text:",
      prepared.resolutionText,
      `Decision package SHA-256: ${prepared.packageSha256}`,
      `Canonical decision package: ${canonicalJson(prepared.decisionPackage)}`,
      `Reason: ${prepared.reason}`,
      `Affected active stages: ${String(prepared.affectedStageCount)}`,
      `Affected active proxies: ${String(prepared.affectedProxyCount)}`,
      `Affected effective ballots: ${String(prepared.affectedBallotCount)}`,
      `Pending feed items removed: ${String(prepared.removedPendingFeedCount)}`,
      `Recipients re-noticed: ${String(prepared.deliveryRecipientCount)}`,
      `Canonical recusal SHA-256: ${prepared.payloadSha256}`,
      prepared.state === "excluded"
        ? "Result: append the recusal, immediately invalidate every affected stage/proxy/ballot, remove the member's pending vote actions, recompute eligible weight, and notify every remaining entitled recipient."
        : "Result: append the lifted state and re-notice entitled recipients; invalidated stages, proxies, and ballots are never restored.",
      `Confirmation code: ${code}`
    ];
  }

  private voteRecusalResult(
    action: VoteRecusalLifecycleAction,
    recusal: ManageVoteRecusalResult
  ): SurfaceToolResult {
    return result(
      MANAGE_RECUSAL,
      recusal.replayed ? "already_applied" : "accepted",
      recusal.exclusionId,
      {
        schema_version: "boardagent.vote-recusal-result.v1",
        vote_id: recusal.voteId,
        member_id: recusal.memberId,
        exclusion_id: recusal.exclusionId,
        exclusion_version: recusal.exclusionVersion,
        state: recusal.state,
        operation: action.operation,
        eligible_weight: "eligibleWeight" in recusal ? recusal.eligibleWeight.toString(10) : null,
        response_sha256: recusal.responseSha256,
        replayed: recusal.replayed
      }
    );
  }

  private voteSourceExclusionAction(input: JsonValue): VoteSourceExclusionLifecycleAction {
    const parsed = toolInputSchema(EXCLUDE_PENDING_VOTE_SOURCE).parse(input) as {
      readonly idempotency_key: string;
      readonly reason: string;
      readonly source_id: string;
      readonly source_sha256: string;
      readonly source_type: "management_submission" | "document" | "question_cutoff";
      readonly source_version: number;
      readonly vote_id: string;
    };
    return {
      voteId: parsed.vote_id,
      sourceType: parsed.source_type,
      sourceId: parsed.source_id,
      sourceVersion: parsed.source_version,
      sourceSha256: parsed.source_sha256,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteSourceExclusionConfirmationLines(
    prepared: PreparedVoteSourceExclusionLifecycleAction,
    code: string
  ): readonly string[] {
    return [
      "BOARDAGENT PENDING VOTE SOURCE EXCLUSION CONFIRMATION",
      `Vote: ${prepared.voteTitle} (${prepared.voteId})`,
      `Canonical resolution SHA-256: ${prepared.resolutionSha256}`,
      "Canonical resolution text:",
      prepared.resolutionText,
      `Decision package SHA-256: ${prepared.packageSha256}`,
      `Canonical decision package: ${canonicalJson(prepared.decisionPackage)}`,
      `Pending cause: ${prepared.causeId}`,
      `Exact source: ${prepared.sourceType}/${prepared.sourceId} version ${String(prepared.sourceVersion)}`,
      `Exact source SHA-256: ${prepared.sourceSha256}`,
      `Reason: ${prepared.reason}`,
      `Canonical exclusion SHA-256: ${prepared.payloadSha256}`,
      "Result: permanently exclude only this exact pending source update; the frozen decision package remains unchanged.",
      `Confirmation code: ${code}`
    ];
  }

  private voteSourceExclusionResult(
    action: VoteSourceExclusionLifecycleAction,
    excluded: ExcludePendingVoteSourceResult
  ): SurfaceToolResult {
    return result(
      EXCLUDE_PENDING_VOTE_SOURCE,
      excluded.replayed ? "already_applied" : "accepted",
      excluded.dispositionId,
      {
        schema_version: "boardagent.vote-source-exclusion-result.v1",
        vote_id: excluded.voteId,
        cause_id: excluded.causeId,
        disposition_id: excluded.dispositionId,
        source_type: action.sourceType,
        source_id: action.sourceId,
        source_version: action.sourceVersion,
        source_sha256: action.sourceSha256,
        remaining_pending_sources:
          "remainingPendingSources" in excluded ? excluded.remainingPendingSources : null,
        vote_state: "voteState" in excluded ? excluded.voteState : null,
        response_sha256: excluded.responseSha256,
        replayed: excluded.replayed
      }
    );
  }

  private voteCancellationAction(input: JsonValue): VoteCancellationLifecycleAction {
    const parsed = toolInputSchema(CANCEL_VOTE).parse(input) as {
      readonly idempotency_key: string;
      readonly reason: string;
      readonly vote_id: string;
    };
    return {
      voteId: parsed.vote_id,
      reason: parsed.reason,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteCancellationConfirmationLines(
    prepared: PreparedVoteCancellationLifecycleAction,
    code: string
  ): readonly string[] {
    const packageLines =
      prepared.decisionPackage === null
        ? ["Decision package: none — this vote is still a draft."]
        : [
            `Decision package SHA-256: ${prepared.packageSha256 ?? "unavailable"}`,
            `Canonical decision package: ${canonicalJson(prepared.decisionPackage)}`
          ];
    return [
      "BOARDAGENT VOTE CANCELLATION CONFIRMATION",
      `Vote: ${prepared.voteTitle} (${prepared.voteId})`,
      `Current state: ${prepared.voteState}`,
      ...(prepared.resolutionText === null
        ? ["Canonical resolution: none — draft has no current resolution."]
        : [
            `Canonical resolution SHA-256: ${prepared.resolutionSha256 ?? "unavailable"}`,
            "Canonical resolution text:",
            prepared.resolutionText
          ]),
      ...packageLines,
      `Deadline: ${prepared.deadlineAt ?? "none"}`,
      `Reason: ${prepared.reason}`,
      `Recipients notified: ${String(prepared.recipientMemberIds.length)}`,
      `Canonical cancellation SHA-256: ${prepared.payloadSha256}`,
      "Result: terminally cancel this vote. Existing stages, proxies, and ballots remain immutable evidence but can never contribute to an outcome.",
      `Confirmation code: ${code}`
    ];
  }

  private voteCancellationResult(cancelled: VoteCancellationLifecycleResult): SurfaceToolResult {
    return result(CANCEL_VOTE, "accepted", cancelled.voteId, {
      schema_version: "boardagent.vote-cancellation-result.v1",
      vote_id: cancelled.voteId,
      state: cancelled.state,
      row_version: cancelled.rowVersion,
      cancelled_at: cancelled.cancelledAt,
      package_sha256: cancelled.packageSha256,
      retained_acts_non_outcome_bearing: cancelled.retainedActs,
      notice_count: cancelled.noticeCount
    });
  }

  private voteCloseAction(input: JsonValue): VoteCloseLifecycleAction {
    const parsed = toolInputSchema(CLOSE_VOTE).parse(input) as {
      readonly expected_package_sha256: string;
      readonly idempotency_key: string;
      readonly vote_id: string;
    };
    return {
      voteId: parsed.vote_id,
      expectedPackageSha256: parsed.expected_package_sha256,
      idempotencyKey: parsed.idempotency_key
    };
  }

  private voteCloseConfirmationLines(
    prepared: PreparedVoteCloseLifecycleAction,
    code: string
  ): readonly string[] {
    return [
      "BOARDAGENT VOTE CLOSE CONFIRMATION",
      `Vote: ${prepared.voteTitle} (${prepared.voteId})`,
      `Canonical resolution SHA-256: ${prepared.resolutionSha256}`,
      "Canonical resolution text:",
      prepared.resolutionText,
      `Decision package SHA-256: ${prepared.packageSha256}`,
      `Canonical decision package: ${canonicalJson(prepared.decisionPackage)}`,
      `Recomputed tally SHA-256: ${prepared.expectedTallySha256}`,
      `Recomputed tally: ${canonicalJson(prepared.expectedTally as unknown as JsonValue)}`,
      `Certificate public reference SHA-256: ${prepared.certificatePublicIdSha256}`,
      `Evidence signing key: ${prepared.signingKeyId}`,
      `Canonical close consent SHA-256: ${prepared.payloadSha256}`,
      "Result: freeze this tally and certificate payload, sign it through the separate Ed25519 evidence-key boundary, and close only after PostgreSQL verifies the signature.",
      "If signing fails, the vote remains recoverably closing and is never reported closed without a certificate.",
      `Confirmation code: ${code}`
    ];
  }

  private documentLifecycleAction(
    tool: DocumentLifecycleTool | typeof MANAGE_RECUSAL,
    input: JsonValue
  ): DocumentLifecycleAction {
    switch (tool) {
      case MANAGE_RECUSAL: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly board_id: string;
          readonly object_id: string;
          readonly object_type: string;
          readonly member_id: string;
          readonly operation: "add" | "lift";
          readonly reason: string;
        };
        if (parsed.object_type !== "document")
          throw new Error("document recusal requires a document target");
        return {
          kind: "access",
          recusal: true,
          boardId: parsed.board_id,
          documentId: parsed.object_id,
          memberId: parsed.member_id,
          operation: parsed.operation === "add" ? "exclude" : "lift_exclusion",
          permission: null,
          reason: parsed.reason
        };
      }
      case CIRCULATE_DOCUMENT: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly board_id: string;
          readonly completeness_statement: "canonical_version_stands_alone";
          readonly document_id: string;
          readonly document_sha256: string;
          readonly recipient_member_ids: readonly string[];
          readonly version_id: string;
        };
        return {
          kind: "circulation",
          boardId: parsed.board_id,
          documentId: parsed.document_id,
          versionId: parsed.version_id,
          documentSha256: parsed.document_sha256,
          recipientMemberIds: parsed.recipient_member_ids,
          completenessStatement: parsed.completeness_statement
        };
      }
      case MANAGE_DOCUMENT_ACCESS: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly board_id: string;
          readonly document_id: string;
          readonly member_id: string;
          readonly operation: "exclude" | "grant" | "lift_exclusion";
          readonly permission: "contribute" | "read" | null;
          readonly reason: string;
        };
        return {
          kind: "access",
          boardId: parsed.board_id,
          documentId: parsed.document_id,
          operation: parsed.operation,
          memberId: parsed.member_id,
          permission: parsed.permission,
          reason: parsed.reason
        };
      }
      case ARCHIVE_DOCUMENT:
      case SOFT_DELETE_DOCUMENT: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly document_id: string;
          readonly reason: string;
        };
        return {
          kind: tool === ARCHIVE_DOCUMENT ? "archive" : "soft_delete",
          documentId: parsed.document_id,
          reason: parsed.reason
        };
      }
    }
  }

  private documentConfirmationLines(
    tool: DocumentLifecycleTool | typeof MANAGE_RECUSAL,
    action: DocumentLifecycleAction,
    prepared: PreparedDocumentLifecycleAction,
    code: string
  ): readonly string[] {
    const common = [
      "BOARDAGENT DOCUMENT ACTION CONFIRMATION",
      `Action: ${tool}`,
      `Document: ${prepared.targetId}`,
      `Board: ${prepared.boardId}`,
      `Canonical action SHA-256: ${prepared.payloadSha256}`,
      `Bound package SHA-256: ${prepared.packageSha256}`
    ];
    switch (action.kind) {
      case "circulation":
        return [
          ...common,
          `Document version: ${action.versionId}`,
          `Document SHA-256: ${action.documentSha256}`,
          `Recipients (${String(action.recipientMemberIds.length)}): ${action.recipientMemberIds.toSorted().join(", ")}`,
          "Result: commit the exact circulation and one informational notice/feed item per recipient.",
          `Confirmation code: ${code}`
        ];
      case "access":
        return [
          ...common,
          `Operation: ${action.operation}`,
          `Member: ${action.memberId}`,
          `Permission: ${action.permission ?? "none"}`,
          `Reason: ${action.reason}`,
          "Result: apply the exact deny-wins access change and tombstone newly hidden feed items.",
          `Confirmation code: ${code}`
        ];
      case "archive":
        return [
          ...common,
          `Reason: ${action.reason}`,
          "Result: archive the document without changing or deleting any canonical version.",
          `Confirmation code: ${code}`
        ];
      case "soft_delete":
        return [
          ...common,
          `Reason: ${action.reason}`,
          "Result: snapshot and hide the document, tombstone visible feed items, and permanently retain every canonical version.",
          `Confirmation code: ${code}`
        ];
    }
  }

  private documentLifecycleResult(
    tool: DocumentLifecycleTool | typeof MANAGE_RECUSAL,
    lifecycle: DocumentLifecycleResult
  ): SurfaceToolResult {
    switch (lifecycle.kind) {
      case "circulation":
        if (tool !== CIRCULATE_DOCUMENT) break;
        return result(tool, "accepted", lifecycle.circulationId, {
          schema_version: "boardagent.document-circulation-result.v1",
          circulation_id: lifecycle.circulationId,
          document_id: lifecycle.documentId,
          document_version_id: lifecycle.documentVersionId,
          document_sha256: lifecycle.documentSha256,
          recipient_member_ids: lifecycle.recipientMemberIds
        });
      case "access":
        if (tool !== MANAGE_DOCUMENT_ACCESS && tool !== MANAGE_RECUSAL) break;
        return result(tool, "accepted", lifecycle.documentId, {
          schema_version:
            tool === MANAGE_RECUSAL
              ? "boardagent.document-recusal-result.v1"
              : "boardagent.document-access-change-result.v1",
          document_id: lifecycle.documentId,
          operation: lifecycle.operation,
          member_id: lifecycle.memberId,
          permission: lifecycle.permission
        });
      case "archive":
        if (tool !== ARCHIVE_DOCUMENT) break;
        return result(tool, "accepted", lifecycle.documentId, {
          schema_version: "boardagent.document-terminal-result.v1",
          document_id: lifecycle.documentId,
          state: lifecycle.state,
          retention_snapshot_id: null,
          deletion_tombstone_id: null
        });
      case "soft_delete":
        if (tool !== SOFT_DELETE_DOCUMENT) break;
        return result(tool, "accepted", lifecycle.documentId, {
          schema_version: "boardagent.document-terminal-result.v1",
          document_id: lifecycle.documentId,
          state: lifecycle.state,
          retention_snapshot_id: lifecycle.retentionSnapshotId,
          deletion_tombstone_id: lifecycle.deletionTombstoneId
        });
    }
    throw new Error(`${tool} returned an unexpected document lifecycle result: ${lifecycle.kind}`);
  }

  private minutesLifecycleAction(
    tool: MinutesLifecycleTool,
    input: JsonValue
  ): MinutesLifecycleAction {
    switch (tool) {
      case PUBLISH_MINUTES: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly minutes_id: string;
          readonly minutes_sha256: string;
          readonly signer_member_ids: readonly string[];
          readonly version_id: string;
        };
        return {
          kind: "publication",
          minutesId: parsed.minutes_id,
          versionId: parsed.version_id,
          minutesSha256: parsed.minutes_sha256,
          signerMemberIds: parsed.signer_member_ids
        };
      }
      case RESOLVE_MINUTES_REVIEW_ITEM: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly disposition: "accept" | "reject";
          readonly minutes_id: string;
          readonly reason: string;
          readonly replacement_text: string | null;
          readonly review_item_id: string;
        };
        return {
          kind: "review_disposition",
          minutesId: parsed.minutes_id,
          reviewItemId: parsed.review_item_id,
          decision: parsed.disposition === "accept" ? "accepted" : "rejected",
          reason: parsed.reason,
          ...(parsed.replacement_text === null ? {} : { replacementText: parsed.replacement_text })
        };
      }
      case CORRECT_MINUTES_PACKAGE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly canonical_text: string;
          readonly expected_version_id: string;
          readonly minutes_id: string;
          readonly reason: string;
        };
        return {
          kind: "package_correction",
          minutesId: parsed.minutes_id,
          expectedVersionId: parsed.expected_version_id,
          canonicalText: parsed.canonical_text,
          reason: parsed.reason
        };
      }
      case PREPARE_MINUTES_FOR_SIGNATURE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly expected_version_id: string;
          readonly minutes_id: string;
          readonly signer_member_ids: readonly string[];
        };
        return {
          kind: "signature_package_issue",
          minutesId: parsed.minutes_id,
          expectedVersionId: parsed.expected_version_id,
          requirements: parsed.signer_member_ids.map((memberId) => ({
            memberId,
            requirement: "required"
          }))
        };
      }
      case STAGE_MINUTES_SIGNATURE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly minutes_id: string;
          readonly package_id: string;
          readonly reservation: string | null;
        };
        return {
          kind: "signature",
          minutesId: parsed.minutes_id,
          packageId: parsed.package_id,
          reservation: parsed.reservation
        };
      }
      case FINALIZE_MINUTES: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly minutes_id: string;
          readonly package_id: string;
        };
        return {
          kind: "finalization",
          minutesId: parsed.minutes_id,
          packageId: parsed.package_id
        };
      }
      case CREATE_MINUTES_CORRECTION_CYCLE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly canonical_text: string;
          readonly minutes_id: string;
          readonly reason: string;
          readonly replacement_minutes_id: string;
        };
        return {
          kind: "finalized_correction",
          minutesId: parsed.minutes_id,
          replacementMinutesId: parsed.replacement_minutes_id,
          canonicalText: parsed.canonical_text,
          reason: parsed.reason
        };
      }
      case CANCEL_MINUTES: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly minutes_id: string;
          readonly reason: string;
        };
        return { kind: "cancellation", minutesId: parsed.minutes_id, reason: parsed.reason };
      }
      case LOG_MINUTES_ACTION_ITEMS:
      case DECLARE_NO_MINUTES_ACTION_ITEMS: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly manifest: MinutesActionManifest;
        };
        const expectedDeclaration =
          tool === LOG_MINUTES_ACTION_ITEMS ? "items_logged" : "no_action_items";
        if (parsed.manifest.declaration !== expectedDeclaration) {
          throw new TypeError(`${tool} requires a ${expectedDeclaration} manifest`);
        }
        return {
          kind: "action_declaration",
          minutesId: parsed.manifest.minutesId,
          manifest: parsed.manifest
        };
      }
    }
  }

  private minutesConfirmationLines(
    tool: MinutesLifecycleTool,
    action: MinutesLifecycleAction,
    prepared: PreparedMinutesLifecycleAction,
    code: string
  ): readonly string[] {
    const common = [
      "BOARDAGENT MINUTES ACTION CONFIRMATION",
      `Action: ${tool}`,
      `Minutes: ${action.minutesId}`,
      `Canonical action SHA-256: ${prepared.payloadSha256}`,
      `Bound package SHA-256: ${prepared.packageSha256}`
    ];
    let details: readonly string[];
    switch (action.kind) {
      case "publication":
        details = [
          `Version: ${action.versionId}`,
          `Minutes SHA-256: ${action.minutesSha256}`,
          `Proposed signers: ${action.signerMemberIds.join(", ")}`,
          "Result: publish this exact immutable version for participant review and deliver review notices."
        ];
        break;
      case "review_disposition":
        details = [
          `Review item: ${action.reviewItemId}`,
          `Decision: ${action.decision}`,
          `Reason: ${action.reason}`,
          `Replacement text SHA-256: ${action.replacementText === undefined ? "none" : sha256Hex(action.replacementText)}`,
          "Result: permanently disposition this exact review item; an accepted redline creates a new immutable minutes version."
        ];
        break;
      case "package_correction":
        details = [
          `Expected current version: ${action.expectedVersionId}`,
          `Corrected text SHA-256: ${sha256Hex(action.canonicalText)}`,
          `Reason: ${action.reason}`,
          "Result: create a new immutable version, invalidate stale draft actions/signatures, and return the package to review."
        ];
        break;
      case "action_declaration": {
        const manifest = MinutesActionManifestSchema.parse(action.manifest);
        details = [
          `Declaration: ${manifest.declaration}`,
          `Manifest SHA-256: ${canonicalSha256(manifest)}`,
          `Draft action items: ${manifest.declaration === "items_logged" ? String(manifest.items.length) : "0"}`,
          "Result: freeze the exact action-items-or-none declaration; any items remain draft until minutes finalization."
        ];
        break;
      }
      case "signature_package_issue":
        details = [
          `Expected current version: ${action.expectedVersionId}`,
          `Required signers: ${action.requirements.map(({ memberId }) => memberId).join(", ")}`,
          "Result: freeze the exact current package and request fresh signatures from the configured signers."
        ];
        break;
      case "signature":
        details = [
          `Signature package: ${action.packageId}`,
          `Reservation SHA-256: ${action.reservation === null ? "none" : sha256Hex(action.reservation)}`,
          "Result: create your attributable signature over this exact current package; an observer signature is an attestation, not a vote."
        ];
        break;
      case "finalization":
        details = [
          `Signature package: ${action.packageId}`,
          "Result: finalize the minutes permanently and activate the exact declared action items."
        ];
        break;
      case "finalized_correction":
        details = [
          `Replacement minutes: ${action.replacementMinutesId}`,
          `Replacement text SHA-256: ${sha256Hex(action.canonicalText)}`,
          `Reason: ${action.reason}`,
          "Result: preserve the finalized original and create a linked replacement aggregate in review."
        ];
        break;
      case "cancellation":
        details = [
          `Reason: ${action.reason}`,
          "Result: cancel this nonfinal minutes package permanently and supersede its draft action items."
        ];
        break;
    }
    return [...common, ...details, `Confirmation code: ${code}`];
  }

  private minutesLifecycleResult(
    tool: MinutesLifecycleTool,
    lifecycle: MinutesLifecycleResult
  ): SurfaceToolResult {
    switch (lifecycle.kind) {
      case "publication":
        if (tool !== PUBLISH_MINUTES) break;
        return result(tool, "accepted", lifecycle.minutesId, {
          schema_version: "boardagent.minutes-publication-result.v1",
          minutes_id: lifecycle.minutesId,
          minutes_version_id: lifecycle.minutesVersionId,
          minutes_sha256: lifecycle.minutesSha256,
          review_recipient_member_ids: [...lifecycle.reviewRecipientMemberIds]
        });
      case "review_disposition":
        if (tool !== RESOLVE_MINUTES_REVIEW_ITEM) break;
        return result(tool, "accepted", lifecycle.dispositionId, {
          schema_version: "boardagent.minutes-review-disposition-result.v1",
          disposition_id: lifecycle.dispositionId,
          minutes_id: lifecycle.minutesId,
          minutes_version_id: lifecycle.minutesVersionId,
          minutes_sha256: lifecycle.minutesSha256,
          decision: lifecycle.decision
        });
      case "package_correction":
        if (tool !== CORRECT_MINUTES_PACKAGE) break;
        return result(tool, "accepted", lifecycle.minutesVersionId, {
          schema_version: "boardagent.minutes-package-correction-result.v1",
          minutes_id: lifecycle.minutesId,
          minutes_version_id: lifecycle.minutesVersionId,
          minutes_sha256: lifecycle.minutesSha256
        });
      case "action_declaration":
        if (tool !== LOG_MINUTES_ACTION_ITEMS && tool !== DECLARE_NO_MINUTES_ACTION_ITEMS) {
          break;
        }
        return result(tool, "accepted", lifecycle.declarationId, {
          schema_version: "boardagent.minutes-action-declaration-result.v1",
          minutes_id: lifecycle.minutesId,
          declaration_id: lifecycle.declarationId,
          manifest_sha256: lifecycle.manifestSha256,
          task_ids: [...lifecycle.taskIds]
        });
      case "signature_package_issue":
        if (tool !== PREPARE_MINUTES_FOR_SIGNATURE) break;
        return result(tool, "accepted", lifecycle.signaturePackageId, {
          schema_version: "boardagent.minutes-signature-package-result.v1",
          minutes_id: lifecycle.minutesId,
          signature_package_id: lifecycle.signaturePackageId,
          package_sha256: lifecycle.packageSha256,
          signer_member_ids: [...lifecycle.signerMemberIds]
        });
      case "signature":
        if (tool !== STAGE_MINUTES_SIGNATURE) break;
        return result(tool, "accepted", lifecycle.signatureId, {
          schema_version: "boardagent.minutes-signature-result.v1",
          minutes_id: lifecycle.minutesId,
          signature_id: lifecycle.signatureId,
          signature_record_sha256: lifecycle.signatureRecordSha256
        });
      case "finalization":
        if (tool !== FINALIZE_MINUTES) break;
        return result(tool, "accepted", lifecycle.minutesId, {
          schema_version: "boardagent.minutes-finalization-result.v1",
          minutes_id: lifecycle.minutesId,
          activation_manifest_sha256: lifecycle.activationManifestSha256,
          activated_task_ids: [...lifecycle.activatedTaskIds]
        });
      case "finalized_correction":
        if (tool !== CREATE_MINUTES_CORRECTION_CYCLE) break;
        return result(tool, "accepted", lifecycle.replacementMinutesId, {
          schema_version: "boardagent.minutes-correction-cycle-result.v1",
          original_minutes_id: lifecycle.originalMinutesId,
          replacement_minutes_id: lifecycle.replacementMinutesId,
          replacement_version_id: lifecycle.replacementVersionId,
          replacement_sha256: lifecycle.replacementSha256
        });
      case "cancellation":
        if (tool !== CANCEL_MINUTES) break;
        return result(tool, "accepted", lifecycle.minutesId, {
          schema_version: "boardagent.minutes-cancellation-result.v1",
          minutes_id: lifecycle.minutesId,
          superseded_draft_task_ids: [...lifecycle.supersededDraftTaskIds]
        });
    }
    throw new Error(`${tool} returned an unexpected minutes lifecycle result: ${lifecycle.kind}`);
  }

  private taskLifecycleAction(tool: TaskLifecycleTool, input: JsonValue): TaskLifecycleAction {
    switch (tool) {
      case REVIEW_TASK_EVIDENCE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly disposition: "accept" | "reject";
          readonly evidence_id: string;
          readonly reason: string;
          readonly task_id: string;
        };
        return {
          kind: "evidence_review",
          taskId: parsed.task_id,
          evidenceId: parsed.evidence_id,
          decision: parsed.disposition === "accept" ? "accepted" : "rejected",
          reason: parsed.reason
        };
      }
      case COMPLETE_TASK: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly evidence_ids: readonly string[];
          readonly task_id: string;
        };
        return {
          kind: "closure",
          taskId: parsed.task_id,
          acceptedEvidenceIds: parsed.evidence_ids
        };
      }
      case CREATE_TASK_CORRECTION_CYCLE: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly description: string;
          readonly due_at: string;
          readonly owner_member_id: string;
          readonly reason: string;
          readonly replacement_task_id: string;
          readonly required_evidence: readonly string[];
          readonly task_id: string;
        };
        return {
          kind: "completed_correction",
          taskId: parsed.task_id,
          replacementTaskId: parsed.replacement_task_id,
          reason: parsed.reason,
          replacement: {
            ownerMemberId: parsed.owner_member_id,
            dueAt: parsed.due_at,
            description: parsed.description,
            requiredEvidence: parsed.required_evidence
          }
        };
      }
      case CANCEL_TASK: {
        const parsed = toolInputSchema(tool).parse(input) as {
          readonly reason: string;
          readonly task_id: string;
        };
        return { kind: "cancellation", taskId: parsed.task_id, reason: parsed.reason };
      }
    }
  }

  private taskCreationAction(input: JsonValue): TaskCreationAction {
    const parsed = toolInputSchema(CREATE_TASK).parse(input) as {
      readonly board_id: string;
      readonly description: string;
      readonly due_at: string;
      readonly owner_member_id: string;
      readonly required_evidence: readonly string[];
      readonly source_minutes_id: string | null;
      readonly source_minutes_version_id: string | null;
      readonly task_id: string;
    };
    return {
      taskId: parsed.task_id,
      boardId: parsed.board_id,
      ownerMemberId: parsed.owner_member_id,
      dueAt: parsed.due_at,
      description: parsed.description,
      requiredEvidence: parsed.required_evidence,
      sourceMinutesId: parsed.source_minutes_id,
      sourceMinutesVersionId: parsed.source_minutes_version_id
    };
  }

  private taskCreationResult(created: TaskCreationResult): SurfaceToolResult {
    return result(CREATE_TASK, "accepted", created.taskId, {
      schema_version: "boardagent.task-creation-result.v1",
      task_id: created.taskId,
      task_sha256: created.taskSha256,
      owner_member_id: created.ownerMemberId
    });
  }

  private taskConfirmationLines(
    tool: TaskLifecycleTool,
    action: TaskLifecycleAction,
    prepared: PreparedTaskLifecycleAction,
    code: string
  ): readonly string[] {
    const common = [
      "BOARDAGENT TASK ACTION CONFIRMATION",
      `Action: ${tool}`,
      `Task: ${action.taskId}`,
      `Canonical action SHA-256: ${prepared.payloadSha256}`,
      `Bound task SHA-256: ${prepared.packageSha256}`
    ];
    let details: readonly string[];
    switch (action.kind) {
      case "evidence_review":
        details = [
          `Evidence: ${action.evidenceId}`,
          `Decision: ${action.decision}`,
          `Reason: ${action.reason}`,
          "Result: permanently review this exact evidence; rejection preserves it and returns the task to open."
        ];
        break;
      case "closure":
        details = [
          `Accepted evidence: ${action.acceptedEvidenceIds.join(", ")}`,
          "Result: complete this task permanently over every exact accepted evidence record."
        ];
        break;
      case "completed_correction":
        details = [
          `Replacement task: ${action.replacementTaskId}`,
          `Replacement owner: ${action.replacement.ownerMemberId}`,
          `Replacement due: ${action.replacement.dueAt}`,
          `Replacement description SHA-256: ${sha256Hex(action.replacement.description)}`,
          `Required evidence items: ${String(action.replacement.requiredEvidence.length)}`,
          `Reason: ${action.reason}`,
          "Result: preserve the completed original and create a separately tracked open replacement task."
        ];
        break;
      case "cancellation":
        details = [`Reason: ${action.reason}`, "Result: cancel this nonterminal task permanently."];
        break;
    }
    return [...common, ...details, `Confirmation code: ${code}`];
  }

  private taskLifecycleResult(
    tool: TaskLifecycleTool,
    lifecycle: TaskLifecycleResult
  ): SurfaceToolResult {
    switch (lifecycle.kind) {
      case "evidence_review":
        if (tool !== REVIEW_TASK_EVIDENCE) break;
        return result(tool, "accepted", lifecycle.reviewId, {
          schema_version: "boardagent.task-evidence-review-result.v1",
          task_id: lifecycle.taskId,
          evidence_id: lifecycle.evidenceId,
          review_id: lifecycle.reviewId,
          decision: lifecycle.decision
        });
      case "closure":
        if (tool !== COMPLETE_TASK) break;
        return result(tool, "accepted", lifecycle.closureId, {
          schema_version: "boardagent.task-closure-result.v1",
          task_id: lifecycle.taskId,
          closure_id: lifecycle.closureId,
          closure_sha256: lifecycle.closureSha256
        });
      case "completed_correction":
        if (tool !== CREATE_TASK_CORRECTION_CYCLE) break;
        return result(tool, "accepted", lifecycle.replacementTaskId, {
          schema_version: "boardagent.task-correction-cycle-result.v1",
          prior_task_id: lifecycle.priorTaskId,
          replacement_task_id: lifecycle.replacementTaskId,
          correction_cycle_id: lifecycle.correctionCycleId
        });
      case "cancellation":
        if (tool !== CANCEL_TASK) break;
        return result(tool, "accepted", lifecycle.taskId, {
          schema_version: "boardagent.task-cancellation-result.v1",
          task_id: lifecycle.taskId
        });
    }
    throw new Error(`${tool} returned an unexpected task lifecycle result: ${lifecycle.kind}`);
  }

  public async replayHumanAction(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<SurfaceToolResult | null> {
    if (tool === MANAGE_MEMBER && !isMemberLifecycleInput(input)) {
      const completed = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          replayCompletedMemberInviteInTransaction(
            client,
            input,
            exactServiceOrigin(principal.serviceOrigin),
            principal.accessTokenRecordId
          ),
        this.transaction
      );
      return completed
        ? result(MANAGE_MEMBER, "already_applied", completed.memberId, {
            schema_version: "boardagent.member-changed.v1",
            operation: "invite",
            member_id: completed.memberId,
            membership_id: completed.membershipId,
            board_id: completed.boardId,
            state: "invited",
            next_action: ISSUE_ENROLLMENT
          })
        : null;
    }
    if (tool === MANAGE_MEMBER && isMemberLifecycleInput(input)) {
      const completed = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          replayCompletedMemberLifecycleInTransaction(
            client,
            input,
            exactServiceOrigin(principal.serviceOrigin),
            principal.accessTokenRecordId
          ),
        this.transaction
      );
      return completed
        ? result(MANAGE_MEMBER, "already_applied", completed.memberId, {
            schema_version: "boardagent.member-changed.v1",
            operation: completed.operation,
            member_id: completed.memberId,
            board_id: completed.boardId,
            member: completed.memberAfter,
            seats: completed.seatsAfter,
            connections_revoked: true
          })
        : null;
    }
    if (tool !== STAGE_BALLOT) return null;
    const action = this.ballotLifecycleAction(tool, input);
    if (action.kind !== "ballot") throw new Error("ballot action mismatch");
    const completed = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) => replayCompletedBallotInTransaction(client, action),
      this.transaction
    );
    return completed
      ? this.ballotLifecycleResult(tool, { kind: "ballot", result: completed })
      : null;
  }

  public async prepareHumanAction(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<PreparedHumanAction> {
    if (this.controlPlane.handlesHumanTool(tool)) {
      return this.controlPlane.prepareHumanAction(principal, tool, input);
    }
    if (
      tool !== ISSUE_ENROLLMENT &&
      tool !== REISSUE_ACTIVATION &&
      tool !== MANAGE_MEMBER &&
      !isAdministrativeAuthorityTool(tool) &&
      tool !== CONFIRM_ENROLLMENT_ACTIVATION &&
      tool !== CREATE_TASK &&
      !isDocumentLifecycleTool(tool) &&
      !isMeetingLifecycleTool(tool) &&
      !isTranscriptLifecycleTool(tool) &&
      !isBallotLifecycleTool(tool) &&
      tool !== CREATE_VOTE &&
      tool !== REPLACE_OPEN_VOTE &&
      tool !== AMEND_RESOLUTION_TEXT &&
      tool !== EXTEND_VOTE_DEADLINE &&
      tool !== MANAGE_RECUSAL &&
      tool !== EXCLUDE_PENDING_VOTE_SOURCE &&
      tool !== CANCEL_VOTE &&
      tool !== CLOSE_VOTE &&
      !isMinutesLifecycleTool(tool) &&
      !isTaskLifecycleTool(tool)
    ) {
      throw new Error(`confirmed surface action is not implemented yet: ${tool}`);
    }
    const code = confirmationCode();
    const expiresAt = new Date(this.now().getTime() + 600_000).toISOString();
    if (isAdministrativeAuthorityTool(tool)) {
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareAdministrativeAuthorityInTransaction(client, input, tool),
        this.transaction
      );
      const snapshot = prepared.snapshot;
      const change = (prepared.request as { change: { reason: string } }).change;
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: tool,
        board_id: snapshot.boardId,
        target_type: snapshot.recordType,
        target_id: snapshot.recordId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: [
          tool === MANAGE_COMPANY_ADMIN
            ? "BOARDAGENT COMPANY ADMINISTRATOR CONFIRMATION"
            : "BOARDAGENT SECRETARY DELEGATION CONFIRMATION",
          `Operation: ${snapshot.operation}`,
          `Acting person: ${snapshot.actorDisplayName} (${snapshot.actorMemberId})`,
          `Named person: ${snapshot.targetDisplayName} (${snapshot.targetMemberId})`,
          ...(snapshot.boardId === null
            ? []
            : [
                `Board: ${snapshot.boardId}`,
                "This authority covers ordinary voting-director administration on this board. Company administration, other boards and further delegation are outside its scope."
              ]),
          `Authority record: ${snapshot.recordId}; resulting version: ${snapshot.recordVersion}`,
          `Reason: ${change.reason}`,
          ...(tool === MANAGE_COMPANY_ADMIN &&
          (snapshot.operation === "grant" || snapshot.operation === "transfer")
            ? [
                "This creates an offer valid for 24 hours from confirmation. The named person must personally accept before authority changes.",
                ...(snapshot.operation === "transfer"
                  ? ["Acceptance transfers your administrator role to the named person."]
                  : [])
              ]
            : [
                `Before: ${canonicalJson(snapshot.before)}`,
                `After: ${canonicalJson(snapshot.after)}`
              ]),
          ...snapshot.memberChanges.map(
            (member) =>
              `${member.displayName} (${member.memberId}): administrator=${String(member.adminAfter)}; existing browser sessions, access and refresh credentials, unused authorization codes and pending confirmations are revoked. Reconnect to use the resulting rights.`
          ),
          "Company administration grants no VPS or root access. Historical governance evidence is retained.",
          `Confirmation code: ${code}`
        ],
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (
      tool === MANAGE_RECUSAL &&
      (isNamedRecusal(input, "question") ||
        isNamedRecusal(input, "meeting") ||
        isNamedRecusal(input, "minutes"))
    ) {
      const action = this.recordRecusalAction(input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (c) => prepareRecordRecusalInTransaction(c, action),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: MANAGE_RECUSAL,
        board_id: prepared.boardId,
        target_type: action.objectType,
        target_id: prepared.targetId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        canonical_payload: prepared.canonicalPayload,
        confirmation_lines: [
          "BOARDAGENT RECORD RECUSAL CONFIRMATION",
          `Board: ${action.boardId}`,
          `Record: ${action.objectType} ${action.objectId}`,
          `Member: ${action.memberId}`,
          `Operation: ${action.operation}`,
          `Reason: ${action.reason}`,
          "Access to this record and its dependent records follows this recusal. Appointments, prior signatures and historical records remain unchanged.",
          "Adding a recusal invalidates pending confirmations and removes affected pending actions. Lifting never restores old confirmations. Required signatures are not waived.",
          `Canonical action SHA-256: ${prepared.payloadSha256}`,
          `Confirmation code: ${code}`
        ]
      };
    }
    if (tool === MANAGE_RECUSAL && isNamedRecusal(input, "board")) {
      const action = this.boardRecusalAction(input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (c) => prepareBoardRecusalInTransaction(c, action),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: MANAGE_RECUSAL,
        board_id: prepared.boardId,
        target_type: "board",
        target_id: prepared.targetId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        canonical_payload: prepared.canonicalPayload,
        confirmation_lines: [
          "BOARDAGENT BOARD RECUSAL CONFIRMATION",
          `Board: ${action.boardId}`,
          `Member: ${action.memberId}`,
          `Operation: ${action.operation}`,
          `Reason: ${action.reason}`,
          "Board access and future board notices follow this recusal. The appointment and historical records remain unchanged.",
          "Adding a recusal invalidates pending confirmations and removes pending board actions. Lifting never restores those actions.",
          `Canonical action SHA-256: ${prepared.payloadSha256}`,
          `Confirmation code: ${code}`
        ]
      };
    }
    if (
      isDocumentLifecycleTool(tool) ||
      (tool === MANAGE_RECUSAL && isNamedRecusal(input, "document"))
    ) {
      const action = this.documentLifecycleAction(tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareDocumentLifecycleActionInTransaction(client, action),
        this.transaction
      );
      if (prepared.actionCode !== tool) {
        throw new Error("prepared document lifecycle action code does not match the surface tool");
      }
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: "document",
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.documentConfirmationLines(tool, action, prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (isMeetingLifecycleTool(tool)) {
      const action = this.meetingLifecycleAction(tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareMeetingLifecycleActionInTransaction(client, action),
        this.transaction
      );
      if (prepared.actionCode !== tool) {
        throw new Error("prepared meeting lifecycle action code does not match the surface tool");
      }
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.meetingConfirmationLines(tool, action, prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (isTranscriptLifecycleTool(tool)) {
      const action = this.transcriptLifecycleAction(tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareTranscriptLifecycleActionInTransaction(client, action),
        this.transaction
      );
      if (prepared.actionCode !== tool) {
        throw new Error(
          "prepared transcript lifecycle action code does not match the surface tool"
        );
      }
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.transcriptConfirmationLines(tool, action, prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (isBallotLifecycleTool(tool)) {
      const action = this.ballotLifecycleAction(tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareBallotLifecycleActionInTransaction(client, action),
        this.transaction
      );
      if (prepared.actionCode !== tool) {
        throw new Error("prepared ballot lifecycle action code does not match the surface tool");
      }
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.ballotConfirmationLines(tool, action, prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === CREATE_VOTE) {
      const action = this.voteCreationAction(input);
      const stageId = UuidV7Schema.parse(this.newId());
      const creation = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          prepareVoteCreationLifecycleActionInTransaction(client, {
            action,
            newId: this.newId
          }),
        this.transaction
      );
      const view: PreparedHumanAction = {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: stageId,
        action_code: CREATE_VOTE,
        board_id: creation.prepared.boardId,
        target_type: "vote",
        target_id: creation.prepared.voteId,
        package_sha256: creation.prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteCreationConfirmationLines(creation.prepared, code),
        canonical_payload: creation.prepared.canonicalPayload
      };
      this.voteCreationMaterial.set(view, creation.material);
      return view;
    }
    if (tool === REPLACE_OPEN_VOTE) {
      const action = this.voteReplacementAction(input);
      const stageId = UuidV7Schema.parse(this.newId());
      const replacement = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          prepareVoteReplacementLifecycleActionInTransaction(client, {
            action,
            newId: this.newId
          }),
        this.transaction
      );
      const view: PreparedHumanAction = {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: stageId,
        action_code: REPLACE_OPEN_VOTE,
        board_id: replacement.prepared.boardId,
        target_type: "vote",
        target_id: replacement.prepared.oldVoteId,
        package_sha256: replacement.prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteReplacementConfirmationLines(replacement.prepared, code),
        canonical_payload: replacement.prepared.canonicalPayload
      };
      this.voteReplacementMaterial.set(view, replacement.material);
      return view;
    }
    if (tool === AMEND_RESOLUTION_TEXT) {
      const stageId = UuidV7Schema.parse(this.newId());
      const replacement = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          prepareVoteResolutionAmendmentLifecycleActionInTransaction(client, {
            ...this.voteResolutionAmendmentInput(input),
            newId: this.newId
          }),
        this.transaction
      );
      const view: PreparedHumanAction = {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: stageId,
        action_code: AMEND_RESOLUTION_TEXT,
        board_id: replacement.prepared.boardId,
        target_type: "vote",
        target_id: replacement.prepared.oldVoteId,
        package_sha256: replacement.prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteReplacementConfirmationLines(replacement.prepared, code),
        canonical_payload: replacement.prepared.canonicalPayload
      };
      this.voteEditReplacement.set(view, {
        action: replacement.action,
        material: replacement.material
      });
      return view;
    }
    if (tool === EXTEND_VOTE_DEADLINE) {
      const stageId = UuidV7Schema.parse(this.newId());
      const replacement = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          prepareVoteDeadlineExtensionLifecycleActionInTransaction(client, {
            ...this.voteDeadlineExtensionInput(input),
            newId: this.newId
          }),
        this.transaction
      );
      const view: PreparedHumanAction = {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: stageId,
        action_code: EXTEND_VOTE_DEADLINE,
        board_id: replacement.prepared.boardId,
        target_type: "vote",
        target_id: replacement.prepared.oldVoteId,
        package_sha256: replacement.prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteReplacementConfirmationLines(replacement.prepared, code),
        canonical_payload: replacement.prepared.canonicalPayload
      };
      this.voteEditReplacement.set(view, {
        action: replacement.action,
        material: replacement.material
      });
      return view;
    }
    if (tool === MANAGE_RECUSAL) {
      const action = this.voteRecusalAction(input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareVoteRecusalLifecycleActionInTransaction(client, action),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteRecusalConfirmationLines(prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === EXCLUDE_PENDING_VOTE_SOURCE) {
      const action = this.voteSourceExclusionAction(input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareVoteSourceExclusionLifecycleActionInTransaction(client, action),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteSourceExclusionConfirmationLines(prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === CANCEL_VOTE) {
      const action = this.voteCancellationAction(input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareVoteCancellationLifecycleActionInTransaction(client, action),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteCancellationConfirmationLines(prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === CLOSE_VOTE) {
      if (!this.voteCertificateSigner) {
        throw new Error("vote certificate signer is unavailable");
      }
      const action = this.voteCloseAction(input);
      const material: VoteCloseStageMaterial = {
        outcomeId: UuidV7Schema.parse(this.newId()),
        certificateId: UuidV7Schema.parse(this.newId()),
        certificatePublicId: secureBytes(this.entropy, 32).toString("base64url"),
        closeConsentRecordId: UuidV7Schema.parse(this.newId()),
        closingAuditEventId: UuidV7Schema.parse(this.newId())
      };
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareVoteCloseLifecycleActionInTransaction(client, { action, material }),
        this.transaction
      );
      const view: PreparedHumanAction = {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: CLOSE_VOTE,
        board_id: prepared.boardId,
        target_type: "vote",
        target_id: prepared.voteId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.voteCloseConfirmationLines(prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
      this.voteCloseMaterial.set(view, material);
      return view;
    }
    if (isMinutesLifecycleTool(tool)) {
      const action = this.minutesLifecycleAction(tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareMinutesLifecycleActionInTransaction(client, action),
        this.transaction
      );
      if (prepared.actionCode !== tool) {
        throw new Error("prepared minutes lifecycle action code does not match the surface tool");
      }
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: "minutes",
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.minutesConfirmationLines(tool, action, prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === CREATE_TASK) {
      const action = this.taskCreationAction(input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareTaskCreationInTransaction(client, action),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: CREATE_TASK,
        board_id: prepared.boardId,
        target_type: "task",
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: [
          "BOARDAGENT TASK CREATION CONFIRMATION",
          `Task: ${prepared.targetId}`,
          `Board: ${prepared.boardId}`,
          `Owner: ${prepared.action.ownerMemberId}`,
          `Due: ${prepared.action.dueAt}`,
          `Description SHA-256: ${sha256Hex(prepared.action.description)}`,
          `Required evidence items: ${String(prepared.action.requiredEvidence.length)}`,
          `Canonical action SHA-256: ${prepared.payloadSha256}`,
          `Bound task SHA-256: ${prepared.packageSha256}`,
          "Result: create one open task and deliver one pending assignment to its owner.",
          `Confirmation code: ${code}`
        ],
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (isTaskLifecycleTool(tool)) {
      const action = this.taskLifecycleAction(tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareTaskLifecycleActionInTransaction(client, action),
        this.transaction
      );
      if (prepared.actionCode !== tool) {
        throw new Error("prepared task lifecycle action code does not match the surface tool");
      }
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: "task",
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: this.taskConfirmationLines(tool, action, prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === CONFIRM_ENROLLMENT_ACTIVATION) {
      const prepared = await this.prepareActivation(principal, input);
      const enteredCode = (input as { confirmation_code?: JsonValue }).confirmation_code;
      if (typeof enteredCode !== "string") {
        throw new Error("activation code is unavailable after strict input validation");
      }
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: CONFIRM_ENROLLMENT_ACTIVATION,
        board_id: null,
        target_type: "member",
        target_id: prepared.memberId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: [
          prepared.recovery
            ? "BOARDAGENT REPLACEMENT PASSKEY CONFIRMATION"
            : "BOARDAGENT MEMBER ACTIVATION CONFIRMATION",
          `Member: ${prepared.memberDisplayName} (${prepared.memberId})`,
          ...prepared.seats.map(
            (seat) =>
              `Board: ${seat.boardName} (${seat.boardId}); seat: ${seat.seatRole}; ` +
              `secretary: ${seat.isSecretary ? "yes" : "no"}; voting weight: ${seat.votingWeight}`
          ),
          `Member's activation code: ${enteredCode}`,
          `Identity proofing: ${prepared.proofingMethod}`,
          `Human code expires: ${prepared.challengeExpiresAt}`,
          ...(prepared.recovery
            ? [
                `Replacement credential: ${prepared.recovery.credentialId}; exact SHA-256: ${prepared.recovery.credentialSha256}`,
                "Result if the code matches: activate only this replacement passkey. Account, seats and roles stay as recorded."
              ]
            : [
                "Result if the code matches: activate this member and create their onboarding task."
              ]),
          "The enrollment link alone is not sufficient; confirm only after verifying the named person.",
          `Confirmation code: ${code}`
        ],
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === MANAGE_MEMBER && isMemberLifecycleInput(input)) {
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareMemberLifecycleInTransaction(client, input),
        this.transaction
      );
      const change = (prepared.request as { change: { reason: string } }).change;
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: MANAGE_MEMBER,
        board_id: prepared.boardId,
        target_type: "member",
        target_id: prepared.memberId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: [
          "BOARDAGENT MEMBER AUTHORITY CONFIRMATION",
          `Operation: ${prepared.operation}`,
          `Member: ${prepared.snapshot.memberBefore.displayName} (${prepared.memberId})`,
          `Scope: ${prepared.boardId ?? "organization-wide person authority"}`,
          `Person state: ${prepared.snapshot.memberBefore.state} → ${prepared.snapshot.memberAfter.state}`,
          `Organization assignments (usable only while the person is active): ${prepared.snapshot.memberBefore.organizationRoles.join(", ") || "none"}`,
          ...prepared.snapshot.seatsAfter.map((after) => {
            const before = prepared.snapshot.seatsBefore.find(
              (seat) => seat.membershipId === after.membershipId
            )!;
            return `Board ${after.boardId}: ${before.state}/${before.seatRole}/secretary=${String(before.isSecretary)}/weight=${before.votingWeight} → ${after.state}/${after.seatRole}/secretary=${String(after.isSecretary)}/weight=${after.votingWeight}`;
          }),
          `Reason: ${change.reason}`,
          prepared.snapshot.connectionEffect,
          ...(prepared.snapshot.administrativeAuthority === undefined
            ? []
            : [
                `Administrative authority and appointment evidence: ${canonicalJson(prepared.snapshot.administrativeAuthority)}`
              ]),
          "Historical ballots, consents and membership versions remain unchanged.",
          `Confirmation code: ${code}`
        ],
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === MANAGE_MEMBER) {
      const prepared = await this.prepareMemberInvite(principal, input);
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: MANAGE_MEMBER,
        board_id: prepared.boardId,
        target_type: "member",
        target_id: prepared.memberId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: [
          "BOARDAGENT MEMBER INVITE CONFIRMATION",
          ...(prepared.reason === null ? [] : [`Reason: ${prepared.reason}`]),
          ...(prepared.administrativeAuthority === null
            ? []
            : [
                `Administrative authority and appointment evidence: ${canonicalJson(prepared.administrativeAuthority)}`
              ]),
          `Operation: Invite and precreate one member seat`,
          `Member: ${prepared.memberDisplayName} (${prepared.memberId})`,
          `Legal name: ${prepared.memberLegalName}`,
          `Kind: ${prepared.memberKind}`,
          `Board: ${prepared.boardName} (${prepared.boardId})`,
          `Seat: ${prepared.seatRole}; secretary: no; voting weight: ${prepared.votingWeight}`,
          ...(prepared.accountablePrincipalId === null
            ? []
            : [
                `Accountable principal: ${prepared.accountablePrincipalName ?? "unnamed"} (${prepared.accountablePrincipalId})`
              ]),
          "Result: member state invited; enrollment remains a separate confirmed action.",
          `Confirmation code: ${code}`
        ],
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (tool === REISSUE_ACTIVATION) {
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareActivationRestartInTransaction(client, input),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: REISSUE_ACTIVATION,
        board_id: null,
        target_type: "member",
        target_id: prepared.memberId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(expiresAt),
        confirmation_lines: [
          "BOARDAGENT ACTIVATION RESTART CONFIRMATION",
          `Member: ${prepared.memberDisplayName} (${prepared.memberId})`,
          ...prepared.seats.map(
            (seat) =>
              `Board: ${seat.boardName} (${seat.boardId}); seat: ${seat.seatRole}; ` +
              `secretary: ${seat.isSecretary ? "yes" : "no"}; voting weight: ${seat.votingWeight}`
          ),
          `Stale activation challenge: ${prepared.staleChallengeId} (${prepared.staleChallengeState}; ` +
            `${String(prepared.attemptCount)} attempts; expired ${prepared.staleExpiresAt})`,
          `Identity proofing for the fresh code: ${prepared.proofingMethod}`,
          "Result if approved: the stale code is revoked and a one-time ten-minute restart link is created.",
          "The person must prove it is them with the passkey they already registered; only then is a fresh ten-minute code shown.",
          "Nothing is activated by this act; you still confirm the fresh code afterwards.",
          `Confirmation code: ${code}`
        ],
        canonical_payload: prepared.canonicalPayload
      };
    }
    const prepared = await this.prepareIssue(principal, input);
    return {
      schema_version: "boardagent.prepared-human-action.v1",
      stage_id: UuidV7Schema.parse(this.newId()),
      action_code: ISSUE_ENROLLMENT,
      board_id: null,
      target_type: "member",
      target_id: prepared.memberId,
      package_sha256: null,
      confirmation_code: code,
      expires_at: Rfc3339UtcSchema.parse(expiresAt),
      confirmation_lines: [
        "BOARDAGENT ENROLLMENT CONFIRMATION",
        `Member: ${prepared.memberDisplayName} (${prepared.memberId})`,
        ...prepared.seats.map(
          (seat) =>
            `Board: ${seat.boardName} (${seat.boardId}); seat: ${seat.seatRole}; ` +
            `secretary: ${seat.isSecretary ? "yes" : "no"}; voting weight: ${seat.votingWeight}`
        ),
        `Handoff: ${(input as { handoff_method?: unknown }).handoff_method === "operator_qr" ? "operator QR" : "operator display"}`,
        `Lifetime: ${(input as { expires_in_seconds?: unknown }).expires_in_seconds as number} seconds`,
        "One-time enrollment link is created only after approval and cannot be recovered or replayed.",
        `Confirmation code: ${code}`
      ],
      canonical_payload: prepared.canonicalPayload
    };
  }

  public async persistHumanStage(input: PersistHumanStageInput): Promise<void> {
    if (isAdministrativeAuthorityTool(input.tool)) {
      const tool = input.tool;
      const boardId =
        tool === MANAGE_COMPANY_ADMIN ? null : UuidV7Schema.parse(input.prepared.board_id);
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      if (
        input.prepared.action_code !== tool ||
        input.prepared.board_id !== boardId ||
        !(
          tool === MANAGE_COMPANY_ADMIN
            ? ["company_admin_proposal", "company_admin_assignment"]
            : ["member_admin_delegation"]
        ).includes(input.prepared.target_type) ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared administrative action has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (client) =>
          stageActionInTransaction(
            client,
            {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              boardId,
              actingForMemberId: null,
              actionCode: tool,
              targetType: input.prepared.target_type,
              targetId,
              canonicalSchema: "boardagent.administrative-authority.v1",
              canonicalPayload: input.prepared.canonical_payload,
              packageSha256: null,
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalName: tool,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            },
            async (requestClient) => {
              const current = await prepareAdministrativeAuthorityInTransaction(
                requestClient,
                input.input,
                tool
              );
              if (
                current.snapshot.recordId !== targetId ||
                current.snapshot.boardId !== boardId ||
                current.snapshot.recordType !== input.prepared.target_type ||
                !safeHashEqual(
                  current.payloadSha256,
                  canonicalSha256(input.prepared.canonical_payload)
                )
              ) {
                throw new Error("prepared administrative authority changed before persistence");
              }
            }
          ),
        this.transaction
      );
      return;
    }
    if (this.controlPlane.handlesHumanTool(input.tool)) {
      await this.controlPlane.persistHumanStage(input);
      return;
    }
    if (
      input.tool === MANAGE_RECUSAL &&
      (isNamedRecusal(input.input, "question") ||
        isNamedRecusal(input.input, "meeting") ||
        isNamedRecusal(input.input, "minutes"))
    ) {
      const action = this.recordRecusalAction(input.input);
      if (
        input.prepared.action_code !== MANAGE_RECUSAL ||
        input.prepared.target_type !== action.objectType ||
        input.prepared.target_id !== action.objectId ||
        input.prepared.board_id !== action.boardId ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared record recusal changed before persistence");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (c) => {
          const staged = await stageRecordRecusalInTransaction(c, {
            action,
            stage: {
              stageId: UuidV7Schema.parse(input.prepared.stage_id),
              inputRequiredAttemptId: this.newId(),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: input.principal.accessTokenRecordId,
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: this.newId(),
                stageCreated: this.newId(),
                elicitationSent: this.newId()
              }
            }
          });
          if (
            !safeHashEqual(staged.payloadSha256, canonicalSha256(input.prepared.canonical_payload))
          )
            throw new Error("prepared record recusal changed before persistence");
        },
        this.transaction
      );
      return;
    }
    if (input.tool === MANAGE_RECUSAL && isNamedRecusal(input.input, "board")) {
      const action = this.boardRecusalAction(input.input);
      if (
        input.prepared.action_code !== MANAGE_RECUSAL ||
        input.prepared.target_type !== "board" ||
        input.prepared.target_id !== action.boardId ||
        input.prepared.board_id !== action.boardId ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared board recusal changed before persistence");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (c) => {
          const staged = await stageBoardRecusalInTransaction(c, {
            action,
            stage: {
              stageId: UuidV7Schema.parse(input.prepared.stage_id),
              inputRequiredAttemptId: this.newId(),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: input.principal.accessTokenRecordId,
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: this.newId(),
                stageCreated: this.newId(),
                elicitationSent: this.newId()
              }
            }
          });
          if (
            !safeHashEqual(staged.payloadSha256, canonicalSha256(input.prepared.canonical_payload))
          )
            throw new Error("prepared board recusal changed before persistence");
        },
        this.transaction
      );
      return;
    }
    if (
      isDocumentLifecycleTool(input.tool) ||
      (input.tool === MANAGE_RECUSAL && isNamedRecusal(input.input, "document"))
    ) {
      if (input.prepared.action_code !== input.tool) {
        throw new Error("prepared document action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      if (
        input.prepared.target_type !== "document" ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared document stage has an invalid protected shape");
      }
      const action = this.documentLifecycleAction(input.tool, input.input);
      if (action.documentId !== targetId) {
        throw new Error("prepared document target changed");
      }
      if (
        (action.kind === "circulation" || action.kind === "access") &&
        action.boardId !== boardId
      ) {
        throw new Error("prepared document board changed");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageDocumentLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== input.tool ||
            staged.stageId !== stageId ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256)
          ) {
            throw new Error("persisted document action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (isMeetingLifecycleTool(input.tool)) {
      if (input.prepared.action_code !== input.tool) {
        throw new Error("prepared meeting action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      if (
        (input.prepared.target_type !== "meeting" &&
          input.prepared.target_type !== "meeting_attendance") ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared meeting stage has an invalid protected shape");
      }
      const action = this.meetingLifecycleAction(input.tool, input.input);
      const actionTargetId =
        action.kind === "attendance_correction" ? action.attendanceId : action.meetingId;
      if (actionTargetId !== targetId) {
        throw new Error("prepared meeting target changed");
      }
      if (action.kind === "create" && action.boardId !== boardId) {
        throw new Error("prepared meeting board changed");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageMeetingLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== input.tool ||
            staged.stageId !== stageId ||
            staged.targetType !== input.prepared.target_type ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256)
          ) {
            throw new Error("persisted meeting action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (isTranscriptLifecycleTool(input.tool)) {
      if (input.prepared.action_code !== input.tool) {
        throw new Error("prepared transcript action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.transcriptLifecycleAction(input.tool, input.input);
      const expectedTargetType =
        action.kind === "challenge_resolution" ? "transcript_challenge" : "meeting_transcript";
      if (
        input.prepared.target_type !== expectedTargetType ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared transcript stage has an invalid protected shape");
      }
      if (
        (action.kind === "verification" && action.transcriptId !== targetId) ||
        (action.kind === "challenge_resolution" && action.challengeId !== targetId)
      ) {
        throw new Error("prepared transcript target changed");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageTranscriptLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== input.tool ||
            staged.stageId !== stageId ||
            staged.targetType !== input.prepared.target_type ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256)
          ) {
            throw new Error("persisted transcript action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (isBallotLifecycleTool(input.tool)) {
      if (input.prepared.action_code !== input.tool) {
        throw new Error("prepared ballot action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.ballotLifecycleAction(input.tool, input.input);
      const expectedTargetType = action.kind === "revoke_proxy" ? "proxy_grant" : "vote";
      const expectedTargetId = action.kind === "revoke_proxy" ? action.proxyGrantId : action.voteId;
      const expectedActingForMemberId =
        action.kind === "ballot" &&
        action.principalMemberId !== null &&
        action.principalMemberId !== input.principal.memberId
          ? action.principalMemberId
          : null;
      if (
        input.prepared.target_type !== expectedTargetType ||
        targetId !== expectedTargetId ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared ballot stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageBallotLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== input.tool ||
            staged.stageId !== stageId ||
            staged.targetType !== input.prepared.target_type ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            staged.actingForMemberId !== expectedActingForMemberId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256)
          ) {
            throw new Error("persisted ballot action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (input.tool === CREATE_VOTE) {
      if (input.prepared.action_code !== CREATE_VOTE) {
        throw new Error("prepared vote creation action code changed before persistence");
      }
      const material = this.voteCreationMaterial.get(input.prepared);
      if (!material) {
        throw new Error("prepared vote creation material is unavailable");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.voteCreationAction(input.input);
      if (
        input.prepared.target_type !== "vote" ||
        action.voteId !== targetId ||
        action.boardId !== boardId ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared vote creation stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      try {
        await withRequestTransaction(
          this.pool,
          requestContext(input.principal),
          async (client) => {
            const staged = await stageVoteCreationLifecycleActionInTransaction(client, {
              action,
              material,
              stage: {
                stageId,
                inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
                nonce: secureBytes(this.entropy, 32),
                confirmationCode: input.prepared.confirmation_code,
                accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
                exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
                originalArguments: input.input,
                clientCapabilities: input.client_capabilities,
                embeddedForm: input.embedded_form,
                embeddedResult: input.embedded_result,
                requestStateBytes: Buffer.from(input.request_state, "utf8"),
                preparedRequestId: input.prepared_request_id,
                auditEventIds: {
                  stageReplaced: UuidV7Schema.parse(this.newId()),
                  stageCreated: UuidV7Schema.parse(this.newId()),
                  elicitationSent: UuidV7Schema.parse(this.newId())
                }
              }
            });
            if (
              staged.actionCode !== CREATE_VOTE ||
              staged.stageId !== stageId ||
              staged.targetType !== "vote" ||
              staged.targetId !== targetId ||
              staged.boardId !== boardId ||
              !safeHashEqual(
                staged.payloadSha256,
                canonicalSha256(input.prepared.canonical_payload)
              ) ||
              staged.packageSha256 === null ||
              !safeHashEqual(staged.packageSha256, packageSha256)
            ) {
              throw new Error("persisted vote creation changed after presentation");
            }
          },
          this.transaction
        );
      } finally {
        this.voteCreationMaterial.delete(input.prepared);
      }
      return;
    }
    if (input.tool === REPLACE_OPEN_VOTE) {
      if (input.prepared.action_code !== REPLACE_OPEN_VOTE) {
        throw new Error("prepared vote replacement action code changed before persistence");
      }
      const material = this.voteReplacementMaterial.get(input.prepared);
      if (!material) throw new Error("prepared vote replacement material is unavailable");
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.voteReplacementAction(input.input);
      if (
        input.prepared.target_type !== "vote" ||
        action.oldVoteId !== targetId ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared vote replacement stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      try {
        await withRequestTransaction(
          this.pool,
          requestContext(input.principal),
          async (client) => {
            const staged = await stageVoteReplacementLifecycleActionInTransaction(client, {
              action,
              material,
              stage: {
                stageId,
                inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
                nonce: secureBytes(this.entropy, 32),
                confirmationCode: input.prepared.confirmation_code,
                accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
                exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
                originalArguments: input.input,
                clientCapabilities: input.client_capabilities,
                embeddedForm: input.embedded_form,
                embeddedResult: input.embedded_result,
                requestStateBytes: Buffer.from(input.request_state, "utf8"),
                preparedRequestId: input.prepared_request_id,
                auditEventIds: {
                  stageReplaced: UuidV7Schema.parse(this.newId()),
                  stageCreated: UuidV7Schema.parse(this.newId()),
                  elicitationSent: UuidV7Schema.parse(this.newId())
                }
              }
            });
            if (
              staged.actionCode !== REPLACE_OPEN_VOTE ||
              staged.stageId !== stageId ||
              staged.targetType !== "vote" ||
              staged.targetId !== targetId ||
              staged.boardId !== boardId ||
              !safeHashEqual(
                staged.payloadSha256,
                canonicalSha256(input.prepared.canonical_payload)
              ) ||
              staged.packageSha256 === null ||
              !safeHashEqual(staged.packageSha256, packageSha256)
            ) {
              throw new Error("persisted vote replacement changed after presentation");
            }
          },
          this.transaction
        );
      } finally {
        this.voteReplacementMaterial.delete(input.prepared);
      }
      return;
    }
    if (input.tool === AMEND_RESOLUTION_TEXT || input.tool === EXTEND_VOTE_DEADLINE) {
      if (input.prepared.action_code !== input.tool) {
        throw new Error("prepared vote edit action code changed before persistence");
      }
      const replacement = this.voteEditReplacement.get(input.prepared);
      if (!replacement || replacement.action.actionCode !== input.tool) {
        throw new Error("prepared vote edit replacement material is unavailable");
      }
      const expectedVoteId =
        input.tool === AMEND_RESOLUTION_TEXT
          ? this.voteResolutionAmendmentInput(input.input).voteId
          : this.voteDeadlineExtensionInput(input.input).voteId;
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      if (
        input.prepared.target_type !== "vote" ||
        expectedVoteId !== targetId ||
        replacement.action.oldVoteId !== targetId ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared vote edit stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      try {
        await withRequestTransaction(
          this.pool,
          requestContext(input.principal),
          async (client) => {
            const staged = await stageVoteReplacementLifecycleActionInTransaction(client, {
              action: replacement.action,
              material: replacement.material,
              stage: {
                stageId,
                inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
                nonce: secureBytes(this.entropy, 32),
                confirmationCode: input.prepared.confirmation_code,
                accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
                exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
                originalArguments: input.input,
                clientCapabilities: input.client_capabilities,
                embeddedForm: input.embedded_form,
                embeddedResult: input.embedded_result,
                requestStateBytes: Buffer.from(input.request_state, "utf8"),
                preparedRequestId: input.prepared_request_id,
                auditEventIds: {
                  stageReplaced: UuidV7Schema.parse(this.newId()),
                  stageCreated: UuidV7Schema.parse(this.newId()),
                  elicitationSent: UuidV7Schema.parse(this.newId())
                }
              }
            });
            if (
              staged.actionCode !== input.tool ||
              staged.stageId !== stageId ||
              staged.targetType !== "vote" ||
              staged.targetId !== targetId ||
              staged.boardId !== boardId ||
              !safeHashEqual(
                staged.payloadSha256,
                canonicalSha256(input.prepared.canonical_payload)
              ) ||
              staged.packageSha256 === null ||
              !safeHashEqual(staged.packageSha256, packageSha256)
            ) {
              throw new Error("persisted vote edit replacement changed after presentation");
            }
          },
          this.transaction
        );
      } finally {
        this.voteEditReplacement.delete(input.prepared);
      }
      return;
    }
    if (input.tool === MANAGE_RECUSAL) {
      if (input.prepared.action_code !== MANAGE_RECUSAL) {
        throw new Error("prepared vote recusal action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.voteRecusalAction(input.input);
      if (
        input.prepared.target_type !== "vote" ||
        targetId !== action.voteId ||
        boardId !== action.boardId ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared vote recusal stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageVoteRecusalLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== MANAGE_RECUSAL ||
            staged.stageId !== stageId ||
            staged.targetType !== "vote" ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256)
          ) {
            throw new Error("persisted vote recusal changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (input.tool === EXCLUDE_PENDING_VOTE_SOURCE) {
      if (input.prepared.action_code !== EXCLUDE_PENDING_VOTE_SOURCE) {
        throw new Error("prepared vote source-exclusion action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.voteSourceExclusionAction(input.input);
      if (
        input.prepared.target_type !== "vote" ||
        targetId !== action.voteId ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared vote source-exclusion stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageVoteSourceExclusionLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== EXCLUDE_PENDING_VOTE_SOURCE ||
            staged.stageId !== stageId ||
            staged.targetType !== "vote" ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256)
          ) {
            throw new Error("persisted vote source exclusion changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (input.tool === CANCEL_VOTE) {
      if (input.prepared.action_code !== CANCEL_VOTE) {
        throw new Error("prepared vote cancellation action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.voteCancellationAction(input.input);
      if (
        input.prepared.target_type !== "vote" ||
        targetId !== action.voteId ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared vote cancellation stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageVoteCancellationLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          const packageChanged =
            staged.packageSha256 === null || packageSha256 === null
              ? staged.packageSha256 !== packageSha256
              : !safeHashEqual(staged.packageSha256, packageSha256);
          if (
            staged.actionCode !== CANCEL_VOTE ||
            staged.stageId !== stageId ||
            staged.targetType !== "vote" ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            packageChanged
          ) {
            throw new Error("persisted vote cancellation changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (input.tool === CLOSE_VOTE) {
      if (input.prepared.action_code !== CLOSE_VOTE) {
        throw new Error("prepared vote close action code changed before persistence");
      }
      const material = this.voteCloseMaterial.get(input.prepared);
      if (!material) {
        throw new Error("prepared vote close material is unavailable");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      const action = this.voteCloseAction(input.input);
      if (
        input.prepared.target_type !== "vote" ||
        targetId !== action.voteId ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared vote close stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      try {
        await withRequestTransaction(
          this.pool,
          requestContext(input.principal),
          async (client) => {
            const staged = await stageVoteCloseLifecycleActionInTransaction(client, {
              action,
              material,
              stage: {
                stageId,
                inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
                nonce: secureBytes(this.entropy, 32),
                confirmationCode: input.prepared.confirmation_code,
                accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
                exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
                originalArguments: input.input,
                clientCapabilities: input.client_capabilities,
                embeddedForm: input.embedded_form,
                embeddedResult: input.embedded_result,
                requestStateBytes: Buffer.from(input.request_state, "utf8"),
                preparedRequestId: input.prepared_request_id,
                auditEventIds: {
                  stageReplaced: UuidV7Schema.parse(this.newId()),
                  stageCreated: UuidV7Schema.parse(this.newId()),
                  elicitationSent: UuidV7Schema.parse(this.newId())
                }
              }
            });
            if (
              staged.actionCode !== CLOSE_VOTE ||
              staged.stageId !== stageId ||
              staged.targetType !== "vote" ||
              staged.targetId !== targetId ||
              staged.boardId !== boardId ||
              !safeHashEqual(
                staged.payloadSha256,
                canonicalSha256(input.prepared.canonical_payload)
              ) ||
              staged.packageSha256 === null ||
              !safeHashEqual(staged.packageSha256, packageSha256)
            ) {
              throw new Error("persisted vote close changed after presentation");
            }
          },
          this.transaction
        );
      } finally {
        this.voteCloseMaterial.delete(input.prepared);
      }
      return;
    }
    if (isMinutesLifecycleTool(input.tool)) {
      if (input.prepared.action_code !== input.tool) {
        throw new Error("prepared minutes action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      if (
        input.prepared.target_type !== "minutes" ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared minutes publication stage has an invalid protected shape");
      }
      const action = this.minutesLifecycleAction(input.tool, input.input);
      if (action.minutesId !== targetId) {
        throw new Error("prepared minutes publication target changed");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageMinutesLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== input.tool ||
            staged.stageId !== stageId ||
            staged.targetId !== targetId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256) ||
            staged.boardId !== boardId
          ) {
            throw new Error("persisted minutes action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (input.tool === CREATE_TASK) {
      if (input.prepared.action_code !== CREATE_TASK) {
        throw new Error("prepared task creation code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      if (
        input.prepared.target_type !== "task" ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared task creation has an invalid protected shape");
      }
      const action = this.taskCreationAction(input.input);
      if (action.taskId !== targetId || action.boardId !== boardId) {
        throw new Error("prepared task creation target changed");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageTaskCreationInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== CREATE_TASK ||
            staged.stageId !== stageId ||
            staged.targetId !== targetId ||
            staged.boardId !== boardId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256)
          ) {
            throw new Error("persisted task creation changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (isTaskLifecycleTool(input.tool)) {
      if (input.prepared.action_code !== input.tool) {
        throw new Error("prepared task action code changed before persistence");
      }
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const boardId = UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      const packageSha256 = input.prepared.package_sha256;
      if (
        input.prepared.target_type !== "task" ||
        packageSha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared task stage has an invalid protected shape");
      }
      const action = this.taskLifecycleAction(input.tool, input.input);
      if (action.taskId !== targetId) {
        throw new Error("prepared task target changed");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageTaskLifecycleActionInTransaction(client, {
            action,
            stage: {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.actionCode !== input.tool ||
            staged.stageId !== stageId ||
            staged.targetId !== targetId ||
            !safeHashEqual(
              staged.payloadSha256,
              canonicalSha256(input.prepared.canonical_payload)
            ) ||
            staged.packageSha256 === null ||
            !safeHashEqual(staged.packageSha256, packageSha256) ||
            staged.boardId !== boardId
          ) {
            throw new Error("persisted task action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (
      input.tool === CONFIRM_ENROLLMENT_ACTIVATION &&
      input.prepared.action_code === CONFIRM_ENROLLMENT_ACTIVATION
    ) {
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      if (
        input.prepared.board_id !== null ||
        input.prepared.target_type !== "member" ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared enrollment activation stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (client) =>
          stageActionInTransaction(
            client,
            {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              boardId: null,
              actingForMemberId: null,
              actionCode: CONFIRM_ENROLLMENT_ACTIVATION,
              targetType: "member",
              targetId,
              canonicalSchema: "boardagent.enrollment-activation.v1",
              canonicalPayload: input.prepared.canonical_payload,
              packageSha256: null,
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalName: CONFIRM_ENROLLMENT_ACTIVATION,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            },
            async (requestClient) => {
              const current = await prepareEnrollmentActivationInTransaction(
                requestClient,
                input.input
              );
              if (
                current.memberId !== targetId ||
                !safeHashEqual(
                  current.payloadSha256,
                  canonicalSha256(input.prepared.canonical_payload)
                )
              ) {
                throw new EnrollmentActivationAdministrationError(
                  "enrollment_activation_unavailable",
                  "prepared enrollment activation changed before persistence"
                );
              }
            }
          ),
        this.transaction
      );
      return;
    }
    if (input.tool === MANAGE_MEMBER && input.prepared.action_code === MANAGE_MEMBER) {
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const lifecycle = isMemberLifecycleInput(input.input);
      const boardId =
        lifecycle && input.prepared.board_id === null
          ? null
          : UuidV7Schema.parse(input.prepared.board_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      if (
        input.prepared.target_type !== "member" ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared member invitation stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (client) =>
          stageActionInTransaction(
            client,
            {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              boardId,
              actingForMemberId: null,
              actionCode: MANAGE_MEMBER,
              targetType: "member",
              targetId,
              canonicalSchema: lifecycle
                ? "boardagent.member-lifecycle.v1"
                : "boardagent.member-invite.v1",
              canonicalPayload: input.prepared.canonical_payload,
              packageSha256: null,
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalName: MANAGE_MEMBER,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            },
            async (requestClient) => {
              const current = lifecycle
                ? await prepareMemberLifecycleInTransaction(requestClient, input.input)
                : await prepareMemberInviteInTransaction(requestClient, input.input);
              if (
                current.memberId !== targetId ||
                current.boardId !== boardId ||
                !safeHashEqual(
                  current.payloadSha256,
                  canonicalSha256(input.prepared.canonical_payload)
                )
              ) {
                throw new MemberAdministrationError(
                  "member_invite_unavailable",
                  "prepared member invitation changed before persistence"
                );
              }
            }
          ),
        this.transaction
      );
      return;
    }
    if (input.tool === REISSUE_ACTIVATION && input.prepared.action_code === REISSUE_ACTIVATION) {
      const stageId = UuidV7Schema.parse(input.prepared.stage_id);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      if (
        input.prepared.board_id !== null ||
        input.prepared.target_type !== "member" ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared activation restart stage has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (client) =>
          stageActionInTransaction(
            client,
            {
              stageId,
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              boardId: null,
              actingForMemberId: null,
              actionCode: REISSUE_ACTIVATION,
              targetType: "member",
              targetId,
              canonicalSchema: "boardagent.activation-restart.v1",
              canonicalPayload: input.prepared.canonical_payload,
              packageSha256: null,
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalName: REISSUE_ACTIVATION,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            },
            async (requestClient) => {
              const current = await prepareActivationRestartInTransaction(
                requestClient,
                input.input
              );
              if (
                current.memberId !== targetId ||
                !safeHashEqual(
                  current.payloadSha256,
                  canonicalSha256(input.prepared.canonical_payload)
                )
              ) {
                throw new EnrollmentAdministrationError(
                  "activation_restart_unavailable",
                  "prepared activation restart changed before persistence"
                );
              }
            }
          ),
        this.transaction
      );
      return;
    }
    if (input.tool !== ISSUE_ENROLLMENT || input.prepared.action_code !== ISSUE_ENROLLMENT) {
      throw new Error(`confirmed surface action is not implemented yet: ${input.tool}`);
    }
    const stageId = UuidV7Schema.parse(input.prepared.stage_id);
    const targetId = UuidV7Schema.parse(input.prepared.target_id);
    if (
      input.prepared.board_id !== null ||
      input.prepared.target_type !== "member" ||
      input.prepared.package_sha256 !== null ||
      !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
    ) {
      throw new Error("prepared enrollment stage has an invalid protected shape");
    }
    Rfc3339UtcSchema.parse(input.prepared.expires_at);
    await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        stageActionInTransaction(
          client,
          {
            stageId,
            inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
            boardId: null,
            actingForMemberId: null,
            actionCode: ISSUE_ENROLLMENT,
            targetType: "member",
            targetId,
            canonicalSchema: "boardagent.enrollment-issuance.v1",
            canonicalPayload: input.prepared.canonical_payload,
            packageSha256: null,
            nonce: secureBytes(this.entropy, 32),
            confirmationCode: input.prepared.confirmation_code,
            accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            originalName: ISSUE_ENROLLMENT,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            embeddedForm: input.embedded_form,
            embeddedResult: input.embedded_result,
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            preparedRequestId: input.prepared_request_id,
            auditEventIds: {
              stageReplaced: UuidV7Schema.parse(this.newId()),
              stageCreated: UuidV7Schema.parse(this.newId()),
              elicitationSent: UuidV7Schema.parse(this.newId())
            }
          },
          async (requestClient) => {
            const current = await prepareEnrollmentIssuanceInTransaction(
              requestClient,
              input.input
            );
            if (
              current.memberId !== targetId ||
              !safeHashEqual(
                current.payloadSha256,
                canonicalSha256(input.prepared.canonical_payload)
              )
            ) {
              throw new EnrollmentAdministrationError(
                "enrollment_issuance_unavailable",
                "prepared enrollment issuance changed before persistence"
              );
            }
          }
        ),
      this.transaction
    );
  }

  public async resolveHumanAction(input: ResolveHumanActionInput): Promise<HumanActionResolution> {
    if (isAdministrativeAuthorityTool(input.tool))
      return this.resolveAdministrativeAuthority(input, input.tool);
    if (this.controlPlane.handlesHumanTool(input.tool)) {
      return this.controlPlane.resolveHumanAction(input);
    }
    if (
      input.tool === MANAGE_RECUSAL &&
      (isNamedRecusal(input.input, "question") ||
        isNamedRecusal(input.input, "meeting") ||
        isNamedRecusal(input.input, "minutes"))
    ) {
      return this.resolveRecordRecusal(input);
    }
    if (input.tool === MANAGE_RECUSAL && isNamedRecusal(input.input, "board")) {
      return this.resolveBoardRecusal(input);
    }
    if (
      isDocumentLifecycleTool(input.tool) ||
      (input.tool === MANAGE_RECUSAL && isNamedRecusal(input.input, "document"))
    ) {
      return this.resolveDocumentLifecycle(input, input.tool);
    }
    if (isMeetingLifecycleTool(input.tool)) {
      return this.resolveMeetingLifecycle(input, input.tool);
    }
    if (isTranscriptLifecycleTool(input.tool)) {
      return this.resolveTranscriptLifecycle(input, input.tool);
    }
    if (isBallotLifecycleTool(input.tool)) {
      return this.resolveBallotLifecycle(input, input.tool);
    }
    if (input.tool === CREATE_VOTE) {
      return this.resolveVoteCreation(input);
    }
    if (input.tool === REPLACE_OPEN_VOTE) {
      return this.resolveVoteReplacement(input);
    }
    if (input.tool === AMEND_RESOLUTION_TEXT) {
      return this.resolveVoteResolutionAmendment(input);
    }
    if (input.tool === EXTEND_VOTE_DEADLINE) {
      return this.resolveVoteDeadlineExtension(input);
    }
    if (input.tool === MANAGE_RECUSAL) {
      return this.resolveVoteRecusal(input);
    }
    if (input.tool === EXCLUDE_PENDING_VOTE_SOURCE) {
      return this.resolveVoteSourceExclusion(input);
    }
    if (input.tool === CANCEL_VOTE) {
      return this.resolveVoteCancellation(input);
    }
    if (input.tool === CLOSE_VOTE) {
      return this.resolveVoteClose(input);
    }
    if (isMinutesLifecycleTool(input.tool)) {
      return this.resolveMinutesLifecycle(input, input.tool);
    }
    if (isTaskLifecycleTool(input.tool)) {
      return this.resolveTaskLifecycle(input, input.tool);
    }
    if (input.tool === CREATE_TASK) {
      return this.resolveTaskCreation(input);
    }
    if (input.tool === CONFIRM_ENROLLMENT_ACTIVATION) {
      return this.resolveEnrollmentActivation(input);
    }
    if (input.tool === MANAGE_MEMBER) {
      return isMemberLifecycleInput(input.input)
        ? this.resolveMemberLifecycle(input)
        : this.resolveMemberInvite(input);
    }
    if (input.tool === REISSUE_ACTIVATION) return this.resolveActivationRestart(input);
    if (input.tool !== ISSUE_ENROLLMENT) {
      throw new Error(`confirmed surface action is not implemented yet: ${input.tool}`);
    }
    const stageId = UuidV7Schema.parse(input.stage_id);
    const unavailablePayloadSha256 = canonicalSha256({
      schemaVersion: ENROLLMENT_UNAVAILABLE_BINDING_SCHEMA,
      stageId
    });
    const consentRecordId = UuidV7Schema.parse(this.newId());
    const consentRecordedEventId = UuidV7Schema.parse(this.newId());
    const consentRejectedEventId = UuidV7Schema.parse(this.newId());
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) => {
        let current: PreparedEnrollmentIssuance | undefined;
        return confirmStagedActionInTransaction(
          client,
          {
            stageId,
            consentRecordId,
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: consentRecordedEventId,
              consentRejected: consentRejectedEventId
            }
          },
          async (requestClient) => {
            try {
              current = await prepareEnrollmentIssuanceInTransaction(requestClient, input.input);
              return { payloadSha256: current.payloadSha256, packageSha256: null };
            } catch (error) {
              if (
                error instanceof EnrollmentAdministrationError &&
                error.code === "enrollment_issuance_unavailable"
              ) {
                return { payloadSha256: unavailablePayloadSha256, packageSha256: null };
              }
              throw error;
            }
          },
          async (requestClient, confirmedConsentRecordId) => {
            if (!current) throw new Error("confirmed enrollment binding is unavailable");
            const oneTimeToken = secureBytes(this.entropy, 32).toString("base64url");
            const issued = await issueEnrollmentInTransaction(requestClient, {
              originalArguments: input.input,
              expectedPayloadSha256: current.payloadSha256,
              invitationId: UuidV7Schema.parse(this.newId()),
              invitationTokenSha256: sha256Hex(oneTimeToken),
              idempotencyRecordId: UuidV7Schema.parse(this.newId()),
              consentRecordId: confirmedConsentRecordId,
              auditEventId: UuidV7Schema.parse(this.newId())
            });
            if (issued.replayed) {
              return {
                value: result(ISSUE_ENROLLMENT, "already_applied", issued.invitationId, {
                  schema_version: "boardagent.enrollment-issued.v1",
                  invitation_id: issued.invitationId,
                  member_id: issued.memberId,
                  expires_at: issued.expiresAt,
                  enrollment_link: null,
                  replayed: true,
                  secret_once: true,
                  instruction:
                    "The original one-time link is deliberately not replayed; revoke it and confirm a new issuance if the secret was lost."
                }),
                auditEvents: []
              };
            }
            return {
              value: result(ISSUE_ENROLLMENT, "accepted", issued.invitationId, {
                schema_version: "boardagent.enrollment-issued.v1",
                invitation_id: issued.invitationId,
                member_id: issued.memberId,
                expires_at: issued.expiresAt,
                handoff_method:
                  (input.input as { handoff_method?: JsonValue }).handoff_method ?? null,
                enrollment_link: invitationLink(input.principal.serviceOrigin, oneTimeToken),
                replayed: false,
                secret_once: true,
                instruction:
                  "Show or encode this link now. BoardAgent stores no recoverable copy; revoke and reissue if it is lost."
              }),
              auditEvents: issued.auditEvent === null ? [] : [issued.auditEvent]
            };
          }
        );
      },
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: resolution.value };
  }

  /**
   * Commit half of `reissue_activation`: on the issuer's confirmation the stale challenge
   * is revoked and a one-use ten-minute restart link is minted. The raw token exists only
   * in this response; the database keeps its hash.
   */
  private async resolveActivationRestart(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const stageId = UuidV7Schema.parse(input.stage_id);
    const unavailablePayloadSha256 = canonicalSha256({
      schemaVersion: ENROLLMENT_UNAVAILABLE_BINDING_SCHEMA,
      stageId
    });
    const consentRecordId = UuidV7Schema.parse(this.newId());
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) => {
        let current: PreparedActivationRestart | undefined;
        return confirmStagedActionInTransaction(
          client,
          {
            stageId,
            consentRecordId,
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          },
          async (requestClient) => {
            try {
              current = await prepareActivationRestartInTransaction(requestClient, input.input);
              return { payloadSha256: current.payloadSha256, packageSha256: null };
            } catch (error) {
              if (
                error instanceof EnrollmentAdministrationError &&
                error.code === "activation_restart_unavailable"
              ) {
                return { payloadSha256: unavailablePayloadSha256, packageSha256: null };
              }
              throw error;
            }
          },
          async (requestClient, confirmedConsentRecordId) => {
            if (!current) throw new Error("confirmed activation restart binding is unavailable");
            const oneTimeToken = secureBytes(this.entropy, 32).toString("base64url");
            const issued = await issueActivationRestartInTransaction(requestClient, {
              originalArguments: input.input,
              expectedPayloadSha256: current.payloadSha256,
              grantId: UuidV7Schema.parse(this.newId()),
              tokenSha256: sha256Hex(oneTimeToken),
              consentRecordId: confirmedConsentRecordId,
              auditEventId: UuidV7Schema.parse(this.newId())
            });
            return {
              value: result(REISSUE_ACTIVATION, "accepted", issued.grantId, {
                schema_version: "boardagent.activation-restart-issued.v1",
                grant_id: issued.grantId,
                member_id: current.memberId,
                stale_challenge_id: issued.staleChallengeId,
                expires_at: issued.expiresAt,
                restart_link: restartLink(input.principal.serviceOrigin, oneTimeToken),
                secret_once: true,
                instruction:
                  "Hand this one-time link to the verified person now; it lasts ten minutes and BoardAgent stores no recoverable copy. They prove it is them with their existing passkey and then receive a fresh activation code for you to confirm."
              }),
              auditEvents: issued.auditEvent === null ? [] : [issued.auditEvent]
            };
          }
        );
      },
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: resolution.value };
  }

  private async resolveRecordRecusal(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.recordRecusalAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (c) =>
        confirmRecordRecusalInTransaction(c, {
          action,
          newId: this.newId,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: this.newId(),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: { consentRecorded: this.newId(), consentRejected: this.newId() }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
    const value = resolution.value;
    return {
      confirmed: true,
      result: result(MANAGE_RECUSAL, "accepted", value.exclusionId, {
        schema_version: "boardagent.record-recusal-result.v1",
        board_id: value.boardId,
        object_type: value.objectType,
        object_id: value.objectId,
        member_id: value.memberId,
        state: value.state,
        invalidated_stages: value.invalidatedStages,
        tombstones: value.tombstones
      })
    };
  }

  private async resolveBoardRecusal(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.boardRecusalAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (c) =>
        confirmBoardRecusalInTransaction(c, {
          action,
          newId: this.newId,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: this.newId(),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: { consentRecorded: this.newId(), consentRejected: this.newId() }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
    const value = resolution.value;
    return {
      confirmed: true,
      result: result(MANAGE_RECUSAL, "accepted", value.exclusionId, {
        schema_version: "boardagent.board-recusal-result.v1",
        board_id: value.boardId,
        member_id: value.memberId,
        state: value.state,
        invalidated_stages: value.invalidatedStages,
        tombstones: value.tombstones
      })
    };
  }

  private async resolveDocumentLifecycle(
    input: ResolveHumanActionInput,
    tool: DocumentLifecycleTool | typeof MANAGE_RECUSAL
  ): Promise<HumanActionResolution> {
    const action = this.documentLifecycleAction(tool, input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmDocumentLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.documentLifecycleResult(tool, resolution.value) };
  }

  private async resolveMeetingLifecycle(
    input: ResolveHumanActionInput,
    tool: MeetingLifecycleTool
  ): Promise<HumanActionResolution> {
    const action = this.meetingLifecycleAction(tool, input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmMeetingLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.meetingLifecycleResult(tool, resolution.value) };
  }

  private async resolveTranscriptLifecycle(
    input: ResolveHumanActionInput,
    tool: TranscriptLifecycleTool
  ): Promise<HumanActionResolution> {
    const action = this.transcriptLifecycleAction(tool, input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmTranscriptLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.transcriptLifecycleResult(tool, resolution.value) };
  }

  private async resolveBallotLifecycle(
    input: ResolveHumanActionInput,
    tool: BallotLifecycleTool
  ): Promise<HumanActionResolution> {
    const action = this.ballotLifecycleAction(tool, input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmBallotLifecycleActionInTransaction(client, {
          action,
          generatedIds: {
            recordId: UuidV7Schema.parse(this.newId()),
            supersessionDispositionId: UuidV7Schema.parse(this.newId()),
            supersessionAuditEventId: UuidV7Schema.parse(this.newId()),
            idempotencyRecordId: UuidV7Schema.parse(this.newId()),
            auditEventId: UuidV7Schema.parse(this.newId())
          },
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.ballotLifecycleResult(tool, resolution.value) };
  }

  private async resolveVoteSourceExclusion(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.voteSourceExclusionAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteSourceExclusionLifecycleActionInTransaction(client, {
          action,
          generatedIds: {
            dispositionId: UuidV7Schema.parse(this.newId()),
            idempotencyRecordId: UuidV7Schema.parse(this.newId()),
            auditEventId: UuidV7Schema.parse(this.newId())
          },
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return {
      confirmed: true,
      result: this.voteSourceExclusionResult(action, resolution.value)
    };
  }

  private async resolveVoteCreation(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.voteCreationAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteCreationLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.voteCreationResult(resolution.value) };
  }

  private async resolveVoteReplacement(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.voteReplacementAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteReplacementLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
    return {
      confirmed: true,
      result: this.voteReplacementResult(REPLACE_OPEN_VOTE, resolution.value)
    };
  }

  private async resolveVoteResolutionAmendment(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.voteResolutionAmendmentInput(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteResolutionAmendmentLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
    return {
      confirmed: true,
      result: this.voteReplacementResult(AMEND_RESOLUTION_TEXT, resolution.value)
    };
  }

  private async resolveVoteDeadlineExtension(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.voteDeadlineExtensionInput(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteDeadlineExtensionLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
    return {
      confirmed: true,
      result: this.voteReplacementResult(EXTEND_VOTE_DEADLINE, resolution.value)
    };
  }

  private async resolveVoteRecusal(input: ResolveHumanActionInput): Promise<HumanActionResolution> {
    const action = this.voteRecusalAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteRecusalLifecycleActionInTransaction(client, {
          action,
          newId: this.newId,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.voteRecusalResult(action, resolution.value) };
  }

  private async resolveVoteCancellation(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.voteCancellationAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteCancellationLifecycleActionInTransaction(client, {
          action,
          newId: this.newId,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.voteCancellationResult(resolution.value) };
  }

  private async resolveVoteClose(input: ResolveHumanActionInput): Promise<HumanActionResolution> {
    const signer = this.voteCertificateSigner;
    if (!signer) throw new Error("vote certificate signer is unavailable");
    const action = this.voteCloseAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmVoteCloseLifecycleActionInTransaction(client, {
          action,
          idempotencyRecordId: UuidV7Schema.parse(this.newId()),
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    const draft = resolution.value;
    const signed = await signer.signVoteCertificate({
      signingKeyId: draft.signingKeyId,
      signingKeyLocator: draft.signingKeyLocator,
      canonicalPayload: canonicalVoteCertificatePayload(draft.payload),
      payloadSha256: draft.payloadSha256
    });
    const finalized = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        finalizeVoteCloseInTransaction(client, {
          organizationId: input.principal.organizationId,
          voteId: draft.voteId,
          outcomeId: draft.outcomeId,
          certificateId: draft.certificateId,
          signatureBase64Url: signed.signatureBase64Url,
          certificateIssuedAuditEventId: UuidV7Schema.parse(this.newId()),
          voteClosedAuditEventId: UuidV7Schema.parse(this.newId())
        }),
      this.transaction
    );
    return {
      confirmed: true,
      result: result(
        CLOSE_VOTE,
        finalized.replayed ? "already_applied" : "accepted",
        finalized.certificateId,
        {
          schema_version: "boardagent.vote-close-result.v1",
          vote_id: finalized.voteId,
          outcome_id: finalized.outcomeId,
          certificate_id: finalized.certificateId,
          certificate_public_id: draft.payload.publicId,
          outcome: draft.payload.outcome,
          tally: draft.payload.tally,
          payload_sha256: finalized.payloadSha256,
          signing_key_id: draft.signingKeyId,
          state: finalized.state,
          closed_at: finalized.closedAt
        },
        `board://${draft.payload.boardId}/votes/${finalized.voteId}/certificates/${finalized.certificateId}`
      )
    };
  }

  private async resolveMinutesLifecycle(
    input: ResolveHumanActionInput,
    tool: MinutesLifecycleTool
  ): Promise<HumanActionResolution> {
    const action = this.minutesLifecycleAction(tool, input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmMinutesLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.minutesLifecycleResult(tool, resolution.value) };
  }

  private async resolveTaskLifecycle(
    input: ResolveHumanActionInput,
    tool: TaskLifecycleTool
  ): Promise<HumanActionResolution> {
    const action = this.taskLifecycleAction(tool, input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmTaskLifecycleActionInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.taskLifecycleResult(tool, resolution.value) };
  }

  private async resolveTaskCreation(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const action = this.taskCreationAction(input.input);
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) =>
        confirmTaskCreationInTransaction(client, {
          action,
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        }),
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: this.taskCreationResult(resolution.value) };
  }

  private async resolveAdministrativeAuthority(
    input: ResolveHumanActionInput,
    tool: AdministrativeAuthorityTool
  ): Promise<HumanActionResolution> {
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) => {
        let current: PreparedAdministrativeAuthority | undefined;
        return confirmStagedActionInTransaction(
          client,
          {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          },
          async (requestClient) => {
            current = await prepareAdministrativeAuthorityInTransaction(
              requestClient,
              input.input,
              tool
            );
            return { payloadSha256: current.payloadSha256, packageSha256: null };
          },
          async (requestClient, consentRecordId) => {
            if (!current) throw new Error("administrative preparation is unavailable");
            const plan = await planAdministrativeAuthorityInTransaction(
              requestClient,
              current,
              consentRecordId,
              this.newId
            );
            return {
              value: result(tool, "accepted", plan.snapshot.recordId, {
                schema_version: "boardagent.administrative-change.v1",
                operation: plan.snapshot.operation,
                record_type: plan.snapshot.recordType,
                record_id: plan.snapshot.recordId,
                record_version: plan.snapshot.recordVersion,
                change_id: plan.changeId,
                state: plan.snapshot.after["state"] ?? "revoked",
                before: plan.snapshot.before,
                after: plan.snapshot.after,
                affected_member_ids: plan.snapshot.affectedMemberIds,
                effective_powers: plan.snapshot.memberChanges.map((member) => ({
                  member_id: member.memberId,
                  company_administrator: member.adminAfter,
                  ...(plan.snapshot.boardId === null
                    ? {}
                    : {
                        board_id: plan.snapshot.boardId,
                        manage_ordinary_voting_directors: plan.snapshot.operation === "grant"
                      })
                })),
                reconnect_required: plan.snapshot.affectedMemberIds.some(
                  (memberId) => memberId === input.principal.memberId
                )
              }),
              auditEvents: [plan.auditEvent],
              finalizeAfterAudit: async (finalClient) =>
                finalizeAdministrativeAuthorityInTransaction(finalClient, plan)
            };
          }
        );
      },
      this.transaction
    );
    return resolution.confirmed
      ? { confirmed: true, result: resolution.value }
      : { confirmed: false, reason: resolution.reason };
  }

  private async resolveMemberLifecycle(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) => {
        let current: PreparedMemberLifecycle | undefined;
        return confirmStagedActionInTransaction(
          client,
          {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          },
          async (requestClient) => {
            current = await prepareMemberLifecycleInTransaction(requestClient, input.input);
            return { payloadSha256: current.payloadSha256, packageSha256: null };
          },
          async (requestClient, consentRecordId) => {
            if (!current) throw new Error("member lifecycle preparation is unavailable");
            const plan = await planMemberLifecycleInTransaction(
              requestClient,
              current,
              consentRecordId,
              this.newId
            );
            return {
              value: result(MANAGE_MEMBER, "accepted", plan.memberId, {
                schema_version: "boardagent.member-changed.v1",
                operation: plan.operation,
                member_id: plan.memberId,
                board_id: plan.boardId,
                member: plan.snapshot.memberAfter,
                seats: plan.snapshot.seatsAfter,
                connections_revoked: true
              }),
              auditEvents: [plan.auditEvent],
              finalizeAfterAudit: async (finalClient) =>
                finalizeMemberLifecycleInTransaction(finalClient, plan)
            };
          }
        );
      },
      this.transaction
    );
    return resolution.confirmed
      ? { confirmed: true, result: resolution.value }
      : { confirmed: false, reason: resolution.reason };
  }

  private async resolveMemberInvite(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const stageId = UuidV7Schema.parse(input.stage_id);
    const unavailablePayloadSha256 = canonicalSha256({
      schemaVersion: MEMBER_UNAVAILABLE_BINDING_SCHEMA,
      stageId
    });
    const consentRecordId = UuidV7Schema.parse(this.newId());
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) => {
        let current: PreparedMemberInvite | undefined;
        return confirmStagedActionInTransaction(
          client,
          {
            stageId,
            consentRecordId,
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          },
          async (requestClient) => {
            try {
              current = await prepareMemberInviteInTransaction(requestClient, input.input);
              return { payloadSha256: current.payloadSha256, packageSha256: null };
            } catch (error) {
              if (
                error instanceof MemberAdministrationError &&
                error.code === "member_invite_unavailable"
              ) {
                return { payloadSha256: unavailablePayloadSha256, packageSha256: null };
              }
              throw error;
            }
          },
          async (requestClient, confirmedConsentRecordId) => {
            if (!current) throw new Error("confirmed member invitation binding is unavailable");
            const plan = await planMemberInviteInTransaction(requestClient, {
              originalArguments: input.input,
              expectedPayloadSha256: current.payloadSha256,
              consentRecordId: confirmedConsentRecordId,
              idempotencyRecordId: UuidV7Schema.parse(this.newId()),
              membershipId: UuidV7Schema.parse(this.newId()),
              membershipVersionId: UuidV7Schema.parse(this.newId()),
              auditEventId: UuidV7Schema.parse(this.newId())
            });
            return {
              value: result(MANAGE_MEMBER, "accepted", plan.memberId, {
                schema_version: "boardagent.member-changed.v1",
                operation: "invite",
                member_id: plan.memberId,
                membership_id: plan.membershipId,
                board_id: plan.boardId,
                state: "invited",
                next_action: ISSUE_ENROLLMENT
              }),
              auditEvents: [plan.auditEvent],
              finalizeAfterAudit: async (finalClient) => {
                const finalized = await finalizeMemberInviteInTransaction(finalClient, plan);
                if (finalized.replayed) {
                  throw new Error("fresh member invitation unexpectedly resolved as a replay");
                }
              }
            };
          }
        );
      },
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: resolution.value };
  }

  private async resolveEnrollmentActivation(
    input: ResolveHumanActionInput
  ): Promise<HumanActionResolution> {
    const stageId = UuidV7Schema.parse(input.stage_id);
    const unavailablePayloadSha256 = canonicalSha256({
      schemaVersion: ACTIVATION_UNAVAILABLE_BINDING_SCHEMA,
      stageId
    });
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      (client) => {
        let current: PreparedEnrollmentActivation | undefined;
        return confirmStagedActionInTransaction(
          client,
          {
            stageId,
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          },
          async (requestClient) => {
            try {
              current = await prepareEnrollmentActivationInTransaction(requestClient, input.input);
              return { payloadSha256: current.payloadSha256, packageSha256: null };
            } catch (error) {
              if (
                error instanceof EnrollmentActivationAdministrationError &&
                error.code === "enrollment_activation_unavailable"
              ) {
                return { payloadSha256: unavailablePayloadSha256, packageSha256: null };
              }
              throw error;
            }
          },
          async (requestClient, consentRecordId) => {
            if (!current) throw new Error("confirmed enrollment activation is unavailable");
            const plan = await planEnrollmentActivationInTransaction(requestClient, {
              originalArguments: input.input,
              expectedPayloadSha256: current.payloadSha256,
              consentRecordId,
              idempotencyRecordId: UuidV7Schema.parse(this.newId()),
              auditEventId: UuidV7Schema.parse(this.newId()),
              feedIds: current.seats.map(({ boardId }) => ({
                boardId,
                feedId: UuidV7Schema.parse(this.newId())
              }))
            });
            const activationData: JsonValue =
              plan.outcome === "activated"
                ? {
                    schema_version: "boardagent.enrollment-activation-result.v1",
                    activated: true,
                    member_id: plan.memberId,
                    challenge_id: plan.challengeId,
                    challenge_state: plan.challengeState,
                    onboarding_tasks_created: plan.feedEntries.length,
                    next_action: plan.recovery ? "fresh_sign_in" : "complete_onboarding"
                  }
                : {
                    schema_version: "boardagent.enrollment-activation-result.v1",
                    activated: false,
                    member_id: plan.memberId,
                    challenge_id: plan.challengeId,
                    reason: "code_mismatch",
                    challenge_state: plan.challengeState,
                    attempt_count: plan.attemptCount,
                    attempts_remaining: Math.max(0, 20 - plan.attemptCount),
                    next_action:
                      plan.challengeState === "issued"
                        ? "verify_person_and_retry"
                        : "reissue_activation"
                  };
            return {
              value: result(
                CONFIRM_ENROLLMENT_ACTIVATION,
                "accepted",
                plan.memberId,
                activationData
              ),
              auditEvents: [plan.auditEvent],
              finalizeAfterAudit: async (finalClient) => {
                await finalizeEnrollmentActivationInTransaction(finalClient, plan);
              }
            };
          }
        );
      },
      this.transaction
    );
    if (!resolution.confirmed) {
      return { confirmed: false, reason: resolution.reason };
    }
    return { confirmed: true, result: resolution.value };
  }

  public readResource(principal: SurfacePrincipal, uri: URL): Promise<SurfaceResourceResult> {
    return this.reads.readResource(principal, uri);
  }
}
