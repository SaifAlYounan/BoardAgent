export type TransitionTable<S extends string> = Readonly<Record<S, readonly S[]>>;

export type InstanceState = "absent" | "active";
export const instanceTransitions: TransitionTable<InstanceState> = {
  absent: ["active"],
  active: []
};

export type MemberState =
  "invited" | "enrollment_pending" | "pending_activation" | "active" | "suspended" | "removed";
export const memberTransitions: TransitionTable<MemberState> = {
  invited: ["enrollment_pending", "removed"],
  enrollment_pending: ["pending_activation", "removed"],
  pending_activation: ["active", "removed"],
  active: ["suspended", "removed"],
  suspended: ["active", "removed"],
  removed: []
};

export type BoardState = "active" | "archived";
export const boardTransitions: TransitionTable<BoardState> = {
  active: ["archived"],
  archived: []
};

export type ConsumableState = "issued" | "consumed" | "expired" | "revoked";
export const consumableTransitions: TransitionTable<ConsumableState> = {
  issued: ["consumed", "expired", "revoked"],
  consumed: [],
  expired: [],
  revoked: []
};

export type RefreshFamilyState = "active" | "revoked" | "compromised" | "expired";
export const refreshFamilyTransitions: TransitionTable<RefreshFamilyState> = {
  active: ["revoked", "compromised", "expired"],
  revoked: [],
  compromised: [],
  expired: []
};

export type DocumentState = "active" | "archived" | "soft_deleted";
export const documentTransitions: TransitionTable<DocumentState> = {
  active: ["archived", "soft_deleted"],
  archived: ["soft_deleted"],
  soft_deleted: []
};

export type SubmissionState =
  "submitted" | "revision_requested" | "resubmitted" | "approved_to_draft" | "rejected";
export const submissionTransitions: TransitionTable<SubmissionState> = {
  submitted: ["revision_requested", "approved_to_draft", "rejected"],
  revision_requested: ["resubmitted", "rejected"],
  resubmitted: ["revision_requested", "approved_to_draft", "rejected"],
  approved_to_draft: [],
  rejected: []
};

export type ManagementQuestionState = "pending" | "overdue" | "answered";
export const managementQuestionTransitions: TransitionTable<ManagementQuestionState> = {
  pending: ["overdue", "answered"],
  overdue: ["answered"],
  answered: ["pending"]
};

export type MeetingState = "draft" | "called" | "completed" | "cancelled";
export const meetingTransitions: TransitionTable<MeetingState> = {
  draft: ["called", "cancelled"],
  called: ["called", "completed", "cancelled"],
  completed: [],
  cancelled: []
};

export type TranscriptState = "unverified" | "secretary_verified";
export const transcriptTransitions: TransitionTable<TranscriptState> = {
  unverified: ["secretary_verified"],
  secretary_verified: []
};

export type ChallengeState = "pending" | "accepted" | "rejected";
export const challengeTransitions: TransitionTable<ChallengeState> = {
  pending: ["accepted", "rejected"],
  accepted: [],
  rejected: []
};

export type MinutesState =
  "unpublished_draft" | "published_review" | "signature_ready" | "finalized" | "cancelled";
export const minutesTransitions: TransitionTable<MinutesState> = {
  unpublished_draft: ["published_review", "cancelled"],
  published_review: ["published_review", "signature_ready", "cancelled"],
  signature_ready: ["published_review", "finalized", "cancelled"],
  finalized: [],
  cancelled: []
};

export type ReviewItemState = "pending" | "accepted" | "rejected" | "withdrawn";
export const reviewItemTransitions: TransitionTable<ReviewItemState> = {
  pending: ["accepted", "rejected", "withdrawn"],
  accepted: [],
  rejected: [],
  withdrawn: []
};

export type TaskState =
  | "draft"
  | "open"
  | "in_progress"
  | "evidence_submitted"
  | "completed"
  | "cancelled"
  | "superseded";
export const taskTransitions: TransitionTable<TaskState> = {
  draft: ["open", "cancelled", "superseded"],
  open: ["in_progress", "evidence_submitted", "cancelled"],
  in_progress: ["open", "evidence_submitted", "cancelled"],
  evidence_submitted: ["open", "completed", "cancelled"],
  completed: [],
  cancelled: [],
  superseded: []
};

export type ResignRequirementState = "pending" | "resolved";
export const resignRequirementTransitions: TransitionTable<ResignRequirementState> = {
  pending: ["resolved"],
  resolved: []
};

export type VoteState =
  "draft" | "open" | "source_update_pending" | "closing" | "closed" | "superseded" | "cancelled";
export const voteTransitions: TransitionTable<VoteState> = {
  draft: ["open", "cancelled"],
  open: ["source_update_pending", "superseded", "closing", "cancelled"],
  source_update_pending: ["open", "superseded", "cancelled"],
  closing: ["closed"],
  closed: [],
  superseded: [],
  cancelled: []
};

export type ProxyGrantState = "active" | "revoked" | "expired" | "superseded";
export const proxyGrantTransitions: TransitionTable<ProxyGrantState> = {
  active: ["revoked", "expired", "superseded"],
  revoked: [],
  expired: [],
  superseded: []
};

export type ConsentStageState =
  "active" | "replaced" | "confirmed" | "rejected" | "expired" | "cancelled";
export const consentStageTransitions: TransitionTable<ConsentStageState> = {
  active: ["replaced", "confirmed", "rejected", "expired", "cancelled"],
  replaced: [],
  confirmed: [],
  rejected: [],
  expired: [],
  cancelled: []
};

export type WizardState = "active" | "ready_to_confirm" | "posted" | "expired" | "cancelled";
export const wizardTransitions: TransitionTable<WizardState> = {
  active: ["ready_to_confirm", "expired", "cancelled"],
  ready_to_confirm: ["posted", "expired", "cancelled"],
  posted: [],
  expired: [],
  cancelled: []
};

export type ProfileState = "draft" | "active" | "superseded";
export const profileTransitions: TransitionTable<ProfileState> = {
  draft: ["active"],
  active: ["superseded"],
  superseded: []
};
export const rulesetTransitions = profileTransitions;

export type ExportState =
  "staged" | "confirmed" | "queued" | "running" | "succeeded" | "failed" | "expired" | "deleted";
export const exportTransitions: TransitionTable<ExportState> = {
  staged: ["confirmed", "expired"],
  confirmed: ["queued", "expired"],
  queued: ["running", "failed", "expired"],
  running: ["succeeded", "failed"],
  succeeded: ["expired", "deleted"],
  failed: [],
  expired: ["deleted"],
  deleted: []
};

export type JobState = "queued" | "leased" | "retry" | "succeeded" | "dead" | "cancelled";
export const jobTransitions: TransitionTable<JobState> = {
  queued: ["leased", "cancelled"],
  leased: ["succeeded", "retry", "dead", "cancelled"],
  retry: ["leased", "dead", "cancelled"],
  succeeded: [],
  dead: [],
  cancelled: []
};

export function transitionAllowed<S extends string>(
  table: TransitionTable<S>,
  current: S,
  next: S
): boolean {
  return table[current].includes(next);
}

export function assertTransition<S extends string>(
  table: TransitionTable<S>,
  current: S,
  next: S
): void {
  if (!transitionAllowed(table, current, next)) {
    throw new Error(`invalid transition: ${current} -> ${next}`);
  }
}
