import type { PoolClient } from "pg";
import { z } from "zod";

import {
  DecisionPackageSchema,
  Rfc3339UtcSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  type DecisionPackage,
  type JsonValue
} from "@boardagent/contracts";
import {
  prepareVoteElectorate,
  replacementPlan,
  voteElectorateEvidenceHash,
  voteReplacementConsentHash,
  type DecisionPackageChangeClass,
  type PreparedVoteElectorate
} from "@boardagent/domain";

import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { RuleSelectionEvidenceError, loadRuleSelectionEvidence } from "./rule-selection.js";
import { readRequestContext } from "./request-context.js";
import {
  replaceVoteInTransaction,
  validateDecisionPackageComponentsInTransaction,
  type ReplaceVoteResult,
  type VoteBallotReplacementInput,
  type VoteFeedTombstoneInput,
  type VoteOpenDeliveryInput,
  type VoteProxyReplacementInput,
  type VoteSourceUpdateDispositionInput,
  type VoteStageReplacementInput
} from "./votes.js";

const CORE_COMPONENT_COUNT = 7;
const UNAVAILABLE_BINDING_SCHEMA = "boardagent.vote-replacement-unavailable.v1" as const;

export type VoteReplacementLifecycleTool =
  "replace_open_vote" | "amend_resolution_text" | "extend_vote_deadline";

const DeliverySchema = z
  .object({
    memberId: UuidV7Schema,
    noticeId: UuidV7Schema,
    feedId: UuidV7Schema,
    noticeAuditEventId: UuidV7Schema
  })
  .strict();

const StageDispositionSchema = z
  .object({ stageId: UuidV7Schema, auditEventId: UuidV7Schema })
  .strict();
const ProxyDispositionSchema = z
  .object({
    proxyGrantId: UuidV7Schema,
    proxyRevocationId: UuidV7Schema,
    auditEventId: UuidV7Schema
  })
  .strict();
const BallotDispositionSchema = z
  .object({
    ballotId: UuidV7Schema,
    ballotDispositionId: UuidV7Schema,
    auditEventId: UuidV7Schema
  })
  .strict();
const FeedTombstoneSchema = z
  .object({ removedFeedId: UuidV7Schema, tombstoneId: UuidV7Schema })
  .strict();
const SourceDispositionSchema = z
  .object({ causeId: UuidV7Schema, dispositionId: UuidV7Schema })
  .strict();

const VoteReplacementStageMaterialSchema = z
  .object({
    newResolutionVersionId: UuidV7Schema,
    decisionPackageId: UuidV7Schema,
    consentRecordId: UuidV7Schema,
    supersessionId: UuidV7Schema,
    idempotencyRecordId: UuidV7Schema,
    decisionPackageComponentIds: z.array(UuidV7Schema).min(CORE_COMPONENT_COUNT).max(10_007),
    questionDecisionLinkIds: z.array(UuidV7Schema).max(10_000),
    electorateEntryIds: z.array(UuidV7Schema).min(1).max(1_000),
    stageDispositions: z.array(StageDispositionSchema).max(10_000),
    proxyDispositions: z.array(ProxyDispositionSchema).max(1_000),
    ballotDispositions: z.array(BallotDispositionSchema).max(1_000),
    feedTombstones: z.array(FeedTombstoneSchema).max(10_000),
    sourceUpdateDispositions: z.array(SourceDispositionSchema).max(10_000),
    newVoteDeliveries: z.array(DeliverySchema).min(1).max(1_000),
    replacementDeliveries: z.array(DeliverySchema).min(1).max(1_000),
    revoteDeliveries: z.array(DeliverySchema).max(1_000),
    resolutionAmendedAuditEventId: UuidV7Schema.nullable(),
    voteSupersededAuditEventId: UuidV7Schema,
    voteOpenedAuditEventId: UuidV7Schema
  })
  .strict();

export type VoteReplacementStageMaterial = z.infer<typeof VoteReplacementStageMaterialSchema>;

export class VoteReplacementLifecycleError extends Error {
  public constructor(
    public readonly code:
      | "vote_replacement_unavailable"
      | "vote_replacement_invalid"
      | "vote_replacement_override_required",
    message: string
  ) {
    super(message);
    this.name = "VoteReplacementLifecycleError";
  }
}

export interface VoteReplacementLifecycleAction {
  readonly actionCode: VoteReplacementLifecycleTool;
  readonly oldVoteId: string;
  readonly newVoteId: string;
  readonly declaredChangedComponentClasses: readonly DecisionPackageChangeClass[];
  readonly newTitle: string;
  readonly newResolutionText: string;
  readonly components: DecisionPackage["components"];
  readonly approvalRuleId: string;
  readonly matterEvaluationId: string;
  readonly selectedRulesetRuleId: string;
  readonly overrideReason: string | null;
  readonly closeMode: "automatic" | "secretariat_confirmed";
  readonly deadlineAt: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

export interface PreparedVoteReplacementLifecycleAction {
  readonly actionCode: VoteReplacementLifecycleTool;
  readonly targetType: "vote";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.vote-replacement-consent.v1";
  readonly organizationId: string;
  readonly boardId: string;
  readonly oldVoteId: string;
  readonly newVoteId: string;
  readonly newTitle: string;
  readonly newResolutionText: string;
  readonly newResolutionSha256: string;
  readonly oldPackage: DecisionPackage;
  readonly oldPackageSha256: string;
  readonly decisionPackage: DecisionPackage;
  readonly packageSha256: string;
  readonly electorate: PreparedVoteElectorate;
  readonly changedComponentClasses: readonly DecisionPackageChangeClass[];
  readonly recipientMemberIds: readonly string[];
  readonly revoteMemberIds: readonly string[];
  readonly payloadSha256: string;
  readonly canonicalPayload: JsonValue;
  readonly reason: string;
}

export interface VoteReplacementLifecycleStageInput {
  readonly action: VoteReplacementLifecycleAction;
  readonly material: VoteReplacementStageMaterial;
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
    | "wizardDraftId"
  >;
}

export interface StagedVoteReplacementLifecycleAction extends StagedAction {
  readonly actionCode: VoteReplacementLifecycleTool;
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
}

export interface VoteReplacementLifecycleConfirmationInput {
  readonly action: VoteReplacementLifecycleAction;
  readonly confirmation: Omit<ConfirmStagedActionInput, "consentRecordId">;
}

export interface VoteResolutionAmendmentLifecycleInput {
  readonly voteId: string;
  readonly expectedResolutionVersionId: string;
  readonly resolutionText: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

export interface VoteDeadlineExtensionLifecycleInput {
  readonly voteId: string;
  readonly deadlineAt: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

interface ReplacementSurfaceRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_state: string;
  readonly vote_row_version: string;
  readonly vote_title: string;
  readonly resolution_version_id: string;
  readonly resolution_version: number;
  readonly resolution_text: string;
  readonly resolution_sha256: Buffer;
  readonly package_payload: Buffer;
  readonly package_sha256: Buffer;
  readonly actor_ready: boolean;
}

interface BoardRootRow {
  readonly organization_id: string;
  readonly state: string;
  readonly current_governance_profile_id: string | null;
  readonly current_ruleset_id: string | null;
  readonly actor_ready: boolean;
}

interface ApprovalRuleRow {
  readonly close_mode: string;
  readonly canonical_sha256: Buffer;
}

interface ElectorateRow {
  readonly member_id: string;
  readonly membership_version_id: string;
  readonly is_chair: boolean;
  readonly voting_weight: string;
  readonly authority_snapshot: unknown;
  readonly authority_snapshot_sha256: Buffer;
}

interface RecipientRow {
  readonly member_id: string;
  readonly entitlement_generation: string;
}

interface OldElectorateRow extends ElectorateRow {
  readonly eligibility_sha256: Buffer;
  readonly eligibility_snapshot: unknown;
}

interface ActiveStageRow {
  readonly id: string;
}

interface ActiveProxyRow {
  readonly id: string;
}

interface ActiveBallotRow {
  readonly id: string;
  readonly principal_member_id: string;
}

interface PendingFeedRow {
  readonly id: string;
  readonly member_id: string;
  readonly action_type: string;
}

interface SourceCauseRow {
  readonly cause_id: string;
}

interface PersistedMaterialRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly old_vote_id: string;
  readonly new_vote_id: string;
  readonly consent_record_id: string;
  readonly canonical_material: Buffer;
  readonly material_sha256: Buffer;
}

interface ReplacementSnapshot {
  readonly action: VoteReplacementLifecycleAction;
  readonly organizationId: string;
  readonly boardId: string;
  readonly oldPackage: DecisionPackage;
  readonly oldPackageSha256: string;
  readonly profileId: string;
  readonly profileSha256: string;
  readonly rulesetId: string;
  readonly rulesetSha256: string;
  readonly approvalRuleSha256: string;
  readonly evaluationResultSha256: string;
  readonly selectedRuleSha256: string;
  readonly electorateRows: readonly ElectorateRow[];
  readonly oldElectorateRows: readonly OldElectorateRow[];
  readonly recipientRows: readonly RecipientRow[];
  readonly activeStageIds: readonly string[];
  readonly activeProxyIds: readonly string[];
  readonly activeBallots: readonly ActiveBallotRow[];
  readonly pendingFeeds: readonly PendingFeedRow[];
  readonly sourceCauseIds: readonly string[];
  readonly revoteMemberIds: readonly string[];
}

interface DerivationSource {
  readonly row: ReplacementSurfaceRow;
  readonly oldPackage: DecisionPackage;
}

function unavailable(message = "vote replacement is unavailable"): never {
  throw new VoteReplacementLifecycleError("vote_replacement_unavailable", message);
}

function invalid(message: string): never {
  throw new VoteReplacementLifecycleError("vote_replacement_invalid", message);
}

async function readDerivationSource(
  client: PoolClient,
  voteIdInput: string
): Promise<DerivationSource> {
  const voteId = UuidV7Schema.parse(voteIdInput);
  const context = await readRequestContext(client);
  const result = await client.query<ReplacementSurfaceRow>(
    "select * from boardagent_lock_vote_replacement_surface($1)",
    [voteId]
  );
  const row = result.rows[0];
  if (
    !row ||
    result.rows.length !== 1 ||
    row.organization_id !== context.organizationId ||
    !["open", "source_update_pending"].includes(row.vote_state) ||
    !row.actor_ready
  ) {
    unavailable();
  }
  const visibility = await client.query<{ allowed: boolean }>(
    "select not boardagent_member_vote_recused($1,$2) as allowed",
    [voteId, context.memberId]
  );
  if (visibility.rows[0]?.allowed !== true) unavailable();
  let oldPackage: DecisionPackage;
  try {
    oldPackage = DecisionPackageSchema.parse(JSON.parse(row.package_payload.toString("utf8")));
  } catch {
    unavailable("source vote package failed persisted integrity validation");
  }
  if (
    oldPackage.voteId !== voteId ||
    oldPackage.resolutionVersionId !== row.resolution_version_id ||
    !safeHashEqual(oldPackage.resolutionSha256, row.resolution_sha256.toString("hex")) ||
    !safeHashEqual(canonicalSha256(oldPackage), row.package_sha256.toString("hex"))
  ) {
    unavailable("source vote package failed persisted integrity validation");
  }
  if (oldPackage.ruleOverride !== null) {
    throw new VoteReplacementLifecycleError(
      "vote_replacement_override_required",
      "this replacement requires a freshly confirmed rule override for the new vote"
    );
  }
  return { row, oldPackage };
}

async function deriveResolutionAmendmentAction(
  client: PoolClient,
  input: VoteResolutionAmendmentLifecycleInput,
  newVoteId: string
): Promise<VoteReplacementLifecycleAction> {
  const source = await readDerivationSource(client, input.voteId);
  if (source.row.resolution_version_id !== UuidV7Schema.parse(input.expectedResolutionVersionId)) {
    unavailable("the expected resolution version is no longer current");
  }
  return {
    actionCode: "amend_resolution_text",
    oldVoteId: source.oldPackage.voteId,
    newVoteId: UuidV7Schema.parse(newVoteId),
    declaredChangedComponentClasses: ["resolution"],
    newTitle: source.row.vote_title,
    newResolutionText: input.resolutionText,
    components: source.oldPackage.components,
    approvalRuleId: source.oldPackage.approvalRuleId,
    matterEvaluationId: source.oldPackage.matterEvaluationId,
    selectedRulesetRuleId: source.oldPackage.selectedRulesetRuleId,
    overrideReason: null,
    closeMode: source.oldPackage.closeMode,
    deadlineAt: source.oldPackage.deadlineAt,
    reason: input.reason,
    idempotencyKey: input.idempotencyKey
  };
}

async function deriveDeadlineExtensionAction(
  client: PoolClient,
  input: VoteDeadlineExtensionLifecycleInput,
  newVoteId: string
): Promise<VoteReplacementLifecycleAction> {
  const source = await readDerivationSource(client, input.voteId);
  const deadlineAt = Rfc3339UtcSchema.parse(input.deadlineAt);
  if (Date.parse(deadlineAt) <= Date.parse(source.oldPackage.deadlineAt)) {
    invalid("extended vote deadline must be strictly later than the current deadline");
  }
  return {
    actionCode: "extend_vote_deadline",
    oldVoteId: source.oldPackage.voteId,
    newVoteId: UuidV7Schema.parse(newVoteId),
    declaredChangedComponentClasses: ["deadline"],
    newTitle: source.row.vote_title,
    newResolutionText: source.row.resolution_text,
    components: source.oldPackage.components,
    approvalRuleId: source.oldPackage.approvalRuleId,
    matterEvaluationId: source.oldPackage.matterEvaluationId,
    selectedRulesetRuleId: source.oldPackage.selectedRulesetRuleId,
    overrideReason: null,
    closeMode: source.oldPackage.closeMode,
    deadlineAt,
    reason: input.reason,
    idempotencyKey: input.idempotencyKey
  };
}

function normalizedAction(input: VoteReplacementLifecycleAction): VoteReplacementLifecycleAction {
  const newTitle = canonicalText(input.newTitle);
  const newResolutionText = canonicalText(input.newResolutionText);
  const reason = canonicalText(input.reason);
  const overrideReason = input.overrideReason === null ? null : canonicalText(input.overrideReason);
  if (newTitle.length < 1 || newTitle.length > 512) {
    throw new RangeError("replacement vote title must contain 1 through 512 characters");
  }
  if (newResolutionText.length < 1 || Buffer.byteLength(newResolutionText, "utf8") > 1_048_576) {
    throw new RangeError("replacement resolution must contain 1 through 1048576 bytes");
  }
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("vote-replacement reason must contain 1 through 65536 characters");
  }
  if (input.idempotencyKey.length < 16 || input.idempotencyKey.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  const oldVoteId = UuidV7Schema.parse(input.oldVoteId);
  const newVoteId = UuidV7Schema.parse(input.newVoteId);
  if (oldVoteId === newVoteId) invalid("replacement requires a distinct new vote identifier");
  return {
    actionCode: z
      .enum(["replace_open_vote", "amend_resolution_text", "extend_vote_deadline"])
      .parse(input.actionCode),
    oldVoteId,
    newVoteId,
    declaredChangedComponentClasses: z
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
      .parse(input.declaredChangedComponentClasses),
    newTitle,
    newResolutionText,
    components: DecisionPackageSchema.shape.components.parse(input.components),
    approvalRuleId: UuidV7Schema.parse(input.approvalRuleId),
    matterEvaluationId: UuidV7Schema.parse(input.matterEvaluationId),
    selectedRulesetRuleId: UuidV7Schema.parse(input.selectedRulesetRuleId),
    overrideReason,
    closeMode: input.closeMode,
    deadlineAt: Rfc3339UtcSchema.parse(input.deadlineAt),
    reason,
    idempotencyKey: input.idempotencyKey
  };
}

async function readSnapshot(
  client: PoolClient,
  input: VoteReplacementLifecycleAction,
  excludeStageId?: string
): Promise<ReplacementSnapshot> {
  const action = normalizedAction(input);
  const context = await readRequestContext(client);
  const locked = await client.query<ReplacementSurfaceRow>(
    "select * from boardagent_lock_vote_replacement_surface($1)",
    [action.oldVoteId]
  );
  const source = locked.rows[0];
  if (
    !source ||
    locked.rows.length !== 1 ||
    source.organization_id !== context.organizationId ||
    !["open", "source_update_pending"].includes(source.vote_state) ||
    !source.actor_ready
  ) {
    unavailable();
  }
  const visibility = await client.query<{ allowed: boolean }>(
    "select not boardagent_member_vote_recused($1,$2) as allowed",
    [action.oldVoteId, context.memberId]
  );
  if (visibility.rows[0]?.allowed !== true) unavailable();
  const existingReplacement = await client.query<{ id: string }>(
    "select id from votes where id=$1",
    [action.newVoteId]
  );
  if (existingReplacement.rows.length !== 0) unavailable();

  let oldPackage: DecisionPackage;
  try {
    oldPackage = DecisionPackageSchema.parse(JSON.parse(source.package_payload.toString("utf8")));
  } catch {
    unavailable("source vote package failed persisted integrity validation");
  }
  const oldPackageSha256 = canonicalSha256(oldPackage);
  if (
    oldPackage.voteId !== action.oldVoteId ||
    oldPackage.resolutionVersionId !== source.resolution_version_id ||
    !safeHashEqual(oldPackage.resolutionSha256, source.resolution_sha256.toString("hex")) ||
    !safeHashEqual(oldPackageSha256, source.package_sha256.toString("hex"))
  ) {
    unavailable("source vote package failed persisted integrity validation");
  }

  const rootResult = await client.query<BoardRootRow>(
    "select * from boardagent_lock_board_root($1)",
    [source.board_id]
  );
  const root = rootResult.rows[0];
  if (
    !root ||
    rootResult.rows.length !== 1 ||
    root.organization_id !== context.organizationId ||
    root.state !== "active" ||
    !root.current_governance_profile_id ||
    !root.current_ruleset_id ||
    !root.actor_ready
  ) {
    unavailable();
  }
  let selection;
  try {
    selection = await loadRuleSelectionEvidence(client, {
      boardId: source.board_id,
      profileId: root.current_governance_profile_id,
      rulesetId: root.current_ruleset_id,
      approvalRuleId: action.approvalRuleId,
      evaluationId: action.matterEvaluationId,
      selectedRuleId: action.selectedRulesetRuleId
    });
  } catch (error) {
    if (error instanceof RuleSelectionEvidenceError) invalid(error.message);
    throw error;
  }
  if (selection.resultDetails.status !== "matched" || selection.row.recommended_rule_id === null) {
    invalid("replacement requires one unambiguous persisted matter evaluation");
  }
  if (
    selection.row.recommended_rule_id !== action.selectedRulesetRuleId ||
    action.overrideReason !== null
  ) {
    throw new VoteReplacementLifecycleError(
      "vote_replacement_override_required",
      "replacement with a nonrecommended rule requires a separately confirmed new override"
    );
  }
  const approval = await client.query<ApprovalRuleRow>(
    `select close_mode,canonical_sha256
       from approval_rules
      where id=$1 and organization_id=$2 and board_id=$3`,
    [action.approvalRuleId, context.organizationId, source.board_id]
  );
  const approvalRow = approval.rows[0];
  if (
    !approvalRow ||
    approval.rows.length !== 1 ||
    approvalRow.close_mode !== action.closeMode ||
    !safeHashEqual(
      approvalRow.canonical_sha256.toString("hex"),
      selection.template.approvalRuleSha256
    )
  ) {
    invalid("replacement close mode or approval rule is not permitted by the active profile");
  }
  await validateDecisionPackageComponentsInTransaction(
    client,
    context.organizationId,
    source.board_id,
    action.components
  );
  const nowResult = await client.query<{ now: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as now`
  );
  if (Date.parse(action.deadlineAt) <= Date.parse(nowResult.rows[0]?.now ?? "")) {
    invalid("replacement vote deadline must remain in the future through confirmation");
  }

  const electorate = await client.query<ElectorateRow>(
    "select * from boardagent_lock_replacement_electorate($1)",
    [action.oldVoteId]
  );
  const recipients = await client.query<RecipientRow>(
    "select * from boardagent_lock_replacement_recipients($1)",
    [action.oldVoteId]
  );
  if (
    electorate.rows.length < 1 ||
    electorate.rows.length > 1_000 ||
    recipients.rows.length < 1 ||
    recipients.rows.length > 1_000
  ) {
    invalid("replacement requires a bounded current electorate and recipient set");
  }
  const recipientIds = new Set(recipients.rows.map(({ member_id }) => member_id));
  if (
    recipientIds.size !== recipients.rows.length ||
    electorate.rows.some(({ member_id }) => !recipientIds.has(member_id))
  ) {
    invalid("replacement electorate is not covered by entitled recipients");
  }
  const oldElectorate = await client.query<OldElectorateRow>(
    `select member_id,membership_version_id,is_chair,voting_weight::text,
            eligibility_snapshot,eligibility_sha256,
            eligibility_snapshot as authority_snapshot,
            eligibility_sha256 as authority_snapshot_sha256
       from vote_electorate where vote_id=$1 order by member_id`,
    [action.oldVoteId]
  );
  if (oldElectorate.rows.length < 1) unavailable("source electorate evidence is unavailable");

  const stages = await client.query<ActiveStageRow>(
    `select id from action_stages
      where organization_id=$1 and board_id=$2 and target_type='vote' and target_id=$3
        and state='active' and ($4::uuid is null or id<>$4::uuid)
      order by id for update`,
    [context.organizationId, source.board_id, action.oldVoteId, excludeStageId ?? null]
  );
  const proxies = await client.query<ActiveProxyRow>(
    `select proxy.id
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.organization_id=$1 and proxy.board_id=$2 and proxy.vote_id=$3
        and revocation.id is null order by proxy.id`,
    [context.organizationId, source.board_id, action.oldVoteId]
  );
  const ballots = await client.query<ActiveBallotRow>(
    `select ballot.id,ballot.principal_member_id
       from ballots as ballot
       left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
      where ballot.organization_id=$1 and ballot.board_id=$2 and ballot.vote_id=$3
        and disposition.id is null order by ballot.id`,
    [context.organizationId, source.board_id, action.oldVoteId]
  );
  const feeds = await client.query<PendingFeedRow>(
    `select id,member_id,action_type
       from pending_action_feed
      where organization_id=$1 and board_id=$2 and object_type='vote' and object_id=$3
        and state='pending' order by id for update`,
    [context.organizationId, source.board_id, action.oldVoteId]
  );
  const causes = await client.query<SourceCauseRow>(
    "select cause_id from boardagent_lock_vote_source_causes($1)",
    [action.oldVoteId]
  );
  if (
    (source.vote_state === "source_update_pending" && causes.rows.length === 0) ||
    (source.vote_state === "open" && causes.rows.length !== 0)
  ) {
    unavailable("source-update state failed exact replacement preparation");
  }
  const eligible = new Set(electorate.rows.map(({ member_id }) => member_id));
  const revoteMemberIds = [
    ...new Set([
      ...ballots.rows.map(({ principal_member_id }) => principal_member_id),
      ...feeds.rows
        .filter(({ action_type }) => action_type === "revote_required")
        .map(({ member_id }) => member_id)
    ])
  ]
    .filter((memberId) => eligible.has(memberId))
    .toSorted();

  return {
    action,
    organizationId: context.organizationId,
    boardId: source.board_id,
    oldPackage,
    oldPackageSha256,
    profileId: selection.resultDetails.profile.id,
    profileSha256: selection.resultDetails.profile.canonicalSha256,
    rulesetId: selection.resultDetails.ruleset.id,
    rulesetSha256: selection.resultDetails.ruleset.canonicalSha256,
    approvalRuleSha256: approvalRow.canonical_sha256.toString("hex"),
    evaluationResultSha256: selection.row.evaluation_result_sha256.toString("hex"),
    selectedRuleSha256: selection.row.selected_rule_sha256.toString("hex"),
    electorateRows: electorate.rows,
    oldElectorateRows: oldElectorate.rows,
    recipientRows: recipients.rows,
    activeStageIds: stages.rows.map(({ id }) => id),
    activeProxyIds: proxies.rows.map(({ id }) => id),
    activeBallots: ballots.rows,
    pendingFeeds: feeds.rows,
    sourceCauseIds: causes.rows.map(({ cause_id }) => cause_id),
    revoteMemberIds
  };
}

function allocationIds(material: VoteReplacementStageMaterial): readonly string[] {
  return [
    material.newResolutionVersionId,
    material.decisionPackageId,
    material.consentRecordId,
    material.supersessionId,
    material.idempotencyRecordId,
    ...material.decisionPackageComponentIds,
    ...material.questionDecisionLinkIds,
    ...material.electorateEntryIds,
    ...material.stageDispositions.map(({ auditEventId }) => auditEventId),
    ...material.proxyDispositions.flatMap(({ proxyRevocationId, auditEventId }) => [
      proxyRevocationId,
      auditEventId
    ]),
    ...material.ballotDispositions.flatMap(({ ballotDispositionId, auditEventId }) => [
      ballotDispositionId,
      auditEventId
    ]),
    ...material.feedTombstones.map(({ tombstoneId }) => tombstoneId),
    ...material.sourceUpdateDispositions.map(({ dispositionId }) => dispositionId),
    ...material.newVoteDeliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
      noticeId,
      feedId,
      noticeAuditEventId
    ]),
    ...material.replacementDeliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
      noticeId,
      feedId,
      noticeAuditEventId
    ]),
    ...material.revoteDeliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
      noticeId,
      feedId,
      noticeAuditEventId
    ]),
    ...(material.resolutionAmendedAuditEventId ? [material.resolutionAmendedAuditEventId] : []),
    material.voteSupersededAuditEventId,
    material.voteOpenedAuditEventId
  ];
}

function allocateMaterial(
  snapshot: ReplacementSnapshot,
  newId: () => string
): VoteReplacementStageMaterial {
  const questionCount = snapshot.action.components.filter(
    ({ type }) => type === "question_cutoff"
  ).length;
  const delivery = (memberId: string): VoteOpenDeliveryInput => ({
    memberId,
    noticeId: newId(),
    feedId: newId(),
    noticeAuditEventId: newId()
  });
  return VoteReplacementStageMaterialSchema.parse({
    newResolutionVersionId: newId(),
    decisionPackageId: newId(),
    consentRecordId: newId(),
    supersessionId: newId(),
    idempotencyRecordId: newId(),
    decisionPackageComponentIds: Array.from(
      { length: CORE_COMPONENT_COUNT + snapshot.action.components.length },
      () => newId()
    ),
    questionDecisionLinkIds: Array.from({ length: questionCount }, () => newId()),
    electorateEntryIds: snapshot.electorateRows.map(() => newId()),
    stageDispositions: snapshot.activeStageIds.map((stageId) => ({
      stageId,
      auditEventId: newId()
    })),
    proxyDispositions: snapshot.activeProxyIds.map((proxyGrantId) => ({
      proxyGrantId,
      proxyRevocationId: newId(),
      auditEventId: newId()
    })),
    ballotDispositions: snapshot.activeBallots.map(({ id: ballotId }) => ({
      ballotId,
      ballotDispositionId: newId(),
      auditEventId: newId()
    })),
    feedTombstones: snapshot.pendingFeeds.map(({ id: removedFeedId }) => ({
      removedFeedId,
      tombstoneId: newId()
    })),
    sourceUpdateDispositions: snapshot.sourceCauseIds.map((causeId) => ({
      causeId,
      dispositionId: newId()
    })),
    newVoteDeliveries: snapshot.electorateRows.map(({ member_id }) => delivery(member_id)),
    replacementDeliveries: snapshot.recipientRows.map(({ member_id }) => delivery(member_id)),
    revoteDeliveries: snapshot.revoteMemberIds.map(delivery),
    resolutionAmendedAuditEventId:
      snapshot.action.actionCode === "amend_resolution_text" ? newId() : null,
    voteSupersededAuditEventId: newId(),
    voteOpenedAuditEventId: newId()
  });
}

function sameOrdered(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function checkedMaterial(
  snapshot: ReplacementSnapshot,
  input: VoteReplacementStageMaterial
): VoteReplacementStageMaterial {
  const material = VoteReplacementStageMaterialSchema.parse(input);
  const questionCount = snapshot.action.components.filter(
    ({ type }) => type === "question_cutoff"
  ).length;
  if (
    material.decisionPackageComponentIds.length !==
      CORE_COMPONENT_COUNT + snapshot.action.components.length ||
    material.questionDecisionLinkIds.length !== questionCount ||
    material.electorateEntryIds.length !== snapshot.electorateRows.length ||
    !sameOrdered(
      material.stageDispositions.map(({ stageId }) => stageId),
      snapshot.activeStageIds
    ) ||
    !sameOrdered(
      material.proxyDispositions.map(({ proxyGrantId }) => proxyGrantId),
      snapshot.activeProxyIds
    ) ||
    !sameOrdered(
      material.ballotDispositions.map(({ ballotId }) => ballotId),
      snapshot.activeBallots.map(({ id }) => id)
    ) ||
    !sameOrdered(
      material.feedTombstones.map(({ removedFeedId }) => removedFeedId),
      snapshot.pendingFeeds.map(({ id }) => id)
    ) ||
    !sameOrdered(
      material.sourceUpdateDispositions.map(({ causeId }) => causeId),
      snapshot.sourceCauseIds
    ) ||
    !sameOrdered(
      material.newVoteDeliveries.map(({ memberId }) => memberId),
      snapshot.electorateRows.map(({ member_id }) => member_id)
    ) ||
    !sameOrdered(
      material.replacementDeliveries.map(({ memberId }) => memberId),
      snapshot.recipientRows.map(({ member_id }) => member_id)
    ) ||
    !sameOrdered(
      material.revoteDeliveries.map(({ memberId }) => memberId),
      snapshot.revoteMemberIds
    )
  ) {
    throw new TypeError("vote replacement stage material does not cover exact current state");
  }
  const ids = [snapshot.action.oldVoteId, snapshot.action.newVoteId, ...allocationIds(material)];
  if (new Set(ids).size !== ids.length) {
    throw new TypeError("vote replacement generated IDs must be globally unique");
  }
  return material;
}

function buildPrepared(
  snapshot: ReplacementSnapshot,
  material: VoteReplacementStageMaterial
): PreparedVoteReplacementLifecycleAction {
  const electorate = prepareVoteElectorate({
    voteId: snapshot.action.newVoteId,
    entries: snapshot.electorateRows.map((row, index) => ({
      id: material.electorateEntryIds[index]!,
      memberId: row.member_id,
      membershipVersionId: row.membership_version_id,
      isChair: row.is_chair,
      votingWeight: BigInt(row.voting_weight),
      eligibilitySnapshot: JSON.parse(canonicalJson(row.authority_snapshot)) as JsonValue
    }))
  });
  if (
    electorate.entries.some(
      (entry, index) =>
        !safeHashEqual(
          entry.eligibilitySha256,
          snapshot.electorateRows[index]!.authority_snapshot_sha256.toString("hex")
        )
    )
  ) {
    invalid("replacement electorate failed its stored eligibility hash");
  }
  const oldEvidenceSha256 = voteElectorateEvidenceHash(
    snapshot.oldElectorateRows.map((row) => ({
      memberId: row.member_id,
      membershipVersionId: row.membership_version_id,
      isChair: row.is_chair,
      votingWeight: BigInt(row.voting_weight),
      eligibilitySnapshot: row.eligibility_snapshot as JsonValue,
      eligibilitySha256: row.eligibility_sha256.toString("hex")
    }))
  );
  const newEvidenceSha256 = voteElectorateEvidenceHash(electorate.entries);
  const resolutionSha256 = canonicalSha256({
    schemaVersion: "boardagent.resolution.v1",
    text: snapshot.action.newResolutionText
  });
  const decisionPackage = DecisionPackageSchema.parse({
    schemaVersion: "boardagent.decision-package.v1",
    voteId: snapshot.action.newVoteId,
    packageVersion: 1,
    resolutionVersionId: material.newResolutionVersionId,
    resolutionSha256,
    governanceProfileVersionId: snapshot.profileId,
    governanceProfileSha256: snapshot.profileSha256,
    rulesetVersionId: snapshot.rulesetId,
    rulesetSha256: snapshot.rulesetSha256,
    approvalRuleId: snapshot.action.approvalRuleId,
    approvalRuleSha256: snapshot.approvalRuleSha256,
    matterEvaluationId: snapshot.action.matterEvaluationId,
    matterEvaluationResultSha256: snapshot.evaluationResultSha256,
    selectedRulesetRuleId: snapshot.action.selectedRulesetRuleId,
    selectedRulesetRuleSha256: snapshot.selectedRuleSha256,
    ruleOverride: null,
    electorateSha256: electorate.electorateSha256,
    closeMode: snapshot.action.closeMode,
    deadlineAt: snapshot.action.deadlineAt,
    components: snapshot.action.components
  });
  const plan = replacementPlan(
    snapshot.oldPackage,
    decisionPackage,
    snapshot.revoteMemberIds,
    electorate.entries.map(({ memberId }) => memberId),
    !safeHashEqual(oldEvidenceSha256, newEvidenceSha256)
  );
  if (
    canonicalJson(plan.changedComponentClasses) !==
    canonicalJson(snapshot.action.declaredChangedComponentClasses)
  ) {
    invalid("declared replacement component classes do not match the exact package delta");
  }
  const packageSha256 = canonicalSha256(decisionPackage);
  const canonicalPayload = {
    schemaVersion: "boardagent.vote-replacement-consent.v1",
    oldVoteId: snapshot.action.oldVoteId,
    newVoteId: snapshot.action.newVoteId,
    newTitle: snapshot.action.newTitle,
    newResolutionVersionId: material.newResolutionVersionId,
    newResolutionSha256: resolutionSha256,
    decisionPackageId: material.decisionPackageId,
    newPackageSha256: packageSha256,
    reason: snapshot.action.reason
  } as const;
  const payloadSha256 = canonicalSha256(canonicalPayload);
  if (
    !safeHashEqual(
      payloadSha256,
      voteReplacementConsentHash({
        oldVoteId: snapshot.action.oldVoteId,
        newVoteId: snapshot.action.newVoteId,
        newTitle: snapshot.action.newTitle,
        newResolutionVersionId: material.newResolutionVersionId,
        newResolutionSha256: resolutionSha256,
        decisionPackageId: material.decisionPackageId,
        newPackageSha256: packageSha256,
        reason: snapshot.action.reason
      })
    )
  ) {
    throw new Error("vote replacement consent payload failed canonical self-check");
  }
  return {
    actionCode: snapshot.action.actionCode,
    targetType: "vote",
    targetId: snapshot.action.oldVoteId,
    canonicalSchema: "boardagent.vote-replacement-consent.v1",
    organizationId: snapshot.organizationId,
    boardId: snapshot.boardId,
    oldVoteId: snapshot.action.oldVoteId,
    newVoteId: snapshot.action.newVoteId,
    newTitle: snapshot.action.newTitle,
    newResolutionText: snapshot.action.newResolutionText,
    newResolutionSha256: resolutionSha256,
    oldPackage: snapshot.oldPackage,
    oldPackageSha256: snapshot.oldPackageSha256,
    decisionPackage,
    packageSha256,
    electorate,
    changedComponentClasses: plan.changedComponentClasses,
    recipientMemberIds: snapshot.recipientRows.map(({ member_id }) => member_id),
    revoteMemberIds: snapshot.revoteMemberIds,
    payloadSha256,
    canonicalPayload: JSON.parse(canonicalJson(canonicalPayload)) as JsonValue,
    reason: snapshot.action.reason
  };
}

async function prepareInternal(
  client: PoolClient,
  action: VoteReplacementLifecycleAction,
  material: VoteReplacementStageMaterial,
  excludeStageId?: string
): Promise<PreparedVoteReplacementLifecycleAction> {
  const snapshot = await readSnapshot(client, action, excludeStageId);
  return buildPrepared(snapshot, checkedMaterial(snapshot, material));
}

export async function prepareVoteReplacementLifecycleActionInTransaction(
  client: PoolClient,
  input: {
    readonly action: VoteReplacementLifecycleAction;
    readonly material?: VoteReplacementStageMaterial;
    readonly newId?: () => string;
    readonly excludeStageId?: string;
  }
): Promise<{
  readonly prepared: PreparedVoteReplacementLifecycleAction;
  readonly material: VoteReplacementStageMaterial;
}> {
  const snapshot = await readSnapshot(client, input.action, input.excludeStageId);
  const material = checkedMaterial(
    snapshot,
    input.material ??
      (input.newId
        ? allocateMaterial(snapshot, input.newId)
        : (() => {
            throw new TypeError("vote replacement preparation requires material or an ID source");
          })())
  );
  return { prepared: buildPrepared(snapshot, material), material };
}

export async function prepareVoteResolutionAmendmentLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteResolutionAmendmentLifecycleInput & { readonly newId: () => string }
): Promise<{
  readonly action: VoteReplacementLifecycleAction;
  readonly prepared: PreparedVoteReplacementLifecycleAction;
  readonly material: VoteReplacementStageMaterial;
}> {
  const action = await deriveResolutionAmendmentAction(client, input, input.newId());
  const replacement = await prepareVoteReplacementLifecycleActionInTransaction(client, {
    action,
    newId: input.newId
  });
  return { action, ...replacement };
}

export async function prepareVoteDeadlineExtensionLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteDeadlineExtensionLifecycleInput & { readonly newId: () => string }
): Promise<{
  readonly action: VoteReplacementLifecycleAction;
  readonly prepared: PreparedVoteReplacementLifecycleAction;
  readonly material: VoteReplacementStageMaterial;
}> {
  const action = await deriveDeadlineExtensionAction(client, input, input.newId());
  const replacement = await prepareVoteReplacementLifecycleActionInTransaction(client, {
    action,
    newId: input.newId
  });
  return { action, ...replacement };
}

export async function stageVoteReplacementLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteReplacementLifecycleStageInput
): Promise<StagedVoteReplacementLifecycleAction> {
  const prepared = await prepareInternal(client, input.action, input.material, input.stage.stageId);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      wizardDraftId: null,
      boardId: prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => {
      // Exact source package, people, active acts and replacement package were recomputed above.
    }
  );
  const canonicalMaterial = canonicalJson(input.material);
  await client.query(
    `insert into vote_replacement_stage_material(
       stage_id,organization_id,board_id,old_vote_id,new_vote_id,consent_record_id,
       canonical_material,material_sha256
     ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      staged.stageId,
      prepared.organizationId,
      prepared.boardId,
      prepared.oldVoteId,
      prepared.newVoteId,
      input.material.consentRecordId,
      Buffer.from(canonicalMaterial, "utf8"),
      Buffer.from(canonicalSha256(input.material), "hex")
    ]
  );
  return {
    ...staged,
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetType: prepared.targetType,
    targetId: prepared.targetId
  };
}

async function readStageEnvelope(
  client: PoolClient,
  stageId: string
): Promise<{
  readonly row: PersistedMaterialRow;
  readonly material: VoteReplacementStageMaterial;
}> {
  const result = await client.query<PersistedMaterialRow>(
    `select organization_id,board_id,old_vote_id,new_vote_id,consent_record_id,
            canonical_material,material_sha256
       from vote_replacement_stage_material where stage_id=$1`,
    [UuidV7Schema.parse(stageId)]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new Error("vote replacement stage material is unavailable");
  }
  const canonicalMaterial = row.canonical_material.toString("utf8");
  if (
    !safeHashEqual(
      row.material_sha256.toString("hex"),
      canonicalSha256(JSON.parse(canonicalMaterial))
    )
  ) {
    throw new Error("vote replacement stage material failed persisted integrity validation");
  }
  const material = VoteReplacementStageMaterialSchema.parse(JSON.parse(canonicalMaterial));
  if (material.consentRecordId !== row.consent_record_id) {
    throw new Error("vote replacement consent material changed after staging");
  }
  return { row, material };
}

async function readStageMaterial(
  client: PoolClient,
  stageId: string,
  action: VoteReplacementLifecycleAction
): Promise<VoteReplacementStageMaterial> {
  const envelope = await readStageEnvelope(client, stageId);
  if (
    envelope.row.old_vote_id !== action.oldVoteId ||
    envelope.row.new_vote_id !== action.newVoteId
  ) {
    throw new Error("vote replacement stage identity changed after staging");
  }
  return envelope.material;
}

export async function confirmVoteReplacementLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteReplacementLifecycleConfirmationInput
): Promise<StagedActionResolution<ReplaceVoteResult>> {
  const action = normalizedAction(input.action);
  const material = await readStageMaterial(client, input.confirmation.stageId, action);
  let prepared: PreparedVoteReplacementLifecycleAction | undefined;
  const unavailablePayloadSha256 = canonicalSha256({
    schemaVersion: UNAVAILABLE_BINDING_SCHEMA,
    stageId: UuidV7Schema.parse(input.confirmation.stageId)
  });
  return confirmStagedActionInTransaction(
    client,
    { ...input.confirmation, consentRecordId: material.consentRecordId },
    async (requestClient) => {
      try {
        prepared = await prepareInternal(
          requestClient,
          action,
          material,
          input.confirmation.stageId
        );
        return {
          payloadSha256: prepared.payloadSha256,
          packageSha256: prepared.packageSha256
        };
      } catch (error) {
        if (
          error instanceof VoteReplacementLifecycleError ||
          error instanceof TypeError ||
          error instanceof RangeError
        ) {
          return { payloadSha256: unavailablePayloadSha256, packageSha256: null };
        }
        throw error;
      }
    },
    async (requestClient, consentRecordId) => {
      if (!prepared || consentRecordId !== material.consentRecordId) {
        throw new Error("confirmed vote replacement preparation is unavailable");
      }
      const replaced = await replaceVoteInTransaction(requestClient, {
        organizationId: prepared.organizationId,
        oldVoteId: prepared.oldVoteId,
        newVoteId: prepared.newVoteId,
        newTitle: prepared.newTitle,
        newResolutionVersionId: material.newResolutionVersionId,
        newResolutionText: prepared.newResolutionText,
        decisionPackageId: material.decisionPackageId,
        decisionPackage: prepared.decisionPackage,
        decisionPackageComponentIds: material.decisionPackageComponentIds,
        questionDecisionLinkIds: material.questionDecisionLinkIds,
        electorate: prepared.electorate,
        consentRecordId,
        supersessionId: material.supersessionId,
        reason: prepared.reason,
        idempotencyRecordId: material.idempotencyRecordId,
        idempotencyKey: action.idempotencyKey,
        stageDispositions: material.stageDispositions as readonly VoteStageReplacementInput[],
        proxyDispositions: material.proxyDispositions as readonly VoteProxyReplacementInput[],
        ballotDispositions: material.ballotDispositions as readonly VoteBallotReplacementInput[],
        feedTombstones: material.feedTombstones as readonly VoteFeedTombstoneInput[],
        sourceUpdateDispositions:
          material.sourceUpdateDispositions as readonly VoteSourceUpdateDispositionInput[],
        newVoteDeliveries: material.newVoteDeliveries,
        replacementDeliveries: material.replacementDeliveries,
        revoteDeliveries: material.revoteDeliveries,
        ...(material.resolutionAmendedAuditEventId
          ? { resolutionAmendedAuditEventId: material.resolutionAmendedAuditEventId }
          : {}),
        voteSupersededAuditEventId: material.voteSupersededAuditEventId,
        voteOpenedAuditEventId: material.voteOpenedAuditEventId
      });
      return {
        value: replaced,
        auditEvents: [],
        preappendedAuditSequences: replaced.replayed
          ? []
          : replaced.auditEvents.map(({ sequence }) => sequence)
      };
    },
    { appendConsentBeforeAct: true, exposeConfirmedProjectionToAct: true }
  );
}

async function rejectUnavailableDerivedReplacementInTransaction(
  client: PoolClient,
  confirmation: Omit<ConfirmStagedActionInput, "consentRecordId">,
  consentRecordId: string
): Promise<StagedActionResolution<ReplaceVoteResult>> {
  const unavailablePayloadSha256 = canonicalSha256({
    schemaVersion: UNAVAILABLE_BINDING_SCHEMA,
    stageId: UuidV7Schema.parse(confirmation.stageId)
  });
  return confirmStagedActionInTransaction(
    client,
    { ...confirmation, consentRecordId },
    async () => ({ payloadSha256: unavailablePayloadSha256, packageSha256: null }),
    async () => {
      throw new Error("unavailable derived vote replacement cannot be confirmed");
    }
  );
}

export async function confirmVoteResolutionAmendmentLifecycleActionInTransaction(
  client: PoolClient,
  input: {
    readonly action: VoteResolutionAmendmentLifecycleInput;
    readonly confirmation: Omit<ConfirmStagedActionInput, "consentRecordId">;
  }
): Promise<StagedActionResolution<ReplaceVoteResult>> {
  const envelope = await readStageEnvelope(client, input.confirmation.stageId);
  if (envelope.row.old_vote_id !== UuidV7Schema.parse(input.action.voteId)) {
    throw new Error("resolution amendment stage target changed after staging");
  }
  let action: VoteReplacementLifecycleAction;
  try {
    action = await deriveResolutionAmendmentAction(client, input.action, envelope.row.new_vote_id);
  } catch (error) {
    if (
      error instanceof VoteReplacementLifecycleError ||
      error instanceof TypeError ||
      error instanceof RangeError
    ) {
      return rejectUnavailableDerivedReplacementInTransaction(
        client,
        input.confirmation,
        envelope.material.consentRecordId
      );
    }
    throw error;
  }
  return confirmVoteReplacementLifecycleActionInTransaction(client, {
    action,
    confirmation: input.confirmation
  });
}

export async function confirmVoteDeadlineExtensionLifecycleActionInTransaction(
  client: PoolClient,
  input: {
    readonly action: VoteDeadlineExtensionLifecycleInput;
    readonly confirmation: Omit<ConfirmStagedActionInput, "consentRecordId">;
  }
): Promise<StagedActionResolution<ReplaceVoteResult>> {
  const envelope = await readStageEnvelope(client, input.confirmation.stageId);
  if (envelope.row.old_vote_id !== UuidV7Schema.parse(input.action.voteId)) {
    throw new Error("deadline extension stage target changed after staging");
  }
  let action: VoteReplacementLifecycleAction;
  try {
    action = await deriveDeadlineExtensionAction(client, input.action, envelope.row.new_vote_id);
  } catch (error) {
    if (
      error instanceof VoteReplacementLifecycleError ||
      error instanceof TypeError ||
      error instanceof RangeError
    ) {
      return rejectUnavailableDerivedReplacementInTransaction(
        client,
        input.confirmation,
        envelope.material.consentRecordId
      );
    }
    throw error;
  }
  return confirmVoteReplacementLifecycleActionInTransaction(client, {
    action,
    confirmation: input.confirmation
  });
}
