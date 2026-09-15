import type { PoolClient } from "pg";

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
  ruleOverrideEvidenceHash,
  type PreparedVoteElectorate,
  type RuleSelectionCitation
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
import { recordRuleOverrideInTransaction } from "./rule-overrides.js";
import { readRequestContext } from "./request-context.js";
import {
  openVoteInTransaction,
  validateDecisionPackageComponentsInTransaction,
  type OpenVoteResult,
  type VoteOpenDeliveryInput
} from "./votes.js";

const CORE_COMPONENT_COUNT = 7;
const UNAVAILABLE_BINDING_SCHEMA = "boardagent.vote-creation-unavailable.v1" as const;

export class VoteCreationLifecycleError extends Error {
  public constructor(
    public readonly code:
      "vote_creation_unavailable" | "vote_creation_invalid" | "vote_creation_override_required",
    message: string
  ) {
    super(message);
    this.name = "VoteCreationLifecycleError";
  }
}

export interface VoteCreationLifecycleAction {
  readonly boardId: string;
  readonly voteId: string;
  readonly title: string;
  readonly resolutionText: string;
  readonly components: DecisionPackage["components"];
  readonly approvalRuleId: string;
  readonly matterEvaluationId: string;
  readonly selectedRulesetRuleId: string;
  readonly overrideReason: string | null;
  readonly closeMode: "automatic" | "secretariat_confirmed";
  readonly deadlineAt: string;
  readonly idempotencyKey: string;
}

export interface VoteCreationStageMaterial {
  readonly wizardDraftId: string;
  readonly wizardStepId: string;
  readonly resolutionVersionId: string;
  readonly decisionPackageId: string;
  readonly consentRecordId: string;
  readonly voteOpenedAuditEventId: string;
  readonly idempotencyRecordId: string;
  readonly ruleOverrideId: string | null;
  readonly ruleOverrideAuditEventId: string | null;
  readonly ruleOverrideIdempotencyRecordId: string | null;
  readonly decisionPackageComponentIds: readonly string[];
  readonly questionDecisionLinkIds: readonly string[];
  readonly electorateEntryIds: readonly string[];
  readonly deliveries: readonly VoteOpenDeliveryInput[];
}

export interface PreparedVoteCreationLifecycleAction {
  readonly actionCode: "create_vote";
  readonly targetType: "vote";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.vote-open.v1";
  readonly organizationId: string;
  readonly boardId: string;
  readonly voteId: string;
  readonly title: string;
  readonly resolutionText: string;
  readonly resolutionSha256: string;
  readonly decisionPackage: DecisionPackage;
  readonly electorate: PreparedVoteElectorate;
  readonly recipientMemberIds: readonly string[];
  readonly ruleCitations: readonly RuleSelectionCitation[];
  readonly recommendedRuleId: string;
  readonly selectedRuleId: string;
  readonly overrideReason: string | null;
  readonly payloadSha256: string;
  readonly packageSha256: string;
  readonly canonicalPayload: JsonValue;
}

export interface VoteCreationLifecycleStageInput {
  readonly action: VoteCreationLifecycleAction;
  readonly material: VoteCreationStageMaterial;
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

export interface StagedVoteCreationLifecycleAction extends StagedAction {
  readonly actionCode: "create_vote";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
}

export interface VoteCreationLifecycleConfirmationInput {
  readonly action: VoteCreationLifecycleAction;
  readonly confirmation: Omit<ConfirmStagedActionInput, "consentRecordId">;
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
  readonly seat_role: string;
  readonly entitlement_generation: string;
}

interface PersistedMaterialRow {
  readonly wizard_draft_id: string;
  readonly wizard_step_id: string;
  readonly resolution_version_id: string;
  readonly decision_package_id: string;
  readonly consent_record_id: string;
  readonly vote_opened_audit_event_id: string;
  readonly idempotency_record_id: string;
  readonly rule_override_id: string | null;
  readonly rule_override_audit_event_id: string | null;
  readonly rule_override_idempotency_record_id: string | null;
  readonly decision_package_component_ids: string[];
  readonly question_decision_link_ids: string[];
  readonly electorate_entry_ids: string[];
  readonly delivery_member_ids: string[];
  readonly delivery_notice_ids: string[];
  readonly delivery_feed_ids: string[];
  readonly delivery_audit_event_ids: string[];
}

interface CreationSnapshot {
  readonly action: VoteCreationLifecycleAction;
  readonly organizationId: string;
  readonly profileId: string;
  readonly profileVersion: number;
  readonly profileSha256: string;
  readonly rulesetId: string;
  readonly rulesetVersion: number;
  readonly rulesetSha256: string;
  readonly approvalRuleSha256: string;
  readonly evaluationResultSha256: string;
  readonly selectedRuleSha256: string;
  readonly recommendedRuleId: string;
  readonly overrideSelected: boolean;
  readonly citations: readonly RuleSelectionCitation[];
  readonly electorateRows: readonly ElectorateRow[];
  readonly recipientRows: readonly RecipientRow[];
}

function unavailable(message = "vote creation is unavailable"): never {
  throw new VoteCreationLifecycleError("vote_creation_unavailable", message);
}

function invalid(message: string): never {
  throw new VoteCreationLifecycleError("vote_creation_invalid", message);
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function normalizedAction(input: VoteCreationLifecycleAction): VoteCreationLifecycleAction {
  const title = canonicalText(input.title);
  if (title.length < 1 || title.length > 1024) {
    throw new RangeError("vote title must contain 1 through 1024 characters");
  }
  const resolutionText = canonicalText(input.resolutionText);
  if (resolutionText.length < 1 || Buffer.byteLength(resolutionText, "utf8") > 1_048_576) {
    throw new RangeError("vote resolution must contain 1 through 1048576 bytes");
  }
  const overrideReason = input.overrideReason === null ? null : canonicalText(input.overrideReason);
  if (overrideReason !== null && (overrideReason.length < 1 || overrideReason.length > 65_536)) {
    throw new RangeError("vote rule-override reason must contain 1 through 65536 characters");
  }
  return {
    boardId: UuidV7Schema.parse(input.boardId),
    voteId: UuidV7Schema.parse(input.voteId),
    title,
    resolutionText,
    components: DecisionPackageSchema.shape.components.parse(input.components),
    approvalRuleId: UuidV7Schema.parse(input.approvalRuleId),
    matterEvaluationId: UuidV7Schema.parse(input.matterEvaluationId),
    selectedRulesetRuleId: UuidV7Schema.parse(input.selectedRulesetRuleId),
    overrideReason,
    closeMode: input.closeMode,
    deadlineAt: Rfc3339UtcSchema.parse(input.deadlineAt),
    idempotencyKey: idempotencyKey(input.idempotencyKey)
  };
}

async function readCreationSnapshot(
  client: PoolClient,
  input: VoteCreationLifecycleAction
): Promise<CreationSnapshot> {
  const action = normalizedAction(input);
  const context = await readRequestContext(client);
  const rootResult = await client.query<BoardRootRow>(
    "select * from boardagent_lock_board_root($1)",
    [action.boardId]
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
  const existingVote = await client.query<{ id: string }>(
    "select id from votes where id=$1 for update",
    [action.voteId]
  );
  if (existingVote.rows.length !== 0) unavailable();

  let selection;
  try {
    selection = await loadRuleSelectionEvidence(client, {
      boardId: action.boardId,
      profileId: root.current_governance_profile_id,
      rulesetId: root.current_ruleset_id,
      approvalRuleId: action.approvalRuleId,
      evaluationId: action.matterEvaluationId,
      selectedRuleId: action.selectedRulesetRuleId
    });
  } catch (error) {
    if (error instanceof RuleSelectionEvidenceError) {
      invalid(error.message);
    }
    throw error;
  }
  if (selection.resultDetails.status !== "matched" || selection.row.recommended_rule_id === null) {
    invalid("vote creation requires one unambiguous persisted matter evaluation");
  }
  const recommendedRuleId = selection.row.recommended_rule_id;
  const overrideSelected = recommendedRuleId !== action.selectedRulesetRuleId;
  if (overrideSelected) {
    if (action.overrideReason === null) {
      throw new VoteCreationLifecycleError(
        "vote_creation_override_required",
        "a nonrecommended rule requires an explicit reason in the final confirmation"
      );
    }
    if (selection.template.overridePolicy !== "reasoned_within_bounds") {
      invalid("the active profile does not permit this rule override");
    }
  } else if (action.overrideReason !== null) {
    invalid("the recommended rule must not carry override evidence");
  }
  const approval = await client.query<ApprovalRuleRow>(
    `select close_mode,canonical_sha256
       from approval_rules
      where id=$1 and organization_id=$2 and board_id=$3`,
    [action.approvalRuleId, context.organizationId, action.boardId]
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
    invalid("vote close mode or approval rule is not permitted by the active profile");
  }
  if (
    selection.resultDetails.profile.id !== root.current_governance_profile_id ||
    selection.resultDetails.ruleset.id !== root.current_ruleset_id
  ) {
    invalid("matter evaluation does not cite the active governance versions");
  }
  await validateDecisionPackageComponentsInTransaction(
    client,
    context.organizationId,
    action.boardId,
    action.components
  );

  const electorate = await client.query<ElectorateRow>(
    "select * from boardagent_lock_vote_creation_electorate($1)",
    [action.boardId]
  );
  if (electorate.rows.length < 1 || electorate.rows.length > 1000) {
    invalid("vote creation requires one through 1000 current eligible voting members");
  }
  const recipients = await client.query<RecipientRow>(
    "select * from boardagent_lock_vote_creation_recipients($1)",
    [action.boardId]
  );
  if (recipients.rows.length < 1 || recipients.rows.length > 1000) {
    invalid("vote creation requires one through 1000 current entitled recipients");
  }
  const recipientIds = new Set(recipients.rows.map(({ member_id }) => member_id));
  if (
    recipientIds.size !== recipients.rows.length ||
    electorate.rows.some(({ member_id }) => !recipientIds.has(member_id))
  ) {
    invalid("the current electorate is not covered by the exact entitled recipients");
  }
  const time = await client.query<{ now: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as now`
  );
  const now = time.rows[0]?.now;
  if (!now || Date.parse(action.deadlineAt) <= Date.parse(now)) {
    invalid("vote deadline must remain in the future through confirmation");
  }
  return {
    action,
    organizationId: context.organizationId,
    profileId: selection.resultDetails.profile.id,
    profileVersion: selection.resultDetails.profile.version,
    profileSha256: selection.resultDetails.profile.canonicalSha256,
    rulesetId: selection.resultDetails.ruleset.id,
    rulesetVersion: selection.resultDetails.ruleset.version,
    rulesetSha256: selection.resultDetails.ruleset.canonicalSha256,
    approvalRuleSha256: approvalRow.canonical_sha256.toString("hex"),
    evaluationResultSha256: selection.row.evaluation_result_sha256.toString("hex"),
    selectedRuleSha256: selection.row.selected_rule_sha256.toString("hex"),
    recommendedRuleId,
    overrideSelected,
    citations: selection.citations,
    electorateRows: electorate.rows,
    recipientRows: recipients.rows
  };
}

function generatedIds(values: readonly string[], label: string): readonly string[] {
  const ids = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(ids).size !== ids.length) throw new TypeError(`${label} must be unique`);
  return ids;
}

function allocateMaterial(
  snapshot: CreationSnapshot,
  newId: () => string
): VoteCreationStageMaterial {
  const questionCount = snapshot.action.components.filter(
    ({ type }) => type === "question_cutoff"
  ).length;
  return {
    wizardDraftId: newId(),
    wizardStepId: newId(),
    resolutionVersionId: newId(),
    decisionPackageId: newId(),
    consentRecordId: newId(),
    voteOpenedAuditEventId: newId(),
    idempotencyRecordId: newId(),
    ruleOverrideId: snapshot.overrideSelected ? newId() : null,
    ruleOverrideAuditEventId: snapshot.overrideSelected ? newId() : null,
    ruleOverrideIdempotencyRecordId: snapshot.overrideSelected ? newId() : null,
    decisionPackageComponentIds: Array.from(
      { length: CORE_COMPONENT_COUNT + snapshot.action.components.length },
      () => newId()
    ),
    questionDecisionLinkIds: Array.from({ length: questionCount }, () => newId()),
    electorateEntryIds: snapshot.electorateRows.map(() => newId()),
    deliveries: snapshot.recipientRows.map(({ member_id }) => ({
      memberId: member_id,
      noticeId: newId(),
      feedId: newId(),
      noticeAuditEventId: newId()
    }))
  };
}

function checkedMaterial(
  snapshot: CreationSnapshot,
  material: VoteCreationStageMaterial
): VoteCreationStageMaterial {
  const questionCount = snapshot.action.components.filter(
    ({ type }) => type === "question_cutoff"
  ).length;
  if (
    material.decisionPackageComponentIds.length !==
      CORE_COMPONENT_COUNT + snapshot.action.components.length ||
    material.questionDecisionLinkIds.length !== questionCount ||
    material.electorateEntryIds.length !== snapshot.electorateRows.length ||
    material.deliveries.length !== snapshot.recipientRows.length
  ) {
    throw new TypeError("vote creation stage material does not cover the exact package");
  }
  const overrideMaterial = [
    material.ruleOverrideId,
    material.ruleOverrideAuditEventId,
    material.ruleOverrideIdempotencyRecordId
  ];
  if (
    snapshot.overrideSelected !== overrideMaterial.every((value) => value !== null) ||
    (!snapshot.overrideSelected && overrideMaterial.some((value) => value !== null))
  ) {
    throw new TypeError("vote creation override material does not match the selected rule");
  }
  const deliveries = material.deliveries.map((delivery, index) => {
    const memberId = UuidV7Schema.parse(delivery.memberId);
    if (memberId !== snapshot.recipientRows[index]?.member_id) {
      throw new TypeError("vote creation delivery recipients changed after preparation");
    }
    return {
      memberId,
      noticeId: UuidV7Schema.parse(delivery.noticeId),
      feedId: UuidV7Schema.parse(delivery.feedId),
      noticeAuditEventId: UuidV7Schema.parse(delivery.noticeAuditEventId)
    };
  });
  const normalized: VoteCreationStageMaterial = {
    wizardDraftId: UuidV7Schema.parse(material.wizardDraftId),
    wizardStepId: UuidV7Schema.parse(material.wizardStepId),
    resolutionVersionId: UuidV7Schema.parse(material.resolutionVersionId),
    decisionPackageId: UuidV7Schema.parse(material.decisionPackageId),
    consentRecordId: UuidV7Schema.parse(material.consentRecordId),
    voteOpenedAuditEventId: UuidV7Schema.parse(material.voteOpenedAuditEventId),
    idempotencyRecordId: UuidV7Schema.parse(material.idempotencyRecordId),
    ruleOverrideId:
      material.ruleOverrideId === null ? null : UuidV7Schema.parse(material.ruleOverrideId),
    ruleOverrideAuditEventId:
      material.ruleOverrideAuditEventId === null
        ? null
        : UuidV7Schema.parse(material.ruleOverrideAuditEventId),
    ruleOverrideIdempotencyRecordId:
      material.ruleOverrideIdempotencyRecordId === null
        ? null
        : UuidV7Schema.parse(material.ruleOverrideIdempotencyRecordId),
    decisionPackageComponentIds: generatedIds(
      material.decisionPackageComponentIds,
      "decision-package component IDs"
    ),
    questionDecisionLinkIds: generatedIds(
      material.questionDecisionLinkIds,
      "question-decision link IDs"
    ),
    electorateEntryIds: generatedIds(material.electorateEntryIds, "electorate entry IDs"),
    deliveries
  };
  generatedIds(
    [
      snapshot.action.voteId,
      normalized.wizardDraftId,
      normalized.wizardStepId,
      normalized.resolutionVersionId,
      normalized.decisionPackageId,
      normalized.consentRecordId,
      normalized.voteOpenedAuditEventId,
      normalized.idempotencyRecordId,
      ...(normalized.ruleOverrideId === null ? [] : [normalized.ruleOverrideId]),
      ...(normalized.ruleOverrideAuditEventId === null
        ? []
        : [normalized.ruleOverrideAuditEventId]),
      ...(normalized.ruleOverrideIdempotencyRecordId === null
        ? []
        : [normalized.ruleOverrideIdempotencyRecordId]),
      ...normalized.decisionPackageComponentIds,
      ...normalized.questionDecisionLinkIds,
      ...normalized.electorateEntryIds,
      ...normalized.deliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
        noticeId,
        feedId,
        noticeAuditEventId
      ])
    ],
    "vote creation generated IDs"
  );
  return normalized;
}

function buildPrepared(
  snapshot: CreationSnapshot,
  material: VoteCreationStageMaterial
): PreparedVoteCreationLifecycleAction {
  const electorate = prepareVoteElectorate({
    voteId: snapshot.action.voteId,
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
    invalid("current electorate eligibility evidence failed its stored hash");
  }
  const resolutionSha256 = canonicalSha256({
    schemaVersion: "boardagent.resolution.v1",
    text: snapshot.action.resolutionText
  });
  const ruleOverride = snapshot.overrideSelected
    ? (() => {
        if (
          snapshot.action.overrideReason === null ||
          material.ruleOverrideId === null ||
          material.ruleOverrideAuditEventId === null
        ) {
          throw new TypeError("vote creation override evidence is incomplete");
        }
        return {
          id: material.ruleOverrideId,
          canonicalSha256: ruleOverrideEvidenceHash({
            evaluationId: snapshot.action.matterEvaluationId,
            evaluationResultSha256: snapshot.evaluationResultSha256,
            wizardDraftId: material.wizardDraftId,
            finalVoteId: snapshot.action.voteId,
            recommendedRuleId: snapshot.recommendedRuleId,
            selectedRuleId: snapshot.action.selectedRulesetRuleId,
            selectedRuleSha256: snapshot.selectedRuleSha256,
            reason: snapshot.action.overrideReason,
            citations: snapshot.citations,
            consentRecordId: material.consentRecordId,
            auditEventId: material.ruleOverrideAuditEventId
          })
        };
      })()
    : null;
  const decisionPackage = DecisionPackageSchema.parse({
    schemaVersion: "boardagent.decision-package.v1",
    voteId: snapshot.action.voteId,
    packageVersion: 1,
    resolutionVersionId: material.resolutionVersionId,
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
    ruleOverride,
    electorateSha256: electorate.electorateSha256,
    closeMode: snapshot.action.closeMode,
    deadlineAt: snapshot.action.deadlineAt,
    components: snapshot.action.components
  });
  const packageSha256 = canonicalSha256(decisionPackage);
  return {
    actionCode: "create_vote",
    targetType: "vote",
    targetId: snapshot.action.voteId,
    canonicalSchema: "boardagent.vote-open.v1",
    organizationId: snapshot.organizationId,
    boardId: snapshot.action.boardId,
    voteId: snapshot.action.voteId,
    title: snapshot.action.title,
    resolutionText: snapshot.action.resolutionText,
    resolutionSha256,
    decisionPackage,
    electorate,
    recipientMemberIds: material.deliveries.map(({ memberId }) => memberId),
    ruleCitations: snapshot.citations,
    recommendedRuleId: snapshot.recommendedRuleId,
    selectedRuleId: snapshot.action.selectedRulesetRuleId,
    overrideReason: snapshot.action.overrideReason,
    payloadSha256: packageSha256,
    packageSha256,
    canonicalPayload: JSON.parse(canonicalJson(decisionPackage)) as JsonValue
  };
}

async function prepareInternal(
  client: PoolClient,
  action: VoteCreationLifecycleAction,
  material: VoteCreationStageMaterial
): Promise<PreparedVoteCreationLifecycleAction> {
  const snapshot = await readCreationSnapshot(client, action);
  return buildPrepared(snapshot, checkedMaterial(snapshot, material));
}

export async function prepareVoteCreationLifecycleActionInTransaction(
  client: PoolClient,
  input: {
    readonly action: VoteCreationLifecycleAction;
    readonly material?: VoteCreationStageMaterial;
    readonly newId?: () => string;
  }
): Promise<{
  readonly prepared: PreparedVoteCreationLifecycleAction;
  readonly material: VoteCreationStageMaterial;
}> {
  const snapshot = await readCreationSnapshot(client, input.action);
  const material = checkedMaterial(
    snapshot,
    input.material ??
      (input.newId
        ? allocateMaterial(snapshot, input.newId)
        : (() => {
            throw new TypeError(
              "vote creation preparation requires stage material or an ID source"
            );
          })())
  );
  return { prepared: buildPrepared(snapshot, material), material };
}

export async function stageVoteCreationLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteCreationLifecycleStageInput
): Promise<StagedVoteCreationLifecycleAction> {
  const prepared = await prepareInternal(client, input.action, input.material);
  const wizardContext = {
    schemaVersion: "boardagent.vote-wizard-context.v1",
    boardId: prepared.boardId,
    voteId: prepared.voteId,
    decisionPackageSha256: prepared.packageSha256
  } as const;
  const canonicalWizardContext = canonicalJson(wizardContext);
  await client.query(
    `insert into wizard_drafts(
       id,organization_id,board_id,draft_type,creator_member_id,current_step,
       signed_context,context_sha256,state,ruleset_id,package_sha256,expires_at
     ) values ($1,$2,$3,'vote',boardagent_context_uuid('boardagent.member_id'),1,
       $4,$5,'ready_to_confirm',$6,$7,transaction_timestamp()+interval '10 minutes')`,
    [
      input.material.wizardDraftId,
      prepared.organizationId,
      prepared.boardId,
      Buffer.from(canonicalWizardContext, "utf8"),
      Buffer.from(canonicalSha256(wizardContext), "hex"),
      prepared.decisionPackage.rulesetVersionId,
      Buffer.from(prepared.packageSha256, "hex")
    ]
  );
  const review = {
    schemaVersion: "boardagent.vote-wizard-final-review.v1",
    voteId: prepared.voteId,
    decisionPackageSha256: prepared.packageSha256,
    matterEvaluationId: prepared.decisionPackage.matterEvaluationId,
    recommendedRulesetRuleId: prepared.recommendedRuleId,
    selectedRulesetRuleId: prepared.selectedRuleId,
    ruleOverride: prepared.decisionPackage.ruleOverride,
    overrideReason: prepared.overrideReason,
    closeMode: prepared.decisionPackage.closeMode,
    deadlineAt: prepared.decisionPackage.deadlineAt
  } as const;
  const canonicalReview = canonicalJson(review);
  await client.query(
    `insert into wizard_steps(
       id,draft_id,ordinal,question_code,value_schema,canonical_value,value_sha256,
       recommended_rule_id,citation_snapshot,override_selected,override_reason,attempt
     ) values ($1,$2,0,'final_package','boardagent.vote-wizard-final-review.v1',$3,$4,
       $5,$6,$7,$8,1)`,
    [
      input.material.wizardStepId,
      input.material.wizardDraftId,
      Buffer.from(canonicalReview, "utf8"),
      Buffer.from(canonicalSha256(review), "hex"),
      prepared.recommendedRuleId,
      JSON.stringify(prepared.ruleCitations),
      prepared.decisionPackage.ruleOverride !== null,
      prepared.overrideReason
    ]
  );
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      wizardDraftId: input.material.wizardDraftId,
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
      // Preparation locked and recomputed the active profile, rule, sources and people.
    }
  );
  await client.query(
    `insert into vote_creation_stage_material(
       stage_id,organization_id,board_id,vote_id,wizard_draft_id,wizard_step_id,
       resolution_version_id,decision_package_id,consent_record_id,
       vote_opened_audit_event_id,idempotency_record_id,rule_override_id,
       rule_override_audit_event_id,rule_override_idempotency_record_id,
       decision_package_component_ids,question_decision_link_ids,electorate_entry_ids,
       delivery_member_ids,delivery_notice_ids,delivery_feed_ids,delivery_audit_event_ids
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
    [
      staged.stageId,
      prepared.organizationId,
      prepared.boardId,
      prepared.voteId,
      input.material.wizardDraftId,
      input.material.wizardStepId,
      input.material.resolutionVersionId,
      input.material.decisionPackageId,
      input.material.consentRecordId,
      input.material.voteOpenedAuditEventId,
      input.material.idempotencyRecordId,
      input.material.ruleOverrideId,
      input.material.ruleOverrideAuditEventId,
      input.material.ruleOverrideIdempotencyRecordId,
      input.material.decisionPackageComponentIds,
      input.material.questionDecisionLinkIds,
      input.material.electorateEntryIds,
      input.material.deliveries.map(({ memberId }) => memberId),
      input.material.deliveries.map(({ noticeId }) => noticeId),
      input.material.deliveries.map(({ feedId }) => feedId),
      input.material.deliveries.map(({ noticeAuditEventId }) => noticeAuditEventId)
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

async function readStageMaterial(
  client: PoolClient,
  stageId: string
): Promise<VoteCreationStageMaterial> {
  const result = await client.query<PersistedMaterialRow>(
    `select wizard_draft_id,wizard_step_id,resolution_version_id,decision_package_id,
            consent_record_id,vote_opened_audit_event_id,idempotency_record_id,
            rule_override_id,rule_override_audit_event_id,
            rule_override_idempotency_record_id,
            decision_package_component_ids,question_decision_link_ids,electorate_entry_ids,
            delivery_member_ids,delivery_notice_ids,delivery_feed_ids,delivery_audit_event_ids
       from vote_creation_stage_material where stage_id=$1`,
    [UuidV7Schema.parse(stageId)]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new Error("vote creation stage material is unavailable");
  }
  if (
    row.delivery_member_ids.length !== row.delivery_notice_ids.length ||
    row.delivery_member_ids.length !== row.delivery_feed_ids.length ||
    row.delivery_member_ids.length !== row.delivery_audit_event_ids.length
  ) {
    throw new Error("vote creation delivery material is internally inconsistent");
  }
  return {
    wizardDraftId: row.wizard_draft_id,
    wizardStepId: row.wizard_step_id,
    resolutionVersionId: row.resolution_version_id,
    decisionPackageId: row.decision_package_id,
    consentRecordId: row.consent_record_id,
    voteOpenedAuditEventId: row.vote_opened_audit_event_id,
    idempotencyRecordId: row.idempotency_record_id,
    ruleOverrideId: row.rule_override_id,
    ruleOverrideAuditEventId: row.rule_override_audit_event_id,
    ruleOverrideIdempotencyRecordId: row.rule_override_idempotency_record_id,
    decisionPackageComponentIds: row.decision_package_component_ids,
    questionDecisionLinkIds: row.question_decision_link_ids,
    electorateEntryIds: row.electorate_entry_ids,
    deliveries: row.delivery_member_ids.map((memberId, index) => ({
      memberId,
      noticeId: row.delivery_notice_ids[index]!,
      feedId: row.delivery_feed_ids[index]!,
      noticeAuditEventId: row.delivery_audit_event_ids[index]!
    }))
  };
}

export async function confirmVoteCreationLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteCreationLifecycleConfirmationInput
): Promise<StagedActionResolution<OpenVoteResult>> {
  const material = await readStageMaterial(client, input.confirmation.stageId);
  let prepared: PreparedVoteCreationLifecycleAction | undefined;
  const unavailablePayloadSha256 = canonicalSha256({
    schemaVersion: UNAVAILABLE_BINDING_SCHEMA,
    stageId: UuidV7Schema.parse(input.confirmation.stageId)
  });
  return confirmStagedActionInTransaction(
    client,
    { ...input.confirmation, consentRecordId: material.consentRecordId },
    async (requestClient) => {
      try {
        prepared = await prepareInternal(requestClient, input.action, material);
        return {
          payloadSha256: prepared.payloadSha256,
          packageSha256: prepared.packageSha256
        };
      } catch (error) {
        if (error instanceof VoteCreationLifecycleError || error instanceof TypeError) {
          return { payloadSha256: unavailablePayloadSha256, packageSha256: null };
        }
        throw error;
      }
    },
    async (requestClient, consentRecordId) => {
      if (!prepared || consentRecordId !== material.consentRecordId) {
        throw new Error("confirmed vote creation preparation is unavailable");
      }
      await requestClient.query(
        `insert into votes(
           id,organization_id,board_id,title,approval_rule_id,governance_profile_id,
           ruleset_id,close_mode,created_by
         ) values ($1,$2,$3,$4,$5,$6,$7,$8,
           boardagent_context_uuid('boardagent.member_id'))`,
        [
          prepared.voteId,
          prepared.organizationId,
          prepared.boardId,
          prepared.title,
          prepared.decisionPackage.approvalRuleId,
          prepared.decisionPackage.governanceProfileVersionId,
          prepared.decisionPackage.rulesetVersionId,
          prepared.decisionPackage.closeMode
        ]
      );
      await requestClient.query(
        `insert into resolution_versions(
           id,organization_id,board_id,vote_id,version,canonical_schema,canonical_text,
           canonical_sha256,author_member_id
         ) values ($1,$2,$3,$4,1,'boardagent.resolution.v1',$5,$6,
           boardagent_context_uuid('boardagent.member_id'))`,
        [
          material.resolutionVersionId,
          prepared.organizationId,
          prepared.boardId,
          prepared.voteId,
          prepared.resolutionText,
          Buffer.from(prepared.resolutionSha256, "hex")
        ]
      );
      const overrideAuditSequences: bigint[] = [];
      if (prepared.decisionPackage.ruleOverride !== null) {
        if (
          prepared.overrideReason === null ||
          material.ruleOverrideId === null ||
          material.ruleOverrideAuditEventId === null ||
          material.ruleOverrideIdempotencyRecordId === null
        ) {
          throw new Error("confirmed vote creation override material is unavailable");
        }
        const recordedOverride = await recordRuleOverrideInTransaction(requestClient, {
          organizationId: prepared.organizationId,
          boardId: prepared.boardId,
          evaluationId: prepared.decisionPackage.matterEvaluationId,
          evaluationResultSha256: prepared.decisionPackage.matterEvaluationResultSha256,
          wizardDraftId: material.wizardDraftId,
          finalVoteId: prepared.voteId,
          selectedRuleId: prepared.selectedRuleId,
          selectedRuleSha256: prepared.decisionPackage.selectedRulesetRuleSha256,
          reason: prepared.overrideReason,
          citations: prepared.ruleCitations,
          packageSha256: prepared.packageSha256,
          consentRecordId,
          ruleOverrideId: material.ruleOverrideId,
          idempotencyRecordId: material.ruleOverrideIdempotencyRecordId,
          idempotencyKey: `create-vote-rule-override:${material.ruleOverrideId}`,
          auditEventId: material.ruleOverrideAuditEventId,
          consentPayloadMode: "package"
        });
        if (
          recordedOverride.ruleOverrideId !== prepared.decisionPackage.ruleOverride.id ||
          !safeHashEqual(
            recordedOverride.canonicalSha256,
            prepared.decisionPackage.ruleOverride.canonicalSha256
          )
        ) {
          throw new Error("recorded rule override changed after final confirmation");
        }
        if (!recordedOverride.replayed) {
          overrideAuditSequences.push(
            ...recordedOverride.auditEvents.map(({ sequence }) => sequence)
          );
        }
      }
      const postedWizard = await requestClient.query(
        `update wizard_drafts
            set state='posted',posted_at=transaction_timestamp(),row_version=row_version+1
          where id=$1 and organization_id=$2 and board_id=$3
            and state='ready_to_confirm' and package_sha256=$4`,
        [
          material.wizardDraftId,
          prepared.organizationId,
          prepared.boardId,
          Buffer.from(prepared.packageSha256, "hex")
        ]
      );
      if (postedWizard.rowCount !== 1) {
        throw new Error("vote creation wizard changed before posting");
      }
      const opened = await openVoteInTransaction(requestClient, {
        organizationId: prepared.organizationId,
        voteId: prepared.voteId,
        decisionPackageId: material.decisionPackageId,
        decisionPackage: prepared.decisionPackage,
        decisionPackageComponentIds: material.decisionPackageComponentIds,
        questionDecisionLinkIds: material.questionDecisionLinkIds,
        electorate: prepared.electorate,
        consentRecordId,
        auditEventId: material.voteOpenedAuditEventId,
        idempotencyRecordId: material.idempotencyRecordId,
        idempotencyKey: input.action.idempotencyKey,
        deliveries: material.deliveries
      });
      return {
        value: opened,
        auditEvents: [],
        preappendedAuditSequences: opened.replayed
          ? overrideAuditSequences
          : [...overrideAuditSequences, ...opened.auditEvents.map(({ sequence }) => sequence)]
      };
    },
    { appendConsentBeforeAct: true, exposeConfirmedProjectionToAct: true }
  );
}
