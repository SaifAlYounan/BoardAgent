import type { PoolClient } from "pg";
import { z } from "zod";

import {
  GovernanceRuleTemplatePayloadSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  type DecisionPackage
} from "@boardagent/contracts";
import {
  ruleOverrideConsentHash,
  ruleOverrideEvidenceHash,
  type RuleSelectionCitation
} from "@boardagent/domain";

import { GovernanceRuleTemplateSchema } from "@boardagent/ruleset";

import { MatterEvaluationResultDetailsSchema } from "./matter-evaluations.js";

export const RuleSelectionCitationSchema = z
  .object({
    ruleId: UuidV7Schema,
    sourceDocumentVersionId: UuidV7Schema,
    sourceDocumentSha256: Sha256HexSchema,
    clause: z.string().min(1).max(512),
    locator: z.string().min(1).max(1024)
  })
  .strict();

export interface RuleSelectionEvidenceRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly evaluation_id: string;
  readonly evaluation_result: string;
  readonly evaluation_result_details: unknown;
  readonly evaluation_result_sha256: Buffer;
  readonly recommended_rule_id: string | null;
  readonly evaluation_candidate_rule_ids: string[];
  readonly selected_rule_id: string;
  readonly selected_rule_sha256: Buffer;
  readonly selected_approval_rule_id: string;
  readonly selected_approval_rule_sha256: Buffer;
  readonly selected_template_payload: unknown;
  readonly selected_template_sha256: Buffer;
  readonly citation_snapshot: unknown;
  readonly evidence_valid: boolean;
}

interface OverrideEvidenceRow {
  readonly evaluation_id: string;
  readonly wizard_draft_id: string;
  readonly final_object_type: string;
  readonly final_object_id: string;
  readonly recommended_rule_id: string | null;
  readonly selected_rule_id: string;
  readonly reason: string;
  readonly citation_snapshot: unknown;
  readonly consent_record_id: string;
  readonly audit_event_id: string;
  readonly canonical_sha256: Buffer;
  readonly package_sha256: Buffer | null;
  readonly consent_payload_sha256: Buffer;
  readonly consent_package_sha256: Buffer | null;
  readonly consent_action_code: string;
  readonly consent_target_type: string;
  readonly consent_target_id: string | null;
  readonly event_type: string | null;
  readonly audit_consent_record_id: string | null;
  readonly audit_object_type: string | null;
  readonly audit_object_id: string | null;
}

export class RuleSelectionEvidenceError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "RuleSelectionEvidenceError";
  }
}

export interface ValidatedRuleSelection {
  readonly evaluationId: string;
  readonly evaluationResultSha256: string;
  readonly selectedRuleId: string;
  readonly selectedRuleSha256: string;
  readonly recommendedRuleId: string | null;
  readonly citations: readonly RuleSelectionCitation[];
  readonly ruleOverrideId: string | null;
  readonly ruleOverrideSha256: string | null;
}

/** Validate original persisted evidence before projecting the authoring format. */
export function validatedRuntimeRuleTemplate(
  payload: unknown,
  persistedTemplateSha256: string,
  persistedApprovalSha256: string
): z.infer<typeof GovernanceRuleTemplatePayloadSchema> {
  if (!safeHashEqual(persistedTemplateSha256, canonicalSha256(payload))) {
    throw new RuleSelectionEvidenceError(
      "persisted template hash does not match its original payload"
    );
  }
  const runtime = GovernanceRuleTemplatePayloadSchema.safeParse(payload);
  if (runtime.success) {
    if (!safeHashEqual(runtime.data.approvalRuleSha256, persistedApprovalSha256)) {
      throw new RuleSelectionEvidenceError("runtime template approval binding is invalid");
    }
    return runtime.data;
  }
  const authored = GovernanceRuleTemplateSchema.parse(payload);
  const approvalSha256 = canonicalSha256({
    schemaVersion: "boardagent.approval-rule.v1",
    approval: authored.approval,
    quorum: authored.quorum,
    approvalDenominator: authored.approvalDenominator,
    abstentionsCountForQuorum: authored.abstentionsCountForQuorum,
    tieBehavior: authored.tieBehavior,
    proxyPolicy: authored.proxyPolicy,
    closeMode: authored.closeMode
  });
  if (!safeHashEqual(approvalSha256, persistedApprovalSha256)) {
    throw new RuleSelectionEvidenceError("authored template approval binding is invalid");
  }
  return GovernanceRuleTemplatePayloadSchema.parse({
    schemaVersion: "boardagent.governance-rule-template.v1",
    approvalRuleSha256: approvalSha256,
    overridePolicy: authored.overridePolicy === "forbidden" ? "forbidden" : "reasoned_within_bounds"
  });
}

export async function loadRuleSelectionEvidence(
  client: PoolClient,
  input: {
    readonly boardId: string;
    readonly profileId: string;
    readonly rulesetId: string;
    readonly approvalRuleId: string;
    readonly evaluationId: string;
    readonly selectedRuleId: string;
  }
): Promise<{
  readonly row: RuleSelectionEvidenceRow;
  readonly resultDetails: z.infer<typeof MatterEvaluationResultDetailsSchema>;
  readonly template: z.infer<typeof GovernanceRuleTemplatePayloadSchema>;
  readonly citations: readonly RuleSelectionCitation[];
}> {
  const result = await client.query<RuleSelectionEvidenceRow>(
    "select * from boardagent_rule_selection_evidence($1,$2,$3,$4,$5,$6)",
    [
      input.boardId,
      input.profileId,
      input.rulesetId,
      input.approvalRuleId,
      input.evaluationId,
      input.selectedRuleId
    ]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1 || !row.evidence_valid) {
    throw new RuleSelectionEvidenceError("rule selection is not permitted by the active profile");
  }
  const resultDetails = MatterEvaluationResultDetailsSchema.parse(row.evaluation_result_details);
  const template = validatedRuntimeRuleTemplate(
    row.selected_template_payload,
    row.selected_template_sha256.toString("hex"),
    row.selected_approval_rule_sha256.toString("hex")
  );
  const resultSha256 = row.evaluation_result_sha256.toString("hex");
  const selectedApprovalRuleSha256 = row.selected_approval_rule_sha256.toString("hex");
  const evaluationShapeValid =
    resultDetails.status === "matched"
      ? resultDetails.matchedRuleId !== null &&
        resultDetails.candidateRuleIds.length === 1 &&
        resultDetails.candidateRuleIds[0] === resultDetails.matchedRuleId &&
        resultDetails.selectedApprovalRuleId === row.selected_approval_rule_id
      : resultDetails.matchedRuleId === null && resultDetails.selectedApprovalRuleId === null;
  if (
    row.evaluation_id !== input.evaluationId ||
    row.selected_rule_id !== input.selectedRuleId ||
    row.selected_approval_rule_id !== input.approvalRuleId ||
    row.evaluation_result !== resultDetails.status ||
    row.recommended_rule_id !== resultDetails.matchedRuleId ||
    resultDetails.profile.id !== input.profileId ||
    resultDetails.ruleset.id !== input.rulesetId ||
    !evaluationShapeValid ||
    canonicalJson(row.evaluation_candidate_rule_ids) !==
      canonicalJson(resultDetails.candidateRuleIds) ||
    !safeHashEqual(resultSha256, canonicalSha256(resultDetails)) ||
    !safeHashEqual(selectedApprovalRuleSha256, template.approvalRuleSha256)
  ) {
    throw new RuleSelectionEvidenceError("matter evaluation failed its persisted evidence binding");
  }
  const citations = z.array(RuleSelectionCitationSchema).min(1).parse(row.citation_snapshot);
  return { row, resultDetails, template, citations };
}

export async function assertPackageRuleSelectionEvidence(
  client: PoolClient,
  input: {
    readonly boardId: string;
    readonly finalVoteId: string;
    readonly decisionPackage: DecisionPackage;
    readonly packageSha256: string;
  }
): Promise<ValidatedRuleSelection> {
  const selection = await loadRuleSelectionEvidence(client, {
    boardId: input.boardId,
    profileId: input.decisionPackage.governanceProfileVersionId,
    rulesetId: input.decisionPackage.rulesetVersionId,
    approvalRuleId: input.decisionPackage.approvalRuleId,
    evaluationId: input.decisionPackage.matterEvaluationId,
    selectedRuleId: input.decisionPackage.selectedRulesetRuleId
  });
  const evaluationResultSha256 = selection.row.evaluation_result_sha256.toString("hex");
  const selectedRuleSha256 = selection.row.selected_rule_sha256.toString("hex");
  if (
    !safeHashEqual(evaluationResultSha256, input.decisionPackage.matterEvaluationResultSha256) ||
    !safeHashEqual(selectedRuleSha256, input.decisionPackage.selectedRulesetRuleSha256)
  ) {
    throw new RuleSelectionEvidenceError("decision package does not bind exact rule evidence");
  }

  const directRecommendation =
    selection.resultDetails.status === "matched" &&
    selection.row.recommended_rule_id === selection.row.selected_rule_id;
  if (directRecommendation) {
    if (input.decisionPackage.ruleOverride !== null) {
      throw new RuleSelectionEvidenceError("recommended rule must not carry override evidence");
    }
    return {
      evaluationId: selection.row.evaluation_id,
      evaluationResultSha256,
      selectedRuleId: selection.row.selected_rule_id,
      selectedRuleSha256,
      recommendedRuleId: selection.row.recommended_rule_id,
      citations: selection.citations,
      ruleOverrideId: null,
      ruleOverrideSha256: null
    };
  }

  const overrideReference = input.decisionPackage.ruleOverride;
  if (
    selection.resultDetails.status !== "matched" ||
    selection.row.recommended_rule_id === null ||
    selection.resultDetails.candidateRuleIds.length !== 1 ||
    selection.resultDetails.candidateRuleIds[0] !== selection.row.recommended_rule_id ||
    selection.resultDetails.selectedApprovalRuleId !== selection.row.selected_approval_rule_id ||
    selection.template.overridePolicy !== "reasoned_within_bounds"
  ) {
    throw new RuleSelectionEvidenceError(
      "failed or nonpermitted matter evaluation cannot be overridden"
    );
  }
  if (!overrideReference) {
    throw new RuleSelectionEvidenceError(
      "nonrecommended rule selection requires confirmed override evidence"
    );
  }
  const overrideResult = await client.query<OverrideEvidenceRow>(
    `select override.evaluation_id,override.wizard_draft_id,override.final_object_type,
            override.final_object_id,override.recommended_rule_id,override.selected_rule_id,
            override.reason,override.citation_snapshot,override.consent_record_id,
            override.audit_event_id,override.canonical_sha256,wizard.package_sha256,
            consent.payload_sha256 as consent_payload_sha256,
            consent.package_sha256 as consent_package_sha256,
            consent.action_code as consent_action_code,
            consent.target_type as consent_target_type,
            consent.target_id as consent_target_id,
            audit.event_type,audit.consent_record_id as audit_consent_record_id,
            audit.object_type as audit_object_type,audit.object_id as audit_object_id
       from rule_overrides as override
       join wizard_drafts as wizard on wizard.id=override.wizard_draft_id
       join consent_records as consent on consent.id=override.consent_record_id
       left join audit_events as audit on audit.id=override.audit_event_id
      where override.id=$1
        and override.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and override.board_id=$2`,
    [overrideReference.id, input.boardId]
  );
  const override = overrideResult.rows[0];
  if (!override || overrideResult.rows.length !== 1) {
    throw new RuleSelectionEvidenceError("rule override evidence is unavailable");
  }
  const overrideCitations = z
    .array(RuleSelectionCitationSchema)
    .min(1)
    .parse(override.citation_snapshot);
  const storedOverrideSha256 = override.canonical_sha256.toString("hex");
  const wizardPackageSha256 = override.package_sha256?.toString("hex") ?? "";
  const consentPackageSha256 = override.consent_package_sha256?.toString("hex") ?? "";
  const expectedConsentPayloadSha256 = ruleOverrideConsentHash({
    evaluationId: override.evaluation_id,
    evaluationResultSha256,
    wizardDraftId: override.wizard_draft_id,
    finalVoteId: override.final_object_id,
    recommendedRuleId: override.recommended_rule_id,
    selectedRuleId: override.selected_rule_id,
    selectedRuleSha256,
    reason: override.reason,
    citations: overrideCitations,
    packageSha256: input.packageSha256
  });
  const consentPayloadSha256 = override.consent_payload_sha256.toString("hex");
  const consentBindsOverrideOrWholePackage =
    safeHashEqual(consentPayloadSha256, expectedConsentPayloadSha256) ||
    safeHashEqual(consentPayloadSha256, input.packageSha256);
  const recomputedOverrideSha256 = ruleOverrideEvidenceHash({
    evaluationId: override.evaluation_id,
    evaluationResultSha256,
    wizardDraftId: override.wizard_draft_id,
    finalVoteId: override.final_object_id,
    recommendedRuleId: override.recommended_rule_id,
    selectedRuleId: override.selected_rule_id,
    selectedRuleSha256,
    reason: override.reason,
    citations: overrideCitations,
    consentRecordId: override.consent_record_id,
    auditEventId: override.audit_event_id
  });
  if (
    override.evaluation_id !== selection.row.evaluation_id ||
    override.final_object_type !== "vote" ||
    override.final_object_id !== input.finalVoteId ||
    override.recommended_rule_id !== selection.row.recommended_rule_id ||
    override.selected_rule_id !== selection.row.selected_rule_id ||
    override.event_type !== "rule_overridden" ||
    override.audit_consent_record_id !== override.consent_record_id ||
    override.audit_object_type !== "rule_override" ||
    override.audit_object_id !== overrideReference.id ||
    override.consent_action_code !== "create_vote" ||
    override.consent_target_type !== "vote" ||
    override.consent_target_id !== input.finalVoteId ||
    !safeHashEqual(wizardPackageSha256, input.packageSha256) ||
    !safeHashEqual(consentPackageSha256, input.packageSha256) ||
    !consentBindsOverrideOrWholePackage ||
    canonicalJson(overrideCitations) !== canonicalJson(selection.citations) ||
    !safeHashEqual(storedOverrideSha256, overrideReference.canonicalSha256) ||
    !safeHashEqual(storedOverrideSha256, recomputedOverrideSha256)
  ) {
    throw new RuleSelectionEvidenceError("rule override failed its exact evidence binding");
  }
  return {
    evaluationId: selection.row.evaluation_id,
    evaluationResultSha256,
    selectedRuleId: selection.row.selected_rule_id,
    selectedRuleSha256,
    recommendedRuleId: selection.row.recommended_rule_id,
    citations: selection.citations,
    ruleOverrideId: overrideReference.id,
    ruleOverrideSha256: storedOverrideSha256
  };
}
