import { BOARDAGENT_TOOL_BY_NAME, type ToolClass } from "@boardagent/contracts";

import {
  OBSERVER_PLATFORM_SELF_SERVICE,
  type AuthorizationRequest,
  type OrganizationRole,
  type Scope
} from "./authorize.js";

function scopesFromAuthority(authority: string): Scope[] {
  // Keep the frozen abbreviation table inside the callable boundary for the
  // same reason as the role cases below: every mutation must be activated by
  // the policy call that its independent matrix assertion exercises.
  const scopeCode = Object.freeze({
    "G:R": "governance:read",
    "D:R": "documents:read",
    "V:A": "vote:act",
    "P:M": "proxy:manage",
    "M:A": "minutes:act",
    MP: "member:propose",
    "S:A": "secretariat:admin",
    "A:R": "audit:read",
    "MT:A": "meeting:act",
    "T:A": "task:act",
    "D:C": "documents:contribute",
    "S:M": "secretariat:message",
    MQ: "management:question",
    "N:M": "notifications:manage",
    "O:R": "onboarding:read"
  } satisfies Record<string, Scope>);
  const result: Scope[] = [];
  for (const [code, scope] of Object.entries(scopeCode)) {
    if (authority.includes(`\`${code}\``)) result.push(scope);
  }
  return result;
}

function rolesForTool(toolName: string): readonly OrganizationRole[] | undefined {
  // Keep the frozen cases inside the callable boundary. Besides avoiding a
  // mutable exported table, this lets mutation execution activate one exact
  // policy case before evaluation instead of losing module-initializer mutants
  // to the Vitest module cache.
  switch (toolName) {
    case "publish_onboarding_terms":
    case "create_board":
    case "update_board":
    case "archive_board":
    case "configure_board_governance":
    case "manage_ruleset":
    case "soft_delete_document":
    case "manage_member_admin_delegation":
    case "list_oauth_clients":
    case "block_oauth_client":
    case "unblock_oauth_client":
    case "link_external_identity":
    case "unlink_external_identity":
    case "export_system_data":
      return ["admin"];
    case "publish_secretary_support":
    case "evaluate_matter":
    case "validate_ruleset_draft":
    case "manage_document_access":
    case "manage_recusal":
    case "archive_document":
    case "list_members":
    case "manage_member":
    case "get_member":
    case "issue_enrollment":
    case "reissue_activation":
    case "list_enrollments":
    case "revoke_enrollment":
    case "confirm_enrollment_activation":
    case "initiate_identity_recovery":
      return ["secretariat", "admin"];
    case "circulate_document":
    case "request_management_revision":
    case "approve_management_submission":
    case "reject_management_submission":
    case "create_meeting":
    case "amend_meeting":
    case "record_attendance":
    case "correct_attendance":
    case "cancel_meeting":
    case "complete_meeting":
    case "create_meeting_transcript_version":
    case "verify_meeting_transcript":
    case "link_meeting_qna":
    case "resolve_transcript_challenge":
    case "create_vote":
    case "amend_resolution_text":
    case "replace_open_vote":
    case "exclude_pending_vote_source":
    case "extend_vote_deadline":
    case "close_vote":
    case "cancel_vote":
    case "create_minutes_version":
    case "publish_minutes":
    case "resolve_minutes_review_item":
    case "correct_minutes_package":
    case "prepare_minutes_for_signature":
    case "finalize_minutes":
    case "create_minutes_correction_cycle":
    case "cancel_minutes":
    case "log_minutes_action_items":
    case "declare_no_minutes_action_items":
    case "create_task":
    case "review_task_evidence":
    case "complete_task":
    case "create_task_correction_cycle":
    case "cancel_task":
    case "list_proposals":
    case "reply_secretariat_request":
      return ["secretariat"];
    case "submit_document_to_secretariat":
    case "reply_to_management_revision":
    case "resubmit_management_materials":
    case "answer_management_question":
      return ["management"];
    case "ask_management":
    case "follow_up_management_question":
    case "comment_minutes":
    case "withdraw_minutes_comment":
    case "propose_minutes_redline":
    case "stage_minutes_signature":
      return ["member", "observer"];
    case "propose_action":
    case "ask_secretariat":
      return ["member", "management"];
  }
  // AuthorizationRequest intentionally models an absent role gate as
  // optional. Avoid manufacturing an equivalent empty-array fallback.
  return undefined;
}

function isTerminalCorrection(toolName: string): boolean {
  return (
    toolName === "create_minutes_correction_cycle" || toolName === "create_task_correction_cycle"
  );
}

export interface SurfaceAuthorizationPolicy extends AuthorizationRequest {
  readonly actionClass: ToolClass;
}

export function policyForTool(toolName: string): SurfaceAuthorizationPolicy {
  const registryEntry = BOARDAGENT_TOOL_BY_NAME.get(toolName);
  if (!registryEntry) throw new Error(`unregistered BoardAgent tool: ${toolName}`);
  const requiredAnyRoles = rolesForTool(toolName);
  // These are explicit alternatives in the frozen authority matrix. Collecting
  // every abbreviation as a mandatory scope would silently turn OR into AND.
  const requiredAnyAuthority: AuthorizationRequest["requiredAnyAuthority"] =
    toolName === "get_vote_certificate"
      ? [{ scopes: ["governance:read"] }, { scopes: ["audit:read"] }]
      : toolName === "get_retention_policy"
        ? [{ scopes: ["audit:read"] }, { scopes: ["secretariat:admin"], roles: ["admin"] }]
        : undefined;
  const common = {
    toolName,
    actionClass: registryEntry.class,
    ...(requiredAnyRoles === undefined ? {} : { requiredAnyRoles }),
    ownPlatformSelfService: OBSERVER_PLATFORM_SELF_SERVICE.has(toolName),
    allowTerminalRead: registryEntry.class === "R" || isTerminalCorrection(toolName)
  };
  if (requiredAnyAuthority === undefined) {
    return { ...common, requiredScopes: scopesFromAuthority(registryEntry.requiredAuthority) };
  }
  return { ...common, requiredScopes: [], requiredAnyAuthority };
}

export function policyForMemberRead(
  actorMemberId: string,
  targetMemberId: string
): SurfaceAuthorizationPolicy {
  const policy = policyForTool("get_member");
  // The frozen authority is own identity OR administrative role plus S:A.
  // Live identity, onboarding and SQL recovery-credential restrictions still apply.
  return actorMemberId === targetMemberId
    ? { ...policy, requiredScopes: [], requiredAnyRoles: [] }
    : policy;
}
