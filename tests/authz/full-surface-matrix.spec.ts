import { describe, expect, it } from "vitest";

import { BOARDAGENT_REGISTRY } from "../../lib/contracts/src/index.js";
import {
  authorize,
  policyForTool,
  type AuthorizationContext,
  type OrganizationRole,
  type Scope
} from "../../lib/authz/src/index.js";

const ALL_SCOPES: readonly Scope[] = [
  "governance:read",
  "documents:read",
  "vote:act",
  "proxy:manage",
  "minutes:act",
  "member:propose",
  "secretariat:admin",
  "audit:read",
  "meeting:act",
  "task:act",
  "documents:contribute",
  "secretariat:message",
  "management:question",
  "notifications:manage",
  "onboarding:read"
];

const EXPECTED_ROLE_TOOLS = [
  {
    roles: ["admin"],
    tools: [
      "archive_board",
      "block_oauth_client",
      "configure_board_governance",
      "create_board",
      "export_system_data",
      "link_external_identity",
      "list_oauth_clients",
      "manage_member_admin_delegation",
      "manage_ruleset",
      "publish_onboarding_terms",
      "soft_delete_document",
      "unblock_oauth_client",
      "unlink_external_identity",
      "update_board"
    ]
  },
  {
    roles: ["secretariat", "admin"],
    tools: [
      "archive_document",
      "confirm_enrollment_activation",
      "evaluate_matter",
      "get_member",
      "initiate_identity_recovery",
      "issue_enrollment",
      "list_enrollments",
      "list_members",
      "manage_member",
      "manage_document_access",
      "manage_recusal",
      "publish_secretary_support",
      "reissue_activation",
      "revoke_enrollment",
      "validate_ruleset_draft"
    ]
  },
  {
    roles: ["secretariat"],
    tools: [
      "amend_meeting",
      "amend_resolution_text",
      "approve_management_submission",
      "cancel_meeting",
      "cancel_minutes",
      "cancel_task",
      "cancel_vote",
      "circulate_document",
      "close_vote",
      "complete_meeting",
      "complete_task",
      "correct_attendance",
      "correct_minutes_package",
      "create_meeting",
      "create_meeting_transcript_version",
      "create_minutes_correction_cycle",
      "create_minutes_version",
      "create_task",
      "create_task_correction_cycle",
      "create_vote",
      "declare_no_minutes_action_items",
      "exclude_pending_vote_source",
      "extend_vote_deadline",
      "finalize_minutes",
      "link_meeting_qna",
      "list_proposals",
      "log_minutes_action_items",
      "prepare_minutes_for_signature",
      "publish_minutes",
      "record_attendance",
      "reject_management_submission",
      "replace_open_vote",
      "reply_secretariat_request",
      "request_management_revision",
      "resolve_minutes_review_item",
      "resolve_transcript_challenge",
      "review_task_evidence",
      "verify_meeting_transcript"
    ]
  },
  {
    roles: ["management"],
    tools: [
      "answer_management_question",
      "reply_to_management_revision",
      "resubmit_management_materials",
      "submit_document_to_secretariat"
    ]
  },
  {
    roles: ["member", "observer"],
    tools: [
      "ask_management",
      "comment_minutes",
      "follow_up_management_question",
      "propose_minutes_redline",
      "stage_minutes_signature",
      "withdraw_minutes_comment"
    ]
  },
  {
    roles: ["member", "management"],
    tools: ["ask_secretariat", "propose_action"]
  }
] as const satisfies readonly {
  readonly roles: readonly OrganizationRole[];
  readonly tools: readonly string[];
}[];

function actor(roles: readonly OrganizationRole[], onboardingCurrent = true): AuthorizationContext {
  return {
    memberId: "member-a",
    active: true,
    onboardingCurrent,
    roles: new Set(roles),
    scopes: new Set(ALL_SCOPES),
    memberBoardIds: new Set(["board-a"])
  };
}

const object = {
  boardId: "board-a",
  ownerMemberId: "member-a",
  visible: true,
  recused: false,
  terminal: false
};

describe("generated full-surface authorization policy", () => {
  it.each(["secretariat", "management", "member", "observer"] as const)(
    "denies the OAuth client directory to non-admin %s despite the administrative scope",
    (role) => {
      expect(authorize(actor([role]), object, policyForTool("list_oauth_clients"))).toEqual({
        allowed: false,
        reason: "missing_role"
      });
    }
  );

  it("allows the OAuth client directory to an admin with the administrative scope", () => {
    expect(authorize(actor(["admin"]), object, policyForTool("list_oauth_clients"))).toEqual({
      allowed: true
    });
  });

  it("denies the OAuth client directory to an admin without the administrative scope", () => {
    const administrator = { ...actor(["admin"]), scopes: new Set<Scope>(["governance:read"]) };
    expect(authorize(administrator, object, policyForTool("list_oauth_clients"))).toEqual({
      allowed: false,
      reason: "missing_scope"
    });
  });

  it("maps every frozen tool exactly once without changing its action class", () => {
    const policies = BOARDAGENT_REGISTRY.tools.map(({ name }) => policyForTool(name));
    const added = new Set([
      "manage_company_admin",
      "manage_member_admin_delegation",
      "list_administrative_access",
      "publish_secretary_support",
      "publish_onboarding_terms",
      "reissue_activation"
    ]);
    const original = policies.filter(({ toolName }) => !added.has(toolName));
    expect(original).toHaveLength(148);
    expect(new Set(original.map(({ toolName }) => toolName)).size).toBe(148);
    expect(policies).toHaveLength(154);
    expect(new Set(policies.map(({ toolName }) => toolName)).size).toBe(154);
    expect(
      Object.fromEntries(
        ["R", "D", "H"].map((kind) => [
          kind,
          original.filter(({ actionClass }) => actionClass === kind).length
        ])
      )
    ).toEqual({ R: 57, D: 30, H: 61 });
    expect(
      Object.fromEntries(
        ["R", "D", "H"].map((kind) => [
          kind,
          policies.filter(({ actionClass }) => actionClass === kind).length
        ])
      )
    ).toEqual({ R: 58, D: 30, H: 66 });
    for (const entry of BOARDAGENT_REGISTRY.tools) {
      expect(policyForTool(entry.name).actionClass).toBe(entry.class);
    }
    expect(() => policyForTool("hidden_backdoor")).toThrow("unregistered BoardAgent tool");
  });

  it("maps every frozen scope abbreviation to the OAuth ceiling", () => {
    expect(policyForTool("list_my_boards").requiredScopes).toEqual(["governance:read"]);
    expect(policyForTool("read_document").requiredScopes).toEqual(["documents:read"]);
    expect(policyForTool("stage_ballot").requiredScopes).toEqual(["vote:act"]);
    expect(policyForTool("grant_proxy").requiredScopes).toEqual(["proxy:manage"]);
    expect(policyForTool("comment_minutes").requiredScopes).toEqual(["minutes:act"]);
    expect(policyForTool("propose_action").requiredScopes).toEqual(["member:propose"]);
    expect(policyForTool("create_board").requiredScopes).toEqual(["secretariat:admin"]);
    expect(policyForTool("export_audit_chain").requiredScopes).toEqual(["audit:read"]);
    expect(policyForTool("rsvp").requiredScopes).toEqual(["meeting:act"]);
    expect(policyForTool("start_task").requiredScopes).toEqual(["task:act"]);
    expect(policyForTool("create_document_version").requiredScopes).toEqual([
      "documents:contribute"
    ]);
    expect(policyForTool("ask_secretariat").requiredScopes).toEqual(["secretariat:message"]);
    expect(policyForTool("ask_management").requiredScopes).toEqual(["management:question"]);
    expect(policyForTool("configure_webhook").requiredScopes).toEqual(["notifications:manage"]);
    expect(policyForTool("get_onboarding").requiredScopes).toEqual(["onboarding:read"]);
  });

  it("maps the complete frozen role and terminal-correction matrices exactly", () => {
    for (const { roles, tools } of EXPECTED_ROLE_TOOLS) {
      expect(
        BOARDAGENT_REGISTRY.tools
          .filter(({ name }) =>
            Object.is(policyForTool(name).requiredAnyRoles?.join("\0"), roles.join("\0"))
          )
          .map(({ name }) => name)
          .toSorted()
      ).toEqual([...tools].toSorted());
    }

    const roleGated = new Set<string>(EXPECTED_ROLE_TOOLS.flatMap(({ tools }) => tools));
    for (const { name } of BOARDAGENT_REGISTRY.tools.filter(({ name }) => !roleGated.has(name))) {
      expect(policyForTool(name).requiredAnyRoles).toBeUndefined();
      expect(policyForTool(name)).not.toHaveProperty("requiredAnyRoles");
    }
    expect(
      BOARDAGENT_REGISTRY.tools
        .filter(({ name, class: actionClass }) =>
          actionClass === "R" ? !policyForTool(name).allowTerminalRead : false
        )
        .map(({ name }) => name)
    ).toEqual([]);
    expect(
      BOARDAGENT_REGISTRY.tools
        .filter(({ class: actionClass }) => actionClass !== "R")
        .filter(({ name }) => policyForTool(name).allowTerminalRead)
        .map(({ name }) => name)
        .toSorted()
    ).toEqual(["create_minutes_correction_cycle", "create_task_correction_cycle"]);
  });

  it("enforces role gates in addition to scopes", () => {
    expect(
      authorize(actor(["secretariat"]), object, policyForTool("manage_member_admin_delegation"))
    ).toEqual({ allowed: false, reason: "missing_role" });
    expect(
      authorize(actor(["admin"]), object, policyForTool("manage_member_admin_delegation"))
    ).toEqual({ allowed: true });
    // Named non-admin acceptance is resolved by the live database operation, with
    // the S:A ceiling and observer denial still enforced by the shared kernel.
    expect(policyForTool("manage_company_admin").requiredAnyRoles).toBeUndefined();
    expect(policyForTool("manage_company_admin").requiredScopes).toEqual(["secretariat:admin"]);
    expect(authorize(actor(["observer"]), object, policyForTool("manage_company_admin"))).toEqual({
      allowed: false,
      reason: "observer_denied"
    });
    expect(authorize(actor(["secretariat"]), object, policyForTool("create_board"))).toEqual({
      allowed: false,
      reason: "missing_role"
    });
    expect(authorize(actor(["admin"]), object, policyForTool("create_board"))).toEqual({
      allowed: true
    });
    expect(
      authorize(actor(["member"]), object, policyForTool("resolve_minutes_review_item"))
    ).toEqual({ allowed: false, reason: "missing_role" });
    expect(
      authorize(actor(["secretariat"]), object, policyForTool("resolve_minutes_review_item"))
    ).toEqual({ allowed: true });
    expect(
      authorize(actor(["management"]), object, policyForTool("answer_management_question"))
    ).toEqual({
      allowed: true
    });
  });

  it("keeps only identity and onboarding reads available while onboarding is stale", () => {
    const stale = actor(["member"], false);
    for (const allowed of [
      "whoami",
      "get_onboarding",
      "get_onboarding_status",
      "prepare_onboarding_attestation"
    ]) {
      expect(authorize(stale, object, policyForTool(allowed))).toEqual({ allowed: true });
    }
    expect(authorize(stale, object, policyForTool("list_my_boards"))).toEqual({
      allowed: false,
      reason: "onboarding_required"
    });
  });

  it("permits terminal reads and only the two linked correction mutations", () => {
    const terminal = { ...object, terminal: true };
    expect(authorize(actor(["member"]), terminal, policyForTool("get_task"))).toEqual({
      allowed: true
    });
    expect(
      authorize(actor(["secretariat"]), terminal, policyForTool("create_task_correction_cycle"))
    ).toEqual({ allowed: true });
    expect(authorize(actor(["secretariat"]), terminal, policyForTool("cancel_task"))).toEqual({
      allowed: false,
      reason: "terminal"
    });
  });
});
