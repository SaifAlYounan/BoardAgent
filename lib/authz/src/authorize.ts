export type OrganizationRole = "admin" | "secretariat" | "management" | "member" | "observer";
export type Scope =
  | "governance:read"
  | "documents:read"
  | "vote:act"
  | "proxy:manage"
  | "minutes:act"
  | "member:propose"
  | "secretariat:admin"
  | "audit:read"
  | "meeting:act"
  | "task:act"
  | "documents:contribute"
  | "secretariat:message"
  | "management:question"
  | "notifications:manage"
  | "onboarding:read";

export type ActionClass = "R" | "D" | "H";

export const OBSERVER_PLATFORM_SELF_SERVICE = new Set([
  "prepare_onboarding_attestation",
  "revoke_my_session",
  "configure_webhook",
  "rotate_webhook_secret",
  "disable_webhook",
  "test_webhook"
]);

export const OBSERVER_GOVERNANCE_EXCEPTIONS = new Set([
  "ask_management",
  "follow_up_management_question",
  "comment_minutes",
  "withdraw_minutes_comment",
  "propose_minutes_redline",
  "stage_minutes_signature"
]);

export const ONBOARDING_ALLOWED_WHEN_STALE = new Set([
  "whoami",
  "get_onboarding",
  "get_onboarding_status",
  "prepare_onboarding_attestation"
]);

export interface AuthorizationContext {
  readonly memberId: string;
  readonly active: boolean;
  readonly onboardingCurrent: boolean;
  readonly roles: ReadonlySet<OrganizationRole>;
  readonly scopes: ReadonlySet<Scope>;
  readonly memberBoardIds: ReadonlySet<string>;
}

export interface ObjectContext {
  readonly boardId: string | null;
  readonly ownerMemberId: string | null;
  readonly visible: boolean;
  readonly recused: boolean;
  readonly terminal: boolean;
}

export interface AuthorizationRequest {
  readonly toolName: string;
  readonly actionClass: ActionClass;
  readonly requiredScopes: readonly Scope[];
  readonly requiredAnyAuthority?: readonly {
    readonly scopes: readonly Scope[];
    readonly roles?: readonly OrganizationRole[];
  }[];
  readonly requiredAnyRoles?: readonly OrganizationRole[];
  readonly ownPlatformSelfService: boolean;
  readonly allowTerminalRead: boolean;
}

export type AuthorizationDecision =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly reason:
        | "inactive_identity"
        | "onboarding_required"
        | "missing_scope"
        | "missing_role"
        | "object_absent"
        | "outside_board"
        | "recused"
        | "observer_denied"
        | "not_owner"
        | "terminal";
    };

export function authorize(
  actor: AuthorizationContext,
  object: ObjectContext,
  request: AuthorizationRequest
): AuthorizationDecision {
  if (!actor.active) return { allowed: false, reason: "inactive_identity" };
  if (!actor.onboardingCurrent && !ONBOARDING_ALLOWED_WHEN_STALE.has(request.toolName)) {
    return { allowed: false, reason: "onboarding_required" };
  }
  if (request.requiredScopes.some((scope) => !actor.scopes.has(scope))) {
    return { allowed: false, reason: "missing_scope" };
  }
  if (request.requiredAnyAuthority !== undefined) {
    const scopeMatches = request.requiredAnyAuthority.filter((alternative) =>
      alternative.scopes.every((scope) => actor.scopes.has(scope))
    );
    if (scopeMatches.length === 0) return { allowed: false, reason: "missing_scope" };
    if (
      !scopeMatches.some(
        (alternative) =>
          alternative.roles === undefined || alternative.roles.some((role) => actor.roles.has(role))
      )
    )
      return { allowed: false, reason: "missing_role" };
  }
  if (
    request.requiredAnyRoles !== undefined &&
    request.requiredAnyRoles.length > 0 &&
    !request.requiredAnyRoles.some((role) => actor.roles.has(role))
  ) {
    return { allowed: false, reason: "missing_role" };
  }
  if (!object.visible) return { allowed: false, reason: "object_absent" };
  if (object.recused) return { allowed: false, reason: "recused" };
  if (object.boardId !== null && !actor.memberBoardIds.has(object.boardId)) {
    return { allowed: false, reason: "outside_board" };
  }
  if (request.ownPlatformSelfService && object.ownerMemberId !== actor.memberId) {
    return { allowed: false, reason: "not_owner" };
  }
  if (actor.roles.has("observer") && request.actionClass !== "R") {
    const platformAllowed =
      request.ownPlatformSelfService && OBSERVER_PLATFORM_SELF_SERVICE.has(request.toolName);
    const governanceAllowed = OBSERVER_GOVERNANCE_EXCEPTIONS.has(request.toolName);
    if (!platformAllowed && !governanceAllowed)
      return { allowed: false, reason: "observer_denied" };
  }
  if (object.terminal && request.actionClass !== "R" && !request.allowTerminalRead) {
    return { allowed: false, reason: "terminal" };
  }
  return { allowed: true };
}
