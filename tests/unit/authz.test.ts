import { describe, expect, it } from "vitest";

import { authorize, type AuthorizationContext } from "../../lib/authz/src/authorize.js";

const observer: AuthorizationContext = {
  memberId: "observer",
  active: true,
  onboardingCurrent: true,
  roles: new Set(["observer"]),
  scopes: new Set([
    "governance:read",
    "management:question",
    "minutes:act",
    "notifications:manage"
  ]),
  memberBoardIds: new Set(["board"])
};

const object = {
  boardId: "board",
  ownerMemberId: "observer",
  visible: true,
  recused: false,
  terminal: false
};

describe("deny-wins authorization", () => {
  it("returns every deny reason before allowing a request", () => {
    const request = {
      toolName: "list_my_boards",
      actionClass: "R" as const,
      requiredScopes: ["governance:read"] as const,
      ownPlatformSelfService: false,
      allowTerminalRead: true
    };

    expect(authorize({ ...observer, active: false }, object, request)).toEqual({
      allowed: false,
      reason: "inactive_identity"
    });
    expect(authorize({ ...observer, onboardingCurrent: false }, object, request)).toEqual({
      allowed: false,
      reason: "onboarding_required"
    });
    expect(authorize({ ...observer, scopes: new Set() }, object, request)).toEqual({
      allowed: false,
      reason: "missing_scope"
    });
    expect(authorize(observer, object, { ...request, requiredAnyRoles: ["admin"] })).toEqual({
      allowed: false,
      reason: "missing_role"
    });
    expect(authorize(observer, { ...object, visible: false }, request)).toEqual({
      allowed: false,
      reason: "object_absent"
    });
    expect(authorize(observer, { ...object, recused: true }, request)).toEqual({
      allowed: false,
      reason: "recused"
    });
    expect(authorize(observer, { ...object, boardId: "board-b" }, request)).toEqual({
      allowed: false,
      reason: "outside_board"
    });
    expect(
      authorize(observer, { ...object, boardId: null }, { ...request, requiredAnyRoles: [] })
    ).toEqual({ allowed: true });
    expect(
      authorize(observer, object, {
        ...request,
        actionClass: "D",
        toolName: "stage_ballot",
        allowTerminalRead: false
      })
    ).toEqual({ allowed: false, reason: "observer_denied" });
    expect(
      authorize(
        { ...observer, roles: new Set(["member"]) },
        { ...object, terminal: true },
        { ...request, actionClass: "D", allowTerminalRead: false }
      )
    ).toEqual({ allowed: false, reason: "terminal" });
    expect(
      authorize({ ...observer, roles: new Set(["member"]) }, object, {
        ...request,
        requiredAnyRoles: ["member"]
      })
    ).toEqual({ allowed: true });
  });

  it("allows only the six observer governance exceptions", () => {
    expect(
      authorize(observer, object, {
        toolName: "ask_management",
        actionClass: "D",
        requiredScopes: ["management:question"],
        ownPlatformSelfService: false,
        allowTerminalRead: false
      }).allowed
    ).toBe(true);
    expect(
      authorize(observer, object, {
        toolName: "stage_ballot",
        actionClass: "H",
        requiredScopes: ["governance:read"],
        ownPlatformSelfService: false,
        allowTerminalRead: false
      })
    ).toEqual({ allowed: false, reason: "observer_denied" });
  });

  it("allows exact own security self-service and blocks another identity", () => {
    const request = {
      toolName: "revoke_my_session",
      actionClass: "D" as const,
      requiredScopes: [] as const,
      ownPlatformSelfService: true,
      allowTerminalRead: false
    };
    expect(authorize(observer, object, request).allowed).toBe(true);
    expect(authorize(observer, { ...object, ownerMemberId: "someone-else" }, request)).toEqual({
      allowed: false,
      reason: "not_owner"
    });
  });

  it("does not infer platform self-service from a tool name without the policy flag", () => {
    expect(
      authorize(observer, object, {
        toolName: "configure_webhook",
        actionClass: "D",
        requiredScopes: ["notifications:manage"],
        ownPlatformSelfService: false,
        allowTerminalRead: false
      })
    ).toEqual({ allowed: false, reason: "observer_denied" });
  });

  it("allows a terminal read even when the mutation-only correction flag is false", () => {
    expect(
      authorize(
        { ...observer, roles: new Set(["member"]) },
        { ...object, terminal: true },
        {
          toolName: "get_task",
          actionClass: "R",
          requiredScopes: ["governance:read"],
          ownPlatformSelfService: false,
          allowTerminalRead: false
        }
      )
    ).toEqual({ allowed: true });
  });

  it("makes recusal indistinguishable from object absence before role privilege", () => {
    expect(
      authorize(
        observer,
        { ...object, recused: true },
        {
          toolName: "read_document",
          actionClass: "R",
          requiredScopes: ["governance:read"],
          ownPlatformSelfService: false,
          allowTerminalRead: true
        }
      )
    ).toEqual({ allowed: false, reason: "recused" });
  });
});
