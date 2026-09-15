import { describe, expect, it } from "vitest";
import {
  authorize,
  policyForMemberRead,
  policyForTool,
  type AuthorizationContext,
  type OrganizationRole,
  type Scope
} from "../../lib/authz/src/index.js";

const object = {
  boardId: "board",
  ownerMemberId: null,
  visible: true,
  recused: false,
  terminal: true
};
const actor = (
  scopes: readonly Scope[],
  roles: readonly OrganizationRole[] = ["member"]
): AuthorizationContext => ({
  memberId: "member",
  active: true,
  onboardingCurrent: true,
  roles: new Set(roles),
  scopes: new Set(scopes),
  memberBoardIds: new Set(["board"])
});

describe("frozen alternative read authority", () => {
  it("allows an ordinary member's own identity without the administrative scope", () => {
    const request = policyForMemberRead("member", "member");
    expect(authorize(actor(["governance:read"]), object, request)).toEqual({ allowed: true });
  });

  it("retains role and scope requirements for another member's identity", () => {
    const request = policyForMemberRead("member", "another-member");
    expect(authorize(actor(["governance:read"]), object, request)).toEqual({
      allowed: false,
      reason: "missing_scope"
    });
    expect(authorize(actor(["secretariat:admin"]), object, request)).toEqual({
      allowed: false,
      reason: "missing_role"
    });
    expect(authorize(actor(["secretariat:admin"], ["admin"]), object, request)).toEqual({
      allowed: true
    });
  });

  it("keeps inactive and stale own-identity reads denied", () => {
    const request = policyForMemberRead("member", "member");
    expect(authorize({ ...actor(["governance:read"]), active: false }, object, request)).toEqual({
      allowed: false,
      reason: "inactive_identity"
    });
    expect(
      authorize({ ...actor(["governance:read"]), onboardingCurrent: false }, object, request)
    ).toEqual({
      allowed: false,
      reason: "onboarding_required"
    });
  });

  it("keeps the normal document-read scope mandatory for an otherwise entitled member", () => {
    const request = policyForTool("read_document");
    expect(authorize(actor([]), object, request)).toEqual({
      allowed: false,
      reason: "missing_scope"
    });
    expect(authorize(actor(["documents:read"]), object, request)).toEqual({ allowed: true });
  });
  it("requires every scope in an authority alternative and any one of its permitted roles", () => {
    const request = {
      ...policyForTool("get_retention_policy"),
      requiredAnyAuthority: [
        {
          scopes: ["audit:read", "governance:read"] as Scope[],
          roles: ["admin", "secretariat"] as OrganizationRole[]
        }
      ]
    };
    for (const role of ["admin", "secretariat"] as const) {
      expect(authorize(actor(["audit:read", "governance:read"], [role]), object, request)).toEqual({
        allowed: true
      });
      for (const scope of ["audit:read", "governance:read"] as const)
        expect(authorize(actor([scope], [role]), object, request)).toEqual({
          allowed: false,
          reason: "missing_scope"
        });
    }
    expect(
      authorize(actor(["audit:read", "governance:read"], ["member"]), object, request)
    ).toEqual({ allowed: false, reason: "missing_role" });
  });

  it.each(["governance:read", "audit:read"] as const)(
    "certificate accepts %s independently without dropping board or recusal checks",
    (scope) => {
      const request = policyForTool("get_vote_certificate");
      expect(authorize(actor([scope]), object, request)).toEqual({ allowed: true });
      expect(authorize(actor([scope]), { ...object, boardId: "foreign" }, request)).toEqual({
        allowed: false,
        reason: "outside_board"
      });
      expect(authorize(actor([scope]), { ...object, recused: true }, request)).toEqual({
        allowed: false,
        reason: "recused"
      });
      expect(authorize(actor([scope]), { ...object, visible: false }, request)).toEqual({
        allowed: false,
        reason: "object_absent"
      });
    }
  );
  it("certificate refuses no scope, unrelated scopes, inactive or stale actors", () => {
    const request = policyForTool("get_vote_certificate");
    for (const scopes of [[], ["documents:read"], ["secretariat:admin"]] as const) {
      expect(authorize(actor(scopes), object, request)).toEqual({
        allowed: false,
        reason: "missing_scope"
      });
    }
    expect(authorize({ ...actor(["audit:read"]), active: false }, object, request)).toEqual({
      allowed: false,
      reason: "inactive_identity"
    });
    expect(
      authorize({ ...actor(["governance:read"]), onboardingCurrent: false }, object, request)
    ).toEqual({ allowed: false, reason: "onboarding_required" });
  });
  it("retention permits audit scope or administrator plus secretariat scope, never secretary alone", () => {
    const request = policyForTool("get_retention_policy");
    const deployment = { ...object, boardId: null };
    expect(authorize(actor(["audit:read"]), deployment, request)).toEqual({ allowed: true });
    expect(authorize(actor(["secretariat:admin"], ["admin"]), deployment, request)).toEqual({
      allowed: true
    });
    expect(authorize(actor(["secretariat:admin"], ["secretariat"]), deployment, request)).toEqual({
      allowed: false,
      reason: "missing_role"
    });
    expect(authorize(actor([], ["admin"]), deployment, request)).toEqual({
      allowed: false,
      reason: "missing_scope"
    });
    expect(authorize(actor(["governance:read"], ["admin"]), deployment, request)).toEqual({
      allowed: false,
      reason: "missing_scope"
    });
  });
  it("accepts one satisfied alternative when a second scope-matched alternative lacks its role", () => {
    // Frozen matrix: audit scope alone OR administrator plus secretariat scope. A secretary
    // holding both scopes matches both alternatives by scope and satisfies the first outright;
    // the role-bearing alternative must not veto it (any alternative suffices, never all).
    const request = policyForTool("get_retention_policy");
    const deployment = { ...object, boardId: null };
    expect(
      authorize(actor(["audit:read", "secretariat:admin"], ["secretariat"]), deployment, request)
    ).toEqual({ allowed: true });
    expect(
      authorize(actor(["audit:read", "secretariat:admin"], ["member"]), deployment, request)
    ).toEqual({ allowed: true });
    const twoRoleBound = {
      ...request,
      requiredAnyAuthority: [
        { scopes: ["audit:read"] as Scope[], roles: ["admin"] as OrganizationRole[] },
        { scopes: ["secretariat:admin"] as Scope[], roles: ["secretariat"] as OrganizationRole[] }
      ]
    };
    for (const role of ["admin", "secretariat"] as const)
      expect(
        authorize(actor(["audit:read", "secretariat:admin"], [role]), deployment, twoRoleBound)
      ).toEqual({ allowed: true });
    expect(
      authorize(actor(["audit:read", "secretariat:admin"], ["member"]), deployment, twoRoleBound)
    ).toEqual({ allowed: false, reason: "missing_role" });
  });
});
