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
const ALL_ROLES: readonly OrganizationRole[] = [
  "admin",
  "secretariat",
  "management",
  "member",
  "observer"
];
const SELF_AND_ONBOARDING = new Set([
  "whoami",
  "get_onboarding",
  "get_onboarding_status",
  "prepare_onboarding_attestation"
]);

function actor(overrides: Partial<AuthorizationContext> = {}): AuthorizationContext {
  return {
    memberId: "member-a",
    active: true,
    onboardingCurrent: false,
    roles: new Set(ALL_ROLES),
    scopes: new Set(ALL_SCOPES),
    memberBoardIds: new Set(["board-a"]),
    ...overrides
  };
}

const ownBoard = {
  boardId: "board-a",
  ownerMemberId: "member-a",
  visible: true,
  recused: false,
  terminal: false
};

describe("TH-47 stale or forged onboarding bypass", () => {
  it("denies every ordinary frozen tool even when stale credentials claim every scope and role", () => {
    const decisions = new Map(
      BOARDAGENT_REGISTRY.tools.map(({ name }) => [
        name,
        authorize(actor(), ownBoard, policyForTool(name))
      ])
    );

    expect(
      [...decisions]
        .filter(([, decision]) => decision.allowed)
        .map(([name]) => name)
        .toSorted()
    ).toEqual([...SELF_AND_ONBOARDING].toSorted());
    for (const [name, decision] of decisions) {
      if (!SELF_AND_ONBOARDING.has(name)) {
        expect(decision, name).toEqual({ allowed: false, reason: "onboarding_required" });
      }
    }
  });

  it("does not let an inactive or foreign principal prepare another member's ceremony", () => {
    const policy = policyForTool("prepare_onboarding_attestation");
    expect(authorize(actor({ active: false }), ownBoard, policy)).toEqual({
      allowed: false,
      reason: "inactive_identity"
    });
    expect(authorize(actor({ memberBoardIds: new Set(["board-b"]) }), ownBoard, policy)).toEqual({
      allowed: false,
      reason: "outside_board"
    });
    expect(authorize(actor(), { ...ownBoard, ownerMemberId: "victim-member" }, policy)).toEqual({
      allowed: false,
      reason: "not_owner"
    });
  });
});
