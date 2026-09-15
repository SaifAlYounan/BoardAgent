import { describe, expect, it } from "vitest";

import { authorize, type Scope } from "../../lib/authz/src/authorize.js";
import { policyForTool } from "../../lib/authz/src/surface-policy.js";

const BOARD_ID = "018f0000-0000-7000-8000-000000003501";

describe("TH-35 system export exfiltration", () => {
  it("requires both audit scope and the exact admin role before a system export can stage", () => {
    const object = {
      boardId: null,
      ownerMemberId: null,
      visible: true,
      recused: false,
      terminal: false
    } as const;
    const actor = (roles: readonly ("admin" | "member")[], scopes: readonly Scope[]) => ({
      memberId: "018f0000-0000-7000-8000-000000003502",
      active: true,
      onboardingCurrent: true,
      roles: new Set(roles),
      scopes: new Set(scopes),
      memberBoardIds: new Set([BOARD_ID])
    });
    const policy = policyForTool("export_system_data");

    expect(authorize(actor(["admin"], ["secretariat:admin"]), object, policy)).toEqual({
      allowed: true
    });
    expect(authorize(actor(["member"], ["secretariat:admin"]), object, policy)).toEqual({
      allowed: false,
      reason: "missing_role"
    });
    expect(authorize(actor(["admin"], []), object, policy)).toEqual({
      allowed: false,
      reason: "missing_scope"
    });
  });
});
