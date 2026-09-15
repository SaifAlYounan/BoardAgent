import { describe, expect, it } from "vitest";

import { authorize, type AuthorizationContext } from "../../lib/authz/src/authorize.js";

const actor: AuthorizationContext = {
  memberId: "member-a",
  active: true,
  onboardingCurrent: true,
  roles: new Set(["member"]),
  scopes: new Set(["governance:read", "vote:act"]),
  memberBoardIds: new Set(["board-a"])
};

describe("TH-04 cross-board confused deputy", () => {
  it("denies substituted board identifiers and preserves invisible-object precedence", () => {
    const foreign = {
      boardId: "board-b",
      ownerMemberId: null,
      visible: true,
      recused: false,
      terminal: false
    };
    expect(
      authorize(actor, foreign, {
        toolName: "get_vote",
        actionClass: "R",
        requiredScopes: ["governance:read"],
        ownPlatformSelfService: false,
        allowTerminalRead: true
      })
    ).toEqual({ allowed: false, reason: "outside_board" });
    expect(
      authorize(
        actor,
        { ...foreign, visible: false },
        {
          toolName: "stage_ballot",
          actionClass: "H",
          requiredScopes: ["vote:act"],
          ownPlatformSelfService: false,
          allowTerminalRead: false
        }
      )
    ).toEqual({ allowed: false, reason: "object_absent" });
  });
});
