import { describe, expect, it } from "vitest";

import { authorize, type AuthorizationContext } from "../../lib/authz/src/authorize.js";

const actor: AuthorizationContext = {
  memberId: "member-a",
  active: true,
  onboardingCurrent: true,
  roles: new Set(["member"]),
  scopes: new Set(["governance:read"]),
  memberBoardIds: new Set(["board-a"])
};

const object = {
  boardId: "board-a",
  ownerMemberId: null,
  visible: true,
  recused: false,
  terminal: false
};

describe("TH-01 compromised read client", () => {
  it("cannot turn a valid read ceiling into stage or act authority", () => {
    expect(
      authorize(actor, object, {
        toolName: "get_vote",
        actionClass: "R",
        requiredScopes: ["governance:read"],
        ownPlatformSelfService: false,
        allowTerminalRead: true
      })
    ).toEqual({ allowed: true });

    for (const toolName of ["stage_ballot", "close_vote", "manage_recusal"]) {
      expect(
        authorize(actor, object, {
          toolName,
          actionClass: "H",
          requiredScopes: ["vote:act"],
          ownPlatformSelfService: false,
          allowTerminalRead: false
        })
      ).toEqual({ allowed: false, reason: "missing_scope" });
    }
  });
});
