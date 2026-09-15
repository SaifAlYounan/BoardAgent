import { describe, expect, it } from "vitest";

import {
  authorize,
  policyForTool,
  type AuthorizationContext,
  type Scope
} from "../../lib/authz/src/index.js";
import { BOARDAGENT_REGISTRY } from "../../lib/contracts/src/index.js";

const ALL_SCOPES = new Set<Scope>([
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
]);

const observer: AuthorizationContext = {
  memberId: "observer-a",
  active: true,
  onboardingCurrent: true,
  roles: new Set(["observer"]),
  scopes: ALL_SCOPES,
  memberBoardIds: new Set(["board-a"])
};

const object = {
  boardId: "board-a",
  ownerMemberId: "observer-a",
  visible: true,
  recused: false,
  terminal: false
};

const EXPECTED_MUTATIONS = [
  "ask_management",
  "comment_minutes",
  "configure_webhook",
  "disable_webhook",
  "follow_up_management_question",
  "prepare_onboarding_attestation",
  "propose_minutes_redline",
  "revoke_my_session",
  "rotate_webhook_secret",
  "stage_minutes_signature",
  "test_webhook",
  "withdraw_minutes_comment"
].toSorted();

describe("observer exception surface", () => {
  it("allows exactly six own-security and six governance mutations", () => {
    const allowed = BOARDAGENT_REGISTRY.tools
      .filter(({ class: actionClass }) => actionClass !== "R")
      .filter(({ name }) => authorize(observer, object, policyForTool(name)).allowed)
      .map(({ name }) => name)
      .toSorted();
    expect(allowed).toEqual(EXPECTED_MUTATIONS);
  });

  it("denies own-security mutation against another identity", () => {
    for (const name of [
      "revoke_my_session",
      "configure_webhook",
      "rotate_webhook_secret",
      "disable_webhook",
      "test_webhook"
    ]) {
      expect(
        authorize(observer, { ...object, ownerMemberId: "member-b" }, policyForTool(name))
      ).toEqual({ allowed: false, reason: "not_owner" });
    }
  });
});
