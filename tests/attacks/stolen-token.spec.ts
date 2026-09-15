import { describe, expect, it } from "vitest";

import { sha256Hex } from "../../lib/contracts/src/canonical.js";
import { verifyConfirmation, type ActionStage } from "../../lib/domain/src/consent.js";
import { authorize, type AuthorizationContext } from "../../lib/authz/src/authorize.js";
import { TOKEN_BOARD_ID, TOKEN_MEMBER_ID, tokenFixture } from "../helpers/token-fixture.js";

describe("TH-02/TH-03 stolen bearer", () => {
  it("loses all authority on ledger revocation and a read bearer cannot mutate", async () => {
    const fixture = await tokenFixture();
    const token = await fixture.sign();
    const auth = await fixture.verify(token);
    const actor: AuthorizationContext = {
      memberId: TOKEN_MEMBER_ID,
      active: true,
      onboardingCurrent: true,
      roles: new Set(["member"]),
      scopes: new Set(auth.scopes as ("governance:read" | "documents:read")[]),
      memberBoardIds: new Set([TOKEN_BOARD_ID])
    };
    const object = {
      boardId: TOKEN_BOARD_ID,
      ownerMemberId: null,
      visible: true,
      recused: false,
      terminal: false
    };
    expect(
      authorize(actor, object, {
        toolName: "stage_ballot",
        actionClass: "H",
        requiredScopes: ["vote:act"],
        ownPlatformSelfService: false,
        allowTerminalRead: false
      })
    ).toEqual({ allowed: false, reason: "missing_scope" });

    fixture.store.current = null;
    await expect(fixture.verify(token)).rejects.toThrow("not active in the BoardAgent ledger");
  });

  it("cannot complete an action bearer without its exact fresh MRTR context and code", () => {
    const state = `${TOKEN_MEMBER_ID}|portable-client|vote-a|package-a`;
    const stage: ActionStage = {
      status: "active",
      actionType: "cast_ballot",
      targetId: "vote-a",
      actorMemberId: TOKEN_MEMBER_ID,
      canonicalHash: "a".repeat(64),
      requestHash: "b".repeat(64),
      protectedStateHash: sha256Hex(state),
      confirmationCodeHash: sha256Hex("BRD7K2Q9"),
      expiresAtMs: 2_000
    };
    const attempt = {
      action: "accept" as const,
      approve: true,
      confirmationCode: "BRD7K2Q9",
      protectedState: `${TOKEN_MEMBER_ID}|stolen-client|vote-a|package-a`,
      requestHash: stage.requestHash,
      canonicalHash: stage.canonicalHash,
      nowMs: 1_000
    };
    expect(verifyConfirmation(stage, attempt)).toEqual({
      accepted: false,
      reason: "state_mismatch"
    });
    expect(
      verifyConfirmation(stage, { ...attempt, protectedState: state, confirmationCode: "BAD" })
    ).toEqual({ accepted: false, reason: "code_mismatch" });
  });
});
