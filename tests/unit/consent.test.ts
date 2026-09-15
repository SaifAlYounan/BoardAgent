import { describe, expect, it } from "vitest";

import { sha256Hex } from "../../lib/contracts/src/index.js";
import {
  verifyConfirmation,
  type ActionStage,
  type ConfirmationAttempt
} from "../../lib/domain/src/index.js";

const protectedState = "bound request state";
const confirmationCode = "BRD7K2Q9";

const stage: ActionStage = {
  status: "active",
  actionType: "cast_ballot",
  targetId: "018f0000-0000-7000-8000-000000000001",
  actorMemberId: "018f0000-0000-7000-8000-000000000002",
  canonicalHash: "a".repeat(64),
  requestHash: "b".repeat(64),
  protectedStateHash: sha256Hex(protectedState),
  confirmationCodeHash: sha256Hex(confirmationCode),
  expiresAtMs: 2_000
};

const attempt: ConfirmationAttempt = {
  action: "accept",
  approve: true,
  confirmationCode,
  protectedState,
  requestHash: stage.requestHash,
  canonicalHash: stage.canonicalHash,
  nowMs: 1_000
};

describe("exact consent confirmation", () => {
  it("accepts only the complete byte-bound confirmation", () => {
    expect(verifyConfirmation(stage, attempt)).toEqual({ accepted: true });
  });

  it.each([
    [Number.NaN, 1_000],
    [Number.POSITIVE_INFINITY, 1_000],
    [Number.NEGATIVE_INFINITY, 1_000],
    [2_000, Number.NaN],
    [2_000, Number.POSITIVE_INFINITY],
    [2_000, Number.NEGATIVE_INFINITY]
  ])("refuses non-finite expiry/clock values %s / %s", (expiresAtMs, nowMs) => {
    expect(() => verifyConfirmation({ ...stage, expiresAtMs }, { ...attempt, nowMs })).toThrow(
      new RangeError("consent expiry and clock must be finite timestamps")
    );
  });

  it.each([
    [{ status: "confirmed" as const }, {}, "stage_not_active"],
    [{}, { nowMs: 2_000 }, "expired"],
    [{}, { action: "decline" as const }, "declined"],
    [{}, { action: "cancel" as const }, "declined"],
    [{}, { approve: false }, "declined"],
    [{}, { requestHash: "c".repeat(64) }, "request_mismatch"],
    [{}, { protectedState: "changed state" }, "state_mismatch"],
    [{}, { canonicalHash: "d".repeat(64) }, "canonical_stale"],
    [{}, { confirmationCode: "WRONG999" }, "code_mismatch"]
  ])("rejects %s / %s as %s", (stagePatch, attemptPatch, reason) => {
    expect(
      verifyConfirmation({ ...stage, ...stagePatch }, { ...attempt, ...attemptPatch })
    ).toEqual({ accepted: false, reason });
  });
});
