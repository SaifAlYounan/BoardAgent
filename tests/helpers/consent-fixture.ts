import { sha256Hex } from "../../lib/contracts/src/canonical.js";
import type { ActionStage, ConfirmationAttempt } from "../../lib/domain/src/consent.js";

export const CONSENT_STATE =
  "member=018f0000-0000-7000-8000-000000000001|client=portable|vote=018f0000-0000-7000-8000-000000000002";
export const CONSENT_CODE = "BRD7K2Q9";

export const consentStage: ActionStage = {
  status: "active",
  actionType: "cast_ballot",
  targetId: "018f0000-0000-7000-8000-000000000002",
  actorMemberId: "018f0000-0000-7000-8000-000000000001",
  canonicalHash: "a".repeat(64),
  requestHash: "b".repeat(64),
  protectedStateHash: sha256Hex(CONSENT_STATE),
  confirmationCodeHash: sha256Hex(CONSENT_CODE),
  expiresAtMs: 2_000
};

export const consentAttempt: ConfirmationAttempt = {
  action: "accept",
  approve: true,
  confirmationCode: CONSENT_CODE,
  protectedState: CONSENT_STATE,
  requestHash: consentStage.requestHash,
  canonicalHash: consentStage.canonicalHash,
  nowMs: 1_000
};
