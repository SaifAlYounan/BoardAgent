import { describe, expect, it } from "vitest";

import { verifyConfirmation } from "../../lib/domain/src/consent.js";
import { consentAttempt, consentStage } from "../helpers/consent-fixture.js";

describe("TH-10 consent-context replay", () => {
  it("binds request, protected actor/client/object state, canonical bytes, and one-use state", () => {
    expect(
      verifyConfirmation(consentStage, { ...consentAttempt, requestHash: "c".repeat(64) })
    ).toEqual({ accepted: false, reason: "request_mismatch" });
    expect(
      verifyConfirmation(consentStage, {
        ...consentAttempt,
        protectedState: `${consentAttempt.protectedState}|different-client`
      })
    ).toEqual({ accepted: false, reason: "state_mismatch" });
    expect(
      verifyConfirmation(consentStage, { ...consentAttempt, canonicalHash: "d".repeat(64) })
    ).toEqual({ accepted: false, reason: "canonical_stale" });
    for (const status of ["confirmed", "replaced", "rejected", "expired", "cancelled"] as const) {
      expect(verifyConfirmation({ ...consentStage, status }, consentAttempt)).toEqual({
        accepted: false,
        reason: "stage_not_active"
      });
    }
  });
});
