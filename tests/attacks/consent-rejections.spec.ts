import { describe, expect, it } from "vitest";

import { verifyConfirmation } from "../../lib/domain/src/consent.js";
import { consentAttempt, consentStage } from "../helpers/consent-fixture.js";

describe("TH-11 atomic consent rejection contract", () => {
  it.each([
    [{ nowMs: 2_000 }, "expired"],
    [{ action: "decline" as const }, "declined"],
    [{ action: "cancel" as const }, "declined"],
    [{ approve: false }, "declined"],
    [{ confirmationCode: "WRONG999" }, "code_mismatch"]
  ])("rejects %o as %s", (patch, reason) => {
    expect(verifyConfirmation(consentStage, { ...consentAttempt, ...patch })).toEqual({
      accepted: false,
      reason
    });
  });

  it("accepts only the complete still-fresh exact confirmation", () => {
    expect(verifyConfirmation(consentStage, consentAttempt)).toEqual({ accepted: true });
  });
});
