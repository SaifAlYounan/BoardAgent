import { describe, expect, it } from "vitest";

import { registryData } from "../../lib/contracts/src/generated/registry.data.js";
import { verifyConfirmation } from "../../lib/domain/src/consent.js";
import { consentAttempt, consentStage } from "../helpers/consent-fixture.js";

describe("TH-12 client auto-approval residual", () => {
  it("never treats a bare approval boolean as consent and preserves client attribution", () => {
    // A bare approval object carries no clock: the domain refuses to evaluate it at all
    // rather than guess, and with a clock it is still not an accepted confirmation.
    expect(() => verifyConfirmation(consentStage, { approve: true } as never)).toThrow(
      new RangeError("consent expiry and clock must be finite timestamps")
    );
    expect(verifyConfirmation(consentStage, { approve: true, nowMs: 1_000 } as never)).toEqual({
      accepted: false,
      reason: "declined"
    });
    expect(verifyConfirmation(consentStage, { ...consentAttempt, confirmationCode: "" })).toEqual({
      accepted: false,
      reason: "code_mismatch"
    });
    expect(verifyConfirmation(consentStage, consentAttempt)).toEqual({ accepted: true });

    const threat = registryData.threats.find(({ id }) => id === "TH-12");
    expect(threat).toMatchObject({
      scenario: "Client auto-echoes confirmation",
      expectedControl: "event remains client-attributable; no comprehension claim"
    });
  });
});
