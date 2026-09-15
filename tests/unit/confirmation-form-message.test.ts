import { describe, expect, it } from "vitest";

import { confirmationFormMessage } from "../../artifacts/server/src/confirmation-form-message.js";

describe("confirmation form message", () => {
  it("places the confirmation code on the second line and keeps every record line", () => {
    const lines = [
      "BOARDAGENT MEMBER INVITE CONFIRMATION",
      "Reason: Appointment per MEC-02-role-register.",
      "Operation: Invite and precreate one member seat",
      "Member: Rowan Ash (01a0a09e-3cfa-767a-bc11-48e2ade54760)",
      "Result: member state invited; enrollment remains a separate confirmed action.",
      "Confirmation code: BRD7K2Q9"
    ];
    const message = confirmationFormMessage(lines);
    expect(message.split("\n")).toEqual([
      "BOARDAGENT MEMBER INVITE CONFIRMATION",
      "Confirmation code: BRD7K2Q9",
      "Reason: Appointment per MEC-02-role-register.",
      "Operation: Invite and precreate one member seat",
      "Member: Rowan Ash (01a0a09e-3cfa-767a-bc11-48e2ade54760)",
      "Result: member state invited; enrollment remains a separate confirmed action."
    ]);
    // Every original line survives exactly once; nothing is rewritten.
    expect(message.split("\n").toSorted()).toEqual([...lines].toSorted());
  });

  it("keeps lines that already show the code on the top two lines, or none at all, unchanged", () => {
    expect(confirmationFormMessage(["TITLE", "Confirmation code: BRD7K2Q9", "Rest"])).toBe(
      "TITLE\nConfirmation code: BRD7K2Q9\nRest"
    );
    expect(confirmationFormMessage(["Confirmation code: BRD7K2Q9", "Rest"])).toBe(
      "Confirmation code: BRD7K2Q9\nRest"
    );
    expect(confirmationFormMessage(["TITLE", "Rest"])).toBe("TITLE\nRest");
    expect(confirmationFormMessage([])).toBe("");
  });
});
