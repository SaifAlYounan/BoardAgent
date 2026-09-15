import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

// Stable TH-71 entry required by the approved release net. These execute the actual
// application journeys in separate disposable databases, with signed test authenticators.
// They do not turn synthetic confirmation into evidence of actual human participation.
describe("TH-71 supported administrative bootstrap and recovery", () => {
  it("executes the one-time bootstrap and separate secretary/director enrollment journey", async () => {
    await runFocusedProof(
      "tests/protocol/secretary-handoff.postgres.test.ts",
      "AC23 ordinary-secretary and separate-director handoff",
      2
    );
  });

  it("executes recovery while refusing an old offer and hidden bootstrap promotion", async () => {
    await runFocusedProof(
      "tests/protocol/administrative-recovery.postgres.test.ts",
      "invalidates a waiting offer after issuer recovery, reconnects with the preserved passkey and refuses bootstrap promotion after total credential loss"
    );
  });
});
