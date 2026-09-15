import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-61 minutes signature/version race", () => {
  it("atomically supersedes stale signatures and creates exact current re-sign work", async () => {
    await runFocusedProof(
      "tests/integration/minutes-transactions.postgres.test.ts",
      "runs disposition, correction, declaration, signatures, finalization and linked correction atomically"
    );
  });
});
