import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-60 false action-item closure", () => {
  it("requires accepted evidence and secretary confirmation while keeping terminal history closed", async () => {
    await runFocusedProof(
      "tests/integration/task-transactions.postgres.test.ts",
      "separates owner evidence from secretary review/closure and never reopens terminal work"
    );
  });
});
