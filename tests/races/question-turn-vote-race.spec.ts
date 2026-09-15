import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-63 question turn and vote race", () => {
  it("blocks only the explicitly linked vote after a post-cutoff turn", async () => {
    await runFocusedProof(
      "tests/integration/question-transactions.postgres.test.ts",
      "blocks only an explicitly linked open vote when a turn passes its frozen cutoff"
    );
  });
});
