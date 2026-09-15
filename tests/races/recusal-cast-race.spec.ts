import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-28 recusal and cast race", () => {
  it("locks the vote root so an excluded principal retains no effective ballot", async () => {
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "serializes recusal and cast so no excluded principal retains an effective ballot"
    );
  });
});
