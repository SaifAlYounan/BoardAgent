import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-43 transcript/minutes signature race", () => {
  it("invalidates stale minutes signature state when the bound transcript changes", async () => {
    await runFocusedProof(
      "tests/integration/surface-transcript-lifecycle.postgres.test.ts",
      "creates, verifies, challenges, corrects and links immutable turns while invalidating stale minutes"
    );
  });
});
