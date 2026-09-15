import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-62 minutes action activation race", () => {
  it("activates and notifies only the freshly confirmed final action manifest", async () => {
    await runFocusedProof(
      "tests/integration/surface-minutes-review.postgres.test.ts",
      "runs disposition, action declaration, signatures, finalization, linked correction and AC16 delegated director replacement through the surface"
    );
  });
});
