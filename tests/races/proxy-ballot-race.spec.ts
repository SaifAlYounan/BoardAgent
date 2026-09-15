import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-29 proxy and ballot races", () => {
  it("rejects graph abuse and serializes proxy/direct ballots to one effective principal vote", async () => {
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "rejects proxy chains and every post-confirmation payload change"
    );
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "serializes direct and proxy casts to one effective principal ballot"
    );
  });
});
