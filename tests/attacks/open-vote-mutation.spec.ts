import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-52 open-vote mutation", () => {
  it("requires linked empty replacement for resolution or deadline changes", async () => {
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "amends an open resolution only by superseding it with an empty linked vote"
    );
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "extends an open deadline only through a linked replacement and rejects shortening"
    );
  });
});
