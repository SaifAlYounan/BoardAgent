import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-26 submission and vote race", () => {
  it("serializes a linked submission revision into source-update-pending before close", async () => {
    await runFocusedProof(
      "tests/integration/management-submissions.postgres.test.ts",
      "appends one immutable revision, notifies the secretary, and blocks the exact linked vote"
    );
  });
});
