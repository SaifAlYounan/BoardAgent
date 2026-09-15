import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-27 replacement notice atomicity", () => {
  it("opens an empty replacement with exact eligible and informational delivery semantics", async () => {
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "atomically opens an empty replacement, dispositions every old act and emits exact recipient deltas"
    );
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "informs an entitled prior principal who became nonvoting without creating an impossible revote action"
    );
  });
});
