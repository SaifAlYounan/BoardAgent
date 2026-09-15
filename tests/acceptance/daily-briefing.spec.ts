import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("AC-05 / TH-44 one-call daily briefing", () => {
  it("returns every own delta, stable pagination, tombstones and explicit overflow", async () => {
    await runFocusedProof(
      "tests/integration/surface-read.postgres.test.ts",
      "returns exactly 0, 1, or 1000 own briefing deltas and signs overflow resync"
    );
    await runFocusedProof(
      "tests/integration/surface-read.postgres.test.ts",
      "returns an own tombstone and signed resync after entitlement revocation"
    );
    await runFocusedProof(
      "tests/integration/surface-read.postgres.test.ts",
      "paginates equal feed sequences across boards without omission or replay"
    );
  });
});
