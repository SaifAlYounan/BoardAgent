import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-39 corrupted restore", () => {
  it("recomputes the full restore manifest, refuses readiness and never repairs", async () => {
    await runFocusedProof(
      "tests/integration/backup-restore.postgres.test.ts",
      "verifies a complete clone, records immutable receipts and rejects corruption without repair"
    );
  });
});
