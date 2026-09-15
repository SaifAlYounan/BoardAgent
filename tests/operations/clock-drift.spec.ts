import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("TH-50 clock drift", () => {
  it("suppresses automatic close until deadline and rejects unhealthy clock evidence", async () => {
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "suppresses automatic close before deadline and lets only the worker close after healthy-clock expiry"
    );
    await runFocusedProof(
      "tests/integration/vote-open.postgres.test.ts",
      "denies direct close writes and suppresses close on unhealthy clock or pending source evidence"
    );
  });
});
