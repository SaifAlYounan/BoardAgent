import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

describe("AC-07 / TH-48 accountable AI observer", () => {
  it("requires accountable identity and connects each live role with separate credentials", async () => {
    await runFocusedProof(
      "tests/integration/member-administration.postgres.test.ts",
      "rejects invalid AI-observer/accountable-principal and seat-weight combinations"
    );
    await runFocusedProof(
      "tests/integration/role-connection-journeys.postgres.test.ts",
      "binds each real MCP client to its own live role and denies a stranger"
    );
  });

  it("allows only the frozen observer self-service and governance exceptions", async () => {
    await runFocusedProof(
      "tests/authz/observer-exception-matrix.spec.ts",
      "allows exactly six own-security and six governance mutations"
    );
    await runFocusedProof(
      "tests/authz/observer-exception-matrix.spec.ts",
      "denies own-security mutation against another identity"
    );
  });
});
