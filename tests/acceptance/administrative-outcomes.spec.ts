import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

// These stable acceptance entries execute the named authoritative scenarios. Each
// transport journey is continuous within its own fixture; separately invoked limit,
// upgrade and restore cases are component evidence. The project owner's human trials remain open.
describe("approved administrative acceptance outcomes", () => {
  it("AC-23 named-recipient acceptance and atomic administrator transfer preserve ordinary rights", async () => {
    await runFocusedProof(
      "tests/protocol/company-admin-transfer-continuity.postgres.test.ts",
      "transfers atomically to a person without a board seat, revokes both connections and stale H stages, preserves votes and reconnects with current rights"
    );
  });

  it("AC-24 evidenced secretary appointments remain limited to the granted board and ordinary directors", async () => {
    await runFocusedProof(
      "tests/protocol/administrative-oauth-mcp.postgres.test.ts",
      "uses signed passkeys and issued bearer tokens for exact H actions, revocation and personal reconnect"
    );
    await runFocusedProof(
      "tests/integration/delegated-secretary-limits.postgres.test.ts",
      "SR097/AC11–15 delegated secretary limits",
      30
    );
    await runFocusedProof(
      "tests/integration/member-admin-delegation.postgres.test.ts",
      "binds one current secretary, board, deadline and readable immutable citation without granting at prepare"
    );
    await runFocusedProof(
      "tests/integration/member-admin-delegation.postgres.test.ts",
      "restoring secretary status does not revive a prior grant; a fresh confirmed grant is required"
    );
    await runFocusedProof(
      "tests/integration/member-admin-delegation.postgres.test.ts",
      "grant cannot complete a previously prepared director change",
      2
    );
  });

  it("AC-25 setup, recovery, upgrade and encrypted restore preserve separated administrative identities", async () => {
    await runFocusedProof(
      "tests/protocol/administrative-authority-journey.spec.ts",
      "TH-71 supported administrative bootstrap and recovery",
      2
    );
    // The AC24 group carries two cases since MR-ENROLL-001 (registered pending member
    // without a replacement grant) joined the recovery journey; both must pass.
    await runFocusedProof(
      "tests/protocol/replacement-passkey-recovery.postgres.test.ts",
      "AC24 replacement passkey recovery",
      2
    );
    await runFocusedProof(
      "tests/integration/administrative-authority-upgrade.postgres.test.ts",
      "upgrades the exact original migration set without rewriting it and isolates new authority tables"
    );
    await runFocusedProof(
      "tests/operations/physical-backup-restore.spec.ts",
      "dumps one exported snapshot, restores an empty database, verifies every invariant, and rejects ciphertext tamper"
    );
  });
});
