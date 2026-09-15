import path from "node:path";

export type VerificationMode = "phase1" | "private-beta" | "release";

export interface VerificationCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly timeoutMs: number;
}

export interface VerificationTier {
  readonly id: `T${number}`;
  readonly name: string;
  readonly commands: readonly VerificationCommand[];
}

const PROJECT = path.resolve(import.meta.dirname, "../..");
const BIN = path.join(PROJECT, "node_modules", ".bin");
const command = (
  name: string,
  args: readonly string[],
  timeoutMs = 15 * 60_000
): VerificationCommand => ({ executable: path.join(BIN, name), args, timeoutMs });

const T0: VerificationTier = {
  id: "T0",
  name: "integrity",
  commands: [
    command("tsx", ["scripts/src/check-registry.ts"]),
    command("tsx", ["scripts/src/generate-supply-chain.ts", "--check"]),
    command("vitest", ["run", "tests/phase0", "--no-file-parallelism", "--maxWorkers=1"])
  ]
};

const T1: VerificationTier = {
  id: "T1",
  name: "static",
  commands: [
    command("prettier", ["--check", "."]),
    command("eslint", ["."]),
    command("oxlint", ["--deny-warnings", "artifacts", "lib", "scripts", "tests"]),
    command("depcruise", [
      "--config",
      "dependency-cruiser.config.cjs",
      "artifacts",
      "lib",
      "scripts",
      "tests"
    ]),
    command("tsc", ["-b", "--pretty", "false"])
  ]
};

const T2: VerificationTier = {
  id: "T2",
  name: "unit-state-coverage",
  commands: [
    command(
      "vitest",
      [
        "run",
        "tests/unit",
        "tests/authz",
        "tests/contracts",
        "--coverage",
        "--coverage.include=lib/domain/src/**",
        "--coverage.include=lib/contracts/src/canonical.ts",
        "--coverage.include=lib/authz/src/**",
        "--coverage.thresholds.branches=100",
        "--no-file-parallelism",
        "--maxWorkers=1"
      ],
      30 * 60_000
    )
  ]
};

const T3: VerificationTier = {
  id: "T3",
  name: "property",
  commands: [
    command(
      "vitest",
      ["run", "tests/property", "--no-file-parallelism", "--maxWorkers=1"],
      30 * 60_000
    )
  ]
};

const T4: VerificationTier = {
  id: "T4",
  name: "mutation",
  commands: [command("stryker", ["run"], 4 * 60 * 60_000)]
};

const T5: VerificationTier = {
  id: "T5",
  name: "postgresql",
  commands: [
    command("tsx", ["scripts/src/check-verification-closure.ts", "T5"]),
    command(
      "vitest",
      ["run", "tests/integration", "--no-file-parallelism", "--maxWorkers=1"],
      60 * 60_000
    ),
    command("tsx", ["tests/performance/verify-phase1-performance.ts"], 30 * 60_000)
  ]
};

const T6: VerificationTier = {
  id: "T6",
  name: "protocol-auth",
  commands: [
    command("tsx", ["scripts/src/check-verification-closure.ts", "T6"]),
    command(
      "vitest",
      [
        "run",
        "tests/protocol",
        "tests/browser",
        "tests/auth",
        "tests/integration/oauth-provider.postgres.test.ts",
        "--no-file-parallelism",
        "--maxWorkers=1"
      ],
      60 * 60_000
    )
  ]
};

const T7: VerificationTier = {
  id: "T7",
  name: "adversarial",
  commands: [
    command("tsx", ["scripts/src/check-verification-closure.ts", "T7"]),
    command(
      "vitest",
      [
        "run",
        "tests/attacks",
        "tests/races",
        "tests/faults",
        "--no-file-parallelism",
        "--maxWorkers=1"
      ],
      60 * 60_000
    )
  ]
};

const T8: VerificationTier = {
  id: "T8",
  name: "acceptance",
  commands: [
    command("tsx", ["scripts/src/check-verification-closure.ts", "T8"]),
    // AC-25 executes the actual encrypted operator restore. It must use this
    // candidate's image even when qualification starts without a prior T9 run.
    command("tsx", ["scripts/src/build-release-image.ts"], 60 * 60_000),
    command(
      "vitest",
      ["run", "tests/acceptance", "--no-file-parallelism", "--maxWorkers=1"],
      60 * 60_000
    )
  ]
};

const T9: VerificationTier = {
  id: "T9",
  name: "operations",
  commands: [
    command("tsx", ["scripts/src/check-verification-closure.ts", "T9"]),
    command("tsx", ["scripts/src/build-release-image.ts"], 60 * 60_000),
    command("tsx", ["scripts/src/scan-release-image.ts"], 60 * 60_000),
    command(
      "vitest",
      ["run", "tests/operations", "tests/load", "--no-file-parallelism", "--maxWorkers=1"],
      2 * 60 * 60_000
    )
  ]
};

const T10: VerificationTier = {
  id: "T10",
  name: "independent-review",
  commands: [command("tsx", ["scripts/src/check-independent-review.ts"])]
};

export function verificationPlan(mode: VerificationMode): readonly VerificationTier[] {
  const phase1 = [T0, T1, T2, T3, T4, T5] as const;
  if (mode === "phase1") return phase1;
  const privateBeta = [...phase1, T6, T7, T8, T9] as const;
  return mode === "private-beta" ? privateBeta : [...privateBeta, T10];
}
