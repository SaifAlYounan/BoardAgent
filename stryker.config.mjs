export default {
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // TypeScript 7 intentionally removed the legacy config-parser API used by
  // Stryker's sandbox rewriter. Vitest/esbuild owns TS transformation here, so
  // point the optional rewriter at no project file instead of weakening the
  // frozen TypeScript 7.0.2 toolchain pin.
  tsconfigFile: "tests/stryker-no-tsconfig.json",
  mutate: [
    "lib/domain/src/**/*.ts",
    "lib/ruleset/src/**/*.ts",
    "lib/authz/src/**/*.ts",
    "lib/audit/src/**/*.ts",
    "!**/*.d.ts"
  ],
  // T4 is intentionally bounded to the deterministic kernel's evidenced consumers.
  // The pinned Stryker core carries upstream fix #6145, so this explicit file filter
  // cannot defer static-mutant activation until after module import.
  testFiles: [
    "tests/unit/**/*.test.ts",
    "tests/property/**/*.property.ts",
    "tests/contracts/**/*.test.ts",
    "tests/authz/**/*.spec.ts",
    "tests/integration/backup-restore.postgres.test.ts",
    "tests/integration/document-transactions.postgres.test.ts",
    "tests/integration/matter-evaluation.postgres.test.ts",
    "tests/integration/minutes-transactions.postgres.test.ts",
    "tests/integration/question-queries.postgres.test.ts",
    "tests/integration/question-transactions.postgres.test.ts",
    "tests/integration/surface-read.postgres.test.ts",
    "tests/integration/vote-open.postgres.test.ts"
  ],
  thresholds: { high: 100, low: 100, break: 100 },
  reporters: ["clear-text", "json"],
  jsonReporter: { fileName: "artifacts/verification/mutation.json" },
  concurrency: 2
};
