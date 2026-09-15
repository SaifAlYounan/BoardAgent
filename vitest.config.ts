import path from "node:path";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // Tests import workspace source directly while runtime composition imports package names.
    // Resolve both spellings to one module identity so V8 does not instrument a source file
    // twice through its compiled sourcemap and report a phantom uncovered function copy.
    alias: {
      "@boardagent/audit": path.resolve(import.meta.dirname, "lib/audit/src/index.ts"),
      "@boardagent/authz": path.resolve(import.meta.dirname, "lib/authz/src/index.ts"),
      "@boardagent/contracts": path.resolve(import.meta.dirname, "lib/contracts/src/index.ts"),
      "@boardagent/config": path.resolve(import.meta.dirname, "lib/config/src/index.ts"),
      "@boardagent/db": path.resolve(import.meta.dirname, "lib/db/src/index.ts"),
      "@boardagent/domain": path.resolve(import.meta.dirname, "lib/domain/src/index.ts"),
      "@boardagent/ruleset": path.resolve(import.meta.dirname, "lib/ruleset/src/index.ts"),
      "@boardagent/server": path.resolve(import.meta.dirname, "artifacts/server/src/index.ts")
    }
  },
  test: {
    environment: "node",
    globals: false,
    include: ["tests/**/*.test.ts", "tests/**/*.spec.ts", "tests/**/*.property.ts"],
    sequence: { concurrent: false },
    pool: "forks",
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "lcov"],
      thresholds: {
        branches: 90,
        lines: 95,
        functions: 95,
        statements: 95
      }
    }
  }
});
