import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { sourceTreeSha256ForFiles } from "../../scripts/src/source-tree-sha256.js";
import {
  verificationExitCode,
  verificationSnapshotStable
} from "../../scripts/src/verify-release.js";
import { verificationPlan } from "../../scripts/src/verification-plan.js";

describe("fail-closed verification orchestration", () => {
  it("runs exactly T0 through T5 for the Phase-1 checkpoint", () => {
    const plan = verificationPlan("phase1");
    expect(plan.map(({ id }) => id)).toEqual(["T0", "T1", "T2", "T3", "T4", "T5"]);
    expect(plan.at(-1)?.commands[0]?.args).toEqual([
      "scripts/src/check-verification-closure.ts",
      "T5"
    ]);
  });

  it("keeps T2 on its frozen pure unit/state target and T5 on PostgreSQL", () => {
    const plan = verificationPlan("phase1");
    expect(plan.find(({ id }) => id === "T2")?.commands[0]?.args).toEqual([
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
    ]);
    expect(plan.find(({ id }) => id === "T5")?.commands[1]?.args).toContain("tests/integration");
  });

  it("keeps T4 on the evidenced deterministic-kernel consumers without broad runtime globs", async () => {
    const module = (await import(new URL("../../stryker.config.mjs", import.meta.url).href)) as {
      default: {
        mutate: readonly string[];
        thresholds: { high: number; low: number; break: number };
        testFiles: readonly string[];
      };
    };
    expect(module.default.mutate).toEqual([
      "lib/domain/src/**/*.ts",
      "lib/ruleset/src/**/*.ts",
      "lib/authz/src/**/*.ts",
      "lib/audit/src/**/*.ts",
      "!**/*.d.ts"
    ]);
    expect(module.default.thresholds).toEqual({ high: 100, low: 100, break: 100 });
    expect(module.default.testFiles).toEqual([
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
    ]);
  });

  it("pins the upstream static-mutant activation correction used by filtered T4", async () => {
    const [workspace, patch] = await Promise.all([
      readFile(new URL("../../pnpm-workspace.yaml", import.meta.url), "utf8"),
      readFile(
        new URL("../../patches/@stryker-mutator__core@10.0.0.patch", import.meta.url),
        "utf8"
      )
    ]);
    expect(workspace).toContain(
      '"@stryker-mutator/core@10.0.0": patches/@stryker-mutator__core@10.0.0.patch'
    );
    expect(patch).toContain("mutantActivation: canHotSwap ? 'runtime' : 'static'");
    expect(
      patch.match(/^\+.*mutantActivation: canHotSwap \? 'runtime' : 'static'/gmu)
    ).toHaveLength(2);
  });

  it("permits private beta to omit only independent review", () => {
    expect(verificationPlan("private-beta").map(({ id }) => id)).toEqual([
      "T0",
      "T1",
      "T2",
      "T3",
      "T4",
      "T5",
      "T6",
      "T7",
      "T8",
      "T9"
    ]);
    expect(verificationPlan("release").map(({ id }) => id)).toEqual([
      "T0",
      "T1",
      "T2",
      "T3",
      "T4",
      "T5",
      "T6",
      "T7",
      "T8",
      "T9",
      "T10"
    ]);
  });

  it("preflights every runtime tier for frozen evidence closure before its test glob", () => {
    for (const tier of verificationPlan("private-beta").filter(({ id }) => /^T[5-9]$/u.test(id))) {
      expect(tier.commands[0]?.args).toEqual([
        "scripts/src/check-verification-closure.ts",
        tier.id
      ]);
    }
  });

  it("builds or verifies an exact-source release image before the T9 operations suite", () => {
    const tier = verificationPlan("private-beta").find(({ id }) => id === "T9");
    expect(tier?.commands.map(({ args }) => args)).toEqual([
      ["scripts/src/check-verification-closure.ts", "T9"],
      ["scripts/src/build-release-image.ts"],
      ["scripts/src/scan-release-image.ts"],
      ["run", "tests/operations", "tests/load", "--no-file-parallelism", "--maxWorkers=1"]
    ]);
  });

  it("prepares the current image before AC-25 invokes encrypted restore in T8", () => {
    const commands = verificationPlan("private-beta").find(({ id }) => id === "T8")!.commands;
    const build = commands.findIndex(
      ({ args }) => args[0] === "scripts/src/build-release-image.ts"
    );
    const acceptance = commands.findIndex(({ args }) => args.includes("tests/acceptance"));
    expect(build).toBeGreaterThan(0); // The approved closure preflight still runs first.
    expect(acceptance).toBeGreaterThan(build);
  });

  it("binds a tracked deletion into the source digest instead of crashing", async () => {
    const files = ["kept.ts", "removed.ts"];
    const deleted = await sourceTreeSha256ForFiles(files, async (name) => {
      if (name === "removed.ts") {
        throw Object.assign(new Error("missing"), { code: "ENOENT" });
      }
      return Buffer.from("kept source", "utf8");
    });
    const repeated = await sourceTreeSha256ForFiles(files, async (name) => {
      if (name === "removed.ts") {
        throw Object.assign(new Error("missing"), { code: "ENOENT" });
      }
      return Buffer.from("kept source", "utf8");
    });
    const absentFromIndex = await sourceTreeSha256ForFiles(["kept.ts"], async () =>
      Buffer.from("kept source", "utf8")
    );
    expect(deleted).toBe(repeated);
    expect(deleted).not.toBe(absentFromIndex);
  });

  it("distinguishes a literal deletion marker from a missing tracked file", async () => {
    const names = ["record.txt"];
    const present = await sourceTreeSha256ForFiles(names, async () => Buffer.from("<deleted>"));
    const missing = await sourceTreeSha256ForFiles(names, async () => {
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    });
    expect(present).not.toBe(missing);
  });

  it("preserves file boundaries when source bytes contain zero delimiters", async () => {
    const names = ["a", "b"];
    const first = await sourceTreeSha256ForFiles(names, async (name) =>
      Buffer.from(name === "a" ? "x\0b\0y" : "z")
    );
    const second = await sourceTreeSha256ForFiles(names, async (name) =>
      Buffer.from(name === "a" ? "x" : "y\0b\0z")
    );
    expect(first).not.toBe(second);
  });

  it("does not turn an unreadable source file into a deletion", async () => {
    const refusal = Object.assign(new Error("unreadable"), { code: "EACCES" });
    await expect(
      sourceTreeSha256ForFiles(["record.txt"], async () => {
        throw refusal;
      })
    ).rejects.toBe(refusal);
  });

  it("fails source stability when Git HEAD changes during a verification run", () => {
    const stable = {
      sourceTreeSha256Before: "a".repeat(64),
      sourceTreeSha256After: "a".repeat(64),
      worktreeStatusSha256Before: "b".repeat(64),
      worktreeStatusSha256After: "b".repeat(64),
      gitHeadBefore: "c".repeat(40),
      gitHeadAfter: "c".repeat(40)
    };
    expect(verificationSnapshotStable(stable)).toBe(true);
    expect(verificationSnapshotStable({ ...stable, gitHeadAfter: "d".repeat(40) })).toBe(false);
  });

  it("returns failure when Gate 3 evidence validation blocks otherwise passing tiers", () => {
    expect(verificationExitCode("passed")).toBe(0);
    expect(verificationExitCode("passed", "private_hardened_beta_candidate_ready_for_gate3")).toBe(
      0
    );
    expect(verificationExitCode("passed", "verification_blocked")).toBe(1);
    expect(verificationExitCode("failed", "public_production_candidate_ready_for_gate3")).toBe(1);
  });
});
