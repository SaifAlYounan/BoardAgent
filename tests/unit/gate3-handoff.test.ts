import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  writeGate3Handoff,
  type Gate3VerificationReceipt
} from "../../scripts/src/gate3-handoff.js";

const ROOT = path.resolve(import.meta.dirname, "../..");

// Unit evidence is synthetic and disposable. It must never depend on (or replace)
// the preceding real release run's mutation, scan or independent-review verdict.
async function fixtureProject() {
  await mkdir(path.join(ROOT, "artifacts/verification"), { recursive: true });
  const projectRoot = await mkdtemp(path.join(ROOT, "artifacts/verification/gate3-fixture-"));
  try {
    const inputs = [
      "BUILD_PLAN.md",
      "README.md",
      "DEPLOY.md",
      "SECURITY.md",
      "Dockerfile",
      "Caddyfile",
      "compose.yaml",
      "compose.production.yaml",
      "compose.recovery.yaml",
      ".env.production.example",
      "package.json",
      "pnpm-lock.yaml",
      "tests/NET.json",
      "docs",
      "planning",
      "lib/contracts/src/generated/registry.manifest.json",
      "artifacts/provenance",
      "artifacts/sbom",
      "artifacts/license-report"
    ];
    for (const input of inputs) {
      const destination = path.join(projectRoot, input);
      await mkdir(path.dirname(destination), { recursive: true });
      await cp(path.join(ROOT, input), destination, { recursive: true });
    }
    // Only this disposable unit fixture declares all requirements resolved. The real
    // register and actual human enrollment remain unchanged and may block release.
    const registerPath = path.join(projectRoot, "docs/VERIFICATION.md");
    await writeFile(
      registerPath,
      (await readFile(registerPath, "utf8")).replace(
        /^(\| SR-\d{3} \|[^\n]+\|) UNRESOLVED\s+\|$/gmu,
        "$1 PROVEN |"
      )
    );
    const sourceTreeSha256 = "c".repeat(64);
    await mkdir(path.join(projectRoot, "artifacts/vulnerability"), { recursive: true });
    await mkdir(path.join(projectRoot, "artifacts/verification/fixture-run"), { recursive: true });
    await writeFile(
      path.join(projectRoot, "artifacts/vulnerability/release-images-scan.receipt.json"),
      JSON.stringify({
        schemaVersion: "boardagent.release-images-scan.v2",
        status: "passed",
        sourceTreeSha256,
        vulnerabilityCount: 0,
        misconfigurationCount: 0,
        secretCount: 0
      })
    );
    await writeFile(
      path.join(projectRoot, "artifacts/verification/mutation.json"),
      JSON.stringify({ files: { "synthetic-fixture.ts": { mutants: [{ status: "Killed" }] } } })
    );
    return {
      projectRoot,
      directory: path.join(projectRoot, "artifacts/verification/fixture-run"),
      sourceTreeSha256
    };
  } catch (error) {
    await rm(projectRoot, { recursive: true, force: true });
    throw error;
  }
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

async function receipt(
  projectRoot: string,
  buildId: string,
  sourceTreeSha256: string,
  worktreeClean = true
): Promise<Gate3VerificationReceipt> {
  const [lockfile, registry, toolchainBytes] = await Promise.all([
    readFile(path.join(projectRoot, "pnpm-lock.yaml")),
    readFile(path.join(projectRoot, "lib/contracts/src/generated/registry.manifest.json")),
    readFile(path.join(projectRoot, "artifacts/provenance/toolchain.json"))
  ]);
  const toolchain = JSON.parse(toolchainBytes.toString("utf8")) as {
    node: { version: string };
  };
  return {
    schemaVersion: "boardagent.verification-receipt.v1",
    buildId,
    mode: "private-beta",
    selectedTier: null,
    label: "PRIVATE HARDENED BETA — INDEPENDENT REVIEW NOT COMPLETE",
    status: "passed",
    startedAt: "2026-09-05T00:00:00.000Z",
    completedAt: "2026-09-05T01:00:00.000Z",
    gitHead: "a".repeat(40),
    sourceTreeSha256,
    sourceTreeStable: true,
    worktreeClean,
    worktreeStatusSha256: worktreeClean ? sha256("") : "b".repeat(64),
    nodeVersion: `v${toolchain.node.version}`,
    lockfileSha256: sha256(lockfile),
    registrySha256: sha256(registry),
    migrationSetSha256: "e".repeat(64),
    tiers: Array.from({ length: 10 }, (_, index) => ({
      id: `T${String(index)}`,
      name: `tier-${String(index)}`,
      status: "passed" as const,
      commands: [
        {
          stdoutTail: " Test Files  1 passed (1)\n      Tests  2 passed (2)\n",
          stderrTail: ""
        }
      ]
    }))
  };
}

describe("Gate 3 evidence handoff", () => {
  it.each(["SR-001", "SR-102"])(
    "blocks a green automated receipt when %s remains unresolved",
    async (id) => {
      const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
      try {
        const registerPath = path.join(projectRoot, "docs/VERIFICATION.md");
        const register = await readFile(registerPath, "utf8");
        const row = register.split("\n").find((line) => line.startsWith(`| ${id} |`));
        expect(row).toBeDefined();
        await writeFile(
          registerPath,
          register.replace(row!, row!.replace(/PROVEN\s+\|$/u, "UNRESOLVED |"))
        );
        const input = await receipt(projectRoot, path.basename(directory), sourceTreeSha256);
        await writeFile(path.join(directory, "result.json"), JSON.stringify(input));
        const result = await writeGate3Handoff({
          projectRoot,
          receiptDirectory: directory,
          receipt: input
        });
        expect(result.candidateStatus).toBe("verification_blocked");
        expect(result.blockers).toContain(`unresolved security requirement ${id}`);
        const manifest = JSON.parse(await readFile(result.manifestPath, "utf8")) as {
          securityRequirementClosure: { registered: number; proven: number; unresolved: string[] };
        };
        expect(manifest.securityRequirementClosure).toMatchObject({
          registered: 102,
          proven: 101,
          unresolved: [id]
        });
        expect(await readFile(path.join(directory, "outcome-comparison.md"), "utf8")).toContain(
          "| Security requirements proven | 94 | 102 | 101 |"
        );
      } finally {
        await rm(projectRoot, { recursive: true, force: true });
      }
    }
  );

  it.each(["missing", "duplicate", "invalid-status", "missing-proof"])(
    "blocks an invalid security register: %s",
    async (fault) => {
      const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
      try {
        const registerPath = path.join(projectRoot, "docs/VERIFICATION.md");
        const register = await readFile(registerPath, "utf8");
        const row = register.split("\n").find((line) => line.startsWith("| SR-102 |"))!;
        const changed =
          fault === "missing"
            ? ""
            : fault === "duplicate"
              ? row.replace("SR-102", "SR-101")
              : fault === "invalid-status"
                ? row.replace(/PROVEN\s+\|$/u, "WAIVED |")
                : row.replace(/`tests\/[^`]+`/gu, "unexecuted");
        await writeFile(registerPath, register.replace(row, changed));
        const input = await receipt(projectRoot, path.basename(directory), sourceTreeSha256);
        await writeFile(path.join(directory, "result.json"), JSON.stringify(input));
        const result = await writeGate3Handoff({
          projectRoot,
          receiptDirectory: directory,
          receipt: input
        });
        expect(result.candidateStatus).toBe("verification_blocked");
        expect(result.blockers).toContain(
          "security requirement register is invalid or unavailable"
        );
      } finally {
        await rm(projectRoot, { recursive: true, force: true });
      }
    }
  );

  it("does not accept a declared passed T10 tier without its verified artifact bytes", async () => {
    const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
    try {
      const valid = await receipt(projectRoot, path.basename(directory), sourceTreeSha256);
      const input: Gate3VerificationReceipt = {
        ...valid,
        mode: "release",
        tiers: [
          ...valid.tiers,
          { id: "T10", name: "independent-review", status: "passed", commands: [] }
        ]
      };
      await writeFile(path.join(directory, "result.json"), JSON.stringify(input));
      const result = await writeGate3Handoff({
        projectRoot,
        receiptDirectory: directory,
        receipt: input
      });
      expect(result.candidateStatus).toBe("verification_blocked");
      expect(result.blockers).toContain("T10 artifact verification failed");
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
  it("binds the clean private-beta receipt, full evidence ledger, limitations, and pending decision", async () => {
    const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
    try {
      const input = await receipt(projectRoot, path.basename(directory), sourceTreeSha256);
      await writeFile(path.join(directory, "result.json"), `${JSON.stringify(input)}\n`);
      const result = await writeGate3Handoff({
        projectRoot,
        receiptDirectory: directory,
        receipt: input
      });

      expect(result).toMatchObject({
        candidateStatus: "private_hardened_beta_candidate_ready_for_gate3",
        blockers: []
      });
      expect(result.manifestSha256).toMatch(/^[0-9a-f]{64}$/u);
      const manifest = JSON.parse(await readFile(result.manifestPath, "utf8")) as {
        gate3Decision: string;
        goLiveAuthorized: boolean;
        deploymentPerformed: boolean;
        independentReview: { status: string };
        registryCounts: { tools: number; securityRequirements: number; threats: number };
        verification: { mutation: { survived: number }; tests: { testsSkipped: number } };
      };
      expect(manifest).toMatchObject({
        gate3Decision: "pending",
        goLiveAuthorized: false,
        deploymentPerformed: false,
        independentReview: { status: "not-completed" },
        registryCounts: { tools: 154, securityRequirements: 102, threats: 71 },
        verification: { mutation: { survived: 0 }, tests: { testsSkipped: 0 } }
      });
      const handoff = await readFile(path.join(directory, "HANDOFF.md"), "utf8");
      expect(handoff).toContain("This pack presents evidence; it is not sponsor approval.");
      // The build log is kept privately. Its absence is stated plainly, is never a
      // blocker, and it is not counted as evidence in the ledger.
      expect(handoff).toContain(
        "- Build log: **build log kept privately, not part of this repository**"
      );
      const ledger = JSON.parse(
        await readFile(path.join(directory, "evidence-ledger.json"), "utf8")
      ) as { status: string; entries: readonly { path: string; status: string }[] };
      expect(ledger.status).toBe("complete");
      expect(ledger.entries.some((entry) => entry.path === "BUILD_LOG.md")).toBe(false);
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it("lists a present build log as optional evidence and never as a requirement", async () => {
    const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
    try {
      const buildLog = "# Build log\n\nsynthetic fixture entry\n";
      await writeFile(path.join(projectRoot, "BUILD_LOG.md"), buildLog);
      const input = await receipt(projectRoot, path.basename(directory), sourceTreeSha256);
      await writeFile(path.join(directory, "result.json"), `${JSON.stringify(input)}\n`);
      const result = await writeGate3Handoff({
        projectRoot,
        receiptDirectory: directory,
        receipt: input
      });

      expect(result.blockers).toEqual([]);
      const digest = createHash("sha256").update(buildLog).digest("hex");
      const handoff = await readFile(path.join(directory, "HANDOFF.md"), "utf8");
      expect(handoff).toContain(
        `- Build log: \`BUILD_LOG.md\` (optional evidence, SHA-256 \`${digest}\`)`
      );
      expect(handoff).not.toContain("build log kept privately, not part of this repository");
      const ledger = JSON.parse(
        await readFile(path.join(directory, "evidence-ledger.json"), "utf8")
      ) as {
        entries: readonly { path: string; status: string; required: boolean; sha256: string }[];
      };
      expect(ledger.entries).toContainEqual(
        expect.objectContaining({
          path: "BUILD_LOG.md",
          category: "build-log",
          required: false,
          status: "present",
          sha256: digest
        })
      );
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it("blocks an otherwise green receipt when the candidate worktree is not clean", async () => {
    const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
    try {
      const input = await receipt(projectRoot, path.basename(directory), sourceTreeSha256, false);
      await writeFile(path.join(directory, "result.json"), `${JSON.stringify(input)}\n`);
      const result = await writeGate3Handoff({
        projectRoot,
        receiptDirectory: directory,
        receipt: input
      });
      expect(result.candidateStatus).toBe("verification_blocked");
      expect(result.blockers).toContain("candidate source is not committed in a clean worktree");
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it("blocks a receipt that is not bound to the evidenced lockfile", async () => {
    const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
    try {
      const valid = await receipt(projectRoot, path.basename(directory), sourceTreeSha256);
      const input: Gate3VerificationReceipt = { ...valid, lockfileSha256: "f".repeat(64) };
      await writeFile(path.join(directory, "result.json"), `${JSON.stringify(input)}\n`);
      const result = await writeGate3Handoff({
        projectRoot,
        receiptDirectory: directory,
        receipt: input
      });
      expect(result.candidateStatus).toBe("verification_blocked");
      expect(result.blockers).toContain(
        "verification receipt is not bound to the evidenced toolchain and lockfile"
      );
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it.each(["Survived", "NoCoverage"])(
    "blocks actual undetected mutation evidence: %s",
    async (status) => {
      const { projectRoot, directory, sourceTreeSha256 } = await fixtureProject();
      try {
        const input = await receipt(projectRoot, path.basename(directory), sourceTreeSha256);
        await writeFile(path.join(directory, "result.json"), JSON.stringify(input));
        await writeFile(
          path.join(projectRoot, "artifacts/verification/mutation.json"),
          JSON.stringify({ files: { "synthetic-fixture.ts": { mutants: [{ status }] } } })
        );
        const result = await writeGate3Handoff({
          projectRoot,
          receiptDirectory: directory,
          receipt: input
        });
        expect(result.candidateStatus).toBe("verification_blocked");
        expect(result.blockers).toContain(
          "mutation evidence is empty or contains an undetected mutant"
        );
      } finally {
        await rm(projectRoot, { recursive: true, force: true });
      }
    }
  );
});
