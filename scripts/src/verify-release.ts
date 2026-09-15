import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { sourceTreeSha256ForFiles } from "./source-tree-sha256.js";
import {
  verificationPlan,
  type VerificationCommand,
  type VerificationMode,
  type VerificationTier
} from "./verification-plan.js";
import { writeGate3Handoff, type Gate3VerificationReceipt } from "./gate3-handoff.js";

interface CommandReceipt {
  readonly executable: string;
  readonly args: readonly string[];
  readonly startedAt: string;
  readonly durationMs: number;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly timedOut: boolean;
  readonly stdoutSha256: string;
  readonly stderrSha256: string;
  readonly stdoutTail: string;
  readonly stderrTail: string;
}

interface TierReceipt {
  readonly id: VerificationTier["id"];
  readonly name: string;
  readonly status: "passed" | "failed";
  readonly commands: readonly CommandReceipt[];
}

const PROJECT = path.resolve(import.meta.dirname, "../..");

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function tail(value: string, maximum = 16_384): string {
  return value.length <= maximum ? value : value.slice(-maximum);
}

async function runCommand(input: VerificationCommand): Promise<CommandReceipt> {
  const startedAt = new Date().toISOString();
  const started = performance.now();
  const child = spawn(input.executable, [...input.args], {
    cwd: PROJECT,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
    process.stdout.write(chunk);
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
    process.stderr.write(chunk);
  });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
  }, input.timeoutMs);
  const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    }
  ).finally(() => clearTimeout(timer));
  return {
    executable: path.relative(PROJECT, input.executable),
    args: input.args,
    startedAt,
    durationMs: Math.round(performance.now() - started),
    exitCode: result.code,
    signal: result.signal,
    timedOut,
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(stderr),
    stdoutTail: tail(stdout),
    stderrTail: tail(stderr)
  };
}

async function hashMigrationSet(): Promise<string> {
  const directory = path.join(PROJECT, "lib", "db", "migrations");
  const names = (await readdir(directory)).filter((name) => name.endsWith(".sql")).toSorted();
  const digest = createHash("sha256");
  for (const name of names) {
    digest.update(name);
    digest.update("\0");
    digest.update(await readFile(path.join(directory, name)));
  }
  return digest.digest("hex");
}

const SOURCE_DIGEST_EXCLUSIONS = [
  "BUILD_LOG.md",
  "artifacts/verification/",
  "artifacts/sbom/",
  "artifacts/license-report/",
  "coverage/"
] as const;

function trackedAndUntrackedFiles(): readonly string[] {
  const result = spawnSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], {
    cwd: PROJECT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024
  });
  if (result.status !== 0) throw new Error("cannot enumerate source tree for verification receipt");
  return result.stdout
    .split("\0")
    .filter(Boolean)
    .filter(
      (name) =>
        !SOURCE_DIGEST_EXCLUSIONS.some((excluded) =>
          excluded.endsWith("/") ? name.startsWith(excluded) : name === excluded
        )
    )
    .toSorted();
}

export async function sourceTreeSha256(): Promise<string> {
  return sourceTreeSha256ForFiles(trackedAndUntrackedFiles(), async (name) =>
    readFile(path.join(PROJECT, name))
  );
}

function worktreeStatus(): { readonly clean: boolean; readonly sha256: string } {
  const result = spawnSync("git", ["status", "--porcelain=v1", "-z", "--untracked-files=all"], {
    cwd: PROJECT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024
  });
  if (result.status !== 0) throw new Error("cannot read worktree state for verification receipt");
  return { clean: result.stdout.length === 0, sha256: sha256(result.stdout) };
}

function gitHead(): string {
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: PROJECT,
    encoding: "utf8"
  });
  return result.status === 0 ? result.stdout.trim() : "unavailable";
}

export function verificationSnapshotStable(input: {
  readonly sourceTreeSha256Before: string;
  readonly sourceTreeSha256After: string;
  readonly worktreeStatusSha256Before: string;
  readonly worktreeStatusSha256After: string;
  readonly gitHeadBefore: string;
  readonly gitHeadAfter: string;
}): boolean {
  return (
    input.sourceTreeSha256Before === input.sourceTreeSha256After &&
    input.worktreeStatusSha256Before === input.worktreeStatusSha256After &&
    input.gitHeadBefore === input.gitHeadAfter
  );
}

export function verificationExitCode(
  status: "passed" | "failed",
  gate3CandidateStatus?: string
): 0 | 1 {
  const gate3Ready =
    gate3CandidateStatus === undefined ||
    gate3CandidateStatus === "private_hardened_beta_candidate_ready_for_gate3" ||
    gate3CandidateStatus === "public_production_candidate_ready_for_gate3";
  return status === "passed" && gate3Ready ? 0 : 1;
}

async function main(): Promise<number> {
  const requestedMode = process.argv[2];
  if (
    requestedMode !== "phase1" &&
    requestedMode !== "private-beta" &&
    requestedMode !== "release"
  ) {
    throw new Error("usage: verify-release.ts <phase1|private-beta|release>");
  }
  const mode: VerificationMode = requestedMode;
  const tierFlag = process.argv.indexOf("--tier");
  const selectedTier = tierFlag < 0 ? undefined : process.argv[tierFlag + 1];
  if (tierFlag >= 0 && !/^T(?:10|[0-9])$/u.test(selectedTier ?? "")) {
    throw new Error("--tier requires one exact tier ID from T0 through T10");
  }
  const plan = verificationPlan(mode);
  const selectedPlan = selectedTier ? plan.filter(({ id }) => id === selectedTier) : plan;
  if (selectedPlan.length === 0) {
    throw new Error(`${selectedTier ?? "requested tier"} is outside the ${mode} plan`);
  }
  const buildStartedAt = new Date().toISOString();
  const sourceTreeSha256Before = await sourceTreeSha256();
  const worktreeStatusBefore = worktreeStatus();
  const gitHeadBefore = gitHead();
  const buildId = `${buildStartedAt.replaceAll(/[-:.TZ]/gu, "").slice(0, 17)}-${gitHeadBefore.slice(0, 12)}-${selectedTier?.toLowerCase() ?? mode}-${String(process.pid)}`;
  const receiptDirectory = path.join(PROJECT, "artifacts", "verification", buildId);
  await mkdir(path.dirname(receiptDirectory), { recursive: true });
  await mkdir(receiptDirectory, { recursive: false });
  const tiers: TierReceipt[] = [];
  for (const tier of selectedPlan) {
    process.stdout.write(`\n=== ${tier.id} ${tier.name} ===\n`);
    const commands: CommandReceipt[] = [];
    for (const invocation of tier.commands) {
      const receipt = await runCommand(invocation);
      commands.push(receipt);
      if (receipt.exitCode !== 0 || receipt.timedOut) break;
    }
    tiers.push({
      id: tier.id,
      name: tier.name,
      status:
        commands.length === tier.commands.length &&
        commands.every(({ exitCode, timedOut }) => exitCode === 0 && !timedOut)
          ? "passed"
          : "failed",
      commands
    });
  }
  const sourceTreeSha256After = await sourceTreeSha256();
  const worktreeStatusAfter = worktreeStatus();
  const gitHeadAfter = gitHead();
  const sourceTreeStable = verificationSnapshotStable({
    sourceTreeSha256Before,
    sourceTreeSha256After,
    worktreeStatusSha256Before: worktreeStatusBefore.sha256,
    worktreeStatusSha256After: worktreeStatusAfter.sha256,
    gitHeadBefore,
    gitHeadAfter
  });
  const status: "passed" | "failed" =
    tiers.every((tier) => tier.status === "passed") && sourceTreeStable ? "passed" : "failed";
  const receipt = {
    schemaVersion: "boardagent.verification-receipt.v1",
    buildId,
    mode,
    selectedTier: selectedTier ?? null,
    label:
      mode === "private-beta"
        ? "PRIVATE HARDENED BETA — INDEPENDENT REVIEW NOT COMPLETE"
        : mode === "release"
          ? "PUBLIC PRODUCTION CANDIDATE"
          : "PHASE 1 — NOT A RELEASE",
    status,
    startedAt: buildStartedAt,
    completedAt: new Date().toISOString(),
    gitHead: gitHeadAfter,
    sourceTreeSha256: sourceTreeSha256After,
    sourceTreeStable,
    worktreeClean: worktreeStatusBefore.clean && worktreeStatusAfter.clean,
    worktreeStatusSha256: worktreeStatusAfter.sha256,
    nodeVersion: process.version,
    lockfileSha256: sha256(await readFile(path.join(PROJECT, "pnpm-lock.yaml"))),
    registrySha256: sha256(
      await readFile(
        path.join(PROJECT, "lib", "contracts", "src", "generated", "registry.manifest.json")
      )
    ),
    migrationSetSha256: await hashMigrationSet(),
    tiers
  };
  const receiptPath = path.join(receiptDirectory, "result.json");
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx" });
  let gate3CandidateStatus: string | undefined;
  if (selectedTier === undefined && mode !== "phase1") {
    const candidateReceipt: Gate3VerificationReceipt = { ...receipt, mode };
    const handoff = await writeGate3Handoff({
      projectRoot: PROJECT,
      receiptDirectory,
      receipt: candidateReceipt
    });
    gate3CandidateStatus = handoff.candidateStatus;
    process.stdout.write(
      `Gate 3 handoff: ${path.relative(PROJECT, handoff.manifestPath)} (${handoff.candidateStatus})\n`
    );
    if (handoff.blockers.length > 0) {
      process.stderr.write(
        `Gate 3 evidence validation blocked this candidate:\n${handoff.blockers.map((blocker) => `- ${blocker}`).join("\n")}\n`
      );
    }
  }
  process.stdout.write(
    `\n${status.toUpperCase()} receipt: ${path.relative(PROJECT, receiptPath)}\n`
  );
  return verificationExitCode(status, gate3CandidateStatus);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await main();
}
