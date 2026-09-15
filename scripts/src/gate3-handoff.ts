import { createHash } from "node:crypto";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { validateVerificationClosure } from "./verification-register.js";

import {
  readAndVerifyIndependentReview,
  REVIEW_METADATA_PATH
} from "./independent-review-evidence.js";

import {
  ACTIVE_REGISTRY_COUNTS,
  ADMINISTRATIVE_AMENDMENT
} from "../../lib/contracts/src/registry/schema.js";

type CandidateMode = "private-beta" | "release";

interface VerificationCommandReceipt {
  readonly stdoutTail: string;
  readonly stderrTail: string;
}

interface VerificationTierReceipt {
  readonly id: string;
  readonly name: string;
  readonly status: "passed" | "failed";
  readonly commands: readonly VerificationCommandReceipt[];
}

export interface Gate3VerificationReceipt {
  readonly schemaVersion: string;
  readonly buildId: string;
  readonly mode: CandidateMode;
  readonly selectedTier: string | null;
  readonly label: string;
  readonly status: "passed" | "failed";
  readonly startedAt: string;
  readonly completedAt: string;
  readonly gitHead: string;
  readonly sourceTreeSha256: string;
  readonly sourceTreeStable: boolean;
  readonly worktreeClean: boolean;
  readonly worktreeStatusSha256: string;
  readonly nodeVersion: string;
  readonly lockfileSha256: string;
  readonly registrySha256: string;
  readonly migrationSetSha256: string;
  readonly tiers: readonly VerificationTierReceipt[];
}

interface EvidenceEntry {
  readonly path: string;
  readonly category: string;
  readonly required: boolean;
  readonly status: "present" | "missing";
  readonly bytes: number | null;
  readonly sha256: string | null;
}

interface ReleaseScanReceipt {
  readonly schemaVersion?: unknown;
  readonly status?: unknown;
  readonly sourceTreeSha256?: unknown;
  readonly vulnerabilityCount?: unknown;
  readonly misconfigurationCount?: unknown;
  readonly secretCount?: unknown;
  readonly scannedAt?: unknown;
  readonly components?: unknown;
}

// The build log is kept privately and is not part of the public repository. When it is
// absent the handoff says so and does not count it as evidence; when present it is
// listed as optional evidence only.
const BUILD_LOG_PATH = "BUILD_LOG.md";
const BUILD_LOG_ABSENT_STATEMENT = "build log kept privately, not part of this repository";

const REQUIRED_EVIDENCE = [
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
  "docs/AGENT_GUIDE.md",
  "docs/HARVEST_REPORT.md",
  "docs/KNOWN_LIMITATIONS.md",
  "docs/SURFACE_REFERENCE.md",
  "docs/THREAT_MODEL.md",
  "docs/VERIFICATION.md",
  ADMINISTRATIVE_AMENDMENT.path,
  ADMINISTRATIVE_AMENDMENT.authorizationPath,
  "planning/GATE1-MANIFEST.md",
  "planning/GATE1-APPROVAL-RECORD.md",
  "planning/gate2/gate2/GATE2-MANIFEST.md",
  "planning/gate2/GATE2-APPROVAL-RECORD.md",
  "lib/contracts/src/generated/registry.manifest.json",
  "artifacts/provenance/container-images.json",
  "artifacts/provenance/toolchain.json",
  "artifacts/sbom/boardagent.cdx.json",
  "artifacts/license-report/dependencies.json",
  "artifacts/vulnerability/release-images-scan.receipt.json",
  "artifacts/verification/mutation.json"
] as const;

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

const EMPTY_WORKTREE_SHA256 = sha256("");
const EXPECTED_REGISTRY_COUNTS = {
  tools: ACTIVE_REGISTRY_COUNTS.tools,
  resourceTemplates: ACTIVE_REGISTRY_COUNTS.resourceTemplates,
  prompts: ACTIVE_REGISTRY_COUNTS.prompts,
  httpAuthorityFamilies: ACTIVE_REGISTRY_COUNTS.httpAuthorityFamilies,
  cliCommands: ACTIVE_REGISTRY_COUNTS.cliCommands,
  events: ACTIVE_REGISTRY_COUNTS.events,
  securityRequirements: ACTIVE_REGISTRY_COUNTS.securityRequirements,
  threats: ACTIVE_REGISTRY_COUNTS.threats,
  acceptanceScenarios: ACTIVE_REGISTRY_COUNTS.acceptanceScenarios
} as const;

function expectedLabel(mode: CandidateMode): string {
  return mode === "release"
    ? "PUBLIC PRODUCTION CANDIDATE"
    : "PRIVATE HARDENED BETA — INDEPENDENT REVIEW NOT COMPLETE";
}

async function filesIn(root: string, relativeDirectory: string): Promise<readonly string[]> {
  const directory = path.join(root, relativeDirectory);
  try {
    return (await readdir(directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile())
      .map((entry) => path.posix.join(relativeDirectory, entry.name))
      .toSorted();
  } catch (error: unknown) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error as { code?: unknown }).code === "ENOENT"
    ) {
      return [];
    }
    throw error;
  }
}

async function evidenceEntry(
  root: string,
  relativePath: string,
  category: string,
  required: boolean
): Promise<EvidenceEntry> {
  try {
    const absolutePath = path.join(root, relativePath);
    const [bytes, metadata] = await Promise.all([readFile(absolutePath), stat(absolutePath)]);
    if (!metadata.isFile()) throw new Error(`${relativePath} is not a regular evidence file`);
    return {
      path: relativePath,
      category,
      required,
      status: "present",
      bytes: bytes.length,
      sha256: sha256(bytes)
    };
  } catch (error: unknown) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error as { code?: unknown }).code === "ENOENT"
    ) {
      return {
        path: relativePath,
        category,
        required,
        status: "missing",
        bytes: null,
        sha256: null
      };
    }
    throw error;
  }
}

function categoryFor(relativePath: string): string {
  if (relativePath === BUILD_LOG_PATH) return "build-log";
  if (relativePath.startsWith("planning/")) return "architect-gates";
  if (relativePath.startsWith("docs/adr/")) return "architecture-decisions";
  if (relativePath.startsWith("docs/runbooks/")) return "operator-runbooks";
  if (relativePath.startsWith("docs/")) return "product-documentation";
  if (relativePath.startsWith("artifacts/vulnerability/")) return "security-scan";
  if (relativePath.startsWith("artifacts/sbom/")) return "sbom";
  if (relativePath.startsWith("artifacts/license-report/")) return "licenses";
  if (relativePath.startsWith("artifacts/provenance/")) return "provenance";
  if (relativePath.startsWith("artifacts/verification/")) return "verification";
  return "release-input";
}

function stripAnsi(value: string): string {
  const [head = "", ...tails] = value.split("\u001b");
  return `${head}${tails.map((tail) => tail.replace(/^\[[0-9;]*m/u, "")).join("")}`;
}

function testTotals(tiers: readonly VerificationTierReceipt[]): {
  readonly testFileInvocationsPassed: number;
  readonly testsPassed: number;
  readonly testsFailed: number;
  readonly testsSkipped: number;
} {
  let testFileInvocationsPassed = 0;
  let testsPassed = 0;
  let testsFailed = 0;
  let testsSkipped = 0;
  for (const command of tiers.flatMap((tier) => tier.commands)) {
    const lines = stripAnsi(`${command.stdoutTail}\n${command.stderrTail}`).split(/\r?\n/u);
    for (const line of lines) {
      if (/\bTest Files\b/u.test(line)) {
        testFileInvocationsPassed += Number(/(\d+) passed/u.exec(line)?.[1] ?? "0");
      } else if (/^\s*Tests\s/u.test(line)) {
        testsPassed += Number(/(\d+) passed/u.exec(line)?.[1] ?? "0");
        testsFailed += Number(/(\d+) failed/u.exec(line)?.[1] ?? "0");
        testsSkipped += Number(/(\d+) skipped/u.exec(line)?.[1] ?? "0");
      }
    }
  }
  return { testFileInvocationsPassed, testsPassed, testsFailed, testsSkipped };
}

async function mutationTotals(root: string): Promise<{
  readonly total: number;
  readonly detected: number;
  readonly survived: number;
  readonly byStatus: Readonly<Record<string, number>>;
}> {
  const report = JSON.parse(
    await readFile(path.join(root, "artifacts/verification/mutation.json"), "utf8")
  ) as { files?: Readonly<Record<string, { mutants?: readonly { status?: unknown }[] }>> };
  const mutants = Object.values(report.files ?? {}).flatMap((file) => file.mutants ?? []);
  const byStatus: Record<string, number> = {};
  for (const mutant of mutants) {
    const status = typeof mutant.status === "string" ? mutant.status : "Unknown";
    byStatus[status] = (byStatus[status] ?? 0) + 1;
  }
  const detected = (byStatus["Killed"] ?? 0) + (byStatus["Timeout"] ?? 0);
  return {
    total: mutants.length,
    detected,
    survived: byStatus["Survived"] ?? 0,
    byStatus: Object.fromEntries(
      Object.entries(byStatus).toSorted(([left], [right]) => left.localeCompare(right))
    )
  };
}

function expectedTiers(mode: CandidateMode): readonly string[] {
  const privateBeta = Array.from({ length: 10 }, (_, index) => `T${String(index)}`);
  return mode === "private-beta" ? privateBeta : [...privateBeta, "T10"];
}

function renderOutcomeComparison(input: {
  readonly receipt: Gate3VerificationReceipt;
  readonly candidateStatus: string;
  readonly blockers: readonly string[];
  readonly counts: Readonly<Record<string, number>>;
  readonly provenSecurityRequirements: number;
  readonly mutation: Awaited<ReturnType<typeof mutationTotals>>;
  readonly tests: ReturnType<typeof testTotals>;
  readonly t10Status: "passed" | "not-completed";
}): string {
  const tiers = input.receipt.tiers.map((tier) => `${tier.id} ${tier.status}`).join(", ");
  const blockerText =
    input.blockers.length === 0
      ? "None for the stated candidate label. Gate 3 approval remains a human decision."
      : input.blockers.map((blocker) => `- ${blocker}`).join("\n");
  return `# BoardAgent outcome versus frozen plan

- Build ID: \`${input.receipt.buildId}\`
- Candidate status: **${input.candidateStatus}**
- Source tree: \`${input.receipt.sourceTreeSha256}\`
- Release label: **${input.receipt.label}**

| Registry objective | Frozen base | With recorded amendments | Observed |
| --- | ---: | ---: | ---: |
| MCP tools | 148 | ${String(ACTIVE_REGISTRY_COUNTS.tools)} | ${String(input.counts["tools"] ?? 0)} |
| Resource templates | 16 | 16 | ${String(input.counts["resourceTemplates"] ?? 0)} |
| Prompts | 7 | 7 | ${String(input.counts["prompts"] ?? 0)} |
| HTTP authority families | 11 | 11 | ${String(input.counts["httpAuthorityFamilies"] ?? 0)} |
| CLI commands | 9 | ${String(ACTIVE_REGISTRY_COUNTS.cliCommands)} | ${String(input.counts["cliCommands"] ?? 0)} |
| Closed events | 128 | ${String(ACTIVE_REGISTRY_COUNTS.events)} | ${String(input.counts["events"] ?? 0)} |
| Security requirements proven | 94 | 102 | ${String(input.provenSecurityRequirements)} |
| Registered threats executed | 63 | 71 | ${String(input.counts["threats"] ?? 0)} |
| Acceptance scenarios | 22 | 25 | ${String(input.counts["acceptanceScenarios"] ?? 0)} |
| Mutation survivors | 0 | 0 | ${String(input.mutation.survived)} |
| Deterministic test failures/skips | 0 | 0 | ${String(input.tests.testsFailed + input.tests.testsSkipped)} |

Executed tier receipts: ${tiers}.

Vitest evidence records ${String(input.tests.testFileInvocationsPassed)} passed test-file
invocations and ${String(input.tests.testsPassed)} passed tests across the tier commands;
intentional cross-tier reruns are counted each time. Mutation evidence records
${String(input.mutation.detected)} detected of ${String(input.mutation.total)} generated
mutants with zero survivors.

T10 independent review: **${input.t10Status}**. Gate 3 sponsor decision: **pending**.
Deployment: **not performed and not authorized by this pack**.

## Blockers and disposition

${blockerText}
`;
}

async function writeExclusive(filePath: string, content: string): Promise<void> {
  await writeFile(filePath, content, { encoding: "utf8", flag: "wx", mode: 0o644 });
}

export async function writeGate3Handoff(input: {
  readonly projectRoot: string;
  readonly receiptDirectory: string;
  readonly receipt: Gate3VerificationReceipt;
}): Promise<{
  readonly candidateStatus: string;
  readonly blockers: readonly string[];
  readonly manifestPath: string;
  readonly manifestSha256: string;
}> {
  const { projectRoot, receiptDirectory, receipt } = input;
  const relativeReceiptDirectory = path.relative(projectRoot, receiptDirectory);
  if (relativeReceiptDirectory.startsWith("..") || path.isAbsolute(relativeReceiptDirectory)) {
    throw new Error("Gate-3 receipt directory must remain inside the project");
  }

  const [adrs, runbooks, scans] = await Promise.all([
    filesIn(projectRoot, "docs/adr"),
    filesIn(projectRoot, "docs/runbooks"),
    filesIn(projectRoot, "artifacts/vulnerability")
  ]);
  const receiptPath = path.posix.join(relativeReceiptDirectory, "result.json");
  const required = new Set<string>([...REQUIRED_EVIDENCE, ...adrs, ...runbooks, receiptPath]);
  const blockers: string[] = [];
  let reviewDigests: Readonly<Record<string, string>> = {};
  if (receipt.mode === "release") {
    required.add(REVIEW_METADATA_PATH);
    try {
      const verified = await readAndVerifyIndependentReview(projectRoot, {
        gitCommit: receipt.gitHead,
        sourceTreeSha256: receipt.sourceTreeSha256
      });
      reviewDigests = verified.artifactSha256;
      for (const name of Object.keys(reviewDigests)) required.add(name);
    } catch {
      blockers.push("T10 artifact verification failed");
    }
  }
  const paths = [...new Set([...required, ...scans, BUILD_LOG_PATH])].toSorted();
  const buildLog = await evidenceEntry(projectRoot, BUILD_LOG_PATH, "build-log", false);
  const entries = (
    await Promise.all(
      paths.map((relativePath) =>
        relativePath === BUILD_LOG_PATH
          ? buildLog
          : evidenceEntry(
              projectRoot,
              relativePath,
              categoryFor(relativePath),
              required.has(relativePath)
            )
      )
    )
  ).filter((entry) => entry.path !== BUILD_LOG_PATH || entry.status === "present");

  for (const [name, digest] of Object.entries(reviewDigests)) {
    if (entries.find((entry) => entry.path === name)?.sha256 !== digest) {
      blockers.push("T10 artifact changed while preparing the evidence ledger");
    }
  }
  if (receipt.schemaVersion !== "boardagent.verification-receipt.v1") {
    blockers.push("verification receipt schema is not supported");
  }
  if (receipt.buildId !== path.basename(receiptDirectory)) {
    blockers.push("verification receipt build ID does not match its evidence directory");
  }
  if (receipt.label !== expectedLabel(receipt.mode)) {
    blockers.push("verification receipt label does not match its candidate mode");
  }
  if (!/^[0-9a-f]{40}$/u.test(receipt.gitHead)) {
    blockers.push("verification receipt is not bound to an exact Git commit");
  }
  if (!/^[0-9a-f]{64}$/u.test(receipt.sourceTreeSha256)) {
    blockers.push("verification receipt has no valid source-tree digest");
  }
  if (receipt.selectedTier !== null) blockers.push("verification was a selected-tier run");
  if (receipt.status !== "passed") blockers.push("verification receipt is not passed");
  if (!receipt.sourceTreeStable) blockers.push("source tree changed during verification");
  if (!receipt.worktreeClean)
    blockers.push("candidate source is not committed in a clean worktree");
  if (receipt.worktreeClean && receipt.worktreeStatusSha256 !== EMPTY_WORKTREE_SHA256) {
    blockers.push("clean-worktree claim does not match the recorded Git status digest");
  }
  const expected = expectedTiers(receipt.mode);
  if (
    receipt.tiers.length !== expected.length ||
    receipt.tiers.some((tier, index) => tier.id !== expected[index] || tier.status !== "passed")
  ) {
    blockers.push(`required ${expected.join("–")} tier sequence is not fully passed`);
  }
  for (const entry of entries) {
    if (entry.required && entry.status === "missing") blockers.push(`missing ${entry.path}`);
  }

  // Registry membership does not establish closure. Read the actual evidence register
  // and bind the same bytes to the ledger before making any candidate-ready claim.
  let securityRequirementClosure: {
    registered: number;
    proven: number;
    unresolved: readonly string[];
    valid: boolean;
    registerSha256: string | null;
  } = { registered: 0, proven: 0, unresolved: [], valid: false, registerSha256: null };
  try {
    const bytes = await readFile(path.join(projectRoot, "docs/VERIFICATION.md"));
    const pointers = validateVerificationClosure(bytes.toString("utf8"));
    const digest = sha256(bytes);
    if (entries.find((entry) => entry.path === "docs/VERIFICATION.md")?.sha256 !== digest) {
      throw new Error("security register changed during evidence capture");
    }
    const unresolved = pointers.filter(({ status }) => status !== "PROVEN").map(({ id }) => id);
    securityRequirementClosure = {
      registered: pointers.length,
      proven: pointers.length - unresolved.length,
      unresolved,
      valid: true,
      registerSha256: digest
    };
    for (const id of unresolved) blockers.push(`unresolved security requirement ${id}`);
  } catch {
    blockers.push("security requirement register is invalid or unavailable");
  }

  const scan = JSON.parse(
    await readFile(
      path.join(projectRoot, "artifacts/vulnerability/release-images-scan.receipt.json"),
      "utf8"
    )
  ) as ReleaseScanReceipt;
  if (
    scan.schemaVersion !== "boardagent.release-images-scan.v2" ||
    scan.status !== "passed" ||
    scan.sourceTreeSha256 !== receipt.sourceTreeSha256 ||
    scan.vulnerabilityCount !== 0 ||
    scan.misconfigurationCount !== 0 ||
    scan.secretCount !== 0
  ) {
    blockers.push("release-image scan is stale, incomplete, or non-green for this source tree");
  }

  const [registryBytes, lockfileBytes, toolchainBytes] = await Promise.all([
    readFile(path.join(projectRoot, "lib/contracts/src/generated/registry.manifest.json")),
    readFile(path.join(projectRoot, "pnpm-lock.yaml")),
    readFile(path.join(projectRoot, "artifacts/provenance/toolchain.json"))
  ]);
  const registryManifest = JSON.parse(registryBytes.toString("utf8")) as {
    registry?: {
      tools?: readonly unknown[];
      resourceTemplates?: readonly unknown[];
      prompts?: readonly unknown[];
      httpAuthorityFamilies?: readonly unknown[];
      cli?: readonly { commands?: readonly unknown[] }[];
      events?: readonly unknown[];
      securityRequirements?: readonly unknown[];
      threats?: readonly unknown[];
      acceptanceScenarios?: readonly unknown[];
    };
  };
  const registry = registryManifest.registry ?? {};
  const counts = {
    tools: registry.tools?.length ?? 0,
    resourceTemplates: registry.resourceTemplates?.length ?? 0,
    prompts: registry.prompts?.length ?? 0,
    httpAuthorityFamilies: registry.httpAuthorityFamilies?.length ?? 0,
    cliCommands: registry.cli?.flatMap((entry) => entry.commands ?? []).length ?? 0,
    events: registry.events?.length ?? 0,
    securityRequirements: registry.securityRequirements?.length ?? 0,
    threats: registry.threats?.length ?? 0,
    acceptanceScenarios: registry.acceptanceScenarios?.length ?? 0
  };
  for (const key of Object.keys(
    EXPECTED_REGISTRY_COUNTS
  ) as (keyof typeof EXPECTED_REGISTRY_COUNTS)[]) {
    if (counts[key] !== EXPECTED_REGISTRY_COUNTS[key]) {
      blockers.push(
        `active registry count ${key} expected ${String(EXPECTED_REGISTRY_COUNTS[key])}, observed ${String(counts[key])}`
      );
    }
  }
  if (receipt.registrySha256 !== sha256(registryBytes)) {
    blockers.push("verification receipt registry digest does not match the evidenced registry");
  }
  const toolchain = JSON.parse(toolchainBytes.toString("utf8")) as {
    schemaVersion?: unknown;
    node?: { version?: unknown };
    lockfileSha256?: unknown;
  };
  const actualLockfileSha256 = sha256(lockfileBytes);
  if (
    toolchain.schemaVersion !== 1 ||
    typeof toolchain.node?.version !== "string" ||
    receipt.nodeVersion !== `v${toolchain.node.version}` ||
    toolchain.lockfileSha256 !== actualLockfileSha256 ||
    receipt.lockfileSha256 !== actualLockfileSha256
  ) {
    blockers.push("verification receipt is not bound to the evidenced toolchain and lockfile");
  }
  const mutation = await mutationTotals(projectRoot);
  if (mutation.total === 0 || mutation.survived !== 0 || mutation.detected !== mutation.total) {
    blockers.push("mutation evidence is empty or contains an undetected mutant");
  }
  const tests = testTotals(receipt.tiers);
  if (
    tests.testFileInvocationsPassed === 0 ||
    tests.testsPassed === 0 ||
    tests.testsFailed !== 0 ||
    tests.testsSkipped !== 0
  ) {
    blockers.push("verification command summaries are missing or contain failed or skipped tests");
  }

  const t10Status = receipt.tiers.some((tier) => tier.id === "T10" && tier.status === "passed")
    ? "passed"
    : "not-completed";
  if (receipt.mode === "release" && t10Status !== "passed") {
    blockers.push("T10 independent review is not passed");
  }
  const candidateStatus =
    blockers.length > 0
      ? "verification_blocked"
      : receipt.mode === "release"
        ? "public_production_candidate_ready_for_gate3"
        : "private_hardened_beta_candidate_ready_for_gate3";

  const ledger = {
    schemaVersion: "boardagent.gate3-evidence-ledger.v1",
    buildId: receipt.buildId,
    generatedAt: receipt.completedAt,
    sourceTreeSha256: receipt.sourceTreeSha256,
    status: entries.every((entry) => !entry.required || entry.status === "present")
      ? "complete"
      : "incomplete",
    entries
  } as const;
  const ledgerContent = `${JSON.stringify(ledger, null, 2)}\n`;
  const ledgerPath = path.join(receiptDirectory, "evidence-ledger.json");
  await writeExclusive(ledgerPath, ledgerContent);

  const outcomeContent = renderOutcomeComparison({
    receipt,
    candidateStatus,
    blockers,
    counts,
    provenSecurityRequirements: securityRequirementClosure.proven,
    mutation,
    tests,
    t10Status
  });
  const outcomePath = path.join(receiptDirectory, "outcome-comparison.md");
  await writeExclusive(outcomePath, outcomeContent);

  const resultBytes = await readFile(path.join(receiptDirectory, "result.json"));
  const limitations = entries.find(({ path: relativePath }) =>
    relativePath.endsWith("docs/KNOWN_LIMITATIONS.md")
  );
  const manifest = {
    schemaVersion: "boardagent.gate3-manifest.v1",
    buildId: receipt.buildId,
    generatedAt: receipt.completedAt,
    candidateStatus,
    releaseLabel: receipt.label,
    gate3Decision: "pending",
    goLiveAuthorized: false,
    deploymentPerformed: false,
    verification: {
      receipt: receiptPath,
      receiptSha256: sha256(resultBytes),
      status: receipt.status,
      sourceTreeSha256: receipt.sourceTreeSha256,
      sourceTreeStable: receipt.sourceTreeStable,
      worktreeClean: receipt.worktreeClean,
      worktreeStatusSha256: receipt.worktreeStatusSha256,
      gitHead: receipt.gitHead,
      nodeVersion: receipt.nodeVersion,
      lockfileSha256: receipt.lockfileSha256,
      registrySha256: receipt.registrySha256,
      migrationSetSha256: receipt.migrationSetSha256,
      tiers: receipt.tiers.map(({ id, name, status }) => ({ id, name, status })),
      tests,
      mutation
    },
    registryCounts: counts,
    securityRequirementClosure,
    releaseImages: scan.components,
    scan: {
      schemaVersion: scan.schemaVersion,
      status: scan.status,
      scannedAt: scan.scannedAt,
      sourceTreeSha256: scan.sourceTreeSha256,
      vulnerabilityCount: scan.vulnerabilityCount,
      misconfigurationCount: scan.misconfigurationCount,
      secretCount: scan.secretCount
    },
    evidenceLedger: {
      path: path.posix.join(relativeReceiptDirectory, "evidence-ledger.json"),
      sha256: sha256(ledgerContent),
      entries: entries.length
    },
    outcomeComparison: {
      path: path.posix.join(relativeReceiptDirectory, "outcome-comparison.md"),
      sha256: sha256(outcomeContent)
    },
    knownLimitations: {
      path: limitations?.path ?? "docs/KNOWN_LIMITATIONS.md",
      sha256: limitations?.sha256 ?? null
    },
    independentReview: {
      requiredForPublicProduction: true,
      status: t10Status
    },
    blockers
  } as const;
  const manifestContent = `${JSON.stringify(manifest, null, 2)}\n`;
  const manifestPath = path.join(receiptDirectory, "gate3-manifest.json");
  await writeExclusive(manifestPath, manifestContent);
  const manifestSha256 = sha256(manifestContent);

  const buildLogLine =
    buildLog.status === "present"
      ? `\`${BUILD_LOG_PATH}\` (optional evidence, SHA-256 \`${buildLog.sha256 ?? ""}\`)`
      : `**${BUILD_LOG_ABSENT_STATEMENT}**`;
  const blockerLines =
    blockers.length === 0
      ? "- No verification blocker exists for the stated candidate label."
      : blockers.map((blocker) => `- ${blocker}`).join("\n");
  const handoffContent = `# BoardAgent Gate 3 handoff

- Candidate: **${candidateStatus}**
- Exact label: **${receipt.label}**
- Source tree: \`${receipt.sourceTreeSha256}\`
- Git commit: \`${receipt.gitHead}\`
- Gate 3 manifest: \`gate3-manifest.json\` (SHA-256 \`${manifestSha256}\`)
- Evidence ledger: \`evidence-ledger.json\`
- Outcome comparison: \`outcome-comparison.md\`
- Build log: ${buildLogLine}
- Gate 3 decision: **pending**
- Deployment: **not performed or authorized**

## Verification disposition

${blockerLines}

T10 independent review is **${t10Status}**. Without T10 the maximum truthful label is
private hardened beta. This pack presents evidence; it is not sponsor approval. The project owner may
accept the exact candidate, accept it with named limitations/follow-ups, or return it to the
build. Deployment, pushing, external-review contact and real-data use remain separate acts.
`;
  await writeExclusive(path.join(receiptDirectory, "HANDOFF.md"), handoffContent);

  return {
    candidateStatus,
    blockers,
    manifestPath,
    manifestSha256
  };
}
