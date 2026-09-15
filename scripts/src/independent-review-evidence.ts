import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import { canonicalJsonFromText } from "@boardagent/contracts";

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/u);
const GitCommit = z.string().regex(/^[0-9a-f]{40}$/u);
const ArtifactPath = z.string().min(1).max(1024);
export const REVIEW_METADATA_PATH = "artifacts/review/independent-security-review.json";
const MAX_METADATA_BYTES = 256 * 1024;
const MAX_REPORT_BYTES = 16 * 1024 * 1024;

export const IndependentReviewSchema = z
  .object({
    schemaVersion: z.literal("boardagent.independent-security-review.v2"),
    reviewedGitCommit: GitCommit,
    sourceTreeSha256: Sha256,
    reviewerOrganization: z.string().trim().min(1).max(512),
    reviewerName: z.string().trim().min(1).max(512),
    completedAt: z.iso.datetime({ offset: false }),
    reportPath: ArtifactPath,
    reportSha256: Sha256,
    unresolvedCritical: z.literal(0),
    unresolvedHigh: z.literal(0),
    mediumDisposition: z.string().trim().min(1).max(65_536),
    deploymentLegalReviewPath: ArtifactPath,
    deploymentLegalReviewSha256: Sha256,
    gate3DecisionPath: ArtifactPath,
    gate3DecisionSha256: Sha256
  })
  .strict();

// Validate the authority-bearing subset; preserved human/candidate attachments may
// contain additional fields. Hash the entire decision, not this parsed projection.
const Gate3DecisionSchema = z.object({
  schemaVersion: z.literal("boardagent.gate3-sponsor-decision.v1"),
  recordedAt: z.iso.datetime({ offset: false }),
  project: z.literal("BoardAgent"),
  candidate: z.object({ gitHead: GitCommit, sourceTreeSha256: Sha256 }),
  decision: z.object({
    status: z.literal("approved"),
    scope: z.literal("exact-private-hardened-beta-candidate-for-independent-t10")
  }),
  authority: z.object({
    gate3Approved: z.literal(true),
    independentT10ReviewAuthorized: z.literal(true)
  })
});

export interface ReviewCandidate {
  readonly gitCommit: string;
  readonly sourceTreeSha256: string;
}

function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertDigest(bytes: Uint8Array, expected: string, maximum: number, label: string): void {
  if (bytes.byteLength === 0 || bytes.byteLength > maximum || hash(bytes) !== expected) {
    throw new Error(`T10 ${label} bytes are absent, oversized or do not match their digest`);
  }
}

export function verifyIndependentReviewEvidence(
  value: unknown,
  candidate: ReviewCandidate,
  report: Uint8Array,
  legalReview: Uint8Array,
  gate3Decision: Uint8Array
): z.infer<typeof IndependentReviewSchema> {
  const review = IndependentReviewSchema.parse(value);
  if (
    review.reviewedGitCommit !== candidate.gitCommit ||
    review.sourceTreeSha256 !== candidate.sourceTreeSha256
  ) {
    throw new Error("T10 review evidence does not bind the current Git commit and source tree");
  }
  assertDigest(report, review.reportSha256, MAX_REPORT_BYTES, "security report");
  assertDigest(legalReview, review.deploymentLegalReviewSha256, MAX_REPORT_BYTES, "legal review");
  assertDigest(gate3Decision, review.gate3DecisionSha256, MAX_METADATA_BYTES, "Gate 3 decision");
  const decision = Gate3DecisionSchema.parse(
    JSON.parse(canonicalJsonFromText(gate3Decision)) as unknown
  );
  if (
    decision.candidate.gitHead !== candidate.gitCommit ||
    decision.candidate.sourceTreeSha256 !== candidate.sourceTreeSha256 ||
    Date.parse(decision.recordedAt) > Date.parse(review.completedAt)
  ) {
    throw new Error("T10 review does not follow an approval for this exact candidate");
  }
  return review;
}

function confinedParts(relativePath: string, allowedRoot: string): string[] {
  const parts = relativePath.split("/");
  if (
    !relativePath.startsWith(`${allowedRoot}/`) ||
    relativePath.includes("\\") ||
    relativePath.includes("\0") ||
    parts.some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error("T10 artifact path escapes its permitted evidence directory");
  }
  return parts;
}

/** Evidence directories are operator-owned. Reject linked paths and bound every read. */
async function readArtifact(
  projectRoot: string,
  relativePath: string,
  allowedRoot: string,
  maximumBytes: number
): Promise<Buffer> {
  const parts = confinedParts(relativePath, allowedRoot);
  const root = await realpath(projectRoot);
  let target = root;
  for (const [index, part] of parts.entries()) {
    target = path.join(target, part);
    const entry = await lstat(target);
    if (entry.isSymbolicLink() || (index < parts.length - 1 && !entry.isDirectory())) {
      throw new Error("T10 evidence paths must not contain symlinks or non-directories");
    }
  }
  const handle = await open(
    target,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  );
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size === 0 || before.size > maximumBytes) {
      throw new Error("T10 evidence must be a nonempty bounded regular file");
    }
    // Read at most maximum+1 even if another process grows the file after stat.
    const buffer = Buffer.alloc(maximumBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = await handle.read(buffer, length, buffer.length - length, null);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    const after = await handle.stat();
    const named = await lstat(target);
    if (
      length !== before.size ||
      length > maximumBytes ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      named.isSymbolicLink() ||
      named.ino !== after.ino ||
      named.dev !== after.dev ||
      (await realpath(target)) !== target
    ) {
      throw new Error("T10 evidence changed or escaped while being read");
    }
    return buffer.subarray(0, length);
  } finally {
    await handle.close();
  }
}

export async function readAndVerifyIndependentReview(
  projectRoot: string,
  candidate: ReviewCandidate
): Promise<{
  readonly review: z.infer<typeof IndependentReviewSchema>;
  readonly artifactSha256: Readonly<Record<string, string>>;
}> {
  const metadata = await readArtifact(
    projectRoot,
    REVIEW_METADATA_PATH,
    "artifacts/review",
    MAX_METADATA_BYTES
  );
  const review = IndependentReviewSchema.parse(
    JSON.parse(canonicalJsonFromText(metadata)) as unknown
  );
  const report = await readArtifact(
    projectRoot,
    review.reportPath,
    "artifacts/review",
    MAX_REPORT_BYTES
  );
  const legal = await readArtifact(
    projectRoot,
    review.deploymentLegalReviewPath,
    "artifacts/review",
    MAX_REPORT_BYTES
  );
  const decision = await readArtifact(
    projectRoot,
    review.gate3DecisionPath,
    "artifacts/verification",
    MAX_METADATA_BYTES
  );
  verifyIndependentReviewEvidence(review, candidate, report, legal, decision);
  return {
    review,
    artifactSha256: {
      [REVIEW_METADATA_PATH]: hash(metadata),
      [review.reportPath]: review.reportSha256,
      [review.deploymentLegalReviewPath]: review.deploymentLegalReviewSha256,
      [review.gate3DecisionPath]: review.gate3DecisionSha256
    }
  };
}
