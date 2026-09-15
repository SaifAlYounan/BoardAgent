import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rename, rm, symlink, truncate, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  readAndVerifyIndependentReview,
  REVIEW_METADATA_PATH,
  verifyIndependentReviewEvidence
} from "../../scripts/src/independent-review-evidence.js";

const digest = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const report = Buffer.from("Synthetic parser test only: not independent review evidence.");
const legal = Buffer.from("Synthetic parser test only: not legal advice or approval.");
const candidate = { gitCommit: "a".repeat(40), sourceTreeSha256: "b".repeat(64) };
const decision = {
  schemaVersion: "boardagent.gate3-sponsor-decision.v1",
  recordedAt: "2026-09-01T00:00:00Z",
  project: "BoardAgent",
  candidate: { gitHead: candidate.gitCommit, sourceTreeSha256: candidate.sourceTreeSha256 },
  decision: {
    status: "approved",
    scope: "exact-private-hardened-beta-candidate-for-independent-t10"
  },
  authority: { gate3Approved: true, independentT10ReviewAuthorized: true },
  syntheticWarning: "UNIT TEST ONLY — no actual sponsor decision"
};
const decisionBytes = Buffer.from(JSON.stringify(decision));
const fixture = {
  schemaVersion: "boardagent.independent-security-review.v2",
  reviewedGitCommit: candidate.gitCommit,
  sourceTreeSha256: candidate.sourceTreeSha256,
  reviewerOrganization: "UNIT TEST ONLY",
  reviewerName: "UNIT TEST ONLY",
  completedAt: "2026-09-01T01:00:00Z",
  reportPath: "artifacts/review/synthetic/report.txt",
  reportSha256: digest(report),
  unresolvedCritical: 0,
  unresolvedHigh: 0,
  mediumDisposition: "UNIT TEST ONLY",
  deploymentLegalReviewPath: "artifacts/review/synthetic/legal.txt",
  deploymentLegalReviewSha256: digest(legal),
  gate3DecisionPath: "artifacts/verification/synthetic/decision.json",
  gate3DecisionSha256: digest(decisionBytes)
};

async function withEvidence(run: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(path.join(os.tmpdir(), "boardagent-synthetic-review-"));
  try {
    await mkdir(path.join(root, "artifacts/review/synthetic"), { recursive: true });
    await mkdir(path.join(root, "artifacts/verification/synthetic"), { recursive: true });
    await writeFile(path.join(root, REVIEW_METADATA_PATH), JSON.stringify(fixture));
    await writeFile(path.join(root, fixture.reportPath), report);
    await writeFile(path.join(root, fixture.deploymentLegalReviewPath), legal);
    await writeFile(path.join(root, fixture.gate3DecisionPath), decisionBytes);
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("independent review artifact integrity (synthetic inputs only)", () => {
  it("requires exact security report and legal artifact bytes", () => {
    expect(() =>
      verifyIndependentReviewEvidence(fixture, candidate, report, legal, decisionBytes)
    ).not.toThrow();
    for (const changed of [
      Buffer.from("changed"),
      Buffer.alloc(0),
      Buffer.alloc(16 * 1024 * 1024 + 1)
    ]) {
      expect(() =>
        verifyIndependentReviewEvidence(fixture, candidate, changed, legal, decisionBytes)
      ).toThrow();
      expect(() =>
        verifyIndependentReviewEvidence(fixture, candidate, report, changed, decisionBytes)
      ).toThrow();
    }
  });
  it("retains exact commit, source and unresolved finding gates", () => {
    for (const changed of [
      { ...candidate, gitCommit: "c".repeat(40) },
      { ...candidate, sourceTreeSha256: "c".repeat(64) }
    ])
      expect(() =>
        verifyIndependentReviewEvidence(fixture, changed, report, legal, decisionBytes)
      ).toThrow();
    for (const changed of [
      { unresolvedHigh: 1 },
      { unresolvedCritical: 1 },
      { schemaVersion: "boardagent.independent-security-review.v1" }
    ]) {
      expect(() =>
        verifyIndependentReviewEvidence(
          { ...fixture, ...changed },
          candidate,
          report,
          legal,
          decisionBytes
        )
      ).toThrow();
    }
  });
  it("requires unchanged sponsor bytes and an earlier approval for this exact candidate", () => {
    const variants = [
      { ...decision, authority: { ...decision.authority, gate3Approved: false } },
      { ...decision, authority: { ...decision.authority, independentT10ReviewAuthorized: false } },
      { ...decision, candidate: { ...decision.candidate, gitHead: "c".repeat(40) } },
      { ...decision, candidate: { ...decision.candidate, sourceTreeSha256: "c".repeat(64) } },
      { ...decision, decision: { ...decision.decision, status: "rejected" } },
      { ...decision, recordedAt: "2026-09-02T00:00:00Z" }
    ];
    for (const changed of variants) {
      const bytes = Buffer.from(JSON.stringify(changed));
      expect(() =>
        verifyIndependentReviewEvidence(fixture, candidate, report, legal, bytes)
      ).toThrow();
      expect(() =>
        verifyIndependentReviewEvidence(
          { ...fixture, gate3DecisionSha256: digest(bytes) },
          candidate,
          report,
          legal,
          bytes
        )
      ).toThrow();
    }
  });
  it("executes filesystem loading through the same verifier used by the release CLI", async () => {
    await withEvidence(async (root) => {
      expect((await readAndVerifyIndependentReview(root, candidate)).review).toEqual(fixture);
      await writeFile(path.join(root, fixture.reportPath), "altered after metadata was recorded");
      await expect(readAndVerifyIndependentReview(root, candidate)).rejects.toThrow(/digest/u);
    });
  });
  it("rejects duplicate metadata keys instead of selecting the last interpretation", async () => {
    await withEvidence(async (root) => {
      const ambiguous = JSON.stringify(fixture).replace("{", '{"unresolvedHigh":1,');
      await writeFile(path.join(root, REVIEW_METADATA_PATH), ambiguous);
      await expect(readAndVerifyIndependentReview(root, candidate)).rejects.toThrow();
    });
  });
  it.each([
    "missing",
    "empty",
    "oversized",
    "directory",
    "symlink",
    "ancestor-symlink",
    "metadata-symlink"
  ])("refuses %s evidence", async (failure) => {
    await withEvidence(async (root) => {
      const target = path.join(root, fixture.reportPath);
      if (failure === "empty") await truncate(target, 0);
      else if (failure === "oversized") await truncate(target, 16 * 1024 * 1024 + 1);
      else if (failure === "ancestor-symlink") {
        const directory = path.dirname(target);
        await rename(directory, `${directory}-real`);
        await symlink(`${directory}-real`, directory);
      } else if (failure === "metadata-symlink") {
        const metadata = path.join(root, REVIEW_METADATA_PATH);
        await rename(metadata, `${metadata}.real`);
        await symlink(`${metadata}.real`, metadata);
      } else {
        await rm(target);
        if (failure === "directory") await mkdir(target);
        if (failure === "symlink")
          await symlink(path.join(root, fixture.deploymentLegalReviewPath), target);
      }
      await expect(readAndVerifyIndependentReview(root, candidate)).rejects.toThrow();
    });
  });
  it.each([
    "/etc/passwd",
    "artifacts/review/../verification/synthetic/decision.json",
    "artifacts/review/./synthetic/report.txt",
    "artifacts/review//synthetic/report.txt",
    "artifacts/review/synthetic\\report.txt"
  ])("rejects escaped or ambiguous path %s", async (reportPath) => {
    await withEvidence(async (root) => {
      await writeFile(
        path.join(root, REVIEW_METADATA_PATH),
        JSON.stringify({ ...fixture, reportPath })
      );
      await expect(readAndVerifyIndependentReview(root, candidate)).rejects.toThrow(/path/u);
    });
  });
});
