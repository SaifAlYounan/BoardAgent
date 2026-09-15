import { describe, expect, it } from "vitest";

import {
  compareDecisionPackages,
  decisionPackageHash,
  prepareVoteElectorate,
  replacementPlan,
  voteElectorateEvidenceHash,
  voteReplacementConsentHash
} from "../../lib/domain/src/index.js";
import { DecisionPackageSchema, canonicalSha256 } from "../../lib/contracts/src/index.js";

const id = (suffix: number): string =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;
const hash = (character: string): string => character.repeat(64);

function decisionPackage(voteId: string, resolutionSha256 = hash("1")) {
  return DecisionPackageSchema.parse({
    schemaVersion: "boardagent.decision-package.v1",
    voteId,
    packageVersion: 1,
    resolutionVersionId: id(2),
    resolutionSha256,
    governanceProfileVersionId: id(3),
    governanceProfileSha256: hash("2"),
    rulesetVersionId: id(4),
    rulesetSha256: hash("3"),
    approvalRuleId: id(5),
    approvalRuleSha256: hash("4"),
    matterEvaluationId: id(7),
    matterEvaluationResultSha256: hash("7"),
    selectedRulesetRuleId: id(8),
    selectedRulesetRuleSha256: hash("8"),
    ruleOverride: null,
    electorateSha256: hash("5"),
    closeMode: "automatic",
    deadlineAt: "2026-09-30T12:00:00Z",
    components: [{ type: "document", ordinal: 1, id: id(6), version: 1, sha256: hash("6") }]
  });
}

describe("immutable decision packages", () => {
  it("hashes exact canonical package bytes", () => {
    const input = decisionPackage(id(1));
    expect(decisionPackageHash(input)).toMatch(/^[0-9a-f]{64}$/u);
    expect(decisionPackageHash(input)).toBe(decisionPackageHash(structuredClone(input)));
  });

  it("classifies every changed frozen component", () => {
    const before = decisionPackage(id(1));
    const after = {
      ...decisionPackage(id(10), hash("9")),
      deadlineAt: "2026-10-01T12:00:00Z" as typeof before.deadlineAt,
      components: [
        {
          ...before.components[0]!,
          sha256: hash("8") as (typeof before.components)[number]["sha256"]
        }
      ]
    };
    expect(compareDecisionPackages(before, after)).toEqual(["resolution", "deadline", "document"]);
  });

  it("classifies each remaining semantic package component", () => {
    const before = decisionPackage(id(1));
    const changed = DecisionPackageSchema.parse({
      ...before,
      governanceProfileVersionId: id(20),
      rulesetVersionId: id(21),
      approvalRuleId: id(22),
      closeMode: "secretariat_confirmed",
      components: [
        { type: "management_submission", ordinal: 1, id: id(30), version: 1, sha256: hash("a") },
        { type: "document", ordinal: 2, id: id(31), version: 1, sha256: hash("b") },
        { type: "question_cutoff", ordinal: 3, id: id(32), version: 1, sha256: hash("c") }
      ]
    });
    expect(compareDecisionPackages(before, changed)).toEqual([
      "governance_profile",
      "ruleset",
      "approval_rule",
      "close_mode",
      "management_submission",
      "document",
      "question_cutoff"
    ]);
  });

  it("classifies every independently changed semantic digest", () => {
    const before = decisionPackage(id(1));
    for (const [field, value, expected] of [
      ["governanceProfileSha256", hash("a"), "governance_profile"],
      ["rulesetSha256", hash("a"), "ruleset"],
      ["matterEvaluationId", id(40), "ruleset"],
      ["matterEvaluationResultSha256", hash("a"), "ruleset"],
      ["selectedRulesetRuleId", id(41), "ruleset"],
      ["selectedRulesetRuleSha256", hash("a"), "ruleset"],
      ["approvalRuleSha256", hash("a"), "approval_rule"]
    ] as const) {
      const after = DecisionPackageSchema.parse({ ...before, [field]: value });
      expect(compareDecisionPackages(before, after)).toEqual([expected]);
    }

    const withOverride = DecisionPackageSchema.parse({
      ...before,
      ruleOverride: { id: id(42), canonicalSha256: hash("a") }
    });
    expect(
      compareDecisionPackages(
        withOverride,
        DecisionPackageSchema.parse({
          ...withOverride,
          ruleOverride: { ...withOverride.ruleOverride!, id: id(43) }
        })
      )
    ).toEqual(["ruleset"]);
    expect(
      compareDecisionPackages(
        withOverride,
        DecisionPackageSchema.parse({
          ...withOverride,
          ruleOverride: { ...withOverride.ruleOverride!, canonicalSha256: hash("b") }
        })
      )
    ).toEqual(["ruleset"]);
  });

  it("creates a linked replacement with explicit zero-carry sets", () => {
    const before = decisionPackage(id(1));
    const after = decisionPackage(id(10), hash("9"));
    const plan = replacementPlan(before, after, [id(50), id(51)], [id(51)], false);
    expect(plan).toMatchObject({
      oldVoteId: before.voteId,
      newVoteId: after.voteId,
      changedComponentClasses: ["resolution"],
      carriedBallotIds: [],
      carriedStageIds: [],
      carriedProxyGrantIds: [],
      revoteRequiredMemberIds: [id(51)]
    });
    expect(() =>
      replacementPlan(before, { ...after, voteId: before.voteId }, [], [], false)
    ).toThrow("distinct vote");
  });

  it("does not report replacement-only IDs or vote-bound electorate hashes as changes", () => {
    const before = decisionPackage(id(1));
    const after = DecisionPackageSchema.parse({
      ...before,
      voteId: id(10),
      resolutionVersionId: id(11),
      electorateSha256: hash("9")
    });
    expect(compareDecisionPackages(before, after, false)).toEqual([]);
    expect(() => replacementPlan(before, after, [], [], false)).toThrow(
      "at least one changed package component"
    );
    expect(compareDecisionPackages(before, after, true)).toEqual(["electorate"]);
  });

  it("freezes a canonical sorted electorate without binding storage row IDs", () => {
    const first = prepareVoteElectorate({
      voteId: id(1),
      entries: [
        {
          id: id(80),
          memberId: id(20),
          membershipVersionId: id(30),
          votingWeight: 2n,
          eligibilitySnapshot: { eligible: true, seat: "B" }
        },
        {
          id: id(81),
          memberId: id(10),
          membershipVersionId: id(31),
          isChair: true,
          votingWeight: 1n,
          eligibilitySnapshot: { eligible: true, seat: "A" }
        }
      ]
    });
    const sameEvidenceDifferentRows = prepareVoteElectorate({
      voteId: id(1),
      entries: [
        { ...first.entries[0]!, id: id(90) },
        { ...first.entries[1]!, id: id(91) }
      ]
    });
    expect(first.entries.map(({ memberId }) => memberId)).toEqual([id(10), id(20)]);
    expect(first.entries.map(({ isChair }) => isChair)).toEqual([true, false]);
    expect(first.entries.map(({ seatRole }) => seatRole)).toEqual([
      "voting_member",
      "voting_member"
    ]);
    expect(sameEvidenceDifferentRows.electorateSha256).toBe(first.electorateSha256);
    expect(voteElectorateEvidenceHash(first.entries)).toBe(
      voteElectorateEvidenceHash(sameEvidenceDifferentRows.entries)
    );
    const expectedEvidenceHash = canonicalSha256({
      schemaVersion: "boardagent.vote-electorate-evidence.v1",
      entries: first.entries.map((entry) => ({
        memberId: entry.memberId,
        membershipVersionId: entry.membershipVersionId,
        seatRole: "voting_member",
        isChair: entry.isChair,
        votingWeight: Number(entry.votingWeight),
        eligibilitySnapshot: entry.eligibilitySnapshot,
        eligibilitySha256: entry.eligibilitySha256
      }))
    });
    expect(voteElectorateEvidenceHash(first.entries)).toBe(expectedEvidenceHash);
    expect(voteElectorateEvidenceHash([...first.entries].reverse())).toBe(expectedEvidenceHash);
    expect(
      prepareVoteElectorate({
        voteId: id(1),
        entries: first.entries.map((entry) => ({ ...entry, isChair: false }))
      }).electorateSha256
    ).not.toBe(first.electorateSha256);
  });

  it("rejects duplicate members and nonpositive or oversized weights", () => {
    const entry = {
      id: id(80),
      memberId: id(20),
      membershipVersionId: id(30),
      votingWeight: 1n,
      eligibilitySnapshot: { eligible: true }
    };
    expect(() =>
      prepareVoteElectorate({ voteId: id(1), entries: [entry, { ...entry, id: id(81) }] })
    ).toThrow("members must be unique");
    expect(() =>
      prepareVoteElectorate({
        voteId: id(1),
        entries: [entry, { ...entry, memberId: id(21) }]
      })
    ).toThrow("row IDs must be unique");
    expect(() => prepareVoteElectorate({ voteId: id(1), entries: [] })).toThrow("1 through 10000");
    expect(
      prepareVoteElectorate({
        voteId: id(1),
        entries: Array.from({ length: 10_000 }, (_, index) => ({
          id: id(100_000 + index),
          memberId: id(200_000 + index),
          membershipVersionId: id(300_000 + index),
          votingWeight: 1n,
          eligibilitySnapshot: { eligible: true }
        }))
      }).entries
    ).toHaveLength(10_000);
    expect(() =>
      prepareVoteElectorate({ voteId: id(1), entries: Array.from({ length: 10_001 }, () => entry) })
    ).toThrow("1 through 10000");
    expect(() =>
      prepareVoteElectorate({ voteId: id(1), entries: [{ ...entry, votingWeight: 0n }] })
    ).toThrow("weight");
    expect(() =>
      prepareVoteElectorate({
        voteId: id(1),
        entries: [{ ...entry, votingWeight: 1_000_000_001n }]
      })
    ).toThrow("weight");
    expect(
      prepareVoteElectorate({
        voteId: id(1),
        entries: [{ ...entry, votingWeight: 1_000_000_000n }]
      }).entries[0]?.votingWeight
    ).toBe(1_000_000_000n);
    expect(() =>
      prepareVoteElectorate({
        voteId: id(1),
        entries: [
          { ...entry, isChair: true },
          { ...entry, id: id(81), memberId: id(21), isChair: true }
        ]
      })
    ).toThrow("at most one chair");
  });

  it("rejects duplicate or malformed semantic electorate evidence", () => {
    const prepared = prepareVoteElectorate({
      voteId: id(1),
      entries: [
        {
          id: id(80),
          memberId: id(20),
          membershipVersionId: id(30),
          votingWeight: 1n,
          eligibilitySnapshot: { eligible: true }
        }
      ]
    });
    const evidence = prepared.entries[0]!;
    expect(() => voteElectorateEvidenceHash([evidence, evidence])).toThrow(
      "members must be unique"
    );
    expect(() => voteElectorateEvidenceHash([{ ...evidence, votingWeight: 2n ** 1_024n }])).toThrow(
      "semantic evidence is invalid"
    );
    expect(() =>
      voteElectorateEvidenceHash([{ ...evidence, eligibilitySha256: hash("f") }])
    ).toThrow("semantic evidence is invalid");
    expect(() => voteElectorateEvidenceHash([{ ...evidence, votingWeight: 0n }])).toThrow(
      "semantic evidence is invalid"
    );
    expect(() =>
      voteElectorateEvidenceHash([{ ...evidence, votingWeight: 1_000_000_001n }])
    ).toThrow("semantic evidence is invalid");
    expect(() => voteElectorateEvidenceHash([{ ...evidence, votingWeight: 1.5 as never }])).toThrow(
      "semantic evidence is invalid"
    );
    expect(voteElectorateEvidenceHash([{ ...evidence, votingWeight: 1_000_000_000n }])).toMatch(
      /^[0-9a-f]{64}$/u
    );
  });

  it("binds replacement title, reason, resolution and exact package into consent", () => {
    const input = {
      oldVoteId: id(1),
      newVoteId: id(2),
      newTitle: "Replacement vote",
      newResolutionVersionId: id(3),
      newResolutionSha256: "a".repeat(64),
      decisionPackageId: id(4),
      newPackageSha256: "b".repeat(64),
      reason: "Exact source bytes changed."
    };
    const expected = voteReplacementConsentHash(input);
    expect(expected).toBe(
      canonicalSha256({
        schemaVersion: "boardagent.vote-replacement-consent.v1",
        ...input
      })
    );
    expect(voteReplacementConsentHash({ ...input })).toBe(expected);
    expect(
      voteReplacementConsentHash({ ...input, newTitle: "Changed after confirmation" })
    ).not.toBe(expected);
    expect(voteReplacementConsentHash({ ...input, reason: "Changed reason" })).not.toBe(expected);
  });
});
