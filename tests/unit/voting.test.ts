import fc from "fast-check";
/*
 * Adapted from LQGovernance-OpenBoard, commit
 * 1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb, vote tally and proxy edge cases.
 * Copyright (c) 2026 Alexios Kirillov. Licensed under the Apache License 2.0.
 * Derived from LQGovernance-OpenBoard (MIT License); see docs/THIRD_PARTY_NOTICES.md.
 * Hostile changes: rewritten against BoardAgent's frozen electorate, exact rational
 * arithmetic, ineligible-principal rejection and principal-over-proxy semantics.
 */
import { describe, expect, it } from "vitest";

import {
  ballotConsentHash,
  canonicalVoteTally,
  chooseEffectiveBallot,
  eligibleVotingWeight,
  proxyGrantConsentHash,
  proxyRevokeConsentHash,
  rational,
  ruleOverrideConsentHash,
  ruleOverrideEvidenceHash,
  tallyVote,
  voteCloseConsentHash,
  voteRecusalConsentHash,
  voteSourceExclusionConsentHash,
  voteTallySha256
} from "../../lib/domain/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";

const majorityRule = {
  approval: rational(1n, 2n),
  quorum: rational(1n, 2n),
  approvalDenominator: "yes_no" as const,
  abstentionsCountForQuorum: true,
  tieBehavior: "reject" as const
};

const canonicalId = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
const canonicalHash = (character = "a"): string => character.repeat(64);

function canonicalOverride() {
  return {
    evaluationId: canonicalId(1),
    evaluationResultSha256: canonicalHash("1"),
    wizardDraftId: canonicalId(2),
    finalVoteId: canonicalId(3),
    recommendedRuleId: canonicalId(4),
    selectedRuleId: canonicalId(5),
    selectedRuleSha256: canonicalHash("2"),
    reason: "Exact documented override",
    citations: [
      {
        ruleId: canonicalId(5),
        sourceDocumentVersionId: canonicalId(6),
        sourceDocumentSha256: canonicalHash("3"),
        clause: "7.2",
        locator: "reserved matters"
      }
    ]
  };
}

describe("weighted voting kernel", () => {
  it("uses the tally kernel's exact eligibility rules for live recomputation", () => {
    expect(
      eligibleVotingWeight([
        {
          memberId: "eligible",
          role: "voting_member",
          weight: 7n,
          eligible: true,
          recused: false,
          chair: false
        },
        {
          memberId: "recused",
          role: "voting_member",
          weight: 11n,
          eligible: true,
          recused: true,
          chair: false
        },
        {
          memberId: "observer",
          role: "observer",
          weight: 0n,
          eligible: true,
          recused: false,
          chair: false
        }
      ])
    ).toBe(7n);
    expect(() =>
      eligibleVotingWeight([
        {
          memberId: "duplicate",
          role: "voting_member",
          weight: 1n,
          eligible: true,
          recused: false,
          chair: false
        },
        {
          memberId: "duplicate",
          role: "voting_member",
          weight: 1n,
          eligible: true,
          recused: false,
          chair: false
        }
      ])
    ).toThrow("duplicate electorate member");
  });

  it("excludes observers, management and recused seats from eligible weight", () => {
    const result = tallyVote(
      [
        {
          memberId: "a",
          role: "voting_member",
          weight: 5n,
          eligible: true,
          recused: false,
          chair: false
        },
        {
          memberId: "b",
          role: "voting_member",
          weight: 100n,
          eligible: true,
          recused: true,
          chair: false
        },
        {
          memberId: "c",
          role: "observer",
          weight: 0n,
          eligible: true,
          recused: false,
          chair: false
        },
        {
          memberId: "d",
          role: "management",
          weight: 0n,
          eligible: true,
          recused: false,
          chair: false
        }
      ],
      [{ principalMemberId: "a", casterMemberId: "a", choice: "yes", source: "own" }],
      majorityRule
    );
    expect(result.eligibleWeight).toBe(5n);
    expect(result.outcome).toBe("approved");
  });

  it("counts abstention toward quorum but not a yes/no denominator", () => {
    const result = tallyVote(
      [
        {
          memberId: "a",
          role: "voting_member",
          weight: 4n,
          eligible: true,
          recused: false,
          chair: false
        },
        {
          memberId: "b",
          role: "voting_member",
          weight: 6n,
          eligible: true,
          recused: false,
          chair: false
        }
      ],
      [
        { principalMemberId: "a", casterMemberId: "a", choice: "yes", source: "own" },
        { principalMemberId: "b", casterMemberId: "b", choice: "abstain", source: "own" }
      ],
      majorityRule
    );
    expect(result.quorumMet).toBe(true);
    expect(result.approvalMet).toBe(true);
  });

  it("rejects an exact tie when the frozen rule says reject", () => {
    const electorate = [
      {
        memberId: "a",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      },
      {
        memberId: "b",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      }
    ];
    const result = tallyVote(
      electorate,
      [
        { principalMemberId: "a", casterMemberId: "a", choice: "yes", source: "own" },
        { principalMemberId: "b", casterMemberId: "b", choice: "no", source: "own" }
      ],
      majorityRule
    );
    expect(result.outcome).toBe("rejected");
  });

  it("applies the one frozen chair casting-vote bit and rejects ambiguous chairs", () => {
    const electorate = [
      {
        memberId: "chair",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: true
      },
      {
        memberId: "member",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      }
    ];
    const result = tallyVote(
      electorate,
      [
        { principalMemberId: "chair", casterMemberId: "chair", choice: "yes", source: "own" },
        { principalMemberId: "member", casterMemberId: "member", choice: "no", source: "own" }
      ],
      { ...majorityRule, tieBehavior: "chair_casting_vote" }
    );
    expect(result.outcome).toBe("approved");
    expect(() =>
      tallyVote([electorate[0]!, { ...electorate[1]!, chair: true }], [], {
        ...majorityRule,
        tieBehavior: "chair_casting_vote"
      })
    ).toThrow("at most one chair");
  });

  it("enforces own/proxy attribution and eligible same-board proxy holders", () => {
    const electorate = [
      {
        memberId: "principal",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      },
      {
        memberId: "holder",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      },
      {
        memberId: "observer",
        role: "observer" as const,
        weight: 0n,
        eligible: true,
        recused: false,
        chair: false
      }
    ];
    expect(() =>
      tallyVote(
        electorate,
        [
          {
            principalMemberId: "principal",
            casterMemberId: "holder",
            choice: "yes",
            source: "own"
          }
        ],
        majorityRule
      )
    ).toThrow("own ballot caster");
    expect(() =>
      tallyVote(
        electorate,
        [
          {
            principalMemberId: "principal",
            casterMemberId: "observer",
            choice: "yes",
            source: "proxy"
          }
        ],
        majorityRule
      )
    ).toThrow("proxy holder is not eligible");
    expect(
      tallyVote(
        electorate,
        [
          {
            principalMemberId: "principal",
            casterMemberId: "holder",
            choice: "yes",
            source: "proxy"
          }
        ],
        majorityRule
      ).outcome
    ).toBe("approved");
  });

  it("allows only an own ballot to supersede an attributed proxy ballot", () => {
    const proxy = {
      principalMemberId: "principal",
      casterMemberId: "holder",
      choice: "yes" as const,
      source: "proxy" as const
    };
    const own = {
      principalMemberId: "principal",
      casterMemberId: "principal",
      choice: "no" as const,
      source: "own" as const
    };
    expect(chooseEffectiveBallot(proxy, own, "principal_supersedes_proxy")).toBe(own);
    expect(() => chooseEffectiveBallot(own, proxy, "principal_supersedes_proxy")).toThrow(
      "only the principal"
    );
    expect(chooseEffectiveBallot(undefined, own, "first_ballot_final")).toBe(own);
    expect(() =>
      chooseEffectiveBallot(
        own,
        { ...own, principalMemberId: "different" },
        "principal_supersedes_proxy"
      )
    ).toThrow("principal mismatch");
    expect(() => chooseEffectiveBallot(own, own, "first_ballot_final")).toThrow(
      "already has an active ballot"
    );
  });

  it("binds every consent and evidence field to its exact canonical envelope", () => {
    const override = canonicalOverride();
    expect(ruleOverrideConsentHash({ ...override, packageSha256: canonicalHash("4") })).toBe(
      canonicalSha256({
        schemaVersion: "boardagent.rule-override-consent.v1",
        ...override,
        packageSha256: canonicalHash("4")
      })
    );
    expect(
      ruleOverrideEvidenceHash({
        ...override,
        consentRecordId: canonicalId(7),
        auditEventId: canonicalId(8)
      })
    ).toBe(
      canonicalSha256({
        schemaVersion: "boardagent.rule-override-evidence.v1",
        ...override,
        consentRecordId: canonicalId(7),
        auditEventId: canonicalId(8)
      })
    );

    const exclusion = {
      voteId: canonicalId(9),
      causeId: canonicalId(10),
      sourceClass: "document" as const,
      sourceId: canonicalId(11),
      sourceVersion: 2,
      sourceSha256: canonicalHash("5"),
      reason: "Superseded source",
      packageSha256: canonicalHash("6")
    };
    expect(voteSourceExclusionConsentHash(exclusion)).toBe(
      canonicalSha256({
        schemaVersion: "boardagent.vote-source-exclusion-consent.v1",
        ...exclusion
      })
    );

    const recusal = {
      voteId: canonicalId(9),
      memberId: canonicalId(12),
      state: "lifted" as const,
      reason: "Conflict resolved",
      packageSha256: canonicalHash("7")
    };
    expect(voteRecusalConsentHash(recusal)).toBe(
      canonicalSha256({ schemaVersion: "boardagent.vote-recusal-consent.v1", ...recusal })
    );

    const grant = {
      voteId: canonicalId(9),
      principalMemberId: canonicalId(12),
      holderMemberId: canonicalId(13),
      policy: "principal_supersedes_proxy" as const,
      expiresAt: "2026-09-02T00:00:00Z",
      packageSha256: canonicalHash("8")
    };
    expect(proxyGrantConsentHash(grant)).toBe(
      canonicalSha256({ schemaVersion: "boardagent.proxy-grant-consent.v1", ...grant })
    );

    const revoke = {
      voteId: canonicalId(9),
      proxyGrantId: canonicalId(14),
      principalMemberId: canonicalId(12),
      reason: "Revoked",
      packageSha256: canonicalHash("9")
    };
    expect(proxyRevokeConsentHash(revoke)).toBe(
      canonicalSha256({ schemaVersion: "boardagent.proxy-revoke-consent.v1", ...revoke })
    );

    const ballot = {
      voteId: canonicalId(9),
      principalMemberId: canonicalId(12),
      casterMemberId: canonicalId(12),
      choice: "abstain" as const,
      statement: "Recorded abstention",
      proxyGrantId: null,
      packageSha256: canonicalHash("a")
    };
    expect(ballotConsentHash(ballot)).toBe(
      canonicalSha256({ schemaVersion: "boardagent.ballot-consent.v1", ...ballot })
    );

    const close = {
      voteId: canonicalId(9),
      packageSha256: canonicalHash("b"),
      expectedTallySha256: canonicalHash("c"),
      outcomeId: canonicalId(15),
      certificateId: canonicalId(16),
      certificatePublicIdSha256: canonicalHash("d"),
      signingKeyId: canonicalId(17)
    };
    expect(voteCloseConsentHash(close)).toBe(
      canonicalSha256({ schemaVersion: "boardagent.vote-close-consent.v1", ...close })
    );
  });

  it("enforces every exact override, exclusion, revocation, and statement boundary", () => {
    const override = canonicalOverride();
    const packageSha256 = canonicalHash("e");
    for (const reason of ["x", "x".repeat(65_536)]) {
      expect(ruleOverrideConsentHash({ ...override, reason, packageSha256 })).toHaveLength(64);
    }
    for (const reason of [" ", "x".repeat(65_537)]) {
      expect(() => ruleOverrideConsentHash({ ...override, reason, packageSha256 })).toThrow(
        "rule-override reason"
      );
    }

    const boundaryCitation = {
      ...override.citations[0]!,
      clause: "c".repeat(512),
      locator: "l".repeat(1024)
    };
    expect(
      ruleOverrideConsentHash({
        ...override,
        citations: [{ ...boundaryCitation, clause: "c", locator: "l" }],
        packageSha256
      })
    ).toHaveLength(64);
    expect(
      ruleOverrideConsentHash({ ...override, citations: [boundaryCitation], packageSha256 })
    ).toHaveLength(64);
    for (const citation of [
      { ...boundaryCitation, clause: "" },
      { ...boundaryCitation, clause: "c".repeat(513) },
      { ...boundaryCitation, locator: "" },
      { ...boundaryCitation, locator: "l".repeat(1025) }
    ]) {
      expect(() =>
        ruleOverrideConsentHash({ ...override, citations: [citation], packageSha256 })
      ).toThrow("bounded exact citations");
    }
    expect(() =>
      ruleOverrideConsentHash({
        ...override,
        citations: [boundaryCitation, { ...boundaryCitation, locator: "" }],
        packageSha256
      })
    ).toThrow("bounded exact citations");

    const exclusion = {
      voteId: canonicalId(20),
      causeId: canonicalId(21),
      sourceClass: "question_cutoff" as const,
      sourceId: canonicalId(22),
      sourceVersion: 1,
      sourceSha256: canonicalHash("1"),
      reason: "x",
      packageSha256
    };
    expect(voteSourceExclusionConsentHash(exclusion)).toHaveLength(64);
    expect(
      voteSourceExclusionConsentHash({ ...exclusion, reason: "x".repeat(65_536) })
    ).toHaveLength(64);
    for (const reason of [" ", "x".repeat(65_537)]) {
      expect(() => voteSourceExclusionConsentHash({ ...exclusion, reason })).toThrow(
        "source-exclusion reason"
      );
    }

    const revoke = {
      voteId: canonicalId(20),
      proxyGrantId: canonicalId(23),
      principalMemberId: canonicalId(24),
      reason: "x",
      packageSha256
    };
    expect(proxyRevokeConsentHash(revoke)).toHaveLength(64);
    expect(proxyRevokeConsentHash({ ...revoke, reason: "x".repeat(65_536) })).toHaveLength(64);
    expect(() => proxyRevokeConsentHash({ ...revoke, reason: "x".repeat(65_537) })).toThrow(
      "proxy revocation reason"
    );

    const ballot = {
      voteId: canonicalId(20),
      principalMemberId: canonicalId(24),
      casterMemberId: canonicalId(24),
      choice: "yes" as const,
      statement: "x".repeat(500),
      proxyGrantId: null,
      packageSha256
    };
    expect(ballotConsentHash(ballot)).toHaveLength(64);
    expect(() => ballotConsentHash({ ...ballot, statement: "x".repeat(501) })).toThrow(
      "ballot statement"
    );
  });

  it("binds consent hashes and rejects malformed override, exclusion, proxy and ballot inputs", () => {
    const id = (suffix: number) =>
      `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
    const hash = "a".repeat(64);
    const override = {
      evaluationId: id(1),
      evaluationResultSha256: hash,
      wizardDraftId: id(2),
      finalVoteId: id(3),
      recommendedRuleId: id(4),
      selectedRuleId: id(5),
      selectedRuleSha256: hash,
      reason: "Exact documented override",
      citations: [
        {
          ruleId: id(5),
          sourceDocumentVersionId: id(6),
          sourceDocumentSha256: hash,
          clause: "7.2",
          locator: "reserved matters"
        }
      ]
    };
    expect(ruleOverrideConsentHash({ ...override, packageSha256: hash })).toHaveLength(64);
    expect(
      ruleOverrideConsentHash({ ...override, recommendedRuleId: null, packageSha256: hash })
    ).toHaveLength(64);
    expect(
      ruleOverrideEvidenceHash({ ...override, consentRecordId: id(7), auditEventId: id(8) })
    ).toHaveLength(64);
    expect(() =>
      ruleOverrideConsentHash({ ...override, reason: " ", packageSha256: hash })
    ).toThrow("reason");
    expect(() =>
      ruleOverrideConsentHash({ ...override, citations: [], packageSha256: hash })
    ).toThrow("citations");
    expect(() =>
      ruleOverrideConsentHash({
        ...override,
        citations: [{ ...override.citations[0]!, clause: "x".repeat(513) }],
        packageSha256: hash
      })
    ).toThrow("citations");

    const exclusion = {
      voteId: id(9),
      causeId: id(10),
      sourceClass: "document" as const,
      sourceId: id(11),
      sourceVersion: 1,
      sourceSha256: hash,
      reason: "Superseded source",
      packageSha256: hash
    };
    expect(voteSourceExclusionConsentHash(exclusion)).toHaveLength(64);
    expect(() => voteSourceExclusionConsentHash({ ...exclusion, reason: "" })).toThrow("reason");
    expect(() =>
      voteSourceExclusionConsentHash({ ...exclusion, sourceClass: "invalid" as never })
    ).toThrow("class");
    expect(() => voteSourceExclusionConsentHash({ ...exclusion, sourceVersion: 0 })).toThrow(
      "version"
    );
    expect(
      voteRecusalConsentHash({
        voteId: id(9),
        memberId: id(12),
        state: "excluded",
        reason: "Conflict",
        packageSha256: hash
      })
    ).toHaveLength(64);

    const grant = {
      voteId: id(9),
      principalMemberId: id(12),
      holderMemberId: id(13),
      policy: "principal_supersedes_proxy" as const,
      expiresAt: "2026-09-02T00:00:00Z",
      packageSha256: hash
    };
    expect(proxyGrantConsentHash(grant)).toHaveLength(64);
    expect(proxyGrantConsentHash({ ...grant, expiresAt: null })).toHaveLength(64);
    expect(() =>
      proxyGrantConsentHash({ ...grant, holderMemberId: grant.principalMemberId })
    ).toThrow("differ");
    expect(() => proxyGrantConsentHash({ ...grant, policy: "invalid" as never })).toThrow("policy");
    expect(
      proxyRevokeConsentHash({
        voteId: grant.voteId,
        proxyGrantId: id(14),
        principalMemberId: grant.principalMemberId,
        reason: "Revoked",
        packageSha256: hash
      })
    ).toHaveLength(64);
    expect(() =>
      proxyRevokeConsentHash({
        voteId: grant.voteId,
        proxyGrantId: id(14),
        principalMemberId: grant.principalMemberId,
        reason: "",
        packageSha256: hash
      })
    ).toThrow("reason");

    const ballot = {
      voteId: grant.voteId,
      principalMemberId: grant.principalMemberId,
      casterMemberId: grant.principalMemberId,
      choice: "yes" as const,
      statement: "Approved",
      proxyGrantId: null,
      packageSha256: hash
    };
    expect(ballotConsentHash(ballot)).toHaveLength(64);
    expect(ballotConsentHash({ ...ballot, statement: null })).toHaveLength(64);
    expect(() => ballotConsentHash({ ...ballot, choice: "invalid" as never })).toThrow("choice");
    expect(() => ballotConsentHash({ ...ballot, statement: "x".repeat(501) })).toThrow("statement");
    expect(() => ballotConsentHash({ ...ballot, proxyGrantId: id(14) })).toThrow("inconsistent");
    expect(() =>
      ballotConsentHash({ ...ballot, casterMemberId: grant.holderMemberId, proxyGrantId: null })
    ).toThrow("inconsistent");
    expect(
      voteCloseConsentHash({
        voteId: grant.voteId,
        packageSha256: hash,
        expectedTallySha256: hash,
        outcomeId: id(15),
        certificateId: id(16),
        certificatePublicIdSha256: hash,
        signingKeyId: id(17)
      })
    ).toHaveLength(64);
  });

  it("serializes the exact tally and rejects remaining electorate and ballot invariants", () => {
    const noQuorum = tallyVote([], [], majorityRule);
    expect(canonicalVoteTally(noQuorum)).toEqual({
      schemaVersion: "boardagent.vote-tally.v1",
      eligibleWeight: "0",
      participatingWeight: "0",
      yesWeight: "0",
      noWeight: "0",
      abstainWeight: "0",
      quorumMet: false,
      approvalMet: false,
      outcome: "no_quorum"
    });
    expect(voteTallySha256(noQuorum)).toHaveLength(64);
    expect(() =>
      eligibleVotingWeight([
        {
          memberId: "observer",
          role: "observer",
          weight: 1n,
          eligible: true,
          recused: false,
          chair: false
        }
      ])
    ).toThrow("zero weight");
    expect(() =>
      eligibleVotingWeight([
        {
          memberId: "observer",
          role: "observer",
          weight: 0n,
          eligible: true,
          recused: false,
          chair: true
        }
      ])
    ).toThrow("voting member may be chair");
    const electorate = [
      {
        memberId: "principal",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      },
      {
        memberId: "holder",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      }
    ];
    expect(() =>
      tallyVote(
        electorate,
        [
          {
            principalMemberId: "principal",
            casterMemberId: "principal",
            choice: "yes",
            source: "proxy"
          }
        ],
        majorityRule
      )
    ).toThrow("proxy ballot caster must differ");
    expect(() =>
      tallyVote(
        electorate,
        [
          {
            principalMemberId: "principal",
            casterMemberId: "principal",
            choice: "yes",
            source: "own"
          },
          {
            principalMemberId: "principal",
            casterMemberId: "principal",
            choice: "no",
            source: "own"
          }
        ],
        majorityRule
      )
    ).toThrow("multiple active ballots");
    expect(() =>
      tallyVote(
        electorate,
        [
          {
            principalMemberId: "absent",
            casterMemberId: "absent",
            choice: "yes",
            source: "own"
          }
        ],
        majorityRule
      )
    ).toThrow("principal is not eligible");
    expect(() =>
      tallyVote(
        electorate,
        [
          {
            principalMemberId: "principal",
            casterMemberId: "absent",
            choice: "yes",
            source: "proxy"
          }
        ],
        majorityRule
      )
    ).toThrow("proxy holder is not eligible");
  });

  it("applies every denominator and abstention-quorum policy", () => {
    const electorate = [
      {
        memberId: "yes",
        role: "voting_member" as const,
        weight: 2n,
        eligible: true,
        recused: false,
        chair: false
      },
      {
        memberId: "abstain",
        role: "voting_member" as const,
        weight: 2n,
        eligible: true,
        recused: false,
        chair: false
      }
    ];
    const ballots = [
      {
        principalMemberId: "yes",
        casterMemberId: "yes",
        choice: "yes" as const,
        source: "own" as const
      },
      {
        principalMemberId: "abstain",
        casterMemberId: "abstain",
        choice: "abstain" as const,
        source: "own" as const
      }
    ];
    expect(
      tallyVote(electorate, ballots, {
        ...majorityRule,
        approvalDenominator: "eligible",
        abstentionsCountForQuorum: false
      }).approvalMet
    ).toBe(true);
    expect(
      tallyVote(electorate, ballots, {
        ...majorityRule,
        approvalDenominator: "participating"
      }).approvalMet
    ).toBe(true);
  });

  it("distinguishes every approval denominator with nonzero no and absent weight", () => {
    const electorate = [
      {
        memberId: "yes",
        role: "voting_member" as const,
        weight: 2n,
        eligible: true,
        recused: false,
        chair: false
      },
      {
        memberId: "abstain",
        role: "voting_member" as const,
        weight: 2n,
        eligible: true,
        recused: false,
        chair: false
      },
      {
        memberId: "absent",
        role: "voting_member" as const,
        weight: 2n,
        eligible: true,
        recused: false,
        chair: false
      }
    ];
    const ballots = [
      {
        principalMemberId: "yes",
        casterMemberId: "yes",
        choice: "yes" as const,
        source: "own" as const
      },
      {
        principalMemberId: "abstain",
        casterMemberId: "abstain",
        choice: "abstain" as const,
        source: "own" as const
      }
    ];
    expect(
      ["eligible", "participating", "yes_no"].map(
        (approvalDenominator) =>
          tallyVote(electorate, ballots, {
            ...majorityRule,
            approvalDenominator: approvalDenominator as "eligible" | "participating" | "yes_no"
          }).approvalMet
      )
    ).toEqual([false, true, true]);
    expect(
      ["participating", "yes_no"].map(
        (approvalDenominator) =>
          tallyVote(electorate, ballots, {
            ...majorityRule,
            approval: rational(3n, 4n),
            approvalDenominator: approvalDenominator as "participating" | "yes_no"
          }).approvalMet
      )
    ).toEqual([false, true]);

    const yesNoBallots = [
      ballots[0]!,
      {
        principalMemberId: "abstain",
        casterMemberId: "abstain",
        choice: "no" as const,
        source: "own" as const
      }
    ];
    expect(
      tallyVote(electorate, yesNoBallots, {
        ...majorityRule,
        approval: rational(3n, 4n),
        approvalDenominator: "yes_no"
      }).approvalMet
    ).toBe(false);

    expect(
      tallyVote(
        [{ ...electorate[0]!, weight: 2n }, { ...electorate[1]!, weight: 1n }, electorate[2]!],
        yesNoBallots,
        {
          ...majorityRule,
          approval: rational(3n, 4n),
          approvalDenominator: "yes_no"
        }
      ).approvalMet
    ).toBe(false);

    expect(
      tallyVote(
        [{ ...electorate[0]!, weight: 1n }],
        [
          {
            principalMemberId: "yes",
            casterMemberId: "yes",
            choice: "abstain",
            source: "own"
          }
        ],
        majorityRule
      )
    ).toMatchObject({
      eligibleWeight: 1n,
      participatingWeight: 1n,
      yesWeight: 0n,
      noWeight: 0n,
      abstainWeight: 1n,
      quorumMet: true,
      approvalMet: false,
      outcome: "rejected"
    });
  });

  it("uses chair support only for an exact tied casting-vote rule", () => {
    const electorate = [
      {
        memberId: "chair",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: true
      },
      {
        memberId: "member",
        role: "voting_member" as const,
        weight: 1n,
        eligible: true,
        recused: false,
        chair: false
      }
    ];
    const chairNo = [
      {
        principalMemberId: "chair",
        casterMemberId: "chair",
        choice: "no" as const,
        source: "own" as const
      },
      {
        principalMemberId: "member",
        casterMemberId: "member",
        choice: "yes" as const,
        source: "own" as const
      }
    ];
    expect(
      tallyVote(electorate, chairNo, {
        ...majorityRule,
        tieBehavior: "chair_casting_vote"
      }).outcome
    ).toBe("rejected");
    expect(
      tallyVote(
        electorate,
        chairNo.map((ballot) => ({
          ...ballot,
          choice: ballot.choice === "yes" ? ("no" as const) : ("yes" as const)
        })),
        majorityRule
      ).outcome
    ).toBe("rejected");

    expect(
      tallyVote(
        [electorate[0]!, { ...electorate[1]!, weight: 2n }],
        [
          {
            principalMemberId: "chair",
            casterMemberId: "chair",
            choice: "yes",
            source: "own"
          },
          {
            principalMemberId: "member",
            casterMemberId: "member",
            choice: "yes",
            source: "own"
          }
        ],
        majorityRule
      ).outcome
    ).toBe("approved");
  });

  it("rejects a voting seat whose weight invariant is not enforced", () => {
    expect(() =>
      eligibleVotingWeight([
        {
          memberId: "zero",
          role: "voting_member",
          weight: 0n,
          eligible: true,
          recused: false,
          chair: false
        }
      ])
    ).toThrow("weight");
  });

  it("preserves total-weight invariants across generated electorates", () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 1, max: 10_000 }), { minLength: 1, maxLength: 40 }),
        fc.array(
          fc.constantFrom("yes" as const, "no" as const, "abstain" as const, "none" as const),
          {
            minLength: 1,
            maxLength: 40
          }
        ),
        (weights, choices) => {
          const electorate = weights.map((weight, index) => ({
            memberId: `m${index}`,
            role: "voting_member" as const,
            weight: BigInt(weight),
            eligible: true,
            recused: false,
            chair: index === 0
          }));
          const ballots = electorate.flatMap((seat, index) => {
            const choice = choices[index % choices.length] ?? "none";
            return choice === "none"
              ? []
              : [
                  {
                    principalMemberId: seat.memberId,
                    casterMemberId: seat.memberId,
                    choice,
                    source: "own" as const
                  }
                ];
          });
          const result = tallyVote(electorate, ballots, majorityRule);
          expect(result.yesWeight + result.noWeight + result.abstainWeight).toBe(
            result.participatingWeight
          );
          expect(result.participatingWeight).toBeLessThanOrEqual(result.eligibleWeight);
        }
      ),
      { numRuns: 10_000, endOnFailure: true }
    );
  });
});
