import { describe, expect, it } from "vitest";

import {
  GovernanceProfileActivationSchema,
  GovernanceProfileSchema,
  governanceProfileSha256,
  selectGovernanceRule,
  type GovernanceProfile
} from "../../lib/ruleset/src/index.js";

const id = (suffix: number): GovernanceProfile["id"] =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}` as GovernanceProfile["id"];
const hash = (character: string): string => character.repeat(64);
const citation = (suffix: number) => ({
  sourceDocumentVersionId: id(suffix),
  sourceDocumentSha256: hash(
    "a"
  ) as GovernanceProfile["sourceAgreements"][number]["sourceDocumentSha256"],
  clause: "Charter §7.2",
  locator: "reserved matters"
});

const profile: GovernanceProfile = {
  schemaVersion: "boardagent.governance-profile.v1",
  id: id(1),
  boardId: id(2),
  version: 1,
  supersedesId: null,
  sourceAgreements: [citation(3)],
  seats: [
    { memberId: id(10), role: "voting_member", weight: "40", chair: true },
    { memberId: id(11), role: "voting_member", weight: "25", chair: false },
    { memberId: id(12), role: "observer", weight: "0", chair: false }
  ],
  templates: [
    {
      id: id(20),
      code: "ordinary",
      label: "Ordinary resolution",
      approval: { numerator: "1", denominator: "2" },
      quorum: { numerator: "1", denominator: "2" },
      approvalDenominator: "yes_no",
      abstentionsCountForQuorum: true,
      tieBehavior: "reject",
      proxyPolicy: "principal_supersedes_proxy",
      noticePeriodSeconds: 86_400,
      closeMode: "secretariat_confirmed",
      overridePolicy: "forbidden",
      citations: [citation(4)]
    },
    {
      id: id(21),
      code: "reserved",
      label: "Reserved matter",
      approval: { numerator: "3", denominator: "4" },
      quorum: { numerator: "2", denominator: "3" },
      approvalDenominator: "eligible",
      abstentionsCountForQuorum: true,
      tieBehavior: "reject",
      proxyPolicy: "forbidden",
      noticePeriodSeconds: 172_800,
      closeMode: "secretariat_confirmed",
      overridePolicy: "strengthen_only",
      citations: [citation(5)]
    }
  ]
};

describe("strict governance profile", () => {
  it.each(["not-an-integer", "1.5", "1e3"])(
    "returns structured validation errors for malformed seat weight %s",
    (weight) => {
      const invalid = { ...profile, seats: [{ ...profile.seats[0]!, weight }] };
      const result = GovernanceProfileSchema.safeParse(invalid);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toEqual(
          expect.arrayContaining([expect.objectContaining({ path: ["seats", 0, "weight"] })])
        );
      }
    }
  );

  it("returns structured activation errors for invalid nested fraction syntax", () => {
    const invalid = {
      ...profile,
      templates: [{ ...profile.templates[0]!, approval: { numerator: "bad", denominator: "2" } }]
    };
    const result = GovernanceProfileActivationSchema.safeParse({
      schemaVersion: "boardagent.governance-profile-activation.v1",
      profile: invalid,
      profileSha256: hash("a"),
      activationConsentRecordId: id(40)
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ path: ["profile", "templates", 0, "approval", "numerator"] })
        ])
      );
    }
  });

  it("hashes the exact cited profile and binds activation to that hash", () => {
    const parsed = GovernanceProfileSchema.parse(profile);
    const profileSha256 = governanceProfileSha256(parsed);
    expect(profileSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(
      GovernanceProfileActivationSchema.parse({
        schemaVersion: "boardagent.governance-profile-activation.v1",
        profile: parsed,
        profileSha256,
        activationConsentRecordId: id(30)
      }).profileSha256
    ).toBe(profileSha256);
    expect(() =>
      GovernanceProfileActivationSchema.parse({
        schemaVersion: "boardagent.governance-profile-activation.v1",
        profile: parsed,
        profileSha256: hash("f"),
        activationConsentRecordId: id(30)
      })
    ).toThrow("profile_hash_mismatch");
  });

  it("rejects unversioned, duplicate, noncanonical, and invalid seat authority", () => {
    expect(() => GovernanceProfileSchema.parse({ ...profile, surprise: true })).toThrow();
    expect(() =>
      GovernanceProfileSchema.parse({ ...profile, version: 2, supersedesId: null })
    ).toThrow("profile_supersession_does_not_match_version");
    expect(() =>
      GovernanceProfileSchema.parse({ ...profile, seats: [profile.seats[0]!, profile.seats[0]!] })
    ).toThrow("duplicate_governance_seat");
    expect(() =>
      GovernanceProfileSchema.parse({
        ...profile,
        seats: [{ memberId: id(10), role: "observer", weight: "1", chair: false }]
      })
    ).toThrow("nonvoting_seat_weight_must_be_zero");
    expect(() =>
      GovernanceProfileSchema.parse({
        ...profile,
        templates: [
          {
            ...profile.templates[0]!,
            approval: { numerator: "2", denominator: "4" }
          }
        ]
      })
    ).toThrow("fraction_must_be_reduced");
  });

  it("selects only a profile template and permits only cited strengthening overrides", () => {
    expect(selectGovernanceRule(profile, "ordinary").template.code).toBe("ordinary");
    expect(() => selectGovernanceRule(profile, "invented")).toThrow(
      "rule_not_permitted_by_profile"
    );
    expect(() =>
      selectGovernanceRule(profile, "ordinary", {
        approval: { numerator: "2", denominator: "3" },
        reason: "Stronger for this matter.",
        citations: [citation(6)]
      })
    ).toThrow("override_forbidden");
    expect(() =>
      selectGovernanceRule(profile, "reserved", {
        approval: { numerator: "2", denominator: "3" },
        reason: "Management request.",
        citations: [citation(6)]
      })
    ).toThrow("override_weakens_approval");
    expect(() =>
      selectGovernanceRule(profile, "reserved", {
        noticePeriodSeconds: 60,
        reason: "Faster notice.",
        citations: [citation(6)]
      })
    ).toThrow("override_shortens_notice");
    const selected = selectGovernanceRule(profile, "reserved", {
      approval: { numerator: "4", denominator: "5" },
      quorum: { numerator: "3", denominator: "4" },
      noticePeriodSeconds: 259_200,
      reason: "The cited side letter requires stronger protections.",
      citations: [citation(6)]
    });
    expect(selected.template.approval).toEqual({ numerator: "4", denominator: "5" });
    expect(selected.override?.reason).toContain("side letter");
    expect(selected.selectionSha256).toMatch(/^[0-9a-f]{64}$/u);
  });
});
