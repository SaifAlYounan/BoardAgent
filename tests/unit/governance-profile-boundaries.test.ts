import { describe, expect, it } from "vitest";
import type { ZodType } from "zod";

import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  GovernanceFractionSchema,
  GovernanceProfileActivationSchema,
  GovernanceProfileSchema,
  GovernanceRuleOverrideSchema,
  GovernanceRuleTemplateSchema,
  GovernanceSeatSchema,
  governanceProfileSha256,
  selectGovernanceRule,
  type GovernanceProfile
} from "../../lib/ruleset/src/index.js";

const id = (suffix: number): GovernanceProfile["id"] =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}` as GovernanceProfile["id"];
const hash = (character: string): string => character.repeat(64);

const citation = (suffix: number) => ({
  sourceDocumentVersionId: id(800_000 + suffix),
  sourceDocumentSha256: hash(
    "a"
  ) as GovernanceProfile["sourceAgreements"][number]["sourceDocumentSha256"],
  clause: "Charter 7.2",
  locator: "reserved matters"
});

const seat = (suffix: number, chair = false) => ({
  memberId: id(100_000 + suffix),
  role: "voting_member" as const,
  weight: "1",
  chair
});

const template = (suffix: number, code = `template_${suffix}`) => ({
  id: id(200_000 + suffix),
  code,
  label: `Template ${suffix}`,
  approval: { numerator: "1", denominator: "2" },
  quorum: { numerator: "1", denominator: "2" },
  approvalDenominator: "eligible" as const,
  abstentionsCountForQuorum: true,
  tieBehavior: "reject" as const,
  proxyPolicy: "forbidden" as const,
  noticePeriodSeconds: 86_400,
  closeMode: "secretariat_confirmed" as const,
  overridePolicy: "strengthen_only" as const,
  citations: [citation(suffix)]
});

const profile: GovernanceProfile = {
  schemaVersion: "boardagent.governance-profile.v1",
  id: id(1),
  boardId: id(2),
  version: 1,
  supersedesId: null,
  sourceAgreements: [citation(1)],
  seats: [seat(1, true), { memberId: id(100_002), role: "observer", weight: "0", chair: false }],
  templates: [template(1, "reserved")]
};

function expectAccepted(schema: ZodType, input: unknown): void {
  expect(schema.safeParse(input).success).toBe(true);
}

function expectRejected(schema: ZodType, input: unknown): void {
  expect(schema.safeParse(input).success).toBe(false);
}

function expectCustomIssue(
  schema: ZodType,
  input: unknown,
  path: readonly (string | number)[],
  message: string
): void {
  const result = schema.safeParse(input);
  expect(result.success).toBe(false);
  if (result.success) throw new Error("expected schema rejection");
  expect(
    result.error.issues.map((issue) => ({
      code: issue.code,
      path: issue.path,
      message: issue.message
    }))
  ).toEqual([{ code: "custom", path: [...path], message }]);
}

describe("governance profile exact boundaries", () => {
  it("enforces canonical integer strings and exact reduced fractions", () => {
    for (const candidate of [
      { numerator: "0", denominator: "1" },
      { numerator: "1", denominator: "1" },
      { numerator: "1", denominator: "2" },
      { numerator: "10", denominator: "11" }
    ]) {
      expectAccepted(GovernanceFractionSchema, candidate);
    }
    for (const candidate of [
      { numerator: "x0", denominator: "1" },
      { numerator: "0x", denominator: "1" },
      { numerator: "01", denominator: "1" },
      { numerator: "1", denominator: "x1" },
      { numerator: "1", denominator: "1x" },
      { numerator: "1", denominator: "0" },
      { numerator: "1", denominator: "01" }
    ]) {
      expectRejected(GovernanceFractionSchema, candidate);
    }
    expectCustomIssue(
      GovernanceFractionSchema,
      { numerator: "2", denominator: "1" },
      [],
      "fraction_out_of_range"
    );
    expectCustomIssue(
      GovernanceFractionSchema,
      { numerator: "2", denominator: "4" },
      [],
      "fraction_must_be_reduced"
    );
  });

  it("accepts every seat role and rejects noncanonical weights", () => {
    for (const role of ["voting_member", "management", "observer"] as const) {
      expectAccepted(GovernanceSeatSchema, {
        memberId: id(10),
        role,
        weight: role === "voting_member" ? "10" : "0",
        chair: false
      });
    }
    for (const weight of ["x0", "0x", "01", "-1", ""]) {
      expectRejected(GovernanceSeatSchema, {
        memberId: id(10),
        role: "observer",
        weight,
        chair: false
      });
    }
  });

  it("enforces exact template text, enum, notice and citation bounds", () => {
    const base = template(10, "a");
    expect(GovernanceRuleTemplateSchema.parse({ ...base, label: "  Label  " }).label).toBe("Label");
    expectAccepted(GovernanceRuleTemplateSchema, {
      ...base,
      code: `a${"b".repeat(127)}`,
      label: "x".repeat(512),
      noticePeriodSeconds: 0,
      citations: Array.from({ length: 64 }, () => citation(10))
    });
    for (const candidate of [
      { ...base, code: "_a" },
      { ...base, code: "a-" },
      { ...base, code: `a${"b".repeat(128)}` },
      { ...base, label: "   " },
      { ...base, label: "x".repeat(513) },
      { ...base, noticePeriodSeconds: -1 },
      { ...base, noticePeriodSeconds: 31_536_001 },
      { ...base, citations: [] },
      { ...base, citations: Array.from({ length: 65 }, () => citation(10)) }
    ]) {
      expectRejected(GovernanceRuleTemplateSchema, candidate);
    }
    expectAccepted(GovernanceRuleTemplateSchema, {
      ...base,
      noticePeriodSeconds: 31_536_000
    });

    for (const approvalDenominator of ["eligible", "participating", "yes_no"] as const) {
      expectAccepted(GovernanceRuleTemplateSchema, { ...base, approvalDenominator });
    }
    for (const tieBehavior of ["reject", "chair_casting_vote"] as const) {
      expectAccepted(GovernanceRuleTemplateSchema, { ...base, tieBehavior });
    }
    for (const proxyPolicy of [
      "principal_supersedes_proxy",
      "first_ballot_final",
      "forbidden"
    ] as const) {
      expectAccepted(GovernanceRuleTemplateSchema, { ...base, proxyPolicy });
    }
    for (const closeMode of ["automatic", "secretariat_confirmed"] as const) {
      expectAccepted(GovernanceRuleTemplateSchema, { ...base, closeMode });
    }
    for (const overridePolicy of ["forbidden", "strengthen_only"] as const) {
      expectAccepted(GovernanceRuleTemplateSchema, { ...base, overridePolicy });
    }
  });

  it("reports every profile relationship violation at its exact path", () => {
    expectAccepted(GovernanceProfileSchema, {
      ...profile,
      version: 2,
      supersedesId: id(99),
      sourceAgreements: [citation(1), citation(2)]
    });
    for (const candidate of [
      { ...profile, version: 1, supersedesId: id(99) },
      { ...profile, version: 2, supersedesId: null }
    ]) {
      expectCustomIssue(
        GovernanceProfileSchema,
        candidate,
        ["supersedesId"],
        "profile_supersession_does_not_match_version"
      );
    }

    const plainSeat = seat(20);
    expectCustomIssue(
      GovernanceProfileSchema,
      { ...profile, seats: [plainSeat, plainSeat] },
      ["seats", 1, "memberId"],
      "duplicate_governance_seat"
    );
    expectCustomIssue(
      GovernanceProfileSchema,
      { ...profile, seats: [{ ...plainSeat, weight: "0" }] },
      ["seats", 0, "weight"],
      "voting_seat_weight_must_be_positive"
    );
    expectCustomIssue(
      GovernanceProfileSchema,
      {
        ...profile,
        seats: [{ ...plainSeat, role: "management", weight: "1" }]
      },
      ["seats", 0, "weight"],
      "nonvoting_seat_weight_must_be_zero"
    );
    expectCustomIssue(
      GovernanceProfileSchema,
      {
        ...profile,
        seats: [{ ...plainSeat, role: "observer", weight: "0", chair: true }]
      },
      ["seats", 0, "chair"],
      "chair_must_be_voting_member"
    );
    expectCustomIssue(
      GovernanceProfileSchema,
      { ...profile, seats: [seat(20, true), seat(21, true)] },
      ["seats"],
      "multiple_chairs"
    );

    const first = template(20, "first");
    expectCustomIssue(
      GovernanceProfileSchema,
      { ...profile, templates: [first, { ...template(21, "second"), id: first.id }] },
      ["templates", 1, "id"],
      "duplicate_governance_template_id"
    );
    expectCustomIssue(
      GovernanceProfileSchema,
      { ...profile, templates: [first, { ...template(21, "first") }] },
      ["templates", 1, "code"],
      "duplicate_governance_template_code"
    );
  });

  it("keeps a non-voting seat's malformed weight as the single field error", () => {
    // The field regex fails first; the dependent zero-weight invariant must not pile a
    // second, misleading issue onto the same path when the weight cannot be parsed.
    const result = GovernanceProfileSchema.safeParse({
      ...profile,
      seats: [{ ...seat(20), role: "observer", weight: "one" }]
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected schema rejection");
    const weightIssues = result.error.issues.filter(
      (issue) => issue.path.join(".") === "seats.0.weight"
    );
    expect(weightIssues).toHaveLength(1);
    expect(weightIssues[0]?.message).not.toBe("nonvoting_seat_weight_must_be_zero");
  });

  it("enforces exact profile collection bounds", () => {
    expectAccepted(GovernanceProfileSchema, {
      ...profile,
      sourceAgreements: Array.from({ length: 256 }, (_, index) => citation(index + 1))
    });
    expectRejected(GovernanceProfileSchema, { ...profile, sourceAgreements: [] });
    expectRejected(GovernanceProfileSchema, {
      ...profile,
      sourceAgreements: Array.from({ length: 257 }, (_, index) => citation(index + 1))
    });

    const seats = Array.from({ length: 10_001 }, (_, index) => ({
      memberId: id(300_000 + index),
      role: "observer" as const,
      weight: "0",
      chair: false
    }));
    expectAccepted(GovernanceProfileSchema, { ...profile, seats: seats.slice(0, 10_000) });
    expectRejected(GovernanceProfileSchema, { ...profile, seats: [] });
    expectRejected(GovernanceProfileSchema, { ...profile, seats });

    const templates = Array.from({ length: 1_001 }, (_, index) =>
      template(1_000 + index, `type_${index}`)
    );
    expectAccepted(GovernanceProfileSchema, {
      ...profile,
      templates: templates.slice(0, 1_000)
    });
    expectRejected(GovernanceProfileSchema, { ...profile, templates: [] });
    expectRejected(GovernanceProfileSchema, { ...profile, templates });
  });

  it("enforces exact override change, text, notice and citation bounds", () => {
    const base = { reason: "  Cited side letter  ", citations: [citation(30)] };
    expectCustomIssue(
      GovernanceRuleOverrideSchema,
      base,
      [],
      "override_must_change_a_permitted_field"
    );
    expect(GovernanceRuleOverrideSchema.parse({ ...base, noticePeriodSeconds: 0 }).reason).toBe(
      "Cited side letter"
    );
    expectAccepted(GovernanceRuleOverrideSchema, {
      ...base,
      approval: { numerator: "1", denominator: "2" },
      reason: "x".repeat(65_536),
      citations: Array.from({ length: 64 }, () => citation(30))
    });
    expectAccepted(GovernanceRuleOverrideSchema, {
      ...base,
      quorum: { numerator: "1", denominator: "2" }
    });
    expectAccepted(GovernanceRuleOverrideSchema, {
      ...base,
      noticePeriodSeconds: 31_536_000
    });
    for (const candidate of [
      { ...base, approval: { numerator: "1", denominator: "2" }, reason: "   " },
      { ...base, approval: { numerator: "1", denominator: "2" }, reason: "x".repeat(65_537) },
      { ...base, noticePeriodSeconds: -1 },
      { ...base, noticePeriodSeconds: 31_536_001 },
      { ...base, approval: { numerator: "1", denominator: "2" }, citations: [] },
      {
        ...base,
        approval: { numerator: "1", denominator: "2" },
        citations: Array.from({ length: 65 }, () => citation(30))
      }
    ]) {
      expectRejected(GovernanceRuleOverrideSchema, candidate);
    }
  });

  it("binds exact selected templates and hashes for fallback, equality and strengthening", () => {
    const parsedProfile = GovernanceProfileSchema.parse(profile);
    const selectedBase = selectGovernanceRule(parsedProfile, "reserved");
    const profileSha256 = governanceProfileSha256(parsedProfile);
    expect(selectedBase).toEqual({
      profileSha256,
      template: parsedProfile.templates[0],
      override: null,
      selectionSha256: canonicalSha256({
        schemaVersion: "boardagent.governance-rule-selection.v1",
        profileSha256,
        template: parsedProfile.templates[0],
        override: null
      })
    });

    expect(() =>
      selectGovernanceRule(parsedProfile, "reserved", {
        quorum: { numerator: "1", denominator: "3" },
        reason: "Weaker quorum.",
        citations: [citation(40)]
      })
    ).toThrow("override_weakens_quorum");

    const equalityInput = {
      approval: { numerator: "1", denominator: "2" },
      quorum: { numerator: "1", denominator: "2" },
      noticePeriodSeconds: 86_400,
      reason: "Exact existing floor.",
      citations: [citation(40)]
    };
    expect(selectGovernanceRule(parsedProfile, "reserved", equalityInput).template).toMatchObject({
      approval: equalityInput.approval,
      quorum: equalityInput.quorum,
      noticePeriodSeconds: equalityInput.noticePeriodSeconds
    });

    const approvalOnlyInput = {
      approval: { numerator: "2", denominator: "3" },
      reason: "Stronger approval.",
      citations: [citation(41)]
    };
    const parsedOverride = GovernanceRuleOverrideSchema.parse(approvalOnlyInput);
    const selected = selectGovernanceRule(parsedProfile, "reserved", approvalOnlyInput);
    const selectedTemplate = GovernanceRuleTemplateSchema.parse({
      ...parsedProfile.templates[0],
      approval: parsedOverride.approval,
      quorum: parsedProfile.templates[0]!.quorum,
      noticePeriodSeconds: parsedProfile.templates[0]!.noticePeriodSeconds
    });
    expect(selected).toEqual({
      profileSha256,
      template: selectedTemplate,
      override: parsedOverride,
      selectionSha256: canonicalSha256({
        schemaVersion: "boardagent.governance-rule-selection.v1",
        profileSha256,
        template: selectedTemplate,
        override: parsedOverride
      })
    });
  });

  it("reports an activation hash mismatch at the exact field", () => {
    const parsedProfile = GovernanceProfileSchema.parse(profile);
    const profileSha256 = governanceProfileSha256(parsedProfile);
    expectAccepted(GovernanceProfileActivationSchema, {
      schemaVersion: "boardagent.governance-profile-activation.v1",
      profile: parsedProfile,
      profileSha256,
      activationConsentRecordId: id(999)
    });
    expectCustomIssue(
      GovernanceProfileActivationSchema,
      {
        schemaVersion: "boardagent.governance-profile-activation.v1",
        profile: parsedProfile,
        profileSha256: hash("f"),
        activationConsentRecordId: id(999)
      },
      ["profileSha256"],
      "profile_hash_mismatch"
    );
  });
});
