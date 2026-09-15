import { z } from "zod";

import { canonicalSha256, Sha256HexSchema, UuidSchema } from "@boardagent/contracts";

import { CitationSchema } from "./schema.js";

function createUnsignedIntegerStringSchema() {
  return z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
}

function createPositiveIntegerStringSchema() {
  return z.string().regex(/^[1-9][0-9]*$/u);
}

const UnsignedIntegerStringSchema = z.lazy(createUnsignedIntegerStringSchema);
const PositiveIntegerStringSchema = z.lazy(createPositiveIntegerStringSchema);

function greatestCommonDivisor(left: bigint, right: bigint): bigint {
  let a = left;
  let b = right;
  while (b !== 0n) {
    const remainder = a % b;
    a = b;
    b = remainder;
  }
  return a;
}

function parseBigInt(value: string): bigint | null {
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function createGovernanceFractionSchema() {
  return z
    .object({
      numerator: UnsignedIntegerStringSchema,
      denominator: PositiveIntegerStringSchema
    })
    .strict()
    .superRefine(({ numerator, denominator }, context) => {
      const numeratorValue = parseBigInt(numerator);
      const denominatorValue = parseBigInt(denominator);
      if (numeratorValue === null || denominatorValue === null) return;
      if (numeratorValue > denominatorValue) {
        context.addIssue({ code: "custom", message: "fraction_out_of_range" });
      }
      if (greatestCommonDivisor(numeratorValue, denominatorValue) !== 1n) {
        context.addIssue({ code: "custom", message: "fraction_must_be_reduced" });
      }
    });
}

export const GovernanceFractionSchema = z.lazy(createGovernanceFractionSchema);
export type GovernanceFraction = z.infer<typeof GovernanceFractionSchema>;

function createGovernanceSeatSchema() {
  return z
    .object({
      memberId: UuidSchema,
      role: z.enum(["voting_member", "management", "observer"]),
      weight: UnsignedIntegerStringSchema,
      chair: z.boolean()
    })
    .strict();
}

export const GovernanceSeatSchema = z.lazy(createGovernanceSeatSchema);
export type GovernanceSeat = z.infer<typeof GovernanceSeatSchema>;

function createGovernanceRuleTemplateSchema() {
  return z
    .object({
      id: UuidSchema,
      code: z.string().regex(/^[a-z][a-z0-9_]{0,127}$/u),
      label: z.string().trim().min(1).max(512),
      approval: GovernanceFractionSchema,
      quorum: GovernanceFractionSchema,
      approvalDenominator: z.enum(["eligible", "participating", "yes_no"]),
      abstentionsCountForQuorum: z.boolean(),
      tieBehavior: z.enum(["reject", "chair_casting_vote"]),
      proxyPolicy: z.enum(["principal_supersedes_proxy", "first_ballot_final", "forbidden"]),
      noticePeriodSeconds: z.number().int().safe().min(0).max(31_536_000),
      closeMode: z.enum(["automatic", "secretariat_confirmed"]),
      overridePolicy: z.enum(["forbidden", "strengthen_only"]),
      citations: z.array(CitationSchema).min(1).max(64)
    })
    .strict();
}

export const GovernanceRuleTemplateSchema = z.lazy(createGovernanceRuleTemplateSchema);
export type GovernanceRuleTemplate = z.infer<typeof GovernanceRuleTemplateSchema>;

function createGovernanceProfileSchema() {
  return z
    .object({
      schemaVersion: z.literal("boardagent.governance-profile.v1"),
      id: UuidSchema,
      boardId: UuidSchema,
      version: z.number().int().positive().safe(),
      supersedesId: UuidSchema.nullable(),
      sourceAgreements: z.array(CitationSchema).min(1).max(256),
      seats: z.array(GovernanceSeatSchema).min(1).max(10_000),
      templates: z.array(GovernanceRuleTemplateSchema).min(1).max(1_000)
    })
    .strict()
    .superRefine((profile, context) => {
      if ((profile.version === 1) !== (profile.supersedesId === null)) {
        context.addIssue({
          code: "custom",
          path: ["supersedesId"],
          message: "profile_supersession_does_not_match_version"
        });
      }
      const seatIds = new Set<string>();
      let chairCount = 0;
      for (const [index, seat] of profile.seats.entries()) {
        if (seatIds.has(seat.memberId)) {
          context.addIssue({
            code: "custom",
            path: ["seats", index, "memberId"],
            message: "duplicate_governance_seat"
          });
        }
        seatIds.add(seat.memberId);
        // Zod still runs refinements after a field's regex failure. Keep that
        // field error instead of throwing while checking dependent invariants.
        const weight = parseBigInt(seat.weight);
        if (seat.role === "voting_member" && weight === 0n) {
          context.addIssue({
            code: "custom",
            path: ["seats", index, "weight"],
            message: "voting_seat_weight_must_be_positive"
          });
        }
        if (seat.role !== "voting_member" && weight !== null && weight !== 0n) {
          context.addIssue({
            code: "custom",
            path: ["seats", index, "weight"],
            message: "nonvoting_seat_weight_must_be_zero"
          });
        }
        if (seat.chair) {
          chairCount += 1;
          if (seat.role !== "voting_member") {
            context.addIssue({
              code: "custom",
              path: ["seats", index, "chair"],
              message: "chair_must_be_voting_member"
            });
          }
        }
      }
      if (chairCount > 1) {
        context.addIssue({ code: "custom", path: ["seats"], message: "multiple_chairs" });
      }
      const templateIds = new Set<string>();
      const templateCodes = new Set<string>();
      for (const [index, template] of profile.templates.entries()) {
        if (templateIds.has(template.id)) {
          context.addIssue({
            code: "custom",
            path: ["templates", index, "id"],
            message: "duplicate_governance_template_id"
          });
        }
        if (templateCodes.has(template.code)) {
          context.addIssue({
            code: "custom",
            path: ["templates", index, "code"],
            message: "duplicate_governance_template_code"
          });
        }
        templateIds.add(template.id);
        templateCodes.add(template.code);
      }
    });
}

export const GovernanceProfileSchema = z.lazy(createGovernanceProfileSchema);
export type GovernanceProfile = z.infer<typeof GovernanceProfileSchema>;

function createGovernanceRuleOverrideSchema() {
  return z
    .object({
      approval: GovernanceFractionSchema.optional(),
      quorum: GovernanceFractionSchema.optional(),
      noticePeriodSeconds: z.number().int().safe().min(0).max(31_536_000).optional(),
      reason: z.string().trim().min(1).max(65_536),
      citations: z.array(CitationSchema).min(1).max(64)
    })
    .strict()
    .refine(
      ({ approval, quorum, noticePeriodSeconds }) =>
        approval !== undefined || quorum !== undefined || noticePeriodSeconds !== undefined,
      "override_must_change_a_permitted_field"
    );
}

export const GovernanceRuleOverrideSchema = z.lazy(createGovernanceRuleOverrideSchema);
export type GovernanceRuleOverride = z.infer<typeof GovernanceRuleOverrideSchema>;

function fractionAtLeast(candidate: GovernanceFraction, floor: GovernanceFraction): boolean {
  return (
    BigInt(candidate.numerator) * BigInt(floor.denominator) >=
    BigInt(floor.numerator) * BigInt(candidate.denominator)
  );
}

export interface SelectedGovernanceRule {
  readonly profileSha256: string;
  readonly template: GovernanceRuleTemplate;
  readonly override: GovernanceRuleOverride | null;
  readonly selectionSha256: string;
}

export function governanceProfileSha256(input: GovernanceProfile): string {
  return canonicalSha256(GovernanceProfileSchema.parse(input));
}

export function selectGovernanceRule(
  profileInput: GovernanceProfile,
  templateCode: string,
  overrideInput?: GovernanceRuleOverride
): SelectedGovernanceRule {
  const profile = GovernanceProfileSchema.parse(profileInput);
  const template = profile.templates.find((candidate) => candidate.code === templateCode);
  if (!template) throw new Error("rule_not_permitted_by_profile");
  const profileSha256 = governanceProfileSha256(profile);
  if (overrideInput === undefined) {
    return {
      profileSha256,
      template,
      override: null,
      selectionSha256: canonicalSha256({
        schemaVersion: "boardagent.governance-rule-selection.v1",
        profileSha256,
        template,
        override: null
      })
    };
  }
  if (template.overridePolicy !== "strengthen_only") throw new Error("override_forbidden");
  const override = GovernanceRuleOverrideSchema.parse(overrideInput);
  if (override.approval && !fractionAtLeast(override.approval, template.approval)) {
    throw new Error("override_weakens_approval");
  }
  if (override.quorum && !fractionAtLeast(override.quorum, template.quorum)) {
    throw new Error("override_weakens_quorum");
  }
  if ((override.noticePeriodSeconds ?? Number.POSITIVE_INFINITY) < template.noticePeriodSeconds) {
    throw new Error("override_shortens_notice");
  }
  const selectedTemplate = GovernanceRuleTemplateSchema.parse({
    ...template,
    approval: override.approval ?? template.approval,
    quorum: override.quorum ?? template.quorum,
    noticePeriodSeconds: override.noticePeriodSeconds ?? template.noticePeriodSeconds
  });
  return {
    profileSha256,
    template: selectedTemplate,
    override,
    selectionSha256: canonicalSha256({
      schemaVersion: "boardagent.governance-rule-selection.v1",
      profileSha256,
      template: selectedTemplate,
      override
    })
  };
}

function createGovernanceProfileActivationSchema() {
  return z
    .object({
      schemaVersion: z.literal("boardagent.governance-profile-activation.v1"),
      profile: GovernanceProfileSchema,
      profileSha256: Sha256HexSchema,
      activationConsentRecordId: UuidSchema
    })
    .strict()
    .superRefine(({ profile, profileSha256 }, context) => {
      // Nested profile issues already belong to this result; hashing reparses
      // the profile and must not throw those issues out of safeParse.
      if (!GovernanceProfileSchema.safeParse(profile).success) return;
      if (governanceProfileSha256(profile) !== profileSha256) {
        context.addIssue({
          code: "custom",
          path: ["profileSha256"],
          message: "profile_hash_mismatch"
        });
      }
    });
}

export const GovernanceProfileActivationSchema = z.lazy(createGovernanceProfileActivationSchema);
