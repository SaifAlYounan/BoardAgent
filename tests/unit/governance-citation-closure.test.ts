import { describe, expect, it } from "vitest";

import { Sha256HexSchema, UuidV7Schema, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  buildGovernanceProfileRequest,
  buildRulesetRequest
} from "../../lib/db/src/transactions/governance-administration.js";
import { governanceEnvelopeFixture } from "../helpers/governance-envelope.js";

const id = (suffix: number) => `018f0000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;
const fixture = () => governanceEnvelopeFixture(id(1), [id(2)], id(3), "a".repeat(64));
const citation = (source: ReturnType<typeof fixture>["profile"]["sourceAgreements"][number]) => ({
  documentVersionId: UuidV7Schema.parse(source.sourceDocumentVersionId),
  sourceDocumentSha256: Sha256HexSchema.parse(source.sourceDocumentSha256),
  clause: source.clause,
  locator: source.locator
});

function buildProfile(
  profile: ReturnType<typeof fixture>["profile"],
  citations: ReturnType<typeof citation>[]
) {
  const count =
    new Set(profile.seats.map(({ role }) => role)).size +
    profile.templates.length +
    profile.sourceAgreements.length +
    profile.templates.reduce((sum, template) => sum + template.citations.length, 0);
  return buildGovernanceProfileRequest({
    boardId: profile.boardId,
    expectedProfileId: null,
    profile,
    citations,
    generatedIds: Array.from({ length: count }, (_, index) => id(100 + index)),
    reason: "Record exact synthetic charter evidence."
  });
}

describe("governance citation closure", () => {
  it("accepts distinct cited clauses without rewriting their profile", () => {
    const { profile } = fixture();
    const digest = canonicalSha256(profile);
    const request = buildProfile(profile, [
      citation(profile.sourceAgreements[0]!),
      citation(profile.templates[0]!.citations[0]!)
    ]);
    expect(request.actionCode).toBe("configure_board_governance");
    expect(canonicalSha256(profile)).toBe(digest);
  });

  it.each(["two_templates", "agreement_and_template"] as const)(
    "accepts one exact clause reused by %s and retains every citation relationship",
    (reuse) => {
      const { profile } = fixture();
      const template = profile.templates[0]!;
      if (reuse === "two_templates") {
        profile.templates.push({ ...template, id: id(20), code: "reserved" });
      } else {
        profile.sourceAgreements = [...template.citations];
      }
      const citations = [
        citation(profile.sourceAgreements[0]!),
        ...(reuse === "two_templates" ? [citation(template.citations[0]!)] : [])
      ];
      const digest = canonicalSha256(profile);
      const request = buildProfile(profile, citations);
      expect(request.actionCode).toBe("configure_board_governance");
      if (request.actionCode !== "configure_board_governance") throw new Error("wrong action");
      expect(request.citations).toHaveLength(citations.length);
      expect(request.citationMaterial).toHaveLength(reuse === "two_templates" ? 3 : 2);
      expect(canonicalSha256(request.profile)).toBe(digest);
      expect(request.citationMaterial.map(({ ruleTemplateId }) => ruleTemplateId)).toEqual([
        null,
        ...profile.templates.map(({ id: templateId }) => templateId)
      ]);
    }
  );

  it("accepts two rules relying on the same exact clause without dropping either rule link", () => {
    const f = fixture();
    const original = f.ruleset(id(30));
    const { canonicalHash: ignored, ...base } = original;
    void ignored;
    base.rules.push({ ...base.rules[0]!, id: id(31), priority: 20 });
    const ruleset = { ...base, canonicalHash: canonicalSha256(base) };
    const request = buildRulesetRequest({
      boardId: base.boardId,
      expectedRulesetId: null,
      ruleset,
      citations: [citation(base.rules[0]!.citations[0]!)],
      generatedMatterTypeIds: [id(32)],
      generatedCitationIds: [id(33), id(34)],
      reason: "Both synthetic rules rely on the same charter clause."
    });
    expect(request.actionCode).toBe("manage_ruleset");
    if (request.actionCode !== "manage_ruleset") throw new Error("wrong action");
    expect(request.citations).toHaveLength(1);
    expect(request.citationMaterial.map(({ ruleId }) => ruleId)).toEqual(
      base.rules.map(({ id: ruleId }) => ruleId)
    );
    expect(request.ruleset).toEqual(ruleset);
  });

  it.each(["missing", "extra", "duplicate", "wrong_hash"] as const)(
    "refuses %s submitted evidence",
    (change) => {
      const { profile } = fixture();
      const citations = [
        citation(profile.sourceAgreements[0]!),
        citation(profile.templates[0]!.citations[0]!)
      ];
      if (change === "missing") citations.pop();
      if (change === "extra") citations.push({ ...citations[0]!, clause: "Uncited clause" });
      if (change === "duplicate") citations.push({ ...citations[0]! });
      if (change === "wrong_hash") {
        citations[0] = {
          ...citations[0]!,
          sourceDocumentSha256: Sha256HexSchema.parse("b".repeat(64))
        };
      }
      expect(() => buildProfile(profile, citations)).toThrow();
    }
  );
});
