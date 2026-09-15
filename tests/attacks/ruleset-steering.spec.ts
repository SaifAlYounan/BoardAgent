import { describe, expect, it } from "vitest";

import { RulesetVersionSchema, evaluateMatter } from "../../lib/ruleset/src/index.js";

const citation = {
  sourceDocumentVersionId: "018f0000-0000-7000-8000-000000000010",
  sourceDocumentSha256: "a".repeat(64),
  clause: "Charter 7.2",
  locator: "reserved matters"
};

function rule(id: string, priority: number, specificity: number) {
  return {
    id,
    matterType: "investment",
    priority,
    specificity,
    condition: { kind: "number_gte" as const, field: "amount", value: 1 },
    approvalRuleId: "018f0000-0000-7000-8000-000000000020",
    citations: [citation]
  };
}

const ruleset = RulesetVersionSchema.parse({
  schemaVersion: "boardagent.ruleset.v1",
  id: "018f0000-0000-7000-8000-000000000001",
  boardId: "018f0000-0000-7000-8000-000000000002",
  version: 1,
  canonicalHash: "0".repeat(64),
  matterTypes: [
    {
      code: "investment",
      fields: [{ name: "amount", type: "integer", required: true }]
    }
  ],
  rules: [
    rule("018f0000-0000-7000-8000-000000000101", 10, 5),
    rule("018f0000-0000-7000-8000-000000000102", 10, 5),
    rule("018f0000-0000-7000-8000-000000000103", 9, 999)
  ]
});

describe("TH-30 ruleset steering", () => {
  it("fails closed on tied authoritative rules and rejects undeclared or floating facts", () => {
    expect(evaluateMatter(ruleset, "investment", { amount: 2 })).toMatchObject({
      status: "ambiguous",
      candidateRuleIds: [
        "018f0000-0000-7000-8000-000000000101",
        "018f0000-0000-7000-8000-000000000102"
      ]
    });
    expect(() => evaluateMatter(ruleset, "investment", { amount: 2, injected: true })).toThrow(
      "unknown matter fact"
    );
    expect(() => evaluateMatter(ruleset, "investment", { amount: 1.5 })).toThrow("safe integer");
  });
});
