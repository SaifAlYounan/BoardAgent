import { describe, expect, it } from "vitest";

import {
  conditionMatches,
  evaluateMatter,
  MatterTypeSchema,
  RulesetVersionSchema,
  type Condition,
  type RulesetVersion
} from "../../lib/ruleset/src/index.js";

const base = {
  schemaVersion: "boardagent.ruleset.v1" as const,
  id: "00000000-0000-7000-8000-000000000001" as RulesetVersion["id"],
  boardId: "00000000-0000-7000-8000-000000000002" as RulesetVersion["boardId"],
  version: 1,
  canonicalHash: "0".repeat(64) as RulesetVersion["canonicalHash"],
  matterTypes: [
    {
      code: "investment",
      fields: [{ name: "amount", type: "integer" as const, required: true }]
    }
  ]
};

const citation = {
  sourceDocumentVersionId:
    "00000000-0000-7000-8000-000000000003" as RulesetVersion["rules"][number]["citations"][number]["sourceDocumentVersionId"],
  sourceDocumentSha256: "1".repeat(
    64
  ) as RulesetVersion["rules"][number]["citations"][number]["sourceDocumentSha256"],
  clause: "Charter 7.2",
  locator: "reserved matters"
};

describe("ruleset evaluator", () => {
  it("evaluates every strict condition operator", () => {
    const facts = { flag: true, amount: 12, category: "reserved", empty: null };
    expect(
      conditionMatches(
        {
          kind: "all",
          conditions: [
            { kind: "exists", field: "flag" },
            { kind: "not", condition: { kind: "exists", field: "empty" } },
            { kind: "equals", field: "category", value: "reserved" },
            { kind: "in", field: "amount", values: [10, 12] },
            { kind: "number_gte", field: "amount", value: 12 },
            { kind: "number_lte", field: "amount", value: 12 }
          ]
        },
        facts
      )
    ).toBe(true);
    expect(
      conditionMatches(
        {
          kind: "any",
          conditions: [
            { kind: "equals", field: "category", value: "ordinary" },
            { kind: "number_lte", field: "amount", value: 11 }
          ]
        },
        facts
      )
    ).toBe(false);
    expect(conditionMatches({ kind: "equals", field: "missing", value: null }, facts)).toBe(false);
    expect(conditionMatches({ kind: "in", field: "missing", values: [null] }, facts)).toBe(false);
    expect(conditionMatches({ kind: "number_gte", field: "category", value: 1 }, facts)).toBe(
      false
    );
    expect(
      conditionMatches(
        {
          kind: "all",
          conditions: [
            { kind: "exists", field: "flag" },
            { kind: "exists", field: "missing" }
          ]
        },
        facts
      )
    ).toBe(false);
    expect(
      conditionMatches(
        {
          kind: "any",
          conditions: [
            { kind: "exists", field: "flag" },
            { kind: "exists", field: "missing" }
          ]
        },
        facts
      )
    ).toBe(true);
    expect(conditionMatches({ kind: "number_gte", field: "amount", value: 13 }, facts)).toBe(false);
    expect(
      conditionMatches({ kind: "number_gte", field: "amount", value: 12 }, { amount: "12" })
    ).toBe(false);
    expect(
      conditionMatches({ kind: "number_lte", field: "amount", value: 12 }, { amount: "12" })
    ).toBe(false);
  });

  it("selects deterministically by priority then specificity", () => {
    const ruleset: RulesetVersion = {
      ...base,
      matterTypes: [
        ...base.matterTypes,
        { code: "other", fields: [{ name: "amount", type: "integer", required: true }] }
      ],
      rules: [
        {
          id: "00000000-0000-7000-8000-000000000010" as RulesetVersion["rules"][number]["id"],
          matterType: "investment",
          priority: 20,
          specificity: 1,
          condition: { kind: "exists", field: "amount" },
          approvalRuleId:
            "00000000-0000-7000-8000-000000000020" as RulesetVersion["rules"][number]["approvalRuleId"],
          citations: [citation]
        },
        {
          id: "00000000-0000-7000-8000-000000000011" as RulesetVersion["rules"][number]["id"],
          matterType: "investment",
          priority: 10,
          specificity: 1_000_000,
          condition: { kind: "number_gte", field: "amount", value: 1_000_000 },
          approvalRuleId:
            "00000000-0000-7000-8000-000000000021" as RulesetVersion["rules"][number]["approvalRuleId"],
          citations: [citation]
        },
        {
          id: "00000000-0000-7000-8000-000000000012" as RulesetVersion["rules"][number]["id"],
          matterType: "other",
          priority: 1_000_000,
          specificity: 1_000_000,
          condition: { kind: "exists", field: "amount" },
          approvalRuleId:
            "00000000-0000-7000-8000-000000000022" as RulesetVersion["rules"][number]["approvalRuleId"],
          citations: [citation]
        }
      ]
    };
    const result = evaluateMatter(ruleset, "investment", { amount: 2_000_000 });
    expect(result.status).toBe("matched");
    if (result.status === "matched") expect(result.rule.id).toBe(ruleset.rules[0]?.id);

    const specificityResult = evaluateMatter(
      {
        ...ruleset,
        rules: [
          { ...ruleset.rules[0]!, priority: 10, specificity: 1 },
          { ...ruleset.rules[1]!, priority: 10, specificity: 2 },
          ruleset.rules[2]!
        ]
      },
      "investment",
      { amount: 2_000_000 }
    );
    expect(specificityResult.status).toBe("matched");
    if (specificityResult.status === "matched") {
      expect(specificityResult.rule.id).toBe(ruleset.rules[1]?.id);
    }
  });

  it("fails closed on equally ranked ambiguity", () => {
    const first = {
      id: "00000000-0000-7000-8000-000000000010" as RulesetVersion["rules"][number]["id"],
      matterType: "reserved",
      priority: 2,
      specificity: 2,
      condition: { kind: "exists" as const, field: "flag" },
      approvalRuleId:
        "00000000-0000-7000-8000-000000000020" as RulesetVersion["rules"][number]["approvalRuleId"],
      citations: [citation]
    };
    const ruleset: RulesetVersion = {
      ...base,
      matterTypes: [
        { code: "reserved", fields: [{ name: "flag", type: "boolean", required: true }] }
      ],
      rules: [
        first,
        { ...first, id: "00000000-0000-7000-8000-000000000011" as typeof first.id },
        {
          ...first,
          id: "00000000-0000-7000-8000-000000000012" as typeof first.id,
          specificity: 1
        },
        {
          ...first,
          id: "00000000-0000-7000-8000-000000000013" as typeof first.id,
          priority: 1
        }
      ]
    };
    expect(evaluateMatter(ruleset, "reserved", { flag: true })).toMatchObject({
      status: "ambiguous",
      candidateRuleIds: [
        "00000000-0000-7000-8000-000000000010",
        "00000000-0000-7000-8000-000000000011"
      ]
    });
  });

  it("fails closed with an explicit missing result and rejects unknown or floating facts", () => {
    const ruleset: RulesetVersion = {
      ...base,
      rules: [
        {
          id: "00000000-0000-7000-8000-000000000010" as RulesetVersion["rules"][number]["id"],
          matterType: "investment",
          priority: 1,
          specificity: 1,
          condition: { kind: "number_gte", field: "amount", value: 1 },
          approvalRuleId:
            "00000000-0000-7000-8000-000000000020" as RulesetVersion["rules"][number]["approvalRuleId"],
          citations: [citation]
        }
      ]
    };
    expect(evaluateMatter(ruleset, "investment", {})).toMatchObject({
      status: "missing",
      missingFields: ["amount"]
    });
    expect(() => evaluateMatter(ruleset, "investment", { amount: 2, surprise: true })).toThrow(
      "unknown matter fact"
    );
    expect(() => evaluateMatter(ruleset, "investment", { amount: 1.5 })).toThrow("integer");
  });

  it("validates boolean, bounded integer and bounded string facts and returns no-match", () => {
    const ruleset: RulesetVersion = {
      ...base,
      matterTypes: [
        {
          code: "mixed",
          fields: [
            { name: "flag", type: "boolean", required: true },
            { name: "amount", type: "integer", required: true, minimum: 1, maximum: 2 },
            { name: "label", type: "string", required: false, maxLength: 3 }
          ]
        }
      ],
      rules: [
        {
          id: "00000000-0000-7000-8000-000000000010" as RulesetVersion["rules"][number]["id"],
          matterType: "mixed",
          priority: 1,
          specificity: 1,
          condition: { kind: "equals", field: "flag", value: false },
          approvalRuleId:
            "00000000-0000-7000-8000-000000000020" as RulesetVersion["rules"][number]["approvalRuleId"],
          citations: [citation]
        }
      ]
    };
    expect(evaluateMatter(ruleset, "mixed", { flag: true, amount: 1, label: null })).toMatchObject({
      status: "no_match",
      candidateRuleIds: []
    });
    expect(() => evaluateMatter(ruleset, "missing", {})).toThrow("unknown matter type");
    expect(() => evaluateMatter(ruleset, "mixed", { flag: "yes", amount: 1 })).toThrow(
      "must be boolean"
    );
    expect(() => evaluateMatter(ruleset, "mixed", { flag: true, amount: "1" })).toThrow(
      "safe integer"
    );
    expect(() => evaluateMatter(ruleset, "mixed", { flag: true, amount: 0 })).toThrow(
      "below its minimum"
    );
    expect(() => evaluateMatter(ruleset, "mixed", { flag: true, amount: 3 })).toThrow(
      "above its maximum"
    );
    expect(() => evaluateMatter(ruleset, "mixed", { flag: true, amount: 1, label: false })).toThrow(
      "must be string"
    );
    expect(() =>
      evaluateMatter(ruleset, "mixed", { flag: true, amount: 1, label: "long" })
    ).toThrow("exceeds maxLength");
    expect(evaluateMatter(ruleset, "mixed", { flag: true, amount: 2, label: "abc" })).toMatchObject(
      { status: "no_match", candidateRuleIds: [] }
    );
    expect(evaluateMatter(ruleset, "mixed", { flag: true, amount: null })).toMatchObject({
      status: "missing",
      missingFields: ["amount"]
    });
  });

  it("rejects rules that reference undeclared facts", () => {
    expect(() =>
      RulesetVersionSchema.parse({
        ...base,
        rules: [
          {
            id: "00000000-0000-7000-8000-000000000010",
            matterType: "investment",
            priority: 1,
            specificity: 1,
            condition: { kind: "exists", field: "undeclared" },
            approvalRuleId: "00000000-0000-7000-8000-000000000020",
            citations: [citation]
          }
        ]
      })
    ).toThrow("undeclared fact");
  });

  it("rejects duplicate definitions, inverted bounds, undeclared types and deep conditions", () => {
    expect(() =>
      MatterTypeSchema.parse({
        code: "investment",
        fields: [
          { name: "amount", type: "integer", required: true, minimum: 2, maximum: 1 },
          { name: "amount", type: "integer", required: false }
        ]
      })
    ).toThrow();
    const rule = {
      id: "00000000-0000-7000-8000-000000000010" as RulesetVersion["rules"][number]["id"],
      matterType: "investment",
      priority: 1,
      specificity: 1,
      condition: { kind: "exists" as const, field: "amount" },
      approvalRuleId:
        "00000000-0000-7000-8000-000000000020" as RulesetVersion["rules"][number]["approvalRuleId"],
      citations: [citation]
    };
    expect(() =>
      RulesetVersionSchema.parse({
        ...base,
        matterTypes: [...base.matterTypes, ...base.matterTypes],
        rules: [rule, rule]
      })
    ).toThrow();
    expect(() =>
      RulesetVersionSchema.parse({
        ...base,
        rules: [{ ...rule, matterType: "undeclared" }]
      })
    ).toThrow("undeclared matter type");
    let deep: Condition = { kind: "exists", field: "amount" };
    for (let index = 0; index < 17; index += 1) deep = { kind: "not", condition: deep };
    expect(() =>
      RulesetVersionSchema.parse({
        ...base,
        rules: [{ ...rule, condition: deep }]
      })
    ).toThrow("depth or node limit");
  });
});
