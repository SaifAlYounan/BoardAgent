import { describe, expect, it } from "vitest";
import type { ZodType } from "zod";

import {
  CitationSchema,
  ConditionSchema,
  MatterFieldSchema,
  MatterTypeSchema,
  MatterValueSchema,
  RuleSchema,
  RulesetVersionSchema,
  type Condition
} from "../../lib/ruleset/src/index.js";

const id = (suffix: number): string =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;
const hash = (character: string): string => character.repeat(64);

const citation = {
  sourceDocumentVersionId: id(900_000),
  sourceDocumentSha256: hash("a"),
  clause: "Charter 7.2",
  locator: "reserved matters"
};

const rule = (
  suffix: number,
  matterType = "investment",
  condition: Condition = { kind: "exists", field: "amount" }
) => ({
  id: id(100_000 + suffix),
  matterType,
  priority: 1,
  specificity: 1,
  condition,
  approvalRuleId: id(500_000 + suffix),
  citations: [citation]
});

const ruleset = {
  schemaVersion: "boardagent.ruleset.v1",
  id: id(1),
  boardId: id(2),
  version: 1,
  canonicalHash: hash("0"),
  matterTypes: [
    {
      code: "investment",
      fields: [{ name: "amount", type: "integer", required: true }]
    }
  ],
  rules: [rule(1)]
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

function nestedNot(depth: number): Condition {
  let condition: Condition = { kind: "exists", field: "amount" };
  for (let index = 1; index < depth; index += 1) {
    condition = { kind: "not", condition };
  }
  return condition;
}

function nestedAny(depth: number): Condition {
  let condition: Condition = { kind: "exists", field: "amount" };
  for (let index = 1; index < depth; index += 1) {
    condition = { kind: "any", conditions: [condition] };
  }
  return condition;
}

function broadTree(nodes: 512 | 513): Condition {
  const leafCount = nodes - 9;
  const groups = Array.from({ length: 8 }, (_, groupIndex) => ({
    kind: "all" as const,
    conditions: Array.from(
      { length: groupIndex === 7 ? leafCount - 7 * 63 : 63 },
      (): Condition => ({ kind: "exists", field: "amount" })
    )
  }));
  return { kind: "all", conditions: groups };
}

describe("ruleset schema exact boundaries", () => {
  it("enforces exact matter-value, field-name, string-length and field-count bounds", () => {
    expectAccepted(MatterValueSchema, "");
    expectAccepted(MatterValueSchema, "x".repeat(4_096));
    expectRejected(MatterValueSchema, "x".repeat(4_097));

    const validName = `a${"b".repeat(127)}`;
    for (const name of ["a", validName]) {
      expectAccepted(MatterFieldSchema, { name, type: "boolean", required: true });
    }
    for (const name of ["_a", "a-", `a${"b".repeat(128)}`]) {
      expectRejected(MatterFieldSchema, { name, type: "boolean", required: true });
    }

    expectAccepted(MatterFieldSchema, {
      name: "label",
      type: "string",
      required: false,
      maxLength: 1
    });
    expectAccepted(MatterFieldSchema, {
      name: "label",
      type: "string",
      required: false,
      maxLength: 262_144
    });
    expectRejected(MatterFieldSchema, {
      name: "label",
      type: "string",
      required: false,
      maxLength: 262_145
    });

    const fields = Array.from({ length: 128 }, (_, index) => ({
      name: `field_${index}`,
      type: "boolean" as const,
      required: false
    }));
    expectAccepted(MatterTypeSchema, { code: "wide", fields });
    expectRejected(MatterTypeSchema, { code: "empty", fields: [] });
    expectRejected(MatterTypeSchema, {
      code: "too_wide",
      fields: [...fields, { name: "field_128", type: "boolean", required: false }]
    });
  });

  it("reports exact duplicate-field and inverted-integer-bound issues", () => {
    expectAccepted(MatterTypeSchema, {
      code: "bounded",
      fields: [
        { name: "amount", type: "integer", required: true, minimum: 2, maximum: 2 },
        { name: "minimum_only", type: "integer", required: false, minimum: 0 },
        { name: "maximum_only", type: "integer", required: false, maximum: 0 },
        { name: "unbounded", type: "integer", required: false }
      ]
    });
    expectCustomIssue(
      MatterTypeSchema,
      {
        code: "duplicate",
        fields: [
          { name: "flag", type: "boolean", required: true },
          { name: "flag", type: "boolean", required: false }
        ]
      },
      ["fields", 1, "name"],
      "duplicate matter fact: flag"
    );
    expectCustomIssue(
      MatterTypeSchema,
      {
        code: "inverted",
        fields: [{ name: "amount", type: "integer", required: true, minimum: 2, maximum: 1 }]
      },
      ["fields", 0],
      "invalid integer bounds for amount"
    );
  });

  it("enforces every condition literal and exact recursive collection bound", () => {
    const leaf: Condition = { kind: "exists", field: "amount" };
    for (const kind of ["all", "any"] as const) {
      expectAccepted(ConditionSchema, { kind, conditions: [leaf] });
      expectAccepted(ConditionSchema, {
        kind,
        conditions: Array.from({ length: 64 }, () => leaf)
      });
      expectRejected(ConditionSchema, { kind, conditions: [] });
      expectRejected(ConditionSchema, {
        kind,
        conditions: Array.from({ length: 65 }, () => leaf)
      });
    }
    for (const condition of [
      { kind: "not", condition: leaf },
      leaf,
      { kind: "equals", field: "amount", value: 1 },
      { kind: "in", field: "amount", values: [1] },
      { kind: "number_gte", field: "amount", value: 1 },
      { kind: "number_lte", field: "amount", value: 1 }
    ]) {
      expectAccepted(ConditionSchema, condition);
    }
    expectAccepted(ConditionSchema, {
      kind: "in",
      field: "amount",
      values: Array.from({ length: 128 }, (_, index) => index)
    });
    expectRejected(ConditionSchema, { kind: "in", field: "amount", values: [] });
    expectRejected(ConditionSchema, {
      kind: "in",
      field: "amount",
      values: Array.from({ length: 129 }, (_, index) => index)
    });
  });

  it("enforces exact citation, rule ranking and citation-count bounds", () => {
    expectAccepted(CitationSchema, { ...citation, clause: "x", locator: "x" });
    expectAccepted(CitationSchema, {
      ...citation,
      clause: "x".repeat(512),
      locator: "x".repeat(1_024)
    });
    for (const candidate of [
      { ...citation, clause: "" },
      { ...citation, clause: "x".repeat(513) },
      { ...citation, locator: "" },
      { ...citation, locator: "x".repeat(1_025) }
    ]) {
      expectRejected(CitationSchema, candidate);
    }

    expectAccepted(RuleSchema, { ...rule(2), priority: 0, specificity: 0 });
    expectAccepted(RuleSchema, {
      ...rule(2),
      matterType: "x".repeat(128),
      priority: 1_000_000,
      specificity: 1_000_000,
      citations: Array.from({ length: 64 }, () => citation)
    });
    for (const candidate of [
      { ...rule(2), matterType: "" },
      { ...rule(2), matterType: "x".repeat(129) },
      { ...rule(2), priority: -1 },
      { ...rule(2), priority: 1_000_001 },
      { ...rule(2), specificity: -1 },
      { ...rule(2), specificity: 1_000_001 },
      { ...rule(2), citations: [] },
      { ...rule(2), citations: Array.from({ length: 65 }, () => citation) }
    ]) {
      expectRejected(RuleSchema, candidate);
    }
  });

  it("reports exact cross-definition issues and accepts the depth limit exactly", () => {
    expectCustomIssue(
      RulesetVersionSchema,
      { ...ruleset, matterTypes: [...ruleset.matterTypes, ...ruleset.matterTypes] },
      ["matterTypes", 1, "code"],
      "duplicate matter type: investment"
    );
    expectCustomIssue(
      RulesetVersionSchema,
      { ...ruleset, rules: [rule(1), rule(1)] },
      ["rules", 1, "id"],
      `duplicate rule id: ${rule(1).id}`
    );
    expectCustomIssue(
      RulesetVersionSchema,
      { ...ruleset, rules: [rule(2, "undeclared")] },
      ["rules", 0, "matterType"],
      "undeclared matter type: undeclared"
    );
    expectCustomIssue(
      RulesetVersionSchema,
      { ...ruleset, rules: [rule(2, "investment", { kind: "exists", field: "undeclared" })] },
      ["rules", 0, "condition"],
      "undeclared fact undeclared for matter type investment"
    );

    expectAccepted(RulesetVersionSchema, {
      ...ruleset,
      rules: [rule(2, "investment", nestedNot(16)), rule(3, "investment", nestedAny(16))]
    });
    expectCustomIssue(
      RulesetVersionSchema,
      { ...ruleset, rules: [rule(2, "investment", nestedNot(17))] },
      ["rules", 0, "condition"],
      "condition tree exceeds depth or node limit"
    );
    expectCustomIssue(
      RulesetVersionSchema,
      { ...ruleset, rules: [rule(3, "investment", nestedAny(17))] },
      ["rules", 0, "condition"],
      "condition tree exceeds depth or node limit"
    );
  });

  it("accepts 512 condition nodes and rejects the 513th", () => {
    expectAccepted(RulesetVersionSchema, {
      ...ruleset,
      rules: [rule(2, "investment", broadTree(512))]
    });
    expectCustomIssue(
      RulesetVersionSchema,
      { ...ruleset, rules: [rule(2, "investment", broadTree(513))] },
      ["rules", 0, "condition"],
      "condition tree exceeds depth or node limit"
    );
  });

  it("enforces exact ruleset collection bounds", () => {
    const matterTypes = Array.from({ length: 1_001 }, (_, index) => ({
      code: `type_${index}`,
      fields: [{ name: "amount", type: "integer" as const, required: true }]
    }));
    expectAccepted(RulesetVersionSchema, {
      ...ruleset,
      matterTypes: matterTypes.slice(0, 1_000),
      rules: [rule(2, "type_0")]
    });
    expectRejected(RulesetVersionSchema, {
      ...ruleset,
      matterTypes,
      rules: [rule(2, "type_0")]
    });
    expectRejected(RulesetVersionSchema, { ...ruleset, matterTypes: [] });

    const rules = Array.from({ length: 10_001 }, (_, index) => rule(index + 1));
    expectAccepted(RulesetVersionSchema, { ...ruleset, rules: rules.slice(0, 10_000) });
    expectRejected(RulesetVersionSchema, { ...ruleset, rules });
    expectRejected(RulesetVersionSchema, { ...ruleset, rules: [] });
  });
});
