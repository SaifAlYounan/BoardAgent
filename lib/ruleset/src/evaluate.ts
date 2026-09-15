import { canonicalSha256 } from "@boardagent/contracts";

import type {
  Condition,
  MatterField,
  MatterType,
  MatterValue,
  Rule,
  RulesetVersion
} from "./schema.js";

export type MatterFacts = Readonly<Record<string, MatterValue>>;

function isSame(left: MatterValue, right: MatterValue): boolean {
  return canonicalSha256(left) === canonicalSha256(right);
}

function isSafeInteger(value: MatterValue): value is number {
  return Number.isSafeInteger(value);
}

export function conditionMatches(condition: Condition, facts: MatterFacts): boolean {
  switch (condition.kind) {
    case "all":
      return condition.conditions.every((entry) => conditionMatches(entry, facts));
    case "any":
      return condition.conditions.some((entry) => conditionMatches(entry, facts));
    case "not":
      return !conditionMatches(condition.condition, facts);
    case "exists":
      return Object.hasOwn(facts, condition.field) && facts[condition.field] !== null;
    case "equals":
      return (
        Object.hasOwn(facts, condition.field) &&
        isSame(facts[condition.field] ?? null, condition.value)
      );
    case "in":
      return (
        Object.hasOwn(facts, condition.field) &&
        condition.values.some((entry) => isSame(facts[condition.field] ?? null, entry))
      );
    case "number_gte": {
      const value = facts[condition.field];
      return typeof value === "number" && value >= condition.value;
    }
    case "number_lte": {
      const value = facts[condition.field];
      return typeof value === "number" && value <= condition.value;
    }
  }
}

export type MatterEvaluation =
  | {
      readonly status: "matched";
      readonly rulesetId: string;
      readonly rulesetVersion: number;
      readonly factsHash: string;
      readonly rule: Rule;
    }
  | {
      readonly status: "no_match" | "ambiguous";
      readonly rulesetId: string;
      readonly rulesetVersion: number;
      readonly factsHash: string;
      readonly candidateRuleIds: readonly string[];
    }
  | {
      readonly status: "missing";
      readonly rulesetId: string;
      readonly rulesetVersion: number;
      readonly factsHash: string;
      readonly missingFields: readonly string[];
    };

function assertFactValue(field: MatterField, value: MatterValue): void {
  if (value === null) return;
  if (field.type === "boolean" && typeof value !== "boolean") {
    throw new TypeError(`matter fact ${field.name} must be boolean`);
  }
  if (field.type === "integer") {
    if (!isSafeInteger(value)) {
      throw new TypeError(`matter fact ${field.name} must be a safe integer`);
    }
    if (value < (field.minimum ?? Number.NEGATIVE_INFINITY)) {
      throw new RangeError(`matter fact ${field.name} is below its minimum`);
    }
    if (value > (field.maximum ?? Number.POSITIVE_INFINITY)) {
      throw new RangeError(`matter fact ${field.name} is above its maximum`);
    }
  }
  if (field.type === "string") {
    if (typeof value !== "string") throw new TypeError(`matter fact ${field.name} must be string`);
    if (value.length > field.maxLength) {
      throw new RangeError(`matter fact ${field.name} exceeds maxLength`);
    }
  }
}

function validateFacts(definition: MatterType, facts: MatterFacts): readonly string[] {
  const fields = new Map(definition.fields.map((field) => [field.name, field]));
  for (const [name, value] of Object.entries(facts)) {
    const field = fields.get(name);
    if (!field) throw new TypeError(`unknown matter fact: ${name}`);
    assertFactValue(field, value);
  }
  return definition.fields
    .filter(
      (field) => field.required && (!Object.hasOwn(facts, field.name) || facts[field.name] === null)
    )
    .map((field) => field.name)
    .toSorted();
}

export function evaluateMatter(
  ruleset: RulesetVersion,
  matterType: string,
  facts: MatterFacts
): MatterEvaluation {
  const factsHash = canonicalSha256(facts);
  const definition = ruleset.matterTypes.find((definition) => definition.code === matterType);
  if (!definition) throw new TypeError(`unknown matter type: ${matterType}`);
  const missingFields = validateFacts(definition, facts);
  if (missingFields.length > 0) {
    return {
      status: "missing",
      rulesetId: ruleset.id,
      rulesetVersion: ruleset.version,
      factsHash,
      missingFields
    };
  }
  const candidates = ruleset.rules
    .filter((rule) => rule.matterType === matterType && conditionMatches(rule.condition, facts))
    .toSorted(
      (left, right) =>
        right.priority - left.priority ||
        right.specificity - left.specificity ||
        left.id.localeCompare(right.id)
    );
  const first = candidates[0];
  if (!first) {
    return {
      status: "no_match",
      rulesetId: ruleset.id,
      rulesetVersion: ruleset.version,
      factsHash,
      candidateRuleIds: []
    };
  }
  const tied = candidates.filter(
    (candidate) =>
      candidate.priority === first.priority && candidate.specificity === first.specificity
  );
  if (tied.length !== 1) {
    return {
      status: "ambiguous",
      rulesetId: ruleset.id,
      rulesetVersion: ruleset.version,
      factsHash,
      candidateRuleIds: tied.map((candidate) => candidate.id)
    };
  }
  return {
    status: "matched",
    rulesetId: ruleset.id,
    rulesetVersion: ruleset.version,
    factsHash,
    rule: first
  };
}
