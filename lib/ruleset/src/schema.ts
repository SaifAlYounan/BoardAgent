import { z } from "zod";

import { Sha256HexSchema, UuidSchema } from "@boardagent/contracts";

function createMatterValueSchema() {
  return z.union([z.boolean(), z.number().int().safe(), z.string().max(4096), z.null()]);
}

export const MatterValueSchema = z.lazy(createMatterValueSchema);
export type MatterValue = z.infer<typeof MatterValueSchema>;

function createMatterFieldNameSchema() {
  return z.string().regex(/^[a-z][a-z0-9_]{0,127}$/u);
}

const MatterFieldNameSchema = z.lazy(createMatterFieldNameSchema);

function createMatterFieldSchema() {
  return z.discriminatedUnion("type", [
    z
      .object({
        name: MatterFieldNameSchema,
        type: z.literal("boolean"),
        required: z.boolean()
      })
      .strict(),
    z
      .object({
        name: MatterFieldNameSchema,
        type: z.literal("integer"),
        required: z.boolean(),
        minimum: z.number().int().safe().optional(),
        maximum: z.number().int().safe().optional()
      })
      .strict(),
    z
      .object({
        name: MatterFieldNameSchema,
        type: z.literal("string"),
        required: z.boolean(),
        maxLength: z.number().int().positive().max(262_144).default(4096)
      })
      .strict()
  ]);
}

export const MatterFieldSchema = z.lazy(createMatterFieldSchema);
export type MatterField = z.infer<typeof MatterFieldSchema>;

function createMatterTypeSchema() {
  return z
    .object({
      code: MatterFieldNameSchema,
      fields: z.array(MatterFieldSchema).min(1).max(128)
    })
    .strict()
    .superRefine((matterType, context) => {
      const names = new Set<string>();
      for (const [index, field] of matterType.fields.entries()) {
        if (names.has(field.name)) {
          context.addIssue({
            code: "custom",
            path: ["fields", index, "name"],
            message: `duplicate matter fact: ${field.name}`
          });
        }
        names.add(field.name);
        switch (field.type) {
          case "integer":
            if (
              (field.minimum ?? Number.NEGATIVE_INFINITY) >
              (field.maximum ?? Number.POSITIVE_INFINITY)
            ) {
              context.addIssue({
                code: "custom",
                path: ["fields", index],
                message: `invalid integer bounds for ${field.name}`
              });
            }
            break;
        }
      }
    });
}

export const MatterTypeSchema = z.lazy(createMatterTypeSchema);
export type MatterType = z.infer<typeof MatterTypeSchema>;

export type Condition =
  | { readonly kind: "all"; readonly conditions: readonly Condition[] }
  | { readonly kind: "any"; readonly conditions: readonly Condition[] }
  | { readonly kind: "not"; readonly condition: Condition }
  | { readonly kind: "exists"; readonly field: string }
  | { readonly kind: "equals"; readonly field: string; readonly value: MatterValue }
  | { readonly kind: "in"; readonly field: string; readonly values: readonly MatterValue[] }
  | { readonly kind: "number_gte"; readonly field: string; readonly value: number }
  | { readonly kind: "number_lte"; readonly field: string; readonly value: number };

function createConditionSchema(): z.ZodType<Condition> {
  return z.discriminatedUnion("kind", [
    z
      .object({ kind: z.literal("all"), conditions: z.array(ConditionSchema).min(1).max(64) })
      .strict(),
    z
      .object({ kind: z.literal("any"), conditions: z.array(ConditionSchema).min(1).max(64) })
      .strict(),
    z.object({ kind: z.literal("not"), condition: ConditionSchema }).strict(),
    z.object({ kind: z.literal("exists"), field: MatterFieldNameSchema }).strict(),
    z
      .object({
        kind: z.literal("equals"),
        field: MatterFieldNameSchema,
        value: MatterValueSchema
      })
      .strict(),
    z
      .object({
        kind: z.literal("in"),
        field: MatterFieldNameSchema,
        values: z.array(MatterValueSchema).min(1).max(128)
      })
      .strict(),
    z
      .object({
        kind: z.literal("number_gte"),
        field: MatterFieldNameSchema,
        value: z.number().int().safe()
      })
      .strict(),
    z
      .object({
        kind: z.literal("number_lte"),
        field: MatterFieldNameSchema,
        value: z.number().int().safe()
      })
      .strict()
  ]);
}

export const ConditionSchema: z.ZodType<Condition> = z.lazy(createConditionSchema);

function createCitationSchema() {
  return z
    .object({
      sourceDocumentVersionId: UuidSchema,
      sourceDocumentSha256: Sha256HexSchema,
      clause: z.string().min(1).max(512),
      locator: z.string().min(1).max(1024)
    })
    .strict();
}

export const CitationSchema = z.lazy(createCitationSchema);
export type Citation = z.infer<typeof CitationSchema>;

function createRuleSchema() {
  return z
    .object({
      id: UuidSchema,
      matterType: z.string().min(1).max(128),
      priority: z.number().int().min(0).max(1_000_000),
      specificity: z.number().int().min(0).max(1_000_000),
      condition: ConditionSchema,
      approvalRuleId: UuidSchema,
      citations: z.array(CitationSchema).min(1).max(64)
    })
    .strict();
}

export const RuleSchema = z.lazy(createRuleSchema);
export type Rule = z.infer<typeof RuleSchema>;

function conditionFields(
  condition: Condition,
  fields: Set<string>,
  counters: { depth: number; nodes: number },
  depth = 1
): void {
  counters.depth = Math.max(counters.depth, depth);
  counters.nodes += 1;
  if (condition.kind === "all" || condition.kind === "any") {
    for (const child of condition.conditions) conditionFields(child, fields, counters, depth + 1);
  } else if (condition.kind === "not") {
    conditionFields(condition.condition, fields, counters, depth + 1);
  } else {
    fields.add(condition.field);
  }
}

function createRulesetVersionSchema() {
  return z
    .object({
      schemaVersion: z.literal("boardagent.ruleset.v1"),
      id: UuidSchema,
      boardId: UuidSchema,
      version: z.number().int().positive().safe(),
      canonicalHash: Sha256HexSchema,
      matterTypes: z.array(MatterTypeSchema).min(1).max(1_000),
      rules: z.array(RuleSchema).min(1).max(10_000)
    })
    .strict()
    .superRefine((ruleset, context) => {
      const definitions = new Map<string, MatterType>();
      for (const [index, matterType] of ruleset.matterTypes.entries()) {
        if (definitions.has(matterType.code)) {
          context.addIssue({
            code: "custom",
            path: ["matterTypes", index, "code"],
            message: `duplicate matter type: ${matterType.code}`
          });
        }
        definitions.set(matterType.code, matterType);
      }
      const ruleIds = new Set<string>();
      for (const [index, rule] of ruleset.rules.entries()) {
        if (ruleIds.has(rule.id)) {
          context.addIssue({
            code: "custom",
            path: ["rules", index, "id"],
            message: `duplicate rule id: ${rule.id}`
          });
        }
        ruleIds.add(rule.id);
        const definition = definitions.get(rule.matterType);
        if (!definition) {
          context.addIssue({
            code: "custom",
            path: ["rules", index, "matterType"],
            message: `undeclared matter type: ${rule.matterType}`
          });
          continue;
        }
        const fields = new Set<string>();
        const counters = { depth: 0, nodes: 0 };
        conditionFields(rule.condition, fields, counters);
        const declared = new Set(definition.fields.map((field) => field.name));
        for (const field of fields) {
          if (!declared.has(field)) {
            context.addIssue({
              code: "custom",
              path: ["rules", index, "condition"],
              message: `undeclared fact ${field} for matter type ${rule.matterType}`
            });
          }
        }
        if (counters.depth > 16 || counters.nodes > 512) {
          context.addIssue({
            code: "custom",
            path: ["rules", index, "condition"],
            message: "condition tree exceeds depth or node limit"
          });
        }
      }
    });
}

export const RulesetVersionSchema = z.lazy(createRulesetVersionSchema);
export type RulesetVersion = z.infer<typeof RulesetVersionSchema>;
