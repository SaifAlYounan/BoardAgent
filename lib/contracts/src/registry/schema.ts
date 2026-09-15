import { z } from "zod";

import { canonicalSha256 } from "../canonical.js";
import {
  ACTIVATION_RESTART_AMENDMENT,
  ACTIVE_REGISTRY_COUNTS,
  ADMINISTRATIVE_REGISTRY_COUNTS,
  ADMINISTRATIVE_AMENDMENT,
  OPERATIONAL_AMENDMENT,
  OPERATIONAL_REGISTRY_COUNTS,
  ONBOARDING_AMENDMENT,
  ONBOARDING_REGISTRY_COUNTS
} from "./amendment.js";

export {
  ACTIVATION_RESTART_AMENDMENT,
  ACTIVE_REGISTRY_COUNTS,
  ADMINISTRATIVE_REGISTRY_COUNTS,
  ADMINISTRATIVE_AMENDMENT,
  OPERATIONAL_AMENDMENT,
  OPERATIONAL_REGISTRY_COUNTS,
  ONBOARDING_AMENDMENT,
  ONBOARDING_REGISTRY_COUNTS
} from "./amendment.js";

export const ToolClassSchema = z.enum(["R", "D", "H"]);
export type ToolClass = z.infer<typeof ToolClassSchema>;

const IdentifierSchema = z.string().regex(/^[a-z][a-z0-9_]*$/u);
const NonEmptyCellSchema = z.string().trim().min(1);

export const ToolRegistryEntrySchema = z
  .object({
    name: IdentifierSchema,
    class: ToolClassSchema,
    section: NonEmptyCellSchema,
    requiredAuthority: NonEmptyCellSchema,
    objectRule: NonEmptyCellSchema,
    requiredEvidence: NonEmptyCellSchema
  })
  .strict();

export const ResourceRegistryEntrySchema = z
  .object({
    uriTemplate: z.string().min(1),
    representations: NonEmptyCellSchema,
    entitlementRoot: NonEmptyCellSchema
  })
  .strict();

export const PromptRegistryEntrySchema = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9-]*$/u),
    intendedFlow: NonEmptyCellSchema
  })
  .strict();

export const HttpAuthorityFamilySchema = z
  .object({
    surface: NonEmptyCellSchema,
    authorityAndBehavior: NonEmptyCellSchema
  })
  .strict();

export const CliRegistryEntrySchema = z
  .object({
    commands: z.array(z.string().regex(/^[a-z][a-z0-9-]*$/u)).min(1),
    authorityPath: NonEmptyCellSchema
  })
  .strict();

export const EventRegistryEntrySchema = z
  .object({
    name: IdentifierSchema,
    category: NonEmptyCellSchema
  })
  .strict();

export const SecurityRequirementSchema = z
  .object({
    id: z.string().regex(/^SR-\d{3}$/u),
    requirement: NonEmptyCellSchema
  })
  .strict();

export const ThreatScenarioSchema = z
  .object({
    id: z.string().regex(/^TH-\d{2}$/u),
    scenario: NonEmptyCellSchema,
    expectedControl: NonEmptyCellSchema,
    plannedProof: z.string().regex(/`tests\/[^`]+`/u)
  })
  .strict();

export const AcceptanceScenarioSchema = z
  .object({
    id: z.string().regex(/^AC-\d{2}$/u),
    outcome: NonEmptyCellSchema
  })
  .strict();

export const VerificationTierSchema = z
  .object({
    id: z.string().regex(/^T(?:10|[0-9])$/u),
    name: NonEmptyCellSchema,
    requiredTarget: NonEmptyCellSchema,
    threshold: NonEmptyCellSchema,
    releaseRule: NonEmptyCellSchema
  })
  .strict();

export const RegistrySourceSchema = z
  .object({
    schemaVersion: z.literal("boardagent.registry.v1"),
    sources: z
      .object({
        surfaceMatrix: z.string().min(1),
        surfaceMatrixSha256: z.string().regex(/^[0-9a-f]{64}$/u),
        verificationMatrix: z.string().min(1),
        verificationMatrixSha256: z.string().regex(/^[0-9a-f]{64}$/u),
        amendment: z
          .object({
            id: z.literal(ADMINISTRATIVE_AMENDMENT.id),
            path: z.literal(ADMINISTRATIVE_AMENDMENT.path),
            sha256: z.literal(ADMINISTRATIVE_AMENDMENT.sha256),
            authorizationPath: z.literal(ADMINISTRATIVE_AMENDMENT.authorizationPath),
            authorizationSha256: z.literal(ADMINISTRATIVE_AMENDMENT.authorizationSha256)
          })
          .strict()
          .optional(),
        onboardingAmendment: z
          .object({
            id: z.literal(ONBOARDING_AMENDMENT.id),
            path: z.literal(ONBOARDING_AMENDMENT.path),
            sha256: z.literal(ONBOARDING_AMENDMENT.sha256),
            instructionPath: z.literal(ONBOARDING_AMENDMENT.instructionPath),
            instructionSha256: z.literal(ONBOARDING_AMENDMENT.instructionSha256),
            parentRegistryDigest: z.literal(ONBOARDING_AMENDMENT.parentRegistryDigest)
          })
          .strict()
          .optional(),
        operationalAmendment: z
          .object({
            id: z.literal(OPERATIONAL_AMENDMENT.id),
            path: z.literal(OPERATIONAL_AMENDMENT.path),
            sha256: z.literal(OPERATIONAL_AMENDMENT.sha256),
            instructionPath: z.literal(OPERATIONAL_AMENDMENT.instructionPath),
            instructionSha256: z.literal(OPERATIONAL_AMENDMENT.instructionSha256),
            parentRegistryDigest: z.literal(OPERATIONAL_AMENDMENT.parentRegistryDigest)
          })
          .strict()
          .optional(),
        activationRestartAmendment: z
          .object({
            id: z.literal(ACTIVATION_RESTART_AMENDMENT.id),
            path: z.literal(ACTIVATION_RESTART_AMENDMENT.path),
            sha256: z.literal(ACTIVATION_RESTART_AMENDMENT.sha256),
            instructionPath: z.literal(ACTIVATION_RESTART_AMENDMENT.instructionPath),
            instructionSha256: z.literal(ACTIVATION_RESTART_AMENDMENT.instructionSha256),
            parentRegistryDigest: z.literal(ACTIVATION_RESTART_AMENDMENT.parentRegistryDigest)
          })
          .strict()
          .optional()
      })
      .strict(),
    tools: z.array(ToolRegistryEntrySchema),
    resourceTemplates: z.array(ResourceRegistryEntrySchema),
    prompts: z.array(PromptRegistryEntrySchema),
    httpAuthorityFamilies: z.array(HttpAuthorityFamilySchema),
    cli: z.array(CliRegistryEntrySchema),
    events: z.array(EventRegistryEntrySchema),
    securityRequirements: z.array(SecurityRequirementSchema),
    threats: z.array(ThreatScenarioSchema),
    acceptanceScenarios: z.array(AcceptanceScenarioSchema),
    verificationTiers: z.array(VerificationTierSchema)
  })
  .strict();

export type RegistrySource = z.infer<typeof RegistrySourceSchema>;

export const FROZEN_REGISTRY_COUNTS = Object.freeze({
  tools: 148,
  readTools: 57,
  directTools: 30,
  humanConfirmedTools: 61,
  resourceTemplates: 16,
  prompts: 7,
  httpAuthorityFamilies: 11,
  cliRows: 8,
  cliCommands: 9,
  events: 128,
  securityRequirements: 94,
  threats: 63,
  acceptanceScenarios: 22,
  verificationTiers: 11
} as const);

function assertUnique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`duplicate ${label}: ${value}`);
    seen.add(value);
  }
}

function assertSequential(
  values: readonly string[],
  prefix: "AC" | "SR" | "TH",
  digits: number
): void {
  values.forEach((value, index) => {
    const expected = `${prefix}-${String(index + 1).padStart(digits, "0")}`;
    if (value !== expected)
      throw new Error(`${prefix} sequence drift: expected ${expected}, got ${value}`);
  });
}

export function assertRegistryInvariants(input: unknown): RegistrySource {
  const registry = RegistrySourceSchema.parse(input);
  const counts =
    registry.sources.activationRestartAmendment !== undefined
      ? ACTIVE_REGISTRY_COUNTS
      : registry.sources.onboardingAmendment !== undefined
        ? ONBOARDING_REGISTRY_COUNTS
        : registry.sources.operationalAmendment !== undefined
          ? OPERATIONAL_REGISTRY_COUNTS
          : registry.sources.amendment === undefined
            ? FROZEN_REGISTRY_COUNTS
            : ADMINISTRATIVE_REGISTRY_COUNTS;
  if (
    registry.sources.operationalAmendment !== undefined &&
    registry.sources.amendment === undefined
  )
    throw new Error("operational amendment requires its administrative parent");
  if (
    registry.sources.amendment !== undefined &&
    (registry.sources.surfaceMatrixSha256 !== ADMINISTRATIVE_AMENDMENT.surfaceMatrixSha256 ||
      registry.sources.verificationMatrixSha256 !==
        ADMINISTRATIVE_AMENDMENT.verificationMatrixSha256)
  )
    throw new Error("amended registry base matrix hash drift");

  if (
    registry.sources.onboardingAmendment !== undefined &&
    registry.sources.operationalAmendment === undefined
  )
    throw new Error("onboarding publication requires its operational parent");
  if (
    registry.sources.activationRestartAmendment !== undefined &&
    registry.sources.onboardingAmendment === undefined
  )
    throw new Error("activation restart requires its onboarding parent");
  const classes = { R: 0, D: 0, H: 0 } satisfies Record<ToolClass, number>;
  for (const tool of registry.tools) classes[tool.class] += 1;

  const exactCounts: ReadonlyArray<readonly [string, number, number]> = [
    ["tools", registry.tools.length, counts.tools],
    ["read tools", classes.R, counts.readTools],
    ["direct tools", classes.D, counts.directTools],
    ["human-confirmed tools", classes.H, counts.humanConfirmedTools],
    ["resource templates", registry.resourceTemplates.length, counts.resourceTemplates],
    ["prompts", registry.prompts.length, counts.prompts],
    [
      "HTTP authority families",
      registry.httpAuthorityFamilies.length,
      counts.httpAuthorityFamilies
    ],
    ["CLI rows", registry.cli.length, counts.cliRows],
    ["CLI commands", registry.cli.flatMap((entry) => entry.commands).length, counts.cliCommands],
    ["events", registry.events.length, counts.events],
    ["security requirements", registry.securityRequirements.length, counts.securityRequirements],
    ["threats", registry.threats.length, counts.threats],
    ["acceptance scenarios", registry.acceptanceScenarios.length, counts.acceptanceScenarios],
    ["verification tiers", registry.verificationTiers.length, counts.verificationTiers]
  ];
  for (const [label, actual, expected] of exactCounts) {
    if (actual !== expected)
      throw new Error(`${label} count drift: expected ${expected}, got ${actual}`);
  }

  assertUnique(
    registry.tools.map((entry) => entry.name),
    "tool"
  );
  assertUnique(
    registry.resourceTemplates.map((entry) => entry.uriTemplate),
    "resource template"
  );
  assertUnique(
    registry.prompts.map((entry) => entry.name),
    "prompt"
  );
  assertUnique(
    registry.events.map((entry) => entry.name),
    "event"
  );
  assertUnique(
    registry.cli.flatMap((entry) => entry.commands),
    "CLI command"
  );

  assertSequential(
    registry.securityRequirements.map((entry) => entry.id),
    "SR",
    3
  );
  assertSequential(
    registry.threats.map((entry) => entry.id),
    "TH",
    2
  );
  assertSequential(
    registry.acceptanceScenarios.map((entry) => entry.id),
    "AC",
    2
  );
  registry.verificationTiers.forEach((entry, index) => {
    if (entry.id !== `T${String(index)}`) {
      throw new Error(`tier sequence drift: expected T${String(index)}, got ${entry.id}`);
    }
  });

  return registry;
}

export function registryDigest(registry: RegistrySource): string {
  return canonicalSha256(registry);
}
