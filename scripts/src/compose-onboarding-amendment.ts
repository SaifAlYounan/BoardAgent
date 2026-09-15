import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  ONBOARDING_AMENDMENT,
  ONBOARDING_REGISTRY_COUNTS,
  RegistrySourceSchema,
  assertRegistryInvariants,
  registryDigest,
  type RegistrySource
} from "../../lib/contracts/src/registry/schema.js";

const ProjectionSchema = z.object({
  schemaVersion: z.literal("boardagent.onboarding-publication-amendment.v1"),
  id: z.literal(ONBOARDING_AMENDMENT.id),
  parentRegistryDigest: z.literal(ONBOARDING_AMENDMENT.parentRegistryDigest),
  basis: z
    .object({
      path: z.literal(ONBOARDING_AMENDMENT.instructionPath),
      sha256: z.literal(ONBOARDING_AMENDMENT.instructionSha256),
      interpretation: z.string().min(1)
    })
    .strict(),
  add: RegistrySourceSchema.pick({ tools: true, events: true }),
  expectedCounts: z
    .object(
      Object.fromEntries(
        Object.entries(ONBOARDING_REGISTRY_COUNTS).map(([key, value]) => [key, z.literal(value)])
      )
    )
    .strict()
});

async function readPinned(root: string, relative: string, digest: string, label: string) {
  const bytes = await readFile(path.join(root, relative));
  if (createHash("sha256").update(bytes).digest("hex") !== digest)
    throw new Error(`${label} hash drift: ${relative}`);
  return bytes.toString("utf8");
}

/** Whole-document pins protect prose as well as this closed, typed registry projection. */
export async function composeOnboardingAmendment(root: string, input: RegistrySource) {
  const base = assertRegistryInvariants(input);
  if (base.sources.onboardingAmendment !== undefined)
    throw new Error("onboarding base is already amended");
  const pin = ONBOARDING_AMENDMENT;
  if (registryDigest(base) !== pin.parentRegistryDigest)
    throw new Error("onboarding amendment parent registry digest mismatch");
  const [document] = await Promise.all([
    readPinned(root, pin.path, pin.sha256, "onboarding amendment"),
    readPinned(root, pin.instructionPath, pin.instructionSha256, "completion instruction")
  ]);
  const amendment = ProjectionSchema.parse(JSON.parse(document));
  return assertRegistryInvariants({
    ...base,
    sources: { ...base.sources, onboardingAmendment: pin },
    tools: [...base.tools, ...amendment.add.tools],
    events: [...base.events, ...amendment.add.events]
  });
}
