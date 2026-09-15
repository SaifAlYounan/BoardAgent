import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  OPERATIONAL_REGISTRY_COUNTS,
  OPERATIONAL_AMENDMENT,
  RegistrySourceSchema,
  assertRegistryInvariants,
  registryDigest,
  type RegistrySource
} from "../../lib/contracts/src/registry/schema.js";

const ProjectionSchema = z.object({
  schemaVersion: z.literal("boardagent.operational-maintenance-amendment.v1"),
  id: z.literal(OPERATIONAL_AMENDMENT.id),
  parentRegistryDigest: z.literal(OPERATIONAL_AMENDMENT.parentRegistryDigest),
  basis: z
    .object({
      path: z.literal(OPERATIONAL_AMENDMENT.instructionPath),
      sha256: z.literal(OPERATIONAL_AMENDMENT.instructionSha256),
      interpretation: z.string().min(1)
    })
    .strict(),
  add: RegistrySourceSchema.pick({ cli: true, events: true }),
  expectedCounts: z
    .object(
      Object.fromEntries(
        Object.entries(OPERATIONAL_REGISTRY_COUNTS).map(([key, value]) => [key, z.literal(value)])
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
export async function composeOperationalAmendment(root: string, input: RegistrySource) {
  const base = assertRegistryInvariants(input);
  if (base.sources.operationalAmendment !== undefined)
    throw new Error("operational base is already amended");
  const pin = OPERATIONAL_AMENDMENT;
  if (registryDigest(base) !== pin.parentRegistryDigest)
    throw new Error("operational amendment parent registry digest mismatch");
  const [document] = await Promise.all([
    readPinned(root, pin.path, pin.sha256, "operational amendment"),
    readPinned(root, pin.instructionPath, pin.instructionSha256, "completion instruction")
  ]);
  const amendment = ProjectionSchema.parse(JSON.parse(document));
  return assertRegistryInvariants({
    ...base,
    sources: { ...base.sources, operationalAmendment: pin },
    cli: [...base.cli, ...amendment.add.cli],
    events: [...base.events, ...amendment.add.events]
  });
}
