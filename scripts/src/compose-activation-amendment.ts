import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  ACTIVATION_RESTART_AMENDMENT,
  ACTIVE_REGISTRY_COUNTS,
  RegistrySourceSchema,
  assertRegistryInvariants,
  registryDigest,
  type RegistrySource
} from "../../lib/contracts/src/registry/schema.js";

const ProjectionSchema = z.object({
  schemaVersion: z.literal("boardagent.activation-restart-amendment.v1"),
  id: z.literal(ACTIVATION_RESTART_AMENDMENT.id),
  status: z.literal("approved"),
  parentRegistryDigest: z.literal(ACTIVATION_RESTART_AMENDMENT.parentRegistryDigest),
  basis: z
    .object({
      path: z.literal(ACTIVATION_RESTART_AMENDMENT.instructionPath),
      sha256: z.literal(ACTIVATION_RESTART_AMENDMENT.instructionSha256),
      interpretation: z.string().min(1)
    })
    .strict(),
  add: RegistrySourceSchema.pick({ tools: true, events: true }),
  expectedCounts: z
    .object(
      Object.fromEntries(
        Object.entries(ACTIVE_REGISTRY_COUNTS).map(([key, value]) => [key, z.literal(value)])
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

/**
 * Whole-document pins protect the approved proposal prose as well as this closed, typed
 * registry projection: one human-confirmed tool and two events, nothing else.
 */
export async function composeActivationAmendment(root: string, input: RegistrySource) {
  const base = assertRegistryInvariants(input);
  if (base.sources.activationRestartAmendment !== undefined)
    throw new Error("activation restart base is already amended");
  const pin = ACTIVATION_RESTART_AMENDMENT;
  if (registryDigest(base) !== pin.parentRegistryDigest)
    throw new Error("activation restart amendment parent registry digest mismatch");
  const [document] = await Promise.all([
    readPinned(root, pin.path, pin.sha256, "activation restart amendment"),
    readPinned(root, pin.instructionPath, pin.instructionSha256, "approved proposal")
  ]);
  const amendment = ProjectionSchema.parse(JSON.parse(document));
  return assertRegistryInvariants({
    ...base,
    sources: { ...base.sources, activationRestartAmendment: pin },
    tools: [...base.tools, ...amendment.add.tools],
    events: [...base.events, ...amendment.add.events]
  });
}
