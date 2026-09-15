import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

import {
  ADMINISTRATIVE_REGISTRY_COUNTS,
  ADMINISTRATIVE_AMENDMENT,
  RegistrySourceSchema,
  ToolRegistryEntrySchema,
  assertRegistryInvariants,
  type RegistrySource
} from "../../lib/contracts/src/registry/schema.js";

const AdditionsSchema = RegistrySourceSchema.pick({
  tools: true,
  events: true,
  securityRequirements: true,
  threats: true,
  acceptanceScenarios: true
});
// The complete document (including non-registry contracts) is verified byte-for-byte
// before parsing. Only these typed projections can affect generated registry rows.
const ProjectionSchema = z.object({
  id: z.literal(ADMINISTRATIVE_AMENDMENT.id),
  base: RegistrySourceSchema.shape.sources.omit({
    amendment: true,
    operationalAmendment: true,
    onboardingAmendment: true,
    activationRestartAmendment: true
  }),
  add: AdditionsSchema,
  modifyTools: z.array(ToolRegistryEntrySchema.omit({ class: true, section: true })).length(1),
  expectedCounts: z
    .object(
      Object.fromEntries(
        Object.entries(ADMINISTRATIVE_REGISTRY_COUNTS).map(([key, value]) => [
          key,
          z.literal(value)
        ])
      )
    )
    .strict()
});

async function readPinned(root: string, relative: string, expected: string, label: string) {
  const bytes = await readFile(path.join(root, relative));
  if (createHash("sha256").update(bytes).digest("hex") !== expected) {
    throw new Error(`${label} hash drift: ${relative}`);
  }
  return bytes.toString("utf8");
}

export async function composeAuthorityAmendment(root: string, base: RegistrySource) {
  if (base.sources.amendment !== undefined) throw new Error("base is already amended");
  assertRegistryInvariants(base);
  const pin = ADMINISTRATIVE_AMENDMENT;
  const [document] = await Promise.all([
    readPinned(root, pin.path, pin.sha256, "amendment"),
    readPinned(root, pin.authorizationPath, pin.authorizationSha256, "authorization instruction")
  ]);
  const amendment = ProjectionSchema.parse(JSON.parse(document));
  if (JSON.stringify(amendment.base) !== JSON.stringify(base.sources)) {
    throw new Error("amendment base matrix path/hash mismatch");
  }
  const modification = amendment.modifyTools[0]!;
  if (
    modification.name !== "manage_member" ||
    base.tools.filter(({ name }) => name === modification.name).length !== 1
  ) {
    throw new Error("unexpected original tool modification");
  }
  return assertRegistryInvariants({
    ...base,
    sources: {
      ...base.sources,
      amendment: {
        id: pin.id,
        path: pin.path,
        sha256: pin.sha256,
        authorizationPath: pin.authorizationPath,
        authorizationSha256: pin.authorizationSha256
      }
    },
    tools: [
      ...base.tools.map((tool) =>
        tool.name === modification.name ? { ...tool, ...modification } : tool
      ),
      ...amendment.add.tools
    ],
    events: [...base.events, ...amendment.add.events],
    securityRequirements: [...base.securityRequirements, ...amendment.add.securityRequirements],
    threats: [...base.threats, ...amendment.add.threats],
    acceptanceScenarios: [...base.acceptanceScenarios, ...amendment.add.acceptanceScenarios]
  });
}
