import { describe, expect, it } from "vitest";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { buildFrozenRegistry } from "../../scripts/src/generate-registry.js";
import { composeAuthorityAmendment } from "../../scripts/src/compose-authority-amendment.js";
import { composeOperationalAmendment } from "../../scripts/src/compose-operational-amendment.js";
import {
  OPERATIONAL_AMENDMENT,
  assertRegistryInvariants
} from "../../lib/contracts/src/registry/schema.js";

const ROOT = path.resolve(import.meta.dirname, "../..");

// This contract belongs to the operational layer, before later additive amendments.
async function buildRegistry(root: string) {
  return {
    registry: await composeOperationalAmendment(
      root,
      await composeAuthorityAmendment(root, await buildFrozenRegistry(root))
    )
  };
}

async function withSource(run: (root: string) => Promise<void>) {
  const root = await mkdtemp(path.join(os.tmpdir(), "boardagent-operational-amendment-"));
  try {
    for (const relative of [
      OPERATIONAL_AMENDMENT.path,
      OPERATIONAL_AMENDMENT.instructionPath,
      "docs/decisions/access-control-amendment-v1.json",
      "docs/decisions/access-control-implementation-authorization.md",
      "planning/gate2/gate2/SURFACE-AUTHORITY-EVENT-MATRIX.md",
      "planning/gate2/gate2/VERIFICATION-AND-RELEASE-NET.md"
    ]) {
      await mkdir(path.dirname(path.join(root, relative)), { recursive: true });
      await writeFile(path.join(root, relative), await readFile(path.join(ROOT, relative)));
    }
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("operator key lifecycle additive contract", () => {
  it("adds the key family/event and existing recovery family, preserving all existing authority and thresholds", async () => {
    const previous = await composeAuthorityAmendment(ROOT, await buildFrozenRegistry(ROOT));
    const { registry } = await buildRegistry(ROOT);
    expect(registry.events).toHaveLength(previous.events.length + 1);
    expect(registry.events.slice(0, -1)).toEqual(previous.events);
    expect(registry.events.at(-1)?.name).toBe("key_lifecycle_changed");
    expect(registry.cli).toHaveLength(previous.cli.length + 2);
    expect(registry.cli.slice(0, -2)).toEqual(previous.cli);
    expect(registry.cli.at(-2)?.commands).toEqual(["audit-recovery"]);
    expect(registry.cli.at(-1)?.commands).toEqual(["key-lifecycle"]);
    for (const key of [
      "tools",
      "resourceTemplates",
      "prompts",
      "httpAuthorityFamilies",
      "securityRequirements",
      "threats",
      "acceptanceScenarios",
      "verificationTiers"
    ] as const) {
      expect(registry[key]).toEqual(previous[key]);
    }
  });

  it.each([OPERATIONAL_AMENDMENT.path, OPERATIONAL_AMENDMENT.instructionPath])(
    "refuses missing or altered actual source bytes: %s",
    async (relative) => {
      await withSource(async (root) => {
        const file = path.join(root, relative);
        const original = await readFile(file);
        await rm(file);
        await expect(buildRegistry(root)).rejects.toThrow();
        await writeFile(file, Buffer.concat([original, Buffer.from("\n")]));
        await expect(buildRegistry(root)).rejects.toThrow(/hash drift/u);
      });
    }
  );

  it("refuses a modified parent even if its declared counts and pins still match", async () => {
    const previous = await composeAuthorityAmendment(ROOT, await buildFrozenRegistry(ROOT));
    const changed = structuredClone(previous);
    changed.cli[0]!.authorityPath = "Claimed unrestricted operator authority";
    expect(() => assertRegistryInvariants(changed)).not.toThrow();
    await expect(composeOperationalAmendment(ROOT, changed)).rejects.toThrow(
      /parent registry digest/u
    );
    await expect(
      composeOperationalAmendment(ROOT, await buildFrozenRegistry(ROOT))
    ).rejects.toThrow(/parent registry digest/u);
  });

  it("refuses repeated composition and detached or altered operational pins", async () => {
    const { registry } = await buildRegistry(ROOT);
    await expect(composeOperationalAmendment(ROOT, registry)).rejects.toThrow(/already amended/u);
    const detached = structuredClone(registry);
    delete detached.sources.amendment;
    expect(() => assertRegistryInvariants(detached)).toThrow(/requires its administrative parent/u);
    expect(() =>
      assertRegistryInvariants({
        ...registry,
        sources: {
          ...registry.sources,
          operationalAmendment: { ...OPERATIONAL_AMENDMENT, instructionSha256: "0".repeat(64) }
        }
      })
    ).toThrow();
  });
});
