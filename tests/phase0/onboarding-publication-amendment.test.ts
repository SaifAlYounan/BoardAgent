import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildFrozenRegistry } from "../../scripts/src/generate-registry.js";
import { composeAuthorityAmendment } from "../../scripts/src/compose-authority-amendment.js";
import { composeOperationalAmendment } from "../../scripts/src/compose-operational-amendment.js";
import { composeOnboardingAmendment } from "../../scripts/src/compose-onboarding-amendment.js";
import { ONBOARDING_AMENDMENT } from "../../lib/contracts/src/registry/amendment.js";
const root = path.resolve(import.meta.dirname, "../..");
const parent = () =>
  buildFrozenRegistry(root)
    .then((base) => composeAuthorityAmendment(root, base))
    .then((base) => composeOperationalAmendment(root, base));
describe("onboarding publication preserves earlier authority and pins the additive decision", () => {
  it("adds only the two confirmed tools and their events without changing earlier role or requirement records", async () => {
    const before = await parent();
    const after = await composeOnboardingAmendment(root, before);
    expect(before.tools).toHaveLength(151);
    expect(after.tools.slice(0, 151)).toEqual(before.tools);
    expect(after.tools.slice(151).map((t) => [t.name, t.class])).toEqual([
      ["publish_secretary_support", "H"],
      ["publish_onboarding_terms", "H"]
    ]);
    expect(after.events.slice(0, before.events.length)).toEqual(before.events);
    for (const key of [
      "resourceTemplates",
      "prompts",
      "httpAuthorityFamilies",
      "cli",
      "securityRequirements",
      "threats",
      "acceptanceScenarios",
      "verificationTiers"
    ] as const)
      expect(after[key]).toEqual(before[key]);
    await expect(composeOnboardingAmendment(root, after)).rejects.toThrow(/already amended/u);
  });
  it.each(["document", "instruction"] as const)(
    "rejects altered %s bytes without accepting a substitute authority",
    async (target) => {
      const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-onboarding-contract-"));
      try {
        for (const relative of [ONBOARDING_AMENDMENT.path, ONBOARDING_AMENDMENT.instructionPath]) {
          const file = path.join(directory, relative);
          await mkdir(path.dirname(file), { recursive: true });
          await writeFile(file, await readFile(path.join(root, relative)));
        }
        const chosen = path.join(
          directory,
          target === "document" ? ONBOARDING_AMENDMENT.path : ONBOARDING_AMENDMENT.instructionPath
        );
        await writeFile(chosen, (await readFile(chosen, "utf8")) + "\n");
        await expect(composeOnboardingAmendment(directory, await parent())).rejects.toThrow(
          /hash drift/u
        );
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  );
});
