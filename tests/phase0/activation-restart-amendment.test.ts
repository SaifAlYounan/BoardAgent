import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildFrozenRegistry } from "../../scripts/src/generate-registry.js";
import { composeAuthorityAmendment } from "../../scripts/src/compose-authority-amendment.js";
import { composeOperationalAmendment } from "../../scripts/src/compose-operational-amendment.js";
import { composeOnboardingAmendment } from "../../scripts/src/compose-onboarding-amendment.js";
import { composeActivationAmendment } from "../../scripts/src/compose-activation-amendment.js";
import { ACTIVATION_RESTART_AMENDMENT } from "../../lib/contracts/src/registry/amendment.js";
const root = path.resolve(import.meta.dirname, "../..");
const parent = () =>
  buildFrozenRegistry(root)
    .then((base) => composeAuthorityAmendment(root, base))
    .then((base) => composeOperationalAmendment(root, base))
    .then((base) => composeOnboardingAmendment(root, base));
describe("activation restart preserves earlier authority and pins the approved proposal", () => {
  it("adds only the one confirmed tool and its two events without changing earlier records", async () => {
    const before = await parent();
    const after = await composeActivationAmendment(root, before);
    expect(before.tools).toHaveLength(153);
    expect(after.tools.slice(0, 153)).toEqual(before.tools);
    expect(after.tools.slice(153).map((t) => [t.name, t.class])).toEqual([
      ["reissue_activation", "H"]
    ]);
    expect(after.events.slice(0, before.events.length)).toEqual(before.events);
    expect(after.events.slice(before.events.length).map((event) => event.name)).toEqual([
      "activation_restart_issued",
      "activation_restart_completed"
    ]);
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
    await expect(composeActivationAmendment(root, after)).rejects.toThrow(/already amended/u);
  });
  it("requires its onboarding parent", async () => {
    const withoutOnboarding = await buildFrozenRegistry(root)
      .then((base) => composeAuthorityAmendment(root, base))
      .then((base) => composeOperationalAmendment(root, base));
    await expect(composeActivationAmendment(root, withoutOnboarding)).rejects.toThrow(
      /parent registry digest mismatch/u
    );
  });
  it.each(["document", "instruction"] as const)(
    "rejects altered %s bytes without accepting a substitute authority",
    async (target) => {
      const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-activation-contract-"));
      try {
        for (const relative of [
          ACTIVATION_RESTART_AMENDMENT.path,
          ACTIVATION_RESTART_AMENDMENT.instructionPath
        ]) {
          const file = path.join(directory, relative);
          await mkdir(path.dirname(file), { recursive: true });
          await writeFile(file, await readFile(path.join(root, relative)));
        }
        const chosen = path.join(
          directory,
          target === "document"
            ? ACTIVATION_RESTART_AMENDMENT.path
            : ACTIVATION_RESTART_AMENDMENT.instructionPath
        );
        await writeFile(chosen, (await readFile(chosen, "utf8")) + "\n");
        await expect(composeActivationAmendment(directory, await parent())).rejects.toThrow(
          /hash drift/u
        );
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  );
});
