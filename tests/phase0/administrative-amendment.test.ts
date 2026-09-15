import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";
import { buildFrozenRegistry } from "../../scripts/src/generate-registry.js";

import { composeAuthorityAmendment } from "../../scripts/src/compose-authority-amendment.js";

async function buildRegistry(root: string) {
  return { registry: await composeAuthorityAmendment(root, await buildFrozenRegistry(root)) };
}

const ROOT = path.resolve(import.meta.dirname, "../..");
const AMENDMENT = "docs/decisions/access-control-amendment-v1.json";
const AUTHORIZATION = "docs/decisions/access-control-implementation-authorization.md";
const SURFACE = "planning/gate2/gate2/SURFACE-AUTHORITY-EVENT-MATRIX.md";
const VERIFICATION = "planning/gate2/gate2/VERIFICATION-AND-RELEASE-NET.md";

async function withSource(run: (root: string) => Promise<void>) {
  const root = await mkdtemp(path.join(os.tmpdir(), "boardagent-admin-amendment-"));
  try {
    for (const name of [AMENDMENT, AUTHORIZATION, SURFACE, VERIFICATION]) {
      await mkdir(path.dirname(path.join(root, name)), { recursive: true });
      await writeFile(path.join(root, name), await readFile(path.join(ROOT, name)));
    }
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("AC27 additive administrative authority contract", () => {
  it("composes exactly three new tools and preserves the original inventory", async () => {
    const base = await buildFrozenRegistry(ROOT);
    const { registry } = await buildRegistry(ROOT);
    expect(base.tools).toHaveLength(148);
    for (const tool of base.tools) {
      const current = registry.tools.find(({ name }) => name === tool.name);
      if (tool.name !== "manage_member") expect(current).toEqual(tool);
      else
        expect(current).toMatchObject({
          name: tool.name,
          class: tool.class,
          section: tool.section
        });
    }
    expect(registry.events.slice(0, 128)).toEqual(base.events);
    expect(registry.securityRequirements.slice(0, 94)).toEqual(base.securityRequirements);
    expect(registry.threats.slice(0, 63)).toEqual(base.threats);
    expect(registry.acceptanceScenarios.slice(0, 22)).toEqual(base.acceptanceScenarios);
    for (const key of ["resourceTemplates", "prompts", "httpAuthorityFamilies", "cli"] as const) {
      expect(registry[key]).toEqual(base[key]);
    }
    expect(registry.tools).toHaveLength(151);
    expect(registry.tools.filter(({ class: kind }) => kind === "R")).toHaveLength(58);
    expect(registry.tools.filter(({ class: kind }) => kind === "H")).toHaveLength(63);
    expect(registry.tools.filter(({ class: kind }) => kind === "D")).toHaveLength(30);
    expect(
      registry.tools.filter(({ name }) => name.startsWith("manage_company_admin"))
    ).toHaveLength(1);
    expect(registry.tools.some(({ name }) => name === "manage_member_admin_delegation")).toBe(true);
    expect(registry.tools.some(({ name }) => name === "list_administrative_access")).toBe(true);
    expect(registry.events).toHaveLength(136);
    expect(registry.securityRequirements.at(-1)?.id).toBe("SR-102");
    expect(registry.threats.at(-1)?.id).toBe("TH-71");
    expect(registry.acceptanceScenarios.at(-1)?.id).toBe("AC-25");
  });

  it("rejects a missing amendment rather than silently returning the older authority", async () => {
    await withSource(async (root) => {
      await rm(path.join(root, AMENDMENT));
      await expect(buildRegistry(root)).rejects.toThrow();
    });
  });

  it("rejects altered amendment bytes even when the JSON still parses", async () => {
    await withSource(async (root) => {
      const file = path.join(root, AMENDMENT);
      await writeFile(file, `${await readFile(file, "utf8")}\n`);
      await expect(buildRegistry(root)).rejects.toThrow(/amendment|digest|hash/u);
    });
  });

  it("rejects changed original surface bytes without replacing the original hash", async () => {
    await withSource(async (root) => {
      const file = path.join(root, SURFACE);
      await writeFile(file, `${await readFile(file, "utf8")}\n`);
      await expect(buildRegistry(root)).rejects.toThrow(/base|matrix|digest|hash/u);
    });
  });

  it("rejects changed implementation-instruction evidence", async () => {
    await withSource(async (root) => {
      await writeFile(path.join(root, AUTHORIZATION), "An unbound claimed approval.\n");
      await expect(buildRegistry(root)).rejects.toThrow(/authorization|instruction|digest|hash/u);
    });
  });

  it("retains all original tiers and their exact thresholds", async () => {
    const original = await buildFrozenRegistry(ROOT);
    const { registry } = await buildRegistry(ROOT);
    expect(registry.verificationTiers).toEqual(original.verificationTiers);
  });
});
