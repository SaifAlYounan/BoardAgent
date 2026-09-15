import { createHash } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";

import { describe, expect, it } from "vitest";

const ROOT = new URL("../../", import.meta.url);

async function source(relative: string): Promise<string> {
  return readFile(new URL(relative, ROOT), "utf8");
}

describe("Phase 0 documentation and provenance closure", () => {
  it("ships the required product, operator, security, agent, and architecture documentation", async () => {
    const required = [
      "README.md",
      "DEPLOY.md",
      "SECURITY.md",
      "LICENSE",
      "docs/AGENT_GUIDE.md",
      "docs/MANUAL.md",
      "docs/HARVEST_REPORT.md",
      "docs/KNOWN_LIMITATIONS.md",
      "docs/SURFACE_REFERENCE.md",
      "docs/THREAT_MODEL.md",
      "docs/VERIFICATION.md",
      "docs/adr/README.md",
      "docs/runbooks/README.md"
    ];
    const documents = await Promise.all(required.map(source));

    expect(documents.every((document) => document.trim().length > 100)).toBe(true);
    expect(documents[0]).toContain("private hardened beta");
    expect(documents[1]).toContain("Gate 3");
    expect(documents[2]).toContain("Independent external review (T10)");
  });

  it("publishes the complete generated surface inventory from the frozen registry", async () => {
    const [reference, manifestText] = await Promise.all([
      source("docs/SURFACE_REFERENCE.md"),
      source("lib/contracts/src/generated/registry.manifest.json")
    ]);
    const manifest = JSON.parse(manifestText) as {
      registryDigest: string;
      registry: {
        tools: readonly { name: string }[];
        resourceTemplates: readonly { uriTemplate: string }[];
        prompts: readonly { name: string }[];
        httpAuthorityFamilies: readonly { surface: string }[];
        cli: readonly { commands: readonly string[] }[];
        events: readonly { name: string }[];
      };
    };

    expect(reference).toContain(`Registry digest: \`${manifest.registryDigest}\``);
    for (const tool of manifest.registry.tools) expect(reference).toContain(`\`${tool.name}\``);
    for (const resource of manifest.registry.resourceTemplates)
      expect(reference).toContain(`\`${resource.uriTemplate}\``);
    for (const prompt of manifest.registry.prompts)
      expect(reference).toContain(`\`${prompt.name}\``);
    for (const entry of manifest.registry.httpAuthorityFamilies)
      expect(reference).toContain(entry.surface);
    for (const entry of manifest.registry.cli)
      for (const command of entry.commands) expect(reference).toContain(`\`${command}\``);
    for (const event of manifest.registry.events) expect(reference).toContain(`\`${event.name}\``);
  });

  it("keeps release-document links local-resolvable and free of unfinished placeholders", async () => {
    const nested = (await readdir(new URL("docs/", ROOT), { recursive: true }))
      .map(String)
      .filter((file) => file.endsWith(".md"))
      .map((file) => `docs/${file}`);
    const documents = ["README.md", "DEPLOY.md", "SECURITY.md", ...nested].toSorted();

    for (const relative of documents) {
      const content = await source(relative);
      // Dated execution snapshots preserve what the builder actually observed on that
      // machine. They are historical evidence, not current release instructions.
      const historicalExecutionRecord =
        /^docs\/execution\/history\/SESSION-through-\d{8}T\d{4}\.md$/u.test(relative);
      if (!historicalExecutionRecord) {
        expect(/\b(?:TODO|TBD|FIXME|coming soon)\b/iu.test(content), relative).toBe(false);
        expect(content.includes("/Users/"), relative).toBe(false);
      }
      for (const match of content.matchAll(/\[[^\]]*\]\(([^)]+)\)/gu)) {
        const target = match[1]!;
        if (/^(?:https?:|mailto:|#)/u.test(target)) continue;
        const fileTarget = target.split("#", 1)[0]!;
        if (fileTarget.length === 0) continue;
        await expect(access(new URL(fileTarget, new URL(relative, ROOT)))).resolves.toBeUndefined();
      }
    }
  });

  it("keeps shared canonical state separate from agent-owned derived memory", async () => {
    const decision = "docs/adr/0005-agent-owned-derived-memory.md";
    const [adr, readme, security, agentGuide] = await Promise.all([
      source(decision),
      source("README.md"),
      source("SECURITY.md"),
      source("docs/AGENT_GUIDE.md")
    ]);

    expect(adr).toContain("BoardAgent has no Open Brain");
    expect(adr).toContain("never accepted by BoardAgent as identity, authority, evidence, consent");
    expect(adr).toContain("management");
    expect(adr).toContain("recusal");
    expect(readme).toContain("docs/adr/0005-agent-owned-derived-memory.md");
    expect(security).toContain("docs/adr/0005-agent-owned-derived-memory.md");
    expect(agentGuide).toContain("adr/0005-agent-owned-derived-memory.md");
  });

  it("ships exactly 33 indexed runbooks with owner, purpose, evidence, and record expectations", async () => {
    const files = (await readdir(new URL("docs/runbooks/", ROOT)))
      .filter((file) => /^\d{2}-[a-z0-9-]+\.md$/u.test(file))
      .toSorted();
    expect(files).toHaveLength(33);
    expect(files.map((file) => file.slice(0, 2))).toEqual(
      Array.from({ length: 33 }, (_, index) => String(index + 1).padStart(2, "0"))
    );

    const index = await source("docs/runbooks/README.md");
    for (const file of files) {
      expect(index).toContain(`](${file})`);
      const runbook = await source(`docs/runbooks/${file}`);
      expect(runbook).toMatch(/\*\*Owners?:\*\*/u);
      expect(runbook).toMatch(/\*\*Purpose:\*\*/u);
      expect(runbook).toMatch(/evidence/iu);
      expect(runbook).toMatch(/\bRecord\b/u);
    }
  });

  it("maps every frozen Gate-2 decision into the ADR set", async () => {
    const files = (await readdir(new URL("docs/adr/", ROOT))).filter((file) =>
      /^\d{4}-[a-z0-9-]+\.md$/u.test(file)
    );
    const authorities = (
      await Promise.all(files.map((file) => source(`docs/adr/${file}`)))
    ).flatMap((document) => document.match(/^- Authority: .*$/gmu) ?? []);
    const covered = new Set<number>();

    for (const authority of authorities) {
      for (const match of authority.matchAll(/D2-(\d{3}) through D2-(\d{3})/gu)) {
        const first = Number(match[1]);
        const last = Number(match[2]);
        for (let value = first; value <= last; value += 1) covered.add(value);
      }
      for (const match of authority.matchAll(/D2-(\d{3})/gu)) covered.add(Number(match[1]));
    }

    expect([...covered].toSorted((left, right) => left - right)).toEqual(
      Array.from({ length: 69 }, (_, index) => index + 1)
    );
  });

  it("preserves all 94 frozen closures and maps the exact eight additive requirements", async () => {
    const rows = (await source("docs/VERIFICATION.md"))
      .split(/\r?\n/u)
      .filter((line) => /^\| SR-\d{3} \|/u.test(line));
    expect(rows).toHaveLength(102);

    // The approved extension must not weaken any original closure.
    rows.slice(0, 94).forEach((row, index) => {
      const cells = row
        .slice(1, -1)
        .split("|")
        .map((cell) => cell.trim());
      expect(cells).toHaveLength(5);
      expect(cells[0]).toBe(`SR-${String(index + 1).padStart(3, "0")}`);
      expect(cells[2]).toContain("`");
      expect(cells[3]).toContain("`tests/");
      expect(cells[4]).toBe("PROVEN");
    });
    rows.slice(94).forEach((row, index) => {
      const cells = row
        .slice(1, -1)
        .split("|")
        .map((cell) => cell.trim());
      expect(cells).toHaveLength(5);
      expect(cells[0]).toBe(`SR-${String(index + 95).padStart(3, "0")}`);
      expect(cells[2]).toMatch(/`(?:artifacts|lib|scripts)\/[^`]+`/u);
      expect(cells[3]).toContain("`tests/");
      if (cells[0] === "SR-102") {
        // Actual human enrollment is not manufactured by these automated tests.
        // The register must retain its honest evidence status separately.
        expect(["PROVEN", "UNRESOLVED"]).toContain(cells[4]);
      } else expect(cells[4]).toBe("PROVEN");
    });
  });

  it("maps every frozen threat to actor/assets, attack, control, proof, and residual risk", async () => {
    const rows = (await source("docs/THREAT_MODEL.md"))
      .split(/\r?\n/u)
      .filter((line) => /^\| TH-\d{2} \|/u.test(line));

    expect(rows).toHaveLength(71);
    rows.forEach((row, index) => {
      const cells = row
        .slice(1, -1)
        .split("|")
        .map((cell) => cell.trim());
      expect(cells).toHaveLength(6);
      expect(cells[0]).toBe(`TH-${String(index + 1).padStart(2, "0")}`);
      expect(cells.slice(1).every((cell) => cell.length > 0)).toBe(true);
      expect(cells[4]).toMatch(/^`tests\//u);
    });
  });

  it("records a bounded verdict for every hostile-harvest candidate and imports none as-is", async () => {
    const report = await source("docs/HARVEST_REPORT.md");
    const candidateSection = report
      .split("## Candidate-by-candidate hostile verdicts\n")[1]
      ?.split("\n## Explicitly rejected shell and feature areas")[0];
    expect(candidateSection).toBeDefined();

    const rows = candidateSection!
      .split(/\r?\n/u)
      .filter((line) => /^\| (?!-)/u.test(line))
      .slice(1);
    expect(rows).toHaveLength(12);
    for (const row of rows) {
      expect(row).toMatch(/\*\*(?:Adapted|Rewritten|Rejected)\*\*/u);
      expect(row).not.toMatch(/\*\*Taken as-is\*\*/u);
    }
    expect(report).toContain("The count for this verdict is **zero**");
  });

  it("records the exact Phase 0 toolchain and lockfile receipt", async () => {
    const receipt = JSON.parse(await source("artifacts/provenance/toolchain.json")) as {
      schemaVersion: number;
      node: { version: string; executableSha256: string };
      pnpm: { version: string; packageManager: string };
      lockfileSha256: string;
    };
    const lockfile = await source("pnpm-lock.yaml");

    expect(receipt).toMatchObject({
      schemaVersion: 1,
      node: { version: "24.20.0" },
      pnpm: { version: "11.24.0", packageManager: "pnpm@11.24.0" }
    });
    expect(receipt.node.executableSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(receipt.lockfileSha256).toBe(createHash("sha256").update(lockfile).digest("hex"));
  });

  it("retains hostile-change provenance on every currently adapted source", async () => {
    const adapted = [
      "lib/db/src/migrate.ts",
      "lib/domain/src/value-objects.ts",
      "lib/domain/src/voting.ts",
      "tests/unit/voting.test.ts"
    ];

    for (const relative of adapted) {
      const content = await source(relative);
      expect(content).toContain("Adapted from LQGovernance-OpenBoard");
      expect(content).toContain("1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb");
      expect(content).toContain("Copyright (c) 2026 Alexios Kirillov");
      expect(content).toContain("MIT License");
      expect(content).toContain("Hostile changes:");
    }
  });
});
