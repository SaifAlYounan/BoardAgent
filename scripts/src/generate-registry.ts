import { composeActivationAmendment } from "./compose-activation-amendment.js";
import { composeOnboardingAmendment } from "./compose-onboarding-amendment.js";
import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { format } from "prettier";

import {
  assertRegistryInvariants,
  ACTIVE_REGISTRY_COUNTS,
  FROZEN_REGISTRY_COUNTS,
  registryDigest,
  type RegistrySource
} from "../../lib/contracts/src/registry/schema.js";
import { composeOperationalAmendment } from "./compose-operational-amendment.js";
import { composeAuthorityAmendment } from "./compose-authority-amendment.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SURFACE_MATRIX = "planning/gate2/gate2/SURFACE-AUTHORITY-EVENT-MATRIX.md";
const VERIFICATION_MATRIX = "planning/gate2/gate2/VERIFICATION-AND-RELEASE-NET.md";
const FORMAT_OPTIONS = {
  printWidth: 100,
  semi: true,
  singleQuote: false,
  trailingComma: "none" as const
};

interface MarkdownTableRow {
  readonly cells: readonly string[];
  readonly section: string;
}

export interface GeneratedArtifact {
  readonly relativePath: string;
  readonly content: string;
}

export interface RegistryBuild {
  readonly registry: RegistrySource;
  readonly digest: string;
  readonly artifacts: readonly GeneratedArtifact[];
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function normalizeCell(value: string): string {
  return value.trim().replace(/\s+/gu, " ");
}

function stripCode(value: string): string {
  const match = /^`([^`]+)`$/u.exec(value.trim());
  if (match?.[1] === undefined) throw new Error(`expected one code literal, got: ${value}`);
  return match[1];
}

function splitTableRow(line: string): readonly string[] {
  const body = line.trim().replace(/^\|/u, "").replace(/\|$/u, "");
  return body.split("|").map(normalizeCell);
}

function rowsWithin(
  markdown: string,
  startHeading: string,
  endHeading: string
): MarkdownTableRow[] {
  const lines = markdown.split(/\r?\n/u);
  let active = false;
  let section = "";
  const rows: MarkdownTableRow[] = [];
  for (const line of lines) {
    if (line === startHeading) {
      active = true;
      continue;
    }
    if (active && line === endHeading) break;
    if (!active) continue;
    if (line.startsWith("### ")) {
      section = line.replace(/^###\s+\d+(?:\.\d+)*\s*/u, "").trim();
      continue;
    }
    if (!line.startsWith("|")) continue;
    const cells = splitTableRow(line);
    if (cells.every((cell) => /^:?-{3,}:?$/u.test(cell))) continue;
    rows.push({ cells, section });
  }
  if (!active) throw new Error(`missing heading: ${startHeading}`);
  return rows;
}

function dataRows(
  markdown: string,
  startHeading: string,
  endHeading: string,
  header: readonly string[],
  width: number
): MarkdownTableRow[] {
  return rowsWithin(markdown, startHeading, endHeading).filter((row) => {
    if (row.cells.length !== width) {
      throw new Error(
        `table width drift under ${startHeading}: expected ${String(width)}, got ${String(row.cells.length)}: ${row.cells.join(" | ")}`
      );
    }
    return !header.every((cell, index) => row.cells[index] === cell);
  });
}

function parseTools(markdown: string): RegistrySource["tools"] {
  return dataRows(
    markdown,
    "## 2. MCP tool registry",
    "## 3. MCP resource templates",
    ["Tool", "Class", "Required authority", "Object rule", "Required evidence/result"],
    5
  ).map(({ cells, section }) => ({
    name: stripCode(cells[0] ?? ""),
    class: cells[1] as "D" | "H" | "R",
    section,
    requiredAuthority: cells[2] ?? "",
    objectRule: cells[3] ?? "",
    requiredEvidence: cells[4] ?? ""
  }));
}

function parseResources(markdown: string): RegistrySource["resourceTemplates"] {
  return dataRows(
    markdown,
    "## 3. MCP resource templates",
    "## 4. MCP prompt registry",
    ["URI template", "Representations", "Entitlement root"],
    3
  ).map(({ cells }) => ({
    uriTemplate: stripCode(cells[0] ?? ""),
    representations: cells[1] ?? "",
    entitlementRoot: cells[2] ?? ""
  }));
}

function parsePrompts(markdown: string): RegistrySource["prompts"] {
  return dataRows(
    markdown,
    "## 4. MCP prompt registry",
    "## 5. Browser/HTTP surface",
    ["Prompt", "Intended flow"],
    2
  ).map(({ cells }) => ({
    name: stripCode(cells[0] ?? ""),
    intendedFlow: cells[1] ?? ""
  }));
}

function parseHttp(markdown: string): RegistrySource["httpAuthorityFamilies"] {
  return dataRows(
    markdown,
    "## 5. Browser/HTTP surface",
    "## 6. CLI registry",
    ["Surface", "Authority and behavior"],
    2
  ).map(({ cells }) => ({
    surface: cells[0] ?? "",
    authorityAndBehavior: cells[1] ?? ""
  }));
}

function parseCli(markdown: string): RegistrySource["cli"] {
  return dataRows(
    markdown,
    "## 6. CLI registry",
    "## 7. Closed event registry",
    ["CLI", "Authority path"],
    2
  ).map(({ cells }) => {
    const commands = [...(cells[0] ?? "").matchAll(/`([a-z][a-z0-9-]*)`/gu)].map(
      (match) => match[1] ?? ""
    );
    if (commands.length === 0) throw new Error(`CLI row has no command: ${cells[0] ?? ""}`);
    return { commands, authorityPath: cells[1] ?? "" };
  });
}

function parseEvents(markdown: string): RegistrySource["events"] {
  const lines = markdown.split(/\r?\n/u);
  let active = false;
  let category = "";
  const events: Array<{ name: string; category: string }> = [];
  for (const line of lines) {
    if (line === "## 7. Closed event registry") {
      active = true;
      continue;
    }
    if (!active) continue;
    if (line.startsWith("### ")) {
      category = line.slice(4).trim();
      continue;
    }
    for (const match of line.matchAll(/`([a-z][a-z0-9_]*)`/gu)) {
      if (category.length === 0) throw new Error(`event without category: ${match[1] ?? ""}`);
      events.push({ name: match[1] ?? "", category });
    }
  }
  return events;
}

function parseSecurityRequirements(markdown: string): RegistrySource["securityRequirements"] {
  return dataRows(
    markdown,
    "## 3. Security-requirement index",
    "## 4. Mandatory adversarial scenarios",
    ["ID", "Requirement"],
    2
  ).map(({ cells }) => ({ id: cells[0] ?? "", requirement: cells[1] ?? "" }));
}

function parseThreats(markdown: string): RegistrySource["threats"] {
  return dataRows(
    markdown,
    "## 4. Mandatory adversarial scenarios",
    "## 5. Acceptance scenarios",
    ["ID", "Attack/scripted scenario", "Expected control", "Planned exact proof"],
    4
  ).map(({ cells }) => ({
    id: cells[0] ?? "",
    scenario: cells[1] ?? "",
    expectedControl: cells[2] ?? "",
    plannedProof: cells[3] ?? ""
  }));
}

function parseAcceptance(markdown: string): RegistrySource["acceptanceScenarios"] {
  return dataRows(
    markdown,
    "## 5. Acceptance scenarios",
    "## 6. Performance and reliability gates",
    ["ID", "End-to-end outcome"],
    2
  ).map(({ cells }) => ({ id: cells[0] ?? "", outcome: cells[1] ?? "" }));
}

function parseTiers(markdown: string): RegistrySource["verificationTiers"] {
  return dataRows(
    markdown,
    "## 2. Frozen scoring tiers",
    "## 3. Security-requirement index",
    ["Tier", "Required target", "Threshold", "Per-category rollback/release rule"],
    4
  ).map(({ cells }) => {
    const match = /^(T(?:10|[0-9]))\s+(.+)$/u.exec(cells[0] ?? "");
    if (match?.[1] === undefined || match[2] === undefined) {
      throw new Error(`invalid tier cell: ${cells[0] ?? ""}`);
    }
    return {
      id: match[1],
      name: match[2],
      requiredTarget: cells[1] ?? "",
      threshold: cells[2] ?? "",
      releaseRule: cells[3] ?? ""
    };
  });
}

function renderDataModule(registry: RegistrySource): string {
  return `/* AUTO-GENERATED by scripts/src/generate-registry.ts. DO NOT EDIT. */\n\nimport type { RegistrySource } from "../registry/schema.js";\n\nexport const registryData: RegistrySource = ${JSON.stringify(registry, null, 2)};\n`;
}

function renderIdsModule(registry: RegistrySource, digest: string): string {
  const arrays = {
    TOOL_IDS: registry.tools.map((entry) => entry.name),
    RESOURCE_TEMPLATE_IDS: registry.resourceTemplates.map((entry) => entry.uriTemplate),
    PROMPT_IDS: registry.prompts.map((entry) => entry.name),
    EVENT_IDS: registry.events.map((entry) => entry.name),
    SECURITY_REQUIREMENT_IDS: registry.securityRequirements.map((entry) => entry.id),
    THREAT_IDS: registry.threats.map((entry) => entry.id),
    ACCEPTANCE_SCENARIO_IDS: registry.acceptanceScenarios.map((entry) => entry.id)
  } as const;
  const lines = [
    "/* AUTO-GENERATED by scripts/src/generate-registry.ts. DO NOT EDIT. */",
    "",
    `export const REGISTRY_DIGEST = ${JSON.stringify(digest)} as const;`,
    `export const REGISTRY_COUNTS = ${JSON.stringify(ACTIVE_REGISTRY_COUNTS, null, 2)} as const;`
  ];
  for (const [name, values] of Object.entries(arrays)) {
    lines.push(`export const ${name} = ${JSON.stringify(values, null, 2)} as const;`);
  }
  return `${lines.join("\n\n")}\n`;
}

function renderNet(registry: RegistrySource, digest: string): string {
  const verificationMode = (id: string): "phase1" | "private-beta" | "release" => {
    const tier = Number(id.slice(1));
    if (tier <= 5) return "phase1";
    if (tier <= 9) return "private-beta";
    return "release";
  };
  const net = {
    schemaVersion: "boardagent.regression-net.v1",
    registryDigest: digest,
    fingerprint: {
      source: [
        "**/*.ts",
        "**/*.mjs",
        "**/*.json",
        "**/*.md",
        "**/*.sql",
        "**/*.yaml",
        "**/*.yml",
        "**/Dockerfile"
      ],
      exclude: [
        "BUILD_LOG.md",
        "artifacts/verification/**",
        "artifacts/sbom/**",
        "artifacts/license-report/**",
        "coverage/**"
      ],
      external: [],
      operator_model: "deterministic-no-llm",
      model_sensitive: false
    },
    llm_policy: "never",
    periodic_audit_days: 30,
    frozenCounts: FROZEN_REGISTRY_COUNTS,
    activeCounts: ACTIVE_REGISTRY_COUNTS,
    authorityAmendment: registry.sources.amendment,
    operationalAmendment: registry.sources.operationalAmendment,
    onboardingAmendment: registry.sources.onboardingAmendment,
    activationRestartAmendment: registry.sources.activationRestartAmendment,
    strengtheningPolicy: {
      mayAddRequirementsOrTests: true,
      mayDeleteFrozenRow: false,
      maySkipRequiredLane: false,
      mayReduceThreshold: false,
      sponsorAmendmentRequiredToWeaken: true
    },
    tiers: registry.verificationTiers.map((tier) => ({
      ...tier,
      kind: "deterministic",
      cmd: [
        "node_modules/.bin/tsx",
        "scripts/src/verify-release.ts",
        verificationMode(tier.id),
        "--tier",
        tier.id
      ]
    })),
    securityRequirements: registry.securityRequirements.map((entry) => entry.id),
    threats: registry.threats.map((entry) => ({ id: entry.id, plannedProof: entry.plannedProof })),
    acceptanceScenarios: registry.acceptanceScenarios.map((entry) => entry.id)
  };
  return `${JSON.stringify(net, null, 2)}\n`;
}

function renderSurfaceReference(registry: RegistrySource, digest: string): string {
  const lines = [
    "# BoardAgent surface reference",
    "",
    "> AUTO-GENERATED inventory from the frozen Gate 2 registry and pinned administrative and operational amendments. Do not edit this file by hand.",
    `> Registry digest: \`${digest}\`.`,
    "",
    "This is the human-readable inventory for BoardAgent's closed MCP, HTTP, CLI and event",
    "surfaces. The generated manifest is the machine authority; live MCP `tools/list`,",
    "`resources/list` and `prompts/list` expose the strict executable schemas and negotiated",
    "profile. Purpose, authority and evidence rules below come from the same frozen source.",
    "",
    "## Reading the inventory",
    "",
    "- **R** is a non-mutating read. SQL authorization, board/object scope, ACL and recusal",
    "  still apply on every request.",
    "- **D** is a direct, nonbinding mutation. It is authorized, idempotent and audited, but",
    "  does not use a fresh human-confirmation ceremony.",
    "- **H** is a binding or security-sensitive mutation. The client must complete the exact",
    "  prepare/present/confirm/act flow with recent authentication. Human approval is required;",
    "  the server cannot establish how the client presented the request or obtained that approval.",
    "- Unknown tools, fields, schema versions, capabilities and authority combinations fail",
    "  closed. Safe errors do not disclose hidden object existence.",
    "",
    "The normative decision and transaction details remain in",
    "[the frozen surface matrix](../planning/gate2/gate2/SURFACE-AUTHORITY-EVENT-MATRIX.md).",
    "Strict input contracts live in `lib/contracts/src/surface-inputs.ts` and related contract",
    "modules; runtime exposure and safe results live in `artifacts/server/src/mcp-surface.ts`,",
    "`artifacts/server/src/surface-read.ts`, and `artifacts/server/src/surface-service.ts`.",
    "",
    "## MCP tools"
  ];

  for (const section of new Set(registry.tools.map((entry) => entry.section))) {
    lines.push("", `### ${section}`, "");
    for (const entry of registry.tools.filter((tool) => tool.section === section)) {
      lines.push(
        `- \`${entry.name}\` — **${entry.class}**. Authority: ${entry.requiredAuthority} Object: ${entry.objectRule} Evidence/result: ${entry.requiredEvidence}`
      );
    }
  }

  lines.push(
    "",
    "## Resource templates",
    "",
    "Resources are stable `board://` representations behind the same authenticated MCP",
    "endpoint. Fetch authorization is recomputed; prepared/completed/interrupted evidence is",
    "honest about server transport and never claims human reading.",
    ""
  );
  for (const entry of registry.resourceTemplates) {
    lines.push(
      `- \`${entry.uriTemplate}\` — representations: ${entry.representations}; entitlement root: ${entry.entitlementRoot}.`
    );
  }

  lines.push("", "## Prompts", "");
  for (const entry of registry.prompts) {
    lines.push(`- \`${entry.name}\` — ${entry.intendedFlow}`);
  }

  lines.push("", "## Browser and HTTP authority families", "");
  for (const entry of registry.httpAuthorityFamilies) {
    lines.push(`- ${entry.surface} — ${entry.authorityAndBehavior}`);
  }

  lines.push("", "## Operator CLI authority", "");
  for (const entry of registry.cli) {
    lines.push(
      `- ${entry.commands.map((commandName) => `\`${commandName}\``).join(" / ")} — ${entry.authorityPath}`
    );
  }

  lines.push(
    "",
    "## Event registry",
    "",
    "Events have strict versioned payloads and are appended inside the transaction that makes",
    "their claim true. An event name is evidence of its defined server-side fact only."
  );
  for (const category of new Set(registry.events.map((entry) => entry.category))) {
    const names = registry.events
      .filter((entry) => entry.category === category)
      .map((entry) => `\`${entry.name}\``)
      .join(", ");
    lines.push("", `### ${category}`, "", names);
  }

  lines.push(
    "",
    "## Discovery, inputs, outputs and retries",
    "",
    "1. Negotiate the exact supported MCP profile and client capability set at the canonical",
    "   `/mcp` resource. Modern calls are sessionless; the bounded legacy profile is read-only.",
    "2. Discover the current tool/resource/prompt schema from the server. Do not reconstruct",
    "   payloads from agent memory or this prose reference.",
    "3. Resolve canonical IDs and versions through entitled reads. Generated text, a resource",
    "   title or a local-memory summary is never an authority token.",
    "4. For an H action, present the entire exact confirmation package to the human and submit",
    "   only the returned stage/nonce with the same authenticated principal, client and origin.",
    "5. Reuse an idempotency key only for the identical canonical request. Conflict, stale",
    "   version, superseded stage and expired/replayed confirmation are terminal until refetch.",
    "6. Retry only safe reads and explicitly retryable transport/job failures. On an ambiguous",
    "   mutation result, refetch canonical state and audit evidence before deciding what happened.",
    "",
    "Content, free-text, count, cursor and error outputs remain subject to the same deny-wins",
    "authorization and recusal rules. Optional webhooks are contentless wake-ups; polling and",
    "canonical refetch remain authoritative. BoardAgent records server handoff, exact consent and",
    "governance state, not comprehension, independent judgment or legal effect.",
    ""
  );
  return `${lines.join("\n")}\n`;
}

export async function buildFrozenRegistry(root = ROOT): Promise<RegistrySource> {
  const [surfaceMarkdown, verificationMarkdown] = await Promise.all([
    readFile(path.join(root, SURFACE_MATRIX), "utf8"),
    readFile(path.join(root, VERIFICATION_MATRIX), "utf8")
  ]);
  return assertRegistryInvariants({
    schemaVersion: "boardagent.registry.v1",
    sources: {
      surfaceMatrix: SURFACE_MATRIX,
      surfaceMatrixSha256: sha256(surfaceMarkdown),
      verificationMatrix: VERIFICATION_MATRIX,
      verificationMatrixSha256: sha256(verificationMarkdown)
    },
    tools: parseTools(surfaceMarkdown),
    resourceTemplates: parseResources(surfaceMarkdown),
    prompts: parsePrompts(surfaceMarkdown),
    httpAuthorityFamilies: parseHttp(surfaceMarkdown),
    cli: parseCli(surfaceMarkdown),
    events: parseEvents(surfaceMarkdown),
    securityRequirements: parseSecurityRequirements(verificationMarkdown),
    threats: parseThreats(verificationMarkdown),
    acceptanceScenarios: parseAcceptance(verificationMarkdown),
    verificationTiers: parseTiers(verificationMarkdown)
  });
}

export async function buildRegistry(root = ROOT): Promise<RegistryBuild> {
  const registry = await composeActivationAmendment(
    root,
    await composeOnboardingAmendment(
      root,
      await composeOperationalAmendment(
        root,
        await composeAuthorityAmendment(root, await buildFrozenRegistry(root))
      )
    )
  );
  const digest = registryDigest(registry);
  const [dataModule, idsModule, manifest, net, surfaceReference] = await Promise.all([
    format(renderDataModule(registry), { ...FORMAT_OPTIONS, parser: "typescript" }),
    format(renderIdsModule(registry, digest), { ...FORMAT_OPTIONS, parser: "typescript" }),
    format(JSON.stringify({ registryDigest: digest, registry }), {
      ...FORMAT_OPTIONS,
      parser: "json"
    }),
    format(renderNet(registry, digest), { ...FORMAT_OPTIONS, parser: "json" }),
    format(renderSurfaceReference(registry, digest), { ...FORMAT_OPTIONS, parser: "markdown" })
  ]);
  return {
    registry,
    digest,
    artifacts: [
      {
        relativePath: "lib/contracts/src/generated/registry.data.ts",
        content: dataModule
      },
      {
        relativePath: "lib/contracts/src/generated/registry.ids.ts",
        content: idsModule
      },
      {
        relativePath: "lib/contracts/src/generated/registry.manifest.json",
        content: manifest
      },
      { relativePath: "docs/SURFACE_REFERENCE.md", content: surfaceReference },
      { relativePath: "tests/NET.json", content: net }
    ]
  };
}

async function atomicWrite(filePath: string, content: string): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  const temporaryPath = `${filePath}.tmp`;
  await writeFile(temporaryPath, content, { encoding: "utf8", mode: 0o644 });
  await rename(temporaryPath, filePath);
}

export async function writeRegistryArtifacts(root = ROOT): Promise<RegistryBuild> {
  const build = await buildRegistry(root);
  await Promise.all(
    build.artifacts.map((artifact) =>
      atomicWrite(path.join(root, artifact.relativePath), artifact.content)
    )
  );
  return build;
}

function isDirectInvocation(): boolean {
  return (
    process.argv[1] !== undefined &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  );
}

if (isDirectInvocation()) {
  if (process.argv.includes("--surface-reference-only")) {
    const build = await buildRegistry();
    const artifact = build.artifacts.find(
      ({ relativePath }) => relativePath === "docs/SURFACE_REFERENCE.md"
    );
    if (artifact === undefined) throw new Error("surface-reference artifact is missing");
    await atomicWrite(path.join(ROOT, artifact.relativePath), artifact.content);
    process.stdout.write(`generated BoardAgent surface reference ${build.digest}\n`);
  } else {
    const build = await writeRegistryArtifacts();
    process.stdout.write(`generated BoardAgent registry ${build.digest}\n`);
  }
}
