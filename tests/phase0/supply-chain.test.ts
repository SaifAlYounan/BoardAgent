import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

const ROOT = new URL("../../", import.meta.url);
const require = createRequire(import.meta.url);

async function json<T>(relative: string): Promise<T> {
  return JSON.parse(await readFile(new URL(relative, ROOT), "utf8")) as T;
}

function capturedSupplyChainFixture() {
  const direct = "pkg:npm/direct@1.0.0";
  const leaf = "pkg:npm/leaf@2.0.0";
  const lock = [
    "lockfileVersion: '9.0'",
    "importers:",
    "  .:",
    "    dependencies:",
    "      direct:",
    "        specifier: 1.0.0",
    "        version: 1.0.0",
    "packages:",
    "  direct@1.0.0: {}",
    "  leaf@2.0.0: {}",
    "snapshots:",
    "  direct@1.0.0:",
    "    dependencies:",
    "      leaf: 2.0.0",
    "  leaf@2.0.0: {}",
    ""
  ].join("\n");
  const sbom = {
    bomFormat: "CycloneDX",
    components: [
      { "bom-ref": direct, name: "direct", purl: direct, version: "1.0.0" },
      { "bom-ref": leaf, name: "leaf", purl: leaf, version: "2.0.0" }
    ],
    dependencies: [
      { dependsOn: [direct], ref: "boardagent@0.0.0-synthetic" },
      { dependsOn: [leaf], ref: direct },
      { dependsOn: [], ref: leaf }
    ],
    metadata: {
      component: { name: "boardagent", type: "application", version: "0.0.0-synthetic" }
    },
    specVersion: "1.6"
  };
  const licenses = {
    packages: [
      { licenses: "Apache-2.0", package: "boardagent@0.0.0-synthetic" },
      { licenses: "MIT", package: "direct@1.0.0" },
      { licenses: "Apache-2.0", package: "leaf@2.0.0" }
    ],
    schemaVersion: 1,
    source: "pnpm-lock.yaml"
  };
  // Producer outputs remain complete when a test mutates only captured evidence.
  const generatedSbom = JSON.stringify(sbom);
  const generatedLicenses = JSON.stringify({
    "boardagent@0.0.0-synthetic": { licenses: "Apache-2.0" },
    "direct@1.0.0": { licenses: "MIT" },
    "leaf@2.0.0": { licenses: "Apache-2.0" }
  });
  return {
    lock,
    provenance: { lockfileSha256: createHash("sha256").update(lock).digest("hex") },
    manifest: {
      dependencies: { direct: "1.0.0" },
      name: "boardagent",
      version: "0.0.0-synthetic"
    },
    sbom,
    licenses,
    generatedSbom,
    generatedLicenses
  };
}

async function checkCapturedSupplyChain(
  fixture: ReturnType<typeof capturedSupplyChainFixture>,
  commandFailure?: Error
) {
  const encoded = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
  const files = new Map([
    ["pnpm-lock.yaml", fixture.lock],
    ["package.json", encoded(fixture.manifest)],
    ["artifacts/provenance/toolchain.json", encoded(fixture.provenance)],
    ["artifacts/sbom/boardagent.cdx.json", encoded(fixture.sbom)],
    ["artifacts/license-report/dependencies.json", encoded(fixture.licenses)]
  ]);
  const relative = (file: unknown) => path.relative(fileURLToPath(ROOT), String(file));
  const forbiddenWrite = vi.fn(() => {
    throw new Error("synthetic supply-chain check attempted a filesystem write");
  });
  const command = vi.fn(
    (
      executable: string,
      args: readonly string[],
      _options?: { env?: Record<string, string | undefined> }
    ) => {
      if (executable === "corepack") {
        expect(args).toEqual([
          "pnpm",
          "sbom",
          "--sbom-format",
          "cyclonedx",
          "--sbom-spec-version",
          "1.6",
          "--sbom-type",
          "application",
          "--prod",
          "--lockfile-only"
        ]);
        if (commandFailure) throw commandFailure;
        expect(files.get("pnpm-lock.yaml")).toBe(fixture.lock);
        return fixture.generatedSbom;
      }
      if (executable === "license-checker-rseidelsohn") {
        expect(args).toEqual(["--production", "--json"]);
        return fixture.generatedLicenses;
      }
      throw new Error("unexpected synthetic supply-chain command");
    }
  );
  vi.resetModules();
  vi.doMock("node:fs", () => ({
    existsSync: (file: unknown) => files.has(relative(file)),
    readFileSync: (file: unknown, encoding?: unknown) => {
      const content = files.get(relative(file));
      if (content === undefined) throw new Error("unexpected synthetic supply-chain file read");
      return encoding === "utf8" ? content : Buffer.from(content);
    },
    mkdirSync: forbiddenWrite,
    writeFileSync: forbiddenWrite
  }));
  vi.doMock("node:child_process", () => ({ execFileSync: command }));
  const originalArgv = process.argv;
  const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  process.argv = [...originalArgv, "--check"];
  try {
    await import("../../scripts/src/generate-supply-chain.js");
  } finally {
    process.argv = originalArgv;
    output.mockRestore();
    vi.doUnmock("node:fs");
    vi.doUnmock("node:child_process");
    vi.resetModules();
    expect(forbiddenWrite).not.toHaveBeenCalled();
  }
  return command.mock.calls.map(([executable, , options]) => ({
    executable,
    corepackNetwork: options?.env?.COREPACK_ENABLE_NETWORK
  }));
}

describe("captured supply-chain completeness", () => {
  it("accepts the complete matching synthetic production evidence without writes", async () => {
    await expect(checkCapturedSupplyChain(capturedSupplyChainFixture())).resolves.toHaveLength(2);
  });

  it("keeps Corepack offline when checking the complete captured evidence", async () => {
    await expect(checkCapturedSupplyChain(capturedSupplyChainFixture())).resolves.toEqual([
      { executable: "corepack", corepackNetwork: "0" },
      { executable: "license-checker-rseidelsohn", corepackNetwork: undefined }
    ]);
  });

  it("refuses unavailable local generator tools instead of accepting captured evidence", async () => {
    const unavailable = Object.assign(new Error("synthetic local tool unavailable"), {
      code: "ENOENT"
    });
    await expect(checkCapturedSupplyChain(capturedSupplyChainFixture(), unavailable)).rejects.toBe(
      unavailable
    );
  });

  it("still refuses a stale captured lockfile hash", async () => {
    const fixture = capturedSupplyChainFixture();
    fixture.provenance.lockfileSha256 = "0".repeat(64);
    await expect(checkCapturedSupplyChain(fixture)).rejects.toThrow(
      "supply-chain evidence is stale for pnpm-lock.yaml"
    );
  });

  it("refuses a captured SBOM missing a transitive component", async () => {
    const fixture = capturedSupplyChainFixture();
    fixture.sbom.components = fixture.sbom.components.filter(({ name }) => name !== "leaf");
    await expect(checkCapturedSupplyChain(fixture)).rejects.toThrow(
      "generated supply-chain evidence drift: artifacts/sbom/boardagent.cdx.json"
    );
  });

  it("refuses a captured SBOM missing a transitive dependency edge", async () => {
    const fixture = capturedSupplyChainFixture();
    fixture.sbom.dependencies.find(({ ref }) => ref === "pkg:npm/direct@1.0.0")!.dependsOn = [];
    await expect(checkCapturedSupplyChain(fixture)).rejects.toThrow(
      "generated supply-chain evidence drift: artifacts/sbom/boardagent.cdx.json"
    );
  });

  it("refuses a captured license inventory missing a transitive package", async () => {
    const fixture = capturedSupplyChainFixture();
    fixture.licenses.packages = fixture.licenses.packages.filter(
      ({ package: name }) => name !== "leaf@2.0.0"
    );
    await expect(checkCapturedSupplyChain(fixture)).rejects.toThrow(
      "generated supply-chain evidence drift: artifacts/license-report/dependencies.json"
    );
  });

  it("refuses an altered captured transitive license value", async () => {
    const fixture = capturedSupplyChainFixture();
    fixture.licenses.packages.find(({ package: name }) => name === "leaf@2.0.0")!.licenses = "MIT";
    await expect(checkCapturedSupplyChain(fixture)).rejects.toThrow(
      "generated supply-chain evidence drift: artifacts/license-report/dependencies.json"
    );
  });
});

describe("deterministic supply-chain evidence", () => {
  it("pins every direct dependency without a permissive range", async () => {
    const manifests = [
      "package.json",
      "artifacts/server/package.json",
      "lib/audit/package.json",
      "lib/authz/package.json",
      "lib/config/package.json",
      "lib/contracts/package.json",
      "lib/db/package.json",
      "lib/domain/package.json",
      "lib/ruleset/package.json",
      "scripts/package.json"
    ];
    for (const path of manifests) {
      const manifest = await json<{
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      }>(path);
      for (const version of Object.values({
        ...manifest.dependencies,
        ...manifest.devDependencies
      })) {
        expect(version).toMatch(/^(?:workspace:\*|\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/u);
      }
    }
    expect((await readFile(new URL(".node-version", ROOT), "utf8")).trim()).toBe("24.20.0");
  });

  it("normalizes the CycloneDX report so repeated runs are byte-stable", async () => {
    const sbom = await json<Record<string, unknown>>("artifacts/sbom/boardagent.cdx.json");
    expect(sbom).toMatchObject({ bomFormat: "CycloneDX", specVersion: "1.6" });
    expect(sbom).not.toHaveProperty("serialNumber");
    expect(sbom.metadata).not.toHaveProperty("timestamp");
    expect(sbom.metadata).toHaveProperty("component.type", "application");
  });

  it("produces a path-independent normalized production license report", async () => {
    const report = await json<{
      schemaVersion: number;
      packages: { package: string; licenses: string | string[] }[];
    }>("artifacts/license-report/dependencies.json");
    expect(report.schemaVersion).toBe(1);
    expect(report.packages.length).toBeGreaterThan(50);
    expect(report.packages.find((entry) => entry.package.startsWith("boardagent@"))).toMatchObject({
      licenses: "Apache-2.0"
    });
    expect(JSON.stringify(report)).not.toContain("/private/tmp/");
  });

  it("records the complete immutable base-image references", async () => {
    const provenance = await json<{
      images: { indexDigest: string; purpose: string; reference: string }[];
      supplementalPackages: Array<{
        architectures: Array<{ alpineArch: string; sha256: string; targetArch: string }>;
        name: string;
        purpose: string;
        repository: string;
        signatureVerification: string;
        version: string;
      }>;
    }>("artifacts/provenance/container-images.json");
    expect(provenance.images.map(({ purpose, reference }) => ({ purpose, reference }))).toEqual([
      { purpose: "build-and-runtime", reference: "node:24.20.0-alpine3.24" },
      { purpose: "database-base", reference: "postgres:18.6-alpine3.24" },
      { purpose: "optional-https-build", reference: "golang:1.26.6-alpine3.24" },
      { purpose: "optional-https-runtime-base", reference: "alpine:3.24" }
    ]);
    expect(
      provenance.images.every((entry) => /^sha256:[0-9a-f]{64}$/u.test(entry.indexDigest))
    ).toBe(true);
    expect(provenance.supplementalPackages).toEqual([
      {
        purpose: "database-security-patch",
        name: "libuuid",
        version: "2.42.3-r1",
        repository: "https://dl-cdn.alpinelinux.org/alpine/v3.24/main",
        signatureVerification: "apk verify --keys-dir /etc/apk/keys",
        architectures: [
          {
            targetArch: "amd64",
            alpineArch: "x86_64",
            sha256: "8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2"
          },
          {
            targetArch: "arm64",
            alpineArch: "aarch64",
            sha256: "9ce20c7ffe2ccaa7c321893c10564abbca13c3f2edb82f60a35f1f68e004f86c"
          }
        ]
      }
    ]);
  });

  it("pins the browser harness and every frozen MCP compatibility client", async () => {
    const [manifest, provenance, lockfile, workspacePolicy] = await Promise.all([
      json<{ devDependencies: Record<string, string> }>("package.json"),
      json<{
        browserHarness: {
          browser: string;
          browserVersion: string;
          executableSha256: string;
          revision: string;
          runner: string;
          runnerVersion: string;
          source: string;
        };
        mcpCompatibility: {
          conformanceSdk: { packages: string[]; version: string };
          legacyProtocol: string;
          primaryProtocol: string;
          releasedClients: Array<{
            embeddedSdkVersion?: string;
            integrity: string;
            name: string;
            packageVersion: string;
            profile: string;
            proof: string;
            releaseTag?: string;
          }>;
        };
      }>("artifacts/provenance/toolchain.json"),
      readFile(new URL("pnpm-lock.yaml", ROOT), "utf8"),
      readFile(new URL("pnpm-workspace.yaml", ROOT), "utf8")
    ]);

    expect(manifest.devDependencies).toMatchObject({
      mcporter: "0.13.7",
      openclaw: "2026.7.1",
      playwright: "1.62.1"
    });
    expect(provenance.browserHarness).toEqual({
      runner: "playwright",
      runnerVersion: "1.62.1",
      browser: "Chrome Headless Shell",
      browserVersion: "151.0.7922.34",
      revision: "1234",
      executableSha256: "7687bff7cb2db075f250e6d5848bbc8838cac3802ac3952a899c574f8eccab45",
      source: "playwright-core@1.62.1/browsers.json"
    });
    expect(provenance.mcpCompatibility).toEqual({
      primaryProtocol: "2026-07-28",
      legacyProtocol: "2025-11-25",
      conformanceSdk: {
        packages: [
          "@modelcontextprotocol/client",
          "@modelcontextprotocol/core",
          "@modelcontextprotocol/node",
          "@modelcontextprotocol/server"
        ],
        version: "2.0.0"
      },
      releasedClients: [
        {
          name: "mcporter",
          packageVersion: "0.13.7",
          profile: "modern",
          integrity:
            "sha512-+xfZwrFv+oO0YOyHUQzyBRaOGomJhMWPtoINGfY6rtEk7s4jW6T+osnjPr/1XAmIpN8J0/P03XiLnTIUkltPzg==",
          proof: "tests/protocol/released-client-matrix.spec.ts"
        },
        {
          name: "OpenClaw",
          releaseTag: "v2026.7.1-2",
          packageVersion: "2026.7.1",
          embeddedSdkVersion: "1.29.0",
          profile: "legacy-read-only",
          integrity:
            "sha512-ge/Xss99CHAjPL/ikmH/UFoiOrjcxDB4sW3y9mhyCD+dYW3wzV7TKbAVdkrXFgAG2d2BjpJofP97zUZ+umxo8g==",
          proof: "tests/protocol/released-client-matrix.spec.ts"
        }
      ]
    });
    for (const client of provenance.mcpCompatibility.releasedClients) {
      expect(lockfile).toContain(
        `${client.name === "OpenClaw" ? "openclaw" : client.name}@${client.packageVersion}:`
      );
      expect(lockfile).toContain(`resolution: {integrity: ${client.integrity}}`);
    }
    for (const denied of [
      '"@google/genai": false',
      "openclaw: false",
      "protobufjs: false",
      "tree-sitter-bash: false"
    ]) {
      expect(workspacePolicy).toContain(denied);
    }

    const playwrightPackage = require.resolve("playwright-core/package.json", {
      paths: [path.dirname(require.resolve("playwright/package.json"))]
    });
    const browserCatalog = JSON.parse(
      await readFile(path.join(path.dirname(playwrightPackage), "browsers.json"), "utf8")
    ) as {
      browsers: Array<{ browserVersion?: string; name: string; revision: string }>;
    };
    expect(
      browserCatalog.browsers.find(({ name }) => name === "chromium-headless-shell")
    ).toMatchObject({
      browserVersion: provenance.browserHarness.browserVersion,
      revision: provenance.browserHarness.revision
    });
  });
});
