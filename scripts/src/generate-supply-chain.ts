import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { z } from "zod";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CHECK = process.argv.includes("--check");

const CycloneDxSchema = z
  .object({
    bomFormat: z.literal("CycloneDX"),
    specVersion: z.string(),
    metadata: z.record(z.string(), z.unknown()),
    components: z.array(z.record(z.string(), z.unknown())).optional(),
    dependencies: z.array(z.record(z.string(), z.unknown())).optional()
  })
  .passthrough();

const RawLicenseSchema = z.record(
  z.string(),
  z
    .object({
      licenses: z.union([z.string(), z.array(z.string())]),
      repository: z.string().optional(),
      publisher: z.string().optional(),
      url: z.string().optional(),
      licenseFile: z.string().optional(),
      private: z.boolean().optional()
    })
    .passthrough()
);

const CapturedToolchainSchema = z
  .object({
    lockfileSha256: z.string().regex(/^[0-9a-f]{64}$/u)
  })
  .passthrough();

const PackageManifestSchema = z
  .object({
    name: z.string().min(1),
    version: z.string().min(1),
    dependencies: z.record(z.string(), z.string())
  })
  .passthrough();

function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .toSorted(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, stable(entry)])
    );
  }
  return value;
}

function bytes(value: unknown): string {
  return `${JSON.stringify(stable(value), null, 2)}\n`;
}

function sha256File(file: string): string | undefined {
  if (!existsSync(file)) return undefined;
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function assertCapturedSupplyChain(): void {
  const lockfile = path.join(ROOT, "pnpm-lock.yaml");
  const provenancePath = path.join(ROOT, "artifacts/provenance/toolchain.json");
  const sbomPath = path.join(ROOT, "artifacts/sbom/boardagent.cdx.json");
  const licensesPath = path.join(ROOT, "artifacts/license-report/dependencies.json");
  const manifestPath = path.join(ROOT, "package.json");
  for (const required of [lockfile, provenancePath, sbomPath, licensesPath, manifestPath]) {
    if (!existsSync(required))
      throw new Error(`missing supply-chain evidence: ${path.relative(ROOT, required)}`);
  }

  const provenance = CapturedToolchainSchema.parse(
    JSON.parse(readFileSync(provenancePath, "utf8"))
  );
  const currentLockSha256 = sha256File(lockfile);
  if (currentLockSha256 !== provenance.lockfileSha256) {
    throw new Error("supply-chain evidence is stale for pnpm-lock.yaml");
  }

  const manifest = PackageManifestSchema.parse(JSON.parse(readFileSync(manifestPath, "utf8")));
  const sbom = CycloneDxSchema.parse(JSON.parse(readFileSync(sbomPath, "utf8")));
  const licenses = z
    .object({
      schemaVersion: z.literal(1),
      source: z.literal("pnpm-lock.yaml"),
      packages: z.array(
        z.object({ package: z.string().min(1), licenses: z.unknown() }).passthrough()
      )
    })
    .strict()
    .parse(JSON.parse(readFileSync(licensesPath, "utf8")));
  const root = sbom.metadata.component;
  if (root === null || typeof root !== "object" || Array.isArray(root)) {
    throw new Error("CycloneDX root component missing");
  }
  const rootRecord = root as Record<string, unknown>;
  if (rootRecord.name !== manifest.name || rootRecord.version !== manifest.version) {
    throw new Error("CycloneDX root component does not match package.json");
  }

  const componentPurls = new Set(
    (sbom.components ?? []).map((component) => String(component.purl ?? component["bom-ref"] ?? ""))
  );
  const licensedPackages = new Set(licenses.packages.map((entry) => entry.package));
  for (const [name, version] of Object.entries(manifest.dependencies)) {
    const encodedName = name.startsWith("@") ? `%40${name.slice(1)}` : name;
    const purl = `pkg:npm/${encodedName}@${version}`;
    if (!componentPurls.has(purl))
      throw new Error(`SBOM omits production dependency ${name}@${version}`);
    if (![...licensedPackages].some((entry) => entry === `${name}@${version}`)) {
      throw new Error(`license evidence omits production dependency ${name}@${version}`);
    }
  }
}

function writeOrCheck(relative: string, content: string): void {
  const destination = path.join(ROOT, relative);
  if (CHECK) {
    if (!existsSync(destination) || readFileSync(destination, "utf8") !== content) {
      throw new Error(`generated supply-chain evidence drift: ${relative}`);
    }
    return;
  }
  mkdirSync(path.dirname(destination), { recursive: true });
  writeFileSync(destination, content, { encoding: "utf8", mode: 0o644 });
}

function generateSbom(): string {
  const output = execFileSync(
    "corepack",
    [
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
    ],
    {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      ...(CHECK ? { env: { ...process.env, COREPACK_ENABLE_NETWORK: "0" } } : {})
    }
  );
  const parsed = CycloneDxSchema.parse(JSON.parse(output));
  delete parsed.serialNumber;
  delete parsed.metadata.timestamp;
  const component = parsed.metadata.component;
  if (component === null || typeof component !== "object" || Array.isArray(component)) {
    throw new Error("CycloneDX root component missing");
  }
  (component as Record<string, unknown>).type = "application";
  parsed.components?.sort((left, right) =>
    String(left["bom-ref"] ?? "").localeCompare(String(right["bom-ref"] ?? ""))
  );
  parsed.dependencies?.sort((left, right) =>
    String(left.ref ?? "").localeCompare(String(right.ref ?? ""))
  );
  for (const dependency of parsed.dependencies ?? []) {
    if (Array.isArray(dependency.dependsOn)) dependency.dependsOn.sort();
  }
  return bytes(parsed);
}

function generateLicenses(): string {
  const output = execFileSync("license-checker-rseidelsohn", ["--production", "--json"], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024
  });
  const raw = RawLicenseSchema.parse(JSON.parse(output));
  const packages = Object.entries(raw)
    .map(([packageName, info]) => ({
      package: packageName,
      licenses: packageName.startsWith("boardagent@") ? "Apache-2.0" : info.licenses,
      ...(info.repository === undefined ? {} : { repository: info.repository }),
      ...(info.publisher === undefined ? {} : { publisher: info.publisher }),
      ...(info.url === undefined ? {} : { url: info.url }),
      ...(info.licenseFile === undefined
        ? {}
        : { licenseFileSha256: sha256File(info.licenseFile) ?? "missing" })
    }))
    .toSorted((left, right) => left.package.localeCompare(right.package));
  return bytes({ schemaVersion: 1, source: "pnpm-lock.yaml", packages });
}

if (CHECK) {
  assertCapturedSupplyChain();
}
writeOrCheck("artifacts/sbom/boardagent.cdx.json", generateSbom());
writeOrCheck("artifacts/license-report/dependencies.json", generateLicenses());
process.stdout.write(
  CHECK ? "supply-chain evidence matches\n" : "supply-chain evidence generated\n"
);
