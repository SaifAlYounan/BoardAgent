import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson, type JsonValue } from "@boardagent/contracts";
import { z } from "zod";

import {
  buildOrVerifyReleaseImages,
  DEFAULT_CADDY_IMAGE,
  DEFAULT_POSTGRES_IMAGE,
  DEFAULT_RELEASE_IMAGE,
  RELEASE_COMPONENT_LABEL,
  type ReleaseImageBinding
} from "./build-release-image.js";
import { sourceTreeSha256 } from "./verify-release.js";

const PROJECT = path.resolve(import.meta.dirname, "../..");
const RECEIPT_DIRECTORY = path.join(PROJECT, "artifacts", "vulnerability");
const Sha256Schema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const SourceSha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);
const HighSeveritySchema = z.enum(["HIGH", "CRITICAL"]);

export const TRIVY_VERSION = "0.74.0";
export const TRIVY_IMAGE =
  "aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969";

const FindingSchema = z
  .object({
    Severity: z.string()
  })
  .passthrough();

const TrivyReportSchema = z
  .object({
    SchemaVersion: z.number().int().positive(),
    CreatedAt: z.iso.datetime({ offset: true }),
    ArtifactName: z.string().min(1),
    Metadata: z
      .object({
        ImageID: Sha256Schema,
        ImageConfig: z
          .object({
            config: z
              .object({
                Labels: z.record(z.string(), z.string())
              })
              .passthrough()
          })
          .passthrough()
      })
      .passthrough(),
    Results: z
      .array(
        z
          .object({
            Vulnerabilities: z.array(FindingSchema).optional(),
            Misconfigurations: z.array(FindingSchema).optional(),
            Secrets: z.array(FindingSchema).optional()
          })
          .passthrough()
      )
      .optional()
  })
  .passthrough();

const TrivyDatabaseMetadataSchema = z
  .object({
    Version: z.number().int().positive(),
    UpdatedAt: z.iso.datetime({ offset: true }),
    DownloadedAt: z.iso.datetime({ offset: true }),
    NextUpdate: z.iso.datetime({ offset: true })
  })
  .strict();

interface CommandResult {
  readonly stdout: string;
  readonly stderr: string;
}

export interface TrivySummary {
  readonly vulnerabilityCount: number;
  readonly misconfigurationCount: number;
  readonly secretCount: number;
}

async function command(executable: string, args: readonly string[]): Promise<CommandResult> {
  const child = spawn(executable, [...args], {
    cwd: PROJECT,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  if (code !== 0) {
    throw new Error(
      `${executable} ${args[0] ?? "command"} failed${stderr ? `: ${stderr.trim()}` : ""}`
    );
  }
  return { stdout, stderr };
}

async function sha256File(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest("hex");
}

function highSeverityCount(findings: readonly z.infer<typeof FindingSchema>[] | undefined): number {
  return (findings ?? []).filter(({ Severity }) => HighSeveritySchema.safeParse(Severity).success)
    .length;
}

export function summarizeTrivyReport(
  raw: unknown,
  expectedSourceTreeSha256: string,
  expectedComponent?: ReleaseImageBinding["component"]
): TrivySummary {
  const report = TrivyReportSchema.parse(raw);
  const expected = SourceSha256Schema.parse(expectedSourceTreeSha256);
  if (report.Metadata.ImageConfig.config.Labels["org.boardagent.source-tree-sha256"] !== expected) {
    throw new Error("Trivy report source label does not match the release image");
  }
  if (
    expectedComponent !== undefined &&
    report.Metadata.ImageConfig.config.Labels[RELEASE_COMPONENT_LABEL] !== expectedComponent
  ) {
    throw new Error("Trivy report component label does not match the release image");
  }
  return (report.Results ?? []).reduce<TrivySummary>(
    (summary, result) => ({
      vulnerabilityCount: summary.vulnerabilityCount + highSeverityCount(result.Vulnerabilities),
      misconfigurationCount:
        summary.misconfigurationCount + highSeverityCount(result.Misconfigurations),
      secretCount: summary.secretCount + highSeverityCount(result.Secrets)
    }),
    { vulnerabilityCount: 0, misconfigurationCount: 0, secretCount: 0 }
  );
}

async function atomicWrite(filePath: string, bytes: Uint8Array | string): Promise<void> {
  const temporary = `${filePath}.partial-${String(process.pid)}`;
  await writeFile(temporary, bytes, { mode: 0o600 });
  await rename(temporary, filePath);
}

function addSummaries(left: TrivySummary, right: TrivySummary): TrivySummary {
  return {
    vulnerabilityCount: left.vulnerabilityCount + right.vulnerabilityCount,
    misconfigurationCount: left.misconfigurationCount + right.misconfigurationCount,
    secretCount: left.secretCount + right.secretCount
  };
}

export async function scanComponent(
  binding: ReleaseImageBinding,
  sourceTreeSha256: string,
  working: string,
  cache: string
): Promise<TrivySummary> {
  const artifactStem =
    binding.component === "application"
      ? "release-image"
      : binding.component === "postgres"
        ? "postgres-image"
        : "caddy-image";
  const imageArchive = path.join(working, `${artifactStem}.tar`);
  const reportPath = path.join(working, `${artifactStem}.trivy.json`);
  await command("docker", ["save", "--output", imageArchive, binding.imageId]);
  await command("docker", [
    "run",
    "--rm",
    "--volume",
    `${working}:/scan`,
    "--volume",
    `${cache}:/root/.cache/trivy`,
    TRIVY_IMAGE,
    "image",
    "--input",
    `/scan/${artifactStem}.tar`,
    "--scanners",
    "vuln,misconfig,secret",
    "--severity",
    "HIGH,CRITICAL",
    "--format",
    "json",
    "--output",
    `/scan/${artifactStem}.trivy.json`,
    "--exit-code",
    "0",
    "--skip-version-check"
  ]);
  const reportBytes = await readFile(reportPath);
  const parsedReport = TrivyReportSchema.parse(JSON.parse(reportBytes.toString("utf8")));
  const currentImage = await command("docker", [
    "image",
    "inspect",
    "--format",
    "{{.Id}}",
    binding.image
  ]);
  if (currentImage.stdout.trim() !== binding.imageId) {
    throw new Error(`${binding.component} release image tag changed while it was being scanned`);
  }
  const summary = summarizeTrivyReport(parsedReport, sourceTreeSha256, binding.component);
  const databaseMetadata = TrivyDatabaseMetadataSchema.parse(
    JSON.parse(await readFile(path.join(cache, "db", "metadata.json"), "utf8"))
  );
  const databaseAgeMs = Date.now() - new Date(databaseMetadata.UpdatedAt).getTime();
  if (databaseAgeMs < -5 * 60_000 || databaseAgeMs > 48 * 60 * 60_000) {
    throw new Error(
      "Trivy vulnerability database is outside the accepted 48-hour freshness window"
    );
  }
  const status =
    summary.vulnerabilityCount + summary.misconfigurationCount + summary.secretCount === 0
      ? "passed"
      : "failed";
  const receipt = {
    schemaVersion: "boardagent.release-component-scan.v1",
    component: binding.component,
    status,
    scannedAt: new Date().toISOString(),
    sourceTreeSha256,
    image: binding.image,
    imageId: binding.imageId,
    scannedConfigId: parsedReport.Metadata.ImageID,
    scanner: { name: "Trivy", version: TRIVY_VERSION, image: TRIVY_IMAGE },
    database: {
      ...databaseMetadata,
      sha256: await sha256File(path.join(cache, "db", "trivy.db"))
    },
    thresholds: {
      severities: ["HIGH", "CRITICAL"],
      maximumVulnerabilities: 0,
      maximumMisconfigurations: 0,
      maximumSecrets: 0
    },
    ...summary,
    reportSha256: createHash("sha256").update(reportBytes).digest("hex")
  };
  await atomicWrite(path.join(RECEIPT_DIRECTORY, `${artifactStem}.trivy.json`), reportBytes);
  await atomicWrite(
    path.join(RECEIPT_DIRECTORY, `${artifactStem}-scan.receipt.json`),
    `${canonicalJson(receipt as JsonValue)}\n`
  );
  if (status !== "passed") {
    throw new Error(
      `${binding.component} release image scan failed: ${String(summary.vulnerabilityCount)} vulnerabilities, ${String(summary.misconfigurationCount)} misconfigurations, ${String(summary.secretCount)} secrets`
    );
  }
  return summary;
}

async function scanReleaseImages(): Promise<TrivySummary> {
  const bindings = await buildOrVerifyReleaseImages({
    ...process.env,
    BOARDAGENT_RELEASE_IMAGE: process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE,
    BOARDAGENT_POSTGRES_IMAGE: process.env["BOARDAGENT_POSTGRES_IMAGE"] ?? DEFAULT_POSTGRES_IMAGE,
    BOARDAGENT_CADDY_IMAGE: process.env["BOARDAGENT_CADDY_IMAGE"] ?? DEFAULT_CADDY_IMAGE
  });
  const working = await mkdtemp(path.join(tmpdir(), "boardagent-trivy-scan-"));
  const cache = path.resolve(
    process.env["TRIVY_CACHE_DIRECTORY"] ?? path.join(tmpdir(), "boardagent-trivy-cache-v2")
  );
  try {
    await mkdir(cache, { recursive: true });
    await mkdir(RECEIPT_DIRECTORY, { recursive: true });
    const version = await command("docker", ["run", "--rm", TRIVY_IMAGE, "--version"]);
    if (!version.stdout.includes(`Version: ${TRIVY_VERSION}`)) {
      throw new Error(`pinned vulnerability scanner is not Trivy ${TRIVY_VERSION}`);
    }
    const application = await scanComponent(
      bindings.application,
      bindings.sourceTreeSha256,
      working,
      cache
    );
    const postgres = await scanComponent(
      bindings.postgres,
      bindings.sourceTreeSha256,
      working,
      cache
    );
    const caddy = await scanComponent(bindings.caddy, bindings.sourceTreeSha256, working, cache);
    const after = await sourceTreeSha256();
    if (after !== bindings.sourceTreeSha256) {
      throw new Error("source tree changed while release images were being scanned");
    }
    const summary = addSummaries(addSummaries(application, postgres), caddy);
    const receipt = {
      schemaVersion: "boardagent.release-images-scan.v2",
      status: "passed",
      scannedAt: new Date().toISOString(),
      sourceTreeSha256: after,
      components: {
        application: { image: bindings.application.image, imageId: bindings.application.imageId },
        postgres: { image: bindings.postgres.image, imageId: bindings.postgres.imageId },
        caddy: { image: bindings.caddy.image, imageId: bindings.caddy.imageId }
      },
      ...summary,
      thresholds: {
        severities: ["HIGH", "CRITICAL"],
        maximumVulnerabilities: 0,
        maximumMisconfigurations: 0,
        maximumSecrets: 0
      }
    };
    await atomicWrite(
      path.join(RECEIPT_DIRECTORY, "release-images-scan.receipt.json"),
      `${canonicalJson(receipt as JsonValue)}\n`
    );
    return summary;
  } finally {
    await rm(working, { recursive: true, force: true });
  }
}

async function main(): Promise<number> {
  const summary = await scanReleaseImages();
  process.stdout.write(
    `${JSON.stringify({ schemaVersion: "boardagent.release-images-scan.v2", status: "passed", ...summary })}\n`
  );
  return 0;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    process.exitCode = await main();
  } catch (error) {
    process.stderr.write(
      `${JSON.stringify({
        schemaVersion: "boardagent.release-images-scan.v2",
        status: "failed",
        reasonCode: "release_image_scan_failed",
        message: error instanceof Error ? error.message : "unknown release image scan failure"
      })}\n`
    );
    process.exitCode = 1;
  }
}
