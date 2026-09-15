import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { createReadStream } from "node:fs";
import { readFile, rename, writeFile } from "node:fs/promises";
import { PassThrough, Readable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  summarizeTrivyReport,
  scanComponent,
  TRIVY_IMAGE,
  TRIVY_VERSION
} from "../../scripts/src/scan-release-image.js";
import { RELEASE_COMPONENT_LABEL } from "../../scripts/src/build-release-image.js";

vi.mock("node:child_process", () => ({ spawn: vi.fn(), spawnSync: vi.fn() }));
vi.mock("node:fs", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:fs")>()),
  createReadStream: vi.fn()
}));
vi.mock("node:fs/promises", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:fs/promises")>()),
  readFile: vi.fn(),
  writeFile: vi.fn(),
  rename: vi.fn()
}));

afterEach(() => vi.resetAllMocks());

const IMAGE_ID = `sha256:${"a".repeat(64)}`;
const SOURCE_DIGEST = "b".repeat(64);

function report(results: unknown[], imageId = IMAGE_ID): unknown {
  return {
    SchemaVersion: 2,
    CreatedAt: "2026-09-04T18:00:00Z",
    ArtifactName: "/scan/release-image.tar",
    Metadata: {
      ImageID: imageId,
      ImageConfig: {
        config: {
          Labels: {
            "org.boardagent.source-tree-sha256": SOURCE_DIGEST,
            [RELEASE_COMPONENT_LABEL]: "application"
          }
        }
      }
    },
    Results: results
  };
}

function inertScanner(finalTagId: string) {
  const changedImageId = `sha256:${"c".repeat(64)}`;
  const binding = {
    component: "application" as const,
    image: "boardagent:synthetic-scan",
    imageId: IMAGE_ID,
    built: false
  };
  let archivedImageId: string | undefined;
  vi.mocked(spawn).mockImplementation((executable, args) => {
    expect(executable).toBe("docker");
    const argv = Array.isArray(args) ? args.map(String) : [];
    const child = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(),
      stderr: new PassThrough()
    });
    queueMicrotask(() => {
      if (argv[0] === "save") {
        // The tag changes after its binding was captured, before archive selection.
        archivedImageId = argv.at(-1) === binding.image ? changedImageId : argv.at(-1);
      } else if (argv[0] === "image" && argv[1] === "inspect") {
        child.stdout.write(`${finalTagId}\n`);
      } else if (argv[0] !== "run") {
        child.emit("error", new Error("unexpected inert Docker command"));
        return;
      }
      child.stdout.end();
      child.stderr.end();
      child.emit("close", 0);
    });
    return child as unknown as ReturnType<typeof spawn>;
  });
  vi.mocked(readFile).mockImplementation(async (file) => {
    if (String(file).endsWith("release-image.trivy.json")) {
      if (!archivedImageId) throw new Error("inert scan has no selected archive");
      return Buffer.from(JSON.stringify(report([], archivedImageId)));
    }
    if (String(file).endsWith("metadata.json")) {
      const now = new Date().toISOString();
      return Buffer.from(
        JSON.stringify({ Version: 2, UpdatedAt: now, DownloadedAt: now, NextUpdate: now })
      );
    }
    throw new Error("unexpected inert scan file read");
  });
  vi.mocked(createReadStream).mockImplementation(
    () =>
      Readable.from([Buffer.from("synthetic scanner database")]) as ReturnType<
        typeof createReadStream
      >
  );
  vi.mocked(writeFile).mockResolvedValue(undefined);
  vi.mocked(rename).mockResolvedValue(undefined);
  return { binding, archivedImageId: () => archivedImageId };
}

describe("release image vulnerability scan", () => {
  it("scans the bound immutable image when its tag changes and is restored", async () => {
    const scan = inertScanner(IMAGE_ID);
    await expect(
      scanComponent(scan.binding, SOURCE_DIGEST, "/synthetic/work", "/synthetic/cache")
    ).resolves.toEqual({ vulnerabilityCount: 0, misconfigurationCount: 0, secretCount: 0 });
    expect(scan.archivedImageId()).toBe(scan.binding.imageId);
    const receiptWrite = vi
      .mocked(writeFile)
      .mock.calls.find(([file]) =>
        String(file).includes("release-image-scan.receipt.json.partial-")
      );
    expect(JSON.parse(String(receiptWrite?.[1]))).toMatchObject({
      imageId: scan.binding.imageId,
      scannedConfigId: scan.archivedImageId(),
      status: "passed"
    });
  });

  it("still refuses when the image tag remains changed after the scan", async () => {
    const scan = inertScanner(`sha256:${"c".repeat(64)}`);
    await expect(
      scanComponent(scan.binding, SOURCE_DIGEST, "/synthetic/work", "/synthetic/cache")
    ).rejects.toThrow("release image tag changed while it was being scanned");
    expect(writeFile).not.toHaveBeenCalled();
  });

  it("pins the scanner itself and accepts an exact-image zero-finding result", () => {
    expect(TRIVY_VERSION).toBe("0.74.0");
    expect(TRIVY_IMAGE).toMatch(/^aquasec\/trivy@sha256:[0-9a-f]{64}$/u);
    expect(
      summarizeTrivyReport(report([{ Target: "image", Vulnerabilities: [] }]), SOURCE_DIGEST)
    ).toEqual({
      vulnerabilityCount: 0,
      misconfigurationCount: 0,
      secretCount: 0
    });
  });

  it("counts every high or critical result category", () => {
    expect(
      summarizeTrivyReport(
        report([
          {
            Vulnerabilities: [{ Severity: "HIGH" }, { Severity: "LOW" }],
            Misconfigurations: [{ Severity: "CRITICAL" }],
            Secrets: [{ Severity: "HIGH" }]
          }
        ]),
        SOURCE_DIGEST
      )
    ).toEqual({ vulnerabilityCount: 1, misconfigurationCount: 1, secretCount: 1 });
  });

  it("rejects a report carrying any other exact-source label", () => {
    expect(() => summarizeTrivyReport(report([]), "c".repeat(64))).toThrowError(
      "Trivy report source label does not match the release image"
    );
  });

  it("rejects a report carrying another release-component label", () => {
    expect(() => summarizeTrivyReport(report([]), SOURCE_DIGEST, "postgres")).toThrowError(
      "Trivy report component label does not match the release image"
    );
  });
});
