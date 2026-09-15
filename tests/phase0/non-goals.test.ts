import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const ROOT = path.resolve(import.meta.dirname, "../..");
// These evidence directories are excluded from the shipped container. Keep scanning
// every other artifact directory, including new runtime artifacts and provenance.
const EXCLUDED_EVIDENCE = [
  "artifacts/verification",
  "artifacts/review",
  "artifacts/sbom",
  "artifacts/license-report",
  "artifacts/vulnerability",
  "artifacts/exports"
];

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    // pnpm workspace links recursively lead back into the dependency graph. Installed
    // dependencies have their own manifest/SBOM checks; inspect every project file here.
    if (name === "node_modules") return [];
    const absolute = path.join(directory, name);
    if (EXCLUDED_EVIDENCE.includes(path.relative(ROOT, absolute))) return [];
    if (statSync(absolute).isDirectory()) return sourceFiles(absolute);
    return /\.(?:ts|js|mjs|cjs|json)$/u.test(name) ? [absolute] : [];
  });
}

describe("v1 negative-space contract", () => {
  it("contains no server AI, conversion, OCR, vector, SMTP, or email dependency", () => {
    const manifest = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
      dependencies: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    const packages = Object.keys({ ...manifest.dependencies, ...manifest.devDependencies }).join(
      "\n"
    );
    expect(packages).not.toMatch(
      /openai|anthropic|langchain|llama|embedding|vector|ocr|tesseract|smtp|nodemailer/iu
    );
  });

  it("does not ship dormant provider secrets or configuration", () => {
    const excludedFromContainer = readFileSync(path.join(ROOT, ".dockerignore"), "utf8")
      .split(/\r?\n/u)
      .map((line) => line.trim());
    for (const directory of EXCLUDED_EVIDENCE) expect(excludedFromContainer).toContain(directory);
    const sources = ["artifacts", "lib", "scripts"].flatMap((directory) =>
      sourceFiles(path.join(ROOT, directory))
    );
    for (const source of sources) {
      expect(readFileSync(source, "utf8"), path.relative(ROOT, source)).not.toMatch(
        /OPENAI_API_KEY|ANTHROPIC_API_KEY|SMTP_PASSWORD|OCR_PROVIDER|EMBEDDING_PROVIDER/u
      );
    }
  });

  it("does not package the untrusted vendor reference", () => {
    expect(readFileSync(path.join(ROOT, ".dockerignore"), "utf8")).toMatch(
      /^vendor\/openboard\/?$/mu
    );
  });
});
