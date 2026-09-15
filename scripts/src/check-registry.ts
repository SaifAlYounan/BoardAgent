import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { validateVerificationClosure } from "./verification-register.js";
import { buildRegistry } from "./generate-registry.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const VERIFICATION_DOC = "docs/VERIFICATION.md";

export type { VerificationPointer } from "./verification-register.js";

export async function checkVerificationClosure(root = ROOT, requireResolved = false) {
  return validateVerificationClosure(
    await readFile(path.join(root, VERIFICATION_DOC), "utf8"),
    requireResolved
  );
}

export async function checkRegistry(root = ROOT, requireResolved = false): Promise<string> {
  const build = await buildRegistry(root);
  const drift: string[] = [];
  for (const artifact of build.artifacts) {
    const expected = artifact.content;
    let actual: string;
    try {
      actual = await readFile(path.join(root, artifact.relativePath), "utf8");
    } catch (error: unknown) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? String((error as { code?: unknown }).code)
          : "UNKNOWN";
      drift.push(`${artifact.relativePath} (${code})`);
      continue;
    }
    if (actual !== expected) drift.push(artifact.relativePath);
  }
  if (drift.length > 0) {
    throw new Error(`generated registry drift: ${drift.join(", ")}; run pnpm registry:generate`);
  }
  await checkVerificationClosure(root, requireResolved);
  return build.digest;
}

const requireResolved = process.argv.includes("--require-resolved");
const digest = await checkRegistry(ROOT, requireResolved);
process.stdout.write(`BoardAgent registry is closed and deterministic: ${digest}\n`);
