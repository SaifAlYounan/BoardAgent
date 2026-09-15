import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

type RuntimeTier = "T5" | "T6" | "T7" | "T8" | "T9";

const PROJECT = path.resolve(import.meta.dirname, "../..");

const POSTGRES_TRANSACTION_PROOFS = [
  "tests/integration/migrations.postgres.test.ts",
  "tests/integration/rls-integrity.postgres.test.ts",
  "tests/integration/audit-repository.postgres.test.ts",
  "tests/integration/document-transactions.postgres.test.ts",
  "tests/integration/question-transactions.postgres.test.ts",
  "tests/integration/management-submissions.postgres.test.ts",
  "tests/integration/consent-transactions.postgres.test.ts",
  "tests/integration/matter-evaluation.postgres.test.ts",
  "tests/integration/vote-open.postgres.test.ts",
  "tests/integration/minutes-transactions.postgres.test.ts",
  "tests/integration/task-transactions.postgres.test.ts",
  "tests/integration/jobs.postgres.test.ts",
  "tests/integration/export-transactions.postgres.test.ts",
  "tests/integration/audit-checkpoints.postgres.test.ts",
  "tests/integration/backup-restore.postgres.test.ts",
  "tests/integration/token-context-store.postgres.test.ts"
] as const;

const PROTOCOL_AUTH_PROOFS = [
  "tests/protocol/frozen-mcp-surface.integration.test.ts",
  "tests/protocol/protocol-downgrade.spec.ts",
  "tests/auth/token-verifier.spec.ts",
  "tests/auth/oauth-authorization-server.spec.ts",
  "tests/auth/oauth-interaction-handler.spec.ts",
  "tests/auth/client-registration.spec.ts",
  "tests/auth/oidc-federation.spec.ts",
  "tests/browser/webauthn-positive.spec.ts",
  "tests/browser/webauthn-negative.spec.ts",
  "tests/browser/webauthn-rate-limit.spec.ts",
  "tests/browser/auth-page-hardening.spec.ts",
  "tests/browser/totp-fallback.spec.ts",
  "tests/integration/oauth-provider.postgres.test.ts"
] as const;

interface NetManifest {
  readonly threats: readonly { readonly id: string; readonly plannedProof: string }[];
  readonly acceptanceScenarios: readonly string[];
}

async function exists(relative: string): Promise<boolean> {
  try {
    await access(path.join(PROJECT, relative));
    return true;
  } catch {
    return false;
  }
}

function proofPath(value: string): string | null {
  return /`(tests\/[A-Za-z0-9_./-]+\.(?:ts|mjs|py))`/u.exec(value)?.[1] ?? null;
}

async function recursiveTypeScript(directory: string): Promise<readonly string[]> {
  const absolute = path.join(PROJECT, directory);
  let entries;
  try {
    entries = await readdir(absolute, { withFileTypes: true });
  } catch {
    return [];
  }
  const files: string[] = [];
  for (const entry of entries) {
    const relative = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await recursiveTypeScript(relative)));
    else if (entry.isFile() && /\.(?:ts|mjs)$/u.test(entry.name)) files.push(relative);
  }
  return files.toSorted();
}

async function missingFiles(files: readonly string[]): Promise<string[]> {
  const checks = await Promise.all(
    files.map(async (file) => ({ file, present: await exists(file) }))
  );
  return checks.filter(({ present }) => !present).map(({ file }) => file);
}

async function loadNet(): Promise<NetManifest> {
  return JSON.parse(await readFile(path.join(PROJECT, "tests/NET.json"), "utf8")) as NetManifest;
}

export async function verificationClosureFailures(tier: RuntimeTier): Promise<readonly string[]> {
  const net = await loadNet();
  if (tier === "T5") return missingFiles(POSTGRES_TRANSACTION_PROOFS);
  if (tier === "T6") return missingFiles(PROTOCOL_AUTH_PROOFS);
  if (tier === "T7") {
    const paths = net.threats.map(({ plannedProof }) => proofPath(plannedProof)).filter(Boolean);
    return missingFiles([...new Set(paths as string[])]);
  }
  if (tier === "T8") {
    const files = await recursiveTypeScript("tests/acceptance");
    const corpus = (
      await Promise.all(files.map(async (file) => readFile(path.join(PROJECT, file), "utf8")))
    ).join("\n");
    return net.acceptanceScenarios
      .filter((scenario) => !new RegExp(`\\b${scenario}\\b`, "u").test(corpus))
      .map((scenario) => `acceptance scenario ${scenario}`);
  }
  const operations = await recursiveTypeScript("tests/operations");
  const load = await recursiveTypeScript("tests/load");
  return [
    ...(operations.length === 0 ? ["tests/operations/**/*.ts"] : []),
    ...(load.length === 0 ? ["tests/load/**/*.ts"] : [])
  ];
}

async function main(): Promise<number> {
  const tier = process.argv[2];
  if (!/^T[5-9]$/u.test(tier ?? "")) {
    throw new Error("usage: check-verification-closure.ts <T5|T6|T7|T8|T9>");
  }
  const failures = await verificationClosureFailures(tier as RuntimeTier);
  if (failures.length > 0) {
    process.stderr.write(
      `verification closure ${tier} is incomplete:\n${failures.map((item) => `- ${item}`).join("\n")}\n`
    );
    return 1;
  }
  process.stdout.write(`verification closure ${tier}: complete\n`);
  return 0;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await main();
}
