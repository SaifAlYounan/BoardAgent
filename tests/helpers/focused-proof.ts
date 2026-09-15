import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { vi } from "vitest";

const execFileAsync = promisify(execFile);
const PROJECT = path.resolve(import.meta.dirname, "../..");
const VITEST = path.join(PROJECT, "node_modules/vitest/vitest.mjs");

vi.setConfig({ testTimeout: 15 * 60_000 });

function withoutAnsi(value: string): string {
  return value.replace(new RegExp(`${String.fromCodePoint(0x1b)}\\[[0-9;]*m`, "gu"), "");
}

function literalPattern(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

/**
 * Re-run one authoritative integration scenario from a tier-specific proof file.
 *
 * The release net deliberately gives threats and acceptance stories stable paths.
 * Their transaction-heavy fixtures already live in the PostgreSQL/protocol suites;
 * invoking one exact case here avoids divergent copies while still executing the
 * real migration, service, client and database boundary in the owning tier.
 */
export async function runFocusedProof(
  relativeFile: string,
  testNamePattern: string,
  expectedPassed = 1
): Promise<void> {
  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    [
      VITEST,
      "run",
      relativeFile,
      "--testNamePattern",
      literalPattern(testNamePattern),
      "--no-file-parallelism",
      "--maxWorkers=1"
    ],
    {
      cwd: PROJECT,
      env: process.env,
      maxBuffer: 16 * 1024 * 1024,
      timeout: 15 * 60_000
    }
  );
  const output = withoutAnsi(`${stdout}\n${stderr}`);
  const passed = /Tests\s+(\d+) passed/u.exec(output)?.[1];
  if (passed !== String(expectedPassed)) {
    throw new Error(
      `focused proof ${relativeFile} / ${testNamePattern} did not execute exactly ${String(expectedPassed)} passing test(s):\n${output.slice(-8_000)}`
    );
  }
}
