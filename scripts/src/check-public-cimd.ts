import { spawnSync } from "node:child_process";
import path from "node:path";

import { runPublicCimdCheck } from "./public-cimd-check.js";
import { sourceTreeSha256 } from "./verify-release.js";

const PROJECT = path.resolve(import.meta.dirname, "../..");

function git(args: readonly string[]): string {
  const result = spawnSync("git", args, { cwd: PROJECT, encoding: "utf8" });
  if (result.status !== 0) throw new Error("cannot resolve the candidate Git state");
  return result.stdout.trim();
}

/**
 * Usage: tsx scripts/src/check-public-cimd.ts https://provider.example/path/document.json
 *
 * Opt-in operator check for SR-013. Performs exactly one bounded public metadata fetch
 * through the production resolver, fetcher and system trust store, then writes a receipt
 * binding the request, addresses, TLS peer, accepted metadata and this candidate. It
 * sends no credentials and runs no model inference. A refusal or timeout exits nonzero.
 */
async function main(): Promise<void> {
  const url = process.argv[2];
  if (!url || process.argv.length !== 3) {
    process.stderr.write("usage: check-public-cimd <https-client-id-url>\n");
    process.exitCode = 64;
    return;
  }
  const candidate = {
    gitCommit: git(["rev-parse", "HEAD"]),
    sourceTreeSha256: await sourceTreeSha256(),
    worktreeClean: git(["status", "--porcelain=v1", "--untracked-files=all"]) === ""
  };
  const { receipt, receiptPath } = await runPublicCimdCheck(PROJECT, url, candidate);
  process.stdout.write(
    `${JSON.stringify({
      status: "passed",
      receiptPath,
      clientIdUrl: receipt.clientIdUrl,
      resolvedAddresses: receipt.resolvedAddresses,
      tlsIssuer: receipt.tlsPeer.issuer,
      canonicalSha256: receipt.metadata.canonicalSha256
    })}\n`
  );
}

await main();
