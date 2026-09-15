import { spawnSync } from "node:child_process";
import path from "node:path";

import { readAndVerifyIndependentReview } from "./independent-review-evidence.js";
import { sourceTreeSha256 } from "./verify-release.js";

const PROJECT = path.resolve(import.meta.dirname, "../..");

function git(args: readonly string[]): string {
  const result = spawnSync("git", args, { cwd: PROJECT, encoding: "utf8" });
  if (result.status !== 0) throw new Error("cannot resolve the candidate Git state");
  return result.stdout.trim();
}

async function main(): Promise<void> {
  if (git(["status", "--porcelain=v1", "--untracked-files=all"]) !== "") {
    throw new Error("T10 requires a clean, committed candidate");
  }
  const gitCommit = git(["rev-parse", "HEAD"]);
  const source = await sourceTreeSha256();
  await readAndVerifyIndependentReview(PROJECT, { gitCommit, sourceTreeSha256: source });
  if (
    git(["rev-parse", "HEAD"]) !== gitCommit ||
    git(["status", "--porcelain=v1", "--untracked-files=all"]) !== "" ||
    (await sourceTreeSha256()) !== source
  ) {
    throw new Error("T10 candidate changed during verification");
  }
  process.stdout.write(
    "T10 artifact bytes and sponsor decision bind the current candidate; reviewer independence and substantive acceptance remain human responsibilities\n"
  );
}

await main();
