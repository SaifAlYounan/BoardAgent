import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { sha256Hex } from "../../lib/contracts/src/index.js";

const ROOT = path.resolve(import.meta.dirname, "../..");

function file(relative: string): Buffer {
  return readFileSync(path.join(ROOT, relative));
}

describe("frozen sponsor authority and prior-art provenance", () => {
  it("keeps the approved Gate-2 authority bytes unchanged", () => {
    expect(sha256Hex(file("BUILD_PLAN.md"))).toBe(
      "1179f3ca3dc4be7b0cbf390972fb770f02c890d9309e18212a726f5180e6ff66"
    );
    expect(sha256Hex(file("planning/gate2/gate2/GATE2-MANIFEST.md"))).toBe(
      "a548ac62f8f135e5dcaf7e1d36ece2922c36cad425c733f5d52cbb6c05e6242b"
    );
  });

  it("pins the read-only OpenBoard reference and exact MIT license", () => {
    const head = execFileSync(
      "git",
      ["-C", path.join(ROOT, "vendor/openboard"), "rev-parse", "HEAD"],
      {
        encoding: "utf8"
      }
    ).trim();
    expect(head).toBe("1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb");
    expect(sha256Hex(file("vendor/openboard/LICENSE"))).toBe(
      "8f8175ef116b82fbd057625d0751517802643de57254e4fb737b4f1e91e06521"
    );
    expect(readFileSync(path.join(ROOT, ".gitignore"), "utf8")).toMatch(/^vendor\/openboard\/$/mu);
  });
});
