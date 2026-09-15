import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { chromium } from "playwright";
import { describe, expect, it } from "vitest";

const ROOT = new URL("../../", import.meta.url);

async function sha256(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

describe("T6 browser toolchain provenance", () => {
  it("executes the exact captured Playwright headless browser", async () => {
    const provenance = JSON.parse(
      await readFile(new URL("artifacts/provenance/toolchain.json", ROOT), "utf8")
    ) as {
      buildHost: string;
      browserHarness: {
        browserVersion: string;
        executableSha256: string;
        revision: string;
      };
    };
    const browserRoot = process.env["PLAYWRIGHT_BROWSERS_PATH"];
    if (!browserRoot) {
      throw new Error(
        "T6 requires PLAYWRIGHT_BROWSERS_PATH so the captured browser binary is unambiguous"
      );
    }
    if (provenance.buildHost !== `${process.platform}-${process.arch}`) {
      throw new Error(
        `browser provenance is for ${provenance.buildHost}, not ${process.platform}-${process.arch}`
      );
    }
    if (process.platform !== "darwin" || process.arch !== "arm64") {
      throw new Error("this release candidate's browser provenance is captured for darwin-arm64");
    }
    const executable = path.join(
      browserRoot,
      `chromium_headless_shell-${provenance.browserHarness.revision}`,
      "chrome-headless-shell-mac-arm64",
      "chrome-headless-shell"
    );
    expect(await sha256(executable)).toBe(provenance.browserHarness.executableSha256);

    const browser = await chromium.launch({ headless: true });
    try {
      expect(browser.version()).toBe(provenance.browserHarness.browserVersion);
    } finally {
      await browser.close();
    }
  });
});
