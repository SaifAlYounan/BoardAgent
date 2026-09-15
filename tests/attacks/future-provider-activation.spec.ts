import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { parseConfig } from "../../lib/config/src/config.js";

const ROOT = path.resolve(import.meta.dirname, "../..");
const local = {
  BOARDAGENT_ENV: "development",
  BOARDAGENT_DATABASE_URL: "postgresql://boardagent:secret@localhost/boardagent",
  BOARDAGENT_PUBLIC_BASE_URL: "http://127.0.0.1:8787",
  BOARDAGENT_AUTHORIZATION_MODE: "builtin",
  BOARDAGENT_BLOB_ROOT: "/tmp/boardagent-blobs",
  BOARDAGENT_DEV_MASTER_SECRET: "this-is-a-long-local-development-secret"
};

function sources(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const absolute = path.join(directory, name);
    return statSync(absolute).isDirectory()
      ? sources(absolute)
      : /\.(?:ts|js|mjs|cjs|json)$/u.test(name)
        ? [absolute]
        : [];
  });
}

describe("TH-23 dormant checker/provider activation", () => {
  it("rejects provider configuration and ships no model-provider dependency or secret", () => {
    expect(() =>
      parseConfig({
        ...local,
        BOARDAGENT_SUBMISSION_CHECK_PROVIDER_URL: "https://model-provider.invalid",
        BOARDAGENT_SUBMISSION_CHECK_PROVIDER_KEY: "must-not-exist"
      })
    ).toThrow("unknown BoardAgent configuration");

    const manifest = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
      dependencies: Record<string, string>;
    };
    expect(Object.keys(manifest.dependencies).join("\n")).not.toMatch(
      /openai|anthropic|gemini|embedding|vector|ocr/iu
    );
    const runtime = ["artifacts/server/src", "lib", "scripts/src"]
      .flatMap((directory) => sources(path.join(ROOT, directory)))
      .map((file) => readFileSync(file, "utf8"))
      .join("\n");
    expect(runtime).not.toMatch(/OPENAI_API_KEY|ANTHROPIC_API_KEY|SUBMISSION_CHECK_PROVIDER_KEY/u);
  });
});
