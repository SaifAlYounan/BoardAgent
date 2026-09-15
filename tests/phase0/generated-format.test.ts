import { format } from "prettier";
import { describe, expect, it } from "vitest";

import { buildRegistry } from "../../scripts/src/generate-registry.js";

const FORMAT_OPTIONS = {
  printWidth: 100,
  semi: true,
  singleQuote: false,
  trailingComma: "none" as const
};

describe("generated registry formatting", () => {
  it("emits byte-stable artifacts that already satisfy the repository formatter", async () => {
    const build = await buildRegistry();

    for (const artifact of build.artifacts) {
      const parser = artifact.relativePath.endsWith(".ts")
        ? "typescript"
        : artifact.relativePath.endsWith(".md")
          ? "markdown"
          : "json";
      await expect(format(artifact.content, { ...FORMAT_OPTIONS, parser })).resolves.toBe(
        artifact.content
      );
    }
  });
});
