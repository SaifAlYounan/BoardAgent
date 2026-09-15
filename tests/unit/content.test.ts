import { describe, expect, it } from "vitest";

import {
  CanonicalDocumentSchema,
  MaterialRejectionSchema,
  isCanonicalMediaType
} from "../../lib/contracts/src/index.js";

describe("machine-readable-only content boundary", () => {
  it.each([
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "image/png",
    "application/zip"
  ])("refuses %s", (mediaType) => {
    expect(isCanonicalMediaType(mediaType)).toBe(false);
  });

  it("accepts only the three canonical v1 media types", () => {
    expect(isCanonicalMediaType("text/markdown; charset=utf-8")).toBe(true);
    expect(isCanonicalMediaType("text/plain; charset=utf-8")).toBe(true);
    expect(isCanonicalMediaType("application/json")).toBe(true);
  });

  it("rejects unknown document fields and carries a loud rejection", () => {
    expect(() =>
      CanonicalDocumentSchema.parse({ schemaVersion: "boardagent.document.v1", surprise: true })
    ).toThrow();
    expect(
      MaterialRejectionSchema.parse({
        accepted: false,
        code: "machine_readable_material_required",
        message:
          "BoardAgent accepts only UTF-8 Markdown, plain text, or versioned strict JSON. Submit a machine-readable source; rejected bytes were not retained.",
        receivedMediaType: "application/pdf"
      }).message
    ).toContain("rejected bytes were not retained");
  });
});
