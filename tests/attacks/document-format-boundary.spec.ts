import { describe, expect, it } from "vitest";

import {
  DocumentValidationError,
  prepareDocumentContribution
} from "../../lib/domain/src/document.js";

const base = {
  organizationId: "018f0000-0000-7000-8000-000000000003",
  boardId: "018f0000-0000-7000-8000-000000000002",
  documentId: "018f0000-0000-7000-8000-000000000001",
  title: "Hostile material",
  documentSchema: null
};

describe("TH-22 document parser boundary", () => {
  it.each([
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/zip",
    "image/png",
    "image/jpeg"
  ])("rejects %s before retaining offered bytes", (mediaType) => {
    const offered = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe]);
    let rejected: unknown;
    try {
      prepareDocumentContribution({ ...base, mediaType, body: offered });
    } catch (error) {
      rejected = error;
    }
    expect(rejected).toBeInstanceOf(DocumentValidationError);
    expect(rejected).toMatchObject({
      code: "machine_readable_material_required",
      remediation: "Submit a machine-readable Markdown, plain-text, or strict JSON source."
    });
    expect(JSON.stringify(rejected)).not.toContain(offered.toString("hex"));
  });

  it("rejects malformed UTF-8 and oversized canonical inputs", () => {
    expect(() =>
      prepareDocumentContribution({
        ...base,
        mediaType: "text/plain; charset=utf-8",
        body: Buffer.from([0xff, 0xfe])
      })
    ).toThrow(DocumentValidationError);
    expect(() =>
      prepareDocumentContribution({
        ...base,
        mediaType: "text/plain; charset=utf-8",
        body: Buffer.alloc(10 * 1024 * 1024 + 1)
      })
    ).toThrow("10 MiB");
  });
});
