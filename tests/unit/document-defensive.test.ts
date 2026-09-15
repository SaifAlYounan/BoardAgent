import { beforeEach, describe, expect, it, vi } from "vitest";

const canonicalState = vi.hoisted(() => ({
  mode: "pass" as "pass" | "throw" | "empty" | "oversized"
}));

vi.mock("@boardagent/contracts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/contracts/src/index.js")>();
  return {
    ...actual,
    canonicalText(value: Uint8Array | string): string {
      if (value instanceof Uint8Array) {
        if (canonicalState.mode === "throw") throw new Error("upstream canonicalizer failed");
        if (canonicalState.mode === "empty") return "";
        if (canonicalState.mode === "oversized") return "x".repeat(10 * 1024 * 1024 + 1);
      }
      return actual.canonicalText(value);
    }
  };
});

import {
  DocumentValidationError,
  prepareDocumentContribution
} from "../../lib/domain/src/document.js";

const base = {
  organizationId: "018f0000-0000-7000-8000-000000000003",
  boardId: "018f0000-0000-7000-8000-000000000002",
  documentId: "018f0000-0000-7000-8000-000000000001",
  title: "Defensive boundary",
  mediaType: "text/plain; charset=utf-8",
  documentSchema: null,
  body: Buffer.from("x")
} as const;

describe("document canonicalizer defensive boundary", () => {
  beforeEach(() => {
    canonicalState.mode = "pass";
  });

  it("does not relabel an unexpected canonicalizer failure", () => {
    canonicalState.mode = "throw";
    let rejection: unknown;
    try {
      prepareDocumentContribution(base);
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(Error);
    expect(rejection).not.toBeInstanceOf(DocumentValidationError);
    expect(rejection).toMatchObject({ message: "upstream canonicalizer failed" });
  });

  it.each([
    ["empty", "document_empty", "canonical document content cannot be empty"],
    ["oversized", "document_too_large", "canonical document content exceeds the exact 10 MiB limit"]
  ] as const)("rejects a defensively %s canonical result", (mode, code, message) => {
    canonicalState.mode = mode;
    let rejection: unknown;
    try {
      prepareDocumentContribution(base);
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(DocumentValidationError);
    expect(rejection).toMatchObject({
      name: "DocumentValidationError",
      code,
      message,
      remediation: "Submit bounded, nonempty machine-readable content."
    });
  });
});
