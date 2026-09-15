import { describe, expect, it } from "vitest";

import {
  DocumentValidationError,
  prepareDocumentContribution
} from "../../lib/domain/src/document.js";

const documentId = "018f0000-0000-7000-8000-000000000001";
const boardId = "018f0000-0000-7000-8000-000000000002";
const organizationId = "018f0000-0000-7000-8000-000000000003";

function captureDocumentError(action: () => unknown): DocumentValidationError {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(DocumentValidationError);
    return error as DocumentValidationError;
  }
  throw new Error("expected document preparation to fail");
}

describe("canonical document preparation", () => {
  it("canonicalizes strict JSON before hashing and produces stable semantic requests", () => {
    const expectedBody =
      '{"schemaVersion":"boardagent.board-pack.v1","sections":[{"body":"Approve phase one.","heading":"Resolution"}],"title":"Board pack"}';
    const expectedByteLength = Buffer.byteLength(expectedBody);
    const first = prepareDocumentContribution({
      organizationId: "018f0000-0000-7000-8000-000000000003",
      boardId,
      documentId,
      title: "Board pack",
      mediaType: "application/json",
      documentSchema: "boardagent.board-pack.v1",
      body: Buffer.from(
        '{ "title": "Board pack", "sections": [{ "heading": "Resolution", "body": "Approve phase one." }], "schemaVersion": "boardagent.board-pack.v1" }'
      )
    });
    const second = prepareDocumentContribution({
      organizationId: "018f0000-0000-7000-8000-000000000003",
      boardId,
      documentId,
      title: "Board pack",
      mediaType: "application/json",
      documentSchema: "boardagent.board-pack.v1",
      body: Buffer.from(expectedBody)
    });
    expect(Buffer.from(first.canonicalBytes).toString("utf8")).toBe(expectedBody);
    expect(first.byteLength).toBe(expectedByteLength);
    expect(first.canonicalizationVersion).toBe("RFC8785+NFC-LF-v1");
    expect(first.sha256).toBe(second.sha256);
    expect(first.requestSha256).toBe(second.requestSha256);
    expect(first.canonicalMetadata).toEqual({
      schemaVersion: "boardagent.document-metadata.v1",
      organizationId: "018f0000-0000-7000-8000-000000000003",
      boardId,
      documentId,
      title: "Board pack",
      mediaType: "application/json",
      documentSchema: "boardagent.board-pack.v1",
      canonicalizationVersion: "RFC8785+NFC-LF-v1",
      byteLength: expectedByteLength,
      sha256: first.sha256
    });
  });

  it("rejects unsupported or malformed input without retaining offered bytes", () => {
    const offered = Buffer.from([0xff, 0xfe, 0xfd]);
    let rejection: unknown;
    try {
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "Opaque upload",
        mediaType: "application/pdf",
        documentSchema: null,
        body: offered
      });
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(DocumentValidationError);
    expect(rejection).toMatchObject({
      name: "DocumentValidationError",
      code: "machine_readable_material_required",
      message:
        "BoardAgent accepts only UTF-8 Markdown, plain text, or versioned strict JSON; rejected bytes were not retained.",
      remediation: "Submit a machine-readable Markdown, plain-text, or strict JSON source."
    });
    expect(JSON.stringify(rejection)).not.toContain(offered.toString("hex"));

    const canonicalFailure = captureDocumentError(() =>
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "Duplicate keys",
        mediaType: "application/json",
        documentSchema: "boardagent.board-pack.v1",
        body: Buffer.from('{"same":1,"s\\u0061me":2}')
      })
    );
    expect(canonicalFailure).toMatchObject({
      name: "DocumentValidationError",
      code: "invalid_canonical_content",
      remediation:
        "Submit strict UTF-8 NFC/LF content; JSON must have unique decoded keys and finite numbers."
    });
    expect(canonicalFailure.message).toMatch(/duplicate object name/u);
    expect(() =>
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "CRLF",
        mediaType: "text/markdown; charset=utf-8",
        documentSchema: null,
        body: Buffer.from("line one\r\nline two\n")
      })
    ).toThrow(/LF line endings/u);
  });

  it("enforces media/schema pairing and the exact 10 MiB byte ceiling", () => {
    expect(() =>
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "Missing schema",
        mediaType: "application/json",
        documentSchema: null,
        body: Buffer.from("{}")
      })
    ).toThrow(/document schema is required/u);
    expect(() =>
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "Invalid schema",
        mediaType: "application/json",
        documentSchema: "unversioned",
        body: Buffer.from("{}")
      })
    ).toThrow(/versioned boardagent identifier/u);
    expect(() =>
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "Forbidden schema",
        mediaType: "text/plain; charset=utf-8",
        documentSchema: "boardagent.text.v1",
        body: Buffer.from("text")
      })
    ).toThrow(/allowed only for application\/json/u);
    expect(() =>
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "Empty",
        mediaType: "text/plain; charset=utf-8",
        documentSchema: null,
        body: Buffer.alloc(0)
      })
    ).toThrow(/cannot be empty/u);
    expect(() =>
      prepareDocumentContribution({
        organizationId: "018f0000-0000-7000-8000-000000000003",
        boardId,
        documentId,
        title: "Too large",
        mediaType: "text/plain; charset=utf-8",
        documentSchema: null,
        body: Buffer.alloc(10 * 1024 * 1024 + 1, 0x61)
      })
    ).toThrow(/10 MiB/u);
  });

  it("returns the exact validation contract for schema and offered-byte failures", () => {
    const cases = [
      {
        input: {
          mediaType: "application/json",
          documentSchema: null,
          body: Buffer.from("{}")
        },
        expected: {
          code: "document_schema_required",
          message: "a versioned document schema is required for application/json",
          remediation: "Supply a schema identifier such as boardagent.board-pack.v1."
        }
      },
      {
        input: {
          mediaType: "application/json",
          documentSchema: "unversioned",
          body: Buffer.from("{}")
        },
        expected: {
          code: "document_schema_invalid",
          message: "document schema must be a versioned boardagent identifier",
          remediation: "Use boardagent.<name>.v<number>."
        }
      },
      {
        input: {
          mediaType: "text/plain; charset=utf-8",
          documentSchema: "boardagent.text.v1",
          body: Buffer.from("text")
        },
        expected: {
          code: "document_schema_forbidden",
          message: "document schema is allowed only for application/json",
          remediation: "Remove documentSchema for Markdown or plain text."
        }
      },
      {
        input: {
          mediaType: "text/plain; charset=utf-8",
          documentSchema: null,
          body: Buffer.alloc(0)
        },
        expected: {
          code: "document_empty",
          message: "canonical document content cannot be empty",
          remediation: "Submit at least one UTF-8 content byte."
        }
      },
      {
        input: {
          mediaType: "text/plain; charset=utf-8",
          documentSchema: null,
          body: Buffer.alloc(10 * 1024 * 1024 + 1, 0x61)
        },
        expected: {
          code: "document_too_large",
          message: "document content exceeds the exact 10 MiB limit",
          remediation: "Split the machine-readable source into separately governed documents."
        }
      }
    ] as const;

    for (const { input, expected } of cases) {
      const error = captureDocumentError(() =>
        prepareDocumentContribution({
          organizationId,
          boardId,
          documentId,
          title: "Rejected source",
          ...input
        })
      );
      expect(error).toMatchObject({ name: "DocumentValidationError", ...expected });
    }
  });

  it("accepts the exact byte ceiling and preserves plain text semantics", () => {
    const atLimit = prepareDocumentContribution({
      organizationId,
      boardId,
      documentId,
      title: "Exact limit",
      mediaType: "text/plain; charset=utf-8",
      documentSchema: null,
      body: Buffer.alloc(10 * 1024 * 1024, 0x61)
    });
    expect(atLimit.offeredByteLength).toBe(10 * 1024 * 1024);
    expect(atLimit.byteLength).toBe(10 * 1024 * 1024);
    expect(atLimit.canonicalText).toHaveLength(10 * 1024 * 1024);

    const plain = prepareDocumentContribution({
      organizationId,
      boardId,
      documentId,
      title: "Plain source",
      mediaType: "text/plain; charset=utf-8",
      documentSchema: null,
      body: Buffer.from("not-json")
    });
    expect(plain.canonicalText).toBe("not-json");
    expect(plain.documentSchema).toBeNull();
  });

  it("requires a supported version as well as complete schema grammar", () => {
    expect(() =>
      prepareDocumentContribution({
        organizationId,
        boardId,
        documentId,
        title: "Version 12",
        mediaType: "application/json",
        documentSchema: "boardagent.board_pack-2.v12",
        body: Buffer.from("{}")
      })
    ).toThrow(/not in the supported versioned catalog/u);

    for (const documentSchema of [
      "xboardagent.board-pack.v1",
      "boardagent.board-pack.v1x",
      "boardagent.board-pack.v"
    ]) {
      expect(
        captureDocumentError(() =>
          prepareDocumentContribution({
            organizationId,
            boardId,
            documentId,
            title: "Invalid schema grammar",
            mediaType: "application/json",
            documentSchema,
            body: Buffer.from("{}")
          })
        )
      ).toMatchObject({ code: "document_schema_invalid" });
    }
  });
});
