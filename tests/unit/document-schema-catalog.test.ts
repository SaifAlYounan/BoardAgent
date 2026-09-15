import { describe, expect, it } from "vitest";
import { prepareDocumentContribution } from "../../lib/domain/src/document.js";

const pack = {
  schemaVersion: "boardagent.board-pack.v1",
  title: "Quarterly operations",
  sections: [{ heading: "Resolution", body: "Approve the exploration programme." }]
};
const prepare = (body: unknown, schema = "boardagent.board-pack.v1") =>
  prepareDocumentContribution({
    organizationId: "018f0000-0000-7000-8000-000000000001",
    boardId: "018f0000-0000-7000-8000-000000000002",
    documentId: "018f0000-0000-7000-8000-000000000003",
    title: "Board pack",
    mediaType: "application/json",
    documentSchema: schema,
    body: Buffer.from(JSON.stringify(body))
  });

describe("versioned JSON document catalog", () => {
  it.each(["xboardagent.board-pack.v1", "boardagent.board-pack.v1!"])(
    "distinguishes malformed identifier %s from an unsupported catalog version",
    (schema) => {
      expect(() => prepare(pack, schema)).toThrowError(
        expect.objectContaining({
          code: "document_schema_invalid",
          message: "document schema must be a versioned boardagent identifier",
          remediation: "Use boardagent.<name>.v<number>."
        })
      );
    }
  );
  it("tells the agent how to repair an unknown schema or an invalid body", () => {
    expect(() => prepare(pack, "boardagent.unknown.v1")).toThrowError(
      expect.objectContaining({
        code: "document_schema_invalid",
        message: "document schema is not in the supported versioned catalog",
        remediation:
          "Use a supported JSON document schema: boardagent.board-pack.v1, boardagent.minutes-comment.v1, boardagent.minutes-redline.v1; or submit canonical Markdown/plain text."
      })
    );
    expect(() => prepare({})).toThrowError(
      expect.objectContaining({
        code: "document_schema_invalid",
        message: "document body does not match its declared versioned schema",
        remediation:
          "Follow the documented boardagent.board-pack.v1 format, including its exact schemaVersion and required fields; rejected bytes were not retained."
      })
    );
  });

  it("accepts a declared typed board pack and preserves its canonical semantic bytes", () => {
    const prepared = prepare(pack);
    expect(JSON.parse(Buffer.from(prepared.canonicalBytes).toString("utf8"))).toEqual(pack);
  });
  it("validates the existing minutes comment and redline formats without executing them", () => {
    const base = {
      minutesId: "018f0000-0000-7000-8000-000000000009",
      baseVersion: 1,
      baseSha256: "a".repeat(64),
      citations: []
    };
    const comment = {
      ...base,
      schemaVersion: "boardagent.minutes-comment.v1",
      comment: "Please clarify the permit date."
    };
    const redline = {
      ...base,
      schemaVersion: "boardagent.minutes-redline.v1",
      anchor: { kind: "lines", startLine: 2, endLine: 2 },
      anchoredTextSha256: "b".repeat(64),
      operation: "replace",
      proposedText: "Permit due 30 September.",
      rationale: "Correct the recorded date."
    };
    for (const body of [comment, redline]) {
      expect(JSON.parse(prepare(body, body.schemaVersion).canonicalText)).toEqual(body);
      expect(() => prepare({ ...body, baseVersion: 0 }, body.schemaVersion)).toThrowError(
        expect.objectContaining({ code: "document_schema_invalid" })
      );
    }
    expect(() => prepare({ ...redline, operation: "delete" }, redline.schemaVersion)).toThrowError(
      expect.objectContaining({ code: "document_schema_invalid" })
    );
    expect(() => prepare(comment, "boardagent.minutes-redline.v1")).toThrowError(
      expect.objectContaining({ code: "document_schema_invalid" })
    );
  });
  it.each([
    {},
    { a: 1 },
    { ...pack, schemaVersion: "boardagent.board-pack.v2" },
    { ...pack, title: 7 },
    { ...pack, sections: [] },
    { ...pack, extra: true },
    { ...pack, sections: [{ heading: "Resolution", body: 42 }] },
    { ...pack, sections: [{ heading: "Resolution", body: "Text", secretAuthority: "admin" }] }
  ])("rejects a mismatched or malformed known body before producing canonical content", (body) => {
    expect(() => prepare(body)).toThrowError(
      expect.objectContaining({ code: "document_schema_invalid" })
    );
  });
  it.each(["boardagent.board_pack-2.v12", "boardagent.board-pack.v2", "boardagent.unknown.v1"])(
    "rejects unknown declared schema %s",
    (schema) => {
      expect(() => prepare(pack, schema)).toThrowError(
        expect.objectContaining({ code: "document_schema_invalid" })
      );
    }
  );
});
