import { describe, expect, it } from "vitest";

import { createStructuredLogger } from "../../lib/config/src/index.js";

describe("security-safe structured logging", () => {
  it("emits deterministic JSON with keyed pseudonyms instead of raw identities", () => {
    const lines: string[] = [];
    const logger = createStructuredLogger({
      pseudonymKey: "test-only-pseudonym-key-with-32-bytes",
      service: "server",
      clock: () => new Date("2026-08-30T00:00:00.000Z"),
      sink: (line) => lines.push(line)
    });
    logger.write({
      level: "info",
      event: "mcp.request.completed",
      requestId: "req_123",
      principalId: "member-secret-id",
      clientId: "client-secret-id",
      result: "success",
      surface: "list_documents",
      durationMs: 17,
      count: 2
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain("member-secret-id");
    expect(lines[0]).not.toContain("client-secret-id");
    expect(JSON.parse(lines[0] as string)).toMatchObject({
      schemaVersion: 1,
      timestamp: "2026-08-30T00:00:00.000Z",
      service: "server",
      event: "mcp.request.completed",
      requestId: "req_123",
      result: "success",
      surface: "list_documents",
      durationMs: 17,
      count: 2
    });
  });

  it("rejects unknown fields so free text cannot leak through the logger", () => {
    const logger = createStructuredLogger({
      pseudonymKey: "test-only-pseudonym-key-with-32-bytes",
      service: "server",
      clock: () => new Date(0),
      sink: () => undefined
    });
    expect(() =>
      logger.write({
        level: "info",
        event: "unsafe",
        result: "success",
        documentText: "confidential board text"
      } as never)
    ).toThrow();
  });
});
