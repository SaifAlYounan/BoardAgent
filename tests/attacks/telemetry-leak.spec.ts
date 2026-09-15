import { describe, expect, it } from "vitest";

import { createStructuredLogger } from "../../lib/config/src/logger.js";

describe("TH-41 telemetry confidentiality", () => {
  it("pseudonymizes identities and refuses content or secret-shaped extension fields", () => {
    const lines: string[] = [];
    const logger = createStructuredLogger({
      pseudonymKey: Buffer.alloc(32, 0x42),
      service: "server",
      clock: () => new Date("2026-09-04T00:00:00Z"),
      sink: (line) => lines.push(line)
    });
    logger.write({
      level: "warn",
      event: "authorization.denied",
      principalId: "member-raw-secret",
      clientId: "client-raw-secret",
      result: "denied",
      reasonCode: "object.absent"
    });
    expect(lines[0]).not.toContain("member-raw-secret");
    expect(lines[0]).not.toContain("client-raw-secret");
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      result: "denied",
      reasonCode: "object.absent"
    });
    expect(() =>
      logger.write({
        level: "error",
        event: "unsafe",
        result: "error",
        documentText: "board-confidential",
        accessToken: "bearer-secret"
      } as never)
    ).toThrow();
  });
});
