import { describe, expect, it } from "vitest";
import { Rfc3339UtcSchema } from "../../lib/contracts/src/schemas.js";

describe("UTC calendar input integrity", () => {
  it.each([
    "2000-02-29T00:00:00Z",
    "2028-02-29T12:34:56.1Z",
    "2400-02-29T23:59:59.123456Z",
    "0099-12-31T23:59:59.000001Z",
    "2026-04-30T23:59:59Z"
  ])("preserves the exact valid timestamp %s", (value) => {
    expect(Rfc3339UtcSchema.parse(value)).toBe(value);
  });

  it.each([
    "2026-02-30T12:00:00Z",
    "2026-02-29T12:00:00Z",
    "1900-02-29T12:00:00Z",
    "2100-02-29T12:00:00Z",
    "2026-04-31T12:00:00Z",
    "2026-06-31T12:00:00Z",
    "2026-09-31T12:00:00Z",
    "2026-11-31T12:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-00-01T12:00:00Z",
    "2026-13-01T12:00:00Z",
    "2026-01-00T12:00:00Z",
    "2026-01-32T12:00:00Z",
    "2026-01-01T12:60:00Z",
    "2026-01-01T12:00:60Z",
    "2026-01-01T12:00:00.1234567Z",
    "2026-01-01T12:00:00+00:00"
  ])("refuses normalization or unsupported timestamp %s", (value) => {
    expect(Rfc3339UtcSchema.safeParse(value).success).toBe(false);
  });
});
