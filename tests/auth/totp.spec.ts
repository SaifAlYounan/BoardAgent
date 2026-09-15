import { describe, expect, it } from "vitest";

import {
  encodeTotpSecret,
  generateTotpCode,
  generateTotpCodeFromBase32
} from "../../artifacts/server/src/index.js";

describe("RFC 6238 TOTP", () => {
  it.each([
    [59, "287082"],
    [1_111_111_109, "081804"],
    [1_111_111_111, "050471"],
    [1_234_567_890, "005924"],
    [2_000_000_000, "279037"],
    [20_000_000_000, "353130"]
  ])("matches the SHA-1 RFC vector at %i seconds", (unixSeconds, expected) => {
    const secret = Buffer.from("12345678901234567890", "ascii");
    expect(generateTotpCode(secret, unixSeconds)).toBe(expected);
  });

  it("uses canonical unpadded Base32 and rejects aliases or invalid time", () => {
    const secret = Buffer.from("12345678901234567890", "ascii");
    const encoded = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    expect(encodeTotpSecret(secret)).toBe(encoded);
    expect(generateTotpCodeFromBase32(encoded, 59)).toBe("287082");
    expect(() => generateTotpCodeFromBase32(encoded.toLowerCase(), 59)).toThrow("canonical Base32");
    expect(() => generateTotpCodeFromBase32(`${encoded}=`, 59)).toThrow("canonical Base32");
    expect(() => generateTotpCode(secret, -1)).toThrow("TOTP time");
    expect(() => generateTotpCode(secret, 59.5)).toThrow("TOTP time");
  });
});
