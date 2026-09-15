import { describe, expect, it } from "vitest";

import { postgresScramVerifier } from "../../scripts/src/database-principals.js";

describe("database principal SCRAM verifier", () => {
  it("is deterministic for an injected salt and contains no plaintext password", () => {
    const password = Buffer.from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", "utf8");
    const verifier = postgresScramVerifier(password, Buffer.alloc(16, 0x51));
    expect(verifier).toBe(
      "SCRAM-SHA-256$4096:UVFRUVFRUVFRUVFRUVFRUQ==$JJJKATLgVV0vhvxTHOVvXRWrZkT0DIdPYu2LTQW94Us=:n4H9K0nuTkYYSzj6F1GwL+DwmxHUfRWiGaWIxtvodWc="
    );
    expect(verifier).not.toContain(password.toString("utf8"));
  });

  it("refuses weak-length password material and malformed salt", () => {
    expect(() => postgresScramVerifier(Buffer.alloc(42), Buffer.alloc(16))).toThrow(
      "invalid length"
    );
    expect(() => postgresScramVerifier(Buffer.alloc(43), Buffer.alloc(15))).toThrow("exactly 16");
  });
});
