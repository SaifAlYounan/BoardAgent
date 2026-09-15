import canonicalize from "canonicalize";
import fc from "fast-check";
import { expect, it } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/index.js";

it("matches the original encoder for 10000 nested JSON values", () => {
  fc.assert(
    fc.property(fc.jsonValue(), (value) => {
      expect(canonicalJson(value)).toBe(canonicalize(value));
    }),
    { seed: 0x4e415449, numRuns: 10000, endOnFailure: true }
  );
});
