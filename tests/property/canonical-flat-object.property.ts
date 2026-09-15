import canonicalize from "canonicalize";
import fc from "fast-check";
import { expect, it } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/index.js";

it("preserves legacy canonical bytes for 10000 scalar maps, including numeric keys and Unicode", () => {
  const scalar = fc.oneof(
    fc.constant(null),
    fc.boolean(),
    fc.double({ noNaN: true, noDefaultInfinity: true }),
    fc.stringMatching(/^[A-Za-z0-9 _-]{0,64}$/u),
    fc.constantFrom("Ω", "😀", "é", '\n\t"\\', "")
  );
  fc.assert(
    fc.property(fc.dictionary(fc.stringMatching(/^[a-z0-9]{1,16}$/u), scalar), (value) => {
      expect(canonicalJson(value)).toBe(canonicalize(value));
    }),
    { seed: 0x43464c41, numRuns: 10000, endOnFailure: true }
  );
  for (const value of [
    { "2": "second", "10": "tenth", "0": -0, "😀": "Ω", é: null },
    { nested: { "2": 2, "10": 10 }, array: [null, { z: "😀", a: true }] },
    Object.assign(Object.create(null) as object, { "2": 2, "10": 10 })
  ])
    expect(canonicalJson(value)).toBe(canonicalize(value));
  for (const value of [
    { text: "e\u0301" },
    { text: "\ud800" },
    { text: "\udc00" },
    { value: Infinity },
    { value: undefined }
  ])
    expect(() => canonicalJson(value)).toThrow();
});

// JSON data cannot carry methods, but internal callers historically could supply a
// non-enumerable serializer. Preserve the general encoder's replacement behavior.
it("preserves the original encoding for a non-enumerable serialization method", () => {
  const value = { original: true };
  Object.defineProperty(value, "toJSON", {
    value: () => ({ replacement: true }),
    enumerable: false
  });
  expect(canonicalJson(value)).toBe('{"replacement":true}');
  expect(canonicalJson(value)).toBe(canonicalize(value));
});
