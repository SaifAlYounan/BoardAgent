import canonicalize from "canonicalize";
import { expect, it } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/index.js";

it("preserves UTF-16 order, integer-index boundaries and Unicode bytes at every depth", () => {
  const special = Object.assign(Object.create(null) as object, {
    "2": "two",
    "10": "ten",
    "0": -0,
    "01": "leading",
    "-0": "negative",
    "4294967294": "last index",
    "4294967295": "ordinary",
    "😀": "Ω",
    é: "é",
    "\u2028": "\u2029",
    "\u0000": '\n\t"\\'
  });
  Object.defineProperty(special, "__proto__", { value: "data", enumerable: true });
  for (const value of [
    special,
    { z: [{ child: special }], a: {} },
    { details: { z: true, a: null }, schemaVersion: 1 }
  ])
    expect(canonicalJson(value)).toBe(canonicalize(value));
  for (const value of [
    { nested: { "e\u0301": true } },
    { nested: ["e\u0301"] },
    { nested: ["\ud800"] },
    { nested: ["\udc00"] },
    { nested: [Infinity] }
  ])
    expect(() => canonicalJson(value)).toThrow();
});

it("keeps legacy serialization for nested methods, accessors and sparse arrays", () => {
  const method = { original: true };
  Object.defineProperty(method, "toJSON", {
    value: () => ({ "2": 2, "10": 10 }),
    enumerable: false
  });
  const getter = Object.defineProperty({}, "answer", { get: () => 42, enumerable: true });
  const arrayMethod = [1, 2];
  Object.defineProperty(arrayMethod, "toJSON", {
    value: () => ({ replacement: true }),
    enumerable: false
  });
  const arrayGetter = [1];
  Object.defineProperty(arrayGetter, "0", { get: () => 42, enumerable: true });
  const sparse: unknown[] = [];
  sparse.length = 2;
  sparse[1] = true;
  for (const value of [{ nested: method }, { nested: getter }, arrayMethod, arrayGetter, sparse])
    expect(canonicalJson(value)).toBe(canonicalize(value));
});

it("preserves errors from a non-enumerable serializer accessor", () => {
  const value = { original: true };
  const failure = new Error("serializer unavailable");
  Object.defineProperty(value, "toJSON", {
    get: () => {
      throw failure;
    },
    enumerable: false
  });
  expect(() => canonicalJson(value)).toThrow(failure);
  expect(() => canonicalize(value)).toThrow(failure);
});
