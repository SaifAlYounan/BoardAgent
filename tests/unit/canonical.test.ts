import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  canonicalJsonFromText,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Bytes,
  sha256Hex
} from "../../lib/contracts/src/index.js";

describe("canonical JSON", () => {
  it("sorts object keys and produces stable hashes", () => {
    expect(canonicalJson({ z: 1, a: [true, null, "x"] })).toBe('{"a":[true,null,"x"],"z":1}');
    expect(canonicalSha256({ b: 2, a: 1 })).toBe(canonicalSha256({ a: 1, b: 2 }));
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, undefined, 1n])(
    "rejects non-contract value %s",
    (value) => {
      expect(() => canonicalJson({ value })).toThrow();
    }
  );

  it("uses the RFC 8785 number serialization while governance schemas remain integer-only", () => {
    expect(canonicalJson({ value: 1.5, negativeZero: -0 })).toBe('{"negativeZero":0,"value":1.5}');
  });

  it("compares only canonical SHA-256 hex", () => {
    const hash = canonicalSha256({ a: 1 });
    expect(safeHashEqual(hash, hash)).toBe(true);
    expect(safeHashEqual(hash, canonicalSha256({ a: 2 }))).toBe(false);
    expect(safeHashEqual("not-a-hash", hash)).toBe(false);
    expect(safeHashEqual(hash, "not-a-hash")).toBe(false);
    expect(Buffer.from(sha256Bytes("value")).toString("hex")).toBe(sha256Hex("value"));
  });

  it("accepts every strict JSON token and canonicalizes parsed text", () => {
    expect(canonicalJsonFromText(' { "z" : [true,false,null,1.5e1,"x\\n"], "a": {} } ')).toBe(
      '{"a":{},"z":[true,false,null,15,"x\\n"]}'
    );
    expect(canonicalJson(Object.assign(Object.create(null) as object, { a: 1 }))).toBe('{"a":1}');
    expect(canonicalJsonFromText("[]")).toBe("[]");
    expect(canonicalText(new TextEncoder().encode("valid\ntext"))).toBe("valid\ntext");
  });

  it.each([
    ['{"a":1} trailing', "trailing JSON bytes"],
    ['{"a":1,"a":2}', "duplicate object name"],
    ["{true}", "object name required"],
    ['{"a" 1}', "missing colon"],
    ['{"a":1 "b":2}', "missing comma"],
    ["[1 2]", "missing comma"],
    ['"unterminated', "unterminated JSON string"],
    [String.raw`"\x"`, "malformed JSON string"],
    ['"bad\u0001control"', "unescaped control character"],
    ["-", "malformed JSON number"],
    ["1e999", "finite JSON number"],
    ["tru", "malformed JSON literal"],
    ["?", "invalid JSON value"],
    ["\ufeff{}", "byte-order mark"]
  ])("rejects strict JSON text %j", (source, message) => {
    expect(() => canonicalJsonFromText(source)).toThrow(message);
  });

  it("rejects invalid UTF-8, Unicode, line endings, prototypes and non-JSON values", () => {
    const invalidUtf8 = Uint8Array.from([0xc3, 0x28]);
    expect(() => canonicalJsonFromText(invalidUtf8)).toThrow("strict UTF-8");
    expect(() => canonicalText(invalidUtf8)).toThrow("strict UTF-8");
    expect(() => canonicalText("\ufefftext")).toThrow("byte-order mark");
    expect(() => canonicalText("a\r\nb")).toThrow("LF line endings");
    expect(() => canonicalText("e\u0301")).toThrow("Unicode NFC");
    expect(() => canonicalJson("\ud800")).toThrow("unpaired surrogate");
    expect(() => canonicalJson("\udc00")).toThrow("unpaired surrogate");
    expect(canonicalJson("\ud83d\ude00")).toBe('"😀"');
    expect(() => canonicalJson(new Date())).toThrow("plain JSON object");
    expect(() => canonicalJson({ value: undefined })).toThrow("cannot be undefined");
    expect(() => canonicalJson(Symbol("value"))).toThrow("not a JSON value");
  });
});
