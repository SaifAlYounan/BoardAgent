import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  canonicalJsonFromText,
  canonicalText,
  CanonicalizationError
} from "../../lib/contracts/src/index.js";

describe("RFC 8785 JSON and canonical UTF-8 text", () => {
  it("matches the RFC 8785 serialization example", () => {
    expect(
      canonicalJson({
        // RFC 8785 §3.2.2 intentionally demonstrates IEEE-754 rounding of this token.
        // eslint-disable-next-line no-loss-of-precision
        numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
        string: '€$\u000f\nA\'B"\\"/',
        literals: [null, true, false]
      })
    ).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\"/"}'
    );
  });

  it.each(['{"a":1,"a":2}', '{"outer":{"x":1,"x":2}}', '{"\\u0061":1,"a":2}'])(
    "rejects duplicate object names before ordinary JSON parsing: %s",
    (source) => {
      expect(() => canonicalJsonFromText(source)).toThrow("duplicate object name");
    }
  );

  it("rejects malformed UTF-8, lone surrogates, non-finite numbers, and trailing bytes", () => {
    expect(() => canonicalJsonFromText(Uint8Array.from([0xc3, 0x28]))).toThrow(
      CanonicalizationError
    );
    expect(() => canonicalJsonFromText('{"value":"\\ud800"}')).toThrow("surrogate");
    expect(() => canonicalJsonFromText('{"value":1e400}')).toThrow("finite");
    expect(() => canonicalJsonFromText('{"value":1} garbage')).toThrow("trailing");
  });

  it("parses strict JSON and emits canonical server bytes", () => {
    expect(canonicalJsonFromText(' { "z": -0, "a": [3, 2, 1] } ')).toBe('{"a":[3,2,1],"z":0}');
  });

  it.each([
    ["decomposed Unicode", "Cafe\u0301"],
    ["CRLF", "line one\r\nline two"],
    ["byte-order mark", "\ufefftext"],
    ["lone surrogate", "bad\ud800text"]
  ])("rejects noncanonical %s text", (_label, source) => {
    expect(() => canonicalText(source)).toThrow(CanonicalizationError);
  });

  it("accepts exact NFC/LF text and fatal-decodes UTF-8", () => {
    const text = "Café\nBoardAgent";
    expect(canonicalText(new TextEncoder().encode(text))).toBe(text);
    expect(() => canonicalText(Uint8Array.from([0xe2, 0x28, 0xa1]))).toThrow(CanonicalizationError);
  });
});
