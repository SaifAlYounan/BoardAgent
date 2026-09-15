import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { inspectProposalPayload } from "../../artifacts/server/src/proposal-payload-inspection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable
} from "../../artifacts/server/src/response-allocation.js";

function binding(bytes: Uint8Array) {
  return {
    canonicalBytes: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}

// Parser units provide an actual live owner context. Reservation-before-byte-load,
// incremental admission and native settlement belong to the caller's integration tests.
function inspect(source: string | Uint8Array) {
  const bytes = typeof source === "string" ? Buffer.from(source, "utf8") : source;
  const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
  return owner.run(() => inspectProposalPayload(bytes, binding(bytes)));
}

describe("private proposal payload inspection", () => {
  it("requires a native owner before parsing", () => {
    const parse = vi.spyOn(JSON, "parse");
    try {
      const bytes = Buffer.from("null");
      expect(() => inspectProposalPayload(bytes, binding(bytes))).toThrow(
        "native response allocation owner is required"
      );
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it.each(["aborted", "terminal"])("refuses an %s owner before parsing", (state) => {
    const controller = new AbortController();
    const owner = new ResponseAllocationManager().openRequest(controller.signal);
    if (state === "aborted") controller.abort();
    else owner.nativeTerminal();
    const parse = vi.spyOn(JSON, "parse");
    try {
      const bytes = Buffer.from("null");
      expect(() => owner.run(() => inspectProposalPayload(bytes, binding(bytes)))).toThrow(
        ResponseAllocationUnavailable
      );
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it.each(["length", "digest"])("checks exact %s before parsing", (field) => {
    const bytes = Buffer.from('{"ok":true}');
    const expected = binding(bytes);
    if (field === "length") expected.canonicalBytes += 1;
    else expected.sha256 = "0".repeat(64);
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    const parse = vi.spyOn(JSON, "parse");
    try {
      expect(() => owner.run(() => inspectProposalPayload(bytes, expected))).toThrow(
        "proposal payload integrity mismatch"
      );
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it.each([
    Buffer.from([0x22, 0xc0, 0xaf, 0x22]),
    Buffer.from("\ufeffnull", "utf8"),
    Buffer.from('{"a":}'),
    Buffer.from("1e400"),
    Buffer.from('"\\ud800"'),
    Buffer.from('{"\\udfff":0}'),
    Buffer.from('"e\\u0301"'),
    Buffer.from('{"e\\u0301":0}')
  ])("refuses unsupported syntax, decoding or surviving values %#", (bytes) => {
    expect(() => inspect(bytes)).toThrow(ResponseAllocationUnavailable);
  });

  it("admits exactly 512 raw containers and measures the surviving graph", () => {
    const measured = inspect("[".repeat(512) + "0" + "]".repeat(512));
    expect(measured).toMatchObject({
      jsonBytesUpper: "1025",
      properties: "0",
      containers: "512",
      maxDepth: 512
    });
  });

  it.each([
    "[".repeat(513) + "0" + "]".repeat(513),
    '{"x":' + "[".repeat(512) + "0" + "]".repeat(512) + ',"x":0}'
  ])("refuses raw excess depth before JSON.parse, including overwritten branches %#", (source) => {
    const parse = vi.spyOn(JSON, "parse");
    try {
      expect(() => inspect(source)).toThrow(ResponseAllocationUnavailable);
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it("ignores quoted delimiters with both escaped quotes and backslashes", () => {
    const text = '[{\\"' + "[".repeat(600) + '\\"}]';
    const source = JSON.stringify({ text, sibling: [] });
    const measured = inspect(source);
    expect(measured.value).toEqual({ text, sibling: [] });
    expect(measured.maxDepth).toBe(2);
  });

  it("retains native duplicate, numeric-key and finite numeric semantics", () => {
    const source = ' {"x":1e400,"x":1,"y":1e-1000,"n":-0,"01":2,"1":3,"10":4} ';
    const measured = inspect(source);
    expect(measured.value).toEqual(JSON.parse(source));
    expect(JSON.stringify(measured.value)).toBe('{"1":3,"10":4,"x":1,"y":0,"n":0,"01":2}');
    expect(measured.properties).toBe("6");
  });

  it("admits JSON NUL and keeps __proto__ as a payload property", () => {
    const source = '{"\\u0000":"\\u0000","__proto__":{"marker":true}}';
    const measured = inspect(source);
    expect(measured.value).toEqual(JSON.parse(source));
    expect(Object.hasOwn(measured.value as object, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(measured.value)).toBe(Object.prototype);
    expect(Object.hasOwn(Object.prototype, "marker")).toBe(false);
  });

  it("counts exact compact number syntax without PostgreSQL decimal expansion", () => {
    const source = "[1e+308,5e-324,1e20,1e-6,9007199254740993,-0,true,false,null]";
    const measured = inspect(source);
    expect(measured.value).toEqual(JSON.parse(source));
    expect(BigInt(measured.jsonBytesUpper)).toBe(
      BigInt(Buffer.byteLength(JSON.stringify(measured.value), "utf8"))
    );
  });

  it("counts every property and container in a manually enumerated nested vector", () => {
    const measured = inspect('{"a":[true,null,{"b":"é"}],"c":0}');
    expect(measured).toMatchObject({ properties: "3", containers: "3", maxDepth: 3 });
    expect(BigInt(measured.jsonBytesUpper)).toBeGreaterThanOrEqual(
      BigInt(Buffer.byteLength(JSON.stringify(measured.value), "utf8"))
    );
  });

  it("bounds independently encoded adversarial strings and both nested response copies", () => {
    const controls = Array.from({ length: 128 }, (_, index) => String.fromCharCode(index)).join("");
    const unicode = "é漢😀\u2028\u2029\u{10ffff}";
    const value = Object.fromEntries(
      Array.from({ length: 32 }, (_, index) => [
        `${String(index)}"\\\u0000`,
        [controls.repeat(index + 1), unicode.repeat(index + 1), false, null]
      ])
    );
    const measured = inspect(JSON.stringify(value));
    expect(measured.value).toEqual(value);
    expect(measured).toMatchObject({ properties: "32", containers: "33", maxDepth: 2 });
    const encoded = JSON.stringify(measured.value);
    const oracleBytes = BigInt(Buffer.byteLength(encoded, "utf8"));
    expect(BigInt(measured.jsonBytesUpper)).toBeGreaterThanOrEqual(oracleBytes);
    // Independent native encoding oracle for a structured copy plus its text copy.
    const nested = JSON.stringify({ structuredContent: value, text: encoded });
    expect(BigInt(Buffer.byteLength(nested, "utf8"))).toBeLessThanOrEqual(
      128n + 3n * BigInt(measured.jsonBytesUpper)
    );
  });

  it("reaches the escaping lower bound for NUL strings", () => {
    const measured = inspect(JSON.stringify("\u0000".repeat(1024)));
    expect(BigInt(measured.jsonBytesUpper)).toBe(
      BigInt(Buffer.byteLength(JSON.stringify(measured.value), "utf8"))
    );
  });

  it("does not introduce a document-size ceiling on the proposal parser", () => {
    const source = '"' + "x".repeat(10_485_759) + '"';
    expect(Buffer.byteLength(source)).toBe(10_485_761);
    const measured = inspect(source);
    expect(typeof measured.value).toBe("string");
    expect(measured).toMatchObject({ properties: "0", containers: "0", maxDepth: 0 });
  });
});
