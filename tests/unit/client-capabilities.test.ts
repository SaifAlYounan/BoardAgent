import { describe, expect, it } from "vitest";

import {
  parseClientCapabilities,
  supportsFormElicitation
} from "../../artifacts/server/src/client-capabilities.js";

function nested(depth: number): unknown {
  let value: unknown = null;
  for (let index = 0; index < depth; index += 1) value = [value];
  return value;
}

describe("client capability JSON admission", () => {
  it("preserves ordinary capability metadata and the existing scalar validation", () => {
    const value = { elicitation: { form: {} }, experimental: { version: 0.125 } };
    expect(parseClientCapabilities(value)).toEqual({ success: true, data: value });
    expect(parseClientCapabilities(nested(16)).success).toBe(true);
    expect(parseClientCapabilities({ value: Infinity }).success).toBe(false);
  });

  it("accepts 512 containers and returns a controlled error for 513", () => {
    expect(parseClientCapabilities(nested(512)).success).toBe(true);
    const result = parseClientCapabilities(nested(513));
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.issues[0]?.message).toContain("exceeds 512");
  });

  it("rejects 5000 nested containers and accepts the next ordinary value", () => {
    const result = parseClientCapabilities(nested(5_000));
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.issues[0]?.message).toContain("exceeds 512");
    const next = { elicitation: { form: {} } };
    expect(parseClientCapabilities(next)).toEqual({ success: true, data: next });
  });

  it("rejects a direct cycle without rejecting shared acyclic objects", () => {
    const value: Record<string, unknown> = {};
    value["self"] = value;
    const result = parseClientCapabilities(value);
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.issues[0]?.message).toContain("JSON cycle");
    const shared = {};
    expect(parseClientCapabilities({ one: shared, two: shared }).success).toBe(true);
  });

  it("preserves unrelated programmer errors", () => {
    const failure = new RangeError("synthetic capability getter failure");
    const value = Object.defineProperty({}, "experimental", {
      enumerable: true,
      get: () => {
        throw failure;
      }
    });
    let caught: unknown;
    try {
      parseClientCapabilities(value);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(failure);
  });
});

describe("form elicitation capability resolution", () => {
  it.each([
    [{ elicitation: { form: {} } }, true],
    [{ elicitation: { form: {}, url: {} } }, true],
    // The spec's backwards-compatible empty object means form mode.
    [{ elicitation: {} }, true],
    [{ elicitation: { url: {} } }, false],
    [{}, false],
    [{ elicitation: null }, false],
    [{ elicitation: [] }, false],
    [{ elicitation: "form" }, false],
    [[], false],
    [null, false]
  ] as const)("resolves %j to form support %s", (capabilities, supported) => {
    expect(supportsFormElicitation(capabilities)).toBe(supported);
  });
});
