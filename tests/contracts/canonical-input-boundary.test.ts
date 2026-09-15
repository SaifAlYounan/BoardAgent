import { describe, expect, it } from "vitest";

import {
  CanonicalizationError,
  canonicalJson,
  canonicalJsonFromText,
  canonicalText,
  MAX_JSON_CONTAINER_DEPTH,
  parseTranscriptAnnex,
  TOOL_INPUT_SCHEMAS,
  toolInputSchema
} from "../../lib/contracts/src/index.js";
import {
  DocumentValidationError,
  prepareDocumentContribution
} from "../../lib/domain/src/document.js";

const DEPTH = 5_000;
const A = "018f0000-0000-7000-8000-000000000001";
const B = "018f0000-0000-7000-8000-000000000002";
const COMMON = {
  schema_version: "boardagent.tool-input.v1",
  idempotency_key: "canonical-depth-regression-0001"
};

function nested(value: unknown, depth: number): unknown {
  let result = value;
  for (let index = 0; index < depth; index += 1) result = [result];
  return result;
}

function deeplyInvalidJson(): string {
  // This is always invalid JSON under the existing duplicate-name contract.
  // The test does not introduce a new allowed nesting threshold.
  return "[".repeat(DEPTH) + '{"x":1,"x":2}' + "]".repeat(DEPTH);
}

function document(body: Uint8Array, mediaType = "application/json") {
  return prepareDocumentContribution({
    organizationId: A,
    boardId: B,
    documentId: A,
    title: "Synthetic parser boundary",
    mediaType,
    documentSchema: mediaType === "application/json" ? "boardagent.board-pack.v1" : null,
    body
  });
}

const RECURSIVE_TOOLS = [
  "evaluate_matter",
  "configure_board_governance",
  "publish_secretary_support"
] as const;

function toolInput(tool: (typeof RECURSIVE_TOOLS)[number], value: unknown) {
  return tool === "evaluate_matter"
    ? {
        ...COMMON,
        board_id: A,
        matter_type_id: B,
        expected_profile_id: B,
        expected_ruleset_id: B,
        facts: { schema_version: "boardagent.facts.v1", values: { item: value } }
      }
    : tool === "configure_board_governance"
      ? {
          ...COMMON,
          board_id: A,
          expected_profile_id: null,
          reason: "Synthetic depth boundary",
          citations: [
            { document_version_id: B, sha256: "a".repeat(64), clause: "1", locator: "1" }
          ],
          profile: {
            schema_version: "boardagent.governance-profile.v1",
            values: { item: value }
          }
        }
      : {
          ...COMMON,
          board_id: A,
          version_id: B,
          support_name: "Synthetic support",
          contact_methods: [value],
          reason: "Synthetic depth boundary"
        };
}

describe("WF-04 untrusted canonical nesting", () => {
  it("keeps an ordinary nested canonical value valid", () => {
    const value = nested({ a: true }, 16);
    const source = JSON.stringify(value);
    expect(canonicalJson(value)).toBe(source);
    expect(canonicalJsonFromText(source)).toBe(source);
  });

  it("rejects deeply nested duplicate names with the canonical error type", () => {
    const source = deeplyInvalidJson();
    expect(Buffer.byteLength(source)).toBeLessThan(32_768);
    expect(() => canonicalJsonFromText(source)).toThrow(CanonicalizationError);
  });

  it("rejects a deeply nested non-JSON value with the canonical error type", () => {
    expect(() => canonicalJson(nested(Infinity, DEPTH))).toThrow(CanonicalizationError);
  });

  it("retains controlled document rejection for small deeply malformed JSON", () => {
    expect(() => document(Buffer.from(deeplyInvalidJson()))).toThrow(DocumentValidationError);
  });

  it("retains controlled transcript rejection for deeply malformed JSON", () => {
    expect(() => parseTranscriptAnnex("application/json", deeplyInvalidJson())).toThrow(
      CanonicalizationError
    );
  });

  it.each(RECURSIVE_TOOLS)(
    "%s safeParse must return a schema result for deep JSON rather than throw a stack error",
    (tool) => {
      const input = toolInput(tool, nested(null, DEPTH));
      // Either a supported parse or an explicit bounded rejection is acceptable.
      // A new depth number is an implementation decision, not invented by this test.
      expect(() => {
        const result = toolInputSchema(tool).safeParse(input);
        expect(typeof result.success).toBe("boolean");
      }).not.toThrow();
    }
  );
});

describe("JSON structural resource boundary", () => {
  it.each(["array", "object", "mixed"])(
    "accepts exactly 512 %s containers and rejects 513 before recursive processing",
    (shape) => {
      const makeValue = (depth: number) => {
        let value: unknown = null;
        for (let index = 0; index < depth; index += 1) {
          value =
            shape === "array" || (shape === "mixed" && index % 2 === 0) ? [value] : { item: value };
        }
        return value;
      };
      expect(MAX_JSON_CONTAINER_DEPTH).toBe(512);
      const accepted = makeValue(512);
      const source = JSON.stringify(accepted);
      expect(canonicalJson(accepted)).toBe(source);
      expect(canonicalJsonFromText(source)).toBe(source);
      const rejected = makeValue(513);
      expect(() => canonicalJson(rejected)).toThrow(/exceeds 512 nested containers/u);
      expect(() => canonicalJsonFromText(JSON.stringify(rejected))).toThrow(
        /exceeds 512 nested containers/u
      );
    }
  );

  it.each(RECURSIVE_TOOLS)(
    "%s includes the whole input envelope in the 512-container boundary",
    (tool) => {
      const envelopeDepth = tool === "publish_secretary_support" ? 2 : 3;
      const accepted = toolInput(tool, nested(null, 512 - envelopeDepth));
      expect(toolInputSchema(tool).safeParse(accepted).success).toBe(true);
      const rejected = toolInput(tool, nested(null, 513 - envelopeDepth));
      // Exercise the exported schema table too, so direct callers cannot skip admission.
      const result = TOOL_INPUT_SCHEMAS[tool].safeParse(rejected);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toEqual([
          expect.objectContaining({
            code: "custom",
            message: expect.stringContaining("exceeds 512")
          })
        ]);
      }
    }
  );

  it("does not count braces, brackets or escaped quotes inside strings as containers", () => {
    const source = JSON.stringify({ text: '\\"[{]}'.repeat(1_024) + "\\" });
    expect(canonicalJsonFromText(source)).toBe(source);
  });

  it("preserves wide and large shallow values within the existing byte limits", () => {
    const value = {
      body: "x".repeat(1_048_576),
      entries: Array.from({ length: 20_000 }, (_, index) => index)
    };
    const source = JSON.stringify(value);
    expect(canonicalJson(value)).toBe(source);
    expect(canonicalJsonFromText(source)).toBe(source);
    expect(
      toolInputSchema("evaluate_matter").safeParse(toolInput("evaluate_matter", value)).success
    ).toBe(true);
  });

  it("accepts shared acyclic subobjects", () => {
    const shared = { answer: [42] };
    const value = { first: shared, second: shared };
    expect(canonicalJson(value)).toBe(JSON.stringify(value));
    expect(
      toolInputSchema("evaluate_matter").safeParse(toolInput("evaluate_matter", value)).success
    ).toBe(true);
  });

  it.each(["array", "object"])(
    "rejects a direct %s ancestor cycle with a canonical error",
    (shape) => {
      const value: unknown[] | Record<string, unknown> = shape === "array" ? [] : {};
      if (Array.isArray(value)) value.push(value);
      else value["self"] = value;
      expect(() => canonicalJson(value)).toThrow(CanonicalizationError);
      expect(() => canonicalJson(value)).toThrow(/JSON cycle/u);
    }
  );

  it.each(RECURSIVE_TOOLS)("%s returns a structured error for an ancestor cycle", (tool) => {
    const value: Record<string, unknown> = {};
    value["self"] = value;
    const result = toolInputSchema(tool).safeParse(toolInput(tool, value));
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.issues[0]?.message).toContain("JSON cycle");
  });

  it("preserves unrelated programmer errors instead of classifying them as input limits", () => {
    const failure = new RangeError("synthetic getter failure");
    const value = Object.defineProperty({}, "schema_version", {
      enumerable: true,
      get: () => {
        throw failure;
      }
    });
    for (const run of [
      () => canonicalJson(value),
      () => toolInputSchema("whoami").safeParse(value)
    ]) {
      let caught: unknown;
      try {
        run();
      } catch (error) {
        caught = error;
      }
      expect(caught).toBe(failure);
    }
  });
});

describe("strict UTF-8 BOM rejection is independent of input representation", () => {
  it("retains valid BOM-free NFC text and JSON bytes", () => {
    expect(canonicalText(Buffer.from("Café\n"))).toBe("Café\n");
    expect(canonicalJsonFromText(Buffer.from('{"a":1}'))).toBe('{"a":1}');
  });

  it("rejects a leading UTF-8 BOM in text bytes just as in a string", () => {
    expect(() => canonicalText("\ufefftext")).toThrow(CanonicalizationError);
    expect(() => canonicalText(Buffer.from("\ufefftext"))).toThrow(CanonicalizationError);
  });

  it("rejects a leading UTF-8 BOM in JSON bytes just as in a string", () => {
    expect(() => canonicalJsonFromText('\ufeff{"a":1}')).toThrow(CanonicalizationError);
    expect(() => canonicalJsonFromText(Buffer.from('\ufeff{"a":1}'))).toThrow(
      CanonicalizationError
    );
  });

  it.each(["text/plain; charset=utf-8", "application/json"])(
    "rejects BOM-prefixed document bytes with media type %s",
    (mediaType) => {
      const body =
        mediaType === "application/json"
          ? '{"schemaVersion":"boardagent.board-pack.v1","title":"Synthetic","sections":[{"heading":"One","body":"Two"}]}'
          : "Synthetic text";
      expect(() => document(Buffer.from("\ufeff" + body), mediaType)).toThrow(
        DocumentValidationError
      );
    }
  );
});
