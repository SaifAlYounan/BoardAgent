import { describe, expect, it } from "vitest";
import { toolInputSchema } from "../../lib/contracts/src/surface-inputs.js";
import { z } from "zod";

const board = "018f0000-0000-7000-8000-000000000001";
const source = "018f0000-0000-7000-8000-000000000002";
const citations = [
  {
    document_version_id: source,
    sha256: "a".repeat(64),
    clause: "C1",
    locator: "Synthetic charter"
  }
];
const common = {
  schema_version: "boardagent.tool-input.v1",
  board_id: board,
  idempotency_key: "governance-envelope-regression",
  citations
};

describe("MCP governance document envelopes", () => {
  it("transports the existing governance profile's camelCase canonical fields", () => {
    const value = {
      ...common,
      expected_profile_id: null,
      reason: "Activate the cited profile",
      profile: {
        schema_version: "boardagent.governance-profile.v1",
        values: {
          schemaVersion: "boardagent.governance-profile.v1",
          boardId: board,
          supersedesId: null,
          sourceAgreements: [{ sourceDocumentVersionId: source }],
          seats: [],
          templates: []
        }
      }
    };
    expect(() => toolInputSchema("configure_board_governance").parse(value)).not.toThrow();
  });
  it.each(["manage_ruleset", "validate_ruleset_draft"])(
    "transports canonical ruleset fields through %s",
    (tool) => {
      const envelope = {
        schema_version: "boardagent.ruleset.v1",
        values: {
          schemaVersion: "boardagent.ruleset.v1",
          boardId: board,
          matterTypes: [],
          rules: [],
          canonicalHash: "b".repeat(64)
        }
      };
      const value =
        tool === "manage_ruleset"
          ? { ...common, expected_ruleset_id: null, reason: "Activate rules", ruleset: envelope }
          : { schema_version: common.schema_version, board_id: board, citations, draft: envelope };
      expect(() => toolInputSchema(tool).parse(value)).not.toThrow();
    }
  );
  it("retains lowercase fact names and strict envelope fields", () => {
    const input = {
      schema_version: common.schema_version,
      board_id: board,
      idempotency_key: common.idempotency_key,
      matter_type_id: source,
      expected_profile_id: source,
      expected_ruleset_id: source,
      facts: { schema_version: "boardagent.facts.v1", values: { budget_usd: 1 } }
    };
    expect(toolInputSchema("evaluate_matter").parse(input)).toEqual(input);
    expect(() =>
      toolInputSchema("evaluate_matter").parse({
        ...input,
        facts: { ...input.facts, values: { budgetUsd: 1 } }
      })
    ).toThrow();
    expect(() =>
      toolInputSchema("configure_board_governance").parse({
        ...common,
        expected_profile_id: null,
        reason: "Not canonical",
        profile: {
          schema_version: "boardagent.governance-profile.v1",
          values: {},
          additional_authority: "admin"
        }
      })
    ).toThrow();
  });
  it("advertises camelCase keys in the actual MCP JSON schema", () => {
    const schema = z.toJSONSchema(toolInputSchema("configure_board_governance")) as unknown as {
      properties: { profile: { properties: { values: { propertyNames: { pattern: string } } } } };
    };
    const pattern = new RegExp(
      schema.properties.profile.properties.values.propertyNames.pattern,
      "u"
    );
    expect(pattern.test("schemaVersion")).toBe(true);
    expect(pattern.test("sourceAgreements")).toBe(true);
  });
  it("retains canonical JSON validation for governance document values", () => {
    expect(() =>
      toolInputSchema("configure_board_governance").parse({
        ...common,
        expected_profile_id: null,
        reason: "Invalid text",
        profile: {
          schema_version: "boardagent.governance-profile.v1",
          values: { label: "Cafe\u0301" }
        }
      })
    ).toThrow();
  });
});
