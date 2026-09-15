import { describe, expect, it } from "vitest";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { validatedRuntimeRuleTemplate } from "../../lib/db/src/transactions/rule-selection.js";
import { governanceEnvelopeFixture } from "../helpers/governance-envelope.js";
import { testId } from "../helpers/authorized-actor.js";

const authored = governanceEnvelopeFixture(testId(1), [testId(2)], testId(3), "a".repeat(64))
  .profile.templates[0]!;
const approval = {
  schemaVersion: "boardagent.approval-rule.v1",
  approval: { numerator: "1", denominator: "2" },
  quorum: { numerator: "1", denominator: "2" },
  approvalDenominator: "yes_no",
  abstentionsCountForQuorum: true,
  tieBehavior: "reject",
  proxyPolicy: "forbidden",
  closeMode: "secretariat_confirmed"
};
const approvalHash = canonicalSha256(approval);
const runtime = {
  schemaVersion: "boardagent.governance-rule-template.v1",
  approvalRuleSha256: approvalHash,
  overridePolicy: "forbidden"
};

describe("immutable governance template evidence", () => {
  it("projects the cited authored template without changing its original values or hash", () => {
    const original = structuredClone(authored);
    const digest = canonicalSha256(authored);
    expect(validatedRuntimeRuleTemplate(authored, digest, approvalHash)).toEqual(runtime);
    expect(authored).toEqual(original);
    expect(canonicalSha256(authored)).toBe(digest);
  });
  it("retains the legacy strict runtime payload", () => {
    expect(validatedRuntimeRuleTemplate(runtime, canonicalSha256(runtime), approvalHash)).toEqual(
      runtime
    );
  });
  it("maps only the explicit strengthening policy to the existing confirmed override gate", () => {
    const value = { ...authored, overridePolicy: "strengthen_only" };
    expect(validatedRuntimeRuleTemplate(value, canonicalSha256(value), approvalHash)).toEqual({
      ...runtime,
      overridePolicy: "reasoned_within_bounds"
    });
  });
  it.each(["authored", "runtime"])("rejects %s evidence with a corrupted stored hash", (kind) => {
    expect(() =>
      validatedRuntimeRuleTemplate(
        kind === "authored" ? authored : runtime,
        "b".repeat(64),
        approvalHash
      )
    ).toThrow(/template hash/);
  });
  it.each(["authored", "runtime"])("rejects %s evidence bound to a different approval", (kind) => {
    const value = kind === "authored" ? authored : runtime;
    expect(() =>
      validatedRuntimeRuleTemplate(value, canonicalSha256(value), "b".repeat(64))
    ).toThrow(/approval binding/);
  });
  it("refuses weakened authored numbers even when that changed template is correctly hashed", () => {
    const value = { ...authored, quorum: { numerator: "1", denominator: "100" } };
    expect(() => validatedRuntimeRuleTemplate(value, canonicalSha256(value), approvalHash)).toThrow(
      /approval binding/
    );
  });
  it.each([
    { ...authored, overridePolicy: "allow_anything" },
    { ...authored, schemaVersion: "boardagent.governance-rule-template.v1" },
    { ...runtime, additionalAuthority: "admin" },
    { ...runtime, schemaVersion: "boardagent.governance-rule-template.v2" }
  ])("rejects unsupported or mixed shapes without repairing their metadata", (value) => {
    expect(() =>
      validatedRuntimeRuleTemplate(value, canonicalSha256(value), approvalHash)
    ).toThrow();
  });
});
