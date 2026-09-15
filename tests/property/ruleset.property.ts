import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { evaluateMatter, type RulesetVersion } from "../../lib/ruleset/src/index.js";

const uuid = (suffix: number): RulesetVersion["id"] =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}` as RulesetVersion["id"];

const citation = {
  sourceDocumentVersionId: uuid(900),
  sourceDocumentSha256: "1".repeat(
    64
  ) as RulesetVersion["rules"][number]["citations"][number]["sourceDocumentSha256"],
  clause: "7.2",
  locator: "reserved matters"
};

describe("ruleset priority/specificity properties", () => {
  it("selects the unique maximum or fails closed on a tied maximum across 100,000 seeds", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            priority: fc.integer({ min: 0, max: 20 }),
            specificity: fc.integer({ min: 0, max: 20 })
          }),
          { minLength: 1, maxLength: 20 }
        ),
        (ranks) => {
          const ruleset: RulesetVersion = {
            schemaVersion: "boardagent.ruleset.v1",
            id: uuid(1),
            boardId: uuid(2),
            version: 1,
            canonicalHash: "0".repeat(64) as RulesetVersion["canonicalHash"],
            matterTypes: [
              { code: "test", fields: [{ name: "flag", type: "boolean", required: true }] }
            ],
            rules: ranks.map((rank, index) => ({
              id: uuid(index + 10),
              matterType: "test",
              priority: rank.priority,
              specificity: rank.specificity,
              condition: { kind: "equals", field: "flag", value: true },
              approvalRuleId: uuid(index + 100),
              citations: [citation]
            }))
          };
          const result = evaluateMatter(ruleset, "test", { flag: true });
          const sorted = ranks
            .map((rank, index) => ({ ...rank, index }))
            .toSorted(
              (left, right) =>
                right.priority - left.priority || right.specificity - left.specificity
            );
          const best = sorted[0]!;
          const tied = sorted.filter(
            (candidate) =>
              candidate.priority === best.priority && candidate.specificity === best.specificity
          );
          if (tied.length === 1) {
            expect(result.status).toBe("matched");
            if (result.status === "matched") expect(result.rule.id).toBe(uuid(best.index + 10));
          } else {
            expect(result.status).toBe("ambiguous");
          }
        }
      ),
      { seed: 0x5e7, numRuns: 100_000, endOnFailure: true }
    );
  });
});
