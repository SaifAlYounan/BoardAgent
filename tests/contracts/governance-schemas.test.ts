import { describe, expect, it } from "vitest";

import {
  BriefingCursorPayloadSchema,
  BriefingFeedPositionSchema,
  BriefingResyncInstructionSchema,
  DecisionPackageSchema,
  MinutesActionManifestSchema,
  MinutesCommentSchema,
  MinutesRedlineSchema,
  PendingActionDeltaSchema
} from "../../lib/contracts/src/index.js";

const id = (suffix: number): string =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;
const hash = (character: string): string => character.repeat(64);

describe("strict governance payload contracts", () => {
  it("accepts an exact minutes comment and rejects attachments or unknown fields", () => {
    const comment = {
      schemaVersion: "boardagent.minutes-comment.v1",
      minutesId: id(1),
      baseVersion: 2,
      baseSha256: hash("a"),
      comment: "Please align this paragraph with the approved resolution.\n",
      citations: [
        {
          sourceDocumentVersionId: id(2),
          sourceDocumentSha256: hash("b"),
          clause: "Resolution 4",
          locator: "paragraph 2"
        }
      ]
    };
    expect(MinutesCommentSchema.parse(comment)).toEqual(comment);
    expect(() => MinutesCommentSchema.parse({ ...comment, attachment: "base64" })).toThrow();
    expect(() => MinutesCommentSchema.parse({ ...comment, comment: "Cafe\u0301" })).toThrow("NFC");
  });

  it("binds a redline to exact base and anchor bytes without fuzzy or binary input", () => {
    const redline = {
      schemaVersion: "boardagent.minutes-redline.v1",
      minutesId: id(1),
      baseVersion: 2,
      baseSha256: hash("a"),
      anchor: { kind: "lines", startLine: 10, endLine: 12 },
      anchoredTextSha256: hash("c"),
      operation: "replace",
      proposedText: "The Board unanimously approved the resolution.\n",
      rationale: "Match the signed decision package.",
      citations: []
    };
    expect(MinutesRedlineSchema.parse(redline)).toEqual(redline);
    expect(() =>
      MinutesRedlineSchema.parse({ ...redline, fuzzyAnchor: "find similar text" })
    ).toThrow();
    expect(() => MinutesRedlineSchema.parse({ ...redline, proposedText: "x\r\n" })).toThrow("LF");
    expect(() =>
      MinutesRedlineSchema.parse({ ...redline, operation: "delete", proposedText: "not empty" })
    ).toThrow("delete redline");
  });

  it("requires an exact no-action declaration or a complete nonempty action manifest", () => {
    const base = {
      schemaVersion: "boardagent.minutes-action-manifest.v1",
      minutesId: id(1),
      minutesVersion: 2,
      minutesSha256: hash("a")
    };
    expect(MinutesActionManifestSchema.parse({ ...base, declaration: "no_action_items" })).toEqual({
      ...base,
      declaration: "no_action_items"
    });
    expect(() =>
      MinutesActionManifestSchema.parse({
        ...base,
        declaration: "no_action_items",
        items: []
      })
    ).toThrow();

    const item = {
      itemId: id(10),
      ownerMemberId: id(11),
      dueAt: "2026-09-30T12:00:00Z",
      sourceLocator: { section: "Actions", line: 18 },
      description: "Deliver the approved implementation report.",
      requiredEvidence: "Canonical report document and acceptance receipt.",
      visibility: "board"
    };
    const logged = MinutesActionManifestSchema.parse({
      ...base,
      declaration: "items_logged",
      items: [item]
    });
    expect(logged.declaration).toBe("items_logged");
    if (logged.declaration === "items_logged") expect(logged.items).toEqual([item]);
    expect(() =>
      MinutesActionManifestSchema.parse({
        ...base,
        declaration: "items_logged",
        items: [item, item]
      })
    ).toThrow("duplicate action item");
  });

  it("freezes decision-package components and prevents duplicate typed references", () => {
    const packageInput = {
      schemaVersion: "boardagent.decision-package.v1",
      voteId: id(20),
      packageVersion: 1,
      resolutionVersionId: id(21),
      resolutionSha256: hash("1"),
      governanceProfileVersionId: id(22),
      governanceProfileSha256: hash("2"),
      rulesetVersionId: id(23),
      rulesetSha256: hash("3"),
      approvalRuleId: id(24),
      approvalRuleSha256: hash("4"),
      matterEvaluationId: id(25),
      matterEvaluationResultSha256: hash("8"),
      selectedRulesetRuleId: id(26),
      selectedRulesetRuleSha256: hash("9"),
      ruleOverride: null,
      electorateSha256: hash("5"),
      closeMode: "secretariat_confirmed",
      deadlineAt: "2026-10-01T12:00:00Z",
      components: [
        { type: "document", ordinal: 1, id: id(30), version: 1, sha256: hash("6") },
        { type: "question_cutoff", ordinal: 2, id: id(31), version: 4, sha256: hash("7") }
      ]
    };
    expect(DecisionPackageSchema.parse(packageInput)).toEqual(packageInput);
    expect(() =>
      DecisionPackageSchema.parse({
        ...packageInput,
        components: [packageInput.components[0], packageInput.components[0]]
      })
    ).toThrow("duplicate decision-package component");
  });

  it("keeps pending-action deltas content-free and strictly cursor-addressable", () => {
    const delta = {
      schemaVersion: "boardagent.pending-action.v1",
      sequence: "42",
      deltaType: "revote_required",
      objectType: "vote",
      objectId: id(40),
      objectVersion: 2,
      entitlementGeneration: 3,
      actionState: "pending",
      safeRefs: { boardId: id(41), replacementVoteId: id(40) },
      createdAt: "2026-08-31T14:00:00Z"
    };
    expect(PendingActionDeltaSchema.parse(delta)).toEqual(delta);
    expect(() => PendingActionDeltaSchema.parse({ ...delta, canonicalText: "secret" })).toThrow();

    const position = {
      sequence: "42",
      boardId: id(41),
      entryKind: "feed",
      entryId: id(42)
    } as const;
    expect(BriefingFeedPositionSchema.parse(position)).toEqual(position);
    expect(() => BriefingFeedPositionSchema.parse({ ...position, entryId: null })).toThrow(
      "complete feed entry"
    );
    expect(() => BriefingFeedPositionSchema.parse({ ...position, sequence: "0" })).toThrow(
      "complete feed entry"
    );

    const cursor = {
      schemaVersion: "boardagent.briefing-cursor.v1",
      memberId: id(40),
      entitlementSetSha256: hash("a"),
      position,
      mode: "delta"
    } as const;
    expect(BriefingCursorPayloadSchema.parse(cursor)).toEqual(cursor);
    expect(() => BriefingCursorPayloadSchema.parse({ ...cursor, hiddenCount: 1 })).toThrow();

    const resync = {
      schema_version: "boardagent.briefing-resync.v1",
      reason: "briefing_overflow",
      resync_token: "opaque.signed",
      steps: ["list_my_boards", "get_my_board_snapshot", "list_my_updates"]
    } as const;
    expect(BriefingResyncInstructionSchema.parse(resync)).toEqual(resync);
  });
});
