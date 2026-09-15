import { describe, expect, it } from "vitest";

import {
  MinutesActionManifestSchema,
  MinutesRedlineSchema,
  canonicalSha256,
  sha256Hex
} from "../../lib/contracts/src/index.js";
import {
  activationManifestHash,
  applyExactMinutesRedline,
  minutesActionManifestHash,
  reviewIsResolved
} from "../../lib/domain/src/index.js";

const id = (suffix: number): string =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;

describe("minutes review and action packages", () => {
  it("applies an exact line-bound redline and refuses stale anchored bytes", () => {
    const base = "# Decisions\nFirst resolution.\nSecond resolution.\n";
    const redline = MinutesRedlineSchema.parse({
      schemaVersion: "boardagent.minutes-redline.v1",
      minutesId: id(1),
      baseVersion: 1,
      baseSha256: sha256Hex(base),
      anchor: { kind: "lines", startLine: 2, endLine: 2 },
      anchoredTextSha256: sha256Hex("First resolution."),
      operation: "replace",
      proposedText: "First resolution approved unanimously.",
      rationale: "Match the vote certificate.",
      citations: []
    });
    expect(applyExactMinutesRedline(base, redline)).toBe(
      "# Decisions\nFirst resolution approved unanimously.\nSecond resolution.\n"
    );
    expect(() => applyExactMinutesRedline(base.replace("First", "Changed"), redline)).toThrow(
      "base hash"
    );
  });

  it("applies every exact line and section operation and preserves terminal-LF shape", () => {
    const lineBase = "alpha\nbeta\ngamma";
    const lineInput = (operation: "delete" | "insert_before" | "insert_after") =>
      MinutesRedlineSchema.parse({
        schemaVersion: "boardagent.minutes-redline.v1",
        minutesId: id(1),
        baseVersion: 1,
        baseSha256: sha256Hex(lineBase),
        anchor: { kind: "lines", startLine: 2, endLine: 2 },
        anchoredTextSha256: sha256Hex("beta"),
        operation,
        proposedText: operation === "delete" ? "" : "new",
        rationale: "Exercise exact operation semantics.",
        citations: []
      });
    expect(applyExactMinutesRedline(lineBase, lineInput("delete"))).toBe("alpha\ngamma");
    expect(applyExactMinutesRedline(lineBase, lineInput("insert_before"))).toBe(
      "alpha\nnew\nbeta\ngamma"
    );
    expect(applyExactMinutesRedline(lineBase, lineInput("insert_after"))).toBe(
      "alpha\nbeta\nnew\ngamma"
    );
    const lastLine = MinutesRedlineSchema.parse({
      ...lineInput("insert_after"),
      anchor: { kind: "lines", startLine: 3, endLine: 3 },
      anchoredTextSha256: sha256Hex("gamma"),
      operation: "replace",
      proposedText: "omega"
    });
    expect(applyExactMinutesRedline(lineBase, lastLine)).toBe("alpha\nbeta\nomega");

    const sectionBase = "# One\nfirst\n## Nested\ninside\n# Two\nsecond\n";
    const section = MinutesRedlineSchema.parse({
      schemaVersion: "boardagent.minutes-redline.v1",
      minutesId: id(2),
      baseVersion: 1,
      baseSha256: sha256Hex(sectionBase),
      anchor: { kind: "section", section: "One" },
      anchoredTextSha256: sha256Hex("# One\nfirst\n## Nested\ninside"),
      operation: "replace",
      proposedText: "# One\nreplacement",
      rationale: "Replace one exact section.",
      citations: []
    });
    expect(applyExactMinutesRedline(sectionBase, section)).toBe(
      "# One\nreplacement\n# Two\nsecond\n"
    );

    const terminalSection = MinutesRedlineSchema.parse({
      ...section,
      anchor: { kind: "section", section: "Two" },
      anchoredTextSha256: sha256Hex("# Two\nsecond"),
      operation: "insert_after",
      proposedText: "tail"
    });
    expect(applyExactMinutesRedline(sectionBase, terminalSection)).toBe(
      "# One\nfirst\n## Nested\ninside\n# Two\nsecond\ntail\n"
    );

    const spacedNestedBase = "##  Nested\ninside\n## Peer\npeer\n";
    const spacedNested = MinutesRedlineSchema.parse({
      ...section,
      baseSha256: sha256Hex(spacedNestedBase),
      anchor: { kind: "section", section: "Nested" },
      anchoredTextSha256: sha256Hex("##  Nested\ninside"),
      proposedText: "## Nested\nreplacement"
    });
    expect(applyExactMinutesRedline(spacedNestedBase, spacedNested)).toBe(
      "## Nested\nreplacement\n## Peer\npeer\n"
    );

    const embeddedHeadingBase = "# One\ninside\nx# Two\nnot a heading\n# Three\nend\n";
    const embeddedHeading = MinutesRedlineSchema.parse({
      ...section,
      baseSha256: sha256Hex(embeddedHeadingBase),
      anchor: { kind: "section", section: "One" },
      anchoredTextSha256: sha256Hex("# One\ninside\nx# Two\nnot a heading"),
      proposedText: "# One\nreplacement"
    });
    expect(applyExactMinutesRedline(embeddedHeadingBase, embeddedHeading)).toBe(
      "# One\nreplacement\n# Three\nend\n"
    );
  });

  it("rejects absent, out-of-range and byte-stale anchors", () => {
    const base = "# Decisions\nOne\n";
    const input = MinutesRedlineSchema.parse({
      schemaVersion: "boardagent.minutes-redline.v1",
      minutesId: id(1),
      baseVersion: 1,
      baseSha256: sha256Hex(base),
      anchor: { kind: "lines", startLine: 1, endLine: 1 },
      anchoredTextSha256: sha256Hex("wrong"),
      operation: "delete",
      proposedText: "",
      rationale: "Reject a stale anchor.",
      citations: []
    });
    expect(() => applyExactMinutesRedline(base, input)).toThrow("anchored text hash");
    expect(() =>
      applyExactMinutesRedline(base, {
        ...input,
        anchor: { kind: "lines", startLine: 3, endLine: 3 }
      })
    ).toThrow("outside base");
    expect(() =>
      applyExactMinutesRedline(base, {
        ...input,
        anchor: { kind: "section", section: "Missing" }
      })
    ).toThrow("section anchor is absent");
    expect(() =>
      applyExactMinutesRedline(
        "x# Fake\nbody\n",
        MinutesRedlineSchema.parse({
          ...input,
          baseSha256: sha256Hex("x# Fake\nbody\n"),
          anchor: { kind: "section", section: "Fake" }
        })
      )
    ).toThrow("section anchor is absent");
  });

  it("requires every nonwithdrawn review item to have a disposition", () => {
    expect(
      reviewIsResolved(
        [
          { itemId: id(1), kind: "comment" },
          { itemId: id(2), kind: "redline" }
        ],
        [{ itemId: id(1) }],
        [{ itemId: id(2) }]
      )
    ).toBe(true);
    expect(reviewIsResolved([{ itemId: id(1), kind: "redline" }], [], [])).toBe(false);
    expect(
      reviewIsResolved(
        [
          { itemId: id(1), kind: "comment" },
          { itemId: id(2), kind: "redline" }
        ],
        [{ itemId: id(1) }],
        []
      )
    ).toBe(false);
    expect(() =>
      reviewIsResolved([{ itemId: id(1), kind: "redline" }], [{ itemId: id(1) }], [])
    ).toThrow("redlines cannot be withdrawn");
  });

  it("rejects duplicate and contradictory review projections", () => {
    expect(() =>
      reviewIsResolved(
        [
          { itemId: id(1), kind: "comment" },
          { itemId: id(1), kind: "comment" }
        ],
        [],
        []
      )
    ).toThrow("duplicate minutes review item");
    expect(() =>
      reviewIsResolved([{ itemId: id(1), kind: "comment" }], [{ itemId: id(2) }], [])
    ).toThrow("withdrawal references unknown item");
    expect(() =>
      reviewIsResolved(
        [{ itemId: id(1), kind: "comment" }],
        [{ itemId: id(1) }, { itemId: id(1) }],
        []
      )
    ).toThrow("duplicate withdrawal");
    expect(() =>
      reviewIsResolved([{ itemId: id(1), kind: "comment" }], [], [{ itemId: id(2) }])
    ).toThrow("disposition references unknown item");
    expect(() =>
      reviewIsResolved(
        [{ itemId: id(1), kind: "comment" }],
        [],
        [{ itemId: id(1) }, { itemId: id(1) }]
      )
    ).toThrow("duplicate disposition");
    expect(() =>
      reviewIsResolved(
        [{ itemId: id(1), kind: "comment" }],
        [{ itemId: id(1) }],
        [{ itemId: id(1) }]
      )
    ).toThrow("withdrawn item also dispositioned");
  });

  it("hashes exact action declarations and activates only their exact draft tasks", () => {
    const manifest = MinutesActionManifestSchema.parse({
      schemaVersion: "boardagent.minutes-action-manifest.v1",
      minutesId: id(1),
      minutesVersion: 1,
      minutesSha256: "a".repeat(64),
      declaration: "items_logged",
      items: [
        {
          itemId: id(10),
          ownerMemberId: id(11),
          dueAt: "2026-10-01T12:00:00Z",
          sourceLocator: { section: "Actions", line: 4 },
          description: "Deliver report.",
          requiredEvidence: "Canonical report.",
          visibility: "board"
        }
      ]
    });
    const manifestHash = minutesActionManifestHash(manifest);
    expect(manifestHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(
      activationManifestHash(manifest, [
        { taskId: id(10), state: "draft", sourceMinutesSha256: "a".repeat(64) }
      ])
    ).toBe(
      canonicalSha256({
        schemaVersion: "boardagent.minutes-action-activation.v1",
        manifestSha256: manifestHash,
        taskIds: [id(10)]
      })
    );
    expect(() =>
      activationManifestHash(manifest, [
        { taskId: id(99), state: "draft", sourceMinutesSha256: "a".repeat(64) }
      ])
    ).toThrow("exact action manifest");
    expect(() =>
      activationManifestHash(manifest, [
        { taskId: id(10), state: "draft", sourceMinutesSha256: "b".repeat(64) }
      ])
    ).toThrow("source minutes hash mismatch");

    const none = MinutesActionManifestSchema.parse({
      schemaVersion: "boardagent.minutes-action-manifest.v1",
      minutesId: id(2),
      minutesVersion: 1,
      minutesSha256: "c".repeat(64),
      declaration: "no_action_items"
    });
    expect(activationManifestHash(none, [])).toMatch(/^[0-9a-f]{64}$/u);
  });
});
