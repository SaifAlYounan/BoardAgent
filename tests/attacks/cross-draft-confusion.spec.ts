import { describe, expect, it } from "vitest";

import { MinutesActionManifestSchema } from "../../lib/contracts/src/governance.js";
import { activationManifestHash } from "../../lib/domain/src/minutes.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;

describe("TH-32 cross-draft confusion", () => {
  it("activates only task IDs and source bytes bound to the confirmed minutes manifest", () => {
    const manifest = MinutesActionManifestSchema.parse({
      schemaVersion: "boardagent.minutes-action-manifest.v1",
      minutesId: id(1),
      minutesVersion: 3,
      minutesSha256: "a".repeat(64),
      declaration: "items_logged",
      items: [
        {
          itemId: id(2),
          ownerMemberId: id(3),
          dueAt: "2026-10-01T00:00:00Z",
          sourceLocator: { section: "Actions", line: 8 },
          description: "Deliver the report.",
          requiredEvidence: "Canonical report hash.",
          visibility: "board"
        }
      ]
    });
    expect(
      activationManifestHash(manifest, [
        { taskId: id(2), state: "draft", sourceMinutesSha256: "a".repeat(64) }
      ])
    ).toMatch(/^[0-9a-f]{64}$/u);
    expect(() =>
      activationManifestHash(manifest, [
        { taskId: id(9), state: "draft", sourceMinutesSha256: "a".repeat(64) }
      ])
    ).toThrow("exact action manifest");
    expect(() =>
      activationManifestHash(manifest, [
        { taskId: id(2), state: "draft", sourceMinutesSha256: "b".repeat(64) }
      ])
    ).toThrow("source minutes hash mismatch");
  });
});
