import { describe, expect, it } from "vitest";

import { sha256Hex } from "../../lib/contracts/src/canonical.js";
import { MinutesRedlineSchema } from "../../lib/contracts/src/governance.js";
import { applyExactMinutesRedline } from "../../lib/domain/src/minutes.js";

const base = "# Decisions\nApprove the original resolution.\n";
const redline = MinutesRedlineSchema.parse({
  schemaVersion: "boardagent.minutes-redline.v1",
  minutesId: "018f0000-0000-7000-8000-000000000001",
  baseVersion: 2,
  baseSha256: sha256Hex(base),
  anchor: { kind: "lines", startLine: 2, endLine: 2 },
  anchoredTextSha256: sha256Hex("Approve the original resolution."),
  operation: "replace",
  proposedText: "Approve the corrected resolution.",
  rationale: "Match the signed vote certificate.",
  citations: []
});

describe("TH-57 exact minutes-redline context", () => {
  it("rejects stale base bytes, changed anchors, and absent fuzzy sections", () => {
    expect(applyExactMinutesRedline(base, redline)).toBe(
      "# Decisions\nApprove the corrected resolution.\n"
    );
    expect(() => applyExactMinutesRedline(base.replace("original", "changed"), redline)).toThrow(
      "base hash mismatch"
    );
    expect(() =>
      applyExactMinutesRedline(base, {
        ...MinutesRedlineSchema.parse({
          ...redline,
          anchoredTextSha256: sha256Hex("approximately the same")
        })
      })
    ).toThrow("anchored text hash mismatch");
    expect(() =>
      applyExactMinutesRedline(base, {
        ...redline,
        anchor: { kind: "section", section: "Similar decisions" }
      })
    ).toThrow("section anchor is absent");
  });
});
