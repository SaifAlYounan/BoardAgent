import { describe, expect, it } from "vitest";

import { MinutesRedlineSchema } from "../../lib/contracts/src/governance.js";

const valid = {
  schemaVersion: "boardagent.minutes-redline.v1",
  minutesId: "018f0000-0000-7000-8000-000000000001",
  baseVersion: 1,
  baseSha256: "a".repeat(64),
  anchor: { kind: "lines", startLine: 1, endLine: 1 },
  anchoredTextSha256: "b".repeat(64),
  operation: "replace",
  proposedText: "Corrected text.",
  rationale: "Match the approved record.",
  citations: []
};

describe("TH-56 minutes redline format boundary", () => {
  it("accepts only strict machine-readable operations and rejects attachment-shaped fields", () => {
    expect(MinutesRedlineSchema.parse(valid)).toMatchObject(valid);
    for (const hostile of [
      { ...valid, attachment: "base64:UEsDBAoAAAAA" },
      { ...valid, trackedChangesDocx: "UEsDBAoAAAAA" },
      { ...valid, operation: "fuzzy_replace" },
      { ...valid, anchor: { kind: "xpath", value: "//w:ins" } },
      { ...valid, proposedText: "", operation: "replace" }
    ]) {
      expect(MinutesRedlineSchema.safeParse(hostile).success).toBe(false);
    }
  });
});
