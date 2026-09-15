import { describe, expect, it } from "vitest";

import { reviewIsResolved } from "../../lib/domain/src/minutes.js";

describe("TH-59 minutes review bypass", () => {
  it("refuses signature readiness while any review remains unresolved or illegally withdrawn", () => {
    const comment = { itemId: "comment-1", kind: "comment" as const };
    const redline = { itemId: "redline-1", kind: "redline" as const };
    expect(reviewIsResolved([comment, redline], [], [])).toBe(false);
    expect(reviewIsResolved([comment, redline], [{ itemId: comment.itemId }], [])).toBe(false);
    expect(
      reviewIsResolved(
        [comment, redline],
        [{ itemId: comment.itemId }],
        [{ itemId: redline.itemId }]
      )
    ).toBe(true);
    expect(() => reviewIsResolved([redline], [{ itemId: redline.itemId }], [])).toThrow(
      "redlines cannot be withdrawn"
    );
    expect(() =>
      reviewIsResolved([comment], [{ itemId: comment.itemId }], [{ itemId: comment.itemId }])
    ).toThrow("withdrawn item also dispositioned");
  });
});
