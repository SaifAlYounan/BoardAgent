import { describe, expect, it } from "vitest";

import { createCursorCodec } from "../../artifacts/server/src/cursor.js";
import { testId } from "../helpers/authorized-actor.js";

describe("TH-37 cursor tamper and entitlement changes", () => {
  it("binds pagination state to the exact member, board, tool, generation input, and lifetime", () => {
    const codec = createCursorCodec(Buffer.alloc(32, 0x37), 60);
    const binding = {
      organizationId: testId(37_001),
      memberId: testId(37_002),
      tool: "list_documents",
      boardId: testId(37_003)
    };
    const cursor = codec.mint(binding, "generation=8\u0000row=9", 1_000);

    expect(codec.verify(cursor, binding, 1_001)).toBe("generation=8\u0000row=9");
    for (const changed of [
      { ...binding, organizationId: testId(37_004) },
      { ...binding, memberId: testId(37_005) },
      { ...binding, boardId: testId(37_006) },
      { ...binding, tool: "search_documents" }
    ]) {
      expect(() => codec.verify(cursor, changed, 1_001)).toThrow("cursor is invalid");
    }
    expect(() => codec.verify(`${cursor.slice(0, -1)}A`, binding, 1_001)).toThrow(
      "cursor is invalid"
    );
    expect(() => codec.verify(cursor, binding, 1_060)).toThrow("cursor is invalid");
  });
});
