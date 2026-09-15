import { describe, expect, it } from "vitest";

import { createCursorCodec } from "../../artifacts/server/src/index.js";

const ORGANIZATION_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const MEMBER_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const OTHER_MEMBER_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
const BOARD_ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e04";

describe("caller-bound pagination cursor", () => {
  it("round-trips one opaque key only for the exact actor/tool/board binding", () => {
    const codec = createCursorCodec(new Uint8Array(32).fill(0x51), 300);
    const binding = {
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      tool: "list_documents",
      boardId: BOARD_ID
    };
    const cursor = codec.mint(binding, "2026-09-01T08:00:00Z\u0000018f-item", 1000);
    expect(codec.verify(cursor, binding, 1200)).toBe("2026-09-01T08:00:00Z\u0000018f-item");
    expect(() => codec.verify(cursor, { ...binding, memberId: OTHER_MEMBER_ID }, 1200)).toThrow(
      "cursor is invalid"
    );
    expect(() => codec.verify(cursor, { ...binding, tool: "list_votes" }, 1200)).toThrow(
      "cursor is invalid"
    );
  });

  it("rejects tampering, expiry and malformed or weak configuration", () => {
    const codec = createCursorCodec(new Uint8Array(32).fill(0x52), 60);
    const binding = {
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      tool: "list_pending_actions",
      boardId: null
    };
    const cursor = codec.mint(binding, "42", 1000);
    const [payload, signature] = cursor.split(".");
    if (!payload || !signature) throw new Error("fixture cursor is malformed");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const canonicalLastIndex = alphabet.indexOf(signature.at(-1) ?? "");
    expect(canonicalLastIndex % 4).toBe(0);
    const noncanonicalSignature = `${signature.slice(0, -1)}${alphabet[canonicalLastIndex + 1]}`;
    expect(Buffer.from(noncanonicalSignature, "base64url")).toEqual(
      Buffer.from(signature, "base64url")
    );
    expect(() => codec.verify(`${payload}.${noncanonicalSignature}`, binding, 1001)).toThrow(
      "cursor is invalid"
    );
    expect(() => codec.verify(cursor, binding, 1060)).toThrow("cursor is invalid");
    expect(() => codec.verify("not-a-cursor", binding, 1001)).toThrow("cursor is invalid");
    expect(() => createCursorCodec("short", 60)).toThrow("at least 32 bytes");
  });
});
