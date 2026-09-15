import { createHmac } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  FeedCursorPayloadSchema,
  PendingActionDeltaSchema
} from "../../lib/contracts/src/index.js";
import {
  decodeFeedCursor,
  encodeFeedCursor,
  listEntitledDeltas,
  type EntitledPendingDelta
} from "../../lib/domain/src/index.js";

const id = (suffix: number): string =>
  `00000000-0000-7000-8000-${String(suffix).padStart(12, "0")}`;
const key = new Uint8Array(32).fill(0x5a);

function signedBody(raw: string, encodedBody = Buffer.from(raw, "utf8").toString("base64url")) {
  const signature = createHmac("sha256", key).update(encodedBody, "ascii").digest("base64url");
  return `${encodedBody}.${signature}`;
}

function delta(sequence: number, memberId = id(1), boardId = id(2)): EntitledPendingDelta {
  return {
    memberId,
    boardId,
    delta: PendingActionDeltaSchema.parse({
      schemaVersion: "boardagent.pending-action.v1",
      sequence: String(sequence),
      deltaType: "action_required",
      objectType: "task",
      objectId: id(sequence + 10),
      objectVersion: 1,
      entitlementGeneration: 4,
      actionState: "pending",
      safeRefs: { boardId },
      createdAt: "2026-08-31T14:00:00Z"
    })
  };
}

describe("signed entitlement-bound feed cursor", () => {
  it("round-trips an exact member/board/generation/position payload", () => {
    const payload = FeedCursorPayloadSchema.parse({
      schemaVersion: "boardagent.feed-cursor.v1",
      memberId: id(1),
      boardId: id(2),
      entitlementGeneration: 4,
      afterSequence: "41"
    });
    const encoded = encodeFeedCursor(payload, key);
    expect(decodeFeedCursor(encoded, key)).toEqual(payload);
    const [body, signature] = encoded.split(".");
    expect(() => decodeFeedCursor(`${body}.${signature?.slice(0, -1)}A`, key)).toThrow("signature");
    expect(() => decodeFeedCursor(`${body}.${signature?.slice(0, -3)}`, key)).toThrow(
      "invalid feed cursor signature"
    );
  });

  it("rejects weak keys and every noncanonical cursor wire form", () => {
    const payload = FeedCursorPayloadSchema.parse({
      schemaVersion: "boardagent.feed-cursor.v1",
      memberId: id(1),
      boardId: id(2),
      entitlementGeneration: 4,
      afterSequence: "0"
    });
    expect(() => encodeFeedCursor(payload, new Uint8Array(31))).toThrow("at least 32 bytes");
    expect(() => decodeFeedCursor("body.signature", new Uint8Array(31))).toThrow(
      "at least 32 bytes"
    );
    expect(() => decodeFeedCursor("missing-separator", key)).toThrow("framing");
    for (const malformed of [".signature", "body.", "body.signature.extra"]) {
      expect(() => decodeFeedCursor(malformed, key)).toThrow("framing");
    }

    const encoded = encodeFeedCursor(payload, key);
    const [body, signature] = encoded.split(".") as [string, string];
    expect(() => decodeFeedCursor(`${body}.${signature}=`, key)).toThrow("signature encoding");

    const paddedBody = `${body}=`;
    expect(() => decodeFeedCursor(signedBody("", paddedBody), key)).toThrow("body encoding");

    const noncanonicalJson = ` ${Buffer.from(body, "base64url").toString("utf8")}`;
    expect(() => decodeFeedCursor(signedBody(noncanonicalJson), key)).toThrow("not canonical");
  });

  it("returns every bounded entitled delta after the cursor and nothing else", () => {
    const cursor = FeedCursorPayloadSchema.parse({
      schemaVersion: "boardagent.feed-cursor.v1",
      memberId: id(1),
      boardId: id(2),
      entitlementGeneration: 4,
      afterSequence: "1"
    });
    const result = listEntitledDeltas(
      [delta(3), delta(1), delta(2), delta(4, id(99)), delta(5, id(1), id(98))],
      cursor,
      { memberId: id(1), boardId: id(2), entitlementGeneration: 4, limit: 100 }
    );
    expect(result.map((entry) => entry.sequence)).toEqual(["2", "3"]);
  });

  it("rejects stale generation, cross-member, cross-board, and duplicate sequence contexts", () => {
    const cursor = FeedCursorPayloadSchema.parse({
      schemaVersion: "boardagent.feed-cursor.v1",
      memberId: id(1),
      boardId: id(2),
      entitlementGeneration: 4,
      afterSequence: "0"
    });
    expect(() =>
      listEntitledDeltas([delta(1)], cursor, {
        memberId: id(1),
        boardId: id(2),
        entitlementGeneration: 5,
        limit: 10
      })
    ).toThrow("generation");
    expect(() =>
      listEntitledDeltas([delta(1)], cursor, {
        memberId: id(99),
        boardId: id(2),
        entitlementGeneration: 4,
        limit: 10
      })
    ).toThrow("member");
    expect(() =>
      listEntitledDeltas([delta(1)], cursor, {
        memberId: id(1),
        boardId: id(98),
        entitlementGeneration: 4,
        limit: 10
      })
    ).toThrow("board");
    expect(() =>
      listEntitledDeltas([delta(1), delta(1)], cursor, {
        memberId: id(1),
        boardId: id(2),
        entitlementGeneration: 4,
        limit: 10
      })
    ).toThrow("duplicate feed sequence");
  });

  it("enforces read bounds, supports all-board cursors, and sorts either input direction", () => {
    const cursor = FeedCursorPayloadSchema.parse({
      schemaVersion: "boardagent.feed-cursor.v1",
      memberId: id(1),
      boardId: null,
      entitlementGeneration: 4,
      afterSequence: "0"
    });
    for (const limit of [0, 1.5, 1_001]) {
      expect(() =>
        listEntitledDeltas([], cursor, {
          memberId: id(1),
          boardId: null,
          entitlementGeneration: 4,
          limit
        })
      ).toThrow("between 1 and 1000");
    }
    for (const limit of [1, 1_000]) {
      expect(
        listEntitledDeltas([delta(1)], cursor, {
          memberId: id(1),
          boardId: null,
          entitlementGeneration: 4,
          limit
        }).map((item) => item.sequence)
      ).toEqual(["1"]);
    }
    const context = {
      memberId: id(1),
      boardId: null,
      entitlementGeneration: 4,
      limit: 10
    };
    expect(
      listEntitledDeltas([delta(10), delta(2), delta(1)], cursor, context).map(
        (item) => item.sequence
      )
    ).toEqual(["1", "2", "10"]);
    expect(
      listEntitledDeltas([delta(1), delta(2)], cursor, context).map((item) => item.sequence)
    ).toEqual(["1", "2"]);
    expect(
      listEntitledDeltas([delta(1), delta(2)], cursor, { ...context, limit: 1 }).map(
        (item) => item.sequence
      )
    ).toEqual(["1"]);
    expect(
      listEntitledDeltas(
        [
          delta(1),
          {
            ...delta(2),
            delta: { ...delta(2).delta, entitlementGeneration: 5 }
          }
        ],
        cursor,
        context
      ).map((item) => item.sequence)
    ).toEqual(["1"]);
  });
});
