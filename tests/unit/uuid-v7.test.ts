import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { UuidV7Schema } from "../../lib/contracts/src/index.js";
import {
  assertWeight,
  confirmationCode,
  meetsFraction,
  rational,
  uuidV7,
  uuidV7TimestampMs
} from "../../lib/domain/src/index.js";

describe("UUIDv7 value object", () => {
  it("sets RFC 9562 version and variant bits and preserves the 48-bit timestamp", () => {
    const timestamp = Date.UTC(2026, 7, 31, 14, 30, 0, 123);
    const id = uuidV7(timestamp, Uint8Array.from([0xab, 1, 0xff, 2, 3, 4, 5, 6, 7, 8]));

    expect(id).toBe("01a0583a-22bb-7b01-bf02-030405060708");
    expect(UuidV7Schema.parse(id)).toBe(id);
    expect(id[14]).toBe("7");
    expect(id[19]).toMatch(/[89ab]/u);
    expect(uuidV7TimestampMs(id)).toBe(timestamp);
  });

  it("sorts lexically by timestamp", () => {
    const random = new Uint8Array(10);
    const ids = [uuidV7(3, random), uuidV7(1, random), uuidV7(2, random)];
    expect(ids.toSorted()).toEqual([uuidV7(1, random), uuidV7(2, random), uuidV7(3, random)]);
  });

  it("round-trips arbitrary valid timestamps and random bits", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 281_474_976_710_655 }),
        fc.uint8Array({ minLength: 10, maxLength: 10 }),
        (timestamp, random) => {
          const id = uuidV7(timestamp, random);
          expect(UuidV7Schema.safeParse(id).success).toBe(true);
          expect(uuidV7TimestampMs(id)).toBe(timestamp);
        }
      ),
      { numRuns: 10_000, endOnFailure: true }
    );
  });

  it.each([-1, 0.1, Number.NaN, 281_474_976_710_656])(
    "rejects invalid timestamp %s",
    (timestamp) => {
      expect(() => uuidV7(timestamp, new Uint8Array(10))).toThrow("timestamp");
    }
  );

  it("rejects incorrect random-byte length and non-v7 UUIDs", () => {
    expect(() => uuidV7(1, new Uint8Array(9))).toThrow("10 random bytes");
    for (const malformed of [
      "00000000-0000-4000-8000-000000000000",
      "x00000000-0000-7000-8000-000000000000",
      "00000000-0000-7000-8000-000000000000x",
      "0-0000-7000-8000-000000000000",
      "gggggggg-0000-7000-8000-000000000000",
      "00000000-0-7000-8000-000000000000",
      "00000000-gggg-7000-8000-000000000000",
      "00000000-0000-70-8000-000000000000",
      "00000000-0000-7ggg-8000-000000000000",
      "00000000-0000-7000-7000-000000000000",
      "00000000-0000-7000-80-000000000000",
      "00000000-0000-7000-8ggg-000000000000",
      "00000000-0000-7000-8000-0",
      "00000000-0000-7000-8000-gggggggggggg"
    ]) {
      expect(() => uuidV7TimestampMs(malformed)).toThrow("canonical UUIDv7");
    }
    expect(UuidV7Schema.safeParse("00000000-0000-4000-8000-000000000000").success).toBe(false);
  });

  it("enforces exact rational and voting-weight bounds", () => {
    expect(rational(0n, 1n)).toEqual({ numerator: 0n, denominator: 1n });
    expect(rational(1n, 1n)).toEqual({ numerator: 1n, denominator: 1n });
    expect(() => rational(0n, 0n)).toThrow("denominator");
    expect(() => rational(-1n, 1n)).toThrow("between zero and one");
    expect(() => rational(2n, 1n)).toThrow("between zero and one");
    expect(meetsFraction(1n, 2n, rational(1n, 2n))).toBe(true);
    expect(meetsFraction(0n, 0n, rational(1n, 2n))).toBe(true);
    expect(meetsFraction(1n, 3n, rational(2n, 3n))).toBe(false);
    expect(() => meetsFraction(-1n, 1n, rational(1n, 2n))).toThrow("negative");
    expect(() => meetsFraction(1n, -1n, rational(1n, 2n))).toThrow("negative");
    expect(assertWeight(1n)).toBe(1n);
    expect(assertWeight(1_000_000_000n)).toBe(1_000_000_000n);
    expect(() => assertWeight(0n)).toThrow("voting weight");
    expect(() => assertWeight(1_000_000_001n)).toThrow("voting weight");
  });

  it("generates eight-character unambiguous confirmation codes", () => {
    expect(confirmationCode(() => Buffer.from([0, 1, 2, 3, 4, 5, 6, 31]))).toBe("ABCDEFG9");
    expect(confirmationCode()).toMatch(/^[A-HJ-NP-Z2-9]{8}$/u);
  });
});
