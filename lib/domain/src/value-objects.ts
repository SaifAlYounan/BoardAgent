/*
 * Adapted from LQGovernance-OpenBoard, commit
 * 1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb, vote tally and voting value objects.
 * Copyright (c) 2026 Alexios Kirillov. Licensed under the Apache License 2.0.
 * Derived from LQGovernance-OpenBoard (MIT License); see docs/THIRD_PARTY_NOTICES.md.
 * Hostile changes: bounded BigInt weights, exact rational cross-multiplication and
 * server-generated ambiguous-character-free confirmation codes.
 */
import { randomBytes } from "node:crypto";

export const MAX_VOTING_WEIGHT = 1_000_000_000n;

export interface Rational {
  readonly numerator: bigint;
  readonly denominator: bigint;
}

export function rational(numerator: bigint, denominator: bigint): Rational {
  if (denominator <= 0n) throw new RangeError("denominator must be positive");
  if (numerator < 0n || numerator > denominator)
    throw new RangeError("fraction must be between zero and one");
  return { numerator, denominator };
}

export function meetsFraction(value: bigint, total: bigint, fraction: Rational): boolean {
  if (value < 0n || total < 0n) throw new RangeError("weights cannot be negative");
  return value * fraction.denominator >= total * fraction.numerator;
}

export function assertWeight(value: bigint): bigint {
  if (value <= 0n || value > MAX_VOTING_WEIGHT) throw new RangeError("invalid voting weight");
  return value;
}

const UUID_V7_MAX_TIMESTAMP = 281_474_976_710_655;

export function uuidV7(timestampMs: number, random: Uint8Array): string {
  if (!Number.isInteger(timestampMs) || timestampMs < 0 || timestampMs > UUID_V7_MAX_TIMESTAMP) {
    throw new RangeError("UUIDv7 timestamp must be a 48-bit nonnegative integer");
  }
  if (random.length !== 10) throw new RangeError("UUIDv7 requires exactly 10 random bytes");

  const bytes = new Uint8Array(16);
  let timestamp = BigInt(timestampMs);
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  // The exact-length guard above proves these three bytes exist.
  bytes[6] = 0x70 | (random[0]! & 0x0f);
  bytes[7] = random[1]!;
  bytes[8] = 0x80 | (random[2]! & 0x3f);
  bytes.set(random.subarray(3), 9);

  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function uuidV7TimestampMs(value: string): number {
  const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  if (!pattern.test(value)) throw new TypeError("value is not a canonical UUIDv7");
  return Number(BigInt(`0x${value.slice(0, 8)}${value.slice(9, 13)}`));
}

export function confirmationCode(random = randomBytes): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = random(8);
  let code = "";
  for (const byte of bytes) code += alphabet[byte % alphabet.length];
  return code;
}
