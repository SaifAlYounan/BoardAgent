import { createHash } from "node:crypto";
import { MAX_JSON_CONTAINER_DEPTH, type JsonValue } from "@boardagent/contracts";
import {
  currentResponseAllocationOwner,
  ResponseAllocationUnavailable
} from "./response-allocation.js";

export interface InspectedProposalPayload {
  readonly value: JsonValue;
  readonly jsonBytesUpper: string;
  readonly properties: string;
  readonly containers: string;
  readonly maxDepth: number;
}

// Syntax remains JSON.parse's responsibility. Count raw containers before parsing,
// including duplicate-name branches that JSON.parse would subsequently discard.
function rawDepth(source: string): number {
  let depth = 0;
  let maximum = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (quoted) {
      if (!escaped && character === '"') quoted = false;
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
    } else if (character === '"') {
      quoted = true;
    } else if (character === "[" || character === "{") {
      depth += 1;
      maximum = Math.max(maximum, depth);
      if (depth > MAX_JSON_CONTAINER_DEPTH) throw new ResponseAllocationUnavailable();
    } else if (character === "]" || character === "}") {
      depth -= 1;
    }
  }
  return maximum;
}

function stringBytesUpper(value: string): bigint {
  if (!/^\p{ASCII}*$/u.test(value)) {
    if (!value.isWellFormed() || value !== value.normalize("NFC"))
      throw new ResponseAllocationUnavailable();
  }
  // Quotes plus worst-case JSON escaping; byte length includes every UTF-8 byte.
  return 2n + 6n * BigInt(Buffer.byteLength(value, "utf8"));
}

function* objectEntries(
  value: Readonly<Record<string, JsonValue>>
): Generator<readonly [string, JsonValue]> {
  for (const key of Object.keys(value)) yield [key, value[key]!] as const;
}

interface Frame {
  readonly entries: Iterator<readonly [string | number, JsonValue]>;
  readonly object: boolean;
  first: boolean;
}

function measure(value: JsonValue): Omit<InspectedProposalPayload, "value" | "maxDepth"> {
  let jsonBytes = 0n;
  let properties = 0n;
  let containers = 0n;
  let current = value;
  const stack: Frame[] = [];
  for (;;) {
    if (current !== null && typeof current === "object") {
      if (stack.length >= MAX_JSON_CONTAINER_DEPTH) throw new ResponseAllocationUnavailable();
      const array = Array.isArray(current);
      containers += 1n;
      jsonBytes += 2n;
      stack.push({
        entries: array
          ? (current as readonly JsonValue[]).entries()
          : objectEntries(current as Readonly<Record<string, JsonValue>>),
        object: !array,
        first: true
      });
    } else if (typeof current === "string") {
      jsonBytes += stringBytesUpper(current);
    } else if (typeof current === "number") {
      if (!Number.isFinite(current)) throw new ResponseAllocationUnavailable();
      // Native doubles have bounded encoding; no PostgreSQL numeric expansion occurs.
      jsonBytes += BigInt(JSON.stringify(current).length);
    } else {
      jsonBytes += current === false ? 5n : 4n;
    }

    for (;;) {
      const frame = stack.at(-1);
      if (!frame) {
        return {
          jsonBytesUpper: jsonBytes.toString(),
          properties: properties.toString(),
          containers: containers.toString()
        };
      }
      const next = frame.entries.next();
      if (next.done) {
        stack.pop();
        continue;
      }
      if (!frame.first) jsonBytes += 1n;
      frame.first = false;
      if (frame.object) {
        properties += 1n;
        jsonBytes += stringBytesUpper(next.value[0] as string) + 1n;
      }
      current = next.value[1];
      break;
    }
  }
}

// The caller MUST reserve raw inspection allocation before loading these exact
// bytes. assertLive prevents an ended owner from beginning inspection; it does not
// prove reservation. Retain the graph privately and the inspection lease through
// incremental final admission, fresh authorization/frontier checks and delivery.
export function inspectProposalPayload(
  bytes: Uint8Array,
  expected: { readonly canonicalBytes: number; readonly sha256: string }
): InspectedProposalPayload {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new Error("native response allocation owner is required");
  owner.assertLive();
  if (
    !Number.isSafeInteger(expected.canonicalBytes) ||
    expected.canonicalBytes < 0 ||
    !/^[a-f0-9]{64}$/u.test(expected.sha256)
  )
    throw new TypeError("invalid proposal payload binding");
  if (
    bytes.byteLength !== expected.canonicalBytes ||
    createHash("sha256").update(bytes).digest("hex") !== expected.sha256
  )
    throw new TypeError("proposal payload integrity mismatch");

  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new ResponseAllocationUnavailable();
  }
  const maxDepth = rawDepth(source);
  let value: JsonValue;
  try {
    value = JSON.parse(source) as JsonValue;
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new ResponseAllocationUnavailable();
  }
  return { value, ...measure(value), maxDepth };
}
