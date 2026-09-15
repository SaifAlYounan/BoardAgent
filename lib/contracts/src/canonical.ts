import { createHash, timingSafeEqual } from "node:crypto";

import canonicalize from "canonicalize";

export type JsonPrimitive = boolean | null | number | string;
export type JsonValue =
  JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export class CanonicalizationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

// A resource bound for recursive parsers/encoders, not a governance schema rule.
// Scalars have depth zero; the root object or array counts as one container.
export const MAX_JSON_CONTAINER_DEPTH = 512;

function assertUnicodeScalar(value: string, path: string): void {
  // ASCII consists entirely of Unicode scalar values already in NFC. The native
  // scan avoids allocating a normalized copy of long hexadecimal inventory data.
  if (/^\p{ASCII}*$/u.test(value)) return;
  if (!value.isWellFormed()) {
    throw new CanonicalizationError(`${path} contains an unpaired surrogate`);
  }
  if (value !== value.normalize("NFC")) {
    throw new CanonicalizationError(`${path} must use Unicode NFC`);
  }
}

function assertJsonScalar(value: unknown, path: string): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    assertUnicodeScalar(value, path);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError(`${path} must be a finite JSON number`);
    }
    return;
  }
  throw new CanonicalizationError(`${path} is not a JSON value`);
}

function* arrayEntries(value: readonly unknown[]): Generator<[string, unknown]> {
  // Match the existing forEach validation: snapshot length and skip absent slots.
  const length = value.length;
  for (let index = 0; index < length; index += 1) {
    if (index in value) yield [String(index), value[index]];
  }
}

interface JsonFrame {
  readonly container: object;
  readonly entries: Iterator<[string, unknown]>;
  readonly path: string;
  readonly array: boolean;
}

function walkJsonStructure(value: unknown, validateValues: boolean): void {
  const ancestors = new WeakSet<object>();
  const stack: JsonFrame[] = [];
  let current = value;
  let path = "$";
  for (;;) {
    if (current !== null && typeof current === "object") {
      const array = Array.isArray(current);
      if (validateValues && !array) {
        const prototype = Object.getPrototypeOf(current);
        if (prototype !== Object.prototype && prototype !== null) {
          throw new CanonicalizationError(`${path} must be a plain JSON object`);
        }
      }
      if (ancestors.has(current)) {
        throw new CanonicalizationError(`${path} contains a JSON cycle`);
      }
      if (stack.length >= MAX_JSON_CONTAINER_DEPTH) {
        throw new CanonicalizationError(
          `JSON exceeds ${String(MAX_JSON_CONTAINER_DEPTH)} nested containers at ${path}`
        );
      }
      ancestors.add(current);
      stack.push({
        container: current,
        entries: array
          ? arrayEntries(current as readonly unknown[])
          : Object.entries(current)[Symbol.iterator](),
        path,
        array
      });
    } else if (validateValues) {
      assertJsonScalar(current, path);
    }

    for (;;) {
      const frame = stack.at(-1);
      if (!frame) return;
      const next = frame.entries.next();
      if (next.done) {
        ancestors.delete(frame.container);
        stack.pop();
        continue;
      }
      const [key, entry] = next.value;
      if (validateValues && !frame.array) {
        assertUnicodeScalar(key, `${frame.path} object name`);
        if (entry === undefined) {
          throw new CanonicalizationError(`${frame.path}.${key} cannot be undefined`);
        }
      }
      current = entry;
      path = frame.array ? `${frame.path}[${key}]` : `${frame.path}.${key}`;
      break;
    }
  }
}

// Admission must precede recursive schema parsing. Leave scalar/type validation to
// that schema (including its optional fields), and preserve unrelated thrown errors.
export function assertJsonStructure(value: unknown): void {
  walkJsonStructure(value, false);
}

function assertJsonValue(value: unknown): asserts value is JsonValue {
  walkJsonStructure(value, true);
}

function assertJsonTextStructure(source: string): void {
  let depth = 0;
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
      if (depth > MAX_JSON_CONTAINER_DEPTH) {
        throw new CanonicalizationError(
          `JSON exceeds ${String(MAX_JSON_CONTAINER_DEPTH)} nested containers at offset ${String(index)}`
        );
      }
    } else if (character === "]" || character === "}") {
      depth -= 1;
    }
  }
  // The strict parser still owns grammar, duplicate-name and Unicode validation.
}

function decodeUtf8(value: Uint8Array | string): string {
  if (typeof value === "string") return value;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(value);
  } catch {
    throw new CanonicalizationError("input is not strict UTF-8");
  }
}

class StrictJsonParser {
  private index = 0;

  public constructor(private readonly source: string) {}

  public parse(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue("$");
    this.skipWhitespace();
    if (this.index !== this.source.length) {
      throw new CanonicalizationError(`trailing JSON bytes at offset ${String(this.index)}`);
    }
    return value;
  }

  private parseValue(path: string): JsonValue {
    const current = this.source[this.index];
    if (current === '"') return this.parseString(path);
    if (current === "{") return this.parseObject(path);
    if (current === "[") return this.parseArray(path);
    if (current === "t") return this.parseLiteral("true", true);
    if (current === "f") return this.parseLiteral("false", false);
    if (current === "n") return this.parseLiteral("null", null);
    if (current === "-" || (current !== undefined && current >= "0" && current <= "9")) {
      return this.parseNumber(path);
    }
    throw new CanonicalizationError(`invalid JSON value at ${path}`);
  }

  private parseObject(path: string): Readonly<Record<string, JsonValue>> {
    this.index += 1;
    this.skipWhitespace();
    const result: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    const names = new Set<string>();
    if (this.consume("}")) return result;
    for (;;) {
      if (this.source[this.index] !== '"') {
        throw new CanonicalizationError(`object name required at ${path}`);
      }
      const name = this.parseString(`${path} object name`);
      if (names.has(name)) {
        throw new CanonicalizationError(`duplicate object name at ${path}: ${name}`);
      }
      names.add(name);
      this.skipWhitespace();
      if (!this.consume(":")) throw new CanonicalizationError(`missing colon at ${path}.${name}`);
      this.skipWhitespace();
      result[name] = this.parseValue(`${path}.${name}`);
      this.skipWhitespace();
      if (this.consume("}")) return result;
      if (!this.consume(",")) throw new CanonicalizationError(`missing comma at ${path}`);
      this.skipWhitespace();
    }
  }

  private parseArray(path: string): readonly JsonValue[] {
    this.index += 1;
    this.skipWhitespace();
    const result: JsonValue[] = [];
    if (this.consume("]")) return result;
    for (;;) {
      result.push(this.parseValue(`${path}[${String(result.length)}]`));
      this.skipWhitespace();
      if (this.consume("]")) return result;
      if (!this.consume(",")) throw new CanonicalizationError(`missing comma at ${path}`);
      this.skipWhitespace();
    }
  }

  private parseString(path: string): string {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.source.length) {
      const unit = this.source.charCodeAt(this.index);
      const character = this.source[this.index];
      if (!escaped && character === '"') {
        this.index += 1;
        let value: string;
        try {
          value = JSON.parse(this.source.slice(start, this.index)) as string;
        } catch {
          throw new CanonicalizationError(`malformed JSON string at ${path}`);
        }
        assertUnicodeScalar(value, path);
        return value;
      }
      if (!escaped && unit <= 0x1f) {
        throw new CanonicalizationError(`unescaped control character at ${path}`);
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
      this.index += 1;
    }
    throw new CanonicalizationError(`unterminated JSON string at ${path}`);
  }

  private parseNumber(path: string): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(
      this.source.slice(this.index)
    );
    if (!match) throw new CanonicalizationError(`malformed JSON number at ${path}`);
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError(`${path} must be a finite JSON number`);
    }
    return value;
  }

  private parseLiteral<T extends boolean | null>(literal: string, value: T): T {
    if (!this.source.startsWith(literal, this.index)) {
      throw new CanonicalizationError(`malformed JSON literal at offset ${String(this.index)}`);
    }
    this.index += literal.length;
    return value;
  }

  private skipWhitespace(): void {
    while (
      this.source[this.index] === " " ||
      this.source[this.index] === "\n" ||
      this.source[this.index] === "\r" ||
      this.source[this.index] === "\t"
    ) {
      this.index += 1;
    }
  }

  private consume(character: string): boolean {
    if (this.source[this.index] !== character) return false;
    this.index += 1;
    return true;
  }
}

const GENERAL_ENCODING_REQUIRED = Symbol("general encoding required");

// Native JSON serialization supplies RFC 8785 scalar encoding. Inserting ordinary
// property names in sorted UTF-16 order supplies its object order, recursively.
// Integer-index names are reordered by JavaScript and must use the original encoder.
// Null-prototype copies prevent inherited serializers/properties from entering the
// result; methods, accessors and sparse arrays retain the original encoder behavior.
function sortedJsonCopy(value: JsonValue): JsonValue {
  if (value === null || typeof value !== "object") return value;
  if (typeof (value as Record<string, unknown>)["toJSON"] === "function")
    throw GENERAL_ENCODING_REQUIRED;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor)) throw GENERAL_ENCODING_REQUIRED;
    }
    return value.map(sortedJsonCopy);
  }
  const result: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
  for (const key of Object.keys(value).sort()) {
    const integer = Number(key);
    if (
      Number.isInteger(integer) &&
      integer >= 0 &&
      integer < 4_294_967_295 &&
      String(integer) === key
    )
      throw GENERAL_ENCODING_REQUIRED;
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor)) throw GENERAL_ENCODING_REQUIRED;
    result[key] = sortedJsonCopy(descriptor.value as JsonValue);
  }
  return result;
}

export function canonicalJson(value: unknown): string {
  assertJsonValue(value);
  try {
    return JSON.stringify(sortedJsonCopy(value));
  } catch (error) {
    if (error !== GENERAL_ENCODING_REQUIRED) throw error;
    // Strict validation excludes inputs for which the encoder returns undefined.
    return canonicalize(value) as string;
  }
}

export function canonicalJsonFromText(value: Uint8Array | string): string {
  const source = decodeUtf8(value);
  if (source.startsWith("\ufeff")) throw new CanonicalizationError("JSON byte-order mark rejected");
  assertJsonTextStructure(source);
  return canonicalJson(new StrictJsonParser(source).parse());
}

export function canonicalText(value: Uint8Array | string): string {
  const text = decodeUtf8(value);
  if (text.startsWith("\ufeff")) throw new CanonicalizationError("text byte-order mark rejected");
  if (text.includes("\r"))
    throw new CanonicalizationError("canonical text requires LF line endings");
  assertUnicodeScalar(text, "text");
  return text;
}

export function sha256Bytes(value: Uint8Array | string): Uint8Array {
  return createHash("sha256").update(value).digest();
}

export function sha256Hex(value: Uint8Array | string): string {
  return Buffer.from(sha256Bytes(value)).toString("hex");
}

export function canonicalSha256(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

export function safeHashEqual(leftHex: string, rightHex: string): boolean {
  if (!/^[0-9a-f]{64}$/u.test(leftHex) || !/^[0-9a-f]{64}$/u.test(rightHex)) return false;
  return timingSafeEqual(Buffer.from(leftHex, "hex"), Buffer.from(rightHex, "hex"));
}
