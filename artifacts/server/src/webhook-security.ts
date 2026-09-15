import { createCipheriv, createDecipheriv, randomBytes as nodeRandomBytes } from "node:crypto";
import { lookup as nodeLookup } from "node:dns/promises";
import { isIP } from "node:net";

import { UuidV7Schema, canonicalSha256, sha256Hex } from "@boardagent/contracts";

const CIPHERTEXT_MAGIC = Buffer.from("BAWH1", "ascii");
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const SECRET_BYTES = 32;
const MAX_ENDPOINT_BYTES = 4_000;
const MAX_DNS_ANSWERS = 16;
const DNS_TIMEOUT_MS = 5_000;

export interface WebhookResolvedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

export type WebhookResolver = (hostname: string) => Promise<readonly WebhookResolvedAddress[]>;

export interface ValidatedWebhookEndpoint {
  readonly endpoint: string;
  readonly endpointSha256: string;
  readonly validationReceiptSha256: string;
  readonly resolvedAddresses: readonly string[];
}

export interface ProtectedWebhookEndpoint extends ValidatedWebhookEndpoint {
  readonly keyId: string;
  readonly endpointCiphertext: Buffer;
}

export interface ProtectedWebhookSecret {
  /** Returned exactly once after a successful confirmed configuration/rotation. */
  readonly secret: string;
  readonly secretSha256: string;
  readonly keyId: string;
  readonly secretCiphertext: Buffer;
}

export interface WebhookSecurityPort {
  readonly activeKeyId: string;
  validateEndpoint(endpoint: string): Promise<ValidatedWebhookEndpoint>;
  protectEndpoint(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
    readonly endpoint: string;
  }): Promise<ProtectedWebhookEndpoint>;
  createSecret(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
  }): ProtectedWebhookSecret;
  openEndpoint(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
    readonly keyId: string;
    readonly endpointCiphertext: Uint8Array;
  }): string;
  openSecret(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
    readonly keyId: string;
    readonly secretCiphertext: Uint8Array;
  }): string;
}

export class WebhookEndpointRejectedError extends Error {
  public constructor(message = "webhook endpoint is not a public HTTPS destination") {
    super(message);
    this.name = "WebhookEndpointRejectedError";
  }
}

/** A transient resolution failure, not evidence that the endpoint is unsafe. */
export class WebhookResolutionTemporaryError extends Error {
  public constructor(message = "webhook DNS resolution is temporarily unavailable") {
    super(message);
    this.name = "WebhookResolutionTemporaryError";
  }
}

export class WebhookResolutionTimeoutError extends WebhookResolutionTemporaryError {
  public constructor() {
    super("webhook DNS resolution timed out");
    this.name = "WebhookResolutionTimeoutError";
  }
}

function parseIpv4(address: string): readonly number[] | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((part) => {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(part)) return -1;
    const value = Number(part);
    return value <= 255 ? value : -1;
  });
  return bytes.some((value) => value < 0) ? null : bytes;
}

function publicIpv4(address: string): boolean {
  const bytes = parseIpv4(address);
  if (!bytes) return false;
  const [a = -1, b = -1] = bytes;
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19 || b === 51)) ||
    (a === 203 && b === 0) ||
    a >= 224
  );
}

function ipv6Groups(value: string): readonly number[] | null {
  const address = value.toLowerCase();
  if (address.includes("%") || address.split("::").length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (side === "") return [];
    const groups: number[] = [];
    for (const part of side.split(":")) {
      if (part.includes(".")) {
        const ipv4 = parseIpv4(part);
        if (!ipv4) return null;
        groups.push((ipv4[0]! << 8) | ipv4[1]!, (ipv4[2]! << 8) | ipv4[3]!);
      } else {
        if (!/^[0-9a-f]{1,4}$/u.test(part)) return null;
        groups.push(Number.parseInt(part, 16));
      }
    }
    return groups;
  };
  const [leftText = "", rightText] = address.split("::");
  const left = parseSide(leftText);
  const right = parseSide(rightText ?? "");
  if (!left || !right) return null;
  if (rightText === undefined) return left.length === 8 ? left : null;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function publicIpv6(address: string): boolean {
  const groups = ipv6Groups(address);
  if (!groups) return false;
  const first = groups[0] ?? 0;
  const allZero = groups.every((value) => value === 0);
  const loopback = groups.slice(0, 7).every((value) => value === 0) && groups[7] === 1;
  const mappedIpv4 = groups.slice(0, 5).every((value) => value === 0) && groups[5] === 0xffff;
  const documentation = first === 0x2001 && groups[1] === 0x0db8;
  const teredo = first === 0x2001 && groups[1] === 0;
  const sixToFour = first === 0x2002;
  return (
    !allZero &&
    !loopback &&
    !mappedIpv4 &&
    !documentation &&
    !teredo &&
    !sixToFour &&
    (first & 0xe000) === 0x2000
  );
}

function publicAddress(address: string, family: 4 | 6): boolean {
  if (isIP(address) !== family) return false;
  return family === 4 ? publicIpv4(address) : publicIpv6(address);
}

function canonicalEndpoint(value: string): {
  readonly endpoint: string;
  readonly hostname: string;
} {
  if (Buffer.byteLength(value, "utf8") > MAX_ENDPOINT_BYTES) {
    throw new WebhookEndpointRejectedError("webhook endpoint exceeds the encrypted URL limit");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new WebhookEndpointRejectedError();
  }
  if (Buffer.byteLength(parsed.href, "utf8") > MAX_ENDPOINT_BYTES) {
    throw new WebhookEndpointRejectedError("webhook endpoint exceeds the encrypted URL limit");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.hostname === ""
  ) {
    throw new WebhookEndpointRejectedError();
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".home.arpa")
  ) {
    throw new WebhookEndpointRejectedError();
  }
  return { endpoint: parsed.href, hostname };
}

function exactKey(value: Uint8Array): Buffer {
  const key = Buffer.from(value);
  if (key.length !== 32) throw new RangeError("webhook data-encryption keys must contain 32 bytes");
  return key;
}

function aad(input: {
  readonly kind: "endpoint" | "secret";
  readonly organizationId: string;
  readonly memberId: string;
  readonly webhookId: string;
  readonly keyId: string;
}): Buffer {
  return Buffer.from(
    [
      "boardagent/webhook/aes-256-gcm/v1",
      input.kind,
      UuidV7Schema.parse(input.organizationId),
      UuidV7Schema.parse(input.memberId),
      UuidV7Schema.parse(input.webhookId),
      UuidV7Schema.parse(input.keyId)
    ].join("\0"),
    "utf8"
  );
}

export interface Aes256GcmWebhookSecurityOptions {
  readonly activeKeyId: string;
  readonly keys: ReadonlyMap<string, Uint8Array>;
  readonly resolve?: WebhookResolver;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export class Aes256GcmWebhookSecurity implements WebhookSecurityPort {
  public readonly activeKeyId: string;
  private readonly keys: ReadonlyMap<string, Buffer>;
  private readonly resolve: WebhookResolver;
  private readonly entropy: (length: number) => Buffer;

  public constructor(options: Aes256GcmWebhookSecurityOptions) {
    this.activeKeyId = UuidV7Schema.parse(options.activeKeyId);
    const keys = new Map<string, Buffer>();
    for (const [rawId, rawKey] of options.keys) {
      keys.set(UuidV7Schema.parse(rawId), exactKey(rawKey));
    }
    if (!keys.has(this.activeKeyId)) {
      throw new Error("active webhook data-encryption key is unavailable");
    }
    this.keys = keys;
    this.resolve =
      options.resolve ??
      (async (hostname) => {
        const answers = await nodeLookup(hostname, { all: true, verbatim: true });
        return answers.map(({ address, family }) => {
          if (family !== 4 && family !== 6) {
            throw new WebhookEndpointRejectedError("webhook DNS returned an invalid family");
          }
          return { address, family };
        });
      });
    const source = options.randomBytes ?? nodeRandomBytes;
    this.entropy = (length) => {
      const bytes = Buffer.from(source(length));
      if (bytes.length !== length) throw new Error("webhook entropy source returned wrong length");
      return bytes;
    };
  }

  private key(keyId: string): Buffer {
    const key = this.keys.get(UuidV7Schema.parse(keyId));
    if (!key) throw new Error("webhook data-encryption key is unavailable");
    return key;
  }

  private seal(plaintext: Uint8Array, keyId: string, binding: Buffer): Buffer {
    const nonce = this.entropy(NONCE_BYTES);
    const cipher = createCipheriv("aes-256-gcm", this.key(keyId), nonce);
    cipher.setAAD(binding);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([CIPHERTEXT_MAGIC, nonce, ciphertext, cipher.getAuthTag()]);
  }

  private open(ciphertextValue: Uint8Array, keyId: string, binding: Buffer): Buffer {
    const envelope = Buffer.from(ciphertextValue);
    const minimum = CIPHERTEXT_MAGIC.length + NONCE_BYTES + TAG_BYTES + 1;
    if (
      envelope.length < minimum ||
      envelope.length > 4_096 ||
      !envelope.subarray(0, CIPHERTEXT_MAGIC.length).equals(CIPHERTEXT_MAGIC)
    ) {
      throw new Error("webhook ciphertext envelope is invalid");
    }
    const nonceStart = CIPHERTEXT_MAGIC.length;
    const ciphertextStart = nonceStart + NONCE_BYTES;
    const tagStart = envelope.length - TAG_BYTES;
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.key(keyId),
        envelope.subarray(nonceStart, ciphertextStart)
      );
      decipher.setAAD(binding);
      decipher.setAuthTag(envelope.subarray(tagStart));
      return Buffer.concat([
        decipher.update(envelope.subarray(ciphertextStart, tagStart)),
        decipher.final()
      ]);
    } catch {
      throw new Error("webhook ciphertext authentication failed");
    }
  }

  private async resolveWithinDeadline(
    hostname: string
  ): Promise<readonly WebhookResolvedAddress[]> {
    const expiresAt = performance.now() + DNS_TIMEOUT_MS;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_resolve, reject) => {
      deadline = setTimeout(() => reject(new WebhookResolutionTimeoutError()), DNS_TIMEOUT_MS);
    });
    try {
      // Bound server configuration/test calls too. The delivery worker has its own
      // shared attempt budget, but these callers do not run inside that worker.
      // OS lookup itself is not cancellable; race observes and ignores late outcomes.
      const answers = await Promise.race([this.resolve(hostname), expired]);
      if (performance.now() >= expiresAt) throw new WebhookResolutionTimeoutError();
      return answers;
    } catch (error) {
      // Only the DNS resolver's temporary failure receives this marker. Invalid
      // endpoints, unsafe answers and unrelated validation errors stay permanent.
      if (error instanceof Error && "code" in error && error.code === "EAI_AGAIN") {
        throw new WebhookResolutionTemporaryError();
      }
      throw error;
    } finally {
      clearTimeout(deadline);
    }
  }

  public async validateEndpoint(value: string): Promise<ValidatedWebhookEndpoint> {
    const { endpoint, hostname } = canonicalEndpoint(value);
    const literalFamily = isIP(hostname);
    const rawAnswers =
      literalFamily === 4 || literalFamily === 6
        ? [{ address: hostname, family: literalFamily } as const]
        : await this.resolveWithinDeadline(hostname);
    if (rawAnswers.length < 1 || rawAnswers.length > MAX_DNS_ANSWERS) {
      throw new WebhookEndpointRejectedError("webhook DNS answer count is invalid");
    }
    const resolved = [
      ...new Set(rawAnswers.map(({ address }) => address.toLowerCase()))
    ].toSorted();
    if (
      resolved.length !== rawAnswers.length ||
      rawAnswers.some(({ address, family }) => !publicAddress(address.toLowerCase(), family))
    ) {
      throw new WebhookEndpointRejectedError();
    }
    const endpointSha256 = sha256Hex(endpoint);
    const validationReceiptSha256 = canonicalSha256({
      schemaVersion: "boardagent.webhook-ssrf-validation.v1",
      endpointSha256,
      hostname,
      resolvedAddresses: resolved,
      redirectPolicy: "manual-reject",
      addressPolicy: "public-only-v1"
    });
    return { endpoint, endpointSha256, validationReceiptSha256, resolvedAddresses: resolved };
  }

  public async protectEndpoint(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
    readonly endpoint: string;
  }): Promise<ProtectedWebhookEndpoint> {
    const validated = await this.validateEndpoint(input.endpoint);
    const keyId = this.activeKeyId;
    const endpointCiphertext = this.seal(
      Buffer.from(validated.endpoint, "utf8"),
      keyId,
      aad({ ...input, kind: "endpoint", keyId })
    );
    return { ...validated, keyId, endpointCiphertext };
  }

  public createSecret(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
  }): ProtectedWebhookSecret {
    const keyId = this.activeKeyId;
    const secretBytes = this.entropy(SECRET_BYTES);
    try {
      const secret = secretBytes.toString("base64url");
      return {
        secret,
        secretSha256: sha256Hex(secretBytes),
        keyId,
        secretCiphertext: this.seal(secretBytes, keyId, aad({ ...input, kind: "secret", keyId }))
      };
    } finally {
      secretBytes.fill(0);
    }
  }

  /** Operator crypto only: preserves the external secret; SQL must bind and audit the change. */
  public rewrapStoredMaterial(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
    readonly keyId: string;
    readonly endpointCiphertext: Uint8Array;
    readonly endpointSha256: string;
    readonly secretCiphertext: Uint8Array;
    readonly secretSha256: string;
  }): {
    readonly keyId: string;
    readonly endpointCiphertext: Buffer;
    readonly secretCiphertext: Buffer;
  } {
    if (
      input.keyId === this.activeKeyId ||
      this.key(input.keyId).equals(this.key(this.activeKeyId))
    ) {
      throw new Error("webhook rewrap requires distinct key material");
    }
    let endpoint: Buffer | undefined;
    let secret: Buffer | undefined;
    try {
      endpoint = this.open(
        input.endpointCiphertext,
        input.keyId,
        aad({ ...input, kind: "endpoint" })
      );
      secret = this.open(input.secretCiphertext, input.keyId, aad({ ...input, kind: "secret" }));
      const endpointText = new TextDecoder("utf-8", { fatal: true }).decode(endpoint);
      if (
        secret.length !== SECRET_BYTES ||
        canonicalEndpoint(endpointText).endpoint !== endpointText ||
        sha256Hex(endpoint) !== input.endpointSha256 ||
        sha256Hex(secret) !== input.secretSha256
      ) {
        throw new Error("webhook plaintext does not match its recorded identity");
      }
      const keyId = this.activeKeyId;
      return {
        keyId,
        endpointCiphertext: this.seal(endpoint, keyId, aad({ ...input, kind: "endpoint", keyId })),
        secretCiphertext: this.seal(secret, keyId, aad({ ...input, kind: "secret", keyId }))
      };
    } finally {
      endpoint?.fill(0);
      secret?.fill(0);
    }
  }

  public openEndpoint(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
    readonly keyId: string;
    readonly endpointCiphertext: Uint8Array;
  }): string {
    const endpoint = this.open(
      input.endpointCiphertext,
      input.keyId,
      aad({ ...input, kind: "endpoint" })
    ).toString("utf8");
    return canonicalEndpoint(endpoint).endpoint;
  }

  public openSecret(input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly webhookId: string;
    readonly keyId: string;
    readonly secretCiphertext: Uint8Array;
  }): string {
    const bytes = this.open(input.secretCiphertext, input.keyId, aad({ ...input, kind: "secret" }));
    try {
      if (bytes.length !== SECRET_BYTES) throw new Error("webhook secret plaintext is invalid");
      return bytes.toString("base64url");
    } finally {
      bytes.fill(0);
    }
  }
}
