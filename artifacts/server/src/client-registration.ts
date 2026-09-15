import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { isIP, type LookupFunction } from "node:net";

import type { Pool, PoolClient } from "pg";
import { z } from "zod";

import { canonicalJsonFromText, OAuthRedirectUriSchema, UuidV7Schema } from "@boardagent/contracts";
import { appendAuditEventsInTransaction, withIdentityTransaction } from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

import { AuthRequestBoundary } from "./auth-page.js";
import { PgRateLimiter, type RateLimitPolicy } from "./pg-rate-limiter.js";

export const MAX_CLIENT_METADATA_BYTES = 32 * 1024;
const MAX_CIMD_ADDRESSES = 16;
const DEFAULT_CIMD_TIMEOUT_MS = 5_000;
const DCR_CLIENT_ID_PATTERN = /^ba_dcr_[A-Za-z0-9_-]{43}$/u;
const SCOPE_PATTERN = /^[a-z][a-z0-9:_-]{0,127}$/u;

export type ProtocolClientIdKind = "verified_cimd_url" | "dcr_opaque" | "preregistered";

export interface TypedProtocolClientId {
  readonly kind: ProtocolClientIdKind;
  readonly value: string;
}

export interface NormalizedClientMetadata {
  readonly clientId?: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
  readonly grantTypes: readonly ["authorization_code", "refresh_token"];
  readonly responseTypes: readonly ["code"];
  readonly tokenEndpointAuthMethod: "none";
  readonly scopes: readonly string[];
  readonly softwareId?: string;
  readonly canonicalMetadata: string;
  readonly metadataSha256: Buffer;
}

export interface CimdResolvedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

export type CimdHostResolver = (hostname: string) => Promise<readonly CimdResolvedAddress[]>;

export interface CimdDocumentFetchRequest {
  readonly clientId: string;
  readonly pinnedAddresses: readonly CimdResolvedAddress[];
  readonly maxBytes: number;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface CimdDocumentFetchResponse {
  readonly statusCode: number;
  readonly contentType: string | undefined;
  readonly body: Uint8Array;
}

export type CimdDocumentFetcher = (
  request: CimdDocumentFetchRequest
) => Promise<CimdDocumentFetchResponse>;

export class ClientRegistrationError extends Error {
  public constructor(
    public readonly code: string,
    public readonly statusCode: number = 400,
    public readonly retryAfterSeconds: number = 0
  ) {
    super(code);
    this.name = "ClientRegistrationError";
  }
}

function refuse(code: string, statusCode = 400, retryAfterSeconds = 0): never {
  throw new ClientRegistrationError(code, statusCode, retryAfterSeconds);
}

function parseUrl(value: string, code: string): URL {
  if (
    value.length === 0 ||
    value.length > 2048 ||
    Buffer.byteLength(value, "utf8") > 2048 ||
    value !== value.normalize("NFC")
  ) {
    refuse(code);
  }
  try {
    return new URL(value);
  } catch {
    refuse(code);
  }
}

export function validateOAuthRedirectUri(value: string): string {
  const parsed = OAuthRedirectUriSchema.safeParse(value);
  if (!parsed.success) refuse("invalid_redirect_uri");
  return parsed.data;
}

function validDnsHostname(hostname: string): boolean {
  if (
    hostname.length === 0 ||
    hostname.length > 253 ||
    hostname.endsWith(".") ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    isIP(hostname) !== 0
  ) {
    return false;
  }
  const labels = hostname.split(".");
  return (
    labels.length >= 2 &&
    labels.every(
      (label) =>
        label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    )
  );
}

export function validateCimdClientId(value: string): string {
  const url = parseUrl(value, "cimd_url_refused");
  if (
    url.href !== value ||
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    !validDnsHostname(url.hostname)
  ) {
    refuse("cimd_url_refused");
  }
  return value;
}

function ipv4Number(address: string): number | null {
  if (isIP(address) !== 4) return null;
  const octets = address.split(".").map(Number);
  if (octets.length !== 4) return null;
  return ((octets[0]! << 24) >>> 0) + (octets[1]! << 16) + (octets[2]! << 8) + octets[3]!;
}

function ipv4Subnet(address: number, base: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (address & mask) >>> 0 === (base & mask) >>> 0;
}

const FORBIDDEN_IPV4_RANGES = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
] as const;

function publicIpv4(address: string): boolean {
  const numeric = ipv4Number(address);
  if (numeric === null) return false;
  return !FORBIDDEN_IPV4_RANGES.some(([base, prefix]) => {
    const baseNumber = ipv4Number(base);
    return baseNumber !== null && ipv4Subnet(numeric, baseNumber, prefix);
  });
}

function ipv6Groups(value: string): readonly number[] | null {
  if (value.includes("%") || isIP(value) !== 6) return null;
  let expanded = value.toLowerCase();
  const lastColon = expanded.lastIndexOf(":");
  const embedded = expanded.slice(lastColon + 1);
  const embeddedIpv4 = ipv4Number(embedded);
  if (embeddedIpv4 !== null) {
    expanded = `${expanded.slice(0, lastColon)}:${((embeddedIpv4 >>> 16) & 0xffff).toString(
      16
    )}:${(embeddedIpv4 & 0xffff).toString(16)}`;
  }
  const halves = expanded.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] === "" ? [] : halves[0]!.split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1]!.split(":");
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right].map((part) =>
    Number.parseInt(part, 16)
  );
  if (
    groups.length !== 8 ||
    groups.some((group) => !Number.isInteger(group) || group < 0 || group > 0xffff)
  ) {
    return null;
  }
  return groups;
}

function publicIpv6(address: string): boolean {
  const groups = ipv6Groups(address);
  if (!groups) return false;
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    const mapped = `${String(groups[6]! >>> 8)}.${String(groups[6]! & 0xff)}.${String(
      groups[7]! >>> 8
    )}.${String(groups[7]! & 0xff)}`;
    return publicIpv4(mapped);
  }
  // Conservatively admit only global-unicast 2000::/3 and exclude IETF/documentation
  // allocations whose routing semantics can hide a non-public destination.
  if (groups[0]! < 0x2000 || groups[0]! > 0x3fff) return false;
  if (groups[0] === 0x2001 && (groups[1]! <= 0x01ff || groups[1] === 0x0db8)) return false;
  if (groups[0] === 0x2002) return false;
  if (groups[0] === 0x3fff && (groups[1]! & 0xf000) === 0) return false;
  return true;
}

export function isPublicCimdAddress(address: string): boolean {
  const family = isIP(address);
  return family === 4 ? publicIpv4(address) : family === 6 ? publicIpv6(address) : false;
}

const SafeTextSchema = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine(
      (value) =>
        value === value.trim() &&
        value === value.normalize("NFC") &&
        [...value].every((character) => {
          const codePoint = character.codePointAt(0);
          return codePoint !== undefined && codePoint > 0x1f && codePoint !== 0x7f;
        })
    );

const InformationalHttpsUrlSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine((value) => {
    try {
      const url = new URL(value);
      return (
        url.href === value &&
        url.protocol === "https:" &&
        url.username === "" &&
        url.password === ""
      );
    } catch {
      return false;
    }
  }, "informational client URLs must be canonical HTTPS");

const BaseClientMetadataSchema = z
  .object({
    client_name: SafeTextSchema(120),
    redirect_uris: z.array(z.string().min(1).max(2048)).min(1).max(10),
    grant_types: z
      .array(z.enum(["authorization_code", "refresh_token"]))
      .min(2)
      .max(2),
    response_types: z.tuple([z.literal("code")]),
    token_endpoint_auth_method: z.literal("none"),
    scope: z.string().min(1).max(4096).optional(),
    software_id: SafeTextSchema(200).optional(),
    // RFC 7591 §2 informational fields released clients send (Claude Code 2.1.270 sends
    // `application_type: "native"`; the MCP SDK schema allows the others). They are
    // bounded and accepted, never used for authority, and anything else stays refused.
    application_type: z.enum(["native", "web"]).optional(),
    client_uri: InformationalHttpsUrlSchema.optional(),
    logo_uri: InformationalHttpsUrlSchema.optional(),
    tos_uri: InformationalHttpsUrlSchema.optional(),
    policy_uri: InformationalHttpsUrlSchema.optional(),
    contacts: z.array(SafeTextSchema(320)).max(10).optional(),
    software_version: SafeTextSchema(64).optional()
  })
  .strict();

const CimdClientMetadataSchema = BaseClientMetadataSchema.extend({
  client_id: z.string().min(1).max(2048)
}).strict();

function parseCanonicalObject(
  body: Uint8Array | string,
  schema: typeof BaseClientMetadataSchema | typeof CimdClientMetadataSchema
): { readonly canonical: string; readonly parsed: z.infer<typeof CimdClientMetadataSchema> } {
  const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
  if (bytes.length === 0 || bytes.length > MAX_CLIENT_METADATA_BYTES) {
    refuse("client_metadata_size_refused");
  }
  try {
    const canonical = canonicalJsonFromText(bytes);
    const parsed = schema.parse(JSON.parse(canonical)) as z.infer<typeof CimdClientMetadataSchema>;
    return { canonical, parsed };
  } catch (error) {
    if (error instanceof ClientRegistrationError) throw error;
    refuse("invalid_client_metadata");
  }
}

function normalizedScopes(
  scope: string | undefined,
  allowedScopeValues: readonly string[]
): string[] {
  const allowedScopes = [...allowedScopeValues].map((scopeValue) => {
    if (!SCOPE_PATTERN.test(scopeValue)) refuse("invalid_client_scope");
    return scopeValue;
  });
  if (allowedScopes.length === 0 || new Set(allowedScopes).size !== allowedScopes.length) {
    refuse("invalid_client_scope");
  }
  allowedScopes.sort();
  if (scope === undefined) return allowedScopes;
  if (!SCOPE_PATTERN.test(scope.split(" ")[0] ?? "") || !/^[^ ]+(?: [^ ]+)*$/u.test(scope)) {
    refuse("invalid_client_scope");
  }
  // The OpenID library advertises `openid` in the authorization-server metadata, and a
  // released client (Claude Code) copies that list verbatim into its registration.
  // BoardAgent grants no OpenID scope: `openid` is dropped from the request and the
  // registration response states the scopes actually registered (RFC 7591 §3.2.1). Every
  // other unknown value still refuses.
  const requested = scope.split(" ").filter((value) => value !== "openid");
  if (requested.length === 0) refuse("invalid_client_scope");
  if (
    requested.some((value) => !SCOPE_PATTERN.test(value) || !allowedScopes.includes(value)) ||
    new Set(requested).size !== requested.length
  ) {
    refuse("invalid_client_scope");
  }
  return requested.toSorted();
}

function normalizeParsedMetadata(
  parsed: z.infer<typeof CimdClientMetadataSchema>,
  canonical: string,
  allowedScopes: readonly string[]
): NormalizedClientMetadata {
  if (
    new Set(parsed.grant_types).size !== 2 ||
    !parsed.grant_types.includes("authorization_code") ||
    !parsed.grant_types.includes("refresh_token")
  ) {
    refuse("invalid_client_metadata");
  }
  const redirectUris = parsed.redirect_uris.map(validateOAuthRedirectUri).toSorted();
  if (new Set(redirectUris).size !== redirectUris.length) refuse("invalid_redirect_uri");
  return {
    ...(parsed.client_id === undefined ? {} : { clientId: parsed.client_id }),
    clientName: parsed.client_name,
    redirectUris,
    grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "none",
    scopes: normalizedScopes(parsed.scope, allowedScopes),
    ...(parsed.software_id === undefined ? {} : { softwareId: parsed.software_id }),
    canonicalMetadata: canonical,
    metadataSha256: createHash("sha256").update(canonical, "utf8").digest()
  };
}

export function parseDcrClientMetadata(
  body: Uint8Array | string,
  allowedScopes: readonly string[]
): NormalizedClientMetadata {
  const { canonical, parsed } = parseCanonicalObject(body, BaseClientMetadataSchema);
  return normalizeParsedMetadata(parsed, canonical, allowedScopes);
}

function parseCimdClientMetadata(
  body: Uint8Array | string,
  expectedClientId: string,
  allowedScopes: readonly string[]
): NormalizedClientMetadata & { readonly clientId: string } {
  const { canonical, parsed } = parseCanonicalObject(body, CimdClientMetadataSchema);
  if (validateCimdClientId(parsed.client_id) !== expectedClientId) {
    refuse("cimd_client_id_mismatch");
  }
  return normalizeParsedMetadata(parsed, canonical, allowedScopes) as NormalizedClientMetadata & {
    readonly clientId: string;
  };
}

export const defaultCimdHostResolver: CimdHostResolver = async (hostname) => {
  const addresses = await dnsLookup(hostname, { all: true, verbatim: true });
  return addresses.map(({ address, family }) => ({
    address,
    family: family === 6 ? 6 : 4
  }));
};

function lookupError(message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code: "EHOSTUNREACH" });
}

export const fetchPinnedCimdDocument: CimdDocumentFetcher = async ({
  clientId,
  pinnedAddresses,
  maxBytes,
  timeoutMs,
  signal
}) => {
  const url = new URL(validateCimdClientId(clientId));
  const addresses = [...pinnedAddresses];
  const pinnedLookup: LookupFunction = (hostname, options, callback) => {
    if (hostname !== url.hostname) {
      callback(lookupError("CIMD lookup hostname changed"), "", 0);
      return;
    }
    const requestedFamily = options.family === 4 || options.family === 6 ? options.family : 0;
    const candidates = addresses.filter(
      ({ family }) => requestedFamily === 0 || family === requestedFamily
    );
    if (candidates.length === 0) {
      callback(lookupError("CIMD has no pinned address for the requested family"), "", 0);
      return;
    }
    if (options.all) {
      callback(
        null,
        candidates.map(({ address, family }) => ({ address, family }))
      );
      return;
    }
    const selected = candidates[0]!;
    callback(null, selected.address, selected.family);
  };

  return new Promise<CimdDocumentFetchResponse>((resolve, reject) => {
    let request: ReturnType<typeof httpsRequest> | undefined;
    let activeResponse: IncomingMessage | undefined;
    let settled = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    const chunks: Buffer[] = [];
    let length = 0;
    const clearAttempt = () => {
      clearTimeout(deadlineTimer);
      signal?.removeEventListener("abort", abortAttempt);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      clearAttempt();
      chunks.length = 0;
      reject(error);
      activeResponse?.destroy(error);
      request?.destroy(error);
    };
    const abortAttempt = () => fail(new ClientRegistrationError("cimd_timeout"));
    if (signal?.aborted) {
      abortAttempt();
      return;
    }
    signal?.addEventListener("abort", abortAttempt, { once: true });
    // A socket inactivity timeout alone allows an endless trickle of metadata.
    deadlineTimer = setTimeout(abortAttempt, timeoutMs);
    try {
      request = httpsRequest(
        url,
        {
          method: "GET",
          agent: false,
          lookup: pinnedLookup,
          maxHeaderSize: 16 * 1024,
          minVersion: "TLSv1.2",
          rejectUnauthorized: true,
          headers: {
            accept: "application/json",
            "accept-encoding": "identity",
            "user-agent": "BoardAgent-CIMD/1"
          }
        },
        (response) => {
          // Observe errors before any refusal or destroy, including late responses.
          response.on("error", fail);
          response.once("aborted", () =>
            fail(new ClientRegistrationError("cimd_response_refused"))
          );
          response.once("close", () => {
            if (!settled) fail(new ClientRegistrationError("cimd_response_refused"));
          });
          if (settled) {
            response.destroy(new ClientRegistrationError("cimd_response_refused"));
            return;
          }
          activeResponse = response;
          const contentLength = response.headers["content-length"];
          if (
            (contentLength !== undefined &&
              (!/^\d+$/u.test(contentLength) || Number(contentLength) > maxBytes)) ||
            response.headers["content-encoding"] !== undefined
          ) {
            fail(new ClientRegistrationError("cimd_response_refused"));
            return;
          }
          response.on("data", (chunk: Buffer | string) => {
            if (settled) return;
            const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            if (bytes.length > maxBytes - length) {
              fail(new ClientRegistrationError("client_metadata_size_refused"));
              return;
            }
            length += bytes.length;
            chunks.push(bytes);
          });
          response.once("end", () => {
            if (settled) return;
            settled = true;
            clearAttempt();
            const contentType = response.headers["content-type"];
            const body = Buffer.concat(chunks, length);
            chunks.length = 0;
            resolve({
              statusCode: response.statusCode ?? 0,
              contentType: Array.isArray(contentType) ? undefined : contentType,
              body
            });
          });
        }
      );
      // Keep error observers attached while destroyed streams finish emitting events.
      request.on("error", fail);
      request.once("close", () => {
        if (!activeResponse && !settled) fail(new ClientRegistrationError("cimd_fetch_failed"));
      });
      request.end();
    } catch (error) {
      fail(error instanceof Error ? error : new ClientRegistrationError("cimd_fetch_failed"));
    }
  });
};

function validateResolvedAddresses(values: readonly CimdResolvedAddress[]): CimdResolvedAddress[] {
  if (values.length === 0 || values.length > MAX_CIMD_ADDRESSES) {
    refuse("cimd_address_refused");
  }
  const addresses = values.map(({ address, family }) => {
    if (
      (family !== 4 && family !== 6) ||
      isIP(address) !== family ||
      !isPublicCimdAddress(address)
    ) {
      refuse("cimd_address_refused");
    }
    return { address, family };
  });
  if (
    new Set(addresses.map(({ address, family }) => `${String(family)}:${address}`)).size !==
    addresses.length
  ) {
    refuse("cimd_address_refused");
  }
  return addresses;
}

export async function resolveCimdClientMetadata(
  clientIdValue: string,
  allowedScopes: readonly string[],
  options: {
    readonly resolver?: CimdHostResolver;
    readonly fetcher?: CimdDocumentFetcher;
    readonly timeoutMs?: number;
  } = {}
): Promise<NormalizedClientMetadata & { readonly clientId: string }> {
  const clientId = validateCimdClientId(clientIdValue);
  const url = new URL(clientId);
  const timeoutMs = options.timeoutMs ?? DEFAULT_CIMD_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new RangeError("CIMD timeout must be 100 through 30000 milliseconds");
  }
  const deadline = performance.now() + timeoutMs;
  const controller = new AbortController();
  const timeoutError = new ClientRegistrationError("cimd_timeout");
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    deadlineTimer = setTimeout(() => {
      reject(timeoutError);
      controller.abort(timeoutError);
    }, timeoutMs);
  });
  const remainingTime = () => {
    const remaining = deadline - performance.now();
    if (controller.signal.aborted || remaining <= 0) {
      controller.abort(timeoutError);
      throw timeoutError;
    }
    return Math.ceil(remaining);
  };
  try {
    let resolved: readonly CimdResolvedAddress[];
    try {
      resolved = await Promise.race([
        (options.resolver ?? defaultCimdHostResolver)(url.hostname),
        expired
      ]);
    } catch (error) {
      if (error instanceof ClientRegistrationError) throw error;
      refuse("cimd_resolution_failed");
    }
    remainingTime();
    const pinnedAddresses = validateResolvedAddresses(resolved);
    let response: CimdDocumentFetchResponse;
    try {
      response = await Promise.race([
        (options.fetcher ?? fetchPinnedCimdDocument)({
          clientId,
          pinnedAddresses,
          maxBytes: MAX_CLIENT_METADATA_BYTES,
          timeoutMs: remainingTime(),
          signal: controller.signal
        }),
        expired
      ]);
    } catch (error) {
      if (error instanceof ClientRegistrationError) throw error;
      refuse("cimd_fetch_failed");
    }
    remainingTime();
    if (response.statusCode !== 200) refuse("cimd_redirect_or_status_refused");
    // The media type must be exactly application/json. Public static hosts commonly add
    // the redundant `charset=utf-8` parameter (JSON is always UTF-8); that one parameter
    // is tolerated, any other parameter or media type is refused.
    const [mediaType = "", ...typeParameters] = (response.contentType ?? "")
      .split(";")
      .map((part) => part.trim().toLowerCase());
    if (
      mediaType !== "application/json" ||
      typeParameters.some((parameter) => parameter !== "" && parameter !== "charset=utf-8")
    ) {
      refuse("cimd_content_type_refused");
    }
    if (response.body.byteLength === 0 || response.body.byteLength > MAX_CLIENT_METADATA_BYTES) {
      refuse("client_metadata_size_refused");
    }
    const metadata = parseCimdClientMetadata(response.body, clientId, allowedScopes);
    remainingTime();
    return metadata;
  } finally {
    clearTimeout(deadlineTimer);
  }
}

function validatePreregisteredId(value: string): string {
  if (
    value.length === 0 ||
    value.length > 2048 ||
    Buffer.byteLength(value, "utf8") > 2048 ||
    value !== value.trim() ||
    value !== value.normalize("NFC") ||
    [...value].some((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint === undefined || codePoint <= 0x1f || codePoint === 0x7f;
    })
  ) {
    refuse("invalid_client_allowlist");
  }
  return value;
}

function validateTypedProtocolClientId(input: TypedProtocolClientId): TypedProtocolClientId {
  if (input.kind === "verified_cimd_url") {
    return { kind: input.kind, value: validateCimdClientId(input.value) };
  }
  if (input.kind === "dcr_opaque") {
    if (!DCR_CLIENT_ID_PATTERN.test(input.value)) refuse("invalid_client_allowlist");
    return { kind: input.kind, value: input.value };
  }
  if (input.kind === "preregistered") {
    return { kind: input.kind, value: validatePreregisteredId(input.value) };
  }
  refuse("invalid_client_allowlist");
}

const TypedProtocolClientIdSchema = z
  .object({
    kind: z.enum(["verified_cimd_url", "dcr_opaque", "preregistered"]),
    value: z.string()
  })
  .strict();

export function parseClientAllowlist(values: readonly unknown[]): readonly TypedProtocolClientId[] {
  if (values.length > 1_000) refuse("invalid_client_allowlist");
  const parsed = values.map((value) =>
    validateTypedProtocolClientId(TypedProtocolClientIdSchema.parse(value))
  );
  const keys = parsed.map(({ kind, value }) => `${kind}\0${value}`);
  if (new Set(keys).size !== keys.length) refuse("invalid_client_allowlist");
  return parsed.toSorted((left, right) => {
    const leftKey = `${left.kind}\0${left.value}`;
    const rightKey = `${right.kind}\0${right.value}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}

export function clientAdmissionAllowed(
  candidateValue: TypedProtocolClientId,
  allowlist: readonly TypedProtocolClientId[] | null,
  assertedSoftwareId?: string
): boolean {
  void assertedSoftwareId;
  let candidate: TypedProtocolClientId;
  try {
    candidate = validateTypedProtocolClientId(TypedProtocolClientIdSchema.parse(candidateValue));
  } catch {
    return false;
  }
  if (allowlist === null) return true;
  return allowlist.some(({ kind, value }) => kind === candidate.kind && value === candidate.value);
}

const RegistrationRatePolicySchema = z
  .object({
    windowSeconds: z.number().int().min(1).max(86_400),
    maxRequests: z.number().int().min(1).max(1_000_000),
    blockSeconds: z.number().int().min(1).max(86_400)
  })
  .strict();

const ActiveClientRowSchema = z
  .object({
    id: UuidV7Schema,
    protocol_id_kind: z.enum(["verified_cimd_url", "dcr_opaque", "preregistered"]),
    protocol_id_value: z.string().min(1).max(2048),
    safe_metadata: z.record(z.string(), z.unknown())
  })
  .strict();

const RegistrationFunctionRowSchema = z
  .object({
    result_internal_id: UuidV7Schema,
    result_inserted: z.boolean()
  })
  .strict();

export interface OAuthClientRegistrationResult {
  readonly internalClientId: string;
  readonly protocolIdKind: ProtocolClientIdKind;
  readonly protocolClientId: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
  readonly scopes: readonly string[];
  readonly softwareId?: string;
  readonly registered: boolean;
}

export interface PgOAuthClientRegistrarOptions {
  readonly organizationId: string;
  readonly allowedScopes: readonly string[];
  readonly maxClients: number;
  readonly rateLimiter: PgRateLimiter;
  readonly rateLimit: RateLimitPolicy;
  readonly allowlist?: readonly unknown[] | null;
  /** Test/bootstrap seam only. Production uses a server-role identity pool. */
  readonly assumeRole?: "boardagent_server";
  readonly newId?: () => string;
  readonly randomBytes?: (size: number) => Uint8Array;
  readonly cimdResolver?: CimdHostResolver;
  readonly cimdFetcher?: CimdDocumentFetcher;
}

interface StoredClientShape {
  readonly internalClientId: string;
  readonly protocolIdKind: ProtocolClientIdKind;
  readonly protocolClientId: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
  readonly scopes: readonly string[];
  readonly softwareId?: string;
}

function sha256(value: Uint8Array | string): Buffer {
  return createHash("sha256").update(value).digest();
}

function safeMetadata(
  method: "cimd" | "dcr",
  metadata: NormalizedClientMetadata
): Readonly<Record<string, unknown>> {
  return {
    name: metadata.clientName,
    registrationMethod: method,
    schemaVersion: 1,
    ...(metadata.softwareId === undefined ? {} : { softwareId: metadata.softwareId })
  };
}

function databaseRegistrationError(error: unknown): ClientRegistrationError {
  if (error instanceof ClientRegistrationError) return error;
  if (typeof error === "object" && error !== null && "code" in error) {
    if (error.code === "invalid_auth_request") {
      return new ClientRegistrationError("invalid_registration_request", 400);
    }
    if (error.code === "54000") return new ClientRegistrationError("client_capacity_reached", 429);
    if (error.code === "23505") return new ClientRegistrationError("client_id_conflict", 400);
    if (error.code === "40001" || error.code === "40P01") {
      return new ClientRegistrationError("registration_contention", 503);
    }
  }
  return new ClientRegistrationError("registration_failed", 500);
}

export class PgOAuthClientRegistrar {
  private readonly organizationId: string;
  private readonly allowedScopes: readonly string[];
  private readonly maxClients: number;
  private readonly rateLimiter: PgRateLimiter;
  private readonly rateLimit: RateLimitPolicy;
  private readonly allowlist: readonly TypedProtocolClientId[] | null;
  private readonly assumeRole: "boardagent_server" | undefined;
  private readonly newId: () => string;
  private readonly entropy: (size: number) => Buffer;
  private readonly cimdResolver: CimdHostResolver;
  private readonly cimdFetcher: CimdDocumentFetcher;

  public constructor(
    private readonly pool: Pool,
    options: PgOAuthClientRegistrarOptions
  ) {
    this.organizationId = UuidV7Schema.parse(options.organizationId);
    this.allowedScopes = normalizedScopes(undefined, options.allowedScopes);
    this.maxClients = z.number().int().min(1).max(10_000).parse(options.maxClients);
    this.rateLimiter = options.rateLimiter;
    this.rateLimit = RegistrationRatePolicySchema.parse(options.rateLimit);
    this.allowlist =
      options.allowlist === undefined || options.allowlist === null
        ? null
        : parseClientAllowlist(options.allowlist);
    this.assumeRole = options.assumeRole;
    this.newId = options.newId ?? (() => uuidV7(Date.now(), nodeRandomBytes(10)));
    const randomSource = options.randomBytes ?? nodeRandomBytes;
    this.entropy = (size) => {
      const value = Buffer.from(randomSource(size));
      if (value.length !== size) {
        throw new Error("client-registration entropy source returned the wrong length");
      }
      return value;
    };
    this.cimdResolver = options.cimdResolver ?? defaultCimdHostResolver;
    this.cimdFetcher = options.cimdFetcher ?? fetchPinnedCimdDocument;
  }

  private transaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    return withIdentityTransaction(
      this.pool,
      { organizationId: this.organizationId },
      run,
      this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole }
    );
  }

  private async consumeRate(clientIpClassValue: string, method: "cimd" | "dcr"): Promise<void> {
    const clientIpClass = z.string().min(1).max(256).parse(clientIpClassValue);
    const decision = await this.rateLimiter.consumeIdentity(this.organizationId, [
      {
        bucketClass: "registration",
        trustedSubject: `${method}:${clientIpClass}`,
        ...this.rateLimit
      }
    ]);
    if (!decision.allowed) {
      throw new ClientRegistrationError(
        "registration_rate_limited",
        429,
        decision.retryAfterSeconds
      );
    }
  }

  private admitted(candidate: TypedProtocolClientId, softwareId?: string): boolean {
    return clientAdmissionAllowed(candidate, this.allowlist, softwareId);
  }

  private async storedClient(protocolClientId: string): Promise<StoredClientShape | null> {
    return this.transaction(async (client) => {
      const result = await client.query(
        `select id,protocol_id_kind,protocol_id_value,safe_metadata
           from oauth_clients
          where organization_id=$1 and protocol_id_value=$2 and state='active'`,
        [this.organizationId, protocolClientId]
      );
      if (result.rows.length === 0) return null;
      if (result.rows.length !== 1) throw new Error("OAuth client lookup is not unique");
      const row = ActiveClientRowSchema.parse(result.rows[0]);
      const display = z
        .object({ name: SafeTextSchema(120), softwareId: SafeTextSchema(200).optional() })
        .passthrough()
        .parse(row.safe_metadata);
      const redirects = await client.query<{ redirect_uri: string }>(
        `select redirect_uri from oauth_client_redirect_uris
          where client_id=$1 order by redirect_uri`,
        [row.id]
      );
      const scopes = await client.query<{ scope: string }>(
        `select distinct scope from oauth_client_grants
          where client_id=$1 order by scope`,
        [row.id]
      );
      return {
        internalClientId: row.id,
        protocolIdKind: row.protocol_id_kind,
        protocolClientId: row.protocol_id_value,
        clientName: display.name,
        redirectUris: redirects.rows.map(({ redirect_uri }) => redirect_uri),
        scopes: scopes.rows.map(({ scope }) => scope),
        ...(display.softwareId === undefined ? {} : { softwareId: display.softwareId })
      };
    });
  }

  private async rejectionAudit(input: {
    readonly method: "cimd" | "dcr";
    readonly candidateSha256: string;
    readonly error: ClientRegistrationError;
  }): Promise<void> {
    await this.transaction(async (client) => {
      await appendAuditEventsInTransaction(client, [
        {
          organizationId: this.organizationId,
          event: {
            eventId: UuidV7Schema.parse(this.newId()),
            eventType: "client_registration_rejected",
            actorMemberId: null,
            actorClientId: null,
            tokenJti: null,
            entityType: "oauth_client_registration",
            entityId: input.candidateSha256,
            boardId: null,
            origin: "oauth",
            details: {
              method: input.method,
              candidateSha256: input.candidateSha256,
              reason: input.error.code,
              rateLimited: input.error.code === "registration_rate_limited"
            },
            schemaVersion: 1
          }
        }
      ]);
    });
  }

  private async auditedAttempt<T>(
    method: "cimd" | "dcr",
    candidateSha256: string,
    operation: () => Promise<T>
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      const normalized = databaseRegistrationError(error);
      try {
        await this.rejectionAudit({ method, candidateSha256, error: normalized });
      } catch {
        throw new ClientRegistrationError("registration_audit_failed", 500);
      }
      throw normalized;
    }
  }

  private async persist(
    method: "cimd" | "dcr",
    protocolIdKind: "verified_cimd_url" | "dcr_opaque",
    protocolClientId: string,
    metadata: NormalizedClientMetadata
  ): Promise<OAuthClientRegistrationResult> {
    const internalClientId = UuidV7Schema.parse(this.newId());
    const displayMetadata = safeMetadata(method, metadata);
    const redirectHashes = metadata.redirectUris.map((redirect) => sha256(redirect));
    const stored = await this.transaction(async (client) => {
      const result = await client.query(
        `select result_internal_id,result_inserted
           from boardagent_register_oauth_client($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          this.organizationId,
          internalClientId,
          protocolIdKind,
          protocolClientId,
          displayMetadata,
          metadata.metadataSha256,
          metadata.redirectUris,
          redirectHashes,
          metadata.scopes,
          this.maxClients
        ]
      );
      if (result.rows.length !== 1) {
        throw new Error("OAuth client registration authority returned no result");
      }
      const row = RegistrationFunctionRowSchema.parse(result.rows[0]);
      if (row.result_inserted) {
        await appendAuditEventsInTransaction(client, [
          {
            organizationId: this.organizationId,
            event: {
              eventId: UuidV7Schema.parse(this.newId()),
              eventType: "client_registered",
              actorMemberId: null,
              actorClientId: null,
              tokenJti: null,
              entityType: "oauth_client",
              entityId: row.result_internal_id,
              boardId: null,
              origin: "oauth",
              details: {
                protocolIdKind,
                protocolIdSha256: sha256(protocolClientId).toString("hex"),
                registrationMethod: method,
                redirectCount: metadata.redirectUris.length,
                scopeCount: metadata.scopes.length,
                selfAssertedSoftwareIdPresent: metadata.softwareId !== undefined
              },
              schemaVersion: 1
            }
          }
        ]);
      }
      return row;
    });
    return {
      internalClientId: stored.result_internal_id,
      protocolIdKind,
      protocolClientId,
      clientName: metadata.clientName,
      redirectUris: metadata.redirectUris,
      scopes: metadata.scopes,
      ...(metadata.softwareId === undefined ? {} : { softwareId: metadata.softwareId }),
      registered: stored.result_inserted
    };
  }

  public async registerDcr(input: {
    readonly clientIpClass: string;
    readonly body: Uint8Array | string;
  }): Promise<OAuthClientRegistrationResult> {
    const candidateBytes =
      typeof input.body === "string" ? Buffer.from(input.body, "utf8") : Buffer.from(input.body);
    const candidateSha256 = sha256(candidateBytes).toString("hex");
    return this.auditedAttempt("dcr", candidateSha256, async () => {
      await this.consumeRate(input.clientIpClass, "dcr");
      const metadata = parseDcrClientMetadata(candidateBytes, this.allowedScopes);
      const protocolClientId = `ba_dcr_${this.entropy(32).toString("base64url")}`;
      if (!DCR_CLIENT_ID_PATTERN.test(protocolClientId)) {
        throw new Error("DCR client identifier generation failed");
      }
      if (!this.admitted({ kind: "dcr_opaque", value: protocolClientId }, metadata.softwareId)) {
        refuse("client_not_allowed", 403);
      }
      return this.persist("dcr", "dcr_opaque", protocolClientId, metadata);
    });
  }

  public async ensureCimd(input: {
    readonly clientIpClass: string;
    readonly clientId: string;
  }): Promise<OAuthClientRegistrationResult> {
    const candidateSha256 = sha256(input.clientId).toString("hex");
    return this.auditedAttempt("cimd", candidateSha256, async () => {
      const clientId = validateCimdClientId(input.clientId);
      const existing = await this.storedClient(clientId);
      if (existing) {
        if (
          !this.admitted(
            { kind: existing.protocolIdKind, value: existing.protocolClientId },
            existing.softwareId
          )
        ) {
          refuse("client_not_allowed", 403);
        }
        return { ...existing, registered: false };
      }
      await this.consumeRate(input.clientIpClass, "cimd");
      if (!this.admitted({ kind: "verified_cimd_url", value: clientId })) {
        refuse("client_not_allowed", 403);
      }
      const metadata = await resolveCimdClientMetadata(clientId, this.allowedScopes, {
        resolver: this.cimdResolver,
        fetcher: this.cimdFetcher
      });
      return this.persist("cimd", "verified_cimd_url", clientId, metadata);
    });
  }

  public async prepareAuthorizationClient(input: {
    readonly clientIpClass: string;
    readonly protocolClientId: string;
  }): Promise<OAuthClientRegistrationResult> {
    const protocolClientId = z.string().min(1).max(2048).parse(input.protocolClientId);
    const existing = await this.storedClient(protocolClientId);
    if (existing) {
      if (
        !this.admitted(
          { kind: existing.protocolIdKind, value: existing.protocolClientId },
          existing.softwareId
        )
      ) {
        throw new ClientRegistrationError("client_not_allowed", 403);
      }
      return { ...existing, registered: false };
    }
    if (protocolClientId.startsWith("https://")) {
      return this.ensureCimd({
        clientIpClass: input.clientIpClass,
        clientId: protocolClientId
      });
    }
    throw new ClientRegistrationError("client_not_registered", 400);
  }
}

export interface OAuthClientRegistrationEndpoint {
  handleRegistration(request: IncomingMessage, response: ServerResponse): Promise<void>;
  prepareAuthorization(request: IncomingMessage): Promise<void>;
}

function rawRequestHeaderValues(request: IncomingMessage, name: string): readonly string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      values.push(request.rawHeaders[index + 1] ?? "");
    }
  }
  return values;
}

function exactRequestHeader(request: IncomingMessage, name: string): string | undefined {
  const rawValues = rawRequestHeaderValues(request, name);
  if (rawValues.length > 1) refuse("invalid_registration_request");
  const value = request.headers[name];
  if (Array.isArray(value)) refuse("invalid_registration_request");
  return rawValues[0] ?? value;
}

function relativeRequestUrl(request: IncomingMessage): URL {
  const target = request.url;
  if (!target || !target.startsWith("/") || target.startsWith("//")) {
    refuse("invalid_registration_request");
  }
  try {
    return new URL(target, "https://boardagent.invalid");
  } catch {
    refuse("invalid_registration_request");
  }
}

async function boundedRegistrationBody(request: IncomingMessage): Promise<Buffer> {
  const contentLength = exactRequestHeader(request, "content-length");
  const transferEncoding = exactRequestHeader(request, "transfer-encoding");
  if (
    (contentLength !== undefined && transferEncoding !== undefined) ||
    (contentLength !== undefined &&
      (!/^\d+$/u.test(contentLength) || Number(contentLength) > MAX_CLIENT_METADATA_BYTES)) ||
    exactRequestHeader(request, "content-encoding") !== undefined
  ) {
    refuse("invalid_registration_request");
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    length += bytes.length;
    if (length > MAX_CLIENT_METADATA_BYTES) refuse("client_metadata_size_refused");
    chunks.push(bytes);
  }
  if (length === 0 || (contentLength !== undefined && Number(contentLength) !== length)) {
    refuse("invalid_registration_request");
  }
  return Buffer.concat(chunks, length);
}

function registrationErrorBody(error: ClientRegistrationError): {
  readonly statusCode: number;
  readonly error: string;
} {
  if (error.statusCode >= 500) return { statusCode: error.statusCode, error: "server_error" };
  if (
    error.code === "registration_rate_limited" ||
    error.code === "client_capacity_reached" ||
    error.code === "registration_contention"
  ) {
    return { statusCode: 429, error: "temporarily_unavailable" };
  }
  if (error.code === "invalid_redirect_uri") {
    return { statusCode: error.statusCode, error: "invalid_redirect_uri" };
  }
  return { statusCode: error.statusCode, error: "invalid_client_metadata" };
}

function writeRegistrationJson(
  response: ServerResponse,
  statusCode: number,
  body: Readonly<Record<string, unknown>>,
  extraHeaders: Readonly<Record<string, string>> = {}
): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(statusCode, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    pragma: "no-cache",
    "x-content-type-options": "nosniff",
    ...extraHeaders
  });
  response.end(JSON.stringify(body));
}

export function createOAuthClientRegistrationEndpoint(options: {
  readonly registrar: PgOAuthClientRegistrar;
  readonly boundary: AuthRequestBoundary;
}): OAuthClientRegistrationEndpoint {
  return {
    async handleRegistration(request, response): Promise<void> {
      try {
        const target = relativeRequestUrl(request);
        if (target.pathname !== "/register" || target.search !== "" || target.hash !== "") {
          writeRegistrationJson(response, 404, { error: "not_found" });
          return;
        }
        if (request.method !== "POST") {
          writeRegistrationJson(response, 405, { error: "invalid_request" }, { allow: "POST" });
          return;
        }
        const inspection = options.boundary.inspect(request, { stateChanging: false });
        if (
          exactRequestHeader(request, "content-type")?.toLowerCase() !== "application/json" ||
          exactRequestHeader(request, "origin") !== undefined ||
          exactRequestHeader(request, "cookie") !== undefined
        ) {
          refuse("invalid_registration_request");
        }
        const body = await boundedRegistrationBody(request);
        const registration = await options.registrar.registerDcr({
          clientIpClass: inspection.clientIpClass,
          body
        });
        writeRegistrationJson(response, 201, {
          client_id: registration.protocolClientId,
          client_name: registration.clientName,
          redirect_uris: registration.redirectUris,
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          scope: registration.scopes.join(" "),
          ...(registration.softwareId === undefined ? {} : { software_id: registration.softwareId })
        });
      } catch (error) {
        const normalized = databaseRegistrationError(error);
        const safe = registrationErrorBody(normalized);
        writeRegistrationJson(
          response,
          safe.statusCode,
          { error: safe.error },
          normalized.retryAfterSeconds > 0
            ? { "retry-after": String(normalized.retryAfterSeconds) }
            : {}
        );
      }
    },

    async prepareAuthorization(request): Promise<void> {
      const target = relativeRequestUrl(request);
      if (request.method !== "GET" || target.pathname !== "/authorize" || target.hash !== "") {
        return;
      }
      const inspection = options.boundary.inspect(request, { stateChanging: false });
      const clientIds = target.searchParams.getAll("client_id");
      if (clientIds.length !== 1 || clientIds[0] === "") {
        throw new ClientRegistrationError("client_not_registered", 400);
      }
      await options.registrar.prepareAuthorizationClient({
        clientIpClass: inspection.clientIpClass,
        protocolClientId: clientIds[0]!
      });
    }
  };
}
