import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import type { IncomingMessage } from "node:http";

import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";

const InteractionUidSchema = z
  .string()
  .min(16)
  .max(256)
  .regex(/^[A-Za-z0-9_-]+$/u);
const CsrfTokenSchema = z
  .string()
  .min(43)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/u);
const TotpFallbackHandleSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const TotpCodeSchema = z.string().regex(/^\d{6}$/u);
const OpaqueProtocolValueSchema = z.string().min(16).max(2048);
const AuthActionSchema = z.enum(["passkey", "totp", "oidc", "cancel"]);
const OidcProviderIdSchema = z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/u);
const OidcProviderChoiceSchema = z
  .object({
    id: OidcProviderIdSchema,
    label: z
      .string()
      .min(1)
      .max(80)
      .refine(
        (value) =>
          value === value.trim() &&
          value === value.normalize("NFC") &&
          [...value].every((character) => {
            const point = character.codePointAt(0);
            return point !== undefined && point > 0x1f && point !== 0x7f;
          })
      )
  })
  .strict();
const Sha256BufferSchema = z.instanceof(Buffer).refine((value) => value.length === 32);
const AuthenticationResponseSchema = z
  .object({
    id: z
      .string()
      .min(1)
      .max(2048)
      .regex(/^[A-Za-z0-9_-]+$/u),
    rawId: z
      .string()
      .min(1)
      .max(2048)
      .regex(/^[A-Za-z0-9_-]+$/u),
    response: z
      .object({
        clientDataJSON: z
          .string()
          .min(1)
          .max(8192)
          .regex(/^[A-Za-z0-9_-]+$/u),
        authenticatorData: z
          .string()
          .min(1)
          .max(4096)
          .regex(/^[A-Za-z0-9_-]+$/u),
        signature: z
          .string()
          .min(1)
          .max(4096)
          .regex(/^[A-Za-z0-9_-]+$/u),
        userHandle: z
          .string()
          .max(2048)
          .regex(/^[A-Za-z0-9_-]*$/u)
          .nullable()
          .optional()
      })
      .strict(),
    type: z.literal("public-key"),
    clientExtensionResults: z.object({}).strict(),
    authenticatorAttachment: z.enum(["cross-platform", "platform"]).optional()
  })
  .strict();

export class AuthPageSecurityError extends Error {
  public readonly code = "invalid_auth_request";

  /**
   * `reason` names the check that refused the request for the operator log; the browser
   * never sees it (every refusal renders the same `invalid_auth_request` body).
   */
  public constructor(public readonly reason: string = "auth_interaction_rejected") {
    super("invalid auth interaction");
    this.name = "AuthPageSecurityError";
  }
}

function rejectAuthRequest(reason: string): never {
  throw new AuthPageSecurityError(reason);
}

function exactOrigin(value: string, allowInsecureLoopbackDevelopment: boolean): URL {
  const parsed = z.url().parse(value);
  const url = new URL(parsed);
  if (
    url.origin !== parsed ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("auth origin must be exact");
  }
  if (url.protocol === "https:") return url;
  if (
    allowInsecureLoopbackDevelopment &&
    url.protocol === "http:" &&
    url.hostname === "localhost"
  ) {
    return url;
  }
  throw new Error("auth origin must use HTTPS");
}

function ipv4Octets(value: string): readonly number[] | null {
  if (isIP(value) !== 4) return null;
  const octets = value.split(".").map(Number);
  return octets.length === 4 ? octets : null;
}

function ipv6Groups(value: string): readonly number[] | null {
  if (value.includes("%") || isIP(value) !== 6) return null;
  let expanded = value.toLowerCase();
  const lastColon = expanded.lastIndexOf(":");
  const possibleIpv4 = expanded.slice(lastColon + 1);
  const embeddedIpv4 = ipv4Octets(possibleIpv4);
  if (embeddedIpv4) {
    expanded = `${expanded.slice(0, lastColon)}:${(
      (embeddedIpv4[0]! << 8) |
      embeddedIpv4[1]!
    ).toString(16)}:${((embeddedIpv4[2]! << 8) | embeddedIpv4[3]!).toString(16)}`;
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

function normalizedIp(value: string | undefined): string | null {
  if (!value) return null;
  const ipv4 = ipv4Octets(value);
  if (ipv4) return ipv4.join(".");
  const ipv6 = ipv6Groups(value);
  if (!ipv6) return null;
  if (ipv6.slice(0, 5).every((group) => group === 0) && ipv6[5] === 0xffff) {
    return [ipv6[6]! >> 8, ipv6[6]! & 0xff, ipv6[7]! >> 8, ipv6[7]! & 0xff].join(".");
  }
  return ipv6.map((group) => group.toString(16).padStart(4, "0")).join(":");
}

function loopbackIp(value: string): boolean {
  const ipv4 = ipv4Octets(value);
  if (ipv4) return ipv4[0] === 127;
  const ipv6 = ipv6Groups(value);
  return Boolean(ipv6 && ipv6.slice(0, 7).every((group) => group === 0) && ipv6[7] === 1);
}

function ipClass(value: string): string {
  const ipv4 = ipv4Octets(value);
  if (ipv4) return `ipv4:${ipv4[0]}.${ipv4[1]}.${ipv4[2]}.0/24`;
  const ipv6 = ipv6Groups(value);
  if (!ipv6) rejectAuthRequest("ip_unparseable");
  const masked = [ipv6[0]!, ipv6[1]!, ipv6[2]!, ipv6[3]! & 0xff00, 0, 0, 0, 0];
  return `ipv6:${masked.map((group) => group.toString(16).padStart(4, "0")).join(":")}/56`;
}

function rawHeaderValues(request: IncomingMessage, name: string): readonly string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name)
      values.push(request.rawHeaders[index + 1] ?? "");
  }
  return values;
}

function singleHeader(
  request: IncomingMessage,
  name: string,
  required = false
): string | undefined {
  const rawValues = rawHeaderValues(request, name);
  if (rawValues.length > 1) rejectAuthRequest("header_shape");
  const header = request.headers[name];
  if (Array.isArray(header)) rejectAuthRequest("header_shape");
  const value = rawValues[0] ?? header;
  if (required && (value === undefined || value === "")) rejectAuthRequest("header_missing");
  return value;
}

export interface AuthRequestInspection {
  readonly canonicalOrigin: string;
  readonly clientIpClass: string;
}

export class AuthRequestBoundary {
  private readonly origin: URL;
  private readonly trustedProxyAddresses: ReadonlySet<string>;
  private readonly trustedProxyHops: number | undefined;
  private readonly allowInsecureLoopbackDevelopment: boolean;

  public constructor(options: {
    readonly origin: string;
    readonly trustedProxyAddresses?: readonly string[];
    readonly trustedProxyHops?: number;
    readonly allowInsecureLoopbackDevelopment?: boolean;
  }) {
    this.allowInsecureLoopbackDevelopment = options.allowInsecureLoopbackDevelopment === true;
    this.origin = exactOrigin(options.origin, this.allowInsecureLoopbackDevelopment);
    const trusted = (options.trustedProxyAddresses ?? []).map((address) => {
      const normalized = normalizedIp(address);
      if (!normalized) throw new Error("trusted proxy address is invalid");
      return normalized;
    });
    if (new Set(trusted).size !== trusted.length) {
      throw new Error("trusted proxy address list contains duplicates");
    }
    if (options.trustedProxyHops !== undefined) {
      if (
        !Number.isInteger(options.trustedProxyHops) ||
        options.trustedProxyHops < 1 ||
        options.trustedProxyHops > 4
      ) {
        throw new Error("trusted proxy hops must be an integer from 1 through 4");
      }
      if (trusted.length > 0) {
        throw new Error("configure trusted proxy addresses or hop count, not both");
      }
    }
    this.trustedProxyAddresses = new Set(trusted);
    this.trustedProxyHops = options.trustedProxyHops;
  }

  public inspect(
    request: IncomingMessage,
    options: { readonly stateChanging: boolean }
  ): AuthRequestInspection {
    if (singleHeader(request, "host", true) !== this.origin.host)
      rejectAuthRequest("host_mismatch");
    if (singleHeader(request, "forwarded") !== undefined) rejectAuthRequest("forwarded_header");
    const remoteAddress = normalizedIp(request.socket.remoteAddress);
    if (!remoteAddress) rejectAuthRequest("remote_address");
    const encrypted = (request.socket as typeof request.socket & { readonly encrypted?: boolean })
      .encrypted;
    const forwardedFor = singleHeader(request, "x-forwarded-for");
    const forwardedProto = singleHeader(request, "x-forwarded-proto");
    const forwardedHost = singleHeader(request, "x-forwarded-host");
    const forwardedPort = singleHeader(request, "x-forwarded-port");
    const anyForwarded =
      forwardedFor !== undefined ||
      forwardedProto !== undefined ||
      forwardedHost !== undefined ||
      forwardedPort !== undefined;
    let clientAddress: string;
    if (encrypted === true) {
      if (anyForwarded || this.origin.protocol !== "https:") rejectAuthRequest("tls_forwarded");
      clientAddress = remoteAddress;
    } else if (
      this.allowInsecureLoopbackDevelopment &&
      this.origin.protocol === "http:" &&
      loopbackIp(remoteAddress)
    ) {
      if (anyForwarded) rejectAuthRequest("loopback_forwarded");
      clientAddress = remoteAddress;
    } else {
      const forwardedChain = forwardedFor?.split(",").map((value) => value.trim()) ?? [];
      const normalizedChain = forwardedChain.map((address) => normalizedIp(address));
      const trustedByAddress = this.trustedProxyAddresses.has(remoteAddress);
      const trustedByHopCount =
        this.trustedProxyHops !== undefined &&
        forwardedChain.length === this.trustedProxyHops &&
        normalizedChain.every((address) => address !== null);
      if (
        (!trustedByAddress && !trustedByHopCount) ||
        forwardedProto !== "https" ||
        (forwardedHost !== undefined && forwardedHost !== this.origin.host) ||
        (forwardedPort !== undefined && forwardedPort !== "443") ||
        forwardedFor === undefined ||
        (trustedByAddress && forwardedFor.includes(","))
      ) {
        rejectAuthRequest("proxy_chain");
      }
      const normalizedForwardedFor = normalizedChain[0];
      if (!normalizedForwardedFor) rejectAuthRequest("proxy_chain");
      clientAddress = normalizedForwardedFor;
    }
    if (options.stateChanging) {
      if (
        request.method !== "POST" ||
        singleHeader(request, "origin", true) !== this.origin.origin ||
        singleHeader(request, "sec-fetch-site", true) !== "same-origin"
      ) {
        rejectAuthRequest("origin_or_fetch_site");
      }
    }
    return { canonicalOrigin: this.origin.origin, clientIpClass: ipClass(clientAddress) };
  }
}

export function authPageSecurityHeaders(options: {
  readonly includeHsts: boolean;
}): Readonly<Record<string, string>> {
  return {
    "cache-control": "no-store, max-age=0",
    pragma: "no-cache",
    expires: "0",
    "content-type": "text/html; charset=utf-8",
    "content-security-policy":
      "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; " +
      "object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'",
    "referrer-policy": "same-origin",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy":
      "camera=(), geolocation=(), microphone=(), payment=(), usb=(), " +
      "publickey-credentials-create=(self), publickey-credentials-get=(self)",
    ...(options.includeHsts
      ? { "strict-transport-security": "max-age=63072000; includeSubDomains" }
      : {})
  };
}

export function escapeAuthHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** End the form navigation before the provider resumes its validated OAuth redirect. */
export function renderOAuthResumePage(issuer: string, returnTo: string): string {
  const target = new URL(returnTo);
  if (
    target.origin !== issuer ||
    target.href !== returnTo ||
    target.username !== "" ||
    target.password !== "" ||
    target.search !== "" ||
    target.hash !== "" ||
    !/^\/authorize\/[A-Za-z0-9_-]{16,256}$/u.test(target.pathname)
  ) {
    throw new AuthPageSecurityError("resume_target");
  }
  const href = escapeAuthHtml(target.pathname);
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    `<meta http-equiv="refresh" content="0;url=${href}">` +
    "<title>Continue with BoardAgent</title></head><body><main>" +
    `<p>Returning to your agent…</p><a href="${href}">Continue</a>` +
    "</main></body></html>"
  );
}

export function renderAuthInteractionPage(input: {
  readonly interactionUid: string;
  readonly csrfToken: string;
  readonly clientDisplayName: string;
}): string {
  const interactionUid = InteractionUidSchema.parse(input.interactionUid);
  const csrfToken = CsrfTokenSchema.parse(input.csrfToken);
  const clientDisplayName = z.string().min(1).max(256).parse(input.clientDisplayName);
  const action = `/auth/interactions/${interactionUid}`;
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Continue with BoardAgent</title></head><body><main>" +
    "<h1>Continue with BoardAgent</h1><p><span data-client-name>" +
    `${escapeAuthHtml(clientDisplayName)}</span> is requesting authentication.</p>` +
    `<form method="post" action="${action}" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${csrfToken}">` +
    '<button type="submit" name="action" value="passkey">Use passkey</button>' +
    '<button type="submit" name="action" value="cancel">Cancel</button>' +
    "</form></main></body></html>"
  );
}

function validatedInteractionPresentation(input: {
  readonly interactionUid: string;
  readonly csrfToken: string;
  readonly clientDisplayName: string;
}): {
  readonly interactionUid: string;
  readonly csrfToken: string;
  readonly clientDisplayName: string;
  readonly basePath: string;
} {
  const interactionUid = InteractionUidSchema.parse(input.interactionUid);
  return {
    interactionUid,
    csrfToken: CsrfTokenSchema.parse(input.csrfToken),
    clientDisplayName: z.string().min(1).max(256).parse(input.clientDisplayName),
    basePath: `/auth/interactions/${interactionUid}`
  };
}

export function renderOAuthPasskeyInteractionPage(input: {
  readonly interactionUid: string;
  readonly csrfToken: string;
  readonly clientDisplayName: string;
  readonly totpFallbackAvailable?: boolean;
  readonly oidcProviders?: readonly { readonly id: string; readonly label: string }[];
}): string {
  const value = validatedInteractionPresentation(input);
  const fallback =
    input.totpFallbackAvailable === true
      ? `<p><a href="${value.basePath}/totp" data-totp-fallback-link>` +
        "Passkey unavailable? Use configured TOTP fallback</a></p>"
      : "";
  const providers = z
    .array(OidcProviderChoiceSchema)
    .max(16)
    .parse(input.oidcProviders ?? []);
  if (new Set(providers.map(({ id }) => id)).size !== providers.length)
    rejectAuthRequest("provider_duplicate");
  const oidc =
    providers.length === 0
      ? ""
      : "<section data-oidc-providers><h2>Or use your linked account</h2>" +
        providers
          .map(
            ({ id, label }) =>
              `<form method="post" action="${value.basePath}/oidc/${id}/start" ` +
              'autocomplete="off">' +
              `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
              `<button type="submit">Continue with ${escapeAuthHtml(label)}</button></form>`
          )
          .join("") +
        "</section>";
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Authenticate with BoardAgent</title>" +
    '<script src="/auth/webauthn.js" defer></script></head><body><main>' +
    "<h1>Authenticate with BoardAgent</h1><p><span data-client-name>" +
    `${escapeAuthHtml(value.clientDisplayName)}</span> is requesting access.</p>` +
    `<form method="post" action="${value.basePath}/passkey/complete" ` +
    'autocomplete="off" data-webauthn-login ' +
    `data-begin-path="${value.basePath}/passkey/begin">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<input type="hidden" name="credential" value="">' +
    '<button type="button" data-passkey-button>Use passkey</button>' +
    '<p role="status" aria-live="polite" data-passkey-status></p></form>' +
    fallback +
    oidc +
    `<form method="post" action="${value.basePath}/cancel" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<button type="submit">Cancel</button></form></main></body></html>'
  );
}

export function renderOAuthOidcCompletionPage(input: {
  readonly interactionUid: string;
  readonly csrfToken: string;
  readonly clientDisplayName: string;
}): string {
  const value = validatedInteractionPresentation(input);
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Finish secure sign-in</title></head><body><main>" +
    "<h1>Finish secure sign-in</h1><p>Return to <span data-client-name>" +
    `${escapeAuthHtml(value.clientDisplayName)}</span> after confirming this sign-in.</p>` +
    `<form method="post" action="${value.basePath}/oidc/complete" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<button type="submit">Continue</button></form>' +
    `<form method="post" action="${value.basePath}/cancel" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<button type="submit">Cancel</button></form></main></body></html>'
  );
}

export function renderOidcPendingIdentityPage(): string {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Identity confirmation required</title></head><body><main>" +
    "<h1>Identity confirmation required</h1>" +
    "<p>This identity has not been granted BoardAgent access. " +
    "An authorized administrator must confirm the existing invitation before sign-in.</p>" +
    "</main></body></html>"
  );
}

export function renderOAuthTotpInteractionPage(input: {
  readonly interactionUid: string;
  readonly csrfToken: string;
  readonly clientDisplayName: string;
}): string {
  const value = validatedInteractionPresentation(input);
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Use BoardAgent TOTP fallback</title></head><body><main>" +
    "<h1>Use configured TOTP fallback</h1><p>Use this only when your passkey is unavailable. " +
    "<span data-client-name>" +
    `${escapeAuthHtml(value.clientDisplayName)}</span> is requesting access.</p>` +
    `<form method="post" action="${value.basePath}/totp/complete" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<label>Fallback ID <input type="text" name="fallback_handle" required maxlength="43" ' +
    'autocapitalize="none" autocomplete="off" spellcheck="false"></label>' +
    '<label>Six-digit code <input type="text" name="code" required inputmode="numeric" ' +
    'pattern="[0-9]{6}" minlength="6" maxlength="6" autocomplete="one-time-code"></label>' +
    '<button type="submit" data-totp-submit>Authenticate</button></form>' +
    `<p><a href="${value.basePath}">Back to passkey</a></p>` +
    `<form method="post" action="${value.basePath}/cancel" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<button type="submit">Cancel</button></form></main></body></html>'
  );
}

export function renderOAuthConsentInteractionPage(input: {
  readonly interactionUid: string;
  readonly csrfToken: string;
  readonly clientDisplayName: string;
  readonly resourceUri: string;
  readonly scopes: readonly string[];
}): string {
  const value = validatedInteractionPresentation(input);
  const resourceUri = z.string().url().max(2048).parse(input.resourceUri);
  const scopes = z
    .array(z.string().regex(/^[a-z][a-z0-9:_-]{0,127}$/u))
    .min(1)
    .max(128)
    .parse(input.scopes);
  if (new Set(scopes).size !== scopes.length) rejectAuthRequest("scope_duplicate");
  const scopeItems = scopes
    .map((scope) => `<li><code>${escapeAuthHtml(scope)}</code></li>`)
    .join("");
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Authorize BoardAgent access</title></head><body><main>" +
    "<h1>Authorize access</h1><p><span data-client-name>" +
    `${escapeAuthHtml(value.clientDisplayName)}</span> requests access to ` +
    `<code data-resource>${escapeAuthHtml(resourceUri)}</code>.</p>` +
    `<ul data-scopes>${scopeItems}</ul>` +
    `<form method="post" action="${value.basePath}/consent" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<button type="submit">Authorize</button></form>' +
    `<form method="post" action="${value.basePath}/cancel" autocomplete="off">` +
    `<input type="hidden" name="csrf_token" value="${value.csrfToken}">` +
    '<button type="submit">Cancel</button></form></main></body></html>'
  );
}

export function parseAuthInteractionPath(rawUrl: string): string {
  const match = /^\/auth\/interactions\/([A-Za-z0-9_-]{16,256})$/u.exec(rawUrl);
  if (!match) rejectAuthRequest("path_invalid");
  return InteractionUidSchema.parse(match[1]);
}

export type OAuthInteractionRouteKind =
  | "page"
  | "passkey_begin"
  | "passkey_complete"
  | "totp_page"
  | "totp_complete"
  | "oidc_start"
  | "oidc_complete"
  | "consent"
  | "cancel";

export type OAuthInteractionRoute =
  | {
      readonly interactionUid: string;
      readonly kind: Exclude<OAuthInteractionRouteKind, "oidc_start">;
    }
  | {
      readonly interactionUid: string;
      readonly kind: "oidc_start";
      readonly providerId: string;
    };

export function parseOAuthInteractionRoute(rawUrl: string): OAuthInteractionRoute {
  const match =
    /^\/auth\/interactions\/([A-Za-z0-9_-]{16,256})(?:\/(passkey\/begin|passkey\/complete|totp|totp\/complete|oidc\/complete|oidc\/([a-z][a-z0-9_-]{0,31})\/start|consent|cancel))?$/u.exec(
      rawUrl
    );
  if (!match) rejectAuthRequest("route_invalid");
  const interactionUid = InteractionUidSchema.parse(match[1]);
  if (match[3] !== undefined) {
    return {
      interactionUid,
      kind: "oidc_start",
      providerId: OidcProviderIdSchema.parse(match[3])
    };
  }
  const kind =
    match[2] === undefined
      ? "page"
      : match[2] === "passkey/begin"
        ? "passkey_begin"
        : match[2] === "passkey/complete"
          ? "passkey_complete"
          : match[2] === "totp"
            ? "totp_page"
            : match[2] === "totp/complete"
              ? "totp_complete"
              : match[2] === "oidc/complete"
                ? "oidc_complete"
                : match[2];
  return {
    interactionUid,
    kind: z
      .enum([
        "page",
        "passkey_begin",
        "passkey_complete",
        "totp_page",
        "totp_complete",
        "oidc_complete",
        "consent",
        "cancel"
      ])
      .parse(kind)
  };
}

export function parseOidcCallbackRoute(rawUrl: string): string {
  if (Buffer.byteLength(rawUrl, "utf8") > 8192) rejectAuthRequest("oidc_callback_route");
  const match = /^\/auth\/oidc\/callback\/([a-z][a-z0-9_-]{0,31})(?:\?[^#]{0,8192})?$/u.exec(
    rawUrl
  );
  if (!match) rejectAuthRequest("oidc_callback_route");
  return OidcProviderIdSchema.parse(match[1]);
}

export interface AuthInteractionSubmission {
  readonly action: z.infer<typeof AuthActionSchema>;
  readonly csrfToken: string;
}

async function readBoundedForm(
  request: IncomingMessage,
  maximumBytes: number
): Promise<URLSearchParams> {
  if (request.method !== "POST") rejectAuthRequest("method_not_allowed");
  const contentType = singleHeader(request, "content-type", true)?.toLowerCase();
  if (
    contentType !== "application/x-www-form-urlencoded" &&
    contentType !== "application/x-www-form-urlencoded; charset=utf-8"
  ) {
    rejectAuthRequest("content_type");
  }
  const contentLength = singleHeader(request, "content-length");
  if (contentLength !== undefined && !/^(?:0|[1-9]\d*)$/u.test(contentLength)) {
    rejectAuthRequest("content_length");
  }
  if (contentLength !== undefined && Number(contentLength) > maximumBytes)
    rejectAuthRequest("body_too_large");
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunkValue of request) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    length += chunk.length;
    if (length > maximumBytes) rejectAuthRequest("body_too_large");
    chunks.push(chunk);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    rejectAuthRequest("body_encoding");
  }
  return new URLSearchParams(text);
}

export async function readAuthInteractionSubmission(
  request: IncomingMessage
): Promise<AuthInteractionSubmission> {
  const form = await readBoundedForm(request, 8192);
  const keys = [...form.keys()].toSorted();
  if (keys.length !== 2 || keys[0] !== "action" || keys[1] !== "csrf_token") {
    rejectAuthRequest("form_keys");
  }
  return {
    action: AuthActionSchema.parse(form.get("action")),
    csrfToken: CsrfTokenSchema.parse(form.get("csrf_token"))
  };
}

export async function readOAuthCsrfSubmission(request: IncomingMessage): Promise<string> {
  const form = await readBoundedForm(request, 8192);
  const keys = [...form.keys()];
  if (keys.length !== 1 || keys[0] !== "csrf_token") rejectAuthRequest("form_keys");
  return CsrfTokenSchema.parse(form.get("csrf_token"));
}

export interface OAuthPasskeyCompletionSubmission {
  readonly csrfToken: string;
  readonly credential: AuthenticationResponseJSON;
}

export async function readOAuthPasskeyCompletion(
  request: IncomingMessage
): Promise<OAuthPasskeyCompletionSubmission> {
  const form = await readBoundedForm(request, 20_480);
  const keys = [...form.keys()].toSorted();
  if (keys.length !== 2 || keys[0] !== "credential" || keys[1] !== "csrf_token") {
    rejectAuthRequest("form_keys");
  }
  let credential: unknown;
  try {
    const serialized = z.string().min(1).max(16_384).parse(form.get("credential"));
    credential = JSON.parse(serialized) as unknown;
  } catch {
    rejectAuthRequest("credential_json");
  }
  return {
    csrfToken: CsrfTokenSchema.parse(form.get("csrf_token")),
    credential: AuthenticationResponseSchema.parse(credential) as AuthenticationResponseJSON
  };
}

export interface OAuthTotpCompletionSubmission {
  readonly csrfToken: string;
  readonly fallbackHandle: string;
  readonly code: string;
}

export async function readOAuthTotpCompletion(
  request: IncomingMessage
): Promise<OAuthTotpCompletionSubmission> {
  const form = await readBoundedForm(request, 8192);
  const keys = [...form.keys()].toSorted();
  if (
    keys.length !== 3 ||
    keys[0] !== "code" ||
    keys[1] !== "csrf_token" ||
    keys[2] !== "fallback_handle"
  ) {
    rejectAuthRequest("form_keys");
  }
  return {
    csrfToken: CsrfTokenSchema.parse(form.get("csrf_token")),
    fallbackHandle: TotpFallbackHandleSchema.parse(form.get("fallback_handle")),
    code: TotpCodeSchema.parse(form.get("code"))
  };
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export interface AuthInteractionBinding {
  readonly interactionUid: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly stateSha256: Buffer;
  readonly nonceSha256: Buffer;
  readonly csrfSha256: Buffer;
  readonly expiresAt: Date;
}

const AuthInteractionBindingSchema = z
  .object({
    interactionUid: InteractionUidSchema,
    sessionId: UuidV7Schema,
    clientId: UuidV7Schema,
    stateSha256: Sha256BufferSchema,
    nonceSha256: Sha256BufferSchema,
    csrfSha256: Sha256BufferSchema,
    expiresAt: z.date()
  })
  .strict();

export function createAuthInteractionBinding(input: {
  readonly interactionUid: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly state: string;
  readonly nonce: string;
  readonly csrfToken: string;
  readonly expiresAt: Date;
}): AuthInteractionBinding {
  return AuthInteractionBindingSchema.parse({
    interactionUid: InteractionUidSchema.parse(input.interactionUid),
    sessionId: UuidV7Schema.parse(input.sessionId),
    clientId: UuidV7Schema.parse(input.clientId),
    stateSha256: sha256(OpaqueProtocolValueSchema.parse(input.state)),
    nonceSha256: sha256(OpaqueProtocolValueSchema.parse(input.nonce)),
    csrfSha256: sha256(CsrfTokenSchema.parse(input.csrfToken)),
    expiresAt: z.date().parse(input.expiresAt)
  });
}

function hashMatches(expected: Buffer, value: string): boolean {
  return timingSafeEqual(expected, sha256(value));
}

export function verifyAuthInteractionBinding(
  bindingValue: AuthInteractionBinding,
  input: {
    readonly interactionUid: string;
    readonly sessionId: string;
    readonly clientId: string;
    readonly state: string;
    readonly nonce: string;
    readonly csrfToken: string;
    readonly now: Date;
  }
): void {
  try {
    const binding = AuthInteractionBindingSchema.parse(bindingValue);
    const interactionUid = InteractionUidSchema.parse(input.interactionUid);
    const sessionId = UuidV7Schema.parse(input.sessionId);
    const clientId = UuidV7Schema.parse(input.clientId);
    const state = OpaqueProtocolValueSchema.parse(input.state);
    const nonce = OpaqueProtocolValueSchema.parse(input.nonce);
    const csrfToken = CsrfTokenSchema.parse(input.csrfToken);
    const now = z.date().parse(input.now);
    if (
      binding.interactionUid !== interactionUid ||
      binding.sessionId !== sessionId ||
      binding.clientId !== clientId ||
      binding.expiresAt.getTime() <= now.getTime() ||
      !hashMatches(binding.stateSha256, state) ||
      !hashMatches(binding.nonceSha256, nonce) ||
      !hashMatches(binding.csrfSha256, csrfToken)
    ) {
      rejectAuthRequest("csrf_or_nonce_mismatch");
    }
  } catch (error) {
    if (error instanceof AuthPageSecurityError) throw error;
    rejectAuthRequest("binding_unavailable");
  }
}

export interface RotatedAuthSession {
  readonly opaqueSessionSha256: Buffer;
  readonly csrfToken: string;
  readonly csrfSha256: Buffer;
  readonly expiresAt: Date;
  readonly setCookie: string;
}

export function rotateAuthSession(
  options: {
    readonly entropy?: Uint8Array;
    readonly now?: Date;
    readonly ttlSeconds?: number;
  } = {}
): RotatedAuthSession {
  const entropy = Buffer.from(options.entropy ?? randomBytes(64));
  if (entropy.length !== 64) throw new RangeError("auth session rotation requires 64 bytes");
  const now = z.date().parse(options.now ?? new Date());
  if (!Number.isFinite(now.getTime())) throw new RangeError("auth session time is invalid");
  const ttlSeconds = z
    .number()
    .int()
    .min(60)
    .max(28_800)
    .parse(options.ttlSeconds ?? 28_800);
  const sessionToken = entropy.subarray(0, 32).toString("base64url");
  const csrfToken = entropy.subarray(32).toString("base64url");
  return {
    opaqueSessionSha256: sha256(sessionToken),
    csrfToken,
    csrfSha256: sha256(csrfToken),
    expiresAt: new Date(now.getTime() + ttlSeconds * 1000),
    setCookie:
      `__Host-boardagent_auth=${sessionToken}; Path=/; Max-Age=${String(ttlSeconds)}; ` +
      "Secure; HttpOnly; SameSite=Lax"
  };
}
