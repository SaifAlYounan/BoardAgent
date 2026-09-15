import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";

import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { z } from "zod";

import {
  AuthPageSecurityError,
  AuthRequestBoundary,
  authPageSecurityHeaders
} from "./auth-page.js";
import { BuiltinOnboardingError, type BuiltinOnboardingService } from "./onboarding.js";
import { WebAuthnCeremonyError } from "./webauthn.js";

const CSRF_TTL_SECONDS = 10 * 60;
const CSRF_NONCE_BYTES = 32;
const CSRF_EXPIRY_BYTES = 8;
const CSRF_MAC_BYTES = 32;
const CSRF_PAYLOAD_BYTES = CSRF_EXPIRY_BYTES + CSRF_NONCE_BYTES;
const CSRF_TOKEN_BYTES = CSRF_PAYLOAD_BYTES + CSRF_MAC_BYTES;
const CSRF_DOMAIN = "boardagent.onboarding.csrf.v1\0";

const CanonicalBase64UrlSchema = z
  .string()
  .min(1)
  .max(16_384)
  .regex(/^[A-Za-z0-9_-]+$/u)
  .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value);
const StageTokenSchema = CanonicalBase64UrlSchema.length(43).refine(
  (value) => Buffer.from(value, "base64url").length === 32
);
const CsrfTokenSchema = CanonicalBase64UrlSchema.length(96).refine(
  (value) => Buffer.from(value, "base64url").length === CSRF_TOKEN_BYTES
);
const AuthenticationResponseSchema = z
  .object({
    id: CanonicalBase64UrlSchema.max(2048),
    rawId: CanonicalBase64UrlSchema.max(2048),
    response: z
      .object({
        clientDataJSON: CanonicalBase64UrlSchema.max(8192),
        authenticatorData: CanonicalBase64UrlSchema.max(4096),
        signature: CanonicalBase64UrlSchema.max(4096),
        userHandle: CanonicalBase64UrlSchema.max(2048).nullable().optional()
      })
      .strict(),
    type: z.literal("public-key"),
    clientExtensionResults: z.object({}).strict(),
    authenticatorAttachment: z.enum(["cross-platform", "platform"]).optional()
  })
  .strict();

export class BuiltinOnboardingBrowserError extends Error {
  public readonly code = "invalid_onboarding_request";

  public constructor() {
    super("invalid onboarding request");
    this.name = "BuiltinOnboardingBrowserError";
  }
}

function rejectOnboardingRequest(): never {
  throw new BuiltinOnboardingBrowserError();
}

function validDate(value: Date): Date {
  if (!Number.isFinite(value.getTime())) throw new Error("onboarding clock is invalid");
  return value;
}

export class BuiltinOnboardingCsrf {
  private readonly key: Buffer;
  private readonly entropy: (length: number) => Buffer;
  private readonly now: () => Date;

  public constructor(options: {
    readonly key: Uint8Array;
    readonly entropy?: (length: number) => Buffer;
    readonly now?: () => Date;
  }) {
    if (options.key.byteLength < 32) {
      throw new Error("onboarding CSRF key must be at least 256 bits");
    }
    this.key = Buffer.from(options.key);
    this.entropy = options.entropy ?? randomBytes;
    this.now = options.now ?? (() => new Date());
  }

  private mac(payload: Uint8Array): Buffer {
    return createHmac("sha256", this.key).update(CSRF_DOMAIN, "utf8").update(payload).digest();
  }

  public issue(): string {
    const nonce = this.entropy(CSRF_NONCE_BYTES);
    if (nonce.length !== CSRF_NONCE_BYTES) {
      throw new Error("onboarding CSRF entropy returned the wrong length");
    }
    const nowSeconds = BigInt(Math.floor(validDate(this.now()).getTime() / 1000));
    const payload = Buffer.alloc(CSRF_PAYLOAD_BYTES);
    payload.writeBigUInt64BE(nowSeconds + BigInt(CSRF_TTL_SECONDS), 0);
    nonce.copy(payload, CSRF_EXPIRY_BYTES);
    return Buffer.concat([payload, this.mac(payload)]).toString("base64url");
  }

  public verify(tokenValue: string): void {
    let token: string;
    try {
      token = CsrfTokenSchema.parse(tokenValue);
    } catch {
      rejectOnboardingRequest();
    }
    const decoded = Buffer.from(token, "base64url");
    const payload = decoded.subarray(0, CSRF_PAYLOAD_BYTES);
    const suppliedMac = decoded.subarray(CSRF_PAYLOAD_BYTES);
    const expectedMac = this.mac(payload);
    if (!timingSafeEqual(suppliedMac, expectedMac)) rejectOnboardingRequest();
    const expirySeconds = payload.readBigUInt64BE(0);
    const nowSeconds = BigInt(Math.floor(validDate(this.now()).getTime() / 1000));
    if (expirySeconds <= nowSeconds || expirySeconds > nowSeconds + BigInt(CSRF_TTL_SECONDS)) {
      rejectOnboardingRequest();
    }
  }
}

function singleHeader(
  request: IncomingMessage,
  name: string,
  required = false
): string | undefined {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      values.push(request.rawHeaders[index + 1] ?? "");
    }
  }
  if (values.length > 1) rejectOnboardingRequest();
  const header = request.headers[name];
  if (Array.isArray(header)) rejectOnboardingRequest();
  const value = values[0] ?? header;
  if (required && (value === undefined || value === "")) rejectOnboardingRequest();
  return value;
}

async function readBoundedForm(
  request: IncomingMessage,
  maximumBytes: number
): Promise<URLSearchParams> {
  if (request.method !== "POST") rejectOnboardingRequest();
  const contentType = singleHeader(request, "content-type", true)?.toLowerCase();
  if (
    contentType !== "application/x-www-form-urlencoded" &&
    contentType !== "application/x-www-form-urlencoded; charset=utf-8"
  ) {
    rejectOnboardingRequest();
  }
  if (singleHeader(request, "content-encoding") !== undefined) rejectOnboardingRequest();
  const contentLength = singleHeader(request, "content-length");
  if (contentLength !== undefined && !/^(?:0|[1-9]\d*)$/u.test(contentLength)) {
    rejectOnboardingRequest();
  }
  if (contentLength !== undefined && Number(contentLength) > maximumBytes) {
    rejectOnboardingRequest();
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunkValue of request) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    length += chunk.length;
    if (length > maximumBytes) rejectOnboardingRequest();
    chunks.push(chunk);
  }
  try {
    return new URLSearchParams(
      new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))
    );
  } catch {
    rejectOnboardingRequest();
  }
}

function exactKeys(form: URLSearchParams, expected: readonly string[]): void {
  const keys = [...form.keys()].toSorted();
  if (keys.length !== expected.length || expected.some((key, index) => key !== keys[index])) {
    rejectOnboardingRequest();
  }
}

async function readBeginSubmission(request: IncomingMessage): Promise<{
  readonly csrfToken: string;
  readonly stageToken: string;
}> {
  const form = await readBoundedForm(request, 8192);
  exactKeys(form, ["csrf_token", "stage_token"]);
  return {
    csrfToken: CsrfTokenSchema.parse(form.get("csrf_token")),
    stageToken: StageTokenSchema.parse(form.get("stage_token"))
  };
}

async function readCompleteSubmission(request: IncomingMessage): Promise<{
  readonly csrfToken: string;
  readonly stageToken: string;
  readonly response: AuthenticationResponseJSON;
}> {
  const form = await readBoundedForm(request, 32_768);
  exactKeys(form, ["attest", "credential", "csrf_token", "stage_token"]);
  if (form.get("attest") !== "true") rejectOnboardingRequest();
  let credential: unknown;
  try {
    credential = JSON.parse(z.string().min(1).max(24_576).parse(form.get("credential"))) as unknown;
  } catch {
    rejectOnboardingRequest();
  }
  return {
    csrfToken: CsrfTokenSchema.parse(form.get("csrf_token")),
    stageToken: StageTokenSchema.parse(form.get("stage_token")),
    response: AuthenticationResponseSchema.parse(credential) as AuthenticationResponseJSON
  };
}

function renderBuiltinOnboardingPage(csrfToken: string): string {
  const csrf = CsrfTokenSchema.parse(csrfToken);
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Complete BoardAgent onboarding</title>" +
    '<script src="/onboarding/webauthn.js" defer></script></head><body><main>' +
    "<h1>Complete BoardAgent onboarding</h1>" +
    "<p>There is no BoardAgent governance portal. Your agent presents canonical board records to you.</p>" +
    '<form autocomplete="off" data-onboarding>' +
    `<input type="hidden" name="csrf_token" value="${csrf}">` +
    '<label>One-time onboarding link <input type="password" name="stage_token" required ' +
    'minlength="43" maxlength="43" autocapitalize="none" autocomplete="off" spellcheck="false"></label>' +
    '<button type="button" data-load-onboarding>Load exact responsibilities</button>' +
    "<section data-onboarding-review hidden><h2>Review the exact record</h2>" +
    "<dl><dt>Organization</dt><dd data-organization></dd><dt>Board</dt><dd data-board></dd>" +
    "<dt>Member</dt><dd data-member></dd><dt>Identity type</dt><dd data-member-kind></dd>" +
    "<dt>Accountable principal</dt><dd data-accountable-principal></dd>" +
    "<dt>Seat</dt><dd data-seat></dd></dl>" +
    "<h2>Current terms</h2><pre data-terms></pre><p>Terms SHA-256: <code data-terms-hash></code></p>" +
    "<h2>Secretary support</h2><p data-support></p><pre data-support-contacts></pre>" +
    "<h2>Your agent-mediated choices</h2><p>Presentation: <strong data-presentation></strong></p>" +
    "<p>Local memory: <strong data-local-memory></strong></p>" +
    "<h2>Responsibility attestation</h2><ul>" +
    "<li>BoardAgent supplies canonical information to my agent; it is not a governance portal.</li>" +
    "<li>I choose and police how my agent presents BoardAgent information.</li>" +
    "<li>I review that information and secure my agent and any local copies.</li>" +
    "<li>I require my agent to refetch before binding acts and process removal tombstones.</li>" +
    "</ul><p>BoardAgent records this attestation; it does not claim that I understood the material.</p>" +
    '<label><input type="checkbox" name="attest" value="true" required> ' +
    "I attest to the exact current terms, responsibilities, support details and choices shown above.</label>" +
    '<button type="button" data-attest-passkey>Attest with passkey</button></section>' +
    '<p role="status" aria-live="polite" data-onboarding-status></p></form>' +
    "</main></body></html>"
  );
}

export const BOARDAGENT_ONBOARDING_BROWSER_SCRIPT = `(() => {
  "use strict";

  const fragmentToken = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  history.replaceState(null, "", "/onboarding");
  const form = document.querySelector("form[data-onboarding]");
  if (!(form instanceof HTMLFormElement)) return;
  const csrf = form.elements.namedItem("csrf_token");
  const stageToken = form.elements.namedItem("stage_token");
  const attest = form.elements.namedItem("attest");
  const loadButton = form.querySelector("[data-load-onboarding]");
  const completeButton = form.querySelector("[data-attest-passkey]");
  const review = form.querySelector("[data-onboarding-review]");
  const status = form.querySelector("[data-onboarding-status]");
  const fields = {
    organization: form.querySelector("[data-organization]"),
    board: form.querySelector("[data-board]"),
    member: form.querySelector("[data-member]"),
    memberKind: form.querySelector("[data-member-kind]"),
    accountablePrincipal: form.querySelector("[data-accountable-principal]"),
    seat: form.querySelector("[data-seat]"),
    terms: form.querySelector("[data-terms]"),
    termsHash: form.querySelector("[data-terms-hash]"),
    support: form.querySelector("[data-support]"),
    supportContacts: form.querySelector("[data-support-contacts]"),
    presentation: form.querySelector("[data-presentation]"),
    localMemory: form.querySelector("[data-local-memory]")
  };
  if (
    !(csrf instanceof HTMLInputElement) ||
    !(stageToken instanceof HTMLInputElement) ||
    !(attest instanceof HTMLInputElement) ||
    !(loadButton instanceof HTMLButtonElement) ||
    !(completeButton instanceof HTMLButtonElement) ||
    !(review instanceof HTMLElement) ||
    !(status instanceof HTMLElement) ||
    Object.values(fields).some((field) => !(field instanceof HTMLElement))
  ) return;
  if (/^[A-Za-z0-9_-]{43}$/.test(fragmentToken)) stageToken.value = fragmentToken;
  let requestOptions = null;

  const decode = (value) => {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error("invalid base64url");
    }
    const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
      value.length + ((4 - (value.length % 4)) % 4), "="
    );
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
  };
  const encode = (value) => {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  };
  const post = async (path, values) => {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(values).toString()
    });
    if (!response.ok) throw new Error("onboarding request failed");
    return response.json();
  };

  loadButton.addEventListener("click", async () => {
    loadButton.disabled = true;
    status.textContent = "Loading the exact current onboarding record…";
    try {
      const result = await post("/onboarding/passkey/begin", {
        csrf_token: csrf.value,
        stage_token: stageToken.value
      });
      if (
        result === null || typeof result !== "object" ||
        typeof result.organizationDisplayName !== "string" ||
        typeof result.boardName !== "string" || typeof result.memberDisplayName !== "string" ||
        (result.memberKind !== "human" && result.memberKind !== "ai_system") ||
        (result.accountablePrincipalId !== null &&
          typeof result.accountablePrincipalId !== "string") ||
        (result.memberKind === "ai_system" &&
          typeof result.accountablePrincipalId !== "string") ||
        typeof result.seatRole !== "string" || result.terms === null ||
        typeof result.terms !== "object" || typeof result.terms.canonicalText !== "string" ||
        typeof result.terms.sha256 !== "string" || result.secretarySupport === null ||
        typeof result.secretarySupport !== "object" ||
        typeof result.secretarySupport.name !== "string" ||
        !Array.isArray(result.secretarySupport.contactMethods) ||
        typeof result.presentationChoice !== "string" ||
        typeof result.localMemoryChoice !== "string" ||
        result.publicKey === null || typeof result.publicKey !== "object"
      ) throw new Error("invalid onboarding response");
      fields.organization.textContent = result.organizationDisplayName;
      fields.board.textContent = result.boardName;
      fields.member.textContent = result.memberDisplayName;
      fields.memberKind.textContent = result.memberKind === "ai_system" ? "AI system" : "Human";
      fields.accountablePrincipal.textContent = result.accountablePrincipalId ??
        "Self — human member";
      fields.seat.textContent = result.seatRole.replaceAll("_", " ");
      fields.terms.textContent = result.terms.canonicalText;
      fields.termsHash.textContent = result.terms.sha256;
      fields.support.textContent = result.secretarySupport.name;
      fields.supportContacts.textContent = JSON.stringify(
        result.secretarySupport.contactMethods, null, 2
      );
      fields.presentation.textContent = result.presentationChoice;
      fields.localMemory.textContent = result.localMemoryChoice;
      requestOptions = result.publicKey;
      stageToken.readOnly = true;
      review.hidden = false;
      status.textContent = "Review everything shown, then attest with your passkey.";
    } catch {
      status.textContent = "The onboarding ceremony could not be verified.";
      loadButton.disabled = false;
    }
  });

  completeButton.addEventListener("click", async () => {
    if (requestOptions === null || !attest.checked) {
      status.textContent = "Review the record and check the attestation box first.";
      return;
    }
    completeButton.disabled = true;
    status.textContent = "Waiting for Face ID, Touch ID, Windows Hello or your security key…";
    try {
      const publicKey = {
        ...requestOptions,
        challenge: decode(requestOptions.challenge),
        ...(Array.isArray(requestOptions.allowCredentials)
          ? { allowCredentials: requestOptions.allowCredentials.map((entry) => ({
              ...entry, id: decode(entry.id)
            })) }
          : {})
      };
      const credential = await navigator.credentials.get({ publicKey });
      if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAssertionResponse)
      ) throw new Error("invalid passkey response");
      const response = {
        id: credential.id,
        rawId: encode(credential.rawId),
        response: {
          clientDataJSON: encode(credential.response.clientDataJSON),
          authenticatorData: encode(credential.response.authenticatorData),
          signature: encode(credential.response.signature),
          userHandle: credential.response.userHandle === null
            ? null : encode(credential.response.userHandle)
        },
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
        ...(credential.authenticatorAttachment === null
          ? {} : { authenticatorAttachment: credential.authenticatorAttachment })
      };
      const completed = await post("/onboarding/passkey/complete", {
        attest: "true",
        credential: JSON.stringify(response),
        csrf_token: csrf.value,
        stage_token: stageToken.value
      });
      if (completed === null || typeof completed !== "object" || completed.status !== "current") {
        throw new Error("invalid onboarding completion");
      }
      stageToken.value = "";
      requestOptions = null;
      attest.disabled = true;
      status.textContent = "Onboarding complete. Return to your agent; it can now continue.";
    } catch {
      status.textContent = "Passkey attestation failed. Reload the exact record and try again.";
      completeButton.disabled = false;
    }
  });
})();
`;

function responseHeaders(
  includeHsts: boolean,
  contentType: "html" | "javascript" | "json"
): Readonly<Record<string, string>> {
  return {
    ...authPageSecurityHeaders({ includeHsts }),
    "referrer-policy": "no-referrer",
    "content-type":
      contentType === "html"
        ? "text/html; charset=utf-8"
        : contentType === "javascript"
          ? "text/javascript; charset=utf-8"
          : "application/json; charset=utf-8"
  };
}

function sendError(
  response: ServerResponse,
  status: 400 | 429 | 500,
  includeHsts: boolean,
  retryAfterSeconds?: number
): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, {
    ...responseHeaders(includeHsts, "json"),
    ...(retryAfterSeconds === undefined
      ? {}
      : { "retry-after": String(Math.max(1, Math.ceil(retryAfterSeconds))) })
  });
  response.end(
    JSON.stringify({
      error:
        status === 400
          ? "invalid_onboarding_request"
          : status === 429
            ? "rate_limited"
            : "server_error"
    })
  );
}

export function createBuiltinOnboardingHandler(options: {
  readonly boundary: AuthRequestBoundary;
  readonly onboarding: Pick<BuiltinOnboardingService, "begin" | "complete">;
  readonly csrf: BuiltinOnboardingCsrf;
  readonly includeHsts: boolean;
}): RequestListener {
  const handle = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const route = request.url;
    if (route === "/onboarding") {
      options.boundary.inspect(request, { stateChanging: false });
      if (request.method !== "GET") rejectOnboardingRequest();
      response.writeHead(200, responseHeaders(options.includeHsts, "html"));
      response.end(renderBuiltinOnboardingPage(options.csrf.issue()));
      return;
    }
    if (route === "/onboarding/webauthn.js") {
      options.boundary.inspect(request, { stateChanging: false });
      if (request.method !== "GET") rejectOnboardingRequest();
      response.writeHead(200, responseHeaders(options.includeHsts, "javascript"));
      response.end(BOARDAGENT_ONBOARDING_BROWSER_SCRIPT);
      return;
    }
    if (route !== "/onboarding/passkey/begin" && route !== "/onboarding/passkey/complete") {
      rejectOnboardingRequest();
    }
    options.boundary.inspect(request, { stateChanging: true });
    if (route === "/onboarding/passkey/begin") {
      const submission = await readBeginSubmission(request);
      options.csrf.verify(submission.csrfToken);
      const begun = await options.onboarding.begin({ stageToken: submission.stageToken });
      response.writeHead(200, responseHeaders(options.includeHsts, "json"));
      response.end(JSON.stringify(begun));
      return;
    }
    const submission = await readCompleteSubmission(request);
    options.csrf.verify(submission.csrfToken);
    const completed = await options.onboarding.complete({
      stageToken: submission.stageToken,
      response: submission.response
    });
    response.writeHead(200, responseHeaders(options.includeHsts, "json"));
    response.end(JSON.stringify(completed));
  };

  return (request, response) => {
    void handle(request, response).catch((error: unknown) => {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") {
        sendError(response, 429, options.includeHsts, error.retryAfterSeconds ?? 1);
      } else if (
        error instanceof BuiltinOnboardingBrowserError ||
        error instanceof AuthPageSecurityError ||
        error instanceof BuiltinOnboardingError ||
        error instanceof WebAuthnCeremonyError ||
        error instanceof z.ZodError
      ) {
        sendError(response, 400, options.includeHsts);
      } else {
        sendError(response, 500, options.includeHsts);
      }
    });
  };
}
