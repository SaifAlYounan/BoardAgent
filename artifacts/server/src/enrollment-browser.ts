import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";

import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { z } from "zod";

import {
  AuthPageSecurityError,
  AuthRequestBoundary,
  authPageSecurityHeaders
} from "./auth-page.js";
import { BuiltinEnrollmentError, type BuiltinEnrollmentService } from "./enrollment.js";
import { WebAuthnCeremonyError } from "./webauthn.js";

const CSRF_TTL_SECONDS = 10 * 60;
const CSRF_NONCE_BYTES = 32;
const CSRF_EXPIRY_BYTES = 8;
const CSRF_MAC_BYTES = 32;
const CSRF_PAYLOAD_BYTES = CSRF_EXPIRY_BYTES + CSRF_NONCE_BYTES;
const CSRF_TOKEN_BYTES = CSRF_PAYLOAD_BYTES + CSRF_MAC_BYTES;
const CSRF_DOMAIN = "boardagent.enrollment.csrf.v1\0";

const CanonicalBase64UrlSchema = z
  .string()
  .min(1)
  .max(16_384)
  .regex(/^[A-Za-z0-9_-]+$/u)
  .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value);
const InvitationTokenSchema = CanonicalBase64UrlSchema.length(43).refine(
  (value) => Buffer.from(value, "base64url").length === 32
);
const CsrfTokenSchema = CanonicalBase64UrlSchema.length(96).refine(
  (value) => Buffer.from(value, "base64url").length === CSRF_TOKEN_BYTES
);
const ProofingMethodSchema = z.enum(["in_person", "verified_number_call"]);
const AuthenticatorTransportSchema = z.enum([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb"
]);
export const RegistrationResponseSchema = z
  .object({
    id: CanonicalBase64UrlSchema.max(2048),
    rawId: CanonicalBase64UrlSchema.max(2048),
    response: z
      .object({
        clientDataJSON: CanonicalBase64UrlSchema.max(8192),
        attestationObject: CanonicalBase64UrlSchema.max(16_384),
        transports: z
          .array(AuthenticatorTransportSchema)
          .max(16)
          .refine((values) => new Set(values).size === values.length)
          .optional()
      })
      .strict(),
    type: z.literal("public-key"),
    clientExtensionResults: z
      .object({
        credProps: z.object({ rk: z.boolean().optional() }).strict().optional()
      })
      .strict(),
    authenticatorAttachment: z.enum(["cross-platform", "platform"]).optional()
  })
  .strict();

export class BuiltinEnrollmentBrowserError extends Error {
  public readonly code = "invalid_enrollment_request";

  public constructor() {
    super("invalid enrollment request");
    this.name = "BuiltinEnrollmentBrowserError";
  }
}

function rejectEnrollmentRequest(): never {
  throw new BuiltinEnrollmentBrowserError();
}

function validDate(value: Date): Date {
  if (!Number.isFinite(value.getTime()))
    throw new Error("enrollment clock returned an invalid date");
  return value;
}

export class BuiltinEnrollmentCsrf {
  private readonly key: Buffer;
  private readonly entropy: (length: number) => Buffer;
  private readonly now: () => Date;

  public constructor(options: {
    readonly key: Uint8Array;
    readonly entropy?: (length: number) => Buffer;
    readonly now?: () => Date;
  }) {
    if (options.key.byteLength < 32)
      throw new Error("enrollment CSRF key must be at least 256 bits");
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
      throw new Error("enrollment CSRF entropy returned the wrong length");
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
      rejectEnrollmentRequest();
    }
    const decoded = Buffer.from(token, "base64url");
    const payload = decoded.subarray(0, CSRF_PAYLOAD_BYTES);
    const suppliedMac = decoded.subarray(CSRF_PAYLOAD_BYTES);
    const expectedMac = this.mac(payload);
    if (!timingSafeEqual(suppliedMac, expectedMac)) rejectEnrollmentRequest();
    const expirySeconds = payload.readBigUInt64BE(0);
    const nowSeconds = BigInt(Math.floor(validDate(this.now()).getTime() / 1000));
    if (expirySeconds <= nowSeconds || expirySeconds > nowSeconds + BigInt(CSRF_TTL_SECONDS)) {
      rejectEnrollmentRequest();
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
  if (values.length > 1) rejectEnrollmentRequest();
  const header = request.headers[name];
  if (Array.isArray(header)) rejectEnrollmentRequest();
  const value = values[0] ?? header;
  if (required && (value === undefined || value === "")) rejectEnrollmentRequest();
  return value;
}

export async function readBoundedForm(
  request: IncomingMessage,
  maximumBytes: number
): Promise<URLSearchParams> {
  if (request.method !== "POST") rejectEnrollmentRequest();
  const contentType = singleHeader(request, "content-type", true)?.toLowerCase();
  if (
    contentType !== "application/x-www-form-urlencoded" &&
    contentType !== "application/x-www-form-urlencoded; charset=utf-8"
  ) {
    rejectEnrollmentRequest();
  }
  if (singleHeader(request, "content-encoding") !== undefined) rejectEnrollmentRequest();
  const contentLength = singleHeader(request, "content-length");
  if (contentLength !== undefined && !/^(?:0|[1-9]\d*)$/u.test(contentLength)) {
    rejectEnrollmentRequest();
  }
  if (contentLength !== undefined && Number(contentLength) > maximumBytes) {
    rejectEnrollmentRequest();
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunkValue of request) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    length += chunk.length;
    if (length > maximumBytes) rejectEnrollmentRequest();
    chunks.push(chunk);
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
    return new URLSearchParams(text);
  } catch {
    rejectEnrollmentRequest();
  }
}

function exactKeys(form: URLSearchParams, expected: readonly string[]): void {
  const keys = [...form.keys()].toSorted();
  if (keys.length !== expected.length || expected.some((key, index) => key !== keys[index])) {
    rejectEnrollmentRequest();
  }
}

async function readBeginSubmission(request: IncomingMessage): Promise<{
  readonly csrfToken: string;
  readonly invitationToken: string;
}> {
  const form = await readBoundedForm(request, 8192);
  exactKeys(form, ["csrf_token", "invitation_token"]);
  return {
    csrfToken: CsrfTokenSchema.parse(form.get("csrf_token")),
    invitationToken: InvitationTokenSchema.parse(form.get("invitation_token"))
  };
}

async function readCompleteSubmission(request: IncomingMessage): Promise<{
  readonly csrfToken: string;
  readonly invitationToken: string;
  readonly proofingMethod: z.infer<typeof ProofingMethodSchema>;
  readonly response: RegistrationResponseJSON;
}> {
  const form = await readBoundedForm(request, 32_768);
  exactKeys(form, ["credential", "csrf_token", "invitation_token", "proofing_method"]);
  let credential: unknown;
  try {
    const serialized = z.string().min(1).max(24_576).parse(form.get("credential"));
    credential = JSON.parse(serialized) as unknown;
  } catch {
    rejectEnrollmentRequest();
  }
  return {
    csrfToken: CsrfTokenSchema.parse(form.get("csrf_token")),
    invitationToken: InvitationTokenSchema.parse(form.get("invitation_token")),
    proofingMethod: ProofingMethodSchema.parse(form.get("proofing_method")),
    response: RegistrationResponseSchema.parse(credential) as RegistrationResponseJSON
  };
}

function renderBuiltinEnrollmentPage(csrfToken: string): string {
  const csrf = CsrfTokenSchema.parse(csrfToken);
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Join your board in BoardAgent</title>" +
    '<script src="/enroll/webauthn.js" defer></script></head><body><main>' +
    "<h1>Join your board</h1>" +
    "<p>Check the organization, your name and every board seat before creating a passkey.</p>" +
    '<form autocomplete="off" data-enrollment>' +
    `<input type="hidden" name="csrf_token" value="${csrf}">` +
    '<label>One-time invitation <input type="password" name="invitation_token" required ' +
    'minlength="43" maxlength="43" autocapitalize="none" autocomplete="off" ' +
    'spellcheck="false"></label>' +
    '<button type="button" data-inspect-invitation>Check invitation</button>' +
    "<section data-candidate hidden><h2>Confirm your seat</h2>" +
    "<p>Organization: <strong data-organization></strong></p>" +
    "<p>Member: <strong data-member></strong></p><ul data-seats></ul>" +
    '<label>How will the secretary verify you? <select name="proofing_method">' +
    '<option value="verified_number_call">Verified-number call</option>' +
    '<option value="in_person">In person</option></select></label>' +
    '<button type="button" data-create-passkey>Create passkey</button></section>' +
    '<p role="status" aria-live="polite" data-enrollment-status></p>' +
    "<pre data-activation-code hidden></pre></form>" +
    "</main></body></html>"
  );
}

export const BOARDAGENT_ENROLLMENT_BROWSER_SCRIPT = `(() => {
  "use strict";

  const fragmentToken = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  history.replaceState(null, "", "/enroll");

  const form = document.querySelector("form[data-enrollment]");
  if (!(form instanceof HTMLFormElement)) return;
  const csrf = form.elements.namedItem("csrf_token");
  const invitation = form.elements.namedItem("invitation_token");
  const proofingMethod = form.elements.namedItem("proofing_method");
  const inspectButton = form.querySelector("[data-inspect-invitation]");
  const createButton = form.querySelector("[data-create-passkey]");
  const candidate = form.querySelector("[data-candidate]");
  const organization = form.querySelector("[data-organization]");
  const member = form.querySelector("[data-member]");
  const seats = form.querySelector("[data-seats]");
  const status = form.querySelector("[data-enrollment-status]");
  const activationCode = form.querySelector("[data-activation-code]");
  if (
    !(csrf instanceof HTMLInputElement) ||
    !(invitation instanceof HTMLInputElement) ||
    !(proofingMethod instanceof HTMLSelectElement) ||
    !(inspectButton instanceof HTMLButtonElement) ||
    !(createButton instanceof HTMLButtonElement) ||
    !(candidate instanceof HTMLElement) ||
    !(organization instanceof HTMLElement) ||
    !(member instanceof HTMLElement) ||
    !(seats instanceof HTMLUListElement) ||
    !(status instanceof HTMLElement) ||
    !(activationCode instanceof HTMLPreElement)
  ) return;

  if (/^[A-Za-z0-9_-]{43}$/.test(fragmentToken)) invitation.value = fragmentToken;
  let creationOptions = null;

  const decode = (value) => {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error("invalid base64url");
    }
    const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
      value.length + ((4 - (value.length % 4)) % 4),
      "="
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
    if (!response.ok) throw new Error("enrollment request failed");
    return response.json();
  };

  inspectButton.addEventListener("click", async () => {
    inspectButton.disabled = true;
    status.textContent = "Checking the invitation…";
    try {
      const result = await post("/enroll/passkey/begin", {
        csrf_token: csrf.value,
        invitation_token: invitation.value
      });
      if (
        result === null ||
        typeof result !== "object" ||
        typeof result.organizationDisplayName !== "string" ||
        typeof result.memberDisplayName !== "string" ||
        !Array.isArray(result.seats) ||
        result.publicKey === null ||
        typeof result.publicKey !== "object"
      ) throw new Error("invalid enrollment response");
      organization.textContent = result.organizationDisplayName;
      member.textContent = result.memberDisplayName;
      seats.replaceChildren();
      for (const seat of result.seats) {
        if (
          seat === null ||
          typeof seat !== "object" ||
          typeof seat.boardName !== "string" ||
          typeof seat.seatRole !== "string"
        ) throw new Error("invalid enrollment seat");
        const item = document.createElement("li");
        item.textContent = seat.boardName + " — " + seat.seatRole.replaceAll("_", " ");
        seats.append(item);
      }
      creationOptions = result.publicKey;
      invitation.readOnly = true;
      candidate.hidden = false;
      status.textContent = "Confirm these details, then create your passkey.";
    } catch {
      status.textContent = "The invitation could not be verified.";
      inspectButton.disabled = false;
    }
  });

  createButton.addEventListener("click", async () => {
    if (creationOptions === null) return;
    createButton.disabled = true;
    status.textContent = "Waiting for Face ID, Touch ID, Windows Hello or your security key…";
    try {
      const publicKey = {
        ...creationOptions,
        challenge: decode(creationOptions.challenge),
        user: { ...creationOptions.user, id: decode(creationOptions.user.id) },
        ...(Array.isArray(creationOptions.excludeCredentials)
          ? {
              excludeCredentials: creationOptions.excludeCredentials.map((entry) => ({
                ...entry,
                id: decode(entry.id)
              }))
            }
          : {})
      };
      const credential = await navigator.credentials.create({ publicKey });
      if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAttestationResponse)
      ) throw new Error("invalid passkey response");
      const response = {
        id: credential.id,
        rawId: encode(credential.rawId),
        response: {
          clientDataJSON: encode(credential.response.clientDataJSON),
          attestationObject: encode(credential.response.attestationObject),
          transports:
            typeof credential.response.getTransports === "function"
              ? credential.response.getTransports()
              : undefined
        },
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
        ...(credential.authenticatorAttachment === null
          ? {}
          : { authenticatorAttachment: credential.authenticatorAttachment })
      };
      const completed = await post("/enroll/passkey/complete", {
        csrf_token: csrf.value,
        invitation_token: invitation.value,
        proofing_method: proofingMethod.value,
        credential: JSON.stringify(response)
      });
      if (
        completed === null ||
        typeof completed !== "object" ||
        completed.status !== "pending_activation" ||
        typeof completed.activationCode !== "string" ||
        typeof completed.activationChallengeId !== "string"
      ) throw new Error("invalid activation response");
      invitation.value = "";
      creationOptions = null;
      activationCode.textContent =
        "Activation reference: " + completed.activationChallengeId +
        "\\nActivation code: " + completed.activationCode +
        "\\n\\nWhat happens next\\n" +
        "1. Within ten minutes, give the reference and the code to the person who invited you, in person or on the verified-number call. They confirm your activation; the code alone activates nothing. (For the first administrator of a new installation, the deployment operator runs the activation from the server.)\\n" +
        "2. Once confirmed, connect your own agent to this board. With Claude Code, in a terminal:\\n" +
        "   claude mcp add --transport http boardagent " + location.origin + "/mcp\\n" +
        "   then start claude, type /mcp, choose boardagent, and sign in here with this passkey.\\n" +
        "3. Your first session only reads onboarding: ask your agent to show the onboarding terms and open the attestation link, attest with this passkey, then reconnect for your normal access.\\n" +
        "Keep this page open until step 1 is done; the code is shown once.";
      activationCode.hidden = false;
      status.textContent = "Passkey created. Board access remains disabled until the person who invited you confirms the code.";
    } catch {
      status.textContent = "Passkey enrollment failed. Request a new invitation if this persists.";
      createButton.disabled = false;
    }
  });
})();
`;

function responseHeaders(
  includeHsts: boolean,
  contentType: "html" | "javascript" | "json"
): Readonly<Record<string, string>> {
  const headers = authPageSecurityHeaders({ includeHsts });
  return {
    ...headers,
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
          ? "invalid_enrollment_request"
          : status === 429
            ? "rate_limited"
            : "server_error"
    })
  );
}

export function createBuiltinEnrollmentHandler(options: {
  readonly boundary: AuthRequestBoundary;
  readonly enrollment: Pick<BuiltinEnrollmentService, "begin" | "complete">;
  readonly csrf: BuiltinEnrollmentCsrf;
  readonly includeHsts: boolean;
}): RequestListener {
  const handle = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const route = request.url;
    if (route === "/enroll") {
      options.boundary.inspect(request, { stateChanging: false });
      if (request.method !== "GET") rejectEnrollmentRequest();
      response.writeHead(200, responseHeaders(options.includeHsts, "html"));
      response.end(renderBuiltinEnrollmentPage(options.csrf.issue()));
      return;
    }
    if (route === "/enroll/webauthn.js") {
      options.boundary.inspect(request, { stateChanging: false });
      if (request.method !== "GET") rejectEnrollmentRequest();
      response.writeHead(200, responseHeaders(options.includeHsts, "javascript"));
      response.end(BOARDAGENT_ENROLLMENT_BROWSER_SCRIPT);
      return;
    }
    if (route !== "/enroll/passkey/begin" && route !== "/enroll/passkey/complete") {
      rejectEnrollmentRequest();
    }
    options.boundary.inspect(request, { stateChanging: true });
    if (route === "/enroll/passkey/begin") {
      const submission = await readBeginSubmission(request);
      options.csrf.verify(submission.csrfToken);
      const begun = await options.enrollment.begin({
        invitationToken: submission.invitationToken
      });
      response.writeHead(200, responseHeaders(options.includeHsts, "json"));
      response.end(JSON.stringify(begun));
      return;
    }
    const submission = await readCompleteSubmission(request);
    options.csrf.verify(submission.csrfToken);
    const completed = await options.enrollment.complete({
      invitationToken: submission.invitationToken,
      proofingMethod: submission.proofingMethod,
      response: submission.response
    });
    response.writeHead(200, responseHeaders(options.includeHsts, "json"));
    response.end(
      JSON.stringify({
        status: completed.status,
        memberId: completed.memberId,
        invitationId: completed.invitationId,
        activationChallengeId: completed.activationChallengeId,
        activationCode: completed.activationCode,
        expiresInSeconds: completed.expiresInSeconds
      })
    );
  };

  return (request, response) => {
    void handle(request, response).catch((error: unknown) => {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") {
        sendError(response, 429, options.includeHsts, error.retryAfterSeconds ?? 1);
      } else if (
        error instanceof BuiltinEnrollmentBrowserError ||
        error instanceof AuthPageSecurityError ||
        error instanceof BuiltinEnrollmentError ||
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
