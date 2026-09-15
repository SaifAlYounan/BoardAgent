import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import type { RequestListener } from "node:http";
import { z } from "zod";
import {
  AuthPageSecurityError,
  authPageSecurityHeaders,
  type AuthRequestBoundary
} from "./auth-page.js";
import { ActivationRestartError, type ActivationRestartService } from "./activation-restart.js";
import {
  BuiltinEnrollmentBrowserError,
  BuiltinEnrollmentCsrf,
  readBoundedForm
} from "./enrollment-browser.js";
import { WebAuthnCeremonyError } from "./webauthn.js";

const CanonicalBase64UrlSchema = z
  .string()
  .min(1)
  .max(16_384)
  .regex(/^[A-Za-z0-9_-]+$/u)
  .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value);
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

export const BOARDAGENT_ACTIVATION_RESTART_BROWSER_SCRIPT = String.raw`(() => {
  "use strict";
  const token = location.hash.slice(1);
  history.replaceState(null, "", "/enroll/restart");
  const form = document.querySelector("form");
  const restart = form.elements.namedItem("restart_token");
  const csrf = form.elements.namedItem("csrf_token");
  const inspect = document.querySelector("[data-inspect]");
  const prove = document.querySelector("[data-prove]");
  const person = document.querySelector("[data-person]");
  const status = document.querySelector("[role=status]");
  const handoff = document.querySelector("[data-handoff]");
  if (/^[A-Za-z0-9_-]{43}$/.test(token)) restart.value = token;
  let options = null;
  const decode = value => {
    const text = value.replaceAll("-", "+").replaceAll("_", "/");
    return Uint8Array.from(atob(text.padEnd(text.length + ((4 - text.length % 4) % 4), "=")), c => c.charCodeAt(0)).buffer;
  };
  const encode = value => {
    let text = ""; for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
    return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  };
  const post = async (path, extra = {}) => {
    const response = await fetch(path, { method: "POST", credentials: "same-origin", redirect: "error",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf_token: csrf.value, restart_token: restart.value, ...extra }).toString() });
    if (!response.ok) throw new Error("Restart unavailable");
    return response.json();
  };
  inspect.addEventListener("click", async () => {
    inspect.disabled = true;
    try {
      const result = await post("/enroll/restart/passkey/begin");
      if (typeof result.memberDisplayName !== "string" || typeof result.organizationDisplayName !== "string" || !result.publicKey) throw new Error("Invalid restart");
      person.textContent = result.organizationDisplayName + " — " + result.memberDisplayName + " (verification: " + result.proofingMethod + ")";
      options = result.publicKey; restart.readOnly = true; prove.hidden = false;
      status.textContent = "Check this is your account, then prove it with the passkey you already registered.";
    } catch { status.textContent = "This restart handoff is unavailable. Ask the person who issued it for a new one."; inspect.disabled = false; }
  });
  prove.addEventListener("click", async () => {
    if (!options) return;
    prove.disabled = true;
    status.textContent = "Waiting for Face ID, Touch ID, Windows Hello or your security key…";
    try {
      const publicKey = { ...options, challenge: decode(options.challenge),
        ...(Array.isArray(options.allowCredentials) ? { allowCredentials: options.allowCredentials.map(c => ({ ...c, id: decode(c.id) })) } : {}) };
      const credential = await navigator.credentials.get({ publicKey });
      if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error("Invalid passkey response");
      const response = { id: credential.id, rawId: encode(credential.rawId), type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
        ...(credential.authenticatorAttachment === null ? {} : { authenticatorAttachment: credential.authenticatorAttachment }),
        response: { clientDataJSON: encode(credential.response.clientDataJSON), authenticatorData: encode(credential.response.authenticatorData),
          signature: encode(credential.response.signature),
          userHandle: credential.response.userHandle === null ? null : encode(credential.response.userHandle) } };
      const result = await post("/enroll/restart/passkey/complete", { credential: JSON.stringify(response) });
      if (result.status !== "pending_activation" || typeof result.activationCode !== "string") throw new Error("Restart incomplete");
      restart.value = ""; options = null; prove.hidden = true;
      handoff.hidden = false;
      handoff.textContent = "Member: " + result.memberId + "\nActivation reference: " + result.activationChallengeId +
        "\nActivation code: " + result.activationCode + "\nProofing method: " + result.proofingMethod +
        "\n\nWhat happens next\n1. Within ten minutes, give the reference and the code to the person who issued this restart, in person or through your verified phone number. They confirm your activation; the code alone activates nothing.\n" +
        "2. Once confirmed, connect your own agent: with Claude Code run  claude mcp add --transport http boardagent " + location.origin + "/mcp  then start claude, type /mcp, choose boardagent and sign in with the passkey you just used.";
      status.textContent = "Your fresh activation code lasts ten minutes. Keep this page open until the person who issued the restart has confirmed it.";
    } catch { status.textContent = "The passkey check did not complete. Retry, or ask for a new restart handoff."; prove.disabled = false; }
  });
})();`;

/**
 * Browser handler for `/enroll/restart` (one-use pending-activation restart handoff).
 * Mounted beside the ordinary enrollment page; the runtime routes every `/enroll*` path
 * to the enrollment listener, which delegates `/enroll/restart*` here.
 */
export function createActivationRestartHandler(options: {
  readonly boundary: AuthRequestBoundary;
  readonly csrf: BuiltinEnrollmentCsrf;
  readonly restart: Pick<ActivationRestartService, "begin" | "complete">;
  readonly includeHsts: boolean;
  readonly onError?: (error: Error) => void;
  readonly consumeAttempt: (
    trustedIpClass: string
  ) => Promise<{ readonly allowed: boolean; readonly retryAfterSeconds: number }>;
}): RequestListener {
  return (request, response) => {
    const send = (status: number, type: string, body: string) => {
      response.writeHead(status, {
        ...authPageSecurityHeaders({ includeHsts: options.includeHsts }),
        "content-type": type
      });
      response.end(body);
    };
    const handle = async () => {
      const path = request.url;
      const read = path === "/enroll/restart" || path === "/enroll/restart/webauthn.js";
      const inspection = options.boundary.inspect(request, { stateChanging: !read });
      if (read) {
        if (request.method !== "GET") throw new ActivationRestartError();
        if (path === "/enroll/restart/webauthn.js")
          return send(
            200,
            "text/javascript; charset=utf-8",
            BOARDAGENT_ACTIVATION_RESTART_BROWSER_SCRIPT
          );
        return send(
          200,
          "text/html; charset=utf-8",
          '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Restart your BoardAgent activation</title><script src="/enroll/restart/webauthn.js" defer></script></head><body><main><h1>Restart your activation</h1><p>Your previous activation code expired or was used up. The person who verifies your identity issued this one-time restart. Check your organization and name, then prove it is you with the passkey you already registered.</p><form autocomplete="off"><input type="hidden" name="csrf_token" value="' +
            options.csrf.issue() +
            '"><label>One-time restart handoff <input type="password" name="restart_token" minlength="43" maxlength="43" required autocomplete="off" spellcheck="false" autocapitalize="none"></label><button type="button" data-inspect>Check restart</button><p data-person></p><button type="button" data-prove hidden>Prove with my passkey</button><p role="status" aria-live="polite"></p><pre data-handoff hidden></pre></form></main></body></html>'
        );
      }
      if (
        request.method !== "POST" ||
        !["/enroll/restart/passkey/begin", "/enroll/restart/passkey/complete"].includes(path ?? "")
      )
        throw new ActivationRestartError();
      const attempt = await options.consumeAttempt(inspection.clientIpClass);
      if (!attempt.allowed)
        throw new WebAuthnCeremonyError(
          "rate_limited",
          "restart entry rate limited",
          attempt.retryAfterSeconds
        );
      const form = await readBoundedForm(request, 32_768);
      const expected =
        path === "/enroll/restart/passkey/begin"
          ? ["csrf_token", "restart_token"]
          : ["credential", "csrf_token", "restart_token"];
      if (JSON.stringify([...form.keys()].sort()) !== JSON.stringify(expected))
        throw new ActivationRestartError(new Error("restart form fields are not the exact set"));
      options.csrf.verify(z.string().parse(form.get("csrf_token")));
      const restartToken = z.string().length(43).parse(form.get("restart_token"));
      const result =
        path === "/enroll/restart/passkey/begin"
          ? await options.restart.begin({ restartToken })
          : await options.restart.complete({
              restartToken,
              response: AuthenticationResponseSchema.parse(
                JSON.parse(z.string().max(24_576).parse(form.get("credential"))) as unknown
              ) as AuthenticationResponseJSON
            });
      send(200, "application/json; charset=utf-8", JSON.stringify(result));
    };
    void handle().catch((error: unknown) => {
      const limited = error instanceof WebAuthnCeremonyError && error.code === "rate_limited";
      if (limited) response.setHeader("retry-after", String(error.retryAfterSeconds ?? 1));
      // A refusal with an underlying cause is still a 400 for the browser; the operator log
      // receives the cause so a misconfiguration is not mistaken for a person's mistake.
      if (error instanceof ActivationRestartError && error.cause instanceof Error) {
        options.onError?.(error.cause);
      }
      const expected =
        error instanceof ActivationRestartError ||
        error instanceof WebAuthnCeremonyError ||
        error instanceof AuthPageSecurityError ||
        error instanceof BuiltinEnrollmentBrowserError ||
        error instanceof z.ZodError ||
        error instanceof SyntaxError;
      if (!expected)
        options.onError?.(error instanceof Error ? error : new Error("restart handler failed"));
      send(
        limited ? 429 : expected ? 400 : 500,
        "application/json; charset=utf-8",
        JSON.stringify({ error: "activation_restart_unavailable" })
      );
    });
  };
}
