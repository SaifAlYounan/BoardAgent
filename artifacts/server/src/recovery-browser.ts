import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import type { RequestListener } from "node:http";
import { z } from "zod";
import {
  AuthPageSecurityError,
  authPageSecurityHeaders,
  type AuthRequestBoundary
} from "./auth-page.js";
import {
  BuiltinEnrollmentBrowserError,
  BuiltinEnrollmentCsrf,
  readBoundedForm,
  RegistrationResponseSchema
} from "./enrollment-browser.js";
import {
  RecoveryRegistrationError,
  type RecoveryRegistrationService
} from "./recovery-registration.js";
import { WebAuthnCeremonyError } from "./webauthn.js";

const BROWSER_SCRIPT = String.raw`(() => {
  "use strict";
  const token = location.hash.slice(1);
  history.replaceState(null, "", "/recover");
  const form = document.querySelector("form");
  const recovery = form.elements.namedItem("recovery_token");
  const csrf = form.elements.namedItem("csrf_token");
  const inspect = document.querySelector("[data-inspect]");
  const create = document.querySelector("[data-create]");
  const person = document.querySelector("[data-person]");
  const status = document.querySelector("[role=status]");
  const handoff = document.querySelector("[data-handoff]");
  if (/^[A-Za-z0-9_-]{43}$/.test(token)) recovery.value = token;
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
      body: new URLSearchParams({ csrf_token: csrf.value, recovery_token: recovery.value, ...extra }).toString() });
    if (!response.ok) throw new Error("Recovery unavailable");
    return response.json();
  };
  inspect.addEventListener("click", async () => {
    inspect.disabled = true;
    try {
      const result = await post("/recover/passkey/begin");
      if (typeof result.memberDisplayName !== "string" || typeof result.organizationDisplayName !== "string" || !result.publicKey) throw new Error("Invalid recovery");
      person.textContent = result.organizationDisplayName + " — " + result.memberDisplayName;
      options = result.publicKey; recovery.readOnly = true; create.hidden = false;
      status.textContent = "Check this is your account, then create your replacement passkey.";
    } catch { status.textContent = "This recovery handoff is unavailable. Contact your administrator."; inspect.disabled = false; }
  });
  create.addEventListener("click", async () => {
    if (!options) return;
    create.disabled = true;
    try {
      const credential = await navigator.credentials.create({ publicKey: { ...options,
        challenge: decode(options.challenge), user: { ...options.user, id: decode(options.user.id) },
        excludeCredentials: (options.excludeCredentials || []).map(c => ({ ...c, id: decode(c.id) })) } });
      if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error("Invalid passkey");
      const response = { id: credential.id, rawId: encode(credential.rawId), type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
        ...(credential.authenticatorAttachment === null ? {} : { authenticatorAttachment: credential.authenticatorAttachment }),
        response: { clientDataJSON: encode(credential.response.clientDataJSON), attestationObject: encode(credential.response.attestationObject),
          transports: typeof credential.response.getTransports === "function" ? credential.response.getTransports() : undefined } };
      const result = await post("/recover/passkey/complete", { credential: JSON.stringify(response) });
      if (result.status !== "pending_activation" || typeof result.activationCode !== "string") throw new Error("Recovery incomplete");
      recovery.value = ""; options = null; create.hidden = true;
      handoff.hidden = false;
      handoff.textContent = "Member: " + result.memberId + "\nRecovery reference: " + result.invitationId +
        "\nChallenge: " + result.activationChallengeId + "\nHuman code: " + result.activationCode +
        "\nProofing method: " + result.proofingMethod;
      status.textContent = "Your replacement passkey is waiting for identity confirmation. Within ten minutes, give this code and these references to the administrator who started recovery, in person or through your verified phone number. They must confirm the replacement before you can use it. Never approve someone else's passkey.";
    } catch { status.textContent = "Passkey recovery was not completed. Retry or ask your administrator for a new handoff."; create.disabled = false; }
  });
})();`;

export function createRecoveryRegistrationHandler(options: {
  readonly boundary: AuthRequestBoundary;
  readonly csrf: BuiltinEnrollmentCsrf;
  readonly recovery: Pick<RecoveryRegistrationService, "begin" | "complete">;
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
      const read = path === "/recover" || path === "/recover/webauthn.js";
      const inspection = options.boundary.inspect(request, { stateChanging: !read });
      if (read) {
        if (request.method !== "GET") throw new RecoveryRegistrationError();
        if (path === "/recover/webauthn.js")
          return send(200, "text/javascript; charset=utf-8", BROWSER_SCRIPT);
        return send(
          200,
          "text/html; charset=utf-8",
          '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Recover your BoardAgent passkey</title><script src="/recover/webauthn.js" defer></script></head><body><main><h1>Recover your passkey</h1><p>Your administrator must verify your identity before giving you this one-time handoff. Check your organization and name before continuing.</p><form autocomplete="off"><input type="hidden" name="csrf_token" value="' +
            options.csrf.issue() +
            '"><label>One-time recovery handoff <input type="password" name="recovery_token" minlength="43" maxlength="43" required autocomplete="off" spellcheck="false" autocapitalize="none"></label><button type="button" data-inspect>Check recovery</button><p data-person></p><button type="button" data-create hidden>Create replacement passkey</button><p role="status" aria-live="polite"></p><pre data-handoff hidden></pre></form></main></body></html>'
        );
      }
      if (
        request.method !== "POST" ||
        !["/recover/passkey/begin", "/recover/passkey/complete"].includes(path ?? "")
      )
        throw new RecoveryRegistrationError();
      const attempt = await options.consumeAttempt(inspection.clientIpClass);
      if (!attempt.allowed)
        throw new WebAuthnCeremonyError(
          "rate_limited",
          "recovery entry rate limited",
          attempt.retryAfterSeconds
        );
      const form = await readBoundedForm(request, 32_768);
      const expected =
        path === "/recover/passkey/begin"
          ? ["csrf_token", "recovery_token"]
          : ["credential", "csrf_token", "recovery_token"];
      if (JSON.stringify([...form.keys()].sort()) !== JSON.stringify(expected))
        throw new RecoveryRegistrationError();
      options.csrf.verify(z.string().parse(form.get("csrf_token")));
      const recoveryToken = z.string().length(43).parse(form.get("recovery_token"));
      const result =
        path === "/recover/passkey/begin"
          ? await options.recovery.begin({ recoveryToken })
          : await options.recovery.complete({
              recoveryToken,
              response: RegistrationResponseSchema.parse(
                JSON.parse(z.string().max(24_576).parse(form.get("credential"))) as unknown
              ) as RegistrationResponseJSON
            });
      send(200, "application/json; charset=utf-8", JSON.stringify(result));
    };
    void handle().catch((error: unknown) => {
      const limited = error instanceof WebAuthnCeremonyError && error.code === "rate_limited";
      if (limited) response.setHeader("retry-after", String(error.retryAfterSeconds ?? 1));
      const expected =
        error instanceof RecoveryRegistrationError ||
        error instanceof WebAuthnCeremonyError ||
        error instanceof AuthPageSecurityError ||
        error instanceof BuiltinEnrollmentBrowserError ||
        error instanceof z.ZodError ||
        error instanceof SyntaxError;
      if (!expected)
        options.onError?.(error instanceof Error ? error : new Error("recovery handler failed"));
      send(
        limited ? 429 : expected ? 400 : 500,
        "application/json; charset=utf-8",
        JSON.stringify({ error: "recovery_unavailable" })
      );
    });
  };
}
