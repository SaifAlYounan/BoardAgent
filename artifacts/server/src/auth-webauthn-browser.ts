export const BOARDAGENT_WEBAUTHN_BROWSER_SCRIPT = `(() => {
  "use strict";

  const form = document.querySelector("form[data-webauthn-login]");
  if (!(form instanceof HTMLFormElement)) return;
  const button = form.querySelector("[data-passkey-button]");
  const status = form.querySelector("[data-passkey-status]");
  const csrf = form.elements.namedItem("csrf_token");
  const credentialField = form.elements.namedItem("credential");
  const beginPath = form.dataset.beginPath;
  if (
    !(button instanceof HTMLButtonElement) ||
    !(status instanceof HTMLElement) ||
    !(csrf instanceof HTMLInputElement) ||
    !(credentialField instanceof HTMLInputElement) ||
    typeof beginPath !== "string"
  ) return;

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

  button.addEventListener("click", async () => {
    button.disabled = true;
    status.textContent = "Waiting for your passkey…";
    try {
      const beginResponse = await fetch(beginPath, {
        method: "POST",
        credentials: "same-origin",
        redirect: "error",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ csrf_token: csrf.value }).toString()
      });
      if (!beginResponse.ok) throw new Error("passkey begin failed");
      const options = await beginResponse.json();
      if (options === null || typeof options !== "object" || typeof options.challenge !== "string") {
        throw new Error("passkey options are invalid");
      }
      const publicKey = {
        ...options,
        challenge: decode(options.challenge),
        ...(Array.isArray(options.allowCredentials)
          ? {
              allowCredentials: options.allowCredentials.map((entry) => ({
                ...entry,
                id: decode(entry.id)
              }))
            }
          : {})
      };
      const credential = await navigator.credentials.get({ publicKey });
      if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAssertionResponse)
      ) {
        throw new Error("passkey response is invalid");
      }
      credentialField.value = JSON.stringify({
        id: credential.id,
        rawId: encode(credential.rawId),
        response: {
          clientDataJSON: encode(credential.response.clientDataJSON),
          authenticatorData: encode(credential.response.authenticatorData),
          signature: encode(credential.response.signature),
          userHandle:
            credential.response.userHandle === null
              ? null
              : encode(credential.response.userHandle)
        },
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
        ...(credential.authenticatorAttachment === null
          ? {}
          : { authenticatorAttachment: credential.authenticatorAttachment })
      });
      form.requestSubmit();
    } catch {
      status.textContent = "Passkey authentication failed. Try again or cancel.";
      button.disabled = false;
    }
  });
})();
`;
