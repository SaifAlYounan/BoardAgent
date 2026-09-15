import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";

import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";

import {
  AuthPageSecurityError,
  AuthRequestBoundary,
  authPageSecurityHeaders,
  parseOidcCallbackRoute,
  type OAuthInteractionRouteKind,
  parseOAuthInteractionRoute,
  readOAuthCsrfSubmission,
  readOAuthPasskeyCompletion,
  readOAuthTotpCompletion,
  renderOAuthConsentInteractionPage,
  renderOAuthOidcCompletionPage,
  renderOAuthPasskeyInteractionPage,
  renderOAuthTotpInteractionPage,
  renderOidcPendingIdentityPage
} from "./auth-page.js";
import { BOARDAGENT_WEBAUTHN_BROWSER_SCRIPT } from "./auth-webauthn-browser.js";
import type {
  BoardAgentOAuthProvider,
  OidcInteractionBinding,
  OidcInteractionBindingStore
} from "./oauth-authorization-server.js";
import { OidcFederationError, type OidcFederationService } from "./oidc-federation.js";
import { TotpError, type TotpAuthenticator } from "./totp.js";
import { WebAuthnCeremonyError, type WebAuthnCeremony } from "./webauthn.js";

const InteractionUidSchema = z.string().regex(/^[A-Za-z0-9_-]{16,256}$/u);
const ScopeSchema = z.string().regex(/^[a-z][a-z0-9:_-]{0,127}$/u);
const InteractionDetailsSchema = z
  .object({
    uid: InteractionUidSchema,
    prompt: z.object({ name: z.enum(["login", "consent"]) }).passthrough(),
    params: z
      .object({
        client_id: z.string().min(1).max(2048),
        resource: z.string().url().max(2048),
        scope: z.string().min(1).max(4096)
      })
      .passthrough(),
    session: z.object({ accountId: UuidV7Schema }).passthrough().optional()
  })
  .passthrough();

type OAuthInteractionWebAuthn = Pick<
  WebAuthnCeremony,
  "beginAuthentication" | "completeAuthentication"
>;

export interface BoardAgentOAuthInteractionHandlerOptions {
  readonly organizationId: string;
  readonly boundary: AuthRequestBoundary;
  readonly provider: BoardAgentOAuthProvider;
  readonly bindingStore: OidcInteractionBindingStore;
  readonly webauthn: OAuthInteractionWebAuthn;
  readonly totp?: TotpAuthenticator;
  readonly oidc?: Pick<
    OidcFederationService,
    "providers" | "start" | "callback" | "consumeCompletion"
  >;
  readonly includeHsts: boolean;
  /**
   * Receives one `OAuthInteractionFailure` for every refused or failed interaction
   * request so the process can log the route and reason. A refused login is not a server
   * error, so this is a separate channel from `onError`. The browser still sees only the
   * generic error body; the failure carries no request content.
   */
  readonly onInteractionFailure?: (failure: OAuthInteractionFailure) => void;
}

/** A refused or failed OAuth interaction request: which route, why, and the status sent. */
export class OAuthInteractionFailure extends Error {
  public constructor(
    public readonly routeKind: OAuthInteractionRouteKind | "unknown",
    public readonly reasonCode: string,
    public readonly status: 400 | 429 | 500,
    cause: unknown
  ) {
    super(`OAuth interaction ${routeKind} failed: ${reasonCode}`, { cause });
    this.name = "OAuthInteractionFailure";
  }
}

function failureReason(error: unknown): string {
  if (error instanceof WebAuthnCeremonyError) return `webauthn_${error.code}`;
  if (error instanceof TotpError) return `totp_${error.code}`;
  if (error instanceof OidcFederationError) return `oidc_federation_${String(error.statusCode)}`;
  if (error instanceof AuthPageSecurityError) return error.reason;
  if (error instanceof z.ZodError) return "auth_submission_invalid";
  return "server_error";
}

function routeKindOf(request: IncomingMessage): OAuthInteractionRouteKind | "unknown" {
  try {
    return parseOAuthInteractionRoute(request.url ?? "").kind;
  } catch {
    return "unknown";
  }
}

function normalizedScopes(value: string): string[] {
  const scopes = value
    .split(" ")
    .filter(Boolean)
    .map((scope) => ScopeSchema.parse(scope));
  const normalized = [...new Set(scopes)].toSorted();
  if (normalized.length === 0 || normalized.length !== scopes.length) {
    throw new AuthPageSecurityError("scope_shape");
  }
  return normalized;
}

function verifyDetails(
  detailsValue: unknown,
  binding: OidcInteractionBinding
): z.infer<typeof InteractionDetailsSchema> {
  try {
    const details = InteractionDetailsSchema.parse(detailsValue);
    const scopes = normalizedScopes(details.params.scope);
    if (
      details.uid !== binding.interactionUid ||
      details.params.client_id !== binding.protocolClientId ||
      details.params.resource !== binding.resourceUri ||
      JSON.stringify(scopes) !== JSON.stringify(binding.scopes)
    ) {
      throw new AuthPageSecurityError("details_mismatch");
    }
    return details;
  } catch (error) {
    if (error instanceof AuthPageSecurityError) throw error;
    throw new AuthPageSecurityError("details_invalid");
  }
}

function verifyCsrf(
  store: OidcInteractionBindingStore,
  binding: OidcInteractionBinding,
  csrfToken: string
): void {
  try {
    store.verifyCsrf(binding, csrfToken);
  } catch {
    throw new AuthPageSecurityError("csrf_invalid");
  }
}

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
        status === 429 ? "rate_limited" : status === 500 ? "server_error" : "invalid_auth_request"
    })
  );
}

export function createBoardAgentOAuthInteractionHandler(
  options: BoardAgentOAuthInteractionHandlerOptions
): RequestListener {
  const organizationId = UuidV7Schema.parse(options.organizationId);

  const handle = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    if (request.url === "/auth/webauthn.js") {
      options.boundary.inspect(request, { stateChanging: false });
      if (request.method !== "GET") throw new AuthPageSecurityError("method_not_allowed");
      response.writeHead(200, responseHeaders(options.includeHsts, "javascript"));
      response.end(BOARDAGENT_WEBAUTHN_BROWSER_SCRIPT);
      return;
    }

    if ((request.url ?? "").startsWith("/auth/oidc/callback")) {
      if (options.oidc === undefined || request.method !== "GET") {
        throw new AuthPageSecurityError("oidc_unavailable");
      }
      const providerId = parseOidcCallbackRoute(request.url ?? "");
      const inspection = options.boundary.inspect(request, { stateChanging: false });
      let currentUrl: URL;
      try {
        currentUrl = new URL(request.url ?? "", inspection.canonicalOrigin);
      } catch {
        throw new AuthPageSecurityError("url_invalid");
      }
      const callback = await options.oidc.callback({
        providerId,
        currentUrl,
        cookieHeader: request.headers.cookie
      });
      if (callback.status === "pending_link") {
        response.writeHead(202, responseHeaders(options.includeHsts, "html"));
        response.end(renderOidcPendingIdentityPage());
        return;
      }
      if (callback.location === null || callback.setCookie === null) {
        throw new OidcFederationError("oidc_federation_store_failed", 500);
      }
      const completionRoute = parseOAuthInteractionRoute(callback.location);
      if (completionRoute.kind !== "oidc_complete") {
        throw new OidcFederationError("oidc_federation_store_failed", 500);
      }
      response.writeHead(303, {
        ...responseHeaders(options.includeHsts, "html"),
        location: callback.location,
        "set-cookie": callback.setCookie
      });
      response.end();
      return;
    }

    const route = parseOAuthInteractionRoute(request.url ?? "");
    const stateChanging =
      route.kind !== "page" &&
      route.kind !== "totp_page" &&
      !(route.kind === "oidc_complete" && request.method === "GET");
    const inspection = options.boundary.inspect(request, { stateChanging });
    if (
      (route.kind === "oidc_complete" && request.method !== "GET" && request.method !== "POST") ||
      (route.kind !== "oidc_complete" && !stateChanging && request.method !== "GET") ||
      (route.kind !== "oidc_complete" && stateChanging && request.method !== "POST")
    ) {
      throw new AuthPageSecurityError("method_not_allowed");
    }

    let binding: OidcInteractionBinding;
    try {
      binding = await options.bindingStore.load(request);
    } catch {
      throw new AuthPageSecurityError("binding_unavailable");
    }
    if (binding.interactionUid !== route.interactionUid)
      throw new AuthPageSecurityError("interaction_mismatch");

    let detailsValue: unknown;
    try {
      detailsValue = await options.provider.interactionDetails(request, response);
    } catch {
      throw new AuthPageSecurityError("details_unavailable");
    }
    const details = verifyDetails(detailsValue, binding);

    if (route.kind === "page") {
      const body =
        details.prompt.name === "login"
          ? renderOAuthPasskeyInteractionPage({
              ...binding,
              totpFallbackAvailable: options.totp !== undefined,
              ...(options.oidc === undefined ? {} : { oidcProviders: options.oidc.providers })
            })
          : renderOAuthConsentInteractionPage(binding);
      response.writeHead(200, responseHeaders(options.includeHsts, "html"));
      response.end(body);
      return;
    }

    if (route.kind === "totp_page") {
      if (details.prompt.name !== "login" || options.totp === undefined) {
        throw new AuthPageSecurityError("prompt_mismatch");
      }
      response.writeHead(200, responseHeaders(options.includeHsts, "html"));
      response.end(renderOAuthTotpInteractionPage(binding));
      return;
    }

    if (route.kind === "oidc_start") {
      if (details.prompt.name !== "login" || options.oidc === undefined) {
        throw new AuthPageSecurityError("prompt_mismatch");
      }
      const csrfToken = await readOAuthCsrfSubmission(request);
      verifyCsrf(options.bindingStore, binding, csrfToken);
      const started = await options.oidc.start({ providerId: route.providerId, binding });
      response.writeHead(303, {
        ...responseHeaders(options.includeHsts, "html"),
        location: started.location,
        "set-cookie": started.setCookie
      });
      response.end();
      return;
    }

    if (route.kind === "oidc_complete") {
      if (details.prompt.name !== "login" || options.oidc === undefined) {
        throw new AuthPageSecurityError("prompt_mismatch");
      }
      if (request.method === "GET") {
        response.writeHead(200, responseHeaders(options.includeHsts, "html"));
        response.end(renderOAuthOidcCompletionPage(binding));
        return;
      }
      const csrfToken = await readOAuthCsrfSubmission(request);
      verifyCsrf(options.bindingStore, binding, csrfToken);
      const authenticated = await options.oidc.consumeCompletion({
        interactionUid: binding.interactionUid,
        cookieHeader: request.headers.cookie
      });
      await options.provider.approveInteraction(request, response, {
        memberId: authenticated.memberId
      });
      return;
    }

    if (route.kind === "passkey_begin") {
      if (details.prompt.name !== "login") throw new AuthPageSecurityError("prompt_mismatch");
      const csrfToken = await readOAuthCsrfSubmission(request);
      verifyCsrf(options.bindingStore, binding, csrfToken);
      const publicKey = await options.webauthn.beginAuthentication({
        organizationId,
        memberId: null,
        sessionId: binding.sessionId,
        purpose: "authentication"
      });
      response.writeHead(200, responseHeaders(options.includeHsts, "json"));
      response.end(JSON.stringify(publicKey));
      return;
    }

    if (route.kind === "passkey_complete") {
      if (details.prompt.name !== "login") throw new AuthPageSecurityError("prompt_mismatch");
      const submission = await readOAuthPasskeyCompletion(request);
      verifyCsrf(options.bindingStore, binding, submission.csrfToken);
      const authenticated = await options.webauthn.completeAuthentication({
        organizationId,
        sessionId: binding.sessionId,
        purpose: "authentication",
        response: submission.credential
      });
      await options.provider.approveInteraction(request, response, {
        memberId: authenticated.memberId
      });
      return;
    }

    if (route.kind === "totp_complete") {
      if (details.prompt.name !== "login" || options.totp === undefined) {
        throw new AuthPageSecurityError("prompt_mismatch");
      }
      const submission = await readOAuthTotpCompletion(request);
      verifyCsrf(options.bindingStore, binding, submission.csrfToken);
      const authenticated = await options.totp.authenticate({
        organizationId,
        sessionId: binding.sessionId,
        clientId: binding.clientId,
        clientIpClass: inspection.clientIpClass,
        fallbackHandle: submission.fallbackHandle,
        code: submission.code
      });
      await options.provider.approveInteraction(request, response, {
        memberId: authenticated.memberId
      });
      return;
    }

    const csrfToken = await readOAuthCsrfSubmission(request);
    verifyCsrf(options.bindingStore, binding, csrfToken);
    if (route.kind === "cancel") {
      await options.provider.denyInteraction(request, response);
      return;
    }
    if (details.prompt.name !== "consent" || !details.session) {
      throw new AuthPageSecurityError("consent_prompt_mismatch");
    }
    await options.provider.approveInteraction(request, response, {
      memberId: details.session.accountId
    });
  };

  return (request, response) => {
    void handle(request, response).catch((error: unknown) => {
      const status: 400 | 429 | 500 =
        (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") ||
        (error instanceof TotpError && error.code === "rate_limited")
          ? 429
          : error instanceof AuthPageSecurityError ||
              error instanceof WebAuthnCeremonyError ||
              error instanceof TotpError ||
              (error instanceof OidcFederationError && error.statusCode === 400) ||
              error instanceof z.ZodError
            ? 400
            : 500;
      options.onInteractionFailure?.(
        new OAuthInteractionFailure(routeKindOf(request), failureReason(error), status, error)
      );
      if (
        (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") ||
        (error instanceof TotpError && error.code === "rate_limited")
      ) {
        sendError(response, 429, options.includeHsts, error.retryAfterSeconds ?? 1);
      } else if (
        error instanceof AuthPageSecurityError ||
        error instanceof WebAuthnCeremonyError ||
        error instanceof TotpError ||
        (error instanceof OidcFederationError && error.statusCode === 400) ||
        error instanceof z.ZodError
      ) {
        sendError(response, 400, options.includeHsts);
      } else if (error instanceof OidcFederationError && error.statusCode === 500) {
        sendError(response, 500, options.includeHsts);
      } else {
        sendError(response, 500, options.includeHsts);
      }
    });
  };
}
