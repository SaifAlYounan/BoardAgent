import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";

import Provider, { errors, type InteractionDetails } from "oidc-provider";
import { z } from "zod";

import { OAuthRedirectUriSchema, UuidV7Schema } from "@boardagent/contracts";

import { authPageSecurityHeaders, renderOAuthResumePage } from "./auth-page.js";

import type { OAuthClientRegistrationEndpoint } from "./client-registration.js";

const OIDC_SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60;

function remainingOidcSessionTtl(_context: unknown, session: { readonly iat?: unknown }): number {
  const issuedAt = session.iat;
  if (typeof issuedAt !== "number" || !Number.isSafeInteger(issuedAt) || issuedAt <= 0) {
    return OIDC_SESSION_ABSOLUTE_SECONDS;
  }
  // oidc-provider samples the clock again after this callback. Leave one second of
  // margin so crossing that boundary can preserve, but never extend, the absolute TTL.
  const remaining = issuedAt + OIDC_SESSION_ABSOLUTE_SECONDS - Math.floor(Date.now() / 1_000) - 1;
  return Math.max(1, Math.min(OIDC_SESSION_ABSOLUTE_SECONDS, remaining));
}

const ExactIssuerSchema = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.origin === value &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === ""
    );
  }, "OAuth issuer must be an exact HTTPS origin");

const ScopeSchema = z.string().regex(/^[a-z][a-z0-9:_-]{0,127}$/u);

const Es256PrivateJwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: z.string().min(1),
    y: z.string().min(1),
    d: z.string().min(1),
    kid: z.string().min(1).max(255),
    use: z.literal("sig"),
    alg: z.literal("ES256")
  })
  .passthrough();

export interface OidcProviderAdapter {
  upsert(id: string, payload: Readonly<Record<string, unknown>>, expiresIn: number): Promise<void>;
  find(id: string): Promise<Readonly<Record<string, unknown>> | undefined>;
  destroy(id: string): Promise<void>;
  consume(id: string): Promise<void>;
  findByUid(uid: string): Promise<Readonly<Record<string, unknown>> | undefined>;
  findByUserCode(userCode: string): Promise<Readonly<Record<string, unknown>> | undefined>;
  revokeByGrantId(grantId: string): Promise<void>;
}

export type OidcProviderAdapterConstructor = new (model: string) => OidcProviderAdapter;

export interface OidcInteractionStateStore {
  run<T>(request: IncomingMessage, operation: () => T): T;
  prepareInteraction(context: unknown, interaction: { readonly uid: string }): string;
}

export interface OidcInteractionBinding {
  readonly interactionUid: string;
  readonly authorizationRequestId: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly protocolClientId: string;
  readonly clientDisplayName: string;
  readonly resourceUri: string;
  readonly scopes: readonly string[];
  readonly csrfToken: string;
  readonly expiresAt: Date;
}

export interface OidcInteractionBindingStore {
  load(request: IncomingMessage): Promise<OidcInteractionBinding>;
  verifyCsrf(binding: OidcInteractionBinding, csrfToken: string): void;
}

export interface BoardAgentOAuthTokenEndpoint {
  handle(request: IncomingMessage, response: ServerResponse): Promise<void>;
}

export interface OAuthClientConfiguration {
  readonly clientId: string;
  readonly redirectUris: readonly string[];
}

export interface BoardAgentOAuthProviderOptions {
  readonly issuer: string;
  readonly resourceUri: string;
  readonly scopes: readonly string[];
  readonly clients: readonly OAuthClientConfiguration[];
  readonly privateJwk: Readonly<Record<string, unknown>>;
  readonly cookieKeys: readonly string[];
  readonly adapter: OidcProviderAdapterConstructor;
  readonly interactionStateStore?: OidcInteractionStateStore;
  readonly tokenEndpoint?: BoardAgentOAuthTokenEndpoint;
  readonly publicKeysEndpoint?: BoardAgentOAuthTokenEndpoint;
  readonly clientRegistration?: OAuthClientRegistrationEndpoint;
}

export interface BoardAgentOAuthProvider {
  readonly issuer: string;
  readonly resourceUri: string;
  callback(): RequestListener;
  interactionDetails(request: unknown, response: unknown): Promise<InteractionDetails>;
  approveInteraction(
    request: unknown,
    response: unknown,
    input: { readonly memberId: string }
  ): Promise<void>;
  denyInteraction(request: unknown, response: unknown): Promise<void>;
}

interface ProviderGrant {
  readonly accountId?: string;
  readonly clientId?: string;
  addOIDCScope(scope: string): void;
  addOIDCClaims(claims: readonly string[]): void;
  addResourceScope(resource: string, scope: string): void;
  save(): Promise<string>;
}

interface ProviderGrantConstructor {
  new (input: { readonly accountId: string; readonly clientId: string }): ProviderGrant;
  find(id: string): Promise<ProviderGrant | undefined>;
}

function uniqueSorted(values: readonly string[], label: string): string[] {
  const sorted = [...values].toSorted();
  if (new Set(sorted).size !== sorted.length) throw new Error(`${label} contains duplicates`);
  return sorted;
}

function validatedOptions(options: BoardAgentOAuthProviderOptions): {
  readonly issuer: string;
  readonly resourceUri: string;
  readonly scopes: readonly string[];
  readonly clients: readonly OAuthClientConfiguration[];
  readonly privateJwk: Readonly<Record<string, unknown>>;
  readonly cookieKeys: readonly string[];
} {
  const issuer = ExactIssuerSchema.parse(options.issuer);
  const expectedResource = `${issuer}/mcp`;
  if (options.resourceUri !== expectedResource) {
    throw new Error(
      `OAuth resource must be the issuer-bound canonical resource ${expectedResource}`
    );
  }
  const scopes = uniqueSorted(
    options.scopes.map((scope) => ScopeSchema.parse(scope)),
    "scope set"
  );
  if (scopes.length === 0) throw new Error("OAuth scope set cannot be empty");
  const clientIds = uniqueSorted(
    options.clients.map(({ clientId }) => z.string().min(1).max(2048).parse(clientId)),
    "OAuth client set"
  );
  const byId = new Map(options.clients.map((client) => [client.clientId, client]));
  const clients = clientIds.map((clientId) => {
    const client = byId.get(clientId);
    if (!client) throw new Error("validated OAuth client disappeared");
    const redirectUris = uniqueSorted(
      client.redirectUris.map((uri) => OAuthRedirectUriSchema.parse(uri)),
      `redirect URI set for ${clientId}`
    );
    if (redirectUris.length === 0) throw new Error(`OAuth client ${clientId} has no redirect URI`);
    return { clientId, redirectUris };
  });
  const privateJwk = Es256PrivateJwkSchema.parse(options.privateJwk);
  const cookieKeys = options.cookieKeys.map((key) => z.string().min(32).max(4096).parse(key));
  if (cookieKeys.length < 2 || new Set(cookieKeys).size !== cookieKeys.length) {
    throw new Error("OAuth browser sessions require at least two distinct cookie keys");
  }
  return { issuer, resourceUri: options.resourceUri, scopes, clients, privateJwk, cookieKeys };
}

export function createBoardAgentOAuthProvider(
  options: BoardAgentOAuthProviderOptions
): BoardAgentOAuthProvider {
  const validated = validatedOptions(options);
  const provider = new Provider(validated.issuer, {
    adapter: options.adapter,
    clients: validated.clients.map(({ clientId, redirectUris }) => ({
      client_id: clientId,
      redirect_uris: redirectUris,
      application_type: redirectUris.some((uri) => new URL(uri).protocol !== "https:")
        ? "native"
        : "web",
      response_types: ["code"],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      id_token_signed_response_alg: "ES256"
    })),
    jwks: { keys: [validated.privateJwk] },
    scopes: validated.scopes,
    responseTypes: ["code"],
    clientAuthMethods: ["none"],
    extraParams: {
      state: async (_context: unknown, value: unknown) => {
        if (
          typeof value !== "string" ||
          Buffer.byteLength(value, "utf8") < 16 ||
          Buffer.byteLength(value, "utf8") > 2048
        ) {
          throw new errors.InvalidRequest("state must contain 16 through 2048 UTF-8 bytes");
        }
      }
    },
    issueRefreshToken: async () => true,
    rotateRefreshToken: async () => true,
    pkce: { required: async () => true },
    ttl: {
      AccessToken: 900,
      AuthorizationCode: 60,
      Grant: 90 * 24 * 60 * 60,
      Interaction: 600,
      RefreshToken: 90 * 24 * 60 * 60,
      Session: remainingOidcSessionTtl
    },
    cookies: {
      keys: validated.cookieKeys,
      long: { httpOnly: true, sameSite: "lax", secure: true, signed: true },
      short: { httpOnly: true, sameSite: "lax", secure: true, signed: true }
    },
    features: {
      clientCredentials: { enabled: false },
      devInteractions: { enabled: false },
      deviceFlow: { enabled: false },
      registration: { enabled: options.clientRegistration !== undefined },
      resourceIndicators: {
        enabled: true,
        defaultResource: async () => {
          throw new errors.InvalidTarget("resource parameter is required");
        },
        getResourceServerInfo: async (_context: unknown, resource: string) => {
          if (resource !== validated.resourceUri) {
            throw new errors.InvalidTarget("resource is not served by BoardAgent");
          }
          return {
            audience: validated.resourceUri,
            scope: validated.scopes.join(" "),
            accessTokenTTL: 900,
            accessTokenFormat: "jwt",
            jwt: { sign: { alg: "ES256", kid: validated.privateJwk["kid"] } }
          };
        }
      }
    },
    routes: {
      authorization: "/authorize",
      registration: "/register",
      token: "/token"
    },
    interactions: {
      url: async (context: unknown, interaction: { readonly uid: string }) =>
        options.interactionStateStore?.prepareInteraction(context, interaction) ??
        `/auth/interactions/${encodeURIComponent(interaction.uid)}`
    },
    extraTokenClaims: async () => ({ resource: validated.resourceUri }),
    renderError: async (
      context: {
        status: number;
        type: string;
        body: unknown;
        set(name: string, value: string): void;
      },
      error: { readonly error: string; readonly error_description?: string }
    ) => {
      context.status = 400;
      context.type = "application/json; charset=utf-8";
      context.set("Cache-Control", "no-store");
      context.set("Pragma", "no-cache");
      context.body = {
        error: error.error,
        ...(error.error_description === undefined
          ? {}
          : { error_description: error.error_description })
      };
    },
    findAccount: async (_context: unknown, memberId: string) => ({
      accountId: memberId,
      claims: async () => ({ sub: memberId })
    })
  });
  // The HTTP runtime and interaction handler validate Host and the configured
  // TLS-offload proxy through AuthRequestBoundary before invoking this provider.
  // Koa must then honor that validated HTTPS scheme for endpoints and secure cookies.
  provider.proxy = true;
  const Grant = (provider as unknown as { readonly Grant: ProviderGrantConstructor }).Grant;
  const finishInteraction = async (
    request: unknown,
    response: unknown,
    result: Readonly<Record<string, unknown>>,
    finishOptions: { readonly mergeWithLastSubmission: boolean }
  ): Promise<void> => {
    const incoming = request as IncomingMessage;
    if (incoming.headers?.["sec-fetch-dest"] !== "document") {
      await provider.interactionFinished(request, response, result, finishOptions);
      return;
    }
    // A browser form redirect can carry form-action 'self' all the way to the
    // external OAuth callback. Complete the form on this origin, then navigate
    // by GET to the provider's exact internal resume URL with the same strict CSP.
    const returnTo = await provider.interactionResult(request, response, result, finishOptions);
    const body = renderOAuthResumePage(validated.issuer, returnTo);
    const outgoing = response as ServerResponse;
    outgoing.writeHead(200, authPageSecurityHeaders({ includeHsts: true }));
    outgoing.end(body);
  };
  const approveInteractionCore = async (
    request: unknown,
    response: unknown,
    input: { readonly memberId: string }
  ): Promise<void> => {
    const memberId = UuidV7Schema.parse(input.memberId);
    const details = await provider.interactionDetails(request, response);
    if (details.prompt.name === "login") {
      await finishInteraction(
        request,
        response,
        { login: { accountId: memberId } },
        { mergeWithLastSubmission: false }
      );
      return;
    }
    if (details.prompt.name !== "consent" || details.session?.accountId !== memberId) {
      throw new Error("OAuth interaction is not approvable");
    }
    const params = z
      .object({ client_id: z.string().min(1).max(2048) })
      .passthrough()
      .parse(details.params);
    const promptDetails = z
      .object({
        missingOIDCScope: z.array(ScopeSchema).optional(),
        missingOIDCClaims: z.array(z.string().min(1).max(256)).max(128).optional(),
        missingResourceScopes: z.record(z.string(), z.array(ScopeSchema)).optional()
      })
      .passthrough()
      .parse(details.prompt.details ?? {});
    let grant: ProviderGrant;
    if (details.grantId) {
      const existing = await Grant.find(details.grantId);
      if (!existing) throw new Error("OAuth consent grant is unavailable");
      grant = existing;
    } else {
      grant = new Grant({ accountId: memberId, clientId: params.client_id });
    }
    if (grant.accountId !== memberId || grant.clientId !== params.client_id) {
      throw new Error("OAuth consent grant binding failed");
    }
    if (promptDetails.missingOIDCScope?.length) {
      grant.addOIDCScope(promptDetails.missingOIDCScope.join(" "));
    }
    if (promptDetails.missingOIDCClaims?.length) {
      grant.addOIDCClaims(promptDetails.missingOIDCClaims);
    }
    for (const [resource, scopes] of Object.entries(promptDetails.missingResourceScopes ?? {})) {
      if (resource !== validated.resourceUri) {
        throw new Error("OAuth consent resource binding failed");
      }
      grant.addResourceScope(resource, scopes.join(" "));
    }
    const grantId = await grant.save();
    await finishInteraction(
      request,
      response,
      { consent: { grantId } },
      { mergeWithLastSubmission: true }
    );
  };
  const denyInteractionCore = async (request: unknown, response: unknown): Promise<void> => {
    await finishInteraction(
      request,
      response,
      { error: "access_denied", error_description: "End-User denied authorization" },
      { mergeWithLastSubmission: false }
    );
  };
  return {
    issuer: validated.issuer,
    resourceUri: validated.resourceUri,
    callback: () => {
      const callback = provider.callback();
      return (request, response) => {
        const invokeProvider = (): void => {
          if (options.interactionStateStore) {
            options.interactionStateStore.run(request, () => callback(request, response));
            return;
          }
          callback(request, response);
        };
        if (options.publicKeysEndpoint && /^\/jwks(?:[?]|$)/u.test(request.url ?? "")) {
          void options.publicKeysEndpoint.handle(request, response).catch(() => {
            if (response.headersSent) {
              response.destroy();
              return;
            }
            response.writeHead(500, {
              "cache-control": "no-store",
              "content-type": "application/json; charset=utf-8",
              pragma: "no-cache"
            });
            response.end(JSON.stringify({ error: "server_error" }));
          });
          return;
        }
        if (options.clientRegistration && /^\/register(?:[/?]|$)/u.test(request.url ?? "")) {
          void options.clientRegistration.handleRegistration(request, response).catch(() => {
            if (response.headersSent) {
              response.destroy();
              return;
            }
            response.writeHead(500, {
              "cache-control": "no-store",
              "content-type": "application/json; charset=utf-8",
              pragma: "no-cache"
            });
            response.end(JSON.stringify({ error: "server_error" }));
          });
          return;
        }
        if (options.tokenEndpoint && /^\/token(?:[/?]|$)/u.test(request.url ?? "")) {
          void options.tokenEndpoint.handle(request, response).catch(() => {
            if (response.headersSent) {
              response.destroy();
              return;
            }
            response.writeHead(500, {
              "cache-control": "no-store",
              "content-type": "application/json; charset=utf-8",
              pragma: "no-cache"
            });
            response.end(JSON.stringify({ error: "server_error" }));
          });
          return;
        }
        if (options.clientRegistration && /^\/authorize(?:[?]|$)/u.test(request.url ?? "")) {
          void options.clientRegistration
            .prepareAuthorization(request)
            .then(invokeProvider)
            .catch(() => {
              if (response.headersSent) {
                response.destroy();
                return;
              }
              response.writeHead(400, {
                "cache-control": "no-store",
                "content-type": "application/json; charset=utf-8",
                pragma: "no-cache"
              });
              response.end(JSON.stringify({ error: "invalid_client" }));
            });
          return;
        }
        invokeProvider();
      };
    },
    interactionDetails: (request, response) =>
      options.interactionStateStore
        ? options.interactionStateStore.run(request as IncomingMessage, () =>
            provider.interactionDetails(request, response)
          )
        : provider.interactionDetails(request, response),
    approveInteraction: (request, response, input) =>
      options.interactionStateStore
        ? options.interactionStateStore.run(request as IncomingMessage, () =>
            approveInteractionCore(request, response, input)
          )
        : approveInteractionCore(request, response, input),
    denyInteraction: (request, response) =>
      options.interactionStateStore
        ? options.interactionStateStore.run(request as IncomingMessage, () =>
            denyInteractionCore(request, response)
          )
        : denyInteractionCore(request, response)
  };
}
