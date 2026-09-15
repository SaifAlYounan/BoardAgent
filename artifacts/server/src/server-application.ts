import { withRuntimeDatabaseLease } from "@boardagent/db";
import { acquireRuntimeMaintenanceLease } from "./runtime-maintenance-lease.js";
import { RecoveryRegistrationService } from "./recovery-registration.js";
import { createRecoveryRegistrationHandler } from "./recovery-browser.js";
import { ActivationRestartService } from "./activation-restart.js";
import { createActivationRestartHandler } from "./activation-restart-browser.js";
import { createHmac, sign } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import type { RequestListener } from "node:http";

import { assertSecretDirectoryReady, type BoardAgentConfig } from "@boardagent/config";
import { safeHashEqual, sha256Hex } from "@boardagent/contracts";
import type { Pool } from "pg";

import { createTokenVerifier } from "./auth.js";
import { AuthRequestBoundary } from "./auth-page.js";
import {
  PgOAuthClientRegistrar,
  createOAuthClientRegistrationEndpoint
} from "./client-registration.js";
import { BuiltinEnrollmentCsrf, createBuiltinEnrollmentHandler } from "./enrollment-browser.js";
import { BuiltinEnrollmentService, PgBuiltinEnrollmentStore } from "./enrollment.js";
import { LocalExportArtifactStore } from "./export-artifact-store.js";
import {
  BOARDAGENT_OAUTH_SCOPES,
  createBoardAgentHttpRuntime,
  type BoardAgentReadiness
} from "./http-runtime.js";
import { loadBoardAgentKeyMaterial, type BoardAgentKeyMaterial } from "./key-material.js";
import { dataDecryptionKeyring } from "./retained-data-keys.js";
import { createBoardAgentMcpHandler } from "./mcp-surface.js";
import { createBoardAgentOAuthProvider } from "./oauth-authorization-server.js";
import {
  createPgOAuthPublicKeysEndpoint,
  createPgOAuthVerificationKeyResolver
} from "./oauth-public-keys.js";
import {
  createBoardAgentOAuthInteractionHandler,
  type OAuthInteractionFailure
} from "./oauth-interaction-handler.js";
import {
  OidcFederationService,
  PgOidcFederationStore,
  discoverUpstreamOidcProfile
} from "./oidc-federation.js";
import { BuiltinOnboardingCsrf, createBuiltinOnboardingHandler } from "./onboarding-browser.js";
import { BuiltinOnboardingService, PgOnboardingBrowserStore } from "./onboarding.js";
import { createPgOAuthTokenEndpoint } from "./pg-oauth-token-endpoint.js";
import { createPgOidcProviderPersistence } from "./pg-oidc-adapter.js";
import { PgRateLimiter } from "./pg-rate-limiter.js";
import { RequestWebAuthnAttemptLimiter } from "./request-webauthn-rate-limiter.js";
import { PgTokenContextStore } from "./pg-token-store.js";
import { PgWebAuthnStore } from "./pg-webauthn-store.js";
import { createProtectedMcpHandler } from "./protected-mcp.js";
import { PgPublicCertificateVerifier } from "./public-certificate-verifier.js";
import { loadBoardAgentRuntimeBinding, type BoardAgentRuntimeBinding } from "./runtime-binding.js";
import { PgSurfaceReadRepository } from "./surface-read.js";
import { PgBoardAgentSurfaceService } from "./surface-service.js";
import { PgTotpService } from "./totp.js";
import { WebAuthnCeremony } from "./webauthn.js";
import { Aes256GcmWebhookSecurity } from "./webhook-security.js";
import type { VoteCertificateSigningPort } from "./ports.js";

const RATE_POLICIES = {
  ip: { windowSeconds: 60, maxRequests: 30, blockSeconds: 60 },
  client: { windowSeconds: 60, maxRequests: 60, blockSeconds: 60 },
  member: { windowSeconds: 300, maxRequests: 20, blockSeconds: 300 },
  token: { windowSeconds: 300, maxRequests: 20, blockSeconds: 300 }
} as const;

const PUBLIC_CERTIFICATE_RATE_POLICY = {
  windowSeconds: 60,
  maxRequests: 20,
  blockSeconds: 300
} as const;

export interface BoardAgentServerApplication {
  readonly handler: RequestListener;
  readonly binding: BoardAgentRuntimeBinding;
  readonly close: () => Promise<void>;
}

export interface BoardAgentServerApplicationOptions {
  /** Test/local-owner seam. Production connects as boardagent_server directly. */
  readonly assumeRole?: "boardagent_server";
  readonly keys?: BoardAgentKeyMaterial;
  readonly onError?: (error: Error) => void;
  /** Refused or failed OAuth interaction steps (route and reason only, never content). */
  readonly onInteractionFailure?: (failure: OAuthInteractionFailure) => void;
}

function derive(root: Uint8Array, purpose: string): Buffer {
  return createHmac("sha256", root)
    .update("boardagent/runtime-subkey/v1\0", "utf8")
    .update(purpose, "utf8")
    .digest();
}

function transactionOptions(assumeRole: "boardagent_server" | undefined): {
  readonly assumeRole?: "boardagent_server";
} {
  return assumeRole === undefined ? {} : { assumeRole };
}

function certificateSigner(
  binding: BoardAgentRuntimeBinding,
  keys: BoardAgentKeyMaterial
): VoteCertificateSigningPort {
  return {
    async signVoteCertificate(input) {
      if (
        input.signingKeyId !== binding.keyIds.evidence_signing ||
        input.signingKeyLocator !== binding.keyLocators.evidence_signing ||
        !safeHashEqual(input.payloadSha256, sha256Hex(input.canonicalPayload))
      ) {
        throw new Error("vote certificate signing request does not match active evidence key");
      }
      return {
        signatureBase64Url: sign(
          null,
          Buffer.from(input.canonicalPayload, "utf8"),
          keys.evidencePrivateKey
        ).toString("base64url")
      };
    }
  };
}

async function secretTextFile(path: string): Promise<string> {
  assertSecretDirectoryReady(path);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  // Allow a 4096-byte value plus CRLF; the extra byte detects growth after stat.
  const maximumFileBytes = 4098;
  const bytes = Buffer.alloc(maximumFileBytes + 1);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || (stat.mode & 0o007) !== 0) {
      throw new Error("OIDC client secret must be a private regular file");
    }
    if (stat.size < 32 || stat.size > maximumFileBytes) {
      throw new Error("OIDC client secret file has invalid length");
    }
    let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await file.read(bytes, length, bytes.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > maximumFileBytes) {
      throw new Error("OIDC client secret file has invalid length");
    }
    const value = new TextDecoder("utf-8", { fatal: true })
      .decode(bytes.subarray(0, length))
      .trimEnd();
    if (Buffer.byteLength(value, "utf8") < 32 || Buffer.byteLength(value, "utf8") > 4096) {
      throw new Error("OIDC client secret file has invalid length");
    }
    return value;
  } finally {
    bytes.fill(0);
    await file.close();
  }
}

async function upstreamOidc(
  pool: Pool,
  config: BoardAgentConfig,
  keys: BoardAgentKeyMaterial,
  assumeRole: "boardagent_server" | undefined
): Promise<OidcFederationService | undefined> {
  if (!config.oidc) return undefined;
  const clientSecret = await secretTextFile(config.oidc.clientSecretFile);
  const profile = await discoverUpstreamOidcProfile({
    id: "primary",
    kind: "generic",
    label: "External identity",
    issuer: config.oidc.issuer,
    callbackUri: new URL("/auth/oidc/callback/primary", config.publicBaseUrl).href,
    clientId: config.oidc.clientId,
    clientSecret
  });
  return new OidcFederationService({
    profiles: [profile],
    store: new PgOidcFederationStore(pool, {
      organizationId: config.organizationId,
      ...transactionOptions(assumeRole)
    }),
    cookieEncryptionKey: derive(keys.browserSessionKey, "upstream-oidc-cookie")
  });
}

/** Compose the complete native HTTP/OAuth/MCP server against one verified instance. */
export async function createBoardAgentServerApplication(
  pool: Pool,
  config: BoardAgentConfig,
  options: BoardAgentServerApplicationOptions = {}
): Promise<BoardAgentServerApplication> {
  if (config.publicBaseUrl.protocol !== "https:") {
    throw new Error("the executable BoardAgent server requires its configured HTTPS edge origin");
  }
  const lease = await acquireRuntimeMaintenanceLease(pool, "server", options.assumeRole);
  try {
    const keys = options.keys ?? (await loadBoardAgentKeyMaterial(config));
    const scoped = transactionOptions(options.assumeRole);
    const binding = await loadBoardAgentRuntimeBinding(pool, config, keys, scoped);
    const origin = config.publicBaseUrl.origin;
    const boundary = new AuthRequestBoundary({
      origin,
      ...(config.trustedProxyHops === 0 ? {} : { trustedProxyHops: config.trustedProxyHops })
    });
    const rateLimiter = new PgRateLimiter(pool, {
      hmacKey: derive(keys.browserSessionKey, "rate-limit"),
      ...scoped
    });
    const browserAttempts = new RequestWebAuthnAttemptLimiter(pool, {
      boundary,
      limiter: rateLimiter,
      policies: RATE_POLICIES,
      ...scoped
    });
    const webauthn = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: config.publicBaseUrl.hostname,
      origin,
      store: new PgWebAuthnStore(pool, scoped),
      attemptLimiter: browserAttempts
    });
    const enrollment = new BuiltinEnrollmentService({
      organizationId: config.organizationId,
      store: new PgBuiltinEnrollmentStore(pool, scoped),
      webauthn
    });
    const onboarding = new BuiltinOnboardingService({
      organizationId: config.organizationId,
      store: new PgOnboardingBrowserStore(pool, scoped),
      webauthn
    });
    const enrollmentHandler = createBuiltinEnrollmentHandler({
      boundary,
      enrollment,
      csrf: new BuiltinEnrollmentCsrf({
        key: derive(keys.browserSessionKey, "enrollment-csrf")
      }),
      includeHsts: true
    });
    const onboardingHandler = createBuiltinOnboardingHandler({
      boundary,
      onboarding,
      csrf: new BuiltinOnboardingCsrf({
        key: derive(keys.browserSessionKey, "onboarding-csrf")
      }),
      includeHsts: true
    });
    const activationRestartHandler = createActivationRestartHandler({
      boundary,
      includeHsts: true,
      consumeAttempt: (trustedIpClass) =>
        rateLimiter.consumeIdentity(config.organizationId, [
          {
            bucketClass: "ip",
            trustedSubject: `activation-restart-entry:${trustedIpClass}`,
            ...RATE_POLICIES.ip
          }
        ]),
      ...(options.onError === undefined ? {} : { onError: options.onError }),
      csrf: new BuiltinEnrollmentCsrf({
        key: derive(keys.browserSessionKey, "activation-restart-csrf")
      }),
      restart: new ActivationRestartService(pool, {
        organizationId: config.organizationId,
        webauthn,
        ...scoped
      })
    });

    const persistence = createPgOidcProviderPersistence({
      pool,
      organizationId: config.organizationId,
      issuer: origin,
      resourceUri: config.canonicalResourceUri,
      stateEncryptionKey: derive(keys.browserSessionKey, "oauth-persistence"),
      ...scoped
    });
    const registration = createOAuthClientRegistrationEndpoint({
      registrar: new PgOAuthClientRegistrar(pool, {
        organizationId: config.organizationId,
        allowedScopes: BOARDAGENT_OAUTH_SCOPES,
        maxClients: 1_000,
        rateLimiter,
        rateLimit: { windowSeconds: 60, maxRequests: 10, blockSeconds: 300 },
        allowlist: config.clientAllowlist ? [...config.clientAllowlist] : null,
        ...scoped
      }),
      boundary
    });
    const oauth = createBoardAgentOAuthProvider({
      issuer: origin,
      resourceUri: config.canonicalResourceUri,
      scopes: BOARDAGENT_OAUTH_SCOPES,
      clients: [],
      privateJwk: keys.oauthPrivateJwk,
      publicKeysEndpoint: createPgOAuthPublicKeysEndpoint(pool, config.organizationId, scoped),
      cookieKeys: [
        derive(keys.browserSessionKey, "oauth-cookie-current").toString("base64url"),
        derive(keys.browserSessionKey, "oauth-cookie-previous").toString("base64url")
      ],
      adapter: persistence.adapter,
      interactionStateStore: persistence.interactionStateStore,
      tokenEndpoint: createPgOAuthTokenEndpoint({
        pool,
        organizationId: config.organizationId,
        resourceUri: config.canonicalResourceUri,
        signingKeyId: binding.keyIds.oauth_signing,
        privateJwk: keys.oauthPrivateJwk,
        ...scoped
      }),
      clientRegistration: registration
    });
    const dataKeys = dataDecryptionKeyring(
      binding.keyIds.data_kek,
      keys.dataEncryptionKey,
      keys.retainedDataKeys
    );
    const configuredOidc =
      config.authorizationMode === "oidc"
        ? await upstreamOidc(pool, config, keys, options.assumeRole)
        : undefined;
    if (config.authorizationMode === "oidc" && configuredOidc === undefined) {
      throw new Error("OIDC authorization mode did not produce an upstream provider");
    }
    const interaction = createBoardAgentOAuthInteractionHandler({
      organizationId: config.organizationId,
      boundary,
      provider: oauth,
      bindingStore: persistence.interactionBindingStore,
      webauthn,
      totp: new PgTotpService(pool, {
        issuer: "BoardAgent",
        activeKeyId: binding.keyIds.data_kek,
        keys: dataKeys,
        rateLimiter,
        rateLimits: RATE_POLICIES,
        maxFailedAttempts: 5,
        lockoutSeconds: 900,
        ...scoped
      }),
      ...(configuredOidc === undefined ? {} : { oidc: configuredOidc }),
      includeHsts: true,
      ...(options.onInteractionFailure === undefined
        ? {}
        : { onInteractionFailure: options.onInteractionFailure })
    });
    const webhookSecurity = config.webhooksEnabled
      ? new Aes256GcmWebhookSecurity({
          activeKeyId: binding.keyIds.data_kek,
          keys: dataKeys
        })
      : undefined;
    const exportArtifacts = new LocalExportArtifactStore(config.blobRoot, {
      maximumArtifactBytes: config.exportMaximumBytes,
      chunkBytes: config.exportChunkBytes
    });
    await exportArtifacts.initialize();
    const reads = new PgSurfaceReadRepository(pool, {
      cursorKey: derive(keys.browserSessionKey, "surface-cursor"),
      transaction: scoped,
      exportChunks: exportArtifacts
    });
    const service = new PgBoardAgentSurfaceService(pool, {
      reads,
      transaction: scoped,
      voteCertificateSigner: certificateSigner(binding, keys),
      ...(webhookSecurity === undefined ? {} : { webhookSecurity })
    });
    const protectedMcp = createProtectedMcpHandler({
      handler: createBoardAgentMcpHandler({
        service,
        requestStateKey: derive(keys.browserSessionKey, "mcp-request-state"),
        requestStateTtlSeconds: config.stageTtlSeconds
      }),
      resourceUri: config.canonicalResourceUri,
      verifier: {
        verifyAccessToken: createTokenVerifier({
          issuer: origin,
          audience: config.canonicalResourceUri,
          publicKey: createPgOAuthVerificationKeyResolver(pool, binding.organizationId, scoped),
          tokens: new PgTokenContextStore(pool, scoped),
          ...(options.onError === undefined ? {} : { onError: options.onError })
        })
      }
    });
    const readiness: BoardAgentReadiness = {
      async check() {
        try {
          await loadBoardAgentRuntimeBinding(pool, config, keys, scoped);
          return { ready: true } as const;
        } catch {
          return { ready: false, reason: "runtime_binding_unavailable" } as const;
        }
      }
    };
    const runtime = createBoardAgentHttpRuntime({
      canonicalOrigin: origin,
      resourceUri: config.canonicalResourceUri,
      boundary,
      mcp: protectedMcp,
      oauth,
      interaction,
      // Every `/enroll*` path reaches this listener; the one-use restart handoff pages
      // (`/enroll/restart*`) are served by their own handler beside ordinary enrollment.
      enrollment: (request, response) =>
        request.url?.startsWith("/enroll/restart")
          ? activationRestartHandler(request, response)
          : enrollmentHandler(request, response),
      recovery: createRecoveryRegistrationHandler({
        boundary,
        includeHsts: true,
        consumeAttempt: (trustedIpClass) =>
          rateLimiter.consumeIdentity(config.organizationId, [
            {
              bucketClass: "ip",
              trustedSubject: `recovery-entry:${trustedIpClass}`,
              ...RATE_POLICIES.ip
            }
          ]),
        ...(options.onError === undefined ? {} : { onError: options.onError }),
        csrf: new BuiltinEnrollmentCsrf({ key: derive(keys.browserSessionKey, "recovery-csrf") }),
        recovery: new RecoveryRegistrationService(pool, {
          organizationId: config.organizationId,
          webauthn,
          ...scoped
        })
      }),
      onboarding: onboardingHandler,
      readiness,
      publicCertificateVerifier: new PgPublicCertificateVerifier(pool, rateLimiter, {
        organizationId: config.organizationId,
        policy: PUBLIC_CERTIFICATE_RATE_POLICY,
        ...scoped
      }),
      includeHsts: true,
      ...(options.onError === undefined ? {} : { onError: options.onError })
    });
    return {
      handler: (request, response) => {
        if (!lease.available) {
          response.writeHead(503, {
            "content-type": "application/json",
            "cache-control": "no-store"
          });
          response.end(JSON.stringify({ status: "unavailable" }));
          return;
        }
        return withRuntimeDatabaseLease(lease, () =>
          browserAttempts.run(request, () => runtime.handler(request, response))
        );
      },
      binding,
      close: async () => {
        try {
          await runtime.close();
        } finally {
          await lease.close();
        }
      }
    };
  } catch (error) {
    await lease.close().catch(() => undefined);
    throw error;
  }
}
