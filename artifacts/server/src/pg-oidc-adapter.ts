import { AsyncLocalStorage } from "node:async_hooks";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual
} from "node:crypto";
import type { IncomingMessage } from "node:http";

import type { Pool, PoolClient } from "pg";
import { z } from "zod";

import { redirectUriMatches, UuidV7Schema } from "@boardagent/contracts";
import { withIdentityTransaction } from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

import { parseOAuthInteractionRoute } from "./auth-page.js";
import type {
  OidcInteractionBinding,
  OidcInteractionBindingStore,
  OidcInteractionStateStore,
  OidcProviderAdapter,
  OidcProviderAdapterConstructor
} from "./oauth-authorization-server.js";

const InteractionUidSchema = z.string().regex(/^[A-Za-z0-9_-]{16,256}$/u);
const ProtocolIdSchema = z.string().min(1).max(2048);
const OAuthStateSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine((value) => {
    const length = Buffer.byteLength(value, "utf8");
    return length >= 16 && length <= 2048;
  });
const ScopeSchema = z.string().regex(/^[a-z][a-z0-9:_-]{0,127}$/u);
const PkceChallengeSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const CsrfTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const EpochSchema = z.number().int().positive();

const InteractionParamsSchema = z
  .object({
    client_id: ProtocolIdSchema,
    code_challenge: PkceChallengeSchema,
    code_challenge_method: z.literal("S256"),
    redirect_uri: z.url(),
    response_type: z.literal("code"),
    scope: z.string().min(1).max(4096),
    state: OAuthStateSchema,
    resource: z.url()
  })
  .passthrough();

const InteractionPayloadSchema = z
  .object({
    iat: EpochSchema,
    exp: EpochSchema,
    kind: z.literal("Interaction"),
    jti: InteractionUidSchema,
    cid: z.string().min(16).max(256),
    params: InteractionParamsSchema,
    prompt: z.object({ name: z.enum(["login", "consent"]) }).passthrough(),
    session: z
      .object({
        accountId: UuidV7Schema,
        uid: z.string().min(16).max(256),
        cookie: z.string().min(16).max(256).optional()
      })
      .passthrough()
      .optional(),
    result: z
      .object({
        login: z.object({ accountId: UuidV7Schema }).passthrough().optional(),
        consent: z
          .object({ grantId: z.string().min(16).max(256) })
          .passthrough()
          .optional(),
        error: z.literal("access_denied").optional(),
        error_description: z.string().min(1).max(256).optional()
      })
      .passthrough()
      .optional()
  })
  .passthrough();

const SessionPayloadSchema = z
  .object({
    iat: EpochSchema,
    exp: EpochSchema,
    kind: z.literal("Session"),
    jti: z.string().min(16).max(256),
    uid: z.string().min(16).max(256),
    accountId: UuidV7Schema,
    loginTs: EpochSchema
  })
  .passthrough();

const GrantPayloadSchema = z
  .object({
    iat: EpochSchema,
    exp: EpochSchema,
    kind: z.literal("Grant"),
    jti: z.string().min(16).max(256),
    accountId: UuidV7Schema,
    clientId: ProtocolIdSchema,
    resources: z.record(z.string(), z.string().min(1).max(4096))
  })
  .passthrough();

const AuthorizationCodePayloadSchema = z
  .object({
    iat: EpochSchema,
    exp: EpochSchema,
    kind: z.literal("AuthorizationCode"),
    jti: z.string().min(16).max(256),
    accountId: UuidV7Schema,
    codeChallenge: PkceChallengeSchema,
    codeChallengeMethod: z.literal("S256"),
    redirectUri: z.url(),
    resource: z.url(),
    scope: z.string().min(1).max(4096),
    clientId: ProtocolIdSchema
  })
  .passthrough();

interface InteractionContinuation {
  requestId?: string;
  rawState?: string;
  codeChallenge?: string;
  interactionUid?: string;
  consentId?: string;
  /** `client_id` of a fresh `/authorize`, known before any request row exists. */
  protocolClientHint?: string;
}

interface SealedContinuation {
  readonly v: 1;
  readonly uid: string;
  readonly requestId: string;
  readonly state: string;
  readonly codeChallenge: string;
}

const SealedContinuationSchema = z
  .object({
    v: z.literal(1),
    uid: InteractionUidSchema,
    requestId: UuidV7Schema,
    state: OAuthStateSchema,
    codeChallenge: PkceChallengeSchema
  })
  .strict();

interface CookieContext {
  readonly cookies: {
    set(
      name: string,
      value: string,
      options: {
        readonly httpOnly: boolean;
        readonly maxAge: number;
        readonly overwrite: boolean;
        readonly path: string;
        readonly sameSite: "lax";
        readonly secure: boolean;
        readonly signed: false;
      }
    ): void;
  };
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function exactOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.origin !== value) {
    throw new Error("OIDC persistence issuer must be an exact HTTPS origin");
  }
  return url.origin;
}

function normalizeScopes(value: string): string[] {
  const scopes = value
    .split(" ")
    .filter(Boolean)
    .map((scope) => ScopeSchema.parse(scope));
  const normalized = [...new Set(scopes)].toSorted();
  if (normalized.length === 0 || normalized.length !== scopes.length || normalized.length > 128) {
    throw new Error("OAuth scope set is invalid");
  }
  return normalized;
}

function epoch(date: Date): number {
  const value = Math.floor(date.getTime() / 1000);
  return EpochSchema.parse(value);
}

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

function uuidBytes(value: string): Buffer {
  const uuid = UuidV7Schema.parse(value);
  return Buffer.from(uuid.replaceAll("-", ""), "hex");
}

function bytesUuid(value: Buffer): string {
  if (value.length !== 16) throw new Error("reference UUID byte length is invalid");
  const hex = value.toString("hex");
  return UuidV7Schema.parse(
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}

class PgOidcInteractionStateStore implements OidcInteractionStateStore {
  private readonly storage = new AsyncLocalStorage<InteractionContinuation>();

  public constructor(
    private readonly issuer: string,
    private readonly key: Buffer
  ) {}

  private cookieName(uid: string): string {
    return `__Secure-boardagent_oidc_${sha256(uid).subarray(0, 12).toString("base64url")}`;
  }

  private requestUid(request: IncomingMessage): string | undefined {
    const rawUrl = request.url ?? "";
    const resume = /^\/authorize\/([A-Za-z0-9_-]{16,256})$/u.exec(rawUrl);
    if (resume) return InteractionUidSchema.parse(resume[1]);
    try {
      return parseOAuthInteractionRoute(rawUrl).interactionUid;
    } catch {
      return undefined;
    }
  }

  private cookie(request: IncomingMessage, uid: string): string | undefined {
    const expected = this.cookieName(uid);
    const values = (request.headers.cookie ?? "")
      .split(";")
      .map((part) => part.trim())
      .filter((part) => part.startsWith(`${expected}=`))
      .map((part) => part.slice(expected.length + 1));
    if (values.length > 1) throw new Error("duplicate OIDC continuation cookie");
    return values[0];
  }

  private seal(value: SealedContinuation): string {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(Buffer.from(`${this.issuer}\0${value.uid}`, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(SealedContinuationSchema.parse(value)), "utf8"),
      cipher.final()
    ]);
    return [
      "v1",
      nonce.toString("base64url"),
      ciphertext.toString("base64url"),
      cipher.getAuthTag().toString("base64url")
    ].join(".");
  }

  private open(uid: string, value: string): SealedContinuation {
    const parts = value.split(".");
    if (parts.length !== 4 || parts[0] !== "v1") throw new Error("OIDC continuation is invalid");
    try {
      const nonce = Buffer.from(parts[1]!, "base64url");
      const ciphertext = Buffer.from(parts[2]!, "base64url");
      const tag = Buffer.from(parts[3]!, "base64url");
      if (
        nonce.length !== 12 ||
        tag.length !== 16 ||
        ciphertext.length > 4096 ||
        nonce.toString("base64url") !== parts[1] ||
        ciphertext.toString("base64url") !== parts[2] ||
        tag.toString("base64url") !== parts[3]
      ) {
        throw new Error("OIDC continuation bounds are invalid");
      }
      const decipher = createDecipheriv("aes-256-gcm", this.key, nonce);
      decipher.setAAD(Buffer.from(`${this.issuer}\0${uid}`, "utf8"));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const parsed = SealedContinuationSchema.parse(JSON.parse(plaintext.toString("utf8")));
      if (parsed.uid !== uid) throw new Error("OIDC continuation UID mismatch");
      return parsed;
    } catch {
      throw new Error("OIDC continuation is invalid");
    }
  }

  public run<T>(request: IncomingMessage, operation: () => T): T {
    const uid = this.requestUid(request);
    const sealed = uid ? this.cookie(request, uid) : undefined;
    const continuation = sealed && uid ? this.open(uid, sealed) : undefined;
    return this.storage.run(
      continuation
        ? {
            requestId: continuation.requestId,
            rawState: continuation.state,
            codeChallenge: continuation.codeChallenge,
            interactionUid: continuation.uid
          }
        : uid
          ? { interactionUid: uid }
          : this.freshAuthorizationHint(request),
      operation
    );
  }

  /**
   * A fresh `/authorize` names its client in the query before any authorization request
   * row exists; the session lookup needs it to refuse another client's browser session.
   */
  private freshAuthorizationHint(request: IncomingMessage): InteractionContinuation {
    let url: URL;
    try {
      url = new URL(request.url ?? "", "http://localhost");
    } catch {
      return {};
    }
    if (url.pathname !== "/authorize") return {};
    const clientId = url.searchParams.get("client_id");
    return clientId === null || clientId === "" ? {} : { protocolClientHint: clientId };
  }

  public current(): InteractionContinuation {
    const current = this.storage.getStore();
    if (!current) throw new Error("OIDC persistence requires a managed request context");
    return current;
  }

  public prepareInteraction(contextValue: unknown, interaction: { readonly uid: string }): string {
    const uid = InteractionUidSchema.parse(interaction.uid);
    const current = this.current();
    if (!current.requestId || !current.rawState || !current.codeChallenge) {
      throw new Error("OIDC interaction has no normalized PostgreSQL binding");
    }
    current.interactionUid = uid;
    const sealed = this.seal({
      v: 1,
      uid,
      requestId: current.requestId,
      state: current.rawState,
      codeChallenge: current.codeChallenge
    });
    const context = contextValue as CookieContext;
    const common = {
      httpOnly: true,
      maxAge: 600_000,
      overwrite: false,
      sameSite: "lax" as const,
      secure: true,
      signed: false as const
    };
    const name = this.cookieName(uid);
    context.cookies.set(name, sealed, { ...common, path: `/auth/interactions/${uid}` });
    context.cookies.set(name, sealed, { ...common, path: `/authorize/${uid}` });
    return `/auth/interactions/${encodeURIComponent(uid)}`;
  }
}

interface ClientRow {
  readonly id: string;
  readonly protocol_id_value: string;
}

interface RequestRow {
  readonly id: string;
  readonly client_id: string;
  readonly resource_uri: string;
  readonly redirect_uri: string;
  readonly scope_set: string[];
  readonly member_id: string | null;
  readonly session_id: string;
  readonly state_hash: Buffer;
  readonly request_state: "pending" | "approved" | "denied" | "consumed" | "expired";
  readonly created_at: Date;
  readonly expires_at: Date;
  readonly session_state: "anonymous" | "authenticated" | "revoked" | "expired";
  readonly session_created_at: Date;
  readonly session_expires_at: Date;
  readonly last_authenticated_at: Date | null;
  readonly protocol_client_id: string;
  readonly client_display_name: string;
  readonly client_state: "active" | "suspended" | "revoked";
  readonly session_member_id: string | null;
  readonly session_client_id: string | null;
  readonly session_exact_origin: string;
  readonly member_is_active: boolean;
  readonly request_is_live: boolean;
  readonly session_is_live: boolean;
}

interface ConsentRow {
  readonly id: string;
  readonly member_id: string;
  readonly client_id: string;
  readonly protocol_client_id: string;
  readonly resource_uri: string;
  readonly scope_set: string[];
  readonly granted_at: Date;
}

interface SessionRow {
  readonly id: string;
  readonly member_id: string;
  readonly client_id: string | null;
  readonly state: "anonymous" | "authenticated" | "revoked" | "expired";
  readonly created_at: Date;
  readonly expires_at: Date;
  readonly last_authenticated_at: Date | null;
  readonly protocol_client_id: string | null;
  readonly consent_id: string | null;
  readonly resource_uri: string | null;
  readonly scope_set: string[] | null;
}

interface CodeRow {
  readonly id: string;
  readonly member_id: string;
  readonly redirect_uri: string;
  readonly resource_uri: string;
  readonly scope_set: string[];
  readonly pkce_s256_challenge: string;
  readonly issued_at: Date;
  readonly expires_at: Date;
  readonly consumed_at: Date | null;
  readonly revoked_at: Date | null;
  readonly session_id: string;
  readonly last_authenticated_at: Date | null;
  readonly protocol_client_id: string;
  readonly consent_id: string;
}

export interface PgOidcProviderPersistenceOptions {
  readonly pool: Pool;
  readonly organizationId: string;
  readonly issuer: string;
  readonly resourceUri: string;
  readonly stateEncryptionKey: Uint8Array;
  /** Test/bootstrap seam only. Production uses an already-scoped server pool. */
  readonly assumeRole?: "boardagent_server";
}

export interface PgOidcProviderPersistence {
  readonly adapter: OidcProviderAdapterConstructor;
  readonly interactionStateStore: OidcInteractionStateStore;
  readonly interactionBindingStore: OidcInteractionBindingStore;
}

export function createPgOidcProviderPersistence(
  options: PgOidcProviderPersistenceOptions
): PgOidcProviderPersistence {
  const organizationId = UuidV7Schema.parse(options.organizationId);
  const issuer = exactOrigin(options.issuer);
  const resourceUri = new URL(options.resourceUri).toString();
  if (resourceUri !== options.resourceUri || resourceUri !== `${issuer}/mcp`)
    throw new Error("OIDC persistence resource is not canonical");
  const stateKey = Buffer.from(options.stateEncryptionKey);
  if (stateKey.length !== 32) throw new Error("OIDC continuation encryption requires 32 bytes");
  const continuationKey = createHmac("sha256", stateKey)
    .update("boardagent/oidc/continuation/aes-256-gcm/v1", "utf8")
    .digest();
  const referenceKey = createHmac("sha256", stateKey)
    .update("boardagent/oidc/internal-reference/hmac-sha256/v1", "utf8")
    .digest();
  const csrfKey = createHmac("sha256", stateKey)
    .update("boardagent/oidc/interaction-csrf/hmac-sha256/v1", "utf8")
    .digest();
  const stateStore = new PgOidcInteractionStateStore(issuer, continuationKey);

  const reference = (kind: string, id: string): string => {
    const identifier = uuidBytes(id);
    const tag = createHmac("sha256", referenceKey)
      .update(kind, "utf8")
      .update(Buffer.from([0]))
      .update(identifier)
      .digest()
      .subarray(0, 16);
    return Buffer.concat([identifier, tag]).toString("base64url");
  };

  const dereference = (kind: string, value: string): string | undefined => {
    let decoded: Buffer;
    try {
      decoded = Buffer.from(value, "base64url");
    } catch {
      return undefined;
    }
    if (decoded.length !== 32) return undefined;
    const identifier = decoded.subarray(0, 16);
    const expected = createHmac("sha256", referenceKey)
      .update(kind, "utf8")
      .update(Buffer.from([0]))
      .update(identifier)
      .digest()
      .subarray(0, 16);
    if (!timingSafeEqual(expected, decoded.subarray(16))) return undefined;
    try {
      return bytesUuid(identifier);
    } catch {
      return undefined;
    }
  };

  const transactionOptions = options.assumeRole ? { assumeRole: options.assumeRole } : {};
  const transaction = <T>(run: (client: PoolClient) => Promise<T>): Promise<T> =>
    withIdentityTransaction(options.pool, { organizationId }, run, transactionOptions);

  const clientFor = async (
    client: PoolClient,
    protocolId: string,
    redirectUri?: string,
    scopes?: readonly string[]
  ): Promise<ClientRow> => {
    const result = await client.query<ClientRow & { readonly redirect_uris: string[] }>(
      `select oauth_client.id,oauth_client.protocol_id_value,
              coalesce((select array_agg(redirect.redirect_uri order by redirect.redirect_uri)
                          from oauth_client_redirect_uris as redirect
                         where redirect.client_id=oauth_client.id),'{}'::text[]) as redirect_uris
         from oauth_clients as oauth_client
        where oauth_client.organization_id=$1
          and oauth_client.protocol_id_value=$2
          and oauth_client.state='active'
          and not exists (
            select 1
              from unnest(coalesce($3::text[],'{}'::text[])) as requested(scope)
              cross join (values ('authorization_code'),('refresh_token')) as required(grant_type)
             where not exists (
               select 1 from oauth_client_grants as grant_row
                where grant_row.client_id=oauth_client.id
                  and grant_row.grant_type=required.grant_type
                  and grant_row.scope=requested.scope
             )
          )`,
      [organizationId, ProtocolIdSchema.parse(protocolId), scopes ?? []]
    );
    const row = result.rows[0];
    if (!row || result.rows.length !== 1) throw new Error("OAuth client binding failed");
    // The registered redirect must match exactly, except that a loopback callback may use
    // any port (RFC 8252 §7.3): native clients such as Claude Code bind an ephemeral port
    // at every login. Host, scheme, path and query stay exact; see redirectUriMatches.
    if (
      redirectUri !== undefined &&
      !row.redirect_uris.some((registered) => redirectUriMatches(registered, redirectUri))
    ) {
      throw new Error("OAuth client binding failed");
    }
    return { id: row.id, protocol_id_value: row.protocol_id_value };
  };

  const requestById = async (
    client: PoolClient,
    requestId: string,
    lock = false
  ): Promise<RequestRow | undefined> => {
    const result = await client.query<RequestRow>(
      `select request.id,request.client_id,request.resource_uri,request.redirect_uri,
              request.scope_set,request.member_id,request.session_id,request.state_hash,
              request.request_state,request.created_at,request.expires_at,
              session.state as session_state,session.created_at as session_created_at,
              session.expires_at as session_expires_at,session.last_authenticated_at,
              oauth_client.protocol_id_value as protocol_client_id,
              case
                when jsonb_typeof(oauth_client.safe_metadata->'name')='string'
                  and length(oauth_client.safe_metadata->>'name') between 1 and 256
                  then oauth_client.safe_metadata->>'name'
                else left(oauth_client.protocol_id_value,256)
              end as client_display_name,
              oauth_client.state as client_state,
              session.member_id as session_member_id,
              session.client_id as session_client_id,
              session.exact_origin as session_exact_origin,
              (request.member_id is null or exists (
                select 1 from members as current_member
                 where current_member.id=request.member_id
                   and current_member.organization_id=request.organization_id
                   and current_member.state='active'
              )) as member_is_active,
              request.expires_at>transaction_timestamp() as request_is_live,
              session.expires_at>transaction_timestamp() as session_is_live
         from oauth_authorization_requests as request
         join auth_sessions as session on session.id=request.session_id
         join oauth_clients as oauth_client on oauth_client.id=request.client_id
        where request.id=$1 and request.organization_id=$2
        ${lock ? "for update of request,session" : ""}`,
      [UuidV7Schema.parse(requestId), organizationId]
    );
    if (result.rows.length > 1) throw new Error("OAuth authorization request is not unique");
    return result.rows[0];
  };

  const requestContextIsBound = (request: RequestRow): boolean =>
    request.client_state === "active" &&
    request.member_is_active &&
    request.session_client_id === request.client_id &&
    request.session_exact_origin === issuer &&
    (request.session_state === "anonymous"
      ? request.session_member_id === null
      : request.session_state === "authenticated" &&
        request.member_id !== null &&
        request.session_member_id === request.member_id);

  const consentForRequest = async (
    client: PoolClient,
    request: RequestRow
  ): Promise<ConsentRow | undefined> => {
    if (!request.member_id) return undefined;
    const result = await client.query<ConsentRow>(
      `select consent.id,consent.member_id,consent.client_id,
              oauth_client.protocol_id_value as protocol_client_id,
              consent.resource_uri,consent.scope_set,consent.granted_at
         from oauth_consents as consent
         join oauth_clients as oauth_client on oauth_client.id=consent.client_id
        where consent.organization_id=$1 and consent.member_id=$2 and consent.client_id=$3
          and consent.resource_uri=$4 and consent.scope_set=$5 and consent.revoked_at is null
        order by consent.granted_at desc,consent.id desc limit 1`,
      [
        organizationId,
        request.member_id,
        request.client_id,
        request.resource_uri,
        request.scope_set
      ]
    );
    return result.rows[0];
  };

  class PgOidcAdapter implements OidcProviderAdapter {
    public constructor(private readonly model: string) {}

    private async upsertInteraction(
      id: string,
      payloadValue: Readonly<Record<string, unknown>>
    ): Promise<void> {
      const payload = InteractionPayloadSchema.parse(payloadValue);
      if (payload.jti !== id || payload.exp <= payload.iat) {
        throw new Error("OIDC interaction lifetime or identifier is invalid");
      }
      const params = payload.params;
      if (params.resource !== resourceUri) {
        throw new Error("OIDC interaction resource is invalid");
      }
      const scopes = normalizeScopes(params.scope);
      const current = stateStore.current();
      await transaction(async (client) => {
        const oauthClient = await clientFor(client, params.client_id, params.redirect_uri, scopes);
        let request = current.requestId
          ? await requestById(client, current.requestId, true)
          : undefined;
        if (!request) {
          if (payload.exp - payload.iat > 600) {
            throw new Error("OIDC interaction lifetime or identifier is invalid");
          }
          const sessionId = newId();
          const requestId = newId();
          await client.query(
            `insert into auth_sessions(
               id,organization_id,opaque_session_sha256,member_id,client_id,state,
               exact_origin,expires_at
             ) values ($1,$2,$3,null,$4,'anonymous',$5,to_timestamp($6))`,
            [sessionId, organizationId, sha256(payload.cid), oauthClient.id, issuer, payload.exp]
          );
          await client.query(
            `insert into oauth_authorization_requests(
               id,organization_id,client_id,resource_uri,redirect_uri,scope_set,member_id,
               session_id,state_hash,request_state,expires_at
             ) values ($1,$2,$3,$4,$5,$6,null,$7,$8,'pending',to_timestamp($9))`,
            [
              requestId,
              organizationId,
              oauthClient.id,
              resourceUri,
              params.redirect_uri,
              scopes,
              sessionId,
              sha256(params.state),
              payload.exp
            ]
          );
          current.requestId = requestId;
          current.rawState = params.state;
          current.codeChallenge = params.code_challenge;
          request = await requestById(client, requestId, true);
        }
        // oidc-provider recalculates exp from a relative TTL on continuation; a
        // scheduling gap can inflate that value. Existing requests retain their
        // original database expiry, which must still be live below. Never renew it
        // from the provider payload. New requests keep the strict issuance cap.
        if (
          !request ||
          !requestContextIsBound(request) ||
          request.request_state !== "pending" ||
          request.client_id !== oauthClient.id ||
          request.resource_uri !== resourceUri ||
          request.redirect_uri !== params.redirect_uri ||
          JSON.stringify(request.scope_set) !== JSON.stringify(scopes) ||
          !timingSafeEqual(request.state_hash, sha256(params.state)) ||
          !request.request_is_live ||
          !request.session_is_live
        ) {
          throw new Error("OIDC interaction changed its normalized authorization request");
        }
        current.rawState = params.state;
        current.codeChallenge = params.code_challenge;

        const authenticatedMember = payload.session?.accountId ?? payload.result?.login?.accountId;
        if (authenticatedMember) {
          const member = await client.query<{ id: string }>(
            "select id from members where id=$1 and organization_id=$2 and state='active'",
            [authenticatedMember, organizationId]
          );
          if (member.rows.length !== 1) throw new Error("OIDC interaction member is unavailable");
        }
        if (payload.session) {
          let sessionId = request.session_id;
          if (request.session_state === "anonymous") {
            const sessionHash = sha256(payload.session.cookie ?? payload.session.uid);
            const existing = await client.query<{ id: string }>(
              `select id from auth_sessions
                where organization_id=$1 and opaque_session_sha256=$2`,
              [organizationId, sessionHash]
            );
            sessionId = existing.rows[0]?.id ?? newId();
            if (existing.rows.length === 0) {
              await client.query(
                `insert into auth_sessions(
                   id,organization_id,opaque_session_sha256,member_id,client_id,state,
                   exact_origin,expires_at,last_authenticated_at
                 ) values ($1,$2,$3,$4,$5,'authenticated',$6,
                           transaction_timestamp()+interval '8 hours',transaction_timestamp())`,
                [
                  sessionId,
                  organizationId,
                  sessionHash,
                  payload.session.accountId,
                  oauthClient.id,
                  issuer
                ]
              );
            }
          }
          await client.query(
            `update oauth_authorization_requests
                set member_id=$2,session_id=$3
              where id=$1 and request_state='pending'`,
            [request.id, payload.session.accountId, sessionId]
          );
        } else if (payload.result?.login) {
          await client.query(
            `update oauth_authorization_requests set member_id=$2
              where id=$1 and request_state='pending'`,
            [request.id, payload.result.login.accountId]
          );
        }
        if (payload.result?.consent) {
          await client.query(
            `update oauth_authorization_requests set request_state='approved'
              where id=$1 and request_state='pending'`,
            [request.id]
          );
        } else if (payload.result?.error === "access_denied") {
          await client.query(
            `update oauth_authorization_requests set request_state='denied'
              where id=$1 and request_state='pending'`,
            [request.id]
          );
        }
      });
    }

    private async upsertSession(
      id: string,
      payloadValue: Readonly<Record<string, unknown>>
    ): Promise<void> {
      // An anonymous provider session (no authenticated account) carries no authority
      // and is never persisted: the browser cookie then references nothing, exactly as
      // if it had never been set. This is the state after another client's session was
      // refused for a fresh authorization and before the passkey login completes.
      if (payloadValue["accountId"] === undefined) return;
      const payload = SessionPayloadSchema.parse(payloadValue);
      if (payload.jti !== id || payload.exp <= payload.iat || payload.exp - payload.iat > 28_800) {
        throw new Error("OIDC session lifetime or identifier is invalid");
      }
      const current = stateStore.current();
      if (!current.requestId) throw new Error("OIDC session has no authorization request");
      await transaction(async (client) => {
        const request = await requestById(client, current.requestId!, true);
        if (!request || request.member_id !== payload.accountId) {
          throw new Error("OIDC session principal binding failed");
        }
        // Authentication and its clock belong to the database-backed ceremony.
        // Provider session persistence rotates a cookie; it cannot extend that
        // authority or replace the verified authentication time with its own clock.
        const updated = await client.query<{ id: string }>(
          `update auth_sessions
              set opaque_session_sha256=$2,
                  expires_at=least(expires_at,to_timestamp($5),created_at+interval '8 hours')
            where id=$1 and member_id=$3 and client_id=$4 and state='authenticated'
              and expires_at>transaction_timestamp() and last_authenticated_at is not null
            returning id`,
          [request.session_id, sha256(id), payload.accountId, request.client_id, payload.exp]
        );
        if (updated.rows.length !== 1) throw new Error("OAuth session rotation is unavailable");
      });
    }

    private async upsertGrant(
      id: string,
      payloadValue: Readonly<Record<string, unknown>>
    ): Promise<void> {
      const payload = GrantPayloadSchema.parse(payloadValue);
      if (payload.jti !== id || payload.exp <= payload.iat)
        throw new Error("OIDC grant is invalid");
      const grantedScope = payload.resources[resourceUri];
      if (!grantedScope) throw new Error("OIDC grant has no BoardAgent resource");
      const scopes = normalizeScopes(grantedScope);
      const current = stateStore.current();
      if (!current.requestId) throw new Error("OIDC grant has no authorization request");
      current.consentId = await transaction(async (client) => {
        const request = await requestById(client, current.requestId!, true);
        if (
          !request ||
          request.member_id !== payload.accountId ||
          request.protocol_client_id !== payload.clientId ||
          JSON.stringify(request.scope_set) !== JSON.stringify(scopes) ||
          request.resource_uri !== resourceUri
        ) {
          throw new Error("OIDC grant binding failed");
        }
        const existing = await consentForRequest(client, request);
        if (existing) return existing.id;
        const consentId = newId();
        await client.query(
          `insert into oauth_consents(
             id,organization_id,member_id,client_id,resource_uri,scope_set
           ) values ($1,$2,$3,$4,$5,$6)`,
          [consentId, organizationId, payload.accountId, request.client_id, resourceUri, scopes]
        );
        return consentId;
      });
    }

    private async upsertAuthorizationCode(
      id: string,
      payloadValue: Readonly<Record<string, unknown>>
    ): Promise<void> {
      const payload = AuthorizationCodePayloadSchema.parse(payloadValue);
      if (
        payload.jti !== id ||
        payload.exp <= payload.iat ||
        payload.exp - payload.iat > 60 ||
        payload.resource !== resourceUri
      ) {
        throw new Error("OIDC authorization code is invalid");
      }
      const scopes = normalizeScopes(payload.scope);
      const current = stateStore.current();
      if (!current.requestId) throw new Error("OIDC code has no authorization request");
      await transaction(async (client) => {
        const request = await requestById(client, current.requestId!, true);
        if (
          !request ||
          request.request_state !== "approved" ||
          request.member_id !== payload.accountId ||
          request.protocol_client_id !== payload.clientId ||
          request.redirect_uri !== payload.redirectUri ||
          JSON.stringify(request.scope_set) !== JSON.stringify(scopes)
        ) {
          throw new Error("OIDC authorization code binding failed");
        }
        await client.query(
          `insert into oauth_authorization_codes(
             id,organization_id,code_sha256,authorization_request_id,client_id,member_id,
             redirect_uri,resource_uri,scope_set,pkce_s256_challenge,issued_at,expires_at
           ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,to_timestamp($11),to_timestamp($12))`,
          [
            newId(),
            organizationId,
            sha256(id),
            request.id,
            request.client_id,
            payload.accountId,
            payload.redirectUri,
            resourceUri,
            scopes,
            payload.codeChallenge,
            payload.iat,
            payload.exp
          ]
        );
      });
    }

    public async upsert(
      id: string,
      payload: Readonly<Record<string, unknown>>,
      _expiresIn: number
    ): Promise<void> {
      switch (this.model) {
        case "Interaction":
          return this.upsertInteraction(id, payload);
        case "Session":
          return this.upsertSession(id, payload);
        case "Grant":
          return this.upsertGrant(id, payload);
        case "AuthorizationCode":
          return this.upsertAuthorizationCode(id, payload);
        case "Client":
          return;
        default:
          throw new Error(`oidc-provider model ${this.model} is not enabled`);
      }
    }

    private async findInteraction(
      id: string
    ): Promise<Readonly<Record<string, unknown>> | undefined> {
      const uid = InteractionUidSchema.parse(id);
      const current = stateStore.current();
      if (
        !current.requestId ||
        !current.rawState ||
        !current.codeChallenge ||
        current.interactionUid !== uid
      ) {
        return undefined;
      }
      return transaction(async (client) => {
        const request = await requestById(client, current.requestId!);
        if (
          !request ||
          !["pending", "approved", "denied"].includes(request.request_state) ||
          !requestContextIsBound(request) ||
          !request.request_is_live ||
          !request.session_is_live ||
          !timingSafeEqual(request.state_hash, sha256(current.rawState!))
        ) {
          return undefined;
        }
        const consent = await consentForRequest(client, request);
        const scopes = request.scope_set.join(" ");
        const login = request.member_id ? { login: { accountId: request.member_id } } : undefined;
        const authenticated = request.session_state === "authenticated";
        const approved = request.request_state === "approved" && consent;
        const denied = request.request_state === "denied";
        const prompt = authenticated
          ? {
              name: "consent",
              reasons: ["op_scopes_missing", "rs_scopes_missing"],
              details: {
                missingOIDCScope: request.scope_set,
                missingResourceScopes: { [resourceUri]: request.scope_set }
              }
            }
          : { name: "login", reasons: ["no_session"], details: {} };
        return {
          iat: epoch(request.created_at),
          exp: epoch(request.expires_at),
          returnTo: `${issuer}/authorize/${uid}`,
          prompt,
          ...(authenticated ? { lastSubmission: login, trusted: [] } : {}),
          params: {
            client_id: request.protocol_client_id,
            code_challenge: current.codeChallenge,
            code_challenge_method: "S256",
            redirect_uri: request.redirect_uri,
            response_type: "code",
            scope: scopes,
            state: current.rawState,
            resource: request.resource_uri
          },
          ...(authenticated && request.member_id
            ? {
                session: {
                  accountId: request.member_id,
                  uid: reference("session-uid", request.session_id)
                }
              }
            : {}),
          cid: reference("interaction-cid", request.id),
          kind: "Interaction",
          jti: uid,
          ...(denied
            ? {
                result: {
                  error: "access_denied",
                  error_description: "End-User denied authorization"
                }
              }
            : approved
              ? {
                  result: {
                    ...login,
                    consent: { grantId: reference("grant", consent.id) }
                  }
                }
              : !authenticated && login
                ? { result: login }
                : {})
        };
      });
    }

    private async sessionRowById(id: string, byUid: boolean): Promise<SessionRow | undefined> {
      return transaction(async (client) => {
        let sessionId = byUid ? dereference("session-uid", id) : undefined;
        if (!sessionId && byUid) {
          const current = stateStore.current();
          if (current.requestId) {
            sessionId = (await requestById(client, current.requestId))?.session_id;
          }
        }
        const result = await client.query<SessionRow>(
          `select session.id,session.member_id,session.client_id,session.state,
                  session.created_at,session.expires_at,session.last_authenticated_at,
                  oauth_client.protocol_id_value as protocol_client_id,
                  consent.id as consent_id,consent.resource_uri,consent.scope_set
             from auth_sessions as session
             left join oauth_clients as oauth_client on oauth_client.id=session.client_id
             left join lateral (
               select active.id,active.resource_uri,active.scope_set
                 from oauth_consents as active
                where active.organization_id=session.organization_id
                  and active.member_id=session.member_id
                  and active.client_id=session.client_id
                  and active.revoked_at is null
                order by active.granted_at desc,active.id desc limit 1
             ) as consent on true
            where session.organization_id=$1
              and session.state='authenticated'
              and session.expires_at>transaction_timestamp()
              and ($2::uuid is not null and session.id=$2
                   or $2::uuid is null and session.opaque_session_sha256=$3)`,
          [organizationId, sessionId ?? null, sha256(id)]
        );
        if (result.rows.length > 1) throw new Error("OIDC session is not unique");
        const row = result.rows[0];
        if (!row) return undefined;
        // A provider session belongs to the client it was authenticated for (one
        // auth_sessions row per member and client). When another client starts an
        // authorization in the same browser, the session is absent for that request, so
        // the provider asks for a fresh passkey login instead of failing the binding.
        const current = stateStore.current();
        if (current.protocolClientHint !== undefined) {
          if (row.protocol_client_id !== current.protocolClientHint) return undefined;
        } else if (current.requestId) {
          const request = await requestById(client, current.requestId);
          if (request && request.client_id !== row.client_id) return undefined;
        }
        return row;
      });
    }

    private sessionPayload(
      row: SessionRow,
      requestedId: string,
      byUid: boolean
    ): Readonly<Record<string, unknown>> {
      if (!row.member_id || !row.protocol_client_id || !row.last_authenticated_at) {
        throw new Error("OIDC authenticated session projection is incomplete");
      }
      const authorization = row.consent_id
        ? {
            [row.protocol_client_id]: {
              sid: reference("session-sid", row.id),
              grantId: reference("grant", row.consent_id)
            }
          }
        : undefined;
      return {
        iat: epoch(row.created_at),
        exp: epoch(row.expires_at),
        uid: reference("session-uid", row.id),
        accountId: row.member_id,
        loginTs: epoch(row.last_authenticated_at),
        kind: "Session",
        jti: byUid ? reference("session-cookie", row.id) : requestedId,
        ...(authorization ? { authorizations: authorization } : {})
      };
    }

    private async findGrant(id: string): Promise<Readonly<Record<string, unknown>> | undefined> {
      return transaction(async (client) => {
        let consentId = dereference("grant", id);
        const current = stateStore.current();
        if (!consentId && current.requestId) {
          const request = await requestById(client, current.requestId);
          if (request) consentId = (await consentForRequest(client, request))?.id;
        }
        if (!consentId) return undefined;
        const result = await client.query<ConsentRow>(
          `select consent.id,consent.member_id,consent.client_id,
                  oauth_client.protocol_id_value as protocol_client_id,
                  consent.resource_uri,consent.scope_set,consent.granted_at
             from oauth_consents as consent
             join oauth_clients as oauth_client on oauth_client.id=consent.client_id
            where consent.id=$1 and consent.organization_id=$2 and consent.revoked_at is null`,
          [consentId, organizationId]
        );
        const consent = result.rows[0];
        if (!consent) return undefined;
        const scopes = consent.scope_set.join(" ");
        return {
          iat: epoch(consent.granted_at),
          exp: epoch(consent.granted_at) + 90 * 24 * 60 * 60,
          accountId: consent.member_id,
          clientId: consent.protocol_client_id,
          kind: "Grant",
          jti: id,
          openid: { scope: scopes },
          resources: { [consent.resource_uri]: scopes }
        };
      });
    }

    private async findAuthorizationCode(
      id: string
    ): Promise<Readonly<Record<string, unknown>> | undefined> {
      return transaction(async (client) => {
        const result = await client.query<CodeRow>(
          `select code.id,code.member_id,code.redirect_uri,code.resource_uri,code.scope_set,
                  code.pkce_s256_challenge,code.issued_at,code.expires_at,
                  code.consumed_at,code.revoked_at,request.session_id,
                  session.last_authenticated_at,oauth_client.protocol_id_value as protocol_client_id,
                  consent.id as consent_id
             from oauth_authorization_codes as code
             join oauth_authorization_requests as request
               on request.id=code.authorization_request_id
             join auth_sessions as session on session.id=request.session_id
             join oauth_clients as oauth_client on oauth_client.id=code.client_id
             join oauth_consents as consent
               on consent.organization_id=code.organization_id
              and consent.member_id=code.member_id and consent.client_id=code.client_id
              and consent.resource_uri=code.resource_uri and consent.scope_set=code.scope_set
              and consent.revoked_at is null
            where code.organization_id=$1 and code.code_sha256=$2`,
          [organizationId, sha256(id)]
        );
        if (result.rows.length !== 1) return undefined;
        const code = result.rows[0]!;
        return {
          iat: epoch(code.issued_at),
          exp: epoch(code.expires_at),
          accountId: code.member_id,
          authTime: epoch(code.last_authenticated_at ?? code.issued_at),
          codeChallenge: code.pkce_s256_challenge,
          codeChallengeMethod: "S256",
          grantId: reference("grant", code.consent_id),
          redirectUri: code.redirect_uri,
          resource: code.resource_uri,
          scope: code.scope_set.join(" "),
          sessionUid: reference("session-uid", code.session_id),
          kind: "AuthorizationCode",
          jti: id,
          clientId: code.protocol_client_id,
          expiresWithSession: true,
          ...(code.consumed_at ? { consumed: epoch(code.consumed_at) } : {})
        };
      });
    }

    private async findClient(id: string): Promise<Readonly<Record<string, unknown>> | undefined> {
      return transaction(async (client) => {
        const oauthClient = await clientFor(client, id).catch(() => undefined);
        if (!oauthClient) return undefined;
        const redirects = await client.query<{ redirect_uri: string }>(
          `select redirect_uri from oauth_client_redirect_uris
            where client_id=$1 order by redirect_uri`,
          [oauthClient.id]
        );
        return {
          client_id: oauthClient.protocol_id_value,
          redirect_uris: redirects.rows.map((row) => row.redirect_uri),
          application_type: redirects.rows.some(
            (row) => new URL(row.redirect_uri).protocol !== "https:"
          )
            ? "native"
            : "web",
          response_types: ["code"],
          grant_types: ["authorization_code", "refresh_token"],
          token_endpoint_auth_method: "none",
          id_token_signed_response_alg: "ES256"
        };
      });
    }

    public async find(id: string): Promise<Readonly<Record<string, unknown>> | undefined> {
      switch (this.model) {
        case "Interaction":
          return this.findInteraction(id);
        case "Session": {
          const row = await this.sessionRowById(id, false);
          return row ? this.sessionPayload(row, id, false) : undefined;
        }
        case "Grant":
          return this.findGrant(id);
        case "AuthorizationCode":
          return this.findAuthorizationCode(id);
        case "Client":
          return this.findClient(id);
        default:
          return undefined;
      }
    }

    public async destroy(id: string): Promise<void> {
      if (this.model === "Grant") {
        await this.revokeByGrantId(id);
      } else if (this.model === "AuthorizationCode") {
        await transaction(async (client) => {
          await client.query(
            `update oauth_authorization_codes set revoked_at=transaction_timestamp()
              where organization_id=$1 and code_sha256=$2
                and consumed_at is null and revoked_at is null`,
            [organizationId, sha256(id)]
          );
        });
      }
      // Interaction deletion is represented by its bounded request state; Session.destroy
      // is an oidc-provider cookie rotation before the replacement Session upsert.
    }

    public async consume(id: string): Promise<void> {
      if (this.model !== "AuthorizationCode") return;
      await transaction(async (client) => {
        await client.query(
          `update oauth_authorization_codes set consumed_at=transaction_timestamp()
            where organization_id=$1 and code_sha256=$2
              and consumed_at is null and revoked_at is null`,
          [organizationId, sha256(id)]
        );
      });
    }

    public async findByUid(uid: string): Promise<Readonly<Record<string, unknown>> | undefined> {
      if (this.model !== "Session") return undefined;
      const row = await this.sessionRowById(uid, true);
      return row ? this.sessionPayload(row, uid, true) : undefined;
    }

    public async findByUserCode(
      _userCode: string
    ): Promise<Readonly<Record<string, unknown>> | undefined> {
      return undefined;
    }

    public async revokeByGrantId(grantId: string): Promise<void> {
      const consentId = dereference("grant", grantId);
      if (!consentId) return;
      await transaction(async (client) => {
        await client.query(
          `update oauth_consents set revoked_at=transaction_timestamp()
            where id=$1 and organization_id=$2 and revoked_at is null`,
          [consentId, organizationId]
        );
      });
    }
  }

  const csrfFor = (requestId: string, interactionUid: string): string =>
    createHmac("sha256", csrfKey)
      .update(uuidBytes(requestId))
      .update(Buffer.from([0]))
      .update(InteractionUidSchema.parse(interactionUid), "utf8")
      .digest("base64url");

  const interactionBindingStore: OidcInteractionBindingStore = {
    load: (incoming) =>
      stateStore.run(incoming, async (): Promise<OidcInteractionBinding> => {
        const current = stateStore.current();
        if (
          !current.requestId ||
          !current.rawState ||
          !current.codeChallenge ||
          !current.interactionUid
        ) {
          throw new Error("OIDC interaction binding is unavailable");
        }
        return transaction(async (client) => {
          const request = await requestById(client, current.requestId!);
          if (
            !request ||
            request.request_state !== "pending" ||
            !requestContextIsBound(request) ||
            !request.request_is_live ||
            !request.session_is_live ||
            !["anonymous", "authenticated"].includes(request.session_state) ||
            request.resource_uri !== resourceUri ||
            !timingSafeEqual(request.state_hash, sha256(current.rawState!))
          ) {
            throw new Error("OIDC interaction binding is unavailable");
          }
          const interactionUid = InteractionUidSchema.parse(current.interactionUid);
          return {
            interactionUid,
            authorizationRequestId: request.id,
            sessionId: request.session_id,
            clientId: request.client_id,
            protocolClientId: request.protocol_client_id,
            clientDisplayName: request.client_display_name,
            resourceUri: request.resource_uri,
            scopes: [...request.scope_set],
            csrfToken: csrfFor(request.id, interactionUid),
            expiresAt: request.expires_at
          };
        });
      }),
    verifyCsrf: (binding, csrfToken) => {
      let actual: Buffer;
      let bound: Buffer;
      try {
        actual = Buffer.from(CsrfTokenSchema.parse(csrfToken), "utf8");
        bound = Buffer.from(CsrfTokenSchema.parse(binding.csrfToken), "utf8");
      } catch {
        throw new Error("OIDC interaction CSRF failed");
      }
      const expectedToken = csrfFor(binding.authorizationRequestId, binding.interactionUid);
      const expected = Buffer.from(expectedToken, "utf8");
      if (
        actual.length !== expected.length ||
        bound.length !== expected.length ||
        !timingSafeEqual(actual, expected) ||
        !timingSafeEqual(bound, expected)
      ) {
        throw new Error("OIDC interaction CSRF failed");
      }
    }
  };

  return {
    adapter: PgOidcAdapter,
    interactionStateStore: stateStore,
    interactionBindingStore
  };
}
