import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes as nodeRandomBytes
} from "node:crypto";

import type { Pool, PoolClient } from "pg";
import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  ClientSecretPost,
  Configuration,
  customFetch,
  discovery,
  type CustomFetch
} from "openid-client";
import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";
import { appendAuditEventsInTransaction, withIdentityTransaction } from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

import type { OidcInteractionBinding } from "./oauth-authorization-server.js";

const ProviderIdSchema = z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/u);
const ProviderKindSchema = z.enum(["generic", "uae_pass"]);
const ProviderLabelSchema = z
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
  );
const InteractionUidSchema = z.string().regex(/^[A-Za-z0-9_-]{16,256}$/u);
const SecretSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const PkceChallengeSchema = SecretSchema;
const SubjectSchema = z
  .string()
  .min(1)
  .max(1024)
  .refine(
    (value) =>
      value === value.normalize("NFC") &&
      Buffer.byteLength(value, "utf8") <= 4096 &&
      [...value].every((character) => {
        const point = character.codePointAt(0);
        return point !== undefined && point > 0x1f && point !== 0x7f;
      })
  );
const Sha256BufferSchema = z.instanceof(Buffer).refine((value) => value.length === 32);
const OidcStartContinuationSchema = z
  .object({
    v: z.literal(1),
    providerId: ProviderIdSchema,
    transactionId: UuidV7Schema,
    interactionUid: InteractionUidSchema,
    state: SecretSchema,
    nonce: SecretSchema,
    codeVerifier: SecretSchema,
    expiresAt: z.number().int().positive()
  })
  .strict();

export type UpstreamOidcProviderKind = z.infer<typeof ProviderKindSchema>;

export interface UpstreamOidcProfile {
  readonly id: string;
  readonly kind: UpstreamOidcProviderKind;
  readonly label: string;
  readonly issuer: string;
  readonly callbackUri: string;
  readonly configuration: Configuration;
}

interface ValidatedUpstreamOidcProfile extends UpstreamOidcProfile {
  readonly id: z.infer<typeof ProviderIdSchema>;
  readonly kind: UpstreamOidcProviderKind;
}

export interface OidcFederationProviderChoice {
  readonly id: string;
  readonly label: string;
}

export class OidcFederationError extends Error {
  public constructor(
    public readonly code: string = "oidc_federation_refused",
    public readonly statusCode: 400 | 500 = 400
  ) {
    super("upstream identity authentication was refused");
    this.name = "OidcFederationError";
  }
}

function refuse(code = "oidc_federation_refused", statusCode: 400 | 500 = 400): never {
  throw new OidcFederationError(code, statusCode);
}

function exactIssuer(value: string): string {
  let url: URL;
  try {
    url = new URL(z.string().min(1).max(2048).parse(value));
  } catch {
    refuse("invalid_oidc_profile", 500);
  }
  const canonicalWithoutRootSlash = `${url.origin}${url.pathname === "/" ? "" : url.pathname}`;
  if (
    url.protocol !== "https:" ||
    url.hostname === "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (value !== url.href && value !== canonicalWithoutRootSlash)
  ) {
    refuse("invalid_oidc_profile", 500);
  }
  return value;
}

function exactHttpsUrl(value: string, code = "invalid_oidc_profile"): URL {
  let url: URL;
  try {
    url = new URL(z.string().min(1).max(2048).parse(value));
  } catch {
    refuse(code, code === "invalid_oidc_profile" ? 500 : 400);
  }
  if (
    url.protocol !== "https:" ||
    url.hostname === "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.href !== value
  ) {
    refuse(code, code === "invalid_oidc_profile" ? 500 : 400);
  }
  return url;
}

function validatedProfile(input: UpstreamOidcProfile): ValidatedUpstreamOidcProfile {
  const id = ProviderIdSchema.parse(input.id);
  const kind = ProviderKindSchema.parse(input.kind);
  const label = ProviderLabelSchema.parse(input.label);
  const issuer = exactIssuer(input.issuer);
  const callback = exactHttpsUrl(input.callbackUri);
  if (
    callback.search !== "" ||
    callback.hash !== "" ||
    callback.pathname !== `/auth/oidc/callback/${id}` ||
    !(input.configuration instanceof Configuration)
  ) {
    refuse("invalid_oidc_profile", 500);
  }
  const server = input.configuration.serverMetadata();
  const client = input.configuration.clientMetadata();
  const responseTypes = server.response_types_supported;
  const pkceMethods = server.code_challenge_methods_supported;
  if (
    server.issuer !== issuer ||
    typeof server.authorization_endpoint !== "string" ||
    typeof server.token_endpoint !== "string" ||
    typeof server.jwks_uri !== "string" ||
    !Array.isArray(responseTypes) ||
    !responseTypes.includes("code") ||
    !Array.isArray(pkceMethods) ||
    !pkceMethods.includes("S256") ||
    typeof client.client_id !== "string" ||
    client.client_id.length === 0 ||
    client.client_id.length > 2048 ||
    !Array.isArray(client.redirect_uris) ||
    !client.redirect_uris.every((value) => typeof value === "string") ||
    !client.redirect_uris.includes(input.callbackUri)
  ) {
    refuse("invalid_oidc_profile", 500);
  }
  for (const endpoint of [server.authorization_endpoint, server.token_endpoint, server.jwks_uri]) {
    exactHttpsUrl(endpoint);
  }
  return { ...input, id, kind, label, issuer };
}

export async function discoverUpstreamOidcProfile(input: {
  readonly id: string;
  readonly kind: UpstreamOidcProviderKind;
  readonly label: string;
  readonly issuer: string;
  readonly callbackUri: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly fetch?: CustomFetch;
}): Promise<UpstreamOidcProfile> {
  const id = ProviderIdSchema.parse(input.id);
  const issuer = exactIssuer(input.issuer);
  const callbackUri = exactHttpsUrl(input.callbackUri).href;
  if (new URL(callbackUri).pathname !== `/auth/oidc/callback/${id}`) {
    refuse("invalid_oidc_profile", 500);
  }
  const clientId = z.string().min(1).max(2048).parse(input.clientId);
  const clientSecret = z.string().min(32).max(4096).parse(input.clientSecret);
  const options = {
    timeout: 5,
    ...(input.fetch === undefined ? {} : { [customFetch]: input.fetch })
  };
  const configuration = await discovery(
    new URL(issuer),
    clientId,
    {
      client_secret: clientSecret,
      redirect_uris: [callbackUri],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post"
    },
    ClientSecretPost(clientSecret),
    options
  );
  return validatedProfile({
    id,
    kind: ProviderKindSchema.parse(input.kind),
    label: ProviderLabelSchema.parse(input.label),
    issuer,
    callbackUri,
    configuration
  });
}

export interface BeginOidcFederationInput {
  readonly transactionId: string;
  readonly providerId: string;
  readonly providerKind: UpstreamOidcProviderKind;
  readonly exactIssuer: string;
  readonly interactionUid: string;
  readonly authorizationRequestId: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly resourceUri: string;
  readonly callbackUri: string;
  readonly stateSha256: Buffer;
  readonly nonceSha256: Buffer;
  readonly pkceS256Challenge: string;
  readonly invitationTokenSha256: Buffer | null;
}

export interface CompleteOidcFederationInput {
  readonly transactionId: string;
  readonly providerId: string;
  readonly providerKind: UpstreamOidcProviderKind;
  readonly exactIssuer: string;
  readonly stateSha256: Buffer;
  readonly nonceSha256: Buffer;
  readonly pkceS256Challenge: string;
  readonly subject: string;
  readonly completionSha256: Buffer;
  readonly pendingLinkId: string;
}

export type CompleteOidcFederationResult =
  | {
      readonly status: "authenticated";
      readonly interactionUid: string;
      readonly memberId: string;
    }
  | {
      readonly status: "pending_link" | "unknown_subject" | "unavailable";
      readonly interactionUid: string | null;
      readonly memberId: null;
    };

export interface OidcFederationStore {
  begin(input: BeginOidcFederationInput): Promise<{ transactionId: string; expiresAt: Date }>;
  complete(input: CompleteOidcFederationInput): Promise<CompleteOidcFederationResult>;
  reject(transactionId: string, failureCode: "binding_refused" | "protocol_refused"): Promise<void>;
  consumeCompletion(interactionUid: string, completionSha256: Buffer): Promise<string | null>;
}

const BeginRowSchema = z
  .object({
    result_transaction_id: UuidV7Schema,
    result_expires_at: z.coerce.date()
  })
  .strict();
const CompleteRowSchema = z
  .object({
    result_status: z.enum(["authenticated", "pending_link", "unknown_subject", "unavailable"]),
    result_interaction_uid: InteractionUidSchema.nullable(),
    result_member_id: UuidV7Schema.nullable()
  })
  .strict();

export class PgOidcFederationStore implements OidcFederationStore {
  private readonly organizationId: string;
  private readonly assumeRole: "boardagent_server" | undefined;
  private readonly newId: () => string;

  public constructor(
    private readonly pool: Pool,
    options: {
      readonly organizationId: string;
      readonly assumeRole?: "boardagent_server";
      readonly newId?: () => string;
    }
  ) {
    this.organizationId = UuidV7Schema.parse(options.organizationId);
    this.assumeRole = options.assumeRole;
    this.newId = options.newId ?? (() => uuidV7(Date.now(), nodeRandomBytes(10)));
  }

  private transaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    return withIdentityTransaction(
      this.pool,
      { organizationId: this.organizationId },
      run,
      this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole }
    );
  }

  private async auditDenial(
    client: PoolClient,
    input: {
      readonly transactionId: string;
      readonly providerId?: string;
      readonly issuer?: string;
      readonly subject?: string;
      readonly reason: string;
      readonly pendingLink: boolean;
    }
  ): Promise<void> {
    await appendAuditEventsInTransaction(client, [
      {
        organizationId: this.organizationId,
        event: {
          eventId: UuidV7Schema.parse(this.newId()),
          eventType: "authorization_denied",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "oidc_login_transaction",
          entityId: UuidV7Schema.parse(input.transactionId),
          boardId: null,
          origin: "oauth",
          details: {
            federation: true,
            reason: input.reason,
            pendingLink: input.pendingLink,
            ...(input.providerId === undefined ? {} : { providerId: input.providerId }),
            ...(input.issuer === undefined
              ? {}
              : { issuerSha256: sha256(input.issuer).toString("hex") }),
            ...(input.subject === undefined
              ? {}
              : { subjectSha256: sha256(input.subject).toString("hex") })
          },
          schemaVersion: 1
        }
      }
    ]);
  }

  public begin(input: BeginOidcFederationInput): Promise<{
    transactionId: string;
    expiresAt: Date;
  }> {
    return this.transaction(async (client) => {
      const result = await client.query(
        `select result_transaction_id,result_expires_at
           from boardagent_begin_oidc_login(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
           )`,
        [
          this.organizationId,
          input.transactionId,
          input.providerId,
          input.providerKind,
          input.exactIssuer,
          input.interactionUid,
          input.authorizationRequestId,
          input.sessionId,
          input.clientId,
          input.resourceUri,
          input.callbackUri,
          input.stateSha256,
          input.nonceSha256,
          input.pkceS256Challenge,
          input.invitationTokenSha256
        ]
      );
      if (result.rows.length !== 1) throw new OidcFederationError();
      const row = BeginRowSchema.parse(result.rows[0]);
      return { transactionId: row.result_transaction_id, expiresAt: row.result_expires_at };
    });
  }

  public complete(input: CompleteOidcFederationInput): Promise<CompleteOidcFederationResult> {
    return this.transaction(async (client) => {
      const result = await client.query(
        `select result_status,result_interaction_uid,result_member_id
           from boardagent_complete_oidc_login(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
           )`,
        [
          this.organizationId,
          input.transactionId,
          input.providerId,
          input.providerKind,
          input.exactIssuer,
          input.stateSha256,
          input.nonceSha256,
          input.pkceS256Challenge,
          input.subject,
          input.completionSha256,
          input.pendingLinkId
        ]
      );
      if (result.rows.length !== 1) throw new OidcFederationError();
      const row = CompleteRowSchema.parse(result.rows[0]);
      if (row.result_status !== "authenticated") {
        await this.auditDenial(client, {
          transactionId: input.transactionId,
          providerId: input.providerId,
          issuer: input.exactIssuer,
          subject: input.subject,
          reason: row.result_status,
          pendingLink: row.result_status === "pending_link"
        });
        return {
          status: row.result_status,
          interactionUid: row.result_interaction_uid,
          memberId: null
        };
      }
      if (!row.result_interaction_uid || !row.result_member_id) {
        throw new OidcFederationError("oidc_federation_store_failed", 500);
      }
      return {
        status: "authenticated",
        interactionUid: row.result_interaction_uid,
        memberId: row.result_member_id
      };
    });
  }

  public reject(
    transactionIdValue: string,
    failureCode: "binding_refused" | "protocol_refused"
  ): Promise<void> {
    const transactionId = UuidV7Schema.parse(transactionIdValue);
    return this.transaction(async (client) => {
      const result = await client.query<{ changed: boolean }>(
        "select boardagent_reject_oidc_login($1,$2,$3) as changed",
        [this.organizationId, transactionId, failureCode]
      );
      if (result.rows[0]?.changed) {
        await this.auditDenial(client, {
          transactionId,
          reason: failureCode,
          pendingLink: false
        });
      }
    });
  }

  public consumeCompletion(
    interactionUidValue: string,
    completionSha256: Buffer
  ): Promise<string | null> {
    const interactionUid = InteractionUidSchema.parse(interactionUidValue);
    Sha256BufferSchema.parse(completionSha256);
    return this.transaction(async (client) => {
      const result = await client.query<{ member_id: string | null }>(
        "select boardagent_consume_oidc_completion($1,$2,$3) as member_id",
        [this.organizationId, interactionUid, completionSha256]
      );
      const memberId = result.rows[0]?.member_id;
      return memberId ? UuidV7Schema.parse(memberId) : null;
    });
  }
}

function sha256(value: Uint8Array | string): Buffer {
  return createHash("sha256").update(value).digest();
}

function exactCookie(header: string | undefined, name: string): string {
  if (!header || Buffer.byteLength(header, "utf8") > 8192) refuse();
  const values = header
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`))
    .map((part) => part.slice(name.length + 1));
  if (values.length !== 1 || values[0] === "") refuse();
  return values[0]!;
}

function cookie(name: string, value: string, path: string, maxAgeSeconds: number): string {
  if (
    !/^__Secure-[A-Za-z0-9_-]{1,120}$/u.test(name) ||
    !/^[A-Za-z0-9._-]{1,4096}$/u.test(value) ||
    !/^\/[A-Za-z0-9/_-]{1,512}$/u.test(path) ||
    !Number.isSafeInteger(maxAgeSeconds) ||
    maxAgeSeconds < 1 ||
    maxAgeSeconds > 600
  ) {
    refuse("oidc_federation_cookie_failed", 500);
  }
  return `${name}=${value}; Path=${path}; Max-Age=${String(maxAgeSeconds)}; HttpOnly; Secure; SameSite=Lax`;
}

function startCookieName(state: string): string {
  return `__Secure-boardagent_upstream_${sha256(state).subarray(0, 12).toString("base64url")}`;
}

function completionCookieName(interactionUid: string): string {
  return `__Secure-boardagent_finish_${sha256(interactionUid)
    .subarray(0, 12)
    .toString("base64url")}`;
}

function startCookiePath(providerId: string): string {
  return `/auth/oidc/callback/${providerId}`;
}

function completionCookiePath(interactionUid: string): string {
  return `/auth/interactions/${interactionUid}/oidc/complete`;
}

export interface OidcFederationServiceOptions {
  readonly profiles: readonly UpstreamOidcProfile[];
  readonly store: OidcFederationStore;
  readonly cookieEncryptionKey: Uint8Array;
  readonly newId?: () => string;
  readonly randomBytes?: (size: number) => Uint8Array;
  readonly now?: () => Date;
}

export interface OidcFederationStartResult {
  readonly location: string;
  readonly setCookie: string;
}

export interface OidcFederationCallbackResult {
  readonly status: "authenticated" | "pending_link";
  readonly location: string | null;
  readonly setCookie: string | null;
}

export class OidcFederationService {
  public readonly providers: readonly OidcFederationProviderChoice[];
  private readonly profiles: ReadonlyMap<string, ValidatedUpstreamOidcProfile>;
  private readonly store: OidcFederationStore;
  private readonly encryptionKey: Buffer;
  private readonly newId: () => string;
  private readonly randomSource: (size: number) => Uint8Array;
  private readonly now: () => Date;

  public constructor(options: OidcFederationServiceOptions) {
    const profiles = options.profiles.map(validatedProfile);
    if (
      profiles.length === 0 ||
      profiles.length > 16 ||
      new Set(profiles.map(({ id }) => id)).size !== profiles.length ||
      new Set(profiles.map(({ callbackUri }) => callbackUri)).size !== profiles.length
    ) {
      refuse("invalid_oidc_profile", 500);
    }
    this.profiles = new Map(profiles.map((profile) => [profile.id, profile]));
    this.providers = profiles
      .map(({ id, label }) => ({ id, label }))
      .toSorted((left, right) => left.id.localeCompare(right.id));
    this.store = options.store;
    const baseKey = Buffer.from(options.cookieEncryptionKey);
    if (baseKey.length !== 32) refuse("invalid_oidc_cookie_key", 500);
    this.encryptionKey = createHmac("sha256", baseKey)
      .update("boardagent/upstream-oidc/continuation/aes-256-gcm/v1", "utf8")
      .digest();
    this.newId = options.newId ?? (() => uuidV7(Date.now(), nodeRandomBytes(10)));
    this.randomSource = options.randomBytes ?? nodeRandomBytes;
    this.now = options.now ?? (() => new Date());
  }

  private profile(providerIdValue: string): ValidatedUpstreamOidcProfile {
    const providerId = ProviderIdSchema.parse(providerIdValue);
    const profile = this.profiles.get(providerId);
    if (!profile) refuse();
    return profile;
  }

  private entropy(size: number): Buffer {
    const bytes = Buffer.from(this.randomSource(size));
    if (bytes.length !== size) refuse("oidc_federation_entropy_failed", 500);
    return bytes;
  }

  private secret(root: Buffer, purpose: string): string {
    return createHmac("sha256", root).update(purpose, "utf8").digest("base64url");
  }

  private seal(
    profile: ValidatedUpstreamOidcProfile,
    value: z.infer<typeof OidcStartContinuationSchema>
  ): string {
    const parsed = OidcStartContinuationSchema.parse(value);
    const nonce = this.entropy(12);
    const cipher = createCipheriv("aes-256-gcm", this.encryptionKey, nonce);
    cipher.setAAD(Buffer.from(`${profile.id}\0${profile.issuer}`, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(parsed), "utf8"),
      cipher.final()
    ]);
    return [
      "v1",
      nonce.toString("base64url"),
      ciphertext.toString("base64url"),
      cipher.getAuthTag().toString("base64url")
    ].join(".");
  }

  private open(
    profile: ValidatedUpstreamOidcProfile,
    value: string
  ): z.infer<typeof OidcStartContinuationSchema> {
    try {
      const parts = value.split(".");
      if (parts.length !== 4 || parts[0] !== "v1") refuse();
      const nonce = Buffer.from(parts[1]!, "base64url");
      const ciphertext = Buffer.from(parts[2]!, "base64url");
      const tag = Buffer.from(parts[3]!, "base64url");
      if (
        nonce.length !== 12 ||
        ciphertext.length === 0 ||
        ciphertext.length > 4096 ||
        tag.length !== 16 ||
        nonce.toString("base64url") !== parts[1] ||
        ciphertext.toString("base64url") !== parts[2] ||
        tag.toString("base64url") !== parts[3]
      ) {
        refuse();
      }
      const decipher = createDecipheriv("aes-256-gcm", this.encryptionKey, nonce);
      decipher.setAAD(Buffer.from(`${profile.id}\0${profile.issuer}`, "utf8"));
      decipher.setAuthTag(tag);
      return OidcStartContinuationSchema.parse(
        JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8"))
      );
    } catch (error) {
      if (error instanceof OidcFederationError) throw error;
      refuse();
    }
  }

  public async start(input: {
    readonly providerId: string;
    readonly binding: OidcInteractionBinding;
    readonly invitationToken?: string;
  }): Promise<OidcFederationStartResult> {
    const profile = this.profile(input.providerId);
    const interactionUid = InteractionUidSchema.parse(input.binding.interactionUid);
    const transactionId = UuidV7Schema.parse(this.newId());
    const root = this.entropy(32);
    const state = this.secret(root, "state");
    const nonce = this.secret(root, "nonce");
    const codeVerifier = this.secret(root, "pkce-verifier");
    const pkceS256Challenge = PkceChallengeSchema.parse(
      await calculatePKCECodeChallenge(codeVerifier)
    );
    let invitationTokenSha256: Buffer | null = null;
    if (input.invitationToken !== undefined) {
      if (profile.kind !== "uae_pass") refuse();
      const invitationToken = z
        .string()
        .min(32)
        .max(4096)
        .refine((value) => value === value.normalize("NFC"))
        .parse(input.invitationToken);
      invitationTokenSha256 = sha256(invitationToken);
    }
    const begun = await this.store.begin({
      transactionId,
      providerId: profile.id,
      providerKind: profile.kind,
      exactIssuer: profile.issuer,
      interactionUid,
      authorizationRequestId: UuidV7Schema.parse(input.binding.authorizationRequestId),
      sessionId: UuidV7Schema.parse(input.binding.sessionId),
      clientId: UuidV7Schema.parse(input.binding.clientId),
      resourceUri: z.string().url().max(2048).parse(input.binding.resourceUri),
      callbackUri: profile.callbackUri,
      stateSha256: sha256(state),
      nonceSha256: sha256(nonce),
      pkceS256Challenge,
      invitationTokenSha256
    });
    if (begun.transactionId !== transactionId || begun.expiresAt <= this.now()) refuse();
    const authorizationUrl = buildAuthorizationUrl(profile.configuration, {
      response_type: "code",
      redirect_uri: profile.callbackUri,
      scope: "openid",
      state,
      nonce,
      code_challenge: pkceS256Challenge,
      code_challenge_method: "S256"
    });
    exactHttpsUrl(authorizationUrl.href);
    const seconds = Math.min(
      600,
      Math.max(1, Math.ceil((begun.expiresAt.getTime() - this.now().getTime()) / 1000))
    );
    const sealed = this.seal(profile, {
      v: 1,
      providerId: profile.id,
      transactionId,
      interactionUid,
      state,
      nonce,
      codeVerifier,
      expiresAt: begun.expiresAt.getTime()
    });
    return {
      location: authorizationUrl.href,
      setCookie: cookie(startCookieName(state), sealed, startCookiePath(profile.id), seconds)
    };
  }

  public async callback(input: {
    readonly providerId: string;
    readonly currentUrl: URL;
    readonly cookieHeader: string | undefined;
  }): Promise<OidcFederationCallbackResult> {
    const profile = this.profile(input.providerId);
    let continuation: z.infer<typeof OidcStartContinuationSchema> | undefined;
    let databaseCompleted = false;
    try {
      const callback = exactHttpsUrl(input.currentUrl.href, "oidc_callback_refused");
      if (
        callback.origin !== new URL(profile.callbackUri).origin ||
        callback.pathname !== new URL(profile.callbackUri).pathname ||
        callback.hash !== "" ||
        callback.searchParams.getAll("code").length !== 1 ||
        callback.searchParams.getAll("state").length !== 1 ||
        callback.searchParams.getAll("error").length !== 0
      ) {
        refuse("oidc_callback_refused");
      }
      const state = SecretSchema.parse(callback.searchParams.get("state"));
      const issuerParameters = callback.searchParams.getAll("iss");
      if (
        issuerParameters.length > 1 ||
        (issuerParameters[0] && issuerParameters[0] !== profile.issuer)
      ) {
        refuse("oidc_callback_refused");
      }
      continuation = this.open(profile, exactCookie(input.cookieHeader, startCookieName(state)));
      if (
        continuation.providerId !== profile.id ||
        continuation.state !== state ||
        continuation.expiresAt <= this.now().getTime()
      ) {
        refuse();
      }
      const tokens = await authorizationCodeGrant(profile.configuration, callback, {
        expectedState: continuation.state,
        expectedNonce: continuation.nonce,
        pkceCodeVerifier: continuation.codeVerifier,
        idTokenExpected: true
      });
      const claims = tokens.claims();
      const identity = z
        .object({ iss: z.string(), sub: SubjectSchema })
        .passthrough()
        .parse(claims);
      if (identity.iss !== profile.issuer) refuse();
      const completionSecret = this.entropy(32).toString("base64url");
      const completed = await this.store.complete({
        transactionId: continuation.transactionId,
        providerId: profile.id,
        providerKind: profile.kind,
        exactIssuer: profile.issuer,
        stateSha256: sha256(continuation.state),
        nonceSha256: sha256(continuation.nonce),
        pkceS256Challenge: PkceChallengeSchema.parse(
          await calculatePKCECodeChallenge(continuation.codeVerifier)
        ),
        subject: identity.sub,
        completionSha256: sha256(completionSecret),
        pendingLinkId: UuidV7Schema.parse(this.newId())
      });
      databaseCompleted = true;
      if (completed.status === "pending_link") {
        return { status: "pending_link", location: null, setCookie: null };
      }
      if (
        completed.status !== "authenticated" ||
        completed.interactionUid !== continuation.interactionUid
      ) {
        refuse();
      }
      const location = completionCookiePath(continuation.interactionUid);
      return {
        status: "authenticated",
        location,
        setCookie: cookie(
          completionCookieName(continuation.interactionUid),
          completionSecret,
          location,
          Math.min(
            600,
            Math.max(1, Math.ceil((continuation.expiresAt - this.now().getTime()) / 1000))
          )
        )
      };
    } catch (error) {
      if (continuation && !databaseCompleted) {
        try {
          await this.store.reject(continuation.transactionId, "protocol_refused");
        } catch {
          throw new OidcFederationError("oidc_federation_audit_failed", 500);
        }
      }
      if (error instanceof OidcFederationError) throw error;
      throw new OidcFederationError();
    }
  }

  public async consumeCompletion(input: {
    readonly interactionUid: string;
    readonly cookieHeader: string | undefined;
  }): Promise<{ readonly memberId: string }> {
    const interactionUid = InteractionUidSchema.parse(input.interactionUid);
    const completion = SecretSchema.parse(
      exactCookie(input.cookieHeader, completionCookieName(interactionUid))
    );
    const memberId = await this.store.consumeCompletion(interactionUid, sha256(completion));
    if (!memberId) refuse();
    return { memberId: UuidV7Schema.parse(memberId) };
  }
}
