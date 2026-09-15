import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes as nodeRandomBytes,
  timingSafeEqual
} from "node:crypto";

import type { Pool, PoolClient } from "pg";
import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";
import { withIdentityTransaction } from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

import { PgRateLimiter, type RateLimitPolicy } from "./pg-rate-limiter.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_SECRET_BYTES = 20;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_CIPHERTEXT_MAGIC = Buffer.from("BATOTP1", "ascii");
const TOTP_NONCE_BYTES = 12;
const TOTP_TAG_BYTES = 16;
const FALLBACK_HANDLE_BYTES = 32;
const FALLBACK_HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const TOTP_CODE_PATTERN = /^\d{6}$/u;

const RatePolicySchema = z
  .object({
    windowSeconds: z.number().int().min(1).max(86_400),
    maxRequests: z.number().int().min(1).max(1_000_000),
    blockSeconds: z.number().int().min(1).max(86_400)
  })
  .strict();

const EnrollmentInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    authorizedByMemberId: UuidV7Schema
  })
  .strict();

const EnrollmentCompletionSchema = z
  .object({
    organizationId: UuidV7Schema,
    credentialId: UuidV7Schema,
    authorizedByMemberId: UuidV7Schema,
    code: z.string().regex(TOTP_CODE_PATTERN)
  })
  .strict();

const AuthenticationInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    sessionId: UuidV7Schema,
    clientId: UuidV7Schema,
    clientIpClass: z.string().min(1).max(256),
    fallbackHandle: z.string().regex(FALLBACK_HANDLE_PATTERN),
    code: z.string().regex(TOTP_CODE_PATTERN)
  })
  .strict();

const CredentialRowSchema = z
  .object({
    id: UuidV7Schema,
    member_id: UuidV7Schema,
    encrypted_secret: z.instanceof(Buffer),
    key_id: UuidV7Schema,
    state: z.enum(["pending_verification", "active"]),
    failed_attempts: z.number().int().min(0).max(10),
    locked_until: z.date().nullable(),
    last_accepted_step: z.string().regex(/^\d+$/u).nullable(),
    member_state: z.string(),
    key_retired_at: z.date().nullable(),
    key_compromised_at: z.date().nullable()
  })
  .strict();

type CredentialRow = z.infer<typeof CredentialRowSchema>;

export type TotpErrorCode =
  "enrollment_not_authorized" | "invalid_enrollment" | "invalid_totp" | "rate_limited";

export class TotpError extends Error {
  public constructor(
    public readonly code: TotpErrorCode,
    public readonly retryAfterSeconds?: number
  ) {
    super(
      code === "rate_limited"
        ? "TOTP authentication is rate limited"
        : code === "enrollment_not_authorized"
          ? "TOTP enrollment is not authorized"
          : code === "invalid_enrollment"
            ? "TOTP enrollment could not be completed"
            : "TOTP authentication failed"
    );
    this.name = "TotpError";
  }
}

export interface TotpRateLimitPolicies {
  readonly ip: RateLimitPolicy;
  readonly client: RateLimitPolicy;
  readonly member: RateLimitPolicy;
  readonly token: RateLimitPolicy;
}

export interface TotpEnrollmentResult {
  readonly credentialId: string;
  readonly fallbackHandle: string;
  readonly secretBase32: string;
  readonly provisioningUri: string;
}

export interface TotpAuthenticationInput {
  readonly organizationId: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly clientIpClass: string;
  readonly fallbackHandle: string;
  readonly code: string;
}

export interface TotpAuthenticationResult {
  readonly memberId: string;
  readonly credentialId: string;
  readonly acceptedStep: number;
}

export interface TotpAuthenticator {
  authenticate(input: TotpAuthenticationInput): Promise<TotpAuthenticationResult>;
}

export interface PgTotpServiceOptions {
  readonly issuer: string;
  readonly activeKeyId: string;
  readonly keys: ReadonlyMap<string, Uint8Array>;
  readonly rateLimiter: PgRateLimiter;
  readonly rateLimits: TotpRateLimitPolicies;
  readonly maxFailedAttempts: number;
  readonly lockoutSeconds: number;
  readonly assumeRole?: "boardagent_server";
  readonly newId?: () => string;
  readonly randomBytes?: (size: number) => Uint8Array;
}

function exactTotpSecret(value: Uint8Array): Buffer {
  const secret = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (secret.length !== TOTP_SECRET_BYTES) {
    throw new RangeError("TOTP secret must contain exactly 20 bytes");
  }
  return secret;
}

function exactUnixSeconds(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError("TOTP time must be a non-negative safe integer in Unix seconds");
  }
  return value;
}

export function encodeTotpSecret(value: Uint8Array): string {
  const secret = exactTotpSecret(value);
  let accumulator = 0;
  let availableBits = 0;
  let encoded = "";
  for (const byte of secret) {
    accumulator = (accumulator << 8) | byte;
    availableBits += 8;
    while (availableBits >= 5) {
      availableBits -= 5;
      encoded += BASE32_ALPHABET[(accumulator >>> availableBits) & 0x1f];
    }
    accumulator &= (1 << availableBits) - 1;
  }
  if (availableBits > 0) encoded += BASE32_ALPHABET[(accumulator << (5 - availableBits)) & 0x1f];
  return encoded;
}

function decodeTotpSecret(value: string): Buffer {
  if (!/^[A-Z2-7]{32}$/u.test(value)) {
    throw new TypeError("TOTP secret must use canonical Base32 without padding");
  }
  let accumulator = 0;
  let availableBits = 0;
  const decoded: number[] = [];
  for (const character of value) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new TypeError("TOTP secret must use canonical Base32 without padding");
    accumulator = (accumulator << 5) | index;
    availableBits += 5;
    if (availableBits >= 8) {
      availableBits -= 8;
      decoded.push((accumulator >>> availableBits) & 0xff);
      accumulator &= (1 << availableBits) - 1;
    }
  }
  const secret = exactTotpSecret(Uint8Array.from(decoded));
  if (availableBits !== 0 || encodeTotpSecret(secret) !== value) {
    throw new TypeError("TOTP secret must use canonical Base32 without padding");
  }
  return secret;
}

export function generateTotpCode(secretValue: Uint8Array, unixSecondsValue: number): string {
  const secret = exactTotpSecret(secretValue);
  const unixSeconds = exactUnixSeconds(unixSecondsValue);
  const step = BigInt(Math.floor(unixSeconds / 30));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(step);
  const digest = createHmac("sha1", secret).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    (((digest[offset]! & 0x7f) << 24) |
      (digest[offset + 1]! << 16) |
      (digest[offset + 2]! << 8) |
      digest[offset + 3]!) >>>
    0;
  return String(binary % 1_000_000).padStart(6, "0");
}

export function generateTotpCodeFromBase32(encodedSecret: string, unixSeconds: number): string {
  const secret = decodeTotpSecret(encodedSecret);
  try {
    return generateTotpCode(secret, unixSeconds);
  } finally {
    secret.fill(0);
  }
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function exactKey(value: Uint8Array): Buffer {
  const key = Buffer.from(value);
  if (key.length !== 32) throw new RangeError("TOTP data-encryption keys must contain 32 bytes");
  return key;
}

function encryptionAad(input: {
  readonly organizationId: string;
  readonly memberId: string;
  readonly credentialId: string;
  readonly keyId: string;
}): Buffer {
  return Buffer.from(
    [
      "boardagent/totp/aes-256-gcm/v1",
      input.organizationId,
      input.memberId,
      input.credentialId,
      input.keyId
    ].join("\0"),
    "utf8"
  );
}

function encryptSecret(secret: Buffer, key: Buffer, nonce: Buffer, aad: Buffer): Buffer {
  if (nonce.length !== TOTP_NONCE_BYTES) {
    throw new RangeError("TOTP encryption nonce must contain 12 bytes");
  }
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
  return Buffer.concat([TOTP_CIPHERTEXT_MAGIC, nonce, ciphertext, cipher.getAuthTag()]);
}

function decryptSecret(ciphertext: Buffer, key: Buffer, aad: Buffer): Buffer {
  const expectedLength =
    TOTP_CIPHERTEXT_MAGIC.length + TOTP_NONCE_BYTES + TOTP_SECRET_BYTES + TOTP_TAG_BYTES;
  if (
    ciphertext.length !== expectedLength ||
    !timingSafeEqual(ciphertext.subarray(0, TOTP_CIPHERTEXT_MAGIC.length), TOTP_CIPHERTEXT_MAGIC)
  ) {
    throw new Error("TOTP ciphertext envelope is invalid");
  }
  const nonceStart = TOTP_CIPHERTEXT_MAGIC.length;
  const ciphertextStart = nonceStart + TOTP_NONCE_BYTES;
  const tagStart = ciphertextStart + TOTP_SECRET_BYTES;
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      ciphertext.subarray(nonceStart, ciphertextStart)
    );
    decipher.setAAD(aad);
    decipher.setAuthTag(ciphertext.subarray(tagStart));
    return exactTotpSecret(
      Buffer.concat([
        decipher.update(ciphertext.subarray(ciphertextStart, tagStart)),
        decipher.final()
      ])
    );
  } catch {
    throw new Error("TOTP ciphertext authentication failed");
  }
}

function matchingStep(secret: Buffer, submittedCode: string, currentStep: number): number | null {
  const submitted = Buffer.from(submittedCode, "ascii");
  let accepted: number | null = null;
  for (const offset of [-1, 0, 1]) {
    const step = currentStep + offset;
    const expected = Buffer.from(generateTotpCode(secret, step * TOTP_PERIOD_SECONDS), "ascii");
    const matches = timingSafeEqual(expected, submitted);
    if (matches && (accepted === null || step > accepted)) accepted = step;
  }
  return accepted;
}

function provisioningUri(issuer: string, fallbackHandle: string, secretBase32: string): string {
  const query = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: String(TOTP_PERIOD_SECONDS)
  });
  return (
    `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(fallbackHandle)}?` +
    query.toString()
  );
}

async function databaseClock(
  client: PoolClient
): Promise<{ readonly now: Date; readonly step: number }> {
  const result = await client.query<{ current_step: string; transaction_time: Date }>(
    `select floor(extract(epoch from transaction_timestamp())/$1)::bigint::text as current_step,
            transaction_timestamp() as transaction_time`,
    [TOTP_PERIOD_SECONDS]
  );
  const step = Number(result.rows[0]?.current_step);
  if (!Number.isSafeInteger(step) || step < 1) throw new Error("database TOTP clock is invalid");
  const now = result.rows[0]?.transaction_time;
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new Error("database TOTP clock is invalid");
  }
  return { now, step };
}

async function enrollmentAuthority(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly authorizedByMemberId: string;
    readonly keyId: string;
  }
): Promise<{ readonly authorized: boolean; readonly keyActive: boolean }> {
  const result = await client.query<{ authorized: boolean; key_active: boolean }>(
    `select
       exists(
         select 1
           from members as actor
           join organization_role_assignments as assignment
             on assignment.organization_id=actor.organization_id
            and assignment.member_id=actor.id
          where actor.organization_id=$1
            and actor.id=$3
            and actor.state='active'
            and assignment.role in ('secretariat','admin')
            and assignment.active_from<=transaction_timestamp()
            and (assignment.active_until is null
                 or assignment.active_until>transaction_timestamp())
       ) and exists(
         select 1 from members as target
          where target.organization_id=$1
            and target.id=$2
            and target.state in ('pending_activation','active')
       ) as authorized,
       exists(
         select 1 from crypto_key_registry as key
          where key.organization_id=$1
            and key.id=$4
            and key.purpose='data_kek'
            and key.algorithm='A256GCM'
            and key.activated_at<=transaction_timestamp()
            and key.retired_at is null
            and key.compromised_at is null
       ) as key_active`,
    [input.organizationId, input.memberId, input.authorizedByMemberId, input.keyId]
  );
  return {
    authorized: result.rows[0]?.authorized === true,
    keyActive: result.rows[0]?.key_active === true
  };
}

async function lockedCredential(
  client: PoolClient,
  organizationId: string,
  where: { readonly credentialId: string } | { readonly fallbackHandleSha256: Buffer }
): Promise<CredentialRow | null> {
  const byId = "credentialId" in where;
  const result = await client.query(
    `select credential.id,credential.member_id,credential.encrypted_secret,credential.key_id,
            credential.state,credential.failed_attempts,credential.locked_until,
            credential.last_accepted_step::text,member.state as member_state,
            key.retired_at as key_retired_at,key.compromised_at as key_compromised_at
       from totp_credentials as credential
       join members as member
         on member.organization_id=credential.organization_id
        and member.id=credential.member_id
       join crypto_key_registry as key
         on key.organization_id=credential.organization_id
        and key.id=credential.key_id
      where credential.organization_id=$1
        and ${byId ? "credential.id=$2" : "credential.fallback_handle_sha256=$2"}
        and credential.state=${byId ? "'pending_verification'" : "'active'"}
      for update of credential`,
    [organizationId, byId ? where.credentialId : where.fallbackHandleSha256]
  );
  if (result.rows.length === 0) return null;
  if (result.rows.length !== 1) throw new Error("TOTP credential lookup was not unique");
  return CredentialRowSchema.parse(result.rows[0]);
}

async function recordFailure(client: PoolClient, credentialId: string): Promise<void> {
  const updated = await client.query(
    `update totp_credentials
        set failed_attempts=least(
              case
                when locked_until is not null and locked_until<=transaction_timestamp() then 0
                else failed_attempts
              end+1,
              max_failed_attempts
            ),
            locked_until=case
              when case
                     when locked_until is not null
                          and locked_until<=transaction_timestamp() then 0
                     else failed_attempts
                   end+1>=max_failed_attempts
                then transaction_timestamp()+make_interval(secs=>lockout_seconds)
              else null
            end
      where id=$1`,
    [credentialId]
  );
  if (updated.rowCount !== 1) throw new Error("TOTP failure transition affected no credential");
}

function lockActive(row: CredentialRow, now: Date): boolean {
  return row.locked_until !== null && row.locked_until.getTime() > now.getTime();
}

export class PgTotpService implements TotpAuthenticator {
  private readonly issuer: string;
  private readonly activeKeyId: string;
  private readonly keys: ReadonlyMap<string, Buffer>;
  private readonly rateLimits: TotpRateLimitPolicies;
  private readonly maxFailedAttempts: number;
  private readonly lockoutSeconds: number;
  private readonly assumeRole: "boardagent_server" | undefined;
  private readonly rateLimiter: PgRateLimiter;
  private readonly newId: () => string;
  private readonly entropy: (size: number) => Buffer;

  public constructor(
    private readonly pool: Pool,
    options: PgTotpServiceOptions
  ) {
    this.issuer = z
      .string()
      .min(1)
      .max(128)
      .refine(
        (value) =>
          value === value.trim() &&
          [...value].every((character) => {
            const codePoint = character.codePointAt(0);
            return codePoint !== undefined && codePoint > 0x1f && codePoint !== 0x7f;
          })
      )
      .parse(options.issuer);
    this.activeKeyId = UuidV7Schema.parse(options.activeKeyId);
    const keys = new Map<string, Buffer>();
    for (const [keyIdValue, keyValue] of options.keys) {
      const keyId = UuidV7Schema.parse(keyIdValue);
      keys.set(keyId, exactKey(keyValue));
    }
    if (!keys.has(this.activeKeyId))
      throw new Error("active TOTP data-encryption key is unavailable");
    this.keys = keys;
    this.rateLimits = {
      ip: RatePolicySchema.parse(options.rateLimits.ip),
      client: RatePolicySchema.parse(options.rateLimits.client),
      member: RatePolicySchema.parse(options.rateLimits.member),
      token: RatePolicySchema.parse(options.rateLimits.token)
    };
    this.maxFailedAttempts = z.number().int().min(3).max(10).parse(options.maxFailedAttempts);
    this.lockoutSeconds = z.number().int().min(60).max(86_400).parse(options.lockoutSeconds);
    this.assumeRole = options.assumeRole;
    this.rateLimiter = options.rateLimiter;
    this.newId = options.newId ?? (() => uuidV7(Date.now(), nodeRandomBytes(10)));
    const randomSource = options.randomBytes ?? nodeRandomBytes;
    this.entropy = (size) => {
      const value = Buffer.from(randomSource(size));
      if (value.length !== size) throw new Error("TOTP entropy source returned the wrong length");
      return value;
    };
  }

  private key(keyId: string): Buffer {
    const key = this.keys.get(keyId);
    if (!key) throw new Error("TOTP data-encryption key is unavailable");
    return key;
  }

  private decrypt(row: CredentialRow, organizationId: string): Buffer {
    return decryptSecret(
      row.encrypted_secret,
      this.key(row.key_id),
      encryptionAad({
        organizationId,
        memberId: row.member_id,
        credentialId: row.id,
        keyId: row.key_id
      })
    );
  }

  private matchingStep(
    row: CredentialRow,
    organizationId: string,
    code: string,
    step: number
  ): number | null {
    const secret = this.decrypt(row, organizationId);
    try {
      return matchingStep(secret, code, step);
    } finally {
      secret.fill(0);
    }
  }

  public async beginEnrollment(inputValue: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly authorizedByMemberId: string;
  }): Promise<TotpEnrollmentResult> {
    const input = EnrollmentInputSchema.parse(inputValue);
    const credentialId = UuidV7Schema.parse(this.newId());
    const secret = exactTotpSecret(this.entropy(TOTP_SECRET_BYTES));
    try {
      const fallbackHandle = this.entropy(FALLBACK_HANDLE_BYTES).toString("base64url");
      if (!FALLBACK_HANDLE_PATTERN.test(fallbackHandle)) {
        throw new Error("TOTP fallback handle generation failed");
      }
      const encryptedSecret = encryptSecret(
        secret,
        this.key(this.activeKeyId),
        this.entropy(TOTP_NONCE_BYTES),
        encryptionAad({
          organizationId: input.organizationId,
          memberId: input.memberId,
          credentialId,
          keyId: this.activeKeyId
        })
      );

      await withIdentityTransaction<void>(
        this.pool,
        { organizationId: input.organizationId, boardIds: [] },
        async (client) => {
          const authority = await enrollmentAuthority(client, {
            ...input,
            keyId: this.activeKeyId
          });
          if (!authority.authorized) throw new TotpError("enrollment_not_authorized");
          if (!authority.keyActive)
            throw new Error("active TOTP data-encryption key is not registered");
          await client.query(
            `update totp_credentials
              set state='replaced',failed_attempts=0,locked_until=null,
                  terminal_at=transaction_timestamp()
            where organization_id=$1 and member_id=$2 and state='pending_verification'`,
            [input.organizationId, input.memberId]
          );
          await client.query(
            `insert into totp_credentials(
             id,organization_id,member_id,encrypted_secret,key_id,fallback_handle_sha256,
             authorized_by,state,max_failed_attempts,lockout_seconds
           ) values ($1,$2,$3,$4,$5,$6,$7,'pending_verification',$8,$9)`,
            [
              credentialId,
              input.organizationId,
              input.memberId,
              encryptedSecret,
              this.activeKeyId,
              sha256(fallbackHandle),
              input.authorizedByMemberId,
              this.maxFailedAttempts,
              this.lockoutSeconds
            ]
          );
        },
        this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole }
      );

      const secretBase32 = encodeTotpSecret(secret);
      return {
        credentialId,
        fallbackHandle,
        secretBase32,
        provisioningUri: provisioningUri(this.issuer, fallbackHandle, secretBase32)
      };
    } finally {
      secret.fill(0);
    }
  }

  public async completeEnrollment(inputValue: {
    readonly organizationId: string;
    readonly credentialId: string;
    readonly authorizedByMemberId: string;
    readonly code: string;
  }): Promise<void> {
    const input = EnrollmentCompletionSchema.parse(inputValue);
    const result = await withIdentityTransaction<"completed" | "invalid">(
      this.pool,
      { organizationId: input.organizationId, boardIds: [] },
      async (client): Promise<"completed" | "invalid"> => {
        const clock = await databaseClock(client);
        const row = await lockedCredential(client, input.organizationId, {
          credentialId: input.credentialId
        });
        if (!row || row.member_state === "suspended" || row.member_state === "removed") {
          matchingStep(Buffer.alloc(TOTP_SECRET_BYTES, 0x5a), input.code, clock.step);
          return "invalid";
        }
        const authority = await enrollmentAuthority(client, {
          organizationId: input.organizationId,
          memberId: row.member_id,
          authorizedByMemberId: input.authorizedByMemberId,
          keyId: row.key_id
        });
        if (!authority.authorized) throw new TotpError("enrollment_not_authorized");
        if (
          !authority.keyActive ||
          row.key_retired_at !== null ||
          row.key_compromised_at !== null
        ) {
          throw new Error("pending TOTP credential does not use an active encryption key");
        }
        if (lockActive(row, clock.now)) return "invalid";
        const acceptedStep = this.matchingStep(row, input.organizationId, input.code, clock.step);
        if (acceptedStep === null) {
          await recordFailure(client, row.id);
          return "invalid";
        }
        await client.query(
          `update totp_credentials
              set state='replaced',failed_attempts=0,locked_until=null,
                  terminal_at=transaction_timestamp()
            where organization_id=$1 and member_id=$2 and state='active' and id<>$3`,
          [input.organizationId, row.member_id, row.id]
        );
        const activated = await client.query(
          `update totp_credentials
              set state='active',failed_attempts=0,locked_until=null,
                  last_accepted_step=$2,activated_at=transaction_timestamp()
            where id=$1 and state='pending_verification'`,
          [row.id, acceptedStep]
        );
        if (activated.rowCount !== 1) throw new Error("TOTP activation affected no credential");
        return "completed";
      },
      this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole }
    );
    if (result === "invalid") throw new TotpError("invalid_enrollment");
  }

  public async authenticate(
    inputValue: TotpAuthenticationInput
  ): Promise<TotpAuthenticationResult> {
    let input: z.infer<typeof AuthenticationInputSchema>;
    try {
      input = AuthenticationInputSchema.parse(inputValue);
    } catch {
      throw new TotpError("invalid_totp");
    }
    const rateDecision = await this.rateLimiter.consumeIdentity(input.organizationId, [
      {
        bucketClass: "ip",
        trustedSubject: input.clientIpClass,
        ...this.rateLimits.ip
      },
      {
        bucketClass: "client",
        trustedSubject: input.clientId,
        ...this.rateLimits.client
      },
      {
        bucketClass: "member",
        trustedSubject: `totp-fallback:${input.fallbackHandle}`,
        ...this.rateLimits.member
      },
      {
        bucketClass: "token",
        trustedSubject: input.sessionId,
        ...this.rateLimits.token
      }
    ]);
    if (!rateDecision.allowed) {
      throw new TotpError("rate_limited", rateDecision.retryAfterSeconds);
    }

    const decision = await withIdentityTransaction<TotpAuthenticationResult | null>(
      this.pool,
      { organizationId: input.organizationId, boardIds: [] },
      async (client): Promise<TotpAuthenticationResult | null> => {
        const clock = await databaseClock(client);
        const row = await lockedCredential(client, input.organizationId, {
          fallbackHandleSha256: sha256(input.fallbackHandle)
        });
        if (!row) {
          matchingStep(Buffer.alloc(TOTP_SECRET_BYTES, 0x6b), input.code, clock.step);
          return null;
        }
        if (row.member_state !== "active") return null;
        if (row.key_compromised_at !== null) {
          await client.query(
            `update totp_credentials
                set state='compromised',failed_attempts=0,locked_until=null,
                    terminal_at=transaction_timestamp()
              where id=$1`,
            [row.id]
          );
          return null;
        }
        if (lockActive(row, clock.now)) return null;
        const acceptedStep = this.matchingStep(row, input.organizationId, input.code, clock.step);
        const lastAcceptedStep =
          row.last_accepted_step === null ? null : Number(row.last_accepted_step);
        if (
          acceptedStep === null ||
          (lastAcceptedStep !== null && acceptedStep <= lastAcceptedStep)
        ) {
          await recordFailure(client, row.id);
          return null;
        }
        const updated = await client.query(
          `update totp_credentials
              set last_accepted_step=$2,failed_attempts=0,locked_until=null
            where id=$1 and state='active'`,
          [row.id, acceptedStep]
        );
        if (updated.rowCount !== 1) throw new Error("TOTP success affected no credential");
        return {
          memberId: row.member_id,
          credentialId: row.id,
          acceptedStep
        };
      },
      this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole }
    );
    if (!decision) throw new TotpError("invalid_totp");
    return decision;
  }
}
