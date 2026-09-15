import { createHash, randomBytes } from "node:crypto";

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON
} from "@simplewebauthn/server";
import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";
import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";
import { uuidV7 } from "@boardagent/domain";

const CEREMONY_TTL_SECONDS = 5 * 60;
const BROWSER_TIMEOUT_MS = 60_000;

const ExactOriginSchema = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return (
      url.origin === value &&
      url.username === "" &&
      url.password === "" &&
      url.pathname === "/" &&
      url.search === "" &&
      url.hash === ""
    );
  }, "WebAuthn origin must be an exact origin");

const RpIdSchema = z
  .string()
  .min(1)
  .max(253)
  .refine((value) => {
    const url = new URL(`https://${value}`);
    return url.hostname === value && url.port === "" && !value.endsWith(".");
  }, "WebAuthn RP ID must be a canonical hostname");

const ChallengeSchema = z
  .string()
  .min(22)
  .max(1024)
  .regex(/^[A-Za-z0-9_-]+$/u);

const TransportSchema = z.enum(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);

export type WebAuthnChallengePurpose =
  "enrollment" | "authentication" | "recent_auth" | "recovery" | "activation_restart";

export interface WebAuthnChallengeRecord {
  readonly recoveryRequestId?: string;
  /** Session-less assertion bound to one live activation-restart handoff (ADR 0011 family). */
  readonly activationRestartGrantId?: string;
  readonly id: string;
  readonly organizationId: string;
  readonly sessionId: string | null;
  readonly memberId: string | null;
  readonly purpose: WebAuthnChallengePurpose;
  readonly challengeSha256: string;
  readonly rpId: string;
  readonly exactOrigin: string;
  readonly expiresAt: Date;
  readonly consumedAt: Date | null;
}

export interface WebAuthnCredentialRecord {
  readonly id: string;
  readonly organizationId: string;
  readonly memberId: string;
  readonly credentialId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly counter: number;
  readonly transports: readonly AuthenticatorTransportFuture[];
  readonly backupEligible: boolean;
  readonly backupState: boolean;
  readonly state: "active" | "suspect" | "revoked";
}

export interface WebAuthnEnrollmentCommit {
  readonly invitationTokenSha256: string;
  readonly activationChallengeId: string;
  readonly activationCodeSha256: string;
  readonly proofingMethod: "in_person" | "verified_number_call";
  readonly auditEventId: string;
}

export interface CompleteWebAuthnRegistrationInput {
  readonly organizationId: string;
  readonly challengeId: string;
  readonly expectedChallengeSha256: string;
  readonly credential: WebAuthnCredentialRecord;
  readonly enrollment?: WebAuthnEnrollmentCommit;
  readonly recovery?: {
    readonly tokenSha256: string;
    readonly recoveryRequestId: string;
    readonly auditEventId: string;
    readonly activationChallengeId: string;
    readonly activationCodeSha256: string;
  };
}

export interface CompleteWebAuthnAuthenticationInput {
  readonly organizationId: string;
  readonly challengeId: string;
  readonly expectedChallengeSha256: string;
  readonly credentialId: string;
  readonly expectedCounter: number;
  readonly expectedBackupEligible: boolean;
  readonly newCounter: number;
  readonly newBackupState: boolean;
  readonly onboarding?: WebAuthnOnboardingCommit;
  readonly activationRestart?: WebAuthnActivationRestartCommit;
}

/**
 * Commit block for the pending-activation restart: after the person re-proves with their
 * already-registered passkey, the store mints the fresh ten-minute activation challenge
 * and consumes the one-use handoff in the same transaction.
 */
export interface WebAuthnActivationRestartCommit {
  readonly organizationId: string;
  readonly memberId: string;
  readonly grantId: string;
  readonly tokenSha256: string;
  readonly freshChallengeId: string;
  readonly activationCodeSha256: string;
  readonly auditEventId: string;
}

export interface WebAuthnOnboardingCommit {
  readonly organizationId: string;
  readonly boardId: string;
  readonly memberId: string;
  readonly sessionId: string;
  readonly stageId: string;
  readonly stageTokenSha256: string;
  readonly attestationId: string;
  readonly auditEventId: string;
  readonly tombstoneId: string;
}

export interface WebAuthnStore {
  saveChallenge(challenge: WebAuthnChallengeRecord): Promise<void>;
  findChallengeBySha256(
    organizationId: string,
    challengeSha256: string
  ): Promise<WebAuthnChallengeRecord | null>;
  listActiveCredentials(
    organizationId: string,
    memberId: string
  ): Promise<readonly WebAuthnCredentialRecord[]>;
  findActiveCredentialByRawId(
    organizationId: string,
    credentialId: Uint8Array,
    options?: { readonly memberState?: "active" | "pending_activation" }
  ): Promise<WebAuthnCredentialRecord | null>;
  completeRegistration(input: CompleteWebAuthnRegistrationInput): Promise<boolean>;
  completeAuthentication(input: CompleteWebAuthnAuthenticationInput): Promise<boolean>;
}

export interface WebAuthnCrypto {
  readonly generateRegistrationOptions: typeof generateRegistrationOptions;
  readonly verifyRegistrationResponse: typeof verifyRegistrationResponse;
  readonly generateAuthenticationOptions: typeof generateAuthenticationOptions;
  readonly verifyAuthenticationResponse: typeof verifyAuthenticationResponse;
  readonly decodeClientDataJSON: typeof decodeClientDataJSON;
}

export type WebAuthnAttemptOperation =
  | "registration_begin"
  | "registration_complete"
  | "authentication_begin"
  | "authentication_complete";

export interface WebAuthnAttemptContext {
  readonly organizationId: string;
  readonly memberId: string | null;
  readonly sessionId: string | null;
  readonly purpose: WebAuthnChallengePurpose;
  readonly operation: WebAuthnAttemptOperation;
}

export interface WebAuthnAttemptLimiter {
  consume(context: WebAuthnAttemptContext): Promise<{
    readonly allowed: boolean;
    readonly retryAfterSeconds: number;
  }>;
}

export interface WebAuthnCeremonyOptions {
  readonly rpName: string;
  readonly rpId: string;
  readonly origin: string;
  readonly store: WebAuthnStore;
  readonly attemptLimiter: WebAuthnAttemptLimiter;
  readonly crypto?: WebAuthnCrypto;
  readonly now?: () => Date;
  readonly newId?: () => string;
  /** Explicit localhost-only seam for a local browser/virtual-authenticator run. */
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface BeginRegistrationInput {
  readonly recoveryRequestId?: string;
  readonly organizationId: string;
  readonly memberId: string;
  readonly sessionId: string | null;
  readonly purpose: "enrollment" | "recovery";
  readonly userName: string;
  readonly displayName: string;
}

export interface BeginAuthenticationInput {
  readonly organizationId: string;
  readonly memberId: string | null;
  /** Null only for the session-less `activation_restart` purpose. */
  readonly sessionId: string | null;
  readonly purpose: "authentication" | "recent_auth" | "activation_restart";
  readonly activationRestartGrantId?: string;
}

export interface CompleteRegistrationInput {
  readonly organizationId: string;
  readonly memberId: string;
  readonly sessionId: string | null;
  readonly purpose: "enrollment" | "recovery";
  readonly response: RegistrationResponseJSON;
  readonly enrollment?: WebAuthnEnrollmentCommit;
  readonly recovery?: {
    readonly tokenSha256: string;
    readonly recoveryRequestId: string;
    readonly auditEventId: string;
    readonly activationChallengeId: string;
    readonly activationCodeSha256: string;
  };
}

export interface CompleteAuthenticationInput {
  readonly organizationId: string;
  /** Null only for the session-less `activation_restart` purpose. */
  readonly sessionId: string | null;
  readonly purpose: "authentication" | "recent_auth" | "activation_restart";
  readonly response: AuthenticationResponseJSON;
  readonly onboarding?: WebAuthnOnboardingCommit;
  readonly activationRestart?: WebAuthnActivationRestartCommit;
}

export interface WebAuthnAuthenticationResult {
  readonly memberId: string;
  readonly sessionId: string | null;
  readonly credentialId: string;
  readonly newCounter: number;
  readonly backupState: boolean;
}

export class WebAuthnCeremonyError extends Error {
  public constructor(
    public readonly code:
      | "challenge_unavailable"
      | "credential_unavailable"
      | "verification_failed"
      | "credential_policy_violation"
      | "ceremony_replayed"
      | "rate_limited",
    message: string,
    public readonly retryAfterSeconds: number | null = null
  ) {
    super(message);
    this.name = "WebAuthnCeremonyError";
  }
}

const defaultCrypto: WebAuthnCrypto = {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  decodeClientDataJSON
};

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function uuidBytes(value: string): Uint8Array<ArrayBuffer> {
  const parsed = Buffer.from(UuidV7Schema.parse(value).replaceAll("-", ""), "hex");
  const bytes = new Uint8Array(parsed.length);
  bytes.set(parsed);
  return bytes;
}

function canonicalBase64Url(value: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new WebAuthnCeremonyError("verification_failed", `${label} is not canonical base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== value) {
    throw new WebAuthnCeremonyError("verification_failed", `${label} is not canonical base64url`);
  }
  return decoded;
}

function credentialPublicId(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function normalizedTransports(
  values: readonly AuthenticatorTransportFuture[] | undefined
): AuthenticatorTransportFuture[] {
  return [...new Set((values ?? []).map((value) => TransportSchema.parse(value)))].toSorted();
}

function usableChallenge(
  challenge: WebAuthnChallengeRecord | null,
  expected: {
    readonly organizationId: string;
    readonly memberId: string | null;
    readonly sessionId: string | null;
    readonly purpose: WebAuthnChallengePurpose;
    readonly rpId: string;
    readonly origin: string;
  },
  now: Date
): WebAuthnChallengeRecord {
  if (
    !challenge ||
    challenge.organizationId !== expected.organizationId ||
    challenge.memberId !== expected.memberId ||
    challenge.sessionId !== expected.sessionId ||
    challenge.purpose !== expected.purpose ||
    challenge.rpId !== expected.rpId ||
    challenge.exactOrigin !== expected.origin ||
    challenge.consumedAt !== null ||
    challenge.expiresAt.getTime() <= now.getTime()
  ) {
    throw new WebAuthnCeremonyError("challenge_unavailable", "WebAuthn challenge is unavailable");
  }
  return challenge;
}

/** Every assertion purpose binds a session except the one-use activation restart handoff. */
function authenticationSessionId(
  purpose: "authentication" | "recent_auth" | "activation_restart",
  sessionId: string | null
): string | null {
  if (purpose === "activation_restart") {
    if (sessionId !== null) {
      throw new WebAuthnCeremonyError("challenge_unavailable", "restart is session-less");
    }
    return null;
  }
  return UuidV7Schema.parse(sessionId);
}

function registrationChallenge(response: RegistrationResponseJSON, crypto: WebAuthnCrypto): string {
  try {
    const decoded = crypto.decodeClientDataJSON(response.response.clientDataJSON);
    if (decoded.crossOrigin === true) {
      throw new Error("cross-origin ceremony");
    }
    return ChallengeSchema.parse(decoded.challenge);
  } catch {
    throw new WebAuthnCeremonyError(
      "verification_failed",
      "WebAuthn registration client data is invalid"
    );
  }
}

function authenticationChallenge(
  response: AuthenticationResponseJSON,
  crypto: WebAuthnCrypto
): string {
  try {
    const decoded = crypto.decodeClientDataJSON(response.response.clientDataJSON);
    if (decoded.crossOrigin === true) {
      throw new Error("cross-origin ceremony");
    }
    return ChallengeSchema.parse(decoded.challenge);
  } catch {
    throw new WebAuthnCeremonyError(
      "verification_failed",
      "WebAuthn authentication client data is invalid"
    );
  }
}

export class WebAuthnCeremony {
  private readonly rpName: string;
  private readonly rpId: string;
  private readonly origin: string;
  private readonly store: WebAuthnStore;
  private readonly attemptLimiter: WebAuthnAttemptLimiter;
  private readonly crypto: WebAuthnCrypto;
  private readonly now: () => Date;
  private readonly newId: () => string;

  public constructor(options: WebAuthnCeremonyOptions) {
    this.rpName = z.string().min(1).max(128).parse(options.rpName);
    this.rpId = RpIdSchema.parse(options.rpId);
    this.origin = ExactOriginSchema.parse(options.origin);
    const origin = new URL(this.origin);
    if (
      origin.protocol !== "https:" &&
      !(
        options.allowInsecureLoopbackDevelopment === true &&
        origin.protocol === "http:" &&
        origin.hostname === "localhost" &&
        this.rpId === "localhost"
      )
    ) {
      throw new Error("WebAuthn origin must be an exact HTTPS origin");
    }
    if (origin.hostname !== this.rpId) {
      throw new Error("WebAuthn RP ID must exactly match the configured origin hostname");
    }
    this.store = options.store;
    this.attemptLimiter = options.attemptLimiter;
    this.crypto = options.crypto ?? defaultCrypto;
    this.now = options.now ?? (() => new Date());
    this.newId = options.newId ?? (() => uuidV7(this.now().getTime(), randomBytes(10)));
  }

  private async consumeAttempt(context: WebAuthnAttemptContext): Promise<void> {
    const decision = z
      .object({
        allowed: z.boolean(),
        retryAfterSeconds: z.number().int().min(0).max(86_400)
      })
      .strict()
      .parse(await this.attemptLimiter.consume(context));
    if (!decision.allowed) {
      throw new WebAuthnCeremonyError(
        "rate_limited",
        "WebAuthn request is temporarily unavailable",
        Math.max(1, decision.retryAfterSeconds)
      );
    }
  }

  public async beginRegistration(
    input: BeginRegistrationInput
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const memberId = UuidV7Schema.parse(input.memberId);
    const sessionId = input.sessionId === null ? null : UuidV7Schema.parse(input.sessionId);
    await this.consumeAttempt({
      organizationId,
      memberId,
      sessionId,
      purpose: input.purpose,
      operation: "registration_begin"
    });
    const existing = await this.store.listActiveCredentials(organizationId, memberId);
    const options = await this.crypto.generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpId,
      userName: z.string().min(1).max(256).parse(input.userName),
      userID: uuidBytes(memberId),
      userDisplayName: z.string().min(1).max(256).parse(input.displayName),
      timeout: BROWSER_TIMEOUT_MS,
      attestationType: "none",
      excludeCredentials: existing.map((credential) => ({
        id: credentialPublicId(credential.credentialId),
        ...(credential.transports.length === 0 ? {} : { transports: [...credential.transports] })
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required"
      }
    });
    const challenge = ChallengeSchema.parse(options.challenge);
    const issuedAt = this.now();
    await this.store.saveChallenge({
      id: UuidV7Schema.parse(this.newId()),
      organizationId,
      sessionId,
      memberId,
      purpose: input.purpose,
      ...(input.recoveryRequestId === undefined
        ? {}
        : { recoveryRequestId: UuidV7Schema.parse(input.recoveryRequestId) }),
      challengeSha256: sha256(challenge),
      rpId: this.rpId,
      exactOrigin: this.origin,
      expiresAt: new Date(issuedAt.getTime() + CEREMONY_TTL_SECONDS * 1000),
      consumedAt: null
    });
    return options;
  }

  public async completeRegistration(
    input: CompleteRegistrationInput
  ): Promise<WebAuthnCredentialRecord> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const memberId = UuidV7Schema.parse(input.memberId);
    const sessionId = input.sessionId === null ? null : UuidV7Schema.parse(input.sessionId);
    await this.consumeAttempt({
      organizationId,
      memberId,
      sessionId,
      purpose: input.purpose,
      operation: "registration_complete"
    });
    const challengeValue = registrationChallenge(input.response, this.crypto);
    const challenge = usableChallenge(
      await this.store.findChallengeBySha256(organizationId, sha256(challengeValue)),
      {
        organizationId,
        memberId,
        sessionId,
        purpose: input.purpose,
        rpId: this.rpId,
        origin: this.origin
      },
      this.now()
    );
    let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    try {
      verified = await this.crypto.verifyRegistrationResponse({
        response: input.response,
        expectedChallenge: challengeValue,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        expectedType: "webauthn.create",
        requireUserPresence: true,
        requireUserVerification: true
      });
    } catch {
      throw new WebAuthnCeremonyError(
        "verification_failed",
        "WebAuthn registration verification failed"
      );
    }
    if (!verified.verified || !verified.registrationInfo.userVerified) {
      throw new WebAuthnCeremonyError(
        "verification_failed",
        "WebAuthn registration did not verify user presence and verification"
      );
    }
    const { credential, credentialBackedUp, credentialDeviceType } = verified.registrationInfo;
    const backupEligible = credentialDeviceType === "multiDevice";
    if (!backupEligible && credentialBackedUp) {
      throw new WebAuthnCeremonyError(
        "credential_policy_violation",
        "single-device credentials cannot report a backed-up state"
      );
    }
    const rawCredentialId = canonicalBase64Url(credential.id, "credential ID");
    if (rawCredentialId.length < 16 || rawCredentialId.length > 1024) {
      throw new WebAuthnCeremonyError(
        "credential_policy_violation",
        "credential ID length is outside the accepted range"
      );
    }
    if (credential.publicKey.length < 32 || credential.publicKey.length > 4096) {
      throw new WebAuthnCeremonyError(
        "credential_policy_violation",
        "credential public key length is outside the accepted range"
      );
    }
    const record: WebAuthnCredentialRecord = {
      id: UuidV7Schema.parse(this.newId()),
      organizationId,
      memberId,
      credentialId: rawCredentialId,
      publicKey: Uint8Array.from(credential.publicKey),
      counter: z.number().int().min(0).max(4_294_967_295).parse(credential.counter),
      transports: normalizedTransports(input.response.response.transports),
      backupEligible,
      backupState: credentialBackedUp,
      state: "active"
    };
    if (
      !(await this.store.completeRegistration({
        organizationId,
        challengeId: challenge.id,
        expectedChallengeSha256: challenge.challengeSha256,
        credential: record,
        ...(input.enrollment === undefined ? {} : { enrollment: input.enrollment }),
        ...(input.recovery === undefined ? {} : { recovery: input.recovery })
      }))
    ) {
      throw new WebAuthnCeremonyError("ceremony_replayed", "WebAuthn registration was replayed");
    }
    return record;
  }

  public async beginAuthentication(
    input: BeginAuthenticationInput
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const memberId = input.memberId === null ? null : UuidV7Schema.parse(input.memberId);
    const sessionId = authenticationSessionId(input.purpose, input.sessionId);
    const activationRestartGrantId =
      input.purpose === "activation_restart"
        ? UuidV7Schema.parse(input.activationRestartGrantId)
        : undefined;
    if (input.purpose === "activation_restart" && memberId === null) {
      throw new WebAuthnCeremonyError("challenge_unavailable", "restart requires the member");
    }
    if (input.purpose !== "activation_restart" && input.activationRestartGrantId !== undefined) {
      throw new WebAuthnCeremonyError("challenge_unavailable", "restart grant is out of place");
    }
    await this.consumeAttempt({
      organizationId,
      memberId,
      sessionId,
      purpose: input.purpose,
      operation: "authentication_begin"
    });
    const credentials =
      memberId === null ? [] : await this.store.listActiveCredentials(organizationId, memberId);
    const options = await this.crypto.generateAuthenticationOptions({
      rpID: this.rpId,
      timeout: BROWSER_TIMEOUT_MS,
      userVerification: "required",
      ...(memberId === null
        ? {}
        : {
            allowCredentials: credentials.map((credential) => ({
              id: credentialPublicId(credential.credentialId),
              ...(credential.transports.length === 0
                ? {}
                : { transports: [...credential.transports] })
            }))
          })
    });
    const challenge = ChallengeSchema.parse(options.challenge);
    const issuedAt = this.now();
    await this.store.saveChallenge({
      id: UuidV7Schema.parse(this.newId()),
      organizationId,
      sessionId,
      memberId,
      purpose: input.purpose,
      challengeSha256: sha256(challenge),
      rpId: this.rpId,
      exactOrigin: this.origin,
      expiresAt: new Date(issuedAt.getTime() + CEREMONY_TTL_SECONDS * 1000),
      consumedAt: null,
      ...(activationRestartGrantId === undefined ? {} : { activationRestartGrantId })
    });
    return options;
  }

  public async completeAuthentication(
    input: CompleteAuthenticationInput
  ): Promise<WebAuthnAuthenticationResult> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const sessionId = authenticationSessionId(input.purpose, input.sessionId);
    if ((input.activationRestart !== undefined) !== (input.purpose === "activation_restart")) {
      throw new WebAuthnCeremonyError(
        "challenge_unavailable",
        "restart commit must accompany exactly the restart purpose"
      );
    }
    await this.consumeAttempt({
      organizationId,
      // The session-less restart names its member up front; every other assertion is
      // attributed only after the credential is verified.
      memberId:
        input.activationRestart === undefined
          ? null
          : UuidV7Schema.parse(input.activationRestart.memberId),
      sessionId,
      purpose: input.purpose,
      operation: "authentication_complete"
    });
    const challengeValue = authenticationChallenge(input.response, this.crypto);
    const challengeLookup = await this.store.findChallengeBySha256(
      organizationId,
      sha256(challengeValue)
    );
    const challenge = usableChallenge(
      challengeLookup,
      {
        organizationId,
        memberId: challengeLookup?.memberId ?? null,
        sessionId,
        purpose: input.purpose,
        rpId: this.rpId,
        origin: this.origin
      },
      this.now()
    );
    if (input.response.id !== input.response.rawId) {
      throw new WebAuthnCeremonyError("verification_failed", "credential ID and raw ID differ");
    }
    const rawCredentialId = canonicalBase64Url(input.response.rawId, "credential ID");
    // The activation restart re-proves a member who is still pending activation; every
    // other assertion belongs to an active member.
    const credential = await this.store.findActiveCredentialByRawId(
      organizationId,
      rawCredentialId,
      input.activationRestart === undefined ? {} : { memberState: "pending_activation" }
    );
    if (
      !credential ||
      (challenge.memberId !== null && challenge.memberId !== credential.memberId)
    ) {
      throw new WebAuthnCeremonyError(
        "credential_unavailable",
        "WebAuthn credential is unavailable"
      );
    }
    let verified: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
    try {
      verified = await this.crypto.verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge: challengeValue,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        expectedType: "webauthn.get",
        requireUserVerification: true,
        credential: {
          id: credentialPublicId(credential.credentialId),
          publicKey: Uint8Array.from(credential.publicKey),
          counter: credential.counter,
          ...(credential.transports.length === 0 ? {} : { transports: [...credential.transports] })
        }
      });
    } catch {
      throw new WebAuthnCeremonyError(
        "verification_failed",
        "WebAuthn authentication verification failed"
      );
    }
    if (!verified.verified || !verified.authenticationInfo.userVerified) {
      throw new WebAuthnCeremonyError(
        "verification_failed",
        "WebAuthn authentication did not verify user presence and verification"
      );
    }
    const backupEligible = verified.authenticationInfo.credentialDeviceType === "multiDevice";
    if (
      backupEligible !== credential.backupEligible ||
      (!backupEligible && verified.authenticationInfo.credentialBackedUp)
    ) {
      throw new WebAuthnCeremonyError(
        "credential_policy_violation",
        "credential backup eligibility changed"
      );
    }
    const newCounter = z
      .number()
      .int()
      .min(0)
      .max(4_294_967_295)
      .parse(verified.authenticationInfo.newCounter);
    if (
      !(await this.store.completeAuthentication({
        organizationId,
        challengeId: challenge.id,
        expectedChallengeSha256: challenge.challengeSha256,
        credentialId: credential.id,
        expectedCounter: credential.counter,
        expectedBackupEligible: credential.backupEligible,
        newCounter,
        newBackupState: verified.authenticationInfo.credentialBackedUp,
        ...(input.onboarding === undefined ? {} : { onboarding: input.onboarding }),
        ...(input.activationRestart === undefined
          ? {}
          : { activationRestart: input.activationRestart })
      }))
    ) {
      throw new WebAuthnCeremonyError(
        "ceremony_replayed",
        "WebAuthn authentication was replayed or raced"
      );
    }
    return {
      memberId: credential.memberId,
      sessionId,
      credentialId: credential.id,
      newCounter,
      backupState: verified.authenticationInfo.credentialBackedUp
    };
  }
}
