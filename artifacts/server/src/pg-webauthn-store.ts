import { createHash } from "node:crypto";
import { z } from "zod";
import type { Pool, PoolClient } from "pg";

import { Sha256HexSchema, UuidV7Schema } from "@boardagent/contracts";
import {
  appendAuditEventsInTransaction,
  completeActivationRestartInTransaction,
  completeBuiltinEnrollmentInTransaction,
  completeOnboardingAttestationInTransaction,
  withIdentityTransaction
} from "@boardagent/db";

import type {
  CompleteWebAuthnAuthenticationInput,
  CompleteWebAuthnRegistrationInput,
  WebAuthnChallengeRecord,
  WebAuthnCredentialRecord,
  WebAuthnStore
} from "./webauthn.js";

const CounterSchema = z.number().int().min(0).max(4_294_967_295);
const TransportSchema = z.enum(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);

const ChallengeRowSchema = z
  .object({
    id: UuidV7Schema,
    organization_id: UuidV7Schema,
    session_id: UuidV7Schema.nullable(),
    member_id: UuidV7Schema.nullable(),
    purpose: z.enum([
      "enrollment",
      "authentication",
      "recent_auth",
      "recovery",
      "activation_restart"
    ]),
    challenge_sha256: Sha256HexSchema,
    rp_id: z.string().min(1).max(253),
    exact_origin: z.url(),
    expires_at: z.date(),
    consumed_at: z.date().nullable()
  })
  .strict();

const CredentialRowSchema = z
  .object({
    id: UuidV7Schema,
    organization_id: UuidV7Schema,
    member_id: UuidV7Schema,
    credential_id: z.instanceof(Buffer),
    public_key: z.instanceof(Buffer),
    signature_counter: z.string().regex(/^\d+$/u),
    transports: z.array(TransportSchema).max(16),
    backup_eligible: z.boolean(),
    backup_state: z.boolean(),
    state: z.enum(["active", "suspect", "revoked"])
  })
  .strict();

interface ChallengeRow {
  readonly id: string;
  readonly organization_id: string;
  readonly session_id: string | null;
  readonly member_id: string | null;
  readonly purpose: string;
  readonly challenge_sha256: string;
  readonly rp_id: string;
  readonly exact_origin: string;
  readonly expires_at: Date;
  readonly consumed_at: Date | null;
}

interface CredentialRow {
  readonly id: string;
  readonly organization_id: string;
  readonly member_id: string;
  readonly credential_id: Buffer;
  readonly public_key: Buffer;
  readonly signature_counter: string;
  readonly transports: string[];
  readonly backup_eligible: boolean;
  readonly backup_state: boolean;
  readonly state: string;
}

interface LockedChallengeRow {
  readonly member_id: string | null;
}

interface LockedCredentialRow {
  readonly member_id: string;
  readonly signature_counter: string;
  readonly backup_eligible: boolean;
}

function safeCounter(value: string | number): number {
  const counter = CounterSchema.parse(typeof value === "number" ? value : Number(value));
  if (!Number.isSafeInteger(counter)) throw new Error("WebAuthn counter is out of range");
  return counter;
}

function digestBytes(value: string): Buffer {
  return Buffer.from(Sha256HexSchema.parse(value), "hex");
}

function credentialBytes(value: Uint8Array): Buffer {
  const parsed = Buffer.from(value);
  if (parsed.length < 16 || parsed.length > 1024) {
    throw new RangeError("WebAuthn credential ID length is outside the accepted range");
  }
  return parsed;
}

function publicKeyBytes(value: Uint8Array): Buffer {
  const parsed = Buffer.from(value);
  if (parsed.length < 32 || parsed.length > 4096) {
    throw new RangeError("WebAuthn public key length is outside the accepted range");
  }
  return parsed;
}

function challengeRecord(rowValue: ChallengeRow): WebAuthnChallengeRecord {
  const row = ChallengeRowSchema.parse(rowValue);
  return {
    id: row.id,
    organizationId: row.organization_id,
    sessionId: row.session_id,
    memberId: row.member_id,
    purpose: row.purpose,
    challengeSha256: row.challenge_sha256,
    rpId: row.rp_id,
    exactOrigin: row.exact_origin,
    expiresAt: row.expires_at,
    consumedAt: row.consumed_at
  };
}

function credentialRecord(rowValue: CredentialRow): WebAuthnCredentialRecord {
  const row = CredentialRowSchema.parse(rowValue);
  return {
    id: row.id,
    organizationId: row.organization_id,
    memberId: row.member_id,
    credentialId: Uint8Array.from(row.credential_id),
    publicKey: Uint8Array.from(row.public_key),
    counter: safeCounter(row.signature_counter),
    transports: row.transports,
    backupEligible: row.backup_eligible,
    backupState: row.backup_state,
    state: row.state
  };
}

const CHALLENGE_PROJECTION = `id,organization_id,session_id,member_id,purpose,
  encode(challenge_sha256,'hex') as challenge_sha256,rp_id,exact_origin,expires_at,consumed_at`;
const CREDENTIAL_PROJECTION = `id,organization_id,member_id,credential_id,public_key,
  signature_counter::text,transports,backup_eligible,backup_state,state`;

export class PgWebAuthnStore implements WebAuthnStore {
  public constructor(
    private readonly pool: Pool,
    private readonly options: {
      /** Test/bootstrap seam only. Production pools connect through scoped credentials. */
      readonly assumeRole?: "boardagent_server";
    } = {}
  ) {}

  private async identity<T>(
    organizationId: string,
    run: (client: PoolClient) => Promise<T>,
    boardIds: readonly string[] = []
  ): Promise<T> {
    return withIdentityTransaction(
      this.pool,
      { organizationId: UuidV7Schema.parse(organizationId), boardIds },
      run,
      this.options
    );
  }

  public async saveChallenge(challenge: WebAuthnChallengeRecord): Promise<void> {
    const organizationId = UuidV7Schema.parse(challenge.organizationId);
    const id = UuidV7Schema.parse(challenge.id);
    const sessionId = challenge.sessionId === null ? null : UuidV7Schema.parse(challenge.sessionId);
    const memberId = challenge.memberId === null ? null : UuidV7Schema.parse(challenge.memberId);
    const purpose = z
      .enum(["enrollment", "authentication", "recent_auth", "recovery", "activation_restart"])
      .parse(challenge.purpose);
    const activationRestartGrantId =
      challenge.activationRestartGrantId === undefined
        ? null
        : UuidV7Schema.parse(challenge.activationRestartGrantId);
    if ((activationRestartGrantId !== null) !== (purpose === "activation_restart")) {
      throw new Error("an activation-restart challenge must bind exactly one grant");
    }
    if (purpose === "activation_restart" && (sessionId !== null || memberId === null)) {
      throw new Error("an activation-restart challenge is session-less and member-bound");
    }
    const rpId = z.string().min(1).max(253).parse(challenge.rpId);
    const exactOrigin = z.url().parse(challenge.exactOrigin);
    const expiresAt = z.date().parse(challenge.expiresAt);
    if (challenge.consumedAt !== null) {
      throw new Error("a new WebAuthn challenge cannot already be consumed");
    }
    await this.identity(organizationId, async (client) => {
      await client.query(
        `insert into webauthn_challenges(
           id,organization_id,challenge_sha256,session_id,member_id,purpose,rp_id,exact_origin,expires_at,recovery_request_id,activation_restart_grant_id
         ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          id,
          organizationId,
          digestBytes(challenge.challengeSha256),
          sessionId,
          memberId,
          purpose,
          rpId,
          exactOrigin,
          expiresAt,
          challenge.recoveryRequestId === undefined
            ? null
            : UuidV7Schema.parse(challenge.recoveryRequestId),
          activationRestartGrantId
        ]
      );
    });
  }

  public async findChallengeBySha256(
    organizationIdValue: string,
    challengeSha256: string
  ): Promise<WebAuthnChallengeRecord | null> {
    const organizationId = UuidV7Schema.parse(organizationIdValue);
    return this.identity(organizationId, async (client) => {
      const result = await client.query<ChallengeRow>(
        `select ${CHALLENGE_PROJECTION}
           from webauthn_challenges
          where organization_id=$1 and challenge_sha256=$2`,
        [organizationId, digestBytes(challengeSha256)]
      );
      if (result.rows.length === 0) return null;
      if (result.rows.length !== 1) throw new Error("WebAuthn challenge hash is not unique");
      return challengeRecord(result.rows[0]!);
    });
  }

  public async listActiveCredentials(
    organizationIdValue: string,
    memberIdValue: string
  ): Promise<readonly WebAuthnCredentialRecord[]> {
    const organizationId = UuidV7Schema.parse(organizationIdValue);
    const memberId = UuidV7Schema.parse(memberIdValue);
    return this.identity(organizationId, async (client) => {
      const result = await client.query<CredentialRow>(
        `select ${CREDENTIAL_PROJECTION}
           from webauthn_credentials
          where organization_id=$1 and member_id=$2 and state='active'
          order by id`,
        [organizationId, memberId]
      );
      return result.rows.map(credentialRecord);
    });
  }

  public async findActiveCredentialByRawId(
    organizationIdValue: string,
    credentialIdValue: Uint8Array,
    options: { readonly memberState?: "active" | "pending_activation" } = {}
  ): Promise<WebAuthnCredentialRecord | null> {
    const organizationId = UuidV7Schema.parse(organizationIdValue);
    const credentialId = credentialBytes(credentialIdValue);
    // Only the activation restart asserts for a member who is still pending activation.
    const memberState = z
      .enum(["active", "pending_activation"])
      .parse(options.memberState ?? "active");
    return this.identity(organizationId, async (client) => {
      const result = await client.query<CredentialRow>(
        `select ${CREDENTIAL_PROJECTION}
           from webauthn_credentials
          where organization_id=$1 and credential_id=$2 and state='active'
            and exists (
              select 1 from members as member
               where member.id=webauthn_credentials.member_id
                 and member.organization_id=webauthn_credentials.organization_id
                 and member.state=$3
            )`,
        [organizationId, credentialId, memberState]
      );
      if (result.rows.length === 0) return null;
      if (result.rows.length !== 1) throw new Error("WebAuthn credential ID is not unique");
      return credentialRecord(result.rows[0]!);
    });
  }

  public async completeRegistration(input: CompleteWebAuthnRegistrationInput): Promise<boolean> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const challengeId = UuidV7Schema.parse(input.challengeId);
    const expectedChallengeSha256 = digestBytes(input.expectedChallengeSha256);
    const credential = input.credential;
    if (
      UuidV7Schema.parse(credential.organizationId) !== organizationId ||
      credential.state !== "active"
    ) {
      return false;
    }
    const credentialId = UuidV7Schema.parse(credential.id);
    const memberId = UuidV7Schema.parse(credential.memberId);
    const counter = CounterSchema.parse(credential.counter);
    const transports = [
      ...new Set(credential.transports.map((value) => TransportSchema.parse(value)))
    ].toSorted();
    if (!credential.backupEligible && credential.backupState) return false;
    if (input.enrollment !== undefined && input.recovery !== undefined) return false;
    return this.identity(organizationId, async (client) => {
      if (input.enrollment !== undefined) {
        const result = await completeBuiltinEnrollmentInTransaction(client, {
          organizationId,
          memberId,
          invitationTokenSha256: input.enrollment.invitationTokenSha256,
          webauthnChallengeId: challengeId,
          expectedChallengeSha256: input.expectedChallengeSha256,
          credentialId,
          rawCredentialId: credentialBytes(credential.credentialId),
          publicKey: publicKeyBytes(credential.publicKey),
          signatureCounter: counter,
          transports,
          backupEligible: credential.backupEligible,
          backupState: credential.backupState,
          activationChallengeId: input.enrollment.activationChallengeId,
          activationCodeSha256: input.enrollment.activationCodeSha256,
          proofingMethod: input.enrollment.proofingMethod,
          auditEventId: input.enrollment.auditEventId
        });
        return result.completed;
      }
      if (input.recovery !== undefined) {
        const tokenHash = digestBytes(input.recovery.tokenSha256);
        const candidate = (
          await client.query(
            "select boardagent_prepare_recovery_registration($1,$2,$3) as candidate",
            [tokenHash, challengeId, expectedChallengeSha256]
          )
        ).rows[0]?.candidate as { recoveryRequestId: string; memberId: string } | null;
        if (
          !candidate ||
          candidate.recoveryRequestId !== input.recovery.recoveryRequestId ||
          candidate.memberId !== memberId
        )
          return false;
        const auditEventId = UuidV7Schema.parse(input.recovery.auditEventId);
        const key = publicKeyBytes(credential.publicKey);
        await appendAuditEventsInTransaction(client, [
          {
            organizationId,
            event: {
              eventId: auditEventId,
              eventType: "enrollment_redeemed",
              actorMemberId: null,
              actorClientId: null,
              tokenJti: null,
              entityType: "identity_recovery",
              entityId: candidate.recoveryRequestId,
              boardId: null,
              origin: "browser",
              details: {
                recoveryRequestId: candidate.recoveryRequestId,
                memberId,
                credentialId,
                publicKeySha256: createHash("sha256").update(key).digest("hex"),
                passkeyUserVerified: true,
                activationChallengeId: input.recovery.activationChallengeId,
                activationCodeSha256: input.recovery.activationCodeSha256,
                state: "pending_activation"
              },
              schemaVersion: 1
            }
          }
        ]);
        const completed = await client.query(
          "select boardagent_complete_recovery_registration($1,$2,$3,$4::jsonb,$5,$6,$7) as completed",
          [
            tokenHash,
            challengeId,
            expectedChallengeSha256,
            {
              id: credentialId,
              memberId,
              rawId: credentialBytes(credential.credentialId).toString("hex"),
              publicKey: key.toString("hex"),
              counter,
              transports,
              backupEligible: credential.backupEligible,
              backupState: credential.backupState
            },
            auditEventId,
            UuidV7Schema.parse(input.recovery.activationChallengeId),
            digestBytes(input.recovery.activationCodeSha256)
          ]
        );
        if (completed.rows[0]?.completed !== true)
          throw new Error("recovery registration became unavailable");
        return true;
      }
      // Only a bound initial enrollment or confirmed recovery may issue a key.
      return false;
    });
  }

  public async completeAuthentication(
    input: CompleteWebAuthnAuthenticationInput
  ): Promise<boolean> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const challengeId = UuidV7Schema.parse(input.challengeId);
    const credentialId = UuidV7Schema.parse(input.credentialId);
    const expectedChallengeSha256 = digestBytes(input.expectedChallengeSha256);
    const expectedCounter = CounterSchema.parse(input.expectedCounter);
    const newCounter = CounterSchema.parse(input.newCounter);
    if (!input.expectedBackupEligible && input.newBackupState) return false;
    return this.identity(
      organizationId,
      async (client) => {
        // A restart assertion is the one session-less purpose; it re-proves a member who is
        // still pending activation, so the member-state requirement follows the purpose.
        const restart = input.activationRestart !== undefined;
        const challenge = await client.query<LockedChallengeRow>(
          `select member_id
           from webauthn_challenges
          where id=$1 and organization_id=$2
            and boardagent_constant_time_sha256_equal(challenge_sha256,$3)
            and purpose = any($4::text[])
            and ($5::boolean = (purpose='activation_restart'))
            and (purpose<>'activation_restart' or activation_restart_grant_id=$6::uuid)
            and consumed_at is null and expires_at>transaction_timestamp()
          for update`,
          [
            challengeId,
            organizationId,
            expectedChallengeSha256,
            restart ? ["activation_restart"] : ["authentication", "recent_auth"],
            restart,
            restart ? UuidV7Schema.parse(input.activationRestart!.grantId) : null
          ]
        );
        if (challenge.rows.length !== 1) return false;
        const credential = await client.query<LockedCredentialRow>(
          `select member_id,signature_counter::text,backup_eligible
           from webauthn_credentials
          where id=$1 and organization_id=$2 and state='active'
            and exists (
              select 1 from members as member
               where member.id=webauthn_credentials.member_id
                 and member.organization_id=webauthn_credentials.organization_id
                 and member.state=$3
            )
          for update`,
          [credentialId, organizationId, restart ? "pending_activation" : "active"]
        );
        if (credential.rows.length !== 1) return false;
        const lockedCredential = credential.rows[0]!;
        const persistedCounter = safeCounter(lockedCredential.signature_counter);
        if (
          (challenge.rows[0]!.member_id !== null &&
            challenge.rows[0]!.member_id !== lockedCredential.member_id) ||
          persistedCounter !== expectedCounter ||
          lockedCredential.backup_eligible !== input.expectedBackupEligible ||
          ((persistedCounter > 0 || newCounter > 0) && newCounter <= persistedCounter)
        ) {
          return false;
        }
        if (input.onboarding !== undefined) {
          const onboarding = await completeOnboardingAttestationInTransaction(client, {
            ...input.onboarding,
            webauthnChallengeId: challengeId,
            webauthnCredentialId: credentialId
          });
          if (!onboarding.completed) return false;
        }
        const updated = await client.query<{ readonly id: string }>(
          `update webauthn_credentials
            set signature_counter=$3,backup_state=$4,last_used_at=transaction_timestamp()
          where id=$1 and organization_id=$2 and state='active'
            and signature_counter=$5 and backup_eligible=$6
          returning id`,
          [
            credentialId,
            organizationId,
            newCounter,
            input.newBackupState,
            expectedCounter,
            input.expectedBackupEligible
          ]
        );
        if (updated.rows.length !== 1) {
          throw new Error("WebAuthn credential update invariant failed");
        }
        const consumed = await client.query<{ readonly id: string }>(
          `update webauthn_challenges
            set consumed_at=transaction_timestamp()
          where id=$1 and organization_id=$2 and consumed_at is null
          returning id`,
          [challengeId, organizationId]
        );
        if (consumed.rows.length !== 1) {
          throw new Error("WebAuthn authentication challenge consumption invariant failed");
        }
        if (input.activationRestart !== undefined) {
          if (input.activationRestart.memberId !== lockedCredential.member_id) return false;
          const completedRestart = await completeActivationRestartInTransaction(client, {
            ...input.activationRestart,
            webauthnChallengeId: challengeId,
            webauthnCredentialId: credentialId
          });
          if (!completedRestart.completed) return false;
        }
        return true;
      },
      input.onboarding === undefined ? [] : [input.onboarding.boardId]
    );
  }
}
