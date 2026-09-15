import { createHash, randomBytes } from "node:crypto";

import type {
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON
} from "@simplewebauthn/server";
import type { Pool } from "pg";
import { z } from "zod";

import { Sha256HexSchema, UuidV7Schema } from "@boardagent/contracts";
import {
  EnrollmentProofingMethodSchema,
  lookupBuiltinEnrollmentInTransaction,
  withIdentityTransaction,
  type BuiltinEnrollmentCandidate,
  type EnrollmentProofingMethod
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

import { WebAuthnCeremonyError, type WebAuthnCeremony } from "./webauthn.js";

const ACTIVATION_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const InvitationTokenSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u)
  .refine((value) => {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === 32 && decoded.toString("base64url") === value;
  }, "invitation token must be canonical 256-bit base64url");

export interface BuiltinEnrollmentStore {
  findCandidate(input: {
    readonly organizationId: string;
    readonly invitationTokenSha256: string;
  }): Promise<BuiltinEnrollmentCandidate | null>;
}

export class PgBuiltinEnrollmentStore implements BuiltinEnrollmentStore {
  public constructor(
    private readonly pool: Pool,
    private readonly options: {
      /** Test/bootstrap seam only. Production pools connect through scoped credentials. */
      readonly assumeRole?: "boardagent_server";
    } = {}
  ) {}

  public async findCandidate(input: {
    readonly organizationId: string;
    readonly invitationTokenSha256: string;
  }): Promise<BuiltinEnrollmentCandidate | null> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const invitationTokenSha256 = Sha256HexSchema.parse(input.invitationTokenSha256);
    return withIdentityTransaction(
      this.pool,
      { organizationId },
      (client) =>
        lookupBuiltinEnrollmentInTransaction(client, {
          organizationId,
          invitationTokenSha256
        }),
      this.options
    );
  }
}

type BuiltinEnrollmentWebAuthn = Pick<
  WebAuthnCeremony,
  "beginRegistration" | "completeRegistration"
>;

export class BuiltinEnrollmentError extends Error {
  public readonly code = "enrollment_unavailable";

  public constructor() {
    super("builtin enrollment is unavailable");
    this.name = "BuiltinEnrollmentError";
  }
}

export interface BuiltinEnrollmentBeginResult {
  readonly organizationDisplayName: string;
  readonly memberDisplayName: string;
  readonly seats: BuiltinEnrollmentCandidate["seats"];
  readonly publicKey: PublicKeyCredentialCreationOptionsJSON;
}

export interface BuiltinEnrollmentCompleteResult {
  readonly status: "pending_activation";
  readonly memberId: string;
  readonly invitationId: string;
  readonly activationChallengeId: string;
  readonly activationCode: string;
  readonly proofingMethod: EnrollmentProofingMethod;
  readonly expiresInSeconds: 600;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function activationCode(entropy: (length: number) => Buffer): string {
  const bytes = entropy(7);
  if (bytes.length !== 7) throw new Error("activation-code entropy returned the wrong length");
  const characters = [...bytes].map(
    (byte) => ACTIVATION_CODE_ALPHABET[byte & 31] ?? ACTIVATION_CODE_ALPHABET[0]!
  );
  return `${characters.slice(0, 3).join("")}-${characters.slice(3).join("")}`;
}

export class BuiltinEnrollmentService {
  private readonly organizationId: string;
  private readonly store: BuiltinEnrollmentStore;
  private readonly webauthn: BuiltinEnrollmentWebAuthn;
  private readonly newId: () => string;
  private readonly entropy: (length: number) => Buffer;

  public constructor(options: {
    readonly organizationId: string;
    readonly store: BuiltinEnrollmentStore;
    readonly webauthn: BuiltinEnrollmentWebAuthn;
    readonly now?: () => Date;
    readonly newId?: () => string;
    readonly entropy?: (length: number) => Buffer;
  }) {
    this.organizationId = UuidV7Schema.parse(options.organizationId);
    this.store = options.store;
    this.webauthn = options.webauthn;
    const now = options.now ?? (() => new Date());
    this.newId = options.newId ?? (() => uuidV7(now().getTime(), randomBytes(10)));
    this.entropy = options.entropy ?? randomBytes;
  }

  private async candidate(invitationToken: string): Promise<{
    readonly token: string;
    readonly tokenSha256: string;
    readonly candidate: BuiltinEnrollmentCandidate;
  }> {
    let token: string;
    try {
      token = InvitationTokenSchema.parse(invitationToken);
    } catch {
      throw new BuiltinEnrollmentError();
    }
    const tokenSha256 = sha256(token);
    const candidate = await this.store.findCandidate({
      organizationId: this.organizationId,
      invitationTokenSha256: tokenSha256
    });
    if (!candidate) throw new BuiltinEnrollmentError();
    return { token, tokenSha256, candidate };
  }

  public async begin(input: {
    readonly invitationToken: string;
  }): Promise<BuiltinEnrollmentBeginResult> {
    const resolved = await this.candidate(input.invitationToken);
    try {
      const publicKey = await this.webauthn.beginRegistration({
        organizationId: this.organizationId,
        memberId: resolved.candidate.memberId,
        sessionId: null,
        purpose: "enrollment",
        userName: resolved.candidate.memberId,
        displayName: resolved.candidate.memberDisplayName
      });
      return {
        organizationDisplayName: resolved.candidate.organizationDisplayName,
        memberDisplayName: resolved.candidate.memberDisplayName,
        seats: resolved.candidate.seats,
        publicKey
      };
    } catch (error) {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") throw error;
      throw new BuiltinEnrollmentError();
    }
  }

  public async complete(input: {
    readonly invitationToken: string;
    readonly proofingMethod: EnrollmentProofingMethod;
    readonly response: RegistrationResponseJSON;
  }): Promise<BuiltinEnrollmentCompleteResult> {
    const resolved = await this.candidate(input.invitationToken);
    const proofingMethod = EnrollmentProofingMethodSchema.parse(input.proofingMethod);
    const code = activationCode(this.entropy);
    const activationChallengeId = UuidV7Schema.parse(this.newId());
    const auditEventId = UuidV7Schema.parse(this.newId());
    try {
      await this.webauthn.completeRegistration({
        organizationId: this.organizationId,
        memberId: resolved.candidate.memberId,
        sessionId: null,
        purpose: "enrollment",
        response: input.response,
        enrollment: {
          invitationTokenSha256: resolved.tokenSha256,
          activationChallengeId,
          activationCodeSha256: sha256(code),
          proofingMethod,
          auditEventId
        }
      });
    } catch (error) {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") throw error;
      throw new BuiltinEnrollmentError();
    }
    return {
      status: "pending_activation",
      memberId: resolved.candidate.memberId,
      invitationId: resolved.candidate.invitationId,
      activationChallengeId,
      activationCode: code,
      proofingMethod,
      expiresInSeconds: 600
    };
  }
}
