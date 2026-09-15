import { createHash, randomBytes } from "node:crypto";

import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialRequestOptionsJSON
} from "@simplewebauthn/server";
import type { Pool } from "pg";
import { z } from "zod";

import { Sha256HexSchema, UuidV7Schema } from "@boardagent/contracts";
import {
  lookupOnboardingStageInTransaction,
  lookupOnboardingStageReferenceInTransaction,
  withIdentityTransaction,
  type OnboardingBrowserCandidate
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

import { WebAuthnCeremonyError, type WebAuthnCeremony } from "./webauthn.js";

const OnboardingTokenSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u)
  .refine((value) => {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === 32 && decoded.toString("base64url") === value;
  });

export interface OnboardingBrowserStore {
  findCandidate(input: {
    readonly organizationId: string;
    readonly stageTokenSha256: string;
  }): Promise<OnboardingBrowserCandidate | null>;
}

export class PgOnboardingBrowserStore implements OnboardingBrowserStore {
  public constructor(
    private readonly pool: Pool,
    private readonly options: {
      /** Test seam only. Production pools connect through scoped credentials. */
      readonly assumeRole?: "boardagent_server";
    } = {}
  ) {}

  public async findCandidate(input: {
    readonly organizationId: string;
    readonly stageTokenSha256: string;
  }): Promise<OnboardingBrowserCandidate | null> {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const stageTokenSha256 = Sha256HexSchema.parse(input.stageTokenSha256);
    const reference = await withIdentityTransaction(
      this.pool,
      { organizationId },
      (client) =>
        lookupOnboardingStageReferenceInTransaction(client, {
          organizationId,
          stageTokenSha256
        }),
      this.options
    );
    if (!reference) return null;
    return withIdentityTransaction(
      this.pool,
      { organizationId, boardIds: [reference.boardId] },
      (client) =>
        lookupOnboardingStageInTransaction(client, {
          organizationId,
          boardId: reference.boardId,
          stageId: reference.stageId,
          stageTokenSha256
        }),
      this.options
    );
  }
}

type OnboardingWebAuthn = Pick<WebAuthnCeremony, "beginAuthentication" | "completeAuthentication">;

export class BuiltinOnboardingError extends Error {
  public readonly code = "onboarding_unavailable";

  public constructor() {
    super("onboarding ceremony is unavailable");
    this.name = "BuiltinOnboardingError";
  }
}

export interface BuiltinOnboardingBeginResult {
  readonly organizationDisplayName: string;
  readonly boardName: string;
  readonly memberDisplayName: string;
  readonly memberKind: "human" | "ai_system";
  readonly accountablePrincipalId: string | null;
  readonly seatRole: "voting_member" | "management" | "observer";
  readonly terms: OnboardingBrowserCandidate["terms"];
  readonly secretarySupport: OnboardingBrowserCandidate["secretarySupport"];
  readonly presentationChoice: string;
  readonly localMemoryChoice: string;
  readonly expiresAt: string;
  readonly publicKey: PublicKeyCredentialRequestOptionsJSON;
}

export interface BuiltinOnboardingCompleteResult {
  readonly status: "current";
  readonly memberId: string;
  readonly boardId: string;
  readonly termsVersionId: string;
  readonly supportVersionId: string;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export class BuiltinOnboardingService {
  private readonly organizationId: string;
  private readonly store: OnboardingBrowserStore;
  private readonly webauthn: OnboardingWebAuthn;
  private readonly newId: () => string;

  public constructor(options: {
    readonly organizationId: string;
    readonly store: OnboardingBrowserStore;
    readonly webauthn: OnboardingWebAuthn;
    readonly now?: () => Date;
    readonly newId?: () => string;
  }) {
    this.organizationId = UuidV7Schema.parse(options.organizationId);
    this.store = options.store;
    this.webauthn = options.webauthn;
    const now = options.now ?? (() => new Date());
    this.newId = options.newId ?? (() => uuidV7(now().getTime(), randomBytes(10)));
  }

  private async candidate(stageToken: string): Promise<{
    readonly tokenSha256: string;
    readonly candidate: OnboardingBrowserCandidate;
  }> {
    let token: string;
    try {
      token = OnboardingTokenSchema.parse(stageToken);
    } catch {
      throw new BuiltinOnboardingError();
    }
    const tokenSha256 = sha256(token);
    const candidate = await this.store.findCandidate({
      organizationId: this.organizationId,
      stageTokenSha256: tokenSha256
    });
    if (!candidate) throw new BuiltinOnboardingError();
    return { tokenSha256, candidate };
  }

  public async begin(input: {
    readonly stageToken: string;
  }): Promise<BuiltinOnboardingBeginResult> {
    const resolved = await this.candidate(input.stageToken);
    try {
      const publicKey = await this.webauthn.beginAuthentication({
        organizationId: this.organizationId,
        memberId: resolved.candidate.memberId,
        sessionId: resolved.candidate.sessionId,
        purpose: "recent_auth"
      });
      return {
        organizationDisplayName: resolved.candidate.organizationDisplayName,
        boardName: resolved.candidate.boardName,
        memberDisplayName: resolved.candidate.memberDisplayName,
        memberKind: resolved.candidate.memberKind,
        accountablePrincipalId: resolved.candidate.accountablePrincipalId,
        seatRole: resolved.candidate.seatRole,
        terms: resolved.candidate.terms,
        secretarySupport: resolved.candidate.secretarySupport,
        presentationChoice: resolved.candidate.presentationChoice,
        localMemoryChoice: resolved.candidate.localMemoryChoice,
        expiresAt: resolved.candidate.expiresAt,
        publicKey
      };
    } catch (error) {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") throw error;
      throw new BuiltinOnboardingError();
    }
  }

  public async complete(input: {
    readonly stageToken: string;
    readonly response: AuthenticationResponseJSON;
  }): Promise<BuiltinOnboardingCompleteResult> {
    const resolved = await this.candidate(input.stageToken);
    const attestationId = UuidV7Schema.parse(this.newId());
    const auditEventId = UuidV7Schema.parse(this.newId());
    const tombstoneId = UuidV7Schema.parse(this.newId());
    try {
      const authenticated = await this.webauthn.completeAuthentication({
        organizationId: this.organizationId,
        sessionId: resolved.candidate.sessionId,
        purpose: "recent_auth",
        response: input.response,
        onboarding: {
          organizationId: this.organizationId,
          boardId: resolved.candidate.boardId,
          memberId: resolved.candidate.memberId,
          sessionId: resolved.candidate.sessionId,
          stageId: resolved.candidate.stageId,
          stageTokenSha256: resolved.tokenSha256,
          attestationId,
          auditEventId,
          tombstoneId
        }
      });
      if (
        authenticated.memberId !== resolved.candidate.memberId ||
        authenticated.sessionId !== resolved.candidate.sessionId
      ) {
        throw new Error("recent authentication principal changed");
      }
    } catch (error) {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") throw error;
      throw new BuiltinOnboardingError();
    }
    return {
      status: "current",
      memberId: resolved.candidate.memberId,
      boardId: resolved.candidate.boardId,
      termsVersionId: resolved.candidate.terms.versionId,
      supportVersionId: resolved.candidate.secretarySupport.versionId
    };
  }
}
