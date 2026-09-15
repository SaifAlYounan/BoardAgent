import { createHash, randomBytes } from "node:crypto";
import type { Pool } from "pg";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { z } from "zod";
import { UuidV7Schema } from "@boardagent/contracts";
import { lookupActivationRestartInTransaction, withIdentityTransaction } from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import { activationCode } from "./enrollment.js";
import { WebAuthnCeremonyError, type WebAuthnCeremony } from "./webauthn.js";

const Token = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u)
  .refine(
    (value) =>
      Buffer.from(value, "base64url").length === 32 &&
      Buffer.from(value, "base64url").toString("base64url") === value
  );
const Candidate = z
  .object({
    grantId: UuidV7Schema,
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    memberDisplayName: z.string().min(1).max(512),
    organizationDisplayName: z.string().min(1).max(512),
    proofingMethod: z.string().min(1).max(1024),
    expiresAt: z.string().min(1).max(64)
  })
  .strict();

/**
 * The browser always sees the same generic refusal. The underlying cause, when there is
 * one, travels on `cause` so the operator log can show it without leaking it to the page.
 */
export class ActivationRestartError extends Error {
  public constructor(cause?: unknown) {
    super("activation restart is unavailable", cause === undefined ? undefined : { cause });
    this.name = "ActivationRestartError";
  }
}

/**
 * The pending-activation restart ceremony (ADR 0011 family, approved 13 September 2026).
 * A person whose ten-minute activation code expired or was exhausted opens the one-use
 * restart handoff, re-proves with the passkey they already registered, and receives a
 * fresh ten-minute code. Nothing here activates the member; the issuer still confirms.
 */
export class ActivationRestartService {
  public constructor(
    private readonly pool: Pool,
    private readonly options: {
      readonly organizationId: string;
      readonly webauthn: Pick<WebAuthnCeremony, "beginAuthentication" | "completeAuthentication">;
      readonly assumeRole?: "boardagent_server";
    }
  ) {}

  private async candidate(tokenValue: string) {
    let token: string;
    try {
      token = Token.parse(tokenValue);
    } catch (error) {
      throw new ActivationRestartError(error);
    }
    const tokenSha256 = createHash("sha256").update(token).digest("hex");
    const value = await withIdentityTransaction(
      this.pool,
      { organizationId: this.options.organizationId },
      (client) => lookupActivationRestartInTransaction(client, { tokenSha256 }),
      this.options.assumeRole === undefined ? {} : { assumeRole: this.options.assumeRole }
    );
    if (!value) throw new ActivationRestartError(new Error("restart handoff is not live"));
    const candidate = Candidate.parse(value);
    if (candidate.organizationId !== this.options.organizationId)
      throw new ActivationRestartError(
        new Error("restart handoff belongs to another organization")
      );
    return { ...candidate, tokenSha256 };
  }

  public async begin(input: { readonly restartToken: string }) {
    const candidate = await this.candidate(input.restartToken);
    try {
      const publicKey = await this.options.webauthn.beginAuthentication({
        organizationId: this.options.organizationId,
        memberId: candidate.memberId,
        sessionId: null,
        purpose: "activation_restart",
        activationRestartGrantId: candidate.grantId
      });
      return {
        memberDisplayName: candidate.memberDisplayName,
        organizationDisplayName: candidate.organizationDisplayName,
        proofingMethod: candidate.proofingMethod,
        expiresAt: candidate.expiresAt,
        publicKey
      };
    } catch (error) {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") throw error;
      throw new ActivationRestartError(error);
    }
  }

  public async complete(input: {
    readonly restartToken: string;
    readonly response: AuthenticationResponseJSON;
  }) {
    const candidate = await this.candidate(input.restartToken);
    const code = activationCode(randomBytes);
    const freshChallengeId = UuidV7Schema.parse(uuidV7(Date.now(), randomBytes(10)));
    try {
      const authenticated = await this.options.webauthn.completeAuthentication({
        organizationId: this.options.organizationId,
        sessionId: null,
        purpose: "activation_restart",
        response: input.response,
        activationRestart: {
          organizationId: this.options.organizationId,
          memberId: candidate.memberId,
          grantId: candidate.grantId,
          tokenSha256: candidate.tokenSha256,
          freshChallengeId,
          activationCodeSha256: createHash("sha256").update(code).digest("hex"),
          auditEventId: UuidV7Schema.parse(uuidV7(Date.now(), randomBytes(10)))
        }
      });
      if (authenticated.memberId !== candidate.memberId) {
        throw new Error("restart assertion principal changed");
      }
    } catch (error) {
      if (error instanceof WebAuthnCeremonyError && error.code === "rate_limited") throw error;
      throw new ActivationRestartError(error);
    }
    return {
      status: "pending_activation",
      memberId: candidate.memberId,
      activationChallengeId: freshChallengeId,
      activationCode: code,
      proofingMethod: candidate.proofingMethod,
      expiresInSeconds: 600
    } as const;
  }
}
