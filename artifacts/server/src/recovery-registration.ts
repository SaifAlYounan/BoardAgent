import { createHash, randomBytes } from "node:crypto";
import type { Pool } from "pg";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { z } from "zod";
import { UuidV7Schema } from "@boardagent/contracts";
import { withIdentityTransaction } from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import { activationCode } from "./enrollment.js";
import type { WebAuthnCeremony } from "./webauthn.js";

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
    proofingMethod: z.enum(["in_person", "verified_number_call"]),
    recoveryRequestId: UuidV7Schema,
    memberId: UuidV7Schema,
    memberDisplayName: z.string().min(1).max(512),
    organizationDisplayName: z.string().min(1).max(512)
  })
  .strict();
export class RecoveryRegistrationError extends Error {
  public constructor() {
    super("recovery registration is unavailable");
  }
}
export class RecoveryRegistrationService {
  public constructor(
    private readonly pool: Pool,
    private readonly options: {
      readonly organizationId: string;
      readonly webauthn: Pick<WebAuthnCeremony, "beginRegistration" | "completeRegistration">;
      readonly assumeRole?: "boardagent_server";
    }
  ) {}
  private async candidate(tokenValue: string) {
    const token = Token.parse(tokenValue);
    const tokenSha256 = createHash("sha256").update(token).digest("hex");
    const value = await withIdentityTransaction(
      this.pool,
      { organizationId: this.options.organizationId },
      async (client) =>
        (
          await client.query("select boardagent_lookup_recovery_registration($1) as candidate", [
            Buffer.from(tokenSha256, "hex")
          ])
        ).rows[0]?.candidate,
      this.options.assumeRole === undefined ? {} : { assumeRole: this.options.assumeRole }
    );
    if (!value) throw new RecoveryRegistrationError();
    return { ...Candidate.parse(value), tokenSha256 };
  }
  public async begin(input: { readonly recoveryToken: string }) {
    const candidate = await this.candidate(input.recoveryToken);
    const publicKey = await this.options.webauthn.beginRegistration({
      organizationId: this.options.organizationId,
      memberId: candidate.memberId,
      sessionId: null,
      purpose: "recovery",
      recoveryRequestId: candidate.recoveryRequestId,
      userName: candidate.memberId,
      displayName: candidate.memberDisplayName
    });
    return {
      memberDisplayName: candidate.memberDisplayName,
      organizationDisplayName: candidate.organizationDisplayName,
      publicKey
    };
  }
  public async complete(input: {
    readonly recoveryToken: string;
    readonly response: RegistrationResponseJSON;
  }) {
    const candidate = await this.candidate(input.recoveryToken);
    const code = activationCode(randomBytes);
    const activationChallengeId = uuidV7(Date.now(), randomBytes(10));
    await this.options.webauthn.completeRegistration({
      organizationId: this.options.organizationId,
      memberId: candidate.memberId,
      sessionId: null,
      purpose: "recovery",
      response: input.response,
      recovery: {
        activationChallengeId,
        activationCodeSha256: createHash("sha256").update(code).digest("hex"),
        tokenSha256: candidate.tokenSha256,
        recoveryRequestId: candidate.recoveryRequestId,
        auditEventId: uuidV7(Date.now(), randomBytes(10))
      }
    });
    return {
      status: "pending_activation",
      memberId: candidate.memberId,
      invitationId: candidate.recoveryRequestId,
      activationChallengeId,
      activationCode: code,
      proofingMethod: candidate.proofingMethod,
      expiresInSeconds: 600
    } as const;
  }
}
