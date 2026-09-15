import type { Pool } from "pg";
import { z } from "zod";

import { OfflineCertificateBundleSchema } from "@boardagent/audit";
import { UuidV7Schema } from "@boardagent/contracts";
import {
  verifyPublicPersistedVoteCertificateInTransaction,
  withIdentityTransaction
} from "@boardagent/db";

import { PgRateLimiter, type RateLimitPolicy } from "./pg-rate-limiter.js";

const PublicCertificateRatePolicySchema = z
  .object({
    windowSeconds: z.number().int().min(1).max(86_400),
    maxRequests: z.number().int().min(1).max(1_000_000),
    blockSeconds: z.number().int().min(1).max(86_400)
  })
  .strict();

export type PublicCertificateVerificationResult =
  | { readonly status: "complete"; readonly valid: boolean }
  | { readonly status: "rate_limited"; readonly retryAfterSeconds: number };

/**
 * Public verification is capability-addressed and deliberately returns one bit. Rate
 * limiting happens before parsing or database lookup so malformed and unknown probes
 * consume the same trusted-IP budget as valid references.
 */
export class PgPublicCertificateVerifier {
  private readonly organizationId: string;
  private readonly policy: RateLimitPolicy;
  private readonly assumeRole: "boardagent_server" | undefined;

  public constructor(
    private readonly pool: Pool,
    private readonly rateLimiter: PgRateLimiter,
    options: {
      readonly organizationId: string;
      readonly policy: RateLimitPolicy;
      /** Test/local-owner seam. Production connects as boardagent_server directly. */
      readonly assumeRole?: "boardagent_server";
    }
  ) {
    this.organizationId = UuidV7Schema.parse(options.organizationId);
    this.policy = PublicCertificateRatePolicySchema.parse(options.policy);
    this.assumeRole = options.assumeRole;
  }

  public async verify(input: {
    readonly candidatePublicId: string | null;
    readonly candidateBundle: unknown | null;
    readonly clientIpClass: string;
  }): Promise<PublicCertificateVerificationResult> {
    const clientIpClass = z.string().min(1).max(256).parse(input.clientIpClass);
    const rate = await this.rateLimiter.consumeIdentity(this.organizationId, [
      {
        bucketClass: "ip",
        trustedSubject: `public-certificate:${clientIpClass}`,
        ...this.policy
      }
    ]);
    if (!rate.allowed) {
      return { status: "rate_limited", retryAfterSeconds: rate.retryAfterSeconds };
    }
    let candidatePublicId = input.candidatePublicId;
    let assertedBundle: unknown | undefined;
    if (input.candidateBundle !== null) {
      const parsed = OfflineCertificateBundleSchema.safeParse(input.candidateBundle);
      if (!parsed.success || candidatePublicId !== null) {
        return { status: "complete", valid: false };
      }
      candidatePublicId = parsed.data.public_id;
      assertedBundle = parsed.data;
    }
    if (candidatePublicId === null) return { status: "complete", valid: false };
    const verdict = await withIdentityTransaction(
      this.pool,
      { organizationId: this.organizationId, boardIds: [] },
      (client) =>
        verifyPublicPersistedVoteCertificateInTransaction(client, {
          certificatePublicId: candidatePublicId,
          ...(assertedBundle === undefined ? {} : { assertedBundle })
        }),
      {
        isolation: "read committed",
        ...(this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole })
      }
    );
    return { status: "complete", valid: verdict.valid };
  }
}
