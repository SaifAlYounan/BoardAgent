import { createHmac } from "node:crypto";

import { z } from "zod";
import type { Pool, PoolClient } from "pg";

import { UuidV7Schema } from "@boardagent/contracts";
import { withIdentityTransaction } from "@boardagent/db";

import type { WebAuthnAttemptContext, WebAuthnAttemptLimiter } from "./webauthn.js";

const BucketClassSchema = z.enum(["ip", "client", "member", "token", "registration"]);
const RateLimitAxisSchema = z
  .object({
    bucketClass: BucketClassSchema,
    trustedSubject: z.string().min(1).max(2048),
    windowSeconds: z.number().int().min(1).max(86_400),
    maxRequests: z.number().int().min(1).max(1_000_000),
    blockSeconds: z.number().int().min(1).max(86_400)
  })
  .strict();
const RateLimitRowSchema = z
  .object({
    result_allowed: z.boolean(),
    result_request_count: z.number().int().min(1),
    result_blocked_until: z.date().nullable(),
    result_retry_after_seconds: z.number().int().min(0).max(86_400)
  })
  .strict();

export type RateLimitBucketClass = z.infer<typeof BucketClassSchema>;
export type RateLimitAxis = z.infer<typeof RateLimitAxisSchema>;

export interface RateLimitBucketDecision {
  readonly bucketClass: RateLimitBucketClass;
  readonly allowed: boolean;
  readonly requestCount: number;
  readonly retryAfterSeconds: number;
}

export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
  readonly buckets: readonly RateLimitBucketDecision[];
}

const RateLimitPolicySchema = RateLimitAxisSchema.pick({
  windowSeconds: true,
  maxRequests: true,
  blockSeconds: true
}).strict();

export type RateLimitPolicy = z.infer<typeof RateLimitPolicySchema>;

export interface WebAuthnRateLimitPolicies {
  readonly ip: RateLimitPolicy;
  readonly client: RateLimitPolicy;
  readonly member: RateLimitPolicy;
  readonly token: RateLimitPolicy;
}

interface RateLimitRow {
  readonly result_allowed: boolean;
  readonly result_request_count: number;
  readonly result_blocked_until: Date | null;
  readonly result_retry_after_seconds: number;
}

interface PreparedAxis extends RateLimitAxis {
  readonly subjectSha256: Buffer;
}

export class PgRateLimiter {
  private readonly hmacKey: Buffer;

  public constructor(
    private readonly pool: Pool,
    options: {
      /** Purpose-separated secret used only to pseudonymize trusted bucket subjects. */
      readonly hmacKey: Uint8Array;
      readonly isolation?: "read committed";
      /** Test/bootstrap seam only. Production pools connect through scoped credentials. */
      readonly assumeRole?: "boardagent_server";
    }
  ) {
    this.hmacKey = Buffer.from(options.hmacKey);
    if (this.hmacKey.length < 32 || this.hmacKey.length > 4096) {
      throw new RangeError("rate-limit HMAC key must contain 32 through 4096 bytes");
    }
    this.options = options;
  }

  private readonly options: {
    readonly hmacKey: Uint8Array;
    readonly isolation?: "read committed";
    readonly assumeRole?: "boardagent_server";
  };

  private prepareAxis(axisValue: RateLimitAxis): PreparedAxis {
    const axis = RateLimitAxisSchema.parse(axisValue);
    const subjectSha256 = createHmac("sha256", this.hmacKey)
      .update("boardagent-rate-limit-v1\0", "utf8")
      .update(axis.bucketClass, "utf8")
      .update("\0", "utf8")
      .update(axis.trustedSubject, "utf8")
      .digest();
    return { ...axis, subjectSha256 };
  }

  private async consumeAxis(
    client: PoolClient,
    axis: PreparedAxis
  ): Promise<RateLimitBucketDecision> {
    const result = await client.query<RateLimitRow>(
      `select result_allowed,result_request_count,result_blocked_until,result_retry_after_seconds
         from boardagent_consume_rate_limit($1,$2,$3,$4,$5)`,
      [
        axis.bucketClass,
        axis.subjectSha256,
        axis.windowSeconds,
        axis.maxRequests,
        axis.blockSeconds
      ]
    );
    if (result.rows.length !== 1) throw new Error("rate-limit authority returned no decision");
    const row = RateLimitRowSchema.parse(result.rows[0]);
    return {
      bucketClass: axis.bucketClass,
      allowed: row.result_allowed,
      requestCount: row.result_request_count,
      retryAfterSeconds: row.result_retry_after_seconds
    };
  }

  public async consumeIdentity(
    organizationIdValue: string,
    axisValues: readonly RateLimitAxis[]
  ): Promise<RateLimitDecision> {
    const organizationId = UuidV7Schema.parse(organizationIdValue);
    const axes = z
      .array(RateLimitAxisSchema)
      .min(1)
      .max(5)
      .parse(axisValues)
      .map((axis) => this.prepareAxis(axis));
    if (new Set(axes.map(({ bucketClass }) => bucketClass)).size !== axes.length) {
      throw new Error("rate-limit request contains a duplicate bucket class");
    }
    axes.sort((left, right) => {
      const leftKey = `${left.bucketClass}:${left.subjectSha256.toString("hex")}`;
      const rightKey = `${right.bucketClass}:${right.subjectSha256.toString("hex")}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
    const buckets = await withIdentityTransaction(
      this.pool,
      { organizationId, boardIds: [] },
      async (client) => {
        const decisions: RateLimitBucketDecision[] = [];
        for (const axis of axes) decisions.push(await this.consumeAxis(client, axis));
        return decisions;
      },
      {
        isolation: this.options.isolation ?? "read committed",
        ...(this.options.assumeRole === undefined ? {} : { assumeRole: this.options.assumeRole })
      }
    );
    return {
      allowed: buckets.every(({ allowed }) => allowed),
      retryAfterSeconds: Math.max(...buckets.map(({ retryAfterSeconds }) => retryAfterSeconds)),
      buckets
    };
  }
}

export class PgWebAuthnAttemptLimiter implements WebAuthnAttemptLimiter {
  private readonly trustedIpClass: string;
  private readonly trustedClientId: string;
  private readonly policies: WebAuthnRateLimitPolicies;

  public constructor(
    private readonly limiter: PgRateLimiter,
    options: {
      /** Normalized by the trusted HTTP edge, for example an IPv4 /24 or IPv6 /56 class. */
      readonly trustedIpClass: string;
      /** Exact authenticated/internal OAuth client identifier supplied by the server. */
      readonly trustedClientId: string;
      readonly policies: WebAuthnRateLimitPolicies;
    }
  ) {
    this.trustedIpClass = z.string().min(1).max(256).parse(options.trustedIpClass);
    this.trustedClientId = z.string().min(1).max(2048).parse(options.trustedClientId);
    this.policies = {
      ip: RateLimitPolicySchema.parse(options.policies.ip),
      client: RateLimitPolicySchema.parse(options.policies.client),
      member: RateLimitPolicySchema.parse(options.policies.member),
      token: RateLimitPolicySchema.parse(options.policies.token)
    };
  }

  public async consume(context: WebAuthnAttemptContext): Promise<{
    readonly allowed: boolean;
    readonly retryAfterSeconds: number;
  }> {
    const axes: RateLimitAxis[] = [
      {
        bucketClass: "ip",
        trustedSubject: this.trustedIpClass,
        ...this.policies.ip
      },
      {
        bucketClass: "client",
        trustedSubject: this.trustedClientId,
        ...this.policies.client
      }
    ];
    if (context.memberId !== null) {
      axes.push({
        bucketClass: "member",
        trustedSubject: UuidV7Schema.parse(context.memberId),
        ...this.policies.member
      });
    }
    if (context.sessionId !== null) {
      axes.push({
        bucketClass: "token",
        trustedSubject: UuidV7Schema.parse(context.sessionId),
        ...this.policies.token
      });
    }
    const decision = await this.limiter.consumeIdentity(context.organizationId, axes);
    return { allowed: decision.allowed, retryAfterSeconds: decision.retryAfterSeconds };
  }
}
