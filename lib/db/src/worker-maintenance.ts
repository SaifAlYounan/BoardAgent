import type { PoolClient } from "pg";
import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";

const WorkerMaintenanceInputSchema = z
  .object({
    jobType: z.enum([
      "action_stage_expiry",
      "wizard_expiry",
      "oauth_ephemera_expiry",
      "refresh_session_revocation",
      "rate_bucket_retention"
    ]),
    organizationId: UuidV7Schema,
    limit: z.number().int().min(1).max(10_000).default(100)
  })
  .strict();

const WorkerMaintenanceResultSchema = z.discriminatedUnion("jobType", [
  z
    .object({ jobType: z.literal("action_stage_expiry"), expiredStages: z.number().int().min(0) })
    .strict(),
  z
    .object({ jobType: z.literal("wizard_expiry"), expiredDrafts: z.number().int().min(0) })
    .strict(),
  z
    .object({
      jobType: z.literal("rate_bucket_retention"),
      deletedBuckets: z.number().int().min(0)
    })
    .strict(),
  z
    .object({
      jobType: z.literal("oauth_ephemera_expiry"),
      expiredSessions: z.number().int().min(0),
      expiredAuthorizationRequests: z.number().int().min(0),
      revokedAuthorizationCodes: z.number().int().min(0),
      expiredActivationChallenges: z.number().int().min(0),
      expiredOnboardingStages: z.number().int().min(0),
      deletedWebauthnChallenges: z.number().int().min(0),
      deletedOidcTransactions: z.number().int().min(0)
    })
    .strict(),
  z
    .object({
      jobType: z.literal("refresh_session_revocation"),
      expiredFamilies: z.number().int().min(0),
      revokedRefreshTokens: z.number().int().min(0),
      revokedAccessTokens: z.number().int().min(0)
    })
    .strict()
]);

export type WorkerMaintenanceInput = z.input<typeof WorkerMaintenanceInputSchema>;
export type WorkerMaintenanceResult = z.infer<typeof WorkerMaintenanceResultSchema>;

const OperationalRetentionInputSchema = z
  .object({
    jobType: z.enum(["job_retention", "log_retention"]),
    organizationId: UuidV7Schema,
    limit: z.number().int().min(1).max(10_000).default(100)
  })
  .strict();

const OperationalRetentionResultSchema = z.discriminatedUnion("jobType", [
  z
    .object({
      jobType: z.literal("job_retention"),
      deletedJobAttempts: z.number().int().min(0),
      deletedJobs: z.number().int().min(0)
    })
    .strict(),
  z
    .object({
      jobType: z.literal("log_retention"),
      deletedNotificationAttempts: z.number().int().min(0)
    })
    .strict()
]);

export type OperationalRetentionInput = z.input<typeof OperationalRetentionInputSchema>;
export type OperationalRetentionResult = z.infer<typeof OperationalRetentionResultSchema>;

/** Invoke one closed, bounded ephemera operation through worker-only DB authority. */
export async function runWorkerMaintenanceInTransaction(
  client: PoolClient,
  rawInput: WorkerMaintenanceInput
): Promise<WorkerMaintenanceResult> {
  const input = WorkerMaintenanceInputSchema.parse(rawInput);
  const result = await client.query<{ result: unknown }>(
    "select public.boardagent_run_worker_maintenance($1,$2,$3) as result",
    [input.jobType, input.organizationId, input.limit]
  );
  if (result.rows.length !== 1) throw new Error("worker maintenance returned an invalid shape");
  return WorkerMaintenanceResultSchema.parse(result.rows[0]?.result);
}

/** Delete only the two Gate-2-approved 30-day operational log classes. */
export async function runOperationalRetentionInTransaction(
  client: PoolClient,
  rawInput: OperationalRetentionInput
): Promise<OperationalRetentionResult> {
  const input = OperationalRetentionInputSchema.parse(rawInput);
  const result = await client.query<{ result: unknown }>(
    "select public.boardagent_run_operational_retention($1,$2,$3) as result",
    [input.jobType, input.organizationId, input.limit]
  );
  if (result.rows.length !== 1) throw new Error("operational retention returned an invalid shape");
  return OperationalRetentionResultSchema.parse(result.rows[0]?.result);
}
