import type { PoolClient } from "pg";
import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";

const CheckpointSchedulingResultSchema = z
  .object({
    result_job_id: UuidV7Schema.nullable(),
    scheduling_status: z.enum(["empty", "not_due", "pending", "scheduled", "blocked"])
  })
  .strict();

/** The database derives the complete job from its own instance and audit history. */
export async function scheduleAuditCheckpointInTransaction(client: PoolClient, jobId: string) {
  const result = await client.query(
    "select result_job_id,scheduling_status from boardagent_schedule_audit_checkpoint($1)",
    [UuidV7Schema.parse(jobId)]
  );
  if (result.rows.length !== 1) throw new Error("checkpoint scheduler returned an invalid shape");
  return CheckpointSchedulingResultSchema.parse(result.rows[0]);
}

/** A closed database producer derives all recurring jobs from its own time and records. */
export async function schedulePeriodicJobsInTransaction(client: PoolClient): Promise<number> {
  const result = await client.query("select boardagent_schedule_periodic_jobs() as scheduled");
  if (result.rows.length !== 1) throw new Error("periodic scheduler returned an invalid shape");
  return z.number().int().min(0).max(1000).parse(result.rows[0]?.scheduled);
}
