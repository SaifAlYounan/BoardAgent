import type { PoolClient } from "pg";
import { z } from "zod";

import { Rfc3339UtcSchema, UuidV7Schema } from "@boardagent/contracts";

const SignedBigintSchema = z.string().regex(/^-?(?:0|[1-9]\d*)$/u);

export interface RecordedClockHealth {
  readonly sampleId: string;
  readonly healthy: boolean;
  readonly measuredAt: string;
  readonly driftMicroseconds: string;
  readonly validUntil: string;
}

export async function readDatabaseClockInTransaction(client: PoolClient): Promise<string> {
  const result = await client.query<{ measured_at: string }>(
    `select to_char(clock_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as measured_at`
  );
  return Rfc3339UtcSchema.parse(result.rows[0]?.measured_at);
}

export async function recordClockHealthInTransaction(
  client: PoolClient,
  input: {
    readonly sampleId: string;
    readonly organizationId: string;
    readonly source: string;
    readonly measuredAt: string;
    readonly driftMicroseconds: string;
    readonly validUntil: string;
  }
): Promise<RecordedClockHealth> {
  const parsed = z
    .object({
      sampleId: UuidV7Schema,
      organizationId: UuidV7Schema,
      source: z.string().regex(/^[a-z][a-z0-9_.-]{1,127}$/u),
      measuredAt: Rfc3339UtcSchema,
      driftMicroseconds: SignedBigintSchema,
      validUntil: Rfc3339UtcSchema
    })
    .strict()
    .parse(input);
  const result = await client.query<{
    sample_id: string;
    healthy: boolean;
    measured_at: string;
    drift_microseconds: string;
    valid_until: string;
  }>(
    `select sample_id,healthy,measured_at,drift_microseconds::text,valid_until
       from boardagent_record_clock_health($1,$2,$3,$4,$5,$6)`,
    [
      parsed.sampleId,
      parsed.organizationId,
      parsed.source,
      parsed.measuredAt,
      parsed.driftMicroseconds,
      parsed.validUntil
    ]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) throw new Error("clock health insert returned no row");
  return {
    sampleId: UuidV7Schema.parse(row.sample_id),
    healthy: row.healthy,
    measuredAt: Rfc3339UtcSchema.parse(row.measured_at),
    driftMicroseconds: SignedBigintSchema.parse(row.drift_microseconds),
    validUntil: Rfc3339UtcSchema.parse(row.valid_until)
  };
}
