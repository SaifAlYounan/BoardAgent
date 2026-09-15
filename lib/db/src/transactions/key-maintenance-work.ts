import type { PoolClient } from "pg";
import { z } from "zod";
import { canonicalSha256 } from "@boardagent/contracts";
import { KeyDependencyInspectionSchema, KeyDependencyTargetSchema } from "./key-dependencies.js";

export const KEY_MAINTENANCE_WORK_GROUPS = [
  "active_contact_points",
  "active_totp",
  "active_webhooks",
  "affected_refresh_families",
  "browser_action_stages",
  "browser_authorization_requests",
  "browser_sessions",
  "closing_votes",
  "leased_jobs",
  "leased_notifications",
  "live_vote_close_stages",
  "pending_exports",
  "pending_totp",
  "running_exports",
  "unfinished_jobs",
  "unfinished_vote_outcomes"
] as const;
const Count = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,6})$/u)
  .refine((v) => BigInt(v) <= 1_000_000n);
export const KeyMaintenanceWorkSchema = z
  .object({
    schemaVersion: z.literal("boardagent.key-maintenance-work.v1"),
    keyDependencies: KeyDependencyInspectionSchema,
    groups: z
      .array(
        z
          .object({
            name: z.enum(KEY_MAINTENANCE_WORK_GROUPS),
            rowCount: Count,
            rowsSha256: z.string().regex(/^[0-9a-f]{64}$/u)
          })
          .strict()
      )
      .length(KEY_MAINTENANCE_WORK_GROUPS.length),
    totalWorkReferences: Count
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.groups.some((g, i) => g.name !== KEY_MAINTENANCE_WORK_GROUPS[i]) ||
      value.groups.reduce((n, g) => n + BigInt(g.rowCount), 0n) !==
        BigInt(value.totalWorkReferences)
    )
      context.addIssue({ code: "custom", message: "inconsistent key maintenance work inventory" });
  });

/** Snapshot facts, never a proof that a running process has stopped or custody exists. */
export async function inspectKeyMaintenanceWorkInTransaction(
  client: PoolClient,
  input: z.input<typeof KeyDependencyTargetSchema>
) {
  const target = KeyDependencyTargetSchema.parse(input);
  const result = await client.query<{ inventory: unknown }>(
    "select boardagent_inspect_key_maintenance_work($1,$2,$3) as inventory",
    [target.instanceId, target.organizationId, target.keyId]
  );
  const parsed = KeyMaintenanceWorkSchema.safeParse(result.rows[0]?.inventory);
  if (
    result.rows.length !== 1 ||
    !parsed.success ||
    parsed.data.keyDependencies.instanceId !== target.instanceId ||
    parsed.data.keyDependencies.organizationId !== target.organizationId ||
    parsed.data.keyDependencies.keyId !== target.keyId
  )
    throw new Error("invalid key maintenance work inventory result");
  const { observedAt: _observedAt, ...dependencies } = parsed.data.keyDependencies;
  return {
    inventory: parsed.data,
    stateSha256: canonicalSha256({ ...parsed.data, keyDependencies: dependencies })
  };
}
