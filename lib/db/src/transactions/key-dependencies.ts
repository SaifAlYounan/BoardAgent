import type { PoolClient } from "pg";
import { z } from "zod";
import { canonicalSha256, UuidV7Schema } from "@boardagent/contracts";

const Hash = z.string().regex(/^[0-9a-f]{64}$/u);
const Count = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,6})$/u)
  .refine((value) => BigInt(value) <= 1_000_000n);
export const KeyDependencyTargetSchema = z
  .object({ instanceId: UuidV7Schema, organizationId: UuidV7Schema, keyId: UuidV7Schema })
  .strict();
const Dependency = z
  .object({
    table: z.string().regex(/^[a-z][a-z0-9_]{0,62}$/u),
    column: z.string().regex(/^[a-z][a-z0-9_]{0,62}$/u),
    rowCount: Count,
    rowsSha256: Hash
  })
  .strict();
export const KeyDependencyInspectionSchema = KeyDependencyTargetSchema.extend({
  schemaVersion: z.literal("boardagent.key-dependency-inspection.v1"),
  digestMethod: z.literal("postgresql18-jsonb-row-sha256-chain-v1"),
  keyPurpose: z.enum([
    "oauth_signing",
    "evidence_signing",
    "browser_session",
    "data_kek",
    "backup_kek"
  ]),
  keyStateSha256: Hash,
  observedAt: z.iso.datetime({ precision: 6 }),
  auditHead: z
    .object({ sequence: z.string().regex(/^(?:0|[1-9][0-9]{0,18})$/u), sha256: Hash })
    .strict(),
  foreignKeyDependencies: z.array(Dependency).min(1).max(256),
  totalReferences: Count
})
  .strict()
  .superRefine((value, context) => {
    const names = value.foreignKeyDependencies.map((entry) => `${entry.table}.${entry.column}`);
    const sorted = names.toSorted();
    if (
      new Set(names).size !== names.length ||
      names.some((name, index) => name !== sorted[index]) ||
      value.foreignKeyDependencies.reduce((sum, entry) => sum + BigInt(entry.rowCount), 0n) !==
        BigInt(value.totalReferences)
    )
      context.addIssue({ code: "custom", message: "inconsistent key dependency inventory" });
  });

export type KeyDependencyInspection = z.infer<typeof KeyDependencyInspectionSchema>;

/** Declared database FK dependencies only; no mutation, filesystem inventory or custody claim. */
export async function inspectKeyDependenciesInTransaction(
  client: PoolClient,
  input: z.input<typeof KeyDependencyTargetSchema>
): Promise<{ readonly inspection: KeyDependencyInspection; readonly stateSha256: string }> {
  const target = KeyDependencyTargetSchema.parse(input);
  const result = await client.query<{ inspection: unknown }>(
    "select boardagent_inspect_key_dependencies($1,$2,$3) as inspection",
    [target.instanceId, target.organizationId, target.keyId]
  );
  const parsed = KeyDependencyInspectionSchema.safeParse(result.rows[0]?.inspection);
  if (
    result.rows.length !== 1 ||
    !parsed.success ||
    parsed.data.instanceId !== target.instanceId ||
    parsed.data.organizationId !== target.organizationId ||
    parsed.data.keyId !== target.keyId
  )
    throw new Error("invalid key dependency inspection result");
  const { observedAt: _observedAt, ...state } = parsed.data;
  return { inspection: parsed.data, stateSha256: canonicalSha256(state) };
}
