import type { PoolClient } from "pg";
import { z } from "zod";

import { UuidV7Schema, canonicalSha256 } from "@boardagent/contracts";

const DailyBackupMaximumAgeSeconds = 24 * 60 * 60;
const CountTextSchema = z.string().regex(/^(?:0|[1-9]\d*)$/u);
const SecondsTextSchema = z.string().regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u);

interface BackupReceiptHealthRow {
  readonly checked_receipts: string;
  readonly backup_receipts: string;
  readonly restore_receipts: string;
  readonly manifest_hash_mismatches: string;
  readonly manifest_canonical_mismatches: string;
  readonly manifest_schema_mismatches: string;
  readonly manifest_binding_mismatches: string;
  readonly key_binding_mismatches: string;
  readonly latest_backup_age_seconds: string | null;
}

export type BackupReceiptHealthIssue =
  | "receipt_missing"
  | "manifest_hash_mismatch"
  | "manifest_noncanonical"
  | "manifest_schema_mismatch"
  | "manifest_binding_mismatch"
  | "key_binding_mismatch"
  | "snapshot_time_invalid"
  | "backup_stale";

export interface BackupReceiptHealthResult {
  readonly valid: boolean;
  readonly issueClass: BackupReceiptHealthIssue | null;
  readonly checkedReceipts: number;
  readonly backupReceipts: number;
  readonly restoreReceipts: number;
  readonly manifestHashMismatches: number;
  readonly manifestCanonicalMismatches: number;
  readonly manifestSchemaMismatches: number;
  readonly manifestBindingMismatches: number;
  readonly keyBindingMismatches: number;
  readonly latestBackupAgeSeconds: number | null;
  readonly evidenceSha256: string;
}

function safeCount(value: string, field: string): number {
  const parsed = Number(BigInt(CountTextSchema.parse(value)));
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${field} must fit a nonnegative safe integer`);
  }
  return parsed;
}

function firstIssue(
  input: Omit<BackupReceiptHealthResult, "evidenceSha256" | "issueClass" | "valid">
): BackupReceiptHealthIssue | null {
  if (input.backupReceipts === 0) return "receipt_missing";
  if (input.manifestHashMismatches > 0) return "manifest_hash_mismatch";
  if (input.manifestCanonicalMismatches > 0) return "manifest_noncanonical";
  if (input.manifestSchemaMismatches > 0) return "manifest_schema_mismatch";
  if (input.manifestBindingMismatches > 0) return "manifest_binding_mismatch";
  if (input.keyBindingMismatches > 0) return "key_binding_mismatch";
  if (input.latestBackupAgeSeconds === null || input.latestBackupAgeSeconds < 0) {
    return "snapshot_time_invalid";
  }
  if (input.latestBackupAgeSeconds > DailyBackupMaximumAgeSeconds) return "backup_stale";
  return null;
}

/**
 * Revalidates immutable backup/restore receipt hashes, row bindings, source lineage,
 * key bindings and daily freshness. Only aggregate counts and a digest cross the
 * worker-only security-definer boundary.
 */
export async function inspectBackupReceiptHealthInTransaction(
  client: PoolClient,
  rawOrganizationId: string
): Promise<BackupReceiptHealthResult> {
  const organizationId = UuidV7Schema.parse(rawOrganizationId);
  const result = await client.query<BackupReceiptHealthRow>(
    `select checked_receipts::text,backup_receipts::text,restore_receipts::text,
            manifest_hash_mismatches::text,manifest_canonical_mismatches::text,
            manifest_schema_mismatches::text,manifest_binding_mismatches::text,
            key_binding_mismatches::text,latest_backup_age_seconds::text
       from public.boardagent_backup_receipt_health($1)`,
    [organizationId]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new Error("backup receipt health inspection returned no aggregate");
  }
  const latestBackupAgeSeconds =
    row.latest_backup_age_seconds === null
      ? null
      : Math.floor(Number(SecondsTextSchema.parse(row.latest_backup_age_seconds)));
  if (
    latestBackupAgeSeconds !== null &&
    (!Number.isSafeInteger(latestBackupAgeSeconds) || !Number.isFinite(latestBackupAgeSeconds))
  ) {
    throw new Error("backup age must fit a safe integer number of seconds");
  }
  const summary = {
    checkedReceipts: safeCount(row.checked_receipts, "checked receipt count"),
    backupReceipts: safeCount(row.backup_receipts, "backup receipt count"),
    restoreReceipts: safeCount(row.restore_receipts, "restore receipt count"),
    manifestHashMismatches: safeCount(row.manifest_hash_mismatches, "manifest hash mismatch count"),
    manifestCanonicalMismatches: safeCount(
      row.manifest_canonical_mismatches,
      "manifest canonical mismatch count"
    ),
    manifestSchemaMismatches: safeCount(
      row.manifest_schema_mismatches,
      "manifest schema mismatch count"
    ),
    manifestBindingMismatches: safeCount(
      row.manifest_binding_mismatches,
      "manifest binding mismatch count"
    ),
    keyBindingMismatches: safeCount(row.key_binding_mismatches, "key binding mismatch count"),
    latestBackupAgeSeconds
  };
  const issueClass = firstIssue(summary);
  return {
    valid: issueClass === null,
    issueClass,
    ...summary,
    evidenceSha256: canonicalSha256({
      schemaVersion: "boardagent.backup-receipt-health.v1",
      organizationRef: canonicalSha256({
        schemaVersion: "boardagent.operational-reference.v1",
        kind: "organization",
        id: organizationId
      }),
      issueClass,
      ...summary
    })
  };
}
