import { createHash } from "node:crypto";

import { Query, type PoolClient, type QueryArrayConfig } from "pg";
import { z } from "zod";
import { AuditRecoveryEvidenceSetSchema } from "@boardagent/audit";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual
} from "@boardagent/contracts";

import { verifyPersistedAuditEvidence } from "./checkpoints.js";
import { appendAuditEventsInTransaction } from "./audit.js";
import { verifyPersistedVoteCertificateInTransaction } from "./vote-close.js";
import { readActiveBackupKeyInTransaction } from "./backup-key.js";

const DecimalCountSchema = z.string().regex(/^(?:0|[1-9]\d*)$/u);
const PositiveDecimalSchema = z.string().regex(/^[1-9]\d*$/u);
const PgLsnSchema = z.string().regex(/^[0-9A-F]+\/[0-9A-F]+$/u);
const DatabaseNameSchema = z.string().min(1).max(63);
const MigrationNameSchema = z.string().regex(/^\d{4}_[a-z0-9_]+\.sql$/u);

export const BackupTableInventorySchema = z
  .object({
    table: z.string().regex(/^[a-z][a-z0-9_]{0,62}$/u),
    rowCount: DecimalCountSchema,
    rowsSha256: Sha256HexSchema
  })
  .strict();

export const BackupMigrationEntrySchema = z
  .object({
    version: z.number().int().positive(),
    name: MigrationNameSchema,
    sha256: Sha256HexSchema,
    appBuild: z.string().min(1).max(256),
    appliedAt: Rfc3339UtcSchema
  })
  .strict();

export const BackupPublicSigningKeySchema = z
  .object({
    id: UuidV7Schema,
    kid: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u),
    purpose: z.enum(["oauth_signing", "evidence_signing"]),
    algorithm: z.enum(["ES256", "EdDSA"]),
    publicJwk: z.record(z.string(), z.unknown()),
    activatedAt: Rfc3339UtcSchema,
    retiredAt: Rfc3339UtcSchema.nullable(),
    compromisedAt: Rfc3339UtcSchema.nullable()
  })
  .strict()
  .superRefine((key, context) => {
    if (typeof key.publicJwk["kty"] !== "string") {
      context.addIssue({ code: "custom", message: "public signing key JWK requires kty" });
    }
    if (
      (key.purpose === "oauth_signing" && key.algorithm !== "ES256") ||
      (key.purpose === "evidence_signing" && key.algorithm !== "EdDSA")
    ) {
      context.addIssue({ code: "custom", message: "public signing key purpose is mismatched" });
    }
  });

const BackupCheckpointBoundarySchema = z
  .object({
    checkpointId: UuidV7Schema,
    firstSequence: PositiveDecimalSchema,
    lastSequence: PositiveDecimalSchema,
    lastEventSha256: Sha256HexSchema,
    manifestSha256: Sha256HexSchema,
    signingKeyId: UuidV7Schema,
    createdAt: Rfc3339UtcSchema
  })
  .strict();

const BackupAuditBoundarySchema = z
  .object({
    eventCount: DecimalCountSchema,
    headSha256: Sha256HexSchema,
    latestCheckpoint: BackupCheckpointBoundarySchema.nullable()
  })
  .strict();

const BackupArtifactSchema = z
  .object({
    format: z.literal("postgresql-custom-encrypted-v1"),
    encryptedStorageLocator: z.string().min(1).max(4096),
    artifactSha256: Sha256HexSchema,
    byteLength: PositiveDecimalSchema,
    pgDumpVersion: z.string().min(1).max(256),
    encryptionTool: z.string().min(1).max(256),
    sourceImageDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u)
  })
  .strict();

const BackupBoundaryFields = {
  schemaVersion: z.literal("boardagent.backup-receipt.v1"),
  receiptKind: z.literal("backup"),
  receiptId: UuidV7Schema,
  instanceId: UuidV7Schema,
  organizationId: UuidV7Schema,
  sourceDatabase: DatabaseNameSchema,
  snapshotId: z.string().min(1).max(256),
  snapshotLsn: PgLsnSchema,
  snapshotAt: Rfc3339UtcSchema,
  migrationLedger: z.array(BackupMigrationEntrySchema).min(1).max(10_000),
  migrationLedgerSha256: Sha256HexSchema,
  publicSigningKeys: z.array(BackupPublicSigningKeySchema).max(10_000),
  publicKeyRegistrySha256: Sha256HexSchema,
  auditBoundary: BackupAuditBoundarySchema,
  tableInventory: z.array(BackupTableInventorySchema).min(1).max(1_000),
  schemaAuthoritySha256: Sha256HexSchema,
  contentSetSha256: Sha256HexSchema,
  encryptionKeyId: UuidV7Schema,
  // Old manifests remain readable; every new boundary/write requires these fields.
  encryptionKeyFingerprintSha256: Sha256HexSchema.optional(),
  encryptionKeyActivatedAt: Rfc3339UtcSchema.optional(),
  secretContinuity: z.literal("operator-custodied-secrets-not-contained-in-database-backup"),
  retention: z
    .object({ daily: z.literal(7), weekly: z.literal(4), monthly: z.literal(12) })
    .strict()
} as const;

function completeBackupKeyMetadata(value: {
  encryptionKeyFingerprintSha256?: string | undefined;
  encryptionKeyActivatedAt?: string | undefined;
}): boolean {
  return (
    (value.encryptionKeyFingerprintSha256 === undefined) ===
    (value.encryptionKeyActivatedAt === undefined)
  );
}
const BackupBoundaryObjectSchema = z.object(BackupBoundaryFields).strict();
const RecoveredBackupBoundaryObjectSchema = BackupBoundaryObjectSchema.extend({
  schemaVersion: z.literal("boardagent.backup-receipt.v2"),
  auditRecoveryEvidence: AuditRecoveryEvidenceSetSchema
});
export const PreparedBackupBoundarySchema = z
  .discriminatedUnion("schemaVersion", [
    BackupBoundaryObjectSchema,
    RecoveredBackupBoundaryObjectSchema
  ])
  .refine(completeBackupKeyMetadata, {
    message: "logical backup key identity is incomplete"
  });
export type PreparedBackupBoundary = z.infer<typeof PreparedBackupBoundarySchema>;

export const BackupManifestSchema = z
  .discriminatedUnion("schemaVersion", [
    BackupBoundaryObjectSchema.extend({ artifact: BackupArtifactSchema }),
    RecoveredBackupBoundaryObjectSchema.extend({ artifact: BackupArtifactSchema })
  ])
  .refine(completeBackupKeyMetadata, { message: "logical backup key identity is incomplete" });
export type BackupManifest = z.infer<typeof BackupManifestSchema>;

const RestoreVerificationSummarySchema = z
  .object({
    tableCount: z.number().int().positive(),
    rowCount: DecimalCountSchema,
    certificateCount: z.number().int().nonnegative(),
    auditEventCount: DecimalCountSchema,
    auditHeadSha256: Sha256HexSchema,
    auditCheckpointCount: z.number().int().nonnegative(),
    schemaAuthoritySha256: Sha256HexSchema,
    transactionReadOnly: z.literal(true),
    evidenceRepaired: z.literal(false),
    failures: z.tuple([])
  })
  .strict();

const RestoreReceiptManifestV1Schema = z
  .object({
    schemaVersion: z.literal("boardagent.restore-receipt.v1"),
    receiptKind: z.literal("restore"),
    receiptId: UuidV7Schema,
    sourceBackupReceiptId: UuidV7Schema,
    sourceBackupManifestSha256: Sha256HexSchema,
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    sourceDatabase: DatabaseNameSchema,
    restoredDatabase: DatabaseNameSchema,
    snapshotLsn: PgLsnSchema,
    snapshotAt: Rfc3339UtcSchema,
    contentSetSha256: Sha256HexSchema,
    encryptionKeyId: UuidV7Schema,
    sourceArtifactSha256: Sha256HexSchema,
    verifiedAt: Rfc3339UtcSchema,
    verification: RestoreVerificationSummarySchema
  })
  .strict();
export const RestoreReceiptManifestSchema = z
  .discriminatedUnion("schemaVersion", [
    RestoreReceiptManifestV1Schema,
    RestoreReceiptManifestV1Schema.extend({
      schemaVersion: z.literal("boardagent.restore-receipt.v2"),
      auditRecoveryEvidence: AuditRecoveryEvidenceSetSchema
    })
  ])
  .refine((manifest) => manifest.sourceDatabase !== manifest.restoredDatabase, {
    message: "restore verification database must differ from the source database"
  });
export type RestoreReceiptManifest = z.infer<typeof RestoreReceiptManifestSchema>;

export class BackupRestoreTransactionError extends Error {
  public constructor(
    public readonly code:
      | "backup_context_invalid"
      | "backup_key_invalid"
      | "backup_evidence_invalid"
      | "backup_manifest_invalid"
      | "backup_receipt_conflict"
      | "restore_not_isolated"
      | "restore_verification_failed",
    message: string
  ) {
    super(message);
    this.name = "BackupRestoreTransactionError";
  }
}

interface OperatorContext {
  readonly database_name: string;
  readonly transaction_isolation: string;
  readonly transaction_read_only: string;
  readonly transaction_scope: string;
  readonly role_name: string;
  readonly snapshot_at: string;
}

interface InstanceRow {
  readonly instance_id: string;
  readonly organization_id: string;
}

interface MigrationRow {
  readonly version: number;
  readonly name: string;
  readonly sha256: string;
  readonly app_build: string;
  readonly applied_at: string;
}

interface PublicKeyRow {
  readonly id: string;
  readonly kid: string;
  readonly purpose: "oauth_signing" | "evidence_signing";
  readonly algorithm: "ES256" | "EdDSA";
  readonly public_jwk: Readonly<Record<string, unknown>>;
  readonly activated_at: string;
  readonly retired_at: string | null;
  readonly compromised_at: string | null;
}

interface AuditHeadRow {
  readonly last_sequence: string;
  readonly last_event_sha256: Buffer;
}

interface CheckpointBoundaryRow {
  readonly id: string;
  readonly first_sequence: string;
  readonly last_sequence: string;
  readonly last_event_sha256: Buffer;
  readonly manifest_sha256: Buffer;
  readonly signing_key_id: string;
  readonly created_at: string;
}

interface CapturedDatabaseState {
  readonly migrationLedger: readonly z.infer<typeof BackupMigrationEntrySchema>[];
  readonly migrationLedgerSha256: string;
  readonly publicSigningKeys: readonly z.infer<typeof BackupPublicSigningKeySchema>[];
  readonly publicKeyRegistrySha256: string;
  readonly auditBoundary: z.infer<typeof BackupAuditBoundarySchema>;
  readonly tableInventory: readonly z.infer<typeof BackupTableInventorySchema>[];
  readonly schemaAuthoritySha256: string;
  readonly contentSetSha256: string;
}

function framedSha256(values: readonly string[]): string {
  const hash = createHash("sha256");
  for (const value of values) {
    const bytes = Buffer.from(value, "utf8");
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function readOperatorContext(
  client: PoolClient,
  expectedScope: "backup" | "restore"
): Promise<OperatorContext> {
  const result = await client.query<OperatorContext>(
    `select current_database() as database_name,
            current_setting('transaction_isolation') as transaction_isolation,
            current_setting('transaction_read_only') as transaction_read_only,
            current_setting('boardagent.transaction_scope',true) as transaction_scope,
            current_user as role_name,
            to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as snapshot_at`
  );
  const context = result.rows[0];
  if (
    !context ||
    result.rows.length !== 1 ||
    context.transaction_isolation !== "repeatable read" ||
    context.transaction_read_only !== "on" ||
    context.transaction_scope !== expectedScope ||
    context.role_name !== "boardagent_backup"
  ) {
    throw new BackupRestoreTransactionError(
      "backup_context_invalid",
      `${expectedScope} requires a managed repeatable-read read-only boardagent_backup transaction`
    );
  }
  return context;
}

async function readTableInventory(
  client: PoolClient
): Promise<readonly z.infer<typeof BackupTableInventorySchema>[]> {
  const driver = client as PoolClient & {
    readonly connectionParameters?: { readonly query_timeout?: unknown };
  };
  if (driver.connectionParameters?.query_timeout)
    throw new Error("backup inventory streaming does not support driver query_timeout");
  const tables = await client.query<{
    table_name: string;
    columns: string[];
    uuid_primary_order: boolean;
  }>(
    `select class.relname as table_name,attributes.names as columns,
            (exists(
              select 1 from pg_constraint as constraint_row
              join pg_index as index_row on index_row.indexrelid=constraint_row.conindid
              join pg_attribute as key on key.attrelid=class.oid
                and key.attnum=constraint_row.conkey[1]
              where constraint_row.conrelid=class.oid and constraint_row.contype='p'
                and cardinality(constraint_row.conkey)=1 and key.attname='id'
                and key.atttypid='uuid'::regtype and key.attnotnull
                and index_row.indisvalid and index_row.indisready and index_row.indisunique
            ) and not exists(select 1 from pg_inherits where inhparent=class.oid)
              and left(jsonb_object(attributes.names,
                array_fill(''::text,array[cardinality(attributes.names)]))::text,7)='{"id": '
            ) as uuid_primary_order
       from pg_class as class
       join pg_namespace as namespace on namespace.oid=class.relnamespace
       cross join lateral (
         select array(select attribute.attname::text from pg_attribute as attribute
                       where attribute.attrelid=class.oid and attribute.attnum>0
                         and not attribute.attisdropped order by attribute.attnum) as names
       ) as attributes
      where namespace.nspname='public' and class.relkind in ('r','p')
      order by class.relname collate "C"`
  );
  const inventory: z.infer<typeof BackupTableInventorySchema>[] = [];
  for (const { table_name: table, columns, uuid_primary_order: uuidPrimaryOrder } of tables.rows) {
    const cursor = "boardagent_backup_inventory_rows";
    const quoted = quoteIdentifier(table);
    // Preserve the original jsonb_each_text normalization: every column becomes
    // its JSON scalar text (or JSON text for an object/array), with SQL NULL retained.
    // Build that object directly instead of aggregating each row's fields twice.
    // OFFSET 0 keeps the normalized projection below the sort, so its byte-identical
    // value and text sort key share one computation. Zero-column rows formerly
    // aggregated zero entries into NULL; retain that representation as well.
    const scalarFields = columns
      .map((column) => `to_jsonb(source_row.${quoteIdentifier(column)})#>>'{}'`)
      .join(",");
    const normalized = columns.length
      ? `jsonb_object($1::text[],array[${scalarFields}]::text[])`
      : "null::jsonb";
    // A unique, non-null UUID first in the actual JSON text decides the complete
    // lexical row order. Its fixed-width hexadecimal text has the same order as UUID.
    // Use that index order only when the catalog and actual JSON key order prove it.
    // Inheritance, other key types and any earlier JSON property use the full sort.
    // Once UUID order is proven, no JSON sort key is needed. Return those same
    // normalized scalar texts directly, avoiding object encoding and parsing for
    // every row. Other tables still sort their complete legacy JSON text.
    const orderedRows = uuidPrimaryOrder
      ? `select ${scalarFields}
           from public.${quoted} as source_row order by source_row."id"`
      : `select normalized::text collate "C" as normalized_json
           from (select ${normalized} as normalized
                   from public.${quoted} as source_row offset 0) as normalized_rows
          order by normalized_json`;
    await client.query(
      `declare ${cursor} no scroll cursor for ${orderedRows}`,
      !uuidPrimaryOrder && columns.length ? [columns] : []
    );
    const hash = createHash("sha256");
    const length = Buffer.alloc(8);
    let rowCount = 0n;
    try {
      while (true) {
        const delivered = await new Promise<number>((resolve, reject) => {
          let count = 0;
          let failed = false;
          let failure: unknown;
          const queryConfig: QueryArrayConfig = {
            text: `fetch forward 1000 from ${cursor}`,
            rowMode: "array"
          };
          const query = new Query<(string | null)[]>(queryConfig);
          // Row listeners avoid retaining the whole page, including large documents.
          query.on("row", (row) => {
            count++;
            if (failed) return;
            try {
              // fromEntries preserves every name as own data, including __proto__.
              // All scalar expressions have text type and retain SQL NULL.
              const canonical = canonicalJson(
                uuidPrimaryOrder
                  ? Object.fromEntries(columns.map((column, index) => [column, row[index]]))
                  : row[0] === null
                    ? null
                    : JSON.parse(row[0]!)
              );
              const bytes = Buffer.from(canonical, "utf8");
              length.writeBigUInt64BE(BigInt(bytes.length));
              hash.update(length);
              hash.update(bytes);
              rowCount += 1n;
            } catch (error) {
              failed = true;
              failure = error;
            }
          });
          query.on("error", reject);
          // Drain this response before the finally block closes the cursor. A SQL
          // failure reaches the transaction wrapper for rollback and pooled cleanup.
          query.once("end", () => (failed ? reject(failure) : resolve(count)));
          client.query(query);
        });
        if (delivered < 1000) break;
      }
    } finally {
      await client.query(`close ${cursor}`).catch(() => undefined);
    }
    inventory.push(
      BackupTableInventorySchema.parse({
        table,
        rowCount: rowCount.toString(10),
        rowsSha256: hash.digest("hex")
      })
    );
  }
  return inventory;
}

async function readSchemaAuthoritySha256(client: PoolClient): Promise<string> {
  const catalogRows: unknown[] = [];
  const add = async (sql: string): Promise<void> => {
    const result = await client.query<Record<string, unknown>>(sql);
    catalogRows.push(...result.rows);
  };
  await add(`
    select 'column' as kind,table_name,column_name,ordinal_position::text,data_type,udt_name,
           is_nullable,column_default
      from information_schema.columns
     where table_schema='public'
     order by table_name collate "C",ordinal_position`);
  await add(`
    select 'constraint' as kind,class.relname as table_name,con.conname as name,
           con.contype::text as type,con.convalidated as validated,
           pg_get_constraintdef(con.oid,true) as definition
      from pg_constraint as con
      join pg_class as class on class.oid=con.conrelid
      join pg_namespace as namespace on namespace.oid=class.relnamespace
     where namespace.nspname='public'
     order by class.relname collate "C",con.conname collate "C"`);
  await add(`
    select 'relation' as kind,class.relname as table_name,class.relkind::text as relation_kind,
           class.relrowsecurity as row_security,class.relforcerowsecurity as force_row_security,
           pg_get_userbyid(class.relowner) as owner
      from pg_class as class
      join pg_namespace as namespace on namespace.oid=class.relnamespace
     where namespace.nspname='public' and class.relkind in ('r','p','v','m','S')
     order by class.relname collate "C"`);
  await add(`
    select 'index' as kind,tablename as table_name,indexname as name,indexdef as definition
      from pg_indexes where schemaname='public'
     order by tablename collate "C",indexname collate "C"`);
  await add(`
    select 'policy' as kind,tablename as table_name,policyname as name,roles::text,
           cmd,qual,with_check
      from pg_policies where schemaname='public'
     order by tablename collate "C",policyname collate "C"`);
  await add(`
    select 'trigger' as kind,class.relname as table_name,trigger.tgname as name,
           trigger.tgenabled::text as enabled,pg_get_triggerdef(trigger.oid,true) as definition
      from pg_trigger as trigger
      join pg_class as class on class.oid=trigger.tgrelid
      join pg_namespace as namespace on namespace.oid=class.relnamespace
     where namespace.nspname='public' and not trigger.tgisinternal
     order by class.relname collate "C",trigger.tgname collate "C"`);
  await add(`
    select 'function' as kind,procedure.proname as name,
           pg_get_function_identity_arguments(procedure.oid) as arguments,
           procedure.provolatile::text as volatility,procedure.prosecdef as security_definer,
           procedure.proacl::text as acl,pg_get_functiondef(procedure.oid) as definition
      from pg_proc as procedure
      join pg_namespace as namespace on namespace.oid=procedure.pronamespace
     where namespace.nspname='public'
     order by procedure.proname collate "C",
              pg_get_function_identity_arguments(procedure.oid) collate "C"`);
  await add(`
    select 'grant' as kind,grantee,table_name,privilege_type,is_grantable
      from information_schema.role_table_grants
     where table_schema='public'
       and grantee in ('boardagent_backup','boardagent_migrator','boardagent_server','boardagent_worker')
     order by grantee collate "C",table_name collate "C",privilege_type collate "C"`);
  await add(`
    select 'role' as kind,rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,
           rolcanlogin,rolreplication,rolbypassrls
      from pg_roles
     where rolname in ('boardagent_backup','boardagent_migrator','boardagent_server','boardagent_worker')
     order by rolname collate "C"`);
  const canonical = catalogRows.map((row) => canonicalJson(row)).toSorted();
  return framedSha256(canonical);
}

async function captureDatabaseState(client: PoolClient): Promise<CapturedDatabaseState> {
  const migrations = await client.query<MigrationRow>(
    `select version,name,sha256,app_build,
            to_char(applied_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as applied_at
       from schema_migrations order by version`
  );
  const migrationLedger = migrations.rows.map((row) =>
    BackupMigrationEntrySchema.parse({
      version: row.version,
      name: row.name,
      sha256: row.sha256,
      appBuild: row.app_build,
      appliedAt: row.applied_at
    })
  );
  const migrationLedgerSha256 = canonicalSha256(migrationLedger);

  const keyRows = await client.query<PublicKeyRow>(
    `select id,kid,purpose,algorithm,public_jwk,
            to_char(activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as activated_at,
            case when retired_at is null then null else
              to_char(retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end as retired_at,
            case when compromised_at is null then null else
              to_char(compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end as compromised_at
       from crypto_key_registry
      where purpose in ('oauth_signing','evidence_signing')
      order by activated_at,id`
  );
  const publicSigningKeys = keyRows.rows.map((row) =>
    BackupPublicSigningKeySchema.parse({
      id: row.id,
      kid: row.kid,
      purpose: row.purpose,
      algorithm: row.algorithm,
      publicJwk: row.public_jwk,
      activatedAt: row.activated_at,
      retiredAt: row.retired_at,
      compromisedAt: row.compromised_at
    })
  );
  const publicKeyRegistrySha256 = canonicalSha256(publicSigningKeys);

  const headResult = await client.query<AuditHeadRow>(
    "select last_sequence::text,last_event_sha256 from audit_chain_head where singleton_key"
  );
  const checkpointResult = await client.query<CheckpointBoundaryRow>(
    `select id,first_sequence::text,last_sequence::text,last_event_sha256,manifest_sha256,
            signing_key_id,
            to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as created_at
       from audit_checkpoints order by audit_checkpoints.last_sequence desc limit 1`
  );
  const head = headResult.rows[0];
  if (!head || headResult.rows.length !== 1) {
    throw new BackupRestoreTransactionError(
      "backup_evidence_invalid",
      "audit head is missing or duplicated"
    );
  }
  const checkpoint = checkpointResult.rows[0];
  const auditBoundary = BackupAuditBoundarySchema.parse({
    eventCount: head.last_sequence,
    headSha256: head.last_event_sha256.toString("hex"),
    latestCheckpoint: checkpoint
      ? {
          checkpointId: checkpoint.id,
          firstSequence: checkpoint.first_sequence,
          lastSequence: checkpoint.last_sequence,
          lastEventSha256: checkpoint.last_event_sha256.toString("hex"),
          manifestSha256: checkpoint.manifest_sha256.toString("hex"),
          signingKeyId: checkpoint.signing_key_id,
          createdAt: checkpoint.created_at
        }
      : null
  });

  const tableInventory = await readTableInventory(client);
  const schemaAuthoritySha256 = await readSchemaAuthoritySha256(client);
  const contentSetSha256 = canonicalSha256({
    migrationLedgerSha256,
    publicKeyRegistrySha256,
    auditBoundary,
    schemaAuthoritySha256,
    tableInventory
  });
  return {
    migrationLedger,
    migrationLedgerSha256,
    publicSigningKeys,
    publicKeyRegistrySha256,
    auditBoundary,
    tableInventory,
    schemaAuthoritySha256,
    contentSetSha256
  };
}

export async function captureBackupBoundaryInTransaction(
  client: PoolClient,
  rawInput: {
    readonly receiptId: string;
    readonly encryptionKeyId: string;
    readonly encryptionKeyFingerprintSha256: string;
  }
): Promise<PreparedBackupBoundary> {
  const receiptId = UuidV7Schema.parse(rawInput.receiptId);
  const encryptionKeyId = UuidV7Schema.parse(rawInput.encryptionKeyId);
  const fingerprint = Sha256HexSchema.parse(rawInput.encryptionKeyFingerprintSha256);
  const context = await readOperatorContext(client, "backup");
  const instanceResult = await client.query<InstanceRow>(
    "select instance_id,organization_id from system_instance where singleton_key"
  );
  const instance = instanceResult.rows[0];
  if (!instance || instanceResult.rows.length !== 1) {
    throw new BackupRestoreTransactionError(
      "backup_evidence_invalid",
      "backup requires one initialized system instance"
    );
  }
  const keyIdentity = await readActiveBackupKeyInTransaction(client, encryptionKeyId).catch(() => {
    throw new BackupRestoreTransactionError(
      "backup_key_invalid",
      "backup requires an active registered backup key fingerprint"
    );
  });
  if (
    keyIdentity.organizationId !== instance.organization_id ||
    keyIdentity.fingerprintSha256 !== fingerprint
  ) {
    throw new BackupRestoreTransactionError(
      "backup_key_invalid",
      "backup key bytes do not match the registered fingerprint"
    );
  }
  const snapshotResult = await client.query<{ snapshot_id: string; snapshot_lsn: string }>(
    "select pg_export_snapshot() as snapshot_id,pg_current_wal_lsn()::text as snapshot_lsn"
  );
  const snapshot = snapshotResult.rows[0];
  if (!snapshot) throw new Error("PostgreSQL did not export the backup snapshot boundary");

  const auditVerification = await verifyPersistedAuditEvidence(client);
  if (!auditVerification.valid || !auditVerification.ready) {
    throw new BackupRestoreTransactionError(
      "backup_evidence_invalid",
      `backup refuses an invalid or checkpoint-lagged audit chain${
        auditVerification.valid ? "" : `: ${auditVerification.reason}`
      }`
    );
  }
  const state = await captureDatabaseState(client);
  if (state.auditBoundary.eventCount !== "0" && state.auditBoundary.latestCheckpoint === null) {
    throw new BackupRestoreTransactionError(
      "backup_evidence_invalid",
      "a nonempty audit chain requires a persisted signed checkpoint before backup"
    );
  }
  return PreparedBackupBoundarySchema.parse({
    ...(auditVerification.recoveryEvidence === undefined
      ? { schemaVersion: "boardagent.backup-receipt.v1" }
      : {
          schemaVersion: "boardagent.backup-receipt.v2",
          auditRecoveryEvidence: auditVerification.recoveryEvidence
        }),
    receiptKind: "backup",
    receiptId,
    instanceId: instance.instance_id,
    organizationId: instance.organization_id,
    sourceDatabase: context.database_name,
    snapshotId: snapshot.snapshot_id,
    snapshotLsn: snapshot.snapshot_lsn,
    snapshotAt: context.snapshot_at,
    ...state,
    encryptionKeyId,
    encryptionKeyFingerprintSha256: fingerprint,
    encryptionKeyActivatedAt: keyIdentity.activatedAt,
    secretContinuity: "operator-custodied-secrets-not-contained-in-database-backup",
    retention: { daily: 7, weekly: 4, monthly: 12 }
  });
}

export function finalizeBackupManifest(
  rawBoundary: PreparedBackupBoundary,
  artifact: z.input<typeof BackupArtifactSchema>
): BackupManifest {
  const boundary = PreparedBackupBoundarySchema.parse(rawBoundary);
  if (
    boundary.encryptionKeyFingerprintSha256 === undefined ||
    boundary.encryptionKeyActivatedAt === undefined
  ) {
    throw new BackupRestoreTransactionError(
      "backup_manifest_invalid",
      "new backups require a registered key fingerprint"
    );
  }
  return BackupManifestSchema.parse({ ...boundary, artifact });
}

export interface PersistedRecoveryReceipt {
  readonly receiptId: string;
  readonly manifestSha256: string;
  readonly replayed: boolean;
  readonly auditEventId?: string;
  readonly auditSequence?: string;
}

async function lookupReceipt(
  client: PoolClient,
  receiptId: string
): Promise<
  | {
      readonly receipt_kind: "backup" | "restore";
      readonly manifest_sha256: Buffer;
      readonly source_backup_receipt_id: string | null;
    }
  | undefined
> {
  const result = await client.query<{
    receipt_kind: "backup" | "restore";
    manifest_sha256: Buffer;
    source_backup_receipt_id: string | null;
  }>("select * from boardagent_backup_receipt_lookup($1)", [receiptId]);
  return result.rows[0];
}

export async function recordBackupCompletedInTransaction(
  client: PoolClient,
  rawInput: { readonly manifest: BackupManifest; readonly auditEventId: string }
): Promise<PersistedRecoveryReceipt> {
  const manifest = BackupManifestSchema.parse(rawInput.manifest);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const canonicalManifest = Buffer.from(canonicalJson(manifest), "utf8");
  const manifestSha256 = canonicalSha256(manifest);
  const existing = await lookupReceipt(client, manifest.receiptId);
  if (existing) {
    if (
      existing.receipt_kind !== "backup" ||
      existing.source_backup_receipt_id !== null ||
      !safeHashEqual(existing.manifest_sha256.toString("hex"), manifestSha256)
    ) {
      throw new BackupRestoreTransactionError(
        "backup_receipt_conflict",
        "backup receipt identifier was already used for different evidence"
      );
    }
    return { receiptId: manifest.receiptId, manifestSha256, replayed: true };
  }
  await client.query(
    `insert into backup_receipts(
       id,organization_id,receipt_kind,schema_version,canonical_manifest,manifest_sha256,
       snapshot_lsn,snapshot_at,content_set_sha256,encryption_key_id,state
     ) values ($1,$2,'backup',$3,$4,$5,$6::pg_lsn,$7::timestamptz,$8,$9,'created')`,
    [
      manifest.receiptId,
      manifest.organizationId,
      manifest.schemaVersion,
      canonicalManifest,
      Buffer.from(manifestSha256, "hex"),
      manifest.snapshotLsn,
      manifest.snapshotAt,
      Buffer.from(manifest.contentSetSha256, "hex"),
      manifest.encryptionKeyId
    ]
  );
  const [event] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: manifest.organizationId,
      event: {
        eventId: auditEventId,
        eventType: "backup_completed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "backup_receipt",
        entityId: manifest.receiptId,
        boardId: null,
        origin: "worker",
        details: {
          manifestSha256,
          contentSetSha256: manifest.contentSetSha256,
          snapshotLsn: manifest.snapshotLsn,
          artifactSha256: manifest.artifact.artifactSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!event) throw new Error("backup completion audit append returned no event");
  return {
    receiptId: manifest.receiptId,
    manifestSha256,
    replayed: false,
    auditEventId: event.eventId,
    auditSequence: event.sequence.toString(10)
  };
}

async function restoreInvariantFailures(client: PoolClient): Promise<readonly string[]> {
  const failures: string[] = [];
  const roles = await client.query<{
    rolname: string;
    rolsuper: boolean;
    rolcanlogin: boolean;
    rolcreaterole: boolean;
    rolcreatedb: boolean;
    rolreplication: boolean;
    rolbypassrls: boolean;
  }>(
    `select rolname,rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls
       from pg_roles
      where rolname in ('boardagent_backup','boardagent_migrator','boardagent_server','boardagent_worker')
      order by rolname`
  );
  if (
    roles.rows.length !== 4 ||
    roles.rows.some(
      (role) =>
        role.rolsuper ||
        role.rolcanlogin ||
        role.rolcreaterole ||
        role.rolcreatedb ||
        role.rolreplication ||
        role.rolbypassrls
    )
  ) {
    failures.push("runtime_role_attributes_invalid");
  }
  const rls = await client.query<{ table_name: string }>(
    `select class.relname as table_name
       from pg_class as class
       join pg_namespace as namespace on namespace.oid=class.relnamespace
      where namespace.nspname='public' and class.relkind in ('r','p')
        and class.relname<>'schema_migrations'
        and (not class.relrowsecurity or not class.relforcerowsecurity)
      order by class.relname`
  );
  if (rls.rows.length > 0) failures.push("forced_rls_incomplete");
  const backupMutation = await client.query<{ table_name: string }>(
    `select class.relname as table_name
       from pg_class as class
       join pg_namespace as namespace on namespace.oid=class.relnamespace
      where namespace.nspname='public' and class.relkind in ('r','p')
        and (has_table_privilege('boardagent_backup',class.oid,'INSERT')
          or has_table_privilege('boardagent_backup',class.oid,'UPDATE')
          or has_table_privilege('boardagent_backup',class.oid,'DELETE')
          or has_table_privilege('boardagent_backup',class.oid,'TRUNCATE'))`
  );
  if (backupMutation.rows.length > 0) failures.push("backup_role_has_mutation_privilege");
  const invalidConstraints = await client.query<{ count: string }>(
    `select count(*)::text as count
       from pg_constraint as con
       join pg_class as class on class.oid=con.conrelid
       join pg_namespace as namespace on namespace.oid=class.relnamespace
      where namespace.nspname='public' and not con.convalidated`
  );
  if (invalidConstraints.rows[0]?.count !== "0") failures.push("unvalidated_constraint");
  const aiAccountability = await client.query<{ count: string }>(
    `select count(*)::text as count from members
      where (member_kind='ai_system' and accountable_principal_id is null)
         or (member_kind='human' and accountable_principal_id is not null)`
  );
  if (aiAccountability.rows[0]?.count !== "0") failures.push("ai_accountability_invalid");
  const tokenKeys = await client.query<{ count: string }>(
    `select count(*)::text as count
       from access_token_records as token
       join system_instance as instance on instance.singleton_key
       left join crypto_key_registry as key on key.id=token.signing_key_id
      where key.id is null or key.organization_id<>token.organization_id
         or key.purpose<>'oauth_signing' or key.algorithm<>'ES256' or key.public_jwk is null
         or token.resource_uri<>instance.canonical_resource_uri
         or token.expires_at>token.issued_at+interval '15 minutes'`
  );
  if (tokenKeys.rows[0]?.count !== "0") failures.push("access_token_key_binding_invalid");
  const keyTopology = await client.query<{ count: string }>(
    `select count(*)::text as count from crypto_key_registry
      where (purpose='oauth_signing' and (algorithm<>'ES256' or public_jwk is null))
         or (purpose='evidence_signing' and (algorithm<>'EdDSA' or public_jwk is null))
         or (purpose in ('browser_session','data_kek','backup_kek') and public_jwk is not null)
         or (purpose in ('data_kek','backup_kek') and algorithm<>'A256GCM')`
  );
  if (keyTopology.rows[0]?.count !== "0") failures.push("key_topology_invalid");
  return failures;
}

export type RestoreVerificationResult =
  | {
      readonly valid: true;
      readonly ready: true;
      readonly receiptManifest: RestoreReceiptManifest;
    }
  | { readonly valid: false; readonly ready: false; readonly failures: readonly string[] };

export async function verifyRestoredBackupInTransaction(
  client: PoolClient,
  rawInput: {
    readonly sourceManifest: BackupManifest;
    readonly sourceBackupReceiptId: string;
    readonly sourceBackupManifestSha256: string;
    readonly restoreReceiptId: string;
  }
): Promise<RestoreVerificationResult> {
  const sourceManifest = BackupManifestSchema.parse(rawInput.sourceManifest);
  const sourceBackupReceiptId = UuidV7Schema.parse(rawInput.sourceBackupReceiptId);
  const sourceBackupManifestSha256 = Sha256HexSchema.parse(rawInput.sourceBackupManifestSha256);
  const restoreReceiptId = UuidV7Schema.parse(rawInput.restoreReceiptId);
  const calculatedSourceHash = canonicalSha256(sourceManifest);
  if (!safeHashEqual(sourceBackupManifestSha256, calculatedSourceHash)) {
    throw new BackupRestoreTransactionError(
      "backup_manifest_invalid",
      "source backup manifest hash does not match its canonical bytes"
    );
  }
  const context = await readOperatorContext(client, "restore");
  if (context.database_name === sourceManifest.sourceDatabase) {
    throw new BackupRestoreTransactionError(
      "restore_not_isolated",
      "restore verification refuses the source database"
    );
  }
  const instanceResult = await client.query<InstanceRow>(
    "select instance_id,organization_id from system_instance where singleton_key"
  );
  const instance = instanceResult.rows[0];
  const failures: string[] = [];
  if (
    !instance ||
    instanceResult.rows.length !== 1 ||
    instance.instance_id !== sourceManifest.instanceId ||
    instance.organization_id !== sourceManifest.organizationId
  ) {
    failures.push("system_instance_mismatch");
  }

  const state = await captureDatabaseState(client);
  if (!safeHashEqual(state.migrationLedgerSha256, sourceManifest.migrationLedgerSha256)) {
    failures.push("migration_ledger_mismatch");
  }
  if (!safeHashEqual(state.publicKeyRegistrySha256, sourceManifest.publicKeyRegistrySha256)) {
    failures.push("public_key_registry_mismatch");
  }
  if (!safeHashEqual(state.schemaAuthoritySha256, sourceManifest.schemaAuthoritySha256)) {
    failures.push("schema_authority_mismatch");
  }
  if (canonicalSha256(state.auditBoundary) !== canonicalSha256(sourceManifest.auditBoundary)) {
    failures.push("audit_boundary_mismatch");
  }
  if (canonicalSha256(state.tableInventory) !== canonicalSha256(sourceManifest.tableInventory)) {
    failures.push("table_content_mismatch");
  }
  if (!safeHashEqual(state.contentSetSha256, sourceManifest.contentSetSha256)) {
    failures.push("content_set_mismatch");
  }

  const audit = await verifyPersistedAuditEvidence(client);
  if (!audit.valid) failures.push(`audit_invalid:${audit.reason}`);
  else if (!audit.ready) failures.push("audit_checkpoint_lagged");
  if (
    audit.valid &&
    canonicalJson(audit.recoveryEvidence ?? []) !==
      canonicalJson(
        sourceManifest.schemaVersion === "boardagent.backup-receipt.v2"
          ? sourceManifest.auditRecoveryEvidence
          : []
      )
  )
    failures.push("audit_recovery_evidence_mismatch");
  if (
    sourceManifest.auditBoundary.eventCount !== "0" &&
    sourceManifest.auditBoundary.latestCheckpoint === null
  ) {
    failures.push("audit_checkpoint_missing");
  }

  const certificates = await client.query<{
    organization_id: string;
    public_id: Buffer;
    certificate_id: string;
  }>(
    `select organization_id,public_id,id as certificate_id
       from vote_certificates where state='current' order by id`
  );
  for (const certificate of certificates.rows) {
    const verified = await verifyPersistedVoteCertificateInTransaction(client, {
      organizationId: certificate.organization_id,
      certificatePublicId: certificate.public_id.toString("base64url")
    });
    if (!verified.valid || verified.certificateId !== certificate.certificate_id) {
      failures.push(`vote_certificate_invalid:${certificate.certificate_id}`);
    }
  }
  failures.push(...(await restoreInvariantFailures(client)));
  const uniqueFailures = [...new Set(failures)].toSorted();
  if (uniqueFailures.length > 0 || !audit.valid) {
    return { valid: false, ready: false, failures: uniqueFailures };
  }
  const rowCount = state.tableInventory.reduce(
    (total, table) => total + BigInt(table.rowCount),
    0n
  );
  const receiptManifest = RestoreReceiptManifestSchema.parse({
    ...(audit.recoveryEvidence === undefined
      ? { schemaVersion: "boardagent.restore-receipt.v1" }
      : {
          schemaVersion: "boardagent.restore-receipt.v2",
          auditRecoveryEvidence: audit.recoveryEvidence
        }),
    receiptKind: "restore",
    receiptId: restoreReceiptId,
    sourceBackupReceiptId,
    sourceBackupManifestSha256,
    instanceId: sourceManifest.instanceId,
    organizationId: sourceManifest.organizationId,
    sourceDatabase: sourceManifest.sourceDatabase,
    restoredDatabase: context.database_name,
    snapshotLsn: sourceManifest.snapshotLsn,
    snapshotAt: sourceManifest.snapshotAt,
    contentSetSha256: sourceManifest.contentSetSha256,
    encryptionKeyId: sourceManifest.encryptionKeyId,
    sourceArtifactSha256: sourceManifest.artifact.artifactSha256,
    verifiedAt: context.snapshot_at,
    verification: {
      tableCount: state.tableInventory.length,
      rowCount: rowCount.toString(10),
      certificateCount: certificates.rows.length,
      auditEventCount: audit.eventCount,
      auditHeadSha256: audit.headHash,
      auditCheckpointCount: audit.checkpointCount,
      schemaAuthoritySha256: state.schemaAuthoritySha256,
      transactionReadOnly: true,
      evidenceRepaired: false,
      failures: []
    }
  });
  return { valid: true, ready: true, receiptManifest };
}

export async function recordRestoreVerifiedInTransaction(
  client: PoolClient,
  rawInput: { readonly manifest: RestoreReceiptManifest; readonly auditEventId: string }
): Promise<PersistedRecoveryReceipt> {
  const manifest = RestoreReceiptManifestSchema.parse(rawInput.manifest);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const canonicalManifest = Buffer.from(canonicalJson(manifest), "utf8");
  const manifestSha256 = canonicalSha256(manifest);
  const existing = await lookupReceipt(client, manifest.receiptId);
  if (existing) {
    if (
      existing.receipt_kind !== "restore" ||
      existing.source_backup_receipt_id !== manifest.sourceBackupReceiptId ||
      !safeHashEqual(existing.manifest_sha256.toString("hex"), manifestSha256)
    ) {
      throw new BackupRestoreTransactionError(
        "backup_receipt_conflict",
        "restore receipt identifier was already used for different evidence"
      );
    }
    return { receiptId: manifest.receiptId, manifestSha256, replayed: true };
  }
  const source = await lookupReceipt(client, manifest.sourceBackupReceiptId);
  if (
    !source ||
    source.receipt_kind !== "backup" ||
    !safeHashEqual(source.manifest_sha256.toString("hex"), manifest.sourceBackupManifestSha256)
  ) {
    throw new BackupRestoreTransactionError(
      "backup_manifest_invalid",
      "restore receipt source does not match immutable backup evidence"
    );
  }
  await client.query(
    `insert into backup_receipts(
       id,organization_id,receipt_kind,source_backup_receipt_id,schema_version,
       canonical_manifest,manifest_sha256,snapshot_lsn,snapshot_at,content_set_sha256,
       encryption_key_id,state,verified_restore_at
     ) values ($1,$2,'restore',$3,$4,$5,$6,$7::pg_lsn,$8::timestamptz,$9,$10,'verified',$11::timestamptz)`,
    [
      manifest.receiptId,
      manifest.organizationId,
      manifest.sourceBackupReceiptId,
      manifest.schemaVersion,
      canonicalManifest,
      Buffer.from(manifestSha256, "hex"),
      manifest.snapshotLsn,
      manifest.snapshotAt,
      Buffer.from(manifest.contentSetSha256, "hex"),
      manifest.encryptionKeyId,
      manifest.verifiedAt
    ]
  );
  const [event] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: manifest.organizationId,
      event: {
        eventId: auditEventId,
        eventType: "restore_verified",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "backup_receipt",
        entityId: manifest.receiptId,
        boardId: null,
        origin: "worker",
        details: {
          manifestSha256,
          sourceBackupReceiptId: manifest.sourceBackupReceiptId,
          sourceBackupManifestSha256: manifest.sourceBackupManifestSha256,
          restoredDatabase: manifest.restoredDatabase,
          contentSetSha256: manifest.contentSetSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!event) throw new Error("restore verification audit append returned no event");
  return {
    receiptId: manifest.receiptId,
    manifestSha256,
    replayed: false,
    auditEventId: event.eventId,
    auditSequence: event.sequence.toString(10)
  };
}
