import type { PoolClient } from "pg";
import { z } from "zod";
import {
  AuditRecoveryEvidenceSetSchema,
  type SignedAuditRecoveryCheckpoint
} from "@boardagent/audit";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  type JsonValue
} from "@boardagent/contracts";

import { enqueueRequestJobInTransaction } from "../jobs.js";
import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

const PositiveBigintStringSchema = z.string().regex(/^[1-9]\d*$/u);
const NonnegativeBigintStringSchema = z.string().regex(/^(?:0|[1-9]\d*)$/u);
const StorageLocatorSchema = z.string().min(1).max(4096);
const FailureClassSchema = z.string().regex(/^[a-z][a-z0-9_]{1,127}$/u);
const PublicIdSchema = z.instanceof(Uint8Array).refine((value) => value.byteLength === 32);

export const SystemDataClassSchema = z.enum([
  "audit",
  "decisions",
  "documents",
  "governance",
  "identity_authority",
  "management",
  "meetings",
  "minutes_tasks",
  "operations"
]);

const SortedDataClassesSchema = z
  .array(SystemDataClassSchema)
  .min(1)
  .max(SystemDataClassSchema.options.length)
  .refine(
    (values) =>
      new Set(values).size === values.length &&
      values.every((value, index) => index === 0 || values[index - 1]! < value),
    "system export data classes must be unique and sorted"
  );

export const ExportScopeSchema = z.discriminatedUnion("exportType", [
  z
    .object({
      schemaVersion: z.literal("boardagent.export-scope.v1"),
      exportType: z.literal("audit_chain"),
      organizationId: UuidV7Schema,
      boardId: UuidV7Schema.nullable(),
      firstSequence: PositiveBigintStringSchema,
      lastSequence: PositiveBigintStringSchema,
      includeCheckpoints: z.literal(true),
      includePublicKeys: z.literal(true)
    })
    .strict()
    .refine(
      (scope) => BigInt(scope.lastSequence) >= BigInt(scope.firstSequence),
      "audit export sequence range is inverted"
    )
    .refine(
      (scope) => BigInt(scope.lastSequence) - BigInt(scope.firstSequence) < 1_000_000n,
      "one audit export may contain at most 1,000,000 sequence positions"
    ),
  z
    .object({
      schemaVersion: z.literal("boardagent.export-scope.v1"),
      exportType: z.literal("system_data"),
      organizationId: UuidV7Schema,
      boardId: UuidV7Schema.nullable(),
      scope: z.enum(["organization", "board", "member_portability"]),
      memberId: UuidV7Schema.nullable(),
      purpose: z.string().min(1).max(65_536),
      dataClasses: SortedDataClassesSchema,
      includeCanonicalContent: z.literal(true),
      excludeSecretMaterial: z.literal(true)
    })
    .strict()
    .superRefine((scope, context) => {
      if (
        (scope.scope === "organization" && (scope.boardId !== null || scope.memberId !== null)) ||
        (scope.scope === "board" && (scope.boardId === null || scope.memberId !== null)) ||
        (scope.scope === "member_portability" &&
          (scope.boardId !== null || scope.memberId === null))
      ) {
        context.addIssue({ code: "custom", message: "system export scope target is invalid" });
      }
    })
]);

export type ExportScope = z.infer<typeof ExportScopeSchema>;

export async function resolveAuditExportRangeInTransaction(
  client: PoolClient,
  input: {
    readonly boardId: string | null;
    readonly firstSequence: string;
    readonly lastSequence: string | null;
    readonly exactOrigin: string;
  }
): Promise<{ readonly firstSequence: string; readonly lastSequence: string }> {
  const result = await client.query<{ first_sequence: string; last_sequence: string }>(
    `select first_sequence,last_sequence
       from boardagent_resolve_audit_export_range($1,$2,$3,$4)`,
    [
      input.boardId === null ? null : UuidV7Schema.parse(input.boardId),
      NonnegativeBigintStringSchema.parse(input.firstSequence),
      input.lastSequence === null ? null : PositiveBigintStringSchema.parse(input.lastSequence),
      input.exactOrigin
    ]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new ExportTransactionError("export_unavailable", "audit export range is unavailable");
  }
  return {
    firstSequence: PositiveBigintStringSchema.parse(row.first_sequence),
    lastSequence: PositiveBigintStringSchema.parse(row.last_sequence)
  };
}

const ExportComponentDescriptorSchema = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9_:-]{1,127}$/u),
    rowCount: NonnegativeBigintStringSchema,
    byteLength: NonnegativeBigintStringSchema,
    sha256: Sha256HexSchema
  })
  .strict();

const ExportSnapshotManifestV1Schema = z
  .object({
    schemaVersion: z.literal("boardagent.export-snapshot.v1"),
    exportRequestId: UuidV7Schema,
    organizationId: UuidV7Schema,
    boardId: UuidV7Schema.nullable(),
    exportType: z.enum(["audit_chain", "system_data"]),
    scopeSha256: Sha256HexSchema,
    transactionSnapshot: z.string().min(1).max(512),
    auditHeadSequence: NonnegativeBigintStringSchema,
    auditHeadSha256: Sha256HexSchema,
    latestCheckpointSha256: Sha256HexSchema,
    migrationLedgerSha256: Sha256HexSchema,
    capturedAt: Rfc3339UtcSchema,
    plaintextContentSetSha256: Sha256HexSchema,
    components: z.array(ExportComponentDescriptorSchema).min(1).max(256)
  })
  .strict();
export const ExportSnapshotManifestSchema = z
  .discriminatedUnion("schemaVersion", [
    ExportSnapshotManifestV1Schema,
    ExportSnapshotManifestV1Schema.extend({
      schemaVersion: z.literal("boardagent.export-snapshot.v2"),
      auditRecoveryEvidence: AuditRecoveryEvidenceSetSchema
    })
  ])
  .refine(
    (manifest) =>
      manifest.components.every(
        (component, index) => index === 0 || manifest.components[index - 1]!.name < component.name
      ),
    "export snapshot components must be uniquely sorted"
  );

export type ExportSnapshotManifest = z.infer<typeof ExportSnapshotManifestSchema>;

const ExportChunkManifestSchema = z
  .object({
    chunkId: UuidV7Schema,
    ordinal: z.number().int().min(0).max(1_000_000),
    byteOffset: NonnegativeBigintStringSchema,
    byteLength: z
      .number()
      .int()
      .min(1)
      .max(10 * 1024 * 1024),
    chunkSha256: Sha256HexSchema,
    storageLocator: StorageLocatorSchema
  })
  .strict();

export const ExportArtifactManifestSchema = z
  .object({
    schemaVersion: z.literal("boardagent.export-artifact.v1"),
    artifactId: UuidV7Schema,
    exportRequestId: UuidV7Schema,
    organizationId: UuidV7Schema,
    scopeSha256: Sha256HexSchema,
    snapshotSha256: Sha256HexSchema,
    plaintextContentSetSha256: Sha256HexSchema,
    encryptedContentSetSha256: Sha256HexSchema,
    encryptionKeyId: UuidV7Schema,
    encryptedStorageLocator: StorageLocatorSchema,
    byteLength: NonnegativeBigintStringSchema,
    complete: z.boolean(),
    chunks: z.array(ExportChunkManifestSchema).min(1).max(1_000_000)
  })
  .strict()
  .superRefine((manifest, context) => {
    let offset = 0n;
    const locators = new Set<string>();
    for (const [index, chunk] of manifest.chunks.entries()) {
      if (chunk.ordinal !== index || BigInt(chunk.byteOffset) !== offset) {
        context.addIssue({
          code: "custom",
          message: "export chunks must be contiguous and ordered"
        });
        return;
      }
      if (locators.has(chunk.storageLocator)) {
        context.addIssue({ code: "custom", message: "export chunk locators must be unique" });
        return;
      }
      locators.add(chunk.storageLocator);
      offset += BigInt(chunk.byteLength);
    }
    if (offset !== BigInt(manifest.byteLength)) {
      context.addIssue({ code: "custom", message: "export byte length does not match its chunks" });
    }
  });

export type ExportArtifactManifest = z.infer<typeof ExportArtifactManifestSchema>;

export interface ExportRequestStageInput {
  readonly exportRequestId: string;
  readonly publicId: Uint8Array;
  readonly scope: unknown;
  /** Exact database-derived expiry presented to the human before the stage is persisted. */
  readonly expiresAt?: string;
  readonly stage: Omit<
    StageActionInput,
    | "boardId"
    | "actingForMemberId"
    | "actionCode"
    | "targetType"
    | "targetId"
    | "canonicalSchema"
    | "canonicalPayload"
    | "packageSha256"
    | "originalName"
  >;
}

export interface PreparedExportRequest {
  readonly exportRequestId: string;
  readonly publicId: string;
  readonly organizationId: string;
  readonly requesterMemberId: string;
  readonly boardId: string | null;
  readonly actionCode: "export_audit_chain" | "export_system_data";
  readonly targetType: "export_request";
  readonly canonicalSchema: "boardagent.export-request.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
  readonly scope: ExportScope;
  readonly recentAuthAt: string;
  readonly expiresAt: string;
}

export interface ExportRequestConfirmationInput {
  readonly exportRequestId: string;
  readonly jobId: string;
  readonly jobIdempotencyKey: string;
  readonly exportRequestedAuditEventId: string;
  readonly confirmation: ConfirmStagedActionInput;
}

export interface QueuedExportRequest {
  readonly exportRequestId: string;
  readonly publicId: string;
  readonly scopeSha256: string;
  readonly state: "queued";
  readonly jobId: string;
}

export type ExportDispositionAction =
  | { readonly kind: "cancel_export"; readonly publicId: string }
  | { readonly kind: "delete_export_artifact"; readonly publicId: string };

export interface PreparedExportDisposition {
  readonly actionCode: ExportDispositionAction["kind"];
  readonly boardId: string | null;
  readonly targetType: "export_request";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.export-disposition.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
}

export interface ExportDispositionStageInput {
  readonly action: ExportDispositionAction;
  readonly exactOrigin: string;
  readonly stage: Omit<
    StageActionInput,
    | "boardId"
    | "actingForMemberId"
    | "actionCode"
    | "targetType"
    | "targetId"
    | "canonicalSchema"
    | "canonicalPayload"
    | "packageSha256"
    | "originalName"
  >;
}

export interface ExportDispositionConfirmationInput {
  readonly action: ExportDispositionAction;
  readonly exactOrigin: string;
  readonly cleanupJobId: string;
  readonly cleanupJobIdempotencyKey: string;
  readonly exportCancelledAuditEventId: string;
  readonly confirmation: ConfirmStagedActionInput;
}

export interface ExportDispositionResult {
  readonly actionCode: ExportDispositionAction["kind"];
  readonly exportRequestId: string;
  readonly publicId: string;
  readonly state: "cancelled" | "deletion_queued";
  readonly cleanupJobId: string | null;
}

export class ExportTransactionError extends Error {
  public constructor(
    public readonly code:
      | "export_unavailable"
      | "export_unauthorized"
      | "export_invalid"
      | "export_stale"
      | "export_artifact_invalid",
    message: string
  ) {
    super(message);
    this.name = "ExportTransactionError";
  }
}

const ExportDispositionSnapshotSchema = z
  .object({
    exportRequestId: UuidV7Schema,
    publicId: z.string().min(32).max(128),
    organizationId: UuidV7Schema,
    boardId: UuidV7Schema.nullable(),
    requesterMemberId: UuidV7Schema,
    exportType: z.enum(["audit_chain", "system_data"]),
    state: z.enum(["queued", "running", "succeeded"]),
    scopeSha256: Sha256HexSchema,
    artifactId: UuidV7Schema.nullable(),
    artifactState: z.enum(["ready", "quarantined", "expired"]).nullable(),
    manifestSha256: Sha256HexSchema.nullable()
  })
  .strict();

interface ExportAuthority {
  readonly context: ActiveRequestContext;
  readonly recentAuthAt: string;
}

async function assertExportAuthority(
  client: PoolClient,
  scope: ExportScope,
  exactOrigin: string
): Promise<ExportAuthority> {
  const context = await readRequestContext(client);
  if (scope.organizationId !== context.organizationId) {
    throw new ExportTransactionError("export_unauthorized", "export organization is unavailable");
  }
  const authority = await client.query<{
    organization_id: string;
    member_id: string;
    client_id: string;
    token_jti: string;
    recent_auth_at: string;
  }>(
    `select organization_id,member_id,client_id,token_jti,recent_auth_at
       from boardagent_assert_export_authority($1,$2,$3)`,
    [scope.exportType, scope.boardId, exactOrigin]
  );
  const row = authority.rows[0];
  if (
    !row ||
    authority.rows.length !== 1 ||
    row.organization_id !== context.organizationId ||
    row.member_id !== context.memberId ||
    row.client_id !== context.clientId ||
    row.token_jti !== context.tokenJti
  ) {
    throw new ExportTransactionError("export_unauthorized", "export authority binding is invalid");
  }
  return { context, recentAuthAt: row.recent_auth_at };
}

interface ExportRequestRow {
  readonly id: string;
  readonly public_id: Buffer;
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly requester_member_id: string;
  readonly export_type: "audit_chain" | "system_data";
  readonly scope_manifest: Buffer;
  readonly scope_sha256: Buffer;
  readonly state: string;
  readonly recent_auth_at: string;
  readonly expires_at: string;
}

function exportActionCode(
  exportType: ExportScope["exportType"]
): "export_audit_chain" | "export_system_data" {
  return exportType === "audit_chain" ? "export_audit_chain" : "export_system_data";
}

function exportPayload(row: ExportRequestRow, scope: ExportScope): JsonValue {
  return {
    schemaVersion: "boardagent.export-request.v1",
    exportRequestId: row.id,
    publicId: row.public_id.toString("base64url"),
    organizationId: row.organization_id,
    boardId: row.board_id,
    requesterMemberId: row.requester_member_id,
    exportType: row.export_type,
    scope,
    scopeSha256: row.scope_sha256.toString("hex"),
    recentAuthAt: row.recent_auth_at,
    expiresAt: row.expires_at
  };
}

export async function prepareExportRequestInTransaction(
  client: PoolClient,
  input: {
    readonly exportRequestId: string;
    readonly publicId: Uint8Array;
    readonly scope: unknown;
    readonly exactOrigin: string;
    readonly expiresAt?: string;
  }
): Promise<PreparedExportRequest> {
  const exportRequestId = UuidV7Schema.parse(input.exportRequestId);
  const publicId = Buffer.from(PublicIdSchema.parse(input.publicId));
  const scope = ExportScopeSchema.parse(input.scope);
  const authority = await assertExportAuthority(client, scope, input.exactOrigin);
  const timing = await client.query<{ expires_at: string }>(
    input.expiresAt === undefined
      ? `select to_char((transaction_timestamp()+interval '24 hours') at time zone 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at`
      : `select to_char($1::timestamptz at time zone 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at
           where $1::timestamptz>transaction_timestamp()
             and $1::timestamptz<=transaction_timestamp()+interval '24 hours'`,
    input.expiresAt === undefined ? [] : [Rfc3339UtcSchema.parse(input.expiresAt)]
  );
  const expiresAt = timing.rows[0]?.expires_at;
  if (!expiresAt) throw new ExportTransactionError("export_stale", "export expiry is unavailable");
  const scopeManifest = Buffer.from(canonicalJson(scope), "utf8");
  const scopeSha256 = canonicalSha256(scope);
  const row: ExportRequestRow = {
    id: exportRequestId,
    public_id: publicId,
    organization_id: authority.context.organizationId,
    board_id: scope.boardId,
    requester_member_id: authority.context.memberId,
    export_type: scope.exportType,
    scope_manifest: scopeManifest,
    scope_sha256: Buffer.from(scopeSha256, "hex"),
    state: "staged",
    recent_auth_at: authority.recentAuthAt,
    expires_at: expiresAt
  };
  const canonicalPayload = exportPayload(row, scope);
  return {
    exportRequestId,
    publicId: publicId.toString("base64url"),
    organizationId: authority.context.organizationId,
    requesterMemberId: authority.context.memberId,
    boardId: scope.boardId,
    actionCode: exportActionCode(scope.exportType),
    targetType: "export_request",
    canonicalSchema: "boardagent.export-request.v1",
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    packageSha256: scopeSha256,
    scope,
    recentAuthAt: authority.recentAuthAt,
    expiresAt
  };
}

function parseStoredScope(row: ExportRequestRow): ExportScope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.scope_manifest.toString("utf8"));
  } catch {
    throw new ExportTransactionError("export_invalid", "stored export scope is not JSON");
  }
  const scope = ExportScopeSchema.parse(parsed);
  if (
    !row.scope_manifest.equals(Buffer.from(canonicalJson(scope), "utf8")) ||
    !safeHashEqual(row.scope_sha256.toString("hex"), canonicalSha256(scope)) ||
    scope.organizationId !== row.organization_id ||
    scope.boardId !== row.board_id ||
    scope.exportType !== row.export_type
  ) {
    throw new ExportTransactionError("export_invalid", "stored export scope binding is invalid");
  }
  return scope;
}

export async function stageExportRequestInTransaction(
  client: PoolClient,
  input: ExportRequestStageInput
): Promise<StagedAction & { readonly exportRequestId: string; readonly scopeSha256: string }> {
  const prepared = await prepareExportRequestInTransaction(client, {
    exportRequestId: input.exportRequestId,
    publicId: input.publicId,
    scope: input.scope,
    exactOrigin: input.stage.exactOrigin,
    ...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt })
  });
  const exportRequestId = prepared.exportRequestId;
  const publicId = Buffer.from(prepared.publicId, "base64url");
  const scope = prepared.scope;
  const scopeManifest = Buffer.from(canonicalJson(scope), "utf8");
  const scopeSha256 = prepared.packageSha256;
  await client.query(
    `insert into export_requests(
       id,public_id,organization_id,board_id,requester_member_id,export_type,
       scope_manifest,scope_sha256,recent_auth_at,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz,$10::timestamptz)`,
    [
      exportRequestId,
      publicId,
      prepared.organizationId,
      scope.boardId,
      prepared.requesterMemberId,
      scope.exportType,
      scopeManifest,
      Buffer.from(scopeSha256, "hex"),
      prepared.recentAuthAt,
      prepared.expiresAt
    ]
  );
  const row: ExportRequestRow = {
    id: exportRequestId,
    public_id: publicId,
    organization_id: prepared.organizationId,
    board_id: scope.boardId,
    requester_member_id: prepared.requesterMemberId,
    export_type: scope.exportType,
    scope_manifest: scopeManifest,
    scope_sha256: Buffer.from(scopeSha256, "hex"),
    state: "staged",
    recent_auth_at: prepared.recentAuthAt,
    expires_at: prepared.expiresAt
  };
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: scope.boardId,
      actingForMemberId: null,
      actionCode: exportActionCode(scope.exportType),
      targetType: "export_request",
      targetId: exportRequestId,
      canonicalSchema: "boardagent.export-request.v1",
      canonicalPayload: exportPayload(row, scope),
      packageSha256: scopeSha256,
      originalName: exportActionCode(scope.exportType)
    },
    async () => undefined
  );
  return { ...staged, exportRequestId, scopeSha256 };
}

async function lockExportRequest(
  client: PoolClient,
  exportRequestId: string,
  exactOrigin: string
): Promise<{
  readonly row: ExportRequestRow;
  readonly scope: ExportScope;
  readonly payloadSha256: string;
}> {
  const result = await client.query<ExportRequestRow>(
    `select id,public_id,organization_id,board_id,requester_member_id,export_type,
            scope_manifest,scope_sha256,state,
            to_char(recent_auth_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as recent_auth_at,
            to_char(expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at
       from export_requests where id=$1 for update`,
    [UuidV7Schema.parse(exportRequestId)]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1 || row.state !== "staged") {
    throw new ExportTransactionError("export_unavailable", "staged export request is unavailable");
  }
  const scope = parseStoredScope(row);
  const authority = await assertExportAuthority(client, scope, exactOrigin);
  if (authority.context.memberId !== row.requester_member_id) {
    throw new ExportTransactionError(
      "export_unauthorized",
      "only the requester may confirm export"
    );
  }
  const live = await client.query<{ live: boolean }>(
    "select $1::timestamptz>transaction_timestamp() as live",
    [row.expires_at]
  );
  if (!live.rows[0]?.live)
    throw new ExportTransactionError("export_stale", "export request expired");
  return { row, scope, payloadSha256: canonicalSha256(exportPayload(row, scope)) };
}

export async function confirmExportRequestInTransaction(
  client: PoolClient,
  input: ExportRequestConfirmationInput
): Promise<StagedActionResolution<QueuedExportRequest>> {
  let prepared:
    | {
        readonly row: ExportRequestRow;
        readonly scope: ExportScope;
        readonly payloadSha256: string;
      }
    | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      const origin = await requestClient.query<{ exact_origin: string }>(
        "select exact_origin from action_stages where id=$1",
        [input.confirmation.stageId]
      );
      const exactOrigin = origin.rows[0]?.exact_origin;
      if (!exactOrigin) {
        throw new ExportTransactionError(
          "export_unavailable",
          "export action stage is unavailable"
        );
      }
      prepared = await lockExportRequest(requestClient, input.exportRequestId, exactOrigin);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.row.scope_sha256.toString("hex")
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("export confirmation preparation is unavailable");
      const context = await readRequestContext(requestClient);
      const confirmed = await requestClient.query(
        `update export_requests
            set state='confirmed',consent_record_id=$2,row_version=row_version+1
          where id=$1 and state='staged'`,
        [prepared.row.id, consentRecordId]
      );
      const queued = await requestClient.query(
        `update export_requests set state='queued',row_version=row_version+1
          where id=$1 and state='confirmed'`,
        [prepared.row.id]
      );
      if (confirmed.rowCount !== 1 || queued.rowCount !== 1) {
        throw new ExportTransactionError("export_stale", "export request changed before queueing");
      }
      const job = await enqueueRequestJobInTransaction(requestClient, {
        jobId: input.jobId,
        envelope: {
          schemaVersion: "boardagent.job.export_build.v1",
          organizationId: prepared.row.organization_id,
          boardId: prepared.row.board_id,
          jobType: "export_build",
          subjectType: "export_request",
          subjectId: prepared.row.id,
          parameters: { exportRequestId: prepared.row.id }
        },
        idempotencyKey: input.jobIdempotencyKey
      });
      const auditEvents: AuditAppendInput[] = [
        {
          organizationId: prepared.row.organization_id,
          consentRecordId,
          event: {
            eventId: UuidV7Schema.parse(input.exportRequestedAuditEventId),
            eventType: "export_requested",
            actorMemberId: prepared.row.requester_member_id,
            actorClientId: context.clientId,
            tokenJti: context.tokenJti,
            entityType: "export_request",
            entityId: prepared.row.id,
            boardId: prepared.row.board_id,
            origin: "mcp",
            details: {
              exportType: prepared.row.export_type,
              scopeSha256: prepared.row.scope_sha256.toString("hex"),
              publicId: prepared.row.public_id.toString("base64url"),
              jobId: job.jobId
            },
            schemaVersion: 1
          }
        }
      ];
      return {
        value: {
          exportRequestId: prepared.row.id,
          publicId: prepared.row.public_id.toString("base64url"),
          scopeSha256: prepared.row.scope_sha256.toString("hex"),
          state: "queued",
          jobId: job.jobId
        },
        auditEvents
      };
    }
  );
}

function exportPublicIdBytes(value: string): Buffer {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) {
    throw new ExportTransactionError("export_invalid", "export reference is invalid");
  }
  return bytes;
}

async function prepareExportDispositionInternal(
  client: PoolClient,
  action: ExportDispositionAction,
  exactOrigin: string
): Promise<PreparedExportDisposition> {
  const publicId = exportPublicIdBytes(action.publicId);
  const result = await client.query<{ snapshot: unknown }>(
    "select boardagent_export_disposition_snapshot($1,$2,$3) as snapshot",
    [action.kind, publicId, exactOrigin]
  );
  const snapshot = ExportDispositionSnapshotSchema.parse(result.rows[0]?.snapshot);
  const canonicalPayload = {
    schemaVersion: "boardagent.export-disposition.v1",
    actionCode: action.kind,
    exportRequestId: snapshot.exportRequestId,
    publicId: snapshot.publicId,
    priorState: snapshot.state,
    scopeSha256: snapshot.scopeSha256,
    artifact: snapshot.artifactId
      ? {
          artifactId: snapshot.artifactId,
          state: snapshot.artifactState,
          manifestSha256: snapshot.manifestSha256
        }
      : null
  } satisfies JsonValue;
  return {
    actionCode: action.kind,
    boardId: snapshot.boardId,
    targetType: "export_request",
    targetId: snapshot.exportRequestId,
    canonicalSchema: "boardagent.export-disposition.v1",
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    packageSha256: snapshot.scopeSha256
  };
}

export function prepareExportDispositionInTransaction(
  client: PoolClient,
  action: ExportDispositionAction,
  exactOrigin: string
): Promise<PreparedExportDisposition> {
  return prepareExportDispositionInternal(client, action, exactOrigin);
}

export async function stageExportDispositionInTransaction(
  client: PoolClient,
  input: ExportDispositionStageInput
): Promise<StagedAction & PreparedExportDisposition> {
  const prepared = await prepareExportDispositionInternal(client, input.action, input.exactOrigin);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => undefined
  );
  if (staged.packageSha256 === null) throw new Error("export disposition lost its scope hash");
  return { ...prepared, ...staged, packageSha256: staged.packageSha256 };
}

export async function confirmExportDispositionInTransaction(
  client: PoolClient,
  input: ExportDispositionConfirmationInput
): Promise<StagedActionResolution<ExportDispositionResult>> {
  let prepared: PreparedExportDisposition | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareExportDispositionInternal(
        requestClient,
        input.action,
        input.exactOrigin
      );
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("export disposition preparation is unavailable");
      const context = await readRequestContext(requestClient);
      const applied = await requestClient.query<{
        export_request_id: string;
        public_id: Buffer;
        organization_id: string;
        board_id: string | null;
        resulting_state: "cancelled" | "deletion_queued";
      }>(
        `select export_request_id,public_id,organization_id,board_id,resulting_state
           from boardagent_apply_export_disposition($1,$2,$3,$4,$5)`,
        [
          input.action.kind,
          exportPublicIdBytes(input.action.publicId),
          input.exactOrigin,
          Buffer.from(prepared.payloadSha256, "hex"),
          consentRecordId
        ]
      );
      const row = applied.rows[0];
      if (!row || row.export_request_id !== prepared.targetId) {
        throw new ExportTransactionError("export_stale", "export disposition result is invalid");
      }
      let cleanupJobId: string | null = null;
      if (row.resulting_state === "deletion_queued") {
        const job = await enqueueRequestJobInTransaction(requestClient, {
          jobId: input.cleanupJobId,
          envelope: {
            schemaVersion: "boardagent.job.export_artifact_expiry.v1",
            organizationId: row.organization_id,
            boardId: null,
            jobType: "export_artifact_expiry",
            subjectType: "organization",
            subjectId: row.organization_id,
            parameters: {}
          },
          idempotencyKey: input.cleanupJobIdempotencyKey
        });
        cleanupJobId = job.jobId;
      }
      const auditEvents: AuditAppendInput[] =
        row.resulting_state === "cancelled"
          ? [
              {
                organizationId: row.organization_id,
                consentRecordId,
                event: {
                  eventId: UuidV7Schema.parse(input.exportCancelledAuditEventId),
                  eventType: "export_cancelled",
                  actorMemberId: context.memberId,
                  actorClientId: context.clientId,
                  tokenJti: context.tokenJti,
                  entityType: "export_request",
                  entityId: row.export_request_id,
                  boardId: row.board_id,
                  origin: "mcp",
                  details: {
                    scopeSha256: prepared.packageSha256,
                    partialArtifactsQuarantined: true
                  },
                  schemaVersion: 1
                }
              }
            ]
          : [];
      return {
        value: {
          actionCode: input.action.kind,
          exportRequestId: row.export_request_id,
          publicId: row.public_id.toString("base64url"),
          state: row.resulting_state,
          cleanupJobId
        },
        auditEvents
      };
    }
  );
}

const SYSTEM_EXPORT_TABLES = {
  audit: ["audit_checkpoints"],
  decisions: [
    "approval_rules",
    "ballot_dispositions",
    "ballots",
    "decision_package_components",
    "decision_packages",
    "proxy_grants",
    "proxy_revocations",
    "resolution_versions",
    "vote_certificates",
    "vote_electorate",
    "vote_exclusions",
    "vote_outcomes",
    "vote_source_update_causes",
    "vote_source_update_dispositions",
    "vote_supersessions",
    "votes"
  ],
  documents: [
    "circulation_recipients",
    "document_access_grants",
    "document_circulations",
    "document_exclusions",
    "document_validation_attempts",
    "document_versions",
    "documents"
  ],
  governance: [
    "board_versions",
    "boards",
    "governance_citations",
    "governance_profiles",
    "governance_rule_templates",
    "governance_seat_rules",
    "matter_evaluations",
    "matter_types",
    "organizations",
    "rule_citations",
    "rule_overrides",
    "ruleset_rules",
    "rulesets",
    "system_instance"
  ],
  identity_authority: [
    "board_exclusions",
    "accountable_principals",
    "administrative_authority_changes",
    "board_memberships",
    "company_admin_proposals",
    "member_admin_delegations",
    "members",
    "membership_versions",
    "onboarding_attestations",
    "onboarding_terms_versions",
    "organization_role_assignments",
    "secretary_support_versions"
  ],
  management: [
    "management_question_answers",
    "management_question_turns",
    "management_questions",
    "management_revision_replies",
    "management_revision_requests",
    "management_submission_dispositions",
    "management_submission_threads",
    "management_submission_versions",
    "question_decision_links",
    "question_visibility"
  ],
  meetings: [
    "meeting_exclusions",
    "agenda_items",
    "agenda_versions",
    "meeting_attendance",
    "meeting_rsvps",
    "meeting_transcript_versions",
    "meeting_transcripts",
    "meeting_versions",
    "meetings",
    "transcript_challenge_dispositions",
    "transcript_challenges",
    "transcript_question_links",
    "transcript_turns",
    "transcript_verifications"
  ],
  minutes_tasks: [
    "minutes_exclusions",
    "minutes",
    "minutes_action_declarations",
    "minutes_action_item_dispositions",
    "minutes_correction_cycles",
    "minutes_diffs",
    "minutes_resign_requirements",
    "minutes_review_dispositions",
    "minutes_review_items",
    "minutes_review_withdrawals",
    "minutes_signature_packages",
    "minutes_signature_requirements",
    "minutes_signature_supersessions",
    "minutes_signatures",
    "minutes_versions",
    "task_closures",
    "task_correction_cycles",
    "task_evidence",
    "task_evidence_reviews",
    "tasks"
  ],
  operations: [
    "clock_health_samples",
    "config_receipts",
    "deletion_tombstones",
    "feed_tombstones",
    "notices",
    "pending_action_feed",
    "retention_snapshots"
  ]
} as const satisfies Record<z.infer<typeof SystemDataClassSchema>, readonly string[]>;

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.boolean(),
    z.null(),
    z.number().finite(),
    z.string(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);

interface SnapshotRootRow {
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly export_type: "audit_chain" | "system_data";
  readonly scope_manifest: Buffer;
  readonly scope_sha256: Buffer;
  readonly transaction_snapshot: string;
  readonly audit_head_sequence: string;
  readonly audit_head_sha256: Buffer;
  readonly latest_checkpoint_sha256: Buffer;
  readonly migration_ledger: unknown;
  readonly captured_at: string;
}

export interface FrozenExportComponent {
  readonly name: string;
  readonly rowCount: string;
  readonly sha256: string;
  readonly bytes: Buffer;
}

export interface FrozenExportSnapshot {
  readonly exportRequestId: string;
  readonly scope: ExportScope;
  readonly snapshot: ExportSnapshotManifest;
  readonly snapshotSha256: string;
  readonly components: readonly FrozenExportComponent[];
}

async function rowsComponent(
  client: PoolClient,
  query: string,
  parameters: readonly unknown[],
  name: string
): Promise<FrozenExportComponent> {
  const result = await client.query<{ table_rows: unknown; row_count: string }>(query, [
    ...parameters
  ]);
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new ExportTransactionError("export_invalid", `export component ${name} is unavailable`);
  }
  const rows = JsonValueSchema.parse(row.table_rows);
  const payload = {
    schemaVersion: "boardagent.export-component.v1",
    name,
    rowEncoding: "postgres-text-v1",
    rows
  } satisfies JsonValue;
  const bytes = Buffer.from(canonicalJson(payload), "utf8");
  return { name, rowCount: row.row_count, sha256: canonicalSha256(payload), bytes };
}

export async function buildFrozenExportSnapshotInTransaction(
  client: PoolClient,
  input: { readonly exportRequestId: string; readonly exportStartedAuditEventId: string }
): Promise<FrozenExportSnapshot> {
  const exportRequestId = UuidV7Schema.parse(input.exportRequestId);
  // Every postgres-text-v1 component uses the same deterministic bytea encoding,
  // regardless of a connection's inherited output setting. Transaction-local only.
  await client.query("select set_config('bytea_output','hex',true)");
  const rootResult = await client.query<SnapshotRootRow>(
    `select organization_id,board_id,export_type,scope_manifest,scope_sha256,
            transaction_snapshot,audit_head_sequence::text,audit_head_sha256,
            latest_checkpoint_sha256,migration_ledger,captured_at
       from boardagent_export_snapshot_root($1)`,
    [exportRequestId]
  );
  const root = rootResult.rows[0];
  if (!root || rootResult.rows.length !== 1) {
    throw new ExportTransactionError("export_unavailable", "export snapshot root is unavailable");
  }
  const pseudoRow: ExportRequestRow = {
    id: exportRequestId,
    public_id: Buffer.alloc(32),
    organization_id: root.organization_id,
    board_id: root.board_id,
    requester_member_id: root.organization_id,
    export_type: root.export_type,
    scope_manifest: root.scope_manifest,
    scope_sha256: root.scope_sha256,
    state: "queued",
    recent_auth_at: root.captured_at,
    expires_at: root.captured_at
  };
  const scope = parseStoredScope(pseudoRow);
  const components: FrozenExportComponent[] = [];
  const includesAudit = scope.exportType === "audit_chain" || scope.dataClasses.includes("audit");
  if (includesAudit) {
    components.push(
      await rowsComponent(
        client,
        "select table_rows,row_count::text from boardagent_export_audit_event_rows($1)",
        [exportRequestId],
        "audit:events"
      ),
      await rowsComponent(
        client,
        "select table_rows,row_count::text from boardagent_export_checkpoint_rows($1)",
        [exportRequestId],
        "audit:checkpoints"
      ),
      await rowsComponent(
        client,
        "select table_rows,row_count::text from boardagent_export_public_key_rows($1)",
        [exportRequestId],
        "audit:public_keys"
      )
    );
  }
  if (scope.exportType === "system_data") {
    for (const dataClass of scope.dataClasses) {
      for (const table of SYSTEM_EXPORT_TABLES[dataClass]) {
        if (dataClass === "audit" && table === "audit_checkpoints") continue;
        components.push(
          await rowsComponent(
            client,
            `select table_rows,row_count::text
               from boardagent_export_system_table_rows($1,$2,$3)`,
            [exportRequestId, dataClass, table],
            `${dataClass}:${table}`
          )
        );
      }
    }
  }
  components.sort((left, right) => left.name.localeCompare(right.name));
  const descriptors = components.map((component) => ({
    name: component.name,
    rowCount: component.rowCount,
    byteLength: component.bytes.length.toString(10),
    sha256: component.sha256
  }));
  const plaintextContentSetSha256 = canonicalSha256({
    schemaVersion: "boardagent.export-content-set.v1",
    components: descriptors
  });
  const migrationLedger = JsonValueSchema.parse(root.migration_ledger);
  const recoveredRows = await client.query<{ canonical_manifest: Buffer; signature: Buffer }>(
    `select checkpoint.canonical_manifest,checkpoint.signature from public.audit_recoveries as recovery
      join public.audit_recovery_completions as completion on completion.recovery_id=recovery.id
      join public.audit_checkpoints as checkpoint on checkpoint.recovery_id=recovery.id and checkpoint.first_sequence=recovery.first_sequence
      where recovery.organization_id=$1 order by recovery.first_sequence`,
    [root.organization_id]
  );
  const recoveryEvidence: SignedAuditRecoveryCheckpoint[] = recoveredRows.rows.map((row) => ({
    payload: JSON.parse(row.canonical_manifest.toString("utf8")),
    signatureBase64Url: row.signature.toString("base64url")
  }));
  const snapshot = ExportSnapshotManifestSchema.parse({
    ...(recoveryEvidence.length === 0
      ? { schemaVersion: "boardagent.export-snapshot.v1" }
      : {
          schemaVersion: "boardagent.export-snapshot.v2",
          auditRecoveryEvidence: recoveryEvidence
        }),
    exportRequestId,
    organizationId: root.organization_id,
    boardId: root.board_id,
    exportType: root.export_type,
    scopeSha256: root.scope_sha256.toString("hex"),
    transactionSnapshot: root.transaction_snapshot,
    auditHeadSequence: root.audit_head_sequence,
    auditHeadSha256: root.audit_head_sha256.toString("hex"),
    latestCheckpointSha256: root.latest_checkpoint_sha256.toString("hex"),
    migrationLedgerSha256: canonicalSha256(migrationLedger),
    capturedAt: root.captured_at,
    plaintextContentSetSha256,
    components: descriptors
  });
  const snapshotSha256 = canonicalSha256(snapshot);
  const updated = await client.query(
    `update export_requests
        set state='running',snapshot_manifest=$2,snapshot_sha256=$3,
            started_at=transaction_timestamp(),row_version=row_version+1
      where id=$1 and state='queued'`,
    [
      exportRequestId,
      Buffer.from(canonicalJson(snapshot), "utf8"),
      Buffer.from(snapshotSha256, "hex")
    ]
  );
  if (updated.rowCount !== 1) {
    throw new ExportTransactionError("export_stale", "export request changed during snapshot");
  }
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: root.organization_id,
      event: {
        eventId: UuidV7Schema.parse(input.exportStartedAuditEventId),
        eventType: "export_started",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "export_request",
        entityId: exportRequestId,
        boardId: root.board_id,
        origin: "worker",
        details: {
          scopeSha256: root.scope_sha256.toString("hex"),
          snapshotSha256,
          auditHeadSequence: root.audit_head_sequence,
          auditHeadSha256: root.audit_head_sha256.toString("hex"),
          componentCount: components.length,
          plaintextContentSetSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  return { exportRequestId, scope, snapshot, snapshotSha256, components };
}

interface RunningExportRow {
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly scope_sha256: Buffer;
  readonly snapshot_manifest: Buffer;
  readonly snapshot_sha256: Buffer;
  readonly state: string;
}

function encryptedContentSetSha256(manifest: ExportArtifactManifest): string {
  return canonicalSha256({
    schemaVersion: "boardagent.export-encrypted-content-set.v1",
    chunks: manifest.chunks.map(({ ordinal, byteOffset, byteLength, chunkSha256 }) => ({
      ordinal,
      byteOffset,
      byteLength,
      chunkSha256
    }))
  });
}

async function lockRunningExport(
  client: PoolClient,
  exportRequestId: string
): Promise<{ readonly row: RunningExportRow; readonly snapshot: ExportSnapshotManifest }> {
  const result = await client.query<RunningExportRow>(
    `select organization_id,board_id,scope_sha256,snapshot_manifest,snapshot_sha256,state
       from export_requests where id=$1 for update`,
    [UuidV7Schema.parse(exportRequestId)]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1 || row.state !== "running") {
    throw new ExportTransactionError("export_unavailable", "running export request is unavailable");
  }
  let rawSnapshot: unknown;
  try {
    rawSnapshot = JSON.parse(row.snapshot_manifest.toString("utf8"));
  } catch {
    throw new ExportTransactionError("export_invalid", "stored export snapshot is not JSON");
  }
  const snapshot = ExportSnapshotManifestSchema.parse(rawSnapshot);
  if (
    !row.snapshot_manifest.equals(Buffer.from(canonicalJson(snapshot), "utf8")) ||
    !safeHashEqual(row.snapshot_sha256.toString("hex"), canonicalSha256(snapshot))
  ) {
    throw new ExportTransactionError("export_invalid", "stored export snapshot binding is invalid");
  }
  return { row, snapshot };
}

async function insertArtifact(
  client: PoolClient,
  row: RunningExportRow,
  snapshot: ExportSnapshotManifest,
  rawManifest: unknown,
  state: "ready" | "quarantined"
): Promise<ExportArtifactManifest> {
  const manifest = ExportArtifactManifestSchema.parse(rawManifest);
  if (
    manifest.exportRequestId !== snapshot.exportRequestId ||
    manifest.organizationId !== row.organization_id ||
    !safeHashEqual(manifest.scopeSha256, row.scope_sha256.toString("hex")) ||
    !safeHashEqual(manifest.snapshotSha256, canonicalSha256(snapshot)) ||
    !safeHashEqual(manifest.plaintextContentSetSha256, snapshot.plaintextContentSetSha256) ||
    !safeHashEqual(manifest.encryptedContentSetSha256, encryptedContentSetSha256(manifest)) ||
    (state === "ready" && !manifest.complete) ||
    (state === "quarantined" && manifest.complete)
  ) {
    throw new ExportTransactionError(
      "export_artifact_invalid",
      "export artifact does not bind the exact frozen snapshot and complete chunk set"
    );
  }
  const key = await client.query<{ organization_id: string; key_id: string }>(
    "select organization_id,key_id from boardagent_export_encryption_key($1,$2)",
    [manifest.exportRequestId, manifest.encryptionKeyId]
  );
  if (
    key.rows.length !== 1 ||
    key.rows[0]?.organization_id !== row.organization_id ||
    key.rows[0]?.key_id !== manifest.encryptionKeyId
  ) {
    throw new ExportTransactionError(
      "export_artifact_invalid",
      "export encryption key is unavailable"
    );
  }
  const canonicalManifest = Buffer.from(canonicalJson(manifest), "utf8");
  await client.query(
    `insert into export_artifacts(
       id,export_request_id,manifest,manifest_sha256,content_set_sha256,
       encrypted_storage_locator,encryption_key_id,byte_length,state
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      manifest.artifactId,
      manifest.exportRequestId,
      canonicalManifest,
      Buffer.from(canonicalSha256(manifest), "hex"),
      Buffer.from(manifest.encryptedContentSetSha256, "hex"),
      manifest.encryptedStorageLocator,
      manifest.encryptionKeyId,
      manifest.byteLength,
      state
    ]
  );
  for (const chunk of manifest.chunks) {
    await client.query(
      `insert into export_chunks(
         id,artifact_id,ordinal,byte_offset,byte_length,chunk_sha256,storage_locator
       ) values ($1,$2,$3,$4,$5,$6,$7)`,
      [
        chunk.chunkId,
        manifest.artifactId,
        chunk.ordinal,
        chunk.byteOffset,
        chunk.byteLength,
        Buffer.from(chunk.chunkSha256, "hex"),
        chunk.storageLocator
      ]
    );
  }
  return manifest;
}

export async function completeExportBuildInTransaction(
  client: PoolClient,
  input: { readonly manifest: unknown; readonly exportPerformedAuditEventId: string }
): Promise<{
  readonly exportRequestId: string;
  readonly artifactId: string;
  readonly manifestSha256: string;
}> {
  const parsed = ExportArtifactManifestSchema.parse(input.manifest);
  const { row, snapshot } = await lockRunningExport(client, parsed.exportRequestId);
  const manifest = await insertArtifact(client, row, snapshot, parsed, "ready");
  const completed = await client.query(
    `update export_requests
        set state='succeeded',completed_at=transaction_timestamp(),row_version=row_version+1
      where id=$1 and state='running'`,
    [manifest.exportRequestId]
  );
  if (completed.rowCount !== 1)
    throw new ExportTransactionError("export_stale", "export completion raced");
  const manifestSha256 = canonicalSha256(manifest);
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: row.organization_id,
      event: {
        eventId: UuidV7Schema.parse(input.exportPerformedAuditEventId),
        eventType: "export_performed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "export_request",
        entityId: manifest.exportRequestId,
        boardId: row.board_id,
        origin: "worker",
        details: {
          artifactId: manifest.artifactId,
          manifestSha256,
          encryptedContentSetSha256: manifest.encryptedContentSetSha256,
          byteLength: manifest.byteLength,
          chunkCount: manifest.chunks.length
        },
        schemaVersion: 1
      }
    }
  ]);
  return {
    exportRequestId: manifest.exportRequestId,
    artifactId: manifest.artifactId,
    manifestSha256
  };
}

/** Reconcile dead preparations under the restricted database inspection boundary. */
export async function failStoppedQueuedExportsInTransaction(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly newAuditEventId: () => string;
  }
): Promise<number> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  // The authoritative job state decides exhaustion, not a duplicated retry limit.
  // Requests without artifacts need database reconciliation even when the storage
  // inventory is empty. Preserve any request that still has queued or leased work.
  const candidates = await client.query<{ id: string }>(
    "select export_request_id as id from public.boardagent_stopped_export_requests($1)",
    [organizationId]
  );
  let failed = 0;
  for (const row of candidates.rows) {
    if (
      await failQueuedExportBuildInTransaction(client, {
        exportRequestId: row.id,
        failureClass: "export_build_stopped",
        exportFailedAuditEventId: input.newAuditEventId()
      })
    )
      failed += 1;
  }
  return failed;
}

/** Record a terminal preparation failure without fabricating a captured snapshot. */
export async function failQueuedExportBuildInTransaction(
  client: PoolClient,
  input: {
    readonly exportRequestId: string;
    readonly failureClass: string;
    readonly exportFailedAuditEventId: string;
  }
): Promise<boolean> {
  const exportRequestId = UuidV7Schema.parse(input.exportRequestId);
  const failureClass = FailureClassSchema.parse(input.failureClass);
  const selected = await client.query<{ organization_id: string; board_id: string | null }>(
    `select organization_id,board_id from public.export_requests
      where id=$1 and state='queued'
        and current_setting('boardagent.transaction_scope',true)='worker'
      for update`,
    [exportRequestId]
  );
  const row = selected.rows[0];
  if (!row) return false;
  const updated = await client.query(
    `update public.export_requests
        set state='failed',failure_class=$2,completed_at=transaction_timestamp(),row_version=row_version+1
      where id=$1 and state='queued'`,
    [exportRequestId, failureClass]
  );
  if (updated.rowCount !== 1)
    throw new ExportTransactionError("export_stale", "export failure raced");
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: row.organization_id,
      event: {
        eventId: UuidV7Schema.parse(input.exportFailedAuditEventId),
        eventType: "export_failed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "export_request",
        entityId: exportRequestId,
        boardId: row.board_id,
        origin: "worker",
        details: { failureClass, failurePhase: "preparation", snapshotCaptured: false },
        schemaVersion: 1
      }
    }
  ]);
  return true;
}

export async function failExportBuildInTransaction(
  client: PoolClient,
  input: {
    readonly exportRequestId: string;
    readonly failureClass: string;
    readonly exportFailedAuditEventId: string;
    readonly partialManifest?: unknown;
  }
): Promise<{ readonly exportRequestId: string; readonly quarantinedArtifactId?: string }> {
  const exportRequestId = UuidV7Schema.parse(input.exportRequestId);
  const failureClass = FailureClassSchema.parse(input.failureClass);
  const { row, snapshot } = await lockRunningExport(client, exportRequestId);
  let quarantinedArtifactId: string | undefined;
  if (input.partialManifest !== undefined) {
    const manifest = await insertArtifact(
      client,
      row,
      snapshot,
      input.partialManifest,
      "quarantined"
    );
    quarantinedArtifactId = manifest.artifactId;
  }
  const failed = await client.query(
    `update export_requests
        set state='failed',failure_class=$2,completed_at=transaction_timestamp(),
            row_version=row_version+1
      where id=$1 and state='running'`,
    [exportRequestId, failureClass]
  );
  if (failed.rowCount !== 1)
    throw new ExportTransactionError("export_stale", "export failure raced");
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: row.organization_id,
      event: {
        eventId: UuidV7Schema.parse(input.exportFailedAuditEventId),
        eventType: "export_failed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "export_request",
        entityId: exportRequestId,
        boardId: row.board_id,
        origin: "worker",
        details: { failureClass, quarantinedArtifactId: quarantinedArtifactId ?? null },
        schemaVersion: 1
      }
    }
  ]);
  return {
    exportRequestId,
    ...(quarantinedArtifactId === undefined ? {} : { quarantinedArtifactId })
  };
}

export async function recordExportArtifactDeletionInTransaction(
  client: PoolClient,
  input: {
    readonly exportRequestId: string;
    readonly storageDeletionVerified: boolean;
    readonly exportArtifactDeletedAuditEventId: string;
  }
): Promise<{ readonly exportRequestId: string; readonly artifactId: string }> {
  if (!input.storageDeletionVerified) {
    throw new ExportTransactionError(
      "export_artifact_invalid",
      "artifact deletion cannot be recorded before storage deletion is verified"
    );
  }
  const exportRequestId = UuidV7Schema.parse(input.exportRequestId);
  const result = await client.query<{
    artifact_id: string;
    artifact_state: string;
    organization_id: string;
    board_id: string | null;
    request_state: string;
    manifest_sha256: Buffer;
    content_set_sha256: Buffer;
  }>(
    `select artifact.id as artifact_id,artifact.state as artifact_state,
            request.organization_id,request.board_id,request.state as request_state,
            artifact.manifest_sha256,artifact.content_set_sha256
       from export_requests as request
       join export_artifacts as artifact on artifact.export_request_id=request.id
      where request.id=$1
      for update of request,artifact`,
    [exportRequestId]
  );
  const row = result.rows[0];
  if (!row || !["ready", "quarantined", "expired"].includes(row.artifact_state)) {
    throw new ExportTransactionError(
      "export_unavailable",
      "deletable export artifact is unavailable"
    );
  }
  await client.query(
    `update export_artifacts
        set state='deleted',deleted_at=transaction_timestamp()
      where id=$1 and state in ('ready','quarantined','expired')`,
    [row.artifact_id]
  );
  if (["succeeded", "expired"].includes(row.request_state)) {
    await client.query(
      `update export_requests
          set state='deleted',completed_at=coalesce(completed_at,transaction_timestamp()),
              row_version=row_version+1
        where id=$1 and state in ('succeeded','expired')`,
      [exportRequestId]
    );
  }
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: row.organization_id,
      event: {
        eventId: UuidV7Schema.parse(input.exportArtifactDeletedAuditEventId),
        eventType: "export_artifact_deleted",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "export_artifact",
        entityId: row.artifact_id,
        boardId: row.board_id,
        origin: "worker",
        details: {
          exportRequestId,
          manifestSha256: row.manifest_sha256.toString("hex"),
          contentSetSha256: row.content_set_sha256.toString("hex"),
          storageDeletionVerified: true
        },
        schemaVersion: 1
      }
    }
  ]);
  return { exportRequestId, artifactId: row.artifact_id };
}

export type ExportArtifactCleanupReason =
  "ttl_expired" | "deletion_requested" | "quarantined_partial";

export interface ClaimedExportArtifactCleanup {
  readonly exportRequestId: string;
  readonly artifactId: string;
  readonly manifest: ExportArtifactManifest;
  readonly manifestSha256: string;
  readonly cleanupReason: ExportArtifactCleanupReason;
  readonly cleanupToken: string;
}

const ExportArtifactCleanupReasonSchema = z.enum([
  "ttl_expired",
  "deletion_requested",
  "quarantined_partial"
]);

function parseCanonicalArtifactManifest(input: {
  readonly canonicalManifest: Buffer;
  readonly storedManifestSha256: Buffer;
  readonly exportRequestId: string;
  readonly artifactId: string;
  readonly organizationId?: string;
}): { readonly manifest: ExportArtifactManifest; readonly manifestSha256: string } {
  let rawManifest: unknown;
  try {
    rawManifest = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(input.canonicalManifest)
    );
  } catch {
    throw new ExportTransactionError(
      "export_artifact_invalid",
      "stored artifact manifest is invalid"
    );
  }
  const manifest = ExportArtifactManifestSchema.parse(rawManifest);
  const manifestSha256 = canonicalSha256(manifest);
  if (
    !input.canonicalManifest.equals(Buffer.from(canonicalJson(manifest), "utf8")) ||
    !safeHashEqual(input.storedManifestSha256.toString("hex"), manifestSha256) ||
    manifest.exportRequestId !== input.exportRequestId ||
    manifest.artifactId !== input.artifactId ||
    (input.organizationId !== undefined && manifest.organizationId !== input.organizationId)
  ) {
    throw new ExportTransactionError(
      "export_artifact_invalid",
      "stored artifact manifest binding is invalid"
    );
  }
  return { manifest, manifestSha256 };
}

export async function claimExportArtifactCleanupInTransaction(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly mode: "expiry" | "reconcile";
    readonly cleanupToken: string;
    readonly leaseSeconds?: number;
  }
): Promise<ClaimedExportArtifactCleanup | null> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const cleanupToken = UuidV7Schema.parse(input.cleanupToken);
  const leaseSeconds = z
    .number()
    .int()
    .min(30)
    .max(300)
    .parse(input.leaseSeconds ?? 120);
  const result = await client.query<{
    export_request_id: string;
    artifact_id: string;
    canonical_manifest: Buffer;
    stored_manifest_sha256: Buffer;
    cleanup_reason: string;
    cleanup_token: string;
  }>(
    `select export_request_id,artifact_id,canonical_manifest,stored_manifest_sha256,
            cleanup_reason,cleanup_token
       from boardagent_claim_export_artifact_cleanup($1,$2,$3,$4)`,
    [organizationId, input.mode, cleanupToken, leaseSeconds]
  );
  const row = result.rows[0];
  if (!row) return null;
  if (result.rows.length !== 1 || row.cleanup_token !== cleanupToken) {
    throw new ExportTransactionError("export_artifact_invalid", "export cleanup claim is invalid");
  }
  const exportRequestId = UuidV7Schema.parse(row.export_request_id);
  const artifactId = UuidV7Schema.parse(row.artifact_id);
  const parsed = parseCanonicalArtifactManifest({
    canonicalManifest: row.canonical_manifest,
    storedManifestSha256: row.stored_manifest_sha256,
    exportRequestId,
    artifactId,
    organizationId
  });
  return {
    exportRequestId,
    artifactId,
    manifest: parsed.manifest,
    manifestSha256: parsed.manifestSha256,
    cleanupReason: ExportArtifactCleanupReasonSchema.parse(row.cleanup_reason),
    cleanupToken
  };
}

export async function releaseExportArtifactCleanupInTransaction(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly exportRequestId: string;
    readonly artifactId: string;
    readonly cleanupToken: string;
  }
): Promise<boolean> {
  const result = await client.query<{ released: boolean }>(
    "select boardagent_release_export_artifact_cleanup($1,$2,$3,$4) as released",
    [
      UuidV7Schema.parse(input.organizationId),
      UuidV7Schema.parse(input.exportRequestId),
      UuidV7Schema.parse(input.artifactId),
      UuidV7Schema.parse(input.cleanupToken)
    ]
  );
  return result.rows[0]?.released === true;
}

export async function completeExportArtifactCleanupInTransaction(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly exportRequestId: string;
    readonly artifactId: string;
    readonly cleanupToken: string;
    readonly cleanupReason: ExportArtifactCleanupReason;
    readonly storageDeletionVerified: boolean;
    readonly exportArtifactDeletedAuditEventId: string;
  }
): Promise<{ readonly exportRequestId: string; readonly artifactId: string }> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const exportRequestId = UuidV7Schema.parse(input.exportRequestId);
  const artifactId = UuidV7Schema.parse(input.artifactId);
  const cleanupToken = UuidV7Schema.parse(input.cleanupToken);
  const cleanupReason = ExportArtifactCleanupReasonSchema.parse(input.cleanupReason);
  if (!input.storageDeletionVerified) {
    throw new ExportTransactionError(
      "export_artifact_invalid",
      "artifact cleanup cannot complete before exact storage deletion"
    );
  }
  const result = await client.query<{
    export_request_id: string;
    artifact_id: string;
    organization_id: string;
    board_id: string | null;
    prior_artifact_state: string;
    manifest_sha256: Buffer;
    content_set_sha256: Buffer;
  }>(
    `select export_request_id,artifact_id,organization_id,board_id,prior_artifact_state,
            manifest_sha256,content_set_sha256
       from boardagent_complete_export_artifact_cleanup($1,$2,$3,$4,$5)`,
    [organizationId, exportRequestId, artifactId, cleanupToken, true]
  );
  const row = result.rows[0];
  if (
    !row ||
    result.rows.length !== 1 ||
    row.export_request_id !== exportRequestId ||
    row.artifact_id !== artifactId ||
    row.organization_id !== organizationId ||
    !["expired", "quarantined"].includes(row.prior_artifact_state)
  ) {
    throw new ExportTransactionError(
      "export_artifact_invalid",
      "artifact cleanup result is invalid"
    );
  }
  await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      event: {
        eventId: UuidV7Schema.parse(input.exportArtifactDeletedAuditEventId),
        eventType: "export_artifact_deleted",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "export_artifact",
        entityId: artifactId,
        boardId: row.board_id,
        origin: "worker",
        details: {
          exportRequestId,
          manifestSha256: row.manifest_sha256.toString("hex"),
          contentSetSha256: row.content_set_sha256.toString("hex"),
          storageDeletionVerified: true,
          cleanupReason
        },
        schemaVersion: 1
      }
    }
  ]);
  return { exportRequestId, artifactId };
}

export interface ExportReconcileTarget {
  readonly exportRequestId: string;
  readonly requestState:
    | "staged"
    | "confirmed"
    | "queued"
    | "running"
    | "succeeded"
    | "failed"
    | "expired"
    | "deleted"
    | "cancelled";
  readonly requestStartedAt: string | null;
  readonly artifactId: string | null;
  readonly artifactState: "ready" | "quarantined" | "deleted" | "expired" | null;
  readonly manifest: ExportArtifactManifest | null;
  readonly manifestSha256: string | null;
  readonly activeExportBuild: boolean;
  readonly safeToFailPartial: boolean;
}

const ExportRequestStateSchema = z.enum([
  "staged",
  "confirmed",
  "queued",
  "running",
  "succeeded",
  "failed",
  "expired",
  "deleted",
  "cancelled"
]);

export async function inspectExportReconcileTargetInTransaction(
  client: PoolClient,
  input: { readonly organizationId: string; readonly exportRequestId: string }
): Promise<ExportReconcileTarget | null> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const exportRequestId = UuidV7Schema.parse(input.exportRequestId);
  const result = await client.query<{
    export_request_id: string;
    request_state: string;
    request_started_at: string | null;
    artifact_id: string | null;
    artifact_state: string | null;
    canonical_manifest: Buffer | null;
    stored_manifest_sha256: Buffer | null;
    active_export_build: boolean;
    safe_to_fail_partial: boolean;
  }>(
    `select export_request_id,request_state,request_started_at,artifact_id,artifact_state,
            canonical_manifest,stored_manifest_sha256,active_export_build,safe_to_fail_partial
       from boardagent_export_reconcile_target($1,$2)`,
    [organizationId, exportRequestId]
  );
  const row = result.rows[0];
  if (!row) return null;
  if (result.rows.length !== 1 || row.export_request_id !== exportRequestId) {
    throw new ExportTransactionError("export_invalid", "export reconcile target is invalid");
  }
  const artifactId = row.artifact_id === null ? null : UuidV7Schema.parse(row.artifact_id);
  let parsed: {
    readonly manifest: ExportArtifactManifest;
    readonly manifestSha256: string;
  } | null = null;
  if (
    artifactId !== null &&
    row.canonical_manifest !== null &&
    row.stored_manifest_sha256 !== null
  ) {
    parsed = parseCanonicalArtifactManifest({
      canonicalManifest: row.canonical_manifest,
      storedManifestSha256: row.stored_manifest_sha256,
      exportRequestId,
      artifactId,
      organizationId
    });
  } else if (
    artifactId !== null ||
    row.canonical_manifest !== null ||
    row.stored_manifest_sha256 !== null
  ) {
    throw new ExportTransactionError("export_invalid", "export reconcile artifact is incomplete");
  }
  return {
    exportRequestId,
    requestState: ExportRequestStateSchema.parse(row.request_state),
    requestStartedAt:
      row.request_started_at === null ? null : Rfc3339UtcSchema.parse(row.request_started_at),
    artifactId,
    artifactState:
      row.artifact_state === null
        ? null
        : z.enum(["ready", "quarantined", "deleted", "expired"]).parse(row.artifact_state),
    manifest: parsed?.manifest ?? null,
    manifestSha256: parsed?.manifestSha256 ?? null,
    activeExportBuild: row.active_export_build,
    safeToFailPartial: row.safe_to_fail_partial
  };
}

export async function settleReconciledExportBuildJobsInTransaction(
  client: PoolClient,
  input: { readonly organizationId: string; readonly exportRequestId: string }
): Promise<number> {
  const result = await client.query<{ settled: number }>(
    "select boardagent_settle_reconciled_export_build_jobs($1,$2) as settled",
    [UuidV7Schema.parse(input.organizationId), UuidV7Schema.parse(input.exportRequestId)]
  );
  return z.number().int().min(0).parse(result.rows[0]?.settled);
}
