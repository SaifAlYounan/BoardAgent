import type { PoolClient } from "pg";

import { AuditEventBodySchema, type AuditEvent, type AuditEventBody } from "@boardagent/audit";
import {
  canonicalJsonFromText,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  Sha256HexSchema,
  sha256Hex,
  UuidV7Schema
} from "@boardagent/contracts";
import type { DocumentValidationError, PreparedDocumentContribution } from "@boardagent/domain";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export class DocumentTransactionError extends Error {
  public constructor(
    public readonly code:
      | "document_contribution_unavailable"
      | "document_version_unavailable"
      | "idempotency_conflict"
      | "idempotency_in_progress"
      | "invalid_prepared_document"
      | "invalid_fetch_outcome",
    message: string
  ) {
    super(message);
    this.name = "DocumentTransactionError";
  }
}

export interface ContributeDocumentVersionInput {
  readonly prepared: PreparedDocumentContribution;
  /** Omit only for trusted internal callers that deliberately accept the locked current head. */
  readonly expectedCurrentVersionId?: string | null;
  readonly documentVersionId: string;
  readonly validationAttemptId: string;
  readonly auditEventId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly offeredName?: string | null;
}

export type DocumentContributionResult =
  | {
      readonly replayed: true;
      readonly documentVersionId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly documentId: string;
      readonly documentVersionId: string;
      readonly version: number;
      readonly sha256: string;
      readonly byteLength: number;
      readonly responseSha256: string;
      readonly auditEvent: AuditEvent;
    };

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
  readonly state: string;
}

interface LockedDocumentRow {
  readonly document_id: string;
  readonly document_title: string;
  readonly document_state: string;
  readonly current_version_id: string | null;
  readonly current_version: number | null;
  readonly row_version: string;
}

function assertPreparedDocument(prepared: PreparedDocumentContribution): void {
  const bytes = Buffer.from(prepared.canonicalBytes);
  const decoded = bytes.toString("utf8");
  const canonical =
    prepared.mediaType === "application/json" ? canonicalJsonFromText(bytes) : canonicalText(bytes);
  const metadataMatches =
    prepared.canonicalMetadata.organizationId === prepared.organizationId &&
    prepared.canonicalMetadata.boardId === prepared.boardId &&
    prepared.canonicalMetadata.documentId === prepared.documentId &&
    prepared.canonicalMetadata.title === prepared.title &&
    prepared.canonicalMetadata.mediaType === prepared.mediaType &&
    prepared.canonicalMetadata.documentSchema === prepared.documentSchema &&
    prepared.canonicalMetadata.byteLength === prepared.byteLength &&
    prepared.canonicalMetadata.sha256 === prepared.sha256;
  if (
    canonical !== decoded ||
    prepared.canonicalText !== decoded ||
    prepared.byteLength !== bytes.length ||
    !safeHashEqual(prepared.sha256, sha256Hex(bytes)) ||
    !metadataMatches ||
    !safeHashEqual(prepared.requestSha256, canonicalSha256(prepared.canonicalMetadata))
  ) {
    throw new DocumentTransactionError(
      "invalid_prepared_document",
      "prepared document failed canonical integrity validation"
    );
  }
  UuidV7Schema.parse(prepared.organizationId);
  UuidV7Schema.parse(prepared.boardId);
  UuidV7Schema.parse(prepared.documentId);
}

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

export async function contributeDocumentVersionInTransaction(
  client: PoolClient,
  input: ContributeDocumentVersionInput
): Promise<DocumentContributionResult> {
  assertPreparedDocument(input.prepared);
  const documentVersionId = UuidV7Schema.parse(input.documentVersionId);
  const validationAttemptId = UuidV7Schema.parse(input.validationAttemptId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const expectedCurrentVersionId =
    input.expectedCurrentVersionId === undefined || input.expectedCurrentVersionId === null
      ? input.expectedCurrentVersionId
      : UuidV7Schema.parse(input.expectedCurrentVersionId);
  const requestSha256 =
    expectedCurrentVersionId === undefined
      ? input.prepared.requestSha256
      : canonicalSha256({
          schemaVersion: "boardagent.document-contribution-request.v2",
          preparedRequestSha256: input.prepared.requestSha256,
          expectedCurrentVersionId
        });
  const context = await readRequestContext(client);
  if (context.organizationId !== input.prepared.organizationId) {
    throw new DocumentTransactionError(
      "document_contribution_unavailable",
      "document contribution is unavailable"
    );
  }

  const boardLock = await client.query<{ allowed: boolean }>(
    "select boardagent_lock_board_for_document_contribution($1) as allowed",
    [input.prepared.boardId]
  );
  if (!boardLock.rows[0]?.allowed) {
    throw new DocumentTransactionError(
      "document_contribution_unavailable",
      "document contribution is unavailable"
    );
  }
  const documentLock = await client.query<LockedDocumentRow>(
    `select document_id, document_title, document_state, current_version_id,
            current_version, row_version::text
       from boardagent_lock_document_for_contribution($1,$2)`,
    [input.prepared.documentId, input.prepared.boardId]
  );
  const existingDocument = documentLock.rows[0];
  const insertedIdempotency = await client.query<{ id: string }>(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'create_document_version',$5,$6,'in_progress',
       transaction_timestamp() + interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing
     returning id`,
    [
      idempotencyRecordId,
      context.organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  const idempotency = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='create_document_version' and idempotency_key=$3
      for update`,
    [context.memberId, context.clientId, idempotencyKey]
  );
  const record = idempotency.rows[0];
  if (!record) throw new Error("idempotency record disappeared inside its transaction");
  if (!safeHashEqual(record.request_sha256.toString("hex"), requestSha256)) {
    throw new DocumentTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different request"
    );
  }
  if (insertedIdempotency.rowCount === 0) {
    if (record.state === "succeeded" && record.safe_response_id && record.safe_response_sha256) {
      if (!existingDocument || existingDocument.document_state !== "active") {
        throw new DocumentTransactionError(
          "document_contribution_unavailable",
          "document contribution is unavailable"
        );
      }
      return {
        replayed: true,
        documentVersionId: record.safe_response_id,
        responseSha256: record.safe_response_sha256.toString("hex")
      };
    }
    throw new DocumentTransactionError(
      "idempotency_in_progress",
      "identical document contribution is already in progress"
    );
  }
  if (
    expectedCurrentVersionId !== undefined &&
    (existingDocument?.current_version_id ?? null) !== expectedCurrentVersionId
  ) {
    throw new DocumentTransactionError(
      "document_contribution_unavailable",
      "document contribution is unavailable"
    );
  }

  let version: number;
  if (existingDocument) {
    if (
      existingDocument.document_title !== input.prepared.title ||
      existingDocument.document_state !== "active" ||
      existingDocument.current_version === null
    ) {
      throw new DocumentTransactionError(
        "document_contribution_unavailable",
        "document contribution is unavailable"
      );
    }
    version = existingDocument.current_version + 1;
  } else {
    version = 1;
    try {
      await client.query(
        `insert into documents(
         id,organization_id,board_id,title,current_version_id,created_by
       ) values ($1,$2,$3,$4,$5,$6)`,
        [
          input.prepared.documentId,
          context.organizationId,
          input.prepared.boardId,
          input.prepared.title,
          documentVersionId,
          context.memberId
        ]
      );
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "23505"
      ) {
        throw new DocumentTransactionError(
          "document_contribution_unavailable",
          "document contribution is unavailable"
        );
      }
      throw error;
    }
  }

  await client.query(
    `insert into document_versions(
       id,organization_id,board_id,document_id,version,media_type,document_schema,
       canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,
       created_by
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [
      documentVersionId,
      context.organizationId,
      input.prepared.boardId,
      input.prepared.documentId,
      version,
      input.prepared.mediaType,
      input.prepared.documentSchema,
      input.prepared.canonicalizationVersion,
      Buffer.from(input.prepared.canonicalBytes),
      input.prepared.byteLength,
      Buffer.from(input.prepared.sha256, "hex"),
      input.prepared.canonicalMetadata,
      context.memberId
    ]
  );
  const updatedSearch = await client.query<{ updated: boolean }>(
    `select boardagent_commit_document_version_projection($1,$2,$3,$4,$5,$6) as updated`,
    [
      input.prepared.documentId,
      input.prepared.boardId,
      existingDocument?.current_version_id ?? documentVersionId,
      documentVersionId,
      Buffer.from(input.prepared.sha256, "hex"),
      input.prepared.canonicalText
    ]
  );
  if (!updatedSearch.rows[0]?.updated) {
    throw new DocumentTransactionError(
      "document_contribution_unavailable",
      "document contribution is unavailable"
    );
  }
  await client.query(
    `insert into document_validation_attempts(
       id,organization_id,board_id,actor_member_id,offered_media_type,offered_name,
       offered_length,offered_sha256,result,result_code,remediation,
       accepted_document_version_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,'accepted','canonical_material_accepted',
       'Canonical UTF-8 source was accepted and persisted exactly.',$9)`,
    [
      validationAttemptId,
      context.organizationId,
      input.prepared.boardId,
      context.memberId,
      input.prepared.mediaType,
      input.offeredName ?? null,
      input.prepared.offeredByteLength,
      Buffer.from(input.prepared.offeredSha256, "hex"),
      documentVersionId
    ]
  );

  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: context.organizationId,
      objectVersion: BigInt(version),
      event: {
        eventId: auditEventId,
        eventType: "document_version_created",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "document_version",
        entityId: documentVersionId,
        boardId: input.prepared.boardId,
        origin: "mcp",
        details: {
          documentId: input.prepared.documentId,
          version,
          mediaType: input.prepared.mediaType,
          documentSchema: input.prepared.documentSchema,
          byteLength: input.prepared.byteLength,
          sha256: input.prepared.sha256,
          requestSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("document contribution audit event was not appended");
  const safeResponse = {
    documentId: input.prepared.documentId,
    documentVersionId,
    version,
    sha256: input.prepared.sha256,
    byteLength: input.prepared.byteLength
  };
  const responseSha256 = canonicalSha256(safeResponse);
  await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='document_version',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4
        and operation='create_document_version' and idempotency_key=$5`,
    [
      documentVersionId,
      Buffer.from(responseSha256, "hex"),
      context.memberId,
      context.clientId,
      idempotencyKey
    ]
  );
  return { replayed: false, ...safeResponse, responseSha256, auditEvent };
}

export interface RecordDocumentValidationRejectionInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly validationAttemptId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly expectedCurrentVersionId?: string | null;
  readonly offeredMediaType: string;
  readonly offeredName?: string | null;
  readonly offeredLength?: number | null;
  readonly offeredSha256?: string | null;
  readonly rejection: DocumentValidationError;
}

export interface DocumentValidationRejectionResult {
  readonly replayed: boolean;
  readonly validationAttemptId: string;
}

export async function recordDocumentValidationRejectionInTransaction(
  client: PoolClient,
  input: RecordDocumentValidationRejectionInput
): Promise<DocumentValidationRejectionResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const validationAttemptId = UuidV7Schema.parse(input.validationAttemptId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const expectedCurrentVersionId =
    input.expectedCurrentVersionId === undefined || input.expectedCurrentVersionId === null
      ? input.expectedCurrentVersionId
      : UuidV7Schema.parse(input.expectedCurrentVersionId);
  if (input.offeredMediaType.length < 1 || input.offeredMediaType.length > 255) {
    throw new RangeError("offered media type must contain 1 through 255 characters");
  }
  const offeredName = input.offeredName ?? null;
  if (offeredName !== null && (offeredName.length < 1 || offeredName.length > 1024)) {
    throw new RangeError("offered name must contain 1 through 1024 characters");
  }
  const offeredLength = input.offeredLength ?? null;
  if (offeredLength !== null && (!Number.isSafeInteger(offeredLength) || offeredLength < 0)) {
    throw new RangeError("offered length must be a nonnegative safe integer");
  }
  const offeredSha256 =
    input.offeredSha256 === null || input.offeredSha256 === undefined
      ? null
      : Sha256HexSchema.parse(input.offeredSha256);
  if (
    !/^[a-z][a-z0-9_]{1,63}$/u.test(input.rejection.code) ||
    input.rejection.remediation.length < 1 ||
    input.rejection.remediation.length > 2048 ||
    input.rejection.message.length < 1 ||
    input.rejection.message.length > 2048
  ) {
    throw new TypeError("document rejection metadata is invalid");
  }

  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new DocumentTransactionError(
      "document_contribution_unavailable",
      "document contribution is unavailable"
    );
  }
  const boardLock = await client.query<{ allowed: boolean }>(
    "select boardagent_lock_board_for_document_contribution($1) as allowed",
    [boardId]
  );
  if (!boardLock.rows[0]?.allowed) {
    throw new DocumentTransactionError(
      "document_contribution_unavailable",
      "document contribution is unavailable"
    );
  }

  const requestSha256 = canonicalSha256({
    schema: "boardagent.document-validation-rejection.v1",
    organizationId,
    boardId,
    offeredMediaType: input.offeredMediaType,
    offeredName,
    offeredLength,
    offeredSha256,
    resultCode: input.rejection.code,
    message: input.rejection.message,
    remediation: input.rejection.remediation,
    ...(expectedCurrentVersionId === undefined ? {} : { expectedCurrentVersionId })
  });
  const insertedIdempotency = await client.query<{ id: string }>(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'create_document_version',$5,$6,'in_progress',
       transaction_timestamp() + interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing
     returning id`,
    [
      idempotencyRecordId,
      organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  const idempotency = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='create_document_version' and idempotency_key=$3
      for update`,
    [context.memberId, context.clientId, idempotencyKey]
  );
  const record = idempotency.rows[0];
  if (!record) throw new Error("idempotency record disappeared inside its transaction");
  if (!safeHashEqual(record.request_sha256.toString("hex"), requestSha256)) {
    throw new DocumentTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different request"
    );
  }
  if (insertedIdempotency.rowCount === 0) {
    if (record.state === "succeeded" && record.safe_response_id) {
      return { replayed: true, validationAttemptId: record.safe_response_id };
    }
    throw new DocumentTransactionError(
      "idempotency_in_progress",
      "identical document validation rejection is already in progress"
    );
  }

  await client.query(
    `insert into document_validation_attempts(
       id,organization_id,board_id,actor_member_id,offered_media_type,offered_name,
       offered_length,offered_sha256,result,result_code,remediation
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,'rejected',$9,$10)`,
    [
      validationAttemptId,
      organizationId,
      boardId,
      context.memberId,
      input.offeredMediaType,
      offeredName,
      offeredLength,
      offeredSha256 === null ? null : Buffer.from(offeredSha256, "hex"),
      input.rejection.code,
      input.rejection.remediation
    ]
  );
  const responseSha256 = canonicalSha256({
    validationAttemptId,
    result: "rejected",
    resultCode: input.rejection.code
  });
  await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='document_validation_attempt',
            safe_response_id=$1,safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4
        and operation='create_document_version' and idempotency_key=$5`,
    [
      validationAttemptId,
      Buffer.from(responseSha256, "hex"),
      context.memberId,
      context.clientId,
      idempotencyKey
    ]
  );
  return { replayed: false, validationAttemptId };
}

export interface FetchDocumentVersionInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly documentId: string;
  readonly version: number | null;
  readonly auditEventId: string;
  readonly requestOrigin: string;
}

interface DocumentVersionRow {
  readonly id: string;
  readonly version: number;
  readonly media_type: string;
  readonly document_schema: string | null;
  readonly canonical_bytes: Buffer;
  readonly byte_length: number;
  readonly sha256: Buffer;
}

export interface PreparedDocumentFetch {
  readonly organizationId: string;
  readonly boardId: string;
  readonly documentId: string;
  readonly documentVersionId: string;
  readonly version: number;
  readonly mediaType: string;
  readonly documentSchema: string | null;
  readonly canonicalBytes: Buffer;
  readonly byteLength: number;
  readonly sha256: string;
  readonly resourceUri: string;
  readonly preparedEvent: AuditEvent;
}

function exactHttpsOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("request origin must be an exact canonical HTTPS origin");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin !== value
  ) {
    throw new TypeError("request origin must be an exact canonical HTTPS origin");
  }
  return value;
}

export async function fetchDocumentVersionInTransaction(
  client: PoolClient,
  input: FetchDocumentVersionInput
): Promise<PreparedDocumentFetch> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const documentId = UuidV7Schema.parse(input.documentId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const requestOrigin = exactHttpsOrigin(input.requestOrigin);
  if (
    input.version !== null &&
    (!Number.isSafeInteger(input.version) || input.version < 1 || input.version > 2_147_483_647)
  ) {
    throw new RangeError("document version must be a positive PostgreSQL integer");
  }
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new DocumentTransactionError(
      "document_version_unavailable",
      "document version is unavailable"
    );
  }
  const version = await client.query<DocumentVersionRow>(
    `select version_row.id,version_row.version,version_row.media_type,
            version_row.document_schema,version_row.canonical_bytes,
            version_row.byte_length,version_row.sha256
       from documents as document
       join document_versions as version_row on version_row.document_id=document.id
      where document.id=$1 and document.organization_id=$2 and document.board_id=$3
        and (($4::integer is null and document.current_version_id=version_row.id)
          or version_row.version=$4)
      limit 1`,
    [documentId, organizationId, boardId, input.version]
  );
  const row = version.rows[0];
  if (!row) {
    throw new DocumentTransactionError(
      "document_version_unavailable",
      "document version is unavailable"
    );
  }
  const sha256 = row.sha256.toString("hex");
  const resourceUri = `board://${boardId}/documents/${documentId}/versions/${String(row.version)}`;
  const [preparedEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: BigInt(row.version),
      event: {
        eventId: auditEventId,
        eventType: "resource_fetch",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "document_version",
        entityId: row.id,
        boardId,
        origin: "mcp",
        details: {
          phase: "prepared",
          resourceUri,
          representation: row.media_type,
          documentSchema: row.document_schema,
          sha256,
          byteLength: row.byte_length,
          memberId: context.memberId,
          tokenJti: context.tokenJti,
          clientId: context.clientId,
          requestOrigin,
          version: row.version
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!preparedEvent) throw new Error("resource fetch prepared event was not appended");
  return {
    organizationId,
    boardId,
    documentId,
    documentVersionId: row.id,
    version: row.version,
    mediaType: row.media_type,
    documentSchema: row.document_schema,
    canonicalBytes: row.canonical_bytes,
    byteLength: row.byte_length,
    sha256,
    resourceUri,
    preparedEvent
  };
}

export interface ResourceFetchOutcomeInput {
  readonly preparedEventId: string;
  readonly outcomeEventId: string;
  readonly outcome: "completed" | "interrupted";
  // Null is explicit uncertainty about canonical resource bytes, permitted only
  // for an observed interrupted transport. Encoded MCP response bytes differ.
  readonly bytesTransferred: number | null;
  readonly observation?: {
    readonly basis:
      "node_response_finish" | "node_response_interruption" | "response_not_associated";
    readonly responseBytesQueued: number;
  };
}

interface StoredPreparedEventRow {
  readonly organization_id: string;
  readonly event_sha256: Buffer;
  readonly canonical_payload: Buffer;
}

export async function recordResourceFetchOutcomeInTransaction(
  client: PoolClient,
  input: ResourceFetchOutcomeInput
): Promise<AuditEvent> {
  const preparedEventId = UuidV7Schema.parse(input.preparedEventId);
  const outcomeEventId = UuidV7Schema.parse(input.outcomeEventId);
  if (
    (input.bytesTransferred === null &&
      (input.outcome !== "interrupted" || input.observation === undefined)) ||
    (input.bytesTransferred !== null &&
      (!Number.isSafeInteger(input.bytesTransferred) || input.bytesTransferred < 0))
  ) {
    throw new DocumentTransactionError(
      "invalid_fetch_outcome",
      "fetch outcome byte count must be known and nonnegative, or explicitly unknown for an observed interruption"
    );
  }
  if (
    input.observation !== undefined &&
    (!Number.isSafeInteger(input.observation.responseBytesQueued) ||
      input.observation.responseBytesQueued < 0 ||
      !["node_response_finish", "node_response_interruption", "response_not_associated"].includes(
        input.observation.basis
      ) ||
      (input.outcome === "completed") !== (input.observation.basis === "node_response_finish"))
  ) {
    throw new DocumentTransactionError(
      "invalid_fetch_outcome",
      "fetch outcome observation is invalid"
    );
  }
  const context = await readRequestContext(client);
  const stored = await client.query<StoredPreparedEventRow>(
    `select organization_id,event_sha256,canonical_payload
       from audit_events
      where id=$1 and organization_id=$2 and event_type='resource_fetch'`,
    [preparedEventId, context.organizationId]
  );
  const row = stored.rows[0];
  if (!row) {
    throw new DocumentTransactionError(
      "invalid_fetch_outcome",
      "prepared resource fetch evidence is unavailable"
    );
  }
  const prepared = AuditEventBodySchema.parse(
    JSON.parse(row.canonical_payload.toString("utf8"))
  ) as AuditEventBody;
  const preparedLength = prepared.details["byteLength"];
  if (
    prepared.eventType !== "resource_fetch" ||
    prepared.details["phase"] !== "prepared" ||
    prepared.actorMemberId !== context.memberId ||
    prepared.actorClientId !== context.clientId ||
    prepared.tokenJti !== context.tokenJti ||
    typeof preparedLength !== "number" ||
    !Number.isSafeInteger(preparedLength) ||
    (input.bytesTransferred !== null && input.bytesTransferred > preparedLength) ||
    (input.outcome === "completed" && input.bytesTransferred !== preparedLength)
  ) {
    throw new DocumentTransactionError(
      "invalid_fetch_outcome",
      "fetch outcome does not match prepared evidence"
    );
  }
  const [outcome] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: row.organization_id,
      event: {
        eventId: outcomeEventId,
        eventType: "resource_fetch",
        actorMemberId: prepared.actorMemberId,
        actorClientId: prepared.actorClientId,
        tokenJti: prepared.tokenJti,
        entityType: prepared.entityType,
        entityId: prepared.entityId,
        boardId: prepared.boardId,
        origin: prepared.origin as AuditEventBody["origin"],
        details: {
          ...prepared.details,
          phase: input.outcome,
          preparedEventId,
          preparedEventHash: row.event_sha256.toString("hex"),
          bytesTransferred: input.bytesTransferred,
          ...(input.observation === undefined
            ? {}
            : {
                outcomeObservationVersion: 1,
                observationBasis: input.observation.basis,
                responseBytesQueued: input.observation.responseBytesQueued
              })
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!outcome) throw new Error("resource fetch outcome event was not appended");
  return outcome;
}
