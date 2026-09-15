import { randomBytes } from "node:crypto";

import type { PoolClient } from "pg";

import {
  PendingActionDeltaSchema,
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  type JsonValue
} from "@boardagent/contracts";
import { uuidV7 } from "@boardagent/domain";

import type { AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

export type DocumentLifecycleAction =
  | {
      readonly kind: "circulation";
      readonly boardId: string;
      readonly documentId: string;
      readonly versionId: string;
      readonly documentSha256: string;
      readonly recipientMemberIds: readonly string[];
      readonly completenessStatement: "canonical_version_stands_alone";
    }
  | {
      readonly kind: "access";
      readonly recusal?: true;
      readonly boardId: string;
      readonly documentId: string;
      readonly operation: "grant" | "exclude" | "lift_exclusion";
      readonly memberId: string;
      readonly permission: "read" | "contribute" | null;
      readonly reason: string;
    }
  | {
      readonly kind: "archive";
      readonly documentId: string;
      readonly reason: string;
    }
  | {
      readonly kind: "soft_delete";
      readonly documentId: string;
      readonly reason: string;
    };

export interface PreparedDocumentLifecycleAction {
  readonly actionCode:
    | "circulate_document"
    | "manage_document_access"
    | "manage_recusal"
    | "archive_document"
    | "soft_delete_document";
  readonly boardId: string;
  readonly targetId: string;
  readonly canonicalSchema: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
}

export interface DocumentLifecycleStageInput {
  readonly action: DocumentLifecycleAction;
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

export interface StagedDocumentLifecycleAction extends StagedAction {
  readonly actionCode: PreparedDocumentLifecycleAction["actionCode"];
  readonly boardId: string;
  readonly targetId: string;
}

export interface DocumentLifecycleConfirmationInput {
  readonly action: DocumentLifecycleAction;
  readonly confirmation: ConfirmStagedActionInput;
}

export type DocumentLifecycleResult =
  | {
      readonly kind: "circulation";
      readonly circulationId: string;
      readonly documentId: string;
      readonly documentVersionId: string;
      readonly documentSha256: string;
      readonly recipientMemberIds: readonly string[];
    }
  | {
      readonly kind: "access";
      readonly documentId: string;
      readonly operation: "grant" | "exclude" | "lift_exclusion";
      readonly memberId: string;
      readonly permission: "read" | "contribute" | null;
    }
  | {
      readonly kind: "archive" | "soft_delete";
      readonly documentId: string;
      readonly state: "archived" | "soft_deleted";
      readonly retentionSnapshotId: string | null;
      readonly deletionTombstoneId: string | null;
    };

export class DocumentLifecycleError extends Error {
  public constructor(
    public readonly code:
      "document_action_unavailable" | "document_action_invalid" | "document_recipient_unavailable",
    message: string
  ) {
    super(message);
    this.name = "DocumentLifecycleError";
  }
}

interface DocumentRootRow {
  readonly document_id: string;
  readonly organization_id: string;
  readonly board_id: string;
  readonly title: string;
  readonly document_state: "active" | "archived" | "soft_deleted";
  readonly row_version: string;
  readonly version_id: string;
  readonly version_number: number;
  readonly document_sha256: Buffer;
  readonly actor_is_secretary: boolean;
  readonly actor_is_admin: boolean;
}

interface RecipientRow {
  readonly member_id: string;
  readonly entitlement_generation: string;
  readonly can_read: boolean;
  readonly already_circulated: boolean;
}

interface PreparedRecipient {
  readonly memberId: string;
  readonly entitlementGeneration: number;
  readonly entitlementSnapshotSha256: string;
}

interface RetentionReference {
  readonly documentVersionId: string;
  readonly version: number;
  readonly mediaType: string;
  readonly documentSchema: string | null;
  readonly byteLength: number;
  readonly sha256: string;
}

type PreparedDetails =
  | { readonly kind: "circulation"; readonly recipients: readonly PreparedRecipient[] }
  | {
      readonly kind: "access";
      readonly activeGrantId: string | null;
      readonly activeExclusionId: string | null;
      readonly exclusionVersion: number;
    }
  | { readonly kind: "archive" }
  | {
      readonly kind: "soft_delete";
      readonly snapshotPayload: JsonValue;
      readonly snapshotSha256: string;
      readonly contentReferences: readonly RetentionReference[];
    };

interface PreparedInternal extends PreparedDocumentLifecycleAction {
  readonly action: DocumentLifecycleAction;
  readonly root: DocumentRootRow;
  readonly context: ActiveRequestContext;
  readonly details: PreparedDetails;
}

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

function boundedReason(value: string): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > 65_536) {
    throw new RangeError("document lifecycle reason must contain 1 through 65536 characters");
  }
  return normalized;
}

function normalizeAction(input: DocumentLifecycleAction): DocumentLifecycleAction {
  const documentId = UuidV7Schema.parse(input.documentId);
  switch (input.kind) {
    case "circulation": {
      const recipientMemberIds = input.recipientMemberIds
        .map((id) => UuidV7Schema.parse(id))
        .toSorted();
      if (
        recipientMemberIds.length === 0 ||
        recipientMemberIds.length > 1_000 ||
        new Set(recipientMemberIds).size !== recipientMemberIds.length
      ) {
        throw new DocumentLifecycleError(
          "document_action_invalid",
          "document circulation requires one through 1000 unique recipients"
        );
      }
      if (input.completenessStatement !== "canonical_version_stands_alone") {
        throw new DocumentLifecycleError(
          "document_action_invalid",
          "document circulation requires the exact completeness statement"
        );
      }
      return {
        ...input,
        documentId,
        boardId: UuidV7Schema.parse(input.boardId),
        versionId: UuidV7Schema.parse(input.versionId),
        documentSha256: Sha256HexSchema.parse(input.documentSha256),
        recipientMemberIds
      };
    }
    case "access": {
      const permission = input.permission;
      if (input.recusal && input.operation === "grant") {
        throw new DocumentLifecycleError(
          "document_action_invalid",
          "recusal cannot grant document access"
        );
      }
      if (
        (input.operation === "grant" && permission === null) ||
        (input.operation !== "grant" && permission !== null)
      ) {
        throw new DocumentLifecycleError(
          "document_action_invalid",
          "grant requires a permission and exclusion operations require null permission"
        );
      }
      return {
        ...input,
        documentId,
        boardId: UuidV7Schema.parse(input.boardId),
        memberId: UuidV7Schema.parse(input.memberId),
        reason: boundedReason(input.reason)
      };
    }
    case "archive":
    case "soft_delete":
      return { ...input, documentId, reason: boundedReason(input.reason) };
  }
}

function operation(action: DocumentLifecycleAction): {
  readonly actionCode: PreparedDocumentLifecycleAction["actionCode"];
  readonly canonicalSchema: string;
} {
  switch (action.kind) {
    case "circulation":
      return {
        actionCode: "circulate_document",
        canonicalSchema: "boardagent.document-circulation.v1"
      };
    case "access":
      return {
        actionCode: action.recusal ? "manage_recusal" : "manage_document_access",
        canonicalSchema: action.recusal
          ? "boardagent.document-recusal.v1"
          : "boardagent.document-access-change.v1"
      };
    case "archive":
      return { actionCode: "archive_document", canonicalSchema: "boardagent.document-archive.v1" };
    case "soft_delete":
      return {
        actionCode: "soft_delete_document",
        canonicalSchema: "boardagent.document-soft-delete.v1"
      };
  }
}

async function lockRoot(
  client: PoolClient,
  action: DocumentLifecycleAction
): Promise<{ readonly root: DocumentRootRow; readonly context: ActiveRequestContext }> {
  const context = await readRequestContext(client);
  const boardId = action.kind === "circulation" || action.kind === "access" ? action.boardId : null;
  const versionId = action.kind === "circulation" ? action.versionId : null;
  const result = await client.query<DocumentRootRow>(
    `select document_id,organization_id,board_id,title,document_state,row_version::text,
            version_id,version_number,document_sha256,actor_is_secretary,actor_is_admin
       from boardagent_lock_document_lifecycle($1,$2,$3)`,
    [action.documentId, boardId, versionId]
  );
  const root = result.rows[0];
  if (!root || result.rows.length !== 1 || root.organization_id !== context.organizationId) {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "document action is unavailable"
    );
  }
  if (
    (action.kind === "circulation" && !root.actor_is_secretary) ||
    ((action.kind === "access" || action.kind === "archive") &&
      !root.actor_is_secretary &&
      !root.actor_is_admin) ||
    (action.kind === "soft_delete" && !root.actor_is_admin)
  ) {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "document action is unavailable"
    );
  }
  const exclusion = await client.query<{ excluded: boolean }>(
    `select exists (
       select 1 from document_exclusions
        where organization_id=$1 and board_id=$2 and document_id=$3 and member_id=$4
          and active_from<=transaction_timestamp()
          and (active_until is null or active_until>transaction_timestamp())
     ) as excluded`,
    [context.organizationId, root.board_id, root.document_id, context.memberId]
  );
  if (exclusion.rows[0]?.excluded !== false) {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "document action is unavailable"
    );
  }
  return { root, context };
}

async function prepareCirculation(
  client: PoolClient,
  action: Extract<DocumentLifecycleAction, { readonly kind: "circulation" }>,
  root: DocumentRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  if (
    root.document_state !== "active" ||
    root.version_id !== action.versionId ||
    !safeHashEqual(root.document_sha256.toString("hex"), action.documentSha256)
  ) {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "exact active document version is unavailable for circulation"
    );
  }
  const recipients = await client.query<RecipientRow>(
    `select member_id,entitlement_generation::text,can_read,already_circulated
       from boardagent_lock_document_recipients($1,$2,$3::uuid[])`,
    [root.document_id, root.version_id, action.recipientMemberIds]
  );
  if (
    recipients.rows.length !== action.recipientMemberIds.length ||
    recipients.rows.some(
      (recipient, index) =>
        recipient.member_id !== action.recipientMemberIds[index] ||
        !recipient.can_read ||
        recipient.already_circulated
    )
  ) {
    throw new DocumentLifecycleError(
      "document_recipient_unavailable",
      "every circulation recipient must be an active, entitled, not-yet-notified member"
    );
  }
  const preparedRecipients = recipients.rows.map((recipient) => {
    const entitlementGeneration = Number(recipient.entitlement_generation);
    if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
      throw new Error("document recipient entitlement generation is invalid");
    }
    return {
      memberId: recipient.member_id,
      entitlementGeneration,
      entitlementSnapshotSha256: canonicalSha256({
        schemaVersion: "boardagent.document-recipient-entitlement.v1",
        boardId: root.board_id,
        documentId: root.document_id,
        documentVersionId: root.version_id,
        documentSha256: action.documentSha256,
        memberId: recipient.member_id,
        entitlementGeneration
      })
    };
  });
  return {
    payload: {
      schemaVersion: "boardagent.document-circulation.v1",
      boardId: root.board_id,
      documentId: root.document_id,
      documentVersionId: root.version_id,
      documentVersion: root.version_number,
      documentSha256: action.documentSha256,
      completenessStatement: action.completenessStatement,
      recipients: preparedRecipients
    },
    details: { kind: "circulation", recipients: preparedRecipients }
  };
}

async function prepareAccess(
  client: PoolClient,
  action: Extract<DocumentLifecycleAction, { readonly kind: "access" }>,
  root: DocumentRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  if (root.document_state !== "active") {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "only an active document may receive an access change"
    );
  }
  const member = await client.query<{
    member_id: string;
    seat_role: string;
    is_secretary: boolean;
    active_now: boolean;
    has_management_role: boolean;
  }>(
    `select member_id,seat_role,is_secretary,active_now,has_management_role
       from boardagent_lock_board_members($1,$2,array[$3]::uuid[])`,
    [root.organization_id, root.board_id, action.memberId]
  );
  const memberRow = member.rows[0];
  if (!memberRow || member.rows.length !== 1 || !memberRow.active_now) {
    throw new DocumentLifecycleError(
      "document_recipient_unavailable",
      "document access target must be an active member of the board"
    );
  }
  if (
    action.operation === "grant" &&
    action.permission === "contribute" &&
    memberRow.seat_role !== "management" &&
    !memberRow.is_secretary &&
    !memberRow.has_management_role
  ) {
    throw new DocumentLifecycleError(
      "document_action_invalid",
      "contribute permission requires an active management or secretariat target"
    );
  }
  const grant =
    action.permission === null
      ? { rows: [] as { id: string }[] }
      : await client.query<{ id: string }>(
          `select id from document_access_grants
            where document_id=$1 and grantee_member_id=$2 and permission=$3
              and active_from<=transaction_timestamp()
              and (active_until is null or active_until>transaction_timestamp())`,
          [root.document_id, action.memberId, action.permission]
        );
  const exclusion = await client.query<{ id: string; version: number }>(
    `select id,version from document_exclusions
      where document_id=$1 and member_id=$2
        and active_from<=transaction_timestamp()
        and (active_until is null or active_until>transaction_timestamp())
      for update`,
    [root.document_id, action.memberId]
  );
  const activeGrantId = grant.rows[0]?.id ?? null;
  const activeExclusionId = exclusion.rows[0]?.id ?? null;
  if (
    (action.operation === "grant" && (activeGrantId !== null || activeExclusionId !== null)) ||
    (action.operation === "exclude" && activeExclusionId !== null) ||
    (action.operation === "lift_exclusion" && activeExclusionId === null)
  ) {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "requested document access change is not available in the current state"
    );
  }
  const nextVersion = await client.query<{ version: number }>(
    `select coalesce(max(version),0)+1 as version
       from document_exclusions where document_id=$1 and member_id=$2`,
    [root.document_id, action.memberId]
  );
  const exclusionVersion =
    action.operation === "lift_exclusion"
      ? (exclusion.rows[0]?.version ?? 0)
      : (nextVersion.rows[0]?.version ?? 1);
  return {
    payload: {
      schemaVersion: action.recusal
        ? "boardagent.document-recusal.v1"
        : "boardagent.document-access-change.v1",
      boardId: root.board_id,
      documentId: root.document_id,
      currentDocumentVersionId: root.version_id,
      currentDocumentSha256: root.document_sha256.toString("hex"),
      operation: action.operation,
      memberId: action.memberId,
      permission: action.permission,
      reason: action.reason,
      exclusionVersion
    },
    details: {
      kind: "access",
      activeGrantId,
      activeExclusionId,
      exclusionVersion
    }
  };
}

async function prepareTerminal(
  client: PoolClient,
  action: Extract<DocumentLifecycleAction, { readonly kind: "archive" | "soft_delete" }>,
  root: DocumentRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  if (
    (action.kind === "archive" && root.document_state !== "active") ||
    (action.kind === "soft_delete" &&
      root.document_state !== "active" &&
      root.document_state !== "archived")
  ) {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "document terminal action is unavailable"
    );
  }
  const base = {
    documentId: root.document_id,
    boardId: root.board_id,
    title: root.title,
    priorState: root.document_state,
    priorRowVersion: root.row_version,
    currentDocumentVersionId: root.version_id,
    currentDocumentSha256: root.document_sha256.toString("hex"),
    reason: action.reason
  };
  if (action.kind === "archive") {
    return {
      payload: { schemaVersion: "boardagent.document-archive.v1", ...base },
      details: { kind: "archive" }
    };
  }
  const versions = await client.query<{
    version_id: string;
    version_number: number;
    media_type: string;
    document_schema: string | null;
    byte_length: number;
    sha256: Buffer;
  }>(
    `select version_id,version_number,media_type,document_schema,byte_length,sha256
       from boardagent_document_retention_manifest($1)`,
    [root.document_id]
  );
  if (versions.rows.length === 0) {
    throw new DocumentLifecycleError(
      "document_action_unavailable",
      "document retention manifest is unavailable"
    );
  }
  const contentReferences = versions.rows.map((version) => ({
    documentVersionId: version.version_id,
    version: version.version_number,
    mediaType: version.media_type,
    documentSchema: version.document_schema,
    byteLength: version.byte_length,
    sha256: version.sha256.toString("hex")
  }));
  const snapshotPayload: JsonValue = {
    schemaVersion: "boardagent.document-retention-snapshot.v1",
    ...base,
    versions: contentReferences
  };
  const snapshotSha256 = canonicalSha256(snapshotPayload);
  return {
    payload: {
      schemaVersion: "boardagent.document-soft-delete.v1",
      ...base,
      retentionSnapshotSha256: snapshotSha256
    },
    details: {
      kind: "soft_delete",
      snapshotPayload,
      snapshotSha256,
      contentReferences
    }
  };
}

async function prepareInternal(
  client: PoolClient,
  rawAction: DocumentLifecycleAction
): Promise<PreparedInternal> {
  const action = normalizeAction(rawAction);
  const { root, context } = await lockRoot(client, action);
  let prepared: { readonly payload: JsonValue; readonly details: PreparedDetails };
  switch (action.kind) {
    case "circulation":
      prepared = await prepareCirculation(client, action, root);
      break;
    case "access":
      prepared = await prepareAccess(client, action, root);
      break;
    case "archive":
    case "soft_delete":
      prepared = await prepareTerminal(client, action, root);
      break;
  }
  const descriptor = operation(action);
  return {
    ...descriptor,
    action,
    root,
    context,
    boardId: root.board_id,
    targetId: root.document_id,
    canonicalPayload: prepared.payload,
    payloadSha256: canonicalSha256(prepared.payload),
    packageSha256:
      action.kind === "circulation"
        ? canonicalSha256(prepared.payload)
        : root.document_sha256.toString("hex"),
    details: prepared.details
  };
}

export async function prepareDocumentLifecycleActionInTransaction(
  client: PoolClient,
  action: DocumentLifecycleAction
): Promise<PreparedDocumentLifecycleAction> {
  const prepared = await prepareInternal(client, action);
  return {
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetId: prepared.targetId,
    canonicalSchema: prepared.canonicalSchema,
    canonicalPayload: prepared.canonicalPayload,
    payloadSha256: prepared.payloadSha256,
    packageSha256: prepared.packageSha256
  };
}

export async function stageDocumentLifecycleActionInTransaction(
  client: PoolClient,
  input: DocumentLifecycleStageInput
): Promise<StagedDocumentLifecycleAction> {
  const prepared = await prepareInternal(client, input.action);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: "document",
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => {
      // Exact document, role, version, ACL and recipient rows were locked by preparation.
    }
  );
  return {
    ...staged,
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetId: prepared.targetId
  };
}

async function nextFeedSequence(
  client: PoolClient,
  boardId: string,
  memberId: string
): Promise<bigint> {
  const result = await client.query<{ next_sequence: string }>(
    `select (greatest(
              coalesce((select max(feed_sequence) from pending_action_feed
                         where board_id=$1 and member_id=$2),0),
              coalesce((select max(feed_sequence) from feed_tombstones
                         where board_id=$1 and member_id=$2),0)
            )+1)::text as next_sequence`,
    [boardId, memberId]
  );
  return BigInt(result.rows[0]?.next_sequence ?? "1");
}

async function timestamp(client: PoolClient): Promise<string> {
  const result = await client.query<{ occurred_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
  );
  const occurredAt = result.rows[0]?.occurred_at;
  if (!occurredAt) throw new Error("document lifecycle timestamp is unavailable");
  return Rfc3339UtcSchema.parse(occurredAt);
}

function auditInput(
  prepared: PreparedInternal,
  consentRecordId: string,
  eventId: string,
  eventType:
    | "document_circulated"
    | "document_access_changed"
    | "recusal_changed"
    | "document_archived"
    | "document_soft_deleted"
    | "notice_delivered",
  details: Readonly<Record<string, JsonValue>>,
  objectVersion: bigint
): AuditAppendInput {
  return {
    organizationId: prepared.root.organization_id,
    consentRecordId,
    objectVersion,
    event: {
      eventId,
      eventType,
      actorMemberId: prepared.context.memberId,
      actorClientId: prepared.context.clientId,
      tokenJti: prepared.context.tokenJti,
      entityType: "document",
      entityId: prepared.root.document_id,
      boardId: prepared.root.board_id,
      origin: "mcp",
      details,
      schemaVersion: 1
    }
  };
}

async function insertDocumentNotice(
  client: PoolClient,
  prepared: PreparedInternal,
  circulationId: string,
  recipient: PreparedRecipient,
  noticeAuditEventId: string
): Promise<void> {
  const noticeId = newId();
  const feedId = newId();
  const feedSequence = await nextFeedSequence(client, prepared.root.board_id, recipient.memberId);
  const delta = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: feedSequence.toString(10),
    deltaType: "notice",
    objectType: "document",
    objectId: prepared.root.document_id,
    objectVersion: prepared.root.version_number,
    entitlementGeneration: recipient.entitlementGeneration,
    actionState: "informational",
    safeRefs: {
      circulationId,
      documentVersionId: prepared.root.version_id,
      documentSha256: prepared.root.document_sha256.toString("hex")
    },
    createdAt: await timestamp(client)
  });
  const contentSha256 = canonicalSha256({
    noticeType: "document_circulated",
    circulationId,
    documentId: prepared.root.document_id,
    documentVersionId: prepared.root.version_id,
    documentSha256: prepared.root.document_sha256.toString("hex"),
    recipientMemberId: recipient.memberId
  });
  await client.query(
    `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,'document_circulated','document',$4,$5,$6,$7,$8,$9)`,
    [
      noticeId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.document_id,
      prepared.root.version_number,
      recipient.memberId,
      Buffer.from(contentSha256, "hex"),
      feedSequence.toString(10),
      noticeAuditEventId
    ]
  );
  const canonicalPayload = Buffer.from(canonicalJson(delta), "utf8");
  await client.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,notice_id,audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,'document_circulated','document',$7,$8,$9,$10,$11,$12,$13)`,
    [
      feedId,
      prepared.root.organization_id,
      prepared.root.board_id,
      recipient.memberId,
      recipient.entitlementGeneration,
      feedSequence.toString(10),
      prepared.root.document_id,
      prepared.root.version_number,
      Buffer.from(recipient.entitlementSnapshotSha256, "hex"),
      canonicalPayload,
      Buffer.from(canonicalSha256(delta), "hex"),
      noticeId,
      noticeAuditEventId
    ]
  );
  await client.query(
    `insert into circulation_recipients(
       circulation_id,member_id,document_version_id,entitlement_snapshot_sha256,
       notice_id,feed_sequence
     ) values ($1,$2,$3,$4,$5,$6)`,
    [
      circulationId,
      recipient.memberId,
      prepared.root.version_id,
      Buffer.from(recipient.entitlementSnapshotSha256, "hex"),
      noticeId,
      feedSequence.toString(10)
    ]
  );
}

async function tombstoneDocumentFeeds(
  client: PoolClient,
  prepared: PreparedInternal,
  memberId: string | null,
  reasonClass: "revoked" | "hidden" | "recused",
  auditEventId: string
): Promise<number> {
  const feeds = await client.query<{
    id: string;
    member_id: string;
    entitlement_generation: string;
    feed_sequence: string;
  }>(
    `select id,member_id,entitlement_generation::text,feed_sequence::text
       from pending_action_feed
      where board_id=$1 and object_type='document' and object_id=$2 and state='pending'
        and ($3::uuid is null or member_id=$3)
      order by member_id,feed_sequence
      for update`,
    [prepared.root.board_id, prepared.root.document_id, memberId]
  );
  for (const feed of feeds.rows) {
    const changed = await client.query(
      `update pending_action_feed set state='superseded'
        where id=$1 and state='pending'`,
      [feed.id]
    );
    if (changed.rowCount !== 1) throw new Error("document feed changed during tombstone");
    const tombstoneSha256 = canonicalSha256({
      schemaVersion: "boardagent.feed-tombstone.v1",
      removedFeedId: feed.id,
      memberId: feed.member_id,
      boardId: prepared.root.board_id,
      objectType: "document",
      objectId: prepared.root.document_id,
      entitlementGeneration: feed.entitlement_generation,
      feedSequence: feed.feed_sequence,
      reasonClass
    });
    await client.query(
      `insert into feed_tombstones(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,$7,'document',$8,$9,$10,$11)`,
      [
        newId(),
        prepared.root.organization_id,
        prepared.root.board_id,
        feed.member_id,
        feed.entitlement_generation,
        feed.feed_sequence,
        feed.id,
        prepared.root.document_id,
        reasonClass,
        Buffer.from(tombstoneSha256, "hex"),
        auditEventId
      ]
    );
  }
  return feeds.rows.length;
}

async function actCirculation(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: DocumentLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "circulation" || prepared.details.kind !== "circulation") {
    throw new Error("document circulation preparation mismatch");
  }
  const circulationId = newId();
  const documentAuditEventId = newId();
  const noticeAuditEventIds = prepared.details.recipients.map(() => newId());
  await client.query(
    `insert into document_circulations(
       id,organization_id,board_id,document_id,document_version_id,document_sha256,
       recipient_policy,package_sha256,consent_record_id,circulated_by,state
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'committed')`,
    [
      circulationId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.document_id,
      prepared.root.version_id,
      prepared.root.document_sha256,
      JSON.stringify({
        type: "explicit_members",
        memberIds: prepared.details.recipients.map(({ memberId }) => memberId)
      }),
      Buffer.from(prepared.packageSha256, "hex"),
      consentRecordId,
      prepared.context.memberId
    ]
  );
  for (const [index, recipient] of prepared.details.recipients.entries()) {
    const noticeAuditEventId = noticeAuditEventIds[index];
    if (!noticeAuditEventId) throw new Error("document notice audit ID is unavailable");
    await insertDocumentNotice(client, prepared, circulationId, recipient, noticeAuditEventId);
  }
  return {
    value: {
      kind: "circulation",
      circulationId,
      documentId: prepared.root.document_id,
      documentVersionId: prepared.root.version_id,
      documentSha256: prepared.root.document_sha256.toString("hex"),
      recipientMemberIds: prepared.details.recipients.map(({ memberId }) => memberId)
    },
    auditEvents: [
      auditInput(
        prepared,
        consentRecordId,
        documentAuditEventId,
        "document_circulated",
        {
          circulationId,
          documentVersionId: prepared.root.version_id,
          documentSha256: prepared.root.document_sha256.toString("hex"),
          packageSha256: prepared.packageSha256,
          recipientMemberIds: prepared.details.recipients.map(({ memberId }) => memberId),
          completenessStatement: prepared.action.completenessStatement
        },
        BigInt(prepared.root.version_number)
      ),
      ...prepared.details.recipients.map((recipient, index) => {
        const noticeAuditEventId = noticeAuditEventIds[index];
        if (!noticeAuditEventId) throw new Error("document notice audit ID is unavailable");
        return auditInput(
          prepared,
          consentRecordId,
          noticeAuditEventId,
          "notice_delivered",
          {
            meaning: "committed_recipient_feed_handoff",
            circulationId,
            recipientMemberId: recipient.memberId,
            noticeType: "document_circulated"
          },
          BigInt(prepared.root.version_number)
        );
      })
    ]
  };
}

async function actAccess(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: DocumentLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "access" || prepared.details.kind !== "access") {
    throw new Error("document access preparation mismatch");
  }
  const auditEventId = newId();
  let accessRecordId: string;
  let tombstoneCount = 0;
  if (prepared.action.operation === "grant") {
    accessRecordId = newId();
    await client.query(
      `insert into document_access_grants(
         id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by
       ) values ($1,$2,$3,$4,$5,$6,$7)`,
      [
        accessRecordId,
        prepared.root.organization_id,
        prepared.root.board_id,
        prepared.root.document_id,
        prepared.action.memberId,
        prepared.action.permission,
        prepared.context.memberId
      ]
    );
  } else if (prepared.action.operation === "exclude") {
    accessRecordId = newId();
    await client.query(
      `insert into document_exclusions(
         id,organization_id,board_id,document_id,member_id,version,reason,created_by
       ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        accessRecordId,
        prepared.root.organization_id,
        prepared.root.board_id,
        prepared.root.document_id,
        prepared.action.memberId,
        prepared.details.exclusionVersion,
        prepared.action.reason,
        prepared.context.memberId
      ]
    );
    tombstoneCount = await tombstoneDocumentFeeds(
      client,
      prepared,
      prepared.action.memberId,
      prepared.action.recusal ? "recused" : "revoked",
      auditEventId
    );
  } else {
    accessRecordId = prepared.details.activeExclusionId ?? "";
    const lifted = await client.query(
      `update document_exclusions set active_until=transaction_timestamp()
        where id=$1 and active_until is null`,
      [accessRecordId]
    );
    if (lifted.rowCount !== 1) throw new Error("document exclusion changed before lift");
  }
  return {
    value: {
      kind: "access",
      documentId: prepared.root.document_id,
      operation: prepared.action.operation,
      memberId: prepared.action.memberId,
      permission: prepared.action.permission
    },
    auditEvents: [
      auditInput(
        prepared,
        consentRecordId,
        auditEventId,
        prepared.action.recusal ? "recusal_changed" : "document_access_changed",
        {
          accessRecordId,
          operation: prepared.action.operation,
          memberId: prepared.action.memberId,
          permission: prepared.action.permission,
          reason: prepared.action.reason,
          exclusionVersion: prepared.details.exclusionVersion,
          tombstoneCount
        },
        BigInt(prepared.root.row_version)
      )
    ]
  };
}

async function actTerminal(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: DocumentLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "archive" && prepared.action.kind !== "soft_delete") {
    throw new Error("document terminal preparation mismatch");
  }
  const auditEventId = newId();
  let retentionSnapshotId: string | null = null;
  let deletionTombstoneId: string | null = null;
  let removedFeedCount = 0;
  if (prepared.action.kind === "soft_delete") {
    if (prepared.details.kind !== "soft_delete") {
      throw new Error("document retention snapshot preparation mismatch");
    }
    retentionSnapshotId = newId();
    deletionTombstoneId = newId();
    await client.query(
      `insert into retention_snapshots(
         id,organization_id,board_id,object_type,object_id,object_version,
         canonical_schema,canonical_payload,canonical_sha256,content_references
       ) values ($1,$2,$3,'document',$4,$5,'boardagent.document-retention-snapshot.v1',
                 $6,$7,$8)`,
      [
        retentionSnapshotId,
        prepared.root.organization_id,
        prepared.root.board_id,
        prepared.root.document_id,
        prepared.root.row_version,
        Buffer.from(canonicalJson(prepared.details.snapshotPayload), "utf8"),
        Buffer.from(prepared.details.snapshotSha256, "hex"),
        JSON.stringify(prepared.details.contentReferences)
      ]
    );
    await client.query(
      `insert into deletion_tombstones(
         id,organization_id,board_id,object_type,object_id,snapshot_id,actor_member_id,reason
       ) values ($1,$2,$3,'document',$4,$5,$6,$7)`,
      [
        deletionTombstoneId,
        prepared.root.organization_id,
        prepared.root.board_id,
        prepared.root.document_id,
        retentionSnapshotId,
        prepared.context.memberId,
        prepared.action.reason
      ]
    );
    removedFeedCount = await tombstoneDocumentFeeds(client, prepared, null, "hidden", auditEventId);
  } else if (prepared.details.kind !== "archive") {
    throw new Error("document archive preparation mismatch");
  }
  const state = prepared.action.kind === "archive" ? "archived" : "soft_deleted";
  const transitioned = await client.query<{ next_row_version: string }>(
    `select boardagent_apply_document_terminal_transition(
       $1,$2::bigint,$3,$4,$5,$6
     )::text as next_row_version`,
    [
      prepared.root.document_id,
      prepared.root.row_version,
      state,
      consentRecordId,
      prepared.root.version_id,
      prepared.root.document_sha256
    ]
  );
  const nextRowVersion = transitioned.rows[0]?.next_row_version;
  if (nextRowVersion !== (BigInt(prepared.root.row_version) + 1n).toString(10)) {
    throw new Error("document terminal transition returned an invalid version");
  }
  return {
    value: {
      kind: prepared.action.kind,
      documentId: prepared.root.document_id,
      state,
      retentionSnapshotId,
      deletionTombstoneId
    },
    auditEvents: [
      auditInput(
        prepared,
        consentRecordId,
        auditEventId,
        prepared.action.kind === "archive" ? "document_archived" : "document_soft_deleted",
        {
          reason: prepared.action.reason,
          priorState: prepared.root.document_state,
          currentDocumentVersionId: prepared.root.version_id,
          currentDocumentSha256: prepared.root.document_sha256.toString("hex"),
          retentionSnapshotId,
          deletionTombstoneId,
          removedFeedCount
        },
        BigInt(nextRowVersion)
      )
    ]
  };
}

async function performAction(
  client: PoolClient,
  prepared: PreparedInternal,
  consentRecordId: string
): Promise<{
  readonly value: DocumentLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  switch (prepared.action.kind) {
    case "circulation":
      return actCirculation(client, prepared, consentRecordId);
    case "access":
      return actAccess(client, prepared, consentRecordId);
    case "archive":
    case "soft_delete":
      return actTerminal(client, prepared, consentRecordId);
  }
}

export async function confirmDocumentLifecycleActionInTransaction(
  client: PoolClient,
  input: DocumentLifecycleConfirmationInput
): Promise<StagedActionResolution<DocumentLifecycleResult>> {
  let prepared: PreparedInternal | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareInternal(requestClient, input.action);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("document lifecycle preparation is unavailable");
      return performAction(requestClient, prepared, consentRecordId);
    }
  );
}
