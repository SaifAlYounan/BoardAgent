import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

type ProposalType = "meeting" | "vote" | "document" | "minutes" | "task" | "other";
type DraftType = "meeting" | "vote" | "minutes" | "task" | "proposal";
type CommunicationOperation =
  | "propose_action"
  | "withdraw_proposal"
  | "approve_proposal"
  | "reject_proposal"
  | "ask_secretariat"
  | "reply_secretariat_request"
  | "close_secretariat_request";

export interface CommunicationResourceReference {
  readonly uri: string;
  readonly sha256: string;
}

interface MutationEvidenceInput {
  readonly organizationId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface ProposeActionInput extends MutationEvidenceInput {
  readonly proposalId: string;
  readonly boardId: string;
  readonly proposalType: ProposalType;
  readonly title: string;
  readonly payload: JsonValue;
  readonly references: readonly CommunicationResourceReference[];
}

export interface WithdrawProposalInput extends MutationEvidenceInput {
  readonly proposalId: string;
}

export interface ApproveProposalInput extends MutationEvidenceInput {
  readonly dispositionId: string;
  readonly proposalId: string;
  readonly resultingDraftId: string;
  readonly draftType: DraftType;
  /** Opaque server-authenticated wizard context; never supplied by the MCP caller. */
  readonly signedContext: Uint8Array;
  readonly contextSha256: string;
}

export interface RejectProposalInput extends MutationEvidenceInput {
  readonly dispositionId: string;
  readonly proposalId: string;
  readonly reason: string;
}

export interface AskSecretariatInput extends MutationEvidenceInput {
  readonly requestId: string;
  readonly initialTurnId: string;
  readonly boardId: string;
  readonly topic: string;
  readonly message: string;
  readonly references: readonly CommunicationResourceReference[];
}

export interface ReplySecretariatRequestInput extends MutationEvidenceInput {
  readonly requestId: string;
  readonly turnId: string;
  readonly reply: string;
}

export interface CloseSecretariatRequestInput extends MutationEvidenceInput {
  readonly requestId: string;
}

export type CommunicationMutationResult =
  | {
      readonly replayed: true;
      readonly operation: CommunicationOperation;
      readonly objectId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly operation: CommunicationOperation;
      readonly objectId: string;
      readonly state: string;
      readonly rowVersion: bigint;
      readonly responseSha256: string;
      readonly auditEvent: AuditEvent;
      readonly resultingDraftId?: string;
    };

export class CommunicationTransactionError extends Error {
  public constructor(
    public readonly code:
      | "communication_unavailable"
      | "communication_reference_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "CommunicationTransactionError";
  }
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface MutationRow {
  readonly object_id: string;
  readonly object_state: string;
  readonly row_version: string;
  readonly board_id: string;
}

const PROPOSAL_TYPES = new Set<ProposalType>([
  "meeting",
  "vote",
  "document",
  "minutes",
  "task",
  "other"
]);
const DRAFT_TYPES = new Set<DraftType>(["meeting", "vote", "minutes", "task", "proposal"]);

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 200 || !/^[A-Za-z0-9._~-]+$/u.test(value)) {
    throw new RangeError("idempotency key must match the frozen 16-to-200 character form");
  }
  return value;
}

function boundedCanonicalText(value: string, label: string, maximum: number): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > maximum) {
    throw new RangeError(`${label} must contain 1 through ${String(maximum)} characters`);
  }
  return normalized;
}

function references(
  supplied: readonly CommunicationResourceReference[]
): readonly CommunicationResourceReference[] {
  if (supplied.length > 256) throw new RangeError("resource references exceed 256 entries");
  const normalized = supplied.map((reference) => {
    if (reference.uri.length < 1 || reference.uri.length > 4096) {
      throw new RangeError("resource reference URI must contain 1 through 4096 characters");
    }
    let uri: URL;
    try {
      uri = new URL(reference.uri);
    } catch {
      throw new CommunicationTransactionError(
        "communication_reference_invalid",
        "resource reference URI is invalid"
      );
    }
    if (uri.protocol !== "board:" || uri.href !== reference.uri) {
      throw new CommunicationTransactionError(
        "communication_reference_invalid",
        "resource reference must be one canonical board:// URI"
      );
    }
    return { uri: reference.uri, sha256: Sha256HexSchema.parse(reference.sha256) };
  });
  if (new Set(normalized.map(({ uri }) => uri)).size !== normalized.length) {
    throw new CommunicationTransactionError(
      "communication_reference_invalid",
      "resource references must be unique by URI"
    );
  }
  return normalized;
}

function responseSha256(operation: CommunicationOperation, objectId: string): string {
  return canonicalSha256({
    schemaVersion: "boardagent.communication-safe-response.v1",
    operation,
    objectId
  });
}

async function assertOrganization(client: PoolClient, organizationId: string) {
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new CommunicationTransactionError(
      "communication_unavailable",
      "communication object is unavailable"
    );
  }
  return context;
}

async function requireAuthorization(
  client: PoolClient,
  sql: string,
  values: readonly unknown[]
): Promise<void> {
  const result = await client.query<{ authorized: boolean }>(sql, [...values]);
  if (result.rows[0]?.authorized !== true) {
    throw new CommunicationTransactionError(
      "communication_unavailable",
      "communication object is unavailable"
    );
  }
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  operation: CommunicationOperation,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation=$3 and idempotency_key=$4
      for update`,
    [actorMemberId, clientId, operation, key]
  );
  return result.rows[0];
}

function replayResult(
  record: IdempotencyRow,
  operation: CommunicationOperation,
  expectedRequestSha256: string,
  expectedResponseType: "proposal" | "secretariat_request"
): Extract<CommunicationMutationResult, { readonly replayed: true }> {
  if (!safeHashEqual(record.request_sha256.toString("hex"), expectedRequestSha256)) {
    throw new CommunicationTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different communication request"
    );
  }
  if (record.state !== "succeeded") {
    throw new CommunicationTransactionError(
      "idempotency_in_progress",
      "identical communication request is already in progress"
    );
  }
  if (
    record.safe_response_type !== expectedResponseType ||
    !record.safe_response_id ||
    !record.safe_response_sha256
  ) {
    throw new Error("communication idempotency record has no safe response");
  }
  const expectedResponseSha256 = responseSha256(operation, record.safe_response_id);
  if (!safeHashEqual(record.safe_response_sha256.toString("hex"), expectedResponseSha256)) {
    throw new Error("communication idempotency safe response hash is invalid");
  }
  return {
    replayed: true,
    operation,
    objectId: record.safe_response_id,
    responseSha256: expectedResponseSha256
  };
}

async function acquireIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly operation: CommunicationOperation;
    readonly key: string;
    readonly requestSha256: string;
    readonly responseType: "proposal" | "secretariat_request";
  }
): Promise<Extract<CommunicationMutationResult, { readonly replayed: true }> | undefined> {
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      input.id,
      input.organizationId,
      input.actorMemberId,
      input.clientId,
      input.operation,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
  const record = await readIdempotency(
    client,
    input.actorMemberId,
    input.clientId,
    input.operation,
    input.key
  );
  if (!record) throw new Error("communication idempotency record disappeared");
  if (inserted.rowCount === 0) {
    return replayResult(record, input.operation, input.requestSha256, input.responseType);
  }
  if (!safeHashEqual(record.request_sha256.toString("hex"), input.requestSha256)) {
    throw new CommunicationTransactionError(
      "idempotency_conflict",
      "communication idempotency record does not bind this request"
    );
  }
  return undefined;
}

async function completeIdempotency(
  client: PoolClient,
  input: {
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly operation: CommunicationOperation;
    readonly key: string;
    readonly responseType: "proposal" | "secretariat_request";
    readonly objectId: string;
    readonly responseSha256: string;
  }
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type=$1,safe_response_id=$2,
            safe_response_sha256=$3,completed_at=transaction_timestamp()
      where actor_member_id=$4 and client_id=$5 and operation=$6 and idempotency_key=$7
        and state='in_progress'`,
    [
      input.responseType,
      input.objectId,
      Buffer.from(input.responseSha256, "hex"),
      input.actorMemberId,
      input.clientId,
      input.operation,
      input.key
    ]
  );
  if (result.rowCount !== 1) throw new Error("communication idempotency completion failed");
}

async function finishMutation(
  client: PoolClient,
  input: {
    readonly context: Awaited<ReturnType<typeof readRequestContext>>;
    readonly organizationId: string;
    readonly operation: CommunicationOperation;
    readonly idempotencyKey: string;
    readonly responseType: "proposal" | "secretariat_request";
    readonly objectId: string;
    readonly boardId: string;
    readonly state: string;
    readonly rowVersion: bigint;
    readonly auditEventId: string;
    readonly eventType:
      | "proposal_submitted"
      | "proposal_withdrawn"
      | "proposal_approved_to_draft"
      | "proposal_rejected"
      | "secretariat_request_created"
      | "secretariat_request_replied"
      | "secretariat_request_closed";
    readonly entityType: "proposal" | "secretariat_request";
    readonly details: Readonly<Record<string, JsonValue>>;
    readonly resultingDraftId?: string;
  }
): Promise<Extract<CommunicationMutationResult, { readonly replayed: false }>> {
  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      objectVersion: input.rowVersion,
      event: {
        eventId: input.auditEventId,
        eventType: input.eventType,
        actorMemberId: input.context.memberId,
        actorClientId: input.context.clientId,
        tokenJti: input.context.tokenJti,
        entityType: input.entityType,
        entityId: input.objectId,
        boardId: input.boardId,
        origin: "mcp",
        details: input.details,
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("communication audit append returned no event");
  const safeResponseSha256 = responseSha256(input.operation, input.objectId);
  await completeIdempotency(client, {
    actorMemberId: input.context.memberId,
    clientId: input.context.clientId,
    operation: input.operation,
    key: input.idempotencyKey,
    responseType: input.responseType,
    objectId: input.objectId,
    responseSha256: safeResponseSha256
  });
  return {
    replayed: false,
    operation: input.operation,
    objectId: input.objectId,
    state: input.state,
    rowVersion: input.rowVersion,
    responseSha256: safeResponseSha256,
    auditEvent,
    ...(input.resultingDraftId ? { resultingDraftId: input.resultingDraftId } : {})
  };
}

function mutationRow(row: MutationRow | undefined): {
  readonly objectId: string;
  readonly state: string;
  readonly rowVersion: bigint;
  readonly boardId: string;
} {
  if (!row) throw new Error("communication mutation returned no row");
  const rowVersion = BigInt(row.row_version);
  if (rowVersion < 1n) throw new Error("communication mutation returned an invalid row version");
  return {
    objectId: row.object_id,
    state: row.object_state,
    rowVersion,
    boardId: UuidV7Schema.parse(row.board_id)
  };
}

/** A terminal state blocks a new effect, not an exact retained successful retry. */
async function completedCommunicationReplay(
  client: PoolClient,
  context: Awaited<ReturnType<typeof assertOrganization>>,
  operation: CommunicationOperation,
  key: string,
  requestHash: string,
  targetId: string,
  responseType: "proposal" | "secretariat_request"
): Promise<Extract<CommunicationMutationResult, { readonly replayed: true }> | undefined> {
  const stored = await readIdempotency(client, context.memberId, context.clientId, operation, key);
  if (!stored || stored.state !== "succeeded") return undefined;
  // Current permission is checked without adding proposal read access for a
  // proposer. Only the terminal-state predicate is omitted; mutation guards stay.
  await requireAuthorization(
    client,
    "select boardagent_communication_replay_authorized($1,$2) as authorized",
    [targetId, operation]
  );
  const replayed = replayResult(stored, operation, requestHash, responseType);
  if (replayed.objectId !== targetId) throw new Error("communication replay target binding failed");
  return replayed;
}

export async function proposeActionInTransaction(
  client: PoolClient,
  input: ProposeActionInput
): Promise<CommunicationMutationResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const proposalId = UuidV7Schema.parse(input.proposalId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  if (!PROPOSAL_TYPES.has(input.proposalType)) throw new TypeError("invalid proposal type");
  const title = boundedCanonicalText(input.title, "proposal title", 1024);
  const normalizedReferences = references(input.references);
  const payloadBytes = Buffer.from(
    canonicalJson({
      schemaVersion: "boardagent.proposal.v1",
      proposalId,
      boardId,
      proposalType: input.proposalType,
      title,
      payload: input.payload,
      references: normalizedReferences
    }),
    "utf8"
  );
  const payloadSha256 = canonicalSha256(JSON.parse(payloadBytes.toString("utf8")) as JsonValue);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.propose-action-request.v1",
    proposalId,
    boardId,
    proposalType: input.proposalType,
    title,
    payloadSha256,
    references: normalizedReferences
  });
  const context = await assertOrganization(client, organizationId);
  await requireAuthorization(client, "select boardagent_proposer_for_board($1) as authorized", [
    boardId
  ]);
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "propose_action",
    key,
    requestSha256: requestHash,
    responseType: "proposal"
  });
  if (replayed) return replayed;
  await requireAuthorization(
    client,
    "select boardagent_idempotency_in_progress($1,'propose_action') as authorized",
    [idempotencyRecordId]
  );
  const result = await client.query<MutationRow>(
    `select proposal_id as object_id,proposal_state as object_state,
            result_row_version::text as row_version,result_board_id as board_id
       from boardagent_create_proposal($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`,
    [
      proposalId,
      boardId,
      input.proposalType,
      title,
      payloadBytes,
      Buffer.from(payloadSha256, "hex"),
      JSON.stringify(normalizedReferences),
      idempotencyRecordId,
      auditEventId
    ]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation: "propose_action",
    idempotencyKey: key,
    responseType: "proposal",
    objectId: changed.objectId,
    boardId,
    state: changed.state,
    rowVersion: changed.rowVersion,
    auditEventId,
    eventType: "proposal_submitted",
    entityType: "proposal",
    details: { proposalType: input.proposalType, title, payloadSha256, requestSha256: requestHash }
  });
}

export async function withdrawProposalInTransaction(
  client: PoolClient,
  input: WithdrawProposalInput
): Promise<CommunicationMutationResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const proposalId = UuidV7Schema.parse(input.proposalId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.withdraw-proposal-request.v1",
    proposalId
  });
  const context = await assertOrganization(client, organizationId);
  const completedReplay = await completedCommunicationReplay(
    client,
    context,
    "withdraw_proposal",
    key,
    requestHash,
    proposalId,
    "proposal"
  );
  if (completedReplay) return completedReplay;
  await requireAuthorization(
    client,
    "select boardagent_proposal_action_authorized($1,'withdraw_proposal') as authorized",
    [proposalId]
  );
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "withdraw_proposal",
    key,
    requestSha256: requestHash,
    responseType: "proposal"
  });
  if (replayed) return replayed;
  await requireAuthorization(
    client,
    "select boardagent_idempotency_in_progress($1,'withdraw_proposal') as authorized",
    [idempotencyRecordId]
  );
  const result = await client.query<MutationRow>(
    `select proposal_id as object_id,proposal_state as object_state,
            result_row_version::text as row_version,result_board_id as board_id
       from boardagent_withdraw_proposal($1,$2,$3)`,
    [proposalId, idempotencyRecordId, auditEventId]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation: "withdraw_proposal",
    idempotencyKey: key,
    responseType: "proposal",
    objectId: changed.objectId,
    boardId: changed.boardId,
    state: changed.state,
    rowVersion: changed.rowVersion,
    auditEventId,
    eventType: "proposal_withdrawn",
    entityType: "proposal",
    details: { requestSha256: requestHash }
  });
}

async function disposeProposalInTransaction(
  client: PoolClient,
  input: ApproveProposalInput | RejectProposalInput,
  disposition: "approved_to_draft" | "rejected"
): Promise<CommunicationMutationResult> {
  const operation = disposition === "approved_to_draft" ? "approve_proposal" : "reject_proposal";
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const proposalId = UuidV7Schema.parse(input.proposalId);
  const dispositionId = UuidV7Schema.parse(input.dispositionId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const approval = disposition === "approved_to_draft" ? (input as ApproveProposalInput) : null;
  const rejection = disposition === "rejected" ? (input as RejectProposalInput) : null;
  const reason = rejection
    ? boundedCanonicalText(rejection.reason, "proposal rejection reason", 65_536)
    : null;
  const resultingDraftId = approval ? UuidV7Schema.parse(approval.resultingDraftId) : null;
  const draftType = approval?.draftType ?? null;
  if (draftType !== null && !DRAFT_TYPES.has(draftType)) throw new TypeError("invalid draft type");
  const signedContext = approval ? Buffer.from(approval.signedContext) : null;
  if (signedContext && (signedContext.length < 32 || signedContext.length > 1_048_576)) {
    throw new RangeError("signed draft context must contain 32 through 1,048,576 bytes");
  }
  const contextSha256 = approval ? Sha256HexSchema.parse(approval.contextSha256) : null;
  if (signedContext && !safeHashEqual(sha256Hex(signedContext), contextSha256!)) {
    throw new CommunicationTransactionError(
      "communication_unavailable",
      "signed draft context hash is invalid"
    );
  }
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.proposal-disposition-request.v1",
    operation,
    proposalId,
    resultingDraftId,
    draftType,
    contextSha256,
    reason
  });
  const context = await assertOrganization(client, organizationId);
  const completedReplay = await completedCommunicationReplay(
    client,
    context,
    operation,
    key,
    requestHash,
    proposalId,
    "proposal"
  );
  if (completedReplay) return completedReplay;
  await requireAuthorization(
    client,
    `select boardagent_proposal_action_authorized($1,$2) as authorized`,
    [proposalId, operation]
  );
  const proposal = await client.query<{ board_id: string; payload_sha256: Buffer }>(
    "select board_id,payload_sha256 from proposals where id=$1 and state='pending'",
    [proposalId]
  );
  const proposalRow = proposal.rows[0];
  if (!proposalRow || proposalRow.payload_sha256.length !== 32) {
    throw new CommunicationTransactionError("communication_unavailable", "proposal is unavailable");
  }
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation,
    key,
    requestSha256: requestHash,
    responseType: "proposal"
  });
  if (replayed) return replayed;
  const result = await client.query<MutationRow>(
    `select proposal_id as object_id,proposal_state as object_state,
            result_row_version::text as row_version,result_board_id as board_id
       from boardagent_dispose_proposal($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      dispositionId,
      proposalId,
      disposition,
      reason,
      resultingDraftId,
      draftType,
      signedContext,
      contextSha256 ? Buffer.from(contextSha256, "hex") : null,
      idempotencyRecordId,
      auditEventId
    ]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation,
    idempotencyKey: key,
    responseType: "proposal",
    objectId: changed.objectId,
    boardId: proposalRow.board_id,
    state: changed.state,
    rowVersion: changed.rowVersion,
    auditEventId,
    eventType:
      disposition === "approved_to_draft" ? "proposal_approved_to_draft" : "proposal_rejected",
    entityType: "proposal",
    details: {
      dispositionId,
      requestSha256: requestHash,
      proposalPayloadSha256: proposalRow.payload_sha256.toString("hex"),
      ...(reason ? { reasonSha256: canonicalSha256(reason) } : {}),
      ...(resultingDraftId && draftType && contextSha256
        ? { resultingDraftId, draftType, contextSha256 }
        : {})
    },
    ...(resultingDraftId ? { resultingDraftId } : {})
  });
}

export function approveProposalInTransaction(
  client: PoolClient,
  input: ApproveProposalInput
): Promise<CommunicationMutationResult> {
  return disposeProposalInTransaction(client, input, "approved_to_draft");
}

export function rejectProposalInTransaction(
  client: PoolClient,
  input: RejectProposalInput
): Promise<CommunicationMutationResult> {
  return disposeProposalInTransaction(client, input, "rejected");
}

export async function askSecretariatInTransaction(
  client: PoolClient,
  input: AskSecretariatInput
): Promise<CommunicationMutationResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const requestId = UuidV7Schema.parse(input.requestId);
  const initialTurnId = UuidV7Schema.parse(input.initialTurnId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const topic = boundedCanonicalText(input.topic, "secretariat topic", 1024);
  const message = boundedCanonicalText(input.message, "secretariat message", 1_048_576);
  const normalizedReferences = references(input.references);
  const textSha256 = canonicalSha256(message);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.secretariat-request.v1",
    requestId,
    boardId,
    topic,
    messageSha256: textSha256,
    references: normalizedReferences
  });
  const context = await assertOrganization(client, organizationId);
  await requireAuthorization(
    client,
    `select (
       boardagent_communication_actor_ready($1,'secretariat:message') and exists (
         select 1 from board_memberships as membership
          where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
            and membership.board_id=$1
            and membership.member_id=boardagent_context_uuid('boardagent.member_id')
            and membership.state='active' and membership.seat_role<>'observer'
            and membership.active_from<=transaction_timestamp()
            and (membership.active_until is null or membership.active_until>transaction_timestamp())
       )
     ) as authorized`,
    [boardId]
  );
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "ask_secretariat",
    key,
    requestSha256: requestHash,
    responseType: "secretariat_request"
  });
  if (replayed) return replayed;
  const result = await client.query<MutationRow>(
    `select request_id as object_id,request_state as object_state,
            result_row_version::text as row_version,result_board_id as board_id
       from boardagent_create_secretariat_request($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`,
    [
      requestId,
      initialTurnId,
      boardId,
      topic,
      message,
      Buffer.from(textSha256, "hex"),
      JSON.stringify(normalizedReferences),
      idempotencyRecordId,
      auditEventId
    ]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation: "ask_secretariat",
    idempotencyKey: key,
    responseType: "secretariat_request",
    objectId: changed.objectId,
    boardId,
    state: changed.state,
    rowVersion: changed.rowVersion,
    auditEventId,
    eventType: "secretariat_request_created",
    entityType: "secretariat_request",
    details: {
      initialTurnId,
      topicSha256: canonicalSha256(topic),
      textSha256,
      requestSha256: requestHash
    }
  });
}

export async function replySecretariatRequestInTransaction(
  client: PoolClient,
  input: ReplySecretariatRequestInput
): Promise<CommunicationMutationResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const requestId = UuidV7Schema.parse(input.requestId);
  const turnId = UuidV7Schema.parse(input.turnId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const reply = boundedCanonicalText(input.reply, "secretariat reply", 1_048_576);
  const textSha256 = canonicalSha256(reply);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.secretariat-reply.v1",
    requestId,
    textSha256
  });
  const context = await assertOrganization(client, organizationId);
  const completedReplay = await completedCommunicationReplay(
    client,
    context,
    "reply_secretariat_request",
    key,
    requestHash,
    requestId,
    "secretariat_request"
  );
  if (completedReplay) return completedReplay;
  await requireAuthorization(
    client,
    "select boardagent_secretariat_request_action_authorized($1,'reply_secretariat_request') as authorized",
    [requestId]
  );
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "reply_secretariat_request",
    key,
    requestSha256: requestHash,
    responseType: "secretariat_request"
  });
  if (replayed) return replayed;
  const result = await client.query<MutationRow>(
    `select request_id as object_id,request_state as object_state,
            result_row_version::text as row_version,result_board_id as board_id
       from boardagent_reply_secretariat_request($1,$2,$3,$4,$5,$6)`,
    [turnId, requestId, reply, Buffer.from(textSha256, "hex"), idempotencyRecordId, auditEventId]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation: "reply_secretariat_request",
    idempotencyKey: key,
    responseType: "secretariat_request",
    objectId: changed.objectId,
    boardId: changed.boardId,
    state: changed.state,
    rowVersion: changed.rowVersion,
    auditEventId,
    eventType: "secretariat_request_replied",
    entityType: "secretariat_request",
    details: { turnId, textSha256, requestSha256: requestHash }
  });
}

export async function closeSecretariatRequestInTransaction(
  client: PoolClient,
  input: CloseSecretariatRequestInput
): Promise<CommunicationMutationResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const requestId = UuidV7Schema.parse(input.requestId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const requestHash = canonicalSha256({
    schemaVersion: "boardagent.secretariat-close.v1",
    requestId
  });
  const context = await assertOrganization(client, organizationId);
  const completedReplay = await completedCommunicationReplay(
    client,
    context,
    "close_secretariat_request",
    key,
    requestHash,
    requestId,
    "secretariat_request"
  );
  if (completedReplay) return completedReplay;
  await requireAuthorization(
    client,
    "select boardagent_secretariat_request_action_authorized($1,'close_secretariat_request') as authorized",
    [requestId]
  );
  const replayed = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    operation: "close_secretariat_request",
    key,
    requestSha256: requestHash,
    responseType: "secretariat_request"
  });
  if (replayed) return replayed;
  const result = await client.query<MutationRow>(
    `select request_id as object_id,request_state as object_state,
            result_row_version::text as row_version,result_board_id as board_id
       from boardagent_close_secretariat_request($1,$2,$3)`,
    [requestId, idempotencyRecordId, auditEventId]
  );
  const changed = mutationRow(result.rows[0]);
  return finishMutation(client, {
    context,
    organizationId,
    operation: "close_secretariat_request",
    idempotencyKey: key,
    responseType: "secretariat_request",
    objectId: changed.objectId,
    boardId: changed.boardId,
    state: changed.state,
    rowVersion: changed.rowVersion,
    auditEventId,
    eventType: "secretariat_request_closed",
    entityType: "secretariat_request",
    details: { requestSha256: requestHash }
  });
}
