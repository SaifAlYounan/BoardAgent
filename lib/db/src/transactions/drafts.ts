import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import { UuidV7Schema, canonicalSha256, canonicalText, safeHashEqual } from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export interface CancelWizardDraftInput {
  readonly organizationId: string;
  readonly exactOrigin: string;
  readonly draftId: string;
  readonly reason: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export type CancelWizardDraftResult =
  | {
      readonly replayed: true;
      readonly draftId: string;
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly draftId: string;
      readonly boardId: string;
      readonly state: "cancelled";
      readonly rowVersion: bigint;
      readonly responseSha256: string;
      readonly auditEvent: AuditEvent;
    };

export class WizardDraftTransactionError extends Error {
  public constructor(
    public readonly code: "draft_unavailable" | "idempotency_conflict" | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "WizardDraftTransactionError";
  }
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface LockedDraftRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly draft_state: string;
  readonly draft_row_version: string;
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 200 || !/^[A-Za-z0-9._~-]+$/u.test(value)) {
    throw new RangeError("idempotency key must match the frozen 16-to-200 character form");
  }
  return value;
}

function boundedReason(value: string): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > 65_536) {
    throw new RangeError("draft cancellation reason must contain 1 through 65,536 characters");
  }
  return normalized;
}

function responseSha256(draftId: string): string {
  return canonicalSha256({ schemaVersion: "boardagent.draft-cancel-response.v1", draftId });
}

function replayResult(
  row: IdempotencyRow,
  requestSha256: string
): Extract<CancelWizardDraftResult, { readonly replayed: true }> {
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new WizardDraftTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different draft cancellation"
    );
  }
  if (
    row.state !== "succeeded" ||
    row.safe_response_type !== "wizard_draft" ||
    !row.safe_response_id ||
    !row.safe_response_sha256
  ) {
    throw new WizardDraftTransactionError(
      "idempotency_in_progress",
      "identical draft cancellation is already in progress"
    );
  }
  const expected = responseSha256(row.safe_response_id);
  if (!safeHashEqual(row.safe_response_sha256.toString("hex"), expected)) {
    throw new Error("draft cancellation safe response hash is invalid");
  }
  return { replayed: true, draftId: row.safe_response_id, responseSha256: expected };
}

async function acquireIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<Extract<CancelWizardDraftResult, { readonly replayed: true }> | undefined> {
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'cancel_draft',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      input.id,
      input.organizationId,
      input.actorMemberId,
      input.clientId,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
  const found = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2 and operation='cancel_draft'
        and idempotency_key=$3
      for update`,
    [input.actorMemberId, input.clientId, input.key]
  );
  const row = found.rows[0];
  if (!row) throw new Error("draft cancellation idempotency record disappeared");
  if (inserted.rowCount === 0) return replayResult(row, input.requestSha256);
  if (!safeHashEqual(row.request_sha256.toString("hex"), input.requestSha256)) {
    throw new WizardDraftTransactionError(
      "idempotency_conflict",
      "draft cancellation idempotency record does not bind this request"
    );
  }
  return undefined;
}

export async function cancelWizardDraftInTransaction(
  client: PoolClient,
  input: CancelWizardDraftInput
): Promise<CancelWizardDraftResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const draftId = UuidV7Schema.parse(input.draftId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const key = idempotencyKey(input.idempotencyKey);
  const reason = boundedReason(input.reason);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new WizardDraftTransactionError("draft_unavailable", "wizard draft is unavailable");
  }
  // Completed responses still require the creator's current access. The original
  // cancellation may have ended the draft, so only the first execution below
  // requires an active, nonexpired draft.
  const admission = await client.query<{ id: string }>(
    `select draft.id
       from wizard_drafts as draft
       join boards as board
         on board.id=draft.board_id and board.organization_id=draft.organization_id
        and board.state='active'
       cross join boardagent_resolve_access_token($1::uuid) as token
      where draft.id=$2 and draft.organization_id=$3 and draft.creator_member_id=$4
        and token.organization_id=$3 and token.member_id=$4
        and token.internal_client_id=$5 and token.resource_uri=$6
        and draft.board_id::text=any(token.board_ids)`,
    [
      context.tokenJti,
      draftId,
      organizationId,
      context.memberId,
      context.clientId,
      `${input.exactOrigin}/mcp`
    ]
  );
  if (admission.rows.length !== 1) {
    throw new WizardDraftTransactionError("draft_unavailable", "wizard draft is unavailable");
  }
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.draft-cancel-request.v1",
    draftId,
    reason
  });
  const replay = await acquireIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    key,
    requestSha256
  });
  if (replay) return replay;

  const locked = await client.query<LockedDraftRow>(
    `select organization_id,board_id,draft_state,draft_row_version::text
       from boardagent_lock_owned_wizard_draft_for_cancel($1)`,
    [draftId]
  );
  const draft = locked.rows[0];
  if (!draft || locked.rows.length !== 1 || draft.organization_id !== organizationId) {
    throw new WizardDraftTransactionError("draft_unavailable", "wizard draft is unavailable");
  }
  const rowVersion = BigInt(draft.draft_row_version) + 1n;
  const updated = await client.query(
    `update wizard_drafts
        set state='cancelled',row_version=row_version+1
      where id=$1 and state=$2 and row_version=$3::bigint`,
    [draftId, draft.draft_state, draft.draft_row_version]
  );
  if (updated.rowCount !== 1) {
    throw new WizardDraftTransactionError(
      "draft_unavailable",
      "wizard draft changed before cancellation"
    );
  }
  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: rowVersion,
      event: {
        eventId: auditEventId,
        eventType: "draft_cancelled",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "wizard_draft",
        entityId: draftId,
        boardId: draft.board_id,
        origin: "mcp",
        details: { reasonSha256: canonicalSha256(reason), requestSha256 },
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("draft cancellation audit append returned no event");
  const safeResponseSha256 = responseSha256(draftId);
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='wizard_draft',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4 and operation='cancel_draft'
        and idempotency_key=$5 and state='in_progress'`,
    [draftId, Buffer.from(safeResponseSha256, "hex"), context.memberId, context.clientId, key]
  );
  if (completed.rowCount !== 1) throw new Error("draft cancellation idempotency completion failed");
  return {
    replayed: false,
    draftId,
    boardId: draft.board_id,
    state: "cancelled",
    rowVersion,
    responseSha256: safeResponseSha256,
    auditEvent
  };
}
