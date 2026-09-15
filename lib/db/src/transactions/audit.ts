import type { PoolClient } from "pg";

import {
  AuditEventBodySchema,
  eventHash,
  type AuditEvent,
  type AuditEventBody
} from "@boardagent/audit";
import { canonicalJson, UuidV7Schema } from "@boardagent/contracts";

const MAX_CANONICAL_AUDIT_BYTES = 10 * 1024 * 1024;
const MAX_BIGINT = 9_223_372_036_854_775_807n;

export interface AuditAppendInput {
  readonly organizationId: string;
  readonly event: Omit<AuditEventBody, "occurredAt">;
  readonly actingForMemberId?: string | null;
  readonly consentRecordId?: string | null;
  readonly objectVersion?: bigint | null;
}

interface AuditHeadRow {
  readonly last_sequence: string;
  readonly last_event_sha256: Buffer;
  readonly occurred_at: string;
}

function optionalUuid(value: string | null | undefined): string | null {
  return value === null || value === undefined ? null : UuidV7Schema.parse(value);
}

function objectVersion(value: bigint | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  if (value < 1n || value > MAX_BIGINT) {
    throw new RangeError("audit object version must fit a positive PostgreSQL bigint");
  }
  return value.toString(10);
}

/**
 * Append one or more events after all aggregate/projection locks have been acquired.
 * The caller owns the surrounding transaction; this function takes the global audit
 * head last and relies on transaction rollback for crash-safe retry.
 */
export async function appendAuditEventsInTransaction(
  client: PoolClient,
  inputs: readonly AuditAppendInput[]
): Promise<readonly AuditEvent[]> {
  if (inputs.length === 0) return [];

  const normalized = inputs.map((input) => ({
    organizationId: UuidV7Schema.parse(input.organizationId),
    actingForMemberId: optionalUuid(input.actingForMemberId),
    consentRecordId: optionalUuid(input.consentRecordId),
    objectVersion: objectVersion(input.objectVersion),
    event: input.event
  }));
  const headResult = await client.query<AuditHeadRow>(
    `select last_sequence::text, last_event_sha256, occurred_at
       from boardagent_lock_audit_head()`
  );
  const head = headResult.rows[0];
  if (!head || headResult.rows.length !== 1 || head.last_event_sha256.length !== 32) {
    throw new Error("audit chain head returned an invalid shape");
  }

  let sequence = BigInt(head.last_sequence);
  let previousHash = head.last_event_sha256.toString("hex");
  const appended: AuditEvent[] = [];

  for (const input of normalized) {
    sequence += 1n;
    const body = AuditEventBodySchema.parse({
      ...input.event,
      occurredAt: head.occurred_at
    }) as AuditEventBody;
    const canonicalPayload = Buffer.from(canonicalJson(body), "utf8");
    if (canonicalPayload.length > MAX_CANONICAL_AUDIT_BYTES) {
      throw new RangeError("canonical audit event exceeds the 10 MiB evidence limit");
    }
    const nextHash = eventHash(sequence, previousHash, body);
    const parsedObjectId = UuidV7Schema.safeParse(body.entityId);
    await client.query(
      `insert into public.audit_events(
         id, sequence, organization_id, board_id, event_type, schema_version,
         actor_member_id, acting_for_member_id, client_id, token_jti, consent_record_id,
         object_type, object_id, object_version, canonical_payload,
         previous_event_sha256, event_sha256, occurred_at
       ) values (
         $1,$2,$3,$4,$5,'boardagent.audit-event.v1',
         $6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
       )`,
      [
        body.eventId,
        sequence.toString(10),
        input.organizationId,
        body.boardId,
        body.eventType,
        body.actorMemberId,
        input.actingForMemberId,
        body.actorClientId,
        body.tokenJti,
        input.consentRecordId,
        body.entityType,
        parsedObjectId.success ? parsedObjectId.data : null,
        input.objectVersion,
        canonicalPayload,
        Buffer.from(previousHash, "hex"),
        Buffer.from(nextHash, "hex"),
        body.occurredAt
      ]
    );
    appended.push({ ...body, sequence, previousHash, eventHash: nextHash });
    previousHash = nextHash;
  }

  return appended;
}
