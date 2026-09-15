import type { PoolClient } from "pg";
import { z } from "zod";
import {
  canonicalJson,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";
import { KeyLifecycleChangedSchema } from "@boardagent/audit";
import { KeyLifecycleRequestSchema } from "./key-lifecycle-request.js";
import { appendAuditEventsInTransaction } from "./audit.js";

const Input = z
  .object({ request: KeyLifecycleRequestSchema, requestSha256: Sha256HexSchema })
  .strict();
const Receipt = z
  .object({
    operationId: UuidV7Schema,
    requestSha256: Sha256HexSchema,
    auditEventId: UuidV7Schema,
    auditSequence: z.string().regex(/^[1-9][0-9]{0,18}$/u),
    auditSha256: Sha256HexSchema,
    completedAt: z.iso.datetime({ precision: 6 }),
    details: KeyLifecycleChangedSchema,
    replayed: z.boolean()
  })
  .strict();

/** Implemented by the operator's authenticated encryption adapter; never sent to SQL. */
export interface KeyLifecycleRewrapPort {
  rewrapStoredMaterial(input: {
    organizationId: string;
    memberId: string;
    webhookId: string;
    keyId: string;
    endpointCiphertext: Uint8Array;
    secretCiphertext: Uint8Array;
    endpointSha256: string;
    secretSha256: string;
  }): {
    keyId: string;
    endpointCiphertext: Uint8Array;
    secretCiphertext: Uint8Array;
  };
}

/** Database effects only. File installation, custody and service restart are separate facts. */
export async function applyKeyLifecycleInTransaction(
  client: PoolClient,
  rawInput: z.input<typeof Input>,
  rewrap?: KeyLifecycleRewrapPort
) {
  const { request, requestSha256 } = Input.parse(rawInput);
  if (canonicalSha256(request) !== requestSha256)
    throw new Error("key lifecycle request digest mismatch");
  const { observedAt: _observedAt, ...dependencies } = request.expectedInventory.keyDependencies;
  const inventory = { ...request.expectedInventory, keyDependencies: dependencies };
  const begun = await client.query<{ operation_id: string; replayed: boolean; details: unknown }>(
    "select operation_id,replayed,details from boardagent_begin_key_lifecycle($1,$2,$3)",
    [
      Buffer.from(canonicalJson(request)),
      Buffer.from(requestSha256, "hex"),
      Buffer.from(canonicalJson(inventory))
    ]
  );
  const result = begun.rows[0];
  if (
    begun.rows.length !== 1 ||
    !result ||
    result.operation_id !== request.operationId ||
    typeof result.replayed !== "boolean"
  )
    throw new Error("invalid key lifecycle operation result");
  const details = KeyLifecycleChangedSchema.parse(result.details);
  if (
    details.operationId !== request.operationId ||
    details.requestSha256 !== requestSha256 ||
    details.instanceId !== request.instanceId ||
    details.organizationId !== request.organizationId ||
    details.dependencyStateSha256 !== canonicalSha256(inventory)
  )
    throw new Error("key lifecycle result does not match request");
  if (!result.replayed) {
    const expectedRewraps = BigInt(details.effects.rewrappedWebhooks);
    if (expectedRewraps > 0n) {
      if (!rewrap || !request.replacement) throw new Error("webhook rewrapping is required");
      let applied = 0n;
      while (applied < expectedRewraps) {
        const batch = await client.query<{
          webhook_id: string;
          organization_id: string;
          member_id: string;
          key_id: string;
          endpoint_ciphertext: Buffer;
          secret_ciphertext: Buffer;
          endpoint_sha256: Buffer;
          secret_sha256: Buffer;
        }>("select * from boardagent_read_key_webhook_rewrap_batch($1)", [request.operationId]);
        if (batch.rows.length === 0 || applied + BigInt(batch.rows.length) > expectedRewraps)
          throw new Error("webhook rewrapping inventory changed");
        for (const row of batch.rows) {
          if (row.organization_id !== request.organizationId || row.key_id !== request.keyId)
            throw new Error("webhook rewrapping target mismatch");
          const changed = rewrap.rewrapStoredMaterial({
            organizationId: row.organization_id,
            memberId: row.member_id,
            webhookId: row.webhook_id,
            keyId: row.key_id,
            endpointCiphertext: row.endpoint_ciphertext,
            secretCiphertext: row.secret_ciphertext,
            endpointSha256: row.endpoint_sha256.toString("hex"),
            secretSha256: row.secret_sha256.toString("hex")
          });
          if (changed.keyId !== request.replacement.keyId)
            throw new Error("webhook rewrapping replacement mismatch");
          await client.query("select boardagent_apply_key_webhook_rewrap($1,$2,$3,$4)", [
            request.operationId,
            row.webhook_id,
            Buffer.from(changed.endpointCiphertext),
            Buffer.from(changed.secretCiphertext)
          ]);
          applied++;
        }
      }
    }
    // Operation IDs are fresh UUIDv7 identities and may also identify their sole audit event.
    const events = await appendAuditEventsInTransaction(client, [
      {
        organizationId: request.organizationId,
        event: {
          eventId: request.operationId,
          eventType: "key_lifecycle_changed",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          boardId: null,
          entityType: "key_lifecycle_operation",
          entityId: request.operationId,
          origin: "cli",
          schemaVersion: 1,
          details
        }
      }
    ]);
    const event = events[0];
    if (!event || events.length !== 1) throw new Error("key lifecycle audit receipt unavailable");
    await client.query(
      "insert into key_lifecycle_completions(operation_id,audit_event_id) values($1,$2)",
      [request.operationId, event.eventId]
    );
  }
  return {
    ...(await readStoredKeyLifecycleReceipt(client, {
      instanceId: request.instanceId,
      organizationId: request.organizationId,
      operationId: request.operationId
    })),
    replayed: result.replayed
  };
}

const StoredReceipt = Receipt.omit({ replayed: true });
const ReceiptTarget = z
  .object({
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    operationId: UuidV7Schema
  })
  .strict();
export type KeyLifecycleReceipt = z.infer<typeof StoredReceipt>;

async function readStoredKeyLifecycleReceipt(
  client: PoolClient,
  target: z.infer<typeof ReceiptTarget>
): Promise<KeyLifecycleReceipt> {
  const stored = await client.query<{ receipt: unknown }>(
    `select jsonb_build_object(
    'operationId',op.id,'requestSha256',encode(op.request_sha256,'hex'),
    'auditEventId',event.id,'auditSequence',event.sequence::text,'auditSha256',encode(event.event_sha256,'hex'),
    'completedAt',to_char(completion.completed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'details',op.details) as receipt
    from key_lifecycle_operations op join key_lifecycle_completions completion on completion.operation_id=op.id
    join audit_events event on event.id=completion.audit_event_id
    where op.id=$1 and op.instance_id=$2 and op.organization_id=$3 and event.organization_id=op.organization_id
      and event.event_type='key_lifecycle_changed' and event.object_type='key_lifecycle_operation' and event.object_id=op.id
      and convert_from(event.canonical_payload,'UTF8')::jsonb->'details'=op.details
      and sha256(op.canonical_request)=op.request_sha256
      and op.details->>'operationId'=op.id::text and op.details->>'requestSha256'=encode(op.request_sha256,'hex')
      and op.details->>'instanceId'=op.instance_id::text and op.details->>'organizationId'=op.organization_id::text`,
    [target.operationId, target.instanceId, target.organizationId]
  );
  if (stored.rows.length !== 1) throw new Error("key lifecycle completion unavailable");
  return StoredReceipt.parse(stored.rows[0]?.receipt);
}

/** Recover a committed outcome without private keys, current-row revalidation or new authority. */
export async function readKeyLifecycleReceiptInTransaction(
  client: PoolClient,
  rawTarget: z.input<typeof ReceiptTarget>
): Promise<KeyLifecycleReceipt> {
  const target = ReceiptTarget.parse(rawTarget);
  const mode = await client.query<{ allowed: boolean }>(`select
    current_user='boardagent_migrator'
    and current_setting('boardagent.transaction_scope',true)='bootstrap'
    and current_setting('transaction_isolation')='serializable'
    and current_setting('transaction_read_only')='on' as allowed`);
  if (mode.rows[0]?.allowed !== true)
    throw new Error(
      "key receipt inspection requires a serializable read-only operator transaction"
    );
  return readStoredKeyLifecycleReceipt(client, target);
}
