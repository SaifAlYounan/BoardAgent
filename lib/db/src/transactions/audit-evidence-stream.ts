import { randomUUID } from "node:crypto";
import { Query, type PoolClient } from "pg";

export interface AuditEvidenceSnapshot {
  instance?: { instance_id: string; organization_id: string };
  head?: { last_sequence: string; last_event_sha256: Buffer };
  now?: string;
  keys: StoredKeyRow[];
  checkpoints: StoredCheckpointRow[];
}

interface EvidenceStreamRow {
  stream_kind: number;
  metadata: Record<string, unknown>;
  id: string | null;
  sequence: string | null;
  organization_id: string | null;
  board_id: string | null;
  event_type: string | null;
  schema_version: string | null;
  actor_member_id: string | null;
  client_id: string | null;
  token_jti: string | null;
  object_type: string | null;
  object_id: string | null;
  occurred_at: string | null;

  canonical_payload: Buffer | null;
  first_hash: Buffer | null;
  last_hash: Buffer | null;
  signature: Buffer | null;
  manifest_hash: Buffer | null;
}

// One cursor supplies one MVCC snapshot, including under ordinary read-committed
// requests. Binary payloads and event columns are streamed directly; no redundant
// JSON encoding/decoding of every event column or JSON/hex copy of event bodies.
const EVIDENCE_STREAM_SQL = `
select stream_kind,metadata,canonical_payload,first_hash,last_hash,signature,manifest_hash,
  id,sequence,organization_id,board_id,event_type,schema_version,actor_member_id,client_id,token_jti,object_type,object_id,occurred_at
from (
  select 0 as stream_kind,0::bigint as stream_sequence,
    jsonb_build_object('instance_id',instance.instance_id,'organization_id',instance.organization_id,
      'last_sequence',head.last_sequence::text,
      'now',to_char(statement_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) as metadata,
    null::bytea as canonical_payload,null::bytea as first_hash,
    head.last_event_sha256 as last_hash,null::bytea as signature,null::bytea as manifest_hash,
    null::uuid as id,null::text as sequence,null::uuid as organization_id,null::uuid as board_id,null::text as event_type,null::text as schema_version,null::uuid as actor_member_id,null::uuid as client_id,null::uuid as token_jti,null::text as object_type,null::uuid as object_id,null::text as occurred_at
    from public.system_instance as instance cross join public.audit_chain_head as head
    where instance.singleton_key and head.singleton_key
  union all
  select 1,0::bigint,jsonb_build_object('id',key.id,'organization_id',key.organization_id,
    'kid',key.kid,'purpose',key.purpose,'algorithm',key.algorithm,'public_jwk',key.public_jwk,
    'activated_at',to_char(key.activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'retired_at',to_char(key.retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'compromised_at',to_char(key.compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
    null::bytea,null::bytea,null::bytea,null::bytea,null::bytea,
    null::uuid,null::text,null::uuid,null::uuid,null::text,null::text,null::uuid,null::uuid,null::uuid,null::text,null::uuid,null::text
    from public.crypto_key_registry as key
  union all
  select 2,checkpoint.first_sequence,jsonb_build_object('id',checkpoint.id,
    'organization_id',checkpoint.organization_id,'first_sequence',checkpoint.first_sequence::text,
    'last_sequence',checkpoint.last_sequence::text,'signing_key_id',checkpoint.signing_key_id,
    'created_at',to_char(checkpoint.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'recovery_id',checkpoint.recovery_id,
    'recovery_authorization',case when recovery.id is null then null else jsonb_build_object(
      'canonical_request',convert_from(recovery.canonical_request,'UTF8'),
      'request_sha256',encode(recovery.request_sha256,'hex'),
      'authorized_at',to_char(recovery.authorized_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'expires_at',to_char(recovery.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'final_checkpoint_id',completion.final_checkpoint_id,
      'final_head_sequence',completion.final_head_sequence::text,
      'final_head_sha256',encode(completion.final_head_sha256,'hex'),
      'completed_at',to_char(completion.completed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) end),
    checkpoint.canonical_manifest,checkpoint.first_event_sha256,checkpoint.last_event_sha256,
    checkpoint.signature,checkpoint.manifest_sha256,
    null::uuid,null::text,null::uuid,null::uuid,null::text,null::text,null::uuid,null::uuid,null::uuid,null::text,null::uuid,null::text
    from public.audit_checkpoints as checkpoint
    left join public.audit_recoveries as recovery on recovery.id=checkpoint.recovery_id
    left join public.audit_recovery_completions as completion on completion.recovery_id=recovery.id
  union all
  select 3,event.sequence,null::jsonb,
    event.canonical_payload,event.previous_event_sha256,event.event_sha256,null::bytea,null::bytea,
    event.id,event.sequence::text,event.organization_id,event.board_id,event.event_type,
    event.schema_version,event.actor_member_id,event.client_id,event.token_jti,event.object_type,
    event.object_id,to_char(event.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    from public.audit_events as event
) as stream order by stream_kind,stream_sequence`;

/** A transaction-local cursor retains the query snapshot across bounded FETCH commands.
 * Row listeners keep pg from accumulating Result.rows. Each FETCH retains the caller's
 * SQL timeout; a large history cannot fill an unbounded driver buffer. Consumer failures
 * drain the cursor before rejection. SQL errors abort the transaction and its wrapper
 * rolls back the WITHOUT HOLD cursor before releasing the connection.
 */
export async function streamAuditEvidence(
  client: PoolClient,
  consume: (event: StoredAuditEventRow, snapshot: AuditEvidenceSnapshot) => void
): Promise<AuditEvidenceSnapshot> {
  // Pinned pg8.23 installs a callback for driver query_timeout, which restores
  // Result.rows accumulation and changes error delivery. Refuse that mode instead
  // of disabling a configured limit. The transaction's SQL statement_timeout stays.
  const driver = client as PoolClient & {
    readonly connectionParameters?: { readonly query_timeout?: unknown };
  };
  if (driver.connectionParameters?.query_timeout)
    throw new Error("audit evidence streaming does not support driver query_timeout");

  // Generated identifier only; no caller-controlled SQL. WITHOUT HOLD also prevents
  // cursor state from surviving a commit or rollback into another pooled request.
  const cursor = `audit_evidence_${randomUUID().replaceAll("-", "")}`;
  await client.query(`DECLARE ${cursor} NO SCROLL CURSOR WITHOUT HOLD FOR ${EVIDENCE_STREAM_SQL}`);
  const snapshot: AuditEvidenceSnapshot = { keys: [], checkpoints: [] };
  let failure: unknown;
  let failed = false;
  const batchSize = 1000;
  let count: number;
  do {
    count = await new Promise<number>((resolve, reject) => {
      let delivered = 0;
      const query = new Query<EvidenceStreamRow>(`FETCH FORWARD ${batchSize} FROM ${cursor}`);
      query.on("row", (row) => {
        delivered++;
        if (failed) return;
        try {
          if (row.stream_kind === 0) {
            snapshot.instance = {
              instance_id: row.metadata["instance_id"] as string,
              organization_id: row.metadata["organization_id"] as string
            };
            snapshot.head = {
              last_sequence: row.metadata["last_sequence"] as string,
              last_event_sha256: row.last_hash!
            };
            snapshot.now = row.metadata["now"] as string;
          } else if (row.stream_kind === 1)
            snapshot.keys.push(row.metadata as unknown as StoredKeyRow);
          else if (row.stream_kind === 2)
            snapshot.checkpoints.push({
              ...row.metadata,
              canonical_manifest: row.canonical_payload!,
              first_event_sha256: row.first_hash!,
              last_event_sha256: row.last_hash!,
              signature: row.signature!,
              manifest_sha256: row.manifest_hash!
            } as unknown as StoredCheckpointRow);
          else if (row.stream_kind === 3)
            consume(
              {
                id: row.id!,
                sequence: row.sequence!,
                organization_id: row.organization_id!,
                board_id: row.board_id!,
                event_type: row.event_type!,
                schema_version: row.schema_version!,
                actor_member_id: row.actor_member_id!,
                client_id: row.client_id!,
                token_jti: row.token_jti!,
                object_type: row.object_type!,
                object_id: row.object_id!,
                occurred_at: row.occurred_at!,
                canonical_payload: row.canonical_payload!,
                previous_event_sha256: row.first_hash!,
                event_sha256: row.last_hash!
              } as unknown as StoredAuditEventRow,
              snapshot
            );
          else throw new Error("unexpected audit evidence stream discriminator");
        } catch (error) {
          failed = true;
          failure = error;
        }
      });
      // Keep the error listener installed: a later connection error must not become
      // an unhandled EventEmitter error or replace the first rejected SQL error.
      query.on("error", reject);
      query.once("end", () => resolve(delivered));
      client.query(query);
    });
  } while (count === batchSize);
  await client.query(`CLOSE ${cursor}`);
  if (failed) throw failure;
  return snapshot;
}

export interface StoredAuditEventRow {
  readonly id: string;
  readonly sequence: string;
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly event_type: string;
  readonly schema_version: string;
  readonly actor_member_id: string | null;
  readonly client_id: string | null;
  readonly token_jti: string | null;
  readonly object_type: string;
  readonly object_id: string | null;
  readonly canonical_payload: Buffer;
  readonly previous_event_sha256: Buffer;
  readonly event_sha256: Buffer;
  readonly occurred_at: string;
}

export interface StoredCheckpointRow {
  readonly id: string;
  readonly organization_id: string;
  readonly first_sequence: string;
  readonly last_sequence: string;
  readonly first_event_sha256: Buffer;
  readonly last_event_sha256: Buffer;
  readonly canonical_manifest: Buffer;
  readonly manifest_sha256: Buffer;
  readonly signature: Buffer;
  readonly signing_key_id: string;
  readonly created_at: string;
  readonly recovery_id: string | null;
  readonly recovery_authorization: {
    readonly canonical_request: string;
    readonly request_sha256: string;
    readonly authorized_at: string;
    readonly expires_at: string;
    readonly final_checkpoint_id: string | null;
    readonly final_head_sequence: string | null;
    readonly final_head_sha256: string | null;
    readonly completed_at: string | null;
  } | null;
}

export interface StoredKeyRow {
  readonly id: string;
  readonly organization_id: string;
  readonly kid: string;
  readonly purpose: string;
  readonly algorithm: string;
  readonly public_jwk: unknown;
  readonly activated_at: string;
  readonly retired_at: string | null;
  readonly compromised_at: string | null;
}
