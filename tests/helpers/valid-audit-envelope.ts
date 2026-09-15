import { createHash } from "node:crypto";
import type { Pool } from "pg";
import { loadBoardAgentWorkerKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  signCheckpoint,
  type AuditEventBody,
  type AuditCheckpointPayload
} from "../../lib/audit/src/index.js";
import type { BoardAgentConfig } from "../../lib/config/src/index.js";
import { testId } from "./authorized-actor.js";

/** Disposable bulk fixture with real hashes/signatures, not production append throughput.
 * Replica mode is limited to fixture construction; the measured verifier gets real roles,
 * normal constraints and no exemptions. No human credentials or external evidence are made.
 */
export async function seedValidAuditEnvelope(
  pool: Pool,
  config: BoardAgentConfig,
  totalEvents: number
) {
  if (!Number.isInteger(totalEvents) || totalEvents < 1000 || totalEvents % 1000 !== 0)
    throw new Error("fixture envelope must contain whole thousand-event blocks");
  const keys = await loadBoardAgentWorkerKeyMaterial(config);
  const root = (await pool.query("select instance_id,organization_id from public.system_instance"))
    .rows[0]!;
  const key = (
    await pool.query(
      "select id,kid from public.crypto_key_registry where purpose='evidence_signing' and retired_at is null"
    )
  ).rows[0]!;
  const head = (
    await pool.query("select last_sequence::text,last_event_sha256 from public.audit_chain_head")
  ).rows[0]!;
  let sequence = Number(head.last_sequence);
  let previousHash = (head.last_event_sha256 as Buffer).toString("hex");
  let firstSequence = 1;
  let firstHash = (
    (await pool.query("select event_sha256 from public.audit_events where sequence=1")).rows[0]!
      .event_sha256 as Buffer
  ).toString("hex");
  let checkpoints = 0;
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("set local session_replication_role=replica");
    while (sequence < totalEvents) {
      const time = (
        await client.query(
          "select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as now"
        )
      ).rows[0]!.now as string;
      const batch: Record<string, unknown>[] = [];
      const append = (body: AuditEventBody) => {
        sequence++;
        // Use the specified canonical hash material directly; the verifier must check it.
        const hash = createHash("sha256")
          .update(
            canonicalJson({
              domain: "boardagent.audit.event.v1",
              sequence: String(sequence),
              previousHash,
              ...body
            })
          )
          .digest("hex");
        batch.push({
          id: body.eventId,
          sequence,
          object_id: body.entityId,
          event_type: body.eventType,
          payload: canonicalJson(body),
          previous_hash: previousHash,
          event_hash: hash,
          occurred_at: body.occurredAt
        });
        previousHash = hash;
      };
      const end = Math.min(totalEvents - 1, (Math.floor(sequence / 1000) + 1) * 1000 - 1);
      while (sequence < end)
        append({
          eventId: testId(9_000_000 + sequence + 1),
          eventType: "context_read",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "context",
          entityId: testId(11_000_000 + sequence + 1),
          boardId: null,
          origin: "worker",
          occurredAt: time,
          details: { synthetic: true, purpose: "valid-audit-envelope" },
          schemaVersion: 1
        });
      const checkpointId = testId(20_000_000 + checkpoints);
      const payload: AuditCheckpointPayload = {
        schema: "boardagent.audit.checkpoint.v1",
        checkpointId,
        instanceId: root.instance_id as string,
        organizationId: root.organization_id as string,
        auditSchema: "boardagent.audit-event.v1",
        firstSequence: String(firstSequence),
        lastSequence: String(sequence),
        firstEventSha256: firstHash,
        lastEventSha256: previousHash,
        issuedAt: time,
        signingKeyId: key.id as string,
        keyId: key.kid as string
      };
      const signed = signCheckpoint(payload, keys.evidencePrivateKey);
      const manifestHash = canonicalSha256(payload);
      await client.query(
        `insert into public.audit_checkpoints(id,organization_id,first_sequence,last_sequence,first_event_sha256,last_event_sha256,canonical_manifest,manifest_sha256,signature,signing_key_id,created_at)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          checkpointId,
          root.organization_id,
          payload.firstSequence,
          payload.lastSequence,
          Buffer.from(firstHash, "hex"),
          Buffer.from(previousHash, "hex"),
          Buffer.from(canonicalJson(payload)),
          Buffer.from(manifestHash, "hex"),
          Buffer.from(signed.signatureBase64Url, "base64url"),
          key.id,
          time
        ]
      );
      append({
        eventId: testId(9_000_000 + sequence + 1),
        eventType: "audit_checkpoint_signed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "audit_checkpoint",
        entityId: checkpointId,
        boardId: null,
        origin: "worker",
        occurredAt: time,
        details: {
          manifestSha256: manifestHash,
          firstSequence: payload.firstSequence,
          lastSequence: payload.lastSequence,
          signedHeadSha256: payload.lastEventSha256
        },
        schemaVersion: 1
      });
      await client.query(
        `insert into public.audit_events(id,sequence,organization_id,event_type,schema_version,object_type,object_id,canonical_payload,previous_event_sha256,event_sha256,occurred_at)
        select row.id,row.sequence,$2,row.event_type,'boardagent.audit-event.v1',
          case when row.event_type='audit_checkpoint_signed' then 'audit_checkpoint' else 'context' end,
          row.object_id,convert_to(row.payload,'UTF8'),decode(row.previous_hash,'hex'),decode(row.event_hash,'hex'),row.occurred_at
        from jsonb_to_recordset($1::jsonb) as row(id uuid,sequence bigint,object_id uuid,event_type text,payload text,previous_hash text,event_hash text,occurred_at timestamptz)`,
        [JSON.stringify(batch), root.organization_id]
      );
      firstSequence = sequence;
      firstHash = previousHash;
      checkpoints++;
    }
    await client.query(
      "update public.audit_chain_head set last_sequence=$1,last_event_sha256=$2 where singleton_key",
      [sequence, Buffer.from(previousHash, "hex")]
    );
    await client.query("commit");
    return { events: sequence, checkpoints, headHash: previousHash };
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}
