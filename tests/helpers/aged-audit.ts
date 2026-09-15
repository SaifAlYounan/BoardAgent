import { generateKeyPairSync } from "node:crypto";
import type { Pool } from "pg";
import { AuditEventBodySchema, eventHash } from "../../lib/audit/src/index.js";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import { seedAuthorizedActor, testId } from "./authorized-actor.js";

/** Correctly hashed, explicitly old synthetic first event. No retained event is edited. */
export async function seedAgedAudit(
  pool: Pool,
  options: { invalidInitialHash?: boolean; ageSeconds?: number; eventCount?: number } = {}
) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["audit:read"]
  });
  const evidence = generateKeyPairSync("ed25519");
  const keyId = testId(92_000);
  await pool.query(
    `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at)
    values($1,$2,'recovery-evidence','evidence_signing','EdDSA',$3,'synthetic-recovery-fixture',transaction_timestamp()-interval '30 minutes')`,
    [keyId, actor.organizationId, evidence.publicKey.export({ format: "jwk" })]
  );
  const time = await pool.query(
    `select to_char((clock_timestamp()-make_interval(secs=>$1)) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`,
    [options.ageSeconds ?? 960]
  );
  const body = AuditEventBodySchema.parse({
    eventId: testId(92_001),
    eventType: "context_read",
    actorMemberId: null,
    actorClientId: null,
    tokenJti: null,
    entityType: "context",
    entityId: testId(92_002),
    boardId: null,
    origin: "worker",
    occurredAt: time.rows[0]!.occurred_at,
    details: { synthetic: true, purpose: "operator recovery keeps authentic old evidence" },
    schemaVersion: 1
  });
  const hash = options.invalidInitialHash ? "aa".repeat(32) : eventHash(1n, "00".repeat(32), body);
  const eventCount = options.eventCount ?? 1;
  if (!Number.isInteger(eventCount) || eventCount < 1 || eventCount > 10000)
    throw new Error("invalid synthetic audit count");
  const client = await pool.connect();
  let previous = Buffer.alloc(32);
  let headHash = hash;
  try {
    await client.query("begin");
    for (let index = 0; index < eventCount; index++) {
      const event = { ...body, eventId: testId(92_001 + index) };
      headHash = index === 0 ? hash : eventHash(BigInt(index + 1), previous.toString("hex"), event);
      await client.query(
        `insert into audit_events(id,sequence,organization_id,board_id,event_type,schema_version,actor_member_id,
          client_id,token_jti,object_type,object_id,canonical_payload,previous_event_sha256,event_sha256,occurred_at)
          values($1,$2,$3,null,'context_read','boardagent.audit-event.v1',null,null,null,'context',$4,$5,$6,$7,$8)`,
        [
          event.eventId,
          index + 1,
          actor.organizationId,
          event.entityId,
          Buffer.from(canonicalJson(event)),
          previous,
          Buffer.from(headHash, "hex"),
          event.occurredAt
        ]
      );
      previous = Buffer.from(headHash, "hex");
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
  return { actor, evidence, keyId, body, hash, headHash, eventCount };
}
