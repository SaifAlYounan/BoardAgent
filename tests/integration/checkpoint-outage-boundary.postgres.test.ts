import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { AuditEventBodySchema, eventHash, signCheckpoint } from "../../lib/audit/src/index.js";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import {
  commitAuditCheckpointInTransaction,
  prepareAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("checkpoint outage evidence boundary", () => {
  it("refuses to persist a late checkpoint and preserves the authentic lagged history", async () => {
    await withMigratedDatabase("checkpoint-outage", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["audit:read"]
      });
      const evidence = generateKeyPairSync("ed25519");
      const keyId = testId(91_000);
      await pool.query(
        "insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at) values($1,$2,'outage-evidence','evidence_signing','EdDSA',$3,'synthetic-outage-fixture',transaction_timestamp()-interval '30 minutes')",
        [keyId, actor.organizationId, evidence.publicKey.export({ format: "jwk" })]
      );
      const time = await pool.query(
        `select to_char((clock_timestamp()-interval '16 minutes') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
      );
      // Insert one explicitly aged, correctly hashed fixture event. No existing record,
      // clock or trigger is changed, and this database is disposable local test data.
      const body = AuditEventBodySchema.parse({
        eventId: testId(91_001),
        eventType: "context_read",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "context",
        entityId: testId(91_002),
        boardId: null,
        origin: "worker",
        occurredAt: time.rows[0]!.occurred_at,
        details: { synthetic: true, purpose: "a signing outage does not move history forward" },
        schemaVersion: 1
      });
      await pool.query(
        `insert into audit_events(id,sequence,organization_id,board_id,event_type,schema_version,actor_member_id,
        client_id,token_jti,object_type,object_id,canonical_payload,previous_event_sha256,event_sha256,occurred_at)
        values($1,1,$2,null,'context_read','boardagent.audit-event.v1',null,null,null,'context',$3,$4,$5,$6,$7)`,
        [
          body.eventId,
          actor.organizationId,
          body.entityId,
          Buffer.from(canonicalJson(body)),
          Buffer.alloc(32),
          Buffer.from(eventHash(1n, "00".repeat(32), body), "hex"),
          body.occurredAt
        ]
      );
      const before = await pool.query(
        "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
      );
      const verified = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
        assumeRole: "boardagent_worker"
      });
      expect(verified).toMatchObject({ valid: true, ready: false, checkpointCount: 0 });
      const prepared = await withWorkerTransaction(
        pool,
        (client) =>
          prepareAuditCheckpointInTransaction(client, {
            checkpointId: testId(91_003),
            signingKeyId: keyId
          }),
        { assumeRole: "boardagent_worker" }
      );
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            commitAuditCheckpointInTransaction(client, {
              checkpoint: signCheckpoint(prepared.payload, evidence.privateKey),
              auditEventId: testId(91_004)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]?.count
      ).toBe(0);
      expect(
        (
          await pool.query(
            "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
          )
        ).rows
      ).toEqual(before.rows);
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({ valid: true, ready: false, checkpointCount: 0 });
    });
  }, 20_000);
});
