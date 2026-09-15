import { generateKeyPairSync } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { signCheckpoint, verifyCheckpoint } from "../../lib/audit/src/index.js";
import {
  appendAuditEventsInTransaction,
  captureBackupBoundaryInTransaction,
  commitAuditCheckpointInTransaction,
  migrate,
  prepareAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withRequestTransaction,
  withWorkerTransaction,
  withBackupTransaction,
  type AuditAppendInput
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_checkpoints_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "checkpoint-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

describe("persisted Ed25519 audit checkpoints", () => {
  it("orders double-digit event/checkpoint sequences numerically and captures the latest backup checkpoint", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        isSecretary: true,
        scopes: ["secretariat:admin"]
      });
      const signing = generateKeyPairSync("ed25519");
      const signingKeyId = testId(30_500),
        backupKeyId = testId(30_501);
      await pool.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
        generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" }),
        testId(8)
      ]);
      await pool.query(
        "insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at) values($1,$3,'numeric-checkpoints','evidence_signing','EdDSA',$4,'disposable-numeric-checkpoint',transaction_timestamp()-interval '1 minute'),($2,$3,'numeric-backup','backup_kek','A256GCM',null,'sha256:'||repeat('a',64),transaction_timestamp()-interval '1 minute')",
        [
          signingKeyId,
          backupKeyId,
          actor.organizationId,
          signing.publicKey.export({ format: "jwk" })
        ]
      );
      await withRequestTransaction(
        pool,
        actor.context,
        (c) =>
          appendAuditEventsInTransaction(c, [
            {
              organizationId: actor.organizationId,
              event: {
                eventId: testId(30_502),
                eventType: "context_read",
                actorMemberId: actor.memberId,
                actorClientId: actor.clientId,
                tokenJti: actor.tokenJti,
                entityType: "context",
                entityId: testId(30_503),
                boardId: actor.boardId,
                origin: "mcp",
                details: { purpose: "numeric sequence boundary" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      for (let index = 0; index < 12; index++) {
        const prepared = await withWorkerTransaction(
          pool,
          (c) =>
            prepareAuditCheckpointInTransaction(c, {
              checkpointId: testId(30_600 + index),
              signingKeyId
            }),
          { assumeRole: "boardagent_worker" }
        );
        await withWorkerTransaction(
          pool,
          (c) =>
            commitAuditCheckpointInTransaction(c, {
              checkpoint: signCheckpoint(prepared.payload, signing.privateKey),
              auditEventId: testId(30_700 + index)
            }),
          { assumeRole: "boardagent_worker" }
        );
      }
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({ valid: true, ready: true });
      const boundary = await withBackupTransaction(
        pool,
        (c) =>
          captureBackupBoundaryInTransaction(c, {
            receiptId: testId(30_800),
            encryptionKeyId: backupKeyId,
            encryptionKeyFingerprintSha256: "a".repeat(64)
          }),
        { assumeRole: "boardagent_backup" }
      );
      expect(boundary.auditBoundary.latestCheckpoint).toMatchObject({
        checkpointId: testId(30_611),
        lastSequence: "12"
      });
      expect(boundary.auditBoundary.eventCount).toBe("13");
    });
  });
  it("rejects a changed head and attacker signature, commits atomically, replays and verifies", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const evidence = generateKeyPairSync("ed25519");
      const attacker = generateKeyPairSync("ed25519");
      const signingKeyId = testId(30_000);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
         ) values ($1,$2,'checkpoint-evidence-1','evidence_signing','EdDSA',$3,
                   'local-checkpoint-test',transaction_timestamp()-interval '1 minute')`,
        [signingKeyId, actor.organizationId, evidence.publicKey.export({ format: "jwk" })]
      );

      const auditInput = (suffix: number): AuditAppendInput => ({
        organizationId: actor.organizationId,
        event: {
          eventId: testId(suffix),
          eventType: "context_read",
          actorMemberId: actor.memberId,
          actorClientId: actor.clientId,
          tokenJti: actor.tokenJti,
          entityType: "context",
          entityId: testId(suffix + 100),
          boardId: actor.boardId,
          origin: "mcp",
          details: { result: "authorized", requestOrdinal: suffix },
          schemaVersion: 1
        }
      });
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          appendAuditEventsInTransaction(client, [auditInput(30_010), auditInput(30_011)]),
        { assumeRole: "boardagent_server" }
      );

      const stalePrepared = await withWorkerTransaction(
        pool,
        (client) =>
          prepareAuditCheckpointInTransaction(client, {
            checkpointId: testId(30_020),
            signingKeyId
          }),
        { assumeRole: "boardagent_worker" }
      );
      const staleSigned = signCheckpoint(stalePrepared.payload, evidence.privateKey);
      expect(verifyCheckpoint(staleSigned, stalePrepared.publicJwk)).toBe(true);
      await withRequestTransaction(
        pool,
        actor.context,
        (client) => appendAuditEventsInTransaction(client, [auditInput(30_012)]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            commitAuditCheckpointInTransaction(client, {
              checkpoint: staleSigned,
              auditEventId: testId(30_021)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toThrow(/exact next chain segment/u);

      const prepared = await withWorkerTransaction(
        pool,
        (client) =>
          prepareAuditCheckpointInTransaction(client, {
            checkpointId: testId(30_030),
            signingKeyId
          }),
        { assumeRole: "boardagent_worker" }
      );
      const attackerSigned = signCheckpoint(prepared.payload, attacker.privateKey);
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            commitAuditCheckpointInTransaction(client, {
              checkpoint: attackerSigned,
              auditEventId: testId(30_031)
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toThrow(/signature did not verify/u);

      const signed = signCheckpoint(prepared.payload, evidence.privateKey);
      const committed = await withWorkerTransaction(
        pool,
        (client) =>
          commitAuditCheckpointInTransaction(client, {
            checkpoint: signed,
            auditEventId: testId(30_032)
          }),
        { assumeRole: "boardagent_worker" }
      );
      expect(committed).toMatchObject({
        checkpointId: prepared.payload.checkpointId,
        replayed: false,
        auditEventId: testId(30_032),
        auditSequence: "4"
      });
      const replay = await withWorkerTransaction(
        pool,
        (client) =>
          commitAuditCheckpointInTransaction(client, {
            checkpoint: signed,
            auditEventId: testId(30_033)
          }),
        { assumeRole: "boardagent_worker" }
      );
      expect(replay).toMatchObject({ checkpointId: prepared.payload.checkpointId, replayed: true });

      {
        const verified = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        });
        expect(verified).toMatchObject({
          valid: true,
          ready: true,
          eventCount: "4",
          checkpointCount: 1,
          coveredThrough: "3",
          lagEvents: "1",
          warnings: []
        });
      }

      await pool.query(
        `update crypto_key_registry
            set compromised_at=(select created_at+interval '1 microsecond'
                                  from audit_checkpoints where id=$1)
          where id=$2`,
        [prepared.payload.checkpointId, signingKeyId]
      );
      {
        const verified = await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        });
        expect(verified.valid).toBe(true);
        if (verified.valid) {
          expect(verified.warnings).toEqual([
            `checkpoint:${prepared.payload.checkpointId}:signing_key_compromised_after_issuance`
          ]);
        }
      }

      await pool.query("alter table audit_checkpoints disable trigger boardagent_immutable");
      await pool.query(
        "update audit_checkpoints set signature=decode(repeat('00',64),'hex') where id=$1",
        [prepared.payload.checkpointId]
      );
      {
        expect(
          await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({
          valid: false,
          ready: false,
          reason: "checkpoint_signature_invalid",
          checkpointId: prepared.payload.checkpointId
        });
      }
    });
  });
});
