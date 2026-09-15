import type { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { BoardAgentCoreWorkerHandlers } from "../../artifacts/server/src/core-worker-handlers.js";
import { loadBoardAgentWorkerKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { loadBoardAgentWorkerRuntimeBinding } from "../../artifacts/server/src/runtime-binding.js";
import { signCheckpoint } from "../../lib/audit/src/index.js";
import {
  appendAuditEventsInTransaction,
  claimTypedJobInTransaction,
  commitAuditCheckpointInTransaction,
  prepareAuditCheckpointInTransaction,
  scheduleAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction,
  type AuditAppendInput
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

function event(organizationId: string): AuditAppendInput {
  return {
    organizationId,
    event: {
      eventId: newWorkerTestId(),
      eventType: "context_read",
      actorMemberId: null,
      actorClientId: null,
      tokenJti: null,
      entityType: "context",
      entityId: newWorkerTestId(),
      boardId: null,
      origin: "worker",
      details: { synthetic: true, purpose: "segmented-checkpoint-test" },
      schemaVersion: 1
    }
  };
}

// An isolated owner fixture creates a recent legacy backlog. The production guard is
// restored before commit. This does not exercise or authorize larger normal appends.
async function seedRecentBacklog(pool: Pool, organizationId: string): Promise<string> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("alter table audit_events disable trigger boardagent_audit_capacity_guard");
    await client.query("set local boardagent.transaction_scope='worker'");
    await appendAuditEventsInTransaction(
      client,
      Array.from({ length: 2505 }, () => event(organizationId))
    );
    await client.query("alter table audit_events enable trigger boardagent_audit_capacity_guard");
    const head = await client.query<{ last_sequence: string }>(
      "select last_sequence::text from audit_chain_head"
    );
    await client.query("commit");
    return head.rows[0]!.last_sequence;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

describe("bounded checkpoint segments", () => {
  it("prepares only the first 1000-event prefix of a recent larger backlog", async () => {
    await withUnseededWorker("checkpoint-prefix", async ({ pool, organizationId }) => {
      await seedRecentBacklog(pool, organizationId);
      const key = await pool.query<{ id: string }>(
        "select id from crypto_key_registry where purpose='evidence_signing'"
      );
      const prepared = await withWorkerTransaction(
        pool,
        (client) =>
          prepareAuditCheckpointInTransaction(client, {
            checkpointId: newWorkerTestId(),
            signingKeyId: key.rows[0]!.id
          }),
        { assumeRole: "boardagent_worker" }
      );
      const endpoint = await pool.query<{ hash: string }>(
        "select encode(event_sha256,'hex') as hash from audit_events where sequence=1000"
      );
      expect(prepared.payload).toMatchObject({
        firstSequence: "1",
        lastSequence: "1000",
        lastEventSha256: endpoint.rows[0]!.hash
      });
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]!.count
      ).toBe(0);
    });
  });

  it("drains consecutive real signatures, includes signer events, and keeps ordinary admission closed until caught up", async () => {
    await withUnseededWorker(
      "checkpoint-segments",
      async ({ pool, organizationId, start, assertRunning }) => {
        const oldHead = await seedRecentBacklog(pool, organizationId);
        await expect(
          withWorkerTransaction(
            pool,
            (client) => appendAuditEventsInTransaction(client, [event(organizationId)]),
            { assumeRole: "boardagent_worker" }
          )
        ).rejects.toMatchObject({
          code: "55000",
          constraint: "boardagent_audit_checkpoint_capacity"
        });
        await Promise.all([start(), start()]);
        await expect
          .poll(
            async () => {
              assertRunning();
              return (await pool.query("select count(*)::int as count from audit_checkpoints"))
                .rows[0]?.count;
            },
            { timeout: 8000, interval: 50 }
          )
          .toBeGreaterThanOrEqual(3);
        const ranges = await pool.query<{ first_sequence: string; last_sequence: string }>(
          "select first_sequence::text,last_sequence::text from audit_checkpoints order by first_sequence"
        );
        expect(ranges.rows.slice(0, 2)).toEqual([
          { first_sequence: "1", last_sequence: "1000" },
          { first_sequence: "1001", last_sequence: "2000" }
        ]);
        for (const row of ranges.rows) {
          expect(BigInt(row.last_sequence) - BigInt(row.first_sequence) + 1n).toBeLessThanOrEqual(
            1000n
          );
        }
        expect(BigInt(ranges.rows[2]!.last_sequence)).toBeGreaterThanOrEqual(BigInt(oldHead) + 2n);
        expect(
          await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({ valid: true, ready: true });
        expect(
          (
            await pool.query(
              "select count(*)::int as count from jobs where job_type='audit_checkpoint' and state='dead'"
            )
          ).rows[0]?.count
        ).toBe(0);
        await expect(
          withWorkerTransaction(
            pool,
            (client) => appendAuditEventsInTransaction(client, [event(organizationId)]),
            { assumeRole: "boardagent_worker" }
          )
        ).resolves.toHaveLength(1);
      }
    );
  }, 20000);

  it("refuses fabricated and replayed signer exceptions and rolls back a partial signing attempt", async () => {
    await withUnseededWorker("checkpoint-exception", async ({ pool, organizationId, config }) => {
      const oldHead = await seedRecentBacklog(pool, organizationId);
      const keys = await loadBoardAgentWorkerKeyMaterial(config);
      const binding = await loadBoardAgentWorkerRuntimeBinding(pool, config, keys, {
        assumeRole: "boardagent_worker"
      });
      const sign = async (client: import("pg").PoolClient) => {
        const prepared = await prepareAuditCheckpointInTransaction(client, {
          checkpointId: newWorkerTestId(),
          signingKeyId: binding.keyIds.evidence_signing
        });
        const result = await commitAuditCheckpointInTransaction(client, {
          checkpoint: signCheckpoint(prepared.payload, keys.evidencePrivateKey),
          auditEventId: newWorkerTestId()
        });
        return { prepared, result };
      };
      const refusal = { code: "55000", constraint: "boardagent_audit_checkpoint_capacity" };
      const ordinary = event(organizationId);
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            appendAuditEventsInTransaction(client, [
              {
                ...ordinary,
                event: {
                  ...ordinary.event,
                  eventType: "audit_checkpoint_signed",
                  entityType: "audit_checkpoint"
                }
              }
            ]),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject(refusal);
      await expect(
        withWorkerTransaction(
          pool,
          async (client) => {
            await sign(client);
            await appendAuditEventsInTransaction(client, [event(organizationId)]);
          },
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject(refusal);
      expect(
        (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe(oldHead);
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]!.count
      ).toBe(0);
      const { prepared, result } = await withWorkerTransaction(pool, sign, {
        assumeRole: "boardagent_worker"
      });
      const replayBase = event(organizationId);
      const replay: AuditAppendInput = {
        ...replayBase,
        event: {
          ...replayBase.event,
          eventType: "audit_checkpoint_signed",
          entityType: "audit_checkpoint",
          entityId: result.checkpointId,
          details: {
            manifestSha256: result.manifestSha256,
            firstSequence: prepared.payload.firstSequence,
            lastSequence: prepared.payload.lastSequence,
            signedHeadSha256: prepared.payload.lastEventSha256,
            signingKeyId: prepared.payload.signingKeyId
          }
        }
      };
      await expect(
        withWorkerTransaction(
          pool,
          async (client) => {
            await client.query("select set_config('boardagent.checkpoint_exception','true',true)");
            await appendAuditEventsInTransaction(client, [replay]);
          },
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject(refusal);
      expect(
        (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe((BigInt(oldHead) + 1n).toString());
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]!.count
      ).toBe(1);
    });
  });

  it("rolls back the whole catch-up if the worker loses its lease between segments", async () => {
    await withUnseededWorker("checkpoint-lease", async ({ pool, organizationId, config }) => {
      const oldHead = await seedRecentBacklog(pool, organizationId);
      const keys = await loadBoardAgentWorkerKeyMaterial(config);
      const binding = await loadBoardAgentWorkerRuntimeBinding(pool, config, keys, {
        assumeRole: "boardagent_worker"
      });
      await withWorkerTransaction(
        pool,
        (client) => scheduleAuditCheckpointInTransaction(client, newWorkerTestId()),
        {
          assumeRole: "boardagent_worker"
        }
      );
      const claim = await withWorkerTransaction(
        pool,
        (client) =>
          claimTypedJobInTransaction(client, {
            leaseOwner: "checkpoint-segment-lease-test",
            leaseSeconds: 30
          }),
        { assumeRole: "boardagent_worker" }
      );
      if (!claim.claimed) throw new Error("real checkpoint claim required");
      const abort = new AbortController();
      let idCount = 0;
      const handlers = new BoardAgentCoreWorkerHandlers(pool, {
        config,
        binding,
        keys,
        assumeRole: "boardagent_worker",
        newId: () => {
          idCount += 1;
          // Deliver the same signal used by the worker heartbeat while preparing the
          // second segment. No authority row or timestamp is forged in this test.
          if (idCount === 3) abort.abort("lease_lost");
          return newWorkerTestId();
        }
      }).handlers();
      await expect(
        handlers.get("audit_checkpoint")!({ job: claim.job, signal: abort.signal })
      ).rejects.toMatchObject({ errorClass: "worker_lease_lost" });
      expect(idCount).toBeGreaterThanOrEqual(3);
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]!.count
      ).toBe(0);
      expect(
        (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe(oldHead);
    });
  });
});
