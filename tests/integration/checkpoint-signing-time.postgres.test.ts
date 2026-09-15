import type { PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { loadBoardAgentWorkerKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { signCheckpoint } from "../../lib/audit/src/index.js";
import {
  commitAuditCheckpointInTransaction,
  prepareAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

describe("checkpoint signing time after head serialization", () => {
  it("uses the real evidence relations despite temporary names on the worker connection", async () => {
    await withUnseededWorker("checkpoint-temp-names", async ({ pool, config }) => {
      const keys = await loadBoardAgentWorkerKeyMaterial(config);
      const keyId = (
        await pool.query(
          "select id from crypto_key_registry where purpose='evidence_signing' and retired_at is null"
        )
      ).rows[0]!.id as string;
      await withWorkerTransaction(
        pool,
        async (client) => {
          // Fresh connection-local lookalikes contain no evidence. They must neither
          // replace the persistent head/key nor change the privileged row types.
          await client.query(
            "create temporary table audit_chain_head (like public.audit_chain_head) on commit drop"
          );
          await client.query(
            "create temporary table crypto_key_registry (like public.crypto_key_registry) on commit drop"
          );
          await client.query(
            "create temporary table audit_checkpoints (like public.audit_checkpoints) on commit drop"
          );
          await client.query(
            "create temporary table audit_events (like public.audit_events) on commit drop"
          );
          const prepared = await prepareAuditCheckpointInTransaction(client, {
            checkpointId: newWorkerTestId(),
            signingKeyId: keyId
          });
          await commitAuditCheckpointInTransaction(client, {
            checkpoint: signCheckpoint(prepared.payload, keys.evidencePrivateKey),
            auditEventId: newWorkerTestId()
          });
          expect(
            (await client.query("select count(*)::int as count from pg_temp.audit_events")).rows[0]
              ?.count
          ).toBe(0);
        },
        { assumeRole: "boardagent_worker" }
      );
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({ valid: true, ready: true, checkpointCount: 1 });
    });
  }, 20_000);

  it("allows an older transaction to sign the event committed by a newer signer", async () => {
    await withUnseededWorker("checkpoint-time-race", async ({ pool, config }) => {
      const keys = await loadBoardAgentWorkerKeyMaterial(config);
      const keyId = (
        await pool.query(
          "select id from crypto_key_registry where purpose='evidence_signing' and retired_at is null"
        )
      ).rows[0]!.id as string;
      const sign = async (client: PoolClient) => {
        await client.query("select last_sequence from boardagent_lock_audit_head()");
        const prepared = await prepareAuditCheckpointInTransaction(client, {
          checkpointId: newWorkerTestId(),
          signingKeyId: keyId
        });
        await commitAuditCheckpointInTransaction(client, {
          checkpoint: signCheckpoint(prepared.payload, keys.evidencePrivateKey),
          auditEventId: newWorkerTestId()
        });
        return prepared.payload;
      };
      const entered = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      const older = withWorkerTransaction(
        pool,
        async (client) => {
          // Fix the transaction timestamp before the later transaction begins. The barrier
          // controls ordering only; it never changes a clock, stored event or signature.
          await client.query("select transaction_timestamp()");
          entered.resolve();
          await release.promise;
          return sign(client);
        },
        { assumeRole: "boardagent_worker" }
      );
      // Attach a rejection handler before releasing the barrier.
      const olderResult = older.then(
        (value) => ({ value }),
        (error: unknown) => ({ error })
      );
      await entered.promise;
      let newer;
      try {
        newer = await withWorkerTransaction(pool, sign, { assumeRole: "boardagent_worker" });
      } finally {
        release.resolve();
      }
      const result = await olderResult;
      if ("error" in result) throw result.error;
      expect(BigInt(result.value.firstSequence)).toBe(BigInt(newer.lastSequence) + 1n);
      expect(result.value.firstSequence).toBe(result.value.lastSequence);
      expect(Date.parse(result.value.issuedAt)).toBeGreaterThanOrEqual(Date.parse(newer.issuedAt));
      expect(
        await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({ valid: true, ready: true, checkpointCount: 2 });
    });
  }, 20_000);
});
