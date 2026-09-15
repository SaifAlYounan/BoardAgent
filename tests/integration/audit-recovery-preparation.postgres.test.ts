import { describe, expect, it } from "vitest";
import {
  appendAuditEventsInTransaction,
  prepareAuditRecoveryInTransaction,
  withBootstrapTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { seedAgedAudit } from "../helpers/aged-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("operator audit recovery preparation", () => {
  const input = {
    recoveryId: testId(93_000),
    instanceId: testId(15),
    organizationId: testId(1),
    signingKeyId: testId(92_000),
    operatorReference: "synthetic-operator-incident-1",
    reason: "Signing worker stopped; intact retained history must keep its missed deadline."
  };
  const operator = { assumeRole: "boardagent_migrator", readOnly: true } as const;

  it("keeps one consistent proposal snapshot when a concurrent audit append commits", async () => {
    await withMigratedDatabase("recovery-snapshot-race", async (pool) => {
      const fixture = await seedAgedAudit(pool);
      const prepared = await withBootstrapTransaction(
        pool,
        async (client) => {
          expect(
            (await client.query("select last_sequence from public.audit_chain_head")).rows[0]!
              .last_sequence
          ).toBe("1");
          await withWorkerTransaction(
            pool,
            (writer) =>
              appendAuditEventsInTransaction(writer, [
                {
                  organizationId: fixture.actor.organizationId,
                  event: { ...fixture.body, eventId: testId(93_002) }
                }
              ]),
            { assumeRole: "boardagent_worker" }
          );
          return prepareAuditRecoveryInTransaction(client, input);
        },
        operator
      );
      expect(prepared.request.lastSequence).toBe("1");
      expect(prepared.request.headSha256).toBe(fixture.hash);
      expect(
        (await pool.query("select last_sequence from public.audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe("2");
      // Preparation is truthful for its MVCC snapshot. Apply must refuse this now-stale head.
    });
  });

  it("fully verifies the retained chain and binds a proposal to the explicit installation, without signing or writing", async () => {
    await withMigratedDatabase("recovery-proposal", async (pool) => {
      const fixture = await seedAgedAudit(pool);
      const prepared = await withBootstrapTransaction(
        pool,
        (client) => prepareAuditRecoveryInTransaction(client, input),
        operator
      );
      expect(prepared.request).toMatchObject({
        ...input,
        firstSequence: "1",
        lastSequence: "1",
        headSha256: fixture.hash,
        firstEventSha256: fixture.hash,
        firstUncoveredEventAt: fixture.body.occurredAt
      });
      expect(prepared.requestSha256).toBe(canonicalSha256(prepared.request));
      expect(Date.parse(prepared.request.expiresAt) - Date.parse(prepared.request.preparedAt)).toBe(
        1_800_000
      );
      expect(prepared.publicJwk).toEqual(fixture.evidence.publicKey.export({ format: "jwk" }));
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows
      ).toEqual([{ count: 0 }]);
      expect((await pool.query("select count(*)::int as count from audit_events")).rows).toEqual([
        { count: 1 }
      ]);
      for (const field of ["instanceId", "organizationId"] as const) {
        await expect(
          withBootstrapTransaction(
            pool,
            (client) =>
              prepareAuditRecoveryInTransaction(client, { ...input, [field]: testId(93_001) }),
            operator
          )
        ).rejects.toMatchObject({ code: "recovery_target_mismatch" });
      }
    });
  });

  it("refuses a retained event whose stored hash does not match its actual contents", async () => {
    await withMigratedDatabase("recovery-broken-chain", async (pool) => {
      await seedAgedAudit(pool, { invalidInitialHash: true });
      await expect(
        withBootstrapTransaction(
          pool,
          (client) => prepareAuditRecoveryInTransaction(client, input),
          operator
        )
      ).rejects.toMatchObject({ code: "recovery_integrity_invalid" });
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows
      ).toEqual([{ count: 0 }]);
    });
  });

  it("refuses private, unknown, mismatched and malformed public-key fields before proposing recovery", async () => {
    await withMigratedDatabase("recovery-key-shape", async (pool) => {
      const fixture = await seedAgedAudit(pool);
      const publicJwk = fixture.evidence.publicKey.export({ format: "jwk" });
      for (const patch of [
        { d: "never-a-real-secret" },
        { unknown: true },
        { kid: "different-key" },
        { x: "invalid" },
        { crv: "X25519" },
        { key_ops: ["sign"] }
      ]) {
        await pool.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
          { ...publicJwk, ...patch },
          fixture.keyId
        ]);
        await expect(
          withBootstrapTransaction(
            pool,
            (client) => prepareAuditRecoveryInTransaction(client, input),
            operator
          )
        ).rejects.toMatchObject({ code: "recovery_invalid" });
      }
    });
  });

  it("refuses recovery when the oldest uncovered event has not missed its deadline", async () => {
    await withMigratedDatabase("recovery-current", async (pool) => {
      await seedAgedAudit(pool, { ageSeconds: 30 });
      await expect(
        withBootstrapTransaction(
          pool,
          (client) => prepareAuditRecoveryInTransaction(client, input),
          operator
        )
      ).rejects.toMatchObject({ code: "55000" });
    });
  });

  it("refuses write-enabled, inconsistent or unmanaged operator preparation", async () => {
    await withMigratedDatabase("recovery-context", async (pool) => {
      const fixture = await seedAgedAudit(pool);
      for (const context of [
        { transaction: "begin isolation level serializable", scope: "bootstrap" },
        { transaction: "begin isolation level read committed read only", scope: "bootstrap" },
        { transaction: "begin isolation level serializable read only", scope: "worker" }
      ]) {
        const client = await pool.connect();
        try {
          await client.query(context.transaction);
          await client.query("set local role boardagent_migrator");
          await client.query("select set_config('boardagent.transaction_scope',$1,true)", [
            context.scope
          ]);
          await expect(
            client.query("select * from boardagent_audit_recovery_snapshot($1)", [fixture.keyId])
          ).rejects.toMatchObject({ code: "25000" });
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
    });
  });

  it("returns a read-only exact overdue snapshot only to the operator, refusing runtime role flags", async () => {
    await withMigratedDatabase("recovery-prepare", async (pool) => {
      const fixture = await seedAgedAudit(pool);
      const original = (
        await pool.query(
          "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
        )
      ).rows;
      const snapshot = await withBootstrapTransaction(
        pool,
        async (client) => {
          expect(
            (await client.query("show transaction_read_only")).rows[0]!.transaction_read_only
          ).toBe("on");
          return client.query("select * from boardagent_audit_recovery_snapshot($1)", [
            fixture.keyId
          ]);
        },
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      expect(snapshot.rows).toMatchObject([
        {
          organization_id: fixture.actor.organizationId,
          first_sequence: "1",
          last_sequence: "1",
          first_event_sha256: Buffer.from(fixture.hash, "hex"),
          last_event_sha256: Buffer.from(fixture.hash, "hex"),
          first_uncovered_event_at: fixture.body.occurredAt,
          signing_key_id: fixture.keyId,
          key_id: "recovery-evidence",
          public_jwk: fixture.evidence.publicKey.export({ format: "jwk" })
        }
      ]);
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"] as const) {
        const client = await pool.connect();
        try {
          await client.query("begin isolation level serializable read only");
          await client.query(`set local role ${role}`);
          await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(
            client.query("select * from boardagent_audit_recovery_snapshot($1)", [fixture.keyId])
          ).rejects.toMatchObject({ code: "42501" });
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
      expect(
        (
          await pool.query(
            "select id,canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
          )
        ).rows
      ).toEqual(original);
    });
  });

  it.each(["retired", "compromised", "future"] as const)(
    "refuses a %s evidence key without changing history",
    async (state) => {
      await withMigratedDatabase(`recovery-key-${state}`, async (pool) => {
        const fixture = await seedAgedAudit(pool);
        const statement =
          state === "retired"
            ? "update crypto_key_registry set retired_at=clock_timestamp() where id=$1"
            : state === "compromised"
              ? "update crypto_key_registry set compromised_at=clock_timestamp() where id=$1"
              : "update crypto_key_registry set activated_at=clock_timestamp()+interval '1 minute' where id=$1";
        await pool.query(statement, [fixture.keyId]);
        await expect(
          withBootstrapTransaction(
            pool,
            (client) =>
              client.query("select * from boardagent_audit_recovery_snapshot($1)", [fixture.keyId]),
            { assumeRole: "boardagent_migrator", readOnly: true }
          )
        ).rejects.toMatchObject({ code: "55000" });
        expect(
          (await pool.query("select count(*)::int as count from audit_checkpoints")).rows
        ).toEqual([{ count: 0 }]);
      });
    }
  );
});
