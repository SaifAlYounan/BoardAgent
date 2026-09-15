import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  signCheckpoint,
  signRecoveryCheckpoint,
  type AuditCheckpointPayload,
  type AuditRecoveryCheckpointPayload,
  type SignedAuditCheckpoint,
  type SignedAuditRecoveryCheckpoint
} from "../../lib/audit/src/index.js";
import * as database from "../../lib/db/src/index.js";
import { seedAgedAudit } from "../helpers/aged-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

type RecoveryEffects = {
  sign: (
    payload: AuditCheckpointPayload | AuditRecoveryCheckpointPayload
  ) => Promise<SignedAuditCheckpoint | SignedAuditRecoveryCheckpoint>;
  createId: () => string;
  signal?: AbortSignal;
};
const apply = database.applyAuditRecoveryInTransaction;
const options = { assumeRole: "boardagent_migrator" } as const;
const preparation = {
  recoveryId: testId(95_000),
  instanceId: testId(15),
  organizationId: testId(1),
  signingKeyId: testId(92_000),
  operatorReference: "synthetic-recovery-operator",
  reason: "Signing service stopped; preserve and report the historical delay."
};

describe("atomic operator audit recovery", () => {
  it.each(["new_audit_event", "retired_key", "compromised_key"] as const)(
    "refuses a prepared request after %s",
    async (change) => {
      await withMigratedDatabase(`recovery-stale-${change}`, async (pool) => {
        const fixture = await seedAgedAudit(pool);
        const proposal = await database.withBootstrapTransaction(
          pool,
          (client) => database.prepareAuditRecoveryInTransaction(client, preparation),
          { ...options, readOnly: true }
        );
        if (change === "new_audit_event")
          await database.withWorkerTransaction(
            pool,
            (client) =>
              database.appendAuditEventsInTransaction(client, [
                {
                  organizationId: fixture.actor.organizationId,
                  event: { ...fixture.body, eventId: testId(98_000) }
                }
              ]),
            { assumeRole: "boardagent_worker" }
          );
        else
          await pool.query(
            change === "retired_key"
              ? "update crypto_key_registry set retired_at=clock_timestamp() where id=$1"
              : "update crypto_key_registry set compromised_at=clock_timestamp() where id=$1",
            [fixture.keyId]
          );
        let signed = false;
        await expect(
          database.withBootstrapTransaction(
            pool,
            (client) =>
              apply(
                client,
                {
                  request: proposal.request,
                  requestSha256: proposal.requestSha256,
                  instanceId: preparation.instanceId,
                  organizationId: preparation.organizationId
                },
                {
                  createId: () => testId(98_001),
                  sign: async () => {
                    signed = true;
                    throw new Error("stale request must not reach signer");
                  }
                }
              ),
            options
          )
        ).rejects.toMatchObject({ code: "55000" });
        expect(signed).toBe(false);
        expect(
          (await pool.query("select count(*)::int as count from audit_recoveries")).rows
        ).toEqual([{ count: 0 }]);
      });
    }
  );
  it.each(["signer_failure", "cancellation", "final_audit_failure"] as const)(
    "rolls back already written segments after %s",
    async (failure) => {
      await withMigratedDatabase(`recovery-${failure}`, async (pool) => {
        const fixture = await seedAgedAudit(pool, { eventCount: 1001 });
        const before = (
          await pool.query("select last_sequence,last_event_sha256 from audit_chain_head")
        ).rows;
        if (failure === "final_audit_failure")
          await pool.query(`
        create function public.synthetic_final_recovery_audit_failure() returns trigger language plpgsql as $$
        begin
          if new.sequence=1004 then raise exception 'synthetic final audit failure'; end if;
          return new;
        end; $$;
        create trigger boardagent_zz_synthetic_final_audit before insert on public.audit_events
          for each row execute function public.synthetic_final_recovery_audit_failure();`);
        const proposal = await database.withBootstrapTransaction(
          pool,
          (client) => database.prepareAuditRecoveryInTransaction(client, preparation),
          { ...options, readOnly: true }
        );
        let nextId = 96_000,
          calls = 0;
        const abort = new AbortController();
        await expect(
          database.withBootstrapTransaction(
            pool,
            (client) =>
              apply(
                client,
                {
                  request: proposal.request,
                  requestSha256: proposal.requestSha256,
                  instanceId: preparation.instanceId,
                  organizationId: preparation.organizationId
                },
                {
                  createId: () => testId(nextId++),
                  signal: abort.signal,
                  sign: async (payload) => {
                    calls++;
                    if (calls === 2 && failure !== "final_audit_failure") {
                      expect(
                        (await client.query("select count(*)::int as count from audit_checkpoints"))
                          .rows
                      ).toEqual([{ count: 1 }]);
                      if (failure === "signer_failure")
                        throw new Error("synthetic signing device failure");
                      abort.abort(new Error("synthetic cancellation"));
                    }
                    return payload.schema === "boardagent.audit.recovery-checkpoint.v1"
                      ? signRecoveryCheckpoint(payload, fixture.evidence.privateKey)
                      : signCheckpoint(payload, fixture.evidence.privateKey);
                  }
                }
              ),
            options
          )
        ).rejects.toThrow(
          failure === "signer_failure"
            ? "synthetic signing device failure"
            : failure === "cancellation"
              ? "synthetic cancellation"
              : "synthetic final audit failure"
        );
        expect(calls).toBe(failure === "final_audit_failure" ? 3 : 2);
        for (const table of ["audit_recoveries", "audit_recovery_completions", "audit_checkpoints"])
          expect((await pool.query(`select count(*)::int as count from ${table}`)).rows).toEqual([
            { count: 0 }
          ]);
        expect(
          (await pool.query("select last_sequence,last_event_sha256 from audit_chain_head")).rows
        ).toEqual(before);
        expect((await pool.query("select count(*)::int as count from audit_events")).rows).toEqual([
          { count: 1001 }
        ]);
      });
    }
  );

  it("serializes competing applications into one complete result and one exact replay", async () => {
    await withMigratedDatabase("recovery-competing", async (pool) => {
      const fixture = await seedAgedAudit(pool, { eventCount: 1001 });
      const proposal = await database.withBootstrapTransaction(
        pool,
        (client) => database.prepareAuditRecoveryInTransaction(client, preparation),
        { ...options, readOnly: true }
      );
      let nextId = 97_000;
      const operation = () =>
        database.withBootstrapTransaction(
          pool,
          (client) =>
            apply(
              client,
              {
                request: proposal.request,
                requestSha256: proposal.requestSha256,
                instanceId: preparation.instanceId,
                organizationId: preparation.organizationId
              },
              {
                createId: () => testId(nextId++),
                sign: async (payload) =>
                  payload.schema === "boardagent.audit.recovery-checkpoint.v1"
                    ? signRecoveryCheckpoint(payload, fixture.evidence.privateKey)
                    : signCheckpoint(payload, fixture.evidence.privateKey)
              }
            ),
          options
        );
      const results = await Promise.all([operation(), operation()]);
      expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
      expect({ ...results[0], replayed: false }).toEqual({ ...results[1], replayed: false });
      const intervals = (
        await pool.query(
          "select first_sequence,last_sequence from audit_checkpoints order by first_sequence"
        )
      ).rows;
      expect(intervals).toEqual([
        { first_sequence: "1", last_sequence: "1000" },
        { first_sequence: "1001", last_sequence: "1001" },
        { first_sequence: "1002", last_sequence: "1003" }
      ]);
      expect(
        (await pool.query("select count(*)::int as count from audit_recoveries")).rows
      ).toEqual([{ count: 1 }]);
      expect(
        await database.withWorkerTransaction(pool, database.verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({
        valid: true,
        ready: true,
        coveredThrough: "1003",
        eventCount: "1004",
        warnings: [`recovery:${preparation.recoveryId}:historical_checkpoint_deadline_missed`]
      });
    });
  });

  it("recovers intact overdue history, preserves original bytes, reports the historical miss and supports exact retry", async () => {
    expect(apply).toBeTypeOf("function");
    await withMigratedDatabase("recovery-apply", async (pool) => {
      const fixture = await seedAgedAudit(pool);
      const original = (
        await pool.query(
          "select canonical_payload,event_sha256,occurred_at from audit_events where sequence=1"
        )
      ).rows;
      const proposal = await database.withBootstrapTransaction(
        pool,
        (client) => database.prepareAuditRecoveryInTransaction(client, preparation),
        { ...options, readOnly: true }
      );
      const input = {
        request: proposal.request,
        requestSha256: proposal.requestSha256,
        instanceId: preparation.instanceId,
        organizationId: preparation.organizationId
      };
      let nextId = 95_100;
      const effects: RecoveryEffects = {
        createId: () => testId(nextId++),
        sign: async (payload) =>
          payload.schema === "boardagent.audit.recovery-checkpoint.v1"
            ? signRecoveryCheckpoint(payload, fixture.evidence.privateKey)
            : signCheckpoint(payload, fixture.evidence.privateKey)
      };
      const result = await database.withBootstrapTransaction(
        pool,
        (client) => apply(client, input, effects),
        options
      );
      expect(result).toMatchObject({
        recoveryId: preparation.recoveryId,
        requestSha256: proposal.requestSha256,
        replayed: false
      });
      expect(
        (
          await pool.query(
            "select canonical_payload,event_sha256,occurred_at from audit_events where sequence=1"
          )
        ).rows
      ).toEqual(original);
      const verification = await database.withWorkerTransaction(
        pool,
        database.verifyPersistedAuditEvidence,
        { assumeRole: "boardagent_worker" }
      );
      expect(verification).toMatchObject({
        valid: true,
        ready: true,
        warnings: [`recovery:${preparation.recoveryId}:historical_checkpoint_deadline_missed`]
      });
      await database.withWorkerTransaction(
        pool,
        async (client) => {
          const next = await database.prepareAuditCheckpointInTransaction(client, {
            checkpointId: testId(95_500),
            signingKeyId: fixture.keyId
          });
          return database.commitAuditCheckpointInTransaction(client, {
            checkpoint: signCheckpoint(next.payload, fixture.evidence.privateKey),
            auditEventId: testId(95_501)
          });
        },
        { assumeRole: "boardagent_worker" }
      );
      expect(
        await database.withWorkerTransaction(pool, database.verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({
        valid: true,
        ready: true,
        warnings: [`recovery:${preparation.recoveryId}:historical_checkpoint_deadline_missed`]
      });
      const replay = await database.withBootstrapTransaction(
        pool,
        (client) =>
          apply(client, input, {
            ...effects,
            sign: async () => {
              throw new Error("retry must not sign again");
            }
          }),
        options
      );
      expect(replay).toEqual({ ...result, replayed: true });
      const changed = { ...proposal.request, reason: "different operation" };
      await expect(
        database.withBootstrapTransaction(
          pool,
          (client) =>
            apply(
              client,
              { ...input, request: changed, requestSha256: canonicalSha256(changed) },
              effects
            ),
          options
        )
      ).rejects.toThrow();
      expect(
        (await pool.query("select count(*)::int as count from audit_recoveries")).rows
      ).toEqual([{ count: 1 }]);
      await pool.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
        {
          kty: "OKP",
          crv: "Ed25519",
          x: "invalid"
        },
        fixture.keyId
      ]);
      expect(
        await database.withWorkerTransaction(pool, database.verifyPersistedAuditEvidence, {
          assumeRole: "boardagent_worker"
        })
      ).toMatchObject({
        valid: false,
        ready: false,
        reason: "checkpoint_signature_invalid"
      });
    });
  });

  it("rolls back provisional authority and history when the signing key is wrong", async () => {
    expect(apply).toBeTypeOf("function");
    await withMigratedDatabase("recovery-wrong-signer", async (pool) => {
      await seedAgedAudit(pool);
      const proposal = await database.withBootstrapTransaction(
        pool,
        (client) => database.prepareAuditRecoveryInTransaction(client, preparation),
        { ...options, readOnly: true }
      );
      const wrong = generateKeyPairSync("ed25519");
      await expect(
        database.withBootstrapTransaction(
          pool,
          (client) =>
            apply(
              client,
              {
                request: proposal.request,
                requestSha256: proposal.requestSha256,
                instanceId: preparation.instanceId,
                organizationId: preparation.organizationId
              },
              {
                createId: () => testId(95_300),
                sign: async (payload) =>
                  payload.schema === "boardagent.audit.recovery-checkpoint.v1"
                    ? signRecoveryCheckpoint(payload, wrong.privateKey)
                    : signCheckpoint(payload, wrong.privateKey)
              }
            ),
          options
        )
      ).rejects.toMatchObject({ code: "recovery_signature_invalid" });
      for (const table of ["audit_recoveries", "audit_recovery_completions", "audit_checkpoints"]) {
        expect((await pool.query(`select count(*)::int as count from ${table}`)).rows).toEqual([
          { count: 0 }
        ]);
      }
      expect((await pool.query("select count(*)::int as count from audit_events")).rows).toEqual([
        { count: 1 }
      ]);
    });
  });
});
