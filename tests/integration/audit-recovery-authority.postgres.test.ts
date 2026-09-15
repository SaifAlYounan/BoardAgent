import { describe, expect, it } from "vitest";
import { signRecoveryCheckpoint } from "../../lib/audit/src/index.js";
import { seedRecoveredAudit } from "../helpers/recovered-audit.js";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  prepareAuditRecoveryInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { seedAgedAudit } from "../helpers/aged-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const input = {
  recoveryId: testId(94_000),
  instanceId: testId(15),
  organizationId: testId(1),
  signingKeyId: testId(92_000),
  operatorReference: "synthetic-operator-incident-2",
  reason: "Recover an intact history after a signing worker outage."
};

describe("operator recovery database authority", () => {
  it("refuses a freshly signed copy of completed recovery authority in a later runtime transaction", async () => {
    await withMigratedDatabase("recovery-copied-authority", async (pool) => {
      const fixture = await seedRecoveredAudit(pool);
      const stored = (
        await pool.query("select canonical_manifest from audit_checkpoints where first_sequence=1")
      ).rows[0]!;
      const payload = JSON.parse(stored.canonical_manifest.toString("utf8"));
      const signed = signRecoveryCheckpoint(
        { ...payload, checkpointId: testId(114_000) },
        fixture.evidence.privateKey
      );
      const client = await pool.connect();
      try {
        await client.query("begin isolation level serializable");
        await client.query("set local role boardagent_worker");
        await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
        await expect(
          client.query(
            `insert into audit_checkpoints(
          id,organization_id,first_sequence,last_sequence,first_event_sha256,last_event_sha256,
          canonical_manifest,manifest_sha256,signature,signing_key_id,created_at)
          values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [
              signed.payload.checkpointId,
              signed.payload.organizationId,
              signed.payload.firstSequence,
              signed.payload.lastSequence,
              Buffer.from(signed.payload.firstEventSha256, "hex"),
              Buffer.from(signed.payload.lastEventSha256, "hex"),
              Buffer.from(canonicalJson(signed.payload)),
              Buffer.from(canonicalSha256(signed.payload), "hex"),
              Buffer.from(signed.signatureBase64Url, "base64url"),
              signed.payload.signingKeyId,
              signed.payload.issuedAt
            ]
          )
        ).rejects.toThrow(/current operator authorization|not authorized in this transaction/u);
      } finally {
        await client.query("rollback");
        client.release();
      }
      expect((await pool.query("select count(*)::int as n from audit_recoveries")).rows).toEqual([
        { n: 1 }
      ]);
      expect((await pool.query("select count(*)::int as n from audit_checkpoints")).rows).toEqual([
        { n: 2 }
      ]);
    });
  });

  it("binds provisional authority to the actual transaction and refuses to commit an unfinished recovery", async () => {
    await withMigratedDatabase("recovery-authority", async (pool) => {
      await seedAgedAudit(pool);
      const prepared = await withBootstrapTransaction(
        pool,
        (client) => prepareAuditRecoveryInTransaction(client, input),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      await expect(
        withBootstrapTransaction(
          pool,
          async (client) => {
            const authorized = await client.query(
              "select * from boardagent_begin_audit_recovery($1,$2)",
              [
                Buffer.from(canonicalJson(prepared.request)),
                Buffer.from(prepared.requestSha256, "hex")
              ]
            );
            expect(authorized.rows).toEqual([{ recovery_id: input.recoveryId, replayed: false }]);
            expect(
              (
                await client.query(
                  "select authorization_transaction_id=pg_current_xact_id() as same_transaction, authorization_server_start=pg_postmaster_start_time() as same_server from audit_recoveries"
                )
              ).rows
            ).toEqual([{ same_transaction: true, same_server: true }]);
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (await pool.query("select count(*)::int as count from audit_recoveries")).rows
      ).toEqual([{ count: 0 }]);
      expect((await pool.query("select count(*)::int as count from audit_events")).rows).toEqual([
        { count: 1 }
      ]);
    });
  });

  it("refuses authorization and direct authority writes from all runtime principals even with operator flags", async () => {
    await withMigratedDatabase("recovery-runtime", async (pool) => {
      await seedAgedAudit(pool);
      const prepared = await withBootstrapTransaction(
        pool,
        (client) => prepareAuditRecoveryInTransaction(client, input),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"] as const) {
        for (const operation of ["function", "insert"] as const) {
          const client = await pool.connect();
          try {
            await client.query("begin isolation level serializable");
            await client.query(`set local role ${role}`);
            await client.query(
              "select set_config('boardagent.transaction_scope','bootstrap',true)"
            );
            await expect(
              operation === "function"
                ? client.query("select * from boardagent_begin_audit_recovery($1,$2)", [
                    Buffer.from(canonicalJson(prepared.request)),
                    Buffer.from(prepared.requestSha256, "hex")
                  ])
                : client.query("insert into audit_recoveries(id) values($1)", [input.recoveryId])
            ).rejects.toMatchObject({ code: "42501" });
          } finally {
            await client.query("rollback");
            client.release();
          }
        }
      }
    });
  });

  it("refuses changed installation, head, key, expiry and request digest before creating authority", async () => {
    await withMigratedDatabase("recovery-bindings", async (pool) => {
      await seedAgedAudit(pool);
      const prepared = await withBootstrapTransaction(
        pool,
        (client) => prepareAuditRecoveryInTransaction(client, input),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      for (const patch of [
        { instanceId: testId(94_001) },
        { headSha256: "aa".repeat(32) },
        { signingKeyId: testId(94_002) },
        { preparedAt: "2026-01-01T00:00:00.000000Z", expiresAt: "2026-01-01T00:30:00.000000Z" },
        { unknown: "not permitted" }
      ]) {
        const request = { ...prepared.request, ...patch };
        await expect(
          withBootstrapTransaction(
            pool,
            (client) =>
              client.query("select * from boardagent_begin_audit_recovery($1,$2)", [
                Buffer.from(canonicalJson(request)),
                Buffer.from(canonicalSha256(request), "hex")
              ]),
            { assumeRole: "boardagent_migrator" }
          )
        ).rejects.toMatchObject({ code: "55000" });
      }
      await expect(
        withBootstrapTransaction(
          pool,
          (client) =>
            client.query("select * from boardagent_begin_audit_recovery($1,$2)", [
              Buffer.from(canonicalJson(prepared.request)),
              Buffer.alloc(32)
            ]),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "55000" });
      expect(
        (await pool.query("select count(*)::int as count from audit_recoveries")).rows
      ).toEqual([{ count: 0 }]);
    });
  });
});
