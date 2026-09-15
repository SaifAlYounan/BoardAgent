import { describe, expect, it } from "vitest";
import {
  appendAuditEventsInTransaction,
  withWorkerTransaction,
  type AuditAppendInput
} from "../../lib/db/src/index.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

function entries(organizationId: string, count: number, padding = ""): AuditAppendInput[] {
  return Array.from({ length: count }, () => ({
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
      details: { synthetic: true, purpose: "atomic-audit-budget", padding },
      schemaVersion: 1
    }
  }));
}

describe("bounded atomic audit admission", () => {
  it("admits one transaction across the signing threshold, then refuses a different transaction even with a copied caller flag", async () => {
    await withUnseededWorker("atomic-admission", async ({ pool, organizationId }) => {
      const before = (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
        .last_sequence as string;
      const transactionId = await withWorkerTransaction(
        pool,
        async (client) => {
          await appendAuditEventsInTransaction(client, entries(organizationId, 600));
          await appendAuditEventsInTransaction(client, entries(organizationId, 600));
          return (await client.query("select pg_current_xact_id()::text as id")).rows[0]!
            .id as string;
        },
        { assumeRole: "boardagent_worker" }
      );
      await expect(
        withWorkerTransaction(
          pool,
          async (client) => {
            await client.query("select set_config('boardagent.audit_transaction_id',$1,true)", [
              transactionId
            ]);
            await appendAuditEventsInTransaction(client, entries(organizationId, 1));
          },
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({
        code: "55000",
        constraint: "boardagent_audit_checkpoint_capacity"
      });
      expect(
        (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe((BigInt(before) + 1200n).toString());
    });
  });

  it("refuses more than 10000 events as an action-size error and rolls back all of its records", async () => {
    await withUnseededWorker("atomic-count-budget", async ({ pool, organizationId }) => {
      const before = (
        await pool.query("select last_sequence::text,last_event_sha256 from audit_chain_head")
      ).rows;
      await expect(
        withWorkerTransaction(
          pool,
          (client) => appendAuditEventsInTransaction(client, entries(organizationId, 10001)),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({
        code: "54000",
        constraint: "boardagent_audit_transaction_capacity"
      });
      expect(
        (await pool.query("select last_sequence::text,last_event_sha256 from audit_chain_head"))
          .rows
      ).toEqual(before);
    });
  }, 20000);

  it("enforces a 16 MiB cumulative byte budget across separate append calls", async () => {
    await withUnseededWorker("atomic-byte-budget", async ({ pool, organizationId }) => {
      const before = (
        await pool.query("select last_sequence::text,last_event_sha256 from audit_chain_head")
      ).rows;
      const padding = "x".repeat(9 * 1024 * 1024);
      await expect(
        withWorkerTransaction(
          pool,
          async (client) => {
            await appendAuditEventsInTransaction(client, entries(organizationId, 1, padding));
            await appendAuditEventsInTransaction(client, entries(organizationId, 1, padding));
          },
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({
        code: "54000",
        constraint: "boardagent_audit_transaction_capacity"
      });
      expect(
        (await pool.query("select last_sequence::text,last_event_sha256 from audit_chain_head"))
          .rows
      ).toEqual(before);
    });
  }, 20000);
  it("accepts exactly 10000 events in one transaction", async () => {
    await withUnseededWorker("atomic-count-edge", async ({ pool, organizationId }) => {
      const before = (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
        .last_sequence as string;
      await withWorkerTransaction(
        pool,
        (client) => appendAuditEventsInTransaction(client, entries(organizationId, 10000)),
        {
          assumeRole: "boardagent_worker"
        }
      );
      expect(
        (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe((BigInt(before) + 10000n).toString());
    });
  }, 20000);

  it("restores the byte allowance when a failed append is rolled back to a savepoint", async () => {
    await withUnseededWorker("atomic-savepoint", async ({ pool, organizationId }) => {
      const before = (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
        .last_sequence as string;
      await withWorkerTransaction(
        pool,
        async (client) => {
          await appendAuditEventsInTransaction(
            client,
            entries(organizationId, 1, "x".repeat(9 * 1024 * 1024))
          );
          await client.query("savepoint second_append");
          await expect(
            appendAuditEventsInTransaction(
              client,
              entries(organizationId, 1, "x".repeat(9 * 1024 * 1024))
            )
          ).rejects.toMatchObject({
            code: "54000",
            constraint: "boardagent_audit_transaction_capacity"
          });
          await client.query("rollback to savepoint second_append");
          await appendAuditEventsInTransaction(
            client,
            entries(organizationId, 1, "x".repeat(6 * 1024 * 1024))
          );
        },
        { assumeRole: "boardagent_worker" }
      );
      expect(
        (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe((BigInt(before) + 2n).toString());
    });
  }, 20000);

  it("denies runtime roles direct changes to the admission allowance", async () => {
    await withUnseededWorker("atomic-roles", async ({ pool }) => {
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"] as const) {
        const client = await pool.connect();
        try {
          await client.query("begin");
          await client.query(`set local role ${role}`);
          await expect(
            client.query("update public.audit_chain_head set admission_payload_bytes=0")
          ).rejects.toMatchObject({ code: "42501" });
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
    });
  });

  it("serializes competing large transactions without partially admitting the loser", async () => {
    await withUnseededWorker("atomic-race", async ({ pool, organizationId }) => {
      const before = (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
        .last_sequence as string;
      const outcomes = await Promise.allSettled(
        [0, 1].map(() =>
          withWorkerTransaction(
            pool,
            (client) => appendAuditEventsInTransaction(client, entries(organizationId, 1200)),
            { assumeRole: "boardagent_worker" }
          )
        )
      );
      expect(outcomes.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter(({ status }) => status === "rejected")).toMatchObject([
        { reason: { code: "55000", constraint: "boardagent_audit_checkpoint_capacity" } }
      ]);
      expect(
        (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
          .last_sequence
      ).toBe((BigInt(before) + 1200n).toString());
    });
  });

  it("refuses matching transaction metadata retained from an earlier server incarnation", async () => {
    await withUnseededWorker("atomic-restored-metadata", async ({ pool, organizationId }) => {
      await withWorkerTransaction(
        pool,
        (client) => appendAuditEventsInTransaction(client, entries(organizationId, 1200)),
        { assumeRole: "boardagent_worker" }
      );
      const client = await pool.connect();
      try {
        await client.query("begin");
        // Owner-only disposable restore-state fixture. Runtime roles cannot write
        // these fields; simulate an xid collision across a restored server.
        await client.query(`update public.audit_chain_head set
          admission_transaction_id=pg_current_xact_id(),
          admission_server_start=pg_postmaster_start_time()-interval '1 hour',
          admission_start_sequence=last_sequence,admission_payload_bytes=0`);
        await client.query("set local role boardagent_worker");
        await client.query("select set_config('boardagent.transaction_scope','worker',true)");
        await expect(
          appendAuditEventsInTransaction(client, entries(organizationId, 1))
        ).rejects.toMatchObject({
          code: "55000",
          constraint: "boardagent_audit_checkpoint_capacity"
        });
      } finally {
        await client.query("rollback");
        client.release();
      }
    });
  });
});
