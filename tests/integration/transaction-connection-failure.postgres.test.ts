import type { PoolClient } from "pg";
import { describe, expect, it } from "vitest";
import {
  withBackupTransaction,
  withBootstrapTransaction,
  withIdentityTransaction,
  withRequestTransaction,
  withRestoreTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";

describe("SR100 leased database connection interruption", () => {
  it.each(["request", "identity", "bootstrap", "worker", "backup", "restore"] as const)(
    "%s fails a connection lost between queries, discards it and starts a new correctly scoped transaction",
    async (scope) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer } = await administrativeActors(pool);
        const run = (callback: (client: PoolClient) => Promise<number>) => {
          switch (scope) {
            case "request":
              return withRequestTransaction(pool, issuer.context, callback, {
                assumeRole: "boardagent_server",
                isolation: "serializable"
              });
            case "identity":
              return withIdentityTransaction(
                pool,
                { organizationId: issuer.organizationId, boardIds: [issuer.boardId] },
                callback,
                { assumeRole: "boardagent_server" }
              );
            case "bootstrap":
              return withBootstrapTransaction(pool, callback, {
                assumeRole: "boardagent_migrator"
              });
            case "worker":
              return withWorkerTransaction(pool, callback, { assumeRole: "boardagent_worker" });
            case "backup":
              return withBackupTransaction(pool, callback, { assumeRole: "boardagent_backup" });
            case "restore":
              return withRestoreTransaction(pool, callback, { assumeRole: "boardagent_backup" });
          }
        };
        let announce: (pid: number) => void = () => {};
        const started = new Promise<number>((resolve) => {
          announce = resolve;
        });
        const pending = run(async (client) => {
          const pid = Number((await client.query("select pg_backend_pid() as pid")).rows[0].pid);
          // Wait for actual socket closure, with no query pending and no test error
          // listener that could mask the missing production handler.
          const ended = new Promise<void>((resolve) => client.once("end", resolve));
          announce(pid);
          await ended;
          return pid;
        }).then(
          (value) => ({ value }),
          (error: unknown) => ({ error })
        );
        const pid = await started;
        expect(
          (
            await pool.query(
              "select pg_terminate_backend(pid) as terminated from pg_stat_activity where pid=$1 and datname=current_database()",
              [pid]
            )
          ).rows[0]
        ).toEqual({ terminated: true });
        expect(await pending).toMatchObject({ error: expect.any(Error) });
        const replacementPid = await run(async (client) => {
          const row = (
            await client.query(
              "select pg_backend_pid() as pid,current_setting('boardagent.transaction_scope') as scope,current_user as role,current_setting('transaction_read_only') as read_only"
            )
          ).rows[0];
          const role =
            scope === "worker"
              ? "boardagent_worker"
              : scope === "bootstrap"
                ? "boardagent_migrator"
                : ["backup", "restore"].includes(scope)
                  ? "boardagent_backup"
                  : "boardagent_server";
          expect(row).toMatchObject({
            scope,
            role,
            read_only: ["backup", "restore"].includes(scope) ? "on" : "off"
          });
          return Number(row.pid);
        });
        expect(replacementPid).not.toBe(pid);
      });
    }
  );
});
