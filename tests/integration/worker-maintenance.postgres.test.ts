import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  migrate,
  runWorkerMaintenanceInTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_worker_maintenance_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "worker-maintenance-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

describe("least-authority worker maintenance", () => {
  it("expires only due ephemera in bounded, replay-safe batches", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const expiredDraftId = testId(38_000);
      const futureDraftId = testId(38_001);
      await pool.query(
        `insert into wizard_drafts(
           id,organization_id,board_id,draft_type,creator_member_id,current_step,
           signed_context,context_sha256,state,expires_at,created_at
         ) values
           ($1,$3,$4,'vote',$5,0,$6,$7,'active',
            transaction_timestamp()-interval '10 minutes',
            transaction_timestamp()-interval '20 minutes'),
           ($2,$3,$4,'vote',$5,0,$6,$7,'active',
            transaction_timestamp()+interval '10 minutes',transaction_timestamp())`,
        [
          expiredDraftId,
          futureDraftId,
          actor.organizationId,
          actor.boardId,
          actor.memberId,
          Buffer.alloc(32, 1),
          Buffer.alloc(32, 2)
        ]
      );
      await pool.query(
        `insert into rate_limit_buckets(
           bucket_class,subject_sha256,window_started_at,window_seconds,request_count,blocked_until
         ) values
           ('ip',$1,transaction_timestamp()-interval '2 days',60,1,null),
           ('ip',$2,transaction_timestamp(),60,1,null)`,
        [Buffer.alloc(32, 3), Buffer.alloc(32, 4)]
      );

      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            client.query("update wizard_drafts set state='expired' where id=$1", [expiredDraftId]),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      const policyProbe = await pool.connect();
      try {
        await policyProbe.query("begin");
        await policyProbe.query("set local role boardagent_migrator");
        await policyProbe.query("select set_config('boardagent.transaction_scope','worker',true)");
        expect(
          (
            await policyProbe.query(
              `select count(*)::integer as count,
                      count(*) filter (
                        where window_started_at+make_interval(secs=>window_seconds)
                                <=transaction_timestamp()-interval '1 hour'
                          and (blocked_until is null
                               or blocked_until<=transaction_timestamp()-interval '1 hour')
                      )::integer as eligible
                 from rate_limit_buckets`
            )
          ).rows
        ).toEqual([{ count: 2, eligible: 1 }]);
        await policyProbe.query("rollback");
      } finally {
        policyProbe.release();
      }

      const expired = await withWorkerTransaction(
        pool,
        (client) =>
          runWorkerMaintenanceInTransaction(client, {
            jobType: "wizard_expiry",
            organizationId: actor.organizationId,
            limit: 100
          }),
        { assumeRole: "boardagent_worker" }
      );
      expect(expired).toEqual({ jobType: "wizard_expiry", expiredDrafts: 1 });

      const pruned = await withWorkerTransaction(
        pool,
        (client) =>
          runWorkerMaintenanceInTransaction(client, {
            jobType: "rate_bucket_retention",
            organizationId: actor.organizationId,
            limit: 100
          }),
        { assumeRole: "boardagent_worker" }
      );
      expect(pruned).toEqual({ jobType: "rate_bucket_retention", deletedBuckets: 1 });

      const states = await pool.query<{ id: string; state: string; row_version: string }>(
        `select id,state,row_version::text from wizard_drafts
          where id=any($1::uuid[]) order by id`,
        [[expiredDraftId, futureDraftId]]
      );
      expect(states.rows).toEqual([
        { id: expiredDraftId, state: "expired", row_version: "2" },
        { id: futureDraftId, state: "active", row_version: "1" }
      ]);
      expect(
        (await pool.query("select count(*)::integer as count from rate_limit_buckets")).rows
      ).toEqual([{ count: 1 }]);

      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            runWorkerMaintenanceInTransaction(client, {
              jobType: "wizard_expiry",
              organizationId: testId(38_002),
              limit: 100
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      expect(
        await withWorkerTransaction(
          pool,
          (client) =>
            runWorkerMaintenanceInTransaction(client, {
              jobType: "wizard_expiry",
              organizationId: actor.organizationId,
              limit: 100
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).toEqual({ jobType: "wizard_expiry", expiredDrafts: 0 });
    });
  });
});
