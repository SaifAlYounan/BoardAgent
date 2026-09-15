import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  appendAuditEventsInTransaction,
  enqueueRequestJobInTransaction,
  runOperationalRetentionInTransaction,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

function sha256(bytes: Buffer): Buffer {
  return createHash("sha256").update(bytes).digest();
}

describe("operational retention authority", () => {
  it("removes only terminal job and notification attempt logs older than 30 days", async () => {
    await withMigratedDatabase("operational-retention", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const oldJobId = testId(80_000);
      const recentJobId = testId(80_001);

      for (const [jobId, suffix] of [
        [oldJobId, "old"],
        [recentJobId, "recent"]
      ] as const) {
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId,
              idempotencyKey: `operational-retention-${suffix}`,
              envelope: {
                schemaVersion: "boardagent.job.compatibility_alert.v1",
                organizationId: actor.organizationId,
                boardId: null,
                jobType: "compatibility_alert",
                subjectType: "organization",
                subjectId: actor.organizationId,
                parameters: {}
              }
            }),
          { assumeRole: "boardagent_server" }
        );
      }
      await pool.query(
        `update jobs
            set state='leased',attempts=1,lease_owner='retention-fixture',
                lease_token=case id when $1 then $3::uuid else $4::uuid end,
                lease_started_at=case id
                  when $1 then transaction_timestamp()-interval '31 days 2 minutes'
                  else transaction_timestamp()-interval '29 days 2 minutes' end,
                lease_expires_at=case id
                  when $1 then transaction_timestamp()-interval '31 days 1 minute'
                  else transaction_timestamp()-interval '29 days 1 minute' end,
                created_at=case id
                  when $1 then transaction_timestamp()-interval '31 days 1 hour'
                  else transaction_timestamp()-interval '29 days 1 hour' end
          where id=any($2::uuid[])`,
        [oldJobId, [oldJobId, recentJobId], testId(80_002), testId(80_003)]
      );
      await pool.query(
        `update jobs
            set state='succeeded',lease_owner=null,lease_token=null,lease_started_at=null,
                lease_expires_at=null,completed_at=case id
                  when $1 then transaction_timestamp()-interval '31 days'
                  else transaction_timestamp()-interval '29 days' end
          where id=any($2::uuid[])`,
        [oldJobId, [oldJobId, recentJobId]]
      );
      await pool.query(
        `insert into job_attempt_results(
           job_id,attempt,lease_token,lease_owner,result_class,result_sha256,error_class,
           resulting_state,started_at,completed_at
         ) values
           ($1,1,$3,'retention-fixture','succeeded',$5,null,'succeeded',
            transaction_timestamp()-interval '31 days 2 minutes',
            transaction_timestamp()-interval '31 days'),
           ($2,1,$4,'retention-fixture','succeeded',$6,null,'succeeded',
            transaction_timestamp()-interval '29 days 2 minutes',
            transaction_timestamp()-interval '29 days')`,
        [oldJobId, recentJobId, testId(80_002), testId(80_003), testHash(80), testHash(81)]
      );

      const auditEventId = testId(80_010);
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: actor.organizationId,
              objectVersion: 1n,
              event: {
                eventId: auditEventId,
                eventType: "notice_delivered",
                actorMemberId: actor.memberId,
                actorClientId: actor.clientId,
                tokenJti: actor.tokenJti,
                entityType: "retention_fixture",
                entityId: testId(80_011),
                boardId: actor.boardId,
                origin: "mcp",
                details: { meaning: "retention-boundary-fixture" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      const noticeId = testId(80_012);
      await pool.query(
        `insert into notices(
           id,organization_id,board_id,notice_type,object_type,object_id,object_version,
           recipient_member_id,content_sha256,feed_sequence,state,audit_event_id
         ) values ($1,$2,$3,'retention_fixture','retention_fixture',$4,1,$5,$6,9000,
                   'committed',$7)`,
        [
          noticeId,
          actor.organizationId,
          actor.boardId,
          testId(80_011),
          actor.memberId,
          testHash(82),
          auditEventId
        ]
      );

      const oldNotificationId = testId(80_020);
      const recentNotificationId = testId(80_021);
      const oldWake = Buffer.from('{"eventClass":"retention_old"}', "utf8");
      const recentWake = Buffer.from('{"eventClass":"retention_recent"}', "utf8");
      await pool.query(
        `insert into notification_jobs(
           id,organization_id,notice_id,recipient_member_id,webhook_id,wake_class,
           random_wake_id,canonical_payload,payload_sha256,state,attempts,available_at,
           created_at,delivered_at
         ) values
           ($1,$3,$4,$5,null,'retention_old',$6,$7,$8,'delivered',1,
            transaction_timestamp()-interval '31 days',
            transaction_timestamp()-interval '31 days 1 hour',
            transaction_timestamp()-interval '31 days'),
           ($2,$3,$4,$5,null,'retention_recent',$9,$10,$11,'delivered',1,
            transaction_timestamp()-interval '29 days',
            transaction_timestamp()-interval '29 days 1 hour',
            transaction_timestamp()-interval '29 days')`,
        [
          oldNotificationId,
          recentNotificationId,
          actor.organizationId,
          noticeId,
          actor.memberId,
          Buffer.alloc(32, 90),
          oldWake,
          sha256(oldWake),
          Buffer.alloc(32, 91),
          recentWake,
          sha256(recentWake)
        ]
      );
      const oldAttemptId = testId(80_022);
      const recentAttemptId = testId(80_023);
      await pool.query(
        `insert into notification_attempts(
           id,notification_job_id,attempt,request_sha256,result_class,error_class,
           http_status,response_sha256,started_at,completed_at
         ) values
           ($1,$3,1,$5,'delivered',null,204,$6,
            transaction_timestamp()-interval '31 days 2 minutes',
            transaction_timestamp()-interval '31 days'),
           ($2,$4,1,$7,'delivered',null,204,$8,
            transaction_timestamp()-interval '29 days 2 minutes',
            transaction_timestamp()-interval '29 days')`,
        [
          oldAttemptId,
          recentAttemptId,
          oldNotificationId,
          recentNotificationId,
          testHash(83),
          testHash(84),
          testHash(85),
          testHash(86)
        ]
      );

      await expect(
        withWorkerTransaction(
          pool,
          (client) => client.query("delete from jobs where id=$1", [oldJobId]),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withWorkerTransaction(
          pool,
          (client) => client.query("delete from notification_attempts where id=$1", [oldAttemptId]),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      expect(
        (
          await pool.query(
            `select count(*)::integer as count
               from notification_attempts as attempt
               join notification_jobs as notification on notification.id=attempt.notification_job_id
              where notification.organization_id=$1
                and notification.state in ('delivered','dead','cancelled')
                and attempt.completed_at<=transaction_timestamp()-interval '30 days'`,
            [actor.organizationId]
          )
        ).rows
      ).toEqual([{ count: 1 }]);
      const policyProbe = await pool.connect();
      try {
        await policyProbe.query("begin");
        await policyProbe.query("set local role boardagent_migrator");
        await policyProbe.query("select set_config('boardagent.transaction_scope','worker',true)");
        expect(
          (
            await policyProbe.query(
              `select count(*)::integer as count
                 from notification_attempts as attempt
                 join notification_jobs as notification
                   on notification.id=attempt.notification_job_id
                where notification.organization_id=$1
                  and notification.state in ('delivered','dead','cancelled')
                  and attempt.completed_at<=transaction_timestamp()-interval '30 days'`,
              [actor.organizationId]
            )
          ).rows
        ).toEqual([{ count: 1 }]);
        await policyProbe.query("rollback");
      } finally {
        policyProbe.release();
      }

      const permanentBefore = await pool.query<{ audits: string; notices: string }>(
        `select (select count(*)::text from audit_events) as audits,
                (select count(*)::text from notices) as notices`
      );
      expect(
        await withWorkerTransaction(
          pool,
          (client) =>
            runOperationalRetentionInTransaction(client, {
              jobType: "job_retention",
              organizationId: actor.organizationId,
              limit: 100
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).toEqual({ jobType: "job_retention", deletedJobAttempts: 1, deletedJobs: 1 });
      expect(
        await withWorkerTransaction(
          pool,
          (client) =>
            runOperationalRetentionInTransaction(client, {
              jobType: "log_retention",
              organizationId: actor.organizationId,
              limit: 100
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).toEqual({ jobType: "log_retention", deletedNotificationAttempts: 1 });

      expect(
        (
          await pool.query("select id from jobs where id=any($1::uuid[]) order by id", [
            [oldJobId, recentJobId]
          ])
        ).rows
      ).toEqual([{ id: recentJobId }]);
      expect(
        (
          await pool.query(
            "select id from notification_attempts where id=any($1::uuid[]) order by id",
            [[oldAttemptId, recentAttemptId]]
          )
        ).rows
      ).toEqual([{ id: recentAttemptId }]);
      expect(
        (
          await pool.query(
            "select id from notification_jobs where id=any($1::uuid[]) order by id",
            [[oldNotificationId, recentNotificationId]]
          )
        ).rows
      ).toEqual([{ id: oldNotificationId }, { id: recentNotificationId }]);
      expect(
        await pool.query<{ audits: string; notices: string }>(
          `select (select count(*)::text from audit_events) as audits,
                  (select count(*)::text from notices) as notices`
        )
      ).toMatchObject({ rows: permanentBefore.rows });

      expect(
        await withWorkerTransaction(
          pool,
          (client) =>
            runOperationalRetentionInTransaction(client, {
              jobType: "job_retention",
              organizationId: actor.organizationId,
              limit: 100
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).toEqual({ jobType: "job_retention", deletedJobAttempts: 0, deletedJobs: 0 });
    });
  });
});
