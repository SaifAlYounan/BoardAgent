import { describe, expect, it } from "vitest";

import {
  Aes256GcmWebhookSecurity,
  BoardAgentNotificationWorker,
  BoardAgentTypedWorker
} from "../../artifacts/server/src/index.js";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  reapExpiredNotificationLeasesInTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("notification worker operations", () => {
  it("reaps expired inner leases with immutable attempts and a bounded dead-letter result", async () => {
    await withMigratedDatabase("notification-ops", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["notifications:manage"]
      });
      const notificationJobId = testId(383_000);
      const payload = {
        eventClass: "security",
        occurredAt: "2026-09-03T12:00:00.000Z",
        schemaVersion: "boardagent.webhook-wake.v1",
        wakeId: Buffer.alloc(32, 71).toString("base64url")
      } as const;
      await pool.query(
        `insert into notification_jobs(
           id,organization_id,notice_id,recipient_member_id,webhook_id,source_kind,
           wake_class,random_wake_id,canonical_payload,payload_sha256,state,attempts,
           available_at,lease_owner,lease_started_at,lease_expires_at
         ) values ($1,$2,null,$3,null,'test','security',$4,$5,$6,'leased',10,
                   transaction_timestamp()-interval '2 minutes','crashed-worker',
                   transaction_timestamp()-interval '90 seconds',
                   transaction_timestamp()-interval '60 seconds')`,
        [
          notificationJobId,
          actor.organizationId,
          actor.memberId,
          Buffer.alloc(32, 71),
          Buffer.from(canonicalJson(payload), "utf8"),
          Buffer.from(canonicalSha256(payload), "hex")
        ]
      );
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            client.query("update notification_jobs set state='dead' where id=$1", [
              notificationJobId
            ]),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      const result = await withWorkerTransaction(
        pool,
        (client) =>
          reapExpiredNotificationLeasesInTransaction(client, {
            organizationId: actor.organizationId,
            attemptIds: [testId(383_001)]
          }),
        { assumeRole: "boardagent_worker" }
      );
      expect(result).toEqual({
        reaped: 1,
        retried: 0,
        dead: 1,
        deadNotificationIds: [notificationJobId]
      });
      expect(
        (
          await pool.query(
            `select notification.state,notification.lease_owner,
                    attempt.attempt,attempt.result_class,attempt.error_class
               from notification_jobs as notification
               join notification_attempts as attempt
                 on attempt.notification_job_id=notification.id
              where notification.id=$1`,
            [notificationJobId]
          )
        ).rows
      ).toEqual([
        {
          state: "dead",
          lease_owner: null,
          attempt: 10,
          result_class: "retryable_failure",
          error_class: "notification_lease_expired"
        }
      ]);
      expect(
        await withWorkerTransaction(
          pool,
          (client) =>
            reapExpiredNotificationLeasesInTransaction(client, {
              organizationId: actor.organizationId,
              attemptIds: [testId(383_002)]
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).toEqual({ reaped: 0, retried: 0, dead: 0, deadNotificationIds: [] });
    });
  });

  it("atomically enqueues and executes an operational alert for a dead notice delivery", async () => {
    await withMigratedDatabase("notification-dead-letter", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["notifications:manage"]
      });
      const objectId = testId(383_010);
      const auditEventId = testId(383_011);
      const noticeId = testId(383_012);
      const notificationJobId = testId(383_013);
      await withWorkerTransaction(pool, async (client) => {
        await appendAuditEventsInTransaction(client, [
          {
            organizationId: actor.organizationId,
            event: {
              eventId: auditEventId,
              eventType: "task_created",
              actorMemberId: actor.memberId,
              actorClientId: actor.clientId,
              tokenJti: actor.tokenJti,
              entityType: "task",
              entityId: objectId,
              boardId: actor.boardId,
              origin: "mcp",
              details: { fixture: "notification_dead_letter" },
              schemaVersion: 1
            }
          }
        ]);
        await client.query(
          `insert into notices(
             id,organization_id,board_id,notice_type,object_type,object_id,object_version,
             recipient_member_id,content_sha256,feed_sequence,audit_event_id
           ) values ($1,$2,$3,'task_due','task',$4,1,$5,$6,1,$7)`,
          [
            noticeId,
            actor.organizationId,
            actor.boardId,
            objectId,
            actor.memberId,
            testHash(84),
            auditEventId
          ]
        );
      });
      const wakePayload = {
        eventClass: "notice",
        occurredAt: "2026-09-03T12:00:00.000Z",
        schemaVersion: "boardagent.webhook-wake.v1",
        wakeId: Buffer.alloc(32, 72).toString("base64url")
      } as const;
      await pool.query(
        `insert into notification_jobs(
           id,organization_id,notice_id,recipient_member_id,webhook_id,source_kind,
           wake_class,random_wake_id,canonical_payload,payload_sha256,state,attempts,
           available_at,lease_owner,lease_started_at,lease_expires_at
         ) values ($1,$2,$3,$4,null,'notice','notice',$5,$6,$7,'leased',10,
                   transaction_timestamp()-interval '2 minutes','crashed-worker',
                   transaction_timestamp()-interval '90 seconds',
                   transaction_timestamp()-interval '60 seconds')`,
        [
          notificationJobId,
          actor.organizationId,
          noticeId,
          actor.memberId,
          Buffer.alloc(32, 72),
          Buffer.from(canonicalJson(wakePayload), "utf8"),
          Buffer.from(canonicalSha256(wakePayload), "hex")
        ]
      );
      const reaperJobId = testId(383_014);
      const reaperEnvelope = {
        boardId: null,
        jobType: "notification_lease_reaper",
        organizationId: actor.organizationId,
        parameters: {},
        schemaVersion: "boardagent.job.notification_lease_reaper.v1",
        subjectId: actor.organizationId,
        subjectType: "organization"
      } as const;
      await pool.query(
        `insert into jobs(
           id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
           canonical_payload,payload_sha256,idempotency_key
         ) values ($1,$2,null,'notification_lease_reaper',$3,'organization',$2,$4,$5,$6)`,
        [
          reaperJobId,
          actor.organizationId,
          reaperEnvelope.schemaVersion,
          Buffer.from(canonicalJson(reaperEnvelope), "utf8"),
          Buffer.from(canonicalSha256(reaperEnvelope), "hex"),
          `notification-lease-reaper:${reaperJobId}`
        ]
      );

      const alerts: { alertClass: string; details: unknown }[] = [];
      let nextId = 383_100;
      const notifications = new BoardAgentNotificationWorker(pool, {
        webhookSecurity: new Aes256GcmWebhookSecurity({
          activeKeyId: testId(383_015),
          keys: new Map([[testId(383_015), Buffer.alloc(32, 73)]]),
          resolve: async () => [{ address: "93.184.216.34", family: 4 }]
        }),
        assumeRole: "boardagent_worker",
        newId: () => testId(nextId++),
        onOperationalAlert: (alertClass, details) => {
          alerts.push({ alertClass, details });
        }
      });
      const worker = new BoardAgentTypedWorker(pool, {
        handlers: notifications.handlers(),
        workerId: "notification-operations",
        assumeRole: "boardagent_worker"
      });

      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobType: "notice_fanout"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobType: "notification_lease_reaper"
      });
      const queuedAlert = await pool.query<{
        id: string;
        job_type: string;
        subject_id: string;
        state: string;
      }>(
        `select id,job_type,subject_id,state from jobs
          where job_type='notification_dead_letter_alert'`
      );
      expect(queuedAlert.rows).toEqual([
        {
          id: expect.any(String),
          job_type: "notification_dead_letter_alert",
          subject_id: notificationJobId,
          state: "queued"
        }
      ]);
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobType: "notification_dead_letter_alert"
      });
      expect(alerts).toEqual([
        {
          alertClass: "notification_dead_letter",
          details: {
            alertJobRef: canonicalSha256({
              schemaVersion: "boardagent.operational-reference.v1",
              kind: "job",
              id: queuedAlert.rows[0]!.id
            }),
            boardRef: canonicalSha256({
              schemaVersion: "boardagent.operational-reference.v1",
              kind: "board",
              id: actor.boardId
            }),
            notificationJobRef: canonicalSha256({
              schemaVersion: "boardagent.operational-reference.v1",
              kind: "notification_job",
              id: notificationJobId
            }),
            organizationRef: canonicalSha256({
              schemaVersion: "boardagent.operational-reference.v1",
              kind: "organization",
              id: actor.organizationId
            }),
            schemaVersion: "boardagent.operational-alert.notification-dead-letter.v1"
          }
        }
      ]);
    });
  });
});
