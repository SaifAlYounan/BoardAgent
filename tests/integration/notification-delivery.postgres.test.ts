import { createHmac } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  Aes256GcmWebhookSecurity,
  BoardAgentNotificationWorker,
  BoardAgentTypedWorker,
  NOTIFICATION_WORKER_JOB_TYPES,
  type WebhookDeliveryTransport,
  type WebhookDeliveryTransportInput
} from "../../artifacts/server/src/index.js";
import { canonicalJson, canonicalSha256, sha256Hex } from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  migrate,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_notification_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "notification-delivery-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

class RecordingTransport implements WebhookDeliveryTransport {
  public readonly calls: WebhookDeliveryTransportInput[] = [];
  public statusCode = 204;

  public async deliver(
    input: WebhookDeliveryTransportInput
  ): Promise<{ readonly statusCode: number; readonly responseSha256: string }> {
    this.calls.push(input);
    return { statusCode: this.statusCode, responseSha256: sha256Hex("response") };
  }
}

describe("contentless notification fanout and delivery", () => {
  it("fans out transactionally, reauthorizes, signs, pins, delivers, and audits", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["notifications:manage"]
      });
      const dataKeyId = testId(380_001);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
         ) values ($1,$2,'notification-test-data-key','data_kek','A256GCM',null,
                   'test://notification-data-key',transaction_timestamp()-interval '1 minute')`,
        [dataKeyId, actor.organizationId]
      );
      let resolutions = 0;
      const security = new Aes256GcmWebhookSecurity({
        activeKeyId: dataKeyId,
        keys: new Map([[dataKeyId, Buffer.alloc(32, 29)]]),
        randomBytes: (length) => Buffer.alloc(length, 31),
        resolve: async () => {
          resolutions += 1;
          return [{ address: "93.184.216.34", family: 4 }];
        }
      });
      const webhookId = testId(380_002);
      const endpoint = "https://hooks.example.com/boardagent";
      const protectedEndpoint = await security.protectEndpoint({
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        webhookId,
        endpoint
      });
      const protectedSecret = security.createSecret({
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        webhookId
      });
      await pool.query(
        `insert into member_webhooks(
           id,organization_id,member_id,endpoint_ciphertext,endpoint_sha256,
           secret_ciphertext,secret_sha256,key_id,ssrf_validation_receipt_sha256,
           event_classes,state,verified_at
         ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active',transaction_timestamp())`,
        [
          webhookId,
          actor.organizationId,
          actor.memberId,
          protectedEndpoint.endpointCiphertext,
          Buffer.from(protectedEndpoint.endpointSha256, "hex"),
          protectedSecret.secretCiphertext,
          Buffer.from(protectedSecret.secretSha256, "hex"),
          dataKeyId,
          Buffer.from(protectedEndpoint.validationReceiptSha256, "hex"),
          ["notice", "pending_action"]
        ]
      );

      const noticeId = testId(380_010);
      const objectId = testId(380_011);
      const sourceAuditId = testId(380_012);
      await withWorkerTransaction(pool, async (client) => {
        await appendAuditEventsInTransaction(client, [
          {
            organizationId: actor.organizationId,
            event: {
              eventId: sourceAuditId,
              eventType: "task_created",
              actorMemberId: actor.memberId,
              actorClientId: actor.clientId,
              tokenJti: actor.tokenJti,
              entityType: "task",
              entityId: objectId,
              boardId: actor.boardId,
              origin: "mcp",
              details: { fixture: "notification_delivery" },
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
            testHash(82),
            sourceAuditId
          ]
        );
        const feedPayload = { schemaVersion: "boardagent.test-feed.v1", objectId };
        await client.query(
          `insert into pending_action_feed(
               id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
               action_type,object_type,object_id,object_version,visibility_sha256,
               canonical_payload,payload_sha256,notice_id,audit_event_id
             ) values ($1,$2,$3,$4,1,1,'task_due','task',$5,1,$6,$7,$8,$9,$10)`,
          [
            testId(380_013),
            actor.organizationId,
            actor.boardId,
            actor.memberId,
            objectId,
            testHash(83),
            Buffer.from(canonicalJson(feedPayload), "utf8"),
            Buffer.from(canonicalSha256(feedPayload), "hex"),
            noticeId,
            sourceAuditId
          ]
        );
      });

      const outbox = await pool.query<{ job_type: string; state: string }>(
        "select job_type,state from jobs where id=$1",
        [noticeId]
      );
      expect(outbox.rows).toEqual([{ job_type: "notice_fanout", state: "queued" }]);

      const transport = new RecordingTransport();
      let nextId = 381_000;
      let wakeByte = 90;
      const notifications = new BoardAgentNotificationWorker(pool, {
        webhookSecurity: security,
        transport,
        workerId: "notification-integration",
        assumeRole: "boardagent_worker",
        newId: () => testId(nextId++),
        randomBytes: (length) => Buffer.alloc(length, wakeByte++)
      });
      const notificationHandlers = notifications.handlers();
      expect([...notificationHandlers.keys()]).toEqual(NOTIFICATION_WORKER_JOB_TYPES);
      const worker = new BoardAgentTypedWorker(pool, {
        handlers: notificationHandlers,
        workerId: "typed-notification-integration",
        assumeRole: "boardagent_worker"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobType: "notice_fanout"
      });
      const deliveryRun = await worker.runOnce();
      expect(deliveryRun).not.toHaveProperty("errorClass");
      expect(deliveryRun).toMatchObject({
        status: "succeeded",
        jobType: "webhook_delivery"
      });

      expect(resolutions).toBe(2);
      expect(transport.calls).toHaveLength(1);
      const call = transport.calls[0]!;
      expect(call.endpoint).toBe(endpoint);
      expect(call.address).toBe("93.184.216.34");
      const body = JSON.parse(call.body.toString("utf8")) as Record<string, unknown>;
      expect(Object.keys(body).toSorted()).toEqual([
        "eventClass",
        "occurredAt",
        "schemaVersion",
        "wakeId"
      ]);
      expect(body).toMatchObject({
        schemaVersion: "boardagent.webhook-wake.v1",
        eventClass: "pending_action"
      });
      expect(call.body.includes(Buffer.from("task"))).toBe(false);

      const deliveryId = call.headers["x-boardagent-delivery"]!;
      const payloadSha256 = sha256Hex(call.body);
      const signatureInput = Buffer.concat([
        Buffer.from(
          ["boardagent.webhook-signature.v1", deliveryId, webhookId, "1", payloadSha256, ""].join(
            "\n"
          ),
          "utf8"
        ),
        call.body
      ]);
      expect(call.headers["x-boardagent-signature"]).toBe(
        `v1=${createHmac("sha256", Buffer.from(protectedSecret.secret, "base64url"))
          .update(signatureInput)
          .digest("hex")}`
      );

      const evidence = await pool.query<{
        state: string;
        attempts: number;
        lease_owner: string | null;
        payload_sha256: Buffer;
        attempt_result: string;
        error_class: string | null;
        event_type: string;
      }>(
        `select notification.state,notification.attempts,notification.lease_owner,
                notification.payload_sha256,attempt.result_class as attempt_result,
                attempt.error_class,audit.event_type
           from notification_jobs as notification
           join notification_attempts as attempt on attempt.notification_job_id=notification.id
           join audit_events as audit on audit.object_id=notification.id
          where notification.id=$1`,
        [deliveryId]
      );
      expect(evidence.rows[0]).toMatchObject({
        state: "delivered",
        attempts: 1,
        lease_owner: null,
        attempt_result: "delivered",
        error_class: null,
        event_type: "webhook_delivery_attempted"
      });
      expect(evidence.rows[0]?.payload_sha256.toString("hex")).toBe(payloadSha256);

      const failedObjectId = testId(380_020);
      const failedNoticeId = testId(380_021);
      const failedAuditId = testId(380_022);
      await withWorkerTransaction(pool, async (client) => {
        await appendAuditEventsInTransaction(client, [
          {
            organizationId: actor.organizationId,
            event: {
              eventId: failedAuditId,
              eventType: "task_created",
              actorMemberId: actor.memberId,
              actorClientId: actor.clientId,
              tokenJti: actor.tokenJti,
              entityType: "task",
              entityId: failedObjectId,
              boardId: actor.boardId,
              origin: "mcp",
              details: { fixture: "notification_dead_delivery" },
              schemaVersion: 1
            }
          }
        ]);
        await client.query(
          `insert into notices(
               id,organization_id,board_id,notice_type,object_type,object_id,object_version,
               recipient_member_id,content_sha256,feed_sequence,audit_event_id
             ) values ($1,$2,$3,'task_due','task',$4,1,$5,$6,2,$7)`,
          [
            failedNoticeId,
            actor.organizationId,
            actor.boardId,
            failedObjectId,
            actor.memberId,
            testHash(85),
            failedAuditId
          ]
        );
        const failedFeedPayload = {
          schemaVersion: "boardagent.test-feed.v1",
          objectId: failedObjectId
        };
        await client.query(
          `insert into pending_action_feed(
               id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
               action_type,object_type,object_id,object_version,visibility_sha256,
               canonical_payload,payload_sha256,notice_id,audit_event_id
             ) values ($1,$2,$3,$4,1,2,'task_due','task',$5,1,$6,$7,$8,$9,$10)`,
          [
            testId(380_023),
            actor.organizationId,
            actor.boardId,
            actor.memberId,
            failedObjectId,
            testHash(86),
            Buffer.from(canonicalJson(failedFeedPayload), "utf8"),
            Buffer.from(canonicalSha256(failedFeedPayload), "hex"),
            failedNoticeId,
            failedAuditId
          ]
        );
      });
      transport.statusCode = 400;
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobType: "notice_fanout"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "dead",
        jobType: "webhook_delivery",
        errorClass: "webhook_permanent_status"
      });
      const deadLetter = await pool.query<{
        notification_state: string;
        alert_state: string;
        alert_subject_id: string;
      }>(
        `select notification.state as notification_state,
                alert.state as alert_state,alert.subject_id as alert_subject_id
           from notification_jobs as notification
           join jobs as alert
             on alert.job_type='notification_dead_letter_alert'
            and alert.subject_id=notification.id
          where notification.notice_id=$1`,
        [failedNoticeId]
      );
      expect(deadLetter.rows).toEqual([
        {
          notification_state: "dead",
          alert_state: "queued",
          alert_subject_id: expect.any(String)
        }
      ]);
    });
  });

  it("cancels a queued delivery when its member disables the webhook", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["notifications:manage"]
      });
      const keyId = testId(382_001);
      const webhookId = testId(382_002);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,nonsecret_locator,activated_at
         ) values ($1,$2,'cancel-data-key','data_kek','A256GCM','test://cancel-key',
                   transaction_timestamp()-interval '1 minute')`,
        [keyId, actor.organizationId]
      );
      const security = new Aes256GcmWebhookSecurity({
        activeKeyId: keyId,
        keys: new Map([[keyId, Buffer.alloc(32, 40)]]),
        resolve: async () => [{ address: "93.184.216.34", family: 4 }]
      });
      const endpoint = await security.protectEndpoint({
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        webhookId,
        endpoint: "https://hooks.example.com/cancel"
      });
      const secret = security.createSecret({
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        webhookId
      });
      await pool.query(
        `insert into member_webhooks(
           id,organization_id,member_id,endpoint_ciphertext,endpoint_sha256,
           secret_ciphertext,secret_sha256,key_id,ssrf_validation_receipt_sha256,
           event_classes,state,verified_at
         ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,array['security'],'active',
                   transaction_timestamp())`,
        [
          webhookId,
          actor.organizationId,
          actor.memberId,
          endpoint.endpointCiphertext,
          Buffer.from(endpoint.endpointSha256, "hex"),
          secret.secretCiphertext,
          Buffer.from(secret.secretSha256, "hex"),
          keyId,
          Buffer.from(endpoint.validationReceiptSha256, "hex")
        ]
      );
      const payload = {
        schemaVersion: "boardagent.webhook-wake.v1",
        eventClass: "security",
        wakeId: Buffer.alloc(32, 51).toString("base64url"),
        occurredAt: "2026-09-03T12:00:00.000Z"
      } as const;
      await pool.query(
        `insert into notification_jobs(
           id,organization_id,notice_id,recipient_member_id,webhook_id,source_kind,
           wake_class,random_wake_id,canonical_payload,payload_sha256,state
         ) values ($1,$2,null,$3,$4,'test','security',$5,$6,$7,'queued')`,
        [
          testId(382_003),
          actor.organizationId,
          actor.memberId,
          webhookId,
          Buffer.alloc(32, 51),
          Buffer.from(canonicalJson(payload), "utf8"),
          Buffer.from(canonicalSha256(payload), "hex")
        ]
      );
      await withWorkerTransaction(pool, (client) =>
        client.query(
          `update member_webhooks
              set state='disabled',disabled_at=transaction_timestamp(),
                  updated_at=transaction_timestamp(),generation=generation+1
            where id=$1`,
          [webhookId]
        )
      );
      const state = await pool.query<{ state: string }>(
        "select state from notification_jobs where webhook_id=$1",
        [webhookId]
      );
      expect(state.rows).toEqual([{ state: "cancelled" }]);
    });
  });
});
