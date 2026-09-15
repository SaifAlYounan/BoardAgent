import { describe, expect, it } from "vitest";

import {
  PendingActionDeltaSchema,
  canonicalJson,
  canonicalSha256
} from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  inspectFeedConsistencyInTransaction,
  reconcileFeedEntitlementsInTransaction,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import {
  seedAuthorizedActor,
  testHash,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

async function seedPendingTaskFeed(
  pool: Parameters<typeof seedAuthorizedActor>[0],
  actor: AuthorizedActorFixture,
  input: {
    readonly feedId: string;
    readonly objectId: string;
    readonly auditEventId: string;
    readonly sequence?: number;
  }
): Promise<Buffer> {
  const sequence = input.sequence ?? 1;
  await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      appendAuditEventsInTransaction(client, [
        {
          organizationId: actor.organizationId,
          objectVersion: 1n,
          event: {
            eventId: input.auditEventId,
            eventType: "notice_delivered",
            actorMemberId: actor.memberId,
            actorClientId: actor.clientId,
            tokenJti: actor.tokenJti,
            entityType: "task",
            entityId: input.objectId,
            boardId: actor.boardId,
            origin: "mcp",
            details: { meaning: "committed_recipient_feed_handoff" },
            schemaVersion: 1
          }
        }
      ]),
    { assumeRole: "boardagent_server" }
  );
  const payload = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: String(sequence),
    deltaType: "task_due",
    objectType: "task",
    objectId: input.objectId,
    objectVersion: 1,
    entitlementGeneration: 1,
    actionState: "pending",
    safeRefs: { taskSha256: "91".repeat(32) },
    createdAt: "2026-09-04T12:00:00.000Z"
  });
  const canonicalPayload = Buffer.from(canonicalJson(payload), "utf8");
  await pool.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,audit_event_id
     ) values ($1,$2,$3,$4,1,$5,'task_due','task',$6,1,$7,$8,$9,$10)`,
    [
      input.feedId,
      actor.organizationId,
      actor.boardId,
      actor.memberId,
      sequence,
      input.objectId,
      testHash(90),
      canonicalPayload,
      Buffer.from(canonicalSha256(payload), "hex"),
      input.auditEventId
    ]
  );
  return canonicalPayload;
}

describe("feed entitlement reconciliation and consistency", () => {
  it("atomically tombstones a stale member feed under worker-only authority", async () => {
    await withMigratedDatabase("feed-reconcile", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read"],
        isSecretary: false
      });
      const feedId = testId(81_000);
      const objectId = testId(81_001);
      const auditEventId = testId(81_002);
      const tombstoneId = testId(81_003);
      await seedPendingTaskFeed(pool, actor, { feedId, objectId, auditEventId });

      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            client.query("update pending_action_feed set state='superseded' where id=$1", [feedId]),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await pool.query(
        `update board_memberships
            set state='ended',active_until=transaction_timestamp(),
                entitlement_generation=entitlement_generation+1
          where organization_id=$1 and board_id=$2 and member_id=$3`,
        [actor.organizationId, actor.boardId, actor.memberId]
      );

      const reconciled = await withWorkerTransaction(
        pool,
        (client) =>
          reconcileFeedEntitlementsInTransaction(client, {
            organizationId: actor.organizationId,
            boardId: actor.boardId,
            memberId: actor.memberId,
            limit: 100,
            newId: () => tombstoneId
          }),
        { assumeRole: "boardagent_worker", isolation: "serializable" }
      );
      expect(reconciled).toEqual({ reconciled: 1, hasMore: false });

      const projection = await pool.query<{
        state: string;
        resolved_at: Date | null;
        entitlement_generation: string;
        feed_sequence: string;
        reason_class: string;
        tombstone_sha256: Buffer;
        audit_event_id: string;
      }>(
        `select feed.state,feed.resolved_at,tombstone.entitlement_generation::text,
                tombstone.feed_sequence::text,tombstone.reason_class,
                tombstone.tombstone_sha256,tombstone.audit_event_id
           from pending_action_feed as feed
           join feed_tombstones as tombstone on tombstone.removed_feed_id=feed.id
          where feed.id=$1`,
        [feedId]
      );
      expect(projection.rows).toHaveLength(1);
      expect(projection.rows[0]).toMatchObject({
        state: "superseded",
        resolved_at: expect.any(Date),
        entitlement_generation: "2",
        feed_sequence: "1",
        reason_class: "revoked",
        audit_event_id: auditEventId
      });
      expect(projection.rows[0]?.tombstone_sha256.toString("hex")).toBe(
        canonicalSha256({
          schemaVersion: "boardagent.feed-tombstone.v1",
          source: "feed_reconcile",
          boardId: actor.boardId,
          memberId: actor.memberId,
          removedFeedId: feedId,
          objectType: "task",
          objectId,
          priorEntitlementGeneration: "1",
          entitlementGeneration: "2",
          feedSequence: "1",
          reasonClass: "revoked"
        })
      );

      expect(
        await withWorkerTransaction(
          pool,
          (client) =>
            reconcileFeedEntitlementsInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              memberId: actor.memberId,
              limit: 100,
              newId: () => testId(81_004)
            }),
          { assumeRole: "boardagent_worker", isolation: "serializable" }
        )
      ).toEqual({ reconciled: 0, hasMore: false });
    });
  });

  it("reports canonical projection drift without mutating or auto-repairing it", async () => {
    await withMigratedDatabase("feed-consistency", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read"],
        isSecretary: false
      });
      const feedId = testId(81_100);
      await seedPendingTaskFeed(pool, actor, {
        feedId,
        objectId: testId(81_101),
        auditEventId: testId(81_102)
      });

      const clean = await withWorkerTransaction(
        pool,
        (client) => inspectFeedConsistencyInTransaction(client, actor.organizationId),
        { assumeRole: "boardagent_worker", isolation: "repeatable read" }
      );
      expect(clean).toMatchObject({
        valid: true,
        checkedFeedRows: 1,
        checkedTombstoneRows: 0,
        payloadHashMismatches: 0,
        payloadCanonicalMismatches: 0,
        payloadBindingMismatches: 0,
        membershipStalePendingRows: 0,
        relationMismatches: 0
      });

      const noncanonical = Buffer.from(
        '{ "schemaVersion": "boardagent.pending-action.v1", "sequence": "1" }',
        "utf8"
      );
      await pool.query(
        "update pending_action_feed set canonical_payload=$2,payload_sha256=sha256($2) where id=$1",
        [feedId, noncanonical]
      );
      const drifted = await withWorkerTransaction(
        pool,
        (client) => inspectFeedConsistencyInTransaction(client, actor.organizationId),
        { assumeRole: "boardagent_worker", isolation: "repeatable read" }
      );
      expect(drifted).toMatchObject({
        valid: false,
        checkedFeedRows: 1,
        payloadHashMismatches: 0,
        payloadCanonicalMismatches: 1,
        payloadBindingMismatches: 0
      });
      expect(drifted.evidenceSha256).toMatch(/^[0-9a-f]{64}$/u);

      const unchanged = await pool.query<{ state: string; canonical_payload: Buffer }>(
        "select state,canonical_payload from pending_action_feed where id=$1",
        [feedId]
      );
      expect(unchanged.rows).toEqual([{ state: "pending", canonical_payload: noncanonical }]);
      expect(
        (
          await pool.query(
            "select count(*)::integer as count from feed_tombstones where removed_feed_id=$1",
            [feedId]
          )
        ).rows
      ).toEqual([{ count: 0 }]);
    });
  });

  it("rolls back reconciliation when a stale row has structural drift", async () => {
    await withMigratedDatabase("feed-reconcile-drift", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read"],
        isSecretary: false
      });
      const feedId = testId(81_200);
      await seedPendingTaskFeed(pool, actor, {
        feedId,
        objectId: testId(81_201),
        auditEventId: testId(81_202)
      });
      const driftedPayload = Buffer.from(
        '{ "schemaVersion": "boardagent.pending-action.v1", "sequence": "1" }',
        "utf8"
      );
      await pool.query(
        `update pending_action_feed
            set canonical_payload=$2,payload_sha256=sha256($2)
          where id=$1`,
        [feedId, driftedPayload]
      );
      await pool.query(
        `update board_memberships
            set state='ended',active_until=transaction_timestamp(),
                entitlement_generation=entitlement_generation+1
          where organization_id=$1 and board_id=$2 and member_id=$3`,
        [actor.organizationId, actor.boardId, actor.memberId]
      );

      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            reconcileFeedEntitlementsInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              memberId: actor.memberId,
              limit: 100,
              newId: () => testId(81_203)
            }),
          { assumeRole: "boardagent_worker", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ issueClass: "payload_noncanonical" });
      expect(
        (
          await pool.query(
            `select feed.state,
                    (select count(*)::integer from feed_tombstones as tombstone
                      where tombstone.removed_feed_id=feed.id) as tombstones
               from pending_action_feed as feed where feed.id=$1`,
            [feedId]
          )
        ).rows
      ).toEqual([{ state: "pending", tombstones: 0 }]);
    });
  });
});
