import type { PoolClient } from "pg";
import {
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  type JsonValue
} from "@boardagent/contracts";
import {
  stageActionInTransaction,
  confirmStagedActionInTransaction,
  type StageActionInput,
  type ConfirmStagedActionInput
} from "./consent.js";
import { readRequestContext } from "./request-context.js";
import type { AuditAppendInput } from "./audit.js";
export interface RecordRecusalAction {
  readonly boardId: string;
  readonly objectType: "question" | "meeting" | "minutes";
  readonly objectId: string;
  readonly memberId: string;
  readonly operation: "add" | "lift";
  readonly reason: string;
  readonly idempotencyKey: string;
}

export async function prepareRecordRecusalInTransaction(
  client: PoolClient,
  input: RecordRecusalAction
) {
  const request = {
    boardId: UuidV7Schema.parse(input.boardId),
    objectType: input.objectType,
    objectId: UuidV7Schema.parse(input.objectId),
    memberId: UuidV7Schema.parse(input.memberId),
    operation: input.operation,
    reason: canonicalText(input.reason),
    idempotencyKey: input.idempotencyKey
  };
  if (
    !["add", "lift"].includes(request.operation) ||
    request.reason.length < 1 ||
    request.reason.length > 65536 ||
    request.idempotencyKey.length < 16 ||
    request.idempotencyKey.length > 256
  )
    throw new Error("record recusal is unavailable");
  const snapshot = await client.query<{ payload: JsonValue }>(
    "select boardagent_prepare_record_recusal($1::jsonb) as payload",
    [JSON.stringify(request)]
  );
  const payload = snapshot.rows[0]?.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("record recusal is unavailable");
  return {
    actionCode: "manage_recusal" as const,
    targetType: request.objectType,
    targetId: request.objectId,
    boardId: request.boardId,
    canonicalSchema: "boardagent.record-recusal-consent.v1",
    canonicalPayload: payload,
    payloadSha256: canonicalSha256(payload),
    packageSha256: null,
    request
  };
}

export async function stageRecordRecusalInTransaction(
  client: PoolClient,
  input: {
    readonly action: RecordRecusalAction;
    readonly stage: Omit<
      StageActionInput,
      | "boardId"
      | "actingForMemberId"
      | "actionCode"
      | "targetType"
      | "targetId"
      | "canonicalSchema"
      | "canonicalPayload"
      | "packageSha256"
      | "originalName"
    >;
  }
) {
  const prepared = await prepareRecordRecusalInTransaction(client, input.action);
  return stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.boardId,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: null,
      originalName: prepared.actionCode
    },
    async () => {}
  );
}

export async function confirmRecordRecusalInTransaction(
  client: PoolClient,
  input: {
    readonly action: RecordRecusalAction;
    readonly confirmation: ConfirmStagedActionInput;
    readonly newId: () => string;
  }
) {
  let prepared: Awaited<ReturnType<typeof prepareRecordRecusalInTransaction>> | undefined;
  let affectedStages: { id: string }[] = [];
  let affectedFeeds: {
    id: string;
    object_type: string;
    object_id: string;
    entitlement_generation: string;
    feed_sequence: string;
  }[] = [];
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (c) => {
      prepared = await prepareRecordRecusalInTransaction(c, input.action);
      if (prepared.request.operation === "add") {
        const context = await readRequestContext(c);
        affectedStages = (
          await c.query<{ id: string }>(
            `select id from action_stages where organization_id=$1 and board_id=$2
        and (actor_member_id=$3 or acting_for_member_id=$3) and state='active' and id<>$4
        and boardagent_recusal_covers($5,$6,target_type,target_id) order by id for update`,
            [
              context.organizationId,
              prepared.boardId,
              prepared.request.memberId,
              input.confirmation.stageId,
              prepared.request.objectType,
              prepared.request.objectId
            ]
          )
        ).rows;
        affectedFeeds = (
          await c.query<{
            id: string;
            object_type: string;
            object_id: string;
            entitlement_generation: string;
            feed_sequence: string;
          }>(
            `select id,object_type,object_id,entitlement_generation::text,feed_sequence::text from pending_action_feed
         where organization_id=$1 and board_id=$2 and member_id=$3 and state='pending'
         and boardagent_recusal_covers($4,$5,object_type,object_id) order by feed_sequence,id for update`,
            [
              context.organizationId,
              prepared.boardId,
              prepared.request.memberId,
              prepared.request.objectType,
              prepared.request.objectId
            ]
          )
        ).rows;
      }
      return { payloadSha256: prepared.payloadSha256, packageSha256: null };
    },
    async (c, consentRecordId) => {
      if (!prepared) throw new Error("record recusal preparation is unavailable");
      const context = await readRequestContext(c);
      const request = prepared.request;
      const exclusionId = UuidV7Schema.parse(input.newId());
      const auditId = UuidV7Schema.parse(input.newId());
      const audits: AuditAppendInput[] = [];
      let invalidatedStages = 0;
      let tombstones = 0;
      if (request.operation === "add") {
        for (const stage of affectedStages) {
          await c.query(
            "update action_stages set state='replaced' where id=$1 and state='active'",
            [stage.id]
          );
          audits.push({
            organizationId: context.organizationId,
            consentRecordId,
            event: {
              eventId: input.newId(),
              eventType: "stage_replaced",
              actorMemberId: context.memberId,
              actorClientId: context.clientId,
              tokenJti: context.tokenJti,
              boardId: request.boardId,
              entityType: "action_stage",
              entityId: stage.id,
              origin: "mcp",
              schemaVersion: 1,
              details: { reason: "record_recusal", memberId: request.memberId, exclusionId }
            }
          });
        }
        invalidatedStages += affectedStages.length;
        for (const feed of affectedFeeds) {
          const feedAuditId = input.newId();
          const payload = {
            schemaVersion: "boardagent.feed-tombstone.v1",
            removedFeedId: feed.id,
            memberId: request.memberId,
            boardId: request.boardId,
            objectType: feed.object_type,
            objectId: feed.object_id,
            entitlementGeneration: feed.entitlement_generation,
            feedSequence: feed.feed_sequence,
            reasonClass: "recused"
          };
          await c.query(
            "update pending_action_feed set state='superseded',resolved_at=transaction_timestamp() where id=$1",
            [feed.id]
          );
          await c.query(
            `insert into feed_tombstones(id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
          removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id)
          values($1,$2,$3,$4,$5,$6,$7,$8,$9,'recused',$10,$11)`,
            [
              input.newId(),
              context.organizationId,
              request.boardId,
              request.memberId,
              feed.entitlement_generation,
              feed.feed_sequence,
              feed.id,
              feed.object_type,
              feed.object_id,
              Buffer.from(canonicalSha256(payload), "hex"),
              feedAuditId
            ]
          );
          audits.push({
            organizationId: context.organizationId,
            consentRecordId,
            event: {
              eventId: feedAuditId,
              eventType: "recusal_changed",
              actorMemberId: context.memberId,
              actorClientId: context.clientId,
              tokenJti: context.tokenJti,
              boardId: request.boardId,
              entityType: feed.object_type,
              entityId: feed.object_id,
              origin: "mcp",
              schemaVersion: 1,
              details: {
                reason: "record_recusal",
                memberId: request.memberId,
                exclusionId,
                removedFeedId: feed.id
              }
            }
          });
        }
        tombstones += affectedFeeds.length;
      }
      audits.push({
        organizationId: context.organizationId,
        consentRecordId,
        event: {
          eventId: auditId,
          eventType: "recusal_changed",
          actorMemberId: context.memberId,
          actorClientId: context.clientId,
          tokenJti: context.tokenJti,
          boardId: request.boardId,
          entityType: request.objectType,
          entityId: request.objectId,
          origin: "mcp",
          schemaVersion: 1,
          details: { request, exclusionId, invalidatedStages, tombstones }
        }
      });
      return {
        value: {
          exclusionId,
          boardId: request.boardId,
          objectType: request.objectType,
          objectId: request.objectId,
          memberId: request.memberId,
          state: request.operation === "add" ? "excluded" : "lifted",
          invalidatedStages,
          tombstones
        },
        auditEvents: audits,
        finalizeAfterAudit: async (finalClient: PoolClient) => {
          await finalClient.query("select boardagent_apply_record_recusal($1,$2,$3)", [
            consentRecordId,
            exclusionId,
            auditId
          ]);
        }
      };
    },
    { exposeConfirmedProjectionToAct: true, appendConsentBeforeAct: true }
  );
}
