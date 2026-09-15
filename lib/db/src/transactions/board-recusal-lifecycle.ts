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
import { manageVoteRecusalInTransaction } from "./recusals.js";
import {
  prepareBoardVoteRecusalInTransaction,
  generatedVoteRecusalDispositions,
  type PreparedVoteRecusalInternal
} from "./vote-recusal-lifecycle.js";

export interface BoardRecusalAction {
  readonly boardId: string;
  readonly memberId: string;
  readonly operation: "add" | "lift";
  readonly reason: string;
  readonly idempotencyKey: string;
}

export async function prepareBoardRecusalInTransaction(
  client: PoolClient,
  input: BoardRecusalAction
) {
  const request = {
    boardId: UuidV7Schema.parse(input.boardId),
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
    throw new Error("board recusal is unavailable");
  const snapshot = await client.query<{ payload: JsonValue }>(
    "select boardagent_prepare_board_recusal($1::jsonb) as payload",
    [JSON.stringify(request)]
  );
  const payload = snapshot.rows[0]?.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("board recusal is unavailable");
  const manifest = (payload as { affectedVotes?: JsonValue }).affectedVotes;
  if (!Array.isArray(manifest)) throw new Error("board recusal vote manifest is unavailable");
  const affectedVotes = manifest.map((entry) => {
    if (
      !entry ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      !("voteId" in entry) ||
      typeof entry.voteId !== "string"
    )
      throw new Error("board recusal vote manifest is invalid");
    return { voteId: UuidV7Schema.parse(entry.voteId) };
  });
  return {
    affectedVotes,
    actionCode: "manage_recusal" as const,
    targetType: "board" as const,
    targetId: request.boardId,
    boardId: request.boardId,
    canonicalSchema: "boardagent.board-recusal-consent.v1",
    canonicalPayload: payload,
    payloadSha256: canonicalSha256(payload),
    packageSha256: null,
    request
  };
}

export async function stageBoardRecusalInTransaction(
  client: PoolClient,
  input: {
    readonly action: BoardRecusalAction;
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
  const prepared = await prepareBoardRecusalInTransaction(client, input.action);
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

export async function confirmBoardRecusalInTransaction(
  client: PoolClient,
  input: {
    readonly action: BoardRecusalAction;
    readonly confirmation: ConfirmStagedActionInput;
    readonly newId: () => string;
  }
) {
  let prepared: Awaited<ReturnType<typeof prepareBoardRecusalInTransaction>> | undefined;
  let voteEffects: PreparedVoteRecusalInternal[] = [];
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
      prepared = await prepareBoardRecusalInTransaction(c, input.action);
      voteEffects = [];
      for (const vote of prepared.affectedVotes) {
        voteEffects.push(
          await prepareBoardVoteRecusalInTransaction(
            c,
            { ...input.action, voteId: vote.voteId },
            input.confirmation.stageId
          )
        );
      }
      if (prepared.request.operation === "add") {
        const context = await readRequestContext(c);
        affectedStages = (
          await c.query<{ id: string }>(
            `select id from action_stages where organization_id=$1 and board_id=$2
        and (actor_member_id=$3 or acting_for_member_id=$3) and state='active' and id<>$4
        and not(target_type='vote' and target_id=any($5::uuid[])) order by id for update`,
            [
              context.organizationId,
              prepared.boardId,
              prepared.request.memberId,
              input.confirmation.stageId,
              prepared.affectedVotes.map((v) => v.voteId)
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
         and not(object_type='vote' and object_id=any($4::uuid[])) order by feed_sequence,id for update`,
            [
              context.organizationId,
              prepared.boardId,
              prepared.request.memberId,
              prepared.affectedVotes.map((v) => v.voteId)
            ]
          )
        ).rows;
      }
      return { payloadSha256: prepared.payloadSha256, packageSha256: null };
    },
    async (c, consentRecordId) => {
      if (!prepared) throw new Error("board recusal preparation is unavailable");
      const context = await readRequestContext(c);
      const request = prepared.request;
      const exclusionId = UuidV7Schema.parse(input.newId());
      const auditId = UuidV7Schema.parse(input.newId());
      const audits: AuditAppendInput[] = [];
      const preappendedAuditSequences: bigint[] = [];
      for (const effect of voteEffects) {
        const generated = generatedVoteRecusalDispositions(effect, input.newId);
        const result = await manageVoteRecusalInTransaction(c, {
          ...generated,
          organizationId: context.organizationId,
          voteId: effect.voteId,
          memberId: request.memberId,
          decisionPackageSha256: effect.packageSha256,
          state: request.operation === "add" ? "excluded" : "lifted",
          reason: request.reason,
          consentRecordId,
          idempotencyKey: `board-recusal:${consentRecordId}:${effect.voteId}`,
          boardCause: { exclusionId, payloadSha256: prepared.payloadSha256 }
        });
        if (!result.replayed)
          preappendedAuditSequences.push(...result.auditEvents.map((e) => e.sequence));
      }
      let invalidatedStages = voteEffects.reduce(
        (sum, effect) => sum + effect.affectedStageCount,
        0
      );
      let tombstones = voteEffects.reduce((sum, effect) => sum + effect.removedPendingFeedCount, 0);
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
              details: { reason: "board_recusal", memberId: request.memberId, exclusionId }
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
                reason: "board_recusal",
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
          entityType: "board",
          entityId: request.boardId,
          origin: "mcp",
          schemaVersion: 1,
          details: { request, exclusionId, invalidatedStages, tombstones }
        }
      });
      return {
        value: {
          exclusionId,
          boardId: request.boardId,
          memberId: request.memberId,
          state: request.operation === "add" ? "excluded" : "lifted",
          invalidatedStages,
          tombstones
        },
        auditEvents: audits,
        preappendedAuditSequences,
        finalizeAfterAudit: async (finalClient: PoolClient) => {
          await finalClient.query("select boardagent_apply_board_recusal($1,$2,$3)", [
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
