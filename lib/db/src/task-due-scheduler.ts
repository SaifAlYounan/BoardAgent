import type { PoolClient } from "pg";

import { Rfc3339UtcSchema, Sha256HexSchema, UuidV7Schema } from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./transactions/audit.js";

export interface ProjectDueTasksInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly through: string;
  readonly newId: () => string;
  readonly limit?: number;
}

export interface TaskDueProjection {
  readonly taskId: string;
  readonly ownerMemberId: string;
  readonly taskVersion: bigint;
  readonly feedSequence: bigint;
}

type DueTaskClass = "minutes_action_item" | "standalone_task";

interface TaskDueCandidateRow {
  readonly task_id: string;
  readonly owner_member_id: string;
  readonly row_version: string;
  readonly due_at: string;
  readonly task_sha256: string;
  readonly entitlement_generation: string;
}

interface TaskDueCommitRow {
  readonly task_id: string;
  readonly feed_sequence: string;
}

function boundedLimit(value: number | undefined): number {
  const limit = value ?? 100;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new RangeError("task due batch limit must be an integer from 1 through 1000");
  }
  return limit;
}

function safePositiveInteger(value: bigint, field: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${field} must fit a positive safe integer`);
  }
  return parsed;
}

/**
 * Lock a bounded board-scoped due set, then atomically append each contentless
 * notice receipt and its recipient feed projection. Task state is never mutated.
 * Minutes-linked action items and standalone tasks use separate typed scans so
 * one queue cannot consume the other queue's work.
 */
async function projectDueTaskClassInTransaction(
  client: PoolClient,
  rawInput: ProjectDueTasksInput,
  taskClass: DueTaskClass
): Promise<readonly TaskDueProjection[]> {
  const organizationId = UuidV7Schema.parse(rawInput.organizationId);
  const boardId = UuidV7Schema.parse(rawInput.boardId);
  const through = Rfc3339UtcSchema.parse(rawInput.through);
  const limit = boundedLimit(rawInput.limit);
  const candidates = await client.query<TaskDueCandidateRow>(
    `select task_id,owner_member_id,row_version::text,due_at,task_sha256,
            entitlement_generation::text
       from public.boardagent_task_due_candidates($1,$2,$3,$4,$5)`,
    [organizationId, boardId, through, limit, taskClass]
  );
  const projections: TaskDueProjection[] = [];

  for (const row of candidates.rows) {
    const taskId = UuidV7Schema.parse(row.task_id);
    const ownerMemberId = UuidV7Schema.parse(row.owner_member_id);
    const taskVersion = BigInt(row.row_version);
    const entitlementGeneration = BigInt(row.entitlement_generation);
    const dueAt = Rfc3339UtcSchema.parse(row.due_at);
    const taskSha256 = Sha256HexSchema.parse(row.task_sha256);
    safePositiveInteger(taskVersion, "task version");
    safePositiveInteger(entitlementGeneration, "task owner entitlement generation");

    const auditEventId = UuidV7Schema.parse(rawInput.newId());
    const noticeId = UuidV7Schema.parse(rawInput.newId());
    const feedId = UuidV7Schema.parse(rawInput.newId());
    if (new Set([auditEventId, noticeId, feedId]).size !== 3) {
      throw new Error("task due projection identifiers must be unique");
    }
    const [auditEvent] = await appendAuditEventsInTransaction(client, [
      {
        organizationId,
        objectVersion: taskVersion,
        event: {
          eventId: auditEventId,
          eventType: "notice_delivered",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "task",
          entityId: taskId,
          boardId,
          origin: "worker",
          details: {
            meaning: "committed_recipient_feed_handoff",
            recipientMemberId: ownerMemberId,
            noticeType: "task_due",
            dueAt,
            taskSha256
          },
          schemaVersion: 1
        }
      }
    ]);
    if (!auditEvent || auditEvent.eventId !== auditEventId) {
      throw new Error("task due audit append returned an invalid projection");
    }

    const committed = await client.query<TaskDueCommitRow>(
      `select task_id,feed_sequence::text
         from public.boardagent_commit_task_due_projection($1,$2,$3,$4,$5,$6,$7,$8)`,
      [organizationId, boardId, taskId, through, noticeId, feedId, auditEventId, taskClass]
    );
    const result = committed.rows[0];
    if (!result || committed.rows.length !== 1 || result.task_id !== taskId) {
      throw new Error("locked task due projection became unavailable");
    }
    const feedSequence = BigInt(result.feed_sequence);
    if (feedSequence < 1n) throw new Error("task due feed sequence is invalid");
    projections.push({ taskId, ownerMemberId, taskVersion, feedSequence });
  }

  return projections;
}

/** Project due reminders for standalone tasks created outside a minutes action manifest. */
export async function projectDueTasksInTransaction(
  client: PoolClient,
  rawInput: ProjectDueTasksInput
): Promise<readonly TaskDueProjection[]> {
  return projectDueTaskClassInTransaction(client, rawInput, "standalone_task");
}

/** Project due reminders only for activated, minutes-linked action items. */
export async function projectDueActionItemsInTransaction(
  client: PoolClient,
  rawInput: ProjectDueTasksInput
): Promise<readonly TaskDueProjection[]> {
  return projectDueTaskClassInTransaction(client, rawInput, "minutes_action_item");
}
