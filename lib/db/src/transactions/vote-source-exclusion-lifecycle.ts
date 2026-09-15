import type { PoolClient } from "pg";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  type JsonValue
} from "@boardagent/contracts";
import { voteSourceExclusionConsentHash } from "@boardagent/domain";

import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import {
  excludePendingVoteSourceInTransaction,
  type ExcludePendingVoteSourceResult
} from "./source-exclusions.js";
import { readRequestContext } from "./request-context.js";

export class VoteSourceExclusionLifecycleTransactionError extends Error {
  public constructor(
    public readonly code: "vote_source_exclusion_unavailable" | "vote_source_exclusion_invalid",
    message: string
  ) {
    super(message);
    this.name = "VoteSourceExclusionLifecycleTransactionError";
  }
}

export interface VoteSourceExclusionLifecycleAction {
  readonly voteId: string;
  readonly sourceType: "management_submission" | "document" | "question_cutoff";
  readonly sourceId: string;
  readonly sourceVersion: number;
  readonly sourceSha256: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

export interface PreparedVoteSourceExclusionLifecycleAction {
  readonly actionCode: "exclude_pending_vote_source";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.vote-source-exclusion-consent.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
  readonly voteId: string;
  readonly voteTitle: string;
  readonly resolutionText: string;
  readonly resolutionSha256: string;
  readonly decisionPackage: JsonValue;
  readonly causeId: string;
  readonly sourceType: VoteSourceExclusionLifecycleAction["sourceType"];
  readonly sourceId: string;
  readonly sourceVersion: number;
  readonly sourceSha256: string;
  readonly reason: string;
}

export interface VoteSourceExclusionLifecycleStageInput {
  readonly action: VoteSourceExclusionLifecycleAction;
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

export interface StagedVoteSourceExclusionLifecycleAction extends StagedAction {
  readonly actionCode: "exclude_pending_vote_source";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
}

export interface VoteSourceExclusionGeneratedIds {
  readonly dispositionId: string;
  readonly idempotencyRecordId: string;
  readonly auditEventId: string;
}

export interface VoteSourceExclusionLifecycleConfirmationInput {
  readonly action: VoteSourceExclusionLifecycleAction;
  readonly generatedIds: VoteSourceExclusionGeneratedIds;
  readonly confirmation: ConfirmStagedActionInput;
}

interface VoteRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_id: string;
  readonly vote_title: string;
  readonly vote_state: string;
  readonly package_sha256: Buffer;
  readonly decision_package: JsonValue;
  readonly resolution_text: string;
  readonly resolution_sha256: Buffer;
  readonly actor_ready: boolean;
}

interface PendingCauseRow {
  readonly cause_id: string;
  readonly source_class: VoteSourceExclusionLifecycleAction["sourceType"];
  readonly source_id: string;
  readonly source_version: number;
  readonly source_sha256: Buffer;
}

interface PreparedInternal extends PreparedVoteSourceExclusionLifecycleAction {
  readonly organizationId: string;
}

function unavailable(message = "pending vote source is unavailable"): never {
  throw new VoteSourceExclusionLifecycleTransactionError(
    "vote_source_exclusion_unavailable",
    message
  );
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

async function prepareInternal(
  client: PoolClient,
  action: VoteSourceExclusionLifecycleAction
): Promise<PreparedInternal> {
  const context = await readRequestContext(client);
  const voteId = UuidV7Schema.parse(action.voteId);
  const sourceId = UuidV7Schema.parse(action.sourceId);
  const sourceSha256 = Sha256HexSchema.parse(action.sourceSha256);
  const reason = canonicalText(action.reason);
  idempotencyKey(action.idempotencyKey);
  if (!Number.isSafeInteger(action.sourceVersion) || action.sourceVersion < 1) {
    throw new VoteSourceExclusionLifecycleTransactionError(
      "vote_source_exclusion_invalid",
      "pending vote source version must be a positive safe integer"
    );
  }
  if (reason.trim().length < 1 || reason.length > 65_536) {
    throw new RangeError("source-exclusion reason must contain 1 through 65536 characters");
  }
  const rootResult = await client.query<VoteRootRow>(
    `select vote.organization_id,vote.board_id,vote.id as vote_id,
            vote.title as vote_title,vote.state as vote_state,
            package.package_sha256,
            convert_from(package.canonical_payload,'UTF8')::jsonb as decision_package,
            resolution.canonical_text as resolution_text,
            resolution.canonical_sha256 as resolution_sha256,
            boardagent_vote_actor_ready(vote.board_id) as actor_ready
       from votes as vote
       join decision_packages as package
         on package.id=vote.current_decision_package_id and package.vote_id=vote.id
       join resolution_versions as resolution on resolution.id=vote.current_resolution_version_id
      where vote.id=$1
        and vote.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(vote.board_id)
        and not boardagent_member_vote_recused(vote.id,
          boardagent_context_uuid('boardagent.member_id'))
      for update of vote`,
    [voteId]
  );
  const root = rootResult.rows[0];
  if (
    !root ||
    rootResult.rows.length !== 1 ||
    root.organization_id !== context.organizationId ||
    !root.actor_ready ||
    root.vote_state !== "source_update_pending"
  ) {
    unavailable();
  }
  const visibility = await client.query<{ recused: boolean }>(
    `select boardagent_member_vote_recused($1,
       boardagent_context_uuid('boardagent.member_id')) as recused`,
    [voteId]
  );
  if (visibility.rows[0]?.recused !== false) unavailable();
  canonicalJson(root.decision_package);
  const causeResult = await client.query<PendingCauseRow>(
    "select * from boardagent_lock_vote_source_causes($1)",
    [voteId]
  );
  const matching = causeResult.rows.filter(
    (row) =>
      row.source_class === action.sourceType &&
      row.source_id === sourceId &&
      row.source_version === action.sourceVersion &&
      safeHashEqual(row.source_sha256.toString("hex"), sourceSha256)
  );
  const cause = matching[0];
  if (!cause || matching.length !== 1) unavailable("exact pending vote source is unavailable");
  const packageSha256 = Sha256HexSchema.parse(root.package_sha256.toString("hex"));
  const canonicalPayload: JsonValue = {
    schemaVersion: "boardagent.vote-source-exclusion-consent.v1",
    voteId,
    causeId: cause.cause_id,
    sourceClass: action.sourceType,
    sourceId,
    sourceVersion: action.sourceVersion,
    sourceSha256,
    reason,
    packageSha256
  };
  const payloadSha256 = canonicalSha256(canonicalPayload);
  if (
    payloadSha256 !==
    voteSourceExclusionConsentHash({
      voteId,
      causeId: cause.cause_id,
      sourceClass: action.sourceType,
      sourceId,
      sourceVersion: action.sourceVersion,
      sourceSha256,
      reason,
      packageSha256
    })
  ) {
    throw new Error("vote source-exclusion consent payload construction drifted");
  }
  return {
    actionCode: "exclude_pending_vote_source",
    boardId: root.board_id,
    targetType: "vote",
    targetId: voteId,
    canonicalSchema: "boardagent.vote-source-exclusion-consent.v1",
    canonicalPayload,
    payloadSha256,
    packageSha256,
    voteId,
    voteTitle: root.vote_title,
    resolutionText: root.resolution_text,
    resolutionSha256: Sha256HexSchema.parse(root.resolution_sha256.toString("hex")),
    decisionPackage: root.decision_package,
    causeId: UuidV7Schema.parse(cause.cause_id),
    sourceType: action.sourceType,
    sourceId,
    sourceVersion: action.sourceVersion,
    sourceSha256,
    reason,
    organizationId: root.organization_id
  };
}

export async function prepareVoteSourceExclusionLifecycleActionInTransaction(
  client: PoolClient,
  action: VoteSourceExclusionLifecycleAction
): Promise<PreparedVoteSourceExclusionLifecycleAction> {
  const prepared = await prepareInternal(client, action);
  const { organizationId: _organizationId, ...view } = prepared;
  return view;
}

export async function stageVoteSourceExclusionLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteSourceExclusionLifecycleStageInput
): Promise<StagedVoteSourceExclusionLifecycleAction> {
  const prepared = await prepareInternal(client, input.action);
  const staged = await stageActionInTransaction(
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
      packageSha256: prepared.packageSha256,
      originalName: prepared.actionCode
    },
    async () => {
      // Preparation locked the vote and every exact pending source cause.
    }
  );
  return {
    ...staged,
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetType: prepared.targetType,
    targetId: prepared.targetId
  };
}

export async function confirmVoteSourceExclusionLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteSourceExclusionLifecycleConfirmationInput
): Promise<StagedActionResolution<ExcludePendingVoteSourceResult>> {
  let prepared: PreparedInternal | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareInternal(requestClient, input.action);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("vote source-exclusion preparation is unavailable");
      const result = await excludePendingVoteSourceInTransaction(requestClient, {
        organizationId: prepared.organizationId,
        voteId: prepared.voteId,
        causeId: prepared.causeId,
        decisionPackageSha256: prepared.packageSha256,
        reason: prepared.reason,
        consentRecordId,
        dispositionId: UuidV7Schema.parse(input.generatedIds.dispositionId),
        idempotencyRecordId: UuidV7Schema.parse(input.generatedIds.idempotencyRecordId),
        idempotencyKey: input.action.idempotencyKey,
        auditEventId: UuidV7Schema.parse(input.generatedIds.auditEventId)
      });
      return {
        value: result,
        auditEvents: [],
        preappendedAuditSequences: result.replayed
          ? []
          : result.auditEvents.map(({ sequence }) => sequence)
      };
    },
    { appendConsentBeforeAct: true, exposeConfirmedProjectionToAct: true }
  );
}
