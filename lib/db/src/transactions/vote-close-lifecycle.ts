import type { PoolClient } from "pg";

import { certificatePublicIdBytes, certificatePublicIdSha256 } from "@boardagent/audit";
import { Sha256HexSchema, UuidV7Schema, safeHashEqual } from "@boardagent/contracts";

import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import {
  initiateVoteCloseInTransaction,
  prepareVoteCloseInTransaction,
  type PreparedVoteClose,
  type VoteCloseDraftResult
} from "./vote-close.js";

export interface VoteCloseLifecycleAction {
  readonly voteId: string;
  readonly expectedPackageSha256: string;
  readonly idempotencyKey: string;
}

export interface VoteCloseStageMaterial {
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly certificatePublicId: string;
  readonly closeConsentRecordId: string;
  readonly closingAuditEventId: string;
}

export interface PreparedVoteCloseLifecycleAction extends PreparedVoteClose {
  readonly actionCode: "close_vote";
  readonly targetType: "vote";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.vote-close-consent.v1";
}

export interface VoteCloseLifecycleStageInput {
  readonly action: VoteCloseLifecycleAction;
  readonly material: VoteCloseStageMaterial;
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

export interface StagedVoteCloseLifecycleAction extends StagedAction {
  readonly actionCode: "close_vote";
  readonly boardId: string;
  readonly targetType: "vote";
  readonly targetId: string;
}

export interface VoteCloseLifecycleConfirmationInput {
  readonly action: VoteCloseLifecycleAction;
  readonly confirmation: Omit<ConfirmStagedActionInput, "consentRecordId">;
  readonly idempotencyRecordId: string;
}

interface PersistedStageMaterialRow {
  readonly outcome_id: string;
  readonly certificate_id: string;
  readonly certificate_public_id: Buffer;
  readonly certificate_public_id_sha256: Buffer;
  readonly signing_key_id: string;
  readonly close_consent_record_id: string;
  readonly closing_audit_event_id: string;
  readonly expected_tally_sha256: Buffer;
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

async function prepareInternal(
  client: PoolClient,
  action: VoteCloseLifecycleAction,
  material: VoteCloseStageMaterial
): Promise<PreparedVoteCloseLifecycleAction> {
  idempotencyKey(action.idempotencyKey);
  const prepared = await prepareVoteCloseInTransaction(client, {
    voteId: UuidV7Schema.parse(action.voteId),
    expectedPackageSha256: Sha256HexSchema.parse(action.expectedPackageSha256),
    outcomeId: UuidV7Schema.parse(material.outcomeId),
    certificateId: UuidV7Schema.parse(material.certificateId),
    certificatePublicId: material.certificatePublicId,
    closeConsentRecordId: UuidV7Schema.parse(material.closeConsentRecordId),
    closingAuditEventId: UuidV7Schema.parse(material.closingAuditEventId)
  });
  return {
    ...prepared,
    actionCode: "close_vote",
    targetType: "vote",
    targetId: prepared.voteId,
    canonicalSchema: "boardagent.vote-close-consent.v1"
  };
}

export async function prepareVoteCloseLifecycleActionInTransaction(
  client: PoolClient,
  input: {
    readonly action: VoteCloseLifecycleAction;
    readonly material: VoteCloseStageMaterial;
  }
): Promise<PreparedVoteCloseLifecycleAction> {
  return prepareInternal(client, input.action, input.material);
}

export async function stageVoteCloseLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteCloseLifecycleStageInput
): Promise<StagedVoteCloseLifecycleAction> {
  const prepared = await prepareInternal(client, input.action, input.material);
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
      // Preparation locked and recomputed the exact vote, package, tally, clock and key.
    }
  );
  const publicId = certificatePublicIdBytes(input.material.certificatePublicId);
  const publicIdSha256 = certificatePublicIdSha256(input.material.certificatePublicId);
  if (!safeHashEqual(publicIdSha256, prepared.certificatePublicIdSha256)) {
    throw new Error("prepared certificate public identifier changed before persistence");
  }
  await client.query(
    `insert into vote_close_stage_material(
       stage_id,organization_id,board_id,vote_id,outcome_id,certificate_id,
       certificate_public_id,certificate_public_id_sha256,signing_key_id,
       close_consent_record_id,closing_audit_event_id,expected_tally_sha256
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [
      staged.stageId,
      prepared.organizationId,
      prepared.boardId,
      prepared.voteId,
      prepared.outcomeId,
      prepared.certificateId,
      publicId,
      Buffer.from(publicIdSha256, "hex"),
      prepared.signingKeyId,
      UuidV7Schema.parse(input.material.closeConsentRecordId),
      UuidV7Schema.parse(input.material.closingAuditEventId),
      Buffer.from(prepared.expectedTallySha256, "hex")
    ]
  );
  return {
    ...staged,
    actionCode: prepared.actionCode,
    boardId: prepared.boardId,
    targetType: prepared.targetType,
    targetId: prepared.targetId
  };
}

async function readStageMaterial(
  client: PoolClient,
  stageId: string
): Promise<
  VoteCloseStageMaterial & { readonly signingKeyId: string; readonly expectedTallySha256: string }
> {
  const result = await client.query<PersistedStageMaterialRow>(
    `select outcome_id,certificate_id,certificate_public_id,
            certificate_public_id_sha256,signing_key_id,close_consent_record_id,
            closing_audit_event_id,expected_tally_sha256
       from vote_close_stage_material where stage_id=$1`,
    [UuidV7Schema.parse(stageId)]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new Error("vote close stage material is unavailable");
  }
  const certificatePublicId = row.certificate_public_id.toString("base64url");
  const certificatePublicIdHash = certificatePublicIdSha256(certificatePublicId);
  if (!safeHashEqual(certificatePublicIdHash, row.certificate_public_id_sha256.toString("hex"))) {
    throw new Error("vote close stage public identifier hash is invalid");
  }
  return {
    outcomeId: UuidV7Schema.parse(row.outcome_id),
    certificateId: UuidV7Schema.parse(row.certificate_id),
    certificatePublicId,
    closeConsentRecordId: UuidV7Schema.parse(row.close_consent_record_id),
    closingAuditEventId: UuidV7Schema.parse(row.closing_audit_event_id),
    signingKeyId: UuidV7Schema.parse(row.signing_key_id),
    expectedTallySha256: Sha256HexSchema.parse(row.expected_tally_sha256.toString("hex"))
  };
}

export async function confirmVoteCloseLifecycleActionInTransaction(
  client: PoolClient,
  input: VoteCloseLifecycleConfirmationInput
): Promise<StagedActionResolution<VoteCloseDraftResult>> {
  let prepared: PreparedVoteCloseLifecycleAction | undefined;
  const material = await readStageMaterial(client, input.confirmation.stageId);
  return confirmStagedActionInTransaction(
    client,
    { ...input.confirmation, consentRecordId: material.closeConsentRecordId },
    async (requestClient) => {
      prepared = await prepareInternal(requestClient, input.action, material);
      if (
        prepared.signingKeyId !== material.signingKeyId ||
        !safeHashEqual(prepared.expectedTallySha256, material.expectedTallySha256)
      ) {
        throw new Error("vote close key or tally changed after staging");
      }
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared || consentRecordId !== material.closeConsentRecordId) {
        throw new Error("confirmed vote close preparation is unavailable");
      }
      const draft = await initiateVoteCloseInTransaction(requestClient, {
        organizationId: prepared.organizationId,
        voteId: prepared.voteId,
        outcomeId: material.outcomeId,
        certificateId: material.certificateId,
        certificatePublicId: material.certificatePublicId,
        expectedPackageSha256: prepared.packageSha256,
        expectedTallySha256: material.expectedTallySha256,
        signingKeyId: material.signingKeyId,
        consentRecordId,
        closingAuditEventId: material.closingAuditEventId,
        idempotencyRecordId: UuidV7Schema.parse(input.idempotencyRecordId),
        idempotencyKey: input.action.idempotencyKey
      });
      return {
        value: draft,
        auditEvents: [],
        preappendedAuditSequences: draft.replayed
          ? []
          : [BigInt(draft.payload.closingAuditSequence)]
      };
    },
    { appendConsentBeforeAct: true, exposeConfirmedProjectionToAct: true }
  );
}
