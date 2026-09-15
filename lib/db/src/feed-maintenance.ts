import { createHash } from "node:crypto";

import type { PoolClient } from "pg";
import { z } from "zod";

import {
  PendingActionDeltaSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalJsonFromText,
  canonicalSha256,
  safeHashEqual,
  sha256Hex
} from "@boardagent/contracts";

const PositiveBigintTextSchema = z.string().regex(/^[1-9]\d*$/u);
const CountTextSchema = z.string().regex(/^(?:0|[1-9]\d*)$/u);

const BootstrapOnboardingFeedSchema = z
  .object({
    schemaVersion: z.literal("boardagent.pending-action.v1"),
    actionType: z.literal("complete_onboarding"),
    memberId: UuidV7Schema,
    boardId: UuidV7Schema,
    objectType: z.literal("member"),
    objectId: UuidV7Schema,
    objectVersion: PositiveBigintTextSchema
  })
  .strict();

interface FeedPayloadRow {
  readonly feed_id: string;
  readonly board_id: string;
  readonly member_id: string;
  readonly action_type: string;
  readonly object_type: string;
  readonly object_id: string;
  readonly object_version: string;
  readonly entitlement_generation: string;
  readonly feed_sequence: string;
  readonly canonical_payload: Buffer;
  readonly payload_sha256: string;
}

interface FeedReconcileCandidateRow extends FeedPayloadRow {
  readonly prior_entitlement_generation: string;
  readonly current_entitlement_generation: string;
  readonly audit_event_id: string;
  readonly existing_tombstones: string;
  readonly audit_binding_valid: boolean;
}

const RelationSummarySchema = z
  .object({
    checkedFeedRows: z.number().int().nonnegative().safe(),
    checkedTombstoneRows: z.number().int().nonnegative().safe(),
    membershipStalePendingRows: z.number().int().nonnegative().safe(),
    noticeBindingMismatches: z.number().int().nonnegative().safe(),
    auditBindingMismatches: z.number().int().nonnegative().safe(),
    tombstoneBindingMismatches: z.number().int().nonnegative().safe(),
    duplicateRemovalTombstones: z.number().int().nonnegative().safe(),
    relationMismatches: z.number().int().nonnegative().safe()
  })
  .strict();

type PayloadIssue = "payload_hash_mismatch" | "payload_noncanonical" | "payload_binding_mismatch";

interface PayloadInspection {
  readonly actualSha256: string;
  readonly hashMismatch: boolean;
  readonly canonicalMismatch: boolean;
  readonly bindingMismatch: boolean;
}

export class FeedProjectionConsistencyError extends Error {
  public constructor(public readonly issueClass: PayloadIssue | "relation_mismatch") {
    super(issueClass);
    this.name = "FeedProjectionConsistencyError";
  }
}

export interface FeedReconciliationInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly memberId: string;
  readonly newId: () => string;
  readonly limit?: number;
}

export interface FeedReconciliationResult {
  readonly reconciled: number;
  readonly hasMore: boolean;
}

export interface FeedConsistencyResult {
  readonly valid: boolean;
  readonly checkedFeedRows: number;
  readonly checkedTombstoneRows: number;
  readonly payloadHashMismatches: number;
  readonly payloadCanonicalMismatches: number;
  readonly payloadBindingMismatches: number;
  readonly membershipStalePendingRows: number;
  readonly noticeBindingMismatches: number;
  readonly auditBindingMismatches: number;
  readonly tombstoneBindingMismatches: number;
  readonly duplicateRemovalTombstones: number;
  readonly relationMismatches: number;
  readonly evidenceSha256: string;
}

function boundedLimit(raw: number | undefined): number {
  const limit = raw ?? 100;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
    throw new RangeError("feed maintenance limit must be an integer from 1 through 1000");
  }
  return limit;
}

function parsePositiveBigint(value: string, field: string): bigint {
  PositiveBigintTextSchema.parse(value);
  const parsed = BigInt(value);
  if (parsed < 1n) throw new Error(`${field} must be positive`);
  return parsed;
}

function parseSafePositive(value: string, field: string): number {
  const parsed = Number(parsePositiveBigint(value, field));
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${field} must fit a positive safe integer`);
  }
  return parsed;
}

function payloadBindingValid(row: FeedPayloadRow, parsed: unknown): boolean {
  if (row.action_type === "complete_onboarding") {
    const legacy = BootstrapOnboardingFeedSchema.safeParse(parsed);
    return (
      legacy.success &&
      row.object_type === "member" &&
      legacy.data.memberId === row.member_id &&
      legacy.data.memberId === legacy.data.objectId &&
      legacy.data.objectId === row.object_id &&
      legacy.data.boardId === row.board_id &&
      legacy.data.objectVersion === row.object_version
    );
  }

  const delta = PendingActionDeltaSchema.safeParse(parsed);
  if (!delta.success) return false;
  let objectVersion: number;
  let entitlementGeneration: number;
  try {
    objectVersion = parseSafePositive(row.object_version, "feed object version");
    entitlementGeneration = parseSafePositive(
      row.entitlement_generation,
      "feed entitlement generation"
    );
  } catch {
    return false;
  }
  return (
    delta.data.sequence === row.feed_sequence &&
    delta.data.objectType === row.object_type &&
    delta.data.objectId === row.object_id &&
    delta.data.objectVersion === objectVersion &&
    delta.data.entitlementGeneration === entitlementGeneration
  );
}

function inspectPayload(row: FeedPayloadRow): PayloadInspection {
  UuidV7Schema.parse(row.feed_id);
  UuidV7Schema.parse(row.board_id);
  UuidV7Schema.parse(row.member_id);
  UuidV7Schema.parse(row.object_id);
  PositiveBigintTextSchema.parse(row.object_version);
  PositiveBigintTextSchema.parse(row.entitlement_generation);
  PositiveBigintTextSchema.parse(row.feed_sequence);
  const storedSha256 = Sha256HexSchema.parse(row.payload_sha256);
  const actualSha256 = sha256Hex(row.canonical_payload);
  const hashMismatch = !safeHashEqual(storedSha256, actualSha256);
  let canonicalMismatch = false;
  let bindingMismatch = false;
  try {
    const canonical = canonicalJsonFromText(row.canonical_payload);
    canonicalMismatch = !Buffer.from(canonical, "utf8").equals(row.canonical_payload);
    if (!canonicalMismatch) {
      bindingMismatch = !payloadBindingValid(row, JSON.parse(canonical) as unknown);
    }
  } catch {
    canonicalMismatch = true;
  }
  return { actualSha256, hashMismatch, canonicalMismatch, bindingMismatch };
}

function firstPayloadIssue(inspection: PayloadInspection): PayloadIssue | null {
  if (inspection.hashMismatch) return "payload_hash_mismatch";
  if (inspection.canonicalMismatch) return "payload_noncanonical";
  if (inspection.bindingMismatch) return "payload_binding_mismatch";
  return null;
}

/**
 * Append only safe removal tombstones for pending entries bound to a no-longer-current
 * member/board entitlement generation. Structural drift aborts the whole transaction.
 */
export async function reconcileFeedEntitlementsInTransaction(
  client: PoolClient,
  rawInput: FeedReconciliationInput
): Promise<FeedReconciliationResult> {
  const organizationId = UuidV7Schema.parse(rawInput.organizationId);
  const boardId = UuidV7Schema.parse(rawInput.boardId);
  const memberId = UuidV7Schema.parse(rawInput.memberId);
  const limit = boundedLimit(rawInput.limit);
  const candidates = await client.query<FeedReconcileCandidateRow>(
    `select feed_id,board_id,member_id,action_type,object_type,object_id,object_version::text,
            prior_entitlement_generation::text,current_entitlement_generation::text,
            prior_entitlement_generation::text as entitlement_generation,
            feed_sequence::text,canonical_payload,payload_sha256,audit_event_id,
            existing_tombstones::text,audit_binding_valid
       from public.boardagent_feed_reconcile_candidates($1,$2,$3,$4)`,
    [organizationId, boardId, memberId, limit]
  );

  const prepared = candidates.rows.map((row) => {
    const inspection = inspectPayload(row);
    const issue = firstPayloadIssue(inspection);
    if (issue) throw new FeedProjectionConsistencyError(issue);
    if (BigInt(CountTextSchema.parse(row.existing_tombstones)) !== 0n || !row.audit_binding_valid) {
      throw new FeedProjectionConsistencyError("relation_mismatch");
    }
    const priorEntitlementGeneration = parsePositiveBigint(
      row.prior_entitlement_generation,
      "prior entitlement generation"
    );
    const currentEntitlementGeneration = parsePositiveBigint(
      row.current_entitlement_generation,
      "current entitlement generation"
    );
    const feedSequence = parsePositiveBigint(row.feed_sequence, "feed sequence");
    const tombstoneId = UuidV7Schema.parse(rawInput.newId());
    const tombstoneSha256 = canonicalSha256({
      schemaVersion: "boardagent.feed-tombstone.v1",
      source: "feed_reconcile",
      boardId,
      memberId,
      removedFeedId: row.feed_id,
      objectType: row.object_type,
      objectId: row.object_id,
      priorEntitlementGeneration: priorEntitlementGeneration.toString(10),
      entitlementGeneration: currentEntitlementGeneration.toString(10),
      feedSequence: feedSequence.toString(10),
      reasonClass: "revoked"
    });
    return { row, tombstoneId, tombstoneSha256 };
  });

  if (new Set(prepared.map(({ tombstoneId }) => tombstoneId)).size !== prepared.length) {
    throw new Error("feed reconciliation tombstone identifiers must be unique");
  }

  let reconciled = 0;
  for (const candidate of prepared) {
    const committed = await client.query<{ feed_id: string; tombstone_id: string }>(
      `select feed_id,tombstone_id
         from public.boardagent_commit_feed_revocation($1,$2,$3,$4,$5,$6)`,
      [
        organizationId,
        boardId,
        memberId,
        candidate.row.feed_id,
        candidate.tombstoneId,
        Buffer.from(candidate.tombstoneSha256, "hex")
      ]
    );
    const result = committed.rows[0];
    if (!result) continue;
    if (
      committed.rows.length !== 1 ||
      result.feed_id !== candidate.row.feed_id ||
      result.tombstone_id !== candidate.tombstoneId
    ) {
      throw new Error("feed revocation commit returned an invalid binding");
    }
    reconciled += 1;
  }
  return { reconciled, hasMore: candidates.rows.length === limit };
}

/** Read every projection in one caller-owned snapshot and return content-safe evidence only. */
export async function inspectFeedConsistencyInTransaction(
  client: PoolClient,
  rawOrganizationId: string
): Promise<FeedConsistencyResult> {
  const organizationId = UuidV7Schema.parse(rawOrganizationId);
  const batchLimit = 1_000;
  let afterId: string | null = null;
  let scanned = 0;
  let payloadHashMismatches = 0;
  let payloadCanonicalMismatches = 0;
  let payloadBindingMismatches = 0;
  const evidence = createHash("sha256");

  for (;;) {
    const batchRows: readonly FeedPayloadRow[] = (
      await client.query<FeedPayloadRow>(
        `select feed_id,board_id,member_id,action_type,object_type,object_id,object_version::text,
                entitlement_generation::text,feed_sequence::text,canonical_payload,payload_sha256
           from public.boardagent_feed_consistency_payloads($1,$2,$3)`,
        [organizationId, afterId, batchLimit]
      )
    ).rows;
    for (const row of batchRows) {
      const inspection = inspectPayload(row);
      if (inspection.hashMismatch) payloadHashMismatches += 1;
      if (inspection.canonicalMismatch) payloadCanonicalMismatches += 1;
      if (inspection.bindingMismatch) payloadBindingMismatches += 1;
      evidence.update(
        canonicalJson({
          feedRef: canonicalSha256({
            schemaVersion: "boardagent.feed-consistency-reference.v1",
            feedId: row.feed_id
          }),
          storedPayloadSha256: row.payload_sha256,
          actualPayloadSha256: inspection.actualSha256,
          hashMismatch: inspection.hashMismatch,
          canonicalMismatch: inspection.canonicalMismatch,
          bindingMismatch: inspection.bindingMismatch
        })
      );
      evidence.update("\n");
      afterId = row.feed_id;
      scanned += 1;
    }
    if (batchRows.length < batchLimit) break;
  }

  const relationsQuery = await client.query<{ result: unknown }>(
    "select public.boardagent_feed_consistency_relations($1) as result",
    [organizationId]
  );
  if (relationsQuery.rows.length !== 1) {
    throw new Error("feed consistency relation check returned an invalid shape");
  }
  const relations = RelationSummarySchema.parse(relationsQuery.rows[0]?.result);
  const scanCoverageMismatches = scanned === relations.checkedFeedRows ? 0 : 1;
  const relationMismatches = relations.relationMismatches + scanCoverageMismatches;
  const rowEvidenceSha256 = evidence.digest("hex");
  const evidenceSha256 = canonicalSha256({
    schemaVersion: "boardagent.feed-consistency-evidence.v1",
    organizationRef: canonicalSha256({
      schemaVersion: "boardagent.feed-consistency-reference.v1",
      organizationId
    }),
    rowEvidenceSha256,
    checkedFeedRows: relations.checkedFeedRows,
    checkedTombstoneRows: relations.checkedTombstoneRows,
    payloadHashMismatches,
    payloadCanonicalMismatches,
    payloadBindingMismatches,
    membershipStalePendingRows: relations.membershipStalePendingRows,
    noticeBindingMismatches: relations.noticeBindingMismatches,
    auditBindingMismatches: relations.auditBindingMismatches,
    tombstoneBindingMismatches: relations.tombstoneBindingMismatches,
    duplicateRemovalTombstones: relations.duplicateRemovalTombstones,
    relationMismatches
  });
  const valid =
    payloadHashMismatches === 0 &&
    payloadCanonicalMismatches === 0 &&
    payloadBindingMismatches === 0 &&
    relations.membershipStalePendingRows === 0 &&
    relationMismatches === 0;

  return {
    valid,
    checkedFeedRows: relations.checkedFeedRows,
    checkedTombstoneRows: relations.checkedTombstoneRows,
    payloadHashMismatches,
    payloadCanonicalMismatches,
    payloadBindingMismatches,
    membershipStalePendingRows: relations.membershipStalePendingRows,
    noticeBindingMismatches: relations.noticeBindingMismatches,
    auditBindingMismatches: relations.auditBindingMismatches,
    tombstoneBindingMismatches: relations.tombstoneBindingMismatches,
    duplicateRemovalTombstones: relations.duplicateRemovalTombstones,
    relationMismatches,
    evidenceSha256
  };
}
