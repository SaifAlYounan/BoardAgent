import type { PoolClient } from "pg";

import type { AuditEvent } from "@boardagent/audit";
import {
  DecisionPackageSchema,
  PendingActionDeltaSchema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  UuidV7Schema,
  type DecisionPackage,
  type JsonValue
} from "@boardagent/contracts";
import {
  prepareVoteElectorate,
  replacementPlan,
  voteElectorateEvidenceHash,
  voteReplacementConsentHash,
  type DecisionPackageChangeClass,
  type PreparedVoteElectorate
} from "@boardagent/domain";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import {
  RuleSelectionEvidenceError,
  assertPackageRuleSelectionEvidence,
  type ValidatedRuleSelection
} from "./rule-selection.js";
import { readRequestContext } from "./request-context.js";

export class VoteTransactionError extends Error {
  public constructor(
    public readonly code:
      | "vote_open_unavailable"
      | "vote_package_invalid"
      | "vote_electorate_invalid"
      | "vote_recipient_invalid"
      | "vote_component_unavailable"
      | "vote_replacement_unavailable"
      | "vote_replacement_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "VoteTransactionError";
  }
}

export interface VoteOpenDeliveryInput {
  readonly memberId: string;
  readonly noticeId: string;
  readonly feedId: string;
  readonly noticeAuditEventId: string;
}

export interface OpenVoteInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly decisionPackageId: string;
  readonly decisionPackage: DecisionPackage;
  /** Five core rows, then one row for each ordered variable package component. */
  readonly decisionPackageComponentIds: readonly string[];
  /** One row for each ordered `question_cutoff` package component. */
  readonly questionDecisionLinkIds: readonly string[];
  readonly electorate: PreparedVoteElectorate;
  readonly consentRecordId: string;
  readonly auditEventId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly deliveries: readonly VoteOpenDeliveryInput[];
}

export interface VoteStageReplacementInput {
  readonly stageId: string;
  readonly auditEventId: string;
}

export interface VoteProxyReplacementInput {
  readonly proxyGrantId: string;
  readonly proxyRevocationId: string;
  readonly auditEventId: string;
}

export interface VoteBallotReplacementInput {
  readonly ballotId: string;
  readonly ballotDispositionId: string;
  readonly auditEventId: string;
}

export interface VoteFeedTombstoneInput {
  readonly removedFeedId: string;
  readonly tombstoneId: string;
}

export interface VoteSourceUpdateDispositionInput {
  readonly causeId: string;
  readonly dispositionId: string;
}

export interface ReplaceVoteInput {
  readonly organizationId: string;
  readonly oldVoteId: string;
  readonly newVoteId: string;
  readonly newTitle: string;
  readonly newResolutionVersionId: string;
  readonly newResolutionText: string;
  readonly decisionPackageId: string;
  readonly decisionPackage: DecisionPackage;
  readonly decisionPackageComponentIds: readonly string[];
  readonly questionDecisionLinkIds: readonly string[];
  readonly electorate: PreparedVoteElectorate;
  readonly consentRecordId: string;
  readonly supersessionId: string;
  readonly reason: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly stageDispositions: readonly VoteStageReplacementInput[];
  readonly proxyDispositions: readonly VoteProxyReplacementInput[];
  readonly ballotDispositions: readonly VoteBallotReplacementInput[];
  /** One tombstone for every pending old-vote feed row, preserving its sequence. */
  readonly feedTombstones: readonly VoteFeedTombstoneInput[];
  /** One incorporation disposition for every unresolved source-update cause. */
  readonly sourceUpdateDispositions: readonly VoteSourceUpdateDispositionInput[];
  /** One `vote_opened` notice/feed for every member in the new electorate. */
  readonly newVoteDeliveries: readonly VoteOpenDeliveryInput[];
  /** One informational `vote_replaced` notice/feed for every current entitled recipient. */
  readonly replacementDeliveries: readonly VoteOpenDeliveryInput[];
  /** One actionable `revote_required` notice/feed for each still-eligible prior principal. */
  readonly revoteDeliveries: readonly VoteOpenDeliveryInput[];
  /** Required for `amend_resolution_text`; omitted for other replacement causes. */
  readonly resolutionAmendedAuditEventId?: string;
  readonly voteSupersededAuditEventId: string;
  readonly voteOpenedAuditEventId: string;
}

export type OpenVoteResult =
  | {
      readonly replayed: true;
      readonly voteId: string;
      readonly decisionPackageId: string;
      readonly state: "open";
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly voteId: string;
      readonly decisionPackageId: string;
      readonly state: "open";
      readonly packageSha256: string;
      readonly electorateSha256: string;
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

export type ReplaceVoteResult =
  | {
      readonly replayed: true;
      readonly oldVoteId: string;
      readonly newVoteId: string;
      readonly decisionPackageId: string;
      readonly state: "open";
      readonly responseSha256: string;
    }
  | {
      readonly replayed: false;
      readonly oldVoteId: string;
      readonly newVoteId: string;
      readonly decisionPackageId: string;
      readonly state: "open";
      readonly oldPackageSha256: string;
      readonly newPackageSha256: string;
      readonly changedComponentClasses: readonly DecisionPackageChangeClass[];
      readonly responseSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

interface LockedVoteRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_state: string;
  readonly vote_row_version: string;
  readonly approval_rule_id: string;
  readonly approval_rule_sha256: Buffer;
  readonly governance_profile_id: string;
  readonly governance_profile_version: number;
  readonly governance_profile_sha256: Buffer;
  readonly ruleset_id: string;
  readonly ruleset_version: number;
  readonly ruleset_sha256: Buffer;
  readonly close_mode: "automatic" | "secretariat_confirmed";
  readonly resolution_version: number;
  readonly resolution_sha256: Buffer;
  readonly actor_ready: boolean;
  readonly binding_valid: boolean;
  readonly consent_valid: boolean;
}

interface LockedElectorateRow {
  readonly member_id: string;
  readonly membership_id: string;
  readonly membership_version_id: string;
  readonly membership_version: number;
  readonly is_chair: boolean;
  readonly voting_weight: string;
  readonly authority_snapshot: unknown;
  readonly authority_snapshot_sha256: Buffer;
}

interface LockedRecipientRow {
  readonly member_id: string;
  readonly seat_role: "voting_member" | "management" | "observer";
  readonly entitlement_generation: string;
}

interface LockedReplacementRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_state: string;
  readonly vote_row_version: string;
  readonly old_package_payload: Buffer;
  readonly old_package_sha256: Buffer;
  readonly approval_rule_sha256: Buffer;
  readonly governance_profile_version: number;
  readonly governance_profile_sha256: Buffer;
  readonly ruleset_version: number;
  readonly ruleset_sha256: Buffer;
  readonly actor_ready: boolean;
  readonly binding_valid: boolean;
  readonly consent_valid: boolean;
}

interface PersistedElectorateRow {
  readonly member_id: string;
  readonly membership_version_id: string;
  readonly is_chair: boolean;
  readonly voting_weight: string;
  readonly eligibility_snapshot: unknown;
  readonly eligibility_sha256: Buffer;
}

interface PendingVoteFeedRow {
  readonly id: string;
  readonly member_id: string;
  readonly entitlement_generation: string;
  readonly feed_sequence: string;
  readonly action_type: string;
}

interface VoteSourceUpdateCauseRow {
  readonly cause_id: string;
  readonly source_class: "management_submission" | "document" | "question_cutoff";
  readonly source_id: string;
  readonly source_version: number;
  readonly source_sha256: Buffer;
}

interface ActiveStageRow {
  readonly id: string;
}

interface ActiveProxyRow {
  readonly id: string;
  readonly principal_member_id: string;
  readonly holder_member_id: string;
}

interface ActiveBallotRow {
  readonly id: string;
  readonly principal_member_id: string;
  readonly caster_member_id: string;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
  readonly state: string;
}

const CORE_COMPONENT_COUNT = 7;

async function validatePackageRuleSelection(
  client: PoolClient,
  input: {
    readonly boardId: string;
    readonly finalVoteId: string;
    readonly decisionPackage: DecisionPackage;
    readonly packageSha256: string;
  }
): Promise<ValidatedRuleSelection> {
  try {
    return await assertPackageRuleSelectionEvidence(client, input);
  } catch (error) {
    if (error instanceof RuleSelectionEvidenceError) {
      throw new VoteTransactionError("vote_package_invalid", error.message);
    }
    throw error;
  }
}

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function uniqueUuidList(values: readonly string[], label: string): readonly string[] {
  const parsed = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(parsed).size !== parsed.length) throw new TypeError(`${label} must be unique`);
  return parsed;
}

function normalizeDeliveries(
  inputs: readonly VoteOpenDeliveryInput[],
  contextLabel = "vote-open"
): readonly VoteOpenDeliveryInput[] {
  const deliveries = inputs
    .map((delivery) => ({
      memberId: UuidV7Schema.parse(delivery.memberId),
      noticeId: UuidV7Schema.parse(delivery.noticeId),
      feedId: UuidV7Schema.parse(delivery.feedId),
      noticeAuditEventId: UuidV7Schema.parse(delivery.noticeAuditEventId)
    }))
    .toSorted((left, right) => left.memberId.localeCompare(right.memberId));
  if (new Set(deliveries.map(({ memberId }) => memberId)).size !== deliveries.length) {
    throw new TypeError(`${contextLabel} deliveries must contain each recipient once`);
  }
  for (const [idLabel, ids] of [
    [`${contextLabel} notice IDs`, deliveries.map(({ noticeId }) => noticeId)],
    [`${contextLabel} feed IDs`, deliveries.map(({ feedId }) => feedId)],
    [
      `${contextLabel} notice audit IDs`,
      deliveries.map(({ noticeAuditEventId }) => noticeAuditEventId)
    ]
  ] as const) {
    if (new Set(ids).size !== ids.length) throw new TypeError(`${idLabel} must be unique`);
  }
  return deliveries;
}

function assertElectoratePrepared(input: PreparedVoteElectorate): PreparedVoteElectorate {
  const prepared = prepareVoteElectorate({
    voteId: input.voteId,
    entries: input.entries.map((entry) => ({
      id: entry.id,
      memberId: entry.memberId,
      membershipVersionId: entry.membershipVersionId,
      isChair: entry.isChair,
      votingWeight: entry.votingWeight,
      eligibilitySnapshot: entry.eligibilitySnapshot
    }))
  });
  if (
    prepared.schemaVersion !== input.schemaVersion ||
    !safeHashEqual(prepared.electorateSha256, input.electorateSha256) ||
    prepared.entries.some(
      (entry, index) =>
        !input.entries[index] ||
        entry.id !== input.entries[index].id ||
        !safeHashEqual(entry.eligibilitySha256, input.entries[index].eligibilitySha256)
    )
  ) {
    throw new VoteTransactionError(
      "vote_electorate_invalid",
      "prepared electorate failed canonical integrity validation"
    );
  }
  return prepared;
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  operation: "create_vote" | "replace_open_vote",
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_id,safe_response_sha256
      from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation=$3 and idempotency_key=$4
      for update`,
    [actorMemberId, clientId, operation, key]
  );
  return result.rows[0];
}

function replayResult(
  record: IdempotencyRow | undefined,
  requestSha256: string,
  voteId: string,
  decisionPackageId: string
): OpenVoteResult | undefined {
  if (!record) return undefined;
  if (!safeHashEqual(record.request_sha256.toString("hex"), requestSha256)) {
    throw new VoteTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different vote-open request"
    );
  }
  if (
    record.state === "succeeded" &&
    record.safe_response_id === decisionPackageId &&
    record.safe_response_sha256
  ) {
    return {
      replayed: true,
      voteId,
      decisionPackageId,
      state: "open",
      responseSha256: record.safe_response_sha256.toString("hex")
    };
  }
  throw new VoteTransactionError(
    "idempotency_in_progress",
    "identical vote-open request is already in progress"
  );
}

export async function validateDecisionPackageComponentsInTransaction(
  client: PoolClient,
  organizationId: string,
  boardId: string,
  components: DecisionPackage["components"]
): Promise<void> {
  for (const component of components) {
    let result;
    if (component.type === "management_submission") {
      result = await client.query<{ version: number; sha256: Buffer }>(
        `select version,payload_sha256 as sha256
           from management_submission_versions
          where id=$1 and organization_id=$2 and board_id=$3 and version=$4`,
        [component.id, organizationId, boardId, component.version]
      );
    } else if (component.type === "document") {
      result = await client.query<{ version: number; sha256: Buffer }>(
        `select version,sha256
           from document_versions
          where id=$1 and organization_id=$2 and board_id=$3 and version=$4`,
        [component.id, organizationId, boardId, component.version]
      );
    } else {
      result = await client.query<{ version: number; sha256: Buffer }>(
        `select turn.ordinal as version,turn.text_sha256 as sha256
           from management_question_turns as turn
           join management_questions as question on question.id=turn.question_id
          where question.id=$1 and question.organization_id=$2 and question.board_id=$3
            and turn.ordinal=$4`,
        [component.id, organizationId, boardId, component.version]
      );
    }
    const row = result.rows[0];
    if (
      result.rows.length !== 1 ||
      !row ||
      row.version !== component.version ||
      !safeHashEqual(row.sha256.toString("hex"), component.sha256)
    ) {
      throw new VoteTransactionError(
        "vote_component_unavailable",
        "one or more exact decision-package components are unavailable"
      );
    }
  }
}

async function nextFeedSequence(
  client: PoolClient,
  boardId: string,
  memberId: string
): Promise<bigint> {
  const result = await client.query<{ next_sequence: string }>(
    `select (
       greatest(
         coalesce((select max(feed_sequence) from notices
                    where board_id=$1 and recipient_member_id=$2),0),
         coalesce((select max(feed_sequence) from pending_action_feed
                    where board_id=$1 and member_id=$2),0),
         coalesce((select max(feed_sequence) from feed_tombstones
                    where board_id=$1 and member_id=$2),0)
       ) + 1
     )::text as next_sequence`,
    [boardId, memberId]
  );
  const sequence = BigInt(result.rows[0]?.next_sequence ?? "0");
  if (sequence < 1n) throw new Error("failed to allocate a positive feed sequence");
  return sequence;
}

export async function openVoteInTransaction(
  client: PoolClient,
  input: OpenVoteInput
): Promise<OpenVoteResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const decisionPackageId = UuidV7Schema.parse(input.decisionPackageId);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const decisionPackage = DecisionPackageSchema.parse(input.decisionPackage);
  const electorate = assertElectoratePrepared(input.electorate);
  const componentIds = uniqueUuidList(
    input.decisionPackageComponentIds,
    "decision-package component IDs"
  );
  const questionLinkIds = uniqueUuidList(
    input.questionDecisionLinkIds,
    "question-decision link IDs"
  );
  const deliveries = normalizeDeliveries(input.deliveries);
  if (decisionPackage.voteId !== voteId || electorate.voteId !== voteId) {
    throw new VoteTransactionError("vote_package_invalid", "vote package identity is invalid");
  }
  if (decisionPackage.packageVersion !== 1) {
    throw new VoteTransactionError(
      "vote_package_invalid",
      "initial vote open requires decision-package version one"
    );
  }
  if (componentIds.length !== CORE_COMPONENT_COUNT + decisionPackage.components.length) {
    throw new TypeError("decision-package component IDs do not match the complete manifest");
  }
  const questionComponents = decisionPackage.components.filter(
    ({ type }) => type === "question_cutoff"
  );
  if (questionLinkIds.length !== questionComponents.length) {
    throw new TypeError("question-decision link IDs do not match question cutoffs");
  }
  const packageSha256 = canonicalSha256(decisionPackage);
  if (!safeHashEqual(decisionPackage.electorateSha256, electorate.electorateSha256)) {
    throw new VoteTransactionError(
      "vote_electorate_invalid",
      "decision package does not bind the prepared electorate"
    );
  }
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-open-request.v1",
    organizationId,
    voteId,
    decisionPackageId,
    packageSha256,
    electorateSha256: electorate.electorateSha256,
    consentRecordId
  });
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new VoteTransactionError("vote_open_unavailable", "vote open is unavailable");
  }

  const voteLock = await client.query<LockedVoteRow>(
    `select * from boardagent_lock_vote_for_open($1,$2,$3,$4)`,
    [
      voteId,
      decisionPackage.resolutionVersionId,
      consentRecordId,
      Buffer.from(packageSha256, "hex")
    ]
  );
  const vote = voteLock.rows[0];
  if (
    !vote ||
    voteLock.rows.length !== 1 ||
    vote.organization_id !== organizationId ||
    !vote.actor_ready ||
    !vote.consent_valid
  ) {
    throw new VoteTransactionError("vote_open_unavailable", "vote open is unavailable");
  }

  if (vote.vote_state === "open") {
    const currentPackage = await client.query<{
      decision_package_id: string | null;
      package_sha256: Buffer | null;
    }>(
      `select vote.current_decision_package_id as decision_package_id,
              package.package_sha256
         from votes as vote
         left join decision_packages as package
           on package.id=vote.current_decision_package_id and package.vote_id=vote.id
        where vote.id=$1 and vote.state='open'`,
      [voteId]
    );
    const current = currentPackage.rows[0];
    if (
      !current ||
      current.decision_package_id !== decisionPackageId ||
      !current.package_sha256 ||
      !safeHashEqual(current.package_sha256.toString("hex"), packageSha256)
    ) {
      throw new VoteTransactionError("vote_open_unavailable", "vote open is unavailable");
    }
    return (
      replayResult(
        await readIdempotency(
          client,
          context.memberId,
          context.clientId,
          "create_vote",
          idempotencyKey
        ),
        requestSha256,
        voteId,
        decisionPackageId
      ) ??
      (() => {
        throw new VoteTransactionError("vote_open_unavailable", "vote open is unavailable");
      })()
    );
  }
  if (vote.vote_state !== "draft" || !vote.binding_valid) {
    throw new VoteTransactionError("vote_open_unavailable", "vote open is unavailable");
  }

  const persistedBindings = [
    [vote.approval_rule_id, decisionPackage.approvalRuleId],
    [vote.governance_profile_id, decisionPackage.governanceProfileVersionId],
    [vote.ruleset_id, decisionPackage.rulesetVersionId]
  ] as const;
  const persistedHashes = [
    [vote.approval_rule_sha256, decisionPackage.approvalRuleSha256],
    [vote.governance_profile_sha256, decisionPackage.governanceProfileSha256],
    [vote.ruleset_sha256, decisionPackage.rulesetSha256],
    [vote.resolution_sha256, decisionPackage.resolutionSha256]
  ] as const;
  if (
    persistedBindings.some(([actual, expected]) => actual !== expected) ||
    persistedHashes.some(
      ([actual, expected]) => !safeHashEqual(actual.toString("hex"), expected)
    ) ||
    vote.close_mode !== decisionPackage.closeMode
  ) {
    throw new VoteTransactionError(
      "vote_package_invalid",
      "decision package does not match persisted governance versions"
    );
  }
  const ruleSelection = await validatePackageRuleSelection(client, {
    boardId: vote.board_id,
    finalVoteId: voteId,
    decisionPackage,
    packageSha256
  });

  const lockedElectorate = await client.query<LockedElectorateRow>(
    "select * from boardagent_lock_vote_electorate($1)",
    [voteId]
  );
  if (
    lockedElectorate.rows.length !== electorate.entries.length ||
    lockedElectorate.rows.some((row, index) => {
      const entry = electorate.entries[index];
      return (
        !entry ||
        row.member_id !== entry.memberId ||
        row.membership_version_id !== entry.membershipVersionId ||
        row.is_chair !== entry.isChair ||
        BigInt(row.voting_weight) !== entry.votingWeight ||
        !safeHashEqual(row.authority_snapshot_sha256.toString("hex"), entry.eligibilitySha256) ||
        !safeHashEqual(canonicalSha256(row.authority_snapshot), entry.eligibilitySha256) ||
        canonicalJson(row.authority_snapshot) !== canonicalJson(entry.eligibilitySnapshot)
      );
    })
  ) {
    throw new VoteTransactionError(
      "vote_electorate_invalid",
      "prepared electorate is not the exact current eligible voting membership"
    );
  }

  const lockedRecipients = await client.query<LockedRecipientRow>(
    "select * from boardagent_lock_vote_recipients($1)",
    [voteId]
  );
  if (
    lockedRecipients.rows.length !== deliveries.length ||
    lockedRecipients.rows.some(
      (recipient, index) => recipient.member_id !== deliveries[index]?.memberId
    )
  ) {
    throw new VoteTransactionError(
      "vote_recipient_invalid",
      "vote-open deliveries must cover every currently entitled board member exactly once"
    );
  }

  await validateDecisionPackageComponentsInTransaction(
    client,
    organizationId,
    vote.board_id,
    decisionPackage.components
  );

  const insertedIdempotency = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'create_vote',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      idempotencyRecordId,
      organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  const existingIdempotency = await readIdempotency(
    client,
    context.memberId,
    context.clientId,
    "create_vote",
    idempotencyKey
  );
  if (!existingIdempotency) throw new Error("vote-open idempotency record disappeared");
  if (insertedIdempotency.rowCount === 0) {
    const replayed = replayResult(existingIdempotency, requestSha256, voteId, decisionPackageId);
    if (replayed) return replayed;
  } else if (!safeHashEqual(existingIdempotency.request_sha256.toString("hex"), requestSha256)) {
    throw new VoteTransactionError(
      "idempotency_conflict",
      "vote-open idempotency record does not bind this request"
    );
  }

  const submissionManifest = decisionPackage.components.filter(
    ({ type }) => type === "management_submission"
  );
  const documentManifest = decisionPackage.components.filter(({ type }) => type === "document");
  const questionCutoffManifest = questionComponents;
  await client.query(
    `insert into decision_packages(
       id,organization_id,board_id,vote_id,version,schema_version,resolution_version_id,
       resolution_sha256,submission_manifest,submission_manifest_sha256,document_manifest,
       document_manifest_sha256,question_cutoff_manifest,question_cutoff_sha256,
       approval_rule_id,approval_rule_sha256,governance_profile_id,
       governance_profile_sha256,ruleset_id,ruleset_sha256,matter_evaluation_id,
       matter_evaluation_result_sha256,selected_ruleset_rule_id,
       selected_ruleset_rule_sha256,rule_override_id,rule_override_sha256,
       electorate_sha256,canonical_payload,package_sha256,created_by
     ) values ($1,$2,$3,$4,$5,'boardagent.decision-package.v1',$6,$7,$8,$9,$10,$11,$12,
       $13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)`,
    [
      decisionPackageId,
      organizationId,
      vote.board_id,
      voteId,
      decisionPackage.packageVersion,
      decisionPackage.resolutionVersionId,
      Buffer.from(decisionPackage.resolutionSha256, "hex"),
      JSON.stringify(submissionManifest),
      Buffer.from(canonicalSha256(submissionManifest), "hex"),
      JSON.stringify(documentManifest),
      Buffer.from(canonicalSha256(documentManifest), "hex"),
      JSON.stringify(questionCutoffManifest),
      Buffer.from(canonicalSha256(questionCutoffManifest), "hex"),
      decisionPackage.approvalRuleId,
      Buffer.from(decisionPackage.approvalRuleSha256, "hex"),
      decisionPackage.governanceProfileVersionId,
      Buffer.from(decisionPackage.governanceProfileSha256, "hex"),
      decisionPackage.rulesetVersionId,
      Buffer.from(decisionPackage.rulesetSha256, "hex"),
      ruleSelection.evaluationId,
      Buffer.from(ruleSelection.evaluationResultSha256, "hex"),
      ruleSelection.selectedRuleId,
      Buffer.from(ruleSelection.selectedRuleSha256, "hex"),
      ruleSelection.ruleOverrideId,
      ruleSelection.ruleOverrideSha256
        ? Buffer.from(ruleSelection.ruleOverrideSha256, "hex")
        : null,
      Buffer.from(electorate.electorateSha256, "hex"),
      Buffer.from(canonicalJson(decisionPackage), "utf8"),
      Buffer.from(packageSha256, "hex"),
      context.memberId
    ]
  );

  for (const entry of electorate.entries) {
    await client.query(
      `insert into vote_electorate(
         id,organization_id,board_id,vote_id,member_id,membership_version_id,seat_role,
         is_chair,voting_weight,eligibility_snapshot,eligibility_sha256
       ) values ($1,$2,$3,$4,$5,$6,'voting_member',$7,$8,$9,$10)`,
      [
        entry.id,
        organizationId,
        vote.board_id,
        voteId,
        entry.memberId,
        entry.membershipVersionId,
        entry.isChair,
        entry.votingWeight.toString(10),
        JSON.stringify(entry.eligibilitySnapshot),
        Buffer.from(entry.eligibilitySha256, "hex")
      ]
    );
  }

  const coreComponents = [
    {
      id: componentIds[0]!,
      componentClass: "resolution",
      ordinal: 0,
      objectType: "resolution_version",
      objectId: decisionPackage.resolutionVersionId,
      objectVersion: vote.resolution_version,
      objectSha256: decisionPackage.resolutionSha256
    },
    {
      id: componentIds[1]!,
      componentClass: "approval_rule",
      ordinal: 0,
      objectType: "approval_rule",
      objectId: decisionPackage.approvalRuleId,
      objectVersion: null,
      objectSha256: decisionPackage.approvalRuleSha256
    },
    {
      id: componentIds[2]!,
      componentClass: "governance_profile",
      ordinal: 0,
      objectType: "governance_profile",
      objectId: decisionPackage.governanceProfileVersionId,
      objectVersion: vote.governance_profile_version,
      objectSha256: decisionPackage.governanceProfileSha256
    },
    {
      id: componentIds[3]!,
      componentClass: "ruleset",
      ordinal: 0,
      objectType: "ruleset",
      objectId: decisionPackage.rulesetVersionId,
      objectVersion: vote.ruleset_version,
      objectSha256: decisionPackage.rulesetSha256
    },
    {
      id: componentIds[4]!,
      componentClass: "electorate",
      ordinal: 0,
      objectType: "vote_electorate",
      objectId: null,
      objectVersion: 1,
      objectSha256: electorate.electorateSha256
    },
    {
      id: componentIds[5]!,
      componentClass: "matter_evaluation",
      ordinal: 0,
      objectType: "matter_evaluation",
      objectId: ruleSelection.evaluationId,
      objectVersion: null,
      objectSha256: ruleSelection.evaluationResultSha256
    },
    {
      id: componentIds[6]!,
      componentClass: "ruleset_rule",
      ordinal: 0,
      objectType: "ruleset_rule",
      objectId: ruleSelection.selectedRuleId,
      objectVersion: null,
      objectSha256: ruleSelection.selectedRuleSha256
    }
  ] as const;
  const variableComponents = decisionPackage.components.map((component, index) => ({
    id: componentIds[CORE_COMPONENT_COUNT + index]!,
    componentClass: component.type === "management_submission" ? "submission" : component.type,
    ordinal: component.ordinal,
    objectType:
      component.type === "management_submission"
        ? "management_submission_version"
        : component.type === "document"
          ? "document_version"
          : "management_question",
    objectId: component.id,
    objectVersion: component.version,
    objectSha256: component.sha256
  }));
  for (const component of [...coreComponents, ...variableComponents]) {
    await client.query(
      `insert into decision_package_components(
         id,decision_package_id,component_class,ordinal,object_type,object_id,
         object_version,object_sha256
       ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        component.id,
        decisionPackageId,
        component.componentClass,
        component.ordinal,
        component.objectType,
        component.objectId,
        component.objectVersion,
        Buffer.from(component.objectSha256, "hex")
      ]
    );
  }

  for (const [index, component] of questionComponents.entries()) {
    await client.query(
      `insert into question_decision_links(
         id,organization_id,board_id,question_id,inclusive_turn_ordinal,
         inclusive_turn_sha256,decision_package_id,decision_package_version,
         decision_package_sha256,selected_by,consent_record_id
       ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        questionLinkIds[index],
        organizationId,
        vote.board_id,
        component.id,
        component.version,
        Buffer.from(component.sha256, "hex"),
        decisionPackageId,
        decisionPackage.packageVersion,
        Buffer.from(packageSha256, "hex"),
        context.memberId,
        consentRecordId
      ]
    );
  }

  const opened = await client.query<{ row_version: string; opened_at: string }>(
    `update votes
        set state='open',current_resolution_version_id=$1,current_decision_package_id=$2,
            electorate_sha256=$3,close_mode=$4,deadline_at=$5,
            matter_evaluation_id=$6,selected_ruleset_rule_id=$7,
            rule_override_id=$8,rule_override_sha256=$9,
            opened_at=transaction_timestamp(),row_version=row_version+1
      where id=$10 and state='draft' and row_version=$11::bigint
      returning row_version::text,
                to_char(opened_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as opened_at`,
    [
      decisionPackage.resolutionVersionId,
      decisionPackageId,
      Buffer.from(electorate.electorateSha256, "hex"),
      decisionPackage.closeMode,
      decisionPackage.deadlineAt,
      ruleSelection.evaluationId,
      ruleSelection.selectedRuleId,
      ruleSelection.ruleOverrideId,
      ruleSelection.ruleOverrideSha256
        ? Buffer.from(ruleSelection.ruleOverrideSha256, "hex")
        : null,
      voteId,
      vote.vote_row_version
    ]
  );
  const openedVote = opened.rows[0];
  if (!openedVote || opened.rows.length !== 1) {
    throw new VoteTransactionError(
      "vote_open_unavailable",
      "vote changed while opening its decision package"
    );
  }
  const objectVersion = BigInt(openedVote.row_version);
  const electorateMembers = new Set(electorate.entries.map(({ memberId }) => memberId));
  const auditInputs = [];
  for (const [index, delivery] of deliveries.entries()) {
    const recipient = lockedRecipients.rows[index];
    if (!recipient || recipient.member_id !== delivery.memberId) {
      throw new Error("locked vote recipient order changed inside the transaction");
    }
    const generation = Number(recipient.entitlement_generation);
    if (!Number.isSafeInteger(generation) || generation < 1) {
      throw new Error("vote recipient entitlement generation is invalid");
    }
    const sequence = await nextFeedSequence(client, vote.board_id, delivery.memberId);
    const canVote = electorateMembers.has(delivery.memberId);
    const feedPayload = PendingActionDeltaSchema.parse({
      schemaVersion: "boardagent.pending-action.v1",
      sequence: sequence.toString(10),
      deltaType: canVote ? "action_required" : "notice",
      objectType: "vote",
      objectId: voteId,
      objectVersion: Number(objectVersion),
      entitlementGeneration: generation,
      actionState: canVote ? "pending" : "informational",
      safeRefs: {
        decisionPackageId,
        packageSha256,
        deadlineAt: decisionPackage.deadlineAt
      },
      createdAt: openedVote.opened_at
    });
    const canonicalFeed = canonicalJson(feedPayload);
    const noticeSha256 = canonicalSha256({
      noticeType: "vote_opened",
      voteId,
      decisionPackageId,
      packageSha256,
      recipientMemberId: delivery.memberId,
      deadlineAt: decisionPackage.deadlineAt
    });
    const visibilitySha256 = canonicalSha256({
      boardId: vote.board_id,
      voteId,
      memberId: delivery.memberId,
      entitlementGeneration: generation
    });
    await client.query(
      `insert into notices(
         id,organization_id,board_id,notice_type,object_type,object_id,object_version,
         recipient_member_id,content_sha256,feed_sequence,audit_event_id
       ) values ($1,$2,$3,'vote_opened','vote',$4,$5,$6,$7,$8,$9)`,
      [
        delivery.noticeId,
        organizationId,
        vote.board_id,
        voteId,
        objectVersion.toString(10),
        delivery.memberId,
        Buffer.from(noticeSha256, "hex"),
        sequence.toString(10),
        delivery.noticeAuditEventId
      ]
    );
    await client.query(
      `insert into pending_action_feed(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         action_type,object_type,object_id,object_version,visibility_sha256,
         canonical_payload,payload_sha256,state,notice_id,audit_event_id,resolved_at
       ) values ($1,$2,$3,$4,$5,$6,'vote_opened','vote',$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [
        delivery.feedId,
        organizationId,
        vote.board_id,
        delivery.memberId,
        recipient.entitlement_generation,
        sequence.toString(10),
        voteId,
        objectVersion.toString(10),
        Buffer.from(visibilitySha256, "hex"),
        Buffer.from(canonicalFeed, "utf8"),
        Buffer.from(canonicalSha256(feedPayload), "hex"),
        canVote ? "pending" : "resolved",
        delivery.noticeId,
        delivery.noticeAuditEventId,
        canVote ? null : openedVote.opened_at
      ]
    );
    auditInputs.push({
      organizationId,
      consentRecordId,
      objectVersion,
      event: {
        eventId: delivery.noticeAuditEventId,
        eventType: "notice_delivered" as const,
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: voteId,
        boardId: vote.board_id,
        origin: "mcp" as const,
        details: {
          noticeType: "vote_opened",
          recipientMemberId: delivery.memberId,
          decisionPackageId,
          packageSha256,
          feedSequence: sequence.toString(10),
          actionRequired: canVote
        },
        schemaVersion: 1 as const
      }
    });
  }
  auditInputs.push({
    organizationId,
    consentRecordId,
    objectVersion,
    event: {
      eventId: auditEventId,
      eventType: "vote_opened" as const,
      actorMemberId: context.memberId,
      actorClientId: context.clientId,
      tokenJti: context.tokenJti,
      entityType: "vote",
      entityId: voteId,
      boardId: vote.board_id,
      origin: "mcp" as const,
      details: {
        decisionPackageId,
        packageVersion: decisionPackage.packageVersion,
        packageSha256,
        resolutionVersionId: decisionPackage.resolutionVersionId,
        matterEvaluationId: ruleSelection.evaluationId,
        matterEvaluationResultSha256: ruleSelection.evaluationResultSha256,
        selectedRulesetRuleId: ruleSelection.selectedRuleId,
        selectedRulesetRuleSha256: ruleSelection.selectedRuleSha256,
        ruleOverrideId: ruleSelection.ruleOverrideId,
        ruleOverrideSha256: ruleSelection.ruleOverrideSha256,
        electorateSha256: electorate.electorateSha256,
        closeMode: decisionPackage.closeMode,
        deadlineAt: decisionPackage.deadlineAt,
        recipientCount: deliveries.length
      },
      schemaVersion: 1 as const
    }
  });
  const auditEvents = await appendAuditEventsInTransaction(client, auditInputs);
  const safeResponse = {
    voteId,
    decisionPackageId,
    state: "open" as const,
    packageSha256,
    electorateSha256: electorate.electorateSha256
  };
  const responseSha256 = canonicalSha256(safeResponse);
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='decision_package',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4 and operation='create_vote'
        and idempotency_key=$5 and state='in_progress'`,
    [
      decisionPackageId,
      Buffer.from(responseSha256, "hex"),
      context.memberId,
      context.clientId,
      idempotencyKey
    ]
  );
  if (completed.rowCount !== 1) throw new Error("vote-open idempotency completion failed");
  return { replayed: false, ...safeResponse, responseSha256, auditEvents };
}

function normalizeStageDispositions(
  inputs: readonly VoteStageReplacementInput[]
): readonly VoteStageReplacementInput[] {
  const normalized = inputs
    .map((input) => ({
      stageId: UuidV7Schema.parse(input.stageId),
      auditEventId: UuidV7Schema.parse(input.auditEventId)
    }))
    .toSorted((left, right) => left.stageId.localeCompare(right.stageId));
  uniqueUuidList(
    normalized.map(({ stageId }) => stageId),
    "replacement stage IDs"
  );
  uniqueUuidList(
    normalized.map(({ auditEventId }) => auditEventId),
    "replacement stage audit IDs"
  );
  return normalized;
}

function normalizeProxyDispositions(
  inputs: readonly VoteProxyReplacementInput[]
): readonly VoteProxyReplacementInput[] {
  const normalized = inputs
    .map((input) => ({
      proxyGrantId: UuidV7Schema.parse(input.proxyGrantId),
      proxyRevocationId: UuidV7Schema.parse(input.proxyRevocationId),
      auditEventId: UuidV7Schema.parse(input.auditEventId)
    }))
    .toSorted((left, right) => left.proxyGrantId.localeCompare(right.proxyGrantId));
  for (const [label, values] of [
    ["replacement proxy grant IDs", normalized.map(({ proxyGrantId }) => proxyGrantId)],
    [
      "replacement proxy revocation IDs",
      normalized.map(({ proxyRevocationId }) => proxyRevocationId)
    ],
    ["replacement proxy audit IDs", normalized.map(({ auditEventId }) => auditEventId)]
  ] as const) {
    uniqueUuidList(values, label);
  }
  return normalized;
}

function normalizeBallotDispositions(
  inputs: readonly VoteBallotReplacementInput[]
): readonly VoteBallotReplacementInput[] {
  const normalized = inputs
    .map((input) => ({
      ballotId: UuidV7Schema.parse(input.ballotId),
      ballotDispositionId: UuidV7Schema.parse(input.ballotDispositionId),
      auditEventId: UuidV7Schema.parse(input.auditEventId)
    }))
    .toSorted((left, right) => left.ballotId.localeCompare(right.ballotId));
  for (const [label, values] of [
    ["replacement ballot IDs", normalized.map(({ ballotId }) => ballotId)],
    [
      "replacement ballot disposition IDs",
      normalized.map(({ ballotDispositionId }) => ballotDispositionId)
    ],
    ["replacement ballot audit IDs", normalized.map(({ auditEventId }) => auditEventId)]
  ] as const) {
    uniqueUuidList(values, label);
  }
  return normalized;
}

function normalizeFeedTombstones(
  inputs: readonly VoteFeedTombstoneInput[]
): readonly VoteFeedTombstoneInput[] {
  const normalized = inputs
    .map((input) => ({
      removedFeedId: UuidV7Schema.parse(input.removedFeedId),
      tombstoneId: UuidV7Schema.parse(input.tombstoneId)
    }))
    .toSorted((left, right) => left.removedFeedId.localeCompare(right.removedFeedId));
  uniqueUuidList(
    normalized.map(({ removedFeedId }) => removedFeedId),
    "replacement removed-feed IDs"
  );
  uniqueUuidList(
    normalized.map(({ tombstoneId }) => tombstoneId),
    "replacement feed-tombstone IDs"
  );
  return normalized;
}

function normalizeSourceUpdateDispositions(
  inputs: readonly VoteSourceUpdateDispositionInput[]
): readonly VoteSourceUpdateDispositionInput[] {
  const normalized = inputs
    .map((input) => ({
      causeId: UuidV7Schema.parse(input.causeId),
      dispositionId: UuidV7Schema.parse(input.dispositionId)
    }))
    .toSorted((left, right) => left.causeId.localeCompare(right.causeId));
  uniqueUuidList(
    normalized.map(({ causeId }) => causeId),
    "replacement source-cause IDs"
  );
  uniqueUuidList(
    normalized.map(({ dispositionId }) => dispositionId),
    "replacement source-disposition IDs"
  );
  return normalized;
}

async function insertDecisionPackageEvidence(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly boardId: string;
    readonly voteId: string;
    readonly decisionPackageId: string;
    readonly decisionPackage: DecisionPackage;
    readonly packageSha256: string;
    readonly electorate: PreparedVoteElectorate;
    readonly componentIds: readonly string[];
    readonly questionLinkIds: readonly string[];
    readonly consentRecordId: string;
    readonly selectedBy: string;
    readonly resolutionVersion: number;
    readonly governanceProfileVersion: number;
    readonly rulesetVersion: number;
    readonly ruleSelection: ValidatedRuleSelection;
  }
): Promise<void> {
  const {
    organizationId,
    boardId,
    voteId,
    decisionPackageId,
    decisionPackage,
    packageSha256,
    electorate,
    componentIds,
    questionLinkIds,
    consentRecordId,
    selectedBy,
    resolutionVersion,
    governanceProfileVersion,
    rulesetVersion,
    ruleSelection
  } = input;
  const submissionManifest = decisionPackage.components.filter(
    ({ type }) => type === "management_submission"
  );
  const documentManifest = decisionPackage.components.filter(({ type }) => type === "document");
  const questionComponents = decisionPackage.components.filter(
    ({ type }) => type === "question_cutoff"
  );
  await client.query(
    `insert into decision_packages(
       id,organization_id,board_id,vote_id,version,schema_version,resolution_version_id,
       resolution_sha256,submission_manifest,submission_manifest_sha256,document_manifest,
       document_manifest_sha256,question_cutoff_manifest,question_cutoff_sha256,
       approval_rule_id,approval_rule_sha256,governance_profile_id,
       governance_profile_sha256,ruleset_id,ruleset_sha256,matter_evaluation_id,
       matter_evaluation_result_sha256,selected_ruleset_rule_id,
       selected_ruleset_rule_sha256,rule_override_id,rule_override_sha256,
       electorate_sha256,canonical_payload,package_sha256,created_by
     ) values ($1,$2,$3,$4,$5,'boardagent.decision-package.v1',$6,$7,$8,$9,$10,$11,$12,
       $13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)`,
    [
      decisionPackageId,
      organizationId,
      boardId,
      voteId,
      decisionPackage.packageVersion,
      decisionPackage.resolutionVersionId,
      Buffer.from(decisionPackage.resolutionSha256, "hex"),
      JSON.stringify(submissionManifest),
      Buffer.from(canonicalSha256(submissionManifest), "hex"),
      JSON.stringify(documentManifest),
      Buffer.from(canonicalSha256(documentManifest), "hex"),
      JSON.stringify(questionComponents),
      Buffer.from(canonicalSha256(questionComponents), "hex"),
      decisionPackage.approvalRuleId,
      Buffer.from(decisionPackage.approvalRuleSha256, "hex"),
      decisionPackage.governanceProfileVersionId,
      Buffer.from(decisionPackage.governanceProfileSha256, "hex"),
      decisionPackage.rulesetVersionId,
      Buffer.from(decisionPackage.rulesetSha256, "hex"),
      ruleSelection.evaluationId,
      Buffer.from(ruleSelection.evaluationResultSha256, "hex"),
      ruleSelection.selectedRuleId,
      Buffer.from(ruleSelection.selectedRuleSha256, "hex"),
      ruleSelection.ruleOverrideId,
      ruleSelection.ruleOverrideSha256
        ? Buffer.from(ruleSelection.ruleOverrideSha256, "hex")
        : null,
      Buffer.from(electorate.electorateSha256, "hex"),
      Buffer.from(canonicalJson(decisionPackage), "utf8"),
      Buffer.from(packageSha256, "hex"),
      selectedBy
    ]
  );

  for (const entry of electorate.entries) {
    await client.query(
      `insert into vote_electorate(
         id,organization_id,board_id,vote_id,member_id,membership_version_id,seat_role,
         is_chair,voting_weight,eligibility_snapshot,eligibility_sha256
       ) values ($1,$2,$3,$4,$5,$6,'voting_member',$7,$8,$9,$10)`,
      [
        entry.id,
        organizationId,
        boardId,
        voteId,
        entry.memberId,
        entry.membershipVersionId,
        entry.isChair,
        entry.votingWeight.toString(10),
        JSON.stringify(entry.eligibilitySnapshot),
        Buffer.from(entry.eligibilitySha256, "hex")
      ]
    );
  }

  const coreComponents = [
    {
      id: componentIds[0]!,
      componentClass: "resolution",
      ordinal: 0,
      objectType: "resolution_version",
      objectId: decisionPackage.resolutionVersionId,
      objectVersion: resolutionVersion,
      objectSha256: decisionPackage.resolutionSha256
    },
    {
      id: componentIds[1]!,
      componentClass: "approval_rule",
      ordinal: 0,
      objectType: "approval_rule",
      objectId: decisionPackage.approvalRuleId,
      objectVersion: null,
      objectSha256: decisionPackage.approvalRuleSha256
    },
    {
      id: componentIds[2]!,
      componentClass: "governance_profile",
      ordinal: 0,
      objectType: "governance_profile",
      objectId: decisionPackage.governanceProfileVersionId,
      objectVersion: governanceProfileVersion,
      objectSha256: decisionPackage.governanceProfileSha256
    },
    {
      id: componentIds[3]!,
      componentClass: "ruleset",
      ordinal: 0,
      objectType: "ruleset",
      objectId: decisionPackage.rulesetVersionId,
      objectVersion: rulesetVersion,
      objectSha256: decisionPackage.rulesetSha256
    },
    {
      id: componentIds[4]!,
      componentClass: "electorate",
      ordinal: 0,
      objectType: "vote_electorate",
      objectId: null,
      objectVersion: 1,
      objectSha256: electorate.electorateSha256
    },
    {
      id: componentIds[5]!,
      componentClass: "matter_evaluation",
      ordinal: 0,
      objectType: "matter_evaluation",
      objectId: ruleSelection.evaluationId,
      objectVersion: null,
      objectSha256: ruleSelection.evaluationResultSha256
    },
    {
      id: componentIds[6]!,
      componentClass: "ruleset_rule",
      ordinal: 0,
      objectType: "ruleset_rule",
      objectId: ruleSelection.selectedRuleId,
      objectVersion: null,
      objectSha256: ruleSelection.selectedRuleSha256
    }
  ] as const;
  const variableComponents = decisionPackage.components.map((component, index) => ({
    id: componentIds[CORE_COMPONENT_COUNT + index]!,
    componentClass: component.type === "management_submission" ? "submission" : component.type,
    ordinal: component.ordinal,
    objectType:
      component.type === "management_submission"
        ? "management_submission_version"
        : component.type === "document"
          ? "document_version"
          : "management_question",
    objectId: component.id,
    objectVersion: component.version,
    objectSha256: component.sha256
  }));
  for (const component of [...coreComponents, ...variableComponents]) {
    await client.query(
      `insert into decision_package_components(
         id,decision_package_id,component_class,ordinal,object_type,object_id,
         object_version,object_sha256
       ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        component.id,
        decisionPackageId,
        component.componentClass,
        component.ordinal,
        component.objectType,
        component.objectId,
        component.objectVersion,
        Buffer.from(component.objectSha256, "hex")
      ]
    );
  }

  for (const [index, component] of questionComponents.entries()) {
    await client.query(
      `insert into question_decision_links(
         id,organization_id,board_id,question_id,inclusive_turn_ordinal,
         inclusive_turn_sha256,decision_package_id,decision_package_version,
         decision_package_sha256,selected_by,consent_record_id
       ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        questionLinkIds[index],
        organizationId,
        boardId,
        component.id,
        component.version,
        Buffer.from(component.sha256, "hex"),
        decisionPackageId,
        decisionPackage.packageVersion,
        Buffer.from(packageSha256, "hex"),
        selectedBy,
        consentRecordId
      ]
    );
  }
}

async function insertReplacementDelivery(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly boardId: string;
    readonly memberId: string;
    readonly entitlementGeneration: number;
    readonly noticeId: string;
    readonly feedId: string;
    readonly auditEventId: string;
    readonly noticeType: "vote_opened" | "vote_replaced" | "revote_required";
    readonly deltaType: "action_required" | "notice" | "vote_replaced" | "revote_required";
    readonly actionState: "pending" | "resolved" | "informational";
    readonly objectId: string;
    readonly objectVersion: bigint;
    readonly changedComponentClasses: readonly DecisionPackageChangeClass[];
    readonly safeRefs: Readonly<Record<string, string | number>>;
    readonly createdAt: string;
  }
): Promise<bigint> {
  const sequence = await nextFeedSequence(client, input.boardId, input.memberId);
  const payload = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: sequence.toString(10),
    deltaType: input.deltaType,
    objectType: "vote",
    objectId: input.objectId,
    objectVersion: Number(input.objectVersion),
    entitlementGeneration: input.entitlementGeneration,
    actionState: input.actionState,
    changedComponentClasses: input.changedComponentClasses,
    safeRefs: input.safeRefs,
    createdAt: input.createdAt
  });
  const contentSha256 = canonicalSha256({
    noticeType: input.noticeType,
    recipientMemberId: input.memberId,
    objectId: input.objectId,
    objectVersion: input.objectVersion.toString(10),
    changedComponentClasses: input.changedComponentClasses,
    safeRefs: input.safeRefs
  });
  const visibilitySha256 = canonicalSha256({
    boardId: input.boardId,
    memberId: input.memberId,
    entitlementGeneration: input.entitlementGeneration,
    objectId: input.objectId
  });
  await client.query(
    `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,$4,'vote',$5,$6,$7,$8,$9,$10)`,
    [
      input.noticeId,
      input.organizationId,
      input.boardId,
      input.noticeType,
      input.objectId,
      input.objectVersion.toString(10),
      input.memberId,
      Buffer.from(contentSha256, "hex"),
      sequence.toString(10),
      input.auditEventId
    ]
  );
  const canonicalPayload = canonicalJson(payload);
  await client.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,state,notice_id,audit_event_id,resolved_at
     ) values ($1,$2,$3,$4,$5,$6,$7,'vote',$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      input.feedId,
      input.organizationId,
      input.boardId,
      input.memberId,
      input.entitlementGeneration,
      sequence.toString(10),
      input.noticeType,
      input.objectId,
      input.objectVersion.toString(10),
      Buffer.from(visibilitySha256, "hex"),
      Buffer.from(canonicalPayload, "utf8"),
      Buffer.from(canonicalSha256(payload), "hex"),
      input.actionState === "pending" ? "pending" : "resolved",
      input.noticeId,
      input.auditEventId,
      input.actionState === "pending" ? null : input.createdAt
    ]
  );
  return sequence;
}

function replacementReplayResult(
  record: IdempotencyRow | undefined,
  requestSha256: string,
  oldVoteId: string,
  newVoteId: string,
  decisionPackageId: string
): ReplaceVoteResult | undefined {
  if (!record) return undefined;
  if (!safeHashEqual(record.request_sha256.toString("hex"), requestSha256)) {
    throw new VoteTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different vote-replacement request"
    );
  }
  if (
    record.state === "succeeded" &&
    record.safe_response_id === decisionPackageId &&
    record.safe_response_sha256
  ) {
    return {
      replayed: true,
      oldVoteId,
      newVoteId,
      decisionPackageId,
      state: "open",
      responseSha256: record.safe_response_sha256.toString("hex")
    };
  }
  throw new VoteTransactionError(
    "idempotency_in_progress",
    "identical vote-replacement request is already in progress"
  );
}

export async function replaceVoteInTransaction(
  client: PoolClient,
  input: ReplaceVoteInput
): Promise<ReplaceVoteResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const oldVoteId = UuidV7Schema.parse(input.oldVoteId);
  const newVoteId = UuidV7Schema.parse(input.newVoteId);
  if (oldVoteId === newVoteId) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement requires distinct old and new vote identifiers"
    );
  }
  const newTitle = canonicalText(input.newTitle);
  if (newTitle.length < 1 || newTitle.length > 512) {
    throw new RangeError("replacement vote title must contain 1 through 512 characters");
  }
  const newResolutionVersionId = UuidV7Schema.parse(input.newResolutionVersionId);
  const newResolutionText = canonicalText(input.newResolutionText);
  if (newResolutionText.length < 1 || Buffer.byteLength(newResolutionText, "utf8") > 1_048_576) {
    throw new RangeError("replacement resolution must contain 1 through 1048576 bytes");
  }
  const decisionPackageId = UuidV7Schema.parse(input.decisionPackageId);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const supersessionId = UuidV7Schema.parse(input.supersessionId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const resolutionAmendedAuditEventId = input.resolutionAmendedAuditEventId
    ? UuidV7Schema.parse(input.resolutionAmendedAuditEventId)
    : null;
  const voteSupersededAuditEventId = UuidV7Schema.parse(input.voteSupersededAuditEventId);
  const voteOpenedAuditEventId = UuidV7Schema.parse(input.voteOpenedAuditEventId);
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const reason = canonicalText(input.reason);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("vote-replacement reason must contain 1 through 65536 characters");
  }
  const decisionPackage = DecisionPackageSchema.parse(input.decisionPackage);
  const electorate = assertElectoratePrepared(input.electorate);
  if (
    decisionPackage.voteId !== newVoteId ||
    electorate.voteId !== newVoteId ||
    decisionPackage.packageVersion !== 1
  ) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement package must be version one and bind the distinct new vote"
    );
  }
  if (!safeHashEqual(decisionPackage.electorateSha256, electorate.electorateSha256)) {
    throw new VoteTransactionError(
      "vote_electorate_invalid",
      "replacement package does not bind the prepared electorate"
    );
  }
  const expectedResolutionSha256 = canonicalSha256({
    schemaVersion: "boardagent.resolution.v1",
    text: newResolutionText
  });
  if (
    decisionPackage.resolutionVersionId !== newResolutionVersionId ||
    !safeHashEqual(decisionPackage.resolutionSha256, expectedResolutionSha256)
  ) {
    throw new VoteTransactionError(
      "vote_package_invalid",
      "replacement resolution bytes do not match the confirmed package"
    );
  }
  const componentIds = uniqueUuidList(
    input.decisionPackageComponentIds,
    "replacement decision-package component IDs"
  );
  const questionLinkIds = uniqueUuidList(
    input.questionDecisionLinkIds,
    "replacement question-decision link IDs"
  );
  const questionComponents = decisionPackage.components.filter(
    ({ type }) => type === "question_cutoff"
  );
  if (componentIds.length !== CORE_COMPONENT_COUNT + decisionPackage.components.length) {
    throw new TypeError("replacement component IDs do not match the complete manifest");
  }
  if (questionLinkIds.length !== questionComponents.length) {
    throw new TypeError("replacement question-link IDs do not match question cutoffs");
  }

  const stageDispositions = normalizeStageDispositions(input.stageDispositions);
  const proxyDispositions = normalizeProxyDispositions(input.proxyDispositions);
  const ballotDispositions = normalizeBallotDispositions(input.ballotDispositions);
  const feedTombstones = normalizeFeedTombstones(input.feedTombstones);
  const sourceUpdateDispositions = normalizeSourceUpdateDispositions(
    input.sourceUpdateDispositions
  );
  const newVoteDeliveries = normalizeDeliveries(input.newVoteDeliveries, "new-vote");
  const replacementDeliveries = normalizeDeliveries(input.replacementDeliveries, "vote-replaced");
  const revoteDeliveries = normalizeDeliveries(input.revoteDeliveries, "revote-required");
  const allGeneratedIds = [
    newVoteId,
    newResolutionVersionId,
    decisionPackageId,
    supersessionId,
    idempotencyRecordId,
    ...(resolutionAmendedAuditEventId ? [resolutionAmendedAuditEventId] : []),
    voteSupersededAuditEventId,
    voteOpenedAuditEventId,
    ...componentIds,
    ...questionLinkIds,
    ...stageDispositions.flatMap(({ auditEventId }) => [auditEventId]),
    ...proxyDispositions.flatMap(({ proxyRevocationId, auditEventId }) => [
      proxyRevocationId,
      auditEventId
    ]),
    ...ballotDispositions.flatMap(({ ballotDispositionId, auditEventId }) => [
      ballotDispositionId,
      auditEventId
    ]),
    ...feedTombstones.flatMap(({ removedFeedId, tombstoneId }) => [removedFeedId, tombstoneId]),
    ...sourceUpdateDispositions.flatMap(({ causeId, dispositionId }) => [causeId, dispositionId]),
    ...newVoteDeliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
      noticeId,
      feedId,
      noticeAuditEventId
    ]),
    ...replacementDeliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
      noticeId,
      feedId,
      noticeAuditEventId
    ]),
    ...revoteDeliveries.flatMap(({ noticeId, feedId, noticeAuditEventId }) => [
      noticeId,
      feedId,
      noticeAuditEventId
    ])
  ];
  if (new Set(allGeneratedIds).size !== allGeneratedIds.length) {
    throw new TypeError("vote replacement generated IDs must be globally unique");
  }

  const newPackageSha256 = canonicalSha256(decisionPackage);
  const confirmedPayloadSha256 = voteReplacementConsentHash({
    oldVoteId,
    newVoteId,
    newTitle,
    newResolutionVersionId,
    newResolutionSha256: expectedResolutionSha256,
    decisionPackageId,
    newPackageSha256,
    reason
  });
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-replacement-request.v1",
    organizationId,
    oldVoteId,
    newVoteId,
    newTitle,
    newResolutionVersionId,
    newResolutionSha256: expectedResolutionSha256,
    decisionPackageId,
    newPackageSha256,
    confirmedPayloadSha256,
    electorateSha256: electorate.electorateSha256,
    consentRecordId,
    reason
  });
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new VoteTransactionError(
      "vote_replacement_unavailable",
      "vote replacement is unavailable"
    );
  }

  const lockResult = await client.query<LockedReplacementRow>(
    `select * from boardagent_lock_vote_for_replacement($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      oldVoteId,
      consentRecordId,
      Buffer.from(confirmedPayloadSha256, "hex"),
      Buffer.from(newPackageSha256, "hex"),
      decisionPackage.approvalRuleId,
      decisionPackage.governanceProfileVersionId,
      decisionPackage.rulesetVersionId,
      decisionPackage.closeMode
    ]
  );
  const locked = lockResult.rows[0];
  if (
    !locked ||
    lockResult.rows.length !== 1 ||
    locked.organization_id !== organizationId ||
    !locked.actor_ready ||
    !locked.consent_valid
  ) {
    throw new VoteTransactionError(
      "vote_replacement_unavailable",
      "vote replacement is unavailable"
    );
  }

  if (locked.vote_state === "superseded") {
    const committed = await client.query<{
      new_vote_id: string;
      decision_package_id: string | null;
      package_sha256: Buffer | null;
    }>(
      `select supersession.new_vote_id,
              vote.current_decision_package_id as decision_package_id,
              package.package_sha256
         from vote_supersessions as supersession
         join votes as vote on vote.id=supersession.new_vote_id
         left join decision_packages as package
           on package.id=vote.current_decision_package_id and package.vote_id=vote.id
        where supersession.old_vote_id=$1`,
      [oldVoteId]
    );
    const replacement = committed.rows[0];
    if (
      !replacement ||
      replacement.new_vote_id !== newVoteId ||
      replacement.decision_package_id !== decisionPackageId ||
      !replacement.package_sha256 ||
      !safeHashEqual(replacement.package_sha256.toString("hex"), newPackageSha256)
    ) {
      throw new VoteTransactionError(
        "vote_replacement_unavailable",
        "vote was superseded by a different replacement"
      );
    }
    return (
      replacementReplayResult(
        await readIdempotency(
          client,
          context.memberId,
          context.clientId,
          "replace_open_vote",
          idempotencyKey
        ),
        requestSha256,
        oldVoteId,
        newVoteId,
        decisionPackageId
      ) ??
      (() => {
        throw new VoteTransactionError(
          "vote_replacement_unavailable",
          "replacement replay evidence is unavailable"
        );
      })()
    );
  }
  if (!["open", "source_update_pending"].includes(locked.vote_state) || !locked.binding_valid) {
    throw new VoteTransactionError(
      "vote_replacement_unavailable",
      "only an open current vote can be replaced"
    );
  }

  let oldDecisionPackage: DecisionPackage;
  try {
    oldDecisionPackage = DecisionPackageSchema.parse(
      JSON.parse(locked.old_package_payload.toString("utf8"))
    );
  } catch {
    throw new VoteTransactionError(
      "vote_replacement_unavailable",
      "source decision package failed persisted integrity validation"
    );
  }
  const oldPackageSha256 = canonicalSha256(oldDecisionPackage);
  if (
    oldDecisionPackage.voteId !== oldVoteId ||
    !safeHashEqual(locked.old_package_sha256.toString("hex"), oldPackageSha256) ||
    safeHashEqual(oldPackageSha256, newPackageSha256)
  ) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement must preserve an exact distinct source package"
    );
  }
  const bindingHashes = [
    [locked.approval_rule_sha256, decisionPackage.approvalRuleSha256],
    [locked.governance_profile_sha256, decisionPackage.governanceProfileSha256],
    [locked.ruleset_sha256, decisionPackage.rulesetSha256]
  ] as const;
  if (
    bindingHashes.some(([actual, expected]) => !safeHashEqual(actual.toString("hex"), expected))
  ) {
    throw new VoteTransactionError(
      "vote_package_invalid",
      "replacement package does not match current governance bytes"
    );
  }
  const replacementRuleSelection = await validatePackageRuleSelection(client, {
    boardId: locked.board_id,
    finalVoteId: newVoteId,
    decisionPackage,
    packageSha256: newPackageSha256
  });

  const persistedOldElectorate = await client.query<PersistedElectorateRow>(
    `select member_id,membership_version_id,is_chair,voting_weight::text,eligibility_snapshot,
            eligibility_sha256
       from vote_electorate
      where vote_id=$1
      order by member_id`,
    [oldVoteId]
  );
  if (persistedOldElectorate.rows.length < 1) {
    throw new VoteTransactionError(
      "vote_replacement_unavailable",
      "source vote electorate evidence is unavailable"
    );
  }
  const oldElectorateEvidenceSha256 = voteElectorateEvidenceHash(
    persistedOldElectorate.rows.map((row) => ({
      memberId: row.member_id,
      membershipVersionId: row.membership_version_id,
      isChair: row.is_chair,
      votingWeight: BigInt(row.voting_weight),
      eligibilitySnapshot: row.eligibility_snapshot as JsonValue,
      eligibilitySha256: row.eligibility_sha256.toString("hex")
    }))
  );
  const newElectorateEvidenceSha256 = voteElectorateEvidenceHash(electorate.entries);
  const electorateChanged = !safeHashEqual(
    oldElectorateEvidenceSha256,
    newElectorateEvidenceSha256
  );
  const plan = replacementPlan(
    oldDecisionPackage,
    decisionPackage,
    [],
    electorate.entries.map(({ memberId }) => memberId),
    electorateChanged
  );

  const lockedElectorate = await client.query<LockedElectorateRow>(
    "select * from boardagent_lock_replacement_electorate($1)",
    [oldVoteId]
  );
  if (
    lockedElectorate.rows.length !== electorate.entries.length ||
    lockedElectorate.rows.some((row, index) => {
      const entry = electorate.entries[index];
      return (
        !entry ||
        row.member_id !== entry.memberId ||
        row.membership_version_id !== entry.membershipVersionId ||
        row.is_chair !== entry.isChair ||
        BigInt(row.voting_weight) !== entry.votingWeight ||
        !safeHashEqual(row.authority_snapshot_sha256.toString("hex"), entry.eligibilitySha256) ||
        canonicalJson(row.authority_snapshot) !== canonicalJson(entry.eligibilitySnapshot)
      );
    })
  ) {
    throw new VoteTransactionError(
      "vote_electorate_invalid",
      "replacement electorate is not the exact current eligible voting membership"
    );
  }

  const lockedRecipients = await client.query<LockedRecipientRow>(
    "select * from boardagent_lock_replacement_recipients($1)",
    [oldVoteId]
  );
  if (
    lockedRecipients.rows.length !== replacementDeliveries.length ||
    lockedRecipients.rows.some(
      (recipient, index) => recipient.member_id !== replacementDeliveries[index]?.memberId
    )
  ) {
    throw new VoteTransactionError(
      "vote_recipient_invalid",
      "vote-replaced deliveries must cover every entitled recipient exactly once"
    );
  }
  if (
    electorate.entries.length !== newVoteDeliveries.length ||
    electorate.entries.some((entry, index) => entry.memberId !== newVoteDeliveries[index]?.memberId)
  ) {
    throw new VoteTransactionError(
      "vote_recipient_invalid",
      "new-vote deliveries must cover every new electorate member exactly once"
    );
  }

  const activeStages = await client.query<ActiveStageRow>(
    `select id
       from action_stages
      where organization_id=$1 and board_id=$2 and target_type='vote' and target_id=$3
        and state='active'
      order by id
      for update`,
    [organizationId, locked.board_id, oldVoteId]
  );
  if (
    activeStages.rows.length !== stageDispositions.length ||
    activeStages.rows.some((stage, index) => stage.id !== stageDispositions[index]?.stageId)
  ) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement stage dispositions do not cover every active old-vote stage"
    );
  }
  const activeProxies = await client.query<ActiveProxyRow>(
    `select proxy.id,proxy.principal_member_id,proxy.holder_member_id
       from proxy_grants as proxy
       left join proxy_revocations as revocation on revocation.grant_id=proxy.id
      where proxy.organization_id=$1 and proxy.board_id=$2 and proxy.vote_id=$3
        and revocation.id is null
      order by proxy.id`,
    [organizationId, locked.board_id, oldVoteId]
  );
  if (
    activeProxies.rows.length !== proxyDispositions.length ||
    activeProxies.rows.some((proxy, index) => proxy.id !== proxyDispositions[index]?.proxyGrantId)
  ) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement proxy dispositions do not cover every old-vote proxy"
    );
  }
  const activeBallots = await client.query<ActiveBallotRow>(
    `select ballot.id,ballot.principal_member_id,ballot.caster_member_id
       from ballots as ballot
       left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
      where ballot.organization_id=$1 and ballot.board_id=$2 and ballot.vote_id=$3
        and disposition.id is null
      order by ballot.id`,
    [organizationId, locked.board_id, oldVoteId]
  );
  if (
    activeBallots.rows.length !== ballotDispositions.length ||
    activeBallots.rows.some((ballot, index) => ballot.id !== ballotDispositions[index]?.ballotId)
  ) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement ballot dispositions do not cover every effective old-vote ballot"
    );
  }

  const pendingVoteFeeds = await client.query<PendingVoteFeedRow>(
    `select id,member_id,entitlement_generation::text,feed_sequence::text,action_type
       from pending_action_feed
      where organization_id=$1 and board_id=$2 and object_type='vote' and object_id=$3
        and state='pending'
      order by id
      for update`,
    [organizationId, locked.board_id, oldVoteId]
  );
  if (
    pendingVoteFeeds.rows.length !== feedTombstones.length ||
    pendingVoteFeeds.rows.some((feed, index) => feed.id !== feedTombstones[index]?.removedFeedId)
  ) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement feed tombstones must cover every pending old-vote row"
    );
  }

  const sourceCauses = await client.query<VoteSourceUpdateCauseRow>(
    "select * from boardagent_lock_vote_source_causes($1)",
    [oldVoteId]
  );
  if (
    (locked.vote_state === "source_update_pending" && sourceCauses.rows.length === 0) ||
    (locked.vote_state === "open" && sourceCauses.rows.length !== 0) ||
    sourceCauses.rows.length !== sourceUpdateDispositions.length ||
    sourceCauses.rows.some(
      (cause, index) => cause.cause_id !== sourceUpdateDispositions[index]?.causeId
    )
  ) {
    throw new VoteTransactionError(
      "vote_replacement_invalid",
      "replacement must disposition every exact pending source-update cause"
    );
  }
  for (const cause of sourceCauses.rows) {
    const incorporated = decisionPackage.components
      .filter(
        (component) =>
          component.type === cause.source_class &&
          component.id === cause.source_id &&
          component.version >= cause.source_version
      )
      .toSorted((left, right) => right.version - left.version)[0];
    if (
      !incorporated ||
      (incorporated.version === cause.source_version &&
        !safeHashEqual(incorporated.sha256, cause.source_sha256.toString("hex")))
    ) {
      throw new VoteTransactionError(
        "vote_replacement_invalid",
        "replacement package does not incorporate every pending source-update cause"
      );
    }
  }

  const priorPrincipalIds = [
    ...new Set([
      ...activeBallots.rows.map((row) => row.principal_member_id),
      ...pendingVoteFeeds.rows
        .filter(({ action_type }) => action_type === "revote_required")
        .map(({ member_id }) => member_id)
    ])
  ].toSorted();
  const eligibleMembers = new Set(electorate.entries.map(({ memberId }) => memberId));
  const expectedRevoteMemberIds = priorPrincipalIds
    .filter((memberId) => eligibleMembers.has(memberId))
    .toSorted();
  if (
    expectedRevoteMemberIds.length !== revoteDeliveries.length ||
    expectedRevoteMemberIds.some(
      (memberId, index) => memberId !== revoteDeliveries[index]?.memberId
    )
  ) {
    throw new VoteTransactionError(
      "vote_recipient_invalid",
      "revote-required deliveries must cover only still-eligible prior principals"
    );
  }

  await validateDecisionPackageComponentsInTransaction(
    client,
    organizationId,
    locked.board_id,
    decisionPackage.components
  );

  const insertedIdempotency = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'replace_open_vote',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      idempotencyRecordId,
      organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  const existingIdempotency = await readIdempotency(
    client,
    context.memberId,
    context.clientId,
    "replace_open_vote",
    idempotencyKey
  );
  if (!existingIdempotency) throw new Error("vote-replacement idempotency record disappeared");
  if (insertedIdempotency.rowCount === 0) {
    const replayed = replacementReplayResult(
      existingIdempotency,
      requestSha256,
      oldVoteId,
      newVoteId,
      decisionPackageId
    );
    if (replayed) return replayed;
  } else if (!safeHashEqual(existingIdempotency.request_sha256.toString("hex"), requestSha256)) {
    throw new VoteTransactionError(
      "idempotency_conflict",
      "vote-replacement idempotency record does not bind this request"
    );
  }

  for (const [index, disposition] of stageDispositions.entries()) {
    const stage = activeStages.rows[index];
    const updated = await client.query(
      `update action_stages
          set state='replaced'
        where id=$1 and state='active'`,
      [stage?.id]
    );
    if (updated.rowCount !== 1 || stage?.id !== disposition.stageId) {
      throw new VoteTransactionError(
        "vote_replacement_unavailable",
        "an old-vote stage changed during replacement"
      );
    }
  }
  for (const [index, disposition] of proxyDispositions.entries()) {
    const proxy = activeProxies.rows[index];
    if (!proxy || proxy.id !== disposition.proxyGrantId) {
      throw new Error("locked proxy order changed during vote replacement");
    }
    await client.query(
      `insert into proxy_revocations(
         id,organization_id,grant_id,revoker_member_id,reason,effect,consent_record_id
       ) values ($1,$2,$3,$4,$5,'superseded',$6)`,
      [
        disposition.proxyRevocationId,
        organizationId,
        proxy.id,
        context.memberId,
        reason,
        consentRecordId
      ]
    );
  }

  await client.query(
    `insert into votes(
       id,organization_id,board_id,title,state,current_resolution_version_id,
       current_decision_package_id,approval_rule_id,governance_profile_id,ruleset_id,
       matter_evaluation_id,selected_ruleset_rule_id,rule_override_id,rule_override_sha256,
       electorate_sha256,close_mode,deadline_at,row_version,created_by,opened_at
     ) values ($1,$2,$3,$4,'open',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,1,$17,
       transaction_timestamp())`,
    [
      newVoteId,
      organizationId,
      locked.board_id,
      newTitle,
      newResolutionVersionId,
      decisionPackageId,
      decisionPackage.approvalRuleId,
      decisionPackage.governanceProfileVersionId,
      decisionPackage.rulesetVersionId,
      replacementRuleSelection.evaluationId,
      replacementRuleSelection.selectedRuleId,
      replacementRuleSelection.ruleOverrideId,
      replacementRuleSelection.ruleOverrideSha256
        ? Buffer.from(replacementRuleSelection.ruleOverrideSha256, "hex")
        : null,
      Buffer.from(electorate.electorateSha256, "hex"),
      decisionPackage.closeMode,
      decisionPackage.deadlineAt,
      context.memberId
    ]
  );
  await client.query(
    `insert into resolution_versions(
       id,organization_id,board_id,vote_id,version,canonical_schema,canonical_text,
       canonical_sha256,author_member_id
     ) values ($1,$2,$3,$4,1,'boardagent.resolution.v1',$5,$6,$7)`,
    [
      newResolutionVersionId,
      organizationId,
      locked.board_id,
      newVoteId,
      newResolutionText,
      Buffer.from(expectedResolutionSha256, "hex"),
      context.memberId
    ]
  );
  // Persist the immutable old->new link before package child rows so their RLS
  // policy can prove that a replacement consent targeting the old vote is the
  // authority for this exact new vote and package.
  await client.query(
    `insert into vote_supersessions(
       id,organization_id,board_id,old_vote_id,new_vote_id,changed_component_classes,
       old_package_sha256,new_package_sha256,secretary_member_id,consent_record_id,reason
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      supersessionId,
      organizationId,
      locked.board_id,
      oldVoteId,
      newVoteId,
      [...plan.changedComponentClasses],
      Buffer.from(oldPackageSha256, "hex"),
      Buffer.from(newPackageSha256, "hex"),
      context.memberId,
      consentRecordId,
      reason
    ]
  );
  await insertDecisionPackageEvidence(client, {
    organizationId,
    boardId: locked.board_id,
    voteId: newVoteId,
    decisionPackageId,
    decisionPackage,
    packageSha256: newPackageSha256,
    electorate,
    componentIds,
    questionLinkIds,
    consentRecordId,
    selectedBy: context.memberId,
    resolutionVersion: 1,
    governanceProfileVersion: locked.governance_profile_version,
    rulesetVersion: locked.ruleset_version,
    ruleSelection: replacementRuleSelection
  });

  for (const [index, disposition] of ballotDispositions.entries()) {
    const ballot = activeBallots.rows[index];
    if (!ballot || ballot.id !== disposition.ballotId) {
      throw new Error("locked ballot order changed during vote replacement");
    }
    await client.query(
      `insert into ballot_dispositions(
         id,prior_ballot_id,replacement_vote_id,reason,effect,audit_event_id
       ) values ($1,$2,$3,$4,'invalidated_by_vote_replacement',$5)`,
      [disposition.ballotDispositionId, ballot.id, newVoteId, reason, disposition.auditEventId]
    );
  }
  for (const [index, disposition] of sourceUpdateDispositions.entries()) {
    const cause = sourceCauses.rows[index];
    if (!cause || cause.cause_id !== disposition.causeId) {
      throw new Error("source-update cause order changed during vote replacement");
    }
    await client.query(
      `insert into vote_source_update_dispositions(
         id,organization_id,board_id,cause_id,source_vote_id,replacement_vote_id,effect,
         consent_record_id,reason,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,'incorporated',$7,$8,$9)`,
      [
        disposition.dispositionId,
        organizationId,
        locked.board_id,
        cause.cause_id,
        oldVoteId,
        newVoteId,
        consentRecordId,
        reason,
        voteSupersededAuditEventId
      ]
    );
  }
  const superseded = await client.query<{ row_version: string; superseded_at: string }>(
    `update votes
        set state='superseded',row_version=row_version+1
      where id=$1 and state in ('open','source_update_pending') and row_version=$2::bigint
      returning row_version::text,
                to_char(transaction_timestamp() at time zone 'UTC',
                  'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as superseded_at`,
    [oldVoteId, locked.vote_row_version]
  );
  const supersededVote = superseded.rows[0];
  if (!supersededVote || superseded.rows.length !== 1) {
    throw new VoteTransactionError(
      "vote_replacement_unavailable",
      "source vote changed during replacement"
    );
  }
  const oldObjectVersion = BigInt(supersededVote.row_version);
  for (const [index, tombstone] of feedTombstones.entries()) {
    const feed = pendingVoteFeeds.rows[index];
    if (!feed || feed.id !== tombstone.removedFeedId) {
      throw new Error("pending feed order changed during vote replacement");
    }
    const updatedFeed = await client.query(
      `update pending_action_feed
          set state='superseded',resolved_at=transaction_timestamp()
        where id=$1 and state='pending'`,
      [feed.id]
    );
    if (updatedFeed.rowCount !== 1) {
      throw new VoteTransactionError(
        "vote_replacement_unavailable",
        "pending vote feed changed during replacement"
      );
    }
    const tombstoneSha256 = canonicalSha256({
      schemaVersion: "boardagent.feed-tombstone.v1",
      removedFeedId: feed.id,
      oldVoteId,
      newVoteId,
      memberId: feed.member_id,
      feedSequence: feed.feed_sequence,
      reasonClass: "superseded"
    });
    await client.query(
      `insert into feed_tombstones(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,$7,'vote',$8,'superseded',$9,$10)`,
      [
        tombstone.tombstoneId,
        organizationId,
        locked.board_id,
        feed.member_id,
        feed.entitlement_generation,
        feed.feed_sequence,
        feed.id,
        oldVoteId,
        Buffer.from(tombstoneSha256, "hex"),
        voteSupersededAuditEventId
      ]
    );
  }

  const recipientByMember = new Map(
    lockedRecipients.rows.map((recipient) => [recipient.member_id, recipient] as const)
  );
  const revoteMembers = new Set(expectedRevoteMemberIds);
  const safeRefs = {
    oldVoteId,
    newVoteId,
    oldPackageSha256,
    newPackageSha256,
    decisionPackageId,
    newDeadlineAt: decisionPackage.deadlineAt
  } as const;
  const auditInputs: AuditAppendInput[] = [];
  for (const [index, disposition] of stageDispositions.entries()) {
    const stage = activeStages.rows[index]!;
    auditInputs.push({
      organizationId,
      consentRecordId,
      event: {
        eventId: disposition.auditEventId,
        eventType: "stage_replaced",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "action_stage",
        entityId: stage.id,
        boardId: locked.board_id,
        origin: "mcp",
        details: { oldVoteId, newVoteId, reason: "vote_replaced" },
        schemaVersion: 1
      }
    });
  }
  for (const [index, disposition] of proxyDispositions.entries()) {
    const proxy = activeProxies.rows[index]!;
    auditInputs.push({
      organizationId,
      consentRecordId,
      actingForMemberId: proxy.principal_member_id,
      event: {
        eventId: disposition.auditEventId,
        eventType: "proxy_revoked",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "proxy_grant",
        entityId: proxy.id,
        boardId: locked.board_id,
        origin: "mcp",
        details: {
          effect: "superseded",
          oldVoteId,
          newVoteId,
          principalMemberId: proxy.principal_member_id,
          holderMemberId: proxy.holder_member_id
        },
        schemaVersion: 1
      }
    });
  }
  for (const [index, disposition] of ballotDispositions.entries()) {
    const ballot = activeBallots.rows[index]!;
    auditInputs.push({
      organizationId,
      consentRecordId,
      actingForMemberId:
        ballot.caster_member_id === ballot.principal_member_id ? null : ballot.principal_member_id,
      event: {
        eventId: disposition.auditEventId,
        eventType: "ballot_superseded",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "ballot",
        entityId: ballot.id,
        boardId: locked.board_id,
        origin: "mcp",
        details: {
          effect: "invalidated_by_vote_replacement",
          oldVoteId,
          newVoteId,
          principalMemberId: ballot.principal_member_id
        },
        schemaVersion: 1
      }
    });
  }
  if (resolutionAmendedAuditEventId) {
    auditInputs.push({
      organizationId,
      consentRecordId,
      objectVersion: 1n,
      event: {
        eventId: resolutionAmendedAuditEventId,
        eventType: "resolution_amended",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "resolution_version",
        entityId: newResolutionVersionId,
        boardId: locked.board_id,
        origin: "mcp",
        details: {
          oldVoteId,
          newVoteId,
          oldResolutionVersionId: oldDecisionPackage.resolutionVersionId,
          oldResolutionSha256: oldDecisionPackage.resolutionSha256,
          newResolutionVersionId,
          newResolutionSha256: expectedResolutionSha256,
          effect: "vote_replaced",
          reason
        },
        schemaVersion: 1
      }
    });
  }
  auditInputs.push({
    organizationId,
    consentRecordId,
    objectVersion: oldObjectVersion,
    event: {
      eventId: voteSupersededAuditEventId,
      eventType: "vote_superseded",
      actorMemberId: context.memberId,
      actorClientId: context.clientId,
      tokenJti: context.tokenJti,
      entityType: "vote",
      entityId: oldVoteId,
      boardId: locked.board_id,
      origin: "mcp",
      details: {
        ...safeRefs,
        changedComponentClasses: plan.changedComponentClasses,
        reason
      },
      schemaVersion: 1
    }
  });
  auditInputs.push({
    organizationId,
    consentRecordId,
    objectVersion: 1n,
    event: {
      eventId: voteOpenedAuditEventId,
      eventType: "vote_opened",
      actorMemberId: context.memberId,
      actorClientId: context.clientId,
      tokenJti: context.tokenJti,
      entityType: "vote",
      entityId: newVoteId,
      boardId: locked.board_id,
      origin: "mcp",
      details: {
        decisionPackageId,
        packageVersion: 1,
        packageSha256: newPackageSha256,
        matterEvaluationId: replacementRuleSelection.evaluationId,
        matterEvaluationResultSha256: replacementRuleSelection.evaluationResultSha256,
        selectedRulesetRuleId: replacementRuleSelection.selectedRuleId,
        selectedRulesetRuleSha256: replacementRuleSelection.selectedRuleSha256,
        ruleOverrideId: replacementRuleSelection.ruleOverrideId,
        ruleOverrideSha256: replacementRuleSelection.ruleOverrideSha256,
        electorateSha256: electorate.electorateSha256,
        closeMode: decisionPackage.closeMode,
        deadlineAt: decisionPackage.deadlineAt,
        replacementForVoteId: oldVoteId,
        recipientCount: newVoteDeliveries.length
      },
      schemaVersion: 1
    }
  });

  for (const delivery of newVoteDeliveries) {
    const recipient = recipientByMember.get(delivery.memberId);
    if (!recipient) {
      throw new VoteTransactionError(
        "vote_recipient_invalid",
        "new electorate member is not an entitled replacement recipient"
      );
    }
    const generation = Number(recipient.entitlement_generation);
    if (!Number.isSafeInteger(generation) || generation < 1) {
      throw new Error("replacement recipient entitlement generation is invalid");
    }
    const requiresRevote = revoteMembers.has(delivery.memberId);
    const sequence = await insertReplacementDelivery(client, {
      organizationId,
      boardId: locked.board_id,
      memberId: delivery.memberId,
      entitlementGeneration: generation,
      noticeId: delivery.noticeId,
      feedId: delivery.feedId,
      auditEventId: delivery.noticeAuditEventId,
      noticeType: "vote_opened",
      deltaType: requiresRevote ? "notice" : "action_required",
      actionState: requiresRevote ? "informational" : "pending",
      objectId: newVoteId,
      objectVersion: 1n,
      changedComponentClasses: plan.changedComponentClasses,
      safeRefs,
      createdAt: supersededVote.superseded_at
    });
    auditInputs.push({
      organizationId,
      consentRecordId,
      objectVersion: 1n,
      event: {
        eventId: delivery.noticeAuditEventId,
        eventType: "notice_delivered",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: newVoteId,
        boardId: locked.board_id,
        origin: "mcp",
        details: {
          noticeType: "vote_opened",
          recipientMemberId: delivery.memberId,
          feedSequence: sequence.toString(10),
          actionRequired: !requiresRevote,
          ...safeRefs,
          changedComponentClasses: plan.changedComponentClasses
        },
        schemaVersion: 1
      }
    });
  }

  for (const delivery of replacementDeliveries) {
    const recipient = recipientByMember.get(delivery.memberId)!;
    const generation = Number(recipient.entitlement_generation);
    const sequence = await insertReplacementDelivery(client, {
      organizationId,
      boardId: locked.board_id,
      memberId: delivery.memberId,
      entitlementGeneration: generation,
      noticeId: delivery.noticeId,
      feedId: delivery.feedId,
      auditEventId: delivery.noticeAuditEventId,
      noticeType: "vote_replaced",
      deltaType: "vote_replaced",
      actionState: "informational",
      objectId: oldVoteId,
      objectVersion: oldObjectVersion,
      changedComponentClasses: plan.changedComponentClasses,
      safeRefs,
      createdAt: supersededVote.superseded_at
    });
    auditInputs.push({
      organizationId,
      consentRecordId,
      objectVersion: oldObjectVersion,
      event: {
        eventId: delivery.noticeAuditEventId,
        eventType: "vote_replaced",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: oldVoteId,
        boardId: locked.board_id,
        origin: "mcp",
        details: {
          recipientMemberId: delivery.memberId,
          feedSequence: sequence.toString(10),
          ...safeRefs,
          changedComponentClasses: plan.changedComponentClasses
        },
        schemaVersion: 1
      }
    });
  }

  for (const delivery of revoteDeliveries) {
    const recipient = recipientByMember.get(delivery.memberId);
    if (!recipient || !revoteMembers.has(delivery.memberId)) {
      throw new Error("revote recipient changed inside the replacement transaction");
    }
    const generation = Number(recipient.entitlement_generation);
    const sequence = await insertReplacementDelivery(client, {
      organizationId,
      boardId: locked.board_id,
      memberId: delivery.memberId,
      entitlementGeneration: generation,
      noticeId: delivery.noticeId,
      feedId: delivery.feedId,
      auditEventId: delivery.noticeAuditEventId,
      noticeType: "revote_required",
      deltaType: "revote_required",
      actionState: "pending",
      objectId: newVoteId,
      objectVersion: 1n,
      changedComponentClasses: plan.changedComponentClasses,
      safeRefs,
      createdAt: supersededVote.superseded_at
    });
    auditInputs.push({
      organizationId,
      consentRecordId,
      objectVersion: 1n,
      event: {
        eventId: delivery.noticeAuditEventId,
        eventType: "revote_required",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: newVoteId,
        boardId: locked.board_id,
        origin: "mcp",
        details: {
          recipientMemberId: delivery.memberId,
          feedSequence: sequence.toString(10),
          ...safeRefs,
          changedComponentClasses: plan.changedComponentClasses
        },
        schemaVersion: 1
      }
    });
  }

  const auditEvents = await appendAuditEventsInTransaction(client, auditInputs);
  const safeResponse = {
    oldVoteId,
    newVoteId,
    decisionPackageId,
    state: "open" as const,
    oldPackageSha256,
    newPackageSha256,
    changedComponentClasses: plan.changedComponentClasses
  };
  const responseSha256 = canonicalSha256(safeResponse);
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='decision_package',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where actor_member_id=$3 and client_id=$4 and operation='replace_open_vote'
        and idempotency_key=$5 and state='in_progress'`,
    [
      decisionPackageId,
      Buffer.from(responseSha256, "hex"),
      context.memberId,
      context.clientId,
      idempotencyKey
    ]
  );
  if (completed.rowCount !== 1) {
    throw new Error("vote-replacement idempotency completion failed");
  }
  return { replayed: false, ...safeResponse, responseSha256, auditEvents };
}
