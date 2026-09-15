import { createPublicKey, type JsonWebKey } from "node:crypto";

import type { PoolClient } from "pg";
import { z } from "zod";

import {
  OfflineCertificateBundleSchema,
  VoteCertificatePayloadSchema,
  canonicalVoteCertificatePayload,
  certificatePublicIdBytes,
  certificatePublicIdSha256,
  verifyVoteCertificate,
  type VoteCertificatePayload
} from "@boardagent/audit";
import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";
import {
  canonicalVoteTally,
  prepareVoteElectorate,
  tallyVote,
  voteCloseConsentHash,
  type ApprovalRule,
  type EffectiveBallot,
  type ElectorSeat
} from "@boardagent/domain";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export class VoteCloseTransactionError extends Error {
  public constructor(
    public readonly code:
      | "vote_close_unavailable"
      | "vote_close_invalid"
      | "vote_close_clock_unhealthy"
      | "vote_close_source_pending"
      | "vote_close_qna_unanswered"
      | "vote_close_signer_invalid"
      | "vote_close_integrity_failure"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "VoteCloseTransactionError";
  }
}

export interface InitiateVoteCloseInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  /** Independent 256-bit random identifier encoded as unpadded base64url. */
  readonly certificatePublicId: string;
  readonly expectedPackageSha256: string;
  readonly expectedTallySha256: string;
  readonly signingKeyId: string;
  readonly consentRecordId: string;
  readonly closingAuditEventId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
}

export interface FinalizeVoteCloseInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly signatureBase64Url: string;
  readonly certificateIssuedAuditEventId: string;
  readonly voteClosedAuditEventId: string;
}

export interface InitiateAutomaticVoteCloseInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly certificatePublicId: string;
  readonly expectedPackageSha256: string;
  readonly expectedTallySha256: string;
  readonly signingKeyId: string;
  readonly closingAuditEventId: string;
}

export interface VoteCloseDraftResult {
  readonly replayed: boolean;
  readonly voteId: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly state: "closing" | "closed";
  readonly payload: VoteCertificatePayload;
  readonly payloadSha256: string;
  readonly signingKeyId: string;
  readonly signingKeyLocator: string;
  readonly responseSha256: string;
}

export interface VoteCloseFinalResult {
  readonly replayed: boolean;
  readonly voteId: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly state: "closed";
  readonly closedAt: string;
  readonly payloadSha256: string;
}

export interface PrepareVoteCloseInput {
  readonly voteId: string;
  readonly expectedPackageSha256: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  /** Independent 256-bit random identifier encoded as unpadded base64url. */
  readonly certificatePublicId: string;
  readonly closeConsentRecordId: string;
  readonly closingAuditEventId: string;
}

export interface PreparedVoteClose {
  readonly organizationId: string;
  readonly boardId: string;
  readonly voteId: string;
  readonly voteTitle: string;
  readonly resolutionText: string;
  readonly resolutionSha256: string;
  readonly decisionPackage: JsonValue;
  readonly packageSha256: string;
  readonly expectedTally: ReturnType<typeof canonicalVoteTally>;
  readonly expectedTallySha256: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly certificatePublicIdSha256: string;
  readonly signingKeyId: string;
  readonly signingKeyLocator: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
}

export interface PrepareAutomaticVoteCloseInput {
  readonly organizationId: string;
  readonly voteId: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly certificatePublicId: string;
  readonly signingKeyId: string;
  readonly closingAuditEventId: string;
}

export interface PreparedAutomaticVoteClose {
  readonly organizationId: string;
  readonly boardId: string;
  readonly voteId: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly certificatePublicId: string;
  readonly expectedPackageSha256: string;
  readonly expectedTallySha256: string;
  readonly signingKeyId: string;
  readonly signingKeyLocator: string;
}

export type PreparedVoteCertificateRecovery =
  | {
      readonly required: false;
      readonly organizationId: string;
      readonly boardId: string;
      readonly voteId: string;
      readonly outcomeId: string;
      readonly certificateId: string;
      readonly state: "closed";
    }
  | {
      readonly required: true;
      readonly organizationId: string;
      readonly boardId: string;
      readonly voteId: string;
      readonly outcomeId: string;
      readonly certificateId: string;
      readonly state: "closing";
      readonly payload: VoteCertificatePayload;
      readonly payloadSha256: string;
      readonly signingKeyId: string;
      readonly signingKeyLocator: string;
    };

interface LockedCloseRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly vote_id: string;
  readonly vote_state: string;
  readonly vote_row_version: string;
  readonly vote_title: string;
  readonly close_mode: "automatic" | "secretariat_confirmed";
  readonly deadline_at: string;
  readonly resolution_version_id: string;
  readonly resolution_version: number;
  readonly resolution_text: string;
  readonly resolution_sha256: Buffer;
  readonly decision_package_id: string;
  readonly decision_package_version: number;
  readonly decision_package_sha256: Buffer;
  readonly submission_manifest_sha256: Buffer;
  readonly document_manifest_sha256: Buffer;
  readonly question_cutoff_sha256: Buffer;
  readonly electorate_sha256: Buffer;
  readonly governance_profile_id: string;
  readonly governance_profile_sha256: Buffer;
  readonly ruleset_id: string;
  readonly ruleset_sha256: Buffer;
  readonly matter_evaluation_id: string;
  readonly matter_evaluation_result_sha256: Buffer;
  readonly selected_ruleset_rule_id: string;
  readonly selected_ruleset_rule_sha256: Buffer;
  readonly rule_override_id: string | null;
  readonly rule_override_sha256: Buffer | null;
  readonly approval_rule_id: string;
  readonly approval_rule_sha256: Buffer;
  readonly threshold_numerator: string;
  readonly threshold_denominator: string;
  readonly quorum_numerator: string;
  readonly quorum_denominator: string;
  readonly approval_denominator: "eligible" | "participating" | "yes_no";
  readonly abstentions_count_for_quorum: boolean;
  readonly tie_behavior: "reject" | "chair_casting_vote";
  readonly proxy_policy: "principal_supersedes_proxy" | "first_ballot_final" | "forbidden";
  readonly instance_id: string;
  readonly signing_key_id: string;
  readonly signing_kid: string;
  readonly signing_public_jwk: unknown;
  readonly signing_locator: string;
  readonly clock_sample_id: string | null;
  readonly clock_measured_at: string | null;
  readonly clock_drift_microseconds: string | null;
  readonly clock_valid_until: string | null;
  readonly close_consent_record_sha256: Buffer | null;
  readonly actor_ready: boolean;
  readonly package_binding_valid: boolean;
  readonly source_ready: boolean;
  readonly qna_ready: boolean;
  readonly clock_healthy: boolean;
  readonly key_valid: boolean;
  readonly consent_valid: boolean;
}

interface PersistedCloseRow extends LockedCloseRow {
  readonly outcome_id: string;
  readonly certificate_id: string;
  readonly certificate_public_id: Buffer;
  readonly canonical_certificate_payload: Buffer;
  readonly certificate_payload_sha256: Buffer;
  readonly canonical_tally: unknown;
  readonly tally_sha256: Buffer;
  readonly persisted_outcome: "approved" | "rejected" | "quorum_not_met";
  readonly close_actor_member_id: string | null;
  readonly close_consent_record_id: string | null;
  readonly closing_audit_event_id: string;
  readonly closing_audit_sequence: string;
  readonly closing_audit_hash: Buffer;
  readonly closing_audit_occurred_at: string;
}

interface IdempotencyRow {
  readonly id: string;
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface ClosingLockRow extends PersistedCloseRow {
  readonly existing_signature: Buffer | null;
  readonly existing_certificate_state: string | null;
}

const PositiveDecimalSchema = z.string().regex(/^[1-9]\d*$/u);
const NonnegativeDecimalSchema = z.string().regex(/^(?:0|[1-9]\d*)$/u);
const IntegerDecimalSchema = z.string().regex(/^-?(?:0|[1-9]\d*)$/u);
const PgJsonBytesSchema = z
  .string()
  .regex(/^\\x(?:[0-9a-f]{2})*$/u)
  .transform((value) => Buffer.from(value.slice(2), "hex"));
const PgJsonSha256Schema = z
  .string()
  .regex(/^\\x[0-9a-f]{64}$/u)
  .transform((value) => Buffer.from(value.slice(2), "hex"));
const PgJsonEd25519SignatureSchema = z
  .string()
  .regex(/^\\x[0-9a-f]{128}$/u)
  .transform((value) => Buffer.from(value.slice(2), "hex"));
const VoteEvidenceSchema = z
  .object({
    electorate: z.array(
      z
        .object({
          id: UuidV7Schema,
          memberId: UuidV7Schema,
          membershipVersionId: UuidV7Schema,
          seatRole: z.literal("voting_member"),
          isChair: z.boolean(),
          votingWeight: PositiveDecimalSchema,
          eligibilitySnapshot: z.unknown(),
          eligibilitySha256: Sha256HexSchema
        })
        .strict()
    ),
    exclusions: z.array(
      z
        .object({
          id: UuidV7Schema,
          memberId: UuidV7Schema,
          version: z.number().int().positive().safe(),
          state: z.enum(["excluded", "lifted"]),
          reason: z.string().min(1).max(65_536),
          actorMemberId: UuidV7Schema,
          consentRecordId: UuidV7Schema,
          consentRecordSha256: Sha256HexSchema,
          effectiveAt: Rfc3339UtcSchema
        })
        .strict()
    ),
    proxies: z.array(
      z
        .object({
          id: UuidV7Schema,
          principalMemberId: UuidV7Schema,
          holderMemberId: UuidV7Schema,
          policy: z.enum(["principal_supersedes_proxy", "first_ballot_final"]),
          consentRecordId: UuidV7Schema,
          consentRecordSha256: Sha256HexSchema,
          grantedAt: Rfc3339UtcSchema,
          expiresAt: Rfc3339UtcSchema.nullable(),
          revocation: z
            .object({
              id: UuidV7Schema,
              effect: z.enum(["revoked", "expired", "superseded"]),
              consentRecordId: UuidV7Schema.nullable(),
              consentRecordSha256: Sha256HexSchema.nullable(),
              revokedAt: Rfc3339UtcSchema
            })
            .strict()
            .nullable()
        })
        .strict()
    ),
    ballots: z.array(
      z
        .object({
          id: UuidV7Schema,
          decisionPackageId: UuidV7Schema,
          principalMemberId: UuidV7Schema,
          casterMemberId: UuidV7Schema,
          choice: z.enum(["yes", "no", "abstain"]),
          statementText: z.string().max(500).nullable(),
          statementSha256: Sha256HexSchema.nullable(),
          votingWeight: PositiveDecimalSchema,
          source: z.enum(["own", "proxy"]),
          proxyGrantId: UuidV7Schema.nullable(),
          consentRecordId: UuidV7Schema,
          consentRecordSha256: Sha256HexSchema,
          castAt: Rfc3339UtcSchema,
          disposition: z
            .object({
              id: UuidV7Schema,
              effect: z.enum([
                "superseded",
                "invalidated_by_recusal",
                "invalidated_by_vote_replacement"
              ]),
              supersedingBallotId: UuidV7Schema.nullable(),
              replacementVoteId: UuidV7Schema.nullable(),
              auditEventId: UuidV7Schema.nullable(),
              createdAt: Rfc3339UtcSchema
            })
            .strict()
            .nullable()
        })
        .strict()
    )
  })
  .strict();

type VoteEvidence = z.infer<typeof VoteEvidenceSchema>;

const PublicCertificateSnapshotRowSchema = z
  .object({
    organization_id: UuidV7Schema,
    board_id: UuidV7Schema,
    vote_id: UuidV7Schema,
    vote_state: z.literal("closed"),
    vote_row_version: PositiveDecimalSchema,
    vote_title: z.string().min(1),
    close_mode: z.enum(["automatic", "secretariat_confirmed"]),
    deadline_at: Rfc3339UtcSchema,
    resolution_version_id: UuidV7Schema,
    resolution_version: z.number().int().positive().safe(),
    resolution_text: z.string().min(1),
    resolution_sha256: PgJsonSha256Schema,
    decision_package_id: UuidV7Schema,
    decision_package_version: z.number().int().positive().safe(),
    decision_package_sha256: PgJsonSha256Schema,
    submission_manifest_sha256: PgJsonSha256Schema,
    document_manifest_sha256: PgJsonSha256Schema,
    question_cutoff_sha256: PgJsonSha256Schema,
    electorate_sha256: PgJsonSha256Schema,
    governance_profile_id: UuidV7Schema,
    governance_profile_sha256: PgJsonSha256Schema,
    ruleset_id: UuidV7Schema,
    ruleset_sha256: PgJsonSha256Schema,
    matter_evaluation_id: UuidV7Schema,
    matter_evaluation_result_sha256: PgJsonSha256Schema,
    selected_ruleset_rule_id: UuidV7Schema,
    selected_ruleset_rule_sha256: PgJsonSha256Schema,
    rule_override_id: UuidV7Schema.nullable(),
    rule_override_sha256: PgJsonSha256Schema.nullable(),
    approval_rule_id: UuidV7Schema,
    approval_rule_sha256: PgJsonSha256Schema,
    // Match the persisted and canonical certificate rule vocabulary, including
    // reduced 0/1 fractions and profiles which forbid proxy voting.
    threshold_numerator: NonnegativeDecimalSchema,
    threshold_denominator: PositiveDecimalSchema,
    quorum_numerator: NonnegativeDecimalSchema,
    quorum_denominator: PositiveDecimalSchema,
    approval_denominator: z.enum(["eligible", "participating", "yes_no"]),
    abstentions_count_for_quorum: z.boolean(),
    tie_behavior: z.enum(["reject", "chair_casting_vote"]),
    proxy_policy: z.enum(["principal_supersedes_proxy", "first_ballot_final", "forbidden"]),
    instance_id: UuidV7Schema,
    signing_key_id: UuidV7Schema,
    signing_kid: z.string().min(1),
    signing_public_jwk: z.record(z.string(), z.unknown()),
    signing_locator: z.string().min(1),
    clock_sample_id: UuidV7Schema.nullable(),
    clock_measured_at: Rfc3339UtcSchema.nullable(),
    clock_drift_microseconds: IntegerDecimalSchema.nullable(),
    clock_valid_until: Rfc3339UtcSchema.nullable(),
    close_consent_record_sha256: PgJsonSha256Schema.nullable(),
    actor_ready: z.boolean(),
    package_binding_valid: z.boolean(),
    source_ready: z.boolean(),
    qna_ready: z.boolean(),
    clock_healthy: z.boolean(),
    key_valid: z.boolean(),
    consent_valid: z.boolean(),
    outcome_id: UuidV7Schema,
    certificate_id: UuidV7Schema,
    certificate_public_id: PgJsonSha256Schema,
    canonical_certificate_payload: PgJsonBytesSchema,
    certificate_payload_sha256: PgJsonSha256Schema,
    canonical_tally: z.unknown(),
    tally_sha256: PgJsonSha256Schema,
    persisted_outcome: z.enum(["approved", "rejected", "quorum_not_met"]),
    close_actor_member_id: UuidV7Schema.nullable(),
    close_consent_record_id: UuidV7Schema.nullable(),
    closing_audit_event_id: UuidV7Schema,
    closing_audit_sequence: PositiveDecimalSchema,
    closing_audit_hash: PgJsonSha256Schema,
    closing_audit_occurred_at: Rfc3339UtcSchema,
    existing_signature: PgJsonEd25519SignatureSchema,
    existing_certificate_issued_at: Rfc3339UtcSchema,
    existing_certificate_state: z.literal("current")
  })
  .strict();

const PublicCertificateSnapshotEnvelopeSchema = z
  .object({
    row: PublicCertificateSnapshotRowSchema,
    evidence: VoteEvidenceSchema
  })
  .strict();

function hex(value: Buffer): string {
  if (value.length !== 32) throw new Error("persisted SHA-256 value has an invalid length");
  return value.toString("hex");
}

function idempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

function distinctIds<const Values extends readonly string[]>(
  values: Values,
  label: string
): Values {
  const parsed = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(parsed).size !== parsed.length) throw new TypeError(`${label} must be unique`);
  return parsed as unknown as Values;
}

async function readVoteEvidence(
  client: PoolClient,
  organizationId: string,
  voteId: string
): Promise<VoteEvidence> {
  const result = await client.query<{
    electorate: unknown;
    exclusions: unknown;
    proxies: unknown;
    ballots: unknown;
  }>("select * from boardagent_vote_close_evidence($1,$2)", [organizationId, voteId]);
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "vote close evidence is unavailable"
    );
  }
  return VoteEvidenceSchema.parse(row);
}

function consentSetSha256(evidence: VoteEvidence, closeConsentSha256: string | null): string {
  const records = [
    ...evidence.exclusions.map(({ consentRecordSha256 }) => consentRecordSha256),
    ...evidence.proxies.flatMap((proxy) => [
      proxy.consentRecordSha256,
      ...(proxy.revocation?.consentRecordSha256 ? [proxy.revocation.consentRecordSha256] : [])
    ]),
    ...evidence.ballots.map(({ consentRecordSha256 }) => consentRecordSha256),
    ...(closeConsentSha256 ? [closeConsentSha256] : [])
  ].toSorted();
  if (new Set(records).size !== records.length) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "vote close evidence reuses a consent record"
    );
  }
  return canonicalSha256({
    schemaVersion: "boardagent.vote-certificate-consent-set.v1",
    recordSha256: records
  });
}

interface ClosePayloadContext {
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly certificatePublicId: string;
  readonly closeActorMemberId: string | null;
  readonly closeConsentRecordId: string | null;
  readonly closeConsentRecordSha256: string | null;
  readonly closingAuditEventId: string;
  readonly closingAuditSequence: string;
  readonly closingAuditHash: string;
  readonly preparedAt: string;
}

interface BuiltClosePayload {
  readonly payload: VoteCertificatePayload;
  readonly payloadSha256: string;
  readonly canonicalPayload: Buffer;
  readonly tally: ReturnType<typeof canonicalVoteTally>;
  readonly tallySha256: string;
}

function buildClosePayload(
  row: LockedCloseRow,
  evidence: VoteEvidence,
  context: ClosePayloadContext
): BuiltClosePayload {
  if (
    !row.clock_sample_id ||
    !row.clock_measured_at ||
    row.clock_drift_microseconds === null ||
    !row.clock_valid_until
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_clock_unhealthy",
      "vote close requires a current healthy clock sample"
    );
  }
  const preparedElectorate = prepareVoteElectorate({
    voteId: row.vote_id,
    entries: evidence.electorate.map((entry) => {
      canonicalJson(entry.eligibilitySnapshot as JsonValue);
      if (
        !safeHashEqual(
          canonicalSha256(entry.eligibilitySnapshot as JsonValue),
          entry.eligibilitySha256
        )
      ) {
        throw new VoteCloseTransactionError(
          "vote_close_integrity_failure",
          "electorate eligibility evidence does not match its hash"
        );
      }
      return {
        id: entry.id,
        memberId: entry.memberId,
        membershipVersionId: entry.membershipVersionId,
        isChair: entry.isChair,
        votingWeight: BigInt(entry.votingWeight),
        eligibilitySnapshot: entry.eligibilitySnapshot as JsonValue
      };
    })
  });
  if (!safeHashEqual(preparedElectorate.electorateSha256, hex(row.electorate_sha256))) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "persisted electorate no longer matches the frozen package"
    );
  }

  const latestExclusion = new Map<string, (typeof evidence.exclusions)[number]>();
  for (const exclusion of evidence.exclusions) latestExclusion.set(exclusion.memberId, exclusion);
  const electorateByMember = new Map(evidence.electorate.map((entry) => [entry.memberId, entry]));
  const electorate: readonly ElectorSeat[] = evidence.electorate.map((entry) => ({
    memberId: entry.memberId,
    role: entry.seatRole,
    weight: BigInt(entry.votingWeight),
    eligible: true,
    recused: latestExclusion.get(entry.memberId)?.state === "excluded",
    chair: entry.isChair
  }));
  const proxiesById = new Map(evidence.proxies.map((proxy) => [proxy.id, proxy]));
  const effectiveBallots: EffectiveBallot[] = [];
  for (const ballot of evidence.ballots) {
    const seat = electorateByMember.get(ballot.principalMemberId);
    if (
      ballot.decisionPackageId !== row.decision_package_id ||
      !seat ||
      ballot.votingWeight !== seat.votingWeight
    ) {
      throw new VoteCloseTransactionError(
        "vote_close_integrity_failure",
        "ballot does not bind the exact package and frozen principal weight"
      );
    }
    if ((ballot.statementText === null) !== (ballot.statementSha256 === null)) {
      throw new VoteCloseTransactionError(
        "vote_close_integrity_failure",
        "ballot statement evidence is incomplete"
      );
    }
    if (
      ballot.statementText !== null &&
      ballot.statementSha256 !== null &&
      !safeHashEqual(sha256Hex(canonicalText(ballot.statementText)), ballot.statementSha256)
    ) {
      throw new VoteCloseTransactionError(
        "vote_close_integrity_failure",
        "ballot statement does not match its persisted hash"
      );
    }
    if (ballot.source === "own") {
      if (ballot.casterMemberId !== ballot.principalMemberId || ballot.proxyGrantId !== null) {
        throw new VoteCloseTransactionError(
          "vote_close_integrity_failure",
          "own ballot attribution is invalid"
        );
      }
    } else {
      const proxy = ballot.proxyGrantId ? proxiesById.get(ballot.proxyGrantId) : undefined;
      if (
        !proxy ||
        proxy.principalMemberId !== ballot.principalMemberId ||
        proxy.holderMemberId !== ballot.casterMemberId ||
        proxy.policy !== row.proxy_policy
      ) {
        throw new VoteCloseTransactionError(
          "vote_close_integrity_failure",
          "proxy ballot does not bind its exact frozen grant"
        );
      }
    }
    if (ballot.disposition === null) {
      effectiveBallots.push({
        principalMemberId: ballot.principalMemberId,
        casterMemberId: ballot.casterMemberId,
        choice: ballot.choice,
        source: ballot.source
      });
    }
  }
  const rule: ApprovalRule = {
    approval: {
      numerator: BigInt(row.threshold_numerator),
      denominator: BigInt(row.threshold_denominator)
    },
    quorum: {
      numerator: BigInt(row.quorum_numerator),
      denominator: BigInt(row.quorum_denominator)
    },
    approvalDenominator: row.approval_denominator,
    abstentionsCountForQuorum: row.abstentions_count_for_quorum,
    tieBehavior: row.tie_behavior
  };
  let tally;
  try {
    tally = canonicalVoteTally(tallyVote(electorate, effectiveBallots, rule));
  } catch (error) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      `persisted vote evidence cannot be tallied: ${error instanceof Error ? error.message : "invalid evidence"}`
    );
  }
  const tallySha256 = canonicalSha256(tally);
  const payload = VoteCertificatePayloadSchema.parse({
    schema: "boardagent.vote-certificate.v1",
    certificateId: context.certificateId,
    publicId: context.certificatePublicId,
    outcomeId: context.outcomeId,
    instanceId: row.instance_id,
    organizationId: row.organization_id,
    boardId: row.board_id,
    vote: {
      id: row.vote_id,
      title: row.vote_title,
      resolutionVersionId: row.resolution_version_id,
      resolutionVersion: row.resolution_version,
      resolutionText: row.resolution_text,
      resolutionSha256: hex(row.resolution_sha256),
      decisionPackageId: row.decision_package_id,
      decisionPackageVersion: row.decision_package_version,
      decisionPackageSha256: hex(row.decision_package_sha256),
      closeMode: row.close_mode,
      deadlineAt: row.deadline_at
    },
    packageEvidence: {
      submissionManifestSha256: hex(row.submission_manifest_sha256),
      documentManifestSha256: hex(row.document_manifest_sha256),
      questionCutoffSha256: hex(row.question_cutoff_sha256)
    },
    governance: {
      governanceProfileId: row.governance_profile_id,
      governanceProfileSha256: hex(row.governance_profile_sha256),
      rulesetId: row.ruleset_id,
      rulesetSha256: hex(row.ruleset_sha256),
      matterEvaluationId: row.matter_evaluation_id,
      matterEvaluationResultSha256: hex(row.matter_evaluation_result_sha256),
      selectedRulesetRuleId: row.selected_ruleset_rule_id,
      selectedRulesetRuleSha256: hex(row.selected_ruleset_rule_sha256),
      ruleOverrideId: row.rule_override_id,
      ruleOverrideSha256: row.rule_override_sha256 ? hex(row.rule_override_sha256) : null,
      approvalRule: {
        id: row.approval_rule_id,
        canonicalSha256: hex(row.approval_rule_sha256),
        approval: {
          numerator: row.threshold_numerator,
          denominator: row.threshold_denominator
        },
        quorum: { numerator: row.quorum_numerator, denominator: row.quorum_denominator },
        approvalDenominator: row.approval_denominator,
        abstentionsCountForQuorum: row.abstentions_count_for_quorum,
        tieBehavior: row.tie_behavior,
        proxyPolicy: row.proxy_policy,
        closeMode: row.close_mode
      }
    },
    electorateSha256: hex(row.electorate_sha256),
    electorate: evidence.electorate.map((entry) => ({
      memberId: entry.memberId,
      membershipVersionId: entry.membershipVersionId,
      seatRole: entry.seatRole,
      isChair: entry.isChair,
      votingWeight: entry.votingWeight,
      eligibilitySha256: entry.eligibilitySha256
    })),
    exclusions: evidence.exclusions.map((exclusion) => ({
      id: exclusion.id,
      memberId: exclusion.memberId,
      version: exclusion.version,
      state: exclusion.state,
      reasonSha256: sha256Hex(canonicalText(exclusion.reason)),
      actorMemberId: exclusion.actorMemberId,
      consentRecordId: exclusion.consentRecordId,
      consentRecordSha256: exclusion.consentRecordSha256,
      effectiveAt: exclusion.effectiveAt
    })),
    proxies: evidence.proxies,
    ballots: evidence.ballots.map(
      ({ decisionPackageId: _decisionPackageId, statementText: _statementText, ...ballot }) =>
        ballot
    ),
    consentSetSha256: consentSetSha256(evidence, context.closeConsentRecordSha256),
    tally,
    tallySha256,
    outcome: tally.outcome,
    close: {
      actorMemberId: context.closeActorMemberId,
      consentRecordId: context.closeConsentRecordId,
      consentRecordSha256: context.closeConsentRecordSha256,
      clockSampleId: row.clock_sample_id,
      measuredAt: row.clock_measured_at,
      driftMicroseconds: row.clock_drift_microseconds,
      validUntil: row.clock_valid_until
    },
    closingAuditEventId: context.closingAuditEventId,
    closingAuditSequence: context.closingAuditSequence,
    closingAuditHash: context.closingAuditHash,
    preparedAt: context.preparedAt,
    keyId: row.signing_kid,
    signingKeyId: row.signing_key_id
  });
  const canonicalPayload = Buffer.from(canonicalVoteCertificatePayload(payload), "utf8");
  return { payload, payloadSha256: canonicalSha256(payload), canonicalPayload, tally, tallySha256 };
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select id,request_sha256,state,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='close_vote' and idempotency_key=$3
      for update`,
    [actorMemberId, clientId, key]
  );
  return result.rows[0];
}

function checkedReplay(
  row: IdempotencyRow | undefined,
  requestSha256: string,
  outcomeId: string
): { readonly responseSha256: string } | undefined {
  if (!row) return undefined;
  if (!safeHashEqual(hex(row.request_sha256), requestSha256)) {
    throw new VoteCloseTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different vote close"
    );
  }
  if (row.state === "succeeded" && row.safe_response_id === outcomeId && row.safe_response_sha256) {
    return { responseSha256: hex(row.safe_response_sha256) };
  }
  throw new VoteCloseTransactionError(
    "idempotency_in_progress",
    "identical vote close is already in progress"
  );
}

async function insertIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly key: string;
    readonly requestSha256: string;
    readonly outcomeId: string;
  }
): Promise<void> {
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'close_vote',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      input.id,
      input.organizationId,
      input.actorMemberId,
      input.clientId,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
  const persisted = await readIdempotency(client, input.actorMemberId, input.clientId, input.key);
  if (!persisted) throw new Error("vote-close idempotency record disappeared");
  if (inserted.rowCount === 0) checkedReplay(persisted, input.requestSha256, input.outcomeId);
  if (!safeHashEqual(hex(persisted.request_sha256), input.requestSha256)) {
    throw new VoteCloseTransactionError(
      "idempotency_conflict",
      "vote-close idempotency record does not bind this request"
    );
  }
}

async function finishIdempotency(
  client: PoolClient,
  id: string,
  outcomeId: string,
  responseSha256: string
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='vote_outcome',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [outcomeId, Buffer.from(responseSha256, "hex"), id]
  );
  if (result.rowCount !== 1) throw new Error("vote-close idempotency completion failed");
}

async function loadPersistedCloseRow(
  client: PoolClient,
  organizationId: string,
  voteId: string,
  outcomeId: string,
  certificateId: string
): Promise<PersistedCloseRow | undefined> {
  const result = await client.query<PersistedCloseRow>(
    `select vote.organization_id,vote.board_id,vote.id as vote_id,
            vote.state as vote_state,vote.row_version::text as vote_row_version,
            vote.title as vote_title,vote.close_mode,
            to_char(vote.deadline_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as deadline_at,
            resolution.id as resolution_version_id,resolution.version as resolution_version,
            resolution.canonical_text as resolution_text,
            resolution.canonical_sha256 as resolution_sha256,
            package.id as decision_package_id,package.version as decision_package_version,
            package.package_sha256 as decision_package_sha256,
            package.submission_manifest_sha256,package.document_manifest_sha256,
            package.question_cutoff_sha256,package.electorate_sha256,
            package.governance_profile_id,package.governance_profile_sha256,
            package.ruleset_id,package.ruleset_sha256,
            package.matter_evaluation_id,package.matter_evaluation_result_sha256,
            package.selected_ruleset_rule_id,package.selected_ruleset_rule_sha256,
            package.rule_override_id,package.rule_override_sha256,
            rule.id as approval_rule_id,rule.canonical_sha256 as approval_rule_sha256,
            rule.threshold_numerator::text,rule.threshold_denominator::text,
            rule.quorum_numerator::text,rule.quorum_denominator::text,
            rule.approval_denominator,rule.abstentions_count_for_quorum,
            rule.tie_behavior,rule.proxy_policy,instance.instance_id,
            evidence_key.id as signing_key_id,evidence_key.kid as signing_kid,
            evidence_key.public_jwk as signing_public_jwk,
            evidence_key.nonsecret_locator as signing_locator,
            clock.id as clock_sample_id,
            to_char(clock.measured_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as clock_measured_at,
            clock.drift_microseconds::text as clock_drift_microseconds,
            to_char(clock.valid_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as clock_valid_until,
            close_consent.record_sha256 as close_consent_record_sha256,
            true as actor_ready,true as package_binding_valid,true as source_ready,
            true as qna_ready,true as clock_healthy,true as key_valid,true as consent_valid,
            outcome.id as outcome_id,outcome.certificate_id,outcome.certificate_public_id,
            outcome.canonical_certificate_payload,outcome.certificate_payload_sha256,
            outcome.canonical_tally,outcome.tally_sha256,
            outcome.outcome as persisted_outcome,outcome.close_actor_member_id,
            outcome.close_consent_record_id,outcome.closing_audit_event_id,
            closing.sequence::text as closing_audit_sequence,
            closing.event_sha256 as closing_audit_hash,
            to_char(closing.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
              as closing_audit_occurred_at
       from vote_outcomes as outcome
       join votes as vote on vote.id=outcome.vote_id
       join system_instance as instance on instance.organization_id=vote.organization_id
       join decision_packages as package on package.id=outcome.decision_package_id
       join resolution_versions as resolution on resolution.id=package.resolution_version_id
       join approval_rules as rule on rule.id=outcome.approval_rule_id
       join crypto_key_registry as evidence_key on evidence_key.id=outcome.signing_key_id
       join clock_health_samples as clock on clock.id=outcome.clock_sample_id
       join audit_events as closing on closing.id=outcome.closing_audit_event_id
       left join consent_records as close_consent on close_consent.id=outcome.close_consent_record_id
      where outcome.organization_id=$1 and outcome.vote_id=$2 and outcome.id=$3
        and outcome.certificate_id=$4`,
    [organizationId, voteId, outcomeId, certificateId]
  );
  return result.rows.length === 1 ? result.rows[0] : undefined;
}

function parsePersistedPayload(row: PersistedCloseRow): VoteCertificatePayload {
  let decoded: unknown;
  try {
    decoded = JSON.parse(row.canonical_certificate_payload.toString("utf8")) as unknown;
  } catch {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "persisted certificate payload is not canonical JSON"
    );
  }
  const payload = VoteCertificatePayloadSchema.parse(decoded);
  if (
    !safeHashEqual(canonicalSha256(payload), hex(row.certificate_payload_sha256)) ||
    canonicalVoteCertificatePayload(payload) !== row.canonical_certificate_payload.toString("utf8")
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "persisted certificate payload does not match its canonical hash"
    );
  }
  return payload;
}

/**
 * Locks and recomputes the exact manual-close evidence before an MRTR stage exists.
 * The active evidence key is selected from persisted key history; only its non-secret
 * locator crosses the later signer port.
 */
export async function prepareVoteCloseInTransaction(
  client: PoolClient,
  input: PrepareVoteCloseInput
): Promise<PreparedVoteClose> {
  const context = await readRequestContext(client);
  const voteId = UuidV7Schema.parse(input.voteId);
  const expectedPackageSha256 = Sha256HexSchema.parse(input.expectedPackageSha256);
  const visibility = await client.query<{ recused: boolean }>(
    `select boardagent_member_vote_recused($1,
       boardagent_context_uuid('boardagent.member_id')) as recused`,
    [voteId]
  );
  if (visibility.rows[0]?.recused !== false) {
    throw new VoteCloseTransactionError("vote_close_unavailable", "vote close is unavailable");
  }
  const [outcomeId, certificateId, closeConsentRecordId, closingAuditEventId] = distinctIds(
    [input.outcomeId, input.certificateId, input.closeConsentRecordId, input.closingAuditEventId],
    "prepared vote-close IDs"
  );
  const certificatePublicId = input.certificatePublicId;
  certificatePublicIdBytes(certificatePublicId);
  const selectedKey = await client.query<{ id: string }>(
    `select id
       from crypto_key_registry
      where organization_id=$1 and purpose='evidence_signing' and algorithm='EdDSA'
        and public_jwk is not null and activated_at<=transaction_timestamp()
        and (retired_at is null or retired_at>transaction_timestamp())
        and compromised_at is null
      order by activated_at desc,id desc
      limit 1`,
    [context.organizationId]
  );
  const signingKeyId = selectedKey.rows[0]?.id;
  if (!signingKeyId || selectedKey.rows.length !== 1) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "vote close requires one active uncompromised Ed25519 evidence key"
    );
  }
  const locked = await client.query<LockedCloseRow>(
    "select * from boardagent_lock_vote_for_close($1,$2,$3,$4)",
    [voteId, null, Buffer.alloc(32), signingKeyId]
  );
  const row = locked.rows[0];
  if (!row || locked.rows.length !== 1 || row.organization_id !== context.organizationId) {
    throw new VoteCloseTransactionError("vote_close_unavailable", "vote close is unavailable");
  }
  const lockedVisibility = await client.query<{ recused: boolean }>(
    `select boardagent_member_vote_recused($1,
       boardagent_context_uuid('boardagent.member_id')) as recused`,
    [voteId]
  );
  if (lockedVisibility.rows[0]?.recused !== false) {
    throw new VoteCloseTransactionError("vote_close_unavailable", "vote close is unavailable");
  }
  if (row.vote_state === "source_update_pending" || !row.source_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_source_pending",
      "vote close is blocked by an unresolved source update"
    );
  }
  if (row.vote_state !== "open" || row.close_mode !== "secretariat_confirmed") {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "confirmed close requires an open secretariat-confirmed vote"
    );
  }
  if (!row.actor_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "vote close actor is unavailable"
    );
  }
  if (
    !row.package_binding_valid ||
    !safeHashEqual(hex(row.decision_package_sha256), expectedPackageSha256)
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_invalid",
      "vote close does not bind the exact current package and governance evidence"
    );
  }
  if (!row.qna_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_qna_unanswered",
      "vote close is blocked until every included Q&A cutoff has a recorded management answer"
    );
  }
  if (!row.clock_healthy) {
    throw new VoteCloseTransactionError(
      "vote_close_clock_unhealthy",
      "vote close is suppressed because the current clock sample is unhealthy or stale"
    );
  }
  if (!row.key_valid || row.signing_key_id !== signingKeyId) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "vote close requires an active uncompromised Ed25519 evidence key"
    );
  }
  const evidence = await readVoteEvidence(client, context.organizationId, voteId);
  const preview = buildClosePayload(row, evidence, {
    outcomeId,
    certificateId,
    certificatePublicId,
    closeActorMemberId: context.memberId,
    closeConsentRecordId,
    closeConsentRecordSha256: "0".repeat(64),
    closingAuditEventId,
    closingAuditSequence: "1",
    closingAuditHash: "0".repeat(64),
    preparedAt: row.clock_measured_at ?? "1970-01-01T00:00:00Z"
  });
  const packageResult = await client.query<{ decision_package: JsonValue }>(
    `select convert_from(canonical_payload,'UTF8')::jsonb as decision_package
       from decision_packages where id=$1 and vote_id=$2`,
    [row.decision_package_id, voteId]
  );
  const decisionPackage = packageResult.rows[0]?.decision_package;
  if (decisionPackage === undefined || packageResult.rows.length !== 1) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "current decision package is unavailable"
    );
  }
  canonicalJson(decisionPackage);
  const publicIdSha256 = certificatePublicIdSha256(certificatePublicId);
  const canonicalPayload: JsonValue = {
    schemaVersion: "boardagent.vote-close-consent.v1",
    voteId,
    packageSha256: expectedPackageSha256,
    expectedTallySha256: preview.tallySha256,
    outcomeId,
    certificateId,
    certificatePublicIdSha256: publicIdSha256,
    signingKeyId
  };
  const payloadSha256 = voteCloseConsentHash({
    voteId,
    packageSha256: expectedPackageSha256,
    expectedTallySha256: preview.tallySha256,
    outcomeId,
    certificateId,
    certificatePublicIdSha256: publicIdSha256,
    signingKeyId
  });
  if (!safeHashEqual(payloadSha256, canonicalSha256(canonicalPayload))) {
    throw new Error("vote close consent payload construction drifted");
  }
  return {
    organizationId: context.organizationId,
    boardId: row.board_id,
    voteId,
    voteTitle: row.vote_title,
    resolutionText: row.resolution_text,
    resolutionSha256: hex(row.resolution_sha256),
    decisionPackage,
    packageSha256: expectedPackageSha256,
    expectedTally: preview.tally,
    expectedTallySha256: preview.tallySha256,
    outcomeId,
    certificateId,
    certificatePublicIdSha256: publicIdSha256,
    signingKeyId,
    signingKeyLocator: row.signing_locator,
    canonicalPayload,
    payloadSha256
  };
}

export async function initiateVoteCloseInTransaction(
  client: PoolClient,
  input: InitiateVoteCloseInput
): Promise<VoteCloseDraftResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const signingKeyId = UuidV7Schema.parse(input.signingKeyId);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const [outcomeId, certificateId, closingAuditEventId, idempotencyRecordId] = distinctIds(
    [input.outcomeId, input.certificateId, input.closingAuditEventId, input.idempotencyRecordId],
    "vote-close generated IDs"
  );
  const certificatePublicId = input.certificatePublicId;
  const publicIdBytes = certificatePublicIdBytes(certificatePublicId);
  const expectedPackageSha256 = Sha256HexSchema.parse(input.expectedPackageSha256);
  const expectedTallySha256 = Sha256HexSchema.parse(input.expectedTallySha256);
  const key = idempotencyKey(input.idempotencyKey);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new VoteCloseTransactionError("vote_close_unavailable", "vote close is unavailable");
  }
  const consentPayloadSha256 = voteCloseConsentHash({
    voteId,
    packageSha256: expectedPackageSha256,
    expectedTallySha256,
    outcomeId,
    certificateId,
    certificatePublicIdSha256: certificatePublicIdSha256(certificatePublicId),
    signingKeyId
  });
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-close-request.v1",
    organizationId,
    voteId,
    outcomeId,
    certificateId,
    certificatePublicId,
    expectedPackageSha256,
    expectedTallySha256,
    signingKeyId,
    consentRecordId
  });
  const locked = await client.query<LockedCloseRow>(
    "select * from boardagent_lock_vote_for_close($1,$2,$3,$4)",
    [voteId, consentRecordId, Buffer.from(consentPayloadSha256, "hex"), signingKeyId]
  );
  const row = locked.rows[0];
  if (!row || locked.rows.length !== 1 || row.organization_id !== organizationId) {
    throw new VoteCloseTransactionError("vote_close_unavailable", "vote close is unavailable");
  }
  const replay = checkedReplay(
    await readIdempotency(client, context.memberId, context.clientId, key),
    requestSha256,
    outcomeId
  );
  if (replay) {
    const persisted = await loadPersistedCloseRow(
      client,
      organizationId,
      voteId,
      outcomeId,
      certificateId
    );
    if (!persisted || !["closing", "closed"].includes(persisted.vote_state)) {
      throw new VoteCloseTransactionError(
        "vote_close_integrity_failure",
        "successful vote-close replay has no persisted close draft"
      );
    }
    return {
      replayed: true,
      voteId,
      outcomeId,
      certificateId,
      state: persisted.vote_state as "closing" | "closed",
      payload: parsePersistedPayload(persisted),
      payloadSha256: hex(persisted.certificate_payload_sha256),
      signingKeyId: persisted.signing_key_id,
      signingKeyLocator: persisted.signing_locator,
      responseSha256: replay.responseSha256
    };
  }
  if (row.vote_state === "source_update_pending" || !row.source_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_source_pending",
      "vote close is blocked by an unresolved source update"
    );
  }
  if (row.vote_state !== "open" || row.close_mode !== "secretariat_confirmed") {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "confirmed close requires an open secretariat-confirmed vote"
    );
  }
  if (!row.actor_ready || !row.consent_valid) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "vote close actor or fresh confirmation is unavailable"
    );
  }
  if (
    !row.package_binding_valid ||
    !safeHashEqual(hex(row.decision_package_sha256), expectedPackageSha256)
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_invalid",
      "vote close does not bind the exact current package and governance evidence"
    );
  }
  if (!row.qna_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_qna_unanswered",
      "vote close is blocked until every included Q&A cutoff has a recorded management answer"
    );
  }
  if (!row.clock_healthy) {
    throw new VoteCloseTransactionError(
      "vote_close_clock_unhealthy",
      "vote close is suppressed because the current clock sample is unhealthy or stale"
    );
  }
  if (!row.key_valid || row.signing_key_id !== signingKeyId) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "vote close requires an active uncompromised Ed25519 evidence key"
    );
  }
  if (!row.close_consent_record_sha256) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "confirmed vote close is missing its consent record hash"
    );
  }
  const evidence = await readVoteEvidence(client, organizationId, voteId);
  const payloadContextBase = {
    outcomeId,
    certificateId,
    certificatePublicId,
    closeActorMemberId: context.memberId,
    closeConsentRecordId: consentRecordId,
    closeConsentRecordSha256: hex(row.close_consent_record_sha256),
    closingAuditEventId,
    closingAuditSequence: "1",
    closingAuditHash: "0".repeat(64),
    preparedAt: row.clock_measured_at ?? "1970-01-01T00:00:00Z"
  } as const;
  const preview = buildClosePayload(row, evidence, payloadContextBase);
  if (!safeHashEqual(preview.tallySha256, expectedTallySha256)) {
    throw new VoteCloseTransactionError(
      "vote_close_invalid",
      "confirmed tally no longer matches the locked persisted vote evidence"
    );
  }
  await insertIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    key,
    requestSha256,
    outcomeId
  });
  const [closingEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      consentRecordId,
      objectVersion: BigInt(row.vote_row_version) + 1n,
      event: {
        eventId: closingAuditEventId,
        eventType: "vote_closing",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: voteId,
        boardId: row.board_id,
        origin: "mcp",
        details: {
          outcomeId,
          certificateId,
          certificatePublicIdSha256: certificatePublicIdSha256(certificatePublicId),
          decisionPackageSha256: expectedPackageSha256,
          tallySha256: preview.tallySha256,
          outcome: preview.tally.outcome,
          signingKeyId
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!closingEvent) throw new Error("vote-closing audit append returned no event");
  const built = buildClosePayload(row, evidence, {
    ...payloadContextBase,
    closingAuditSequence: closingEvent.sequence.toString(10),
    closingAuditHash: closingEvent.eventHash,
    preparedAt: closingEvent.occurredAt
  });
  if (!safeHashEqual(built.tallySha256, preview.tallySha256)) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "vote tally changed while preparing the immutable certificate payload"
    );
  }
  const committed = await client.query<{ vote_id: string; outcome_id: string; state: string }>(
    `select * from boardagent_commit_vote_close_draft(
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
     )`,
    [
      organizationId,
      voteId,
      outcomeId,
      certificateId,
      publicIdBytes,
      row.decision_package_id,
      row.electorate_sha256,
      row.approval_rule_id,
      built.tally,
      Buffer.from(built.tallySha256, "hex"),
      built.tally.outcome === "no_quorum" ? "quorum_not_met" : built.tally.outcome,
      row.close_mode,
      context.memberId,
      consentRecordId,
      built.canonicalPayload,
      Buffer.from(built.payloadSha256, "hex"),
      signingKeyId,
      row.clock_sample_id,
      closingAuditEventId,
      Buffer.from(consentPayloadSha256, "hex")
    ]
  );
  if (committed.rows.length !== 1 || committed.rows[0]?.state !== "closing") {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "vote close draft did not enter the recoverable closing state"
    );
  }
  const responseSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-close-draft-response.v1",
    voteId,
    outcomeId,
    certificateId,
    payloadSha256: built.payloadSha256,
    state: "closing"
  });
  await finishIdempotency(client, idempotencyRecordId, outcomeId, responseSha256);
  return {
    replayed: false,
    voteId,
    outcomeId,
    certificateId,
    state: "closing",
    payload: built.payload,
    payloadSha256: built.payloadSha256,
    signingKeyId,
    signingKeyLocator: row.signing_locator,
    responseSha256
  };
}

/**
 * Recomputes the immutable expectations for a deadline-driven close before any close
 * draft is written. The initiating transaction rechecks every value after this lock is
 * released, so a concurrent governance change fails closed rather than being signed.
 */
export async function prepareAutomaticVoteCloseInTransaction(
  client: PoolClient,
  input: PrepareAutomaticVoteCloseInput
): Promise<PreparedAutomaticVoteClose> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const signingKeyId = UuidV7Schema.parse(input.signingKeyId);
  const [outcomeId, certificateId, closingAuditEventId] = distinctIds(
    [input.outcomeId, input.certificateId, input.closingAuditEventId],
    "automatic vote-close preparation IDs"
  );
  const certificatePublicId = input.certificatePublicId;
  certificatePublicIdBytes(certificatePublicId);
  const locked = await client.query<LockedCloseRow>(
    "select * from boardagent_lock_vote_for_close($1,$2,$3,$4)",
    [voteId, null, Buffer.alloc(32), signingKeyId]
  );
  const row = locked.rows[0];
  if (!row || locked.rows.length !== 1 || row.organization_id !== organizationId) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "automatic vote close is unavailable"
    );
  }
  if (row.vote_state === "source_update_pending" || !row.source_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_source_pending",
      "automatic vote close is blocked by an unresolved source update"
    );
  }
  if (row.vote_state !== "open" || row.close_mode !== "automatic" || !row.actor_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "automatic close requires an open automatic vote whose deadline has elapsed"
    );
  }
  if (!row.package_binding_valid) {
    throw new VoteCloseTransactionError(
      "vote_close_invalid",
      "automatic vote close does not bind the exact current package"
    );
  }
  if (!row.qna_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_qna_unanswered",
      "automatic vote close is blocked by included unanswered Q&A"
    );
  }
  if (!row.clock_healthy) {
    throw new VoteCloseTransactionError(
      "vote_close_clock_unhealthy",
      "automatic vote close is suppressed by unhealthy or stale clock evidence"
    );
  }
  if (!row.key_valid || !row.consent_valid || row.signing_key_id !== signingKeyId) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "automatic vote close requires its active Ed25519 evidence key"
    );
  }
  const evidence = await readVoteEvidence(client, organizationId, voteId);
  const preview = buildClosePayload(row, evidence, {
    outcomeId,
    certificateId,
    certificatePublicId,
    closeActorMemberId: null,
    closeConsentRecordId: null,
    closeConsentRecordSha256: null,
    closingAuditEventId,
    closingAuditSequence: "1",
    closingAuditHash: "0".repeat(64),
    preparedAt: row.clock_measured_at ?? "1970-01-01T00:00:00Z"
  });
  return {
    organizationId,
    boardId: row.board_id,
    voteId,
    outcomeId,
    certificateId,
    certificatePublicId,
    expectedPackageSha256: hex(row.decision_package_sha256),
    expectedTallySha256: preview.tallySha256,
    signingKeyId,
    signingKeyLocator: row.signing_locator
  };
}

/**
 * Recomputes a frozen closing draft for a crash-safe signer retry. It never creates or
 * changes governance state; a completed concurrent recovery is returned as a replay.
 */
export async function prepareVoteCertificateRecoveryInTransaction(
  client: PoolClient,
  input: { readonly organizationId: string; readonly voteId: string }
): Promise<PreparedVoteCertificateRecovery> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const identity = await client.query<{
    outcome_id: string;
    certificate_id: string;
    vote_state: string;
  }>(
    `select outcome_id,certificate_id,vote_state
       from boardagent_closing_vote_recovery_identity($1,$2)`,
    [organizationId, voteId]
  );
  const reference = identity.rows[0];
  if (!reference || identity.rows.length !== 1) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "certificate recovery is unavailable"
    );
  }
  const outcomeId = UuidV7Schema.parse(reference.outcome_id);
  const certificateId = UuidV7Schema.parse(reference.certificate_id);
  const locked = await client.query<ClosingLockRow>(
    "select * from boardagent_lock_closing_vote($1,$2,$3,$4)",
    [organizationId, voteId, outcomeId, certificateId]
  );
  const row = locked.rows[0];
  if (!row || locked.rows.length !== 1 || row.organization_id !== organizationId) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "certificate recovery is unavailable"
    );
  }
  if (row.vote_state === "closed") {
    if (row.existing_certificate_state !== "current" || row.existing_signature === null) {
      throw new VoteCloseTransactionError(
        "vote_close_integrity_failure",
        "closed vote recovery could not prove its current signed certificate"
      );
    }
    return {
      required: false,
      organizationId,
      boardId: row.board_id,
      voteId,
      outcomeId,
      certificateId,
      state: "closed"
    };
  }
  if (
    reference.vote_state !== "closing" ||
    row.vote_state !== "closing" ||
    row.existing_signature !== null ||
    !row.key_valid
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "certificate recovery does not bind one unsigned closing vote and valid key"
    );
  }
  const built = await recomputePersistedClose(client, row);
  return {
    required: true,
    organizationId,
    boardId: row.board_id,
    voteId,
    outcomeId,
    certificateId,
    state: "closing",
    payload: built.payload,
    payloadSha256: built.payloadSha256,
    signingKeyId: row.signing_key_id,
    signingKeyLocator: row.signing_locator
  };
}

/** Deadline-driven close entrypoint. It is callable only inside the restricted worker role. */
export async function initiateAutomaticVoteCloseInTransaction(
  client: PoolClient,
  input: InitiateAutomaticVoteCloseInput
): Promise<VoteCloseDraftResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const signingKeyId = UuidV7Schema.parse(input.signingKeyId);
  const [outcomeId, certificateId, closingAuditEventId] = distinctIds(
    [input.outcomeId, input.certificateId, input.closingAuditEventId],
    "automatic vote-close generated IDs"
  );
  const certificatePublicId = input.certificatePublicId;
  const publicIdBytes = certificatePublicIdBytes(certificatePublicId);
  const expectedPackageSha256 = Sha256HexSchema.parse(input.expectedPackageSha256);
  const expectedTallySha256 = Sha256HexSchema.parse(input.expectedTallySha256);
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.automatic-vote-close-request.v1",
    organizationId,
    voteId,
    outcomeId,
    certificateId,
    certificatePublicId,
    expectedPackageSha256,
    expectedTallySha256,
    signingKeyId
  });
  const locked = await client.query<LockedCloseRow>(
    "select * from boardagent_lock_vote_for_close($1,$2,$3,$4)",
    [voteId, null, Buffer.from(requestSha256, "hex"), signingKeyId]
  );
  const row = locked.rows[0];
  if (!row || locked.rows.length !== 1 || row.organization_id !== organizationId) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "automatic vote close is unavailable"
    );
  }
  if (["closing", "closed"].includes(row.vote_state)) {
    const closing = await client.query<ClosingLockRow>(
      "select * from boardagent_lock_closing_vote($1,$2,$3,$4)",
      [organizationId, voteId, outcomeId, certificateId]
    );
    const persisted = closing.rows[0];
    if (!persisted || closing.rows.length !== 1) {
      throw new VoteCloseTransactionError(
        "vote_close_integrity_failure",
        "automatic close replay does not match the persisted close draft"
      );
    }
    const built = await recomputePersistedClose(client, persisted);
    const responseSha256 = canonicalSha256({
      schemaVersion: "boardagent.vote-close-draft-response.v1",
      voteId,
      outcomeId,
      certificateId,
      payloadSha256: built.payloadSha256,
      state: "closing"
    });
    return {
      replayed: true,
      voteId,
      outcomeId,
      certificateId,
      state: persisted.vote_state as "closing" | "closed",
      payload: built.payload,
      payloadSha256: built.payloadSha256,
      signingKeyId,
      signingKeyLocator: persisted.signing_locator,
      responseSha256
    };
  }
  if (row.vote_state === "source_update_pending" || !row.source_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_source_pending",
      "automatic vote close is blocked by an unresolved source update"
    );
  }
  if (row.vote_state !== "open" || row.close_mode !== "automatic" || !row.actor_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "automatic close requires an open automatic vote whose deadline has elapsed"
    );
  }
  if (
    !row.package_binding_valid ||
    !safeHashEqual(hex(row.decision_package_sha256), expectedPackageSha256)
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_invalid",
      "automatic vote close does not bind the exact current package"
    );
  }
  if (!row.qna_ready) {
    throw new VoteCloseTransactionError(
      "vote_close_qna_unanswered",
      "automatic vote close is blocked by included unanswered Q&A"
    );
  }
  if (!row.clock_healthy) {
    throw new VoteCloseTransactionError(
      "vote_close_clock_unhealthy",
      "automatic vote close is suppressed by unhealthy or stale clock evidence"
    );
  }
  if (!row.key_valid || !row.consent_valid || row.signing_key_id !== signingKeyId) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "automatic vote close requires its active Ed25519 evidence key"
    );
  }
  const evidence = await readVoteEvidence(client, organizationId, voteId);
  const payloadContextBase = {
    outcomeId,
    certificateId,
    certificatePublicId,
    closeActorMemberId: null,
    closeConsentRecordId: null,
    closeConsentRecordSha256: null,
    closingAuditEventId,
    closingAuditSequence: "1",
    closingAuditHash: "0".repeat(64),
    preparedAt: row.clock_measured_at ?? "1970-01-01T00:00:00Z"
  } as const;
  const preview = buildClosePayload(row, evidence, payloadContextBase);
  if (!safeHashEqual(preview.tallySha256, expectedTallySha256)) {
    throw new VoteCloseTransactionError(
      "vote_close_invalid",
      "automatic close tally no longer matches persisted vote evidence"
    );
  }
  const [closingEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: BigInt(row.vote_row_version) + 1n,
      event: {
        eventId: closingAuditEventId,
        eventType: "vote_closing",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "vote",
        entityId: voteId,
        boardId: row.board_id,
        origin: "worker",
        details: {
          closeTrigger: "deadline",
          outcomeId,
          certificateId,
          certificatePublicIdSha256: certificatePublicIdSha256(certificatePublicId),
          decisionPackageSha256: expectedPackageSha256,
          tallySha256: preview.tallySha256,
          outcome: preview.tally.outcome,
          signingKeyId
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!closingEvent) throw new Error("automatic vote-closing audit append returned no event");
  const built = buildClosePayload(row, evidence, {
    ...payloadContextBase,
    closingAuditSequence: closingEvent.sequence.toString(10),
    closingAuditHash: closingEvent.eventHash,
    preparedAt: closingEvent.occurredAt
  });
  const committed = await client.query<{ state: string }>(
    `select * from boardagent_commit_vote_close_draft(
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
     )`,
    [
      organizationId,
      voteId,
      outcomeId,
      certificateId,
      publicIdBytes,
      row.decision_package_id,
      row.electorate_sha256,
      row.approval_rule_id,
      built.tally,
      Buffer.from(built.tallySha256, "hex"),
      built.tally.outcome === "no_quorum" ? "quorum_not_met" : built.tally.outcome,
      row.close_mode,
      null,
      null,
      built.canonicalPayload,
      Buffer.from(built.payloadSha256, "hex"),
      signingKeyId,
      row.clock_sample_id,
      closingAuditEventId,
      Buffer.from(requestSha256, "hex")
    ]
  );
  if (committed.rows[0]?.state !== "closing") {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "automatic vote close did not enter its recoverable closing state"
    );
  }
  const responseSha256 = canonicalSha256({
    schemaVersion: "boardagent.vote-close-draft-response.v1",
    voteId,
    outcomeId,
    certificateId,
    payloadSha256: built.payloadSha256,
    state: "closing"
  });
  return {
    replayed: false,
    voteId,
    outcomeId,
    certificateId,
    state: "closing",
    payload: built.payload,
    payloadSha256: built.payloadSha256,
    signingKeyId,
    signingKeyLocator: row.signing_locator,
    responseSha256
  };
}

async function recomputePersistedClose(
  client: PoolClient,
  row: PersistedCloseRow,
  evidenceInput?: VoteEvidence
): Promise<BuiltClosePayload> {
  const evidence =
    evidenceInput ?? (await readVoteEvidence(client, row.organization_id, row.vote_id));
  const built = buildClosePayload(row, evidence, {
    outcomeId: row.outcome_id,
    certificateId: row.certificate_id,
    certificatePublicId: row.certificate_public_id.toString("base64url"),
    closeActorMemberId: row.close_actor_member_id,
    closeConsentRecordId: row.close_consent_record_id,
    closeConsentRecordSha256: row.close_consent_record_sha256
      ? hex(row.close_consent_record_sha256)
      : null,
    closingAuditEventId: row.closing_audit_event_id,
    closingAuditSequence: row.closing_audit_sequence,
    closingAuditHash: hex(row.closing_audit_hash),
    preparedAt: row.closing_audit_occurred_at
  });
  const expectedOutcome =
    row.persisted_outcome === "quorum_not_met" ? "no_quorum" : row.persisted_outcome;
  if (
    canonicalJson(row.canonical_tally as JsonValue) !== canonicalJson(built.tally) ||
    !safeHashEqual(hex(row.tally_sha256), built.tallySha256) ||
    expectedOutcome !== built.tally.outcome ||
    !safeHashEqual(hex(row.certificate_payload_sha256), built.payloadSha256) ||
    !row.canonical_certificate_payload.equals(built.canonicalPayload)
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "persisted outcome or certificate draft does not recompute from vote truth"
    );
  }
  const persistedPayload = parsePersistedPayload(row);
  if (
    canonicalVoteCertificatePayload(persistedPayload) !==
    canonicalVoteCertificatePayload(built.payload)
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "persisted certificate payload differs from recomputed vote truth"
    );
  }
  return built;
}

function trustedEvidenceKey(publicJwk: unknown) {
  try {
    return createPublicKey({ key: publicJwk as JsonWebKey, format: "jwk" });
  } catch {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "persisted evidence key is not a valid public JWK"
    );
  }
}

async function readCloseExecutionContext(client: PoolClient): Promise<
  | {
      readonly scope: "request";
      readonly actorMemberId: string;
      readonly actorClientId: string;
      readonly tokenJti: string;
      readonly origin: "mcp";
      readonly organizationId: string;
    }
  | {
      readonly scope: "worker";
      readonly actorMemberId: null;
      readonly actorClientId: null;
      readonly tokenJti: null;
      readonly origin: "worker";
      readonly organizationId: null;
    }
> {
  const scope = await client.query<{ scope: string | null }>(
    "select current_setting('boardagent.transaction_scope',true) as scope"
  );
  if (scope.rows[0]?.scope === "worker") {
    return {
      scope: "worker",
      actorMemberId: null,
      actorClientId: null,
      tokenJti: null,
      origin: "worker",
      organizationId: null
    };
  }
  const context = await readRequestContext(client);
  return {
    scope: "request",
    actorMemberId: context.memberId,
    actorClientId: context.clientId,
    tokenJti: context.tokenJti,
    origin: "mcp",
    organizationId: context.organizationId
  };
}

export async function finalizeVoteCloseInTransaction(
  client: PoolClient,
  input: FinalizeVoteCloseInput
): Promise<VoteCloseFinalResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const voteId = UuidV7Schema.parse(input.voteId);
  const [outcomeId, certificateId, certificateIssuedAuditEventId, voteClosedAuditEventId] =
    distinctIds(
      [
        input.outcomeId,
        input.certificateId,
        input.certificateIssuedAuditEventId,
        input.voteClosedAuditEventId
      ],
      "vote-certificate finalization IDs"
    );
  if (!/^[A-Za-z0-9_-]{86}$/u.test(input.signatureBase64Url)) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "vote certificate signature is not a 64-byte Ed25519 signature"
    );
  }
  const signature = Buffer.from(input.signatureBase64Url, "base64url");
  if (signature.length !== 64) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "vote certificate signature is not a 64-byte Ed25519 signature"
    );
  }
  const context = await readCloseExecutionContext(client);
  if (context.scope === "request" && context.organizationId !== organizationId) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "certificate finalization is unavailable"
    );
  }
  const locked = await client.query<ClosingLockRow>(
    "select * from boardagent_lock_closing_vote($1,$2,$3,$4)",
    [organizationId, voteId, outcomeId, certificateId]
  );
  const lock = locked.rows[0];
  if (
    !lock ||
    locked.rows.length !== 1 ||
    lock.organization_id !== organizationId ||
    lock.outcome_id !== outcomeId ||
    lock.certificate_id !== certificateId
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "certificate finalization is unavailable"
    );
  }
  const persisted: PersistedCloseRow = lock;
  const built = await recomputePersistedClose(client, persisted);
  if (!lock.key_valid || lock.signing_key_id !== persisted.signing_key_id) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "certificate finalization requires its active uncompromised evidence key"
    );
  }
  const publicKey = trustedEvidenceKey(lock.signing_public_jwk);
  if (
    !verifyVoteCertificate(
      {
        payload: built.payload,
        payloadSha256: built.payloadSha256,
        signatureBase64Url: input.signatureBase64Url
      },
      publicKey
    )
  ) {
    throw new VoteCloseTransactionError(
      "vote_close_signer_invalid",
      "certificate signature does not verify against the trusted evidence key"
    );
  }
  if (lock.vote_state === "closed") {
    if (
      lock.existing_certificate_state !== "current" ||
      !lock.existing_signature ||
      !lock.existing_signature.equals(signature)
    ) {
      throw new VoteCloseTransactionError(
        "vote_close_integrity_failure",
        "closed vote certificate does not match the supplied signed draft"
      );
    }
    const replay = await client.query<{ closed_at: string }>(
      `select to_char(closed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as closed_at
         from votes where id=$1 and state='closed'`,
      [voteId]
    );
    const closedAt = replay.rows[0]?.closed_at;
    if (!closedAt) throw new Error("closed vote is missing its closure time");
    return {
      replayed: true,
      voteId,
      outcomeId,
      certificateId,
      state: "closed",
      closedAt,
      payloadSha256: built.payloadSha256
    };
  }
  if (lock.vote_state !== "closing" || lock.existing_signature !== null) {
    throw new VoteCloseTransactionError(
      "vote_close_unavailable",
      "certificate finalization requires an unsigned closing vote"
    );
  }
  const recoveringHumanClose =
    context.scope === "worker" && lock.close_mode === "secretariat_confirmed";
  const eventActorMemberId = recoveringHumanClose
    ? lock.close_actor_member_id
    : context.actorMemberId;
  if (recoveringHumanClose && eventActorMemberId === null) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "manual certificate recovery lost its original close actor"
    );
  }
  const recoveryConsent = recoveringHumanClose ? lock.close_consent_record_id : null;
  if (recoveringHumanClose && recoveryConsent === null) {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "manual certificate recovery lost its original consent record"
    );
  }
  const events = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      objectVersion: BigInt(lock.vote_row_version) + 1n,
      ...(recoveryConsent === null ? {} : { consentRecordId: recoveryConsent }),
      event: {
        eventId: certificateIssuedAuditEventId,
        eventType: "certificate_issued",
        actorMemberId: eventActorMemberId,
        actorClientId: context.actorClientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: voteId,
        boardId: lock.board_id,
        origin: context.origin,
        details: {
          outcomeId,
          certificateId,
          payloadSha256: built.payloadSha256,
          signingKeyId: persisted.signing_key_id,
          ...(recoveringHumanClose ? { recoveredByWorker: true } : {})
        },
        schemaVersion: 1
      }
    },
    {
      organizationId,
      objectVersion: BigInt(lock.vote_row_version) + 1n,
      ...(recoveryConsent === null ? {} : { consentRecordId: recoveryConsent }),
      event: {
        eventId: voteClosedAuditEventId,
        eventType: "vote_closed",
        actorMemberId: eventActorMemberId,
        actorClientId: context.actorClientId,
        tokenJti: context.tokenJti,
        entityType: "vote",
        entityId: voteId,
        boardId: lock.board_id,
        origin: context.origin,
        details: {
          outcomeId,
          certificateId,
          payloadSha256: built.payloadSha256,
          tallySha256: built.tallySha256,
          outcome: built.tally.outcome,
          ...(recoveringHumanClose ? { recoveredByWorker: true } : {})
        },
        schemaVersion: 1
      }
    }
  ]);
  if (events.length !== 2) throw new Error("vote close final audit append is incomplete");
  const committed = await client.query<{
    vote_id: string;
    certificate_id: string;
    state: string;
    closed_at: string;
  }>(
    `select * from boardagent_commit_vote_certificate(
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
     )`,
    [
      organizationId,
      voteId,
      outcomeId,
      certificateId,
      lock.certificate_public_id,
      built.canonicalPayload,
      Buffer.from(built.payloadSha256, "hex"),
      signature,
      persisted.signing_key_id,
      certificateIssuedAuditEventId,
      voteClosedAuditEventId
    ]
  );
  const closed = committed.rows[0];
  if (!closed || committed.rows.length !== 1 || closed.state !== "closed") {
    throw new VoteCloseTransactionError(
      "vote_close_integrity_failure",
      "signed certificate did not atomically close the vote"
    );
  }
  return {
    replayed: false,
    voteId,
    outcomeId,
    certificateId,
    state: "closed",
    closedAt: closed.closed_at,
    payloadSha256: built.payloadSha256
  };
}

export type PersistedCertificateVerification =
  | { readonly valid: true; readonly voteId: string; readonly certificateId: string }
  | { readonly valid: false };

export interface PublicPersistedCertificateVerification {
  readonly valid: boolean;
}

/** Anonymous persisted-truth verifier. It accepts and returns no enumerable identity. */
export async function verifyPublicPersistedVoteCertificateInTransaction(
  client: PoolClient,
  input: { readonly certificatePublicId: string; readonly assertedBundle?: unknown }
): Promise<PublicPersistedCertificateVerification> {
  try {
    const publicId = certificatePublicIdBytes(input.certificatePublicId);
    const found = await client.query<{ snapshot: unknown }>(
      "select boardagent_public_certificate_snapshot($1) as snapshot",
      [publicId]
    );
    const raw = found.rows[0]?.snapshot;
    if (found.rows.length !== 1 || raw === null || raw === undefined) return { valid: false };
    const snapshot = PublicCertificateSnapshotEnvelopeSchema.parse(raw);
    const {
      existing_signature: signature,
      existing_certificate_issued_at: certificateIssuedAt,
      existing_certificate_state: _certificateState,
      ...persisted
    } = snapshot.row;
    const built = await recomputePersistedClose(client, persisted, snapshot.evidence);
    const publicKey = trustedEvidenceKey(persisted.signing_public_jwk);
    const signatureBase64Url = signature.toString("base64url");
    if (
      !verifyVoteCertificate(
        {
          payload: built.payload,
          payloadSha256: built.payloadSha256,
          signatureBase64Url
        },
        publicKey
      )
    ) {
      return { valid: false };
    }
    if (input.assertedBundle !== undefined) {
      const asserted = OfflineCertificateBundleSchema.parse(input.assertedBundle);
      const expected = OfflineCertificateBundleSchema.parse({
        schema_version: "boardagent.vote-certificate-bundle.v1",
        certificate_id: built.payload.certificateId,
        vote_id: built.payload.vote.id,
        outcome_id: built.payload.outcomeId,
        public_id: built.payload.publicId,
        canonical_payload: built.payload,
        payload_sha256: built.payloadSha256,
        signature_base64url: signatureBase64Url,
        signing_key: {
          id: persisted.signing_key_id,
          kid: persisted.signing_kid,
          algorithm: "EdDSA",
          public_jwk: persisted.signing_public_jwk
        },
        issued_at: certificateIssuedAt
      });
      if (canonicalJson(asserted) !== canonicalJson(expected)) return { valid: false };
    }
    return { valid: true };
  } catch {
    return { valid: false };
  }
}

/** Authenticated persisted-truth verifier. Public transports must preserve this generic verdict. */
export async function verifyPersistedVoteCertificateInTransaction(
  client: PoolClient,
  input: { readonly organizationId: string; readonly certificatePublicId: string }
): Promise<PersistedCertificateVerification> {
  try {
    const organizationId = UuidV7Schema.parse(input.organizationId);
    const publicId = certificatePublicIdBytes(input.certificatePublicId);
    const found = await client.query<{
      vote_id: string;
      outcome_id: string;
      certificate_id: string;
      signature: Buffer;
    }>(
      `select certificate.vote_id,certificate.outcome_id,certificate.id as certificate_id,
              certificate.signature
         from vote_certificates as certificate
        where certificate.organization_id=$1 and certificate.public_id=$2
          and certificate.state='current'`,
      [organizationId, publicId]
    );
    const certificate = found.rows[0];
    if (!certificate || found.rows.length !== 1) return { valid: false };
    const persisted = await loadPersistedCloseRow(
      client,
      organizationId,
      certificate.vote_id,
      certificate.outcome_id,
      certificate.certificate_id
    );
    if (!persisted || persisted.vote_state !== "closed") return { valid: false };
    const built = await recomputePersistedClose(client, persisted);
    const publicKey = trustedEvidenceKey(persisted.signing_public_jwk);
    const valid = verifyVoteCertificate(
      {
        payload: built.payload,
        payloadSha256: built.payloadSha256,
        signatureBase64Url: certificate.signature.toString("base64url")
      },
      publicKey
    );
    return valid
      ? {
          valid: true,
          voteId: certificate.vote_id,
          certificateId: certificate.certificate_id
        }
      : { valid: false };
  } catch {
    return { valid: false };
  }
}
