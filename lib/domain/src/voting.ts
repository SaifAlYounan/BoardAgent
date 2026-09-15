/*
 * Adapted from LQGovernance-OpenBoard, commit
 * 1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb, vote tally and proxy voting areas.
 * Copyright (c) 2026 Alexios Kirillov. Licensed under the Apache License 2.0.
 * Derived from LQGovernance-OpenBoard (MIT License); see docs/THIRD_PARTY_NOTICES.md.
 * Hostile changes: one exact BigInt oracle, frozen electorate inputs, deny-ineligible
 * ballots, explicit abstention/tie semantics and attributed no-chain proxy precedence.
 */
import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  canonicalText
} from "@boardagent/contracts";

import { assertWeight, meetsFraction, type Rational } from "./value-objects.js";

export type BallotChoice = "yes" | "no" | "abstain";
export type SeatRole = "voting_member" | "management" | "observer";
export type ApprovalDenominator = "eligible" | "participating" | "yes_no";
export type TieBehavior = "reject" | "chair_casting_vote";

export interface RuleSelectionCitation {
  readonly ruleId: string;
  readonly sourceDocumentVersionId: string;
  readonly sourceDocumentSha256: string;
  readonly clause: string;
  readonly locator: string;
}

interface RuleOverrideSelectionInput {
  readonly evaluationId: string;
  readonly evaluationResultSha256: string;
  readonly wizardDraftId: string;
  readonly finalVoteId: string;
  readonly recommendedRuleId: string | null;
  readonly selectedRuleId: string;
  readonly selectedRuleSha256: string;
  readonly reason: string;
  readonly citations: readonly RuleSelectionCitation[];
}

function canonicalRuleOverrideSelection(input: RuleOverrideSelectionInput) {
  const reason = canonicalText(input.reason);
  if (reason.trim().length < 1 || reason.length > 65_536) {
    throw new RangeError("rule-override reason must contain 1 through 65536 characters");
  }
  const citations = input.citations.map((citation) => ({
    ruleId: UuidV7Schema.parse(citation.ruleId),
    sourceDocumentVersionId: UuidV7Schema.parse(citation.sourceDocumentVersionId),
    sourceDocumentSha256: Sha256HexSchema.parse(citation.sourceDocumentSha256),
    clause: canonicalText(citation.clause),
    locator: canonicalText(citation.locator)
  }));
  if (
    citations.length < 1 ||
    citations.some(
      ({ clause, locator }) =>
        clause.length < 1 || clause.length > 512 || locator.length < 1 || locator.length > 1024
    )
  ) {
    throw new RangeError("rule override requires bounded exact citations");
  }
  return {
    evaluationId: UuidV7Schema.parse(input.evaluationId),
    evaluationResultSha256: Sha256HexSchema.parse(input.evaluationResultSha256),
    wizardDraftId: UuidV7Schema.parse(input.wizardDraftId),
    finalVoteId: UuidV7Schema.parse(input.finalVoteId),
    recommendedRuleId:
      input.recommendedRuleId === null ? null : UuidV7Schema.parse(input.recommendedRuleId),
    selectedRuleId: UuidV7Schema.parse(input.selectedRuleId),
    selectedRuleSha256: Sha256HexSchema.parse(input.selectedRuleSha256),
    reason,
    citations
  };
}

export function ruleOverrideConsentHash(
  input: RuleOverrideSelectionInput & { readonly packageSha256: string }
): string {
  return canonicalSha256({
    schemaVersion: "boardagent.rule-override-consent.v1",
    ...canonicalRuleOverrideSelection(input),
    packageSha256: Sha256HexSchema.parse(input.packageSha256)
  });
}

export function ruleOverrideEvidenceHash(
  input: RuleOverrideSelectionInput & {
    readonly consentRecordId: string;
    readonly auditEventId: string;
  }
): string {
  return canonicalSha256({
    schemaVersion: "boardagent.rule-override-evidence.v1",
    ...canonicalRuleOverrideSelection(input),
    consentRecordId: UuidV7Schema.parse(input.consentRecordId),
    auditEventId: UuidV7Schema.parse(input.auditEventId)
  });
}

export function voteSourceExclusionConsentHash(input: {
  readonly voteId: string;
  readonly causeId: string;
  readonly sourceClass: "management_submission" | "document" | "question_cutoff";
  readonly sourceId: string;
  readonly sourceVersion: number;
  readonly sourceSha256: string;
  readonly reason: string;
  readonly packageSha256: string;
}): string {
  const reason = canonicalText(input.reason);
  if (reason.trim().length < 1 || reason.length > 65_536) {
    throw new RangeError("source-exclusion reason must contain 1 through 65536 characters");
  }
  if (
    !(["management_submission", "document", "question_cutoff"] as const).includes(input.sourceClass)
  ) {
    throw new TypeError("source-exclusion class is invalid");
  }
  if (!Number.isSafeInteger(input.sourceVersion) || input.sourceVersion < 1) {
    throw new RangeError("source-exclusion version must be a positive safe integer");
  }
  return canonicalSha256({
    schemaVersion: "boardagent.vote-source-exclusion-consent.v1",
    voteId: UuidV7Schema.parse(input.voteId),
    causeId: UuidV7Schema.parse(input.causeId),
    sourceClass: input.sourceClass,
    sourceId: UuidV7Schema.parse(input.sourceId),
    sourceVersion: input.sourceVersion,
    sourceSha256: Sha256HexSchema.parse(input.sourceSha256),
    reason,
    packageSha256: Sha256HexSchema.parse(input.packageSha256)
  });
}

export function voteRecusalConsentHash(input: {
  readonly voteId: string;
  readonly memberId: string;
  readonly state: "excluded" | "lifted";
  readonly reason: string;
  readonly packageSha256: string;
}): string {
  return canonicalSha256({
    schemaVersion: "boardagent.vote-recusal-consent.v1",
    voteId: UuidV7Schema.parse(input.voteId),
    memberId: UuidV7Schema.parse(input.memberId),
    state: input.state,
    reason: input.reason,
    packageSha256: Sha256HexSchema.parse(input.packageSha256)
  });
}

export function proxyGrantConsentHash(input: {
  readonly voteId: string;
  readonly principalMemberId: string;
  readonly holderMemberId: string;
  readonly policy: "principal_supersedes_proxy" | "first_ballot_final";
  readonly expiresAt: string | null;
  readonly packageSha256: string;
}): string {
  const principalMemberId = UuidV7Schema.parse(input.principalMemberId);
  const holderMemberId = UuidV7Schema.parse(input.holderMemberId);
  if (principalMemberId === holderMemberId)
    throw new Error("proxy holder must differ from principal");
  if (!(["principal_supersedes_proxy", "first_ballot_final"] as const).includes(input.policy)) {
    throw new TypeError("proxy policy is invalid");
  }
  return canonicalSha256({
    schemaVersion: "boardagent.proxy-grant-consent.v1",
    voteId: UuidV7Schema.parse(input.voteId),
    principalMemberId,
    holderMemberId,
    policy: input.policy,
    expiresAt: input.expiresAt === null ? null : Rfc3339UtcSchema.parse(input.expiresAt),
    packageSha256: Sha256HexSchema.parse(input.packageSha256)
  });
}

export function proxyRevokeConsentHash(input: {
  readonly voteId: string;
  readonly proxyGrantId: string;
  readonly principalMemberId: string;
  readonly reason: string;
  readonly packageSha256: string;
}): string {
  const reason = canonicalText(input.reason);
  if (reason.length < 1 || reason.length > 65_536) {
    throw new RangeError("proxy revocation reason must contain 1 through 65536 characters");
  }
  return canonicalSha256({
    schemaVersion: "boardagent.proxy-revoke-consent.v1",
    voteId: UuidV7Schema.parse(input.voteId),
    proxyGrantId: UuidV7Schema.parse(input.proxyGrantId),
    principalMemberId: UuidV7Schema.parse(input.principalMemberId),
    reason,
    packageSha256: Sha256HexSchema.parse(input.packageSha256)
  });
}

export function ballotConsentHash(input: {
  readonly voteId: string;
  readonly principalMemberId: string;
  readonly casterMemberId: string;
  readonly choice: BallotChoice;
  readonly statement: string | null;
  readonly proxyGrantId: string | null;
  readonly packageSha256: string;
}): string {
  const principalMemberId = UuidV7Schema.parse(input.principalMemberId);
  const casterMemberId = UuidV7Schema.parse(input.casterMemberId);
  if (!(["yes", "no", "abstain"] as const).includes(input.choice)) {
    throw new TypeError("ballot choice is invalid");
  }
  const statement = input.statement === null ? null : canonicalText(input.statement);
  if (statement !== null && statement.length > 500) {
    throw new RangeError("ballot statement must not exceed 500 characters");
  }
  const proxyGrantId = input.proxyGrantId === null ? null : UuidV7Schema.parse(input.proxyGrantId);
  if (
    (principalMemberId === casterMemberId && proxyGrantId !== null) ||
    (principalMemberId !== casterMemberId && proxyGrantId === null)
  ) {
    throw new Error("ballot attribution and proxy grant are inconsistent");
  }
  return canonicalSha256({
    schemaVersion: "boardagent.ballot-consent.v1",
    voteId: UuidV7Schema.parse(input.voteId),
    principalMemberId,
    casterMemberId,
    choice: input.choice,
    statement,
    proxyGrantId,
    packageSha256: Sha256HexSchema.parse(input.packageSha256)
  });
}

export function voteCloseConsentHash(input: {
  readonly voteId: string;
  readonly packageSha256: string;
  readonly expectedTallySha256: string;
  readonly outcomeId: string;
  readonly certificateId: string;
  readonly certificatePublicIdSha256: string;
  readonly signingKeyId: string;
}): string {
  return canonicalSha256({
    schemaVersion: "boardagent.vote-close-consent.v1",
    voteId: UuidV7Schema.parse(input.voteId),
    packageSha256: Sha256HexSchema.parse(input.packageSha256),
    expectedTallySha256: Sha256HexSchema.parse(input.expectedTallySha256),
    outcomeId: UuidV7Schema.parse(input.outcomeId),
    certificateId: UuidV7Schema.parse(input.certificateId),
    certificatePublicIdSha256: Sha256HexSchema.parse(input.certificatePublicIdSha256),
    signingKeyId: UuidV7Schema.parse(input.signingKeyId)
  });
}

export interface ElectorSeat {
  readonly memberId: string;
  readonly role: SeatRole;
  readonly weight: bigint;
  readonly eligible: boolean;
  readonly recused: boolean;
  readonly chair: boolean;
}

export interface EffectiveBallot {
  readonly principalMemberId: string;
  readonly casterMemberId: string;
  readonly choice: BallotChoice;
  readonly source: "own" | "proxy";
}

export interface ApprovalRule {
  readonly approval: Rational;
  readonly quorum: Rational;
  readonly approvalDenominator: ApprovalDenominator;
  readonly abstentionsCountForQuorum: boolean;
  readonly tieBehavior: TieBehavior;
}

export interface VoteTally {
  readonly eligibleWeight: bigint;
  readonly participatingWeight: bigint;
  readonly yesWeight: bigint;
  readonly noWeight: bigint;
  readonly abstainWeight: bigint;
  readonly quorumMet: boolean;
  readonly approvalMet: boolean;
  readonly outcome: "approved" | "rejected" | "no_quorum";
}

export interface CanonicalVoteTally {
  readonly schemaVersion: "boardagent.vote-tally.v1";
  readonly eligibleWeight: string;
  readonly participatingWeight: string;
  readonly yesWeight: string;
  readonly noWeight: string;
  readonly abstainWeight: string;
  readonly quorumMet: boolean;
  readonly approvalMet: boolean;
  readonly outcome: "approved" | "rejected" | "no_quorum";
}

export function canonicalVoteTally(tally: VoteTally): CanonicalVoteTally {
  return {
    schemaVersion: "boardagent.vote-tally.v1",
    eligibleWeight: tally.eligibleWeight.toString(10),
    participatingWeight: tally.participatingWeight.toString(10),
    yesWeight: tally.yesWeight.toString(10),
    noWeight: tally.noWeight.toString(10),
    abstainWeight: tally.abstainWeight.toString(10),
    quorumMet: tally.quorumMet,
    approvalMet: tally.approvalMet,
    outcome: tally.outcome
  };
}

export function voteTallySha256(tally: VoteTally): string {
  return canonicalSha256(canonicalVoteTally(tally));
}

function eligibleSeat(seat: ElectorSeat): boolean {
  if (seat.role !== "voting_member") return false;
  return seat.eligible && !seat.recused;
}

function validateElectorate(electorate: readonly ElectorSeat[]): {
  readonly eligibleWeight: bigint;
  readonly seats: ReadonlyMap<string, ElectorSeat>;
} {
  const seats = new Map<string, ElectorSeat>();
  let eligibleWeight = 0n;
  let chairCount = 0;
  for (const seat of electorate) {
    if (seats.has(seat.memberId)) throw new Error(`duplicate electorate member: ${seat.memberId}`);
    if (seat.role === "voting_member") assertWeight(seat.weight);
    else if (seat.weight !== 0n) throw new RangeError("non-voting seats must have zero weight");
    if (seat.chair && seat.role !== "voting_member") {
      throw new Error("only a voting member may be chair");
    }
    if (seat.chair) chairCount += 1;
    seats.set(seat.memberId, seat);
    if (eligibleSeat(seat)) eligibleWeight += seat.weight;
  }
  if (chairCount > 1) throw new Error("electorate may contain at most one chair");
  return { seats, eligibleWeight };
}

export function eligibleVotingWeight(electorate: readonly ElectorSeat[]): bigint {
  return validateElectorate(electorate).eligibleWeight;
}

export function tallyVote(
  electorate: readonly ElectorSeat[],
  ballots: readonly EffectiveBallot[],
  rule: ApprovalRule
): VoteTally {
  const { seats, eligibleWeight } = validateElectorate(electorate);

  const effective = new Map<string, EffectiveBallot>();
  for (const ballot of ballots) {
    const seat = seats.get(ballot.principalMemberId);
    if (!seat || !eligibleSeat(seat)) throw new Error("ballot principal is not eligible");
    if (ballot.source === "own" && ballot.casterMemberId !== ballot.principalMemberId) {
      throw new Error("own ballot caster must be the principal");
    }
    if (ballot.source === "proxy") {
      if (ballot.casterMemberId === ballot.principalMemberId) {
        throw new Error("proxy ballot caster must differ from the principal");
      }
      const holder = seats.get(ballot.casterMemberId);
      if (!holder || !eligibleSeat(holder)) throw new Error("proxy holder is not eligible");
    }
    if (effective.has(ballot.principalMemberId))
      throw new Error("multiple active ballots for principal");
    effective.set(ballot.principalMemberId, ballot);
  }

  let yesWeight = 0n;
  let noWeight = 0n;
  let abstainWeight = 0n;
  let chairYes = false;
  for (const [memberId, ballot] of effective) {
    // `effective` is populated only after resolving the principal from this
    // immutable local map, so the seat is structurally present here.
    const seat = seats.get(memberId)!;
    if (ballot.choice === "yes") {
      yesWeight += seat.weight;
      chairYes ||= seat.chair;
    } else if (ballot.choice === "no") {
      noWeight += seat.weight;
    } else {
      abstainWeight += seat.weight;
    }
  }

  const quorumParticipation =
    yesWeight + noWeight + (rule.abstentionsCountForQuorum ? abstainWeight : 0n);
  const participatingWeight = yesWeight + noWeight + abstainWeight;
  const approvalTotal =
    rule.approvalDenominator === "eligible"
      ? eligibleWeight
      : rule.approvalDenominator === "participating"
        ? participatingWeight
        : yesWeight + noWeight;
  const quorumMet =
    eligibleWeight > 0n && meetsFraction(quorumParticipation, eligibleWeight, rule.quorum);
  let approvalMet = meetsFraction(yesWeight, approvalTotal, rule.approval);
  if (yesWeight === noWeight) {
    approvalMet = rule.tieBehavior === "chair_casting_vote" && chairYes;
  }
  const outcome = !quorumMet ? "no_quorum" : approvalMet ? "approved" : "rejected";

  return {
    eligibleWeight,
    participatingWeight,
    yesWeight,
    noWeight,
    abstainWeight,
    quorumMet,
    approvalMet,
    outcome
  };
}

export type PrincipalSupersessionRule = "principal_supersedes_proxy" | "first_ballot_final";

export function chooseEffectiveBallot(
  current: EffectiveBallot | undefined,
  incoming: EffectiveBallot,
  policy: PrincipalSupersessionRule
): EffectiveBallot {
  if (!current) return incoming;
  if (current.principalMemberId !== incoming.principalMemberId)
    throw new Error("principal mismatch");
  if (policy === "first_ballot_final") throw new Error("principal already has an active ballot");
  if (incoming.source !== "own") throw new Error("only the principal may supersede a proxy ballot");
  return incoming;
}
