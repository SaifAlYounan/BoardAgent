import {
  DecisionPackageSchema,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema,
  type JsonValue,
  type DecisionPackage
} from "@boardagent/contracts";

export type DecisionPackageChangeClass =
  | "resolution"
  | "governance_profile"
  | "ruleset"
  | "approval_rule"
  | "electorate"
  | "close_mode"
  | "deadline"
  | "management_submission"
  | "document"
  | "question_cutoff";

export function decisionPackageHash(decisionPackage: DecisionPackage): string {
  return canonicalSha256(DecisionPackageSchema.parse(decisionPackage));
}

function componentDigest(
  decisionPackage: DecisionPackage,
  type: DecisionPackageChangeClass
): string {
  return canonicalSha256(decisionPackage.components.filter((component) => component.type === type));
}

export function compareDecisionPackages(
  before: DecisionPackage,
  after: DecisionPackage,
  electorateChanged = false
): readonly DecisionPackageChangeClass[] {
  const oldPackage = DecisionPackageSchema.parse(before);
  const newPackage = DecisionPackageSchema.parse(after);
  const changes: DecisionPackageChangeClass[] = [];
  // A replacement necessarily creates a new immutable resolution row.  The
  // component changed only when the confirmed canonical resolution bytes did.
  if (oldPackage.resolutionSha256 !== newPackage.resolutionSha256) {
    changes.push("resolution");
  }
  if (
    oldPackage.governanceProfileVersionId !== newPackage.governanceProfileVersionId ||
    oldPackage.governanceProfileSha256 !== newPackage.governanceProfileSha256
  ) {
    changes.push("governance_profile");
  }
  if (
    oldPackage.rulesetVersionId !== newPackage.rulesetVersionId ||
    oldPackage.rulesetSha256 !== newPackage.rulesetSha256 ||
    oldPackage.matterEvaluationId !== newPackage.matterEvaluationId ||
    oldPackage.matterEvaluationResultSha256 !== newPackage.matterEvaluationResultSha256 ||
    oldPackage.selectedRulesetRuleId !== newPackage.selectedRulesetRuleId ||
    oldPackage.selectedRulesetRuleSha256 !== newPackage.selectedRulesetRuleSha256 ||
    oldPackage.ruleOverride?.id !== newPackage.ruleOverride?.id ||
    oldPackage.ruleOverride?.canonicalSha256 !== newPackage.ruleOverride?.canonicalSha256
  ) {
    changes.push("ruleset");
  }
  if (
    oldPackage.approvalRuleId !== newPackage.approvalRuleId ||
    oldPackage.approvalRuleSha256 !== newPackage.approvalRuleSha256
  ) {
    changes.push("approval_rule");
  }
  // electorateSha256 is intentionally vote-bound, so callers must compare the
  // persisted member/version/weight/evidence tuples and supply the semantic result.
  if (electorateChanged) changes.push("electorate");
  if (oldPackage.closeMode !== newPackage.closeMode) changes.push("close_mode");
  if (oldPackage.deadlineAt !== newPackage.deadlineAt) changes.push("deadline");
  for (const type of ["management_submission", "document", "question_cutoff"] as const) {
    if (componentDigest(oldPackage, type) !== componentDigest(newPackage, type)) {
      changes.push(type);
    }
  }
  return changes;
}

export interface VoteReplacementPlan {
  readonly oldVoteId: string;
  readonly newVoteId: string;
  readonly oldPackageSha256: string;
  readonly newPackageSha256: string;
  readonly changedComponentClasses: readonly DecisionPackageChangeClass[];
  readonly carriedBallotIds: readonly never[];
  readonly carriedStageIds: readonly never[];
  readonly carriedProxyGrantIds: readonly never[];
  readonly revoteRequiredMemberIds: readonly string[];
}

export function voteReplacementConsentHash(input: {
  readonly oldVoteId: string;
  readonly newVoteId: string;
  readonly newTitle: string;
  readonly newResolutionVersionId: string;
  readonly newResolutionSha256: string;
  readonly decisionPackageId: string;
  readonly newPackageSha256: string;
  readonly reason: string;
}): string {
  return canonicalSha256({
    schemaVersion: "boardagent.vote-replacement-consent.v1",
    oldVoteId: UuidV7Schema.parse(input.oldVoteId),
    newVoteId: UuidV7Schema.parse(input.newVoteId),
    newTitle: input.newTitle,
    newResolutionVersionId: UuidV7Schema.parse(input.newResolutionVersionId),
    newResolutionSha256: Sha256HexSchema.parse(input.newResolutionSha256),
    decisionPackageId: UuidV7Schema.parse(input.decisionPackageId),
    newPackageSha256: Sha256HexSchema.parse(input.newPackageSha256),
    reason: input.reason
  });
}

export function replacementPlan(
  before: DecisionPackage,
  after: DecisionPackage,
  priorBallotPrincipalIds: readonly string[],
  newlyEligibleMemberIds: readonly string[],
  electorateChanged: boolean
): VoteReplacementPlan {
  const oldPackage = DecisionPackageSchema.parse(before);
  const newPackage = DecisionPackageSchema.parse(after);
  if (oldPackage.voteId === newPackage.voteId) {
    throw new Error("replacement requires a distinct vote identifier");
  }
  const changedComponentClasses = compareDecisionPackages(
    oldPackage,
    newPackage,
    electorateChanged
  );
  if (changedComponentClasses.length === 0) {
    throw new Error("replacement requires at least one changed package component");
  }
  const eligible = new Set(newlyEligibleMemberIds);
  const revoteRequiredMemberIds = [...new Set(priorBallotPrincipalIds)]
    .filter((memberId) => eligible.has(memberId))
    .toSorted();
  return {
    oldVoteId: oldPackage.voteId,
    newVoteId: newPackage.voteId,
    oldPackageSha256: decisionPackageHash(oldPackage),
    newPackageSha256: decisionPackageHash(newPackage),
    changedComponentClasses,
    carriedBallotIds: [],
    carriedStageIds: [],
    carriedProxyGrantIds: [],
    revoteRequiredMemberIds
  };
}

export interface VoteElectorateEntryInput {
  readonly id: string;
  readonly memberId: string;
  readonly membershipVersionId: string;
  readonly isChair?: boolean;
  readonly votingWeight: bigint;
  readonly eligibilitySnapshot: JsonValue;
}

export interface PreparedVoteElectorateEntry {
  readonly id: string;
  readonly memberId: string;
  readonly membershipVersionId: string;
  readonly seatRole: "voting_member";
  readonly isChair: boolean;
  readonly votingWeight: bigint;
  readonly eligibilitySnapshot: JsonValue;
  readonly eligibilitySha256: string;
}

export interface PreparedVoteElectorate {
  readonly schemaVersion: "boardagent.vote-electorate.v1";
  readonly voteId: string;
  readonly entries: readonly PreparedVoteElectorateEntry[];
  readonly electorateSha256: string;
}

export interface VoteElectorateEvidenceEntry {
  readonly memberId: string;
  readonly membershipVersionId: string;
  readonly isChair: boolean;
  readonly votingWeight: bigint;
  readonly eligibilitySnapshot: JsonValue;
  readonly eligibilitySha256: string;
}

/**
 * Hash the semantic electorate evidence without a vote ID or storage row ID.
 * This is for change classification only; the package electorate hash remains
 * bound to its vote to prevent cross-vote reuse.
 */
export function voteElectorateEvidenceHash(input: readonly VoteElectorateEvidenceEntry[]): string {
  const entries = input
    .map((entry) => ({
      memberId: UuidV7Schema.parse(entry.memberId),
      membershipVersionId: UuidV7Schema.parse(entry.membershipVersionId),
      seatRole: "voting_member" as const,
      isChair: entry.isChair,
      votingWeight: Number(entry.votingWeight),
      eligibilitySnapshot: entry.eligibilitySnapshot,
      eligibilitySha256: Sha256HexSchema.parse(entry.eligibilitySha256)
    }))
    .toSorted((left, right) => left.memberId.localeCompare(right.memberId));
  if (new Set(entries.map(({ memberId }) => memberId)).size !== entries.length) {
    throw new TypeError("vote electorate evidence members must be unique");
  }
  for (const entry of entries) {
    if (
      !Number.isSafeInteger(entry.votingWeight) ||
      entry.votingWeight < 1 ||
      entry.votingWeight > Number(MAX_VOTING_WEIGHT) ||
      canonicalSha256(entry.eligibilitySnapshot) !== entry.eligibilitySha256
    ) {
      throw new TypeError("vote electorate semantic evidence is invalid");
    }
  }
  return canonicalSha256({
    schemaVersion: "boardagent.vote-electorate-evidence.v1",
    entries
  });
}

const MAX_VOTING_WEIGHT = 1_000_000_000n;

/**
 * Build the one canonical baseline electorate frozen into a decision package.
 * Storage row IDs are deliberately excluded from the digest; member identity,
 * immutable membership version, exact weight and eligibility evidence are bound.
 */
export function prepareVoteElectorate(input: {
  readonly voteId: string;
  readonly entries: readonly VoteElectorateEntryInput[];
}): PreparedVoteElectorate {
  const voteId = UuidV7Schema.parse(input.voteId);
  if (input.entries.length < 1 || input.entries.length > 10_000) {
    throw new RangeError("vote electorate must contain 1 through 10000 voting members");
  }
  const entries = input.entries
    .map((entry): PreparedVoteElectorateEntry => {
      const id = UuidV7Schema.parse(entry.id);
      const memberId = UuidV7Schema.parse(entry.memberId);
      const membershipVersionId = UuidV7Schema.parse(entry.membershipVersionId);
      const isChair = entry.isChair ?? false;
      if (entry.votingWeight < 1n || entry.votingWeight > MAX_VOTING_WEIGHT) {
        throw new RangeError("vote electorate weight must be between 1 and 1000000000");
      }
      return {
        id,
        memberId,
        membershipVersionId,
        seatRole: "voting_member",
        isChair,
        votingWeight: entry.votingWeight,
        eligibilitySnapshot: entry.eligibilitySnapshot,
        eligibilitySha256: canonicalSha256(entry.eligibilitySnapshot)
      };
    })
    .toSorted((left, right) => left.memberId.localeCompare(right.memberId));
  if (new Set(entries.map(({ id }) => id)).size !== entries.length) {
    throw new TypeError("vote electorate row IDs must be unique");
  }
  if (new Set(entries.map(({ memberId }) => memberId)).size !== entries.length) {
    throw new TypeError("vote electorate members must be unique");
  }
  if (entries.filter(({ isChair }) => isChair).length > 1) {
    throw new TypeError("vote electorate may contain at most one chair");
  }
  const manifest = {
    schemaVersion: "boardagent.vote-electorate.v1" as const,
    voteId,
    entries: entries.map((entry) => ({
      memberId: entry.memberId,
      membershipVersionId: entry.membershipVersionId,
      seatRole: entry.seatRole,
      isChair: entry.isChair,
      votingWeight: Number(entry.votingWeight),
      eligibilitySnapshot: entry.eligibilitySnapshot,
      eligibilitySha256: entry.eligibilitySha256
    }))
  };
  return {
    schemaVersion: manifest.schemaVersion,
    voteId,
    entries,
    electorateSha256: canonicalSha256(manifest)
  };
}
