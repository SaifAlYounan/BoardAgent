import { canonicalSha256 } from "../../lib/contracts/src/canonical.js";
import type { VoteCertificatePayload } from "../../lib/audit/src/certificate.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;

const hash = (character: string): string => character.repeat(64);

export function voteCertificatePayload(): VoteCertificatePayload {
  const tally = {
    schemaVersion: "boardagent.vote-tally.v1" as const,
    eligibleWeight: "1",
    participatingWeight: "1",
    yesWeight: "1",
    noWeight: "0",
    abstainWeight: "0",
    quorumMet: true,
    approvalMet: true,
    outcome: "approved" as const
  };
  return {
    schema: "boardagent.vote-certificate.v1",
    certificateId: id(1),
    publicId: Buffer.alloc(32, 0xa5).toString("base64url"),
    outcomeId: id(2),
    instanceId: id(3),
    organizationId: id(4),
    boardId: id(5),
    vote: {
      id: id(6),
      title: "Certificate attack fixture",
      resolutionVersionId: id(7),
      resolutionVersion: 1,
      resolutionText: "RESOLVED: retain exact persisted evidence.",
      resolutionSha256: hash("1"),
      decisionPackageId: id(8),
      decisionPackageVersion: 1,
      decisionPackageSha256: hash("2"),
      closeMode: "secretariat_confirmed",
      deadlineAt: "2026-09-01T12:00:00Z"
    },
    packageEvidence: {
      submissionManifestSha256: hash("3"),
      documentManifestSha256: hash("4"),
      questionCutoffSha256: hash("5")
    },
    governance: {
      governanceProfileId: id(9),
      governanceProfileSha256: hash("6"),
      rulesetId: id(10),
      rulesetSha256: hash("7"),
      matterEvaluationId: id(11),
      matterEvaluationResultSha256: hash("8"),
      selectedRulesetRuleId: id(12),
      selectedRulesetRuleSha256: hash("9"),
      ruleOverrideId: null,
      ruleOverrideSha256: null,
      approvalRule: {
        id: id(13),
        canonicalSha256: hash("a"),
        approval: { numerator: "1", denominator: "2" },
        quorum: { numerator: "1", denominator: "2" },
        approvalDenominator: "eligible",
        abstentionsCountForQuorum: true,
        tieBehavior: "reject",
        proxyPolicy: "principal_supersedes_proxy",
        closeMode: "secretariat_confirmed"
      }
    },
    electorateSha256: hash("b"),
    electorate: [
      {
        memberId: id(20),
        membershipVersionId: id(21),
        seatRole: "voting_member",
        isChair: false,
        votingWeight: "1",
        eligibilitySha256: hash("c")
      }
    ],
    exclusions: [],
    proxies: [],
    ballots: [
      {
        id: id(22),
        principalMemberId: id(20),
        casterMemberId: id(20),
        choice: "yes",
        statementSha256: null,
        votingWeight: "1",
        source: "own",
        proxyGrantId: null,
        consentRecordId: id(23),
        consentRecordSha256: hash("c"),
        castAt: "2026-09-01T11:59:00Z",
        disposition: null
      }
    ],
    consentSetSha256: hash("d"),
    tally,
    tallySha256: canonicalSha256(tally),
    outcome: "approved",
    close: {
      actorMemberId: id(14),
      consentRecordId: id(15),
      consentRecordSha256: hash("e"),
      clockSampleId: id(16),
      measuredAt: "2026-09-01T12:00:00Z",
      driftMicroseconds: "0",
      validUntil: "2026-09-01T12:05:00Z"
    },
    closingAuditEventId: id(17),
    closingAuditSequence: "99",
    closingAuditHash: hash("f"),
    preparedAt: "2026-09-01T12:00:00Z",
    keyId: "evidence-key-1",
    signingKeyId: id(18)
  };
}
