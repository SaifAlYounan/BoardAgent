import { sign, verify, type KeyObject } from "node:crypto";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  sha256Hex
} from "@boardagent/contracts";
import { z } from "zod";

function createPositiveDecimalSchema() {
  return z.string().refine((value) => /^[1-9]\d*$/u.test(value));
}

function createNonnegativeDecimalSchema() {
  return z.string().refine((value) => /^(?:0|[1-9]\d*)$/u.test(value));
}

function createPublicIdSchema() {
  return z.string().superRefine((value, context) => {
    if (decodeCanonicalBase64Url(value, 32) === null) {
      context.addIssue({ code: "custom", message: "invalid certificate public ID" });
    }
  });
}

const PositiveDecimalSchema = z.lazy(createPositiveDecimalSchema);
const NonnegativeDecimalSchema = z.lazy(createNonnegativeDecimalSchema);
const PublicIdSchema = z.lazy(createPublicIdSchema);

function createRationalSchema() {
  return z
    .object({ numerator: NonnegativeDecimalSchema, denominator: PositiveDecimalSchema })
    .strict();
}

const RationalSchema = z.lazy(createRationalSchema);

function createCertificateApprovalRuleSchema() {
  return z
    .object({
      id: UuidV7Schema,
      canonicalSha256: Sha256HexSchema,
      approval: RationalSchema,
      quorum: RationalSchema,
      approvalDenominator: z.enum(["eligible", "participating", "yes_no"]),
      abstentionsCountForQuorum: z.boolean(),
      tieBehavior: z.enum(["reject", "chair_casting_vote"]),
      proxyPolicy: z.enum(["principal_supersedes_proxy", "first_ballot_final", "forbidden"]),
      closeMode: z.enum(["automatic", "secretariat_confirmed"])
    })
    .strict();
}

export const CertificateApprovalRuleSchema = z.lazy(createCertificateApprovalRuleSchema);

function createCertificateElectorateEntrySchema() {
  return z
    .object({
      memberId: UuidV7Schema,
      membershipVersionId: UuidV7Schema,
      seatRole: z.literal("voting_member"),
      isChair: z.boolean(),
      votingWeight: PositiveDecimalSchema,
      eligibilitySha256: Sha256HexSchema
    })
    .strict();
}

export const CertificateElectorateEntrySchema = z.lazy(createCertificateElectorateEntrySchema);

function createCertificateBallotDispositionSchema() {
  return z
    .object({
      id: UuidV7Schema,
      effect: z.enum(["superseded", "invalidated_by_recusal", "invalidated_by_vote_replacement"]),
      supersedingBallotId: UuidV7Schema.nullable(),
      replacementVoteId: UuidV7Schema.nullable(),
      auditEventId: UuidV7Schema.nullable(),
      createdAt: Rfc3339UtcSchema
    })
    .strict();
}

const CertificateBallotDispositionSchema = z.lazy(createCertificateBallotDispositionSchema);

function createCertificateBallotEntrySchema() {
  return z
    .object({
      id: UuidV7Schema,
      principalMemberId: UuidV7Schema,
      casterMemberId: UuidV7Schema,
      choice: z.enum(["yes", "no", "abstain"]),
      statementSha256: Sha256HexSchema.nullable(),
      votingWeight: PositiveDecimalSchema,
      source: z.enum(["own", "proxy"]),
      proxyGrantId: UuidV7Schema.nullable(),
      consentRecordId: UuidV7Schema,
      consentRecordSha256: Sha256HexSchema,
      castAt: Rfc3339UtcSchema,
      disposition: CertificateBallotDispositionSchema.nullable()
    })
    .strict()
    .superRefine((ballot, context) => {
      if (
        (ballot.source === "own" &&
          (ballot.principalMemberId !== ballot.casterMemberId || ballot.proxyGrantId !== null)) ||
        (ballot.source === "proxy" &&
          (ballot.principalMemberId === ballot.casterMemberId || ballot.proxyGrantId === null))
      ) {
        context.addIssue({ code: "custom", message: "certificate ballot attribution is invalid" });
      }
    });
}

export const CertificateBallotEntrySchema = z.lazy(createCertificateBallotEntrySchema);

function createCertificateProxyRevocationSchema() {
  return z
    .object({
      id: UuidV7Schema,
      effect: z.enum(["revoked", "expired", "superseded"]),
      consentRecordId: UuidV7Schema.nullable(),
      consentRecordSha256: Sha256HexSchema.nullable(),
      revokedAt: Rfc3339UtcSchema
    })
    .strict()
    .superRefine((revocation, context) => {
      if ((revocation.consentRecordId === null) !== (revocation.consentRecordSha256 === null)) {
        context.addIssue({
          code: "custom",
          message: "proxy revocation consent must move together"
        });
      }
    });
}

const CertificateProxyRevocationSchema = z.lazy(createCertificateProxyRevocationSchema);

function createCertificateProxyEntrySchema() {
  return z
    .object({
      id: UuidV7Schema,
      principalMemberId: UuidV7Schema,
      holderMemberId: UuidV7Schema,
      policy: z.enum(["principal_supersedes_proxy", "first_ballot_final"]),
      consentRecordId: UuidV7Schema,
      consentRecordSha256: Sha256HexSchema,
      grantedAt: Rfc3339UtcSchema,
      expiresAt: Rfc3339UtcSchema.nullable(),
      revocation: CertificateProxyRevocationSchema.nullable()
    })
    .strict()
    .refine((proxy) => proxy.principalMemberId !== proxy.holderMemberId, {
      message: "certificate proxy cannot be self-delegated"
    });
}

export const CertificateProxyEntrySchema = z.lazy(createCertificateProxyEntrySchema);

function createCertificateExclusionEntrySchema() {
  return z
    .object({
      id: UuidV7Schema,
      memberId: UuidV7Schema,
      version: z.number().int().positive().safe(),
      state: z.enum(["excluded", "lifted"]),
      reasonSha256: Sha256HexSchema,
      actorMemberId: UuidV7Schema,
      consentRecordId: UuidV7Schema,
      consentRecordSha256: Sha256HexSchema,
      effectiveAt: Rfc3339UtcSchema
    })
    .strict();
}

export const CertificateExclusionEntrySchema = z.lazy(createCertificateExclusionEntrySchema);

function createCanonicalVoteTallySchema() {
  return z
    .object({
      schemaVersion: z.literal("boardagent.vote-tally.v1"),
      eligibleWeight: NonnegativeDecimalSchema,
      participatingWeight: NonnegativeDecimalSchema,
      yesWeight: NonnegativeDecimalSchema,
      noWeight: NonnegativeDecimalSchema,
      abstainWeight: NonnegativeDecimalSchema,
      quorumMet: z.boolean(),
      approvalMet: z.boolean(),
      outcome: z.enum(["approved", "rejected", "no_quorum"])
    })
    .strict();
}

export const CanonicalVoteTallySchema = z.lazy(createCanonicalVoteTallySchema);

function orderedUnique<T>(
  values: readonly T[],
  key: (value: T) => string,
  context: z.RefinementCtx,
  label: string
): void {
  const keys = values.map(key);
  if (new Set(keys).size !== keys.length) {
    context.addIssue({ code: "custom", message: `${label} contains duplicate ordering keys` });
  }
  if (keys.slice(1).some((value, index) => value <= keys[index]!)) {
    context.addIssue({ code: "custom", message: `${label} must be strictly ordered` });
  }
}

function createVoteCertificatePayloadSchema() {
  return z
    .object({
      schema: z.literal("boardagent.vote-certificate.v1"),
      certificateId: UuidV7Schema,
      publicId: PublicIdSchema,
      outcomeId: UuidV7Schema,
      instanceId: UuidV7Schema,
      organizationId: UuidV7Schema,
      boardId: UuidV7Schema,
      vote: z
        .object({
          id: UuidV7Schema,
          title: z.string().min(1).max(512),
          resolutionVersionId: UuidV7Schema,
          resolutionVersion: z.number().int().positive().safe(),
          resolutionText: z.string().min(1).max(1_048_576),
          resolutionSha256: Sha256HexSchema,
          decisionPackageId: UuidV7Schema,
          decisionPackageVersion: z.number().int().positive().safe(),
          decisionPackageSha256: Sha256HexSchema,
          closeMode: z.enum(["automatic", "secretariat_confirmed"]),
          deadlineAt: Rfc3339UtcSchema
        })
        .strict(),
      packageEvidence: z
        .object({
          submissionManifestSha256: Sha256HexSchema,
          documentManifestSha256: Sha256HexSchema,
          questionCutoffSha256: Sha256HexSchema
        })
        .strict(),
      governance: z
        .object({
          governanceProfileId: UuidV7Schema,
          governanceProfileSha256: Sha256HexSchema,
          rulesetId: UuidV7Schema,
          rulesetSha256: Sha256HexSchema,
          matterEvaluationId: UuidV7Schema,
          matterEvaluationResultSha256: Sha256HexSchema,
          selectedRulesetRuleId: UuidV7Schema,
          selectedRulesetRuleSha256: Sha256HexSchema,
          ruleOverrideId: UuidV7Schema.nullable(),
          ruleOverrideSha256: Sha256HexSchema.nullable(),
          approvalRule: CertificateApprovalRuleSchema
        })
        .strict(),
      electorateSha256: Sha256HexSchema,
      electorate: z.array(CertificateElectorateEntrySchema).min(1).max(10_000),
      exclusions: z.array(CertificateExclusionEntrySchema).max(100_000),
      proxies: z.array(CertificateProxyEntrySchema).max(10_000),
      ballots: z.array(CertificateBallotEntrySchema).max(100_000),
      consentSetSha256: Sha256HexSchema,
      tally: CanonicalVoteTallySchema,
      tallySha256: Sha256HexSchema,
      outcome: z.enum(["approved", "rejected", "no_quorum"]),
      close: z
        .object({
          actorMemberId: UuidV7Schema.nullable(),
          consentRecordId: UuidV7Schema.nullable(),
          consentRecordSha256: Sha256HexSchema.nullable(),
          clockSampleId: UuidV7Schema,
          measuredAt: Rfc3339UtcSchema,
          driftMicroseconds: z.string().refine((value) => /^-?(?:0|[1-9]\d*)$/u.test(value)),
          validUntil: Rfc3339UtcSchema
        })
        .strict(),
      closingAuditEventId: UuidV7Schema,
      closingAuditSequence: PositiveDecimalSchema,
      closingAuditHash: Sha256HexSchema,
      preparedAt: Rfc3339UtcSchema,
      keyId: z.string().refine((value) => /^[A-Za-z0-9._-]{1,128}$/u.test(value)),
      signingKeyId: UuidV7Schema
    })
    .strict()
    .superRefine((payload, context) => {
      if (
        payload.governance.approvalRule.proxyPolicy === "forbidden" &&
        (payload.proxies.length !== 0 ||
          payload.ballots.some((ballot) => ballot.source === "proxy"))
      ) {
        context.addIssue({
          code: "custom",
          message: "a proxies-forbidden certificate cannot contain proxy authority or ballots"
        });
      }
      if (payload.vote.id === payload.certificateId) {
        context.addIssue({ code: "custom", message: "vote and certificate IDs must differ" });
      }
      if (payload.vote.closeMode !== payload.governance.approvalRule.closeMode) {
        context.addIssue({ code: "custom", message: "certificate close modes do not match" });
      }
      if (payload.outcome !== payload.tally.outcome) {
        context.addIssue({ code: "custom", message: "certificate outcome does not match tally" });
      }
      if (!safeHashEqual(payload.tallySha256, canonicalSha256(payload.tally))) {
        context.addIssue({ code: "custom", message: "certificate tally hash is invalid" });
      }
      const hasOverrideId = payload.governance.ruleOverrideId !== null;
      if (hasOverrideId !== (payload.governance.ruleOverrideSha256 !== null)) {
        context.addIssue({
          code: "custom",
          message: "certificate override evidence must move together"
        });
      }
      const manual = payload.vote.closeMode === "secretariat_confirmed";
      if (
        manual !== (payload.close.actorMemberId !== null) ||
        manual !== (payload.close.consentRecordId !== null) ||
        manual !== (payload.close.consentRecordSha256 !== null)
      ) {
        context.addIssue({
          code: "custom",
          message: "certificate close consent mode is inconsistent"
        });
      }
      if (payload.electorate.filter(({ isChair }) => isChair).length > 1) {
        context.addIssue({ code: "custom", message: "certificate electorate has multiple chairs" });
      }
      orderedUnique(payload.electorate, ({ memberId }) => memberId, context, "electorate");
      orderedUnique(
        payload.exclusions,
        ({ memberId, version, id }) =>
          `${memberId}\u0000${String(version).padStart(10, "0")}\u0000${id}`,
        context,
        "exclusions"
      );
      orderedUnique(payload.proxies, ({ id }) => id, context, "proxies");
      orderedUnique(
        payload.ballots,
        ({ principalMemberId, castAt, id }) => `${principalMemberId}\u0000${castAt}\u0000${id}`,
        context,
        "ballots"
      );
    });
}

export const VoteCertificatePayloadSchema = z.lazy(createVoteCertificatePayloadSchema);

export type VoteCertificatePayload = z.input<typeof VoteCertificatePayloadSchema>;

export interface VoteCertificate {
  readonly payload: VoteCertificatePayload;
  readonly payloadSha256: string;
  readonly signatureBase64Url: string;
}

function decodeCanonicalBase64Url(value: string, expectedByteLength: number): Buffer | null {
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== expectedByteLength) return null;
  return decoded.toString("base64url") === value ? decoded : null;
}

export function certificatePublicIdBytes(publicId: string): Buffer {
  return decodeCanonicalBase64Url(PublicIdSchema.parse(publicId), 32)!;
}

export function certificatePublicIdSha256(publicId: string): string {
  return sha256Hex(certificatePublicIdBytes(publicId));
}

export function canonicalVoteCertificatePayload(payload: VoteCertificatePayload): string {
  return canonicalJson(VoteCertificatePayloadSchema.parse(payload));
}

export function issueVoteCertificate(
  input: VoteCertificatePayload,
  key: KeyObject | string
): VoteCertificate {
  const payload = VoteCertificatePayloadSchema.parse(input);
  const bytes = canonicalVoteCertificatePayload(payload);
  return {
    payload,
    payloadSha256: canonicalSha256(payload),
    signatureBase64Url: sign(null, Buffer.from(bytes), key).toString("base64url")
  };
}

export function verifyVoteCertificate(
  certificate: VoteCertificate,
  trustedKey: KeyObject | string
): boolean {
  const parsed = VoteCertificatePayloadSchema.safeParse(certificate.payload);
  if (!parsed.success) return false;
  const signature = decodeCanonicalBase64Url(certificate.signatureBase64Url, 64);
  if (signature === null) return false;
  if (!safeHashEqual(certificate.payloadSha256, canonicalSha256(parsed.data))) return false;
  return verify(
    null,
    Buffer.from(canonicalVoteCertificatePayload(parsed.data)),
    trustedKey,
    signature
  );
}
