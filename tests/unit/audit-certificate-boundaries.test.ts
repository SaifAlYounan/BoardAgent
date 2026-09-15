import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";
import type { z } from "zod";

import {
  canonicalVoteCertificatePayload,
  CanonicalVoteTallySchema,
  certificatePublicIdBytes,
  certificatePublicIdSha256,
  CertificateApprovalRuleSchema,
  CertificateBallotEntrySchema,
  CertificateElectorateEntrySchema,
  CertificateExclusionEntrySchema,
  CertificateProxyEntrySchema,
  issueVoteCertificate,
  verifyVoteCertificate,
  VoteCertificatePayloadSchema,
  type VoteCertificatePayload
} from "../../lib/audit/src/index.js";
import { canonicalSha256, sha256Hex } from "../../lib/contracts/src/index.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
const hash = (character = "a"): string => character.repeat(64);

function tally(outcome: "approved" | "rejected" | "no_quorum" = "approved") {
  return {
    schemaVersion: "boardagent.vote-tally.v1" as const,
    eligibleWeight: "3",
    participatingWeight: "2",
    yesWeight: outcome === "approved" ? "2" : "0",
    noWeight: outcome === "rejected" ? "2" : "0",
    abstainWeight: "0",
    quorumMet: outcome !== "no_quorum",
    approvalMet: outcome === "approved",
    outcome
  };
}

function payload(
  outcome: "approved" | "rejected" | "no_quorum" = "approved",
  closeMode: "automatic" | "secretariat_confirmed" = "secretariat_confirmed"
): VoteCertificatePayload {
  const canonicalTally = tally(outcome);
  const manual = closeMode === "secretariat_confirmed";
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
      title: "Certificate fixture",
      resolutionVersionId: id(7),
      resolutionVersion: 1,
      resolutionText: "RESOLVED: retain exact evidence.",
      resolutionSha256: hash("1"),
      decisionPackageId: id(8),
      decisionPackageVersion: 1,
      decisionPackageSha256: hash("2"),
      closeMode,
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
        closeMode
      }
    },
    electorateSha256: hash("b"),
    electorate: [electorateEntry(20)],
    exclusions: [],
    proxies: [],
    ballots: [],
    consentSetSha256: hash("c"),
    tally: canonicalTally,
    tallySha256: canonicalSha256(canonicalTally),
    outcome,
    close: {
      actorMemberId: manual ? id(14) : null,
      consentRecordId: manual ? id(15) : null,
      consentRecordSha256: manual ? hash("d") : null,
      clockSampleId: id(16),
      measuredAt: "2026-09-01T12:00:00Z",
      driftMicroseconds: "0",
      validUntil: "2026-09-01T12:05:00Z"
    },
    closingAuditEventId: id(17),
    closingAuditSequence: "99",
    closingAuditHash: hash("e"),
    preparedAt: "2026-09-01T12:00:00Z",
    keyId: "evidence-key_1",
    signingKeyId: id(18)
  };
}

function electorateEntry(suffix: number, isChair = false) {
  return {
    memberId: id(suffix),
    membershipVersionId: id(suffix + 100),
    seatRole: "voting_member" as const,
    isChair,
    votingWeight: "1",
    eligibilitySha256: hash("f")
  };
}

function ballotEntry(
  options: {
    idSuffix?: number;
    principalSuffix?: number;
    casterSuffix?: number;
    source?: "own" | "proxy";
    proxyGrantId?: string | null;
    castAt?: string;
  } = {}
) {
  const principalSuffix = options.principalSuffix ?? 30;
  const source = options.source ?? "own";
  return {
    id: id(options.idSuffix ?? 31),
    principalMemberId: id(principalSuffix),
    casterMemberId: id(options.casterSuffix ?? principalSuffix),
    choice: "yes" as const,
    statementSha256: null,
    votingWeight: "1",
    source,
    proxyGrantId: options.proxyGrantId ?? null,
    consentRecordId: id(32),
    consentRecordSha256: hash("1"),
    castAt: options.castAt ?? "2026-09-01T12:00:00Z",
    disposition: null
  };
}

function proxyEntry(suffix: number) {
  return {
    id: id(suffix),
    principalMemberId: id(suffix + 100),
    holderMemberId: id(suffix + 101),
    policy: "principal_supersedes_proxy" as const,
    consentRecordId: id(suffix + 102),
    consentRecordSha256: hash("2"),
    grantedAt: "2026-09-01T12:00:00Z",
    expiresAt: null,
    revocation: null
  };
}

function exclusionEntry(suffix: number, version = 1) {
  return {
    id: id(suffix),
    memberId: id(40),
    version,
    state: "excluded" as const,
    reasonSha256: hash("3"),
    actorMemberId: id(41),
    consentRecordId: id(42),
    consentRecordSha256: hash("4"),
    effectiveAt: "2026-09-01T12:00:00Z"
  };
}

function expectCustomFailure(schema: z.ZodType, value: unknown, message: string): void {
  const result = schema.safeParse(value);
  expect(result.success).toBe(false);
  if (result.success) throw new Error("expected schema failure");
  expect(result.error.issues).toContainEqual(expect.objectContaining({ code: "custom", message }));
}

function expectDuplicateOrderingFailure(
  value: VoteCertificatePayload,
  label: "electorate" | "exclusions" | "proxies" | "ballots"
): void {
  const result = VoteCertificatePayloadSchema.safeParse(value);
  expect(result.success).toBe(false);
  if (result.success) throw new Error("expected duplicate ordering failure");
  expect(result.error.issues).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        code: "custom",
        message: `${label} contains duplicate ordering keys`
      }),
      expect.objectContaining({ code: "custom", message: `${label} must be strictly ordered` })
    ])
  );
}

function noncanonicalAlias(value: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(value.at(-1)!);
  const alias = alphabet[(last & ~3) | ((last + 1) & 3)]!;
  const changed = `${value.slice(0, -1)}${alias}`;
  expect(Buffer.from(changed, "base64url")).toEqual(Buffer.from(value, "base64url"));
  return changed;
}

describe("vote certificate exact boundary", () => {
  // Exercise enum variants at the first lazy-schema initialization so per-test
  // mutation coverage attributes the cached parser definition to its complete oracle.
  it("accepts every frozen approval, ballot, proxy, exclusion, and tally enum", () => {
    const approvalRule = payload().governance.approvalRule;
    for (const approvalDenominator of ["eligible", "participating", "yes_no"] as const) {
      expect(CertificateApprovalRuleSchema.parse({ ...approvalRule, approvalDenominator })).toEqual(
        {
          ...approvalRule,
          approvalDenominator
        }
      );
    }

    for (const tieBehavior of ["reject", "chair_casting_vote"] as const) {
      expect(CertificateApprovalRuleSchema.parse({ ...approvalRule, tieBehavior })).toEqual({
        ...approvalRule,
        tieBehavior
      });
    }
    for (const proxyPolicy of [
      "principal_supersedes_proxy",
      "first_ballot_final",
      "forbidden"
    ] as const) {
      expect(CertificateApprovalRuleSchema.parse({ ...approvalRule, proxyPolicy })).toEqual({
        ...approvalRule,
        proxyPolicy
      });
    }
    for (const closeMode of ["automatic", "secretariat_confirmed"] as const) {
      expect(CertificateApprovalRuleSchema.parse({ ...approvalRule, closeMode })).toEqual({
        ...approvalRule,
        closeMode
      });
    }

    const baseBallot = ballotEntry();
    for (const choice of ["yes", "no", "abstain"] as const) {
      expect(CertificateBallotEntrySchema.parse({ ...baseBallot, choice })).toEqual({
        ...baseBallot,
        choice
      });
    }
    for (const effect of [
      "superseded",
      "invalidated_by_recusal",
      "invalidated_by_vote_replacement"
    ] as const) {
      const disposition = {
        id: id(33),
        effect,
        supersedingBallotId: id(34),
        replacementVoteId: null,
        auditEventId: id(35),
        createdAt: "2026-09-01T12:01:00Z"
      };
      expect(
        CertificateBallotEntrySchema.parse({ ...baseBallot, disposition }).disposition
      ).toEqual(disposition);
    }

    const baseProxy = proxyEntry(50);
    for (const policy of ["principal_supersedes_proxy", "first_ballot_final"] as const) {
      expect(CertificateProxyEntrySchema.parse({ ...baseProxy, policy }).policy).toBe(policy);
    }
    for (const effect of ["revoked", "expired", "superseded"] as const) {
      const revocation = {
        id: id(60),
        effect,
        consentRecordId: id(61),
        consentRecordSha256: hash("5"),
        revokedAt: "2026-09-01T12:02:00Z"
      };
      expect(CertificateProxyEntrySchema.parse({ ...baseProxy, revocation }).revocation).toEqual(
        revocation
      );
    }

    for (const state of ["excluded", "lifted"] as const) {
      expect(CertificateExclusionEntrySchema.parse({ ...exclusionEntry(70), state }).state).toBe(
        state
      );
    }
    for (const outcome of ["approved", "rejected", "no_quorum"] as const) {
      expect(CanonicalVoteTallySchema.parse(tally(outcome))).toEqual(tally(outcome));
      expect(VoteCertificatePayloadSchema.parse(payload(outcome)).outcome).toBe(outcome);
    }
    expect(VoteCertificatePayloadSchema.parse(payload("approved", "automatic"))).toEqual(
      payload("approved", "automatic")
    );
  });

  it("accepts a proxies-forbidden package without proxy records and explains a mixed-ballot refusal", () => {
    const base = payload();
    const governance = {
      ...base.governance,
      approvalRule: {
        ...base.governance.approvalRule,
        proxyPolicy: "forbidden" as const
      }
    };
    const direct = ballotEntry();
    const forbidden = { ...base, governance, proxies: [], ballots: [] };
    expect(VoteCertificatePayloadSchema.parse(forbidden)).toEqual(forbidden);
    expectCustomFailure(
      VoteCertificatePayloadSchema,
      {
        ...forbidden,
        ballots: [
          direct,
          ballotEntry({
            idSuffix: 40,
            principalSuffix: 50,
            casterSuffix: 51,
            source: "proxy",
            proxyGrantId: id(90)
          })
        ]
      },
      "a proxies-forbidden certificate cannot contain proxy authority or ballots"
    );
  });

  it("enforces canonical positive and nonnegative decimal strings", () => {
    for (const votingWeight of ["1", "10", "9".repeat(256)]) {
      expect(
        CertificateElectorateEntrySchema.parse({ ...electorateEntry(20), votingWeight })
          .votingWeight
      ).toBe(votingWeight);
    }
    for (const votingWeight of ["", "0", "01", "-1", "x1", "1x", "1.0"]) {
      expect(
        CertificateElectorateEntrySchema.safeParse({ ...electorateEntry(20), votingWeight }).success
      ).toBe(false);
    }
    for (const eligibleWeight of ["0", "1", "10", "9".repeat(256)]) {
      expect(CanonicalVoteTallySchema.parse({ ...tally(), eligibleWeight }).eligibleWeight).toBe(
        eligibleWeight
      );
    }
    for (const eligibleWeight of ["", "00", "01", "-1", "x1", "1x", "1.0"]) {
      expect(CanonicalVoteTallySchema.safeParse({ ...tally(), eligibleWeight }).success).toBe(
        false
      );
    }
    for (const closingAuditSequence of ["1", "10", "9".repeat(256)]) {
      expect(
        VoteCertificatePayloadSchema.parse({ ...payload(), closingAuditSequence })
          .closingAuditSequence
      ).toBe(closingAuditSequence);
    }
    for (const closingAuditSequence of ["", "0", "01", "-1", "x1", "1x"]) {
      expect(
        VoteCertificatePayloadSchema.safeParse({ ...payload(), closingAuditSequence }).success
      ).toBe(false);
    }
  });

  it("enforces every own and proxy ballot attribution combination", () => {
    const own = ballotEntry();
    const proxy = ballotEntry({
      principalSuffix: 30,
      casterSuffix: 31,
      source: "proxy",
      proxyGrantId: id(90)
    });
    expect(CertificateBallotEntrySchema.parse(own)).toEqual(own);
    expect(CertificateBallotEntrySchema.parse(proxy)).toEqual(proxy);

    for (const invalid of [
      { ...own, casterMemberId: id(31) },
      { ...own, proxyGrantId: id(90) },
      { ...own, casterMemberId: id(31), proxyGrantId: id(90) },
      { ...proxy, casterMemberId: proxy.principalMemberId },
      { ...proxy, proxyGrantId: null },
      { ...proxy, casterMemberId: proxy.principalMemberId, proxyGrantId: null }
    ]) {
      expectCustomFailure(
        CertificateBallotEntrySchema,
        invalid,
        "certificate ballot attribution is invalid"
      );
    }
  });

  it("requires proxy revocation evidence to move together and forbids self-delegation", () => {
    const proxy = proxyEntry(100);
    expect(CertificateProxyEntrySchema.parse(proxy)).toEqual(proxy);
    expectCustomFailure(
      CertificateProxyEntrySchema,
      { ...proxy, holderMemberId: proxy.principalMemberId },
      "certificate proxy cannot be self-delegated"
    );

    const revocation = {
      id: id(110),
      effect: "revoked" as const,
      consentRecordId: id(111),
      consentRecordSha256: hash("6"),
      revokedAt: "2026-09-01T12:03:00Z"
    };
    expect(CertificateProxyEntrySchema.parse({ ...proxy, revocation }).revocation).toEqual(
      revocation
    );
    expect(
      CertificateProxyEntrySchema.parse({
        ...proxy,
        revocation: { ...revocation, consentRecordId: null, consentRecordSha256: null }
      }).revocation
    ).toMatchObject({ consentRecordId: null, consentRecordSha256: null });
    for (const invalid of [
      { ...revocation, consentRecordSha256: null },
      { ...revocation, consentRecordId: null }
    ]) {
      expectCustomFailure(
        CertificateProxyEntrySchema,
        { ...proxy, revocation: invalid },
        "proxy revocation consent must move together"
      );
    }
  });

  it("returns the exact custom issue for every payload relationship", () => {
    const base = payload();
    const invalidCases: readonly [VoteCertificatePayload, string][] = [
      [
        { ...base, vote: { ...base.vote, id: base.certificateId } },
        "vote and certificate IDs must differ"
      ],
      [
        {
          ...base,
          governance: {
            ...base.governance,
            approvalRule: { ...base.governance.approvalRule, closeMode: "automatic" }
          }
        },
        "certificate close modes do not match"
      ],
      [{ ...base, outcome: "rejected" }, "certificate outcome does not match tally"],
      [{ ...base, tallySha256: hash("0") }, "certificate tally hash is invalid"],
      [
        {
          ...base,
          governance: { ...base.governance, ruleOverrideId: id(120) }
        },
        "certificate override evidence must move together"
      ],
      [
        {
          ...base,
          governance: { ...base.governance, ruleOverrideSha256: hash("7") }
        },
        "certificate override evidence must move together"
      ],
      [
        { ...base, close: { ...base.close, actorMemberId: null } },
        "certificate close consent mode is inconsistent"
      ],
      [
        { ...base, close: { ...base.close, consentRecordId: null } },
        "certificate close consent mode is inconsistent"
      ],
      [
        { ...base, close: { ...base.close, consentRecordSha256: null } },
        "certificate close consent mode is inconsistent"
      ],
      [
        {
          ...base,
          electorate: [electorateEntry(20, true), electorateEntry(21, true)]
        },
        "certificate electorate has multiple chairs"
      ]
    ];
    for (const [invalid, message] of invalidCases) {
      expectCustomFailure(VoteCertificatePayloadSchema, invalid, message);
    }

    const automatic = payload("approved", "automatic");
    for (const close of [
      { ...automatic.close, actorMemberId: id(121) },
      { ...automatic.close, consentRecordId: id(122) },
      { ...automatic.close, consentRecordSha256: hash("8") }
    ]) {
      expectCustomFailure(
        VoteCertificatePayloadSchema,
        { ...automatic, close },
        "certificate close consent mode is inconsistent"
      );
    }

    expect(
      VoteCertificatePayloadSchema.parse({
        ...base,
        governance: {
          ...base.governance,
          ruleOverrideId: id(123),
          ruleOverrideSha256: hash("9")
        }
      }).governance
    ).toMatchObject({ ruleOverrideId: id(123), ruleOverrideSha256: hash("9") });
    expect(
      VoteCertificatePayloadSchema.parse({
        ...base,
        electorate: [{ ...base.electorate[0]!, isChair: true }]
      }).electorate[0]
    ).toMatchObject({ isChair: true });
  });

  it("requires every certificate collection to be unique and strictly ordered", () => {
    const base = payload();
    const electorate = [electorateEntry(20), electorateEntry(21)];
    expect(VoteCertificatePayloadSchema.parse({ ...base, electorate }).electorate).toEqual(
      electorate
    );
    expectCustomFailure(
      VoteCertificatePayloadSchema,
      { ...base, electorate: electorate.toReversed() },
      "electorate must be strictly ordered"
    );
    expectDuplicateOrderingFailure(
      { ...base, electorate: [electorate[0]!, electorate[0]!] },
      "electorate"
    );

    const exclusions = [exclusionEntry(130, 2), exclusionEntry(131, 10)];
    expect(VoteCertificatePayloadSchema.parse({ ...base, exclusions }).exclusions).toEqual(
      exclusions
    );
    expectCustomFailure(
      VoteCertificatePayloadSchema,
      { ...base, exclusions: exclusions.toReversed() },
      "exclusions must be strictly ordered"
    );
    expectDuplicateOrderingFailure(
      { ...base, exclusions: [exclusions[0]!, exclusions[0]!] },
      "exclusions"
    );

    const proxies = [proxyEntry(140), proxyEntry(141)];
    expect(VoteCertificatePayloadSchema.parse({ ...base, proxies }).proxies).toEqual(proxies);
    expectCustomFailure(
      VoteCertificatePayloadSchema,
      { ...base, proxies: proxies.toReversed() },
      "proxies must be strictly ordered"
    );
    expectDuplicateOrderingFailure({ ...base, proxies: [proxies[0]!, proxies[0]!] }, "proxies");

    const ballots = [
      ballotEntry({ idSuffix: 150, principalSuffix: 30, castAt: "2026-09-01T12:00:00Z" }),
      ballotEntry({ idSuffix: 151, principalSuffix: 30, castAt: "2026-09-01T12:01:00Z" }),
      ballotEntry({ idSuffix: 152, principalSuffix: 31, castAt: "2026-09-01T12:00:00Z" })
    ];
    expect(VoteCertificatePayloadSchema.parse({ ...base, ballots }).ballots).toEqual(ballots);
    expectCustomFailure(
      VoteCertificatePayloadSchema,
      { ...base, ballots: ballots.toReversed() },
      "ballots must be strictly ordered"
    );
    expectDuplicateOrderingFailure({ ...base, ballots: [ballots[0]!, ballots[0]!] }, "ballots");
    const sameTime = [
      ballotEntry({ idSuffix: 153, principalSuffix: 32 }),
      ballotEntry({ idSuffix: 154, principalSuffix: 32 })
    ];
    expect(VoteCertificatePayloadSchema.parse({ ...base, ballots: sameTime }).ballots).toEqual(
      sameTime
    );
  });

  it("enforces exact drift, key ID, and canonical public-ID wire forms", () => {
    const base = payload();
    for (const driftMicroseconds of ["0", "-0", "1", "-1", "10", "-10"]) {
      expect(
        VoteCertificatePayloadSchema.parse({
          ...base,
          close: { ...base.close, driftMicroseconds }
        }).close.driftMicroseconds
      ).toBe(driftMicroseconds);
    }
    for (const driftMicroseconds of ["", "+1", "00", "01", "-01", "1x", "x1", "1.0"]) {
      expect(
        VoteCertificatePayloadSchema.safeParse({
          ...base,
          close: { ...base.close, driftMicroseconds }
        }).success
      ).toBe(false);
    }
    for (const keyId of ["x", "a".repeat(128), "A-z_0.9-"]) {
      expect(VoteCertificatePayloadSchema.parse({ ...base, keyId }).keyId).toBe(keyId);
    }
    for (const keyId of ["", "a".repeat(129), "/invalid", "valid/invalid"]) {
      expect(VoteCertificatePayloadSchema.safeParse({ ...base, keyId }).success).toBe(false);
    }

    const publicId = base.publicId;
    expect(certificatePublicIdBytes(publicId)).toEqual(Buffer.alloc(32, 0xa5));
    expect(certificatePublicIdSha256(publicId)).toBe(sha256Hex(Buffer.alloc(32, 0xa5)));
    for (const invalid of [
      `x${publicId}`,
      `${publicId}x`,
      publicId.slice(1),
      `!${publicId.slice(1)}`,
      noncanonicalAlias(publicId)
    ]) {
      expect(() => certificatePublicIdBytes(invalid)).toThrow("invalid certificate public ID");
      expectCustomFailure(
        VoteCertificatePayloadSchema,
        { ...base, publicId: invalid },
        "invalid certificate public ID"
      );
    }
  });

  it("signs exact canonical bytes and rejects malformed or noncanonical certificate framing", () => {
    const keys = generateKeyPairSync("ed25519");
    const input = payload();
    const certificate = issueVoteCertificate(input, keys.privateKey);
    expect(certificate.payload).toEqual(input);
    expect(certificate.payloadSha256).toBe(canonicalSha256(input));
    expect(canonicalVoteCertificatePayload(input)).toBe(
      canonicalVoteCertificatePayload(structuredClone(input))
    );
    expect(Buffer.from(certificate.signatureBase64Url, "base64url")).toHaveLength(64);
    expect(verifyVoteCertificate(certificate, keys.publicKey)).toBe(true);

    const privatePem = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(verifyVoteCertificate(issueVoteCertificate(input, privatePem), publicPem)).toBe(true);

    for (const payloadSha256 of ["invalid", "0".repeat(64), `x${certificate.payloadSha256}`]) {
      expect(verifyVoteCertificate({ ...certificate, payloadSha256 }, keys.publicKey)).toBe(false);
    }
    for (const signatureBase64Url of [
      "invalid",
      `x${certificate.signatureBase64Url}`,
      `${certificate.signatureBase64Url}x`,
      certificate.signatureBase64Url.slice(1),
      `!${certificate.signatureBase64Url.slice(1)}`,
      noncanonicalAlias(certificate.signatureBase64Url)
    ]) {
      expect(verifyVoteCertificate({ ...certificate, signatureBase64Url }, keys.publicKey)).toBe(
        false
      );
    }
    expect(
      verifyVoteCertificate(
        { ...certificate, payload: { ...input, schema: "invalid" as never } },
        keys.publicKey
      )
    ).toBe(false);
  });
});
