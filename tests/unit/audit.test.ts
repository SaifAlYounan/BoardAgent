import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  appendEvent,
  canonicalVoteCertificatePayload,
  certificatePublicIdBytes,
  certificatePublicIdSha256,
  CertificateBallotEntrySchema,
  CertificateProxyEntrySchema,
  issueVoteCertificate,
  signCheckpoint,
  verifyChain,
  verifyCheckpoint,
  verifyVoteCertificate,
  VoteCertificatePayloadSchema,
  type AuditEventBody,
  type VoteCertificatePayload
} from "../../lib/audit/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";

function body(index: number): AuditEventBody {
  return {
    eventId: `018f0000-0000-7000-8000-${index.toString(16).padStart(12, "0")}`,
    eventType: "context_read",
    actorMemberId: null,
    actorClientId: null,
    tokenJti: null,
    entityType: "test",
    entityId: `018f0000-0000-7000-9000-${index.toString(16).padStart(12, "0")}`,
    boardId: null,
    occurredAt: "2026-08-28T00:00:00Z",
    origin: "mcp",
    details: { index },
    schemaVersion: 1
  };
}

describe("tamper-evident evidence", () => {
  it("matches the hand-authored independent canonical byte/hash vector", () => {
    const vector: AuditEventBody = {
      eventId: "018f0000-0000-7000-8000-000000000001",
      eventType: "context_read",
      actorMemberId: null,
      actorClientId: null,
      tokenJti: null,
      entityType: "context",
      entityId: "018f0000-0000-7000-8000-000000000002",
      boardId: null,
      occurredAt: "2026-08-28T00:00:00Z",
      origin: "mcp",
      details: {
        requestId: "018f0000-0000-7000-8000-000000000003",
        result: "authorized"
      },
      schemaVersion: 1
    };
    expect(appendEvent(undefined, vector).eventHash).toBe(
      "c487a2c6444f605d9981818f7e753147e9e6a8f0f75f42ff689faaeecff59e54"
    );
  });

  it("refuses event names outside the frozen 128-entry registry", () => {
    expect(() =>
      appendEvent(undefined, { ...body(1), eventType: "not_registered" as never })
    ).toThrow();
  });

  it("detects mutation, reordering and truncation against a signed head", () => {
    const first = appendEvent(undefined, body(1));
    const second = appendEvent(first, body(2));
    const expected = { count: 2n, headHash: second.eventHash };
    expect(verifyChain([first, second], expected).valid).toBe(true);
    expect(verifyChain([second, first], expected).valid).toBe(false);
    expect(verifyChain([first], expected).valid).toBe(false);
    expect(verifyChain([{ ...first, origin: "tampered" }, second], expected).valid).toBe(false);
  });

  it("signs checkpoints and certificates only under separately supplied trusted keys", () => {
    const evidence = generateKeyPairSync("ed25519");
    const attacker = generateKeyPairSync("ed25519");
    const checkpoint = signCheckpoint(
      {
        schema: "boardagent.audit.checkpoint.v1",
        checkpointId: "018f0000-0000-7000-8000-000000000001",
        instanceId: "018f0000-0000-7000-8000-000000000002",
        organizationId: "018f0000-0000-7000-8000-000000000003",
        auditSchema: "boardagent.audit-event.v1",
        firstSequence: "1",
        lastSequence: "1",
        firstEventSha256: "0".repeat(64),
        lastEventSha256: "0".repeat(64),
        issuedAt: "2026-08-28T00:00:00Z",
        signingKeyId: "018f0000-0000-7000-8000-000000000004",
        keyId: "evidence-1"
      },
      evidence.privateKey
    );
    expect(verifyCheckpoint(checkpoint, evidence.publicKey)).toBe(true);
    expect(verifyCheckpoint(checkpoint, attacker.publicKey)).toBe(false);

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
    const payload: VoteCertificatePayload = {
      schema: "boardagent.vote-certificate.v1",
      certificateId: "018f0000-0000-7000-8000-000000000100",
      publicId: Buffer.alloc(32, 1).toString("base64url"),
      outcomeId: "018f0000-0000-7000-8000-000000000101",
      instanceId: "018f0000-0000-7000-8000-000000000102",
      organizationId: "018f0000-0000-7000-8000-000000000103",
      boardId: "018f0000-0000-7000-8000-000000000104",
      vote: {
        id: "018f0000-0000-7000-8000-000000000105",
        title: "Certificate fixture",
        resolutionVersionId: "018f0000-0000-7000-8000-000000000106",
        resolutionVersion: 1,
        resolutionText: "RESOLVED: test the certificate.",
        resolutionSha256: "1".repeat(64),
        decisionPackageId: "018f0000-0000-7000-8000-000000000107",
        decisionPackageVersion: 1,
        decisionPackageSha256: "2".repeat(64),
        closeMode: "secretariat_confirmed",
        deadlineAt: "2026-08-28T01:00:00Z"
      },
      packageEvidence: {
        submissionManifestSha256: "c".repeat(64),
        documentManifestSha256: "d".repeat(64),
        questionCutoffSha256: "e".repeat(64)
      },
      governance: {
        governanceProfileId: "018f0000-0000-7000-8000-000000000108",
        governanceProfileSha256: "3".repeat(64),
        rulesetId: "018f0000-0000-7000-8000-000000000109",
        rulesetSha256: "4".repeat(64),
        matterEvaluationId: "018f0000-0000-7000-8000-000000000110",
        matterEvaluationResultSha256: "5".repeat(64),
        selectedRulesetRuleId: "018f0000-0000-7000-8000-000000000111",
        selectedRulesetRuleSha256: "6".repeat(64),
        ruleOverrideId: null,
        ruleOverrideSha256: null,
        approvalRule: {
          id: "018f0000-0000-7000-8000-000000000112",
          canonicalSha256: "7".repeat(64),
          approval: { numerator: "1", denominator: "2" },
          quorum: { numerator: "1", denominator: "2" },
          approvalDenominator: "eligible",
          abstentionsCountForQuorum: true,
          tieBehavior: "reject",
          proxyPolicy: "principal_supersedes_proxy",
          closeMode: "secretariat_confirmed"
        }
      },
      electorateSha256: "4".repeat(64),
      electorate: [
        {
          memberId: "018f0000-0000-7000-8000-000000000113",
          membershipVersionId: "018f0000-0000-7000-8000-000000000114",
          seatRole: "voting_member",
          isChair: false,
          votingWeight: "1",
          eligibilitySha256: "8".repeat(64)
        }
      ],
      exclusions: [],
      proxies: [],
      ballots: [],
      consentSetSha256: "9".repeat(64),
      tally,
      tallySha256: canonicalSha256(tally),
      outcome: "approved",
      close: {
        actorMemberId: "018f0000-0000-7000-8000-000000000115",
        consentRecordId: "018f0000-0000-7000-8000-000000000116",
        consentRecordSha256: "a".repeat(64),
        clockSampleId: "018f0000-0000-7000-8000-000000000117",
        measuredAt: "2026-08-28T00:00:00Z",
        driftMicroseconds: "0",
        validUntil: "2026-08-28T00:05:00Z"
      },
      closingAuditEventId: "018f0000-0000-7000-8000-000000000118",
      closingAuditSequence: "99",
      closingAuditHash: "b".repeat(64),
      preparedAt: "2026-08-28T00:00:00Z",
      keyId: "evidence-1",
      signingKeyId: "018f0000-0000-7000-8000-000000000119"
    };
    const certificate = issueVoteCertificate(payload, evidence.privateKey);
    expect(verifyVoteCertificate(certificate, evidence.publicKey)).toBe(true);
    expect(verifyVoteCertificate(certificate, attacker.publicKey)).toBe(false);
    expect(certificatePublicIdBytes(payload.publicId)).toEqual(Buffer.alloc(32, 1));
    expect(certificatePublicIdSha256(payload.publicId)).toHaveLength(64);
    expect(JSON.parse(canonicalVoteCertificatePayload(payload))).toEqual(payload);

    const privatePem = evidence.privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString("utf8");
    const publicPem = evidence.publicKey.export({ format: "pem", type: "spki" }).toString("utf8");
    const pemCertificate = issueVoteCertificate(payload, privatePem);
    expect(verifyVoteCertificate(pemCertificate, publicPem)).toBe(true);
    expect(
      verifyVoteCertificate(
        { ...certificate, payload: { ...payload, schema: "invalid" as never } },
        evidence.publicKey
      )
    ).toBe(false);
    expect(
      verifyVoteCertificate({ ...certificate, payloadSha256: "invalid" }, evidence.publicKey)
    ).toBe(false);
    expect(
      verifyVoteCertificate({ ...certificate, signatureBase64Url: "invalid" }, evidence.publicKey)
    ).toBe(false);
    expect(
      verifyVoteCertificate({ ...certificate, payloadSha256: "0".repeat(64) }, evidence.publicKey)
    ).toBe(false);

    const ballot = {
      id: "018f0000-0000-7000-8000-000000000120",
      principalMemberId: "018f0000-0000-7000-8000-000000000121",
      casterMemberId: "018f0000-0000-7000-8000-000000000121",
      choice: "yes" as const,
      statementSha256: null,
      votingWeight: "1",
      source: "own" as const,
      proxyGrantId: null,
      consentRecordId: "018f0000-0000-7000-8000-000000000122",
      consentRecordSha256: "c".repeat(64),
      castAt: "2026-08-28T00:00:00Z",
      disposition: null
    };
    expect(CertificateBallotEntrySchema.parse(ballot)).toEqual(ballot);
    expect(() =>
      CertificateBallotEntrySchema.parse({ ...ballot, casterMemberId: payload.close.actorMemberId })
    ).toThrow("attribution");
    expect(() =>
      CertificateBallotEntrySchema.parse({
        ...ballot,
        source: "proxy",
        casterMemberId: ballot.principalMemberId,
        proxyGrantId: null
      })
    ).toThrow("attribution");

    const proxy = {
      id: "018f0000-0000-7000-8000-000000000123",
      principalMemberId: "018f0000-0000-7000-8000-000000000124",
      holderMemberId: "018f0000-0000-7000-8000-000000000125",
      policy: "principal_supersedes_proxy" as const,
      consentRecordId: "018f0000-0000-7000-8000-000000000126",
      consentRecordSha256: "d".repeat(64),
      grantedAt: "2026-08-28T00:00:00Z",
      expiresAt: null,
      revocation: null
    };
    expect(CertificateProxyEntrySchema.parse(proxy)).toEqual(proxy);
    expect(() =>
      CertificateProxyEntrySchema.parse({ ...proxy, holderMemberId: proxy.principalMemberId })
    ).toThrow("self-delegated");
    expect(() =>
      CertificateProxyEntrySchema.parse({
        ...proxy,
        revocation: {
          id: "018f0000-0000-7000-8000-000000000127",
          effect: "revoked",
          consentRecordId: "018f0000-0000-7000-8000-000000000128",
          consentRecordSha256: null,
          revokedAt: "2026-08-28T00:00:00Z"
        }
      })
    ).toThrow("consent must move together");

    const invalidPayloads: VoteCertificatePayload[] = [
      { ...payload, vote: { ...payload.vote, id: payload.certificateId } },
      {
        ...payload,
        governance: {
          ...payload.governance,
          approvalRule: { ...payload.governance.approvalRule, closeMode: "automatic" }
        }
      },
      { ...payload, outcome: "rejected" },
      { ...payload, tallySha256: "f".repeat(64) },
      {
        ...payload,
        governance: {
          ...payload.governance,
          ruleOverrideId: "018f0000-0000-7000-8000-000000000129"
        }
      },
      { ...payload, close: { ...payload.close, actorMemberId: null } },
      {
        ...payload,
        electorate: [
          { ...payload.electorate[0]!, isChair: true },
          {
            ...payload.electorate[0]!,
            memberId: "018f0000-0000-7000-8000-000000000130",
            membershipVersionId: "018f0000-0000-7000-8000-000000000131",
            isChair: true
          }
        ]
      },
      { ...payload, electorate: [payload.electorate[0]!, payload.electorate[0]!] }
    ];
    for (const invalidPayload of invalidPayloads) {
      expect(VoteCertificatePayloadSchema.safeParse(invalidPayload).success).toBe(false);
    }
    const withExclusion: VoteCertificatePayload = {
      ...payload,
      exclusions: [
        {
          id: "018f0000-0000-7000-8000-000000000132",
          memberId: "018f0000-0000-7000-8000-000000000133",
          version: 1,
          state: "excluded",
          reasonSha256: "e".repeat(64),
          actorMemberId: payload.close.actorMemberId!,
          consentRecordId: payload.close.consentRecordId!,
          consentRecordSha256: payload.close.consentRecordSha256!,
          effectiveAt: "2026-08-28T00:00:00Z"
        }
      ]
    };
    expect(VoteCertificatePayloadSchema.parse(withExclusion).exclusions).toHaveLength(1);
  });
});
