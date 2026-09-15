import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  OfflineCertificateBundleSchema,
  VoteCertificatePayloadSchema,
  OfflineEvidenceKeySchema,
  TrustedEvidenceKeySetSchema,
  issueVoteCertificate,
  verifyOfflineCertificateBundle,
  type VoteCertificatePayload
} from "../../lib/audit/src/index.js";
import type { JsonValue } from "../../lib/contracts/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { voteCertificatePayload } from "../helpers/certificate-fixture.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;

function fixture() {
  const trusted = generateKeyPairSync("ed25519");
  const attacker = generateKeyPairSync("ed25519");
  const payload = voteCertificatePayload();
  const certificate = issueVoteCertificate(payload, trusted.privateKey);
  const signingKey = {
    id: payload.signingKeyId,
    kid: payload.keyId,
    algorithm: "EdDSA" as const,
    public_jwk: trusted.publicKey.export({ format: "jwk" }) as JsonValue
  };
  const bundle = {
    schema_version: "boardagent.vote-certificate-bundle.v1" as const,
    certificate_id: payload.certificateId,
    vote_id: payload.vote.id,
    outcome_id: payload.outcomeId,
    public_id: payload.publicId,
    canonical_payload: payload,
    payload_sha256: certificate.payloadSha256,
    signature_base64url: certificate.signatureBase64Url,
    signing_key: signingKey,
    issued_at: "2026-09-01T12:00:00Z"
  };
  const trust = {
    schema_version: "boardagent.trusted-evidence-keys.v1" as const,
    keys: [signingKey]
  };
  return { attacker, bundle, payload, signingKey, trust, trusted };
}

function signedVariant(base: ReturnType<typeof fixture>, payload: VoteCertificatePayload) {
  const normalized = {
    ...payload,
    tallySha256: canonicalSha256(payload.tally),
    outcome: payload.tally.outcome
  };
  const signed = issueVoteCertificate(normalized, base.trusted.privateKey);
  return {
    ...base.bundle,
    canonical_payload: normalized,
    payload_sha256: signed.payloadSha256,
    signature_base64url: signed.signatureBase64Url
  };
}

function exclusion(
  version: number,
  state: "excluded" | "lifted",
  memberId = id(20),
  entryId = id(31 + version)
) {
  return {
    id: entryId,
    memberId,
    version,
    state,
    reasonSha256: "c".repeat(64),
    actorMemberId: id(14),
    consentRecordId: id(40 + version),
    consentRecordSha256: "d".repeat(64),
    effectiveAt: "2026-09-01T11:00:00Z"
  };
}

function emptyTally(eligibleWeight: string): VoteCertificatePayload["tally"] {
  return {
    schemaVersion: "boardagent.vote-tally.v1",
    eligibleWeight,
    participatingWeight: "0",
    yesWeight: "0",
    noWeight: "0",
    abstainWeight: "0",
    quorumMet: false,
    approvalMet: false,
    outcome: "no_quorum"
  };
}

describe("offline certificate boundary", () => {
  it("independently verifies proxy attribution and frozen ballot weights", () => {
    const base = fixture();
    const own = base.payload.ballots[0]!;
    const proxy = {
      id: id(30),
      principalMemberId: id(20),
      holderMemberId: id(24),
      policy: "principal_supersedes_proxy" as const,
      consentRecordId: id(31),
      consentRecordSha256: "c".repeat(64),
      grantedAt: "2026-09-01T11:00:00Z",
      expiresAt: null,
      revocation: null
    };
    const payload: VoteCertificatePayload = {
      ...base.payload,
      electorate: [
        ...base.payload.electorate,
        { ...base.payload.electorate[0]!, memberId: id(24), membershipVersionId: id(25) }
      ],
      proxies: [proxy],
      ballots: [{ ...own, source: "proxy", casterMemberId: id(24), proxyGrantId: proxy.id }],
      tally: { ...base.payload.tally, eligibleWeight: "2" }
    };
    expect(verifyOfflineCertificateBundle(signedVariant(base, payload), base.trust)).toBe(true);
    const invalid: VoteCertificatePayload[] = [
      { ...payload, proxies: [] },
      { ...payload, proxies: [{ ...proxy, principalMemberId: id(26) }] },
      { ...payload, proxies: [{ ...proxy, holderMemberId: id(26) }] },
      { ...payload, proxies: [{ ...proxy, policy: "first_ballot_final" }] },
      { ...payload, ballots: [{ ...payload.ballots[0]!, votingWeight: "2" }] },
      { ...base.payload, ballots: [{ ...own, principalMemberId: id(99), casterMemberId: id(99) }] }
    ];
    for (const candidate of invalid) {
      expect(verifyOfflineCertificateBundle(signedVariant(base, candidate), base.trust)).toBe(
        false
      );
    }
  });

  it("recomputes recusal and later lifting instead of trusting the declared total", () => {
    const base = fixture();
    const excluded: VoteCertificatePayload = {
      ...base.payload,
      exclusions: [exclusion(1, "excluded")],
      ballots: [],
      tally: emptyTally("0")
    };
    expect(verifyOfflineCertificateBundle(signedVariant(base, excluded), base.trust)).toBe(true);
    const restored = {
      ...base.payload,
      exclusions: [exclusion(1, "excluded"), exclusion(2, "lifted")]
    };
    expect(verifyOfflineCertificateBundle(signedVariant(base, restored), base.trust)).toBe(true);
    const excludedAgain = {
      ...excluded,
      exclusions: [exclusion(1, "lifted"), exclusion(2, "excluded")]
    };
    expect(verifyOfflineCertificateBundle(signedVariant(base, excludedAgain), base.trust)).toBe(
      true
    );
    const unknown = { ...base.payload, exclusions: [exclusion(1, "excluded", id(99))] };
    expect(verifyOfflineCertificateBundle(signedVariant(base, unknown), base.trust)).toBe(false);
    const forged = { ...excluded, tally: emptyTally("1") };
    expect(verifyOfflineCertificateBundle(signedVariant(base, forged), base.trust)).toBe(false);
  });

  it("rejects repeated or numerically decreasing exclusion versions", () => {
    const base = fixture();
    const ambiguous = {
      ...base.payload,
      ballots: [],
      tally: emptyTally("0"),
      exclusions: [exclusion(1, "excluded", id(20), id(32)), exclusion(1, "lifted", id(20), id(33))]
    };
    expect(verifyOfflineCertificateBundle(signedVariant(base, ambiguous), base.trust)).toBe(false);
    // Neither selecting the first nor selecting the last duplicate may make it valid.
    const lastDuplicateMatches = { ...base.payload, exclusions: ambiguous.exclusions };
    expect(
      verifyOfflineCertificateBundle(signedVariant(base, lastDuplicateMatches), base.trust)
    ).toBe(false);
    // These safe integers satisfy the payload's lexical ordering but decrease numerically.
    const decreasing = {
      ...ambiguous,
      exclusions: [
        exclusion(10_000_000_000, "excluded", id(20), id(32)),
        exclusion(9_999_999_999, "lifted", id(20), id(33))
      ]
    };
    expect(verifyOfflineCertificateBundle(signedVariant(base, decreasing), base.trust)).toBe(false);
    const lastDecreasingMatches = { ...base.payload, exclusions: decreasing.exclusions };
    expect(
      verifyOfflineCertificateBundle(signedVariant(base, lastDecreasingMatches), base.trust)
    ).toBe(false);
  });

  it("retains disposed ballot history without counting it again", () => {
    const base = fixture();
    const ballot = base.payload.ballots[0]!;
    const replaced: VoteCertificatePayload = {
      ...base.payload,
      ballots: [
        {
          ...ballot,
          choice: "no",
          castAt: "2026-09-01T11:58:00Z",
          disposition: {
            id: id(50),
            effect: "superseded",
            supersedingBallotId: id(51),
            replacementVoteId: null,
            auditEventId: id(52),
            createdAt: "2026-09-01T11:59:00Z"
          }
        },
        { ...ballot, id: id(51) }
      ]
    };
    expect(verifyOfflineCertificateBundle(signedVariant(base, replaced), base.trust)).toBe(true);
  });

  it("rejects a correctly signed certificate whose tally does not follow its ballots", () => {
    const { bundle, trust, payload, trusted } = fixture();
    const tally = { ...payload.tally, yesWeight: "2" };
    const inconsistent = { ...payload, tally, tallySha256: canonicalSha256(tally) };
    const signed = issueVoteCertificate(inconsistent, trusted.privateKey);
    expect(
      verifyOfflineCertificateBundle(
        {
          ...bundle,
          canonical_payload: inconsistent,
          payload_sha256: signed.payloadSha256,
          signature_base64url: signed.signatureBase64Url
        },
        trust
      )
    ).toBe(false);
  });
  it("accepts only fully anchored public IDs, signatures, and evidence-key IDs", () => {
    const { bundle, signingKey } = fixture();
    expect(OfflineEvidenceKeySchema.parse(signingKey)).toEqual(signingKey);
    for (const kid of [`!${signingKey.kid}`, `${signingKey.kid}!`, "", "a".repeat(129)]) {
      expect(OfflineEvidenceKeySchema.safeParse({ ...signingKey, kid }).success).toBe(false);
    }
    for (const public_id of [`!${bundle.public_id}`, `${bundle.public_id}!`]) {
      expect(OfflineCertificateBundleSchema.safeParse({ ...bundle, public_id }).success).toBe(
        false
      );
    }
    for (const signature_base64url of [
      `!${bundle.signature_base64url}`,
      `${bundle.signature_base64url}!`
    ]) {
      expect(
        OfflineCertificateBundleSchema.safeParse({ ...bundle, signature_base64url }).success
      ).toBe(false);
    }
    expect(OfflineCertificateBundleSchema.parse(bundle)).toEqual(bundle);
  });

  it("requires one to 1,000 keys with independently unique IDs and kids", () => {
    const { signingKey } = fixture();
    const second = { ...signingKey, id: id(901), kid: "evidence-key-2" };
    const base = {
      schema_version: "boardagent.trusted-evidence-keys.v1" as const,
      keys: [signingKey, second]
    };
    expect(TrustedEvidenceKeySetSchema.parse(base).keys).toHaveLength(2);
    expect(TrustedEvidenceKeySetSchema.safeParse({ ...base, keys: [] }).success).toBe(false);
    expect(
      TrustedEvidenceKeySetSchema.safeParse({
        ...base,
        keys: Array.from({ length: 1_001 }, (_, index) => ({
          ...signingKey,
          id: id(1_000 + index),
          kid: `key-${String(index)}`
        }))
      }).success
    ).toBe(false);

    const duplicateId = TrustedEvidenceKeySetSchema.safeParse({
      ...base,
      keys: [signingKey, { ...second, id: signingKey.id }]
    });
    const duplicateKid = TrustedEvidenceKeySetSchema.safeParse({
      ...base,
      keys: [signingKey, { ...second, kid: signingKey.kid }]
    });
    expect(duplicateId.success).toBe(false);
    expect(duplicateKid.success).toBe(false);
    if (duplicateId.success || duplicateKid.success) throw new Error("expected duplicate failure");
    expect(duplicateId.error.issues[0]?.message).toBe(
      "trusted evidence key identifiers must be unique"
    );
    expect(duplicateKid.error.issues[0]?.message).toBe(
      "trusted evidence key identifiers must be unique"
    );
  });

  it("binds every bundle projection and the separately trusted exact key", () => {
    const { attacker, bundle, payload, signingKey, trust } = fixture();
    expect(verifyOfflineCertificateBundle(bundle, trust)).toBe(true);
    expect(
      verifyOfflineCertificateBundle(bundle, {
        ...trust,
        keys: [{ ...signingKey, id: id(915), kid: "unrelated-key" }, signingKey]
      })
    ).toBe(true);

    const attackerJwk = attacker.publicKey.export({ format: "jwk" }) as JsonValue;
    const invalidBundles = [
      { ...bundle, certificate_id: id(910) },
      { ...bundle, vote_id: id(911) },
      { ...bundle, outcome_id: id(912) },
      { ...bundle, public_id: Buffer.alloc(32, 0x42).toString("base64url") },
      { ...bundle, signing_key: { ...signingKey, id: id(913) } },
      { ...bundle, signing_key: { ...signingKey, kid: "other-key" } },
      { ...bundle, signing_key: { ...signingKey, public_jwk: attackerJwk } },
      {
        ...bundle,
        canonical_payload: {
          ...payload,
          vote: { ...payload.vote, resolutionText: "tampered resolution" }
        }
      },
      { ...bundle, payload_sha256: "f".repeat(64) },
      { ...bundle, signature_base64url: "A".repeat(86) }
    ];
    for (const invalid of invalidBundles) {
      expect(verifyOfflineCertificateBundle(invalid, trust)).toBe(false);
    }

    expect(
      verifyOfflineCertificateBundle(bundle, {
        ...trust,
        keys: [{ ...signingKey, id: id(914) }]
      })
    ).toBe(false);
    expect(
      verifyOfflineCertificateBundle(bundle, {
        ...trust,
        keys: [{ ...signingKey, kid: "other-key" }]
      })
    ).toBe(false);
    const invalidJwkKey = { ...signingKey, public_jwk: {} };
    expect(
      verifyOfflineCertificateBundle(
        { ...bundle, signing_key: invalidJwkKey },
        { ...trust, keys: [invalidJwkKey] }
      )
    ).toBe(false);
    expect(verifyOfflineCertificateBundle({}, trust)).toBe(false);
    expect(verifyOfflineCertificateBundle(bundle, {})).toBe(false);
  });
});

describe("charter-forbidden proxy certificates", () => {
  it("issues and independently verifies a direct-only ballot under a proxies-forbidden charter", () => {
    const base = fixture();
    const payload: VoteCertificatePayload = {
      ...base.payload,
      governance: {
        ...base.payload.governance,
        approvalRule: { ...base.payload.governance.approvalRule, proxyPolicy: "forbidden" }
      }
    };
    const bundle = signedVariant(base, payload);
    expect(verifyOfflineCertificateBundle(bundle, base.trust)).toBe(true);
  });
  it("refuses proxy grants or attributed ballots in a proxies-forbidden certificate", () => {
    const base = fixture();
    const payload = {
      ...base.payload,
      governance: {
        ...base.payload.governance,
        approvalRule: { ...base.payload.governance.approvalRule, proxyPolicy: "forbidden" }
      }
    };
    const proxy = {
      id: id(991),
      principalMemberId: id(20),
      holderMemberId: id(992),
      policy: "principal_supersedes_proxy",
      consentRecordId: id(993),
      consentRecordSha256: "a".repeat(64),
      grantedAt: "2026-09-01T12:00:00Z",
      expiresAt: null,
      revocation: null
    };
    expect(VoteCertificatePayloadSchema.safeParse({ ...payload, proxies: [proxy] }).success).toBe(
      false
    );
    expect(
      VoteCertificatePayloadSchema.safeParse({
        ...payload,
        ballots: [
          { ...payload.ballots[0], casterMemberId: id(992), source: "proxy", proxyGrantId: id(991) }
        ]
      }).success
    ).toBe(false);
  });
});
