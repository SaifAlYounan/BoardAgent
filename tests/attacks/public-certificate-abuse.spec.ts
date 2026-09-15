import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  certificatePublicIdBytes,
  issueVoteCertificate,
  verifyOfflineCertificateBundle,
  verifyVoteCertificate
} from "../../lib/audit/src/index.js";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import { runOperator } from "../../scripts/src/operator.js";
import { voteCertificatePayload } from "../helpers/certificate-fixture.js";

describe("TH-15 public certificate abuse", () => {
  it("rejects guessed identifiers, forged signatures, and stale asserted payloads generically", () => {
    const trusted = generateKeyPairSync("ed25519");
    const attacker = generateKeyPairSync("ed25519");
    const payload = voteCertificatePayload();
    const certificate = issueVoteCertificate(payload, trusted.privateKey);
    const signingKey = {
      id: payload.signingKeyId,
      kid: payload.keyId,
      algorithm: "EdDSA" as const,
      public_jwk: trusted.publicKey.export({ format: "jwk" })
    };
    const bundle = {
      schema_version: "boardagent.vote-certificate-bundle.v1",
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
      schema_version: "boardagent.trusted-evidence-keys.v1",
      keys: [signingKey]
    };

    expect(verifyVoteCertificate(certificate, trusted.publicKey)).toBe(true);
    expect(verifyOfflineCertificateBundle(bundle, trust)).toBe(true);
    expect(verifyVoteCertificate(certificate, attacker.publicKey)).toBe(false);
    expect(
      verifyVoteCertificate(
        {
          ...certificate,
          payload: {
            ...payload,
            vote: { ...payload.vote, resolutionText: "ATTACKER ASSERTED TEXT" }
          }
        },
        trusted.publicKey
      )
    ).toBe(false);
    const attackerCertificate = issueVoteCertificate(payload, attacker.privateKey);
    expect(
      verifyOfflineCertificateBundle(
        {
          ...bundle,
          payload_sha256: attackerCertificate.payloadSha256,
          signature_base64url: attackerCertificate.signatureBase64Url,
          signing_key: {
            ...signingKey,
            public_jwk: attacker.publicKey.export({ format: "jwk" })
          }
        },
        trust
      )
    ).toBe(false);

    for (const guessed of ["", "known-vote-id", "A".repeat(42), "A".repeat(44), "!".repeat(43)]) {
      expect(() => certificatePublicIdBytes(guessed)).toThrow("invalid certificate public ID");
    }
  });

  it("verifies a bundle offline without database or runtime configuration", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-offline-certificate-"));
    try {
      const trusted = generateKeyPairSync("ed25519");
      const payload = voteCertificatePayload();
      const certificate = issueVoteCertificate(payload, trusted.privateKey);
      const signingKey = {
        id: payload.signingKeyId,
        kid: payload.keyId,
        algorithm: "EdDSA" as const,
        public_jwk: trusted.publicKey.export({ format: "jwk" })
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
      const bundleFile = path.join(directory, "certificate.json");
      const trustFile = path.join(directory, "trusted-keys.json");
      await writeFile(bundleFile, canonicalJson(bundle), { encoding: "utf8", mode: 0o600 });
      await writeFile(trustFile, canonicalJson(trust), { encoding: "utf8", mode: 0o600 });
      const output: string[] = [];
      expect(
        await runOperator(
          ["verify-certificate", bundleFile, trustFile],
          {},
          {
            stdout: (line) => output.push(line),
            stderr: (line) => output.push(line)
          }
        )
      ).toBe(0);
      expect(JSON.parse(output.join(""))).toEqual({
        schemaVersion: "boardagent.operator-certificate-verification.v1",
        command: "verify-certificate",
        valid: true
      });

      const attacker = generateKeyPairSync("ed25519");
      await writeFile(
        trustFile,
        canonicalJson({
          ...trust,
          keys: [
            {
              ...signingKey,
              public_jwk: attacker.publicKey.export({ format: "jwk" })
            }
          ]
        }),
        { encoding: "utf8", mode: 0o600 }
      );
      const rejectedOutput: string[] = [];
      expect(
        await runOperator(
          ["verify-certificate", bundleFile, trustFile],
          {},
          {
            stdout: (line) => rejectedOutput.push(line),
            stderr: (line) => rejectedOutput.push(line)
          }
        )
      ).toBe(1);
      expect(JSON.parse(rejectedOutput.join(""))).toMatchObject({ valid: false });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
