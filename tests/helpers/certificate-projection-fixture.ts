import { generateKeyPairSync } from "node:crypto";
import type { Pool } from "pg";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { issueVoteCertificate } from "../../lib/audit/src/certificate.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { appendAuditEventsInTransaction } from "../../lib/db/src/transactions/audit.js";
import { voteCertificatePayload } from "./certificate-fixture.js";
import { seedVoteProjectionOutcome } from "./vote-projection-outcome-fixture.js";
import { testId, type AuthorizedActorFixture } from "./authorized-actor.js";

// Genuinely signed, schema-valid synthetic storage. The body uses the existing
// offline fixture with bound resource IDs; it is not recomputed persisted vote
// truth, public issuance/close authorization or an accepted corporate act.
export async function seedCertificateProjectionFixture(
  pool: Pool,
  actor: AuthorizedActorFixture,
  voteId: string
) {
  const keys = generateKeyPairSync("ed25519"),
    base = voteCertificatePayload();
  const publicId = Buffer.alloc(32, 0x6d),
    kid = "certificate-projection-fixture";
  const publicJwk = {
    ...keys.publicKey.export({ format: "jwk" }),
    fixture: {
      label: "Δ",
      wide: 1e40,
      tiny: 1e-40,
      nested: [{}, [], { text: 'Δ🙂\n"\\', flag: false, empty: null }]
    }
  } as JsonValue;
  const payload = {
    ...base,
    certificateId: testId(224001),
    outcomeId: testId(224000),
    organizationId: actor.organizationId,
    boardId: actor.boardId,
    publicId: publicId.toString("base64url"),
    vote: { ...base.vote, id: voteId },
    signingKeyId: testId(224002),
    keyId: kid
  };
  const signed = issueVoteCertificate(payload, keys.privateKey);
  const canonicalPayload = Buffer.from(canonicalJson(signed.payload), "utf8");
  const outcome = await seedVoteProjectionOutcome(
    pool,
    actor,
    voteId,
    canonicalJson(signed.payload.tally),
    {
      canonicalPayload,
      publicId,
      kid,
      publicJwk
    }
  );
  const issuedId = testId(225000),
    closedId = testId(225001);
  // Normal insert guards demand both exact audit events and the matching
  // immutable draft. Certificate insertion and final closed state share a txn.
  await withRequestTransaction(pool, actor.context, async (client) => {
    const source = await client.query<{ close_consent_record_id: string }>(
      "select close_consent_record_id from vote_outcomes where id=$1 and vote_id=$2",
      [outcome.outcomeId, voteId]
    );
    if (source.rows.length !== 1)
      throw new Error("certificate fixture requires one bound closing outcome");
    await appendAuditEventsInTransaction(client, [
      {
        organizationId: actor.organizationId,
        consentRecordId: source.rows[0]!.close_consent_record_id,
        event: {
          eventId: issuedId,
          eventType: "certificate_issued",
          actorMemberId: actor.memberId,
          actorClientId: actor.clientId,
          tokenJti: actor.tokenJti,
          entityType: "vote",
          entityId: voteId,
          boardId: actor.boardId,
          origin: "mcp",
          details: { syntheticStorageFixture: true },
          schemaVersion: 1
        }
      },
      {
        organizationId: actor.organizationId,
        consentRecordId: source.rows[0]!.close_consent_record_id,
        event: {
          eventId: closedId,
          eventType: "vote_closed",
          actorMemberId: actor.memberId,
          actorClientId: actor.clientId,
          tokenJti: actor.tokenJti,
          entityType: "vote",
          entityId: voteId,
          boardId: actor.boardId,
          origin: "mcp",
          details: { syntheticStorageFixture: true },
          schemaVersion: 1
        }
      }
    ]);
    const inserted = await client.query(
      `insert into vote_certificates(id,organization_id,board_id,vote_id,outcome_id,
      public_id,schema_version,canonical_payload,payload_sha256,signature,signing_key_id,
      certificate_issued_audit_event_id,vote_closed_audit_event_id)
      values($1,$2,$3,$4,$5,$6,'boardagent.vote-certificate.v1',$7,$8,$9,$10,$11,$12) returning id`,
      [
        outcome.certificateId,
        actor.organizationId,
        actor.boardId,
        voteId,
        outcome.outcomeId,
        publicId,
        canonicalPayload,
        Buffer.from(signed.payloadSha256, "hex"),
        Buffer.from(signed.signatureBase64Url, "base64url"),
        outcome.signingKeyId,
        issuedId,
        closedId
      ]
    );
    if (inserted.rowCount !== 1)
      throw new Error("certificate fixture did not store its exact signed bytes");
    const closed = await client.query(
      `update votes set state='closed',closed_at=transaction_timestamp(),
      row_version=row_version+1 where id=$1 and state='closing' returning id`,
      [voteId]
    );
    if (closed.rowCount !== 1)
      throw new Error("certificate fixture could not close its exact vote");
  });
  const trust = {
    schema_version: "boardagent.trusted-evidence-keys.v1" as const,
    keys: [{ id: outcome.signingKeyId, kid, algorithm: "EdDSA" as const, public_jwk: publicJwk }]
  };
  return { ...outcome, canonicalPayload, publicJwk, trust, signed };
}
