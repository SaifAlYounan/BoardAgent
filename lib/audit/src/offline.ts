import { createPublicKey, type JsonWebKey } from "node:crypto";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";
import { z } from "zod";
import { canonicalVoteTally, tallyVote } from "@boardagent/domain";

import { VoteCertificatePayloadSchema, verifyVoteCertificate } from "./certificate.js";
import { AuditCheckpointPayloadSchema, verifyCheckpoint } from "./checkpoint.js";
import {
  AuditRecoveryCheckpointPayloadSchema,
  AuditRecoveryEvidenceSetSchema,
  verifyRecoveryCheckpoint,
  type SignedAuditRecoveryCheckpoint
} from "./recovery-checkpoint.js";
import { AuditEventBodySchema, GENESIS_HASH, eventHash } from "./event.js";
import {
  SignedAuditExportAttestationSchema,
  verifyAuditExportAttestation
} from "./export-attestation.js";

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);

export const OfflineEvidenceKeySchema = z
  .object({
    id: UuidV7Schema,
    kid: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u),
    algorithm: z.literal("EdDSA"),
    public_jwk: z.record(z.string(), JsonValueSchema)
  })
  .strict();

export const TrustedEvidenceKeySetSchema = z
  .object({
    schema_version: z.literal("boardagent.trusted-evidence-keys.v1"),
    keys: z
      .array(OfflineEvidenceKeySchema)
      .min(1)
      .max(1_000)
      .refine(
        (keys) =>
          new Set(keys.map(({ id }) => id)).size === keys.length &&
          new Set(keys.map(({ kid }) => kid)).size === keys.length,
        "trusted evidence key identifiers must be unique"
      )
  })
  .strict();

export const OfflineCertificateBundleSchema = z
  .object({
    schema_version: z.literal("boardagent.vote-certificate-bundle.v1"),
    certificate_id: UuidV7Schema,
    vote_id: UuidV7Schema,
    outcome_id: UuidV7Schema,
    public_id: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
    canonical_payload: VoteCertificatePayloadSchema,
    payload_sha256: Sha256HexSchema,
    signature_base64url: z.string().regex(/^[A-Za-z0-9_-]{86}$/u),
    signing_key: OfflineEvidenceKeySchema,
    issued_at: Rfc3339UtcSchema
  })
  .strict();

export type OfflineCertificateBundle = z.infer<typeof OfflineCertificateBundleSchema>;
export type TrustedEvidenceKeySet = z.infer<typeof TrustedEvidenceKeySetSchema>;

function trustedEvidenceKey(
  keySet: TrustedEvidenceKeySet,
  signingKeyId: string,
  keyId: string
): TrustedEvidenceKeySet["keys"][number] | undefined {
  const index = new Map<string, TrustedEvidenceKeySet["keys"][number]>(
    keySet.keys.map((key) => [`${key.id}:${key.kid}`, key])
  );
  return index.get(`${signingKeyId}:${keyId}`);
}

/** Stateless verification against a separately supplied trust anchor; bundle keys are never trusted alone. */
export function verifyOfflineCertificateBundle(
  bundleValue: unknown,
  trustedKeysValue: unknown
): boolean {
  let bundle: OfflineCertificateBundle;
  let trustedKeys: TrustedEvidenceKeySet;
  try {
    bundle = OfflineCertificateBundleSchema.parse(bundleValue);
    trustedKeys = TrustedEvidenceKeySetSchema.parse(trustedKeysValue);
  } catch {
    return false;
  }
  const payload = bundle.canonical_payload;
  const trusted = trustedEvidenceKey(trustedKeys, payload.signingKeyId, payload.keyId);
  if (!trusted) return false;
  const bundleProjection = canonicalJson({
    certificateId: bundle.certificate_id,
    voteId: bundle.vote_id,
    outcomeId: bundle.outcome_id,
    publicId: bundle.public_id,
    signingKeyId: bundle.signing_key.id,
    keyId: bundle.signing_key.kid,
    publicJwk: bundle.signing_key.public_jwk
  });
  const trustedProjection = canonicalJson({
    certificateId: payload.certificateId,
    voteId: payload.vote.id,
    outcomeId: payload.outcomeId,
    publicId: payload.publicId,
    signingKeyId: trusted.id,
    keyId: trusted.kid,
    publicJwk: trusted.public_jwk
  });
  if (bundleProjection !== trustedProjection) return false;
  try {
    const exclusions = new Map<string, (typeof payload.exclusions)[number]>();
    const seatWeights = new Map(
      payload.electorate.map((seat) => [seat.memberId, seat.votingWeight])
    );
    for (const exclusion of payload.exclusions) {
      if (!seatWeights.has(exclusion.memberId)) return false;
      const prior = exclusions.get(exclusion.memberId);
      if (prior && exclusion.version <= prior.version) return false;
      exclusions.set(exclusion.memberId, exclusion);
    }
    const proxies = new Map<string | null, (typeof payload.proxies)[number]>(
      payload.proxies.map((proxy) => [proxy.id, proxy])
    );
    for (const ballot of payload.ballots) {
      if (seatWeights.get(ballot.principalMemberId) !== ballot.votingWeight) return false;
      if (ballot.source === "proxy") {
        const proxy = proxies.get(ballot.proxyGrantId);
        if (
          !proxy ||
          proxy.principalMemberId !== ballot.principalMemberId ||
          proxy.holderMemberId !== ballot.casterMemberId ||
          proxy.policy !== payload.governance.approvalRule.proxyPolicy
        )
          return false;
      }
    }
    const rule = payload.governance.approvalRule;
    const recomputed = canonicalVoteTally(
      tallyVote(
        payload.electorate.map((seat) => ({
          memberId: seat.memberId,
          role: seat.seatRole,
          weight: BigInt(seat.votingWeight),
          eligible: true,
          recused: exclusions.get(seat.memberId)?.state === "excluded",
          chair: seat.isChair
        })),
        payload.ballots.filter((ballot) => ballot.disposition === null),
        {
          approval: {
            numerator: BigInt(rule.approval.numerator),
            denominator: BigInt(rule.approval.denominator)
          },
          quorum: {
            numerator: BigInt(rule.quorum.numerator),
            denominator: BigInt(rule.quorum.denominator)
          },
          approvalDenominator: rule.approvalDenominator,
          abstentionsCountForQuorum: rule.abstentionsCountForQuorum,
          tieBehavior: rule.tieBehavior
        }
      )
    );
    if (canonicalJson(recomputed) !== canonicalJson(payload.tally)) return false;
    return verifyVoteCertificate(
      {
        payload,
        payloadSha256: bundle.payload_sha256,
        signatureBase64Url: bundle.signature_base64url
      },
      createPublicKey({ key: trusted.public_jwk as JsonWebKey, format: "jwk" })
    );
  } catch {
    return false;
  }
}

export const OfflinePositiveDecimalSchema = z.string().regex(/^[1-9]\d*$/u);
export const OfflinePgSha256Schema = z.string().regex(/^\\x[0-9a-f]{64}$/u);
export const OfflinePgBytesSchema = z.string().regex(/^\\x(?:[0-9a-f]{2})+$/u);
export const OfflinePgSignatureSchema = z.string().regex(/^\\x[0-9a-f]{128}$/u);

export const OfflineExportComponentSchema = z
  .object({
    schemaVersion: z.literal("boardagent.export-component.v1"),
    name: z.string().regex(/^[a-z][a-z0-9_:-]{1,127}$/u),
    rowEncoding: z.literal("postgres-text-v1"),
    rows: z.array(z.unknown()).max(1_000_000)
  })
  .strict();

export const OfflineFullAuditEventRowSchema = z
  .object({
    id: UuidV7Schema,
    sequence: OfflinePositiveDecimalSchema,
    organization_id: UuidV7Schema,
    board_id: UuidV7Schema.nullable(),
    event_type: z.string().min(1),
    schema_version: z.literal("boardagent.audit-event.v1"),
    actor_member_id: UuidV7Schema.nullable(),
    acting_for_member_id: UuidV7Schema.nullable(),
    client_id: UuidV7Schema.nullable(),
    token_jti: UuidV7Schema.nullable(),
    consent_record_id: UuidV7Schema.nullable(),
    object_type: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),
    object_id: UuidV7Schema.nullable(),
    object_version: OfflinePositiveDecimalSchema.nullable(),
    canonical_payload: OfflinePgBytesSchema,
    previous_event_sha256: OfflinePgSha256Schema,
    event_sha256: OfflinePgSha256Schema,
    occurred_at: z.string().min(1)
  })
  .strict();

export const OfflineRedactedAuditEventRowSchema = z
  .object({
    sequence: OfflinePositiveDecimalSchema,
    previous_event_sha256: OfflinePgSha256Schema,
    event_sha256: OfflinePgSha256Schema,
    redacted: z.literal("true")
  })
  .strict();

export const OfflineAuditCheckpointRowSchema = z
  .object({
    id: UuidV7Schema,
    organization_id: UuidV7Schema,
    first_sequence: OfflinePositiveDecimalSchema,
    last_sequence: OfflinePositiveDecimalSchema,
    first_event_sha256: OfflinePgSha256Schema,
    last_event_sha256: OfflinePgSha256Schema,
    canonical_manifest: OfflinePgBytesSchema,
    manifest_sha256: OfflinePgSha256Schema,
    signature: OfflinePgSignatureSchema,
    signing_key_id: UuidV7Schema,
    created_at: z.string().min(1)
  })
  .strict();

export interface OfflineAuditExportExpectation {
  readonly organizationId: string;
  readonly boardId: string | null;
  readonly rangeFirstSequence: string;
  readonly rangeLastSequence: string;
  readonly auditHeadSequence: string;
  readonly auditHeadSha256: string;
  readonly latestCheckpointSha256: string;
}

export const OfflineAuditExportExpectationSchema: z.ZodType<OfflineAuditExportExpectation> = z
  .object({
    organizationId: UuidV7Schema,
    boardId: UuidV7Schema.nullable(),
    rangeFirstSequence: OfflinePositiveDecimalSchema,
    rangeLastSequence: OfflinePositiveDecimalSchema,
    auditHeadSequence: z.string().regex(/^(?:0|[1-9]\d*)$/u),
    auditHeadSha256: Sha256HexSchema,
    latestCheckpointSha256: Sha256HexSchema
  })
  .strict()
  .refine(
    ({ rangeFirstSequence, rangeLastSequence }) =>
      BigInt(rangeLastSequence) >= BigInt(rangeFirstSequence),
    "expected audit export sequence range is inverted"
  );

export type OfflineAuditExportVerification =
  | {
      readonly valid: true;
      readonly eventCount: string;
      readonly firstSequence: string;
      readonly lastSequence: string;
      readonly headHash: string;
      readonly checkpointCount: number;
      readonly anchorSequence: string | null;
      readonly latestCheckpointLastSequence: string;
      readonly proof?: "signed_export_snapshot";
      readonly attestedRangeLastSequence?: string;
      readonly warnings?: readonly string[];
      readonly recoveryEvidence?: readonly SignedAuditRecoveryCheckpoint[];
    }
  | {
      readonly valid: false;
      readonly firstBreakSequence: string | null;
      readonly reason: string;
    };

export interface OfflineAuditExportAttestationContext {
  readonly signed: unknown;
  readonly exportRequestId: string;
  readonly scopeSha256: string;
  readonly snapshotSha256: string;
  readonly auditRecoveryEvidence?: readonly SignedAuditRecoveryCheckpoint[];
}

export function parseOfflineCanonicalJson(bytesValue: Uint8Array): JsonValue {
  const bytes = Buffer.from(bytesValue);
  const parsed = JsonValueSchema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))
  );
  if (!bytes.equals(Buffer.from(canonicalJson(parsed)))) {
    throw new Error("offline JSON is not canonical UTF-8");
  }
  return parsed;
}

export function parseOfflineExportComponent(
  bytesValue: Uint8Array,
  name: "audit:events" | "audit:checkpoints"
) {
  const parsed = OfflineExportComponentSchema.parse(parseOfflineCanonicalJson(bytesValue));
  if (parsed.name !== name) {
    throw new Error("export component is not the expected canonical byte sequence");
  }
  return parsed;
}

function pgHex(value: string): string {
  return value.slice(2);
}

// PostgreSQL exports ISO timestamps with an offset; signed payloads are RFC 3339 UTC and
// have already passed Rfc3339UtcSchema. Compare exact instants without losing the final
// three fractional digits to Date. Every branch below is observable through the public
// verifier: the two sides are parsed by different functions, so a defect in one cannot be
// masked by the same defect in the other.
const EXPORTED_INSTANT =
  /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:Z|([+-])(\d{2})(?::(\d{2}))?(?::(\d{2}))?)$/u;

function fractionMicroseconds(digits: string): bigint {
  // BigInt("") is 0n, so an absent fraction needs no special case.
  return BigInt(digits) * 10n ** BigInt(6 - digits.length);
}

function exportedMicroseconds(value: string): bigint | null {
  const match = EXPORTED_INSTANT.exec(value);
  if (!match) return null;
  const utcWhole = `${match[1]}T${match[2]}Z`;
  if (!Rfc3339UtcSchema.safeParse(utcWhole).success) return null;
  const whole = BigInt(Date.parse(utcWhole)) * 1000n + fractionMicroseconds(match[3] ?? "");
  const sign = match[4];
  if (sign === undefined) return whole;
  const hours = Number(match[5]);
  const minutes = match[6] === undefined ? 0 : Number(match[6]);
  const seconds = match[7] === undefined ? 0 : Number(match[7]);
  if (hours > 23 || minutes > 59 || seconds > 59) return null;
  const offset = BigInt(hours * 3600 + minutes * 60 + seconds) * 1_000_000n;
  return sign === "+" ? whole - offset : whole + offset;
}

function signedMicroseconds(value: string): bigint {
  // Rfc3339Utc: YYYY-MM-DDTHH:MM:SS(.f{1,6})?Z. Date only keeps milliseconds, so parse the
  // whole seconds through Date and the fraction digits (after position 19) exactly.
  return (
    BigInt(Date.parse(`${value.slice(0, 19)}Z`)) * 1000n + fractionMicroseconds(value.slice(20, -1))
  );
}

function sameTimestamp(exported: string, signed: string): boolean {
  // An unparseable export is null and never equals the signed instant.
  return exportedMicroseconds(exported) === signedMicroseconds(signed);
}

function invalidAudit(
  reason: string,
  firstBreakSequence: string | null = null
): OfflineAuditExportVerification {
  return { valid: false, firstBreakSequence, reason };
}

/** Verify canonical exported rows, chain links, hashes, and the latest separately trusted checkpoint. */
export function verifyOfflineAuditExport(
  eventComponentBytes: Uint8Array,
  checkpointComponentBytes: Uint8Array,
  expectationValue: OfflineAuditExportExpectation,
  trustedKeysValue: unknown,
  attestationContext?: OfflineAuditExportAttestationContext
): OfflineAuditExportVerification {
  try {
    const expectation = OfflineAuditExportExpectationSchema.parse(expectationValue);
    const trustedKeys = TrustedEvidenceKeySetSchema.parse(trustedKeysValue);
    let attestedInstanceId: string | undefined;
    let attestedRecoveryEvidence: readonly SignedAuditRecoveryCheckpoint[] = [];
    if (attestationContext !== undefined) {
      const signed = SignedAuditExportAttestationSchema.parse(attestationContext.signed);
      const payload = signed.payload;
      const trusted = trustedEvidenceKey(trustedKeys, payload.signingKeyId, payload.keyId);
      if (
        !trusted ||
        !verifyAuditExportAttestation(
          signed,
          createPublicKey({ key: trusted.public_jwk as JsonWebKey, format: "jwk" })
        )
      ) {
        return invalidAudit("export_attestation_signature_invalid");
      }
      if (
        payload.exportRequestId !== attestationContext.exportRequestId ||
        payload.scopeSha256 !== attestationContext.scopeSha256 ||
        payload.snapshotSha256 !== attestationContext.snapshotSha256 ||
        payload.organizationId !== expectation.organizationId ||
        payload.boardId !== expectation.boardId ||
        payload.firstSequence !== expectation.rangeFirstSequence ||
        payload.lastSequence !== expectation.rangeLastSequence ||
        payload.auditHeadSequence !== expectation.auditHeadSequence ||
        payload.auditHeadSha256 !== expectation.auditHeadSha256 ||
        payload.latestCheckpointSha256 !== expectation.latestCheckpointSha256 ||
        payload.eventComponentSha256 !== sha256Hex(eventComponentBytes) ||
        payload.checkpointComponentSha256 !== sha256Hex(checkpointComponentBytes)
      ) {
        return invalidAudit("export_attestation_binding_mismatch");
      }
      attestedInstanceId = payload.instanceId;
      attestedRecoveryEvidence =
        payload.schemaVersion === "boardagent.audit-export-attestation.v2"
          ? payload.auditRecoveryEvidence
          : [];
      if (
        canonicalJson(attestedRecoveryEvidence) !==
        canonicalJson(attestationContext.auditRecoveryEvidence ?? [])
      )
        return invalidAudit("export_recovery_evidence_binding_mismatch");
    }
    const eventComponent = parseOfflineExportComponent(eventComponentBytes, "audit:events");
    if (eventComponent.rows.length === 0) return invalidAudit("audit_export_empty");

    const hashesBySequence = new Map<string, string>();
    let firstSequence = 0n;
    let previousSequence = 0n;
    let previousHash = GENESIS_HASH;
    let containsRedactedRows = false;
    for (const [index, rawRow] of eventComponent.rows.entries()) {
      const redacted = OfflineRedactedAuditEventRowSchema.safeParse(rawRow);
      containsRedactedRows ||= redacted.success;
      const full = redacted.success ? null : OfflineFullAuditEventRowSchema.parse(rawRow);
      if (redacted.success && expectation.boardId === null) {
        return invalidAudit("unexpected_redaction", redacted.data.sequence);
      }
      const sequenceText = redacted.success ? redacted.data.sequence : full!.sequence;
      const sequence = BigInt(sequenceText);
      const rowPreviousHash = pgHex(
        redacted.success ? redacted.data.previous_event_sha256 : full!.previous_event_sha256
      );
      const rowHash = pgHex(redacted.success ? redacted.data.event_sha256 : full!.event_sha256);
      if (index === 0) {
        firstSequence = sequence;
        if (sequence === 1n && !safeHashEqual(rowPreviousHash, GENESIS_HASH)) {
          return invalidAudit("genesis_hash_mismatch", sequenceText);
        }
      } else if (sequence !== previousSequence + 1n) {
        return invalidAudit("sequence_gap_or_reorder", (previousSequence + 1n).toString(10));
      } else if (!safeHashEqual(rowPreviousHash, previousHash)) {
        return invalidAudit("previous_hash_mismatch", sequenceText);
      }
      if (full) {
        if (full.organization_id !== expectation.organizationId) {
          return invalidAudit("event_scope_mismatch", sequenceText);
        }
        if (expectation.boardId !== null && full.board_id !== expectation.boardId) {
          return invalidAudit("event_scope_mismatch", sequenceText);
        }
        const canonicalPayload = Buffer.from(pgHex(full.canonical_payload), "hex");
        const body = AuditEventBodySchema.parse(parseOfflineCanonicalJson(canonicalPayload));
        const bodyEntityUuid = UuidV7Schema.safeParse(body.entityId);
        const rowProjection = canonicalJson({
          id: full.id,
          eventType: full.event_type,
          actorMemberId: full.actor_member_id,
          actorClientId: full.client_id,
          tokenJti: full.token_jti,
          entityType: full.object_type,
          entityId: full.object_id,
          boardId: full.board_id
        });
        const bodyProjection = canonicalJson({
          id: body.eventId,
          eventType: body.eventType,
          actorMemberId: body.actorMemberId,
          actorClientId: body.actorClientId,
          tokenJti: body.tokenJti,
          entityType: body.entityType,
          entityId: bodyEntityUuid.success ? bodyEntityUuid.data : null,
          boardId: body.boardId
        });
        if (rowProjection !== bodyProjection || !sameTimestamp(full.occurred_at, body.occurredAt)) {
          return invalidAudit("event_hash_or_projection_mismatch", sequenceText);
        }
        if (!safeHashEqual(eventHash(sequence, rowPreviousHash, body), rowHash)) {
          return invalidAudit("event_hash_or_projection_mismatch", sequenceText);
        }
      }
      hashesBySequence.set(sequenceText, rowHash);
      previousSequence = sequence;
      previousHash = rowHash;
    }
    if (firstSequence !== BigInt(expectation.rangeFirstSequence)) {
      return invalidAudit("export_range_start_mismatch", expectation.rangeFirstSequence);
    }
    const expectedLastSequence = BigInt(expectation.rangeLastSequence);
    if (previousSequence < expectedLastSequence) {
      return invalidAudit("export_range_end_mismatch", (previousSequence + 1n).toString(10));
    }
    if (previousSequence > expectedLastSequence) {
      return invalidAudit("export_range_end_mismatch", expectation.rangeLastSequence);
    }
    if (previousSequence > BigInt(expectation.auditHeadSequence)) {
      return invalidAudit("export_range_exceeds_audit_head", previousSequence.toString(10));
    }
    if (
      previousSequence === BigInt(expectation.auditHeadSequence) &&
      !safeHashEqual(previousHash, expectation.auditHeadSha256)
    ) {
      return invalidAudit("exported_head_mismatch", previousSequence.toString(10));
    }

    const checkpointComponent = parseOfflineExportComponent(
      checkpointComponentBytes,
      "audit:checkpoints"
    );
    let latestTrustedCheckpoint:
      | {
          readonly firstSequence: string;
          readonly lastSequence: string;
          readonly manifestSha256: string;
        }
      | undefined;
    const recoveryEvidence: SignedAuditRecoveryCheckpoint[] = [];
    const recoveryRequests = new Map<string, string>();
    for (const rawRow of checkpointComponent.rows) {
      const row = OfflineAuditCheckpointRowSchema.parse(rawRow);
      const sequence = row.last_sequence;
      const manifestBytes = Buffer.from(pgHex(row.canonical_manifest), "hex");
      const payload = z
        .union([AuditCheckpointPayloadSchema, AuditRecoveryCheckpointPayloadSchema])
        .parse(parseOfflineCanonicalJson(manifestBytes));
      if (attestedInstanceId !== undefined && payload.instanceId !== attestedInstanceId) {
        return invalidAudit("checkpoint_instance_mismatch", sequence);
      }
      const manifestSha256 = pgHex(row.manifest_sha256);
      const trusted = trustedEvidenceKey(trustedKeys, payload.signingKeyId, payload.keyId);
      const rowProjection = canonicalJson({
        organizationId: row.organization_id,
        checkpointId: row.id,
        firstSequence: row.first_sequence,
        lastSequence: row.last_sequence,
        firstEventSha256: pgHex(row.first_event_sha256),
        lastEventSha256: pgHex(row.last_event_sha256),
        signingKeyId: row.signing_key_id
      });
      const payloadProjection = canonicalJson({
        organizationId: expectation.organizationId,
        checkpointId: payload.checkpointId,
        firstSequence: payload.firstSequence,
        lastSequence: payload.lastSequence,
        firstEventSha256: payload.firstEventSha256,
        lastEventSha256: payload.lastEventSha256,
        signingKeyId: payload.signingKeyId
      });
      if (
        payload.organizationId !== expectation.organizationId ||
        rowProjection !== payloadProjection ||
        !sameTimestamp(row.created_at, payload.issuedAt)
      ) {
        return invalidAudit("checkpoint_signature_or_projection_mismatch", sequence);
      }
      if (!safeHashEqual(sha256Hex(manifestBytes), manifestSha256)) {
        return invalidAudit("checkpoint_signature_or_projection_mismatch", sequence);
      }
      if (!trusted) {
        return invalidAudit("checkpoint_signature_or_projection_mismatch", sequence);
      }
      const signatureBase64Url = Buffer.from(pgHex(row.signature), "hex").toString("base64url");
      const publicKey = createPublicKey({ key: trusted.public_jwk as JsonWebKey, format: "jwk" });
      const signatureValid =
        payload.schema === "boardagent.audit.recovery-checkpoint.v1"
          ? verifyRecoveryCheckpoint({ payload, signatureBase64Url }, publicKey)
          : verifyCheckpoint({ payload, signatureBase64Url }, publicKey);
      if (!signatureValid) {
        return invalidAudit("checkpoint_signature_or_projection_mismatch", sequence);
      }
      if (payload.schema === "boardagent.audit.recovery-checkpoint.v1") {
        const request = payload.recovery.request;
        // Strict recovery schema and the signed organization check above bind the request.
        if (BigInt(request.lastSequence) > BigInt(expectation.auditHeadSequence)) {
          return invalidAudit("recovery_request_scope_mismatch", sequence);
        }
        const requestBytes = canonicalJson(request);
        const previousRequest = recoveryRequests.get(request.recoveryId);
        if (previousRequest !== undefined && previousRequest !== requestBytes)
          return invalidAudit("recovery_request_mismatch", sequence);
        recoveryRequests.set(request.recoveryId, requestBytes);
        if (payload.firstSequence === request.firstSequence) {
          recoveryEvidence.push({
            payload,
            signatureBase64Url: Buffer.from(pgHex(row.signature), "hex").toString("base64url")
          });
        }
      }
      const firstHash = hashesBySequence.get(payload.firstSequence);
      const lastHash = hashesBySequence.get(payload.lastSequence);
      if (firstHash !== undefined && !safeHashEqual(firstHash, payload.firstEventSha256)) {
        return invalidAudit("checkpoint_chain_mismatch", sequence);
      }
      if (lastHash !== undefined && !safeHashEqual(lastHash, payload.lastEventSha256)) {
        return invalidAudit("checkpoint_chain_mismatch", sequence);
      }
      if (manifestSha256 === expectation.latestCheckpointSha256) {
        if (latestTrustedCheckpoint !== undefined) {
          return invalidAudit("duplicate_latest_trusted_checkpoint", sequence);
        }
        latestTrustedCheckpoint = {
          firstSequence: payload.firstSequence,
          lastSequence: sequence,
          manifestSha256
        };
      }
    }
    if (recoveryRequests.size > 0) {
      if (
        !AuditRecoveryEvidenceSetSchema.safeParse(recoveryEvidence).success ||
        recoveryRequests.size !== recoveryEvidence.length ||
        canonicalJson(recoveryEvidence) !== canonicalJson(attestedRecoveryEvidence)
      ) {
        return invalidAudit("export_recovery_evidence_binding_mismatch");
      }
    } else if (attestedRecoveryEvidence.length > 0) {
      return invalidAudit("export_recovery_evidence_binding_mismatch");
    }
    if (!latestTrustedCheckpoint) {
      return invalidAudit("latest_trusted_checkpoint_unavailable");
    }
    // A redacted row's claimed hash cannot authenticate its claimed predecessor.
    // Only a signature over the exact exported projection can protect such links.
    if (attestedInstanceId === undefined && containsRedactedRows) {
      return invalidAudit("legacy_redacted_proof_unavailable");
    }
    const checkpointLastHash = hashesBySequence.get(latestTrustedCheckpoint.lastSequence);
    const checkpointFirstHash = hashesBySequence.get(latestTrustedCheckpoint.firstSequence);
    const anchorSequence = checkpointLastHash
      ? latestTrustedCheckpoint.lastSequence
      : checkpointFirstHash
        ? latestTrustedCheckpoint.firstSequence
        : null;
    if (anchorSequence === null && attestedInstanceId === undefined) {
      return invalidAudit("latest_checkpoint_outside_exported_range");
    }
    // A signed prefix does not authenticate a subsequently recomputed suffix.
    if (attestedInstanceId === undefined && anchorSequence !== previousSequence.toString(10)) {
      return invalidAudit("latest_checkpoint_does_not_anchor_export_end");
    }
    return {
      valid: true,
      eventCount: eventComponent.rows.length.toString(10),
      firstSequence: firstSequence.toString(10),
      lastSequence: previousSequence.toString(10),
      headHash: previousHash,
      checkpointCount: checkpointComponent.rows.length,
      anchorSequence,
      latestCheckpointLastSequence: latestTrustedCheckpoint.lastSequence,
      ...(recoveryEvidence.length === 0
        ? {}
        : {
            recoveryEvidence,
            warnings: recoveryEvidence.map(
              ({ payload }) =>
                `recovery:${payload.recovery.request.recoveryId}:historical_checkpoint_deadline_missed`
            )
          }),
      ...(attestedInstanceId === undefined
        ? {}
        : {
            proof: "signed_export_snapshot" as const,
            attestedRangeLastSequence: previousSequence.toString(10)
          })
    };
  } catch {
    return invalidAudit("export_format_invalid");
  }
}
