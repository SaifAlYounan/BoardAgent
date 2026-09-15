import type { PoolClient } from "pg";
import { createPublicKey, type JsonWebKey } from "node:crypto";

import {
  AuditCheckpointPayloadSchema,
  AuditRecoveryCheckpointPayloadSchema,
  AuditRecoveryRequestSchema,
  AuditChainVerifier,
  verifyCheckpoint,
  verifyRecoveryCheckpoint,
  type AuditCheckpointPayload,
  type AuditRecoveryCheckpointPayload,
  type SignedAuditRecoveryCheckpoint,
  type AuditEventBody,
  type PublicJsonWebKey,
  type SignedAuditCheckpoint
} from "@boardagent/audit";
import { UuidV7Schema, canonicalJson, canonicalSha256, safeHashEqual } from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";
import {
  streamAuditEvidence,
  type AuditEvidenceSnapshot,
  type StoredAuditEventRow,
  type StoredCheckpointRow
} from "./audit-evidence-stream.js";

interface CheckpointSnapshotRow {
  readonly instance_id: string;
  readonly organization_id: string;
  readonly first_sequence: string;
  readonly last_sequence: string;
  readonly first_event_sha256: Buffer;
  readonly last_event_sha256: Buffer;
  readonly issued_at: string;
  readonly signing_key_id: string;
  readonly key_id: string;
  readonly public_jwk: unknown;
}

interface CheckpointKeyRow {
  readonly instance_id: string;
  readonly organization_id: string;
  readonly key_id: string;
  readonly public_jwk: unknown;
}

export interface PreparedAuditCheckpoint {
  readonly payload: AuditCheckpointPayload;
  readonly publicJwk: PublicJsonWebKey;
}

export interface CommittedAuditCheckpoint {
  readonly checkpointId: string;
  readonly manifestSha256: string;
  readonly replayed: boolean;
  readonly auditEventId?: string;
  readonly auditSequence?: string;
}

export class AuditCheckpointTransactionError extends Error {
  public constructor(
    public readonly code:
      "checkpoint_invalid" | "checkpoint_conflict" | "checkpoint_signature_invalid",
    message: string
  ) {
    super(message);
    this.name = "AuditCheckpointTransactionError";
  }
}

function asPublicJwk(value: unknown): PublicJsonWebKey {
  if (typeof value !== "object" || value === null || !("kty" in value)) {
    throw new AuditCheckpointTransactionError(
      "checkpoint_invalid",
      "evidence key did not expose a public JWK"
    );
  }
  return value as PublicJsonWebKey;
}

export async function prepareAuditCheckpointInTransaction(
  client: PoolClient,
  input: { readonly checkpointId: string; readonly signingKeyId: string }
): Promise<PreparedAuditCheckpoint> {
  const checkpointId = UuidV7Schema.parse(input.checkpointId);
  const signingKeyId = UuidV7Schema.parse(input.signingKeyId);
  const result = await client.query<CheckpointSnapshotRow>(
    `select instance_id,organization_id,first_sequence::text,last_sequence::text,
            first_event_sha256,last_event_sha256,issued_at,signing_key_id,key_id,public_jwk
       from boardagent_audit_checkpoint_snapshot($1)`,
    [signingKeyId]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1) {
    throw new AuditCheckpointTransactionError(
      "checkpoint_invalid",
      "checkpoint snapshot returned an invalid shape"
    );
  }
  const payload = AuditCheckpointPayloadSchema.parse({
    schema: "boardagent.audit.checkpoint.v1",
    checkpointId,
    instanceId: row.instance_id,
    organizationId: row.organization_id,
    auditSchema: "boardagent.audit-event.v1",
    firstSequence: row.first_sequence,
    lastSequence: row.last_sequence,
    firstEventSha256: row.first_event_sha256.toString("hex"),
    lastEventSha256: row.last_event_sha256.toString("hex"),
    issuedAt: row.issued_at,
    signingKeyId: row.signing_key_id,
    keyId: row.key_id
  });
  return { payload, publicJwk: asPublicJwk(row.public_jwk) };
}

export async function commitAuditCheckpointInTransaction(
  client: PoolClient,
  input: {
    readonly checkpoint: SignedAuditCheckpoint;
    readonly auditEventId: string;
  }
): Promise<CommittedAuditCheckpoint> {
  const payload = AuditCheckpointPayloadSchema.parse(input.checkpoint.payload);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const signature = Buffer.from(input.checkpoint.signatureBase64Url, "base64url");
  if (signature.length !== 64) {
    throw new AuditCheckpointTransactionError(
      "checkpoint_signature_invalid",
      "checkpoint signature must be exactly 64 bytes"
    );
  }
  const canonicalManifest = Buffer.from(canonicalJson(payload), "utf8");
  const manifestSha256 = canonicalSha256(payload);
  const existing = await client.query<{ manifest_sha256: Buffer; signature: Buffer }>(
    "select manifest_sha256,signature from boardagent_audit_checkpoint_lookup($1)",
    [payload.checkpointId]
  );
  const existingRow = existing.rows[0];
  if (existingRow) {
    if (
      !safeHashEqual(existingRow.manifest_sha256.toString("hex"), manifestSha256) ||
      !existingRow.signature.equals(signature)
    ) {
      throw new AuditCheckpointTransactionError(
        "checkpoint_conflict",
        "checkpoint identifier was already used for different signed evidence"
      );
    }
    return { checkpointId: payload.checkpointId, manifestSha256, replayed: true };
  }

  const keyResult = await client.query<CheckpointKeyRow>(
    `select instance_id,organization_id,key_id,public_jwk
       from boardagent_audit_checkpoint_key($1,$2::timestamptz)`,
    [payload.signingKeyId, payload.issuedAt]
  );
  const key = keyResult.rows[0];
  if (
    !key ||
    keyResult.rows.length !== 1 ||
    key.instance_id !== payload.instanceId ||
    key.organization_id !== payload.organizationId ||
    key.key_id !== payload.keyId
  ) {
    throw new AuditCheckpointTransactionError(
      "checkpoint_invalid",
      "checkpoint instance, organization, or evidence key binding changed"
    );
  }
  if (
    !verifyCheckpoint(
      { payload, signatureBase64Url: signature.toString("base64url") },
      asPublicJwk(key.public_jwk)
    )
  ) {
    throw new AuditCheckpointTransactionError(
      "checkpoint_signature_invalid",
      "checkpoint Ed25519 signature did not verify against the registered evidence key"
    );
  }

  await client.query(
    `insert into public.audit_checkpoints(
       id,organization_id,first_sequence,last_sequence,first_event_sha256,last_event_sha256,
       canonical_manifest,manifest_sha256,signature,signing_key_id,created_at
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::timestamptz)`,
    [
      payload.checkpointId,
      payload.organizationId,
      payload.firstSequence,
      payload.lastSequence,
      Buffer.from(payload.firstEventSha256, "hex"),
      Buffer.from(payload.lastEventSha256, "hex"),
      canonicalManifest,
      Buffer.from(manifestSha256, "hex"),
      signature,
      payload.signingKeyId,
      payload.issuedAt
    ]
  );
  const [auditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: payload.organizationId,
      event: {
        eventId: auditEventId,
        eventType: "audit_checkpoint_signed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "audit_checkpoint",
        entityId: payload.checkpointId,
        boardId: null,
        origin: "worker",
        details: {
          manifestSha256,
          firstSequence: payload.firstSequence,
          lastSequence: payload.lastSequence,
          signedHeadSha256: payload.lastEventSha256,
          signingKeyId: payload.signingKeyId
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!auditEvent) throw new Error("checkpoint append did not return its audit event");
  return {
    checkpointId: payload.checkpointId,
    manifestSha256,
    replayed: false,
    auditEventId: auditEvent.eventId,
    auditSequence: auditEvent.sequence.toString(10)
  };
}

export type PersistedAuditVerification =
  | {
      readonly valid: true;
      readonly ready: boolean;
      readonly eventCount: string;
      readonly headHash: string;
      readonly checkpointCount: number;
      readonly coveredThrough: string;
      readonly lagEvents: string;
      readonly lagSeconds: number;
      readonly warnings: readonly string[];
      readonly recoveryEvidence?: readonly SignedAuditRecoveryCheckpoint[];
    }
  | {
      readonly valid: false;
      readonly ready: false;
      readonly reason: string;
      readonly firstBreakSequence?: string;
      readonly checkpointId?: string;
    };

function invalidAudit(
  reason: string,
  context: { readonly firstBreakSequence?: string; readonly checkpointId?: string } = {}
): PersistedAuditVerification {
  return { valid: false, ready: false, reason, ...context };
}

function sameNullable(left: string | null, right: string | null): boolean {
  return left === right;
}

function milliseconds(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError("invalid persisted timestamp");
  return parsed;
}

function microseconds(value: string): bigint {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z$/u.exec(value);
  if (!match?.[1]) throw new TypeError("invalid persisted UTC timestamp");
  const wholeSeconds = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(wholeSeconds)) throw new TypeError("invalid persisted UTC timestamp");
  const fraction = (match[2] ?? "").padEnd(6, "0");
  return BigInt(wholeSeconds) * 1_000n + BigInt(fraction || "0");
}

function persistedCheckpointSignatureValid(
  row: StoredCheckpointRow,
  payload: AuditCheckpointPayload | AuditRecoveryCheckpointPayload,
  publicJwk: unknown
): boolean {
  try {
    return payload.schema === "boardagent.audit.recovery-checkpoint.v1"
      ? verifyRecoveryCheckpoint(
          { payload, signatureBase64Url: row.signature.toString("base64url") },
          createPublicKey({ key: asPublicJwk(publicJwk) as JsonWebKey, format: "jwk" })
        )
      : verifyCheckpoint(
          { payload, signatureBase64Url: row.signature.toString("base64url") },
          asPublicJwk(publicJwk)
        );
  } catch {
    return false;
  }
}

/** Verify within the caller's active request, worker, backup or bootstrap transaction.
 * The audit cursor shares that transaction's permissions and snapshot; this function
 * never starts, commits or rolls back a transaction on the caller's behalf.
 */
export async function verifyPersistedAuditEvidence(
  client: PoolClient
): Promise<PersistedAuditVerification> {
  const chainVerifier = new AuditChainVerifier();
  const eventsBySequence = new Map<string, { eventHash: string; occurredAt: string }>();
  const signedEvents = new Map<
    string,
    { sequence: bigint; origin: string; details: AuditEventBody["details"] }
  >();
  const neededSequences = new Set<string>(["1"]);
  let checkpointsById: Map<string, StoredCheckpointRow> | undefined;
  let eventFailure: PersistedAuditVerification | undefined;
  const consume = (
    row: StoredAuditEventRow,
    snapshot: AuditEvidenceSnapshot
  ): PersistedAuditVerification | undefined => {
    const instance = snapshot.instance;
    if (!instance) return invalidAudit("audit_verifier_root_shape_invalid");
    if (!checkpointsById) {
      checkpointsById = new Map(
        snapshot.checkpoints.map((checkpoint) => [checkpoint.id, checkpoint])
      );
      for (const checkpoint of snapshot.checkpoints) {
        neededSequences.add(checkpoint.first_sequence);
        neededSequences.add(checkpoint.last_sequence);
        neededSequences.add((BigInt(checkpoint.last_sequence) + 1n).toString(10));
        if (checkpoint.recovery_authorization) {
          try {
            const request = AuditRecoveryRequestSchema.parse(
              JSON.parse(checkpoint.recovery_authorization.canonical_request)
            );
            neededSequences.add(request.firstSequence);
            neededSequences.add(request.lastSequence);
            if (checkpoint.recovery_authorization.final_head_sequence)
              neededSequences.add(checkpoint.recovery_authorization.final_head_sequence);
          } catch {
            /* Report after event and chain validation, preserving error precedence. */
          }
        }
      }
    }
    const decoded = chainVerifier.addCanonicalEvent({
      canonicalPayload: row.canonical_payload,
      sequence: BigInt(row.sequence),
      previousHash: row.previous_event_sha256.toString("hex"),
      eventHash: row.event_sha256.toString("hex")
    });
    if ("reason" in decoded)
      return invalidAudit(decoded.reason, { firstBreakSequence: row.sequence });
    const event = decoded.event;
    const body = event;
    const parsedObjectId = UuidV7Schema.safeParse(body.entityId);
    if (
      row.organization_id !== instance.organization_id ||
      row.id !== body.eventId ||
      row.event_type !== body.eventType ||
      row.schema_version !== "boardagent.audit-event.v1" ||
      !sameNullable(row.actor_member_id, body.actorMemberId) ||
      !sameNullable(row.client_id, body.actorClientId) ||
      !sameNullable(row.token_jti, body.tokenJti) ||
      !sameNullable(row.board_id, body.boardId) ||
      row.object_type !== body.entityType ||
      row.object_id !== (parsedObjectId.success ? parsedObjectId.data : null) ||
      row.occurred_at !== body.occurredAt
    ) {
      return invalidAudit("event_column_manifest_mismatch", {
        firstBreakSequence: row.sequence
      });
    }
    if (neededSequences.has(row.sequence))
      eventsBySequence.set(row.sequence, {
        eventHash: event.eventHash,
        occurredAt: event.occurredAt
      });
    const checkpoint = checkpointsById.get(body.entityId);
    if (
      body.eventType === "audit_checkpoint_signed" &&
      checkpoint &&
      !signedEvents.has(checkpoint.id) &&
      body.details["manifestSha256"] === checkpoint.manifest_sha256.toString("hex")
    ) {
      signedEvents.set(checkpoint.id, {
        sequence: event.sequence,
        origin: body.origin,
        details: body.details
      });
    }
    return undefined;
  };
  const snapshot = await streamAuditEvidence(client, (row, state) => {
    // Keep the original precedence: malformed rows are reported before chain failures.
    // A failure does not retain the rest of the result, but the query is fully drained.
    if (!eventFailure) eventFailure = consume(row, state);
  });
  if (eventFailure) return eventFailure;
  const { instance, head, now } = snapshot;
  if (!instance || !head || !now) return invalidAudit("audit_verifier_root_shape_invalid");
  const chain = chainVerifier.finish({
    count: BigInt(head.last_sequence),
    headHash: head.last_event_sha256.toString("hex")
  });
  if (!chain.valid) {
    return invalidAudit(chain.reason, {
      firstBreakSequence: chain.firstBreakSequence.toString(10)
    });
  }

  const keys = new Map(snapshot.keys.map((key) => [key.id, key]));
  let coveredThrough = 0n;
  const warnings: string[] = [];
  const recoveryEvidence: SignedAuditRecoveryCheckpoint[] = [];
  for (const row of snapshot.checkpoints) {
    let payload: AuditCheckpointPayload | AuditRecoveryCheckpointPayload;
    try {
      const raw = JSON.parse(row.canonical_manifest.toString("utf8")) as { schema?: unknown };
      payload =
        raw?.schema === "boardagent.audit.recovery-checkpoint.v1"
          ? AuditRecoveryCheckpointPayloadSchema.parse(raw)
          : AuditCheckpointPayloadSchema.parse(raw);
    } catch {
      return invalidAudit("checkpoint_manifest_schema_invalid", { checkpointId: row.id });
    }
    if (!row.canonical_manifest.equals(Buffer.from(canonicalJson(payload), "utf8"))) {
      return invalidAudit("checkpoint_manifest_not_canonical", { checkpointId: row.id });
    }
    const manifestSha256 = canonicalSha256(payload);
    const first = eventsBySequence.get(row.first_sequence);
    const last = eventsBySequence.get(row.last_sequence);
    if (
      row.organization_id !== instance.organization_id ||
      payload.instanceId !== instance.instance_id ||
      payload.organizationId !== row.organization_id ||
      payload.checkpointId !== row.id ||
      payload.firstSequence !== row.first_sequence ||
      payload.lastSequence !== row.last_sequence ||
      payload.firstEventSha256 !== row.first_event_sha256.toString("hex") ||
      payload.lastEventSha256 !== row.last_event_sha256.toString("hex") ||
      payload.signingKeyId !== row.signing_key_id ||
      payload.issuedAt !== row.created_at ||
      !safeHashEqual(manifestSha256, row.manifest_sha256.toString("hex")) ||
      !first ||
      !last ||
      first.eventHash !== payload.firstEventSha256 ||
      last.eventHash !== payload.lastEventSha256 ||
      BigInt(row.first_sequence) !== coveredThrough + 1n
    ) {
      return invalidAudit("checkpoint_manifest_row_or_interval_mismatch", {
        checkpointId: row.id,
        firstBreakSequence: row.first_sequence
      });
    }
    const key = keys.get(row.signing_key_id);
    const issuedAt = microseconds(payload.issuedAt);
    if (
      !key ||
      key.organization_id !== row.organization_id ||
      key.kid !== payload.keyId ||
      key.purpose !== "evidence_signing" ||
      key.algorithm !== "EdDSA" ||
      microseconds(key.activated_at) > issuedAt ||
      (key.retired_at !== null && microseconds(key.retired_at) <= issuedAt) ||
      (key.compromised_at !== null && microseconds(key.compromised_at) <= issuedAt)
    ) {
      return invalidAudit("checkpoint_key_history_invalid", { checkpointId: row.id });
    }
    if (!persistedCheckpointSignatureValid(row, payload, key.public_jwk)) {
      return invalidAudit("checkpoint_signature_invalid", { checkpointId: row.id });
    }
    if (key.compromised_at !== null && microseconds(key.compromised_at) > issuedAt) {
      warnings.push(`checkpoint:${row.id}:signing_key_compromised_after_issuance`);
    }
    const signedEvent = signedEvents.get(row.id);
    if (!signedEvent || signedEvent.sequence <= BigInt(row.last_sequence)) {
      return invalidAudit("checkpoint_audit_event_missing", { checkpointId: row.id });
    }
    const oldestCoveredAt = microseconds(first.occurredAt);
    if (payload.schema === "boardagent.audit.recovery-checkpoint.v1" && !row.recovery_id)
      return invalidAudit("checkpoint_recovery_authority_missing", { checkpointId: row.id });
    if (row.recovery_id) {
      try {
        const authority = row.recovery_authorization;
        if (
          !authority?.completed_at ||
          !authority.final_checkpoint_id ||
          !authority.final_head_sequence ||
          !authority.final_head_sha256
        )
          return invalidAudit("checkpoint_recovery_authority_missing", { checkpointId: row.id });
        const request = AuditRecoveryRequestSchema.parse(JSON.parse(authority.canonical_request));
        const originalFirst = eventsBySequence.get(request.firstSequence);
        const originalLast = eventsBySequence.get(request.lastSequence);
        const finalHead = eventsBySequence.get(authority.final_head_sequence);
        const finalCheckpoint = checkpointsById?.get(authority.final_checkpoint_id);
        const finalAttestation = signedEvents.get(authority.final_checkpoint_id);
        if (
          request.recoveryId !== row.recovery_id ||
          canonicalJson(request) !== authority.canonical_request ||
          canonicalSha256(request) !== authority.request_sha256 ||
          request.instanceId !== instance.instance_id ||
          request.organizationId !== row.organization_id ||
          request.signingKeyId !== row.signing_key_id ||
          request.keyId !== payload.keyId ||
          request.firstEventSha256 !== originalFirst?.eventHash ||
          request.firstUncoveredEventAt !== originalFirst.occurredAt ||
          request.headSha256 !== originalLast?.eventHash ||
          authority.expires_at !== request.expiresAt ||
          microseconds(authority.authorized_at) < microseconds(request.preparedAt) ||
          issuedAt < microseconds(authority.authorized_at) ||
          microseconds(authority.completed_at) < issuedAt ||
          microseconds(authority.completed_at) >= microseconds(request.expiresAt) ||
          BigInt(payload.firstSequence) < BigInt(request.firstSequence) ||
          BigInt(payload.lastSequence) >= BigInt(authority.final_head_sequence) ||
          finalHead?.eventHash !== authority.final_head_sha256 ||
          finalCheckpoint?.recovery_id !== row.recovery_id ||
          BigInt(finalCheckpoint.last_sequence) + 1n !== BigInt(authority.final_head_sequence) ||
          finalAttestation?.sequence !== BigInt(authority.final_head_sequence) ||
          finalAttestation.origin !== "cli" ||
          signedEvent.origin !== "cli" ||
          canonicalJson(signedEvent.details) !==
            canonicalJson({
              manifestSha256,
              firstSequence: payload.firstSequence,
              lastSequence: payload.lastSequence,
              signedHeadSha256: payload.lastEventSha256,
              signingKeyId: payload.signingKeyId
            })
        )
          return invalidAudit("checkpoint_recovery_authority_invalid", { checkpointId: row.id });
        if (payload.schema === "boardagent.audit.recovery-checkpoint.v1") {
          if (
            canonicalJson(payload.recovery.request) !== authority.canonical_request ||
            payload.recovery.requestSha256 !== authority.request_sha256 ||
            payload.recovery.firstCoveredEventAt !== first.occurredAt
          )
            return invalidAudit("checkpoint_recovery_findings_invalid", { checkpointId: row.id });
          const warning = `recovery:${row.recovery_id}:historical_checkpoint_deadline_missed`;
          if (!warnings.includes(warning)) warnings.push(warning);
          if (payload.firstSequence === request.firstSequence)
            recoveryEvidence.push({
              payload,
              signatureBase64Url: row.signature.toString("base64url")
            });
        }
      } catch {
        return invalidAudit("checkpoint_recovery_authority_invalid", { checkpointId: row.id });
      }
    }
    if (
      payload.schema === "boardagent.audit.checkpoint.v1" &&
      issuedAt - oldestCoveredAt > 15n * 60n * 1_000_000n
    ) {
      return invalidAudit("checkpoint_time_window_exceeded", {
        checkpointId: row.id,
        firstBreakSequence: row.first_sequence
      });
    }
    coveredThrough = BigInt(row.last_sequence);
  }

  const eventCount = BigInt(head.last_sequence);
  const lagEvents = eventCount - coveredThrough;
  const firstUncovered = eventsBySequence.get((coveredThrough + 1n).toString(10));
  const lagSeconds = firstUncovered
    ? Math.max(0, Math.floor((milliseconds(now) - milliseconds(firstUncovered.occurredAt)) / 1_000))
    : 0;
  return {
    valid: true,
    ready: lagEvents <= 1_000n && lagSeconds <= 15 * 60,
    eventCount: eventCount.toString(10),
    headHash: chain.headHash,
    checkpointCount: snapshot.checkpoints.length,
    coveredThrough: coveredThrough.toString(10),
    lagEvents: lagEvents.toString(10),
    lagSeconds,
    warnings,
    ...(recoveryEvidence.length === 0 ? {} : { recoveryEvidence })
  };
}
