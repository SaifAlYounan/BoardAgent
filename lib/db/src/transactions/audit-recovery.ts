import { createPublicKey } from "node:crypto";
import type { PoolClient } from "pg";
import { z } from "zod";
import {
  AuditRecoveryRequestSchema,
  AuditRecoveryCheckpointPayloadSchema,
  AuditCheckpointPayloadSchema,
  verifyCheckpoint,
  verifyRecoveryCheckpoint,
  type AuditRecoveryRequest,
  type AuditCheckpointPayload,
  type AuditRecoveryCheckpointPayload,
  type SignedAuditCheckpoint,
  type SignedAuditRecoveryCheckpoint
} from "@boardagent/audit";
import {
  canonicalJson,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";
import { verifyPersistedAuditEvidence } from "./checkpoints.js";
import { appendAuditEventsInTransaction } from "./audit.js";

const PreparationInputSchema = z
  .object({
    recoveryId: UuidV7Schema,
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    signingKeyId: UuidV7Schema,
    operatorReference: AuditRecoveryRequestSchema.in.shape.operatorReference,
    reason: AuditRecoveryRequestSchema.in.shape.reason
  })
  .strict();

const RecoveryPublicJwkSchema = z
  .object({
    kty: z.literal("OKP"),
    crv: z.literal("Ed25519"),
    x: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/u)
      .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value),
    kid: z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,128}$/u)
      .optional(),
    alg: z.literal("EdDSA").optional(),
    use: z.literal("sig").optional(),
    key_ops: z.tuple([z.literal("verify")]).optional()
  })
  .strict();

export class AuditRecoveryTransactionError extends Error {
  public constructor(
    public readonly code:
      | "recovery_invalid"
      | "recovery_target_mismatch"
      | "recovery_integrity_invalid"
      | "recovery_signature_invalid",
    message: string
  ) {
    super(message);
    this.name = "AuditRecoveryTransactionError";
  }
}

interface RecoverySnapshotRow {
  instance_id: string;
  organization_id: string;
  first_sequence: string;
  last_sequence: string;
  first_event_sha256: Buffer;
  last_event_sha256: Buffer;
  first_uncovered_event_at: string;
  prepared_at: string;
  expires_at: string;
  signing_key_id: string;
  key_id: string;
  public_jwk: unknown;
}

export interface PreparedAuditRecovery {
  readonly request: AuditRecoveryRequest;
  readonly requestSha256: string;
  readonly publicJwk: z.infer<typeof RecoveryPublicJwkSchema>;
}

/** Run with the operator credential in withBootstrapTransaction(..., {readOnly:true}).
 * A consistent snapshot is enforced in SQL. This returns a proposal, never authority
 * to change the database. Application must recheck the exact head, key and expiry.
 */
export async function prepareAuditRecoveryInTransaction(
  client: PoolClient,
  rawInput: z.input<typeof PreparationInputSchema>
): Promise<PreparedAuditRecovery> {
  const input = PreparationInputSchema.parse(rawInput);
  const snapshot = await client.query<RecoverySnapshotRow>(
    "select * from public.boardagent_audit_recovery_snapshot($1)",
    [input.signingKeyId]
  );
  const row = snapshot.rows[0];
  if (!row || snapshot.rows.length !== 1) {
    throw new AuditRecoveryTransactionError("recovery_invalid", "recovery snapshot is unavailable");
  }
  if (
    row.instance_id !== input.instanceId ||
    row.organization_id !== input.organizationId ||
    row.signing_key_id !== input.signingKeyId
  ) {
    throw new AuditRecoveryTransactionError(
      "recovery_target_mismatch",
      "recovery target does not match the installation record"
    );
  }
  const publicJwk = RecoveryPublicJwkSchema.safeParse(row.public_jwk);
  if (
    !publicJwk.success ||
    (publicJwk.data.kid !== undefined && publicJwk.data.kid !== row.key_id)
  ) {
    throw new AuditRecoveryTransactionError("recovery_invalid", "recovery public key is invalid");
  }
  const key = createPublicKey({ key: publicJwk.data, format: "jwk" });
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new AuditRecoveryTransactionError("recovery_invalid", "recovery public key is invalid");
  }

  const verified = await verifyPersistedAuditEvidence(client);
  if (
    !verified.valid ||
    verified.eventCount !== row.last_sequence ||
    verified.headHash !== row.last_event_sha256.toString("hex") ||
    BigInt(verified.coveredThrough) + 1n !== BigInt(row.first_sequence)
  ) {
    throw new AuditRecoveryTransactionError(
      "recovery_integrity_invalid",
      "retained audit evidence did not verify; recovery was not prepared"
    );
  }
  const request = AuditRecoveryRequestSchema.parse({
    schemaVersion: "boardagent.audit-recovery-request.v1",
    ...input,
    firstSequence: row.first_sequence,
    lastSequence: row.last_sequence,
    firstEventSha256: row.first_event_sha256.toString("hex"),
    headSha256: row.last_event_sha256.toString("hex"),
    keyId: row.key_id,
    firstUncoveredEventAt: row.first_uncovered_event_at,
    preparedAt: row.prepared_at,
    expiresAt: row.expires_at
  });
  return { request, requestSha256: canonicalSha256(request), publicJwk: publicJwk.data };
}

const ApplyInputSchema = z
  .object({
    request: AuditRecoveryRequestSchema,
    requestSha256: Sha256HexSchema,
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema
  })
  .strict();

export interface AuditRecoveryEffects {
  readonly sign: (
    payload: AuditCheckpointPayload | AuditRecoveryCheckpointPayload
  ) => Promise<SignedAuditCheckpoint | SignedAuditRecoveryCheckpoint>;
  readonly createId: () => string;
  readonly signal?: AbortSignal;
}

export interface AppliedAuditRecovery {
  readonly recoveryId: string;
  readonly requestSha256: string;
  readonly finalCheckpointId: string;
  readonly finalHeadSequence: string;
  readonly finalHeadSha256: string;
  readonly completedAt: string;
  readonly replayed: boolean;
}

function recoveryMicroseconds(value: string): bigint {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z$/u.exec(value);
  if (!match?.[1])
    throw new AuditRecoveryTransactionError("recovery_invalid", "invalid recovery timestamp");
  return BigInt(Date.parse(`${match[1]}Z`)) * 1000n + BigInt((match[2] ?? "").padEnd(6, "0"));
}

async function recoveryReceipt(
  client: PoolClient,
  recoveryId: string,
  replayed: boolean
): Promise<AppliedAuditRecovery> {
  const result = await client.query<{
    request_sha256: Buffer;
    final_checkpoint_id: string;
    final_head_sequence: string;
    final_head_sha256: Buffer;
    completed_at: string;
  }>(
    `select recovery.request_sha256,completion.final_checkpoint_id,completion.final_head_sequence::text,
       completion.final_head_sha256,to_char(completion.completed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as completed_at
       from public.audit_recoveries as recovery join public.audit_recovery_completions as completion on completion.recovery_id=recovery.id
       where recovery.id=$1`,
    [recoveryId]
  );
  const row = result.rows[0];
  if (!row || result.rows.length !== 1)
    throw new AuditRecoveryTransactionError(
      "recovery_invalid",
      "completed recovery receipt is unavailable"
    );
  return {
    recoveryId,
    requestSha256: row.request_sha256.toString("hex"),
    finalCheckpointId: row.final_checkpoint_id,
    finalHeadSequence: row.final_head_sequence,
    finalHeadSha256: row.final_head_sha256.toString("hex"),
    completedAt: row.completed_at,
    replayed
  };
}

/** The caller owns one SERIALIZABLE operator transaction. Every checkpoint, attestation
 * and completion rolls back together on error. A returned value is durable only after
 * the wrapper's COMMIT succeeds; a lost reply is resolved by retrying the exact request.
 */
export async function applyAuditRecoveryInTransaction(
  client: PoolClient,
  rawInput: z.input<typeof ApplyInputSchema>,
  effects: AuditRecoveryEffects
): Promise<AppliedAuditRecovery> {
  effects.signal?.throwIfAborted();
  const input = ApplyInputSchema.parse(rawInput);
  const request = input.request;
  if (canonicalSha256(request) !== input.requestSha256)
    throw new AuditRecoveryTransactionError(
      "recovery_invalid",
      "the supplied recovery digest does not match the exact request"
    );
  const instance = (
    await client.query<{ instance_id: string; organization_id: string }>(
      "select instance_id,organization_id from public.system_instance where singleton_key"
    )
  ).rows[0];
  if (
    !instance ||
    request.instanceId !== input.instanceId ||
    request.organizationId !== input.organizationId ||
    instance.instance_id !== input.instanceId ||
    instance.organization_id !== input.organizationId
  )
    throw new AuditRecoveryTransactionError(
      "recovery_target_mismatch",
      "recovery target does not match the installation record"
    );
  const began = await client.query<{ recovery_id: string; replayed: boolean }>(
    "select * from public.boardagent_begin_audit_recovery($1,$2)",
    [Buffer.from(canonicalJson(request)), Buffer.from(input.requestSha256, "hex")]
  );
  if (began.rows.length !== 1 || began.rows[0]!.recovery_id !== request.recoveryId)
    throw new AuditRecoveryTransactionError(
      "recovery_invalid",
      "recovery authority returned an invalid result"
    );
  if (began.rows[0]!.replayed) return recoveryReceipt(client, request.recoveryId, true);

  const before = await verifyPersistedAuditEvidence(client);
  if (
    !before.valid ||
    before.eventCount !== request.lastSequence ||
    before.headHash !== request.headSha256 ||
    BigInt(before.coveredThrough) + 1n !== BigInt(request.firstSequence)
  )
    throw new AuditRecoveryTransactionError(
      "recovery_integrity_invalid",
      "retained audit evidence did not verify; recovery was not applied"
    );
  const keyRow = (
    await client.query<{ public_jwk: unknown; kid: string }>(
      "select public_jwk,kid from public.crypto_key_registry where id=$1",
      [request.signingKeyId]
    )
  ).rows[0];
  const keyShape = RecoveryPublicJwkSchema.safeParse(keyRow?.public_jwk);
  if (
    !keyShape.success ||
    keyRow?.kid !== request.keyId ||
    (keyShape.data.kid !== undefined && keyShape.data.kid !== request.keyId)
  )
    throw new AuditRecoveryTransactionError("recovery_invalid", "recovery public key is invalid");
  const publicKey = createPublicKey({ key: keyShape.data, format: "jwk" });
  let completed = false;
  for (let step = 0; step < 1002; step++) {
    effects.signal?.throwIfAborted();
    const snapshot = (
      await client.query<{ head: string; covered: string; issued_at: string }>(
        `select head.last_sequence::text as head,(select coalesce(max(checkpoint.last_sequence),0)::text from public.audit_checkpoints as checkpoint) as covered,
        to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as issued_at from public.audit_chain_head as head where head.singleton_key`
      )
    ).rows[0];
    if (!snapshot)
      throw new AuditRecoveryTransactionError("recovery_invalid", "recovery head is unavailable");
    const head = BigInt(snapshot.head),
      covered = BigInt(snapshot.covered);
    if (step > 0 && covered >= BigInt(request.lastSequence) && head - covered === 1n) {
      completed = true;
      break;
    }
    const first = covered + 1n;
    const firstEvent = (
      await client.query<{ event_sha256: Buffer; occurred_at: string }>(
        `select event_sha256,to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at from public.audit_events where sequence=$1`,
        [first.toString()]
      )
    ).rows[0];
    if (!firstEvent)
      throw new AuditRecoveryTransactionError(
        "recovery_integrity_invalid",
        "recovery endpoint is missing"
      );
    const missed =
      recoveryMicroseconds(snapshot.issued_at) -
      recoveryMicroseconds(firstEvent.occurred_at) -
      900_000_000n;
    const latest = missed > 0n ? BigInt(request.lastSequence) : head;
    const last = first + 999n < latest ? first + 999n : latest;
    if (last < first)
      throw new AuditRecoveryTransactionError(
        "recovery_invalid",
        "new recovery activity exceeded the normal signing deadline; the attempt must roll back"
      );
    const lastEvent = (
      await client.query<{ event_sha256: Buffer }>(
        "select event_sha256 from public.audit_events where sequence=$1",
        [last.toString()]
      )
    ).rows[0];
    if (!lastEvent)
      throw new AuditRecoveryTransactionError(
        "recovery_integrity_invalid",
        "recovery endpoint is missing"
      );
    const base = {
      checkpointId: UuidV7Schema.parse(effects.createId()),
      instanceId: request.instanceId,
      organizationId: request.organizationId,
      auditSchema: "boardagent.audit-event.v1",
      firstSequence: first.toString(),
      lastSequence: last.toString(),
      firstEventSha256: firstEvent.event_sha256.toString("hex"),
      lastEventSha256: lastEvent.event_sha256.toString("hex"),
      issuedAt: snapshot.issued_at,
      signingKeyId: request.signingKeyId,
      keyId: request.keyId
    };
    const payload =
      missed > 0n
        ? AuditRecoveryCheckpointPayloadSchema.parse({
            ...base,
            schema: "boardagent.audit.recovery-checkpoint.v1",
            recovery: {
              request,
              requestSha256: input.requestSha256,
              firstCoveredEventAt: firstEvent.occurred_at,
              missedByMicroseconds: missed.toString()
            }
          })
        : AuditCheckpointPayloadSchema.parse({ ...base, schema: "boardagent.audit.checkpoint.v1" });
    const canonicalManifest = canonicalJson(payload);
    const manifestSha256 = canonicalSha256(payload);
    const signed = await effects.sign(payload);
    effects.signal?.throwIfAborted();
    const valid =
      signed.payload.schema === "boardagent.audit.recovery-checkpoint.v1"
        ? verifyRecoveryCheckpoint(signed, publicKey)
        : verifyCheckpoint(signed as SignedAuditCheckpoint, publicKey);
    if (!valid || canonicalJson(signed.payload) !== canonicalManifest)
      throw new AuditRecoveryTransactionError(
        "recovery_signature_invalid",
        "the recovery signer did not sign the exact checkpoint with the registered key"
      );
    const signature = Buffer.from(signed.signatureBase64Url, "base64url");
    if (signature.length !== 64 || signature.toString("base64url") !== signed.signatureBase64Url)
      throw new AuditRecoveryTransactionError(
        "recovery_signature_invalid",
        "the recovery signature encoding is invalid"
      );
    await client.query(
      `insert into public.audit_checkpoints(id,organization_id,first_sequence,last_sequence,first_event_sha256,last_event_sha256,
      canonical_manifest,manifest_sha256,signature,signing_key_id,created_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::timestamptz)`,
      [
        payload.checkpointId,
        payload.organizationId,
        payload.firstSequence,
        payload.lastSequence,
        Buffer.from(payload.firstEventSha256, "hex"),
        Buffer.from(payload.lastEventSha256, "hex"),
        Buffer.from(canonicalManifest),
        Buffer.from(manifestSha256, "hex"),
        signature,
        payload.signingKeyId,
        payload.issuedAt
      ]
    );
    await appendAuditEventsInTransaction(client, [
      {
        organizationId: request.organizationId,
        event: {
          eventId: UuidV7Schema.parse(effects.createId()),
          eventType: "audit_checkpoint_signed",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "audit_checkpoint",
          entityId: payload.checkpointId,
          boardId: null,
          origin: "cli",
          schemaVersion: 1,
          details: {
            manifestSha256,
            firstSequence: payload.firstSequence,
            lastSequence: payload.lastSequence,
            signedHeadSha256: payload.lastEventSha256,
            signingKeyId: payload.signingKeyId
          }
        }
      }
    ]);
  }
  if (!completed)
    throw new AuditRecoveryTransactionError(
      "recovery_invalid",
      "recovery exceeded its bounded segment count"
    );
  effects.signal?.throwIfAborted();
  await client.query("insert into public.audit_recovery_completions(recovery_id) values($1)", [
    request.recoveryId
  ]);
  const after = await verifyPersistedAuditEvidence(client);
  if (
    !after.valid ||
    !after.ready ||
    !after.warnings.includes(`recovery:${request.recoveryId}:historical_checkpoint_deadline_missed`)
  )
    throw new AuditRecoveryTransactionError(
      "recovery_integrity_invalid",
      "completed recovery did not pass verification; the attempt must roll back"
    );
  effects.signal?.throwIfAborted();
  return recoveryReceipt(client, request.recoveryId, false);
}

/** Inspect an immutable completed receipt without signing or modifying evidence. */
export async function readAuditRecoveryReceiptInTransaction(
  client: PoolClient,
  rawInput: {
    readonly recoveryId: string;
    readonly instanceId: string;
    readonly organizationId: string;
  }
): Promise<AppliedAuditRecovery> {
  const input = z
    .object({ recoveryId: UuidV7Schema, instanceId: UuidV7Schema, organizationId: UuidV7Schema })
    .strict()
    .parse(rawInput);
  const target = await client.query<{ instance_id: string; organization_id: string }>(
    "select instance_id,organization_id from public.system_instance where singleton_key"
  );
  if (
    target.rows.length !== 1 ||
    target.rows[0]?.instance_id !== input.instanceId ||
    target.rows[0]?.organization_id !== input.organizationId
  ) {
    throw new AuditRecoveryTransactionError(
      "recovery_target_mismatch",
      "recovery target does not match the installation record"
    );
  }
  return recoveryReceipt(client, input.recoveryId, true);
}
