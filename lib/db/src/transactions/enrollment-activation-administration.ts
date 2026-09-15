import type { PoolClient } from "pg";
import { z } from "zod";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  sha256Hex,
  toolInputSchema,
  type JsonValue
} from "@boardagent/contracts";

import type { AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const ActivationArgumentsSchema = toolInputSchema("confirm_enrollment_activation") as z.ZodType<{
  readonly schema_version: "boardagent.tool-input.v1";
  readonly member_id: string;
  readonly invitation_id: string;
  readonly challenge_id: string;
  readonly confirmation_code: string;
  readonly proofing_method: string;
  readonly idempotency_key: string;
}>;

const ProofingMethodSchema = z.enum(["in_person", "verified_number_call"]);
type ProofingMethod = z.infer<typeof ProofingMethodSchema>;

const ActivationSeatSchema = z
  .object({
    boardId: UuidV7Schema,
    boardName: z.string().min(1).max(512),
    seatRole: z.enum(["voting_member", "management", "observer"]),
    isSecretary: z.boolean(),
    votingWeight: z.string().regex(/^\d+$/u),
    entitlementGeneration: z.string().regex(/^[1-9]\d*$/u)
  })
  .strict();
type ActivationSeat = z.infer<typeof ActivationSeatSchema>;

interface PreparationRow {
  readonly result_status: "ready" | "unavailable";
  readonly result_member_display_name: string | null;
  readonly result_member_state: "pending_activation" | null;
  readonly result_member_row_version: string | null;
  readonly result_challenge_expires_at: string | null;
  readonly result_seats: unknown;
}

interface PlanRow {
  readonly result_status: "activated" | "code_mismatch" | "unavailable";
  readonly result_challenge_state: "consumed" | "issued" | "revoked" | null;
  readonly result_attempt_count: number | null;
  readonly result_member_row_version: string | null;
}

interface FinalizationRow {
  readonly result_status: "activated" | "code_mismatch" | "unavailable" | "idempotency_conflict";
  readonly result_challenge_state: "consumed" | "issued" | "revoked" | null;
  readonly result_attempt_count: number | null;
  readonly result_member_row_version: string | null;
  readonly result_safe_response_sha256: Buffer | null;
}

export class EnrollmentActivationAdministrationError extends Error {
  public constructor(
    public readonly code:
      | "enrollment_activation_unavailable"
      | "enrollment_activation_idempotency_conflict"
      | "enrollment_activation_safe_response_invalid",
    message: string
  ) {
    super(message);
    this.name = "EnrollmentActivationAdministrationError";
  }
}

function argumentsAndProofing(raw: unknown): {
  readonly request: z.output<typeof ActivationArgumentsSchema>;
  readonly proofingMethod: ProofingMethod;
} {
  const request = ActivationArgumentsSchema.parse(raw);
  const proofingMethod = ProofingMethodSchema.parse(request.proofing_method);
  return { request, proofingMethod };
}

export interface PreparedEnrollmentActivation {
  readonly memberId: string;
  readonly memberDisplayName: string;
  readonly memberState: "pending_activation" | "active";
  readonly recovery?: { readonly credentialId: string; readonly credentialSha256: string };
  readonly memberRowVersion: string;
  readonly invitationId: string;
  readonly challengeId: string;
  readonly challengeExpiresAt: string;
  readonly proofingMethod: ProofingMethod;
  readonly protectedCodeSha256: string;
  readonly seats: readonly ActivationSeat[];
  readonly requestSha256: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
}

export async function prepareEnrollmentActivationInTransaction(
  client: PoolClient,
  rawArguments: unknown
): Promise<PreparedEnrollmentActivation> {
  const { request, proofingMethod } = argumentsAndProofing(rawArguments);
  const protectedCodeSha256 = sha256Hex(request.confirmation_code);
  const protectedRequest = {
    schema_version: request.schema_version,
    member_id: request.member_id,
    invitation_id: request.invitation_id,
    challenge_id: request.challenge_id,
    confirmation_code_sha256: protectedCodeSha256,
    proofing_method: proofingMethod,
    idempotency_key: request.idempotency_key
  } satisfies JsonValue;
  const recoveryResult = await client.query(
    "select boardagent_prepare_recovery_activation($1::jsonb) as payload",
    [protectedRequest]
  );
  if (recoveryResult.rows[0]?.payload) {
    const payload = z
      .object({
        schemaVersion: z.literal("boardagent.enrollment-activation.v1"),
        request: z.json(),
        member: z
          .object({
            memberId: UuidV7Schema,
            memberDisplayName: z.string().min(1).max(512),
            memberState: z.literal("active"),
            memberRowVersion: z.string().regex(/^[1-9][0-9]*$/u)
          })
          .strict(),
        challenge: z
          .object({
            invitationId: UuidV7Schema,
            challengeId: UuidV7Schema,
            expiresAt: Rfc3339UtcSchema,
            proofingMethod: ProofingMethodSchema
          })
          .strict(),
        seats: z.array(ActivationSeatSchema).max(25),
        recovery: z
          .object({ credentialId: UuidV7Schema, credentialSha256: Sha256HexSchema })
          .strict()
      })
      .strict()
      .parse(recoveryResult.rows[0].payload);
    if (
      canonicalJson(payload.request) !== canonicalJson(protectedRequest) ||
      payload.member.memberId !== request.member_id ||
      payload.challenge.invitationId !== request.invitation_id ||
      payload.challenge.challengeId !== request.challenge_id ||
      payload.challenge.proofingMethod !== proofingMethod
    ) {
      throw new Error("recovery activation preparation returned a different request");
    }
    return {
      memberId: payload.member.memberId,
      memberDisplayName: payload.member.memberDisplayName,
      memberState: "active",
      memberRowVersion: payload.member.memberRowVersion,
      invitationId: payload.challenge.invitationId,
      challengeId: payload.challenge.challengeId,
      challengeExpiresAt: payload.challenge.expiresAt,
      proofingMethod,
      protectedCodeSha256,
      seats: payload.seats,
      recovery: payload.recovery,
      requestSha256: canonicalSha256(request),
      canonicalPayload: payload,
      payloadSha256: canonicalSha256(payload)
    };
  }

  const result = await client.query<PreparationRow>(
    `select result_status,result_member_display_name,result_member_state,
            result_member_row_version::text,result_challenge_expires_at,result_seats
       from boardagent_prepare_confirmed_enrollment_activation($1,$2,$3,$4,$5)`,
    [
      request.member_id,
      request.invitation_id,
      request.challenge_id,
      Buffer.from(protectedCodeSha256, "hex"),
      proofingMethod
    ]
  );
  const row = result.rows[0];
  if (!row || row.result_status !== "ready") {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_unavailable",
      "enrollment activation is unavailable"
    );
  }
  if (
    row.result_member_display_name === null ||
    row.result_member_state !== "pending_activation" ||
    row.result_member_row_version === null ||
    row.result_challenge_expires_at === null
  ) {
    throw new Error("enrollment activation preparation returned an invalid projection");
  }
  const seats = z.array(ActivationSeatSchema).min(1).max(25).parse(row.result_seats);
  const challengeExpiresAt = Rfc3339UtcSchema.parse(row.result_challenge_expires_at);
  const canonicalPayload = {
    schemaVersion: "boardagent.enrollment-activation.v1",
    request: protectedRequest,
    member: {
      memberId: request.member_id,
      memberDisplayName: row.result_member_display_name,
      memberState: row.result_member_state,
      memberRowVersion: row.result_member_row_version
    },
    challenge: {
      invitationId: request.invitation_id,
      challengeId: request.challenge_id,
      expiresAt: challengeExpiresAt,
      proofingMethod
    },
    seats
  } satisfies JsonValue;
  return {
    memberId: request.member_id,
    memberDisplayName: row.result_member_display_name,
    memberState: row.result_member_state,
    memberRowVersion: row.result_member_row_version,
    invitationId: request.invitation_id,
    challengeId: request.challenge_id,
    challengeExpiresAt,
    proofingMethod,
    protectedCodeSha256,
    seats,
    requestSha256: canonicalSha256(request),
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload)
  };
}

const FeedIdentifierSchema = z.object({ boardId: UuidV7Schema, feedId: UuidV7Schema }).strict();

export interface PlanEnrollmentActivationInput {
  readonly originalArguments: unknown;
  readonly expectedPayloadSha256: string;
  readonly consentRecordId: string;
  readonly idempotencyRecordId: string;
  readonly auditEventId: string;
  readonly feedIds: readonly { readonly boardId: string; readonly feedId: string }[];
}

interface ActivationFeedPlan {
  readonly feedId: string;
  readonly boardId: string;
  readonly entitlementGeneration: string;
  readonly feedSequence: string;
  readonly visibility: JsonValue;
  readonly payload: JsonValue;
}

export interface EnrollmentActivationPlan extends PreparedEnrollmentActivation {
  readonly originalArguments: z.output<typeof ActivationArgumentsSchema>;
  readonly idempotencyKey: string;
  readonly consentRecordId: string;
  readonly idempotencyRecordId: string;
  readonly auditEvent: AuditAppendInput;
  readonly outcome: "activated" | "code_mismatch";
  readonly challengeState: "consumed" | "issued" | "revoked";
  readonly attemptCount: number;
  readonly resultingMemberRowVersion: string | null;
  readonly feedEntries: readonly ActivationFeedPlan[];
  readonly safeResponseSha256: string;
}

export async function planEnrollmentActivationInTransaction(
  client: PoolClient,
  rawInput: PlanEnrollmentActivationInput
): Promise<EnrollmentActivationPlan> {
  const { request } = argumentsAndProofing(rawInput.originalArguments);
  const expectedPayloadSha256 = Sha256HexSchema.parse(rawInput.expectedPayloadSha256);
  const consentRecordId = UuidV7Schema.parse(rawInput.consentRecordId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const suppliedFeedIds = z.array(FeedIdentifierSchema).max(25).parse(rawInput.feedIds);
  if (
    new Set(suppliedFeedIds.map(({ boardId }) => boardId)).size !== suppliedFeedIds.length ||
    new Set(suppliedFeedIds.map(({ feedId }) => feedId)).size !== suppliedFeedIds.length
  ) {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_unavailable",
      "activation feed identifiers must be unique"
    );
  }
  const prepared = await prepareEnrollmentActivationInTransaction(client, request);
  if (!safeHashEqual(prepared.payloadSha256, expectedPayloadSha256)) {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_unavailable",
      "enrollment activation canonical payload changed"
    );
  }
  if (
    canonicalJson(suppliedFeedIds.map(({ boardId }) => boardId).toSorted()) !==
    canonicalJson(prepared.seats.map(({ boardId }) => boardId).toSorted())
  ) {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_unavailable",
      "activation feed identifiers do not cover the exact member boards"
    );
  }
  let outcome: PlanRow | undefined;
  if (prepared.recovery) {
    const raw = await client.query(
      "select boardagent_plan_recovery_activation($1::jsonb,$2,$3) as plan",
      [
        (prepared.canonicalPayload as { request: JsonValue }).request,
        Buffer.from(prepared.payloadSha256, "hex"),
        consentRecordId
      ]
    );
    const value = z
      .object({
        outcome: z.enum(["activated", "code_mismatch"]),
        challengeState: z.enum(["consumed", "issued", "revoked"]),
        attemptCount: z.number().int().min(0).max(20),
        memberRowVersion: z
          .string()
          .regex(/^[1-9][0-9]*$/u)
          .nullable()
      })
      .strict()
      .parse(raw.rows[0]?.plan);
    outcome = {
      result_status: value.outcome,
      result_challenge_state: value.challengeState,
      result_attempt_count: value.attemptCount,
      result_member_row_version: value.memberRowVersion
    };
  } else {
    const planned = await client.query<PlanRow>(
      `select result_status,result_challenge_state,result_attempt_count,
            result_member_row_version::text
       from boardagent_plan_confirmed_enrollment_activation(
         $1,$2,$3,$4,$5,$6,$7,$8
       )`,
      [
        prepared.memberId,
        prepared.invitationId,
        prepared.challengeId,
        Buffer.from(prepared.protectedCodeSha256, "hex"),
        prepared.proofingMethod,
        request.idempotency_key,
        Buffer.from(prepared.payloadSha256, "hex"),
        consentRecordId
      ]
    );
    outcome = planned.rows[0];
  }
  if (
    !outcome ||
    (outcome.result_status !== "activated" && outcome.result_status !== "code_mismatch") ||
    outcome.result_challenge_state === null ||
    outcome.result_attempt_count === null
  ) {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_unavailable",
      "enrollment activation is unavailable"
    );
  }
  if (
    (outcome.result_status === "activated" &&
      (outcome.result_challenge_state !== "consumed" ||
        outcome.result_member_row_version === null)) ||
    (outcome.result_status === "code_mismatch" &&
      (outcome.result_challenge_state === "consumed" || outcome.result_member_row_version !== null))
  ) {
    throw new Error("enrollment activation plan returned an invalid outcome");
  }

  const context = await readRequestContext(client);
  const feedEntries: ActivationFeedPlan[] = [];
  if (outcome.result_status === "activated" && !prepared.recovery) {
    for (const seat of prepared.seats) {
      const feedId = suppliedFeedIds.find(({ boardId }) => boardId === seat.boardId)?.feedId;
      if (!feedId) throw new Error("validated activation feed identifier disappeared");
      const sequence = await client.query<{ next_sequence: string }>(
        `select (coalesce(max(feed_sequence),0)+1)::text as next_sequence
           from pending_action_feed
          where member_id=$1 and board_id=$2 and entitlement_generation=$3`,
        [prepared.memberId, seat.boardId, seat.entitlementGeneration]
      );
      const feedSequence = sequence.rows[0]?.next_sequence;
      if (!feedSequence) throw new Error("activation feed sequence is unavailable");
      feedEntries.push({
        feedId,
        boardId: seat.boardId,
        entitlementGeneration: seat.entitlementGeneration,
        feedSequence,
        visibility: {
          memberId: prepared.memberId,
          boardId: seat.boardId,
          entitlementGeneration: seat.entitlementGeneration
        },
        payload: {
          schemaVersion: "boardagent.pending-action.v1",
          actionType: "complete_onboarding",
          memberId: prepared.memberId,
          boardId: seat.boardId,
          objectType: "member",
          objectId: prepared.memberId,
          objectVersion: outcome.result_member_row_version
        }
      });
    }
  }
  const safeResponseSha256 = canonicalSha256({
    schemaVersion: "boardagent.activation-safe-response.v1",
    outcome: outcome.result_status,
    memberId: prepared.memberId,
    challengeId: prepared.challengeId,
    challengeState: outcome.result_challenge_state,
    attemptCount: outcome.result_attempt_count
  });
  const auditEvent: AuditAppendInput = prepared.recovery
    ? {
        organizationId: context.organizationId,
        consentRecordId,
        event: {
          eventId: auditEventId,
          eventType:
            outcome.result_status === "activated" ? "enrollment_redeemed" : "authorization_denied",
          actorMemberId: context.memberId,
          actorClientId: context.clientId,
          tokenJti: context.tokenJti,
          entityType: "identity_recovery",
          entityId: prepared.invitationId,
          boardId: null,
          origin: "mcp",
          details: {
            recoveryRequestId: prepared.invitationId,
            memberId: prepared.memberId,
            credentialId: prepared.recovery.credentialId,
            challengeId: prepared.challengeId,
            proofingMethod: prepared.proofingMethod,
            outcome: outcome.result_status,
            attemptCount: outcome.result_attempt_count
          },
          schemaVersion: 1
        }
      }
    : outcome.result_status === "activated"
      ? {
          organizationId: context.organizationId,
          consentRecordId,
          objectVersion: BigInt(outcome.result_member_row_version!),
          event: {
            eventId: auditEventId,
            eventType: "member_activated",
            actorMemberId: context.memberId,
            actorClientId: context.clientId,
            tokenJti: context.tokenJti,
            entityType: "member",
            entityId: prepared.memberId,
            boardId: null,
            origin: "mcp",
            details: {
              invitationId: prepared.invitationId,
              challengeId: prepared.challengeId,
              proofingMethod: prepared.proofingMethod,
              passkeyEnrolled: true,
              feedBoardCount: prepared.seats.length
            },
            schemaVersion: 1
          }
        }
      : {
          organizationId: context.organizationId,
          consentRecordId,
          event: {
            eventId: auditEventId,
            eventType: "authorization_denied",
            actorMemberId: context.memberId,
            actorClientId: context.clientId,
            tokenJti: context.tokenJti,
            entityType: "enrollment_activation",
            entityId: prepared.challengeId,
            boardId: null,
            origin: "mcp",
            details: {
              reason: "code_mismatch",
              memberId: prepared.memberId,
              invitationId: prepared.invitationId,
              attemptCount: outcome.result_attempt_count,
              challengeState: outcome.result_challenge_state
            },
            schemaVersion: 1
          }
        };
  return {
    ...prepared,
    originalArguments: request,
    idempotencyKey: request.idempotency_key,
    consentRecordId,
    idempotencyRecordId,
    auditEvent,
    outcome: outcome.result_status,
    challengeState: outcome.result_challenge_state,
    attemptCount: outcome.result_attempt_count,
    resultingMemberRowVersion: outcome.result_member_row_version,
    feedEntries,
    safeResponseSha256
  };
}

export interface FinalizeEnrollmentActivationResult {
  readonly outcome: "activated" | "code_mismatch";
  readonly challengeState: "consumed" | "issued" | "revoked";
  readonly attemptCount: number;
  readonly memberRowVersion: string | null;
  readonly safeResponseSha256: string;
}

export async function finalizeEnrollmentActivationInTransaction(
  client: PoolClient,
  plan: EnrollmentActivationPlan
): Promise<FinalizeEnrollmentActivationResult> {
  if (plan.recovery) {
    const result = await client.query(
      "select boardagent_finalize_recovery_activation($1::jsonb,$2,$3,$4,$5,$6,$7) as result",
      [
        (plan.canonicalPayload as { request: JsonValue }).request,
        Buffer.from(plan.payloadSha256, "hex"),
        plan.consentRecordId,
        plan.auditEvent.event.eventId,
        plan.idempotencyRecordId,
        Buffer.from(plan.requestSha256, "hex"),
        Buffer.from(plan.safeResponseSha256, "hex")
      ]
    );
    const value = z
      .object({
        outcome: z.enum(["activated", "code_mismatch"]),
        challengeState: z.enum(["consumed", "issued", "revoked"]),
        attemptCount: z.number().int().min(0).max(20),
        memberRowVersion: z
          .string()
          .regex(/^[1-9][0-9]*$/u)
          .nullable(),
        safeResponseSha256: Sha256HexSchema
      })
      .strict()
      .parse(result.rows[0]?.result);
    if (
      value.outcome !== plan.outcome ||
      value.challengeState !== plan.challengeState ||
      value.attemptCount !== plan.attemptCount ||
      value.memberRowVersion !== plan.resultingMemberRowVersion ||
      !safeHashEqual(value.safeResponseSha256, plan.safeResponseSha256)
    ) {
      throw new Error("recovery activation result changed during finalization");
    }
    return value;
  }
  for (const feed of plan.feedEntries) {
    await client.query(
      `insert into pending_action_feed(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         action_type,object_type,object_id,object_version,visibility_sha256,
         canonical_payload,payload_sha256,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,'complete_onboarding','member',$4,$7,$8,$9,$10,$11)`,
      [
        feed.feedId,
        plan.auditEvent.organizationId,
        feed.boardId,
        plan.memberId,
        feed.entitlementGeneration,
        feed.feedSequence,
        plan.resultingMemberRowVersion,
        Buffer.from(canonicalSha256(feed.visibility), "hex"),
        Buffer.from(canonicalJson(feed.payload), "utf8"),
        Buffer.from(canonicalSha256(feed.payload), "hex"),
        plan.auditEvent.event.eventId
      ]
    );
  }
  const result = await client.query<FinalizationRow>(
    `select result_status,result_challenge_state,result_attempt_count,
            result_member_row_version::text,result_safe_response_sha256
       from boardagent_finalize_confirmed_enrollment_activation(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::uuid[],$13
       )`,
    [
      plan.memberId,
      plan.invitationId,
      plan.challengeId,
      Buffer.from(plan.protectedCodeSha256, "hex"),
      plan.proofingMethod,
      plan.idempotencyKey,
      Buffer.from(plan.requestSha256, "hex"),
      Buffer.from(plan.payloadSha256, "hex"),
      plan.consentRecordId,
      plan.idempotencyRecordId,
      plan.auditEvent.event.eventId,
      plan.feedEntries.map(({ feedId }) => feedId),
      Buffer.from(plan.safeResponseSha256, "hex")
    ]
  );
  const row = result.rows[0];
  if (!row || row.result_status === "unavailable") {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_unavailable",
      "enrollment activation is unavailable"
    );
  }
  if (row.result_status === "idempotency_conflict") {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_idempotency_conflict",
      "activation idempotency key was already used for another request"
    );
  }
  if (
    row.result_status !== plan.outcome ||
    row.result_challenge_state !== plan.challengeState ||
    row.result_attempt_count !== plan.attemptCount ||
    row.result_member_row_version !== plan.resultingMemberRowVersion ||
    row.result_safe_response_sha256 === null
  ) {
    throw new Error("enrollment activation finalization returned an invalid projection");
  }
  const safeResponseSha256 = Sha256HexSchema.parse(row.result_safe_response_sha256.toString("hex"));
  if (!safeHashEqual(safeResponseSha256, plan.safeResponseSha256)) {
    throw new EnrollmentActivationAdministrationError(
      "enrollment_activation_safe_response_invalid",
      "activation safe response evidence is invalid"
    );
  }
  return {
    outcome: plan.outcome,
    challengeState: plan.challengeState,
    attemptCount: plan.attemptCount,
    memberRowVersion: plan.resultingMemberRowVersion,
    safeResponseSha256
  };
}
