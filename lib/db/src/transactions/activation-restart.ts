import type { PoolClient } from "pg";
import { z } from "zod";

import type { AuditEvent } from "@boardagent/audit";
import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  safeHashEqual,
  toolInputSchema,
  type JsonValue
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import { EnrollmentAdministrationError } from "./enrollment-administration.js";
import { readRequestContext } from "./request-context.js";

/*
 * Pending-activation restart (docs/decisions/activation-restart-proposal-2026-09-13.md).
 * SQL 0170 owns every eligibility rule; this module binds the tool arguments, the
 * canonical confirmation payload and the audit evidence around those functions. The raw
 * restart token and the raw activation code never reach this boundary: callers pass
 * SHA-256 hex only, and audit details carry identifiers alone.
 */

const ReissueActivationArgumentsSchema = toolInputSchema("reissue_activation") as z.ZodType<{
  readonly schema_version: "boardagent.tool-input.v1";
  readonly member_id: string;
  readonly challenge_id: string;
  readonly proofing_method: string;
  readonly idempotency_key: string;
}>;

export const ActivationRestartProofingMethodSchema = z.enum(["in_person", "verified_number_call"]);
export type ActivationRestartProofingMethod = z.infer<typeof ActivationRestartProofingMethodSchema>;

const ActivationRestartSeatSchema = z
  .object({
    board_id: UuidV7Schema,
    board_name: z.string().min(1).max(512),
    seat_role: z.enum(["voting_member", "management", "observer"]),
    is_secretary: z.boolean(),
    voting_weight: z.string().regex(/^\d+$/u)
  })
  .strict();

const PreparationSchema = z.discriminatedUnion("result_status", [
  z.object({ result_status: z.literal("unavailable") }).strict(),
  z
    .object({
      result_status: z.literal("ready"),
      member_id: UuidV7Schema,
      member_display_name: z.string().min(1).max(512),
      member_state: z.literal("pending_activation"),
      member_row_version: z.string().regex(/^[1-9][0-9]*$/u),
      stale_challenge_id: UuidV7Schema,
      stale_challenge_state: z.enum(["issued", "expired"]),
      stale_expires_at: Rfc3339UtcSchema,
      attempt_count: z.number().int().min(0).max(20),
      proofing_method: ActivationRestartProofingMethodSchema,
      invitation_id: UuidV7Schema,
      seats: z.array(ActivationRestartSeatSchema).min(1).max(25)
    })
    .strict()
]);

export interface ActivationRestartSeat {
  readonly boardId: string;
  readonly boardName: string;
  readonly seatRole: "voting_member" | "management" | "observer";
  readonly isSecretary: boolean;
  readonly votingWeight: string;
}

export interface PreparedActivationRestart {
  readonly memberId: string;
  readonly memberDisplayName: string;
  readonly staleChallengeId: string;
  readonly staleChallengeState: "issued" | "expired";
  readonly staleExpiresAt: string;
  readonly attemptCount: number;
  readonly proofingMethod: ActivationRestartProofingMethod;
  readonly seats: readonly ActivationRestartSeat[];
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
}

function unavailable(message: string): EnrollmentAdministrationError {
  return new EnrollmentAdministrationError("activation_restart_unavailable", message);
}

function refusedByDatabase(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error.code === "42501" || error.code === "22023" || error.code === "23514")
  );
}

/**
 * Read-only prepare half of `reissue_activation`. Locks invitation, member and challenges
 * (the ordinary activation lock order) and projects the exact payload the issuer confirms.
 * Refuses with `activation_restart_unavailable` unless the caller may issue for this
 * member and the member is stuck: pending activation, passkey registered, latest code
 * expired or exhausted, never consumed, no live handoff.
 */
export async function prepareActivationRestartInTransaction(
  client: PoolClient,
  rawArguments: JsonValue
): Promise<PreparedActivationRestart> {
  const request = ReissueActivationArgumentsSchema.parse(rawArguments);
  const proofingMethod = ActivationRestartProofingMethodSchema.safeParse(request.proofing_method);
  if (!proofingMethod.success) throw unavailable("activation restart proofing method is unknown");
  const result = await client.query<{ readonly candidate: unknown }>(
    "select boardagent_prepare_activation_restart($1,$2,$3) as candidate",
    [request.member_id, request.challenge_id, proofingMethod.data]
  );
  const candidate = PreparationSchema.parse(result.rows[0]?.candidate);
  if (candidate.result_status !== "ready") throw unavailable("activation restart is unavailable");
  if (
    candidate.member_id !== request.member_id ||
    candidate.stale_challenge_id !== request.challenge_id ||
    candidate.proofing_method !== proofingMethod.data
  ) {
    throw new Error("activation restart preparation returned a different target");
  }
  const seats = candidate.seats.map((seat) => ({
    boardId: seat.board_id,
    boardName: seat.board_name,
    seatRole: seat.seat_role,
    isSecretary: seat.is_secretary,
    votingWeight: seat.voting_weight
  }));
  // Key for key what SQL0170 boardagent_activation_restart_payload rebuilds at commit.
  const canonicalPayload = {
    schemaVersion: "boardagent.activation-restart.v1",
    request,
    member: {
      memberId: candidate.member_id,
      memberDisplayName: candidate.member_display_name,
      memberState: candidate.member_state,
      memberRowVersion: candidate.member_row_version
    },
    staleChallenge: {
      challengeId: candidate.stale_challenge_id,
      state: candidate.stale_challenge_state,
      expiresAt: candidate.stale_expires_at,
      attemptCount: candidate.attempt_count,
      proofingMethod: candidate.proofing_method,
      invitationId: candidate.invitation_id
    },
    seats
  } satisfies JsonValue;
  return {
    memberId: candidate.member_id,
    memberDisplayName: candidate.member_display_name,
    staleChallengeId: candidate.stale_challenge_id,
    staleChallengeState: candidate.stale_challenge_state,
    staleExpiresAt: candidate.stale_expires_at,
    attemptCount: candidate.attempt_count,
    proofingMethod: candidate.proofing_method,
    seats,
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload)
  };
}

export interface IssueActivationRestartInput {
  readonly originalArguments: JsonValue;
  readonly expectedPayloadSha256: string;
  readonly grantId: string;
  /** SHA-256 of the 256-bit restart token. The raw token must never cross this boundary. */
  readonly tokenSha256: string;
  readonly consentRecordId: string;
  readonly auditEventId: string;
}

export const IssueActivationRestartInputSchema = z
  .object({
    originalArguments: z.unknown(),
    expectedPayloadSha256: Sha256HexSchema,
    grantId: UuidV7Schema,
    tokenSha256: Sha256HexSchema,
    consentRecordId: UuidV7Schema,
    auditEventId: UuidV7Schema
  })
  .strict();

export interface IssuedActivationRestart {
  readonly grantId: string;
  readonly staleChallengeId: string;
  readonly memberDisplayName: string;
  readonly expiresAt: string;
  /**
   * Always null: the `activation_restart_issued` event is appended INSIDE this call,
   * because the SQL commit half verifies that exact row before it records the grant. A
   * caller feeding `confirmStagedActionInTransaction` must therefore pass no further
   * event for it; the appended record is `appendedAuditEvent`.
   */
  readonly auditEvent: AuditAppendInput | null;
  readonly appendedAuditEvent: AuditEvent;
}

const IssuanceResultSchema = z
  .object({
    grantId: UuidV7Schema,
    staleChallengeId: UuidV7Schema,
    memberDisplayName: z.string().min(1).max(512),
    expiresAt: Rfc3339UtcSchema
  })
  .strict();

async function transactionExpiry(client: PoolClient): Promise<string> {
  const result = await client.query<{ readonly expires_at: string }>(
    `select to_char((transaction_timestamp()+interval '10 minutes') at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at`
  );
  const expiresAt = result.rows[0]?.expires_at;
  if (!expiresAt) throw new Error("transaction expiry is unavailable");
  return Rfc3339UtcSchema.parse(expiresAt);
}

/**
 * Commit half of `reissue_activation`, inside the confirming request transaction: re-runs
 * the prepare projection, appends the issuance audit, then lets SQL0170 verify the fresh
 * consent and that audit before it revokes the stale challenge and records the grant.
 */
export async function issueActivationRestartInTransaction(
  client: PoolClient,
  rawInput: IssueActivationRestartInput
): Promise<IssuedActivationRestart> {
  const input = IssueActivationRestartInputSchema.parse(rawInput);
  const request = ReissueActivationArgumentsSchema.parse(input.originalArguments);
  const prepared = await prepareActivationRestartInTransaction(client, request);
  if (!safeHashEqual(prepared.payloadSha256, input.expectedPayloadSha256)) {
    throw unavailable("activation restart canonical payload changed");
  }
  const context = await readRequestContext(client);
  const expiresAt = await transactionExpiry(client);
  const [appendedAuditEvent] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: context.organizationId,
      consentRecordId: input.consentRecordId,
      event: {
        eventId: input.auditEventId,
        eventType: "activation_restart_issued",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "activation_restart_grant",
        entityId: input.grantId,
        boardId: null,
        origin: "mcp",
        details: {
          memberId: prepared.memberId,
          staleChallengeId: prepared.staleChallengeId,
          grantId: input.grantId,
          proofingMethod: prepared.proofingMethod,
          expiresAt
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!appendedAuditEvent) throw new Error("activation restart issuance audit was not appended");
  let issued: unknown;
  try {
    const result = await client.query<{ readonly issued: unknown }>(
      "select boardagent_issue_activation_restart($1::jsonb,$2,$3,$4,$5,$6) as issued",
      [
        request,
        Buffer.from(input.expectedPayloadSha256, "hex"),
        input.grantId,
        Buffer.from(input.tokenSha256, "hex"),
        input.consentRecordId,
        input.auditEventId
      ]
    );
    issued = result.rows[0]?.issued;
  } catch (error) {
    if (refusedByDatabase(error)) {
      throw new EnrollmentAdministrationError(
        "activation_restart_unavailable",
        error instanceof Error ? error.message : "activation restart is unavailable",
        { cause: error }
      );
    }
    throw error;
  }
  const row = IssuanceResultSchema.parse(issued);
  if (
    row.grantId !== input.grantId ||
    row.staleChallengeId !== prepared.staleChallengeId ||
    row.expiresAt !== expiresAt
  ) {
    throw new Error("activation restart issuance returned a different grant");
  }
  return {
    grantId: row.grantId,
    staleChallengeId: row.staleChallengeId,
    memberDisplayName: row.memberDisplayName,
    expiresAt: row.expiresAt,
    auditEvent: null,
    appendedAuditEvent
  };
}

const LookupSchema = z
  .object({
    grantId: UuidV7Schema,
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    memberDisplayName: z.string().min(1).max(512),
    organizationDisplayName: z.string().min(1).max(512),
    proofingMethod: ActivationRestartProofingMethodSchema,
    staleChallengeId: UuidV7Schema,
    expiresAt: Rfc3339UtcSchema
  })
  .strict();

export interface ActivationRestartCandidate {
  readonly grantId: string;
  readonly organizationId: string;
  readonly memberId: string;
  readonly memberDisplayName: string;
  readonly organizationDisplayName: string;
  readonly proofingMethod: ActivationRestartProofingMethod;
  readonly expiresAt: string;
}

async function lookupCandidate(
  client: PoolClient,
  tokenSha256: string
): Promise<z.infer<typeof LookupSchema> | null> {
  const result = await client.query<{ readonly candidate: unknown }>(
    "select boardagent_lookup_activation_restart($1) as candidate",
    [Buffer.from(Sha256HexSchema.parse(tokenSha256), "hex")]
  );
  const candidate = result.rows[0]?.candidate;
  if (candidate === null || candidate === undefined) return null;
  return LookupSchema.parse(candidate);
}

/** Identity scope: the live, unconsumed handoff of a person still pending activation, or null. */
export async function lookupActivationRestartInTransaction(
  client: PoolClient,
  input: { readonly tokenSha256: string }
): Promise<ActivationRestartCandidate | null> {
  const candidate = await lookupCandidate(client, input.tokenSha256);
  if (!candidate) return null;
  return {
    grantId: candidate.grantId,
    organizationId: candidate.organizationId,
    memberId: candidate.memberId,
    memberDisplayName: candidate.memberDisplayName,
    organizationDisplayName: candidate.organizationDisplayName,
    proofingMethod: candidate.proofingMethod,
    expiresAt: candidate.expiresAt
  };
}

export const CompleteActivationRestartInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    grantId: UuidV7Schema,
    tokenSha256: Sha256HexSchema,
    freshChallengeId: UuidV7Schema,
    /** SHA-256 of the fresh human activation code. The raw code must never cross this boundary. */
    activationCodeSha256: Sha256HexSchema,
    auditEventId: UuidV7Schema,
    webauthnChallengeId: UuidV7Schema,
    webauthnCredentialId: UuidV7Schema
  })
  .strict();
export type CompleteActivationRestartInput = z.input<typeof CompleteActivationRestartInputSchema>;

export interface CompletedActivationRestart {
  readonly completed: boolean;
  readonly activationChallengeId?: string;
  readonly invitationId?: string;
}

const CompletionResultSchema = z
  .object({
    activationChallengeId: UuidV7Schema,
    memberId: UuidV7Schema,
    invitationId: UuidV7Schema,
    expiresInSeconds: z.literal(600),
    expiresAt: Rfc3339UtcSchema
  })
  .strict();

/**
 * Identity scope, inside the WebAuthn store's authentication commit AFTER it marked the
 * restart assertion challenge consumed. Appends the completion audit and lets SQL0170
 * mint the fresh ten-minute challenge and consume the handoff. Refusals roll back to a
 * savepoint and report `{completed:false}` so the store decides the outcome.
 */
export async function completeActivationRestartInTransaction(
  client: PoolClient,
  rawInput: CompleteActivationRestartInput
): Promise<CompletedActivationRestart> {
  const input = CompleteActivationRestartInputSchema.parse(rawInput);
  const candidate = await lookupCandidate(client, input.tokenSha256);
  if (
    !candidate ||
    candidate.grantId !== input.grantId ||
    candidate.memberId !== input.memberId ||
    candidate.organizationId !== input.organizationId
  ) {
    return { completed: false };
  }
  await client.query("savepoint boardagent_activation_restart");
  try {
    const expiresAt = await transactionExpiry(client);
    await appendAuditEventsInTransaction(client, [
      {
        organizationId: candidate.organizationId,
        event: {
          eventId: input.auditEventId,
          eventType: "activation_restart_completed",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "activation_restart_grant",
          entityId: candidate.grantId,
          boardId: null,
          origin: "browser",
          details: {
            grantId: candidate.grantId,
            memberId: candidate.memberId,
            credentialId: input.webauthnCredentialId,
            staleChallengeId: candidate.staleChallengeId,
            freshChallengeId: input.freshChallengeId,
            proofingMethod: candidate.proofingMethod,
            passkeyUserVerified: true,
            expiresInSeconds: 600,
            expiresAt
          },
          schemaVersion: 1
        }
      }
    ]);
    const result = await client.query<{ readonly completed: unknown }>(
      "select boardagent_complete_activation_restart($1,$2,$3,$4,$5,$6) as completed",
      [
        Buffer.from(input.tokenSha256, "hex"),
        input.webauthnChallengeId,
        input.webauthnCredentialId,
        input.freshChallengeId,
        Buffer.from(input.activationCodeSha256, "hex"),
        input.auditEventId
      ]
    );
    const row = CompletionResultSchema.parse(result.rows[0]?.completed);
    if (
      row.activationChallengeId !== input.freshChallengeId ||
      row.memberId !== candidate.memberId ||
      row.expiresAt !== expiresAt
    ) {
      throw new Error("activation restart completion returned a different challenge");
    }
    await client.query("release savepoint boardagent_activation_restart");
    return {
      completed: true,
      activationChallengeId: row.activationChallengeId,
      invitationId: row.invitationId
    };
  } catch (error) {
    if (!refusedByDatabase(error)) throw error;
    await client.query("rollback to savepoint boardagent_activation_restart");
    return { completed: false };
  }
}
