import type { PoolClient } from "pg";
import { z } from "zod";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  safeHashEqual,
  toolInputSchema,
  type JsonValue
} from "@boardagent/contracts";

import type { AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const IssueEnrollmentArgumentsSchema = toolInputSchema("issue_enrollment") as z.ZodType<{
  readonly schema_version: "boardagent.tool-input.v1";
  readonly member_id: string;
  readonly handoff_method: "operator_display" | "operator_qr";
  readonly expires_in_seconds: number;
  readonly idempotency_key: string;
}>;

const EnrollmentSeatSchema = z
  .object({
    boardId: UuidV7Schema,
    boardName: z.string().min(1).max(512),
    seatRole: z.enum(["voting_member", "management", "observer"]),
    isSecretary: z.boolean(),
    votingWeight: z.string().regex(/^\d+$/u),
    entitlementGeneration: z.string().regex(/^[1-9]\d*$/u)
  })
  .strict();

export interface PreparedEnrollmentIssuance {
  readonly memberId: string;
  readonly memberDisplayName: string;
  readonly memberKind: "human" | "ai_system";
  readonly memberState: "invited";
  readonly memberRowVersion: string;
  readonly seats: readonly z.infer<typeof EnrollmentSeatSchema>[];
  readonly requestSha256: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
}

interface PreparationRow {
  readonly result_status: "ready" | "unavailable";
  readonly result_member_display_name: string | null;
  readonly result_member_kind: "human" | "ai_system" | null;
  readonly result_member_state: "invited" | null;
  readonly result_member_row_version: string | null;
  readonly result_seats: unknown;
}

interface FinalizationRow {
  readonly result_status: "issued" | "replayed" | "unavailable" | "idempotency_conflict";
  readonly result_invitation_id: string | null;
  readonly result_expires_at: string | null;
  readonly result_safe_response_sha256: Buffer | null;
}

export class EnrollmentAdministrationError extends Error {
  public constructor(
    public readonly code:
      | "enrollment_issuance_unavailable"
      | "enrollment_idempotency_conflict"
      | "enrollment_safe_response_invalid"
      | "activation_restart_unavailable",
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "EnrollmentAdministrationError";
  }
}

export async function prepareEnrollmentIssuanceInTransaction(
  client: PoolClient,
  rawArguments: unknown
): Promise<PreparedEnrollmentIssuance> {
  const request = IssueEnrollmentArgumentsSchema.parse(rawArguments);
  const result = await client.query<PreparationRow>(
    `select result_status,result_member_display_name,result_member_kind,
            result_member_state,result_member_row_version::text,result_seats
       from boardagent_prepare_enrollment_issuance($1)`,
    [request.member_id]
  );
  const row = result.rows[0];
  if (!row || row.result_status !== "ready") {
    throw new EnrollmentAdministrationError(
      "enrollment_issuance_unavailable",
      "enrollment issuance is unavailable"
    );
  }
  if (
    row.result_member_display_name === null ||
    row.result_member_kind === null ||
    row.result_member_state !== "invited" ||
    row.result_member_row_version === null
  ) {
    throw new Error("enrollment issuance preparation returned an invalid ready projection");
  }
  const seats = z.array(EnrollmentSeatSchema).min(1).max(25).parse(row.result_seats);
  const requestSha256 = canonicalSha256(request);
  const canonicalPayload = {
    schemaVersion: "boardagent.enrollment-issuance.v1",
    request,
    member: {
      memberId: request.member_id,
      memberDisplayName: row.result_member_display_name,
      memberKind: row.result_member_kind,
      memberState: row.result_member_state,
      memberRowVersion: row.result_member_row_version
    },
    seats
  } satisfies JsonValue;
  return {
    memberId: request.member_id,
    memberDisplayName: row.result_member_display_name,
    memberKind: row.result_member_kind,
    memberState: row.result_member_state,
    memberRowVersion: row.result_member_row_version,
    seats,
    requestSha256,
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload)
  };
}

export interface IssueEnrollmentInput {
  readonly originalArguments: unknown;
  readonly expectedPayloadSha256: string;
  readonly invitationId: string;
  /** SHA-256 of the 256-bit secret. The raw secret must never cross this boundary. */
  readonly invitationTokenSha256: string;
  readonly idempotencyRecordId: string;
  readonly consentRecordId: string;
  readonly auditEventId: string;
}

export interface IssueEnrollmentResult {
  readonly replayed: boolean;
  readonly invitationId: string;
  readonly memberId: string;
  readonly expiresAt: string;
  readonly safeResponseSha256: string;
  readonly auditEvent: AuditAppendInput | null;
}

export async function issueEnrollmentInTransaction(
  client: PoolClient,
  rawInput: IssueEnrollmentInput
): Promise<IssueEnrollmentResult> {
  const request = IssueEnrollmentArgumentsSchema.parse(rawInput.originalArguments);
  const expectedPayloadSha256 = Sha256HexSchema.parse(rawInput.expectedPayloadSha256);
  const invitationId = UuidV7Schema.parse(rawInput.invitationId);
  const invitationTokenSha256 = Sha256HexSchema.parse(rawInput.invitationTokenSha256);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const consentRecordId = UuidV7Schema.parse(rawInput.consentRecordId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const prepared = await prepareEnrollmentIssuanceInTransaction(client, request);
  if (!safeHashEqual(prepared.payloadSha256, expectedPayloadSha256)) {
    throw new EnrollmentAdministrationError(
      "enrollment_issuance_unavailable",
      "enrollment issuance canonical payload changed"
    );
  }
  const context = await readRequestContext(client);
  const proposedSafeResponseSha256 = canonicalSha256({
    schemaVersion: "boardagent.enrollment-safe-response.v1",
    invitationId,
    memberId: request.member_id
  });
  const finalized = await client.query<FinalizationRow>(
    `select result_status,result_invitation_id,result_expires_at,
            result_safe_response_sha256
       from boardagent_finalize_enrollment_issuance(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
       )`,
    [
      request.member_id,
      request.handoff_method,
      request.expires_in_seconds,
      request.idempotency_key,
      Buffer.from(prepared.requestSha256, "hex"),
      Buffer.from(prepared.payloadSha256, "hex"),
      consentRecordId,
      invitationId,
      Buffer.from(invitationTokenSha256, "hex"),
      idempotencyRecordId,
      Buffer.from(proposedSafeResponseSha256, "hex")
    ]
  );
  const row = finalized.rows[0];
  if (!row || row.result_status === "unavailable") {
    throw new EnrollmentAdministrationError(
      "enrollment_issuance_unavailable",
      "enrollment issuance is unavailable"
    );
  }
  if (row.result_status === "idempotency_conflict") {
    throw new EnrollmentAdministrationError(
      "enrollment_idempotency_conflict",
      "enrollment idempotency key was already used for another request"
    );
  }
  if (
    row.result_invitation_id === null ||
    row.result_expires_at === null ||
    row.result_safe_response_sha256 === null
  ) {
    throw new Error("enrollment issuance finalization returned an invalid projection");
  }
  const resultInvitationId = UuidV7Schema.parse(row.result_invitation_id);
  const safeResponseSha256 = Sha256HexSchema.parse(row.result_safe_response_sha256.toString("hex"));
  const expectedSafeResponseSha256 = canonicalSha256({
    schemaVersion: "boardagent.enrollment-safe-response.v1",
    invitationId: resultInvitationId,
    memberId: request.member_id
  });
  if (!safeHashEqual(safeResponseSha256, expectedSafeResponseSha256)) {
    throw new EnrollmentAdministrationError(
      "enrollment_safe_response_invalid",
      "enrollment safe response evidence is invalid"
    );
  }
  if (row.result_status === "replayed") {
    return {
      replayed: true,
      invitationId: resultInvitationId,
      memberId: request.member_id,
      expiresAt: row.result_expires_at,
      safeResponseSha256,
      auditEvent: null
    };
  }
  if (resultInvitationId !== invitationId) {
    throw new Error("enrollment issuance returned a different invitation identifier");
  }
  return {
    replayed: false,
    invitationId: resultInvitationId,
    memberId: request.member_id,
    expiresAt: row.result_expires_at,
    safeResponseSha256,
    auditEvent: {
      organizationId: context.organizationId,
      consentRecordId,
      event: {
        eventId: auditEventId,
        eventType: "enrollment_issued",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "enrollment_invitation",
        entityId: resultInvitationId,
        boardId: null,
        origin: "mcp",
        details: {
          memberId: request.member_id,
          memberDisplayName: prepared.memberDisplayName,
          handoffMethod: request.handoff_method,
          expiresInSeconds: request.expires_in_seconds,
          expiresAt: row.result_expires_at,
          seatBoardIds: prepared.seats.map(({ boardId }) => boardId),
          oneTimeSecret: true
        },
        schemaVersion: 1
      }
    }
  };
}
