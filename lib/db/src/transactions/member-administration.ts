import type { PoolClient } from "pg";
import { z } from "zod";

import {
  Sha256HexSchema,
  AdministrativeReasonSchema,
  AdministrativeEvidenceSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  toolInputSchema,
  type JsonValue
} from "@boardagent/contracts";

import type { AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const ManageMemberArgumentsSchema = toolInputSchema("manage_member");

const MemberInviteArgumentsSchema = z
  .object({
    schema_version: z.literal("boardagent.tool-input.v1"),
    change: z
      .object({
        operation: z.literal("invite"),
        member_id: UuidV7Schema,
        board_id: UuidV7Schema,
        member_kind: z.enum(["human", "ai_observer"]),
        seat_role: z.enum(["voting_member", "management", "observer"]),
        legal_name: z.string().min(1).max(1024),
        display_name: z.string().min(1).max(1024),
        voting_weight: z.number().int().min(0).max(1_000_000_000),
        accountable_principal_id: UuidV7Schema.nullable(),
        reason: AdministrativeReasonSchema.optional()
      })
      .strict(),
    authority_evidence: AdministrativeEvidenceSchema.optional(),
    idempotency_key: z
      .string()
      .min(16)
      .max(200)
      .regex(/^[A-Za-z0-9._~-]+$/u)
  })
  .strict();
type MemberInviteArguments = z.infer<typeof MemberInviteArgumentsSchema>;

interface PreparationRow {
  readonly result_status: "ready" | "unavailable";
  readonly result_board_name: string | null;
  readonly result_board_row_version: string | null;
  readonly result_persisted_member_kind: "human" | "ai_system" | null;
  readonly result_accountable_principal_name: string | null;
}

interface FinalizationRow {
  readonly result_status: "created" | "replayed" | "unavailable" | "idempotency_conflict";
  readonly result_member_id: string | null;
  readonly result_membership_id: string | null;
  readonly result_member_row_version: string | null;
  readonly result_safe_response_sha256: Buffer | null;
}

export class MemberAdministrationError extends Error {
  public constructor(
    public readonly code:
      | "member_invite_unavailable"
      | "member_invite_operation_required"
      | "member_idempotency_conflict"
      | "member_safe_response_invalid",
    message: string
  ) {
    super(message);
    this.name = "MemberAdministrationError";
  }
}

function inviteArguments(raw: unknown): MemberInviteArguments {
  const managed = ManageMemberArgumentsSchema.parse(raw) as {
    readonly change: { readonly operation: string };
  };
  if (managed.change.operation !== "invite") {
    throw new MemberAdministrationError(
      "member_invite_operation_required",
      "member invitation preparation requires the invite operation"
    );
  }
  return MemberInviteArgumentsSchema.parse(managed);
}

function semanticallyValid(request: MemberInviteArguments): boolean {
  const change = request.change;
  if (change.legal_name.length > 512 || change.display_name.length > 512) return false;
  if (change.member_kind === "human" && change.accountable_principal_id !== null) return false;
  if (
    change.member_kind === "ai_observer" &&
    (change.accountable_principal_id === null || change.seat_role !== "observer")
  ) {
    return false;
  }
  return change.seat_role === "voting_member"
    ? change.voting_weight >= 1
    : change.voting_weight === 0;
}

export interface PreparedMemberInvite {
  readonly administrativeAuthority: JsonValue | null;
  readonly reason: string | null;
  readonly memberId: string;
  readonly memberKind: "human" | "ai_observer";
  readonly persistedMemberKind: "human" | "ai_system";
  readonly memberLegalName: string;
  readonly memberDisplayName: string;
  readonly accountablePrincipalId: string | null;
  readonly accountablePrincipalName: string | null;
  readonly boardId: string;
  readonly boardName: string;
  readonly boardRowVersion: string;
  readonly seatRole: "voting_member" | "management" | "observer";
  readonly votingWeight: string;
  readonly requestSha256: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly authoritySnapshot: JsonValue;
  readonly authoritySnapshotSha256: string;
}

export async function prepareMemberInviteInTransaction(
  client: PoolClient,
  rawArguments: unknown
): Promise<PreparedMemberInvite> {
  const request = inviteArguments(rawArguments);
  if (!semanticallyValid(request)) {
    throw new MemberAdministrationError(
      "member_invite_unavailable",
      "member invitation is unavailable"
    );
  }
  const change = request.change;
  let administrativeAuthority: JsonValue | null;
  try {
    const authority = await client.query<{ authority: unknown }>(
      "select boardagent_member_administration_authority($1::jsonb) as authority",
      [request]
    );
    administrativeAuthority = z
      .record(z.string(), z.json())
      .nullable()
      .parse(authority.rows[0]?.authority);
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "42501") {
      throw new MemberAdministrationError(
        "member_invite_unavailable",
        "member invitation is unavailable"
      );
    }
    throw error;
  }
  const result = await client.query<PreparationRow>(
    `select result_status,result_board_name,result_board_row_version::text,
            result_persisted_member_kind,result_accountable_principal_name
       from boardagent_prepare_member_invite($1,$2,$3,$4,$5,$6)`,
    [
      change.board_id,
      change.member_id,
      change.member_kind,
      change.seat_role,
      change.voting_weight,
      change.accountable_principal_id
    ]
  );
  const row = result.rows[0];
  if (
    !row ||
    row.result_status !== "ready" ||
    row.result_board_name === null ||
    row.result_board_row_version === null ||
    row.result_persisted_member_kind === null
  ) {
    throw new MemberAdministrationError(
      "member_invite_unavailable",
      "member invitation is unavailable"
    );
  }
  const authoritySnapshot = {
    schemaVersion: "boardagent.membership-authority.v1",
    memberId: change.member_id,
    boardId: change.board_id,
    seatRole: change.seat_role,
    isSecretary: false,
    votingWeight: change.voting_weight,
    ...(administrativeAuthority === null ? {} : { administrativeAuthority })
  } satisfies JsonValue;
  const canonicalPayload = {
    schemaVersion: "boardagent.member-invite.v1",
    ...(administrativeAuthority === null ? {} : { administrativeAuthority }),
    request: z.json().parse(request),
    board: {
      boardId: change.board_id,
      boardName: row.result_board_name,
      boardState: "active",
      boardRowVersion: row.result_board_row_version
    },
    member: {
      memberId: change.member_id,
      memberKind: change.member_kind,
      persistedMemberKind: row.result_persisted_member_kind,
      legalName: change.legal_name,
      displayName: change.display_name,
      accountablePrincipalId: change.accountable_principal_id,
      accountablePrincipalName: row.result_accountable_principal_name
    },
    seat: {
      seatRole: change.seat_role,
      isSecretary: false,
      votingWeight: String(change.voting_weight)
    }
  } satisfies JsonValue;
  return {
    administrativeAuthority,
    reason: change.reason ?? null,
    memberId: change.member_id,
    memberKind: change.member_kind,
    persistedMemberKind: row.result_persisted_member_kind,
    memberLegalName: change.legal_name,
    memberDisplayName: change.display_name,
    accountablePrincipalId: change.accountable_principal_id,
    accountablePrincipalName: row.result_accountable_principal_name,
    boardId: change.board_id,
    boardName: row.result_board_name,
    boardRowVersion: row.result_board_row_version,
    seatRole: change.seat_role,
    votingWeight: String(change.voting_weight),
    requestSha256: canonicalSha256(request),
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    authoritySnapshot,
    authoritySnapshotSha256: canonicalSha256(authoritySnapshot)
  };
}

const CompletedMemberInviteSchema = z
  .object({
    memberId: UuidV7Schema,
    boardId: UuidV7Schema,
    membershipId: UuidV7Schema,
    safeResponseSha256: Sha256HexSchema
  })
  .strict();

export async function replayCompletedMemberInviteInTransaction(
  client: PoolClient,
  rawArguments: unknown,
  exactOrigin: string,
  accessTokenRecordId: string
): Promise<z.infer<typeof CompletedMemberInviteSchema> | null> {
  const request = inviteArguments(rawArguments);
  const row = await client.query<{ completed: unknown }>(
    "select boardagent_replay_member_invite($1::jsonb,$2,$3,$4) as completed",
    [
      request,
      Buffer.from(canonicalSha256(request), "hex"),
      exactOrigin,
      UuidV7Schema.parse(accessTokenRecordId)
    ]
  );
  if (row.rows[0]?.completed === null) return null;
  const completed = CompletedMemberInviteSchema.parse(row.rows[0]?.completed);
  const expectedSha256 = canonicalSha256({
    schemaVersion: "boardagent.member-safe-response.v1",
    memberId: completed.memberId,
    membershipId: completed.membershipId,
    boardId: completed.boardId
  });
  if (!safeHashEqual(completed.safeResponseSha256, expectedSha256)) {
    throw new MemberAdministrationError(
      "member_safe_response_invalid",
      "member invitation safe response evidence is invalid"
    );
  }
  return completed;
}

export interface PlanMemberInviteInput {
  readonly originalArguments: unknown;
  readonly expectedPayloadSha256: string;
  readonly consentRecordId: string;
  readonly idempotencyRecordId: string;
  readonly membershipId: string;
  readonly membershipVersionId: string;
  readonly auditEventId: string;
}

export interface MemberInvitePlan extends PreparedMemberInvite {
  readonly originalArguments: MemberInviteArguments;
  readonly consentRecordId: string;
  readonly idempotencyRecordId: string;
  readonly membershipId: string;
  readonly membershipVersionId: string;
  readonly auditEvent: AuditAppendInput;
  readonly safeResponseSha256: string;
}

export async function planMemberInviteInTransaction(
  client: PoolClient,
  rawInput: PlanMemberInviteInput
): Promise<MemberInvitePlan> {
  const originalArguments = inviteArguments(rawInput.originalArguments);
  const expectedPayloadSha256 = Sha256HexSchema.parse(rawInput.expectedPayloadSha256);
  const consentRecordId = UuidV7Schema.parse(rawInput.consentRecordId);
  const idempotencyRecordId = UuidV7Schema.parse(rawInput.idempotencyRecordId);
  const membershipId = UuidV7Schema.parse(rawInput.membershipId);
  const membershipVersionId = UuidV7Schema.parse(rawInput.membershipVersionId);
  const auditEventId = UuidV7Schema.parse(rawInput.auditEventId);
  const prepared = await prepareMemberInviteInTransaction(client, originalArguments);
  if (!safeHashEqual(prepared.payloadSha256, expectedPayloadSha256)) {
    throw new MemberAdministrationError(
      "member_invite_unavailable",
      "member invitation canonical payload changed"
    );
  }
  const context = await readRequestContext(client);
  const safeResponseSha256 = canonicalSha256({
    schemaVersion: "boardagent.member-safe-response.v1",
    memberId: prepared.memberId,
    membershipId,
    boardId: prepared.boardId
  });
  return {
    ...prepared,
    originalArguments,
    consentRecordId,
    idempotencyRecordId,
    membershipId,
    membershipVersionId,
    safeResponseSha256,
    auditEvent: {
      organizationId: context.organizationId,
      consentRecordId,
      objectVersion: 1n,
      event: {
        eventId: auditEventId,
        eventType: "member_changed",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "member",
        entityId: prepared.memberId,
        boardId: prepared.boardId,
        origin: "mcp",
        details: {
          operation: "invite",
          memberId: prepared.memberId,
          boardId: prepared.boardId,
          memberKind: prepared.memberKind,
          persistedMemberKind: prepared.persistedMemberKind,
          membershipId,
          membershipVersionId,
          seatRole: prepared.seatRole,
          isSecretary: false,
          votingWeight: prepared.votingWeight,
          accountablePrincipalId: prepared.accountablePrincipalId,
          authoritySnapshotSha256: prepared.authoritySnapshotSha256
        },
        schemaVersion: 1
      }
    }
  };
}

export interface FinalizeMemberInviteResult {
  readonly replayed: boolean;
  readonly memberId: string;
  readonly membershipId: string;
  readonly memberRowVersion: string;
  readonly safeResponseSha256: string;
}

export async function finalizeMemberInviteInTransaction(
  client: PoolClient,
  plan: MemberInvitePlan
): Promise<FinalizeMemberInviteResult> {
  const request = inviteArguments(plan.originalArguments);
  const result = await client.query<FinalizationRow>(
    `select result_status,result_member_id,result_membership_id,
            result_member_row_version::text,result_safe_response_sha256
       from boardagent_finalize_member_invite(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
       )`,
    [
      plan.boardId,
      plan.memberId,
      plan.memberKind,
      plan.memberLegalName,
      plan.memberDisplayName,
      plan.seatRole,
      Number(plan.votingWeight),
      plan.accountablePrincipalId,
      request.idempotency_key,
      Buffer.from(plan.requestSha256, "hex"),
      Buffer.from(plan.payloadSha256, "hex"),
      plan.consentRecordId,
      plan.idempotencyRecordId,
      plan.membershipId,
      plan.membershipVersionId,
      plan.auditEvent.event.eventId,
      plan.authoritySnapshot,
      Buffer.from(plan.authoritySnapshotSha256, "hex"),
      Buffer.from(plan.safeResponseSha256, "hex"),
      Buffer.from(canonicalJson(plan.authoritySnapshot), "utf8"),
      Buffer.from(
        canonicalJson({
          schemaVersion: "boardagent.member-safe-response.v1",
          memberId: plan.memberId,
          membershipId: plan.membershipId,
          boardId: plan.boardId
        }),
        "utf8"
      )
    ]
  );
  const row = result.rows[0];
  if (!row || row.result_status === "unavailable") {
    throw new MemberAdministrationError(
      "member_invite_unavailable",
      "member invitation is unavailable"
    );
  }
  if (row.result_status === "idempotency_conflict") {
    throw new MemberAdministrationError(
      "member_idempotency_conflict",
      "member idempotency key was already used for another request"
    );
  }
  if (
    row.result_member_id === null ||
    row.result_membership_id === null ||
    row.result_member_row_version === null ||
    row.result_safe_response_sha256 === null
  ) {
    throw new Error("member invitation finalization returned an invalid projection");
  }
  const memberId = UuidV7Schema.parse(row.result_member_id);
  const membershipId = UuidV7Schema.parse(row.result_membership_id);
  const safeResponseSha256 = Sha256HexSchema.parse(row.result_safe_response_sha256.toString("hex"));
  const expectedSafeResponseSha256 = canonicalSha256({
    schemaVersion: "boardagent.member-safe-response.v1",
    memberId,
    membershipId,
    boardId: plan.boardId
  });
  if (!safeHashEqual(safeResponseSha256, expectedSafeResponseSha256)) {
    throw new MemberAdministrationError(
      "member_safe_response_invalid",
      "member invitation safe response evidence is invalid"
    );
  }
  return {
    replayed: row.result_status === "replayed",
    memberId,
    membershipId,
    memberRowVersion: row.result_member_row_version,
    safeResponseSha256
  };
}
