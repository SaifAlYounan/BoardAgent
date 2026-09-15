import type { PoolClient } from "pg";
import { z } from "zod";

import { Sha256HexSchema, UuidV7Schema } from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";

const TransportSchema = z.enum(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
export const EnrollmentProofingMethodSchema = z.enum(["in_person", "verified_number_call"]);
export type EnrollmentProofingMethod = z.infer<typeof EnrollmentProofingMethodSchema>;

const EnrollmentSeatSchema = z
  .object({
    boardId: UuidV7Schema,
    boardName: z.string().min(1).max(512),
    seatRole: z.enum(["voting_member", "management", "observer"])
  })
  .strict();

export interface BuiltinEnrollmentCandidate {
  readonly invitationId: string;
  readonly memberId: string;
  readonly organizationDisplayName: string;
  readonly memberDisplayName: string;
  readonly handoffMethod: string;
  readonly seats: readonly z.infer<typeof EnrollmentSeatSchema>[];
}

interface LookupRow {
  readonly result_status: "available" | "unavailable";
  readonly result_invitation_id: string | null;
  readonly result_member_id: string | null;
  readonly result_organization_display_name: string | null;
  readonly result_member_display_name: string | null;
  readonly result_handoff_method: string | null;
  readonly result_seats: unknown;
}

export async function lookupBuiltinEnrollmentInTransaction(
  client: PoolClient,
  input: { readonly organizationId: string; readonly invitationTokenSha256: string }
): Promise<BuiltinEnrollmentCandidate | null> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const invitationTokenSha256 = Sha256HexSchema.parse(input.invitationTokenSha256);
  const result = await client.query<LookupRow>(
    `select result_status,result_invitation_id,result_member_id,
            result_organization_display_name,result_member_display_name,
            result_handoff_method,result_seats
       from boardagent_lookup_builtin_enrollment($1,$2)`,
    [organizationId, Buffer.from(invitationTokenSha256, "hex")]
  );
  const row = result.rows[0];
  if (!row || row.result_status === "unavailable") return null;
  if (
    row.result_invitation_id === null ||
    row.result_member_id === null ||
    row.result_organization_display_name === null ||
    row.result_member_display_name === null ||
    row.result_handoff_method === null
  ) {
    throw new Error("builtin enrollment lookup returned an invalid available projection");
  }
  return {
    invitationId: UuidV7Schema.parse(row.result_invitation_id),
    memberId: UuidV7Schema.parse(row.result_member_id),
    organizationDisplayName: z.string().min(1).max(512).parse(row.result_organization_display_name),
    memberDisplayName: z.string().min(1).max(512).parse(row.result_member_display_name),
    handoffMethod: z.string().min(1).max(512).parse(row.result_handoff_method),
    seats: z.array(EnrollmentSeatSchema).min(1).max(25).parse(row.result_seats)
  };
}

export const CompleteBuiltinEnrollmentInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    invitationTokenSha256: Sha256HexSchema,
    webauthnChallengeId: UuidV7Schema,
    expectedChallengeSha256: Sha256HexSchema,
    credentialId: UuidV7Schema,
    rawCredentialId: z
      .instanceof(Buffer)
      .refine((value) => value.length >= 16 && value.length <= 1024),
    publicKey: z.instanceof(Buffer).refine((value) => value.length >= 32 && value.length <= 4096),
    signatureCounter: z.number().int().min(0).max(4_294_967_295),
    transports: z
      .array(TransportSchema)
      .max(16)
      .refine((value) => new Set(value).size === value.length),
    backupEligible: z.boolean(),
    backupState: z.boolean(),
    activationChallengeId: UuidV7Schema,
    activationCodeSha256: Sha256HexSchema,
    proofingMethod: EnrollmentProofingMethodSchema,
    auditEventId: UuidV7Schema
  })
  .strict()
  .refine((value) => value.backupEligible || !value.backupState, {
    message: "single-device credentials cannot be backed up"
  });
export type CompleteBuiltinEnrollmentInput = z.input<typeof CompleteBuiltinEnrollmentInputSchema>;

interface PreparationRow {
  readonly result_status: "ready" | "unavailable";
  readonly result_invitation_id: string | null;
  readonly result_member_row_version: string | null;
  readonly result_issued_by: string | null;
  readonly result_handoff_method: string | null;
  readonly result_rp_id: string | null;
  readonly result_exact_origin: string | null;
}

interface FinalizationRow {
  readonly result_status: "completed" | "unavailable";
  readonly result_invitation_id: string | null;
  readonly result_member_row_version: string | null;
}

export type CompleteBuiltinEnrollmentResult =
  | { readonly completed: false }
  | {
      readonly completed: true;
      readonly invitationId: string;
      readonly memberRowVersion: string;
      readonly auditEventId: string;
      readonly auditSequence: string;
    };

function parameters(
  input: z.output<typeof CompleteBuiltinEnrollmentInputSchema>
): readonly unknown[] {
  return [
    input.organizationId,
    input.memberId,
    Buffer.from(input.invitationTokenSha256, "hex"),
    input.webauthnChallengeId,
    Buffer.from(input.expectedChallengeSha256, "hex"),
    input.credentialId,
    input.rawCredentialId,
    input.publicKey,
    input.signatureCounter,
    input.transports,
    input.backupEligible,
    input.backupState,
    input.activationChallengeId,
    Buffer.from(input.activationCodeSha256, "hex"),
    input.proofingMethod
  ];
}

export async function completeBuiltinEnrollmentInTransaction(
  client: PoolClient,
  rawInput: CompleteBuiltinEnrollmentInput
): Promise<CompleteBuiltinEnrollmentResult> {
  const input = CompleteBuiltinEnrollmentInputSchema.parse(rawInput);
  const prepared = await client.query<PreparationRow>(
    `select result_status,result_invitation_id,result_member_row_version::text,
            result_issued_by,result_handoff_method,result_rp_id,result_exact_origin
       from boardagent_prepare_builtin_enrollment_redemption(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text[],$11,$12,$13,$14,$15
       )`,
    [...parameters(input)]
  );
  const preparation = prepared.rows[0];
  if (!preparation || preparation.result_status === "unavailable") {
    return { completed: false };
  }
  if (
    preparation.result_invitation_id === null ||
    preparation.result_member_row_version === null ||
    preparation.result_issued_by === null ||
    preparation.result_handoff_method === null ||
    preparation.result_rp_id === null ||
    preparation.result_exact_origin === null
  ) {
    throw new Error("builtin enrollment preparation returned an invalid ready projection");
  }

  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.auditEventId,
        eventType: "enrollment_redeemed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "enrollment_invitation",
        entityId: preparation.result_invitation_id,
        boardId: null,
        origin: "browser",
        details: {
          memberId: input.memberId,
          invitationId: preparation.result_invitation_id,
          issuedBy: preparation.result_issued_by,
          handoffMethod: preparation.result_handoff_method,
          credentialId: input.credentialId,
          activationChallengeId: input.activationChallengeId,
          proofingMethod: input.proofingMethod,
          rpId: preparation.result_rp_id,
          exactOrigin: preparation.result_exact_origin,
          passkeyUserVerified: true
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("builtin enrollment redemption did not append its audit event");

  const finalized = await client.query<FinalizationRow>(
    `select result_status,result_invitation_id,result_member_row_version::text
       from boardagent_finalize_builtin_enrollment_redemption(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text[],$11,$12,$13,$14,$15,$16
       )`,
    [...parameters(input), input.auditEventId]
  );
  const finalization = finalized.rows[0];
  if (
    !finalization ||
    finalization.result_status !== "completed" ||
    finalization.result_invitation_id !== preparation.result_invitation_id ||
    finalization.result_member_row_version === null
  ) {
    throw new Error("builtin enrollment finalization returned an invalid projection");
  }
  return {
    completed: true,
    invitationId: finalization.result_invitation_id,
    memberRowVersion: finalization.result_member_row_version,
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}
