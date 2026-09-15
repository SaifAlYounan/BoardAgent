import type { PoolClient } from "pg";
import { z } from "zod";
import {
  canonicalJson,
  canonicalSha256,
  toolInputSchema,
  UuidV7Schema,
  type JsonValue
} from "@boardagent/contracts";
import type { AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const SeatSchema = z
  .object({
    membershipId: UuidV7Schema,
    boardId: UuidV7Schema,
    seatRole: z.enum(["voting_member", "management", "observer"]),
    isSecretary: z.boolean(),
    isChair: z.boolean(),
    votingWeight: z.string().regex(/^\d+$/u),
    state: z.enum(["active", "suspended", "ended"]),
    entitlementGeneration: z.string().regex(/^[1-9]\d*$/u)
  })
  .strict();
const MemberSchema = z
  .object({
    memberId: UuidV7Schema,
    displayName: z.string(),
    organizationRoles: z.array(z.enum(["admin", "secretariat", "management"])),
    memberKind: z.enum(["human", "ai_system"]),
    state: z.enum(["active", "suspended", "removed"]),
    identityGeneration: z.string().regex(/^[1-9]\d*$/u),
    rowVersion: z.string().regex(/^[1-9]\d*$/u)
  })
  .strict();
const SnapshotSchema = z
  .object({
    memberBefore: MemberSchema,
    memberAfter: MemberSchema,
    seatsBefore: z.array(SeatSchema),
    seatsAfter: z.array(SeatSchema),
    connectionEffect: z.string(),
    administrativeAuthority: z.record(z.string(), z.json()).optional()
  })
  .strict();
export function isMemberLifecycleInput(input: unknown): boolean {
  const request = toolInputSchema("manage_member").parse(input) as {
    change: { operation: string };
  };
  return request.change.operation !== "invite";
}
export interface PreparedMemberLifecycle {
  readonly memberId: string;
  readonly boardId: string | null;
  readonly operation: string;
  readonly request: JsonValue;
  readonly snapshot: z.infer<typeof SnapshotSchema>;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
}
export async function prepareMemberLifecycleInTransaction(
  client: PoolClient,
  input: unknown
): Promise<PreparedMemberLifecycle> {
  const request = toolInputSchema("manage_member").parse(input) as JsonValue;
  if (!isMemberLifecycleInput(request))
    throw new TypeError("member lifecycle requires a non-invitation change");
  const change = (
    request as { change: { operation: string; member_id: string; board_id: string | null } }
  ).change;
  const result = await client.query<{ snapshot: unknown }>(
    "select boardagent_member_lifecycle_snapshot($1::jsonb) as snapshot",
    [request]
  );
  const snapshot = SnapshotSchema.parse(result.rows[0]?.snapshot);
  const canonicalPayload = {
    schemaVersion: "boardagent.member-lifecycle.v1",
    request,
    current: z.json().parse(snapshot)
  } satisfies JsonValue;
  return {
    memberId: change.member_id,
    boardId: change.board_id,
    operation: change.operation,
    request,
    snapshot,
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload)
  };
}
export async function planMemberLifecycleInTransaction(
  client: PoolClient,
  prepared: PreparedMemberLifecycle,
  consentRecordId: string,
  newId: () => string
) {
  const context = await readRequestContext(client);
  const auditEventId = UuidV7Schema.parse(newId());
  const versions = prepared.snapshot.seatsAfter.map((after) => {
    const before = prepared.snapshot.seatsBefore.find(
      (seat) => seat.membershipId === after.membershipId
    );
    if (!before) throw new Error("member lifecycle before snapshot missing");
    const snapshot = {
      schemaVersion: "boardagent.membership-lifecycle-authority.v1",
      operation: prepared.operation,
      ...(prepared.snapshot.administrativeAuthority === undefined
        ? {}
        : { administrativeAuthority: prepared.snapshot.administrativeAuthority }),
      memberBefore: prepared.snapshot.memberBefore,
      memberAfter: prepared.snapshot.memberAfter,
      before,
      after
    };
    return {
      id: UuidV7Schema.parse(newId()),
      membershipId: after.membershipId,
      canonicalHex: Buffer.from(canonicalJson(snapshot), "utf8").toString("hex")
    };
  });
  const auditEvent: AuditAppendInput = {
    organizationId: context.organizationId,
    consentRecordId,
    objectVersion: BigInt(prepared.snapshot.memberAfter.rowVersion),
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
        operation: prepared.operation,
        ...(prepared.snapshot.administrativeAuthority === undefined
          ? {}
          : { administrativeAuthority: prepared.snapshot.administrativeAuthority }),
        payloadSha256: prepared.payloadSha256,
        before: prepared.snapshot.memberBefore,
        after: prepared.snapshot.memberAfter,
        seatsBefore: prepared.snapshot.seatsBefore,
        seatsAfter: prepared.snapshot.seatsAfter
      },
      schemaVersion: 1
    }
  };
  return {
    ...prepared,
    consentRecordId,
    auditEvent,
    versions,
    idempotencyRecordId: UuidV7Schema.parse(newId())
  };
}
export async function finalizeMemberLifecycleInTransaction(
  client: PoolClient,
  plan: Awaited<ReturnType<typeof planMemberLifecycleInTransaction>>
): Promise<void> {
  await client.query(
    "select boardagent_finalize_member_lifecycle($1::jsonb,$2,$3,$4,$5::jsonb,$6,$7)",
    [
      plan.request,
      Buffer.from(plan.payloadSha256, "hex"),
      plan.consentRecordId,
      plan.auditEvent.event.eventId,
      JSON.stringify(plan.versions),
      plan.idempotencyRecordId,
      Buffer.from(canonicalSha256(plan.request), "hex")
    ]
  );
}

const CompletedMemberLifecycleSchema = z
  .object({
    operation: z.enum(["change_seat", "suspend", "remove", "reactivate"]),
    memberId: UuidV7Schema,
    boardId: UuidV7Schema.nullable(),
    memberAfter: MemberSchema,
    seatsAfter: z.array(SeatSchema)
  })
  .strict();

/** Read only the original safe result after current authority is revalidated in SQL.
 * The narrow definer avoids broadening raw stage/consent/audit RLS for token rotation.
 */
export async function replayCompletedMemberLifecycleInTransaction(
  client: PoolClient,
  input: unknown,
  exactOrigin: string,
  accessTokenRecordId: string
): Promise<z.infer<typeof CompletedMemberLifecycleSchema> | null> {
  const request = toolInputSchema("manage_member").parse(input);
  if (!isMemberLifecycleInput(request)) return null;
  const row = await client.query<{ completed: unknown }>(
    "select boardagent_replay_member_lifecycle($1::jsonb,$2,$3,$4) as completed",
    [
      request,
      Buffer.from(canonicalSha256(request as JsonValue), "hex"),
      exactOrigin,
      UuidV7Schema.parse(accessTokenRecordId)
    ]
  );
  const completed = row.rows[0]?.completed;
  return completed === null ? null : CompletedMemberLifecycleSchema.parse(completed);
}
