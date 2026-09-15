import type { PoolClient } from "pg";
import { z } from "zod";
import {
  canonicalSha256,
  toolInputSchema,
  UuidV7Schema,
  type JsonValue
} from "@boardagent/contracts";
import type { AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";

export type AdministrativeAuthorityTool = "manage_company_admin" | "manage_member_admin_delegation";
export function isAdministrativeAuthorityTool(tool: string): tool is AdministrativeAuthorityTool {
  return tool === "manage_company_admin" || tool === "manage_member_admin_delegation";
}

const VersionSchema = z.string().regex(/^[1-9]\d*$/u);
const SnapshotSchema = z
  .object({
    operation: z.enum(["grant", "transfer", "accept", "decline", "cancel", "revoke"]),
    recordType: z.enum([
      "company_admin_proposal",
      "company_admin_assignment",
      "member_admin_delegation"
    ]),
    recordId: UuidV7Schema,
    recordVersion: VersionSchema,
    boardId: UuidV7Schema.nullable(),
    actorMemberId: UuidV7Schema,
    actorDisplayName: z.string(),
    actorIdentityGeneration: VersionSchema,
    targetMemberId: UuidV7Schema,
    targetDisplayName: z.string(),
    targetIdentityGeneration: VersionSchema,
    targetMemberVersion: VersionSchema,
    issuerMemberId: UuidV7Schema,
    issuerIdentityGeneration: VersionSchema,
    before: z.record(z.string(), z.json()).nullable(),
    after: z.record(z.string(), z.json()),
    eventType: z.enum([
      "company_admin_proposed",
      "company_admin_granted",
      "company_admin_transferred",
      "company_admin_revoked",
      "company_admin_proposal_declined",
      "company_admin_proposal_cancelled",
      "member_admin_delegation_granted",
      "member_admin_delegation_revoked"
    ]),
    affectedMemberIds: z.array(UuidV7Schema),
    memberChanges: z.array(
      z
        .object({
          memberId: UuidV7Schema,
          displayName: z.string(),
          beforeIdentityGeneration: VersionSchema,
          afterIdentityGeneration: VersionSchema,
          beforeRowVersion: VersionSchema,
          afterRowVersion: VersionSchema,
          adminAfter: z.boolean()
        })
        .strict()
    )
  })
  .strict();

export interface PreparedAdministrativeAuthority {
  readonly tool: AdministrativeAuthorityTool;
  readonly request: JsonValue;
  readonly snapshot: z.infer<typeof SnapshotSchema>;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
}
export async function prepareAdministrativeAuthorityInTransaction(
  client: PoolClient,
  input: unknown,
  tool: AdministrativeAuthorityTool
): Promise<PreparedAdministrativeAuthority> {
  const request = toolInputSchema(tool).parse(input) as JsonValue;
  const result = await client.query<{ snapshot: unknown }>(
    tool === "manage_company_admin"
      ? "select boardagent_company_admin_snapshot($1::jsonb) as snapshot"
      : "select boardagent_member_admin_delegation_snapshot($1::jsonb) as snapshot",
    [request]
  );
  const snapshot = SnapshotSchema.parse(result.rows[0]?.snapshot);
  if (
    (tool === "manage_member_admin_delegation") !==
      (snapshot.recordType === "member_admin_delegation") ||
    (tool === "manage_member_admin_delegation") !== (snapshot.boardId !== null)
  ) {
    throw new Error("administrative snapshot does not match the selected tool");
  }
  const canonicalPayload = {
    schemaVersion: "boardagent.administrative-authority.v1",
    tool,
    request,
    snapshot
  } satisfies JsonValue;
  return {
    tool,
    request,
    snapshot,
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload)
  };
}
export async function planAdministrativeAuthorityInTransaction(
  client: PoolClient,
  prepared: PreparedAdministrativeAuthority,
  consentRecordId: string,
  newId: () => string
) {
  const context = await readRequestContext(client);
  const snapshot = prepared.snapshot;
  const auditEvent: AuditAppendInput = {
    organizationId: context.organizationId,
    consentRecordId,
    objectVersion: BigInt(snapshot.recordVersion),
    event: {
      eventId: UuidV7Schema.parse(newId()),
      eventType: snapshot.eventType,
      actorMemberId: context.memberId,
      actorClientId: context.clientId,
      tokenJti: context.tokenJti,
      entityType: snapshot.recordType,
      entityId: snapshot.recordId,
      boardId: snapshot.boardId,
      origin: "mcp",
      details: {
        operation: snapshot.operation,
        administrativeRecordId: snapshot.recordId,
        payloadSha256: prepared.payloadSha256,
        before: snapshot.before,
        after: snapshot.after,
        affectedMemberIds: snapshot.affectedMemberIds,
        memberChanges: snapshot.memberChanges
      },
      schemaVersion: 1
    }
  };
  return {
    ...prepared,
    consentRecordId,
    auditEvent,
    changeId: UuidV7Schema.parse(newId()),
    idempotencyRecordId: UuidV7Schema.parse(newId())
  };
}
export async function finalizeAdministrativeAuthorityInTransaction(
  client: PoolClient,
  plan: Awaited<ReturnType<typeof planAdministrativeAuthorityInTransaction>>
): Promise<void> {
  await client.query(
    plan.tool === "manage_company_admin"
      ? "select boardagent_finalize_company_admin($1::jsonb,$2,$3,$4,$5,$6,$7)"
      : "select boardagent_finalize_member_admin_delegation($1::jsonb,$2,$3,$4,$5,$6,$7)",
    [
      plan.request,
      Buffer.from(plan.payloadSha256, "hex"),
      plan.consentRecordId,
      plan.auditEvent.event.eventId,
      plan.changeId,
      plan.idempotencyRecordId,
      Buffer.from(canonicalSha256(plan.request), "hex")
    ]
  );
}
