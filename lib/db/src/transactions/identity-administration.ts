import type { PoolClient } from "pg";
import { z } from "zod";

import type { AuditEventType } from "@boardagent/audit";
import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";

import type { AuditAppendInput } from "./audit.js";
import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StageActionInput,
  type StagedAction,
  type StagedActionResolution
} from "./consent.js";
import { readRequestContext } from "./request-context.js";

const SnapshotSchema = z.record(z.string(), z.json());

export type IdentityAdministrationAction =
  | { readonly kind: "revoke_enrollment"; readonly invitationId: string; readonly reason: string }
  | {
      readonly kind: "initiate_identity_recovery";
      readonly memberId: string;
      readonly reason: string;
      readonly proofingMethod: string;
      readonly credentialDisposition: "revoke_all" | "preserve_named";
      readonly preservedCredentialIds: readonly string[];
    }
  | {
      readonly kind: "revoke_my_session";
      readonly sessionId: string;
      readonly recentAuthProofSha256: string;
    }
  | { readonly kind: "block_oauth_client"; readonly clientId: string; readonly reason: string }
  | { readonly kind: "unblock_oauth_client"; readonly clientId: string; readonly reason: string }
  | {
      readonly kind: "link_external_identity";
      readonly memberId: string;
      readonly issuer: string;
      readonly subject: string;
      readonly browserProofSha256: string;
    }
  | {
      readonly kind: "unlink_external_identity";
      readonly identityLinkId: string;
      readonly reason: string;
    };

export interface PreparedIdentityAdministrationAction {
  readonly actionCode: IdentityAdministrationAction["kind"];
  readonly boardId: null;
  readonly targetType: "enrollment" | "member" | "session" | "oauth_client" | "external_identity";
  readonly targetId: string;
  readonly canonicalSchema: "boardagent.identity-administration.v1";
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: null;
}

export interface IdentityAdministrationStageInput {
  readonly action: IdentityAdministrationAction;
  readonly stage: Omit<
    StageActionInput,
    | "boardId"
    | "actingForMemberId"
    | "actionCode"
    | "targetType"
    | "targetId"
    | "canonicalSchema"
    | "canonicalPayload"
    | "packageSha256"
    | "originalName"
  >;
}

export interface IdentityAdministrationConfirmationInput {
  readonly action: IdentityAdministrationAction;
  readonly recoveryRequestId: string;
  readonly confirmation: ConfirmStagedActionInput;
  readonly auditEventId: string;
}

export interface IdentityAdministrationResult {
  readonly actionCode: IdentityAdministrationAction["kind"];
  readonly targetId: string;
  readonly data: JsonValue;
}

export class IdentityAdministrationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "IdentityAdministrationError";
  }
}

function bounded(value: string, label: string, maximum = 65_536): string {
  const normalized = canonicalText(value);
  if (normalized.length < 1 || normalized.length > maximum) {
    throw new RangeError(`${label} must contain 1 through ${String(maximum)} characters`);
  }
  return normalized;
}

function exactIssuer(value: string): string {
  const issuer = new URL(value);
  if (
    issuer.protocol !== "https:" ||
    issuer.username !== "" ||
    issuer.password !== "" ||
    issuer.search !== "" ||
    issuer.hash !== ""
  ) {
    throw new TypeError("external identity issuer must be one exact HTTPS URL");
  }
  return issuer.href;
}

export function hashOpaqueIdentityProof(value: string): string {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 24 || bytes.toString("base64url") !== value) {
    throw new TypeError("identity proof must be a canonical opaque reference");
  }
  return sha256Hex(bytes);
}

export function normalizeIdentityAdministrationAction(
  input: IdentityAdministrationAction
): IdentityAdministrationAction {
  switch (input.kind) {
    case "revoke_enrollment":
      return {
        kind: input.kind,
        invitationId: UuidV7Schema.parse(input.invitationId),
        reason: bounded(input.reason, "enrollment revocation reason")
      };
    case "initiate_identity_recovery": {
      const preservedCredentialIds = input.preservedCredentialIds
        .map((value) => UuidV7Schema.parse(value))
        .toSorted();
      if (
        preservedCredentialIds.length > 32 ||
        new Set(preservedCredentialIds).size !== preservedCredentialIds.length ||
        (input.credentialDisposition === "revoke_all" && preservedCredentialIds.length !== 0) ||
        (input.credentialDisposition === "preserve_named" && preservedCredentialIds.length === 0)
      ) {
        throw new IdentityAdministrationError("identity recovery credential selection is invalid");
      }
      return {
        kind: input.kind,
        memberId: UuidV7Schema.parse(input.memberId),
        reason: bounded(input.reason, "identity recovery reason"),
        proofingMethod: bounded(input.proofingMethod, "identity recovery proofing method", 2048),
        credentialDisposition: input.credentialDisposition,
        preservedCredentialIds
      };
    }
    case "revoke_my_session":
      return {
        kind: input.kind,
        sessionId: UuidV7Schema.parse(input.sessionId),
        recentAuthProofSha256: Sha256HexSchema.parse(input.recentAuthProofSha256)
      };
    case "block_oauth_client":
    case "unblock_oauth_client":
      return {
        kind: input.kind,
        clientId: UuidV7Schema.parse(input.clientId),
        reason: bounded(input.reason, "OAuth client transition reason")
      };
    case "link_external_identity":
      return {
        kind: input.kind,
        memberId: UuidV7Schema.parse(input.memberId),
        issuer: exactIssuer(input.issuer),
        subject: bounded(input.subject, "external identity subject", 1024),
        browserProofSha256: Sha256HexSchema.parse(input.browserProofSha256)
      };
    case "unlink_external_identity":
      return {
        kind: input.kind,
        identityLinkId: UuidV7Schema.parse(input.identityLinkId),
        reason: bounded(input.reason, "external identity unlink reason")
      };
  }
}

function target(action: IdentityAdministrationAction): {
  readonly type: PreparedIdentityAdministrationAction["targetType"];
  readonly id: string;
} {
  switch (action.kind) {
    case "revoke_enrollment":
      return { type: "enrollment", id: action.invitationId };
    case "initiate_identity_recovery":
    case "link_external_identity":
      return { type: "member", id: action.memberId };
    case "revoke_my_session":
      return { type: "session", id: action.sessionId };
    case "block_oauth_client":
    case "unblock_oauth_client":
      return { type: "oauth_client", id: action.clientId };
    case "unlink_external_identity":
      return { type: "external_identity", id: action.identityLinkId };
  }
}

function safeRequest(action: IdentityAdministrationAction): JsonValue {
  switch (action.kind) {
    case "revoke_enrollment":
      return { invitationId: action.invitationId, reason: action.reason };
    case "initiate_identity_recovery":
      return {
        memberId: action.memberId,
        reason: action.reason,
        proofingMethod: action.proofingMethod,
        credentialDisposition: action.credentialDisposition,
        preservedCredentialIds: [...action.preservedCredentialIds]
      };
    case "revoke_my_session":
      return {
        sessionId: action.sessionId,
        recentAuthProofSha256: action.recentAuthProofSha256
      };
    case "block_oauth_client":
    case "unblock_oauth_client":
      return { clientId: action.clientId, reason: action.reason };
    case "link_external_identity":
      return {
        memberId: action.memberId,
        issuer: action.issuer,
        subject: action.subject,
        browserProofSha256: action.browserProofSha256
      };
    case "unlink_external_identity":
      return { identityLinkId: action.identityLinkId, reason: action.reason };
  }
}

async function prepareInternal(
  client: PoolClient,
  rawAction: IdentityAdministrationAction
): Promise<PreparedIdentityAdministrationAction> {
  const action = normalizeIdentityAdministrationAction(rawAction);
  const actionTarget = target(action);
  const request = safeRequest(action);
  const snapshotResult = await client.query<{ snapshot: unknown }>(
    "select boardagent_identity_admin_snapshot($1,$2,$3::jsonb) as snapshot",
    [action.kind, actionTarget.id, request]
  );
  const snapshot = SnapshotSchema.parse(snapshotResult.rows[0]?.snapshot) as JsonValue;
  const canonicalPayload = {
    schemaVersion: "boardagent.identity-administration.v1",
    actionCode: action.kind,
    targetType: actionTarget.type,
    targetId: actionTarget.id,
    request,
    current: snapshot,
    ...(action.kind === "initiate_identity_recovery"
      ? {
          replacementRegistration: {
            schemaVersion: "boardagent.recovery-registration-policy.v1",
            eligibility: "other-active-human-with-in-person-or-verified-number-proof",
            handoffExpiresInSeconds: 600,
            activationCodeExpiresInSeconds: 600,
            activation: "fresh-original-issuer-confirmation-of-human-code-and-exact-credential",
            changesRolesOrSeats: false
          }
        }
      : {})
  } satisfies JsonValue;
  return {
    actionCode: action.kind,
    boardId: null,
    targetType: actionTarget.type,
    targetId: actionTarget.id,
    canonicalSchema: "boardagent.identity-administration.v1",
    canonicalPayload,
    payloadSha256: canonicalSha256(canonicalPayload),
    packageSha256: null
  };
}

export function prepareIdentityAdministrationActionInTransaction(
  client: PoolClient,
  action: IdentityAdministrationAction
): Promise<PreparedIdentityAdministrationAction> {
  return prepareInternal(client, action);
}

export async function stageIdentityAdministrationActionInTransaction(
  client: PoolClient,
  input: IdentityAdministrationStageInput
): Promise<StagedAction & PreparedIdentityAdministrationAction> {
  const prepared = await prepareInternal(client, input.action);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: null,
      actingForMemberId: null,
      actionCode: prepared.actionCode,
      targetType: prepared.targetType,
      targetId: prepared.targetId,
      canonicalSchema: prepared.canonicalSchema,
      canonicalPayload: prepared.canonicalPayload,
      packageSha256: null,
      originalName: prepared.actionCode
    },
    async () => undefined
  );
  return { ...prepared, ...staged, packageSha256: null };
}

function auditType(action: IdentityAdministrationAction["kind"]): AuditEventType {
  switch (action) {
    case "revoke_enrollment":
      return "enrollment_revoked";
    case "initiate_identity_recovery":
      return "identity_recovery_started";
    case "revoke_my_session":
      return "session_revoked";
    case "block_oauth_client":
      return "oauth_client_blocked";
    case "unblock_oauth_client":
      return "oauth_client_unblocked";
    case "link_external_identity":
      return "external_identity_linked";
    case "unlink_external_identity":
      return "external_identity_unlinked";
  }
}

export async function confirmIdentityAdministrationActionInTransaction(
  client: PoolClient,
  input: IdentityAdministrationConfirmationInput
): Promise<StagedActionResolution<IdentityAdministrationResult>> {
  let prepared: PreparedIdentityAdministrationAction | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareInternal(requestClient, input.action);
      return { payloadSha256: prepared.payloadSha256, packageSha256: null };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("identity administration preparation is unavailable");
      const context = await readRequestContext(requestClient);
      const action = normalizeIdentityAdministrationAction(input.action);
      const applied = await requestClient.query<{ result: unknown }>(
        `select boardagent_apply_identity_admin_action($1,$2,$3::jsonb,$4,$5,$6) as result`,
        [
          action.kind,
          prepared.targetId,
          safeRequest(action),
          Buffer.from(prepared.payloadSha256, "hex"),
          consentRecordId,
          UuidV7Schema.parse(input.recoveryRequestId)
        ]
      );
      const data = SnapshotSchema.parse(applied.rows[0]?.result) as JsonValue;
      const auditEvents: AuditAppendInput[] = [
        {
          organizationId: context.organizationId,
          consentRecordId,
          event: {
            eventId: UuidV7Schema.parse(input.auditEventId),
            eventType: auditType(action.kind),
            actorMemberId: context.memberId,
            actorClientId: context.clientId,
            tokenJti: context.tokenJti,
            entityType: prepared.targetType,
            entityId: prepared.targetId,
            boardId: null,
            origin: "mcp",
            details: {
              actionCode: action.kind,
              payloadSha256: prepared.payloadSha256,
              resultSha256: canonicalSha256(data)
            },
            schemaVersion: 1
          }
        }
      ];
      return {
        value: { actionCode: action.kind, targetId: prepared.targetId, data },
        auditEvents
      };
    }
  );
}
