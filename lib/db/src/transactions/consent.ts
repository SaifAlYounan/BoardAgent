import type { PoolClient } from "pg";
import { z } from "zod";

import {
  canonicalJson,
  canonicalSha256,
  safeHashEqual,
  sha256Hex,
  Sha256HexSchema,
  UuidV7Schema,
  type JsonValue
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction, type AuditAppendInput } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const ActionCodeSchema = z.string().regex(/^[a-z][a-z0-9_]{1,127}$/u);
const TargetTypeSchema = z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u);
const CanonicalSchemaNameSchema = z.string().regex(/^boardagent\.[a-z0-9_.-]+\.v[0-9]+$/u);
const AcceptedInputResponseSchema = z
  .object({ approve: z.boolean(), confirmation_code: z.string().length(8) })
  .strict();
// Form-mode elicitation per the MCP capability rules: `form` declared, or neither `form`
// nor `url` declared (the spec's backwards-compatible empty object). A `url`-only client
// cannot receive the confirmation form. Mirrors the reference SDK's mode resolution.
const FormElicitationCapabilitiesSchema = z
  .object({
    elicitation: z
      .object({ form: z.object({}).strict().optional(), url: z.unknown().optional() })
      .passthrough()
      .refine(
        (value) => Object.hasOwn(value, "form") || !Object.hasOwn(value, "url"),
        "client capabilities do not declare form elicitation"
      )
  })
  .passthrough();

function boundedBytes(value: Uint8Array, label: string, minimum: number, maximum: number): Buffer {
  const bytes = Buffer.from(value);
  if (bytes.length < minimum || bytes.length > maximum) {
    throw new RangeError(
      `${label} must contain ${String(minimum)} through ${String(maximum)} bytes`
    );
  }
  return bytes;
}

function exactHttpsOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("exact origin must be an absolute URL origin");
  }
  if (parsed.protocol !== "https:" || parsed.origin !== value || parsed.pathname !== "/") {
    throw new TypeError("exact origin must be one canonical HTTPS origin");
  }
  return value;
}

function optionalUuid(value: string | null): string | null {
  return value === null ? null : UuidV7Schema.parse(value);
}

function optionalHash(value: string | null): string | null {
  return value === null ? null : Sha256HexSchema.parse(value);
}

async function currentContextSha256(client: PoolClient): Promise<string> {
  const result = await client.query<{ context_sha256: string | null }>(
    "select nullif(current_setting('boardagent.context_sha256',true),'') as context_sha256"
  );
  const value = result.rows[0]?.context_sha256;
  if (!value) throw new Error("managed request context hash is unavailable");
  return Sha256HexSchema.parse(value);
}

async function assertCurrentToken(
  client: PoolClient,
  accessTokenRecordId: string,
  organizationId: string,
  memberId: string,
  clientId: string,
  tokenJti: string
): Promise<void> {
  const token = await client.query<{ id: string }>(
    `select token.id
       from access_token_records as token
       join oauth_clients as oauth_client on oauth_client.id=token.client_id
       join system_instance as instance on instance.organization_id=token.organization_id
      where token.id=$1 and token.organization_id=$2 and token.member_id=$3
        and token.client_id=$4 and token.jti=$5
        and token.revoked_at is null and token.expires_at>transaction_timestamp()
        and oauth_client.state='active'
        and instance.canonical_resource_uri=token.resource_uri`,
    [accessTokenRecordId, organizationId, memberId, clientId, tokenJti]
  );
  if (token.rows.length !== 1) throw new Error("current access token is unavailable");
}

export interface StageActionInput {
  readonly stageId: string;
  readonly inputRequiredAttemptId: string;
  readonly wizardDraftId?: string | null;
  readonly boardId: string | null;
  readonly actingForMemberId: string | null;
  readonly actionCode: string;
  readonly targetType: string;
  readonly targetId: string | null;
  readonly canonicalSchema: string;
  readonly canonicalPayload: JsonValue;
  readonly packageSha256: string | null;
  readonly nonce: Uint8Array;
  readonly confirmationCode: string;
  readonly accessTokenRecordId: string;
  readonly exactOrigin: string;
  readonly originalName: string;
  readonly originalArguments: JsonValue;
  readonly clientCapabilities: JsonValue;
  readonly embeddedForm: JsonValue;
  readonly embeddedResult: JsonValue;
  readonly requestStateBytes: Uint8Array;
  readonly preparedRequestId: Uint8Array;
  readonly auditEventIds: {
    readonly stageReplaced: string;
    readonly stageCreated: string;
    readonly elicitationSent: string;
  };
}

export interface StagedAction {
  readonly stageId: string;
  readonly inputRequiredAttemptId: string;
  readonly replacedStageId: string | null;
  readonly payloadSha256: string;
  readonly packageSha256: string | null;
  readonly requestStateSha256: string;
  readonly originalArgumentsSha256: string;
  readonly capabilitiesSha256: string;
  readonly expiresAt: string;
  readonly auditSequences: readonly bigint[];
}

/** Caller must lock and authorize the aggregate before this stage/idempotency boundary. */
export async function stageActionInTransaction(
  client: PoolClient,
  input: StageActionInput,
  lockAndAuthorizeAggregate: (client: PoolClient) => Promise<void>
): Promise<StagedAction> {
  await lockAndAuthorizeAggregate(client);
  const context = await readRequestContext(client);
  const stageId = UuidV7Schema.parse(input.stageId);
  const inputRequiredAttemptId = UuidV7Schema.parse(input.inputRequiredAttemptId);
  const wizardDraftId = optionalUuid(input.wizardDraftId ?? null);
  const boardId = optionalUuid(input.boardId);
  const actingForMemberId = optionalUuid(input.actingForMemberId);
  const actionCode = ActionCodeSchema.parse(input.actionCode);
  const targetType = TargetTypeSchema.parse(input.targetType);
  const targetId = optionalUuid(input.targetId);
  const canonicalSchema = CanonicalSchemaNameSchema.parse(input.canonicalSchema);
  const canonicalPayload = Buffer.from(canonicalJson(input.canonicalPayload), "utf8");
  const payloadSha256 = sha256Hex(canonicalPayload);
  const packageSha256 = optionalHash(input.packageSha256);
  const nonceSha256 = sha256Hex(boundedBytes(input.nonce, "nonce", 16, 1024));
  if (input.confirmationCode.length !== 8) {
    throw new RangeError("confirmation code must contain exactly 8 characters");
  }
  const protectedCodeSha256 = sha256Hex(input.confirmationCode);
  const accessTokenRecordId = UuidV7Schema.parse(input.accessTokenRecordId);
  const exactOrigin = exactHttpsOrigin(input.exactOrigin);
  const originalName = ActionCodeSchema.parse(input.originalName);
  const originalArgumentsSha256 = canonicalSha256(input.originalArguments);
  FormElicitationCapabilitiesSchema.parse(input.clientCapabilities);
  const capabilitiesSha256 = canonicalSha256(input.clientCapabilities);
  const embeddedFormSha256 = canonicalSha256(input.embeddedForm);
  const embeddedResultSha256 = canonicalSha256(input.embeddedResult);
  const requestStateBytes = boundedBytes(input.requestStateBytes, "request state", 32, 4096);
  const requestStateSha256 = sha256Hex(requestStateBytes);
  const preparedRequestId = boundedBytes(input.preparedRequestId, "prepared request ID", 1, 1024);
  const contextSha256 = await currentContextSha256(client);
  await assertCurrentToken(
    client,
    accessTokenRecordId,
    context.organizationId,
    context.memberId,
    context.clientId,
    context.tokenJti
  );

  const active = await client.query<{ id: string }>(
    `select id from action_stages
      where actor_member_id=$1 and client_id=$2 and action_code=$3
        and target_type=$4 and target_id is not distinct from $5 and state='active'
      for update`,
    [context.memberId, context.clientId, actionCode, targetType, targetId]
  );
  if (active.rows.length > 1) throw new Error("multiple active action stages violate uniqueness");
  const replacedStageId = active.rows[0]?.id ?? null;
  if (replacedStageId) {
    const replaced = await client.query(
      "update action_stages set state='replaced' where id=$1 and state='active'",
      [replacedStageId]
    );
    if (replaced.rowCount !== 1) throw new Error("active action stage changed during replacement");
  }

  const insertedStage = await client.query<{ expires_at: string }>(
    `insert into action_stages(
       id,organization_id,board_id,actor_member_id,acting_for_member_id,action_code,
       target_type,target_id,canonical_schema,canonicalization_version,canonical_payload,
       payload_sha256,package_sha256,nonce_sha256,protected_code_sha256,client_id,
       access_token_record_id,token_jti,exact_origin,context_sha256,state,replaces_stage_id,
       expires_at
     ) values (
       $1,$2,$3,$4,$5,$6,$7,$8,$9,'RFC8785+NFC-LF-v1',$10,$11,$12,$13,$14,$15,$16,$17,
       $18,$19,'active',$20,transaction_timestamp()+interval '10 minutes'
     )
     returning to_char(expires_at at time zone 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at`,
    [
      stageId,
      context.organizationId,
      boardId,
      context.memberId,
      actingForMemberId,
      actionCode,
      targetType,
      targetId,
      canonicalSchema,
      canonicalPayload,
      Buffer.from(payloadSha256, "hex"),
      packageSha256 === null ? null : Buffer.from(packageSha256, "hex"),
      Buffer.from(nonceSha256, "hex"),
      Buffer.from(protectedCodeSha256, "hex"),
      context.clientId,
      accessTokenRecordId,
      context.tokenJti,
      exactOrigin,
      Buffer.from(contextSha256, "hex"),
      replacedStageId
    ]
  );
  const expiresAt = insertedStage.rows[0]?.expires_at;
  if (!expiresAt) throw new Error("database stage expiry is unavailable");
  await client.query(
    `insert into input_required_attempts(
       id,organization_id,stage_id,wizard_draft_id,protocol_version,protocol_header_version,
       result_meta_version,original_method,original_name,original_arguments_sha256,
       capabilities_sha256,embedded_form_sha256,embedded_result_sha256,request_state_bytes,
       request_state_sha256,prepared_request_id
     ) values (
       $1,$2,$3,$4,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call',$5,$6,$7,$8,$9,$10,$11,$12
     )`,
    [
      inputRequiredAttemptId,
      context.organizationId,
      stageId,
      wizardDraftId,
      originalName,
      Buffer.from(originalArgumentsSha256, "hex"),
      Buffer.from(capabilitiesSha256, "hex"),
      Buffer.from(embeddedFormSha256, "hex"),
      Buffer.from(embeddedResultSha256, "hex"),
      requestStateBytes,
      Buffer.from(requestStateSha256, "hex"),
      preparedRequestId
    ]
  );

  const auditInputs: AuditAppendInput[] = [];
  if (replacedStageId) {
    auditInputs.push({
      organizationId: context.organizationId,
      event: {
        eventId: UuidV7Schema.parse(input.auditEventIds.stageReplaced),
        eventType: "stage_replaced",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "action_stage",
        entityId: replacedStageId,
        boardId,
        origin: "mcp",
        details: { replacementStageId: stageId, actionCode, targetType },
        schemaVersion: 1
      }
    });
  }
  auditInputs.push(
    {
      organizationId: context.organizationId,
      event: {
        eventId: UuidV7Schema.parse(input.auditEventIds.stageCreated),
        eventType: "stage_created",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "action_stage",
        entityId: stageId,
        boardId,
        origin: "mcp",
        details: { actionCode, targetType, targetId, payloadSha256, packageSha256 },
        schemaVersion: 1
      }
    },
    {
      organizationId: context.organizationId,
      event: {
        eventId: UuidV7Schema.parse(input.auditEventIds.elicitationSent),
        eventType: "elicitation_sent",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "input_required_attempt",
        entityId: inputRequiredAttemptId,
        boardId,
        origin: "mcp",
        details: {
          stageId,
          originalName,
          originalArgumentsSha256,
          capabilitiesSha256,
          requestStateSha256
        },
        schemaVersion: 1
      }
    }
  );
  const audits = await appendAuditEventsInTransaction(client, auditInputs);
  return {
    stageId,
    inputRequiredAttemptId,
    replacedStageId,
    payloadSha256,
    packageSha256,
    requestStateSha256,
    originalArgumentsSha256,
    capabilitiesSha256,
    expiresAt,
    auditSequences: audits.map(({ sequence }) => sequence)
  };
}

interface ConfirmationRow {
  readonly stage_id: string;
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly actor_member_id: string;
  readonly acting_for_member_id: string | null;
  readonly action_code: string;
  readonly target_type: string;
  readonly target_id: string | null;
  readonly canonical_schema: string;
  readonly payload_sha256: string;
  readonly package_sha256: string | null;
  readonly protected_code_sha256: string;
  readonly access_token_record_id: string;
  readonly token_jti: string;
  readonly client_id: string;
  readonly exact_origin: string;
  readonly context_sha256: string;
  readonly stage_state: string;
  readonly expires_at: string;
  readonly expired: boolean;
  readonly staged_at: string;
  readonly attempt_id: string;
  readonly original_arguments_sha256: string;
  readonly capabilities_sha256: string;
  readonly request_state_sha256: string;
  readonly prepared_request_id: Buffer;
  readonly attempt_state: string;
}

export type ConfirmationFailureReason =
  | "stage_unavailable"
  | "context_mismatch"
  | "stage_not_active"
  | "expired"
  | "declined"
  | "retry_request_reused"
  | "request_mismatch"
  | "capabilities_mismatch"
  | "state_mismatch"
  | "canonical_stale"
  | "code_mismatch";

export interface ConfirmStagedActionInput {
  readonly stageId: string;
  readonly consentRecordId: string;
  readonly retryRequestId: Uint8Array;
  readonly originalArguments: JsonValue;
  readonly clientCapabilities: JsonValue;
  readonly exactOrigin: string;
  readonly requestStateBytes: Uint8Array;
  readonly responseAction: "accept" | "decline" | "cancel";
  readonly inputResponse: JsonValue | null;
  readonly auditEventIds: {
    readonly consentRecorded: string;
    readonly consentRejected: string;
  };
}

export interface CurrentActionBindings {
  readonly payloadSha256: string;
  readonly packageSha256: string | null;
}

export interface ConfirmedAct<T> {
  readonly value: T;
  readonly auditEvents: readonly AuditAppendInput[];
  /**
   * Sequences appended by a legacy transaction repository after the consent event.
   * This is accepted only when `appendConsentBeforeAct` is explicitly enabled.
   */
  readonly preappendedAuditSequences?: readonly bigint[];
  /**
   * Optional evidence-linked projection step. Audit rows are appended first and the
   * surrounding transaction rolls all evidence and projections back if this fails.
   * The callback may touch only aggregates already locked by the binding callback.
   */
  readonly finalizeAfterAudit?: (client: PoolClient) => Promise<void>;
}

export interface ConfirmStagedActionOptions {
  /**
   * Append `consent_recorded` before invoking a repository that still appends its own
   * domain audit rows. The surrounding transaction preserves all-or-nothing behavior.
   */
  readonly appendConsentBeforeAct?: boolean;
  /**
   * Advance the stage/attempt projections before the act callback so an older
   * repository can verify the just-created consent row. Transaction rollback still
   * prevents any externally visible partial confirmation.
   */
  readonly exposeConfirmedProjectionToAct?: boolean;
}

export type StagedActionResolution<T> =
  | {
      readonly confirmed: true;
      readonly value: T;
      readonly consentRecordId: string;
      readonly consentRecordSha256: string;
      readonly auditSequences: readonly bigint[];
    }
  | { readonly confirmed: false; readonly reason: ConfirmationFailureReason };

async function readConfirmationRow(
  client: PoolClient,
  stageId: string
): Promise<ConfirmationRow | undefined> {
  const result = await client.query<ConfirmationRow>(
    `select stage.id as stage_id,stage.organization_id,stage.board_id,
            stage.actor_member_id,stage.acting_for_member_id,stage.action_code,
            stage.target_type,stage.target_id,stage.canonical_schema,
            encode(stage.payload_sha256,'hex') as payload_sha256,
            case when stage.package_sha256 is null then null
                 else encode(stage.package_sha256,'hex') end as package_sha256,
            encode(stage.protected_code_sha256,'hex') as protected_code_sha256,
            stage.access_token_record_id,stage.token_jti,stage.client_id,stage.exact_origin,
            encode(stage.context_sha256,'hex') as context_sha256,stage.state as stage_state,
            to_char(stage.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at,
            stage.expires_at<=transaction_timestamp() as expired,
            to_char(stage.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as staged_at,
            attempt.id as attempt_id,
            encode(attempt.original_arguments_sha256,'hex') as original_arguments_sha256,
            encode(attempt.capabilities_sha256,'hex') as capabilities_sha256,
            encode(attempt.request_state_sha256,'hex') as request_state_sha256,
            attempt.prepared_request_id,attempt.state as attempt_state
       from action_stages as stage
       join input_required_attempts as attempt on attempt.stage_id=stage.id
      where stage.id=$1
      for update of stage,attempt`,
    [stageId]
  );
  if (result.rows.length > 1) throw new Error("action stage has multiple MRTR attempts");
  return result.rows[0];
}

async function rejectConfirmation(
  client: PoolClient,
  row: ConfirmationRow,
  input: ConfirmStagedActionInput,
  reason: ConfirmationFailureReason,
  retryRequestId: Buffer,
  inputResponseSha256: string
): Promise<void> {
  if (reason === "expired") {
    await client.query("update action_stages set state='expired' where id=$1 and state='active'", [
      row.stage_id
    ]);
    await client.query(
      `update input_required_attempts
          set retry_request_id=$1,input_response_sha256=$2,response_action=$3,
              retry_received_at=transaction_timestamp(),completed_at=transaction_timestamp(),
              state='expired'
        where id=$4 and state='prepared'`,
      [
        retryRequestId,
        Buffer.from(inputResponseSha256, "hex"),
        input.responseAction,
        row.attempt_id
      ]
    );
  } else {
    const cancelled = input.responseAction === "cancel";
    await client.query(
      cancelled
        ? "update action_stages set state='cancelled',cancelled_at=transaction_timestamp() where id=$1 and state='active'"
        : "update action_stages set state='rejected',rejected_at=transaction_timestamp() where id=$1 and state='active'",
      [row.stage_id]
    );
    await client.query(
      `update input_required_attempts
          set retry_request_id=$1,input_response_sha256=$2,response_action=$3,
              retry_received_at=transaction_timestamp(),completed_at=transaction_timestamp(),
              state=$4
        where id=$5 and state='prepared'`,
      [
        retryRequestId,
        Buffer.from(inputResponseSha256, "hex"),
        input.responseAction,
        cancelled ? "cancelled" : input.responseAction === "decline" ? "declined" : "accepted",
        row.attempt_id
      ]
    );
  }
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: row.organization_id,
      event: {
        eventId: UuidV7Schema.parse(input.auditEventIds.consentRejected),
        eventType: "consent_rejected",
        actorMemberId: row.actor_member_id,
        actorClientId: row.client_id,
        tokenJti: row.token_jti,
        entityType: "action_stage",
        entityId: row.stage_id,
        boardId: row.board_id,
        origin: "mcp",
        details: {
          actionCode: row.action_code,
          targetType: row.target_type,
          targetId: row.target_id,
          reason,
          inputResponseSha256
        },
        schemaVersion: 1
      }
    }
  ]);
}

/** Aggregate lock/authorization runs before stage locks; the act callback must not relock roots. */
export async function confirmStagedActionInTransaction<T>(
  client: PoolClient,
  input: ConfirmStagedActionInput,
  lockAuthorizeAndReadBindings: (client: PoolClient) => Promise<CurrentActionBindings>,
  act: (client: PoolClient, consentRecordId: string) => Promise<ConfirmedAct<T>>,
  options: ConfirmStagedActionOptions = {}
): Promise<StagedActionResolution<T>> {
  const stageId = UuidV7Schema.parse(input.stageId);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const retryRequestId = boundedBytes(input.retryRequestId, "retry request ID", 1, 1024);
  const requestStateBytes = boundedBytes(input.requestStateBytes, "request state", 32, 4096);
  const originalArgumentsSha256 = canonicalSha256(input.originalArguments);
  FormElicitationCapabilitiesSchema.parse(input.clientCapabilities);
  const capabilitiesSha256 = canonicalSha256(input.clientCapabilities);
  const exactOrigin = exactHttpsOrigin(input.exactOrigin);
  const inputResponseSha256 = canonicalSha256({
    action: input.responseAction,
    content: input.inputResponse
  });
  const bindings = await lockAuthorizeAndReadBindings(client);
  const currentPayloadSha256 = Sha256HexSchema.parse(bindings.payloadSha256);
  const currentPackageSha256 = optionalHash(bindings.packageSha256);
  const context = await readRequestContext(client);
  const row = await readConfirmationRow(client, stageId);
  if (!row) return { confirmed: false, reason: "stage_unavailable" };
  if (
    row.organization_id !== context.organizationId ||
    row.actor_member_id !== context.memberId ||
    row.client_id !== context.clientId ||
    row.token_jti !== context.tokenJti ||
    row.exact_origin !== exactOrigin ||
    !safeHashEqual(row.context_sha256, await currentContextSha256(client))
  ) {
    return { confirmed: false, reason: "context_mismatch" };
  }
  if (row.stage_state !== "active" || row.attempt_state !== "prepared") {
    return { confirmed: false, reason: "stage_not_active" };
  }
  await assertCurrentToken(
    client,
    row.access_token_record_id,
    context.organizationId,
    context.memberId,
    context.clientId,
    context.tokenJti
  );

  let reason: ConfirmationFailureReason | undefined;
  if (row.expired) reason = "expired";
  else if (input.responseAction !== "accept") reason = "declined";
  else if (row.prepared_request_id.equals(retryRequestId)) reason = "retry_request_reused";
  else if (!safeHashEqual(row.original_arguments_sha256, originalArgumentsSha256))
    reason = "request_mismatch";
  else if (!safeHashEqual(row.capabilities_sha256, capabilitiesSha256))
    reason = "capabilities_mismatch";
  else if (!safeHashEqual(row.request_state_sha256, sha256Hex(requestStateBytes)))
    reason = "state_mismatch";
  else if (
    !safeHashEqual(row.payload_sha256, currentPayloadSha256) ||
    row.package_sha256 !== currentPackageSha256
  )
    reason = "canonical_stale";
  else {
    const response = AcceptedInputResponseSchema.safeParse(input.inputResponse);
    if (!response.success || !response.data.approve) reason = "declined";
    else if (!safeHashEqual(row.protected_code_sha256, sha256Hex(response.data.confirmation_code)))
      reason = "code_mismatch";
  }
  if (reason) {
    await rejectConfirmation(client, row, input, reason, retryRequestId, inputResponseSha256);
    return { confirmed: false, reason };
  }

  const timestamp = await client.query<{ confirmed_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as confirmed_at`
  );
  const confirmedAt = timestamp.rows[0]?.confirmed_at;
  if (!confirmedAt) throw new Error("confirmation timestamp is unavailable");
  const protectedCodeRecordSha256 = canonicalSha256({
    schemaVersion: "boardagent.protected-code-record.v1",
    stageId,
    protectedCodeSha256: row.protected_code_sha256
  });
  const consentRecord = {
    schemaVersion: "boardagent.consent-record.v1",
    id: consentRecordId,
    stageId,
    inputRequiredAttemptId: row.attempt_id,
    actorMemberId: row.actor_member_id,
    actingForMemberId: row.acting_for_member_id,
    actionCode: row.action_code,
    targetType: row.target_type,
    targetId: row.target_id,
    payloadSha256: row.payload_sha256,
    packageSha256: row.package_sha256,
    protectedCodeRecordSha256,
    accessTokenRecordId: row.access_token_record_id,
    tokenJti: row.token_jti,
    clientId: row.client_id,
    exactOrigin: row.exact_origin,
    stagedAt: row.staged_at,
    confirmedAt,
    inputResponseSha256
  };
  const consentRecordSha256 = canonicalSha256(consentRecord);
  await client.query("select boardagent_record_confirmed_consent($1,$2,$3,$4,$5,$6,$7,$8)", [
    stageId,
    consentRecordId,
    retryRequestId,
    Buffer.from(canonicalJson(input.originalArguments), "utf8"),
    Buffer.from(canonicalJson(input.clientCapabilities), "utf8"),
    requestStateBytes,
    Buffer.from(
      canonicalJson({ action: input.responseAction, content: input.inputResponse }),
      "utf8"
    ),
    Buffer.from(canonicalJson(consentRecord), "utf8")
  ]);
  if (options.exposeConfirmedProjectionToAct && !options.appendConsentBeforeAct) {
    throw new Error("early confirmed projection requires consent-before-act audit ordering");
  }
  const confirmProjection = async (): Promise<void> => {
    const stageUpdate = await client.query(
      `update action_stages
          set state='confirmed',confirmed_at=transaction_timestamp()
        where id=$1 and state='active'`,
      [stageId]
    );
    const attemptUpdate = await client.query(
      `update input_required_attempts
          set retry_request_id=$1,input_response_sha256=$2,response_action='accept',
              retry_received_at=transaction_timestamp(),completed_at=transaction_timestamp(),
              state='confirmed'
        where id=$3 and state='prepared'`,
      [retryRequestId, Buffer.from(inputResponseSha256, "hex"), row.attempt_id]
    );
    if (stageUpdate.rowCount !== 1 || attemptUpdate.rowCount !== 1) {
      throw new Error("confirmation state changed before commit");
    }
  };
  if (options.exposeConfirmedProjectionToAct) await confirmProjection();
  const consentAudit: AuditAppendInput = {
    organizationId: row.organization_id,
    actingForMemberId: row.acting_for_member_id,
    consentRecordId,
    event: {
      eventId: UuidV7Schema.parse(input.auditEventIds.consentRecorded),
      eventType: "consent_recorded",
      actorMemberId: row.actor_member_id,
      actorClientId: row.client_id,
      tokenJti: row.token_jti,
      entityType: "consent_record",
      entityId: consentRecordId,
      boardId: row.board_id,
      origin: "mcp",
      details: {
        stageId,
        inputRequiredAttemptId: row.attempt_id,
        actionCode: row.action_code,
        payloadSha256: row.payload_sha256,
        packageSha256: row.package_sha256,
        recordSha256: consentRecordSha256
      },
      schemaVersion: 1
    }
  };
  const consentAudits = options.appendConsentBeforeAct
    ? await appendAuditEventsInTransaction(client, [consentAudit])
    : [];
  const confirmedAct = await act(client, consentRecordId);
  if (
    !options.appendConsentBeforeAct &&
    (confirmedAct.preappendedAuditSequences?.length ?? 0) > 0
  ) {
    throw new Error("preappended action audits require consent-before-act ordering");
  }
  const trailingAudits = await appendAuditEventsInTransaction(client, [
    ...(options.appendConsentBeforeAct ? [] : [consentAudit]),
    ...confirmedAct.auditEvents
  ]);
  const auditSequences = [
    ...consentAudits.map(({ sequence }) => sequence),
    ...(confirmedAct.preappendedAuditSequences ?? []),
    ...trailingAudits.map(({ sequence }) => sequence)
  ];
  await confirmedAct.finalizeAfterAudit?.(client);
  if (!options.exposeConfirmedProjectionToAct) await confirmProjection();
  return {
    confirmed: true,
    value: confirmedAct.value,
    consentRecordId,
    consentRecordSha256,
    auditSequences
  };
}
