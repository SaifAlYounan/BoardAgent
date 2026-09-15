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

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const PrepareArgumentsSchema = toolInputSchema("prepare_onboarding_attestation") as z.ZodType<{
  readonly schema_version: "boardagent.tool-input.v1";
  readonly board_id: string;
  readonly terms_version_id: string;
  readonly support_version_id: string;
  readonly presentation_choice: string;
  readonly local_memory_choice: string;
  readonly idempotency_key: string;
}>;

const ExactOriginSchema = z
  .string()
  .url()
  .refine((value) => {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.origin === value &&
      parsed.username === "" &&
      parsed.password === ""
    );
  }, "onboarding origin must be an exact HTTPS origin");

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().safe(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);

export const PrepareOnboardingStageInputSchema = z
  .object({
    originalArguments: PrepareArgumentsSchema,
    exactOrigin: ExactOriginSchema,
    stageId: UuidV7Schema,
    stageTokenSha256: Sha256HexSchema,
    idempotencyRecordId: UuidV7Schema,
    auditEventId: UuidV7Schema
  })
  .strict();
export type PrepareOnboardingStageInput = z.input<typeof PrepareOnboardingStageInputSchema>;

export const CompleteOnboardingAttestationInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    boardId: UuidV7Schema,
    memberId: UuidV7Schema,
    sessionId: UuidV7Schema,
    stageId: UuidV7Schema,
    stageTokenSha256: Sha256HexSchema,
    webauthnChallengeId: UuidV7Schema,
    webauthnCredentialId: UuidV7Schema,
    attestationId: UuidV7Schema,
    auditEventId: UuidV7Schema,
    tombstoneId: UuidV7Schema
  })
  .strict();
export type CompleteOnboardingAttestationInput = z.input<
  typeof CompleteOnboardingAttestationInputSchema
>;

export class OnboardingTransactionError extends Error {
  public constructor(
    public readonly code:
      | "onboarding_unavailable"
      | "onboarding_already_current"
      | "onboarding_stage_active"
      | "onboarding_idempotency_conflict"
      | "onboarding_idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "OnboardingTransactionError";
  }
}

interface LiveTokenRow {
  readonly token_record_id: string;
  readonly organization_id: string;
  readonly member_id: string;
  readonly internal_client_id: string;
  readonly session_id: string;
  readonly resource_uri: string;
  readonly scope_set: string[];
  readonly board_ids: string[];
}

interface MembershipRow {
  readonly seat_role: "voting_member" | "management" | "observer";
  readonly entitlement_generation: string;
}

interface TermsRow {
  readonly id: string;
  readonly version: number;
  readonly schema_version: string;
  readonly canonical_text: string;
  readonly canonical_sha256: Buffer;
  readonly effective_at: Date;
}

interface SupportRow {
  readonly id: string;
  readonly version: number;
  readonly support_name: string;
  readonly contact_methods: unknown;
  readonly canonical_sha256: Buffer;
  readonly effective_at: Date;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: "in_progress" | "succeeded" | "failed" | "expired";
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface StageReplayRow {
  readonly id: string;
  readonly expires_at: Date;
  readonly safe_response_sha256: Buffer;
}

export interface PreparedOnboardingStage {
  readonly replayed: boolean;
  readonly stageId: string;
  readonly memberId: string;
  readonly boardId: string;
  readonly termsVersionId: string;
  readonly supportVersionId: string;
  readonly expiresAt: string;
  readonly safeResponseSha256: string;
  readonly auditEventId: string | null;
  readonly auditSequence: string | null;
}

function unavailable(message = "onboarding is unavailable"): OnboardingTransactionError {
  return new OnboardingTransactionError("onboarding_unavailable", message);
}

function safeResponse(input: {
  readonly stageId: string;
  readonly memberId: string;
  readonly boardId: string;
  readonly termsVersionId: string;
  readonly supportVersionId: string;
}): Readonly<Record<string, JsonValue>> {
  return {
    schemaVersion: "boardagent.onboarding-stage-safe-response.v1",
    stageId: input.stageId,
    memberId: input.memberId,
    boardId: input.boardId,
    termsVersionId: input.termsVersionId,
    supportVersionId: input.supportVersionId,
    secretOnce: true
  };
}

async function liveToken(client: PoolClient, tokenJti: string): Promise<LiveTokenRow | undefined> {
  const result = await client.query<LiveTokenRow>(
    `select resolved.token_record_id,resolved.organization_id,resolved.member_id,
            resolved.internal_client_id,token.session_id,resolved.resource_uri,
            resolved.scope_set,resolved.board_ids
       from boardagent_resolve_access_token($1) as resolved
       join access_token_records as token on token.id=resolved.token_record_id
        and token.organization_id=resolved.organization_id
        and token.member_id=resolved.member_id and token.client_id=resolved.internal_client_id
        and token.session_id is not null`,
    [tokenJti]
  );
  return result.rows.length === 1 ? result.rows[0] : undefined;
}

async function currentTerms(
  client: PoolClient,
  organizationId: string,
  seatRole: MembershipRow["seat_role"]
): Promise<TermsRow | undefined> {
  const result = await client.query<TermsRow>(
    `select id,version,schema_version,canonical_text,canonical_sha256,effective_at
       from onboarding_terms_versions
      where organization_id=$1 and seat_role=$2
        and effective_at<=transaction_timestamp()
      order by version desc limit 1`,
    [organizationId, seatRole]
  );
  return result.rows[0];
}

async function currentSupport(
  client: PoolClient,
  organizationId: string,
  boardId: string
): Promise<SupportRow | undefined> {
  const result = await client.query<SupportRow>(
    `select id,version,support_name,contact_methods,canonical_sha256,effective_at
       from secretary_support_versions
      where organization_id=$1 and board_id=$2
        and effective_at<=transaction_timestamp()
      order by version desc limit 1`,
    [organizationId, boardId]
  );
  return result.rows[0];
}

async function readIdempotency(
  client: PoolClient,
  memberId: string,
  clientId: string,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='prepare_onboarding_attestation' and idempotency_key=$3
      for update`,
    [memberId, clientId, key]
  );
  return result.rows[0];
}

async function replayStage(
  client: PoolClient,
  row: IdempotencyRow,
  requestSha256: string,
  expected: Pick<
    PreparedOnboardingStage,
    "memberId" | "boardId" | "termsVersionId" | "supportVersionId"
  >
): Promise<PreparedOnboardingStage> {
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new OnboardingTransactionError(
      "onboarding_idempotency_conflict",
      "onboarding idempotency key was used for another request"
    );
  }
  if (
    row.state !== "succeeded" ||
    row.safe_response_type !== "onboarding_stage" ||
    row.safe_response_id === null ||
    row.safe_response_sha256 === null
  ) {
    throw new OnboardingTransactionError(
      "onboarding_idempotency_in_progress",
      "identical onboarding preparation is already in progress"
    );
  }
  const stage = await client.query<StageReplayRow>(
    `select id,expires_at,safe_response_sha256
       from onboarding_browser_stages where id=$1`,
    [row.safe_response_id]
  );
  const persisted = stage.rows[0];
  if (!persisted || stage.rows.length !== 1) throw unavailable();
  const calculated = canonicalSha256(
    safeResponse({
      stageId: persisted.id,
      memberId: expected.memberId,
      boardId: expected.boardId,
      termsVersionId: expected.termsVersionId,
      supportVersionId: expected.supportVersionId
    })
  );
  if (
    !safeHashEqual(persisted.safe_response_sha256.toString("hex"), calculated) ||
    !safeHashEqual(row.safe_response_sha256.toString("hex"), calculated)
  ) {
    throw unavailable("onboarding replay evidence is invalid");
  }
  return {
    replayed: true,
    stageId: persisted.id,
    memberId: expected.memberId,
    boardId: expected.boardId,
    termsVersionId: expected.termsVersionId,
    supportVersionId: expected.supportVersionId,
    expiresAt: persisted.expires_at.toISOString(),
    safeResponseSha256: calculated,
    auditEventId: null,
    auditSequence: null
  };
}

export async function prepareOnboardingStageInTransaction(
  client: PoolClient,
  rawInput: PrepareOnboardingStageInput
): Promise<PreparedOnboardingStage> {
  const input = PrepareOnboardingStageInputSchema.parse(rawInput);
  const request = input.originalArguments;
  const context = await readRequestContext(client);
  const token = await liveToken(client, context.tokenJti);
  if (
    !token ||
    token.organization_id !== context.organizationId ||
    token.member_id !== context.memberId ||
    token.internal_client_id !== context.clientId ||
    token.resource_uri !== `${input.exactOrigin}/mcp` ||
    !token.scope_set.includes("onboarding:read") ||
    !token.board_ids.includes(request.board_id)
  ) {
    throw unavailable();
  }
  const membershipResult = await client.query<MembershipRow>(
    `select seat_role,entitlement_generation::text
       from board_memberships
      where organization_id=$1 and board_id=$2 and member_id=$3
        and state='active' and active_from<=transaction_timestamp()
        and (active_until is null or active_until>transaction_timestamp())`,
    [context.organizationId, request.board_id, context.memberId]
  );
  const membership = membershipResult.rows[0];
  if (!membership || membershipResult.rows.length !== 1) throw unavailable();
  const terms = await currentTerms(client, context.organizationId, membership.seat_role);
  const support = await currentSupport(client, context.organizationId, request.board_id);
  if (
    !terms ||
    !support ||
    terms.id !== request.terms_version_id ||
    support.id !== request.support_version_id
  ) {
    throw unavailable("onboarding terms or secretary support changed");
  }
  const current = await client.query<{ id: string }>(
    `select id from onboarding_attestations
      where member_id=$1 and board_id=$2 and terms_version_id=$3 and support_version_id=$4
      limit 1`,
    [context.memberId, request.board_id, terms.id, support.id]
  );
  if (current.rows.length > 0) {
    throw new OnboardingTransactionError(
      "onboarding_already_current",
      "onboarding is already current"
    );
  }

  const requestSha256 = canonicalSha256(request);
  const existingIdempotency = await readIdempotency(
    client,
    context.memberId,
    context.clientId,
    request.idempotency_key
  );
  const expected = {
    memberId: context.memberId,
    boardId: request.board_id,
    termsVersionId: terms.id,
    supportVersionId: support.id
  };
  if (existingIdempotency) {
    return replayStage(client, existingIdempotency, requestSha256, expected);
  }

  await client.query(
    `update onboarding_browser_stages set state='expired'
      where member_id=$1 and client_id=$2 and board_id=$3
        and state='active' and expires_at<=transaction_timestamp()`,
    [context.memberId, context.clientId, request.board_id]
  );
  const active = await client.query<{ id: string }>(
    `select id from onboarding_browser_stages
      where member_id=$1 and client_id=$2 and board_id=$3 and state='active'
      for update`,
    [context.memberId, context.clientId, request.board_id]
  );
  if (active.rows.length > 0) {
    throw new OnboardingTransactionError(
      "onboarding_stage_active",
      "an onboarding browser ceremony is already active"
    );
  }
  const insertedIdempotency = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'prepare_onboarding_attestation',$5,$6,'in_progress',
               transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      input.idempotencyRecordId,
      context.organizationId,
      context.memberId,
      context.clientId,
      request.idempotency_key,
      Buffer.from(requestSha256, "hex")
    ]
  );
  if (insertedIdempotency.rowCount !== 1) {
    const raced = await readIdempotency(
      client,
      context.memberId,
      context.clientId,
      request.idempotency_key
    );
    if (!raced) throw unavailable();
    return replayStage(client, raced, requestSha256, expected);
  }

  const safeResponseSha256 = canonicalSha256(
    safeResponse({
      stageId: input.stageId,
      memberId: context.memberId,
      boardId: request.board_id,
      termsVersionId: terms.id,
      supportVersionId: support.id
    })
  );
  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: context.organizationId,
      event: {
        eventId: input.auditEventId,
        eventType: "onboarding_stage_created",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "onboarding_browser_stage",
        entityId: input.stageId,
        boardId: request.board_id,
        origin: "mcp",
        details: {
          memberId: context.memberId,
          termsVersionId: terms.id,
          termsSha256: terms.canonical_sha256.toString("hex"),
          supportVersionId: support.id,
          supportSha256: support.canonical_sha256.toString("hex"),
          presentationChoice: request.presentation_choice,
          localMemoryChoice: request.local_memory_choice,
          browserPasskeyRequired: true,
          comprehensionClaimed: false
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("onboarding stage audit event was not appended");
  const inserted = await client.query<{ expires_at: Date }>(
    `insert into onboarding_browser_stages(
       id,organization_id,board_id,member_id,session_id,client_id,access_token_record_id,
       token_jti,terms_version_id,support_version_id,presentation_choice,
       local_memory_choice,request_sha256,stage_token_sha256,safe_response_sha256,
       idempotency_record_id,exact_origin,expires_at,created_audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
               transaction_timestamp()+interval '10 minutes',$18)
     returning expires_at`,
    [
      input.stageId,
      context.organizationId,
      request.board_id,
      context.memberId,
      token.session_id,
      context.clientId,
      token.token_record_id,
      context.tokenJti,
      terms.id,
      support.id,
      request.presentation_choice,
      request.local_memory_choice,
      Buffer.from(requestSha256, "hex"),
      Buffer.from(input.stageTokenSha256, "hex"),
      Buffer.from(safeResponseSha256, "hex"),
      input.idempotencyRecordId,
      input.exactOrigin,
      audit.eventId
    ]
  );
  const expiresAt = inserted.rows[0]?.expires_at;
  if (!expiresAt || inserted.rows.length !== 1) throw unavailable();
  const completedIdempotency = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='onboarding_stage',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [input.stageId, Buffer.from(safeResponseSha256, "hex"), input.idempotencyRecordId]
  );
  if (completedIdempotency.rowCount !== 1) {
    throw new Error("onboarding idempotency completion failed");
  }
  return {
    replayed: false,
    stageId: input.stageId,
    memberId: context.memberId,
    boardId: request.board_id,
    termsVersionId: terms.id,
    supportVersionId: support.id,
    expiresAt: expiresAt.toISOString(),
    safeResponseSha256,
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}

interface StageReferenceRow {
  readonly id: string;
  readonly board_id: string;
}

export async function lookupOnboardingStageReferenceInTransaction(
  client: PoolClient,
  input: { readonly organizationId: string; readonly stageTokenSha256: string }
): Promise<{ readonly stageId: string; readonly boardId: string } | null> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const tokenSha256 = Sha256HexSchema.parse(input.stageTokenSha256);
  const result = await client.query<StageReferenceRow>(
    `select id,board_id from onboarding_browser_stages
      where organization_id=$1 and state='active' and expires_at>transaction_timestamp()
        and boardagent_constant_time_sha256_equal(stage_token_sha256,$2)`,
    [organizationId, Buffer.from(tokenSha256, "hex")]
  );
  if (result.rows.length === 0) return null;
  if (result.rows.length !== 1) throw new Error("onboarding stage token is not unique");
  return { stageId: result.rows[0]!.id, boardId: result.rows[0]!.board_id };
}

interface CandidateRow {
  readonly stage_id: string;
  readonly organization_id: string;
  readonly organization_display_name: string;
  readonly board_id: string;
  readonly board_name: string;
  readonly member_id: string;
  readonly member_display_name: string;
  readonly member_kind: "human" | "ai_system";
  readonly accountable_principal_id: string | null;
  readonly session_id: string;
  readonly client_id: string;
  readonly token_jti: string;
  readonly seat_role: "voting_member" | "management" | "observer";
  readonly terms_version_id: string;
  readonly terms_version: number;
  readonly terms_schema_version: string;
  readonly terms_canonical_text: string;
  readonly terms_sha256: string;
  readonly support_version_id: string;
  readonly support_version: number;
  readonly support_name: string;
  readonly support_contact_methods: unknown;
  readonly support_sha256: string;
  readonly presentation_choice: string;
  readonly local_memory_choice: string;
  readonly expires_at: Date;
}

export interface OnboardingBrowserCandidate {
  readonly stageId: string;
  readonly organizationId: string;
  readonly organizationDisplayName: string;
  readonly boardId: string;
  readonly boardName: string;
  readonly memberId: string;
  readonly memberDisplayName: string;
  readonly memberKind: "human" | "ai_system";
  readonly accountablePrincipalId: string | null;
  readonly sessionId: string;
  readonly clientId: string;
  readonly tokenJti: string;
  readonly seatRole: "voting_member" | "management" | "observer";
  readonly terms: {
    readonly versionId: string;
    readonly version: number;
    readonly schemaVersion: string;
    readonly canonicalText: string;
    readonly sha256: string;
  };
  readonly secretarySupport: {
    readonly versionId: string;
    readonly version: number;
    readonly name: string;
    readonly contactMethods: readonly JsonValue[];
    readonly sha256: string;
  };
  readonly presentationChoice: string;
  readonly localMemoryChoice: string;
  readonly expiresAt: string;
}

export async function lookupOnboardingStageInTransaction(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly boardId: string;
    readonly stageId: string;
    readonly stageTokenSha256: string;
  }
): Promise<OnboardingBrowserCandidate | null> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const stageId = UuidV7Schema.parse(input.stageId);
  const tokenSha256 = Sha256HexSchema.parse(input.stageTokenSha256);
  const result = await client.query<CandidateRow>(
    `select stage.id as stage_id,stage.organization_id,organization.display_name as organization_display_name,
            stage.board_id,board.name as board_name,stage.member_id,
            member.display_name as member_display_name,member.member_kind,
            member.accountable_principal_id,stage.session_id,stage.client_id,stage.token_jti,
            membership.seat_role,
            terms.id as terms_version_id,terms.version as terms_version,
            terms.schema_version as terms_schema_version,
            terms.canonical_text as terms_canonical_text,
            encode(terms.canonical_sha256,'hex') as terms_sha256,
            support.id as support_version_id,support.version as support_version,
            support.support_name, support.contact_methods as support_contact_methods,
            encode(support.canonical_sha256,'hex') as support_sha256,
            stage.presentation_choice,stage.local_memory_choice,stage.expires_at
       from onboarding_browser_stages as stage
       join organizations as organization on organization.id=stage.organization_id
       join boards as board on board.id=stage.board_id and board.organization_id=stage.organization_id
       join members as member on member.id=stage.member_id
        and member.organization_id=stage.organization_id and member.state='active'
       join board_memberships as membership on membership.organization_id=stage.organization_id
        and membership.board_id=stage.board_id and membership.member_id=stage.member_id
        and membership.state='active' and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
       join onboarding_terms_versions as terms on terms.id=stage.terms_version_id
        and terms.organization_id=stage.organization_id and terms.seat_role=membership.seat_role
       join secretary_support_versions as support on support.id=stage.support_version_id
        and support.organization_id=stage.organization_id and support.board_id=stage.board_id
       join access_token_records as token_record on token_record.id=stage.access_token_record_id
        and token_record.organization_id=stage.organization_id
        and token_record.member_id=stage.member_id and token_record.client_id=stage.client_id
        and token_record.jti=stage.token_jti and token_record.session_id=stage.session_id
        and token_record.revoked_at is null and token_record.expires_at>transaction_timestamp()
       join auth_sessions as session on session.id=stage.session_id
        and session.organization_id=stage.organization_id and session.member_id=stage.member_id
        and session.client_id=stage.client_id and session.state='authenticated'
        and session.expires_at>transaction_timestamp()
      where stage.id=$1 and stage.organization_id=$2 and stage.board_id=$3
        and stage.state='active' and stage.expires_at>transaction_timestamp()
        and board.state='active'
        and not boardagent_member_board_recused(stage.board_id,stage.member_id)
        and boardagent_constant_time_sha256_equal(stage.stage_token_sha256,$4)
        and terms.id=(select current_terms.id from onboarding_terms_versions as current_terms
                       where current_terms.organization_id=stage.organization_id
                         and current_terms.seat_role=membership.seat_role
                         and current_terms.effective_at<=transaction_timestamp()
                       order by current_terms.version desc limit 1)
        and support.id=(select current_support.id from secretary_support_versions as current_support
                         where current_support.organization_id=stage.organization_id
                           and current_support.board_id=stage.board_id
                           and current_support.effective_at<=transaction_timestamp()
                         order by current_support.version desc limit 1)
        and exists (
          select 1 from boardagent_resolve_access_token(stage.token_jti) as active
           where active.token_record_id=stage.access_token_record_id
             and active.member_id=stage.member_id and active.internal_client_id=stage.client_id
             and stage.board_id::text=any(active.board_ids)
             and 'onboarding:read'=any(active.scope_set)
        )
        and not exists (
          select 1 from onboarding_attestations as attestation
           where attestation.member_id=stage.member_id and attestation.board_id=stage.board_id
             and attestation.terms_version_id=stage.terms_version_id
             and attestation.support_version_id=stage.support_version_id
        )`,
    [stageId, organizationId, boardId, Buffer.from(tokenSha256, "hex")]
  );
  if (result.rows.length === 0) return null;
  if (result.rows.length !== 1) throw new Error("onboarding browser candidate is not unique");
  const row = result.rows[0]!;
  const contactMethods = z.array(JsonValueSchema).max(32).parse(row.support_contact_methods);
  return {
    stageId: UuidV7Schema.parse(row.stage_id),
    organizationId: UuidV7Schema.parse(row.organization_id),
    organizationDisplayName: z.string().min(1).max(512).parse(row.organization_display_name),
    boardId: UuidV7Schema.parse(row.board_id),
    boardName: z.string().min(1).max(512).parse(row.board_name),
    memberId: UuidV7Schema.parse(row.member_id),
    memberDisplayName: z.string().min(1).max(512).parse(row.member_display_name),
    memberKind: row.member_kind,
    accountablePrincipalId:
      row.accountable_principal_id === null
        ? null
        : UuidV7Schema.parse(row.accountable_principal_id),
    sessionId: UuidV7Schema.parse(row.session_id),
    clientId: UuidV7Schema.parse(row.client_id),
    tokenJti: UuidV7Schema.parse(row.token_jti),
    seatRole: row.seat_role,
    terms: {
      versionId: UuidV7Schema.parse(row.terms_version_id),
      version: z.number().int().positive().parse(row.terms_version),
      schemaVersion: z.literal("boardagent.onboarding-terms.v1").parse(row.terms_schema_version),
      canonicalText: z.string().min(1).max(1_048_576).parse(row.terms_canonical_text),
      sha256: Sha256HexSchema.parse(row.terms_sha256)
    },
    secretarySupport: {
      versionId: UuidV7Schema.parse(row.support_version_id),
      version: z.number().int().positive().parse(row.support_version),
      name: z.string().min(1).max(512).parse(row.support_name),
      contactMethods,
      sha256: Sha256HexSchema.parse(row.support_sha256)
    },
    presentationChoice: z.string().min(1).max(2048).parse(row.presentation_choice),
    localMemoryChoice: z.string().min(1).max(2048).parse(row.local_memory_choice),
    expiresAt: z.date().parse(row.expires_at).toISOString()
  };
}

export type CompleteOnboardingAttestationResult =
  | { readonly completed: false }
  | {
      readonly completed: true;
      readonly attestationId: string;
      readonly auditEventId: string;
      readonly auditSequence: string;
    };

export async function completeOnboardingAttestationInTransaction(
  client: PoolClient,
  rawInput: CompleteOnboardingAttestationInput
): Promise<CompleteOnboardingAttestationResult> {
  const input = CompleteOnboardingAttestationInputSchema.parse(rawInput);
  const scope = await client.query<{ transaction_scope: string | null }>(
    "select current_setting('boardagent.transaction_scope',true) as transaction_scope"
  );
  if (scope.rows[0]?.transaction_scope !== "identity") {
    throw new Error("onboarding completion requires a managed identity transaction");
  }
  const locked = await client.query<{ id: string }>(
    `select id from onboarding_browser_stages
      where id=$1 and organization_id=$2 and board_id=$3 and member_id=$4 and session_id=$5
        and state='active' and expires_at>transaction_timestamp()
        and boardagent_constant_time_sha256_equal(stage_token_sha256,$6)
      for update`,
    [
      input.stageId,
      input.organizationId,
      input.boardId,
      input.memberId,
      input.sessionId,
      Buffer.from(input.stageTokenSha256, "hex")
    ]
  );
  if (locked.rows.length !== 1) return { completed: false };
  const candidate = await lookupOnboardingStageInTransaction(client, {
    organizationId: input.organizationId,
    boardId: input.boardId,
    stageId: input.stageId,
    stageTokenSha256: input.stageTokenSha256
  });
  if (
    !candidate ||
    candidate.memberId !== input.memberId ||
    candidate.sessionId !== input.sessionId
  ) {
    return { completed: false };
  }
  const passkey = await client.query<{
    challenge_member_id: string | null;
    credential_member_id: string;
  }>(
    `select challenge.member_id as challenge_member_id,
            credential.member_id as credential_member_id
       from webauthn_challenges as challenge
       join webauthn_credentials as credential on credential.id=$2
        and credential.organization_id=challenge.organization_id and credential.state='active'
      where challenge.id=$1 and challenge.organization_id=$3
        and challenge.session_id=$4 and challenge.purpose='recent_auth'
        and challenge.consumed_at is null and challenge.expires_at>transaction_timestamp()`,
    [input.webauthnChallengeId, input.webauthnCredentialId, input.organizationId, input.sessionId]
  );
  const proof = passkey.rows[0];
  if (
    !proof ||
    proof.credential_member_id !== input.memberId ||
    (proof.challenge_member_id !== null && proof.challenge_member_id !== input.memberId)
  ) {
    return { completed: false };
  }

  const attestation = await client.query(
    `insert into onboarding_attestations(
       id,organization_id,member_id,board_id,terms_version_id,support_version_id,
       presentation_choice,local_memory_choice,consent_record_id,onboarding_browser_stage_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,null,$9)
     on conflict (member_id,board_id,terms_version_id,support_version_id) do nothing`,
    [
      input.attestationId,
      input.organizationId,
      input.memberId,
      input.boardId,
      candidate.terms.versionId,
      candidate.secretarySupport.versionId,
      candidate.presentationChoice,
      candidate.localMemoryChoice,
      input.stageId
    ]
  );
  if (attestation.rowCount !== 1) return { completed: false };

  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.auditEventId,
        eventType: "onboarding_attested",
        actorMemberId: input.memberId,
        actorClientId: candidate.clientId,
        tokenJti: candidate.tokenJti,
        entityType: "onboarding_attestation",
        entityId: input.attestationId,
        boardId: input.boardId,
        origin: "browser",
        details: {
          stageId: input.stageId,
          memberId: input.memberId,
          memberKind: candidate.memberKind,
          accountablePrincipalId: candidate.accountablePrincipalId,
          termsVersionId: candidate.terms.versionId,
          termsSha256: candidate.terms.sha256,
          supportVersionId: candidate.secretarySupport.versionId,
          supportSha256: candidate.secretarySupport.sha256,
          presentationChoice: candidate.presentationChoice,
          localMemoryChoice: candidate.localMemoryChoice,
          webauthnCredentialId: input.webauthnCredentialId,
          passkeyUserVerified: true,
          comprehensionClaimed: false
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("onboarding attestation audit event was not appended");

  const pending = await client.query<{
    id: string;
    entitlement_generation: string;
  }>(
    `select id,entitlement_generation::text from pending_action_feed
      where organization_id=$1 and board_id=$2 and member_id=$3
        and action_type='complete_onboarding' and object_type='member' and object_id=$3
        and state='pending'
      order by feed_sequence for update`,
    [input.organizationId, input.boardId, input.memberId]
  );
  if (pending.rows.length > 1) {
    throw new Error("onboarding completion found duplicate pending actions");
  }
  const pendingAction = pending.rows[0];
  if (pendingAction) {
    const resolved = await client.query(
      `update pending_action_feed set state='resolved',resolved_at=transaction_timestamp()
        where id=$1 and state='pending'`,
      [pendingAction.id]
    );
    if (resolved.rowCount !== 1) throw new Error("onboarding pending action was not resolved");
    const sequence = await client.query<{ next_sequence: string }>(
      `select (greatest(
          coalesce((select max(feed_sequence) from pending_action_feed
                    where member_id=$1 and board_id=$2 and entitlement_generation=$3),0),
          coalesce((select max(feed_sequence) from feed_tombstones
                    where member_id=$1 and board_id=$2 and entitlement_generation=$3),0)
        )+1)::text as next_sequence`,
      [input.memberId, input.boardId, pendingAction.entitlement_generation]
    );
    const nextSequence = sequence.rows[0]?.next_sequence;
    if (!nextSequence) throw new Error("onboarding tombstone sequence is unavailable");
    const tombstoneSha256 = canonicalSha256({
      schemaVersion: "boardagent.feed-tombstone.v1",
      memberId: input.memberId,
      boardId: input.boardId,
      removedFeedId: pendingAction.id,
      objectType: "member",
      objectId: input.memberId,
      reasonClass: "resolved",
      sequence: nextSequence,
      attestationId: input.attestationId
    });
    await client.query(
      `insert into feed_tombstones(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,$7,'member',$4,'resolved',$8,$9)`,
      [
        input.tombstoneId,
        input.organizationId,
        input.boardId,
        input.memberId,
        pendingAction.entitlement_generation,
        nextSequence,
        pendingAction.id,
        Buffer.from(tombstoneSha256, "hex"),
        audit.eventId
      ]
    );
  }
  const stage = await client.query(
    `update onboarding_browser_stages
        set state='completed',completed_at=transaction_timestamp(),attested_audit_event_id=$2
      where id=$1 and state='active'`,
    [input.stageId, audit.eventId]
  );
  if (stage.rowCount !== 1) throw new Error("onboarding stage completion failed");
  return {
    completed: true,
    attestationId: input.attestationId,
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}
