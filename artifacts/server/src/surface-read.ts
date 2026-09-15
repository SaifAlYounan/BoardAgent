import { loadAdmittedExportStatus } from "./export-status-projection.js";
import { loadAdmittedWhoami, loadAdmittedOnboarding } from "./identity-onboarding-projection.js";
import { reserveFixedRead } from "./fixed-read-projection.js";
import { loadAdmittedResumeDraft } from "./draft-resume-projection.js";
import { loadAdmittedGovernanceList } from "./governance-list-projection.js";
import { loadAdmittedDocumentMetadata } from "./document-metadata-projection.js";
import {
  loadAdmittedBoardVotePage,
  loadAdmittedProxyStatus,
  loadAdmittedVoteLineage
} from "./board-vote-read-projection.js";
import { loadAdmittedMeetingList } from "./meeting-list-projection.js";
import { loadAdmittedAgenda, loadAdmittedAttendance } from "./meeting-tool-projection.js";
import { loadAdmittedMinutesLineage } from "./minutes-lineage-projection.js";
import { loadAdmittedGovernanceToolProjection } from "./governance-tool-projection.js";
import { loadAdmittedVoteToolProjection } from "./vote-tool-projection.js";
import { loadAdmittedMinutesToolProjection } from "./minutes-tool-projection.js";
import { loadAdmittedMinutesList } from "./minutes-list-projection.js";
import { createHash, randomBytes } from "node:crypto";
import { loadAdmittedCertificateToolProjection } from "./certificate-tool-projection.js";
import { loadAdmittedCertificateProjection } from "./certificate-projection-resource.js";
import { loadAdmittedBoardProjection } from "./board-projection-read.js";
import { loadAdmittedVoteProjection } from "./vote-projection-resource.js";
import { loadAdmittedTaskProjection } from "./task-projection-resource.js";
import { loadAdmittedTaskToolProjection } from "./task-tool-projection.js";
import { loadWithResponseAllocation, responseAllocationPlan } from "./response-allocation.js";
import { loadAdmittedTranscriptProjection } from "./transcript-projection-read.js";
import { loadAdmittedCommunicationsList } from "./communications-list-read.js";
import { loadAdmittedCanonicalVersion } from "./canonical-version-resource.js";
import { loadAdmittedGovernanceCanonicalResource } from "./governance-canonical-resource.js";
import { loadAdmittedGovernanceJson } from "./governance-json-resource.js";
import { loadAdmittedSearchProjection } from "./search-projection-read.js";
import { loadAdmittedSubmission } from "./management-submission-projection.js";
import { loadAdmittedSubmissionList } from "./management-submission-list-projection.js";
import { loadAdmittedQuestionList } from "./management-question-list-projection.js";
import { loadAdmittedManagementQuestion } from "./question-projection-read.js";

import {
  BOARDAGENT_TOOL_BY_NAME,
  BriefingCursorPayloadSchema,
  BriefingFeedPositionSchema,
  BriefingResyncInstructionSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  sha256Hex,
  toolInputSchema,
  type BriefingCursorPayload,
  type BriefingFeedPosition,
  type JsonValue
} from "@boardagent/contracts";
import { OfflineCertificateBundleSchema, verifyOfflineCertificateBundle } from "@boardagent/audit";
import {
  authorize,
  policyForMemberRead,
  policyForTool,
  type OrganizationRole,
  type Scope
} from "@boardagent/authz";
import {
  fetchDocumentVersionInTransaction,
  appendAuditEventsInTransaction,
  recordResourceFetchOutcomeInTransaction,
  verifyPersistedAuditEvidence,
  verifyPersistedVoteCertificateInTransaction,
  withRequestTransaction,
  type TransactionOptions
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import { RulesetVersionSchema } from "@boardagent/ruleset";
import type { Pool, PoolClient } from "pg";
import { z } from "zod";

import { createCursorCodec, type CursorCodec } from "./cursor.js";
import { attachPreparedResource } from "./resource-delivery.js";
import type { SurfacePrincipal, SurfaceResourceResult, SurfaceToolResult } from "./ports.js";

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);

const PageAnchorSchema = z
  .object({ at: z.string().min(1).max(64), id: z.string().uuid() })
  .strict();

const AdministrativeAnchorSchema = z
  .object({
    mode: z.enum(["mine", "organization"]),
    generation: z.string().regex(/^[0-9a-f]{64}$/u),
    at: z.string().min(1).max(64),
    id: UuidV7Schema,
    kind: z.enum(["company_admin_assignment", "company_admin_proposal", "member_admin_delegation"])
  })
  .strict();
const AdministrativePageSchema = z
  .object({
    generation: z.string().regex(/^[0-9a-f]{64}$/u),
    rows: z
      .array(
        z
          .object({
            item: z.record(z.string(), JsonValueSchema),
            at: z.string().min(1).max(64),
            id: UuidV7Schema,
            kind: AdministrativeAnchorSchema.shape.kind
          })
          .strict()
      )
      .max(101)
  })
  .strict();

interface LiveActor {
  readonly active: boolean;
  readonly onboardingCurrent: boolean;
  readonly roles: ReadonlySet<OrganizationRole>;
  readonly scopes: ReadonlySet<Scope>;
  readonly boardIds: ReadonlySet<string>;
}

interface PageRow {
  readonly item: JsonValue;
  readonly cursor_at: string;
  readonly cursor_id: string;
}

interface FeedPositionRow {
  readonly feed_sequence: string;
  readonly board_id: string;
  readonly entry_kind: "feed" | "tombstone";
  readonly entry_kind_order: number;
  readonly entry_id: string;
}

interface FeedEntryRow extends FeedPositionRow {
  readonly item: JsonValue;
}

interface MembershipGenerationRow {
  readonly board_id: string;
  readonly entitlement_generation: string;
}

const BRIEFING_LIMIT = 1_000;
const GENESIS_FEED_POSITION: BriefingFeedPosition = {
  sequence: "0",
  boardId: null,
  entryKind: null,
  entryId: null
};

interface LoadedResource {
  readonly entityType: string;
  readonly entityId: string;
  readonly boardId: string | null;
  readonly objectVersion: bigint;
  readonly mediaType: SurfaceResourceResult["media_type"];
  readonly bytes: Buffer;
}

export interface ExportChunkReader {
  readExactChunk(input: {
    readonly exportRequestId: string;
    readonly artifactId: string;
    readonly ordinal: number;
    readonly storageLocator: string;
    readonly byteLength: number;
    readonly expectedSha256: string;
  }): Promise<Uint8Array>;
}

export interface PgSurfaceReadOptions {
  readonly cursorKey: Uint8Array | string;
  readonly cursorTtlSeconds?: number;
  readonly transaction?: TransactionOptions;
  readonly exportChunks?: ExportChunkReader;
}

function json(value: unknown): JsonValue {
  return JsonValueSchema.parse(value);
}

function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new TypeError("tool input must be an object");
  }
  return value as Readonly<Record<string, JsonValue>>;
}

function jsonRecord(value: JsonValue | undefined): Readonly<Record<string, JsonValue>> | null {
  if (value === undefined || value === null || Array.isArray(value) || typeof value !== "object") {
    return null;
  }
  return value as Readonly<Record<string, JsonValue>>;
}

function requiredString(input: Readonly<Record<string, JsonValue>>, key: string): string {
  const value = input[key];
  if (typeof value !== "string") throw new TypeError(`${key} must be a string`);
  return value;
}

function nullableString(input: Readonly<Record<string, JsonValue>>, key: string): string | null {
  const value = input[key];
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") throw new TypeError(`${key} must be a string or null`);
  return value;
}

function pageLimit(input: Readonly<Record<string, JsonValue>>): number {
  const value = input["limit"];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError("limit must be a safe integer");
  }
  return value;
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  const a = [...new Set(left)].toSorted();
  const b = [...new Set(right)].toSorted();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

function result(
  tool: string,
  data: JsonValue,
  options: { readonly reference?: string | null; readonly resourceUri?: string | null } = {}
): SurfaceToolResult {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: options.reference ?? null,
    resource_uri: options.resourceUri ?? null,
    data
  };
}

function canonicalPageAnchor(value: z.infer<typeof PageAnchorSchema>): string {
  return canonicalJson(PageAnchorSchema.parse(value));
}

function feedPosition(row: FeedPositionRow): BriefingFeedPosition {
  return BriefingFeedPositionSchema.parse({
    sequence: row.feed_sequence,
    boardId: row.board_id,
    entryKind: row.entry_kind,
    entryId: row.entry_id
  });
}

function feedEntryKindOrder(kind: BriefingFeedPosition["entryKind"]): number | null {
  return kind === null ? null : kind === "feed" ? 0 : 1;
}

/**
 * PostgreSQL-backed implementation of the complete frozen read lane. Every query has a
 * fixed table/column shape and executes inside the caller's forced-RLS transaction.
 */
export class PgSurfaceReadRepository {
  private readonly cursors: CursorCodec;

  public constructor(
    private readonly pool: Pool,
    private readonly options: PgSurfaceReadOptions
  ) {
    this.cursors = createCursorCodec(options.cursorKey, options.cursorTtlSeconds);
  }

  private requestContext(principal: SurfacePrincipal) {
    return {
      organizationId: principal.organizationId,
      memberId: principal.memberId,
      clientId: principal.clientId,
      tokenJti: principal.tokenJti,
      boardIds: principal.boardIds
    } as const;
  }

  private observePreparedResource<T extends object>(
    principal: SurfacePrincipal,
    response: T,
    preparedEventId: string,
    byteLength: number
  ): T {
    const context = { ...this.requestContext(principal), boardIds: [...principal.boardIds] };
    return attachPreparedResource(response, {
      preparedEventId,
      byteLength,
      record: async (outcome) => {
        // The outcome append runs after the response, beside the burst's serializable
        // writes, which replay on conflict; without replay this append was always the
        // deadlock victim (observed under the 100-way T9 load burst). It
        // is database-only and idempotent per attempt, so it replays the same way; a
        // failure after the bounded schedule is still reported by the runtime.
        await withRequestTransaction(
          this.pool,
          context,
          (client) =>
            recordResourceFetchOutcomeInTransaction(client, {
              preparedEventId,
              outcomeEventId: newId(),
              outcome: outcome.outcome,
              bytesTransferred: outcome.bytesTransferred,
              observation: {
                basis: outcome.observationBasis,
                responseBytesQueued: outcome.responseBytesQueued
              }
            }),
          { ...this.options.transaction, retryConflicts: true }
        );
      }
    });
  }

  private async liveActor(client: PoolClient, principal: SurfacePrincipal): Promise<LiveActor> {
    const token = await client.query<{
      token_record_id: string;
      organization_id: string;
      member_id: string;
      internal_client_id: string;
      protocol_client_id: string;
      resource_uri: string;
      scope_set: string[];
      roles: string[];
      board_ids: string[];
    }>(
      `select token_record_id,organization_id,member_id,internal_client_id,
              protocol_client_id,resource_uri,scope_set,roles,board_ids
         from boardagent_resolve_access_token($1)`,
      [principal.tokenJti]
    );
    const row = token.rows[0];
    if (
      !row ||
      token.rows.length !== 1 ||
      row.token_record_id !== principal.accessTokenRecordId ||
      row.organization_id !== principal.organizationId ||
      row.member_id !== principal.memberId ||
      row.internal_client_id !== principal.clientId ||
      row.protocol_client_id !== principal.protocolClientId ||
      new URL(row.resource_uri).origin !== principal.serviceOrigin ||
      !sameSet(row.scope_set, principal.scopes) ||
      !sameSet(row.roles, principal.roles) ||
      !sameSet(row.board_ids, principal.boardIds)
    ) {
      throw new Error("authenticated context is no longer active");
    }

    const onboarding = await client.query<{ current: boolean }>(
      `select not exists (
         select 1
           from board_memberships as membership
          where membership.member_id=$1 and membership.state='active'
            and membership.active_from<=transaction_timestamp()
            and (membership.active_until is null or membership.active_until>transaction_timestamp())
            and not exists (
              select 1
                from onboarding_attestations as attestation
               where attestation.member_id=membership.member_id
                 and attestation.board_id=membership.board_id
                 and attestation.terms_version_id=(
                   select terms.id from onboarding_terms_versions as terms
                    where terms.organization_id=membership.organization_id
                      and terms.seat_role=membership.seat_role
                      and terms.effective_at<=transaction_timestamp()
                    order by terms.version desc limit 1
                 )
                 and attestation.support_version_id=(
                   select support.id from secretary_support_versions as support
                    where support.organization_id=membership.organization_id
                      and support.board_id=membership.board_id
                      and support.effective_at<=transaction_timestamp()
                    order by support.version desc limit 1
                 )
            )
       ) as current`,
      [principal.memberId]
    );
    const roleValues = row.roles.filter((role): role is OrganizationRole =>
      ["admin", "secretariat", "management", "member", "observer"].includes(role)
    );
    const scopeValues = row.scope_set.filter((scope): scope is Scope =>
      [
        "governance:read",
        "documents:read",
        "vote:act",
        "proxy:manage",
        "minutes:act",
        "member:propose",
        "secretariat:admin",
        "audit:read",
        "meeting:act",
        "task:act",
        "documents:contribute",
        "secretariat:message",
        "management:question",
        "notifications:manage",
        "onboarding:read"
      ].includes(scope)
    );
    return {
      active: true,
      onboardingCurrent: onboarding.rows[0]?.current === true,
      roles: new Set(roleValues),
      scopes: new Set(scopeValues),
      boardIds: new Set(row.board_ids)
    };
  }

  private authorizeRead(
    principal: SurfacePrincipal,
    actor: LiveActor,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): void {
    const policy =
      tool === "get_member"
        ? policyForMemberRead(principal.memberId, requiredString(input, "member_id"))
        : policyForTool(tool);
    const boardId = typeof input["board_id"] === "string" ? input["board_id"] : null;
    // Organization discovery has its own exact org/board SQL boundary. An
    // administrator need not hold a board seat to inspect that board's grants.
    const organizationAdministrativeRead =
      actor.roles.has("admin") &&
      ((tool === "list_administrative_access" && input["mode"] === "organization") ||
        // This pure validator reads only the caller's submitted draft, no board records.
        tool === "validate_ruleset_draft");
    const decision = authorize(
      {
        memberId: principal.memberId,
        active: actor.active,
        onboardingCurrent: actor.onboardingCurrent,
        roles: actor.roles,
        scopes: actor.scopes,
        memberBoardIds: actor.boardIds
      },
      {
        boardId: organizationAdministrativeRead ? null : boardId,
        ownerMemberId: principal.memberId,
        visible: true,
        recused: false,
        terminal: false
      },
      policy
    );
    if (!decision.allowed) throw new Error(`authorization denied: ${decision.reason}`);
  }

  private anchor(
    principal: SurfacePrincipal,
    tool: string,
    boardId: string | null,
    wire: string | null
  ): z.infer<typeof PageAnchorSchema> | null {
    if (wire === null) return null;
    const raw = this.cursors.verify(wire, {
      organizationId: principal.organizationId,
      memberId: principal.memberId,
      tool,
      boardId
    });
    return PageAnchorSchema.parse(JSON.parse(raw));
  }

  private page(
    principal: SurfacePrincipal,
    tool: string,
    boardId: string | null,
    rows: readonly PageRow[],
    limit: number
  ): JsonValue {
    const hasMore = rows.length > limit;
    const selected = rows.slice(0, limit);
    const last = selected.at(-1);
    return {
      items: selected.map(({ item }) => item),
      next_cursor:
        hasMore && last
          ? this.cursors.mint(
              {
                organizationId: principal.organizationId,
                memberId: principal.memberId,
                tool,
                boardId
              },
              canonicalPageAnchor({ at: last.cursor_at, id: last.cursor_id })
            )
          : null
    };
  }

  public async executeRead(
    principal: SurfacePrincipal,
    tool: string,
    rawInput: JsonValue
  ): Promise<SurfaceToolResult> {
    const registry = BOARDAGENT_TOOL_BY_NAME.get(tool);
    if (!registry || registry.class !== "R") throw new Error("unregistered read tool");
    const input = record(json(toolInputSchema(tool).parse(rawInput)));
    return withRequestTransaction(
      this.pool,
      this.requestContext(principal),
      async (client) => {
        const actor = await this.liveActor(client, principal);
        this.authorizeRead(principal, actor, tool, input);
        return this.dispatch(client, principal, tool, input);
      },
      this.options.transaction
    );
  }

  private async dispatch(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    switch (tool) {
      case "list_administrative_access":
        return this.listAdministrativeAccess(client, principal, tool, input);
      case "whoami":
        return this.whoami(client, principal);
      case "list_my_boards":
        return this.listBoards(client, principal, tool, input);
      case "get_board":
        return this.getBoard(client, principal, tool, requiredString(input, "board_id"));
      case "get_my_board_snapshot":
        return this.getBoardSnapshot(client, principal, requiredString(input, "board_id"));
      case "list_my_updates":
      case "list_pending_actions":
        return this.listFeed(client, principal, tool, input);
      case "get_onboarding":
      case "get_onboarding_status":
        return this.getOnboarding(client, principal, tool, requiredString(input, "board_id"));
      case "get_board_governance_profile":
      case "list_approval_rule_templates":
      case "list_matter_types":
      case "get_ruleset":
      case "list_ruleset_versions":
      case "validate_ruleset_draft":
        return this.readRules(client, principal, tool, input);
      case "list_documents":
      case "search_documents":
      case "get_document_hash":
      case "list_document_versions":
      case "get_document_validation_status":
        return this.readDocumentMetadata(client, principal, tool, input);
      case "read_document":
        return this.readDocument(client, principal, input);
      case "list_management_submissions":
      case "get_management_submission":
        return this.readSubmission(client, principal, tool, input);
      case "list_management_questions":
      case "get_management_question":
        return this.readQuestion(client, principal, tool, input);
      case "list_meetings":
      case "get_agenda":
      case "get_attendance":
      case "list_meeting_transcripts":
      case "get_meeting_transcript":
        return this.readMeeting(client, principal, tool, input);
      case "list_votes":
      case "get_vote":
      case "get_vote_lineage":
      case "get_proxy_status":
      case "get_vote_certificate":
      case "verify_certificate":
        return this.readVote(client, principal, tool, input);
      case "get_minutes":
      case "list_minutes_versions":
      case "get_minutes_lineage":
      case "list_minutes_review_items":
        return this.readMinutes(client, principal, tool, input);
      case "list_my_tasks":
      case "list_action_items":
      case "get_task":
      case "get_action_item":
        return this.readTask(client, principal, tool, input);
      case "list_proposals":
      case "list_secretariat_requests":
        return this.readCommunications(client, principal, tool, input);
      case "list_members":
      case "get_member":
      case "list_enrollments":
      case "list_my_sessions":
      case "list_oauth_clients":
        return this.readIdentity(client, principal, tool, input);
      case "verify_audit_chain":
      case "get_export_status":
      case "read_export_chunk":
      case "get_retention_policy":
      case "list_my_webhooks":
        return this.readOperations(client, principal, tool, input);
      case "list_my_drafts":
      case "resume_draft":
        return this.readDraft(client, principal, tool, input);
      default:
        throw new Error(`read tool has no fixed dispatcher: ${tool}`);
    }
  }

  private async listAdministrativeAccess(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    const mode = requiredString(input, "mode");
    const boardId = nullableString(input, "board_id");
    const limit = pageLimit(input);
    const wire = nullableString(input, "cursor");
    const binding = {
      organizationId: principal.organizationId,
      memberId: principal.memberId,
      tool,
      boardId
    };
    const anchor =
      wire === null
        ? null
        : AdministrativeAnchorSchema.parse(JSON.parse(this.cursors.verify(wire, binding)));
    if (anchor !== null && anchor.mode !== mode)
      throw new Error("administrative cursor is invalid");
    const query = await client.query<{ page: unknown }>(
      "select boardagent_administrative_access_page($1,$2,$3,$4) as page",
      [mode, boardId, limit, anchor]
    );
    const page = AdministrativePageSchema.parse(query.rows[0]?.page);
    const selected = page.rows.slice(0, limit);
    const last = selected.at(-1);
    return result(tool, {
      items: selected.map((row) => row.item),
      next_cursor:
        page.rows.length > limit && last
          ? this.cursors.mint(
              binding,
              canonicalJson(
                AdministrativeAnchorSchema.parse({
                  mode,
                  generation: page.generation,
                  at: last.at,
                  id: last.id,
                  kind: last.kind
                })
              )
            )
          : null
    });
  }

  private async whoami(
    client: PoolClient,
    principal: SurfacePrincipal
  ): Promise<SurfaceToolResult> {
    const rows = await loadAdmittedWhoami(client, principal);
    const view = rows[0]?.view;
    if (!view) throw new Error("identity unavailable");
    return result("whoami", view, { reference: principal.memberId });
  }

  private async listBoards(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    const limit = pageLimit(input);
    const anchor = this.anchor(principal, tool, null, nullableString(input, "cursor"));
    const rows = await loadAdmittedBoardVotePage(client, {
      kind: "boards",
      selectorId: principal.memberId,
      at: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      take: limit + 1
    });
    return result(tool, this.page(principal, tool, null, rows, limit));
  }

  private async getBoard(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    boardId: string
  ): Promise<SurfaceToolResult> {
    const found = await loadAdmittedBoardProjection(client, boardId, "tool");
    const board = found?.payload ?? null;
    const response = result(tool, { board }, { reference: boardId });
    if (board !== null) {
      const metadata = record(board);
      const canonicalBoardId = requiredString(metadata, "board_id");
      // Bind exactly this tool's metadata projection. resources/read has its own
      // projection; their hashes are not interchangeable. Transport completion is
      // not observable here, so this read records only response preparation.
      const bytes = this.resourceJson(board);
      const preparedEventId = await this.prepareResourceAudit(
        client,
        principal,
        new URL(`board://${canonicalBoardId}`),
        {
          entityType: "board",
          entityId: canonicalBoardId,
          boardId: canonicalBoardId,
          objectVersion: BigInt(requiredString(metadata, "row_version")),
          mediaType: "application/json",
          bytes
        }
      );
      return this.observePreparedResource(principal, response, preparedEventId, bytes.byteLength);
    }
    return response;
  }

  private async getBoardSnapshot(
    client: PoolClient,
    principal: SurfacePrincipal,
    boardId: string
  ): Promise<SurfaceToolResult> {
    const found = await client.query<{ view: JsonValue }>(
      `select jsonb_build_object(
          'board_id',board.id,'name',board.name,'timezone',board.timezone,'state',board.state,
          'row_version',board.row_version::text,
          'entitlement_generation',membership.entitlement_generation::text,
          'resources',jsonb_strip_nulls(jsonb_build_object(
             'board','board://' || board.id::text,
             'governance_profile',case when profile.id is null then null else
               'board://' || board.id::text || '/governance-profile/' || profile.version::text end,
             'ruleset',case when ruleset.id is null then null else
               'board://' || board.id::text || '/rulesets/' || ruleset.version::text end
          )),
          'feed_high_watermark',coalesce((
             select max(feed.feed_sequence)::text from pending_action_feed as feed
              where feed.board_id=board.id and feed.member_id=$2
          ),'0')
        ) as view
       from boards as board
       join board_memberships as membership
         on membership.board_id=board.id and membership.member_id=$2 and membership.state='active'
       left join governance_profiles as profile on profile.id=board.current_governance_profile_id
       left join rulesets as ruleset on ruleset.id=board.current_ruleset_id
      where board.id=$1`,
      [boardId, principal.memberId]
    );
    return result(
      "get_my_board_snapshot",
      { snapshot: found.rows[0]?.view ?? null },
      {
        reference: boardId,
        resourceUri: found.rows[0] ? `board://${boardId}` : null
      }
    );
  }

  private feedCursorBinding(principal: SurfacePrincipal, tool: string) {
    return {
      organizationId: principal.organizationId,
      memberId: principal.memberId,
      tool,
      boardId: null
    } as const;
  }

  private decodeBriefingCursor(
    principal: SurfacePrincipal,
    tool: string,
    wire: string
  ): BriefingCursorPayload {
    const raw = this.cursors.verify(wire, this.feedCursorBinding(principal, tool));
    try {
      const parsed = BriefingCursorPayloadSchema.parse(JSON.parse(raw) as unknown);
      if (parsed.memberId !== principal.memberId || canonicalJson(parsed) !== raw) {
        throw new Error("cursor is invalid");
      }
      return parsed;
    } catch {
      throw new Error("cursor is invalid");
    }
  }

  private mintBriefingCursor(
    principal: SurfacePrincipal,
    tool: string,
    entitlementSetSha256: string,
    position: BriefingFeedPosition,
    mode: BriefingCursorPayload["mode"]
  ): string {
    const payload = BriefingCursorPayloadSchema.parse({
      schemaVersion: "boardagent.briefing-cursor.v2",
      memberId: principal.memberId,
      entitlementSetSha256,
      position,
      mode
    });
    return this.cursors.mint(this.feedCursorBinding(principal, tool), canonicalJson(payload));
  }

  private async entitlementSetSha256(client: PoolClient, memberId: string): Promise<string> {
    const memberships = await client.query<MembershipGenerationRow>(
      `select membership.board_id,membership.entitlement_generation::text
         from board_memberships as membership
        where membership.member_id=$1
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null
               or membership.active_until>transaction_timestamp())
        order by membership.board_id`,
      [memberId]
    );
    return canonicalSha256({
      schemaVersion: "boardagent.entitlement-set.v1",
      memberId,
      memberships: memberships.rows.map((membership) => ({
        boardId: membership.board_id,
        entitlementGeneration: membership.entitlement_generation
      }))
    });
  }

  private async feedHighWatermark(
    client: PoolClient,
    memberId: string
  ): Promise<BriefingFeedPosition> {
    const high = await client.query<FeedPositionRow>(
      `select sync.change_sequence::text as feed_sequence,sync.board_id,sync.entry_kind,
              case when sync.entry_kind='feed' then 0 else 1 end as entry_kind_order,
              sync.entry_id
         from member_feed_sync_positions as sync where sync.member_id=$1
        order by sync.change_sequence desc limit 1`,
      [memberId]
    );
    const row = high.rows[0];
    return row ? feedPosition(row) : GENESIS_FEED_POSITION;
  }

  private async readFeedEntries(
    client: PoolClient,
    memberId: string,
    position: BriefingFeedPosition,
    options: {
      readonly limit: number;
      readonly pendingOnly: boolean;
      readonly tombstonesOnly?: boolean;
    }
  ): Promise<readonly FeedEntryRow[]> {
    const rows = await client.query<FeedEntryRow>(
      `with entries as materialized (
         select jsonb_build_object(
                  'entry_kind','feed',
                  'feed_sequence',feed.feed_sequence::text,'board_id',feed.board_id,
                  'action_type',feed.action_type,'object_type',feed.object_type,
                  'object_id',feed.object_id,'object_version',feed.object_version::text,
                  'state',feed.state,
                  'payload',convert_from(feed.canonical_payload,'UTF8')::jsonb,
                  'payload_sha256',encode(feed.payload_sha256,'hex'),
                  'created_at',to_char(feed.created_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                  'resolved_at',case when feed.resolved_at is null then null else
                    to_char(feed.resolved_at at time zone 'UTC',
                      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
                ) as item,
                sync.change_sequence as feed_sequence,feed.board_id,0 as entry_kind_order,
                'feed'::text as entry_kind,feed.id as entry_id
           from pending_action_feed as feed
           join member_feed_sync_positions as sync on sync.feed_id=feed.id
          where feed.member_id=$1 and (not $6::boolean or feed.state='pending')
            and (feed.object_type<>'vote' or (
              not boardagent_member_vote_recused(feed.object_id,$1)
              and not exists (select 1 from vote_supersessions as linked
                where (linked.old_vote_id=feed.object_id or linked.new_vote_id=feed.object_id)
                  and (convert_from(feed.canonical_payload,'UTF8')::jsonb
                    ->'safeRefs'->>'oldVoteId')=linked.old_vote_id::text
                  and (convert_from(feed.canonical_payload,'UTF8')::jsonb
                    ->'safeRefs'->>'newVoteId')=linked.new_vote_id::text
                  and (boardagent_member_vote_recused(linked.old_vote_id,$1)
                    or boardagent_member_vote_recused(linked.new_vote_id,$1)))))
         union all
         select jsonb_build_object(
                  'entry_kind','tombstone',
                  'feed_sequence',tombstone.feed_sequence::text,
                  'board_id',tombstone.board_id,
                  'action_type','tombstone','object_type',tombstone.object_type,
                  'object_id',tombstone.object_id,
                  'object_version',removed.object_version::text,
                  'state','resolved',
                  'payload',jsonb_build_object(
                    'schemaVersion','boardagent.feed-tombstone.v1',
                    'reasonClass',tombstone.reason_class,
                    'removedFeedId',tombstone.removed_feed_id
                  ),
                  'payload_sha256',encode(tombstone.tombstone_sha256,'hex'),
                  'created_at',to_char(tombstone.created_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                  'resolved_at',to_char(tombstone.created_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
                ) as item,
                sync.change_sequence as feed_sequence,tombstone.board_id,1 as entry_kind_order,
                'tombstone'::text as entry_kind,tombstone.id as entry_id
           from feed_tombstones as tombstone
           join member_feed_sync_positions as sync on sync.tombstone_id=tombstone.id
           left join pending_action_feed as removed on removed.id=tombstone.removed_feed_id
          where tombstone.member_id=$1
       )
       select entries.item,entries.feed_sequence::text,entries.board_id,entries.entry_kind,
              entries.entry_kind_order,entries.entry_id
         from entries
        where (
          $2::bigint=0
          or feed_sequence>$2::bigint
          or (feed_sequence=$2::bigint and board_id>$3::uuid)
          or (feed_sequence=$2::bigint and board_id=$3::uuid
              and entry_kind_order>$4::integer)
          or (feed_sequence=$2::bigint and board_id=$3::uuid
              and entry_kind_order=$4::integer and entry_id>$5::uuid)
        )
          and (not $8::boolean or entry_kind='tombstone')
        order by entries.feed_sequence,entries.board_id,entries.entry_kind_order,entries.entry_id
        limit $7`,
      [
        memberId,
        position.sequence,
        position.boardId,
        feedEntryKindOrder(position.entryKind),
        position.entryId,
        options.pendingOnly,
        options.limit,
        options.tombstonesOnly ?? false
      ]
    );
    return rows.rows;
  }

  private briefingResync(
    principal: SurfacePrincipal,
    tool: string,
    reason: "briefing_overflow" | "entitlement_changed" | "cursor_version_changed",
    entitlementSetSha256: string,
    position: BriefingFeedPosition
  ) {
    return BriefingResyncInstructionSchema.parse({
      schema_version: "boardagent.briefing-resync.v1",
      reason,
      resync_token: this.mintBriefingCursor(
        principal,
        tool,
        entitlementSetSha256,
        position,
        "resync"
      ),
      steps: ["list_my_boards", "get_my_board_snapshot", "list_my_updates"]
    });
  }

  private async listFeed(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    const limit = pageLimit(input);
    const pendingOnly = tool === "list_pending_actions";
    if (pendingOnly && limit !== BRIEFING_LIMIT) {
      throw new Error("daily briefing limit must be exactly 1000");
    }
    const entitlementSetSha256 = await this.entitlementSetSha256(client, principal.memberId);
    const wire = nullableString(input, "cursor");
    const cursor =
      wire === null
        ? BriefingCursorPayloadSchema.parse({
            schemaVersion: "boardagent.briefing-cursor.v2",
            memberId: principal.memberId,
            entitlementSetSha256,
            position: GENESIS_FEED_POSITION,
            mode: "delta"
          })
        : this.decodeBriefingCursor(principal, tool, wire);
    const highWatermark = await this.feedHighWatermark(client, principal.memberId);

    if (cursor.schemaVersion !== "boardagent.briefing-cursor.v2") {
      // Per-board v1 positions cannot be translated to a cross-board change
      // order. Explicitly restart synchronization rather than silently skip data.
      return result(tool, {
        status: "cursor_resync_required",
        items: [],
        next_cursor: null,
        resync: this.briefingResync(
          principal,
          tool,
          "cursor_version_changed",
          entitlementSetSha256,
          GENESIS_FEED_POSITION
        )
      });
    }

    if (cursor.entitlementSetSha256 !== entitlementSetSha256) {
      const tombstones = await this.readFeedEntries(client, principal.memberId, cursor.position, {
        limit: BRIEFING_LIMIT,
        pendingOnly: false,
        tombstonesOnly: true
      });
      return result(tool, {
        status: "entitlement_resync_required",
        items: tombstones.map(({ item }) => item),
        next_cursor: null,
        resync: this.briefingResync(
          principal,
          tool,
          "entitlement_changed",
          entitlementSetSha256,
          highWatermark
        )
      });
    }

    const rows = await this.readFeedEntries(client, principal.memberId, cursor.position, {
      limit: pendingOnly ? BRIEFING_LIMIT + 1 : limit + 1,
      pendingOnly
    });
    if (pendingOnly && rows.length > BRIEFING_LIMIT) {
      return result(tool, {
        status: "briefing_overflow",
        items: [],
        next_cursor: null,
        resync: this.briefingResync(
          principal,
          tool,
          "briefing_overflow",
          entitlementSetSha256,
          highWatermark
        )
      });
    }

    const hasMore = !pendingOnly && rows.length > limit;
    const selected = rows.slice(0, limit);
    const continuationPosition = hasMore
      ? feedPosition(selected.at(-1) as FeedEntryRow)
      : highWatermark;
    return result(tool, {
      status: "complete",
      items: selected.map(({ item }) => item),
      next_cursor: this.mintBriefingCursor(
        principal,
        tool,
        entitlementSetSha256,
        continuationPosition,
        "delta"
      )
    });
  }

  private async getOnboarding(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    boardId: string
  ): Promise<SurfaceToolResult> {
    const rows = await loadAdmittedOnboarding(client, boardId, principal.memberId);
    const onboarding = rows[0]?.view ?? null;
    if (tool === "get_onboarding_status") {
      const view = jsonRecord(onboarding ?? undefined);
      const terms = jsonRecord(view?.["terms"]);
      return result(tool, {
        board_id: boardId,
        status: view === null ? "unavailable" : view["attested"] === true ? "current" : "required",
        terms_version_id: terms?.["version_id"] ?? null
      });
    }
    return result(tool, { onboarding }, { reference: boardId });
  }

  private async readRules(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    const boardId = requiredString(input, "board_id");
    if (tool === "get_board_governance_profile") {
      const version = input["version"] as number | null;
      const profile = await loadAdmittedGovernanceToolProjection(client, {
        kind: "profile",
        boardId,
        version
      });
      const profileRecord = jsonRecord(profile ?? undefined);
      return result(
        tool,
        { profile },
        {
          resourceUri: profileRecord
            ? `board://${boardId}/governance-profile/${String(profileRecord["version"])}`
            : null
        }
      );
    }
    if (tool === "get_ruleset") {
      const rulesetId = nullableString(input, "ruleset_id");
      const ruleset = await loadAdmittedGovernanceToolProjection(client, {
        kind: "ruleset",
        boardId,
        rulesetId
      });
      const rulesetRecord = jsonRecord(ruleset ?? undefined);
      return result(
        tool,
        { ruleset },
        {
          reference: rulesetId,
          resourceUri: rulesetRecord
            ? `board://${boardId}/rulesets/${String(rulesetRecord["version"])}`
            : null
        }
      );
    }
    if (tool === "validate_ruleset_draft") {
      const draft = input["draft"];
      const draftRecord =
        draft && typeof draft === "object" && !Array.isArray(draft) ? draft : null;
      const checked = RulesetVersionSchema.safeParse(draftRecord?.["values"]);
      return result(tool, {
        valid: checked.success,
        issues: checked.success
          ? []
          : checked.error.issues.map((issue) => ({
              path: issue.path.map(String).join("."),
              code: issue.code,
              message: issue.message
            }))
      });
    }

    const limit = pageLimit(input);
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    if (tool === "list_ruleset_versions") {
      const rows = await loadAdmittedGovernanceList(client, {
        kind: "rulesets",
        boardId,
        cursorAt: anchor?.at ?? null,
        cursorId: anchor?.id ?? null,
        limit
      });
      return result(tool, this.page(principal, tool, boardId, rows, limit));
    }
    if (tool === "list_approval_rule_templates") {
      const rows = await loadAdmittedGovernanceList(client, {
        kind: "templates",
        boardId,
        cursorAt: anchor?.at ?? null,
        cursorId: anchor?.id ?? null,
        limit
      });
      return result(tool, this.page(principal, tool, boardId, rows, limit));
    }
    const rows = await loadAdmittedGovernanceList(client, {
      kind: "matter_types",
      boardId,
      cursorAt: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      limit
    });
    return result(tool, this.page(principal, tool, boardId, rows, limit));
  }

  private async readDocumentMetadata(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "get_document_hash") {
      const documentId = requiredString(input, "document_id");
      const versionId = requiredString(input, "version_id");
      const rows = await loadAdmittedDocumentMetadata(client, {
        kind: "hash",
        selectorId: documentId,
        versionId,
        cursorAt: null,
        cursorId: null,
        limit: 1
      });
      return result(tool, { document_hash: rows[0]?.item ?? null }, { reference: versionId });
    }
    if (tool === "get_document_validation_status") {
      const attemptId = requiredString(input, "validation_attempt_id");
      const rows = await loadAdmittedDocumentMetadata(client, {
        kind: "validation",
        selectorId: attemptId,
        versionId: null,
        cursorAt: null,
        cursorId: null,
        limit: 1
      });
      return result(tool, { validation: rows[0]?.item ?? null }, { reference: attemptId });
    }
    if (tool === "list_document_versions") {
      const documentId = requiredString(input, "document_id");
      const limit = pageLimit(input);
      const anchor = this.anchor(principal, tool, null, nullableString(input, "cursor"));
      const rows = await loadAdmittedDocumentMetadata(client, {
        kind: "versions",
        selectorId: documentId,
        versionId: null,
        cursorAt: anchor?.at ?? null,
        cursorId: anchor?.id ?? null,
        limit
      });
      return result(tool, this.page(principal, tool, null, rows, limit), { reference: documentId });
    }

    const boardId = requiredString(input, "board_id");
    const limit = pageLimit(input);
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    if (tool === "search_documents") {
      const rows = await loadAdmittedSearchProjection(client, {
        boardId,
        query: requiredString(input, "query"),
        cursorAt: anchor?.at ?? null,
        cursorId: anchor?.id ?? null,
        limit
      });
      return result(tool, this.page(principal, tool, boardId, rows, limit));
    }
    const rows = await loadAdmittedDocumentMetadata(client, {
      kind: "documents",
      selectorId: boardId,
      versionId: null,
      cursorAt: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      limit
    });
    return result(tool, this.page(principal, tool, boardId, rows, limit));
  }

  private async readDocument(
    client: PoolClient,
    principal: SurfacePrincipal,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    const documentId = requiredString(input, "document_id");
    const versionId = nullableString(input, "version_id");
    const target = await client.query<{
      board_id: string;
      id: string;
      version: number;
      byte_length: number;
      sha256: string;
      media_type: string;
    }>(
      `select document.board_id,version_row.id,version_row.version,version_row.byte_length,
              encode(version_row.sha256,'hex') as sha256,version_row.media_type
         from documents as document
         join document_versions as version_row on version_row.document_id=document.id
        where document.id=$1
          and (($2::uuid is null and version_row.id=document.current_version_id) or version_row.id=$2)
        limit 1`,
      [documentId, versionId]
    );
    const row = target.rows[0];
    if (!row) return result("read_document", { document: null }, { reference: documentId });
    const plan = responseAllocationPlan({
      kind: "document",
      representation: "tool",
      sourceId: row.id,
      sourceVersion: `${documentId}:${String(row.version)}`,
      sha256: row.sha256,
      canonicalBytes: row.byte_length
    });
    const prepared = await loadWithResponseAllocation(plan, () =>
      fetchDocumentVersionInTransaction(client, {
        organizationId: principal.organizationId,
        boardId: row.board_id,
        documentId,
        // This selected immutable (document, version) tuple must never re-resolve current_version_id.
        version: row.version,
        auditEventId: newId(),
        requestOrigin: principal.serviceOrigin
      })
    );
    if (
      prepared.documentVersionId !== row.id ||
      prepared.version !== row.version ||
      prepared.mediaType !== row.media_type ||
      prepared.byteLength !== row.byte_length ||
      prepared.canonicalBytes.length !== row.byte_length ||
      prepared.sha256 !== row.sha256 ||
      createHash("sha256").update(prepared.canonicalBytes).digest("hex") !== row.sha256
    )
      throw new Error("document version failed integrity verification");
    const body = prepared.canonicalBytes.toString("utf8");
    const response = result(
      "read_document",
      {
        document_id: prepared.documentId,
        version_id: prepared.documentVersionId,
        version: prepared.version,
        media_type: prepared.mediaType,
        document_schema: prepared.documentSchema,
        canonical_body: body,
        byte_length: prepared.byteLength,
        sha256: prepared.sha256
      },
      { reference: prepared.documentVersionId, resourceUri: prepared.resourceUri }
    );
    return this.observePreparedResource(
      principal,
      response,
      prepared.preparedEvent.eventId,
      prepared.byteLength
    );
  }

  private async readSubmission(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "get_management_submission") {
      const submissionId = requiredString(input, "submission_id");
      const submission = await loadAdmittedSubmission(client, submissionId, principal.memberId);
      return result(tool, { submission }, { reference: submissionId });
    }

    const boardId = requiredString(input, "board_id");
    const limit = pageLimit(input);
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    const rows = await loadAdmittedSubmissionList(client, {
      boardId,
      memberId: principal.memberId,
      cursorAt: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      limit
    });
    return result(tool, this.page(principal, tool, boardId, rows, limit));
  }

  private async readQuestion(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "get_management_question") {
      const questionId = requiredString(input, "question_id");
      const question = await loadAdmittedManagementQuestion(client, questionId, "tool");
      return result(
        tool,
        { question: question === null ? null : json(question) },
        {
          reference: questionId,
          resourceUri:
            question === null ? null : `board://${question.boardId}/questions/${questionId}`
        }
      );
    }
    const boardId = requiredString(input, "board_id");
    const limit = pageLimit(input);
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    const pageResult = await loadAdmittedQuestionList(client, {
      boardId,
      limit,
      ...(anchor ? { after: { createdAt: anchor.at, questionId: anchor.id } } : {})
    });
    const next = pageResult.nextCursor
      ? this.cursors.mint(
          {
            organizationId: principal.organizationId,
            memberId: principal.memberId,
            tool,
            boardId
          },
          canonicalPageAnchor({
            at: pageResult.nextCursor.createdAt,
            id: pageResult.nextCursor.questionId
          })
        )
      : null;
    return result(tool, {
      items: json(pageResult.items),
      total_visible: pageResult.totalVisible,
      next_cursor: next
    });
  }

  private async readMeeting(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "get_agenda") {
      const meetingId = requiredString(input, "meeting_id");
      const version = input["version"] as number | null;
      const found = await loadAdmittedAgenda(client, meetingId, version);
      return result(tool, { agenda: found[0]?.view ?? null }, { reference: meetingId });
    }
    if (tool === "get_attendance") {
      const meetingId = requiredString(input, "meeting_id");
      const items = await loadAdmittedAttendance(client, meetingId);
      return result(
        tool,
        { meeting_id: meetingId, records: items },
        {
          reference: meetingId
        }
      );
    }
    if (tool === "get_meeting_transcript") {
      const transcriptId = requiredString(input, "transcript_id");
      const versionId = nullableString(input, "version_id");
      const row = await loadAdmittedTranscriptProjection(client, transcriptId, versionId);
      const response = result(
        tool,
        { transcript: row?.view ?? null },
        { reference: versionId ?? transcriptId }
      );
      if (!row) return response;
      const uri = new URL(
        `board://${row.board_id}/meetings/${row.meeting_id}/transcripts/${String(row.version)}`
      );
      const preparedEventId = await this.prepareResourceAudit(client, principal, uri, {
        entityType: "meeting_transcript_version",
        entityId: row.version_id,
        boardId: row.board_id,
        objectVersion: BigInt(row.version),
        mediaType: row.media_type,
        bytes: row.canonical_bytes
      });
      return this.observePreparedResource(
        principal,
        response,
        preparedEventId,
        row.canonical_bytes.byteLength
      );
    }

    const limit = pageLimit(input);
    if (tool === "list_meeting_transcripts") {
      const meetingId = requiredString(input, "meeting_id");
      const anchor = this.anchor(principal, tool, null, nullableString(input, "cursor"));
      const rows = await loadAdmittedMeetingList(client, {
        kind: "transcripts",
        selectorId: meetingId,
        memberId: null,
        cursorAt: anchor?.at ?? null,
        cursorId: anchor?.id ?? null,
        limit
      });
      return result(tool, this.page(principal, tool, null, rows, limit), {
        reference: meetingId
      });
    }
    const boardId = requiredString(input, "board_id");
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    const rows = await loadAdmittedMeetingList(client, {
      kind: "meetings",
      selectorId: boardId,
      memberId: principal.memberId,
      cursorAt: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      limit
    });
    return result(tool, this.page(principal, tool, boardId, rows, limit));
  }

  private async readVote(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "verify_certificate") {
      const publicId = nullableString(input, "public_id");
      if (publicId === null) {
        try {
          const parsed = OfflineCertificateBundleSchema.parse(
            JSON.parse(requiredString(input, "bundle"))
          );
          const key = await client.query<{
            id: string;
            kid: string;
            algorithm: "EdDSA";
            public_jwk: JsonValue;
          }>(
            `select id,kid,algorithm,public_jwk
               from crypto_key_registry
              where organization_id=$1 and id=$2 and purpose='evidence_signing'`,
            [principal.organizationId, parsed.signing_key.id]
          );
          const trusted = key.rows[0];
          const offlineValid =
            key.rows.length === 1 &&
            trusted !== undefined &&
            verifyOfflineCertificateBundle(parsed, {
              schema_version: "boardagent.trusted-evidence-keys.v1",
              keys: [trusted]
            });
          const persisted = await verifyPersistedVoteCertificateInTransaction(client, {
            organizationId: principal.organizationId,
            certificatePublicId: parsed.public_id
          });
          const valid =
            offlineValid && persisted.valid && persisted.certificateId === parsed.certificate_id;
          return result(tool, {
            valid,
            ...(valid ? { certificate_id: parsed.certificate_id } : {})
          });
        } catch {
          return result(tool, { valid: false });
        }
      }
      const verdict = await verifyPersistedVoteCertificateInTransaction(client, {
        organizationId: principal.organizationId,
        certificatePublicId: publicId
      });
      return result(tool, json(verdict), {
        reference: verdict.valid ? verdict.certificateId : null
      });
    }
    if (tool === "get_vote_certificate") {
      const voteId = requiredString(input, "vote_id");
      const certificateId = nullableString(input, "certificate_id");
      const certificateRow = await loadAdmittedCertificateToolProjection(
        client,
        voteId,
        certificateId
      );
      const certificate = certificateRow?.view ?? null;
      const certificateRecord = jsonRecord(certificate ?? undefined);
      return result(
        tool,
        { certificate },
        {
          reference: certificateId ?? voteId,
          resourceUri: certificateRecord
            ? `board://${certificateRow?.board_id ?? "unavailable"}/votes/${voteId}/certificates/${String(certificateRecord["certificate_id"])}`
            : null
        }
      );
    }
    if (tool === "get_proxy_status") {
      const voteId = requiredString(input, "vote_id");
      const memberId = nullableString(input, "member_id") ?? principal.memberId;
      const items = await loadAdmittedProxyStatus(client, voteId, memberId, principal.memberId);
      return result(
        tool,
        { vote_id: voteId, member_id: memberId, grants: items },
        {
          reference: voteId
        }
      );
    }
    if (tool === "get_vote_lineage") {
      const voteId = requiredString(input, "vote_id");
      const items = await loadAdmittedVoteLineage(client, voteId);
      return result(
        tool,
        { vote_id: voteId, lineage: items },
        {
          reference: voteId
        }
      );
    }
    if (tool === "get_vote") {
      const voteId = requiredString(input, "vote_id");
      const found = await loadAdmittedVoteToolProjection(client, voteId, principal.memberId);
      const vote = found[0]?.view ?? null;
      const voteRecord = jsonRecord(vote ?? undefined);
      return result(
        tool,
        { vote },
        {
          reference: voteId,
          resourceUri: voteRecord
            ? `board://${String(voteRecord["board_id"])}/votes/${voteId}`
            : null
        }
      );
    }

    const boardId = requiredString(input, "board_id");
    const limit = pageLimit(input);
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    const rows = await loadAdmittedBoardVotePage(client, {
      kind: "votes",
      selectorId: boardId,
      at: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      take: limit + 1
    });
    return result(tool, this.page(principal, tool, boardId, rows, limit));
  }

  private async readMinutes(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    const minutesId = requiredString(input, "minutes_id");
    if (tool === "get_minutes") {
      const found = await loadAdmittedMinutesToolProjection(client, minutesId);
      const minutes = found[0]?.view ?? null;
      const minutesRecord = jsonRecord(minutes ?? undefined);
      const versionRecord = jsonRecord(minutesRecord?.["version"]);
      return result(
        tool,
        { minutes },
        {
          reference: minutesId,
          resourceUri:
            minutesRecord && versionRecord
              ? `board://${String(minutesRecord["board_id"])}/minutes/${minutesId}/versions/${String(versionRecord["version"])}`
              : null
        }
      );
    }
    if (tool === "get_minutes_lineage") {
      const items = await loadAdmittedMinutesLineage(client, minutesId);
      return result(
        tool,
        { minutes_id: minutesId, correction_cycles: items },
        { reference: minutesId }
      );
    }
    const limit = pageLimit(input);
    const anchor = this.anchor(principal, tool, null, nullableString(input, "cursor"));
    if (tool === "list_minutes_versions") {
      const rows = await loadAdmittedMinutesList(client, {
        kind: "versions",
        minutesId,
        cursorAt: anchor?.at ?? null,
        cursorId: anchor?.id ?? null,
        limit
      });
      return result(tool, this.page(principal, tool, null, rows, limit), {
        reference: minutesId
      });
    }
    const rows = await loadAdmittedMinutesList(client, {
      kind: "reviews",
      minutesId,
      cursorAt: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      limit
    });
    return result(tool, this.page(principal, tool, null, rows, limit), {
      reference: minutesId
    });
  }

  private async readTask(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "get_task" || tool === "get_action_item") {
      const taskId = requiredString(input, "task_id");
      // Measured admission of the original task graph (evidence, latest reviews,
      // closure, correction cycles); the frozen original SQL lives with its tests.
      const found = await loadAdmittedTaskToolProjection(client, {
        taskId,
        actionOnly: tool === "get_action_item",
        memberId: principal.memberId
      });
      return result(tool, { task: found?.view ?? null }, { reference: taskId });
    }
    const limit = pageLimit(input);
    const boardId = tool === "list_action_items" ? requiredString(input, "board_id") : null;
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    const rows = await client.query<PageRow>(
      `select jsonb_build_object(
         'task_id',task.id,'board_id',task.board_id,'owner_member_id',task.owner_member_id,
         'due_at',to_char(task.due_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
         'canonical_description',task.canonical_description,
         'required_evidence',task.required_evidence,'task_sha256',encode(task.task_sha256,'hex'),
         'state',task.state,'row_version',task.row_version::text,
         'source_minutes_id',task.source_minutes_id,
         'source_minutes_version_id',task.source_minutes_version_id,
         'source_minutes_sha256',case when task.source_minutes_sha256 is null then null
            else encode(task.source_minutes_sha256,'hex') end,
         'created_at',to_char(task.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
       ) as item,
       to_char(task.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
       task.id::text as cursor_id
       from tasks as task
      where (($1::uuid is null and task.owner_member_id=$2)
          or ($1::uuid is not null and task.board_id=$1 and task.source_minutes_id is not null))
        and ($3::timestamptz is null or (task.created_at,task.id)<($3::timestamptz,$4::uuid))
      order by task.created_at desc,task.id desc limit $5`,
      [boardId, principal.memberId, anchor?.at ?? null, anchor?.id ?? null, limit + 1]
    );
    return result(tool, this.page(principal, tool, boardId, rows.rows, limit));
  }

  private async readCommunications(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    const limit = pageLimit(input);
    const boardId = nullableString(input, "board_id");
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    const rows = await loadAdmittedCommunicationsList(client, {
      kind: tool === "list_proposals" ? "proposals" : "secretariat",
      boardId,
      memberId: principal.memberId,
      state: nullableString(input, "state"),
      cursorAt: anchor?.at ?? null,
      cursorId: anchor?.id ?? null,
      limit
    });
    return result(tool, this.page(principal, tool, boardId, rows, limit));
  }

  private async readIdentity(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "get_member") {
      const memberId = requiredString(input, "member_id");
      const found = await client.query<{ view: JsonValue }>(
        `select jsonb_build_object(
           'member_id',member.id,'member_kind',member.member_kind,
           'legal_name',case when member.id=$2 then member.legal_name else null end,
           'display_name',member.display_name,'state',member.state,
           'accountable_principal',case when principal.id is null then null else
             jsonb_build_object('principal_id',principal.id,'legal_name',principal.legal_name,
                                'reference',principal.reference) end,
           'identity_generation',member.identity_generation::text,
           'onboarding_generation',member.onboarding_generation::text,
           'row_version',member.row_version::text,
           'recovery_credentials',boardagent_member_recovery_credentials(member.id),
           'organization_roles',coalesce((select jsonb_agg(role_assignment.role
              order by role_assignment.role) from organization_role_assignments as role_assignment
              where role_assignment.member_id=member.id
                and role_assignment.active_from<=transaction_timestamp()
                and (role_assignment.active_until is null
                     or role_assignment.active_until>transaction_timestamp())),'[]'::jsonb),
           'memberships',coalesce((select jsonb_agg(jsonb_build_object(
              'membership_id',membership.id,'board_id',membership.board_id,
              'seat_role',membership.seat_role,'is_chair',membership.is_chair,
              'is_secretary',membership.is_secretary,
              'voting_weight',membership.voting_weight::text,'state',membership.state,
              'entitlement_generation',membership.entitlement_generation::text
            ) order by membership.board_id,membership.id) from board_memberships as membership
             where membership.member_id=member.id
               and (member.id=$2 or boardagent_secretariat_for_board(membership.board_id))),'[]'::jsonb),
           'created_at',to_char(member.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) as view from members as member
         left join accountable_principals as principal on principal.id=member.accountable_principal_id
        where member.id=$1 and (member.id=$2 or exists (
          select 1 from board_memberships as target_membership
           where target_membership.member_id=member.id
             and boardagent_secretariat_for_board(target_membership.board_id)
        ) or exists (
          select 1 from organization_role_assignments as role_assignment
           where role_assignment.member_id=$2 and role_assignment.role in ('secretariat','admin')
             and role_assignment.active_from<=transaction_timestamp()
             and (role_assignment.active_until is null
                  or role_assignment.active_until>transaction_timestamp())
        ))`,
        [memberId, principal.memberId]
      );
      return result(tool, { member: found.rows[0]?.view ?? null }, { reference: memberId });
    }

    const limit = pageLimit(input);
    const boardId = tool === "list_members" ? nullableString(input, "board_id") : null;
    const anchor = this.anchor(principal, tool, boardId, nullableString(input, "cursor"));
    if (tool === "list_members") {
      const state = nullableString(input, "state");
      reserveFixedRead("list_members", principal.memberId, limit);
      const rows = await client.query<PageRow>(
        `select jsonb_build_object(
           'member_id',member.id,'member_kind',member.member_kind,
           'display_name',member.display_name,'state',member.state,
           'accountable_principal_id',member.accountable_principal_id,
           'identity_generation',member.identity_generation::text,
           'onboarding_generation',member.onboarding_generation::text,
           'row_version',member.row_version::text,
           'membership',case when membership.id is null then null else jsonb_build_object(
              'membership_id',membership.id,'board_id',membership.board_id,
              'seat_role',membership.seat_role,'is_chair',membership.is_chair,
              'is_secretary',membership.is_secretary,
              'voting_weight',membership.voting_weight::text,'state',membership.state,
              'entitlement_generation',membership.entitlement_generation::text
           ) end,
           'created_at',to_char(member.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) as item,
         to_char(member.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         member.id::text as cursor_id
         from members as member
         left join board_memberships as membership on membership.member_id=member.id
          and ($1::uuid is null or membership.board_id=$1)
        where ($1::uuid is null or membership.id is not null)
          and (boardagent_secretariat_for_board(membership.board_id) or exists (
            select 1 from organization_role_assignments as role_assignment
             where role_assignment.organization_id=member.organization_id
               and role_assignment.member_id=boardagent_context_uuid('boardagent.member_id')
               and role_assignment.role in ('secretariat','admin')
               and role_assignment.active_from<=transaction_timestamp()
               and (role_assignment.active_until is null
                    or role_assignment.active_until>transaction_timestamp())
          ))
          and ($2::text is null or member.state=$2)
          and ($3::timestamptz is null or (member.created_at,member.id)<($3::timestamptz,$4::uuid))
        order by member.created_at desc,member.id desc limit $5`,
        [boardId, state, anchor?.at ?? null, anchor?.id ?? null, limit + 1]
      );
      return result(tool, this.page(principal, tool, boardId, rows.rows, limit));
    }
    if (tool === "list_enrollments") {
      const state = nullableString(input, "state");
      reserveFixedRead("list_enrollments", principal.memberId, limit);
      const rows = await client.query<PageRow>(
        `select jsonb_build_object(
           'invitation_id',invitation.id,'member_id',invitation.member_id,
           'issued_by',invitation.issued_by,'handoff_method',invitation.handoff_method,
           'state',case when invitation.revoked_at is not null then 'revoked'
             when invitation.consumed_at is not null then 'consumed'
             when invitation.expires_at<=transaction_timestamp() then 'expired' else 'issued' end,
           'issued_at',to_char(invitation.issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'expires_at',to_char(invitation.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'consumed_at',case when invitation.consumed_at is null then null else
              to_char(invitation.consumed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end,
           'pending_activation_member_id',invitation.pending_activation_member_id
         ) as item,
         to_char(invitation.issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         invitation.id::text as cursor_id
         from enrollment_invitations as invitation
        where ($1::text is null or case when invitation.revoked_at is not null then 'revoked'
             when invitation.consumed_at is not null then 'consumed'
             when invitation.expires_at<=transaction_timestamp() then 'expired' else 'issued' end=$1)
          and ($2::timestamptz is null or
               (invitation.issued_at,invitation.id)<($2::timestamptz,$3::uuid))
        order by invitation.issued_at desc,invitation.id desc limit $4`,
        [state, anchor?.at ?? null, anchor?.id ?? null, limit + 1]
      );
      return result(tool, this.page(principal, tool, null, rows.rows, limit));
    }
    if (tool === "list_my_sessions") {
      const rows = await client.query<PageRow>(
        "select item,cursor_at,cursor_id from boardagent_own_session_page($1,$2,$3)",
        [anchor?.at ?? null, anchor?.id ?? null, limit + 1]
      );
      return result(tool, this.page(principal, tool, null, rows.rows, limit));
    }
    const rows = await client.query<PageRow>(
      `select jsonb_build_object(
         'client_id',client.id,'protocol_id_kind',client.protocol_id_kind,
         'protocol_id',client.protocol_id_value,'safe_metadata',client.safe_metadata,
         'metadata_sha256',encode(client.metadata_sha256,'hex'),'state',client.state,
         'registered_by',client.registered_by,
         'registered_at',to_char(client.registered_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
       ) as item,
       to_char(client.registered_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
       client.id::text as cursor_id from oauth_clients as client
      where ($1::timestamptz is null or
             (client.registered_at,client.id)<($1::timestamptz,$2::uuid))
      order by client.registered_at desc,client.id desc limit $3`,
      [anchor?.at ?? null, anchor?.id ?? null, limit + 1]
    );
    return result(tool, this.page(principal, tool, null, rows.rows, limit));
  }

  private opaqueBytes(value: string): Buffer {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.length < 24 || bytes.toString("base64url") !== value) {
      throw new Error("opaque reference is invalid");
    }
    return bytes;
  }

  private async readOperations(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "verify_audit_chain") {
      const verification = await verifyPersistedAuditEvidence(client);
      return result(tool, json(verification));
    }
    if (tool === "get_retention_policy") {
      reserveFixedRead("get_retention_policy", principal.memberId);
      const snapshots = await client.query<{ count: string }>(
        "select count(*)::text as count from retention_snapshots"
      );
      return result(tool, {
        schema_version: "boardagent.retention-policy.v1",
        governance_records: "indefinite",
        physical_purge_available: false,
        soft_delete_behavior: "hidden_from_ordinary_surfaces_with_permanent_snapshot_and_tombstone",
        ephemeral_classes: {
          authorization_codes: "short_lived_then_inert",
          action_stages: "ten_minutes_then_inert",
          enrollment_links: "bounded_one_use",
          export_artifacts: "operator_configured_expiry_with_permanent_receipt"
        },
        retained_snapshot_count: snapshots.rows[0]?.count ?? "0"
      });
    }
    if (tool === "list_my_webhooks") {
      const limit = pageLimit(input);
      const anchor = this.anchor(principal, tool, null, nullableString(input, "cursor"));
      reserveFixedRead("list_my_webhooks", principal.memberId, limit);
      const rows = await client.query<PageRow>(
        `select jsonb_build_object(
           'webhook_id',webhook.id,'state',webhook.state,
           'endpoint_fingerprint',encode(webhook.endpoint_sha256,'hex'),
           'ssrf_validation_receipt_sha256',encode(webhook.ssrf_validation_receipt_sha256,'hex'),
           'generation',webhook.generation::text,'key_id',webhook.key_id,
           'created_at',to_char(webhook.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'disabled_at',case when webhook.disabled_at is null then null else
             to_char(webhook.disabled_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as item,
         to_char(webhook.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         webhook.id::text as cursor_id from member_webhooks as webhook
        where webhook.member_id=$1
          and ($2::timestamptz is null or
               (webhook.created_at,webhook.id)<($2::timestamptz,$3::uuid))
        order by webhook.created_at desc,webhook.id desc limit $4`,
        [principal.memberId, anchor?.at ?? null, anchor?.id ?? null, limit + 1]
      );
      return result(tool, this.page(principal, tool, null, rows.rows, limit));
    }

    const exportId = requiredString(input, "export_id");
    const publicId = this.opaqueBytes(exportId);
    if (tool === "get_export_status") {
      const rows = await loadAdmittedExportStatus(client, publicId, exportId, principal.memberId);
      return result(tool, { export: rows[0]?.view ?? null }, { reference: exportId });
    }

    if (!this.options.exportChunks) throw new Error("export chunk storage is unavailable");
    const ordinal = input["chunk_no"];
    if (typeof ordinal !== "number" || !Number.isSafeInteger(ordinal)) {
      throw new TypeError("chunk_no must be a safe integer");
    }
    const found = await client.query<{
      request_id: string;
      board_id: string | null;
      artifact_id: string;
      storage_locator: string;
      byte_length: number;
      sha256: string;
    }>(
      `select request.id as request_id,request.board_id,artifact.id as artifact_id,
              chunk.storage_locator,chunk.byte_length,encode(chunk.chunk_sha256,'hex') as sha256
         from export_requests as request
         join export_artifacts as artifact on artifact.export_request_id=request.id
         join export_chunks as chunk on chunk.artifact_id=artifact.id
        where request.public_id=$1 and request.requester_member_id=$2
          and request.state='succeeded' and artifact.state='ready' and chunk.ordinal=$3`,
      [publicId, principal.memberId, ordinal]
    );
    const chunk = found.rows[0];
    if (!chunk) return result(tool, { chunk: null }, { reference: exportId });
    const bytes = Buffer.from(
      await loadWithResponseAllocation(
        responseAllocationPlan({
          kind: "export",
          representation: "tool",
          sourceId: chunk.artifact_id,
          sourceVersion: `${chunk.request_id}:${String(ordinal)}`,
          sha256: chunk.sha256,
          canonicalBytes: chunk.byte_length
        }),
        () =>
          this.options.exportChunks!.readExactChunk({
            exportRequestId: chunk.request_id,
            artifactId: chunk.artifact_id,
            ordinal,
            storageLocator: chunk.storage_locator,
            byteLength: chunk.byte_length,
            expectedSha256: chunk.sha256
          })
      )
    );
    if (
      bytes.length !== chunk.byte_length ||
      createHash("sha256").update(bytes).digest("hex") !== chunk.sha256
    ) {
      throw new Error("export chunk failed integrity verification");
    }
    const response = result(
      tool,
      {
        export_id: exportId,
        chunk_no: ordinal,
        byte_length: bytes.length,
        sha256: chunk.sha256,
        encoding: "base64url",
        bytes: bytes.toString("base64url")
      },
      { reference: exportId, resourceUri: `export://${exportId}/chunks/${String(ordinal)}` }
    );
    const preparedEventId = await this.prepareResourceAudit(
      client,
      principal,
      new URL(`export://${exportId}/chunks/${String(ordinal)}`),
      {
        entityType: "export_chunk",
        entityId: chunk.request_id,
        boardId: chunk.board_id,
        objectVersion: BigInt(ordinal + 1),
        mediaType: "application/octet-stream",
        bytes
      }
    );
    return this.observePreparedResource(principal, response, preparedEventId, bytes.byteLength);
  }

  private async readDraft(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Readonly<Record<string, JsonValue>>
  ): Promise<SurfaceToolResult> {
    if (tool === "resume_draft") {
      const draftId = requiredString(input, "draft_id");
      const found = { rows: await loadAdmittedResumeDraft(client, draftId, principal.memberId) };
      return result(tool, { draft: found.rows[0]?.view ?? null }, { reference: draftId });
    }
    const limit = pageLimit(input);
    const draftType = nullableString(input, "draft_type");
    const anchor = this.anchor(principal, tool, null, nullableString(input, "cursor"));
    reserveFixedRead("list_my_drafts", principal.memberId, limit);
    const rows = await client.query<PageRow>(
      `select jsonb_build_object(
         'draft_id',draft.id,'board_id',draft.board_id,'draft_type',draft.draft_type,
         'current_step',draft.current_step,'state',draft.state,'ruleset_id',draft.ruleset_id,
         'package_sha256',case when draft.package_sha256 is null then null
            else encode(draft.package_sha256,'hex') end,
         'row_version',draft.row_version::text,
         'expires_at',to_char(draft.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
         'created_at',to_char(draft.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
       ) as item,
       to_char(draft.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
       draft.id::text as cursor_id from wizard_drafts as draft
      where draft.creator_member_id=$1 and draft.state in ('active','ready_to_confirm')
        and draft.expires_at>transaction_timestamp()
        and ($2::text is null or draft.draft_type=$2)
        and ($3::timestamptz is null or (draft.created_at,draft.id)<($3::timestamptz,$4::uuid))
      order by draft.created_at desc,draft.id desc limit $5`,
      [principal.memberId, draftType, anchor?.at ?? null, anchor?.id ?? null, limit + 1]
    );
    return result(tool, this.page(principal, tool, null, rows.rows, limit));
  }

  private positiveVersion(value: string): number {
    if (!/^[1-9][0-9]*$/u.test(value)) throw new Error("resource version is invalid");
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed > 2_147_483_647) {
      throw new Error("resource version is invalid");
    }
    return parsed;
  }

  private resourceJson(value: unknown): Buffer {
    return Buffer.from(canonicalJson(json(value)), "utf8");
  }

  private async loadBoardResource(
    client: PoolClient,
    principal: SurfacePrincipal,
    uri: URL
  ): Promise<LoadedResource | null> {
    const boardId = UuidV7Schema.parse(uri.hostname);
    const parts = uri.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    if (parts.length === 0) {
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_board", {
        board_id: boardId
      });
      const row = await loadAdmittedBoardProjection(client, boardId, "resource");
      return row
        ? {
            entityType: "board",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.row_version),
            mediaType: "application/json",
            bytes: this.resourceJson(row.payload)
          }
        : null;
    }

    if (parts[0] === "governance-profile" && parts.length === 2) {
      this.authorizeRead(
        principal,
        await this.liveActor(client, principal),
        "get_board_governance_profile",
        { board_id: boardId }
      );
      const version = this.positiveVersion(parts[1] ?? "");
      const row = await loadAdmittedGovernanceJson(client, {
        kind: "governance_profile",
        boardId,
        version
      });
      return row
        ? {
            entityType: "governance_profile",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.version),
            mediaType: "application/json",
            bytes: this.resourceJson(row.payload)
          }
        : null;
    }

    if (parts[0] === "rulesets" && parts.length === 2) {
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_ruleset", {
        board_id: boardId
      });
      const version = this.positiveVersion(parts[1] ?? "");
      const row = await loadAdmittedGovernanceJson(client, { kind: "ruleset", boardId, version });
      return row
        ? {
            entityType: "ruleset",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.version),
            mediaType: "application/json",
            bytes: this.resourceJson(row.payload)
          }
        : null;
    }

    if (parts[0] === "documents" && parts[2] === "versions" && parts.length === 4) {
      const documentId = UuidV7Schema.parse(parts[1]);
      const version = this.positiveVersion(parts[3] ?? "");
      this.authorizeRead(principal, await this.liveActor(client, principal), "read_document", {});
      const found = await client.query<{
        id: string;
        version: number;
        media_type: LoadedResource["mediaType"];
        byte_length: number;
        sha256: string;
      }>(
        `select version_row.id,version_row.version,version_row.media_type,version_row.byte_length,
                encode(version_row.sha256,'hex') as sha256
           from documents as document
           join document_versions as version_row on version_row.document_id=document.id
          where document.board_id=$1 and document.id=$2 and version_row.version=$3`,
        [boardId, documentId, version]
      );
      const row = found.rows[0];
      if (!row) return null;
      const plan = responseAllocationPlan({
        kind: "document",
        representation: "resource",
        sourceId: row.id,
        sourceVersion: `${documentId}:${String(row.version)}`,
        sha256: row.sha256,
        canonicalBytes: row.byte_length
      });
      const loaded = await loadWithResponseAllocation(plan, () =>
        client.query<{ canonical_bytes: Buffer }>(
          `select version_row.canonical_bytes
           from documents as document
           join document_versions as version_row on version_row.document_id=document.id
          where document.board_id=$1 and document.id=$2 and version_row.id=$3 and version_row.version=$4
            and version_row.byte_length=$5 and version_row.sha256=$6 and version_row.media_type=$7`,
          [
            boardId,
            documentId,
            row.id,
            row.version,
            row.byte_length,
            Buffer.from(row.sha256, "hex"),
            row.media_type
          ]
        )
      );
      const bytes = loaded.rows[0]?.canonical_bytes;
      if (!bytes) return null;
      if (
        bytes.length !== row.byte_length ||
        createHash("sha256").update(bytes).digest("hex") !== row.sha256
      )
        throw new Error("document version failed integrity verification");
      return {
        entityType: "document_version",
        entityId: row.id,
        boardId,
        objectVersion: BigInt(row.version),
        mediaType: row.media_type,
        bytes
      };
    }

    if (parts[0] === "submissions" && parts[2] === "versions" && parts.length === 4) {
      const submissionId = UuidV7Schema.parse(parts[1]);
      const version = this.positiveVersion(parts[3] ?? "");
      this.authorizeRead(
        principal,
        await this.liveActor(client, principal),
        "get_management_submission",
        {}
      );
      const row = await loadAdmittedCanonicalVersion(client, {
        kind: "submission",
        boardId,
        parentId: submissionId,
        version,
        memberId: principal.memberId
      });
      return row
        ? {
            entityType: "management_submission_version",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.version),
            mediaType: "application/json",
            bytes: row.bytes
          }
        : null;
    }

    if (parts[0] === "questions" && parts.length === 2) {
      const questionId = UuidV7Schema.parse(parts[1]);
      this.authorizeRead(
        principal,
        await this.liveActor(client, principal),
        "get_management_question",
        {}
      );
      const question = await loadAdmittedManagementQuestion(
        client,
        questionId,
        "resource",
        boardId
      );
      return question && question.boardId === boardId
        ? {
            entityType: "management_question",
            entityId: questionId,
            boardId,
            objectVersion: BigInt(question.rowVersion),
            mediaType: "application/json",
            bytes: this.resourceJson(question)
          }
        : null;
    }

    if (parts[0] === "meetings" && parts[2] === "agendas" && parts.length === 4) {
      const meetingId = UuidV7Schema.parse(parts[1]);
      const version = this.positiveVersion(parts[3] ?? "");
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_agenda", {});
      const row = await loadAdmittedCanonicalVersion(client, {
        kind: "agenda",
        boardId,
        parentId: meetingId,
        version,
        memberId: principal.memberId
      });
      return row
        ? {
            entityType: "agenda_version",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.version),
            mediaType: "application/json",
            bytes: row.bytes
          }
        : null;
    }

    if (parts[0] === "meetings" && parts[2] === "transcripts" && parts.length === 4) {
      const meetingId = UuidV7Schema.parse(parts[1]);
      const version = this.positiveVersion(parts[3] ?? "");
      this.authorizeRead(
        principal,
        await this.liveActor(client, principal),
        "get_meeting_transcript",
        {}
      );
      const found = await client.query<{
        id: string;
        version: number;
        media_type: LoadedResource["mediaType"];
        byte_length: number;
        sha256: string;
      }>(
        `select version_row.id,version_row.version,version_row.media_type,
                octet_length(version_row.canonical_bytes) as byte_length,
                encode(version_row.canonical_sha256,'hex') as sha256
           from meetings as meeting
           join meeting_transcripts as transcript on transcript.meeting_id=meeting.id
           join meeting_transcript_versions as version_row on version_row.transcript_id=transcript.id
          where meeting.board_id=$1 and meeting.id=$2 and version_row.version=$3`,
        [boardId, meetingId, version]
      );
      const row = found.rows[0];
      if (!row) return null;
      const plan = responseAllocationPlan({
        kind: "transcript",
        representation: "resource",
        sourceId: row.id,
        sourceVersion: `${meetingId}:${String(row.version)}`,
        sha256: row.sha256,
        canonicalBytes: row.byte_length
      });
      const loaded = await loadWithResponseAllocation(plan, () =>
        client.query<{ canonical_bytes: Buffer }>(
          `select version_row.canonical_bytes
           from meetings as meeting
           join meeting_transcripts as transcript on transcript.meeting_id=meeting.id
           join meeting_transcript_versions as version_row on version_row.transcript_id=transcript.id
          where meeting.board_id=$1 and meeting.id=$2 and version_row.id=$3 and version_row.version=$4
            and octet_length(version_row.canonical_bytes)=$5
            and version_row.canonical_sha256=$6 and version_row.media_type=$7`,
          [
            boardId,
            meetingId,
            row.id,
            row.version,
            row.byte_length,
            Buffer.from(row.sha256, "hex"),
            row.media_type
          ]
        )
      );
      const bytes = loaded.rows[0]?.canonical_bytes;
      if (!bytes) return null;
      if (
        bytes.length !== row.byte_length ||
        createHash("sha256").update(bytes).digest("hex") !== row.sha256
      )
        throw new Error("transcript version failed integrity verification");
      return {
        entityType: "meeting_transcript_version",
        entityId: row.id,
        boardId,
        objectVersion: BigInt(row.version),
        mediaType: row.media_type,
        bytes
      };
    }

    return this.loadBoardGovernanceResource(client, principal, boardId, parts);
  }

  private async loadBoardGovernanceResource(
    client: PoolClient,
    principal: SurfacePrincipal,
    boardId: string,
    parts: readonly string[]
  ): Promise<LoadedResource | null> {
    if (parts[0] === "minutes" && parts[2] === "versions" && parts.length === 4) {
      const minutesId = UuidV7Schema.parse(parts[1]);
      const version = this.positiveVersion(parts[3] ?? "");
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_minutes", {});
      const row = await loadAdmittedGovernanceCanonicalResource(client, {
        kind: "minutes",
        boardId,
        parentId: minutesId,
        version
      });
      return row
        ? {
            entityType: "minutes_version",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.version),
            mediaType: "text/plain; charset=utf-8",
            bytes: row.bytes
          }
        : null;
    }
    if (parts[0] === "minutes" && parts[2] === "review" && parts.length === 4) {
      const minutesId = UuidV7Schema.parse(parts[1]);
      const itemId = UuidV7Schema.parse(parts[3]);
      this.authorizeRead(
        principal,
        await this.liveActor(client, principal),
        "list_minutes_review_items",
        {}
      );
      const row = await loadAdmittedGovernanceCanonicalResource(client, {
        kind: "minutes_review",
        boardId,
        parentId: minutesId,
        itemId
      });
      return row
        ? {
            entityType: "minutes_review_item",
            entityId: row.id,
            boardId,
            objectVersion: 1n,
            mediaType: "application/json",
            bytes: row.bytes
          }
        : null;
    }
    if (parts[0] === "action-items" && parts.length === 2) {
      const taskId = UuidV7Schema.parse(parts[1]);
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_action_item", {});
      return this.loadTaskResource(client, principal, boardId, taskId, true);
    }
    if (parts[0] === "tasks" && parts.length === 2) {
      const taskId = UuidV7Schema.parse(parts[1]);
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_task", {});
      return this.loadTaskResource(client, principal, boardId, taskId, false);
    }
    if (parts[0] === "votes" && parts.length === 2) {
      const voteId = UuidV7Schema.parse(parts[1]);
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_vote", {});
      const row = await loadAdmittedVoteProjection(client, boardId, voteId);
      return row
        ? {
            entityType: "vote",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.row_version),
            mediaType: "application/json",
            bytes: this.resourceJson(row.payload)
          }
        : null;
    }
    if (parts[0] === "votes" && parts[2] === "packages" && parts.length === 4) {
      const voteId = UuidV7Schema.parse(parts[1]);
      const version = this.positiveVersion(parts[3] ?? "");
      this.authorizeRead(principal, await this.liveActor(client, principal), "get_vote", {});
      const row = await loadAdmittedGovernanceCanonicalResource(client, {
        kind: "decision_package",
        boardId,
        parentId: voteId,
        version
      });
      return row
        ? {
            entityType: "decision_package",
            entityId: row.id,
            boardId,
            objectVersion: BigInt(row.version),
            mediaType: "application/json",
            bytes: row.bytes
          }
        : null;
    }
    if (parts[0] === "votes" && parts[2] === "certificates" && parts.length === 4) {
      const voteId = UuidV7Schema.parse(parts[1]);
      const certificateId = UuidV7Schema.parse(parts[3]);
      this.authorizeRead(
        principal,
        await this.liveActor(client, principal),
        "get_vote_certificate",
        {}
      );
      const row = await loadAdmittedCertificateProjection(client, boardId, voteId, certificateId);
      return row
        ? {
            entityType: "vote_certificate",
            entityId: row.id,
            boardId,
            objectVersion: 1n,
            mediaType: "application/json",
            bytes: this.resourceJson(row.payload)
          }
        : null;
    }
    throw new Error("resource URI does not match the frozen registry");
  }

  private async loadTaskResource(
    client: PoolClient,
    principal: SurfacePrincipal,
    boardId: string,
    taskId: string,
    actionOnly: boolean
  ): Promise<LoadedResource | null> {
    // Measured admission of the original task resource (task row, evidence, closure);
    // the frozen original SQL lives with its tests.
    const row = await loadAdmittedTaskProjection(client, {
      boardId,
      taskId,
      actionOnly,
      memberId: principal.memberId
    });
    return row
      ? {
          entityType: actionOnly ? "action_item" : "task",
          entityId: row.id,
          boardId,
          objectVersion: BigInt(row.row_version),
          mediaType: "application/json",
          bytes: this.resourceJson(row.payload)
        }
      : null;
  }

  private async loadExportResource(
    client: PoolClient,
    principal: SurfacePrincipal,
    uri: URL
  ): Promise<LoadedResource | null> {
    if (!this.options.exportChunks) throw new Error("export chunk storage is unavailable");
    const exportId = uri.hostname;
    const match = /^\/chunks\/(0|[1-9][0-9]*)$/u.exec(uri.pathname);
    if (!match?.[1]) throw new Error("resource URI does not match the frozen registry");
    const ordinal = Number(match[1]);
    if (!Number.isSafeInteger(ordinal)) throw new Error("export chunk number is invalid");
    const actor = await this.liveActor(client, principal);
    this.authorizeRead(principal, actor, "read_export_chunk", {});
    const found = await client.query<{
      request_id: string;
      board_id: string | null;
      artifact_id: string;
      storage_locator: string;
      byte_length: number;
      sha256: string;
    }>(
      `select request.id as request_id,request.board_id,artifact.id as artifact_id,
              chunk.storage_locator,chunk.byte_length,encode(chunk.chunk_sha256,'hex') as sha256
         from export_requests as request
         join export_artifacts as artifact on artifact.export_request_id=request.id
         join export_chunks as chunk on chunk.artifact_id=artifact.id
        where request.public_id=$1 and request.requester_member_id=$2
          and request.state='succeeded' and artifact.state='ready' and chunk.ordinal=$3`,
      [this.opaqueBytes(exportId), principal.memberId, ordinal]
    );
    const row = found.rows[0];
    if (!row) return null;
    const bytes = Buffer.from(
      await loadWithResponseAllocation(
        responseAllocationPlan({
          kind: "export",
          representation: "resource",
          sourceId: row.artifact_id,
          sourceVersion: `${row.request_id}:${String(ordinal)}`,
          sha256: row.sha256,
          canonicalBytes: row.byte_length
        }),
        () =>
          this.options.exportChunks!.readExactChunk({
            exportRequestId: row.request_id,
            artifactId: row.artifact_id,
            ordinal,
            storageLocator: row.storage_locator,
            byteLength: row.byte_length,
            expectedSha256: row.sha256
          })
      )
    );
    if (
      bytes.length !== row.byte_length ||
      createHash("sha256").update(bytes).digest("hex") !== row.sha256
    ) {
      throw new Error("export chunk failed integrity verification");
    }
    return {
      entityType: "export_chunk",
      entityId: row.request_id,
      boardId: row.board_id,
      objectVersion: BigInt(ordinal + 1),
      mediaType: "application/octet-stream",
      bytes
    };
  }

  private async prepareResourceAudit(
    client: PoolClient,
    principal: SurfacePrincipal,
    uri: URL,
    loaded: LoadedResource
  ): Promise<string> {
    const preparedEventId = newId();
    const digest = sha256Hex(loaded.bytes);
    const [prepared] = await appendAuditEventsInTransaction(client, [
      {
        organizationId: principal.organizationId,
        objectVersion: loaded.objectVersion,
        event: {
          eventId: preparedEventId,
          eventType: "resource_fetch",
          actorMemberId: principal.memberId,
          actorClientId: principal.clientId,
          tokenJti: principal.tokenJti,
          entityType: loaded.entityType,
          entityId: loaded.entityId,
          boardId: loaded.boardId,
          origin: "mcp",
          details: {
            phase: "prepared",
            resourceUri: uri.href,
            representation: loaded.mediaType,
            documentSchema: null,
            sha256: digest,
            byteLength: loaded.bytes.length,
            memberId: principal.memberId,
            tokenJti: principal.tokenJti,
            clientId: principal.clientId,
            requestOrigin: principal.serviceOrigin,
            version: loaded.objectVersion.toString()
          },
          schemaVersion: 1
        }
      }
    ]);
    if (!prepared) throw new Error("resource fetch prepared event was not appended");
    return preparedEventId;
  }

  private async auditResource(
    client: PoolClient,
    principal: SurfacePrincipal,
    uri: URL,
    loaded: LoadedResource
  ): Promise<SurfaceResourceResult> {
    const preparedEventId = await this.prepareResourceAudit(client, principal, uri, loaded);
    const response: SurfaceResourceResult =
      loaded.mediaType === "application/octet-stream"
        ? {
            uri: uri.href,
            media_type: loaded.mediaType,
            blob_base64: loaded.bytes.toString("base64")
          }
        : { uri: uri.href, media_type: loaded.mediaType, text: loaded.bytes.toString("utf8") };
    // Return proves preparation, not transport completion. The private handle can
    // be observed only by an explicit request collector; no wire field is added.
    return this.observePreparedResource(principal, response, preparedEventId, loaded.bytes.length);
  }

  public async readResource(principal: SurfacePrincipal, uri: URL): Promise<SurfaceResourceResult> {
    if (uri.username || uri.password || uri.port || uri.search || uri.hash) {
      throw new Error("resource URI is not canonical");
    }
    return withRequestTransaction(
      this.pool,
      this.requestContext(principal),
      async (client) => {
        await this.liveActor(client, principal);
        const loaded =
          uri.protocol === "board:"
            ? await this.loadBoardResource(client, principal, uri)
            : uri.protocol === "export:"
              ? await this.loadExportResource(client, principal, uri)
              : null;
        if (!loaded) throw new Error("resource unavailable");
        return this.auditResource(client, principal, uri, loaded);
      },
      this.options.transaction
    );
  }
}
