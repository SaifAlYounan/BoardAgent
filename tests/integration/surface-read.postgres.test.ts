import path from "node:path";
import { withDirectResponseAllocation } from "../helpers/direct-response-allocation.js";
import { tmpdir } from "node:os";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";

import { Pool, type PoolClient } from "pg";
import { createCursorCodec } from "../../artifacts/server/src/cursor.js";
import {
  ResourceDeliveryCollector,
  registerPreparedResource,
  registerResourceResponse
} from "../../artifacts/server/src/resource-delivery.js";
import { describe, expect, it } from "vitest";

import {
  PgSurfaceReadRepository,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  BOARDAGENT_TOOL_BY_NAME,
  TOOL_INPUT_SCHEMA_VERSION,
  canonicalJson,
  canonicalSha256,
  sha256Hex
} from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  migrate,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const ALL_SURFACE_SCOPES = [
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
] as const;
let databaseCounter = 0;

async function withDatabase<T>(
  run: (owner: Pool) => Promise<T>,
  migrationDirectory = MIGRATIONS
): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_surface_read_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const ownerUrl = new URL(BASE_URL);
  ownerUrl.pathname = `/${database}`;
  const owner = new Pool({ connectionString: ownerUrl.toString(), max: 4 });
  let passed = false;
  try {
    await migrate(owner, migrationDirectory, "surface-read-test");
    const value = await run(owner);
    passed = true;
    return value;
  } finally {
    await owner.end();
    if (passed) await dropClosedTestDatabase(admin, database);
    else console.error(`Preserved failed fixture database: ${database}`);
    await admin.end();
  }
}

async function surfacePrincipal(
  owner: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  options: {
    readonly sessionId: string;
    readonly boardIds?: readonly string[];
    readonly roles?: readonly string[];
    readonly scopes?: readonly string[];
  }
): Promise<SurfacePrincipal> {
  await owner.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
               transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
    [options.sessionId, actor.organizationId, testHash(101), actor.memberId, actor.clientId]
  );
  await owner.query("update access_token_records set session_id=$1 where id=$2", [
    options.sessionId,
    actor.accessTokenRecordId
  ]);
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "authorized-test-client",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: options.scopes ?? ["governance:read", "onboarding:read"],
    roles: options.roles ?? ["member", "secretariat"],
    boardIds: options.boardIds ?? [actor.boardId]
  };
}

async function seedFeedAudit(
  owner: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  auditEventId: string
): Promise<string> {
  const [audit] = await withRequestTransaction(
    owner,
    actor.context,
    (client) =>
      appendAuditEventsInTransaction(client, [
        {
          organizationId: actor.organizationId,
          event: {
            eventId: auditEventId,
            eventType: "context_read",
            actorMemberId: actor.memberId,
            actorClientId: actor.clientId,
            tokenJti: actor.tokenJti,
            entityType: "briefing_fixture",
            entityId: actor.memberId,
            boardId: actor.boardId,
            origin: "mcp",
            details: { fixture: true },
            schemaVersion: 1
          }
        }
      ]),
    { assumeRole: "boardagent_server" }
  );
  if (!audit) throw new Error("briefing fixture audit event was not appended");
  return audit.eventId;
}

async function seedPendingFeed(
  owner: Pool | PoolClient,
  input: {
    readonly organizationId: string;
    readonly boardId: string;
    readonly memberId: string;
    readonly auditEventId: string;
    readonly count: number;
    readonly sequenceOffset?: number;
    readonly idOffset?: number;
  }
): Promise<void> {
  const payload = { schemaVersion: "boardagent.test-pending-action.v1" } as const;
  await owner.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,audit_event_id,created_at
     )
     select (
              '018f0000-0000-7000-8000-' ||
              lpad(to_hex($8::bigint+generated.sequence),12,'0')
            )::uuid,
            $1,$2,$3,1,$6::bigint+generated.sequence,
            'action_required','task',
            (
              '018f0000-0000-7000-8000-' ||
              lpad(to_hex($8::bigint+1000000+generated.sequence),12,'0')
            )::uuid,
            1,$4,$5,$7,$9,
            transaction_timestamp()+generated.sequence*interval '1 microsecond'
       from generate_series(1,$10::integer) as generated(sequence)`,
    [
      input.organizationId,
      input.boardId,
      input.memberId,
      testHash(111),
      Buffer.from(canonicalJson(payload), "utf8"),
      input.sequenceOffset ?? 0,
      Buffer.from(canonicalSha256(payload), "hex"),
      input.idOffset ?? 100_000,
      input.auditEventId,
      input.count
    ]
  );
}

async function seedAdditionalEntitledBoard(
  owner: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>,
  idBase: number
): Promise<string> {
  const boardId = testId(idBase + 1);
  const supportVersionId = testId(idBase + 3);
  await owner.query(
    `insert into boards(id,organization_id,slug,name,timezone)
     values ($1,$2,$3,'Additional briefing board','UTC')`,
    [boardId, actor.organizationId, `briefing-${String(idBase)}`]
  );
  await owner.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
    [testId(idBase + 2), actor.organizationId, boardId, actor.memberId]
  );
  await owner.query(
    `insert into secretary_support_versions(
       id,organization_id,board_id,version,support_name,contact_methods,canonical_sha256,
       effective_at,created_by
     ) values ($1,$2,$3,1,'Additional board secretary','[]',$4,
       transaction_timestamp()-interval '1 minute',$5)`,
    [supportVersionId, actor.organizationId, boardId, testHash(122), actor.memberId]
  );
  await owner.query(
    `insert into onboarding_attestations(
       id,organization_id,member_id,board_id,terms_version_id,support_version_id,
       presentation_choice,local_memory_choice,consent_record_id
     ) select $1,$2,$3,$4,terms.id,$5,'structured','local-only',$6
         from onboarding_terms_versions as terms
        where terms.organization_id=$2 and terms.seat_role='voting_member'
        order by terms.version desc limit 1`,
    [
      testId(idBase + 4),
      actor.organizationId,
      actor.memberId,
      boardId,
      supportVersionId,
      actor.consentRecordId
    ]
  );
  return boardId;
}

function feedData(result: Awaited<ReturnType<PgSurfaceReadRepository["executeRead"]>>): {
  readonly status: string;
  readonly items: readonly Record<string, unknown>[];
  readonly next_cursor: string | null;
  readonly resync?: { readonly reason: string; readonly resync_token: string };
} {
  return result.data as {
    readonly status: string;
    readonly items: readonly Record<string, unknown>[];
    readonly next_cursor: string | null;
    readonly resync?: { readonly reason: string; readonly resync_token: string };
  };
}

describe("PostgreSQL frozen read surface", () => {
  it("keeps document preparation separate from an explicitly observed outcome", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["documents:read"]
      });
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(812_031),
        scopes: ["documents:read"],
        roles: ["member"]
      });
      const documentId = testId(812_032);
      const versionId = testId(812_033);
      const bytes = Buffer.from('Exact "document"\nΔ', "utf8");
      await owner.query(
        "insert into documents(id,organization_id,board_id,title,created_by) values ($1,$2,$3,'Observed document',$4)",
        [documentId, actor.organizationId, actor.boardId, actor.memberId]
      );
      await owner.query(
        `insert into document_versions(id,organization_id,board_id,document_id,version,media_type,
         canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by)
         values ($1,$2,$3,$4,1,'text/plain; charset=utf-8','RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)`,
        [
          versionId,
          actor.organizationId,
          actor.boardId,
          documentId,
          bytes,
          bytes.byteLength,
          Buffer.from(sha256Hex(bytes), "hex"),
          actor.memberId
        ]
      );
      await owner.query(
        "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
        [versionId, documentId]
      );
      await owner.query(
        `insert into document_access_grants(id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by)
         values ($1,$2,$3,$4,$5,'read',$5)`,
        [testId(812_034), actor.organizationId, actor.boardId, documentId, actor.memberId]
      );
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x57),
        transaction: { assumeRole: "boardagent_server" }
      });
      const collector = new ResourceDeliveryCollector();
      const read = await collector.run(async () => {
        const value = await withDirectResponseAllocation(() =>
          repository.executeRead(principal, "read_document", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            document_id: documentId,
            version_id: versionId
          })
        );
        registerPreparedResource(value, 41);
        registerResourceResponse(value, 41, { structuredContent: value });
        return value;
      });
      expect(read.data).toMatchObject({
        canonical_body: bytes.toString("utf8"),
        sha256: sha256Hex(bytes)
      });
      const fetchEvidence = () =>
        owner.query<{ body: Record<string, unknown> }>(
          "select convert_from(canonical_payload,'UTF8')::jsonb as body from audit_events where event_type='resource_fetch' order by sequence"
        );
      const prepared = await fetchEvidence();
      expect(prepared.rows).toHaveLength(1);
      expect(prepared.rows[0]?.body).toMatchObject({
        details: { phase: "prepared", byteLength: bytes.byteLength }
      });
      // This is an explicit in-memory observation, not a test of the blocked HTTP hookup.
      collector.verifyResponse(200, "application/json", {
        jsonrpc: "2.0",
        id: 41,
        result: { structuredContent: read }
      });
      expect(await collector.settle("interrupted", 7)).toEqual([]);
      expect(await collector.settle("completed", 100)).toEqual([]);
      const observed = await fetchEvidence();
      expect(observed.rows).toHaveLength(2);
      expect(observed.rows[1]?.body).toMatchObject({
        actorMemberId: actor.memberId,
        actorClientId: actor.clientId,
        tokenJti: actor.tokenJti,
        details: {
          phase: "interrupted",
          preparedEventId: prepared.rows[0]?.body["eventId"],
          bytesTransferred: null,
          responseBytesQueued: 7,
          outcomeObservationVersion: 1,
          sha256: sha256Hex(bytes),
          byteLength: bytes.byteLength
        }
      });
    });
  });

  it("serves an ordinary own-member read without administrative scope and keeps recovery data private", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(812_001),
        scopes: ["governance:read"],
        roles: ["member"]
      });
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x54),
        transaction: { assumeRole: "boardagent_server" }
      });
      const input = { schema_version: TOOL_INPUT_SCHEMA_VERSION, member_id: actor.memberId };
      const response = await repository.executeRead(principal, "get_member", input);
      expect(response.data).toMatchObject({
        member: { member_id: actor.memberId, recovery_credentials: null }
      });
      await expect(
        repository.executeRead(principal, "get_member", {
          ...input,
          member_id: testId(812_002)
        })
      ).rejects.toThrow("authorization denied: missing_scope");
      await owner.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [actor.accessTokenRecordId]
      );
      await expect(repository.executeRead(principal, "get_member", input)).rejects.toThrow(
        "no longer active"
      );
    });
  });

  it("requires the live admin role for the OAuth client directory", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(812_011),
        scopes: ["secretariat:admin"]
      });
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x55),
        transaction: { assumeRole: "boardagent_server" }
      });
      const input = { schema_version: TOOL_INPUT_SCHEMA_VERSION, cursor: null, limit: 10 };
      await expect(repository.executeRead(principal, "list_oauth_clients", input)).rejects.toThrow(
        "authorization denied: missing_role"
      );
      await owner.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values ($1,$2,$3,'admin','Synthetic directory authority control')",
        [testId(812_012), actor.organizationId, actor.memberId]
      );
      const administrator = { ...principal, roles: ["admin", "member", "secretariat"] };
      const response = await repository.executeRead(administrator, "list_oauth_clients", input);
      expect(response.data).toMatchObject({
        items: [expect.objectContaining({ client_id: actor.clientId })]
      });
    });
  });

  it("prepares exact get_board audit evidence and refuses an unauditable board read", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(812_021),
        scopes: ["governance:read"],
        roles: ["member"]
      });
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x56),
        transaction: { assumeRole: "boardagent_server" }
      });
      const input = { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: actor.boardId };
      const response = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "get_board", input)
      );
      const board = (response.data as { readonly board: unknown }).board;
      expect(board).toMatchObject({ board_id: actor.boardId });
      const events = await owner.query<{ body: unknown }>(
        "select convert_from(canonical_payload,'UTF8')::jsonb as body from audit_events where event_type='resource_fetch' order by sequence"
      );
      expect(events.rows).toHaveLength(1);
      expect(events.rows[0]?.body).toMatchObject({
        actorMemberId: actor.memberId,
        actorClientId: actor.clientId,
        tokenJti: actor.tokenJti,
        entityType: "board",
        entityId: actor.boardId,
        boardId: actor.boardId,
        details: {
          phase: "prepared",
          resourceUri: `board://${actor.boardId}`,
          representation: "application/json",
          sha256: canonicalSha256(board),
          byteLength: Buffer.byteLength(canonicalJson(board)),
          memberId: actor.memberId,
          tokenJti: actor.tokenJti,
          clientId: actor.clientId,
          requestOrigin: principal.serviceOrigin
        }
      });
      await owner.query(`
        create function reject_board_fetch_audit() returns trigger language plpgsql as $$
        begin
          if new.event_type='resource_fetch' then raise exception 'synthetic board audit unavailable'; end if;
          return new;
        end $$;
        create trigger reject_board_fetch_audit before insert on audit_events
        for each row execute function reject_board_fetch_audit();
      `);
      await expect(
        withDirectResponseAllocation(() => repository.executeRead(principal, "get_board", input))
      ).rejects.toThrow("synthetic board audit unavailable");
      const count = await owner.query<{ count: string }>(
        "select count(*)::text as count from audit_events where event_type='resource_fetch'"
      );
      expect(count.rows[0]?.count).toBe("1");
    });
  });

  it("keeps secretary identity reads within the boards where the actor is secretary", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ALL_SURFACE_SCOPES,
        isSecretary: true
      });
      const otherBoardId = await seedAdditionalEntitledBoard(owner, actor, 810_000);
      const firstMember = testId(811_001);
      const otherMember = testId(811_002);
      for (const [memberId, boardId, seatId] of [
        [firstMember, actor.boardId, testId(811_003)],
        [otherMember, otherBoardId, testId(811_004)]
      ]) {
        await owner.query(
          `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
           values ($1,$2,'human','Trial person','Trial person','active')`,
          [memberId, actor.organizationId]
        );
        await owner.query(
          `insert into board_memberships(id,organization_id,board_id,member_id,seat_role,voting_weight)
           values ($1,$2,$3,$4,'voting_member',1)`,
          [seatId, actor.organizationId, boardId, memberId]
        );
      }
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(811_005),
        scopes: ALL_SURFACE_SCOPES,
        boardIds: [actor.boardId, otherBoardId]
      });
      await owner.query(
        `insert into board_memberships(id,organization_id,board_id,member_id,seat_role,voting_weight)
         values ($1,$2,$3,$4,'voting_member',1)`,
        [testId(811_006), actor.organizationId, otherBoardId, firstMember]
      );
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x52),
        transaction: { assumeRole: "boardagent_server" }
      });
      const ownBoardMember = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "get_member", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          member_id: firstMember
        })
      );
      expect.soft(ownBoardMember.data).toMatchObject({ member: { member_id: firstMember } });
      expect(ownBoardMember.data).toMatchObject({
        member: { memberships: [expect.objectContaining({ board_id: actor.boardId })] }
      });
      const otherBoardMember = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "get_member", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          member_id: otherMember
        })
      );
      expect(otherBoardMember.data).toMatchObject({ member: null });
      const otherList = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "list_members", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: otherBoardId,
          state: null,
          cursor: null,
          limit: 100
        })
      );
      expect.soft(feedData(otherList).items).toEqual([]);
      const allList = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "list_members", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: null,
          state: null,
          cursor: null,
          limit: 100
        })
      );
      expect(feedData(allList).items.map((item) => item["member_id"])).toContain(firstMember);
      expect(feedData(allList).items.map((item) => item["member_id"])).not.toContain(otherMember);
      const ownIdentity = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "get_member", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          member_id: actor.memberId
        })
      );
      expect(ownIdentity.data).toMatchObject({
        member: {
          memberships: expect.arrayContaining([
            expect.objectContaining({ board_id: actor.boardId }),
            expect.objectContaining({ board_id: otherBoardId })
          ])
        }
      });
      await owner.query(
        `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
         values ($1,$2,$3,'admin','Synthetic administrator authorization comparison')`,
        [testId(811_007), actor.organizationId, actor.memberId]
      );
      const administrator = { ...principal, roles: ["admin", "member", "secretariat"] };
      const authorizedOther = await withDirectResponseAllocation(() =>
        repository.executeRead(administrator, "get_member", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          member_id: otherMember
        })
      );
      expect(authorizedOther.data).toMatchObject({ member: { member_id: otherMember } });
      const authorizedOtherList = await withDirectResponseAllocation(() =>
        repository.executeRead(administrator, "list_members", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: otherBoardId,
          state: null,
          cursor: null,
          limit: 100
        })
      );
      expect(feedData(authorizedOtherList).items.map((item) => item["member_id"])).toContain(
        otherMember
      );
    });
  });

  it("executes every frozen read tool against live forced-RLS context", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ALL_SURFACE_SCOPES,
        isSecretary: true
      });
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(36_001),
        scopes: ALL_SURFACE_SCOPES,
        roles: ["admin", "member", "secretariat"]
      });
      await owner.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values ($1,$2,$3,'admin','Synthetic all-read directory control')",
        [testId(36_003), actor.organizationId, actor.memberId]
      );
      const publicId = Buffer.alloc(24, 0x7a).toString("base64url");
      const absentId = testId(36_002);
      const schemaVersion = TOOL_INPUT_SCHEMA_VERSION;
      type ReadInput = Parameters<PgSurfaceReadRepository["executeRead"]>[2];
      const cases: ReadonlyArray<{ readonly tool: string; readonly input: ReadInput }> = [
        { tool: "whoami", input: { schema_version: schemaVersion } },
        { tool: "list_administrative_access", input: { schema_version: schemaVersion } },
        {
          tool: "list_my_boards",
          input: { schema_version: schemaVersion, cursor: null, limit: 1 }
        },
        {
          tool: "get_board",
          input: { schema_version: schemaVersion, board_id: actor.boardId }
        },
        {
          tool: "get_my_board_snapshot",
          input: { schema_version: schemaVersion, board_id: actor.boardId }
        },
        {
          tool: "list_my_updates",
          input: { schema_version: schemaVersion, cursor: null, limit: 1 }
        },
        {
          tool: "list_pending_actions",
          input: { schema_version: schemaVersion, cursor: null, limit: 1_000 }
        },
        {
          tool: "get_onboarding",
          input: { schema_version: schemaVersion, board_id: actor.boardId }
        },
        {
          tool: "get_onboarding_status",
          input: { schema_version: schemaVersion, board_id: actor.boardId }
        },
        {
          tool: "get_board_governance_profile",
          input: { schema_version: schemaVersion, board_id: actor.boardId, version: null }
        },
        {
          tool: "list_approval_rule_templates",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "list_matter_types",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_ruleset",
          input: { schema_version: schemaVersion, board_id: actor.boardId, ruleset_id: null }
        },
        {
          tool: "list_ruleset_versions",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "validate_ruleset_draft",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            draft: { schema_version: "boardagent.ruleset-draft.v1", values: {} },
            citations: [
              {
                document_version_id: absentId,
                sha256: testHash(0x41).toString("hex"),
                clause: "test clause",
                locator: "test locator"
              }
            ]
          }
        },
        {
          tool: "list_documents",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "read_document",
          input: { schema_version: schemaVersion, document_id: absentId, version_id: null }
        },
        {
          tool: "search_documents",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            query: "absent",
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_document_hash",
          input: {
            schema_version: schemaVersion,
            document_id: absentId,
            version_id: absentId
          }
        },
        {
          tool: "list_document_versions",
          input: {
            schema_version: schemaVersion,
            document_id: absentId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_document_validation_status",
          input: { schema_version: schemaVersion, validation_attempt_id: absentId }
        },
        {
          tool: "list_management_submissions",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_management_submission",
          input: { schema_version: schemaVersion, submission_id: absentId }
        },
        {
          tool: "list_management_questions",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_management_question",
          input: { schema_version: schemaVersion, question_id: absentId }
        },
        {
          tool: "list_meetings",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_agenda",
          input: { schema_version: schemaVersion, meeting_id: absentId, version: null }
        },
        {
          tool: "get_attendance",
          input: { schema_version: schemaVersion, meeting_id: absentId }
        },
        {
          tool: "list_meeting_transcripts",
          input: {
            schema_version: schemaVersion,
            meeting_id: absentId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_meeting_transcript",
          input: { schema_version: schemaVersion, transcript_id: absentId, version_id: null }
        },
        {
          tool: "list_votes",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        { tool: "get_vote", input: { schema_version: schemaVersion, vote_id: absentId } },
        {
          tool: "get_vote_lineage",
          input: { schema_version: schemaVersion, vote_id: absentId }
        },
        {
          tool: "get_proxy_status",
          input: { schema_version: schemaVersion, vote_id: absentId, member_id: null }
        },
        {
          tool: "get_vote_certificate",
          input: { schema_version: schemaVersion, vote_id: absentId, certificate_id: null }
        },
        {
          tool: "verify_certificate",
          input: { schema_version: schemaVersion, public_id: publicId, bundle: null }
        },
        { tool: "get_minutes", input: { schema_version: schemaVersion, minutes_id: absentId } },
        {
          tool: "list_minutes_versions",
          input: {
            schema_version: schemaVersion,
            minutes_id: absentId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_minutes_lineage",
          input: { schema_version: schemaVersion, minutes_id: absentId }
        },
        {
          tool: "list_minutes_review_items",
          input: {
            schema_version: schemaVersion,
            minutes_id: absentId,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "list_my_tasks",
          input: { schema_version: schemaVersion, cursor: null, limit: 1 }
        },
        {
          tool: "list_action_items",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            cursor: null,
            limit: 1
          }
        },
        { tool: "get_task", input: { schema_version: schemaVersion, task_id: absentId } },
        {
          tool: "get_action_item",
          input: { schema_version: schemaVersion, task_id: absentId }
        },
        {
          tool: "list_proposals",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            state: null,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "list_secretariat_requests",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            state: null,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "list_members",
          input: {
            schema_version: schemaVersion,
            board_id: actor.boardId,
            state: null,
            cursor: null,
            limit: 1
          }
        },
        {
          tool: "get_member",
          input: { schema_version: schemaVersion, member_id: actor.memberId }
        },
        {
          tool: "list_enrollments",
          input: { schema_version: schemaVersion, state: null, cursor: null, limit: 1 }
        },
        {
          tool: "list_my_sessions",
          input: { schema_version: schemaVersion, cursor: null, limit: 1 }
        },
        {
          tool: "list_oauth_clients",
          input: { schema_version: schemaVersion, cursor: null, limit: 1 }
        },
        {
          tool: "verify_audit_chain",
          input: {
            schema_version: schemaVersion,
            export_id: null,
            from_sequence: null,
            to_sequence: null
          }
        },
        {
          tool: "get_export_status",
          input: { schema_version: schemaVersion, export_id: publicId }
        },
        {
          tool: "read_export_chunk",
          input: {
            schema_version: schemaVersion,
            export_id: publicId,
            chunk_no: 0,
            recent_auth_proof: publicId
          }
        },
        { tool: "get_retention_policy", input: { schema_version: schemaVersion } },
        {
          tool: "list_my_webhooks",
          input: { schema_version: schemaVersion, cursor: null, limit: 1 }
        },
        {
          tool: "list_my_drafts",
          input: {
            schema_version: schemaVersion,
            draft_type: null,
            cursor: null,
            limit: 1
          }
        },
        { tool: "resume_draft", input: { schema_version: schemaVersion, draft_id: absentId } }
      ];
      expect(cases.map(({ tool }) => tool).toSorted()).toEqual(
        [...BOARDAGENT_TOOL_BY_NAME.values()]
          .filter(({ class: toolClass }) => toolClass === "R")
          .map(({ name }) => name)
          .toSorted()
      );

      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x50),
        transaction: { assumeRole: "boardagent_server" },
        exportChunks: {
          readExactChunk: async () => Buffer.alloc(0)
        }
      });
      for (const readCase of cases) {
        // Every direct read runs under a synthetic allocation owner: the projections that
        // reserve response capacity refuse without one, exactly as the native path does.
        const read = await withDirectResponseAllocation(() =>
          repository.executeRead(principal, readCase.tool, readCase.input)
        );
        expect(read, readCase.tool).toMatchObject({ tool: readCase.tool, status: "ok" });
      }

      const invalidBundle = await repository.executeRead(principal, "verify_certificate", {
        schema_version: schemaVersion,
        public_id: null,
        bundle: "{}"
      });
      expect(invalidBundle.data).toEqual({ valid: false });

      const boardResource = await withDirectResponseAllocation(() =>
        repository.readResource(principal, new URL(`board://${actor.boardId}`))
      );
      expect(boardResource).toMatchObject({
        uri: `board://${actor.boardId}`,
        media_type: "application/json"
      });
      const absentResources = [
        `board://${actor.boardId}/governance-profile/1`,
        `board://${actor.boardId}/rulesets/1`,
        `board://${actor.boardId}/documents/${absentId}/versions/1`,
        `board://${actor.boardId}/submissions/${absentId}/versions/1`,
        `board://${actor.boardId}/questions/${absentId}`,
        `board://${actor.boardId}/meetings/${absentId}/agendas/1`,
        `board://${actor.boardId}/meetings/${absentId}/transcripts/1`,
        `board://${actor.boardId}/minutes/${absentId}/versions/1`,
        `board://${actor.boardId}/minutes/${absentId}/review/${absentId}`,
        `board://${actor.boardId}/action-items/${absentId}`,
        `board://${actor.boardId}/tasks/${absentId}`,
        `board://${actor.boardId}/votes/${absentId}`,
        `board://${actor.boardId}/votes/${absentId}/packages/1`,
        `board://${actor.boardId}/votes/${absentId}/certificates/${absentId}`,
        `export://${publicId}/chunks/0`
      ];
      for (const uri of absentResources) {
        await expect(
          withDirectResponseAllocation(() => repository.readResource(principal, new URL(uri))),
          uri
        ).rejects.toThrow("resource unavailable");
      }
      await expect(
        repository.readResource(principal, new URL(`board://${actor.boardId}/governance-profile/0`))
      ).rejects.toThrow("resource version is invalid");
      await expect(
        repository.readResource(
          principal,
          new URL(`board://${actor.boardId}/governance-profile/999999999999999999999999999999999`)
        )
      ).rejects.toThrow("resource version is invalid");
      await expect(
        repository.readResource(principal, new URL(`board://${actor.boardId}/unknown`))
      ).rejects.toThrow("resource URI does not match the frozen registry");
      await expect(
        repository.readResource(principal, new URL(`export://${publicId}/chunks/00`))
      ).rejects.toThrow("resource URI does not match the frozen registry");
      await expect(
        repository.readResource(
          principal,
          new URL(`export://${publicId}/chunks/999999999999999999999999999999999`)
        )
      ).rejects.toThrow("export chunk number is invalid");
      await expect(
        repository.readResource(principal, new URL(`board://${actor.boardId}?query=1`))
      ).rejects.toThrow("resource URI is not canonical");
      await expect(
        repository.readResource(principal, new URL("https://boardagent.test/not-a-resource"))
      ).rejects.toThrow("resource unavailable");
    });
  });

  it("binds live token context, serves entitled reads/resources, and records fetch evidence", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read", "onboarding:read"],
        isSecretary: true
      });
      const sessionId = testId(36_101);
      await owner.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, testHash(101), actor.memberId, actor.clientId]
      );
      await owner.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);

      const principal: SurfacePrincipal = {
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        serviceOrigin: "https://boardagent.test",
        clientId: actor.clientId,
        protocolClientId: "authorized-test-client",
        accessTokenRecordId: actor.accessTokenRecordId,
        tokenJti: actor.tokenJti,
        keyId: "test-oauth",
        scopes: ["governance:read", "onboarding:read"],
        roles: ["member", "secretariat"],
        boardIds: [actor.boardId]
      };
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x51),
        transaction: { assumeRole: "boardagent_server" }
      });

      const identity = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "whoami", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION
        })
      );
      expect(identity.data).toMatchObject({ member_id: actor.memberId });

      const boards = await withDirectResponseAllocation(() =>
        repository.executeRead(principal, "list_my_boards", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: null,
          limit: 10
        })
      );
      expect(boards.data).toMatchObject({
        items: [{ board_id: actor.boardId, seat_role: "voting_member", is_secretary: true }]
      });

      const resource = await withDirectResponseAllocation(() =>
        repository.readResource(principal, new URL(`board://${actor.boardId}`))
      );
      expect(resource.media_type).toBe("application/json");
      expect(JSON.parse(resource.text ?? "{}")).toMatchObject({ board_id: actor.boardId });
      const evidence = await owner.query<{ phase: string }>(
        `select convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'phase' as phase
           from audit_events where event_type='resource_fetch' order by sequence desc limit 2`
      );
      // Repository return is preparation only. A bare call cannot observe HTTP finish.
      expect(evidence.rows.map(({ phase }) => phase)).toEqual(["prepared"]);

      await owner.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [actor.accessTokenRecordId]
      );
      await expect(
        withDirectResponseAllocation(() =>
          repository.executeRead(principal, "whoami", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION
          })
        )
      ).rejects.toThrow("no longer active");
    });
  });

  it("returns exactly 0, 1, or 1000 own briefing deltas and signs overflow resync", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read", "onboarding:read"],
        isSecretary: true
      });
      const principal = await surfacePrincipal(owner, actor, { sessionId: testId(36_201) });
      const auditEventId = await seedFeedAudit(owner, actor, testId(36_202));
      const otherMemberId = testId(36_203);
      await owner.query(
        `insert into members(
           id,organization_id,member_kind,legal_name,display_name,state
         ) values ($1,$2,'human','Other member','Other member','active')`,
        [otherMemberId, actor.organizationId]
      );
      await owner.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,voting_weight,state
         ) values ($1,$2,$3,$4,'voting_member',1,'active')`,
        [testId(36_204), actor.organizationId, actor.boardId, otherMemberId]
      );
      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        memberId: otherMemberId,
        auditEventId,
        count: 1,
        idOffset: 400_000
      });

      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x61),
        transaction: { assumeRole: "boardagent_server" }
      });
      const empty = feedData(
        await repository.executeRead(principal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: null
        })
      );
      expect(empty).toMatchObject({ status: "complete", items: [] });
      expect(empty.next_cursor).toEqual(expect.any(String));

      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        memberId: actor.memberId,
        auditEventId,
        count: 1_000,
        idOffset: 200_000
      });
      const bounded = feedData(
        await repository.executeRead(principal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: empty.next_cursor
        })
      );
      expect(bounded.status).toBe("complete");
      expect(bounded.items).toHaveLength(1_000);
      expect(new Set(bounded.items.map((item) => item.object_id)).size).toBe(1_000);
      expect(bounded.items.every((item) => item.entry_kind === "feed")).toBe(true);
      expect(bounded.next_cursor).toEqual(expect.any(String));

      const stable = feedData(
        await repository.executeRead(principal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: bounded.next_cursor
        })
      );
      expect(stable).toMatchObject({ status: "complete", items: [] });

      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        memberId: actor.memberId,
        auditEventId,
        count: 1,
        sequenceOffset: 1_000,
        idOffset: 300_000
      });
      const one = feedData(
        await repository.executeRead(principal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: bounded.next_cursor
        })
      );
      expect(one).toMatchObject({ status: "complete" });
      expect(one.items).toHaveLength(1);
      expect(one.items[0]).toMatchObject({ feed_sequence: "1001", entry_kind: "feed" });

      const overflow = feedData(
        await repository.executeRead(principal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: null
        })
      );
      expect(overflow).toMatchObject({
        status: "briefing_overflow",
        items: [],
        next_cursor: null,
        resync: { reason: "briefing_overflow" }
      });
      const resyncToken = overflow.resync?.resync_token;
      expect(resyncToken).toEqual(expect.any(String));
      if (!resyncToken) throw new Error("briefing overflow did not return a resync token");
      const afterResync = feedData(
        await repository.executeRead(principal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: resyncToken
        })
      );
      expect(afterResync).toMatchObject({ status: "complete", items: [] });
      await expect(
        repository.executeRead(principal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: `${resyncToken.startsWith("A") ? "B" : "A"}${resyncToken.slice(1)}`
        })
      ).rejects.toThrow("cursor is invalid");
    });
  });

  it("returns an own tombstone and signed resync after entitlement revocation", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read", "onboarding:read"],
        isSecretary: true
      });
      const activePrincipal = await surfacePrincipal(owner, actor, {
        sessionId: testId(36_301)
      });
      const auditEventId = await seedFeedAudit(owner, actor, testId(36_302));
      const feedIdOffset = 500_000;
      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        memberId: actor.memberId,
        auditEventId,
        count: 1,
        idOffset: feedIdOffset
      });
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x62),
        transaction: { assumeRole: "boardagent_server" }
      });
      const beforeRevocation = feedData(
        await repository.executeRead(activePrincipal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: null
        })
      );
      expect(beforeRevocation.items).toHaveLength(1);
      expect(beforeRevocation.next_cursor).toEqual(expect.any(String));

      const removedFeedId = testId(feedIdOffset + 1);
      await owner.query(
        `insert into feed_tombstones(
           id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
           removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
         )
         select $1,feed.organization_id,feed.board_id,feed.member_id,
                feed.entitlement_generation,feed.feed_sequence,feed.id,
                feed.object_type,feed.object_id,'revoked',$2,$3
           from pending_action_feed as feed where feed.id=$4`,
        [testId(36_303), testHash(121), auditEventId, removedFeedId]
      );
      await owner.query(
        `update board_memberships
            set state='ended',active_until=transaction_timestamp(),
                entitlement_generation=entitlement_generation+1
          where organization_id=$1 and board_id=$2 and member_id=$3`,
        [actor.organizationId, actor.boardId, actor.memberId]
      );
      const revokedPrincipal: SurfacePrincipal = {
        ...activePrincipal,
        roles: [],
        boardIds: []
      };
      const stale = feedData(
        await repository.executeRead(revokedPrincipal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: beforeRevocation.next_cursor
        })
      );
      expect(stale).toMatchObject({
        status: "entitlement_resync_required",
        next_cursor: null,
        resync: { reason: "entitlement_changed" },
        items: [
          {
            entry_kind: "tombstone",
            action_type: "tombstone",
            object_id: beforeRevocation.items[0]?.object_id,
            payload: { reasonClass: "revoked", removedFeedId }
          }
        ]
      });
      const resyncToken = stale.resync?.resync_token;
      if (!resyncToken) throw new Error("entitlement resync did not return a token");
      const afterResync = feedData(
        await repository.executeRead(revokedPrincipal, "list_pending_actions", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: resyncToken
        })
      );
      expect(afterResync).toMatchObject({ status: "complete", items: [] });
    });
  });

  it("delivers late low-sequence board events and completion state after a saved cursor", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read", "onboarding:read"],
        isSecretary: true
      });
      const otherBoard = await seedAdditionalEntitledBoard(owner, actor, 36_500);
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(36_551),
        boardIds: [actor.boardId, otherBoard]
      });
      const auditEventId = await seedFeedAudit(owner, actor, testId(36_552));
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x64),
        transaction: { assumeRole: "boardagent_server" }
      });
      const updates = async (cursor: string | null) =>
        feedData(
          await repository.executeRead(principal, "list_my_updates", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            cursor,
            limit: 100
          })
        );
      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        memberId: actor.memberId,
        auditEventId,
        count: 1,
        sequenceOffset: 49,
        idOffset: 800_000
      });
      const first = await updates(null);
      expect(first.items).toHaveLength(1);
      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: otherBoard,
        memberId: actor.memberId,
        auditEventId,
        count: 1,
        idOffset: 810_000
      });
      const late = await updates(first.next_cursor);
      expect(late.items).toHaveLength(1);
      expect(late.items[0]).toMatchObject({
        board_id: otherBoard,
        feed_sequence: "1",
        state: "pending"
      });
      // Keep the original immutable payload, notice and feed sequence; only the
      // existing completion projection changes, as actual signature/task flows do.
      const before = await owner.query(
        "select encode(payload_sha256,'hex') as hash,feed_sequence::text,canonical_payload from pending_action_feed where id=$1",
        [testId(810_001)]
      );
      await owner.query(
        "update pending_action_feed set state='resolved',resolved_at=transaction_timestamp() where id=$1",
        [testId(810_001)]
      );
      const completed = await updates(late.next_cursor);
      expect(completed.items).toHaveLength(1);
      expect(completed.items[0]).toMatchObject({
        board_id: otherBoard,
        object_id: testId(1_810_001),
        state: "resolved"
      });
      const after = await owner.query(
        "select encode(payload_sha256,'hex') as hash,feed_sequence::text,canonical_payload from pending_action_feed where id=$1",
        [testId(810_001)]
      );
      expect(after.rows).toEqual(before.rows);
      expect((await updates(completed.next_cursor)).items).toEqual([]);
    });
  });

  it("upgrades existing feed and tombstone positions without changing original evidence", async () => {
    const priorMigrations = await mkdtemp(path.join(tmpdir(), "boardagent-feed-upgrade-"));
    try {
      for (const name of await readdir(MIGRATIONS)) {
        if (/^\d{4}_.+\.sql$/u.test(name) && Number(name.slice(0, 4)) <= 146) {
          await copyFile(path.join(MIGRATIONS, name), path.join(priorMigrations, name));
        }
      }
      await withDatabase(async (owner) => {
        const actor = await seedAuthorizedActor(owner, {
          seatRole: "voting_member",
          scopes: ["governance:read", "onboarding:read"],
          isSecretary: true
        });
        const principal = await surfacePrincipal(owner, actor, { sessionId: testId(36_801) });
        const auditEventId = await seedFeedAudit(owner, actor, testId(36_802));
        await seedPendingFeed(owner, { ...actor, auditEventId, count: 1, idOffset: 850_000 });
        await owner.query(
          "update pending_action_feed set state='resolved',resolved_at=transaction_timestamp() where id=$1",
          [testId(850_001)]
        );
        await owner.query(
          `insert into feed_tombstones(id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id)
          select $2,organization_id,board_id,member_id,entitlement_generation,feed_sequence+1,id,object_type,object_id,'resolved',$3,audit_event_id from pending_action_feed where id=$1`,
          [testId(850_001), testId(36_803), testHash(117)]
        );
        const originals = async () =>
          (
            await owner.query(`select row_to_json(source)::text as original from pending_action_feed as source
          union all select row_to_json(source)::text from feed_tombstones as source order by original`)
          ).rows;
        const before = await originals();
        await migrate(owner, MIGRATIONS, "feed-sync-upgrade-test");
        expect(await originals()).toEqual(before);
        expect(
          (await owner.query("select count(*)::int as n from member_feed_sync_positions")).rows[0]
            ?.n
        ).toBe(2);
        const repository = new PgSurfaceReadRepository(owner, {
          cursorKey: Buffer.alloc(32, 0x67),
          transaction: { assumeRole: "boardagent_server" }
        });
        const all = feedData(
          await repository.executeRead(principal, "list_my_updates", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            cursor: null,
            limit: 100
          })
        );
        expect(all.items.map((item) => item.entry_kind)).toEqual(["feed", "tombstone"]);
        expect(all.items.every((item) => item.state === "resolved")).toBe(true);
        await seedPendingFeed(owner, {
          ...actor,
          auditEventId,
          count: 1,
          sequenceOffset: 2,
          idOffset: 860_000
        });
        const next = feedData(
          await repository.executeRead(principal, "list_my_updates", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            cursor: all.next_cursor,
            limit: 100
          })
        );
        expect(next.items).toHaveLength(1);
        expect(next.items[0]).toMatchObject({ object_id: testId(1_860_001), state: "pending" });
      }, priorMigrations);
    } finally {
      await rm(priorMigrations, { recursive: true, force: true });
    }
  });

  it("resynchronizes signed legacy cursors and keeps the position index private", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read", "onboarding:read"],
        isSecretary: true
      });
      const principal = await surfacePrincipal(owner, actor, { sessionId: testId(36_601) });
      const auditEventId = await seedFeedAudit(owner, actor, testId(36_602));
      await seedPendingFeed(owner, { ...actor, auditEventId, count: 1, idOffset: 820_000 });
      const key = Buffer.alloc(32, 0x65);
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: key,
        transaction: { assumeRole: "boardagent_server" }
      });
      const updates = async (cursor: string | null) =>
        feedData(
          await repository.executeRead(principal, "list_my_updates", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            cursor,
            limit: 100
          })
        );
      const current = await updates(null);
      const codec = createCursorCodec(key);
      const binding = {
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        tool: "list_my_updates",
        boardId: null
      };
      const decoded = JSON.parse(codec.verify(current.next_cursor!, binding));
      expect(decoded.schemaVersion).toBe("boardagent.briefing-cursor.v2");
      const legacy = codec.mint(
        binding,
        canonicalJson({ ...decoded, schemaVersion: "boardagent.briefing-cursor.v1" })
      );
      const reset = await updates(legacy);
      expect(reset).toMatchObject({
        status: "cursor_resync_required",
        items: [],
        next_cursor: null,
        resync: { reason: "cursor_version_changed" }
      });
      expect((await updates(reset.resync!.resync_token)).items).toEqual(current.items);
      const rights =
        await owner.query(`select has_table_privilege('boardagent_server','member_feed_sync_positions','INSERT,UPDATE,DELETE') as writes,
        has_table_privilege('boardagent_server','member_feed_sync_counters','SELECT,INSERT,UPDATE,DELETE') as counter_access,
        has_function_privilege('boardagent_server','boardagent_track_feed_sync_position()','EXECUTE') as trigger_access`);
      expect(rights.rows[0]).toEqual({
        writes: false,
        counter_access: false,
        trigger_access: false
      });
      const hidden = await withRequestTransaction(
        owner,
        { ...actor.context, memberId: testId(36_603) },
        (client) => client.query("select count(*)::int as n from member_feed_sync_positions"),
        { assumeRole: "boardagent_server" }
      );
      expect(hidden.rows[0]?.n).toBe(0);
      const outsideBoard = await withRequestTransaction(
        owner,
        { ...actor.context, boardIds: [] },
        (client) => client.query("select count(*)::int as n from member_feed_sync_positions"),
        { assumeRole: "boardagent_server" }
      );
      expect(outsideBoard.rows[0]?.n).toBe(0);
    });
  });

  it.each(["commit", "rollback"] as const)(
    "serializes cross-board positions through %s without exposing or skipping uncommitted changes",
    async (finish) => {
      await withDatabase(async (owner) => {
        const actor = await seedAuthorizedActor(owner, {
          seatRole: "voting_member",
          scopes: ["governance:read", "onboarding:read"],
          isSecretary: true
        });
        const otherBoard = await seedAdditionalEntitledBoard(owner, actor, 36_700);
        const principal = await surfacePrincipal(owner, actor, {
          sessionId: testId(36_751),
          boardIds: [actor.boardId, otherBoard]
        });
        const auditEventId = await seedFeedAudit(owner, actor, testId(36_752));
        const repository = new PgSurfaceReadRepository(owner, {
          cursorKey: Buffer.alloc(32, 0x66),
          transaction: { assumeRole: "boardagent_server" }
        });
        const updates = async (cursor: string | null) =>
          feedData(
            await repository.executeRead(principal, "list_my_updates", {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              cursor,
              limit: 100
            })
          );
        const initial = await updates(null);
        const first = await owner.connect(),
          second = await owner.connect();
        let secondInsert: Promise<void> | undefined;
        try {
          await first.query("begin");
          await second.query("begin");
          const firstPid = (await first.query("select pg_backend_pid() as pid")).rows[0]
            .pid as number;
          const secondPid = (await second.query("select pg_backend_pid() as pid")).rows[0]
            .pid as number;
          await seedPendingFeed(first, {
            ...actor,
            boardId: otherBoard,
            auditEventId,
            count: 1,
            idOffset: 830_000
          });
          secondInsert = seedPendingFeed(second, {
            ...actor,
            auditEventId,
            count: 1,
            sequenceOffset: 99,
            idOffset: 840_000
          });
          // Observe the actual transaction lock, rather than treating elapsed time as proof.
          let blockers: number[] = [];
          for (let attempt = 0; attempt < 100; attempt++) {
            blockers = (await owner.query("select pg_blocking_pids($1) as blockers", [secondPid]))
              .rows[0].blockers as number[];
            if (blockers.includes(firstPid)) break;
            await new Promise((resolve) => setTimeout(resolve, 5));
          }
          expect(blockers).toContain(firstPid);
          expect((await updates(initial.next_cursor)).items).toEqual([]);
          await first.query(finish);
          await secondInsert;
          const middle = await updates(initial.next_cursor);
          expect(middle.items.map((item) => item.board_id)).toEqual(
            finish === "commit" ? [otherBoard] : []
          );
          await second.query("commit");
          const last = await updates(middle.next_cursor);
          expect(last.items.map((item) => item.board_id)).toEqual([actor.boardId]);
          expect((await updates(last.next_cursor)).items).toEqual([]);
        } finally {
          await first.query("rollback");
          await secondInsert?.catch(() => undefined);
          await second.query("rollback");
          first.release();
          second.release();
        }
      });
    }
  );

  it("paginates equal feed sequences across boards without omission or replay", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read", "onboarding:read"],
        isSecretary: true
      });
      const secondBoardId = await seedAdditionalEntitledBoard(owner, actor, 36_400);
      const principal = await surfacePrincipal(owner, actor, {
        sessionId: testId(36_451),
        boardIds: [actor.boardId, secondBoardId]
      });
      const auditEventId = await seedFeedAudit(owner, actor, testId(36_452));
      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        memberId: actor.memberId,
        auditEventId,
        count: 1,
        idOffset: 600_000
      });
      await seedPendingFeed(owner, {
        organizationId: actor.organizationId,
        boardId: secondBoardId,
        memberId: actor.memberId,
        auditEventId,
        count: 1,
        idOffset: 700_000
      });

      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x63),
        transaction: { assumeRole: "boardagent_server" }
      });
      const first = feedData(
        await repository.executeRead(principal, "list_my_updates", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: null,
          limit: 1
        })
      );
      expect(first.items).toHaveLength(1);
      expect(first.next_cursor).toEqual(expect.any(String));

      const second = feedData(
        await repository.executeRead(principal, "list_my_updates", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: first.next_cursor,
          limit: 1
        })
      );
      expect(second.items).toHaveLength(1);
      expect(new Set([first.items[0]?.board_id, second.items[0]?.board_id])).toEqual(
        new Set([actor.boardId, secondBoardId])
      );

      const stable = feedData(
        await repository.executeRead(principal, "list_my_updates", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: second.next_cursor,
          limit: 1
        })
      );
      expect(stable).toMatchObject({ status: "complete", items: [] });
    });
  });
});

describe("administrator owned draft validation", () => {
  it("allows an administrator without a board seat to validate only their submitted rules draft", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin", "governance:read"]
      });
      await owner.query(
        `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
        values($1,$2,$3,'admin','Synthetic draft validation')`,
        [testId(899100), actor.organizationId, actor.memberId]
      );
      await owner.query(
        "update board_memberships set state='ended',active_until=transaction_timestamp() where member_id=$1",
        [actor.memberId]
      );
      const p = await surfacePrincipal(owner, actor, {
        sessionId: testId(899101),
        roles: ["admin"],
        boardIds: [],
        scopes: ["secretariat:admin", "governance:read"]
      });
      const repository = new PgSurfaceReadRepository(owner, {
        cursorKey: Buffer.alloc(32, 0x52),
        transaction: { assumeRole: "boardagent_server" }
      });
      const answer = await repository.executeRead(p, "validate_ruleset_draft", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: actor.boardId,
        citations: [
          {
            document_version_id: testId(899102),
            sha256: "a".repeat(64),
            clause: "Synthetic",
            locator: "Only input data"
          }
        ],
        draft: { schema_version: "boardagent.ruleset.v1", values: {} }
      });
      expect(answer.data).toMatchObject({ valid: false, issues: expect.any(Array) });
      await expect(
        repository.executeRead(p, "get_board", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId
        })
      ).rejects.toThrow("outside_board");
      expect((await owner.query("select count(*)::int as n from rulesets")).rows[0].n).toBe(0);
    });
  });
});
