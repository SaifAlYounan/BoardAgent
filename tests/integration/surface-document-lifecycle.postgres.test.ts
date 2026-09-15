import path from "node:path";
import { withDirectResponseAllocation } from "../helpers/direct-response-allocation.js";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { migrate, withRequestTransaction } from "../../lib/db/src/index.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_surface_document_lifecycle_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  let passed = false;
  try {
    await migrate(pool, MIGRATIONS, "surface-document-lifecycle-test");
    const value = await run(pool);
    passed = true;
    return value;
  } finally {
    await pool.end();
    if (passed) await dropClosedTestDatabase(admin, database);
    else console.error(`Preserved failed fixture database: ${database}`);
    await admin.end();
  }
}

function principal(
  actor: AuthorizedActorFixture,
  roles: readonly ("admin" | "member" | "observer" | "secretariat")[],
  scopes: readonly string[]
): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://document-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes,
    roles,
    boardIds: [actor.boardId]
  };
}

let confirmationSequence = 0;

async function confirmSurfaceAction(
  service: BoardAgentSurfaceService,
  actorPrincipal: SurfacePrincipal,
  tool: string,
  input: JsonValue
) {
  confirmationSequence += 1;
  const requestLabel = `surface-document-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const prepared = await service.prepareHumanAction(actorPrincipal, tool, input);
  expect(prepared).toMatchObject({ action_code: tool, target_type: "document" });
  const clientCapabilities = { elicitation: { form: {} } } as const;
  const requestState = `${requestLabel}-request-state-bound-by-client`;
  await service.persistHumanStage({
    principal: actorPrincipal,
    tool,
    input,
    prepared,
    client_capabilities: clientCapabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm exact ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${requestLabel}-prepare`)
  });
  const resolution = await service.resolveHumanAction({
    principal: actorPrincipal,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: clientCapabilities,
    request_state: requestState,
    retry_request_id: Buffer.from(`${requestLabel}-retry`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolution.confirmed) throw new Error(`${tool} failed: ${resolution.reason}`);
  return resolution.result;
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by document lifecycle test");
  },
  readResource: async () => {
    throw new Error("resource read not used by document lifecycle test");
  }
};

async function canRead(
  pool: Pool,
  actor: AuthorizedActorFixture,
  documentId: string
): Promise<boolean> {
  return withRequestTransaction(
    pool,
    actor.context,
    async (client) => {
      const permission = await client.query<{ allowed: boolean }>(
        "select boardagent_document_permission($1,'read') as allowed",
        [documentId]
      );
      return permission.rows[0]?.allowed ?? false;
    },
    { assumeRole: "boardagent_server" }
  );
}

describe("confirmed document lifecycle surface", () => {
  it.each(["manage_document_access", "manage_recusal"] as const)(
    "%s grants exact access, circulates, excludes, restores, archives, and soft-deletes without purging",
    async (recusalTool) => {
      await withDatabase(async (pool) => {
        const secretary = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["documents:contribute", "secretariat:admin"],
          isSecretary: true
        });
        await pool.query(
          `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','Document lifecycle test administrator.')`,
          [testId(140_000), secretary.organizationId, secretary.memberId]
        );
        const member = await seedAdditionalAuthorizedActor(pool, secretary, {
          idBase: 140_100,
          seatRole: "voting_member",
          scopes: ["documents:read"]
        });
        const observer = await seedAdditionalAuthorizedActor(pool, secretary, {
          idBase: 140_200,
          seatRole: "observer",
          scopes: ["documents:read"]
        });
        const adminOnly = await seedAdditionalAuthorizedActor(pool, secretary, {
          idBase: 140_300,
          seatRole: "voting_member",
          scopes: ["secretariat:admin"]
        });
        await pool.query(
          `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','Exact document administrator boundary test.')`,
          [testId(140_350), secretary.organizationId, adminOnly.memberId]
        );
        const secretaryOnly = await seedAdditionalAuthorizedActor(pool, secretary, {
          idBase: 140_400,
          seatRole: "voting_member",
          scopes: ["secretariat:admin"],
          isSecretary: true
        });
        let nextId = 140_500;
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableReads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(nextId++)
        });
        const secretaryPrincipal = principal(
          secretary,
          ["admin", "member", "secretariat"],
          ["documents:contribute", "secretariat:admin"]
        );
        const body = "# Exploration programme\n\nPhase one drilling and permit controls.\n";
        const documentId = testId(141_000);
        const contributionInput = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: secretary.boardId,
          document_id: documentId,
          title: "Exploration programme",
          media_type: "text/markdown; charset=utf-8",
          schema_name: null,
          canonical_body: body,
          expected_current_version_id: null,
          idempotency_key: "surface-document-lifecycle-create-0001"
        };
        const created = await service.executeDirect(
          secretaryPrincipal,
          "create_document_version",
          contributionInput
        );
        if (created.reference === null) throw new Error("document version reference is missing");
        await expect(
          service.executeDirect(secretaryPrincipal, "create_document_version", contributionInput)
        ).resolves.toMatchObject({
          status: "already_applied",
          reference: created.reference
        });

        await expect(
          withRequestTransaction(
            pool,
            adminOnly.context,
            async (client) => {
              const authority = await client.query<{ admin: boolean; secretary: boolean }>(
                `select boardagent_document_admin_for_board($1) as admin,
                      boardagent_document_secretary_for_board($1) as secretary`,
                [secretary.boardId]
              );
              expect(authority.rows[0]).toEqual({ admin: true, secretary: false });
              await client.query(
                `insert into document_circulations(
                 id,organization_id,board_id,document_id,document_version_id,
                 document_sha256,recipient_policy,package_sha256,consent_record_id,
                 circulated_by,state
               ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'committed')`,
                [
                  testId(141_100),
                  secretary.organizationId,
                  secretary.boardId,
                  documentId,
                  created.reference,
                  Buffer.from(sha256Hex(body), "hex"),
                  { recipient_member_ids: [member.memberId] },
                  Buffer.alloc(32, 101),
                  adminOnly.consentRecordId,
                  adminOnly.memberId
                ]
              );
            },
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toThrow("row-level security policy");

        await expect(
          withRequestTransaction(
            pool,
            secretaryOnly.context,
            async (client) => {
              const authority = await client.query<{ admin: boolean; secretary: boolean }>(
                `select boardagent_document_admin_for_board($1) as admin,
                      boardagent_document_secretary_for_board($1) as secretary`,
                [secretary.boardId]
              );
              expect(authority.rows[0]).toEqual({ admin: false, secretary: true });
              await client.query(
                `insert into retention_snapshots(
                 id,organization_id,board_id,object_type,object_id,object_version,
                 canonical_schema,canonical_payload,canonical_sha256,content_references
               ) values ($1,$2,$3,'document',$4,1,$5,$6,$7,'[]'::jsonb)`,
                [
                  testId(141_101),
                  secretary.organizationId,
                  secretary.boardId,
                  documentId,
                  "boardagent.document-retention.v1",
                  Buffer.from("{}"),
                  Buffer.alloc(32, 102)
                ]
              );
            },
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toThrow("row-level security policy");

        for (const [recipient, suffix] of [
          [member, "member"],
          [observer, "observer"]
        ] as const) {
          await expect(
            confirmSurfaceAction(service, secretaryPrincipal, "manage_document_access", {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              board_id: secretary.boardId,
              document_id: documentId,
              operation: "grant",
              member_id: recipient.memberId,
              permission: "read",
              reason: `Grant ${suffix} access for the board pack.`,
              idempotency_key: `surface-document-access-grant-${suffix}-0001`
            })
          ).resolves.toMatchObject({
            tool: "manage_document_access",
            status: "accepted",
            reference: documentId
          });
        }
        await expect(canRead(pool, member, documentId)).resolves.toBe(true);
        await expect(canRead(pool, observer, documentId)).resolves.toBe(true);

        const circulated = await confirmSurfaceAction(
          service,
          secretaryPrincipal,
          "circulate_document",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: secretary.boardId,
            document_id: documentId,
            version_id: created.reference,
            document_sha256: sha256Hex(body),
            recipient_member_ids: [observer.memberId, member.memberId],
            completeness_statement: "canonical_version_stands_alone",
            idempotency_key: "surface-document-circulate-0001"
          }
        );
        expect(circulated).toMatchObject({
          tool: "circulate_document",
          status: "accepted",
          data: {
            document_id: documentId,
            document_version_id: created.reference,
            recipient_member_ids: [member.memberId, observer.memberId].toSorted()
          }
        });
        const circulation = await pool.query<{
          circulations: string;
          recipients: string;
          notices: string;
          feeds: string;
          circulation_events: string;
          notice_events: string;
        }>(
          `select
          (select count(*)::text from document_circulations where document_id=$1) as circulations,
          (select count(*)::text from circulation_recipients as recipient
            join document_circulations as circulation on circulation.id=recipient.circulation_id
           where circulation.document_id=$1) as recipients,
          (select count(*)::text from notices
           where object_id=$1 and notice_type='document_circulated') as notices,
          (select count(*)::text from pending_action_feed
           where object_id=$1 and action_type='document_circulated' and state='pending') as feeds,
          (select count(*)::text from audit_events
           where object_id=$1 and event_type='document_circulated') as circulation_events,
          (select count(*)::text from audit_events
           where object_id=$1 and event_type='notice_delivered') as notice_events`,
          [documentId]
        );
        expect(circulation.rows[0]).toEqual({
          circulations: "1",
          recipients: "2",
          notices: "2",
          feeds: "2",
          circulation_events: "1",
          notice_events: "2"
        });
        await expect(
          service.prepareHumanAction(secretaryPrincipal, "circulate_document", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: secretary.boardId,
            document_id: documentId,
            version_id: created.reference,
            document_sha256: sha256Hex(body),
            recipient_member_ids: [member.memberId, observer.memberId],
            completeness_statement: "canonical_version_stands_alone",
            idempotency_key: "surface-document-circulate-duplicate-0001"
          })
        ).rejects.toThrow(
          "every circulation recipient must be an active, entitled, not-yet-notified member"
        );

        const tamperInput = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          document_id: documentId,
          reason: "Prepare an archive solely to prove protected stage binding.",
          idempotency_key: "surface-document-archive-stage-tamper-0001"
        } as const;
        const tamperPrepared = await service.prepareHumanAction(
          secretaryPrincipal,
          "archive_document",
          tamperInput
        );
        await expect(
          service.persistHumanStage({
            principal: secretaryPrincipal,
            tool: "archive_document",
            input: tamperInput,
            prepared: { ...tamperPrepared, board_id: testId(141_999) },
            client_capabilities: { elicitation: { form: {} } },
            embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
            embedded_result: { message: "Tampered document board binding" },
            request_state: "surface-document-tamper-request-state-bound-by-client",
            prepared_request_id: Buffer.from("surface-document-tamper-prepare")
          })
        ).rejects.toThrow("changed after presentation");
        const tamperEvidence = await pool.query<{ stages: string }>(
          "select count(*)::text as stages from action_stages where id=$1",
          [tamperPrepared.stage_id]
        );
        expect(tamperEvidence.rows[0]?.stages).toBe("0");

        await expect(
          confirmSurfaceAction(service, secretaryPrincipal, recusalTool, {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: secretary.boardId,
            ...(recusalTool === "manage_recusal"
              ? { object_type: "document", object_id: documentId, operation: "add" }
              : { document_id: documentId, operation: "exclude", permission: null }),
            member_id: member.memberId,
            reason: "Member is recused from this document.",
            idempotency_key: "surface-document-access-exclude-0001"
          })
        ).resolves.toMatchObject({
          data: { operation: "exclude", member_id: member.memberId }
        });
        await expect(canRead(pool, member, documentId)).resolves.toBe(false);
        const consentBinding = await pool.query(
          `select consent.action_code,consent.target_type,stage.action_code as stage_action,
                attempt.original_name
           from consent_records consent join action_stages stage on stage.id=consent.stage_id
           join input_required_attempts attempt on attempt.id=consent.input_required_attempt_id
          where consent.target_id=$1 and consent.action_code=$2 order by consent.id desc limit 1`,
          [documentId, recusalTool]
        );
        expect(consentBinding.rows[0]).toMatchObject({
          action_code: recusalTool,
          target_type: "document",
          stage_action: recusalTool,
          original_name: recusalTool
        });
        const recusalEvents = await pool.query(
          `select count(*)::int as n from audit_events where object_id=$1 and event_type='recusal_changed'`,
          [documentId]
        );
        expect(recusalEvents.rows[0].n).toBe(recusalTool === "manage_recusal" ? 1 : 0);
        const excludedFeed = await pool.query<{ state: string; tombstones: string }>(
          `select feed.state,
                (select count(*)::text from feed_tombstones
                  where removed_feed_id=feed.id and reason_class=$3) as tombstones
           from pending_action_feed as feed
          where feed.object_id=$1 and feed.member_id=$2`,
          [documentId, member.memberId, recusalTool === "manage_recusal" ? "recused" : "revoked"]
        );
        expect(excludedFeed.rows[0]).toEqual({ state: "superseded", tombstones: "1" });

        await expect(
          confirmSurfaceAction(service, secretaryPrincipal, recusalTool, {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: secretary.boardId,
            ...(recusalTool === "manage_recusal"
              ? { object_type: "document", object_id: documentId, operation: "lift" }
              : { document_id: documentId, operation: "lift_exclusion", permission: null }),
            member_id: member.memberId,
            reason: "The document-specific recusal has ended.",
            idempotency_key: "surface-document-access-lift-0001"
          })
        ).resolves.toMatchObject({
          data: { operation: "lift_exclusion", member_id: member.memberId }
        });
        await expect(canRead(pool, member, documentId)).resolves.toBe(true);

        await expect(
          service.prepareHumanAction(
            principal(member, ["member"], ["documents:read"]),
            "archive_document",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              document_id: documentId,
              reason: "Unauthorized archive attempt.",
              idempotency_key: "surface-document-archive-denied-0001"
            }
          )
        ).rejects.toThrow("document action is unavailable");

        await expect(
          confirmSurfaceAction(service, secretaryPrincipal, "archive_document", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            document_id: documentId,
            reason: "The exploration programme was superseded.",
            idempotency_key: "surface-document-archive-0001"
          })
        ).resolves.toMatchObject({ data: { document_id: documentId, state: "archived" } });
        await expect(
          confirmSurfaceAction(service, secretaryPrincipal, "soft_delete_document", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            document_id: documentId,
            reason: "Hide the superseded pack while permanently retaining its evidence.",
            idempotency_key: "surface-document-soft-delete-0001"
          })
        ).resolves.toMatchObject({ data: { document_id: documentId, state: "soft_deleted" } });

        const retained = await pool.query<{
          state: string;
          hidden: boolean;
          snapshots: string;
          deletion_tombstones: string;
          versions: string;
          canonical_bytes: string;
          hidden_feed_tombstones: string;
        }>(
          `select document.state,(document.hidden_at is not null) as hidden,
                (select count(*)::text from retention_snapshots
                  where object_type='document' and object_id=document.id) as snapshots,
                (select count(*)::text from deletion_tombstones
                  where object_type='document' and object_id=document.id) as deletion_tombstones,
                (select count(*)::text from document_versions
                  where document_id=document.id) as versions,
                (select convert_from(canonical_bytes,'UTF8') from document_versions
                  where document_id=document.id and version=1) as canonical_bytes,
                (select count(*)::text from feed_tombstones
                  where object_type='document' and object_id=document.id
                    and reason_class='hidden') as hidden_feed_tombstones
           from documents as document where document.id=$1`,
          [documentId]
        );
        expect(retained.rows[0]).toEqual({
          state: "soft_deleted",
          hidden: true,
          snapshots: "1",
          deletion_tombstones: "1",
          versions: "1",
          canonical_bytes: body,
          hidden_feed_tombstones: "1"
        });
        await expect(canRead(pool, member, documentId)).resolves.toBe(false);
        await expect(canRead(pool, observer, documentId)).resolves.toBe(false);
        // An exact old receipt must still respect the current object-state restriction.
        const evidenceCounts = async () =>
          (
            await pool.query(`select
          (select count(*)::int from document_versions) as versions,
          (select count(*)::int from document_validation_attempts) as attempts,
          (select count(*)::int from idempotency_records) as receipts,
          (select count(*)::int from audit_events) as events`)
          ).rows;
        const beforeRetry = await evidenceCounts();
        const hiddenRetry = await service
          .executeDirect(secretaryPrincipal, "create_document_version", contributionInput)
          .then(
            () => "returned_hidden_reference",
            (error: unknown) => {
              expect(error).toMatchObject({ code: "document_contribution_unavailable" });
              return "unavailable";
            }
          );
        expect(await evidenceCounts()).toEqual(beforeRetry);
        expect(hiddenRetry).toBe("unavailable");
      });
    },
    60_000
  );
});

describe("exact actor document exclusion during lifecycle preparation", () => {
  it("hides the document from an excluded secretary and refuses lifecycle material until another secretary lifts it", async () => {
    await withDatabase(async (pool) => {
      const creatorScopes = ["documents:contribute", "secretariat:admin"];
      const creator = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: creatorScopes,
        isSecretary: true
      });
      const actorScopes = ["documents:read", "documents:contribute", "secretariat:admin"];
      const actor = await seedAdditionalAuthorizedActor(pool, creator, {
        idBase: 152_100,
        seatRole: "voting_member",
        scopes: actorScopes,
        isSecretary: true
      });
      const recipient = await seedAdditionalAuthorizedActor(pool, creator, {
        idBase: 152_200,
        seatRole: "voting_member",
        scopes: ["documents:read"]
      });
      await pool.query(
        `insert into organization_role_assignments(
         id,organization_id,member_id,role,change_reason
       ) values ($1,$2,$3,'admin','Synthetic exact document exclusion boundary.')`,
        [testId(152_150), creator.organizationId, actor.memberId]
      );
      const creatorPrincipal = principal(creator, ["member", "secretariat"], creatorScopes);
      const actorPrincipal = {
        ...principal(actor, ["admin", "member", "secretariat"], actorScopes),
        protocolClientId: "authorized-test-client-152100"
      };
      let nextId = 152_500;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const reader = new PgSurfaceReadRepository(pool, {
        cursorKey: Buffer.alloc(32, 0x68),
        transaction: { assumeRole: "boardagent_server" }
      });
      const documentId = testId(153_000);
      const body = "# Synthetic restricted exploration pack\n\nPrivate drill planning material.\n";
      const title = "Synthetic restricted exploration pack";
      const created = await service.executeDirect(creatorPrincipal, "create_document_version", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: creator.boardId,
        document_id: documentId,
        title,
        media_type: "text/markdown; charset=utf-8",
        schema_name: null,
        canonical_body: body,
        expected_current_version_id: null,
        idempotency_key: "document-exclusion-create-0001"
      });
      if (!created.reference) throw new Error("synthetic document version missing");
      for (const member of [actor, recipient]) {
        await confirmSurfaceAction(service, creatorPrincipal, "manage_document_access", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: creator.boardId,
          document_id: documentId,
          member_id: member.memberId,
          operation: "grant",
          permission: "read",
          reason: "Synthetic exact read grant.",
          idempotency_key: `document-exclusion-grant-${member.memberId}`
        });
      }
      const sessionId = testId(153_001);
      await pool.query(
        `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
         values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, Buffer.alloc(32, 0x69), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);
      const readInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        document_id: documentId,
        version_id: created.reference
      };
      await expect(
        withDirectResponseAllocation(() =>
          reader.executeRead(actorPrincipal, "read_document", readInput)
        )
      ).resolves.toMatchObject({
        data: { canonical_body: body, sha256: sha256Hex(body) }
      });
      expect(creatorPrincipal.scopes).not.toContain("documents:read");
      await expect(
        service.prepareHumanAction(creatorPrincipal, "archive_document", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          document_id: documentId,
          reason: "Eligible management control without a document-read scope.",
          idempotency_key: "document-exclusion-control-prepare-0001"
        })
      ).resolves.toMatchObject({ canonical_payload: { title } });

      await confirmSurfaceAction(service, creatorPrincipal, "manage_document_access", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: creator.boardId,
        document_id: documentId,
        member_id: actor.memberId,
        operation: "exclude",
        permission: null,
        reason: "Synthetic exact actor document exclusion.",
        idempotency_key: "document-exclusion-apply-0001"
      });
      const hidden = await reader.executeRead(actorPrincipal, "read_document", readInput);
      const absent = await reader.executeRead(actorPrincipal, "read_document", {
        ...readInput,
        document_id: testId(153_999),
        version_id: null
      });
      expect(hidden.data).toEqual({ document: null });
      expect(hidden.data).toEqual(absent.data);
      await expect(canRead(pool, actor, documentId)).resolves.toBe(false);

      const terminal = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        document_id: documentId,
        reason: "Synthetic excluded actor preparation probe."
      };
      await expect(
        service.prepareHumanAction(actorPrincipal, "archive_document", {
          ...terminal,
          document_id: testId(153_999),
          idempotency_key: "document-exclusion-missing-control-0001"
        })
      ).rejects.toMatchObject({ code: "document_action_unavailable" });
      const probes: readonly (readonly [string, JsonValue])[] = [
        [
          "manage_document_access",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: creator.boardId,
            document_id: documentId,
            member_id: actor.memberId,
            operation: "lift_exclusion",
            permission: null,
            reason: "Synthetic excluded actor preparation probe.",
            idempotency_key: "document-exclusion-access-probe-0001"
          }
        ],
        [
          "manage_recusal",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: creator.boardId,
            object_type: "document",
            object_id: documentId,
            member_id: actor.memberId,
            operation: "lift",
            reason: "Synthetic excluded actor preparation probe.",
            idempotency_key: "document-exclusion-recusal-probe-0001"
          }
        ],
        [
          "archive_document",
          { ...terminal, idempotency_key: "document-exclusion-archive-probe-0001" }
        ],
        [
          "soft_delete_document",
          { ...terminal, idempotency_key: "document-exclusion-delete-probe-0001" }
        ],
        [
          "circulate_document",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: creator.boardId,
            document_id: documentId,
            version_id: created.reference,
            document_sha256: sha256Hex(body),
            recipient_member_ids: [recipient.memberId],
            completeness_statement: "canonical_version_stands_alone",
            idempotency_key: "document-exclusion-circulate-probe-0001"
          }
        ]
      ];
      const effects = async () =>
        (
          await pool.query(
            `select
          (select row_to_json(document) from documents document where id=$1) as document,
          (select jsonb_agg(exclusion order by version) from document_exclusions exclusion where document_id=$1) as exclusions,
          (select count(*)::int from document_versions) as versions,
          (select count(*)::int from action_stages) as stages,
          (select count(*)::int from consent_records) as consents,
          (select count(*)::int from document_circulations) as circulations,
          (select count(*)::int from retention_snapshots) as snapshots,
          (select count(*)::int from deletion_tombstones) as tombstones,
          (select count(*)::int from audit_events) as events`,
            [documentId]
          )
        ).rows[0];
      const beforeProbes = await effects();
      for (const [tool, input] of probes) {
        const outcome = await service.prepareHumanAction(actorPrincipal, tool, input).then(
          (prepared) => ({ prepared, error: null }),
          (error: unknown) => ({ prepared: null, error })
        );
        expect.soft(outcome.error, `${tool} must use the same unavailable refusal`).toMatchObject({
          code: "document_action_unavailable"
        });
        expect
          .soft(
            outcome.prepared?.canonical_payload ?? null,
            `${tool} must not expose confirmation material`
          )
          .toBeNull();
      }
      expect(await effects()).toEqual(beforeProbes);

      await confirmSurfaceAction(service, creatorPrincipal, "manage_document_access", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: creator.boardId,
        document_id: documentId,
        member_id: actor.memberId,
        operation: "lift_exclusion",
        permission: null,
        reason: "Another eligible secretary lifts the synthetic exclusion.",
        idempotency_key: "document-exclusion-eligible-lift-0001"
      });
      await expect(
        withDirectResponseAllocation(() =>
          reader.executeRead(actorPrincipal, "read_document", readInput)
        )
      ).resolves.toMatchObject({
        data: { canonical_body: body, sha256: sha256Hex(body) }
      });
      await expect(
        service.prepareHumanAction(actorPrincipal, "archive_document", {
          ...terminal,
          idempotency_key: "document-exclusion-restored-prepare-0001"
        })
      ).resolves.toMatchObject({
        canonical_payload: { title, currentDocumentVersionId: created.reference }
      });
    });
  }, 60_000);
});
