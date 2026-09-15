import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  canonicalSha256,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { migrate, withRequestTransaction } from "../../lib/db/src/index.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";
import {
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
  const database = `boardagent_surface_governance_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "surface-governance-administration-test");
    return await run(pool);
  } finally {
    await pool.end();
    await dropClosedTestDatabase(admin, database);
    await admin.end();
  }
}

function principal(actor: AuthorizedActorFixture): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://governance-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: ["secretariat:admin"],
    roles: ["admin"],
    boardIds: [actor.boardId]
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by governance administration test");
  },
  readResource: async () => {
    throw new Error("resource read not used by governance administration test");
  }
};

let confirmationSequence = 0;
async function confirm(
  service: BoardAgentSurfaceService,
  actor: SurfacePrincipal,
  tool: string,
  input: JsonValue
) {
  confirmationSequence += 1;
  const label = `surface-governance-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const prepared = await service.prepareHumanAction(actor, tool, input);
  expect(prepared.action_code).toBe(tool);
  expect(prepared.confirmation_lines.join("\n")).toContain(prepared.target_id);
  const clientCapabilities = { elicitation: { form: {} } } as const;
  const requestState = `${label}-request-state-is-bound-to-the-client`;
  await service.persistHumanStage({
    principal: actor,
    tool,
    input,
    prepared,
    client_capabilities: clientCapabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm exact ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${label}-prepare`)
  });
  const resolved = await service.resolveHumanAction({
    principal: actor,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: clientCapabilities,
    request_state: requestState,
    retry_request_id: Buffer.from(`${label}-retry`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolved.confirmed) throw new Error(`${tool} failed: ${resolved.reason}`);
  return resolved.result;
}

describe("confirmed board and governance administration surface", () => {
  it.each([false, true])("stores exact governance with shared clause=%s", async (shared) => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"]
      });
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','Governance administration integration authority')`,
        [testId(200_000), actor.organizationId, actor.memberId]
      );
      let nextId = 205_000;
      let entropyByte = 101;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++),
        entropy: (length) => Buffer.alloc(length, entropyByte++)
      });
      const caller = principal(actor);

      const createdBoardId = testId(200_010);
      const created = await confirm(surface, caller, "create_board", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-create-board-0001",
        board_id: createdBoardId,
        slug: "investment-committee",
        name: "Investment Committee",
        timezone: "Asia/Dubai",
        initial_settings: {
          schema_version: "boardagent.board-settings.v1",
          values: { meeting_notice_days: 7 }
        },
        secretary_member_id: actor.memberId
      });
      expect(created.data).toMatchObject({
        boardId: createdBoardId,
        state: "active",
        version: 1,
        implicitSeatsCreated: false
      });
      const implicitSeat = await pool.query<{ count: string }>(
        "select count(*)::text as count from board_memberships where board_id=$1",
        [createdBoardId]
      );
      expect(implicitSeat.rows[0]?.count).toBe("0");
      await pool.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
         ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
        [testId(200_011), actor.organizationId, createdBoardId, actor.memberId]
      );

      const amended = await confirm(surface, caller, "update_board", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-update-board-0001",
        board_id: actor.boardId,
        expected_row_version: 1,
        name: "Main Exploration Board",
        timezone: "Asia/Dubai",
        settings: {
          schema_version: "boardagent.board-settings.v1",
          values: { reporting_currency: "USD" }
        },
        reason: "Adopt the board's initial operating settings."
      });
      expect(amended.data).toMatchObject({ boardId: actor.boardId, version: 1 });

      const charterDocumentId = testId(200_020);
      const charterVersionId = testId(200_021);
      const charterBytes = Buffer.from(
        "# Charter\n\nSections 7.1, 7.2 and 8.1 govern decisions.\n",
        "utf8"
      );
      const charterSha256 = sha256Hex(charterBytes);
      await pool.query(
        `insert into documents(id,organization_id,board_id,title,created_by)
         values ($1,$2,$3,'Board charter',$4)`,
        [charterDocumentId, actor.organizationId, actor.boardId, actor.memberId]
      );
      await pool.query(
        `insert into document_versions(
           id,organization_id,board_id,document_id,version,media_type,
           canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,
           created_by
         ) values ($1,$2,$3,$4,1,'text/markdown; charset=utf-8','RFC8785+NFC-LF-v1',
                   $5,$6,$7,'{}',$8)`,
        [
          charterVersionId,
          actor.organizationId,
          actor.boardId,
          charterDocumentId,
          charterBytes,
          charterBytes.length,
          Buffer.from(charterSha256, "hex"),
          actor.memberId
        ]
      );
      await pool.query(
        "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
        [charterVersionId, charterDocumentId]
      );
      const sourceAgreement = {
        sourceDocumentVersionId: charterVersionId,
        sourceDocumentSha256: charterSha256,
        clause: "Charter section 7.1",
        locator: "Ordinary board decisions"
      };
      const templateCitation = shared
        ? sourceAgreement
        : {
            sourceDocumentVersionId: charterVersionId,
            sourceDocumentSha256: charterSha256,
            clause: "Charter section 7.2",
            locator: "Voting threshold"
          };
      const profileId = testId(200_030);
      const templateId = testId(200_031);
      const profile = {
        schemaVersion: "boardagent.governance-profile.v1" as const,
        id: profileId,
        boardId: actor.boardId,
        version: 1,
        supersedesId: null,
        sourceAgreements: [sourceAgreement],
        seats: [
          {
            memberId: actor.memberId,
            role: "voting_member" as const,
            weight: "1",
            chair: false
          }
        ],
        templates: [
          {
            id: templateId,
            code: "ordinary",
            label: "Ordinary resolution",
            approval: { numerator: "1", denominator: "2" },
            quorum: { numerator: "1", denominator: "2" },
            approvalDenominator: "yes_no" as const,
            abstentionsCountForQuorum: true,
            tieBehavior: "reject" as const,
            proxyPolicy: "forbidden" as const,
            noticePeriodSeconds: 86_400,
            closeMode: "secretariat_confirmed" as const,
            overridePolicy: "forbidden" as const,
            citations: [templateCitation]
          }
        ]
      };
      const configured = await confirm(surface, caller, "configure_board_governance", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-configure-governance-0001",
        board_id: actor.boardId,
        expected_profile_id: null,
        profile: { schema_version: "boardagent.governance-profile.v1", values: profile },
        citations: [
          {
            document_version_id: charterVersionId,
            sha256: charterSha256,
            clause: sourceAgreement.clause,
            locator: sourceAgreement.locator
          },
          ...(shared
            ? []
            : [
                {
                  document_version_id: charterVersionId,
                  sha256: charterSha256,
                  clause: templateCitation.clause,
                  locator: templateCitation.locator
                }
              ])
        ],
        reason: "Activate the cited charter profile."
      });
      expect(configured.data).toMatchObject({
        boardId: actor.boardId,
        profileId,
        profileVersion: 1,
        state: "active"
      });
      if (shared) {
        const relationships = await pool.query<{
          rule_template_id: string | null;
          clause: string;
          locator: string;
        }>(
          `select rule_template_id,clause,locator from governance_citations
            where profile_id=$1 order by rule_template_id nulls first`,
          [profileId]
        );
        expect(relationships.rows).toEqual([
          {
            rule_template_id: null,
            clause: sourceAgreement.clause,
            locator: sourceAgreement.locator
          },
          {
            rule_template_id: templateId,
            clause: sourceAgreement.clause,
            locator: sourceAgreement.locator
          }
        ]);
      }

      const approval = await pool.query<{ id: string }>(
        `select approval_rule_id as id from governance_rule_templates
          where profile_id=$1 and id=$2`,
        [profileId, templateId]
      );
      const approvalRuleId = approval.rows[0]?.id;
      if (!approvalRuleId) throw new Error("activated approval rule is unavailable");
      const rulesetCitation = {
        sourceDocumentVersionId: charterVersionId,
        sourceDocumentSha256: charterSha256,
        clause: "Charter section 8.1",
        locator: "Exploration programme approval"
      };
      const rulesetId = testId(200_040);
      const ruleId = testId(200_041);
      const rulesetBase = {
        schemaVersion: "boardagent.ruleset.v1" as const,
        id: rulesetId,
        boardId: actor.boardId,
        version: 1,
        matterTypes: [
          {
            code: "exploration_programme",
            fields: [{ name: "budget_usd", type: "integer" as const, required: true, minimum: 1 }]
          }
        ],
        rules: [
          {
            id: ruleId,
            matterType: "exploration_programme",
            priority: 10,
            specificity: 10,
            condition: { kind: "number_gte" as const, field: "budget_usd", value: 1 },
            approvalRuleId,
            citations: [rulesetCitation]
          }
        ]
      };
      const ruleset = { ...rulesetBase, canonicalHash: canonicalSha256(rulesetBase) };
      const managed = await confirm(surface, caller, "manage_ruleset", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-manage-ruleset-0001",
        board_id: actor.boardId,
        expected_ruleset_id: null,
        ruleset: { schema_version: "boardagent.ruleset.v1", values: ruleset },
        citations: [
          {
            document_version_id: charterVersionId,
            sha256: charterSha256,
            clause: rulesetCitation.clause,
            locator: rulesetCitation.locator
          }
        ],
        reason: "Activate the cited exploration decision rules."
      });
      expect(managed.data).toMatchObject({
        boardId: actor.boardId,
        rulesetId,
        rulesetVersion: 1,
        profileId,
        state: "active"
      });

      const createdBoardCaller = {
        ...caller,
        boardIds: [...caller.boardIds, createdBoardId]
      } satisfies SurfacePrincipal;
      const archived = await confirm(surface, createdBoardCaller, "archive_board", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-archive-board-0001",
        board_id: createdBoardId,
        reason: "The committee was consolidated before any governance action opened."
      });
      expect(archived.data).toMatchObject({ boardId: createdBoardId, state: "archived" });

      const proof = await pool.query<{
        active_profile: string;
        active_ruleset: string;
        archive_state: string;
        audit_count: string;
        board_version_count: string;
        citation_count: string;
      }>(
        `select
          (select current_governance_profile_id::text from boards where id=$1) as active_profile,
          (select current_ruleset_id::text from boards where id=$1) as active_ruleset,
          (select state from boards where id=$2) as archive_state,
          (select count(*)::text from board_versions where board_id in ($1,$2)) as board_version_count,
          (select count(*)::text from governance_citations where profile_id=$3) as citation_count,
          (select count(*)::text from audit_events where event_type in (
             'board_created','board_amended','governance_profile_activated',
             'ruleset_amended','board_archived'
           )) as audit_count`,
        [actor.boardId, createdBoardId, profileId]
      );
      expect(proof.rows[0]).toEqual({
        active_profile: profileId,
        active_ruleset: rulesetId,
        archive_state: "archived",
        board_version_count: "2",
        citation_count: "2",
        audit_count: "5"
      });
    });
  });
});

describe("organization administrator setup without a board seat", () => {
  it("invites the first director and updates a new board without gaining board record reads", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"]
      });
      await pool.query(
        `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
        values($1,$2,$3,'admin','Initial board setup')`,
        [testId(220000), actor.organizationId, actor.memberId]
      );
      let sequence = 221000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(sequence++)
      });
      await pool.query(
        `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
        values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [testId(220003), actor.organizationId, Buffer.alloc(32, 93), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        testId(220003),
        actor.accessTokenRecordId
      ]);
      const caller = principal(actor);
      const boardId = testId(220001);
      await confirm(service, caller, "create_board", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "nonmember-create-board-0001",
        board_id: boardId,
        slug: "separate-committee",
        name: "Separate Committee",
        timezone: "UTC",
        initial_settings: { schema_version: "boardagent.board-settings.v1", values: {} },
        secretary_member_id: actor.memberId
      });
      const invited = await confirm(service, caller, "manage_member", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "nonmember-invite-first-0001",
        change: {
          operation: "invite",
          member_id: testId(220002),
          board_id: boardId,
          member_kind: "human",
          seat_role: "voting_member",
          legal_name: "First Committee Director",
          display_name: "First Committee Director",
          voting_weight: 1,
          accountable_principal_id: null
        }
      });
      expect(invited.data).toMatchObject({
        operation: "invite",
        state: "invited",
        board_id: boardId
      });
      const amended = await confirm(service, caller, "update_board", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "nonmember-update-board-0001",
        board_id: boardId,
        expected_row_version: 1,
        name: "Configured Committee",
        timezone: "UTC",
        settings: { schema_version: "boardagent.board-settings.v1", values: {} },
        reason: "Complete initial setup."
      });
      expect(amended.data).toMatchObject({ boardId, version: 2 });
      expect(
        (await pool.query("select member_id from board_memberships where board_id=$1", [boardId]))
          .rows
      ).toEqual([{ member_id: testId(220002) }]);
      const hidden = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const board = await client.query("select id from boards where id=$1", [boardId]);
          const members = await client.query(
            "select member_id from board_memberships where board_id=$1",
            [boardId]
          );
          return { boards: board.rowCount, memberships: members.rowCount };
        },
        { assumeRole: "boardagent_server" }
      );
      expect(hidden).toEqual({ boards: 0, memberships: 0 });
      const authority = async (changes: Record<string, string> = {}) =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            client.query(
              "select boardagent_owned_administrative_stage($1,$2,$3,$4,$5,$6) as allowed",
              [
                changes["org"] ?? actor.organizationId,
                changes["board"] ?? boardId,
                changes["actor"] ?? actor.memberId,
                changes["client"] ?? actor.clientId,
                changes["token"] ?? actor.tokenJti,
                changes["action"] ?? "manage_member"
              ]
            ),
          { assumeRole: "boardagent_server" }
        );
      expect((await authority()).rows).toEqual([{ allowed: true }]);
      for (const change of [
        { action: "stage_ballot" },
        { action: "create_document_version" },
        { org: testId(222001) },
        { board: testId(222002) },
        { actor: testId(222003) },
        { client: testId(222004) },
        { token: testId(222005) }
      ])
        expect((await authority(change)).rows).toEqual([{ allowed: false }]);
      const ownEvidence = () =>
        withRequestTransaction(
          pool,
          actor.context,
          async (client) => ({
            stages: (
              await client.query("select id from action_stages where board_id=$1", [boardId])
            ).rowCount,
            consents: (
              await client.query("select id from consent_records where board_id=$1", [boardId])
            ).rowCount,
            audit: (await client.query("select id from audit_events where board_id=$1", [boardId]))
              .rowCount
          }),
          { assumeRole: "boardagent_server" }
        );
      expect(await ownEvidence()).toEqual({ stages: 2, consents: 2, audit: 0 });
      await pool.query(
        "update organization_role_assignments set active_until=transaction_timestamp() where id=$1",
        [testId(220000)]
      );
      expect((await authority()).rows).toEqual([{ allowed: false }]);
      expect(await ownEvidence()).toEqual({ stages: 0, consents: 0, audit: 0 });
    });
  });
});
