import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import {
  confirmStagedActionInTransaction,
  migrate,
  stageActionInTransaction,
  withRequestTransaction,
  type StageActionInput
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_consent_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 3 });
  try {
    await migrate(pool, MIGRATIONS, "consent-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

const originalArguments = (boardId: string) => ({ board_id: boardId, name: "Board amended" });
const capabilities = { elicitation: { form: {} } };

function stageInput(
  sequence: number,
  boardId: string,
  confirmationCode = "BRD7K2Q9"
): StageActionInput {
  return {
    stageId: testId(sequence),
    inputRequiredAttemptId: testId(sequence + 1),
    boardId,
    actingForMemberId: null,
    actionCode: "update_board",
    targetType: "board",
    targetId: boardId,
    canonicalSchema: "boardagent.board-update.v1",
    canonicalPayload: { boardId, name: "Board amended" },
    packageSha256: null,
    nonce: Buffer.alloc(32, sequence % 256),
    confirmationCode,
    accessTokenRecordId: testId(9),
    exactOrigin: "https://client.example",
    originalName: "update_board",
    originalArguments: originalArguments(boardId),
    clientCapabilities: capabilities,
    embeddedForm: { type: "object", required: ["approve", "confirmation_code"] },
    embeddedResult: { message: "Confirm exact board amendment", confirmationCode },
    requestStateBytes: Buffer.alloc(48, sequence % 256),
    preparedRequestId: Buffer.from(`prepared-${String(sequence)}`),
    auditEventIds: {
      stageReplaced: testId(sequence + 2),
      stageCreated: testId(sequence + 3),
      elicitationSent: testId(sequence + 4)
    }
  };
}

async function lockBoard(client: PoolClient, boardId: string): Promise<void> {
  const locked = await client.query<{ locked: boolean }>(
    "select boardagent_lock_board_for_document_contribution($1) as locked",
    [boardId]
  );
  if (locked.rows[0]?.locked !== true) throw new Error("test board unavailable");
}

describe("persisted MRTR stage and confirmation transaction", () => {
  it("restages, rejects, confirms, and rolls crash points back as one evidence chain", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin", "documents:contribute"],
        isSecretary: true
      });
      const firstInput = stageInput(100, actor.boardId);
      const first = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          stageActionInTransaction(client, firstInput, (requestClient) =>
            lockBoard(requestClient, actor.boardId)
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(first.replacedStageId).toBeNull();
      expect(first.auditSequences).toEqual([1n, 2n]);
      const frozenInvocation = await pool.query<{
        expires_at: string;
        lifetime_seconds: string;
        original_method: string;
        protocol_header_version: string;
        protocol_version: string;
        result_meta_version: string;
      }>(
        `select to_char(stage.expires_at at time zone 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at,
                extract(epoch from stage.expires_at-stage.created_at)::text as lifetime_seconds,
                attempt.protocol_version,attempt.protocol_header_version,
                attempt.result_meta_version,attempt.original_method
           from action_stages as stage
           join input_required_attempts as attempt on attempt.stage_id=stage.id
          where stage.id=$1`,
        [first.stageId]
      );
      expect(frozenInvocation.rows[0]).toMatchObject({
        expires_at: first.expiresAt,
        original_method: "tools/call",
        protocol_header_version: "2026-07-28",
        protocol_version: "2026-07-28",
        result_meta_version: "boardagent.mrtr.v1"
      });
      expect(Number(frozenInvocation.rows[0]?.lifetime_seconds)).toBe(600);

      const secondInput = stageInput(110, actor.boardId, "RST8L3Q2");
      const second = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          stageActionInTransaction(client, secondInput, (requestClient) =>
            lockBoard(requestClient, actor.boardId)
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(second.replacedStageId).toBe(first.stageId);
      expect(second.auditSequences).toEqual([3n, 4n, 5n]);
      const firstState = await pool.query<{ state: string }>(
        "select state from action_stages where id=$1",
        [first.stageId]
      );
      expect(firstState.rows[0]?.state).toBe("replaced");

      let rejectedActCalled = false;
      const rejected = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          confirmStagedActionInTransaction(
            client,
            {
              stageId: second.stageId,
              consentRecordId: testId(119),
              retryRequestId: Buffer.from("retry-wrong-code"),
              originalArguments: originalArguments(actor.boardId),
              clientCapabilities: capabilities,
              exactOrigin: "https://client.example",
              requestStateBytes: secondInput.requestStateBytes,
              responseAction: "accept",
              inputResponse: { approve: true, confirmation_code: "WRONG999" },
              auditEventIds: {
                consentRecorded: testId(118),
                consentRejected: testId(117)
              }
            },
            async (requestClient) => {
              await lockBoard(requestClient, actor.boardId);
              return { payloadSha256: second.payloadSha256, packageSha256: null };
            },
            async () => {
              rejectedActCalled = true;
              return { value: null, auditEvents: [] };
            }
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(rejected).toEqual({ confirmed: false, reason: "code_mismatch" });
      expect(rejectedActCalled).toBe(false);
      const rejectedRows = await pool.query<{ consents: string; state: string }>(
        `select stage.state,count(consent.id)::text as consents
           from action_stages as stage
           left join consent_records as consent on consent.stage_id=stage.id
          where stage.id=$1 group by stage.state`,
        [second.stageId]
      );
      expect(rejectedRows.rows[0]).toEqual({ consents: "0", state: "rejected" });

      const thirdInput = stageInput(120, actor.boardId, "CNF7K2Q9");
      const third = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          stageActionInTransaction(client, thirdInput, (requestClient) =>
            lockBoard(requestClient, actor.boardId)
          ),
        { assumeRole: "boardagent_server" }
      );
      const confirmed = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          confirmStagedActionInTransaction(
            client,
            {
              stageId: third.stageId,
              consentRecordId: testId(129),
              retryRequestId: Buffer.from("retry-confirmed"),
              originalArguments: originalArguments(actor.boardId),
              clientCapabilities: capabilities,
              exactOrigin: "https://client.example",
              requestStateBytes: thirdInput.requestStateBytes,
              responseAction: "accept",
              inputResponse: { approve: true, confirmation_code: "CNF7K2Q9" },
              auditEventIds: {
                consentRecorded: testId(128),
                consentRejected: testId(127)
              }
            },
            async (requestClient) => {
              await lockBoard(requestClient, actor.boardId);
              return { payloadSha256: third.payloadSha256, packageSha256: null };
            },
            async (_requestClient, consentRecordId) => ({
              value: { boardId: actor.boardId, consentRecordId },
              auditEvents: []
            })
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(confirmed.confirmed).toBe(true);
      if (confirmed.confirmed) {
        expect(confirmed.auditSequences).toEqual([9n]);
        expect(confirmed.value).toEqual({
          boardId: actor.boardId,
          consentRecordId: testId(129)
        });
      }
      const committed = await pool.query<{
        attempt_state: string;
        board_name: string;
        consent_count: string;
        stage_state: string;
      }>(
        `select stage.state as stage_state,attempt.state as attempt_state,
                board.name as board_name,count(consent.id)::text as consent_count
           from action_stages as stage
           join input_required_attempts as attempt on attempt.stage_id=stage.id
           join boards as board on board.id=stage.board_id
           left join consent_records as consent on consent.stage_id=stage.id
          where stage.id=$1
          group by stage.state,attempt.state,board.name`,
        [third.stageId]
      );
      expect(committed.rows[0]).toEqual({
        attempt_state: "confirmed",
        board_name: "Board",
        consent_count: "1",
        stage_state: "confirmed"
      });

      const fourthInput = stageInput(140, actor.boardId, "CRS7K2Q9");
      const fourth = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          stageActionInTransaction(client, fourthInput, (requestClient) =>
            lockBoard(requestClient, actor.boardId)
          ),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            confirmStagedActionInTransaction(
              client,
              {
                stageId: fourth.stageId,
                consentRecordId: testId(149),
                retryRequestId: Buffer.from("retry-crash"),
                originalArguments: originalArguments(actor.boardId),
                clientCapabilities: capabilities,
                exactOrigin: "https://client.example",
                requestStateBytes: fourthInput.requestStateBytes,
                responseAction: "accept",
                inputResponse: { approve: true, confirmation_code: "CRS7K2Q9" },
                auditEventIds: {
                  consentRecorded: testId(148),
                  consentRejected: testId(147)
                }
              },
              async (requestClient) => {
                await lockBoard(requestClient, actor.boardId);
                return { payloadSha256: fourth.payloadSha256, packageSha256: null };
              },
              async () => {
                throw new Error("injected act crash");
              }
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("injected act crash");
      const rolledBack = await pool.query<{
        board_name: string;
        consents: string;
        stage_state: string;
      }>(
        `select board.name as board_name,stage.state as stage_state,
                count(consent.id)::text as consents
           from action_stages as stage
           join boards as board on board.id=stage.board_id
           left join consent_records as consent on consent.stage_id=stage.id
          where stage.id=$1 group by board.name,stage.state`,
        [fourth.stageId]
      );
      expect(rolledBack.rows[0]).toEqual({
        board_name: "Board",
        consents: "0",
        stage_state: "active"
      });
    });
  });

  it("refuses incapable clients, caller-controlled lifetime, binding rewrites, and origin drift", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin", "documents:contribute"],
        isSecretary: true
      });
      // URL-only elicitation cannot carry the confirmation form. The spec's empty
      // elicitation object means form mode and is exercised by the capable paths.
      const incapable = {
        ...stageInput(200, actor.boardId),
        clientCapabilities: { elicitation: { url: {} } }
      };
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            stageActionInTransaction(client, incapable, (requestClient) =>
              lockBoard(requestClient, actor.boardId)
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const absent = await pool.query<{ count: string }>(
        "select count(*)::text as count from action_stages where id=$1",
        [incapable.stageId]
      );
      expect(absent.rows[0]?.count).toBe("0");

      const validInput = stageInput(210, actor.boardId, "ORG7K2Q9");
      const staged = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          stageActionInTransaction(client, validInput, (requestClient) =>
            lockBoard(requestClient, actor.boardId)
          ),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        pool.query(
          `insert into action_stages(
             id,organization_id,board_id,actor_member_id,acting_for_member_id,action_code,
             target_type,target_id,canonical_schema,canonicalization_version,canonical_payload,
             payload_sha256,package_sha256,nonce_sha256,protected_code_sha256,client_id,
             access_token_record_id,token_jti,exact_origin,context_sha256,state,replaces_stage_id,
             expires_at,created_at
           )
           select $1,organization_id,board_id,actor_member_id,acting_for_member_id,'archive_board',
                  target_type,target_id,canonical_schema,canonicalization_version,canonical_payload,
                  payload_sha256,package_sha256,decode(repeat('a1',32),'hex'),
                  decode(repeat('a2',32),'hex'),client_id,access_token_record_id,token_jti,
                  exact_origin,context_sha256,'active',null,
                  transaction_timestamp()+interval '11 minutes',transaction_timestamp()
             from action_stages where id=$2`,
          [testId(230), staged.stageId]
        )
      ).rejects.toThrow(/exact ten-minute lifetime/u);
      await expect(
        pool.query("update action_stages set exact_origin='https://drift.example' where id=$1", [
          staged.stageId
        ])
      ).rejects.toThrow(/binding fields are immutable/u);

      let actCalled = false;
      const mismatched = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          confirmStagedActionInTransaction(
            client,
            {
              stageId: staged.stageId,
              consentRecordId: testId(231),
              retryRequestId: Buffer.from("retry-origin-drift"),
              originalArguments: originalArguments(actor.boardId),
              clientCapabilities: capabilities,
              exactOrigin: "https://drift.example",
              requestStateBytes: validInput.requestStateBytes,
              responseAction: "accept",
              inputResponse: { approve: true, confirmation_code: "ORG7K2Q9" },
              auditEventIds: {
                consentRecorded: testId(232),
                consentRejected: testId(233)
              }
            },
            async (requestClient) => {
              await lockBoard(requestClient, actor.boardId);
              return { payloadSha256: staged.payloadSha256, packageSha256: null };
            },
            async () => {
              actCalled = true;
              return { value: null, auditEvents: [] };
            }
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(mismatched).toEqual({ confirmed: false, reason: "context_mismatch" });
      expect(actCalled).toBe(false);
      const untouched = await pool.query<{ consents: string; state: string }>(
        `select stage.state,count(consent.id)::text as consents
           from action_stages as stage
           left join consent_records as consent on consent.stage_id=stage.id
          where stage.id=$1 group by stage.state`,
        [staged.stageId]
      );
      expect(untouched.rows[0]).toEqual({ consents: "0", state: "active" });
    });
  });

  it("can append exact act evidence before an evidence-linked final projection", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin", "documents:contribute"],
        isSecretary: true
      });
      const stagedInput = stageInput(300, actor.boardId, "EVD7K2Q9");
      const staged = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          stageActionInTransaction(client, stagedInput, (requestClient) =>
            lockBoard(requestClient, actor.boardId)
          ),
        { assumeRole: "boardagent_server" }
      );
      let evidenceVisible = false;
      const confirmed = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          confirmStagedActionInTransaction(
            client,
            {
              stageId: staged.stageId,
              consentRecordId: testId(310),
              retryRequestId: Buffer.from("retry-evidence-finalize"),
              originalArguments: originalArguments(actor.boardId),
              clientCapabilities: capabilities,
              exactOrigin: "https://client.example",
              requestStateBytes: stagedInput.requestStateBytes,
              responseAction: "accept",
              inputResponse: { approve: true, confirmation_code: "EVD7K2Q9" },
              auditEventIds: {
                consentRecorded: testId(311),
                consentRejected: testId(312)
              }
            },
            async (requestClient) => {
              await lockBoard(requestClient, actor.boardId);
              return { payloadSha256: staged.payloadSha256, packageSha256: null };
            },
            async () => ({
              value: { finalized: true },
              auditEvents: [
                {
                  organizationId: actor.organizationId,
                  consentRecordId: testId(310),
                  event: {
                    eventId: testId(313),
                    eventType: "member_changed",
                    actorMemberId: actor.memberId,
                    actorClientId: actor.clientId,
                    tokenJti: actor.tokenJti,
                    entityType: "member",
                    entityId: testId(314),
                    boardId: actor.boardId,
                    origin: "mcp",
                    details: { operation: "test_evidence_order" },
                    schemaVersion: 1
                  }
                }
              ],
              finalizeAfterAudit: async (requestClient: PoolClient) => {
                const evidence = await requestClient.query<{ count: string }>(
                  `select count(*)::text as count from audit_events
                    where id in ($1,$2) and consent_record_id=$3`,
                  [testId(311), testId(313), testId(310)]
                );
                evidenceVisible = evidence.rows[0]?.count === "2";
              }
            })
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(confirmed).toMatchObject({ confirmed: true, value: { finalized: true } });
      expect(evidenceVisible).toBe(true);

      const crashInput = stageInput(320, actor.boardId, "RBK7K2Q9");
      const crashStage = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          stageActionInTransaction(client, crashInput, (requestClient) =>
            lockBoard(requestClient, actor.boardId)
          ),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            confirmStagedActionInTransaction(
              client,
              {
                stageId: crashStage.stageId,
                consentRecordId: testId(330),
                retryRequestId: Buffer.from("retry-evidence-crash"),
                originalArguments: originalArguments(actor.boardId),
                clientCapabilities: capabilities,
                exactOrigin: "https://client.example",
                requestStateBytes: crashInput.requestStateBytes,
                responseAction: "accept",
                inputResponse: { approve: true, confirmation_code: "RBK7K2Q9" },
                auditEventIds: {
                  consentRecorded: testId(331),
                  consentRejected: testId(332)
                }
              },
              async (requestClient) => {
                await lockBoard(requestClient, actor.boardId);
                return { payloadSha256: crashStage.payloadSha256, packageSha256: null };
              },
              async () => ({
                value: null,
                auditEvents: [
                  {
                    organizationId: actor.organizationId,
                    consentRecordId: testId(330),
                    event: {
                      eventId: testId(333),
                      eventType: "member_changed",
                      actorMemberId: actor.memberId,
                      actorClientId: actor.clientId,
                      tokenJti: actor.tokenJti,
                      entityType: "member",
                      entityId: testId(334),
                      boardId: actor.boardId,
                      origin: "mcp",
                      details: { operation: "test_rollback" },
                      schemaVersion: 1
                    }
                  }
                ],
                finalizeAfterAudit: async () => {
                  throw new Error("injected evidence-linked finalization crash");
                }
              })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("injected evidence-linked finalization crash");
      const rolledBack = await pool.query<{
        audits: string;
        consents: string;
        stage_state: string;
      }>(
        `select stage.state as stage_state,
                (select count(*)::text from consent_records where id=$2) as consents,
                (select count(*)::text from audit_events where id in ($3,$4)) as audits
           from action_stages as stage where stage.id=$1`,
        [crashStage.stageId, testId(330), testId(331), testId(333)]
      );
      expect(rolledBack.rows[0]).toEqual({ audits: "0", consents: "0", stage_state: "active" });
    });
  });
});
