import path from "node:path";
import { confirmSyntheticSurfaceAction } from "../helpers/confirmed-surface-action.js";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import {
  preserveHistoricRecords,
  replaceDirectorThroughDelegate
} from "../helpers/delegated-director-replacement.js";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { seedCapacitySeats } from "../helpers/capacity-seats.js";
import { withConfiguredFixtureWorker } from "../helpers/configured-worker.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";
import {
  migrate,
  scheduleAuditCheckpointInTransaction,
  verifyPersistedAuditEvidence,
  withWorkerTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
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
  const database = `boardagent_surface_minutes_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "surface-minutes-review-test");
    return await run(pool);
  } finally {
    await pool.end();
    await dropClosedTestDatabase(admin, database);
    await admin.end();
  }
}

function principal(
  actor: AuthorizedActorFixture,
  role: "member" | "observer" | "secretariat"
): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: `https://${role}-agent.test/client.json`,
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes:
      role === "secretariat"
        ? ["minutes:act", "secretariat:admin"]
        : role === "member"
          ? ["minutes:act", "task:act"]
          : ["minutes:act"],
    roles: [role],
    boardIds: [actor.boardId]
  };
}

let confirmationSequence = 0;

async function confirmSurfaceAction(
  service: BoardAgentSurfaceService,
  actor: AuthorizedActorFixture,
  role: "member" | "observer" | "secretariat",
  tool: string,
  input: JsonValue,
  afterStage?: () => Promise<void>
) {
  confirmationSequence += 1;
  const requestLabel = `surface-minutes-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const actorPrincipal = principal(actor, role);
  const prepared = await service.prepareHumanAction(actorPrincipal, tool, input);
  const targetType = [
    "create_task",
    "review_task_evidence",
    "complete_task",
    "create_task_correction_cycle",
    "cancel_task"
  ].includes(tool)
    ? "task"
    : "minutes";
  expect(prepared).toMatchObject({ action_code: tool, target_type: targetType });
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
  await afterStage?.();
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
  if (!resolution.confirmed) {
    throw new Error(`${tool} failed: ${resolution.reason}`);
  }
  return resolution.result;
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by minutes review test");
  },
  readResource: async () => {
    throw new Error("resource read not used by minutes review test");
  }
};

async function seedCalledMeeting(
  pool: Pool,
  secretary: AuthorizedActorFixture
): Promise<{ meetingId: string; minutesId: string; text: string }> {
  const meetingId = testId(121_000);
  const minutesId = testId(121_001);
  const text = "# Minutes\nApproved draft.\n";
  await pool.query(
    `insert into meetings(
       id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by
     ) values ($1,$2,$3,'Review meeting','called',transaction_timestamp()+interval '1 hour',
               transaction_timestamp()+interval '2 hours',$4)`,
    [meetingId, secretary.organizationId, secretary.boardId, secretary.memberId]
  );
  return { meetingId, minutesId, text };
}

describe("direct minutes review surface", () => {
  it.each(["document", "version", "hash", "retry", "unreadable"] as const)(
    "binds task evidence to the exact readable document tuple (%s)",
    async (changed) => {
      await withDatabase(async (pool) => {
        const scopes =
          changed === "unreadable"
            ? ["documents:contribute", "task:act"]
            : ["documents:read", "documents:contribute", "task:act"];
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "management",
          isSecretary: true,
          scopes
        });
        const actorPrincipal: SurfacePrincipal = {
          ...principal(actor, "secretariat"),
          scopes
        };
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableReads,
          transaction: { assumeRole: "boardagent_server" }
        });
        const documentId = testId(128_001);
        const text = "# Evidence\n\nThe synthetic permit report is complete.\n";
        const document = await service.executeDirect(actorPrincipal, "create_document_version", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId,
          document_id: documentId,
          title: "Synthetic task evidence",
          media_type: "text/markdown; charset=utf-8",
          schema_name: null,
          canonical_body: text,
          expected_current_version_id: null,
          idempotency_key: "task-reference-source-0001"
        });
        expect(document.status).toBe("accepted");
        const reference = {
          document_id: documentId,
          version_id: document.reference!,
          sha256: sha256Hex(Buffer.from(text, "utf8"))
        };
        const taskId = testId(128_002);
        await pool.query(
          `insert into tasks(
             id,organization_id,board_id,owner_member_id,due_at,description_schema,
             canonical_description,required_evidence,task_sha256,state,created_by
           ) values ($1,$2,$3,$4,transaction_timestamp()+interval '1 day',
             'boardagent.task.v1','Deliver the permit report.',
             '{"text":"Canonical source report."}',$5,'open',$4)`,
          [taskId, actor.organizationId, actor.boardId, actor.memberId, Buffer.alloc(32, 7)]
        );
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: taskId,
          evidence_id: testId(128_003),
          canonical_text: null,
          document_references: [reference],
          resource_references: [],
          idempotency_key: "task-reference-evidence-0001"
        };
        if (changed === "unreadable") {
          await expect(
            service.executeDirect(actorPrincipal, "submit_task_evidence", input)
          ).rejects.toThrow("task evidence document reference is unavailable");
          expect((await pool.query("select id from task_evidence")).rows).toEqual([]);
          expect((await pool.query("select state from tasks where id=$1", [taskId])).rows).toEqual([
            { state: "open" }
          ]);
          return;
        }
        if (changed === "retry") {
          await expect(
            service.executeDirect(actorPrincipal, "submit_task_evidence", input)
          ).resolves.toMatchObject({ status: "accepted", data: { replayed: false } });
          await expect(
            service.executeDirect(actorPrincipal, "submit_task_evidence", input)
          ).resolves.toMatchObject({ status: "already_applied", data: { replayed: true } });
        }
        const before = (
          await pool.query("select row_to_json(e)::text as bytes from task_evidence e order by id")
        ).rows;
        const wrong = {
          ...reference,
          ...(changed === "document" || changed === "retry"
            ? { document_id: testId(128_004) }
            : changed === "version"
              ? { version_id: testId(128_005) }
              : { sha256: "a".repeat(64) })
        };
        await expect(
          service.executeDirect(actorPrincipal, "submit_task_evidence", {
            ...input,
            document_references: [wrong]
          })
        ).rejects.toThrow("task evidence document reference is unavailable");
        expect(
          (
            await pool.query(
              "select row_to_json(e)::text as bytes from task_evidence e order by id"
            )
          ).rows
        ).toEqual(before);
        await expect(
          service.executeDirect(actorPrincipal, "submit_task_evidence", input)
        ).resolves.toMatchObject({
          status: changed === "retry" ? "already_applied" : "accepted",
          data: { replayed: changed === "retry" }
        });
        expect((await pool.query("select id from task_evidence")).rows).toHaveLength(1);
      });
    }
  );

  it("publishes a 1000-signer package atomically and signs every recipient notice", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const memberIds = await seedCapacitySeats(pool, secretary, 999);
      const minutes = await seedCalledMeeting(pool, secretary);
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const draft = await service.executeDirect(
        principal(secretary, "secretariat"),
        "create_minutes_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          meeting_id: minutes.meetingId,
          canonical_text: minutes.text,
          transcript_version_id: null,
          expected_current_version_id: null,
          idempotency_key: "surface-minutes-capacity-draft-0001"
        }
      );
      if (!draft.reference) throw new Error("minutes version reference missing");
      await withConfiguredFixtureWorker(pool, secretary.organizationId, async (worker) => {
        let headBefore = 0n;
        const published = await confirmSurfaceAction(
          service,
          secretary,
          "secretariat",
          "publish_minutes",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: minutes.minutesId,
            version_id: draft.reference,
            minutes_sha256: sha256Hex(minutes.text),
            signer_member_ids: [secretary.memberId, ...memberIds],
            idempotency_key: "surface-minutes-capacity-publish-0001"
          },
          async () => {
            await worker.worker.runOnce();
            headBefore = BigInt(
              (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
                .last_sequence as string
            );
          }
        );
        expect(published).toMatchObject({ status: "accepted" });
        expect(
          (
            await pool.query("select count(*)::int as count from notices where object_id=$1", [
              minutes.minutesId
            ])
          ).rows
        ).toEqual([{ count: 1000 }]);
        const headAfter = BigInt(
          (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
            .last_sequence as string
        );
        expect(headAfter - headBefore).toBe(1002n);
        await withWorkerTransaction(
          pool,
          (client) => scheduleAuditCheckpointInTransaction(client, testId(7_900_000)),
          { assumeRole: "boardagent_worker" }
        );
        await worker.worker.runOnce();
        await expect(
          withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).resolves.toMatchObject({
          valid: true,
          ready: true
        });
      });
    });
  }, 60000);

  it("lets the secretary create one exact standalone task and assigns it to the owner", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const owner = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 120_000,
        seatRole: "management",
        scopes: ["task:act"]
      });
      let nextId = 120_500;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const taskId = testId(120_900);
      const created = await confirmSurfaceAction(service, secretary, "secretariat", "create_task", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        task_id: taskId,
        board_id: secretary.boardId,
        owner_member_id: owner.memberId,
        due_at: "2026-10-20T12:00:00Z",
        description: "Deliver the monthly exploration programme and permit status report.",
        required_evidence: ["Canonical report hash.", "Permit register version identifier."],
        source_minutes_id: null,
        source_minutes_version_id: null,
        idempotency_key: "surface-task-create-0001"
      });
      expect(created).toMatchObject({
        tool: "create_task",
        status: "accepted",
        reference: taskId,
        data: {
          schema_version: "boardagent.task-creation-result.v1",
          task_id: taskId,
          owner_member_id: owner.memberId
        }
      });
      const evidence = await pool.query<{
        owner_member_id: string;
        state: string;
        required_evidence: { readonly items: readonly string[] };
        notices: string;
        feeds: string;
        task_events: string;
      }>(
        `select task.owner_member_id,task.state,task.required_evidence,
                (select count(*)::text from notices
                  where object_id=task.id and notice_type='task_assigned') as notices,
                (select count(*)::text from pending_action_feed
                  where object_id=task.id and member_id=$2 and action_type='task_assigned'
                    and state='pending') as feeds,
                (select count(*)::text from audit_events
                  where object_id=task.id and event_type='task_created') as task_events
           from tasks as task where task.id=$1`,
        [taskId, owner.memberId]
      );
      expect(evidence.rows[0]).toEqual({
        owner_member_id: owner.memberId,
        state: "open",
        required_evidence: {
          items: ["Canonical report hash.", "Permit register version identifier."]
        },
        notices: "1",
        feeds: "1",
        task_events: "1"
      });
      await expect(
        service.prepareHumanAction(principal(owner, "member"), "create_task", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: testId(120_901),
          board_id: secretary.boardId,
          owner_member_id: owner.memberId,
          due_at: "2026-10-21T12:00:00Z",
          description: "Attempt to create a task without secretariat authority.",
          required_evidence: ["Canonical evidence."],
          source_minutes_id: null,
          source_minutes_version_id: null,
          idempotency_key: "surface-task-create-denied-0001"
        })
      ).rejects.toThrow("task creation is unavailable");
    });
  }, 60_000);

  it("binds an optional task source to one exact minutes version and rejects a partial source", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const owner = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 121_200,
        seatRole: "management",
        scopes: ["task:act"]
      });
      const minutes = await seedCalledMeeting(pool, secretary);
      let nextId = 121_500;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const draft = await service.executeDirect(
        principal(secretary, "secretariat"),
        "create_minutes_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          meeting_id: minutes.meetingId,
          canonical_text: minutes.text,
          transcript_version_id: null,
          expected_current_version_id: null,
          idempotency_key: "surface-task-source-minutes-0001"
        }
      );
      if (draft.reference === null) throw new Error("task source minutes version is missing");
      const taskId = testId(121_900);
      const sourcedInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        task_id: taskId,
        board_id: secretary.boardId,
        owner_member_id: owner.memberId,
        due_at: "2026-10-22T12:00:00Z",
        description: "Deliver a report tied to the exact source minutes version.",
        required_evidence: ["Canonical report hash."],
        source_minutes_id: minutes.minutesId,
        source_minutes_version_id: draft.reference,
        idempotency_key: "surface-task-create-sourced-0001"
      };
      // SQL0168: a minutes-linked action item binds only the signed, finalized current
      // version. A draft source is refused before any task effect; draft items belong to
      // log_minutes_action_items and open when the minutes finalize.
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "create_task", sourcedInput)
      ).rejects.toThrow("task source must identify one exact minutes version on the active board");
      expect((await pool.query("select id from tasks where id=$1", [taskId])).rows).toEqual([]);
      await confirmSurfaceAction(service, secretary, "secretariat", "publish_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutes.minutesId,
        version_id: draft.reference,
        minutes_sha256: sha256Hex(minutes.text),
        signer_member_ids: [secretary.memberId],
        idempotency_key: "surface-task-source-publish-0001"
      });
      // The signature package needs the exact current action declaration; these minutes
      // declare no draft items, so the sourced task below is the only minutes-linked item.
      await confirmSurfaceAction(
        service,
        secretary,
        "secretariat",
        "declare_no_minutes_action_items",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          manifest: {
            schemaVersion: "boardagent.minutes-action-manifest.v1",
            minutesId: minutes.minutesId,
            minutesVersion: 1,
            minutesSha256: sha256Hex(minutes.text),
            declaration: "no_action_items"
          },
          idempotency_key: "surface-task-source-declare-0001"
        }
      );
      const signaturePackage = await confirmSurfaceAction(
        service,
        secretary,
        "secretariat",
        "prepare_minutes_for_signature",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          expected_version_id: draft.reference,
          signer_member_ids: [secretary.memberId],
          idempotency_key: "surface-task-source-package-0001"
        }
      );
      if (signaturePackage.reference === null) {
        throw new Error("minutes signature package reference is missing");
      }
      await confirmSurfaceAction(service, secretary, "secretariat", "stage_minutes_signature", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutes.minutesId,
        package_id: signaturePackage.reference,
        reservation: null,
        idempotency_key: "surface-task-source-signature-0001"
      });
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "finalize_minutes", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          package_id: signaturePackage.reference,
          idempotency_key: "surface-task-source-finalize-0001"
        })
      ).resolves.toMatchObject({ tool: "finalize_minutes", status: "accepted" });
      expect(
        (
          await pool.query("select state,current_version_id from minutes where id=$1", [
            minutes.minutesId
          ])
        ).rows
      ).toEqual([{ state: "finalized", current_version_id: draft.reference }]);
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "create_task", {
          ...sourcedInput,
          idempotency_key: "surface-task-create-sourced-0002"
        })
      ).resolves.toMatchObject({
        tool: "create_task",
        status: "accepted",
        reference: taskId
      });
      const source = await pool.query<{
        source_meeting_id: string;
        source_minutes_id: string;
        source_minutes_version_id: string;
        source_minutes_sha256: string;
      }>(
        `select source_meeting_id,source_minutes_id,source_minutes_version_id,
                encode(source_minutes_sha256,'hex') as source_minutes_sha256
           from tasks where id=$1`,
        [taskId]
      );
      expect(source.rows[0]).toEqual({
        source_meeting_id: minutes.meetingId,
        source_minutes_id: minutes.minutesId,
        source_minutes_version_id: draft.reference,
        source_minutes_sha256: sha256Hex(minutes.text)
      });
      await expect(
        service.prepareHumanAction(principal(secretary, "secretariat"), "create_task", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: testId(121_901),
          board_id: secretary.boardId,
          owner_member_id: owner.memberId,
          due_at: "2026-10-23T12:00:00Z",
          description: "Invalid partially sourced task.",
          required_evidence: ["Canonical evidence."],
          source_minutes_id: minutes.minutesId,
          source_minutes_version_id: null,
          idempotency_key: "surface-task-create-partial-source-0001"
        })
      ).rejects.toThrow("must both be present or both be null");
    });
  }, 60_000);

  it("lets an observer comment, propose an exact redline, and withdraw only their comment", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const observer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 122_000,
        seatRole: "observer",
        scopes: ["minutes:act"]
      });
      const minutes = await seedCalledMeeting(pool, secretary);
      let nextId = 123_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const draft = await service.executeDirect(
        principal(secretary, "secretariat"),
        "create_minutes_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          meeting_id: minutes.meetingId,
          canonical_text: minutes.text,
          transcript_version_id: null,
          expected_current_version_id: null,
          idempotency_key: "surface-minutes-version-0001"
        }
      );
      expect(draft).toMatchObject({
        tool: "create_minutes_version",
        status: "accepted",
        resource_uri: `board://${secretary.boardId}/minutes/${minutes.minutesId}/versions/1`,
        data: { version: 1, canonical_sha256: sha256Hex(minutes.text), replayed: false }
      });
      if (draft.reference === null) throw new Error("minutes draft version reference is missing");
      const minutesSha256 = sha256Hex(minutes.text);
      const publishInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutes.minutesId,
        version_id: draft.reference,
        minutes_sha256: minutesSha256,
        signer_member_ids: [secretary.memberId, observer.memberId],
        idempotency_key: "surface-minutes-publish-0001"
      } as const;
      const preparedPublication = await service.prepareHumanAction(
        principal(secretary, "secretariat"),
        "publish_minutes",
        publishInput
      );
      expect(preparedPublication.confirmation_lines.join("\n")).toContain(minutesSha256);
      const clientCapabilities = { elicitation: { form: {} } } as const;
      const requestState = "surface-minutes-publication-request-state";
      await service.persistHumanStage({
        principal: principal(secretary, "secretariat"),
        tool: "publish_minutes",
        input: publishInput,
        prepared: preparedPublication,
        client_capabilities: clientCapabilities,
        embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
        embedded_result: { message: "Confirm exact minutes publication" },
        request_state: requestState,
        prepared_request_id: Buffer.from("surface-minutes-publication-prepare")
      });
      const publication = await service.resolveHumanAction({
        principal: principal(secretary, "secretariat"),
        tool: "publish_minutes",
        input: publishInput,
        stage_id: preparedPublication.stage_id,
        client_capabilities: clientCapabilities,
        request_state: requestState,
        retry_request_id: Buffer.from("surface-minutes-publication-retry"),
        response_action: "accept",
        input_response: {
          approve: true,
          confirmation_code: preparedPublication.confirmation_code
        }
      });
      if (!publication.confirmed) {
        throw new Error(`minutes publication failed: ${publication.reason}`);
      }
      expect(publication.result).toMatchObject({
        tool: "publish_minutes",
        status: "accepted",
        data: {
          minutes_id: minutes.minutesId,
          minutes_version_id: draft.reference,
          minutes_sha256: minutesSha256,
          review_recipient_member_ids: [secretary.memberId, observer.memberId].toSorted()
        }
      });
      const commentInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        payload: {
          schemaVersion: "boardagent.minutes-comment.v1",
          minutesId: minutes.minutesId,
          baseVersion: 1,
          baseSha256: minutesSha256,
          comment: "Please retain the approved wording.\n",
          citations: []
        },
        idempotency_key: "surface-minutes-comment-0001"
      } as const;

      const comment = await service.executeDirect(
        principal(observer, "observer"),
        "comment_minutes",
        commentInput
      );
      expect(comment).toMatchObject({
        tool: "comment_minutes",
        status: "accepted",
        data: {
          minutes_id: minutes.minutesId,
          review_kind: "comment",
          replayed: false
        }
      });
      await expect(
        service.executeDirect(principal(observer, "observer"), "comment_minutes", commentInput)
      ).resolves.toMatchObject({
        status: "already_applied",
        reference: comment.reference,
        data: { replayed: true }
      });

      const redline = await service.executeDirect(
        principal(observer, "observer"),
        "propose_minutes_redline",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          payload: {
            schemaVersion: "boardagent.minutes-redline.v1",
            minutesId: minutes.minutesId,
            baseVersion: 1,
            baseSha256: minutesSha256,
            anchor: { kind: "lines", startLine: 2, endLine: 2 },
            anchoredTextSha256: sha256Hex("Approved draft."),
            operation: "replace",
            proposedText: "Approved final wording.",
            rationale: "Use the exact approved resolution wording.",
            citations: []
          },
          idempotency_key: "surface-minutes-redline-0001"
        }
      );
      expect(redline).toMatchObject({
        tool: "propose_minutes_redline",
        status: "accepted",
        data: { review_kind: "redline", replayed: false }
      });

      const withdrawal = await service.executeDirect(
        principal(observer, "observer"),
        "withdraw_minutes_comment",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          review_item_id: comment.reference,
          idempotency_key: "surface-minutes-withdraw-0001"
        }
      );
      expect(withdrawal).toMatchObject({
        tool: "withdraw_minutes_comment",
        status: "accepted",
        data: {
          minutes_id: minutes.minutesId,
          review_item_id: comment.reference,
          replayed: false
        }
      });
      await expect(
        service.executeDirect(principal(observer, "observer"), "withdraw_minutes_comment", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: testId(121_099),
          review_item_id: redline.reference,
          idempotency_key: "surface-minutes-withdraw-0002"
        })
      ).rejects.toThrow("minutes comment is unavailable");

      const evidence = await pool.query<{
        comments: string;
        feeds: string;
        notices: string;
        redlines: string;
        withdrawals: string;
      }>(
        `select
          (select count(*)::text from minutes_review_items where item_kind='comment') as comments,
          (select count(*)::text from minutes_review_items where item_kind='redline') as redlines,
          (select count(*)::text from minutes_review_withdrawals) as withdrawals,
          (select count(*)::text from notices where notice_type='minutes_review_submitted') as notices,
          (select count(*)::text from pending_action_feed
            where action_type='minutes_review_submitted') as feeds`
      );
      expect(evidence.rows[0]).toEqual({
        comments: "1",
        redlines: "1",
        withdrawals: "1",
        notices: "2",
        feeds: "2"
      });
    });
  });

  it("runs disposition, action declaration, signatures, finalization, linked correction and AC16 delegated director replacement through the surface", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const member = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 124_000,
        seatRole: "voting_member",
        scopes: ["minutes:act", "task:act"]
      });
      const observer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 125_000,
        seatRole: "observer",
        scopes: ["minutes:act"]
      });
      const minutes = await seedCalledMeeting(pool, secretary);
      let nextId = 126_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const draft = await service.executeDirect(
        principal(secretary, "secretariat"),
        "create_minutes_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          meeting_id: minutes.meetingId,
          canonical_text: minutes.text,
          transcript_version_id: null,
          expected_current_version_id: null,
          idempotency_key: "surface-minutes-lifecycle-version-0001"
        }
      );
      if (draft.reference === null) throw new Error("minutes draft version reference is missing");
      const minutesSha256 = sha256Hex(minutes.text);
      await confirmSurfaceAction(service, secretary, "secretariat", "publish_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutes.minutesId,
        version_id: draft.reference,
        minutes_sha256: minutesSha256,
        signer_member_ids: [secretary.memberId, member.memberId, observer.memberId],
        idempotency_key: "surface-minutes-lifecycle-publish-0001"
      });
      const comment = await service.executeDirect(principal(member, "member"), "comment_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        payload: {
          schemaVersion: "boardagent.minutes-comment.v1",
          minutesId: minutes.minutesId,
          baseVersion: 1,
          baseSha256: minutesSha256,
          comment: "Please make the action owner explicit.",
          citations: []
        },
        idempotency_key: "surface-minutes-lifecycle-comment-0001"
      });
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "resolve_minutes_review_item", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          review_item_id: comment.reference,
          disposition: "reject",
          reason: "The exact action owner is recorded in the structured action manifest.",
          replacement_text: null,
          idempotency_key: "surface-minutes-lifecycle-disposition-0001"
        })
      ).resolves.toMatchObject({
        tool: "resolve_minutes_review_item",
        status: "accepted",
        data: { decision: "rejected", minutes_version_id: draft.reference }
      });
      const taskId = testId(127_000);
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "log_minutes_action_items", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          manifest: {
            schemaVersion: "boardagent.minutes-action-manifest.v1",
            minutesId: minutes.minutesId,
            minutesVersion: 1,
            minutesSha256,
            declaration: "items_logged",
            items: [
              {
                itemId: taskId,
                ownerMemberId: member.memberId,
                dueAt: "2026-10-01T12:00:00Z",
                sourceLocator: { section: "Minutes", line: 2 },
                description: "Deliver the exploration permit status report.",
                requiredEvidence: "Canonical report hash.",
                visibility: "board"
              }
            ]
          },
          idempotency_key: "surface-minutes-lifecycle-actions-0001"
        })
      ).resolves.toMatchObject({
        tool: "log_minutes_action_items",
        status: "accepted",
        data: { minutes_id: minutes.minutesId, task_ids: [taskId] }
      });
      const signaturePackage = await confirmSurfaceAction(
        service,
        secretary,
        "secretariat",
        "prepare_minutes_for_signature",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          expected_version_id: draft.reference,
          signer_member_ids: [secretary.memberId, member.memberId, observer.memberId],
          idempotency_key: "surface-minutes-lifecycle-signature-package-0001"
        }
      );
      expect(signaturePackage).toMatchObject({
        tool: "prepare_minutes_for_signature",
        status: "accepted",
        data: {
          minutes_id: minutes.minutesId,
          signer_member_ids: [secretary.memberId, member.memberId, observer.memberId].toSorted()
        }
      });
      if (signaturePackage.reference === null) {
        throw new Error("minutes signature package reference is missing");
      }
      const recuse = async (
        kind: "meeting" | "minutes",
        target: AuthorizedActorFixture,
        operation: "add" | "lift",
        key: string
      ) =>
        confirmSyntheticSurfaceAction(
          service,
          principal(secretary, "secretariat"),
          "manage_recusal",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: secretary.boardId,
            object_type: kind,
            object_id: kind === "meeting" ? minutes.meetingId : minutes.minutesId,
            member_id: target.memberId,
            operation,
            reason: "Synthetic declared conflict lifecycle",
            idempotency_key: key
          }
        );
      const appointmentBefore = (
        await pool.query(
          "select row_to_json(m)::text bytes from board_memberships m where member_id=$1",
          [member.memberId]
        )
      ).rows;
      await expect(
        confirmSurfaceAction(
          service,
          member,
          "member",
          "stage_minutes_signature",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: minutes.minutesId,
            package_id: signaturePackage.reference,
            reservation: null,
            idempotency_key: "surface-recusal-stale-signature-0001"
          },
          async () => {
            await recuse("meeting", member, "add", "surface-recusal-parent-add-0001");
          }
        )
      ).rejects.toThrow();
      expect(
        (
          await pool.query("select id from minutes_signatures where signer_member_id=$1", [
            member.memberId
          ])
        ).rows
      ).toEqual([]);
      const replacedSignatureStages = (
        await pool.query(
          "select id,state from action_stages where actor_member_id=$1 and action_code='stage_minutes_signature'",
          [member.memberId]
        )
      ).rows;
      expect(replacedSignatureStages).toHaveLength(1);
      expect(replacedSignatureStages[0].state).toBe("replaced");
      await recuse("minutes", member, "add", "surface-recusal-child-add-0001");
      await recuse("meeting", member, "lift", "surface-recusal-parent-lift-0001");
      expect(
        await withRequestTransaction(
          pool,
          member.context,
          async (c) => ({
            minutes: (await c.query("select id from minutes where id=$1", [minutes.minutesId]))
              .rows,
            tasks: (await c.query("select id from tasks where id=$1", [taskId])).rows,
            packages: (
              await c.query("select id from minutes_signature_packages where minutes_id=$1", [
                minutes.minutesId
              ])
            ).rows
          }),
          { assumeRole: "boardagent_server" }
        )
      ).toEqual({ minutes: [], tasks: [], packages: [] });
      await expect(
        service.prepareHumanAction(principal(member, "member"), "stage_minutes_signature", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          package_id: signaturePackage.reference,
          reservation: null,
          idempotency_key: "surface-recusal-denied-signature-0001"
        })
      ).rejects.toThrow();
      await expect(
        service.prepareHumanAction(principal(secretary, "secretariat"), "finalize_minutes", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          package_id: signaturePackage.reference,
          idempotency_key: "surface-recusal-no-waiver-0001"
        })
      ).rejects.toThrow(/signature/);
      await recuse("minutes", member, "lift", "surface-recusal-child-lift-0001");
      expect(
        (
          await pool.query(
            "select id,state from action_stages where actor_member_id=$1 and action_code='stage_minutes_signature'",
            [member.memberId]
          )
        ).rows
      ).toEqual(replacedSignatureStages);
      expect(
        (
          await pool.query(
            "select row_to_json(m)::text bytes from board_memberships m where member_id=$1",
            [member.memberId]
          )
        ).rows
      ).toEqual(appointmentBefore);
      for (const [actor, role] of [
        [secretary, "secretariat"],
        [member, "member"],
        [observer, "observer"]
      ] as const) {
        await expect(
          confirmSurfaceAction(service, actor, role, "stage_minutes_signature", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            minutes_id: minutes.minutesId,
            package_id: signaturePackage.reference,
            reservation: role === "observer" ? "Observer attestation only; not a vote." : null,
            idempotency_key: `surface-minutes-lifecycle-signature-${role}-0001`
          })
        ).resolves.toMatchObject({
          tool: "stage_minutes_signature",
          status: "accepted",
          data: { minutes_id: minutes.minutesId }
        });
      }
      const signatureHistory = (
        await pool.query("select row_to_json(s)::text bytes from minutes_signatures s order by id")
      ).rows;
      await recuse("minutes", observer, "add", "surface-recusal-signed-observer-add-0001");
      expect(
        (
          await pool.query(
            "select row_to_json(s)::text bytes from minutes_signatures s order by id"
          )
        ).rows
      ).toEqual(signatureHistory);
      expect((await pool.query("select id from minutes_signature_supersessions")).rows).toEqual([]);
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "finalize_minutes", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          package_id: signaturePackage.reference,
          idempotency_key: "surface-minutes-lifecycle-finalize-0001"
        })
      ).resolves.toMatchObject({
        tool: "finalize_minutes",
        status: "accepted",
        data: { minutes_id: minutes.minutesId, activated_task_ids: [taskId] }
      });
      await recuse("minutes", observer, "lift", "surface-recusal-signed-observer-lift-0001");
      expect(
        (
          await pool.query(
            "select row_to_json(s)::text bytes from minutes_signatures s order by id"
          )
        ).rows
      ).toEqual(signatureHistory);
      await expect(
        service.executeDirect(principal(member, "member"), "start_task", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: taskId,
          idempotency_key: "surface-task-start-0001"
        })
      ).resolves.toMatchObject({
        tool: "start_task",
        status: "accepted",
        reference: taskId,
        data: { task_id: taskId, replayed: false }
      });
      const evidenceId = testId(127_002);
      await expect(
        service.executeDirect(principal(member, "member"), "submit_task_evidence", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: taskId,
          evidence_id: evidenceId,
          canonical_text: "The exploration permit status report is complete.\n",
          document_references: [],
          resource_references: [],
          idempotency_key: "surface-task-evidence-0001"
        })
      ).resolves.toMatchObject({
        tool: "submit_task_evidence",
        status: "accepted",
        reference: evidenceId,
        data: { task_id: taskId, evidence_id: evidenceId, replayed: false }
      });
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "review_task_evidence", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: taskId,
          evidence_id: evidenceId,
          disposition: "accept",
          reason: "The exact canonical report evidence is sufficient.",
          idempotency_key: "surface-task-review-0001"
        })
      ).resolves.toMatchObject({
        tool: "review_task_evidence",
        status: "accepted",
        data: { task_id: taskId, evidence_id: evidenceId, decision: "accepted" }
      });
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "complete_task", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: taskId,
          evidence_ids: [evidenceId],
          idempotency_key: "surface-task-complete-0001"
        })
      ).resolves.toMatchObject({
        tool: "complete_task",
        status: "accepted",
        data: { task_id: taskId }
      });
      const replacementTaskId = testId(127_003);
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "create_task_correction_cycle", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: taskId,
          replacement_task_id: replacementTaskId,
          owner_member_id: member.memberId,
          due_at: "2026-10-15T12:00:00Z",
          description: "Deliver the corrected exploration permit status report.",
          required_evidence: ["Corrected canonical report hash."],
          reason: "The board requires a separately tracked correction.",
          idempotency_key: "surface-task-correction-cycle-0001"
        })
      ).resolves.toMatchObject({
        tool: "create_task_correction_cycle",
        status: "accepted",
        reference: replacementTaskId,
        data: { prior_task_id: taskId, replacement_task_id: replacementTaskId }
      });
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "cancel_task", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          task_id: replacementTaskId,
          reason: "The board withdrew the corrected obligation.",
          idempotency_key: "surface-task-cancel-0001"
        })
      ).resolves.toMatchObject({
        tool: "cancel_task",
        status: "accepted",
        data: { task_id: replacementTaskId }
      });
      const replacementMinutesId = testId(127_001);
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "create_minutes_correction_cycle", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          replacement_minutes_id: replacementMinutesId,
          canonical_text: `${minutes.text}\n# Correction\nLinked replacement.\n`,
          reason: "Preserve the original while recording the final correction.",
          idempotency_key: "surface-minutes-lifecycle-correction-cycle-0001"
        })
      ).resolves.toMatchObject({
        tool: "create_minutes_correction_cycle",
        status: "accepted",
        reference: replacementMinutesId,
        data: {
          original_minutes_id: minutes.minutesId,
          replacement_minutes_id: replacementMinutesId
        }
      });

      const evidence = await pool.query<{
        original_state: string;
        replacement_state: string;
        replacement_task_state: string;
        task_state: string;
      }>(
        `select
          (select state from minutes where id=$1) as original_state,
          (select state from minutes where id=$2) as replacement_state,
          (select state from tasks where id=$3) as task_state,
          (select state from tasks where id=$4) as replacement_task_state`,
        [minutes.minutesId, replacementMinutesId, taskId, replacementTaskId]
      );
      expect(evidence.rows[0]).toEqual({
        original_state: "finalized",
        replacement_state: "published_review",
        replacement_task_state: "cancelled",
        task_state: "completed"
      });
      const history = await preserveHistoricRecords(pool, [
        "meetings",
        "minutes",
        "minutes_versions",
        "minutes_review_items",
        "minutes_review_dispositions",
        "minutes_action_declarations",
        "minutes_correction_cycles",
        "minutes_signature_packages",
        "minutes_signature_requirements",
        "minutes_signatures",
        "tasks",
        "task_evidence",
        "task_evidence_reviews",
        "task_closures",
        "task_correction_cycles",
        "membership_versions",
        "consent_records",
        "audit_events"
      ]);
      expect(history.counts).toMatchObject({
        minutes: 2,
        minutes_signatures: 3,
        tasks: 2,
        task_closures: 1
      });
      const departedSignature = (
        await pool.query("select id from minutes_signatures where signer_member_id=$1", [
          member.memberId
        ])
      ).rows;
      expect(departedSignature).toHaveLength(1);
      const { successorId } = await replaceDirectorThroughDelegate(
        pool,
        secretary,
        member,
        history.assertPreserved
      );
      expect(
        (
          await pool.query("select id from minutes_signatures where signer_member_id=$1", [
            member.memberId
          ])
        ).rows
      ).toEqual(departedSignature);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from minutes_signatures where signer_member_id=$1",
            [successorId]
          )
        ).rows[0]
      ).toEqual({ n: 0 });
      await history.assertPreserved();
    });
  }, 60_000);

  it("corrects a published package, records no action items, and cancels with exact bindings", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["minutes:act", "secretariat:admin"],
        isSecretary: true
      });
      const minutes = await seedCalledMeeting(pool, secretary);
      let nextId = 128_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const draft = await service.executeDirect(
        principal(secretary, "secretariat"),
        "create_minutes_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          meeting_id: minutes.meetingId,
          canonical_text: minutes.text,
          transcript_version_id: null,
          expected_current_version_id: null,
          idempotency_key: "surface-minutes-correction-version-0001"
        }
      );
      if (draft.reference === null) throw new Error("minutes draft version reference is missing");
      await confirmSurfaceAction(service, secretary, "secretariat", "publish_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutes.minutesId,
        version_id: draft.reference,
        minutes_sha256: sha256Hex(minutes.text),
        signer_member_ids: [secretary.memberId],
        idempotency_key: "surface-minutes-correction-publish-0001"
      });
      const tamperInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutes.minutesId,
        reason: "Tamper probe must never persist.",
        idempotency_key: "surface-minutes-stage-tamper-0001"
      } as const;
      const tamperPrepared = await service.prepareHumanAction(
        principal(secretary, "secretariat"),
        "cancel_minutes",
        tamperInput
      );
      await expect(
        service.persistHumanStage({
          principal: principal(secretary, "secretariat"),
          tool: "cancel_minutes",
          input: tamperInput,
          prepared: { ...tamperPrepared, board_id: testId(128_998) },
          client_capabilities: { elicitation: { form: {} } },
          embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
          embedded_result: { message: "Tampered board binding" },
          request_state: "surface-minutes-tamper-request-state-bound-by-client",
          prepared_request_id: Buffer.from("surface-minutes-tamper-prepare")
        })
      ).rejects.toThrow("changed after presentation");
      const tamperEvidence = await pool.query<{ stages: string }>(
        "select count(*)::text as stages from action_stages where id=$1",
        [tamperPrepared.stage_id]
      );
      expect(tamperEvidence.rows[0]?.stages).toBe("0");
      const correctedText = `${minutes.text}\n# Correction\nPermit number clarified.\n`;
      await expect(
        service.prepareHumanAction(principal(secretary, "secretariat"), "correct_minutes_package", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          expected_version_id: testId(128_999),
          canonical_text: correctedText,
          reason: "Bind the exact exploration permit number.",
          idempotency_key: "surface-minutes-correction-stale-0001"
        })
      ).rejects.toThrow("exact current version");
      const corrected = await confirmSurfaceAction(
        service,
        secretary,
        "secretariat",
        "correct_minutes_package",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          expected_version_id: draft.reference,
          canonical_text: correctedText,
          reason: "Bind the exact exploration permit number.",
          idempotency_key: "surface-minutes-correction-0001"
        }
      );
      expect(corrected).toMatchObject({
        tool: "correct_minutes_package",
        status: "accepted",
        data: {
          minutes_id: minutes.minutesId,
          minutes_sha256: sha256Hex(correctedText)
        }
      });
      if (corrected.reference === null) {
        throw new Error("corrected minutes version reference is missing");
      }
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "declare_no_minutes_action_items", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          manifest: {
            schemaVersion: "boardagent.minutes-action-manifest.v1",
            minutesId: minutes.minutesId,
            minutesVersion: 2,
            minutesSha256: sha256Hex(correctedText),
            declaration: "no_action_items"
          },
          idempotency_key: "surface-minutes-no-actions-0001"
        })
      ).resolves.toMatchObject({
        tool: "declare_no_minutes_action_items",
        status: "accepted",
        data: { minutes_id: minutes.minutesId, task_ids: [] }
      });
      await expect(
        confirmSurfaceAction(service, secretary, "secretariat", "cancel_minutes", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          reason: "The board ordered a fresh minutes process.",
          idempotency_key: "surface-minutes-cancel-0001"
        })
      ).resolves.toMatchObject({
        tool: "cancel_minutes",
        status: "accepted",
        data: { minutes_id: minutes.minutesId, superseded_draft_task_ids: [] }
      });
      const evidence = await pool.query<{ state: string; versions: string }>(
        `select
          (select state from minutes where id=$1) as state,
          (select count(*)::text from minutes_versions where minutes_id=$1) as versions`,
        [minutes.minutesId]
      );
      expect(evidence.rows[0]).toEqual({ state: "cancelled", versions: "2" });
    });
  }, 60_000);
});

describe("minutes feed lifecycle", () => {
  interface SignatureFeedItem {
    readonly action_type: string;
    readonly object_id: string;
    readonly state: string;
    readonly payload: {
      readonly deltaType: string;
      readonly safeRefs: { readonly signaturePackageId: string; readonly packageSha256: string };
    };
  }

  async function fixture(pool: Pool) {
    const { PgSurfaceReadRepository } = await import("../../artifacts/server/src/index.js");
    const secretary = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["minutes:act", "secretariat:admin", "governance:read"],
      isSecretary: true
    });
    const memberA = await seedAdditionalAuthorizedActor(pool, secretary, {
      idBase: 160_000,
      seatRole: "voting_member",
      scopes: ["minutes:act", "task:act", "governance:read"]
    });
    const memberB = await seedAdditionalAuthorizedActor(pool, secretary, {
      idBase: 161_000,
      seatRole: "voting_member",
      scopes: ["minutes:act", "task:act", "governance:read"]
    });
    const readPrincipals = new Map<string, SurfacePrincipal>();
    for (const [actor, idBase] of [
      [memberA, 160_000],
      [memberB, 161_000]
    ] as const) {
      const sessionId = testId(idBase + 900);
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [
          sessionId,
          actor.organizationId,
          Buffer.from(sha256Hex(`minutes-feed-session-${actor.memberId}`), "hex"),
          actor.memberId,
          actor.clientId
        ]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);
      readPrincipals.set(actor.memberId, {
        ...principal(actor, "member"),
        protocolClientId: `authorized-test-client-${String(idBase)}`,
        keyId: `test-oauth-${String(idBase)}`,
        scopes: ["minutes:act", "task:act", "governance:read"]
      });
    }
    const minutes = await seedCalledMeeting(pool, secretary);
    let nextId = 162_000;
    const reader = new PgSurfaceReadRepository(pool, {
      cursorKey: Buffer.alloc(32, 0x6d),
      transaction: { assumeRole: "boardagent_server" }
    });
    const service = new PgBoardAgentSurfaceService(pool, {
      reads: reader,
      transaction: { assumeRole: "boardagent_server" },
      newId: () => testId(nextId++)
    });
    const draft = await service.executeDirect(
      principal(secretary, "secretariat"),
      "create_minutes_version",
      {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutes.minutesId,
        meeting_id: minutes.meetingId,
        canonical_text: minutes.text,
        transcript_version_id: null,
        expected_current_version_id: null,
        idempotency_key: "minutes-feed-initial-draft-0001"
      }
    );
    expect(draft.status).toBe("accepted");
    if (!draft.reference) throw new Error("minutes feed fixture draft reference missing");
    let currentVersionId = draft.reference;
    let version = 1;
    let text = minutes.text;
    await confirmSurfaceAction(service, secretary, "secretariat", "publish_minutes", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      minutes_id: minutes.minutesId,
      version_id: currentVersionId,
      minutes_sha256: sha256Hex(text),
      signer_member_ids: [memberA.memberId, memberB.memberId],
      idempotency_key: "minutes-feed-initial-publish-0001"
    });

    const pending = async (actor: AuthorizedActorFixture): Promise<SignatureFeedItem[]> => {
      const readPrincipal = readPrincipals.get(actor.memberId);
      if (!readPrincipal) throw new Error("minutes feed read principal is missing");
      const response = await reader.executeRead(readPrincipal, "list_pending_actions", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        cursor: null
      });
      const data = response.data as unknown as {
        readonly status: string;
        readonly items: SignatureFeedItem[];
      };
      expect(data.status).toBe("complete");
      expect(Array.isArray(data.items)).toBe(true);
      return data.items.filter(
        (item) =>
          item.object_id === minutes.minutesId &&
          ["minutes_signature_required", "minutes_resign_required"].includes(item.action_type)
      );
    };

    const issue = async (signers: readonly AuthorizedActorFixture[] = [memberA]) => {
      await confirmSurfaceAction(
        service,
        secretary,
        "secretariat",
        "declare_no_minutes_action_items",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          manifest: {
            schemaVersion: "boardagent.minutes-action-manifest.v1",
            minutesId: minutes.minutesId,
            minutesVersion: version,
            minutesSha256: sha256Hex(text),
            declaration: "no_action_items"
          },
          idempotency_key: `minutes-feed-no-actions-version-${String(version)}`
        }
      );
      const issued = await confirmSurfaceAction(
        service,
        secretary,
        "secretariat",
        "prepare_minutes_for_signature",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          expected_version_id: currentVersionId,
          signer_member_ids: signers.map((actor) => actor.memberId),
          idempotency_key: `minutes-feed-issue-version-${String(version)}`
        }
      );
      expect(issued.status).toBe("accepted");
      if (!issued.reference) throw new Error("minutes feed fixture package reference missing");
      return issued.reference;
    };

    const correct = async () => {
      const nextText = `${text}\nCorrection ${String(version + 1)}: clarify the exploration programme.\n`;
      const corrected = await confirmSurfaceAction(
        service,
        secretary,
        "secretariat",
        "correct_minutes_package",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          expected_version_id: currentVersionId,
          canonical_text: nextText,
          reason: "The secretary presents corrected synthetic programme wording for fresh review.",
          idempotency_key: `minutes-feed-correct-version-${String(version)}`
        }
      );
      expect(corrected.status).toBe("accepted");
      if (!corrected.reference)
        throw new Error("minutes feed fixture correction reference missing");
      currentVersionId = corrected.reference;
      text = nextText;
      version += 1;
    };

    const sign = async (actor: AuthorizedActorFixture, packageId: string) => {
      const signed = await confirmSurfaceAction(
        service,
        actor,
        "member",
        "stage_minutes_signature",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutes.minutesId,
          package_id: packageId,
          reservation: null,
          idempotency_key: `minutes-feed-sign-${packageId}-${actor.memberId}`
        }
      );
      expect(signed.status).toBe("accepted");
    };

    const packageFeedRows = async (packageId: string) =>
      (
        await pool.query<{ id: string; state: string; resolved_at: Date | null }>(
          `select id,state,resolved_at from pending_action_feed
            where object_type='minutes' and object_id=$1
              and convert_from(canonical_payload,'UTF8')::jsonb->'safeRefs'->>'signaturePackageId'=$2
            order by id`,
          [minutes.minutesId, packageId]
        )
      ).rows;

    return {
      service,
      secretary,
      memberA,
      memberB,
      minutes,
      pending,
      issue,
      correct,
      sign,
      packageFeedRows
    };
  }

  it("keeps the current re-sign delta after two corrections without an interim signature", async () => {
    await withDatabase(async (pool) => {
      const f = await fixture(pool);
      const p1 = await f.issue();
      expect(await f.pending(f.memberA)).toMatchObject([
        { action_type: "minutes_signature_required" }
      ]);
      await f.sign(f.memberA, p1);
      expect(await f.pending(f.memberA)).toEqual([]);
      const signedHistory = (
        await pool.query("select row_to_json(s)::text bytes from minutes_signatures s order by id")
      ).rows;
      await f.correct();
      const p2 = await f.issue();
      expect(await f.pending(f.memberA)).toMatchObject([
        {
          action_type: "minutes_resign_required",
          payload: { deltaType: "minutes_resign_required", safeRefs: { signaturePackageId: p2 } }
        }
      ]);
      await f.correct();
      const p3 = await f.issue();
      const current = (await f.pending(f.memberA)).filter(
        (item) => item.payload.safeRefs.signaturePackageId === p3
      );
      expect.soft(current).toEqual([
        expect.objectContaining({
          action_type: "minutes_resign_required",
          payload: expect.objectContaining({
            deltaType: "minutes_resign_required",
            safeRefs: expect.objectContaining({ signaturePackageId: p3 })
          })
        })
      ]);
      expect(
        (
          await pool.query(
            "select to_package_id,state from minutes_resign_requirements where signer_member_id=$1 and state='pending'",
            [f.memberA.memberId]
          )
        ).rows
      ).toEqual([{ to_package_id: p3, state: "pending" }]);
      expect(
        (
          await pool.query(
            "select row_to_json(s)::text bytes from minutes_signatures s order by id"
          )
        ).rows
      ).toEqual(signedHistory);
      await confirmSurfaceAction(f.service, f.secretary, "secretariat", "cancel_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: f.minutes.minutesId,
        reason: "End the synthetic correction case without carrying any prior signature.",
        idempotency_key: "minutes-feed-cancel-classification-case"
      });
      expect(await f.pending(f.memberA)).toEqual([]);
    });
  }, 60_000);

  it.each(["signature", "re-sign"] as const)(
    "retires obsolete %s actions on correction and preserves their history",
    async (kind) => {
      await withDatabase(async (pool) => {
        const f = await fixture(pool);
        let obsoletePackage = await f.issue();
        if (kind === "re-sign") {
          await f.sign(f.memberA, obsoletePackage);
          await f.correct();
          obsoletePackage = await f.issue();
        }
        expect(await f.pending(f.memberA)).toHaveLength(1);
        const history = await f.packageFeedRows(obsoletePackage);
        expect(history).toHaveLength(1);
        await f.correct();
        expect.soft(await f.pending(f.memberA)).toEqual([]);
        const retired = await f.packageFeedRows(obsoletePackage);
        expect(retired.map(({ id }) => id)).toEqual(history.map(({ id }) => id));
        expect
          .soft(
            retired.every(({ state, resolved_at }) => state !== "pending" && resolved_at !== null)
          )
          .toBe(true);
        expect(
          (
            await pool.query("select state,current_signature_package_id from minutes where id=$1", [
              f.minutes.minutesId
            ])
          ).rows
        ).toEqual([{ state: "published_review", current_signature_package_id: null }]);
        const currentPackage = await f.issue();
        const current = (await f.pending(f.memberA)).filter(
          (item) => item.payload.safeRefs.signaturePackageId === currentPackage
        );
        expect(current).toHaveLength(1);
        await f.sign(f.memberA, currentPackage);
        expect(await f.pending(f.memberA)).toEqual([]);
        expect((await f.packageFeedRows(obsoletePackage)).map(({ id }) => id)).toEqual(
          history.map(({ id }) => id)
        );
      });
    },
    60_000
  );

  it("leaves no obsolete re-sign action after a fresh signer set completes and finalizes", async () => {
    await withDatabase(async (pool) => {
      const f = await fixture(pool);
      const p1 = await f.issue();
      await f.sign(f.memberA, p1);
      await f.correct();
      const p2 = await f.issue();
      expect(await f.pending(f.memberA)).toMatchObject([
        { action_type: "minutes_resign_required" }
      ]);
      const history = await f.packageFeedRows(p2);
      await f.correct();
      // This is a new, fully confirmed package. No current-package required signer is waived.
      const p3 = await f.issue([f.memberB]);
      expect(
        (
          await pool.query(
            "select member_id,requirement from minutes_signature_requirements where package_id=$1",
            [p3]
          )
        ).rows
      ).toEqual([{ member_id: f.memberB.memberId, requirement: "required" }]);
      const finalizeInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: f.minutes.minutesId,
        package_id: p3,
        idempotency_key: "minutes-feed-finalize-fresh-signer-set"
      };
      await expect(
        f.service.prepareHumanAction(
          principal(f.secretary, "secretariat"),
          "finalize_minutes",
          finalizeInput
        )
      ).rejects.toThrow(/signature/u);
      await f.sign(f.memberB, p3);
      const finalized = await confirmSurfaceAction(
        f.service,
        f.secretary,
        "secretariat",
        "finalize_minutes",
        finalizeInput
      );
      expect(finalized.status).toBe("accepted");
      expect(
        (await pool.query("select state from minutes where id=$1", [f.minutes.minutesId])).rows
      ).toEqual([{ state: "finalized" }]);
      expect(await f.pending(f.memberB)).toEqual([]);
      expect.soft(await f.pending(f.memberA)).toEqual([]);
      const retired = await f.packageFeedRows(p2);
      expect(retired.map(({ id }) => id)).toEqual(history.map(({ id }) => id));
      expect
        .soft(
          retired.every(({ state, resolved_at }) => state !== "pending" && resolved_at !== null)
        )
        .toBe(true);
      expect(
        (
          await pool.query(
            "select id from minutes_resign_requirements where minutes_id=$1 and state='pending'",
            [f.minutes.minutesId]
          )
        ).rows
      ).toEqual([]);
      expect(
        (await pool.query("select id from minutes_signatures where package_id=$1", [p2])).rows
      ).toEqual([]);
    });
  }, 60_000);

  async function feedHistory(pool: Pool) {
    const history: Record<string, { id: string; bytes: string }[]> = {};
    for (const table of [
      "minutes",
      "minutes_versions",
      "minutes_signature_packages",
      "minutes_signatures",
      "minutes_resign_requirements",
      "notices",
      "pending_action_feed",
      "feed_tombstones",
      "consent_records",
      "audit_events"
    ] as const) {
      history[table] = (
        await pool.query<{ id: string; bytes: string }>(
          `select id,row_to_json(record)::text as bytes from ${table} record order by id`
        )
      ).rows;
    }
    history["minutes_signature_requirements"] = (
      await pool.query<{ id: string; bytes: string }>(
        `select package_id::text||':'||member_id::text as id,row_to_json(record)::text as bytes
         from minutes_signature_requirements record order by package_id,member_id`
      )
    ).rows;
    return history;
  }

  it("keeps ordinary minutes lifecycle feeds consistent with their persisted audit evidence", async () => {
    const { inspectFeedConsistencyInTransaction } = await import("../../lib/db/src/index.js");
    await withDatabase(async (pool) => {
      const f = await fixture(pool);
      const observations: {
        readonly phase: string;
        readonly result: Awaited<ReturnType<typeof inspectFeedConsistencyInTransaction>>;
      }[] = [];
      const inspect = async (phase: string) => {
        const result = await withWorkerTransaction(
          pool,
          (client) => inspectFeedConsistencyInTransaction(client, f.secretary.organizationId),
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        );
        observations.push({ phase, result });
        const stored = await pool.query<{ feeds: number; tombstones: number }>(
          `select (select count(*)::int from pending_action_feed where organization_id=$1) as feeds,
                  (select count(*)::int from feed_tombstones where organization_id=$1) as tombstones`,
          [f.secretary.organizationId]
        );
        expect(result.checkedFeedRows).toBe(stored.rows[0]!.feeds);
        expect(result.checkedTombstoneRows).toBe(stored.rows[0]!.tombstones);
        expect(result.checkedFeedRows).toBeGreaterThan(0);
        expect(result.evidenceSha256).toMatch(/^[0-9a-f]{64}$/u);
      };
      await inspect("published");
      const p1 = await f.issue();
      await inspect("first package issued");
      await f.sign(f.memberA, p1);
      await inspect("first package signed");
      await f.correct();
      await inspect("corrected package in review");
      const p2 = await f.issue();
      await inspect("replacement package issued");
      await f.sign(f.memberA, p2);
      await inspect("replacement package signed");
      const finalized = await confirmSurfaceAction(
        f.service,
        f.secretary,
        "secretariat",
        "finalize_minutes",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: f.minutes.minutesId,
          package_id: p2,
          idempotency_key: "minutes-feed-consistency-finalize"
        }
      );
      expect(finalized.status).toBe("accepted");
      await inspect("finalized");
      for (const { phase, result } of observations) {
        // Keep the entire content-safe inspector receipt in a failing reporter message.
        expect.soft(result, `${phase}: ${JSON.stringify(result)}`).toMatchObject({
          valid: true,
          payloadHashMismatches: 0,
          payloadCanonicalMismatches: 0,
          payloadBindingMismatches: 0,
          membershipStalePendingRows: 0,
          noticeBindingMismatches: 0,
          auditBindingMismatches: 0,
          tombstoneBindingMismatches: 0,
          duplicateRemovalTombstones: 0,
          relationMismatches: 0
        });
      }
    });
  }, 60_000);

  it("refuses malformed and foreign minutes audit bindings without altering history", async () => {
    await withDatabase(async (pool) => {
      const f = await fixture(pool);
      const p1 = await f.issue([f.memberA, f.memberB]);
      await f.sign(f.memberA, p1);
      await f.correct();
      const p2 = await f.issue([f.memberA, f.memberB]);
      const rows = (
        await pool.query<{
          id: string;
          member_id: string;
          audit_event_id: string;
          payload: Record<string, JsonValue>;
          audit_payload: Record<string, JsonValue>;
        }>(
          `select feed.id,feed.member_id,feed.audit_event_id,
                convert_from(feed.canonical_payload,'UTF8')::jsonb as payload,
                convert_from(audit.canonical_payload,'UTF8')::jsonb as audit_payload
           from pending_action_feed feed join audit_events audit on audit.id=feed.audit_event_id
          where convert_from(feed.canonical_payload,'UTF8')::jsonb->'safeRefs'->>'signaturePackageId'=$1
          order by feed.member_id`,
          [p2]
        )
      ).rows;
      expect(rows).toHaveLength(2);
      const a = rows.find((row) => row.member_id === f.memberA.memberId)!;
      const b = rows.find((row) => row.member_id === f.memberB.memberId)!;
      const encoded = (value: unknown) =>
        `\\x${Buffer.from(JSON.stringify(value)).toString("hex")}`;
      const refs = a.payload["safeRefs"] as Record<string, JsonValue>;
      const details = a.audit_payload["details"] as Record<string, JsonValue>;
      const cases: {
        name: string;
        feed: Record<string, unknown>;
        audit: Record<string, unknown>;
      }[] = [
        {
          name: "different package in the same lineage",
          feed: {
            canonical_payload: encoded({
              ...a.payload,
              safeRefs: { ...refs, signaturePackageId: p1 }
            })
          },
          audit: {}
        },
        {
          name: "wrong package hash",
          feed: {
            canonical_payload: encoded({
              ...a.payload,
              safeRefs: { ...refs, packageSha256: "00".repeat(32) }
            })
          },
          audit: {}
        },
        { name: "foreign organization", feed: { organization_id: testId(169_001) }, audit: {} },
        { name: "foreign board", feed: { board_id: testId(169_002) }, audit: {} },
        { name: "foreign minutes", feed: { object_id: testId(169_003) }, audit: {} },
        { name: "other configured recipient", feed: { member_id: f.memberB.memberId }, audit: {} },
        { name: "unconfigured recipient", feed: { member_id: f.secretary.memberId }, audit: {} },
        {
          name: "other recipient audit",
          feed: { audit_event_id: b.audit_event_id },
          audit: { id: b.audit_event_id, canonical_payload: encoded(b.audit_payload) }
        },
        {
          name: "wrong notice action",
          feed: { action_type: "minutes_review_requested" },
          audit: {}
        },
        {
          name: "wrong audit event",
          feed: {},
          audit: { event_type: "minutes_signature_package_issued" }
        },
        {
          name: "wrong audit notice type",
          feed: {},
          audit: {
            canonical_payload: encoded({
              ...a.audit_payload,
              details: { ...details, noticeType: "minutes_review_requested" }
            })
          }
        },
        {
          name: "missing safe references",
          feed: { canonical_payload: encoded({ ...a.payload, safeRefs: {} }) },
          audit: {}
        },
        { name: "null payload", feed: { canonical_payload: null }, audit: {} },
        { name: "malformed UTF8", feed: { canonical_payload: "\\xff" }, audit: {} },
        { name: "malformed JSON", feed: { canonical_payload: "\\x7b5d" }, audit: {} },
        { name: "malformed audit JSON", feed: {}, audit: { canonical_payload: "\\x7b5d" } },
        {
          name: "feed JSON numeric overflow",
          feed: { canonical_payload: `\\x${Buffer.from('{"number":1e1000000}').toString("hex")}` },
          audit: {}
        },
        {
          name: "audit JSON numeric overflow",
          feed: {},
          audit: { canonical_payload: `\\x${Buffer.from('{"number":1e1000000}').toString("hex")}` }
        },
        {
          name: "feed unsupported escaped Unicode",
          feed: { canonical_payload: `\\x${Buffer.from('{"text":"\\u0000"}').toString("hex")}` },
          audit: {}
        },
        {
          name: "audit unsupported escaped Unicode",
          feed: {},
          audit: { canonical_payload: `\\x${Buffer.from('{"text":"\\u0000"}').toString("hex")}` }
        }
      ];
      const history = await feedHistory(pool);
      const binding = async (feed: Record<string, unknown>, audit: Record<string, unknown>) =>
        (
          await pool.query<{ valid: boolean }>(
            `select public.boardagent_minutes_feed_audit_binding(
                    jsonb_populate_record(feed,$2::jsonb),jsonb_populate_record(audit,$3::jsonb)) as valid
             from pending_action_feed feed join audit_events audit on audit.id=feed.audit_event_id
            where feed.id=$1`,
            [a.id, JSON.stringify(feed), JSON.stringify(audit)]
          )
        ).rows[0]!.valid;
      expect(await binding({}, {})).toBe(true);
      for (const candidate of cases) {
        const observed = await binding(candidate.feed, candidate.audit).then(
          (valid) => ({ returned: true, valid }),
          (error: unknown) => ({
            returned: false,
            code: typeof error === "object" && error !== null && "code" in error ? error.code : null
          })
        );
        expect
          .soft(observed, `${candidate.name}: ${JSON.stringify(observed)}`)
          .toEqual({ returned: true, valid: false });
      }
      // Only transient composite arguments were changed; no persisted audit or feed was rewritten.
      expect(await feedHistory(pool)).toEqual(history);
      const { inspectFeedConsistencyInTransaction } = await import("../../lib/db/src/index.js");
      expect(
        await withWorkerTransaction(
          pool,
          (client) => inspectFeedConsistencyInTransaction(client, f.secretary.organizationId),
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        )
      ).toMatchObject({ valid: true, relationMismatches: 0 });
    });
  }, 60_000);

  it("reconciles a stale minutes recipient once and rejects unrelated removal evidence", async () => {
    const { inspectFeedConsistencyInTransaction, reconcileFeedEntitlementsInTransaction } =
      await import("../../lib/db/src/index.js");
    await withDatabase(async (pool) => {
      const f = await fixture(pool);
      const packageId = await f.issue([f.memberA, f.memberB]);
      const history = await feedHistory(pool);
      const reconcile = () =>
        withWorkerTransaction(
          pool,
          (client) =>
            reconcileFeedEntitlementsInTransaction(client, {
              organizationId: f.secretary.organizationId,
              boardId: f.secretary.boardId,
              memberId: f.memberA.memberId,
              newId: () => testId(169_100)
            }),
          { assumeRole: "boardagent_worker", isolation: "serializable" }
        );
      expect(await reconcile()).toEqual({ reconciled: 0, hasMore: false });
      expect(await feedHistory(pool)).toEqual(history);
      await pool.query(
        `update board_memberships set state='ended',active_until=transaction_timestamp(),entitlement_generation=entitlement_generation+1 where member_id=$1 and board_id=$2`,
        [f.memberA.memberId, f.secretary.boardId]
      );
      expect(await reconcile()).toEqual({ reconciled: 1, hasMore: false });
      expect(await reconcile()).toEqual({ reconciled: 0, hasMore: false });
      const inspector = () =>
        withWorkerTransaction(
          pool,
          (client) => inspectFeedConsistencyInTransaction(client, f.secretary.organizationId),
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        );
      expect(await inspector()).toMatchObject({
        valid: true,
        checkedTombstoneRows: 1,
        membershipStalePendingRows: 0,
        relationMismatches: 0
      });
      const reconciled = await feedHistory(pool);
      expect(reconciled["audit_events"]).toEqual(history["audit_events"]);
      expect(reconciled["notices"]).toEqual(history["notices"]);
      const otherAudit = (
        await pool.query<{ audit_event_id: string }>(
          `select audit_event_id from pending_action_feed where member_id=$1
          and convert_from(canonical_payload,'UTF8')::jsonb->'safeRefs'->>'signaturePackageId'=$2`,
          [f.memberB.memberId, packageId]
        )
      ).rows[0]!.audit_event_id;
      for (const kind of ["other audit", "missing feed", "wrong reason"] as const) {
        const rollback = new Error(`rollback minutes tombstone fixture: ${kind}`);
        await expect(
          withWorkerTransaction(pool, async (client) => {
            await client.query(
              `insert into feed_tombstones(id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id)
             select $2,source.organization_id,source.board_id,source.member_id,removed.entitlement_generation,source.feed_sequence,
                    case when $3='missing feed' then null else source.removed_feed_id end,
                    source.object_type,source.object_id,case when $3='wrong reason' then 'resolved' else source.reason_class end,
                    sha256(convert_to($3,'UTF8')),case when $3='other audit' then $4::uuid else source.audit_event_id end
               from feed_tombstones source join pending_action_feed removed on removed.id=source.removed_feed_id
              where source.id=$1`,
              [testId(169_100), testId(169_101), kind, otherAudit]
            );
            await client.query("set local role boardagent_worker");
            const result = await inspectFeedConsistencyInTransaction(
              client,
              f.secretary.organizationId
            );
            expect(result.valid, JSON.stringify({ kind, result })).toBe(false);
            expect(
              result.tombstoneBindingMismatches,
              JSON.stringify({ kind, result })
            ).toBeGreaterThan(0);
            throw rollback;
          })
        ).rejects.toBe(rollback);
        expect(await feedHistory(pool)).toEqual(reconciled);
      }
      expect(await inspector()).toMatchObject({ valid: true, relationMismatches: 0 });
    });
  }, 60_000);

  it("upgrades genuine schema161 minutes history without rewriting evidence or widening routine authority", async () => {
    const { copyFile, mkdtemp, readdir, readFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { inspectFeedConsistencyInTransaction } = await import("../../lib/db/src/index.js");
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-minutes-feed-upgrade-"));
    let admin: Pool | undefined;
    let pool: Pool | undefined;
    let database: string | undefined;
    try {
      const files = (await readdir(MIGRATIONS))
        .filter((name) => /^\d{4}_.+\.sql$/u.test(name) && Number(name.slice(0, 4)) <= 161)
        .sort();
      expect(files).toHaveLength(161);
      for (const file of files)
        await copyFile(path.join(MIGRATIONS, file), path.join(directory, file));
      databaseCounter += 1;
      database = `boardagent_minutes_upgrade_${String(process.pid)}_${String(databaseCounter)}`;
      const adminUrl = new URL(BASE_URL);
      adminUrl.pathname = "/postgres";
      admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
      await admin.query(`create database "${database}"`);
      const testUrl = new URL(BASE_URL);
      testUrl.pathname = `/${database}`;
      pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
      await migrate(pool, directory, "minutes-feed-upgrade161-base");
      const f = await fixture(pool);
      const p1 = await f.issue();
      await f.sign(f.memberA, p1);
      await f.correct();
      await f.issue();
      const inspect = () =>
        withWorkerTransaction(
          pool!,
          (client) => inspectFeedConsistencyInTransaction(client, f.secretary.organizationId),
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        );
      expect(await inspect()).toMatchObject({
        valid: false,
        auditBindingMismatches: 2,
        relationMismatches: 2
      });
      const before = await feedHistory(pool);
      const functionAuthority = () =>
        pool!.query(
          `select procedure.proname,pg_get_userbyid(procedure.proowner) as owner,procedure.proacl::text as acl,procedure.proconfig,procedure.prosecdef from pg_proc procedure join pg_namespace namespace on namespace.oid=procedure.pronamespace where namespace.nspname='public' and procedure.proname in ('boardagent_feed_reconcile_candidates','boardagent_commit_feed_revocation','boardagent_feed_consistency_relations') order by procedure.proname`
        );
      const authority = (await functionAuthority()).rows;
      expect(authority).toHaveLength(3);
      for (const routine of authority)
        expect(routine).toMatchObject({
          owner: "boardagent_migrator",
          proconfig: ["search_path=pg_catalog, public, pg_temp"],
          prosecdef: true
        });
      const ledgerBefore = (
        await pool.query("select to_jsonb(m) as row from schema_migrations m order by version")
      ).rows;
      expect(ledgerBefore).toHaveLength(161);
      const migrationName = "0162_minutes_feed_audit_bindings.sql";
      const migrationSha256 = sha256Hex(await readFile(path.join(MIGRATIONS, migrationName)));
      await copyFile(path.join(MIGRATIONS, migrationName), path.join(directory, migrationName));
      expect(await migrate(pool, directory, "minutes-feed-upgrade161-162")).toBe(1);
      expect((await functionAuthority()).rows).toEqual(authority);
      const helper = (
        await pool.query(`select pg_get_userbyid(p.proowner) as owner,p.prosecdef,p.proconfig,
        has_function_privilege('boardagent_server',p.oid,'execute') as server_execute,
        has_function_privilege('boardagent_worker',p.oid,'execute') as worker_execute,
        exists(select 1 from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl where acl.grantee=0 and acl.privilege_type='EXECUTE') as public_execute
        from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname='boardagent_minutes_feed_audit_binding'`)
      ).rows;
      expect(helper).toEqual([
        {
          owner: "boardagent_migrator",
          prosecdef: false,
          proconfig: ["search_path=pg_catalog, public, pg_temp"],
          server_execute: false,
          worker_execute: false,
          public_execute: false
        }
      ]);
      const after = await feedHistory(pool);
      const oldAuditIds = new Set(before["audit_events"]!.map(({ id }) => id));
      expect(after["audit_events"]!.filter(({ id }) => oldAuditIds.has(id))).toEqual(
        before["audit_events"]
      );
      expect(after["audit_events"]).toHaveLength(before["audit_events"]!.length + 1);
      expect(after).toEqual({ ...before, audit_events: after["audit_events"] });
      const migrationAudit = (
        await pool.query<{ payload: unknown; previous_hash: string; prior_hash: string }>(
          `select convert_from(a.canonical_payload,'UTF8')::jsonb as payload,
                encode(a.previous_event_sha256,'hex') as previous_hash,
                encode(previous.event_sha256,'hex') as prior_hash
           from audit_events a join audit_events previous on previous.sequence=a.sequence-1
          where a.event_type='migration_applied'`
        )
      ).rows;
      expect(migrationAudit).toHaveLength(1);
      expect(migrationAudit[0]!.previous_hash).toBe(migrationAudit[0]!.prior_hash);
      expect(migrationAudit[0]!.payload).toMatchObject({
        eventType: "migration_applied",
        entityType: "schema_migration",
        entityId: migrationName,
        origin: "migration",
        details: {
          version: 162,
          name: migrationName,
          sha256: migrationSha256,
          appBuild: "minutes-feed-upgrade161-162"
        }
      });
      const ledgerAfter = (
        await pool.query("select to_jsonb(m) as row from schema_migrations m order by version")
      ).rows;
      expect(ledgerAfter).toHaveLength(162);
      expect(ledgerAfter.slice(0, 161)).toEqual(ledgerBefore);
      expect(ledgerAfter[161]!.row).toMatchObject({
        version: 162,
        name: migrationName,
        sha256: migrationSha256,
        app_build: "minutes-feed-upgrade161-162"
      });
      expect(await inspect()).toMatchObject({
        valid: true,
        auditBindingMismatches: 0,
        relationMismatches: 0
      });
      expect(await migrate(pool, directory, "minutes-feed-upgrade-repeat")).toBe(0);
      expect(await feedHistory(pool)).toEqual(after);
      expect(
        (await pool.query("select to_jsonb(m) as row from schema_migrations m order by version"))
          .rows
      ).toEqual(ledgerAfter);
    } finally {
      try {
        await pool?.end();
      } finally {
        try {
          if (admin && database) await dropClosedTestDatabase(admin, database);
        } finally {
          await admin?.end();
          await rm(directory, { recursive: true, force: true });
        }
      }
    }
  }, 60_000);

  it("upgrades legacy superseded minutes feeds without changing current or unbound projections", async () => {
    const { copyFile, mkdtemp, readdir, readFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { inspectFeedConsistencyInTransaction } = await import("../../lib/db/src/index.js");
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-minutes-disposition-upgrade-"));
    let admin: Pool | undefined;
    let pool: Pool | undefined;
    let database: string | undefined;
    try {
      const files = (await readdir(MIGRATIONS))
        .filter((name) => /^\d{4}_.+\.sql$/u.test(name) && Number(name.slice(0, 4)) <= 161)
        .sort();
      expect(files).toHaveLength(161);
      for (const file of files)
        await copyFile(path.join(MIGRATIONS, file), path.join(directory, file));
      databaseCounter += 1;
      database = `boardagent_minutes_cleanup_${String(process.pid)}_${String(databaseCounter)}`;
      const adminUrl = new URL(BASE_URL);
      adminUrl.pathname = "/postgres";
      admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
      await admin.query(`create database "${database}"`);
      const testUrl = new URL(BASE_URL);
      testUrl.pathname = `/${database}`;
      pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
      await migrate(pool, directory, "minutes-cleanup-upgrade161-base");
      const f = await fixture(pool);
      const p1 = await f.issue();
      await f.sign(f.memberA, p1);
      await f.correct();
      const p2 = await f.issue();
      await f.correct();
      const p3 = await f.issue([f.memberB]);
      const obsoleteId = (await f.packageFeedRows(p2))[0]!.id;
      const currentId = (await f.packageFeedRows(p3))[0]!.id;
      // Existing-component legacy state seam: current runtime correctly retired P2.
      // Restore ONLY its mutable disposition to the state produced by the original
      // pre-fix correction runtime (before02), leaving canonical evidence untouched.
      const original = await feedHistory(pool);
      await pool.query(
        "update pending_action_feed set state='pending',resolved_at=null where id=$1",
        [obsoleteId]
      );
      const legacyPending = await f.pending(f.memberA);
      expect(legacyPending).toEqual([
        expect.objectContaining({
          action_type: "minutes_resign_required",
          payload: expect.objectContaining({
            safeRefs: expect.objectContaining({ signaturePackageId: p2 })
          })
        })
      ]);
      expect(
        (
          await pool.query(
            "select state from board_memberships where member_id=$1 and board_id=$2",
            [f.memberA.memberId, f.secretary.boardId]
          )
        ).rows
      ).toEqual([{ state: "active" }]);
      const legacy = await feedHistory(pool);
      expect(legacy).toEqual({ ...original, pending_action_feed: legacy["pending_action_feed"] });
      const originalFeed = JSON.parse(
        original["pending_action_feed"]!.find(({ id }) => id === obsoleteId)!.bytes
      ) as Record<string, unknown>;
      const legacyFeed = JSON.parse(
        legacy["pending_action_feed"]!.find(({ id }) => id === obsoleteId)!.bytes
      ) as Record<string, unknown>;
      expect(legacyFeed).toEqual({ ...originalFeed, state: "pending", resolved_at: null });
      await copyFile(
        path.join(MIGRATIONS, "0162_minutes_feed_audit_bindings.sql"),
        path.join(directory, "0162_minutes_feed_audit_bindings.sql")
      );
      expect(await migrate(pool, directory, "minutes-cleanup-upgrade162-only")).toBe(1);
      expect(await f.pending(f.memberA)).toEqual(legacyPending);
      expect(await f.packageFeedRows(p2)).toEqual([
        { id: obsoleteId, state: "pending", resolved_at: null }
      ]);
      expect(
        await withWorkerTransaction(
          pool,
          (client) => inspectFeedConsistencyInTransaction(client, f.secretary.organizationId),
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        )
      ).toMatchObject({ valid: true, relationMismatches: 0 });

      // A second real publication supplies unrelated pending review actions.
      const secondMeeting = testId(169_200);
      const secondMinutes = testId(169_201);
      const secondText = "# Minutes\nSynthetic second meeting remains in review.\n";
      await pool.query(
        `insert into meetings(id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by) values($1,$2,$3,'Separate review meeting','called',transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
        [secondMeeting, f.secretary.organizationId, f.secretary.boardId, f.secretary.memberId]
      );
      const secondDraft = await f.service.executeDirect(
        principal(f.secretary, "secretariat"),
        "create_minutes_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: secondMinutes,
          meeting_id: secondMeeting,
          canonical_text: secondText,
          transcript_version_id: null,
          expected_current_version_id: null,
          idempotency_key: "minutes-cleanup-unrelated-draft"
        }
      );
      expect(secondDraft.status).toBe("accepted");
      expect(secondDraft.reference).toBeTruthy();
      await confirmSurfaceAction(f.service, f.secretary, "secretariat", "publish_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: secondMinutes,
        version_id: secondDraft.reference!,
        minutes_sha256: sha256Hex(secondText),
        signer_member_ids: [f.memberA.memberId, f.memberB.memberId],
        idempotency_key: "minutes-cleanup-unrelated-publish"
      });
      const unrelated = (
        await pool.query<{ id: string; notice_id: string }>(
          "select id,notice_id from pending_action_feed where object_id=$1 and state='pending' order by id",
          [secondMinutes]
        )
      ).rows;
      expect(unrelated).toHaveLength(2);

      // Permissible stored corruption controls, newly inserted in this disposable DB.
      // Distinct synthetic generations avoid the feed uniqueness constraint without
      // rewriting any existing canonical row. They are intentionally inconsistent and
      // are not represented as ordinary user-created feed history or valid inspection.
      const badIds: string[] = [];
      for (const [index, kind] of [
        "missing references",
        "malformed UTF8",
        "wrong payload hash",
        "wrong notice"
      ].entries()) {
        const id = testId(169_210 + index);
        badIds.push(id);
        await pool.query(
          `insert into pending_action_feed(
          id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,action_type,object_type,object_id,object_version,visibility_sha256,canonical_payload,payload_sha256,state,notice_id,audit_event_id)
          select $2,organization_id,board_id,member_id,entitlement_generation+$3,feed_sequence,action_type,object_type,object_id,object_version,visibility_sha256,
            case when $4='missing references' then convert_to('{}','UTF8') when $4='malformed UTF8' then decode('ffff','hex') else canonical_payload end,
            case when $4='missing references' then sha256(convert_to('{}','UTF8')) when $4='malformed UTF8' then sha256(decode('ffff','hex')) when $4='wrong payload hash' then decode(repeat('00',32),'hex') else payload_sha256 end,
            'pending',case when $4='wrong notice' then $5::uuid else notice_id end,audit_event_id
          from pending_action_feed where id=$1`,
          [obsoleteId, id, index + 10, kind, unrelated[0]!.notice_id]
        );
      }
      const authority = async () => ({
        policies: (
          await pool!.query(
            "select to_jsonb(p)::text as bytes from pg_policies p where schemaname='public' order by tablename,policyname"
          )
        ).rows,
        tables: (
          await pool!.query(
            "select c.relname,pg_get_userbyid(c.relowner) as owner,c.relacl::text as acl,c.relrowsecurity,c.relforcerowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind in ('r','p') order by c.relname"
          )
        ).rows,
        routines: (
          await pool!.query(
            "select p.proname,pg_get_function_identity_arguments(p.oid) as arguments,pg_get_userbyid(p.proowner) as owner,p.proacl::text as acl,p.prosecdef,p.proconfig from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' order by p.proname,arguments"
          )
        ).rows
      });
      const projectionSync = async () => ({
        positions: (
          await pool!.query(
            "select to_jsonb(p) as row from member_feed_sync_positions p order by entry_kind,entry_id"
          )
        ).rows,
        counters: (
          await pool!.query(
            "select to_jsonb(c) as row from member_feed_sync_counters c order by organization_id,member_id"
          )
        ).rows
      });
      const before = await feedHistory(pool);
      const beforeAuthority = await authority();
      const beforeSync = await projectionSync();
      const ledgerBefore = (
        await pool.query("select to_jsonb(m) as row from schema_migrations m order by version")
      ).rows;
      expect(ledgerBefore).toHaveLength(162);
      const migrationName = "0163_superseded_minutes_feed_dispositions.sql";
      const migrationSql = await readFile(path.join(MIGRATIONS, migrationName), "utf8");
      const migrationSha256 = sha256Hex(migrationSql);
      await copyFile(path.join(MIGRATIONS, migrationName), path.join(directory, migrationName));
      expect(await migrate(pool, directory, "minutes-cleanup-upgrade163")).toBe(1);
      const after = await feedHistory(pool);
      const oldAuditIds = new Set(before["audit_events"]!.map(({ id }) => id));
      expect(after["audit_events"]!.filter(({ id }) => oldAuditIds.has(id))).toEqual(
        before["audit_events"]
      );
      expect(after["audit_events"]).toHaveLength(before["audit_events"]!.length + 1);
      expect(after).toEqual({
        ...before,
        pending_action_feed: after["pending_action_feed"],
        audit_events: after["audit_events"]
      });
      expect(after["pending_action_feed"]!.map(({ id }) => id)).toEqual(
        before["pending_action_feed"]!.map(({ id }) => id)
      );
      for (const row of before["pending_action_feed"]!) {
        const result = after["pending_action_feed"]!.find(({ id }) => id === row.id)!;
        if (row.id !== obsoleteId) expect(result).toEqual(row);
        else {
          const changed = JSON.parse(result.bytes) as Record<string, unknown>;
          expect(changed["resolved_at"]).toEqual(expect.any(String));
          expect(changed).toEqual({
            ...JSON.parse(row.bytes),
            state: "superseded",
            resolved_at: changed["resolved_at"]
          });
        }
      }
      expect(
        (
          await pool.query(
            "select id,state from pending_action_feed where id=any($1::uuid[]) order by id",
            [[currentId, ...unrelated.map(({ id }) => id), ...badIds]]
          )
        ).rows
      ).toEqual(
        [currentId, ...unrelated.map(({ id }) => id), ...badIds]
          .sort()
          .map((id) => ({ id, state: "pending" }))
      );
      expect(await authority()).toEqual(beforeAuthority);
      const afterSync = await projectionSync();
      expect(afterSync.positions).toHaveLength(beforeSync.positions.length);
      const counterBefore = beforeSync.counters.find(
        ({ row }) => row.member_id === f.memberA.memberId
      )!.row;
      const expectedSequence = counterBefore.last_sequence + 1;
      expect(afterSync.counters).toEqual(
        beforeSync.counters.map(({ row }) => ({
          row:
            row.member_id === f.memberA.memberId ? { ...row, last_sequence: expectedSequence } : row
        }))
      );
      expect(afterSync.positions).toEqual(
        beforeSync.positions.map(({ row }) => ({
          row: row.feed_id === obsoleteId ? { ...row, change_sequence: expectedSequence } : row
        }))
      );
      const ledgerAfter = (
        await pool.query("select to_jsonb(m) as row from schema_migrations m order by version")
      ).rows;
      expect(ledgerAfter.slice(0, 162)).toEqual(ledgerBefore);
      expect(ledgerAfter).toHaveLength(163);
      expect(ledgerAfter[162]!.row).toMatchObject({
        version: 163,
        name: migrationName,
        sha256: migrationSha256,
        app_build: "minutes-cleanup-upgrade163"
      });
      const migrationAudit = (
        await pool.query<{ payload: unknown; previous_hash: string; prior_hash: string }>(
          `select convert_from(a.canonical_payload,'UTF8')::jsonb as payload,encode(a.previous_event_sha256,'hex') as previous_hash,encode(previous.event_sha256,'hex') as prior_hash from audit_events a join audit_events previous on previous.sequence=a.sequence-1 where a.event_type='migration_applied' and convert_from(a.canonical_payload,'UTF8')::jsonb->>'entityId'=$1`,
          [migrationName]
        )
      ).rows;
      expect(migrationAudit).toHaveLength(1);
      expect(migrationAudit[0]!.previous_hash).toBe(migrationAudit[0]!.prior_hash);
      expect(migrationAudit[0]!.payload).toMatchObject({
        eventType: "migration_applied",
        entityType: "schema_migration",
        entityId: migrationName,
        origin: "migration",
        details: {
          version: 163,
          name: migrationName,
          sha256: migrationSha256,
          appBuild: "minutes-cleanup-upgrade163"
        }
      });
      expect(await migrate(pool, directory, "minutes-cleanup-repeat")).toBe(0);
      expect(await feedHistory(pool)).toEqual(after);
      expect(await projectionSync()).toEqual(afterSync);
      expect(
        (await pool.query("select to_jsonb(m) as row from schema_migrations m order by version"))
          .rows
      ).toEqual(ledgerAfter);
      // Re-execute the idempotent data statement in the same managed role/scope.
      // This is a dedicated disposable DB, not a historical failed evidence fixture.
      await withWorkerTransaction(pool, async (client) => {
        await client.query("set local role boardagent_migrator");
        await client.query(migrationSql);
      });
      expect(await feedHistory(pool)).toEqual(after);
      expect(await projectionSync()).toEqual(afterSync);
      expect(await authority()).toEqual(beforeAuthority);
      expect(
        (await pool.query("select to_jsonb(m) as row from schema_migrations m order by version"))
          .rows
      ).toEqual(ledgerAfter);
    } finally {
      try {
        await pool?.end();
      } finally {
        try {
          if (admin && database) await dropClosedTestDatabase(admin, database);
        } finally {
          await admin?.end();
          await rm(directory, { recursive: true, force: true });
        }
      }
    }
  }, 60_000);
});
