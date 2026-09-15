import path from "node:path";
import { withDirectResponseAllocation } from "../helpers/direct-response-allocation.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

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
  canonicalJson,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  migrate,
  recordExportArtifactDeletionInTransaction,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import {
  seedAuthorizedActor,
  testHash,
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
  const database = `boardagent_surface_export_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  let passed = false;
  try {
    await migrate(pool, MIGRATIONS, "surface-export-lifecycle-test");
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

function principal(actor: AuthorizedActorFixture): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://export-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: ["audit:read", "secretariat:admin"],
    roles: ["admin", "secretariat"],
    boardIds: [actor.boardId]
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by export lifecycle test");
  },
  readResource: async () => {
    throw new Error("resource read not used by export lifecycle test");
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
  const label = `surface-export-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const prepared = await service.prepareHumanAction(actor, tool, input);
  expect(prepared).toMatchObject({ action_code: tool, target_type: "export_request" });
  expect(prepared.package_sha256).toMatch(/^[0-9a-f]{64}$/u);
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

async function seedAdmin(pool: Pool): Promise<AuthorizedActorFixture> {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["audit:read", "secretariat:admin"],
    isSecretary: true
  });
  await pool.query(
    `insert into organization_role_assignments(
       id,organization_id,member_id,role,change_reason
     ) values ($1,$2,$3,'admin','Export integration authority')`,
    [testId(180_000), actor.organizationId, actor.memberId]
  );
  const sessionId = testId(180_001);
  await pool.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
               transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
    [sessionId, actor.organizationId, testHash(180), actor.memberId, actor.clientId]
  );
  await pool.query("update access_token_records set session_id=$1 where id=$2", [
    sessionId,
    actor.accessTokenRecordId
  ]);
  await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      appendAuditEventsInTransaction(client, [
        {
          organizationId: actor.organizationId,
          event: {
            eventId: testId(180_002),
            eventType: "context_read",
            actorMemberId: actor.memberId,
            actorClientId: actor.clientId,
            tokenJti: actor.tokenJti,
            entityType: "context",
            entityId: testId(180_003),
            boardId: actor.boardId,
            origin: "mcp",
            details: { result: "authorized" },
            schemaVersion: 1
          }
        }
      ]),
    { assumeRole: "boardagent_server" }
  );
  return actor;
}

describe("confirmed export lifecycle surface", () => {
  it("prepares exact export chunk evidence and refuses an unauditable chunk", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAdmin(pool);
      let nextId = 184_000;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++),
        entropy: (length) => Buffer.alloc(length, 0x59)
      });
      const caller = principal(actor);
      const queued = await confirm(surface, caller, "export_system_data", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "export-read-evidence-0001",
        board_id: null,
        scope: "organization",
        purpose: "Synthetic read evidence fixture.",
        recent_auth_proof: Buffer.alloc(32, 3).toString("base64url")
      });
      const data = queued.data as Record<string, JsonValue>;
      const requestId = String(data["request_id"]);
      const exportId = String(data["export_id"]);
      const artifactId = testId(184_800);
      const keyId = testId(184_801);
      const bytes = Buffer.from([0, 1, 127, 128, 255, 12]);
      await pool.query(
        `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,nonsecret_locator,activated_at)
        values ($1,$2,'synthetic-read-data-key','data_kek','A256GCM','synthetic-read-key',transaction_timestamp()-interval '1 minute')`,
        [keyId, actor.organizationId]
      );
      await pool.query(
        "update export_requests set state='running',snapshot_manifest='{}',snapshot_sha256=$2,started_at=transaction_timestamp(),row_version=row_version+1 where id=$1",
        [requestId, testHash(184)]
      );
      const manifest = Buffer.from(
        canonicalJson({
          schemaVersion: "boardagent.export-artifact.v1",
          artifactId,
          exportRequestId: requestId,
          scopeSha256: String(data["scope_sha256"]),
          snapshotSha256: testHash(184).toString("hex"),
          encryptedContentSetSha256: sha256Hex(bytes),
          encryptedStorageLocator: "synthetic-export-artifact",
          encryptionKeyId: keyId,
          byteLength: String(bytes.byteLength)
        }),
        "utf8"
      );
      await pool.query(
        `insert into export_artifacts(id,export_request_id,manifest,manifest_sha256,content_set_sha256,encrypted_storage_locator,encryption_key_id,byte_length,state)
        values ($1,$2,$3,$4,$5,'synthetic-export-artifact',$6,$7,'ready')`,
        [
          artifactId,
          requestId,
          manifest,
          Buffer.from(sha256Hex(manifest), "hex"),
          Buffer.from(sha256Hex(bytes), "hex"),
          keyId,
          bytes.byteLength
        ]
      );
      await pool.query(
        `insert into export_chunks(id,artifact_id,ordinal,byte_offset,byte_length,chunk_sha256,storage_locator)
        values ($1,$2,0,0,$3,$4,'synthetic-chunk-zero')`,
        [testId(184_802), artifactId, bytes.byteLength, Buffer.from(sha256Hex(bytes), "hex")]
      );
      await pool.query(
        "update export_requests set state='succeeded',completed_at=transaction_timestamp(),row_version=row_version+1 where id=$1",
        [requestId]
      );
      const reader = new PgSurfaceReadRepository(pool, {
        cursorKey: Buffer.alloc(32, 0x59),
        transaction: { assumeRole: "boardagent_server" },
        exportChunks: { readExactChunk: async () => bytes }
      });
      const readCaller = {
        ...caller,
        protocolClientId: "authorized-test-client",
        roles: ["admin", "member", "secretariat"]
      };
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        export_id: exportId,
        chunk_no: 0,
        recent_auth_proof: Buffer.alloc(32, 3).toString("base64url")
      };
      const read = await withDirectResponseAllocation(() =>
        reader.executeRead(readCaller, "read_export_chunk", input)
      );
      expect(read.data).toMatchObject({
        bytes: bytes.toString("base64url"),
        encoding: "base64url",
        sha256: sha256Hex(bytes)
      });
      const events = await pool.query<{ body: unknown }>(
        "select convert_from(canonical_payload,'UTF8')::jsonb as body from audit_events where event_type='resource_fetch'"
      );
      expect(events.rows).toHaveLength(1);
      expect(events.rows[0]?.body).toMatchObject({
        actorMemberId: actor.memberId,
        actorClientId: actor.clientId,
        tokenJti: actor.tokenJti,
        entityType: "export_chunk",
        entityId: requestId,
        boardId: null,
        details: {
          phase: "prepared",
          resourceUri: `export://${exportId}/chunks/0`,
          representation: "application/octet-stream",
          sha256: sha256Hex(bytes),
          byteLength: bytes.byteLength,
          requestOrigin: caller.serviceOrigin
        }
      });
      await pool.query(`create function reject_export_fetch_audit() returns trigger language plpgsql as $$ begin
        if new.event_type='resource_fetch' then raise exception 'synthetic export audit unavailable'; end if;
        return new; end $$; create trigger reject_export_fetch_audit before insert on audit_events for each row execute function reject_export_fetch_audit()`);
      await expect(
        withDirectResponseAllocation(() =>
          reader.executeRead(readCaller, "read_export_chunk", input)
        )
      ).rejects.toThrow("synthetic export audit unavailable");
      expect(
        await pool.query("select id from audit_events where event_type='resource_fetch'")
      ).toMatchObject({ rowCount: 1 });
    });
  });

  it("queues both frozen export types, cancels one, and deletes one only through verified cleanup", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAdmin(pool);
      let nextId = 181_000;
      let entropyByte = 91;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++),
        entropy: (length) => Buffer.alloc(length, entropyByte++)
      });
      const caller = principal(actor);
      const auditRequest = await confirm(surface, caller, "export_audit_chain", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-export-audit-0001",
        board_id: actor.boardId,
        from_sequence: "1",
        to_sequence: null,
        recent_auth_proof: Buffer.alloc(32, 1).toString("base64url")
      });
      expect(auditRequest.data).toMatchObject({ state: "queued" });
      const auditExportId = String((auditRequest.data as Record<string, JsonValue>)["export_id"]);
      const cancelled = await confirm(surface, caller, "cancel_export", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-export-cancel-0001",
        export_id: auditExportId
      });
      expect(cancelled.data).toMatchObject({ state: "cancelled", cleanup_job_id: null });

      const systemRequest = await confirm(surface, caller, "export_system_data", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-export-system-0001",
        board_id: null,
        scope: "organization",
        purpose: "Create an encrypted administrative portability package.",
        recent_auth_proof: Buffer.alloc(32, 2).toString("base64url")
      });
      expect(systemRequest.data).toMatchObject({ state: "queued" });
      const systemData = systemRequest.data as Record<string, JsonValue>;
      const systemExportId = String(systemData["export_id"]);
      const systemRequestId = String(systemData["request_id"]);
      const encryptionKeyId = testId(181_900);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,nonsecret_locator,activated_at
         ) values ($1,$2,'surface-export-data-key','data_kek','A256GCM',
                   'local-surface-export-key',transaction_timestamp()-interval '1 minute')`,
        [encryptionKeyId, actor.organizationId]
      );
      await pool.query(
        `update export_requests
            set state='running',snapshot_manifest='{}',snapshot_sha256=$2,
                started_at=transaction_timestamp(),row_version=row_version+1
          where id=$1 and state='queued'`,
        [systemRequestId, testHash(181)]
      );
      const artifactId = testId(181_901);
      const contentSetSha256 = testHash(183);
      const artifactManifest = Buffer.from(
        JSON.stringify({
          schemaVersion: "boardagent.export-artifact.v1",
          artifactId,
          exportRequestId: systemRequestId,
          scopeSha256: String(systemData["scope_sha256"]),
          snapshotSha256: testHash(181).toString("hex"),
          encryptedContentSetSha256: contentSetSha256.toString("hex"),
          encryptedStorageLocator: "encrypted://surface-export/artifact",
          encryptionKeyId,
          byteLength: "0"
        }),
        "utf8"
      );
      await pool.query(
        `insert into export_artifacts(
           id,export_request_id,manifest,manifest_sha256,content_set_sha256,
           encrypted_storage_locator,encryption_key_id,byte_length,state
         ) values ($1,$2,$3,$4,$5,'encrypted://surface-export/artifact',$6,0,'ready')`,
        [
          artifactId,
          systemRequestId,
          artifactManifest,
          testHash(182),
          contentSetSha256,
          encryptionKeyId
        ]
      );
      await pool.query(
        `update export_requests
            set state='succeeded',completed_at=transaction_timestamp(),row_version=row_version+1
          where id=$1 and state='running'`,
        [systemRequestId]
      );
      const deletion = await confirm(surface, caller, "delete_export_artifact", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-export-delete-0001",
        export_id: systemExportId
      });
      expect(deletion.data).toMatchObject({ state: "deletion_queued" });
      expect((deletion.data as Record<string, JsonValue>)["cleanup_job_id"]).toEqual(
        expect.any(String)
      );

      await withWorkerTransaction(
        pool,
        (client) =>
          recordExportArtifactDeletionInTransaction(client, {
            exportRequestId: systemRequestId,
            storageDeletionVerified: true,
            exportArtifactDeletedAuditEventId: testId(181_902)
          }),
        { assumeRole: "boardagent_worker" }
      );
      const proof = await pool.query<{
        artifact_state: string;
        cancel_events: string;
        delete_events: string;
        request_state: string;
      }>(
        `select
          (select state from export_requests where id=$1) as request_state,
          (select state from export_artifacts where id=$2) as artifact_state,
          (select count(*)::text from audit_events where event_type='export_cancelled') as cancel_events,
          (select count(*)::text from audit_events where event_type='export_artifact_deleted') as delete_events`,
        [systemRequestId, artifactId]
      );
      expect(proof.rows[0]).toEqual({
        request_state: "deleted",
        artifact_state: "deleted",
        cancel_events: "1",
        delete_events: "1"
      });
    });
  });
});
