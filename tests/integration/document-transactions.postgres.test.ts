import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { canonicalJson, sha256Hex } from "../../lib/contracts/src/index.js";
import {
  DocumentValidationError,
  prepareDocumentContribution
} from "../../lib/domain/src/index.js";
import {
  contributeDocumentVersionInTransaction,
  fetchDocumentVersionInTransaction,
  migrate,
  recordDocumentValidationRejectionInTransaction,
  recordResourceFetchOutcomeInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
const hash = (byte: number): Buffer => Buffer.alloc(32, byte);
const boardPack = (answer: number) => ({
  schemaVersion: "boardagent.board-pack.v1",
  title: "Board pack",
  sections: [{ heading: "Answer", body: String(answer) }]
});
const boardPackBody = (answer: number): string => canonicalJson(boardPack(answer));

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_documents_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "document-transactions-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedAuthorizedContributor(pool: Pool): Promise<{
  boardId: string;
  clientId: string;
  context: {
    organizationId: string;
    memberId: string;
    clientId: string;
    tokenJti: string;
    boardIds: string[];
  };
  memberId: string;
  organizationId: string;
  consentRecordId: string;
  supportVersionId: string;
  tokenJti: string;
}> {
  const organizationId = id(1);
  const boardId = id(2);
  const memberId = id(3);
  const membershipId = id(4);
  const supportVersionId = id(5);
  const termsVersionId = id(6);
  const clientId = id(7);
  const signingKeyId = id(8);
  const accessTokenRecordId = id(9);
  const stageId = id(10);
  const inputRequiredAttemptId = id(11);
  const consentRecordId = id(12);
  const attestationId = id(13);
  const tokenJti = id(14);

  await pool.query(
    "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
    [organizationId]
  );
  await pool.query(
    "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Contributor','Contributor','active')",
    [memberId, organizationId]
  );
  await pool.query(
    "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'board','Board','UTC')",
    [boardId, organizationId]
  );
  await pool.query(
    "insert into system_instance(instance_id,organization_id,canonical_resource_uri) values ($1,$2,'https://boardagent.test/mcp')",
    [id(15), organizationId]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'management',false,0,'active')`,
    [membershipId, organizationId, boardId, memberId]
  );
  await pool.query(
    `insert into secretary_support_versions(
       id,organization_id,board_id,version,support_name,contact_methods,canonical_sha256,
       effective_at,created_by
     ) values ($1,$2,$3,1,'Board secretary','[]',$4,
       transaction_timestamp() - interval '1 minute',$5)`,
    [supportVersionId, organizationId, boardId, hash(1), memberId]
  );
  await pool.query(
    `insert into onboarding_terms_versions(
       id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
       material_change,effective_at,created_by
     ) values ($1,$2,'management',1,'boardagent.onboarding-terms.v1','Terms',$3,true,
       transaction_timestamp() - interval '1 minute',$4)`,
    [termsVersionId, organizationId, hash(2), memberId]
  );
  await pool.query(
    `insert into oauth_clients(
       id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,
       state,registered_by
     ) values ($1,$2,'preregistered','document-test-client','{}',$3,'active',$4)`,
    [clientId, organizationId, hash(3), memberId]
  );
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,'test-oauth','oauth_signing','ES256','{}','local-test-key',
       transaction_timestamp() - interval '1 minute')`,
    [signingKeyId, organizationId]
  );
  await pool.query(
    `insert into access_token_records(
       id,organization_id,jti,member_id,client_id,resource_uri,scope_set,signing_key_id,
       expires_at
     ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',
       array['documents:contribute','documents:read'],$6,
       transaction_timestamp() + interval '10 minutes')`,
    [accessTokenRecordId, organizationId, tokenJti, memberId, clientId, signingKeyId]
  );
  await pool.query(
    `insert into action_stages(
       id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
       canonical_schema,canonicalization_version,canonical_payload,payload_sha256,
       nonce_sha256,protected_code_sha256,client_id,access_token_record_id,token_jti,
       exact_origin,context_sha256,expires_at
     ) values (
       $1,$2,$3,$4,'prepare_onboarding_attestation','member',$4,
       'boardagent.onboarding-attestation.v1','RFC8785+NFC-LF-v1',$5,$6,$7,$8,$9,$10,$11,
       'https://client.example',$12,transaction_timestamp() + interval '10 minutes'
     )`,
    [
      stageId,
      organizationId,
      boardId,
      memberId,
      Buffer.from("{}"),
      hash(4),
      hash(5),
      hash(6),
      clientId,
      accessTokenRecordId,
      tokenJti,
      hash(7)
    ]
  );
  await pool.query(
    `insert into input_required_attempts(
       id,organization_id,stage_id,protocol_version,protocol_header_version,
       result_meta_version,original_method,original_name,original_arguments_sha256,
       capabilities_sha256,embedded_form_sha256,embedded_result_sha256,request_state_bytes,
       request_state_sha256,prepared_request_id
     ) values (
       $1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call',
       'prepare_onboarding_attestation',$4,$5,$6,$7,$8,$9,$10
     )`,
    [
      inputRequiredAttemptId,
      organizationId,
      stageId,
      hash(8),
      hash(9),
      hash(10),
      hash(11),
      Buffer.alloc(32, 12),
      hash(12),
      Buffer.from("request-1")
    ]
  );
  await pool.query(
    `insert into consent_records(
       id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
       action_code,target_type,target_id,canonical_schema,payload_sha256,
       protected_code_record_sha256,access_token_record_id,token_jti,client_id,exact_origin,
       staged_at,record_sha256
     ) values (
       $1,$2,$3,$4,$5,$6,'prepare_onboarding_attestation','member',$6,
       'boardagent.consent-record.v1',$7,$8,$9,$10,$11,'https://client.example',
       transaction_timestamp(),$12
     )`,
    [
      consentRecordId,
      organizationId,
      boardId,
      stageId,
      inputRequiredAttemptId,
      memberId,
      hash(13),
      hash(14),
      accessTokenRecordId,
      tokenJti,
      clientId,
      hash(15)
    ]
  );
  await pool.query(
    `insert into onboarding_attestations(
       id,organization_id,member_id,board_id,terms_version_id,support_version_id,
       presentation_choice,local_memory_choice,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,'structured','local-only',$7)`,
    [
      attestationId,
      organizationId,
      memberId,
      boardId,
      termsVersionId,
      supportVersionId,
      consentRecordId
    ]
  );

  return {
    organizationId,
    boardId,
    memberId,
    clientId,
    consentRecordId,
    supportVersionId,
    tokenJti,
    context: { organizationId, memberId, clientId, tokenJti, boardIds: [boardId] }
  };
}

describe("canonical document contribution and audited fetch transactions", () => {
  it("commits exact bytes once, replays safely, and denies unaudited or unentitled fetches", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedContributor(pool);
      const documentId = id(20);
      const prepared = prepareDocumentContribution({
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        documentId,
        title: "Board pack",
        mediaType: "application/json",
        documentSchema: "boardagent.board-pack.v1",
        body: Buffer.from(JSON.stringify(boardPack(42), null, 2))
      });

      const created = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          contributeDocumentVersionInTransaction(client, {
            prepared,
            documentVersionId: id(21),
            validationAttemptId: id(22),
            auditEventId: id(23),
            idempotencyRecordId: id(24),
            idempotencyKey: "document-create-0001",
            offeredName: "board-pack.json"
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(created).toMatchObject({
        replayed: false,
        documentId,
        documentVersionId: id(21),
        version: 1,
        sha256: prepared.sha256
      });

      const replayed = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          contributeDocumentVersionInTransaction(client, {
            prepared,
            documentVersionId: id(25),
            validationAttemptId: id(26),
            auditEventId: id(27),
            idempotencyRecordId: id(28),
            idempotencyKey: "document-create-0001",
            offeredName: "board-pack.json"
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(replayed).toMatchObject({ replayed: true, documentVersionId: id(21) });

      const conflicting = prepareDocumentContribution({
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        documentId,
        title: "Board pack",
        mediaType: "application/json",
        documentSchema: "boardagent.board-pack.v1",
        body: Buffer.from(boardPackBody(43))
      });
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            contributeDocumentVersionInTransaction(client, {
              prepared: conflicting,
              documentVersionId: id(29),
              validationAttemptId: id(30),
              auditEventId: id(31),
              idempotencyRecordId: id(32),
              idempotencyKey: "document-create-0001",
              offeredName: "board-pack.json"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("idempotency key was already used for a different request");

      const stored = await pool.query<{
        canonical_bytes: Buffer;
        current_version_id: string;
        search_text: string;
        version_count: string;
      }>(
        `select d.current_version_id,
                v.canonical_bytes,
                s.search_text,
                (select count(*)::text from document_versions where document_id = d.id) as version_count
           from documents d
           join document_versions v on v.id = d.current_version_id
           join document_search s on s.document_id = d.id
          where d.id = $1`,
        [documentId]
      );
      expect(stored.rows[0]).toMatchObject({
        current_version_id: id(21),
        search_text: boardPackBody(42),
        version_count: "1"
      });
      expect(stored.rows[0]?.canonical_bytes.equals(Buffer.from(boardPackBody(42)))).toBe(true);

      const fetched = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          fetchDocumentVersionInTransaction(client, {
            organizationId: actor.organizationId,
            boardId: actor.boardId,
            documentId,
            version: 1,
            auditEventId: id(33),
            requestOrigin: "https://client.example"
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(fetched.canonicalBytes.equals(Buffer.from(boardPackBody(42)))).toBe(true);
      expect(fetched.preparedEvent.sequence).toBe(2n);

      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            fetchDocumentVersionInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              documentId,
              version: 1,
              auditEventId: id(33),
              requestOrigin: "https://client.example"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();

      const completed = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          recordResourceFetchOutcomeInTransaction(client, {
            preparedEventId: fetched.preparedEvent.eventId,
            outcomeEventId: id(34),
            outcome: "completed",
            bytesTransferred: fetched.byteLength
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(completed.eventType).toBe("resource_fetch");
      expect(completed.details).toMatchObject({ phase: "completed" });

      await pool.query(
        "update access_token_records set scope_set = array['documents:contribute'] where jti = $1",
        [actor.tokenJti]
      );
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            fetchDocumentVersionInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              documentId,
              version: 1,
              auditEventId: id(35),
              requestOrigin: "https://client.example"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("document version is unavailable");
      await pool.query(
        "update access_token_records set scope_set = array['documents:contribute','documents:read'] where jti = $1",
        [actor.tokenJti]
      );
      await pool.query(
        `insert into document_exclusions(
           id,organization_id,board_id,document_id,member_id,version,reason,created_by
         ) values ($1,$2,$3,$4,$5,1,'live recusal',$5)`,
        [id(36), actor.organizationId, actor.boardId, documentId, actor.memberId]
      );
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            fetchDocumentVersionInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              documentId,
              version: 1,
              auditEventId: id(37),
              requestOrigin: "https://client.example"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("document version is unavailable");
    });
  });

  it("serializes competing versions and rolls the entire contribution back at a crash point", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedContributor(pool);
      const documentId = id(40);
      const prepared = (answer: number) =>
        prepareDocumentContribution({
          organizationId: actor.organizationId,
          boardId: actor.boardId,
          documentId,
          title: "Concurrent pack",
          mediaType: "application/json",
          documentSchema: "boardagent.board-pack.v1",
          body: Buffer.from(boardPackBody(answer))
        });
      const contribute = (
        content: ReturnType<typeof prepared>,
        baseId: number,
        idempotencyKey: string
      ) =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            contributeDocumentVersionInTransaction(client, {
              prepared: content,
              documentVersionId: id(baseId),
              validationAttemptId: id(baseId + 1),
              auditEventId: id(baseId + 2),
              idempotencyRecordId: id(baseId + 3),
              idempotencyKey,
              offeredName: "concurrent.json"
            }),
          { assumeRole: "boardagent_server" }
        );

      await contribute(prepared(1), 41, "document-concurrent-0001");
      const raced = await Promise.all([
        contribute(prepared(2), 50, "document-concurrent-0002"),
        contribute(prepared(3), 60, "document-concurrent-0003")
      ]);
      expect(
        raced
          .filter((result) => !result.replayed)
          .map((result) => (result.replayed ? 0 : result.version))
          .toSorted()
      ).toEqual([2, 3]);

      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            await contributeDocumentVersionInTransaction(client, {
              prepared: prepared(4),
              documentVersionId: id(70),
              validationAttemptId: id(71),
              auditEventId: id(72),
              idempotencyRecordId: id(73),
              idempotencyKey: "document-concurrent-0004",
              offeredName: "concurrent.json"
            });
            throw new Error("synthetic document crash");
          },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("synthetic document crash");
      const afterCrash = await pool.query<{
        audit_count: string;
        idempotency_count: string;
        row_version: string;
        version_count: string;
      }>(
        `select d.row_version::text,
                (select count(*)::text from document_versions where document_id=d.id) as version_count,
                (select count(*)::text from audit_events) as audit_count,
                (select count(*)::text from idempotency_records) as idempotency_count
           from documents d where d.id=$1`,
        [documentId]
      );
      expect(afterCrash.rows[0]).toEqual({
        row_version: "3",
        version_count: "3",
        audit_count: "3",
        idempotency_count: "3"
      });

      const retried = await contribute(prepared(4), 70, "document-concurrent-0004");
      expect(retried).toMatchObject({ replayed: false, version: 4 });
      const finalState = await pool.query<{ row_version: string; version_count: string }>(
        `select d.row_version::text,
                (select count(*)::text from document_versions where document_id=d.id) as version_count
           from documents d where d.id=$1`,
        [documentId]
      );
      expect(finalState.rows[0]).toEqual({ row_version: "4", version_count: "4" });
    });
  });

  it("denies observers and stale onboarding before it creates an idempotency record", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedContributor(pool);
      const documentId = id(80);
      const prepared = prepareDocumentContribution({
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        documentId,
        title: "Authority pack",
        mediaType: "text/plain; charset=utf-8",
        documentSchema: null,
        body: Buffer.from("version one\n")
      });
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          contributeDocumentVersionInTransaction(client, {
            prepared,
            documentVersionId: id(81),
            validationAttemptId: id(82),
            auditEventId: id(83),
            idempotencyRecordId: id(84),
            idempotencyKey: "document-authority-0001"
          }),
        { assumeRole: "boardagent_server" }
      );

      await pool.query(
        `insert into onboarding_terms_versions(
           id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
           material_change,effective_at,created_by
         ) values ($1,$2,'observer',1,'boardagent.onboarding-terms.v1','Observer terms',$3,
           true,transaction_timestamp(),$4)`,
        [id(85), actor.organizationId, hash(20), actor.memberId]
      );
      await pool.query(
        `insert into onboarding_attestations(
           id,organization_id,member_id,board_id,terms_version_id,support_version_id,
           presentation_choice,local_memory_choice,consent_record_id
         ) values ($1,$2,$3,$4,$5,$6,'structured','local-only',$7)`,
        [
          id(86),
          actor.organizationId,
          actor.memberId,
          actor.boardId,
          id(85),
          actor.supportVersionId,
          actor.consentRecordId
        ]
      );
      await pool.query(
        "update board_memberships set seat_role='observer',voting_weight=0,is_secretary=false where board_id=$1 and member_id=$2",
        [actor.boardId, actor.memberId]
      );
      const versionTwo = prepareDocumentContribution({
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        documentId,
        title: "Authority pack",
        mediaType: "text/plain; charset=utf-8",
        documentSchema: null,
        body: Buffer.from("version two\n")
      });
      const attemptVersionTwo = () =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            contributeDocumentVersionInTransaction(client, {
              prepared: versionTwo,
              documentVersionId: id(87),
              validationAttemptId: id(88),
              auditEventId: id(89),
              idempotencyRecordId: id(90),
              idempotencyKey: "document-authority-0002"
            }),
          { assumeRole: "boardagent_server" }
        );
      await expect(attemptVersionTwo()).rejects.toThrow("document contribution is unavailable");

      await pool.query(
        "update board_memberships set seat_role='management',voting_weight=0 where board_id=$1 and member_id=$2",
        [actor.boardId, actor.memberId]
      );
      await pool.query(
        `insert into onboarding_terms_versions(
           id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
           material_change,effective_at,created_by
         ) values ($1,$2,'management',2,'boardagent.onboarding-terms.v1','Changed terms',$3,
           true,transaction_timestamp(),$4)`,
        [id(91), actor.organizationId, hash(21), actor.memberId]
      );
      await expect(attemptVersionTwo()).rejects.toThrow("document contribution is unavailable");
      const noPartialAttempt = await pool.query<{ count: string }>(
        "select count(*)::text as count from idempotency_records where id=$1",
        [id(90)]
      );
      expect(noPartialAttempt.rows[0]?.count).toBe("0");

      await pool.query(
        `insert into onboarding_attestations(
           id,organization_id,member_id,board_id,terms_version_id,support_version_id,
           presentation_choice,local_memory_choice,consent_record_id
         ) values ($1,$2,$3,$4,$5,$6,'structured','local-only',$7)`,
        [
          id(92),
          actor.organizationId,
          actor.memberId,
          actor.boardId,
          id(91),
          actor.supportVersionId,
          actor.consentRecordId
        ]
      );
      await expect(attemptVersionTwo()).resolves.toMatchObject({ replayed: false, version: 2 });
    });
  });

  it("persists only safe rejected-input metadata and replays that evidence idempotently", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedContributor(pool);
      const offered = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
      let rejection: DocumentValidationError | undefined;
      try {
        prepareDocumentContribution({
          organizationId: actor.organizationId,
          boardId: actor.boardId,
          documentId: id(100),
          title: "Rejected image",
          mediaType: "image/jpeg",
          documentSchema: null,
          body: offered
        });
      } catch (error) {
        if (error instanceof DocumentValidationError) rejection = error;
        else throw error;
      }
      expect(rejection).toBeDefined();

      const recorded = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          recordDocumentValidationRejectionInTransaction(client, {
            organizationId: actor.organizationId,
            boardId: actor.boardId,
            validationAttemptId: id(101),
            idempotencyRecordId: id(102),
            idempotencyKey: "document-rejection-0001",
            offeredMediaType: "image/jpeg",
            offeredName: "scan.jpg",
            offeredLength: offered.length,
            offeredSha256: null,
            rejection: rejection!
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(recorded).toEqual({ replayed: false, validationAttemptId: id(101) });

      const replayed = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          recordDocumentValidationRejectionInTransaction(client, {
            organizationId: actor.organizationId,
            boardId: actor.boardId,
            validationAttemptId: id(103),
            idempotencyRecordId: id(104),
            idempotencyKey: "document-rejection-0001",
            offeredMediaType: "image/jpeg",
            offeredName: "scan.jpg",
            offeredLength: offered.length,
            offeredSha256: null,
            rejection: rejection!
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(replayed).toEqual({ replayed: true, validationAttemptId: id(101) });
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            recordDocumentValidationRejectionInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              validationAttemptId: id(105),
              idempotencyRecordId: id(106),
              idempotencyKey: "document-rejection-0001",
              offeredMediaType: "image/png",
              offeredName: "scan.png",
              offeredLength: offered.length,
              offeredSha256: null,
              rejection: rejection!
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("idempotency key was already used for a different request");

      const stored = await pool.query<{
        accepted_document_version_id: string | null;
        attempt_count: string;
        document_count: string;
        offered_length: string;
        offered_sha256: Buffer | null;
        result: string;
        result_code: string;
      }>(
        `select attempt.result,attempt.result_code,attempt.offered_length::text,
                attempt.offered_sha256,attempt.accepted_document_version_id,
                (select count(*)::text from document_validation_attempts) as attempt_count,
                (select count(*)::text from documents) as document_count
           from document_validation_attempts attempt
          where attempt.id=$1`,
        [id(101)]
      );
      expect(stored.rows[0]).toEqual({
        result: "rejected",
        result_code: "machine_readable_material_required",
        offered_length: String(offered.length),
        offered_sha256: null,
        accepted_document_version_id: null,
        attempt_count: "1",
        document_count: "0"
      });
    });
  });

  it("enforces explicit document ACL permissions before read or contribution and lets exclusion win", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedContributor(pool);
      const ownerId = id(110);
      const documentId = id(111);
      const documentVersionId = id(112);
      const canonicalBytes = Buffer.from("confidential\n");
      const canonicalHash = sha256Hex(canonicalBytes);
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Owner','Owner','active')",
        [ownerId, actor.organizationId]
      );
      await pool.query(
        `insert into documents(id,organization_id,board_id,title,created_by)
         values ($1,$2,$3,'Private pack',$4)`,
        [documentId, actor.organizationId, actor.boardId, ownerId]
      );
      await pool.query(
        `insert into document_versions(
           id,organization_id,board_id,document_id,version,media_type,document_schema,
           canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,
           created_by
         ) values ($1,$2,$3,$4,1,'text/plain; charset=utf-8',null,
           'RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)`,
        [
          documentVersionId,
          actor.organizationId,
          actor.boardId,
          documentId,
          canonicalBytes,
          canonicalBytes.length,
          Buffer.from(canonicalHash, "hex"),
          ownerId
        ]
      );
      await pool.query("update documents set current_version_id=$1,row_version=2 where id=$2", [
        documentVersionId,
        documentId
      ]);
      await pool.query(
        `insert into document_search(
           document_id,board_id,current_version_id,canonical_text_sha256,search_text
         ) values ($1,$2,$3,$4,$5)`,
        [
          documentId,
          actor.boardId,
          documentVersionId,
          Buffer.from(canonicalHash, "hex"),
          canonicalBytes.toString("utf8")
        ]
      );

      const fetch = (auditEventId: string) =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            fetchDocumentVersionInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              documentId,
              version: 1,
              auditEventId,
              requestOrigin: "https://client.example"
            }),
          { assumeRole: "boardagent_server" }
        );
      await expect(fetch(id(113))).rejects.toThrow("document version is unavailable");
      await pool.query(
        `insert into document_access_grants(
           id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by
         ) values ($1,$2,$3,$4,$5,'read',$6)`,
        [id(114), actor.organizationId, actor.boardId, documentId, actor.memberId, ownerId]
      );
      await expect(fetch(id(115))).resolves.toMatchObject({ sha256: canonicalHash });

      const nextVersion = prepareDocumentContribution({
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        documentId,
        title: "Private pack",
        mediaType: "text/plain; charset=utf-8",
        documentSchema: null,
        body: Buffer.from("authorized revision\n")
      });
      const contribute = () =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            contributeDocumentVersionInTransaction(client, {
              prepared: nextVersion,
              documentVersionId: id(116),
              validationAttemptId: id(117),
              auditEventId: id(118),
              idempotencyRecordId: id(119),
              idempotencyKey: "document-acl-0001"
            }),
          { assumeRole: "boardagent_server" }
        );
      await expect(contribute()).rejects.toThrow("document contribution is unavailable");
      await pool.query(
        `insert into document_access_grants(
           id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by
         ) values ($1,$2,$3,$4,$5,'contribute',$6)`,
        [id(120), actor.organizationId, actor.boardId, documentId, actor.memberId, ownerId]
      );
      await expect(contribute()).resolves.toMatchObject({ replayed: false, version: 2 });

      await pool.query(
        `insert into document_exclusions(
           id,organization_id,board_id,document_id,member_id,version,reason,created_by
         ) values ($1,$2,$3,$4,$5,1,'deny wins',$6)`,
        [id(121), actor.organizationId, actor.boardId, documentId, actor.memberId, ownerId]
      );
      await expect(fetch(id(122))).rejects.toThrow("document version is unavailable");
    });
  });
});
