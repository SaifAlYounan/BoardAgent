import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import { migrate, withRequestTransaction } from "../../lib/db/src/index.js";
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
  const database = `boardagent_surface_document_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "surface-document-contribution-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function principal(actor: AuthorizedActorFixture): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://secretary-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: ["documents:contribute"],
    roles: ["member", "secretariat"],
    boardIds: [actor.boardId]
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by document contribution test");
  },
  readResource: async () => {
    throw new Error("resource read not used by document contribution test");
  }
};

describe("direct canonical document contribution surface", () => {
  it("accepts exact source, replays safely, rejects invalid bytes, and enforces the expected base", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["documents:contribute"],
        isSecretary: true
      });
      let nextId = 110_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const documentId = testId(111_000);
      const firstInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: actor.boardId,
        document_id: documentId,
        title: "Exploration programme",
        media_type: "text/markdown; charset=utf-8",
        schema_name: null,
        canonical_body: "# Exploration programme\n\nPhase one drilling.\n",
        expected_current_version_id: null,
        idempotency_key: "surface-document-create-0001"
      } as const;

      const created = await service.executeDirect(
        principal(actor),
        "create_document_version",
        firstInput
      );
      expect(created).toMatchObject({
        tool: "create_document_version",
        status: "accepted",
        resource_uri: `board://${actor.boardId}/documents/${documentId}/versions/1`,
        data: {
          document_id: documentId,
          version: 1,
          validation_result: "accepted",
          replayed: false
        }
      });
      const versionId = created.reference;
      expect(versionId).toMatch(/^018f/u);
      const contributionAuthority = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const permission = await client.query<{ allowed: boolean }>(
            "select boardagent_document_permission($1,'contribute') as allowed",
            [documentId]
          );
          const visibleSearch = await client.query<{ count: string }>(
            "select count(*)::text as count from document_search where document_id=$1",
            [documentId]
          );
          return {
            allowed: permission.rows[0]?.allowed,
            visibleSearch: visibleSearch.rows[0]?.count
          };
        },
        { assumeRole: "boardagent_server" }
      );
      expect(contributionAuthority).toEqual({ allowed: true, visibleSearch: "0" });

      await expect(
        service.executeDirect(principal(actor), "create_document_version", firstInput)
      ).resolves.toMatchObject({
        status: "already_applied",
        reference: versionId,
        data: { document_version_id: versionId, replayed: true }
      });

      await expect(
        service.executeDirect(principal(actor), "create_document_version", {
          ...firstInput,
          canonical_body: "# Stale overwrite\n",
          idempotency_key: "surface-document-create-0002"
        })
      ).rejects.toThrow("document contribution is unavailable");

      const second = await service.executeDirect(principal(actor), "create_document_version", {
        ...firstInput,
        canonical_body: "# Exploration programme\n\nPhase two drilling.\n",
        expected_current_version_id: versionId,
        idempotency_key: "surface-document-create-0003"
      });
      expect(second).toMatchObject({
        status: "accepted",
        resource_uri: `board://${actor.boardId}/documents/${documentId}/versions/2`,
        data: { version: 2, replayed: false }
      });
      // A newer active head does not change the original safe receipt.
      await expect(
        service.executeDirect(principal(actor), "create_document_version", firstInput)
      ).resolves.toMatchObject({
        status: "already_applied",
        reference: versionId,
        data: { document_version_id: versionId, replayed: true }
      });
      expect(
        (
          await pool.query(
            "select count(*)::int as count from document_versions where document_id=$1",
            [documentId]
          )
        ).rows[0]?.count
      ).toBe(2);

      await expect(
        service.executeDirect(principal(actor), "create_document_version", {
          ...firstInput,
          document_id: testId(111_001),
          title: "Malformed JSON",
          media_type: "application/json",
          schema_name: "boardagent.board-pack.v1",
          canonical_body: '{"duplicate":1,"duplicate":2}',
          idempotency_key: "surface-document-reject-0001"
        })
      ).rejects.toThrow(/invalid_canonical_content.*validation attempt/iu);

      for (const [index, schemaName] of [
        "boardagent.board-pack.v1",
        "boardagent.unknown.v1"
      ].entries()) {
        await expect(
          service.executeDirect(principal(actor), "create_document_version", {
            ...firstInput,
            document_id: testId(111_002 + index),
            title: "Invalid typed JSON",
            media_type: "application/json",
            schema_name: schemaName,
            canonical_body: "{}",
            idempotency_key: `surface-document-invalid-schema-${index}`
          })
        ).rejects.toThrow(/document_schema_invalid.*validation attempt/iu);
      }
      const rejectedDocuments = await pool.query<{ count: string }>(
        "select count(*)::text as count from documents where id=any($1::uuid[])",
        [[testId(111_001), testId(111_002), testId(111_003)]]
      );
      expect(rejectedDocuments.rows[0]?.count).toBe("0");
      // No rejected body or version is retained, only validation-attempt metadata.
      const allVersions = await pool.query<{ count: string }>(
        "select count(*)::text as count from document_versions"
      );
      expect(allVersions.rows[0]?.count).toBe("2");

      const stored = await pool.query<{
        accepted_count: string;
        current_version_id: string;
        rejected_count: string;
        version_count: string;
      }>(
        `select document.current_version_id,
                (select count(*)::text from document_versions
                  where document_id=document.id) as version_count,
                (select count(*)::text from document_validation_attempts
                  where result='accepted') as accepted_count,
                (select count(*)::text from document_validation_attempts
                  where result='rejected') as rejected_count
           from documents as document where document.id=$1`,
        [documentId]
      );
      expect(stored.rows[0]).toEqual({
        current_version_id: second.reference,
        version_count: "2",
        accepted_count: "2",
        rejected_count: "3"
      });
    });
  });
});
