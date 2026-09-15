import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";
import {
  createBoardAgentMcpHandler,
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import { appendAuditEventsInTransaction, withWorkerTransaction } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withConfiguredFixtureWorker } from "../helpers/configured-worker.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { newWorkerTestId } from "../helpers/unseeded-worker.js";

const unusedReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("not used by direct contribution test");
  },
  readResource: async () => {
    throw new Error("not used by direct contribution test");
  }
};

it("MCP capacity refusal rolls back the document and retries exactly once after real signing", async () => {
  await withMigratedDatabase("audit-capacity-mcp", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["documents:contribute"],
      isSecretary: true
    });
    await withConfiguredFixtureWorker(pool, actor.organizationId, async (worker) => {
      const resource = new URL("https://boardagent.test/mcp");
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unusedReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: newWorkerTestId
      });
      const handler = createBoardAgentMcpHandler({
        service,
        requestStateKey: new Uint8Array(32).fill(0x73),
        requestStateTtlSeconds: 600
      });
      // Real SDK/HTTP and server database capability; synthetic authenticated actor.
      // This test does not claim actual browser enrollment or OAuth acceptance.
      const authInfo: AuthInfo = {
        token: "synthetic-capacity-test",
        clientId: "https://capacity-agent.test/client.json",
        scopes: ["documents:contribute"],
        expiresAt: Math.floor(Date.now() / 1000) + 600,
        resource,
        extra: {
          organizationId: actor.organizationId,
          memberId: actor.memberId,
          internalClientId: actor.clientId,
          accessTokenRecordId: actor.accessTokenRecordId,
          jti: actor.tokenJti,
          keyId: "test-oauth",
          roles: ["member", "secretariat"],
          boardIds: [actor.boardId]
        }
      };
      const client = new Client(
        { name: "capacity-agent", version: "1.0.0" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          cachePartition: actor.memberId
        }
      );
      try {
        await client.connect(
          new StreamableHTTPClientTransport(resource, {
            fetch: async (input, init) => handler.fetch(new Request(input, init), { authInfo })
          })
        );
        const before = Number(
          (await pool.query("select last_sequence from public.audit_chain_head")).rows[0]!
            .last_sequence
        );
        await withWorkerTransaction(
          pool,
          (db) =>
            appendAuditEventsInTransaction(
              db,
              Array.from({ length: 1000 - before }, () => ({
                organizationId: actor.organizationId,
                event: {
                  eventId: newWorkerTestId(),
                  eventType: "context_read" as const,
                  actorMemberId: null,
                  actorClientId: null,
                  tokenJti: null,
                  entityType: "context",
                  entityId: newWorkerTestId(),
                  boardId: null,
                  origin: "worker",
                  details: { synthetic: true },
                  schemaVersion: 1
                }
              }))
            ),
          { assumeRole: "boardagent_worker" }
        );
        const documentId = testId(5_600_001);
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId,
          document_id: documentId,
          title: "Synthetic audit capacity test",
          media_type: "text/markdown; charset=utf-8",
          schema_name: null,
          canonical_body: "# Synthetic record\n",
          expected_current_version_id: null,
          idempotency_key: "audit-capacity-document-0001"
        };
        const refused = await client.callTool({
          name: "create_document_version",
          arguments: input
        });
        expect(refused.isError).toBe(true);
        expect(refused.structuredContent).toMatchObject({
          code: "audit_checkpoint_capacity",
          retryable: true
        });
        expect(
          (
            await pool.query("select count(*)::int as count from documents where id=$1", [
              documentId
            ])
          ).rows[0]?.count
        ).toBe(0);
        expect(
          (
            await pool.query(
              "select count(*)::int as count from document_versions where document_id=$1",
              [documentId]
            )
          ).rows[0]?.count
        ).toBe(0);
        expect(
          (await pool.query("select last_sequence::text from public.audit_chain_head")).rows
        ).toEqual([{ last_sequence: "1000" }]);
        expect(await worker.worker.runOnce()).toMatchObject({
          status: "succeeded",
          jobType: "audit_checkpoint"
        });
        const accepted = await client.callTool({
          name: "create_document_version",
          arguments: input
        });
        expect(accepted.isError).not.toBe(true);
        expect(accepted.structuredContent).toMatchObject({
          status: "accepted",
          data: { replayed: false }
        });
        const replayed = await client.callTool({
          name: "create_document_version",
          arguments: input
        });
        expect(replayed.structuredContent).toMatchObject({
          status: "already_applied",
          data: { replayed: true }
        });
        expect(
          (
            await pool.query(
              "select count(*)::int as count from document_versions where document_id=$1",
              [documentId]
            )
          ).rows[0]?.count
        ).toBe(1);
      } finally {
        await client.close();
        await handler.close();
      }
    });
  });
}, 25_000);
