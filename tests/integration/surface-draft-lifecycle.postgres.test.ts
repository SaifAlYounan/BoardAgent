import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION, sha256Hex } from "../../lib/contracts/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
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
  const database = `boardagent_surface_draft_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "surface-draft-lifecycle-test");
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
    protocolClientId: "https://draft-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: ["member:propose"],
    roles: ["member"],
    boardIds: [actor.boardId]
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by draft lifecycle test");
  },
  readResource: async () => {
    throw new Error("resource read not used by draft lifecycle test");
  }
};

async function attachLiveSessions(
  pool: Pool,
  actors: readonly AuthorizedActorFixture[]
): Promise<void> {
  for (const [index, actor] of actors.entries()) {
    const sessionId = testId(50_000 + index);
    await pool.query(
      `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,
        client_id,state,exact_origin,expires_at,last_authenticated_at)
       values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
         transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
      [
        sessionId,
        actor.organizationId,
        Buffer.alloc(32, 200 + index),
        actor.memberId,
        actor.clientId
      ]
    );
    await pool.query("update access_token_records set session_id=$1 where id=$2", [
      sessionId,
      actor.accessTokenRecordId
    ]);
  }
}

async function insertDraft(
  pool: Pool,
  actor: AuthorizedActorFixture,
  draftId: string,
  state: "active" | "ready_to_confirm" = "active"
): Promise<void> {
  const context = Buffer.from(
    JSON.stringify({ schemaVersion: "boardagent.test-draft-context.v1", draftId }),
    "utf8"
  );
  await pool.query(
    `insert into wizard_drafts(
       id,organization_id,board_id,draft_type,creator_member_id,current_step,
       signed_context,context_sha256,state,expires_at
     ) values ($1,$2,$3,'proposal',$4,1,$5,$6,$7,
       transaction_timestamp()+interval '10 minutes')`,
    [
      draftId,
      actor.organizationId,
      actor.boardId,
      actor.memberId,
      context,
      Buffer.from(sha256Hex(context), "hex"),
      state
    ]
  );
}

describe("wizard draft direct lifecycle surface", () => {
  it.each([
    "revoked_token",
    "suspended_member",
    "blocked_client",
    "removed_membership",
    "archived_board",
    "wrong_origin",
    "mismatched_token"
  ] as const)("refuses completed replay after %s without duplicating effects", async (change) => {
    await withDatabase(async (pool) => {
      const owner = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["member:propose"]
      });
      const other = await seedAdditionalAuthorizedActor(pool, owner, {
        idBase: 100,
        seatRole: "voting_member",
        scopes: ["member:propose"]
      });
      await attachLiveSessions(pool, [owner, other]);
      const draftId = testId(200);
      await insertDraft(pool, owner, draftId);
      let nextId = 10_000;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "draft-cancel-live-replay-0001",
        draft_id: draftId,
        reason: "This synthetic draft is no longer needed."
      } as const;
      const caller = principal(owner);
      await expect(surface.executeDirect(caller, "cancel_draft", input)).resolves.toMatchObject({
        status: "accepted"
      });
      await expect(surface.executeDirect(caller, "cancel_draft", input)).resolves.toMatchObject({
        status: "already_applied",
        reference: draftId
      });
      const inspect = async () =>
        (
          await pool.query(
            `select
        (select count(*)::int from audit_events where object_type='wizard_draft' and object_id=$1) as audit_count,
        (select count(*)::int from idempotency_records where actor_member_id=$2 and operation='cancel_draft') as idempotency_count,
        (select row_version::text from wizard_drafts where id=$1) as row_version`,
            [draftId, owner.memberId]
          )
        ).rows;
      const before = await inspect();
      let stale = caller;
      switch (change) {
        case "revoked_token":
          await pool.query(
            "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
            [owner.accessTokenRecordId]
          );
          break;
        case "suspended_member":
          await pool.query(
            "update members set state='suspended',row_version=row_version+1 where id=$1",
            [owner.memberId]
          );
          break;
        case "blocked_client":
          await pool.query("update oauth_clients set state='suspended' where id=$1", [
            owner.clientId
          ]);
          break;
        case "removed_membership":
          await pool.query(
            "update board_memberships set state='ended',active_until=transaction_timestamp() where member_id=$1 and board_id=$2",
            [owner.memberId, owner.boardId]
          );
          break;
        case "archived_board":
          await pool.query(
            "update boards set state='archived',row_version=row_version+1 where id=$1",
            [owner.boardId]
          );
          break;
        case "wrong_origin":
          stale = { ...caller, serviceOrigin: "https://different-board.example" };
          break;
        case "mismatched_token":
          stale = { ...caller, tokenJti: other.tokenJti };
          break;
      }
      await expect(surface.executeDirect(stale, "cancel_draft", input)).rejects.toThrow(
        /unavailable|authorized/u
      );
      expect(await inspect()).toEqual(before);
    });
  });

  it("cancels only the creator's nonexpired draft, retains its bytes, audits once, and replays safely", async () => {
    await withDatabase(async (pool) => {
      const owner = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["member:propose"]
      });
      const other = await seedAdditionalAuthorizedActor(pool, owner, {
        idBase: 100,
        seatRole: "voting_member",
        scopes: ["member:propose"]
      });
      await attachLiveSessions(pool, [owner, other]);
      const draftId = testId(200);
      await insertDraft(pool, owner, draftId, "ready_to_confirm");
      let nextId = 10_000;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-cancel-draft-0001",
        draft_id: draftId,
        reason: "The proposed action is no longer required."
      } as const;

      await expect(surface.executeDirect(principal(other), "cancel_draft", input)).rejects.toThrow(
        /unavailable|authorized/u
      );
      const cancelled = await surface.executeDirect(principal(owner), "cancel_draft", input);
      expect(cancelled).toMatchObject({
        tool: "cancel_draft",
        status: "accepted",
        reference: draftId,
        data: { state: "cancelled", row_version: "2", replayed: false }
      });
      const replayed = await surface.executeDirect(principal(owner), "cancel_draft", input);
      expect(replayed).toMatchObject({
        status: "already_applied",
        reference: draftId,
        data: { replayed: true }
      });

      const stored = await pool.query<{
        audit_count: string;
        context_length: number;
        row_version: string;
        state: string;
      }>(
        `select draft.state,draft.row_version::text,octet_length(draft.signed_context) as context_length,
                (select count(*)::text from audit_events as event
                  where event.object_type='wizard_draft' and event.object_id=draft.id
                    and event.event_type='draft_cancelled') as audit_count
           from wizard_drafts as draft where draft.id=$1`,
        [draftId]
      );
      expect(stored.rows[0]).toEqual({
        state: "cancelled",
        row_version: "2",
        context_length: expect.any(Number),
        audit_count: "1"
      });
      expect(stored.rows[0]!.context_length).toBeGreaterThan(31);
    });
  });
});
