import type { Pool, PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

/**
 * SR-023 revocation timing, as disposed in
 * `docs/decisions/revocation-timing-disposition-2026-09.md`: authority is re-resolved at
 * every request boundary (`boardagent_resolve_access_token`, the query behind the
 * server's `liveActor`), a request already admitted completes under the context it was
 * admitted with, and the next request refuses. Nothing here changes an access policy.
 */

interface ResolvedToken {
  readonly token_record_id: string;
  readonly board_ids: string[];
  readonly roles: string[];
}

async function resolve(client: PoolClient, jti: string): Promise<ResolvedToken[]> {
  const result = await client.query<ResolvedToken>(
    "select token_record_id,board_ids,roles from boardagent_resolve_access_token($1)",
    [jti]
  );
  return result.rows;
}

async function readBoard(client: PoolClient, boardId: string): Promise<number> {
  const result = await client.query("select id from boards where id=$1", [boardId]);
  return result.rowCount ?? 0;
}

/**
 * The resolver also requires a current browser session behind the token
 * (`boardagent_access_session_current`); seed the constrained synthetic session the
 * projection fixtures use. Not browser authentication.
 */
async function seedActor(pool: Pool): Promise<AuthorizedActorFixture> {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["governance:read"]
  });
  const sessionId = testId(286010);
  await pool.query(
    `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,
    state,exact_origin,expires_at,last_authenticated_at)
    values($1,$2,$3,$4,$5,'authenticated',$6,transaction_timestamp()+interval '10 minutes',transaction_timestamp())`,
    [
      sessionId,
      actor.organizationId,
      Buffer.alloc(32, 0x96),
      actor.memberId,
      actor.clientId,
      "https://boardagent.test"
    ]
  );
  const linked = await pool.query(
    "update access_token_records set session_id=$2 where id=$1 and session_id is null returning id",
    [actor.accessTokenRecordId, sessionId]
  );
  expect(linked.rowCount).toBe(1);
  return actor;
}

function request<T>(
  pool: Parameters<typeof withRequestTransaction<T>>[0],
  actor: AuthorizedActorFixture,
  run: (client: PoolClient) => Promise<T>
): Promise<T> {
  // Reads run at the default read-committed level, like the surface read service.
  return withRequestTransaction(pool, actor.context, run, { assumeRole: "boardagent_server" });
}

describe("SR-023 revocation timing — request boundary", () => {
  it("lets an admitted request finish after its seat ends, then refuses the next request", async () => {
    await withMigratedDatabase("revocation-in-flight-seat", async (pool) => {
      const actor = await seedActor(pool);
      const inFlight = await request(pool, actor, async (client) => {
        const atAdmission = await resolve(client, actor.tokenJti);
        expect(atAdmission).toHaveLength(1);
        expect(atAdmission[0]?.board_ids).toContain(actor.boardId);
        const before = await readBoard(client, actor.boardId);
        // Authority ends on another connection while this request is still running.
        await pool.query(
          "update board_memberships set state='ended',active_until=transaction_timestamp() where member_id=$1 and board_id=$2 and state='active'",
          [actor.memberId, actor.boardId]
        );
        const after = await readBoard(client, actor.boardId);
        return { before, after };
      });
      // The admitted request completed under its admitted board scope.
      expect(inFlight).toEqual({ before: 1, after: 1 });
      // The next request re-resolves and no longer carries the seat: the surface's live
      // actor check denies any board read for it.
      const next = await request(pool, actor, (client) => resolve(client, actor.tokenJti));
      expect(next).toHaveLength(1);
      expect(next[0]?.board_ids).not.toContain(actor.boardId);
      expect(next[0]?.roles).not.toContain("member");
    });
  }, 60_000);

  it("refuses the next request outright once the token is revoked mid-request", async () => {
    await withMigratedDatabase("revocation-in-flight-token", async (pool) => {
      const actor = await seedActor(pool);
      const inFlight = await request(pool, actor, async (client) => {
        expect(await resolve(client, actor.tokenJti)).toHaveLength(1);
        const before = await readBoard(client, actor.boardId);
        await pool.query(
          "update access_token_records set revoked_at=transaction_timestamp() where jti=$1 and revoked_at is null",
          [actor.tokenJti]
        );
        const after = await readBoard(client, actor.boardId);
        return { before, after };
      });
      expect(inFlight).toEqual({ before: 1, after: 1 });
      const next = await request(pool, actor, (client) => resolve(client, actor.tokenJti));
      expect(next).toHaveLength(0);
    });
  }, 60_000);
});
