import type { Pool } from "pg";
import { expect } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import { testId, type AuthorizedActorFixture } from "./authorized-actor.js";

// Constrained synthetic session storage + actual live resolver, matching the
// passed minutes-list fixture. This is not browser/provider authentication.
// Call exactly once for this actor in a fresh fixture database.
export async function meetingProjectionPrincipal(
  pool: Pool,
  actor: AuthorizedActorFixture
): Promise<SurfacePrincipal> {
  const sessionId = testId(285010);
  await pool.query(
    `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,
    state,exact_origin,expires_at,last_authenticated_at)
    values($1,$2,$3,$4,$5,'authenticated',$6,transaction_timestamp()+interval '10 minutes',transaction_timestamp())`,
    [
      sessionId,
      actor.organizationId,
      Buffer.alloc(32, 0x95),
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
  const live = await withRequestTransaction(
    pool,
    actor.context,
    async (client) => {
      const selected = await client.query<{
        token_record_id: string;
        organization_id: string;
        member_id: string;
        internal_client_id: string;
        protocol_client_id: string;
        resource_uri: string;
        scope_set: string[];
        roles: string[];
        board_ids: string[];
      }>(
        "select token_record_id,organization_id,member_id,internal_client_id,protocol_client_id,resource_uri,scope_set,roles,board_ids from boardagent_resolve_access_token($1)",
        [actor.tokenJti]
      );
      expect(selected.rows).toHaveLength(1);
      return selected.rows[0]!;
    },
    { assumeRole: "boardagent_server" }
  );
  expect(live).toMatchObject({
    token_record_id: actor.accessTokenRecordId,
    organization_id: actor.organizationId,
    member_id: actor.memberId,
    internal_client_id: actor.clientId
  });
  expect(live.resource_uri).toBe("https://boardagent.test/mcp");
  expect(live.protocol_client_id.length).toBeGreaterThan(0);
  expect([...live.scope_set].sort()).toEqual([
    "documents:contribute",
    "documents:read",
    "governance:read",
    "meeting:act",
    "secretariat:admin"
  ]);
  expect([...live.roles].sort()).toEqual(["member", "secretariat"]);
  expect(live.board_ids).toEqual([actor.boardId]);
  return {
    organizationId: live.organization_id,
    memberId: live.member_id,
    serviceOrigin: "https://boardagent.test",
    clientId: live.internal_client_id,
    protocolClientId: live.protocol_client_id,
    accessTokenRecordId: live.token_record_id,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: live.scope_set,
    roles: live.roles,
    boardIds: live.board_ids
  };
}
