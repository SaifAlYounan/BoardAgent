import { describe, expect, it } from "vitest";

import { PgTokenContextStore } from "../../artifacts/server/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { runFocusedProof } from "../helpers/focused-proof.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("AC-08 / TH-46 conforming client portability", () => {
  it("keeps one member's identity, roles, history and entitlements stable across two brands", async () => {
    await withMigratedDatabase("client_portability", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "documents:read"],
        isSecretary: true
      });
      const firstSessionId = testId(46_000);
      const secondClientId = testId(46_001);
      const secondSessionId = testId(46_002);
      const secondTokenId = testId(46_003);
      const secondJti = testId(46_004);
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://client-a.example',
           transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [firstSessionId, actor.organizationId, testHash(46), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        firstSessionId,
        actor.accessTokenRecordId
      ]);
      await pool.query(
        `insert into oauth_clients(
           id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,
           state,registered_by
         ) values ($1,$2,'preregistered','portable-client-b',
           '{"client_name":"Independent Brand B"}',$3,'active',$4)`,
        [secondClientId, actor.organizationId, testHash(47), actor.memberId]
      );
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://client-b.example',
           transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [secondSessionId, actor.organizationId, testHash(48), actor.memberId, secondClientId]
      );
      await pool.query(
        `insert into access_token_records(
           id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,
           signing_key_id,expires_at
         ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',
           array['governance:read','documents:read'],$6,$7,
           transaction_timestamp()+interval '10 minutes')`,
        [
          secondTokenId,
          actor.organizationId,
          secondJti,
          actor.memberId,
          secondClientId,
          secondSessionId,
          testId(8)
        ]
      );

      const store = new PgTokenContextStore(pool, { assumeRole: "boardagent_server" });
      const first = await store.findActiveByJti(actor.tokenJti);
      const second = await store.findActiveByJti(secondJti);
      expect(first).not.toBeNull();
      expect(second).not.toBeNull();
      if (!first || !second) throw new Error("both portable client contexts must resolve");
      expect({
        organizationId: second.organizationId,
        memberId: second.memberId,
        roles: second.roles,
        scopes: second.scopes,
        boardIds: second.boardIds
      }).toEqual({
        organizationId: first.organizationId,
        memberId: first.memberId,
        roles: first.roles,
        scopes: first.scopes,
        boardIds: first.boardIds
      });
      expect(second.internalClientId).not.toBe(first.internalClientId);
      expect(second.protocolClientId).toBe("portable-client-b");
      expect(first.protocolClientId).toBe("authorized-test-client");

      const view = (clientId: string, tokenJti: string) =>
        withRequestTransaction(
          pool,
          {
            organizationId: actor.organizationId,
            memberId: actor.memberId,
            clientId,
            tokenJti,
            boardIds: [actor.boardId]
          },
          async (client) => ({
            boards: (
              await client.query(
                `select board.id,board.name,membership.seat_role,membership.is_secretary
                   from boards as board
                   join board_memberships as membership on membership.board_id=board.id
                  where membership.member_id=$1 order by board.id`,
                [actor.memberId]
              )
            ).rows,
            consentHistory: (
              await client.query(
                `select action_code,target_type,target_id
                   from consent_records where actor_member_id=$1 order by staged_at,id`,
                [actor.memberId]
              )
            ).rows
          }),
          { assumeRole: "boardagent_server" }
        );
      expect(await view(secondClientId, secondJti)).toEqual(
        await view(actor.clientId, actor.tokenJti)
      );

      await pool.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [secondTokenId]
      );
      expect(await store.findActiveByJti(secondJti)).toBeNull();
      expect(await store.findActiveByJti(actor.tokenJti)).not.toBeNull();
    });
  });

  it("connects real MCP clients, keeps legacy read-only and rejects cross-client retry", async () => {
    await runFocusedProof(
      "tests/integration/role-connection-journeys.postgres.test.ts",
      "binds each real MCP client to its own live role and denies a stranger"
    );
    await runFocusedProof(
      "tests/protocol/frozen-mcp-surface.integration.test.ts",
      "advertises exactly the 58 approved read tools to the frozen legacy profile"
    );
    await runFocusedProof(
      "tests/attacks/consent-context-replay.spec.ts",
      "binds request, protected actor/client/object state, canonical bytes, and one-use state"
    );
  });
});
