import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { PgTokenContextStore } from "../../artifacts/server/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (owner: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_token_context_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const ownerUrl = new URL(BASE_URL);
  ownerUrl.pathname = `/${database}`;
  const owner = new Pool({ connectionString: ownerUrl.toString(), max: 4 });
  try {
    await migrate(owner, MIGRATIONS, "token-context-test");
    return await run(owner);
  } finally {
    await owner.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

describe("database-bound bearer context", () => {
  it("returns the exact active token/client/member/session context and disappears on revoke", async () => {
    await withDatabase(async (owner) => {
      const actor = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: ["governance:read", "documents:read"],
        isSecretary: true
      });
      const sessionId = testId(36_001);
      const tokenId = testId(36_002);
      const jti = testId(36_003);
      await owner.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://portable-client.test',
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, testHash(36), actor.memberId, actor.clientId]
      );
      await owner.query(
        `insert into access_token_records(
           id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,
           signing_key_id,expires_at
         ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',
                   array['documents:read','governance:read'],$6,$7,
                   date_trunc('second',transaction_timestamp())+interval '15 minutes')`,
        [tokenId, actor.organizationId, jti, actor.memberId, actor.clientId, sessionId, testId(8)]
      );

      const store = new PgTokenContextStore(owner, { assumeRole: "boardagent_server" });
      const resolved = await store.findActiveByJti(jti);
      expect(resolved).toMatchObject({
        tokenRecordId: tokenId,
        organizationId: actor.organizationId,
        memberId: actor.memberId,
        internalClientId: actor.clientId,
        protocolClientId: "authorized-test-client",
        resourceUri: "https://boardagent.test/mcp",
        scopes: ["documents:read", "governance:read"],
        roles: ["member", "secretariat"],
        boardIds: [actor.boardId]
      });

      await owner.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [tokenId]
      );
      expect(await store.findActiveByJti(jti)).toBeNull();
    });
  });
});
