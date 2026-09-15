import path from "node:path";
import { Pool } from "pg";
import { migrate } from "../../lib/db/src/migrate.js";
import { dropClosedTestDatabase } from "./drop-test-database.js";
import { seedAuthorizedActor, seedAdditionalAuthorizedActor, testId } from "./authorized-actor.js";

let counter = 0;
export async function withAdministrativeDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  const base =
    process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
    "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
  const name = `boardagent_admin_authority_${String(process.pid)}_${String(++counter)}`;
  const adminUrl = new URL(base);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${name}"`);
  const url = new URL(base);
  url.pathname = `/${name}`;
  const pool = new Pool({ connectionString: url.toString(), max: 8 });
  try {
    await migrate(
      pool,
      path.resolve(import.meta.dirname, "../../lib/db/migrations"),
      "administrative-authority-test"
    );
    return await run(pool);
  } finally {
    await pool.end();
    await dropClosedTestDatabase(admin, name);
    await admin.end();
  }
}

export async function administrativeActors(pool: Pool, grantAdmin = true) {
  const issuer = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    isSecretary: true,
    scopes: ["secretariat:admin", "governance:read"]
  });
  const target = await seedAdditionalAuthorizedActor(pool, issuer, {
    idBase: 71_000,
    seatRole: "voting_member",
    scopes: ["secretariat:admin", "governance:read"]
  });
  for (const [index, person] of [issuer, target].entries()) {
    const sessionId = testId(72_010 + index);
    await pool.query(
      "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())",
      [
        sessionId,
        person.organizationId,
        Buffer.alloc(32, 180 + index),
        person.memberId,
        person.clientId
      ]
    );
    await pool.query("update access_token_records set session_id=$1 where id=$2", [
      sessionId,
      person.accessTokenRecordId
    ]);
    await pool.query(
      "insert into refresh_families(id,organization_id,member_id,client_id,resource_uri,state,idle_expires_at,absolute_expires_at) values($1,$2,$3,$4,'https://boardagent.test/mcp','active',transaction_timestamp()+interval '30 days',transaction_timestamp()+interval '90 days')",
      [testId(72_020 + index), person.organizationId, person.memberId, person.clientId]
    );
    await pool.query(
      "insert into oauth_authorization_requests(id,organization_id,client_id,member_id,session_id,resource_uri,redirect_uri,scope_set,state_hash,request_state,expires_at) values($1,$2,$3,$4,$5,'https://boardagent.test/mcp','http://127.0.0.1:9000/callback',array['secretariat:admin'],$6,'approved',transaction_timestamp()+interval '1 minute')",
      [
        testId(72_030 + index),
        person.organizationId,
        person.clientId,
        person.memberId,
        sessionId,
        Buffer.alloc(32, 190 + index)
      ]
    );
    await pool.query(
      "insert into oauth_authorization_codes(id,organization_id,client_id,member_id,authorization_request_id,resource_uri,redirect_uri,scope_set,code_sha256,pkce_s256_challenge,expires_at) values($1,$2,$3,$4,$5,'https://boardagent.test/mcp','http://127.0.0.1:9000/callback',array['secretariat:admin'],$6,$7,transaction_timestamp()+interval '60 seconds')",
      [
        testId(72_040 + index),
        person.organizationId,
        person.clientId,
        person.memberId,
        testId(72_030 + index),
        Buffer.alloc(32, 200 + index),
        "A".repeat(43)
      ]
    );
  }
  if (grantAdmin)
    await pool.query(
      "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values ($1,$2,$3,'admin','Disposable authorized-admin test fixture')",
      [testId(72_000), issuer.organizationId, issuer.memberId]
    );
  return { issuer, target };
}
