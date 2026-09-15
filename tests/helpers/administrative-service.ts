import type { Pool } from "pg";
import {
  PgBoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { DirectReadRepository } from "./direct-response-allocation.js";
import type { JsonValue } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import type { AuthorizedActorFixture } from "./authorized-actor.js";
import { testId } from "./authorized-actor.js";

/** A disposable database credential fixture, never a claimed human login. */
export async function freshAdministrativeTestCredential(
  pool: Pool,
  actor: AuthorizedActorFixture,
  idBase: number
): Promise<AuthorizedActorFixture> {
  const sessionId = testId(idBase),
    accessTokenRecordId = testId(idBase + 1),
    tokenJti = testId(idBase + 2);
  await pool.query(
    "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())",
    [
      sessionId,
      actor.organizationId,
      Buffer.from(tokenJti.replaceAll("-", "").repeat(2), "hex"),
      actor.memberId,
      actor.clientId
    ]
  );
  await pool.query(
    "insert into access_token_records(id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,signing_key_id,expires_at) select $1,organization_id,$2,member_id,client_id,resource_uri,array['secretariat:admin','governance:read','documents:read'],$3,signing_key_id,transaction_timestamp()+interval '10 minutes' from access_token_records where id=$4",
    [accessTokenRecordId, tokenJti, sessionId, actor.accessTokenRecordId]
  );
  return { ...actor, accessTokenRecordId, tokenJti, context: { ...actor.context, tokenJti } };
}

export async function administrativeService(pool: Pool, actor: AuthorizedActorFixture) {
  const row = await withRequestTransaction(
    pool,
    actor.context,
    async (client) =>
      (
        await client.query<{
          protocol_client_id: string;
          roles: string[];
          scope_set: string[];
          board_ids: string[];
          resource_uri: string;
        }>("select * from boardagent_resolve_access_token($1)", [actor.tokenJti])
      ).rows[0],
    { assumeRole: "boardagent_server" }
  );
  if (!row) throw new Error("synthetic actor has no live token");
  const principal: SurfacePrincipal = {
    ...actor.context,
    accessTokenRecordId: actor.accessTokenRecordId,
    protocolClientId: row.protocol_client_id,
    serviceOrigin: new URL(row.resource_uri).origin,
    keyId: "test-oauth",
    roles: row.roles,
    scopes: row.scope_set,
    boardIds: row.board_ids
  };
  // Direct fixture: each read carries its own synthetic allocation owner (native parity).
  const reads = new DirectReadRepository(pool, {
    cursorKey: Buffer.alloc(32, 7),
    transaction: { assumeRole: "boardagent_server" }
  });
  const service = new PgBoardAgentSurfaceService(pool, {
    reads,
    transaction: { assumeRole: "boardagent_server" }
  });
  return { principal, service, reads };
}
export async function stageAdministrativeAction(
  pool: Pool,
  actor: AuthorizedActorFixture,
  tool: string,
  input: JsonValue
) {
  const { principal, service } = await administrativeService(pool, actor);
  const prepared = await service.prepareHumanAction(principal, tool, input);
  const client_capabilities = { elicitation: { form: {} } };
  const request_state = `administrative-test-state-${prepared.stage_id}`;
  await service.persistHumanStage({
    principal,
    tool,
    input,
    prepared,
    client_capabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: "Review exact administrative authority" },
    request_state,
    prepared_request_id: Buffer.from("prepare-0001")
  });
  return {
    prepared,
    confirm: (code = prepared.confirmation_code) =>
      service.resolveHumanAction({
        principal,
        tool,
        input,
        stage_id: prepared.stage_id,
        client_capabilities,
        request_state,
        retry_request_id: Buffer.from("retry-0001"),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: code }
      })
  };
}
