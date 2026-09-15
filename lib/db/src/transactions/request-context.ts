import type { PoolClient } from "pg";

interface RequestContextRow {
  readonly organization_id: string | null;
  readonly member_id: string | null;
  readonly client_id: string | null;
  readonly token_jti: string | null;
}

export interface ActiveRequestContext {
  readonly organizationId: string;
  readonly memberId: string;
  readonly clientId: string;
  readonly tokenJti: string;
}

export async function readRequestContext(client: PoolClient): Promise<ActiveRequestContext> {
  const result = await client.query<RequestContextRow>(
    `select boardagent_context_uuid('boardagent.organization_id')::text as organization_id,
            boardagent_context_uuid('boardagent.member_id')::text as member_id,
            boardagent_context_uuid('boardagent.client_id')::text as client_id,
            boardagent_context_uuid('boardagent.token_jti')::text as token_jti`
  );
  const row = result.rows[0];
  if (!row?.organization_id || !row.member_id || !row.client_id || !row.token_jti) {
    throw new Error("managed request context is unavailable");
  }
  return {
    organizationId: row.organization_id,
    memberId: row.member_id,
    clientId: row.client_id,
    tokenJti: row.token_jti
  };
}
