import { guardRuntimeDatabaseTransaction } from "@boardagent/db";
import { z } from "zod";
import type { Pool } from "pg";

import { Rfc3339UtcSchema, UuidV7Schema } from "@boardagent/contracts";

import type { ActiveTokenContext, TokenContextStore } from "./auth.js";

const ActiveTokenRowSchema = z
  .object({
    token_record_id: UuidV7Schema,
    organization_id: UuidV7Schema,
    member_id: UuidV7Schema,
    internal_client_id: UuidV7Schema,
    protocol_client_id: z.string().min(1).max(2048),
    resource_uri: z.url(),
    scope_set: z.array(z.string().min(1).max(128)).max(32),
    expires_at_epoch: z.string().regex(/^[1-9]\d*$/u),
    signing_key_kid: z.string().min(1).max(255),
    roles: z.array(z.enum(["admin", "secretariat", "management", "member", "observer"])).max(8),
    board_ids: z.array(UuidV7Schema).max(25)
  })
  .strict();

interface ActiveTokenRow {
  readonly token_record_id: string;
  readonly organization_id: string;
  readonly member_id: string;
  readonly internal_client_id: string;
  readonly protocol_client_id: string;
  readonly resource_uri: string;
  readonly scope_set: string[];
  readonly expires_at_epoch: string;
  readonly signing_key_kid: string;
  readonly roles: string[];
  readonly board_ids: string[];
}

export class PgTokenContextStore implements TokenContextStore {
  public constructor(
    private readonly pool: Pool,
    private readonly options: {
      /** Test/bootstrap seam only. Production pools connect through scoped credentials. */
      readonly assumeRole?: "boardagent_server";
    } = {}
  ) {}

  public async findActiveByJti(jti: string): Promise<ActiveTokenContext | null> {
    const parsedJti = UuidV7Schema.parse(jti);
    const query = `select token_record_id,organization_id,member_id,internal_client_id,
                          protocol_client_id,resource_uri,scope_set,expires_at_epoch::text,
                          signing_key_kid,roles,board_ids
                     from boardagent_resolve_access_token($1)`;
    const result = await (async () => {
      const client = await this.pool.connect();
      try {
        await client.query("begin");
        if (this.options.assumeRole)
          await client.query(`set local role ${this.options.assumeRole}`);
        await guardRuntimeDatabaseTransaction(client);
        const scoped = await client.query<ActiveTokenRow>(query, [parsedJti]);
        await client.query("commit");
        return scoped;
      } catch (error) {
        await client.query("rollback").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    })();
    if (result.rows.length === 0) return null;
    if (result.rows.length !== 1) throw new Error("access token JTI is not unique");
    const row = ActiveTokenRowSchema.parse(result.rows[0]);
    const expiresAt = Number(row.expires_at_epoch);
    if (!Number.isSafeInteger(expiresAt)) throw new Error("access token expiry is out of range");
    // Keep URL and epoch validation explicit at the database/application seam.
    Rfc3339UtcSchema.parse(new Date(expiresAt * 1000).toISOString().replace(".000Z", "Z"));
    return {
      tokenRecordId: row.token_record_id,
      organizationId: row.organization_id,
      memberId: row.member_id,
      internalClientId: row.internal_client_id,
      protocolClientId: row.protocol_client_id,
      resourceUri: new URL(row.resource_uri).toString(),
      scopes: [...new Set(row.scope_set)].toSorted(),
      expiresAt,
      signingKeyKid: row.signing_key_kid,
      roles: [...new Set(row.roles)].toSorted(),
      boardIds: [...new Set(row.board_ids)].toSorted()
    };
  }
}
