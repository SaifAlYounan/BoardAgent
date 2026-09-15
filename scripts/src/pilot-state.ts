import type { PoolClient } from "pg";
import { UuidV7Schema } from "@boardagent/contracts";

/** Counts only. This inventory does not authorize deletion or decide a replacement. */
export async function readPilotStateInTransaction(client: PoolClient, organizationIdValue: string) {
  const organizationId = UuidV7Schema.parse(organizationIdValue);
  const instance = await client.query<{
    instance_id: string;
    read_only: boolean;
    observed_at: string;
  }>(
    `select instance_id,current_setting('transaction_read_only')='on' as read_only,
      to_char(transaction_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as observed_at
      from public.system_instance where singleton_key and organization_id=$1`,
    [organizationId]
  );
  if (instance.rows.length !== 1 || !instance.rows[0]?.read_only)
    throw new Error("pilot inventory requires the exact instance and a read-only transaction");
  const tables = await client.query<{ tablename: string }>(
    "select tablename from pg_catalog.pg_tables where schemaname='public' order by tablename"
  );
  const tableRowCounts: Record<string, string> = {};
  for (const { tablename } of tables.rows) {
    if (!/^[a-z][a-z0-9_]{0,62}$/u.test(tablename))
      throw new Error("pilot inventory encountered an unsupported table name");
    const result = await client.query<{ count: string }>(
      `select count(*)::text as count from public."${tablename}"`
    );
    const count = result.rows[0]?.count;
    if (!count || !/^(0|[1-9][0-9]*)$/u.test(count))
      throw new Error("pilot inventory count is incomplete");
    tableRowCounts[tablename] = count;
  }
  const members = await client.query<{ state: string; count: string }>(
    "select state,count(*)::text as count from public.members group by state order by state"
  );
  return {
    organizationId,
    instanceId: UuidV7Schema.parse(instance.rows[0].instance_id),
    observedAt: instance.rows[0].observed_at,
    readOnly: true,
    membersByState: members.rows,
    tableRowCounts
  };
}
