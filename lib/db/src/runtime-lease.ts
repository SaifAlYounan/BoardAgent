import { AsyncLocalStorage } from "node:async_hooks";
import type { PoolClient } from "pg";

/** Database-wide maintenance lock, shared by running services and their transactions. */
export const RUNTIME_MAINTENANCE_LOCK = [424248, 1] as const;
export interface RuntimeDatabaseLease {
  readonly backendPid: number;
  readonly markerKeys: readonly [number, number, number, number];
  assertAvailable(): void;
}
const runtimeLease = new AsyncLocalStorage<RuntimeDatabaseLease>();

/** Production assembly supplies the lease; direct operator/repository callers do not. */
export function withRuntimeDatabaseLease<T>(lease: RuntimeDatabaseLease, run: () => T): T {
  lease.assertAvailable();
  return runtimeLease.run(lease, run);
}

export class RuntimeDatabaseLeaseUnavailableError extends Error {
  readonly code = "runtime_lease_unavailable";
  constructor() {
    super("runtime database lease unavailable; restart the process");
  }
}

/** Hold exclusion until COMMIT even if the process's lifetime connection dies meanwhile. */
export async function guardRuntimeDatabaseTransaction(client: PoolClient): Promise<void> {
  const lease = runtimeLease.getStore();
  if (!lease) return;
  lease.assertAvailable();
  const locked = await client.query<{ locked: boolean }>(
    "select pg_try_advisory_xact_lock_shared($1,$2) as locked",
    RUNTIME_MAINTENANCE_LOCK.slice()
  );
  if (locked.rows[0]?.locked !== true) throw new RuntimeDatabaseLeaseUnavailableError();
  const marker = lease.markerKeys.map((value) => value >>> 0);
  const held = await client.query<{ held: boolean }>(
    `select count(distinct (l.classid,l.objid))=3 as held
    from pg_catalog.pg_locks l
    where l.locktype='advisory' and l.mode='ShareLock' and l.granted and l.objsubid=2
      and l.database=(select oid from pg_catalog.pg_database where datname=current_database())
      and l.pid=$1 and ((l.classid::bigint=$2 and l.objid::bigint=$3)
        or (l.classid::bigint=$4 and l.objid::bigint=$5) or (l.classid::bigint=$6 and l.objid::bigint=$7))`,
    [lease.backendPid, ...RUNTIME_MAINTENANCE_LOCK, ...marker]
  );
  if (held.rows[0]?.held !== true) throw new RuntimeDatabaseLeaseUnavailableError();
}
