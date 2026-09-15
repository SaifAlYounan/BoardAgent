import { randomBytes } from "node:crypto";
import { Client, type Pool } from "pg";
import {
  RUNTIME_MAINTENANCE_LOCK,
  RuntimeDatabaseLeaseUnavailableError,
  type RuntimeDatabaseLease
} from "@boardagent/db";

export interface RuntimeMaintenanceLease extends RuntimeDatabaseLease {
  readonly available: boolean;
  close(): Promise<void>;
}

/** One dedicated direct PostgreSQL session. Pool size and borrowed clients stay independent. */
export async function acquireRuntimeMaintenanceLease(
  pool: Pool,
  component: "server" | "worker",
  assumeRole?: "boardagent_server" | "boardagent_worker"
): Promise<RuntimeMaintenanceLease> {
  const client = new Client({
    ...pool.options,
    application_name: `boardagent-runtime-${component}`,
    keepAlive: true
  });
  let available = false,
    closing: Promise<void> | undefined;
  const unavailable = () => {
    available = false;
  };
  client.on("error", unavailable);
  client.on("end", unavailable);
  const close = () => {
    available = false;
    closing ??= client.end().finally(() => {
      client.removeListener("error", unavailable);
      client.removeListener("end", unavailable);
    });
    return closing;
  };
  try {
    await client.connect();
    if (assumeRole) await client.query(`set role ${assumeRole}`);
    const held = await client.query<{ locked: boolean; backend_pid: number }>(
      "select pg_try_advisory_lock_shared($1,$2) as locked,pg_backend_pid() as backend_pid",
      RUNTIME_MAINTENANCE_LOCK.slice()
    );
    if (held.rows[0]?.locked !== true)
      throw new Error("key maintenance is active; retry process startup after it completes");
    let markerKeys: [number, number, number, number];
    do {
      const bytes = randomBytes(16);
      markerKeys = [
        bytes.readInt32BE(0),
        bytes.readInt32BE(4),
        bytes.readInt32BE(8),
        bytes.readInt32BE(12)
      ];
    } while (
      (markerKeys[0] === markerKeys[2] && markerKeys[1] === markerKeys[3]) ||
      (markerKeys[0] === RUNTIME_MAINTENANCE_LOCK[0] &&
        markerKeys[1] === RUNTIME_MAINTENANCE_LOCK[1]) ||
      (markerKeys[2] === RUNTIME_MAINTENANCE_LOCK[0] &&
        markerKeys[3] === RUNTIME_MAINTENANCE_LOCK[1])
    );
    await client.query(
      "select pg_advisory_lock_shared($1,$2),pg_advisory_lock_shared($3,$4)",
      markerKeys
    );
    available = true;
    return {
      backendPid: held.rows[0].backend_pid,
      markerKeys: Object.freeze(markerKeys),
      get available() {
        return available;
      },
      assertAvailable() {
        if (!available) throw new RuntimeDatabaseLeaseUnavailableError();
      },
      close
    };
  } catch (error) {
    await close().catch(() => undefined);
    throw error;
  }
}
