import {
  acquireRuntimeMaintenanceLease,
  type RuntimeMaintenanceLease
} from "./runtime-maintenance-lease.js";
import type { JsonValue } from "@boardagent/contracts";
import { randomBytes } from "node:crypto";
import {
  scheduleAuditCheckpointInTransaction,
  schedulePeriodicJobsInTransaction,
  withWorkerTransaction
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import type { BoardAgentConfig } from "@boardagent/config";
import { Pool } from "pg";
import { observeDatabasePoolErrors } from "./database-pool-errors.js";

import { BoardAgentCoreWorkerHandlers } from "./core-worker-handlers.js";
import { LocalExportArtifactStore } from "./export-artifact-store.js";
import { loadBoardAgentWorkerKeyMaterial } from "./key-material.js";
import {
  BoardAgentNotificationWorker,
  type WebhookDeliveryTransport
} from "./notification-worker.js";
import { loadBoardAgentWorkerRuntimeBinding } from "./runtime-binding.js";
import { Aes256GcmWebhookSecurity } from "./webhook-security.js";
import { dataDecryptionKeyring } from "./retained-data-keys.js";
import { BoardAgentTypedWorker, composeTypedJobHandlers } from "./worker.js";

export interface StartBoardAgentWorkerOptions {
  readonly onProgress?: () => void;
  readonly pool?: Pool;
  readonly closePool?: boolean;
  readonly workerId?: string;
  readonly leaseSeconds?: number;
  readonly heartbeatMilliseconds?: number;
  readonly pollMilliseconds?: number;
  readonly transport?: WebhookDeliveryTransport;
  readonly onOperationalAlert?: (alertClass: string, details: JsonValue) => void | Promise<void>;
  /** Capability role entered from a purpose-specific, unprivileged login principal. */
  readonly assumeRole?: "boardagent_worker";
}

export interface RunningBoardAgentWorker {
  readonly worker: BoardAgentTypedWorker;
  run(signal: AbortSignal): Promise<void>;
  close(): Promise<void>;
}

/**
 * Binds every frozen job handler to one production worker coordinator. Startup proves the
 * instance/key binding and initializes the shared encrypted artifact store before polling.
 */
export async function startBoardAgentWorker(
  config: BoardAgentConfig,
  options: StartBoardAgentWorkerOptions = {}
): Promise<RunningBoardAgentWorker> {
  const ownsPool = options.pool === undefined;
  // Reserve one of the twelve process connections for the maintenance lease.
  const pool = options.pool ?? new Pool({ connectionString: config.databaseUrl, max: 11 });
  const stopObservingPool = observeDatabasePoolErrors(
    pool,
    options.onOperationalAlert
      ? () => options.onOperationalAlert!("database_connection_lost", { component: "worker" })
      : undefined
  );
  let runtimeLease: RuntimeMaintenanceLease | undefined;
  try {
    runtimeLease = await acquireRuntimeMaintenanceLease(pool, "worker", options.assumeRole);
    const keys = await loadBoardAgentWorkerKeyMaterial(config);
    const scoped =
      options.assumeRole === undefined ? {} : ({ assumeRole: options.assumeRole } as const);
    const binding = await loadBoardAgentWorkerRuntimeBinding(pool, config, keys, scoped);
    const exportArtifacts = new LocalExportArtifactStore(config.blobRoot, {
      maximumArtifactBytes: config.exportMaximumBytes,
      chunkBytes: config.exportChunkBytes
    });
    await exportArtifacts.initialize();
    const webhookSecurity = new Aes256GcmWebhookSecurity({
      activeKeyId: binding.keyIds.data_kek,
      keys: dataDecryptionKeyring(
        binding.keyIds.data_kek,
        keys.dataEncryptionKey,
        keys.retainedDataKeys
      )
    });
    const notifications = new BoardAgentNotificationWorker(pool, {
      webhookSecurity,
      ...(options.transport === undefined ? {} : { transport: options.transport }),
      ...(options.onOperationalAlert === undefined
        ? {}
        : { onOperationalAlert: options.onOperationalAlert }),
      ...scoped
    });
    const core = new BoardAgentCoreWorkerHandlers(pool, {
      config,
      binding,
      keys,
      exportArtifacts,
      ...(options.onOperationalAlert === undefined
        ? {}
        : { onOperationalAlert: options.onOperationalAlert }),
      ...scoped
    });
    let lastBlockedCheckpointId: string | null = null;
    let lastSchedulerFailure: string | null = null;
    const worker = new BoardAgentTypedWorker(pool, {
      runtimeDatabaseLease: runtimeLease,
      beforeClaim: async () => {
        const checkpoint = await withWorkerTransaction(
          pool,
          async (client) => {
            const result = await scheduleAuditCheckpointInTransaction(
              client,
              uuidV7(Date.now(), randomBytes(10))
            );
            await schedulePeriodicJobsInTransaction(client);
            return result;
          },
          scoped
        ).catch(async (error: unknown) => {
          const code =
            typeof error === "object" && error !== null && "code" in error ? error.code : null;
          // The transaction wrapper has rolled back before this catch. A transient
          // producer failure must not prevent an independent claim of existing work.
          // Permission, integrity, malformed state and connection failures still propagate.
          if (typeof code !== "string" || !["55P03", "40001", "40P01", "57014"].includes(code))
            throw error;
          if (lastSchedulerFailure !== code) {
            lastSchedulerFailure = code;
            const details = {
              reason: code === "57014" ? "database_statement_cancelled" : "database_contention",
              sqlstate: code
            };
            const fallback = () => {
              process.stderr.write(
                `${JSON.stringify({ event: "worker_scheduler_deferred", status: "error", ...details })}\n`
              );
            };
            try {
              if (options.onOperationalAlert)
                await options.onOperationalAlert("worker_scheduler_deferred", details);
              else fallback();
            } catch {
              fallback();
            }
          }
          return null;
        });
        if (checkpoint === null) return;
        lastSchedulerFailure = null;
        if (checkpoint.scheduling_status === "blocked") {
          if (lastBlockedCheckpointId !== checkpoint.result_job_id) {
            lastBlockedCheckpointId = checkpoint.result_job_id;
            // The dead row and immutable attempt result remain the durable finding.
            // A broken alert sink must not stop unrelated jobs; report once per process.
            await Promise.resolve()
              .then(() =>
                options.onOperationalAlert?.("audit_checkpoint_blocked", {
                  reason: "dead_checkpoint_job"
                })
              )
              .catch(() => undefined);
          }
        } else lastBlockedCheckpointId = null;
      },
      ...(options.onProgress === undefined ? {} : { onProgress: options.onProgress }),
      handlers: composeTypedJobHandlers(core.handlers(), notifications.handlers()),
      ...(options.workerId === undefined ? {} : { workerId: options.workerId }),
      ...(options.leaseSeconds === undefined ? {} : { leaseSeconds: options.leaseSeconds }),
      ...(options.heartbeatMilliseconds === undefined
        ? {}
        : { heartbeatMilliseconds: options.heartbeatMilliseconds }),
      ...(options.pollMilliseconds === undefined
        ? {}
        : { pollMilliseconds: options.pollMilliseconds }),
      ...scoped
    });
    worker.assertCompleteRegistry();
    let closing: Promise<void> | undefined;
    const close = (): Promise<void> => {
      closing ??= (async () => {
        try {
          await worker.drain();
        } finally {
          try {
            await runtimeLease?.close();
            if (ownsPool || options.closePool === true) await pool.end();
          } finally {
            stopObservingPool();
          }
        }
      })();
      return closing;
    };
    return { worker, run: (signal) => worker.run(signal), close };
  } catch (error) {
    await runtimeLease?.close().catch(() => undefined);
    if (ownsPool || options.closePool === true) await pool.end().catch(() => undefined);
    stopObservingPool();
    throw error;
  }
}
