import { once } from "node:events";
import { request } from "node:http";
import { pathToFileURL } from "node:url";

import { assertProductionDatabasePurpose, parseConfig } from "@boardagent/config";
import type { JsonValue } from "@boardagent/contracts";

import { startBoardAgentServer } from "./process-runtime.js";
import { startBoardAgentWorker } from "./worker-process.js";
import { probeWorkerHealth, startWorkerHealth } from "./worker-health.js";
import {
  acquireKernelMaintenanceLease,
  PRODUCTION_MAINTENANCE_LOCK_FILE,
  type KernelMaintenanceLease
} from "./kernel-maintenance-lease.js";

type Service = "boardagent.process" | "boardagent.server" | "boardagent.worker";

function lifecycle(
  service: Service,
  event: string,
  result: "success" | "error",
  reasonCode?: string
): void {
  process.stderr.write(
    `${JSON.stringify({
      schemaVersion: 1,
      timestamp: new Date().toISOString(),
      service,
      level: result === "success" ? "info" : "error",
      event,
      result,
      ...(reasonCode === undefined ? {} : { reasonCode })
    })}\n`
  );
}

async function healthcheck(): Promise<boolean> {
  const config = parseConfig(process.env);
  assertProductionDatabasePurpose(config, "server");
  if (config.trustedProxyHops < 1) return false;
  const forwarded = Array.from(
    { length: config.trustedProxyHops },
    (_unused, index) => `127.0.0.${String(index + 1)}`
  ).join(", ");
  return new Promise((resolve) => {
    const outbound = request(
      {
        hostname: "127.0.0.1",
        port: 8787,
        path: "/health/ready",
        method: "GET",
        headers: {
          host: config.publicBaseUrl.host,
          "x-forwarded-for": forwarded,
          "x-forwarded-proto": "https"
        },
        timeout: 2_000
      },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode === 200));
      }
    );
    outbound.once("timeout", () => outbound.destroy());
    outbound.once("error", () => resolve(false));
    outbound.end();
  });
}

async function serve(): Promise<void> {
  const config = parseConfig(process.env);
  assertProductionDatabasePurpose(config, "server");
  const running = await startBoardAgentServer(config, {
    assumeRole: "boardagent_server",
    onError: () => lifecycle("boardagent.server", "request.failed", "error", "request_rejected"),
    // A refused login or consent step names its route and reason (never the request
    // content) so an operator can tell a bad passkey from a stale interaction.
    onInteractionFailure: (failure) =>
      lifecycle(
        "boardagent.server",
        "auth.interaction.failed",
        "error",
        `${failure.routeKind}.${failure.reasonCode}`
      )
  });
  lifecycle("boardagent.server", "server.started", "success");
  const termination = Promise.withResolvers<void>();
  let serverError: Error | undefined;
  const stop = (): void => termination.resolve();
  const onError = (error: Error): void => {
    serverError ??= error;
    termination.reject(error);
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  // Keep errors observed until cleanup settles, including repeated errors while
  // closing. Resolving/rejecting the same terminal promise cannot close twice.
  running.server.on("error", onError);
  try {
    await termination.promise;
  } finally {
    try {
      await running.close();
    } finally {
      process.removeListener("SIGTERM", stop);
      process.removeListener("SIGINT", stop);
      running.server.removeListener("error", onError);
    }
  }
  if (serverError) throw serverError;
  lifecycle("boardagent.server", "server.stopped", "success");
}

async function operationalAlert(alertClass: string, details: JsonValue): Promise<void> {
  const accepted = process.stderr.write(
    `${JSON.stringify({
      schemaVersion: 1,
      timestamp: new Date().toISOString(),
      service: "boardagent.worker",
      level: "warn",
      event: "operational.alert",
      result: "success",
      alertClass,
      details
    })}\n`
  );
  if (!accepted) await once(process.stderr, "drain");
}

async function work(): Promise<void> {
  const config = parseConfig(process.env);
  assertProductionDatabasePurpose(config, "worker");
  const health = await startWorkerHealth();
  const abort = new AbortController();
  const stop = (): void => abort.abort("process_signal");
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  let running: Awaited<ReturnType<typeof startBoardAgentWorker>> | undefined;
  try {
    running = await startBoardAgentWorker(config, {
      assumeRole: "boardagent_worker",
      onProgress: health.progress,
      onOperationalAlert: operationalAlert
    });
    lifecycle("boardagent.worker", "worker.started", "success");
    await running.run(abort.signal);
    await running.close();
    running = undefined;
    lifecycle("boardagent.worker", "worker.stopped", "success");
  } finally {
    process.removeListener("SIGTERM", stop);
    process.removeListener("SIGINT", stop);
    try {
      await running?.close();
    } finally {
      await health.close();
    }
  }
}

export async function main(args = process.argv.slice(2)): Promise<number> {
  const command = args[0] ?? "server";
  const workerProbe = args.length === 2 && command === "healthcheck" && args[1] === "worker";
  if ((!workerProbe && args.length > 1) || !["server", "worker", "healthcheck"].includes(command)) {
    lifecycle("boardagent.process", "process.refused", "error", "unknown_command");
    return 64;
  }
  if (workerProbe) return (await probeWorkerHealth()) ? 0 : 1;
  if (command === "healthcheck") return (await healthcheck()) ? 0 : 1;
  let lease: KernelMaintenanceLease | undefined;
  try {
    if (process.env["BOARDAGENT_ENV"] === "production")
      lease = await acquireKernelMaintenanceLease(PRODUCTION_MAINTENANCE_LOCK_FILE, "shared");
    if (command === "worker") await work();
    else await serve();
    return 0;
  } catch {
    lifecycle(
      command === "worker" ? "boardagent.worker" : "boardagent.server",
      "process.failed",
      "error",
      "startup_or_shutdown_failed"
    );
    return 1;
  } finally {
    await lease?.close();
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await main();
}
