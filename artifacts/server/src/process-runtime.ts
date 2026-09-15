import { createServer, type Server } from "node:http";

import type { BoardAgentConfig } from "@boardagent/config";
import { Pool } from "pg";
import type { OAuthInteractionFailure } from "./oauth-interaction-handler.js";
import { observeDatabasePoolErrors } from "./database-pool-errors.js";

import {
  createBoardAgentServerApplication,
  type BoardAgentServerApplication
} from "./server-application.js";

export const SERVER_DATABASE_CONNECTION_LIMIT = 20;

export interface RunningBoardAgentServer {
  readonly server: Server;
  readonly application: BoardAgentServerApplication;
  readonly port: number;
  close(): Promise<void>;
}

export interface StartBoardAgentServerOptions {
  readonly pool?: Pool;
  readonly host?: string;
  readonly port?: number;
  /** Capability role entered from a purpose-specific, unprivileged login principal. */
  readonly assumeRole?: "boardagent_server";
  readonly closePool?: boolean;
  readonly shutdownGraceMilliseconds?: number;
  readonly onError?: (error: Error) => void;
  readonly onInteractionFailure?: (failure: OAuthInteractionFailure) => void;
}

function boundedPort(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 65_535) {
    throw new RangeError("server port must be an integer from 0 through 65535");
  }
  return value;
}

function boundedGrace(value: number): number {
  if (!Number.isInteger(value) || value < 1_000 || value > 60_000) {
    throw new RangeError("shutdown grace must be an integer from 1000 through 60000 milliseconds");
  }
  return value;
}

/** Starts one bounded native HTTP process. Signal policy remains at the CLI boundary. */
export async function startBoardAgentServer(
  config: BoardAgentConfig,
  options: StartBoardAgentServerOptions = {}
): Promise<RunningBoardAgentServer> {
  const ownsPool = options.pool === undefined;
  const pool =
    options.pool ??
    // One of the process's bounded connections belongs to the maintenance lease.
    new Pool({ connectionString: config.databaseUrl, max: SERVER_DATABASE_CONNECTION_LIMIT - 1 });
  const stopObservingPool = observeDatabasePoolErrors(
    pool,
    options.onError ? () => options.onError!(new Error("database pool connection lost")) : undefined
  );
  let application: BoardAgentServerApplication;
  try {
    application = await createBoardAgentServerApplication(pool, config, {
      ...(options.assumeRole === undefined ? {} : { assumeRole: options.assumeRole }),
      ...(options.onError === undefined ? {} : { onError: options.onError }),
      ...(options.onInteractionFailure === undefined
        ? {}
        : { onInteractionFailure: options.onInteractionFailure })
    });
  } catch (error) {
    if (ownsPool || options.closePool === true) await pool.end().catch(() => undefined);
    stopObservingPool();
    throw error;
  }
  const server = createServer(application.handler);
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 100;
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(boundedPort(options.port ?? 8787), options.host ?? "0.0.0.0", resolve);
    });
  } catch (error) {
    await application.close().catch(() => undefined);
    if (ownsPool || options.closePool === true) await pool.end().catch(() => undefined);
    stopObservingPool();
    throw error;
  }
  const address = server.address();
  if (!address || typeof address === "string") {
    await application.close().catch(() => undefined);
    if (ownsPool || options.closePool === true) await pool.end().catch(() => undefined);
    stopObservingPool();
    throw new Error("BoardAgent server did not bind a TCP address");
  }
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => {
    if (closing) return closing;
    closing = (async () => {
      const forceTimer = setTimeout(
        () => server.closeAllConnections(),
        boundedGrace(options.shutdownGraceMilliseconds ?? 25_000)
      );
      forceTimer.unref();
      try {
        await new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve()))
        );
      } finally {
        clearTimeout(forceTimer);
        try {
          await application.close();
        } finally {
          try {
            if (ownsPool || options.closePool === true) await pool.end();
          } finally {
            stopObservingPool();
          }
        }
      }
    })();
    return closing;
  };
  return { server, application, port: address.port, close };
}
