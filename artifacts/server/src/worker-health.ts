import { mkdir, lstat, unlink, chmod } from "node:fs/promises";
import { createServer, request } from "node:http";
import path from "node:path";

export const WORKER_HEALTH_SOCKET = "/tmp/boardagent-worker-health/status.sock";
const MAX_PROGRESS_AGE_MS = 30_000;

/** Container-local readiness; no TCP listener, DB credentials or public authority. */
export async function startWorkerHealth(
  options: {
    readonly socketPath?: string;
    readonly now?: () => number;
  } = {}
) {
  const socketPath = options.socketPath ?? WORKER_HEALTH_SOCKET;
  const directory = path.dirname(socketPath);
  const now = options.now ?? (() => performance.now());
  await mkdir(directory, { mode: 0o700, recursive: true });
  const parent = await lstat(directory);
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    parent.uid !== process.getuid?.() ||
    (parent.mode & 0o077) !== 0
  ) {
    throw new Error("worker health directory must be private and owned");
  }
  try {
    const previous = await lstat(socketPath);
    if (!previous.isSocket() || previous.uid !== parent.uid)
      throw new Error("unsafe worker health socket");
    await unlink(socketPath);
  } catch (error) {
    if (!(
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ))
      throw error;
  }
  let progressAt: number | null = null;
  let closing = false;
  const server = createServer((incoming, response) => {
    const age = progressAt === null ? Infinity : now() - progressAt;
    const ready = !closing && age >= 0 && age <= MAX_PROGRESS_AGE_MS;
    const route = incoming.method === "GET" && incoming.url === "/health/ready";
    response.writeHead(route ? (ready ? 200 : 503) : 404, {
      "content-type": "application/json",
      "cache-control": "no-store",
      connection: "close"
    });
    response.end(JSON.stringify({ status: route && ready ? "ready" : "unavailable" }));
  });
  server.requestTimeout = 2_000;
  server.headersTimeout = 2_000;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  await chmod(socketPath, 0o600);
  return {
    progress(): void {
      if (!closing) progressAt = now();
    },
    async close(): Promise<void> {
      closing = true;
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
    }
  };
}

export function probeWorkerHealth(socketPath = WORKER_HEALTH_SOCKET): Promise<boolean> {
  return new Promise((resolve) => {
    const outgoing = request(
      { socketPath, path: "/health/ready", method: "GET", timeout: 2_000 },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode === 200));
        response.once("error", () => resolve(false));
      }
    );
    outgoing.once("timeout", () => outgoing.destroy());
    outgoing.once("error", () => resolve(false));
    outgoing.end();
  });
}
