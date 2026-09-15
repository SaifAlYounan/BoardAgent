import { EventEmitter } from "node:events";
import type { Pool } from "pg";
import type { BoardAgentConfig } from "../../lib/config/src/config.js";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({
  pool: undefined as unknown,
  createServer: vi.fn(),
  createApplication: vi.fn()
}));

// Every transport/database constructor is inert. These tests exercise cleanup only.
vi.mock("node:http", () => ({ createServer: mocked.createServer }));
vi.mock("pg", () => ({
  Pool: vi.fn(function () {
    return mocked.pool;
  })
}));
vi.mock("../../artifacts/server/src/server-application.js", () => ({
  createBoardAgentServerApplication: mocked.createApplication
}));

import { startBoardAgentServer } from "../../artifacts/server/src/process-runtime.js";

afterEach(() => {
  vi.clearAllMocks();
});

function fixture(applicationFailure?: Error, poolFailure?: Error) {
  const applicationClose = vi.fn(async () => {
    if (applicationFailure) throw applicationFailure;
  });
  const pool = Object.assign(new EventEmitter(), {
    end: vi.fn(async () => {
      if (poolFailure) throw poolFailure;
    })
  });
  const otherPoolListener = vi.fn();
  pool.on("error", otherPoolListener);
  const server = Object.assign(new EventEmitter(), {
    listen: vi.fn((_port: number, _host: string, ready: () => void) => ready()),
    address: () => ({ port: 1 }),
    close: vi.fn((closed: () => void) => closed()),
    closeAllConnections: vi.fn()
  });
  mocked.pool = pool;
  mocked.createServer.mockReturnValue(server);
  mocked.createApplication.mockResolvedValue({ handler: vi.fn(), close: applicationClose });
  const config = { databaseUrl: "postgresql://synthetic.invalid/unused" } as BoardAgentConfig;
  return { pool, server, config, applicationClose, otherPoolListener };
}

describe("server runtime cleanup ownership", () => {
  it.each([
    { ownership: "owned", failure: "none" },
    { ownership: "owned", failure: "application" },
    { ownership: "borrowed", failure: "none" },
    { ownership: "borrowed", failure: "application" },
    { ownership: "explicit", failure: "application" },
    { ownership: "owned", failure: "pool" }
  ] as const)("closes $ownership resources after $failure outcome", async (scenario) => {
    const failure = new Error(`synthetic ${scenario.failure} failure`);
    const f = fixture(
      scenario.failure === "application" ? failure : undefined,
      scenario.failure === "pool" ? failure : undefined
    );
    const runtime = await startBoardAgentServer(f.config, {
      ...(scenario.ownership === "owned" ? {} : { pool: f.pool as unknown as Pool }),
      ...(scenario.ownership === "explicit" ? { closePool: true } : {})
    });
    expect(f.pool.listenerCount("error")).toBe(2);
    const closing = runtime.close();
    expect(runtime.close()).toBe(closing);
    if (scenario.failure === "none") await expect(closing).resolves.toBeUndefined();
    else await expect(closing).rejects.toBe(failure);
    expect(f.server.close).toHaveBeenCalledOnce();
    expect(f.applicationClose).toHaveBeenCalledOnce();
    expect(f.pool.end).toHaveBeenCalledTimes(scenario.ownership === "borrowed" ? 0 : 1);
    expect(f.pool.listeners("error")).toEqual([f.otherPoolListener]);
    expect(f.server.closeAllConnections).not.toHaveBeenCalled();
  });
});
