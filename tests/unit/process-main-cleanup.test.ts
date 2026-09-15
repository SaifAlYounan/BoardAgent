import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({
  startServer: vi.fn(),
  acquireLease: vi.fn(),
  parseConfig: vi.fn(),
  assertPurpose: vi.fn(),
  forbiddenTransport: vi.fn(() => {
    throw new Error("unexpected transport in inert server-lifecycle test");
  })
}));
vi.mock("@boardagent/config", () => ({
  parseConfig: mocked.parseConfig,
  assertProductionDatabasePurpose: mocked.assertPurpose
}));
vi.mock("node:http", () => ({ request: mocked.forbiddenTransport }));
vi.mock("../../artifacts/server/src/process-runtime.js", () => ({
  startBoardAgentServer: mocked.startServer
}));
vi.mock("../../artifacts/server/src/worker-process.js", () => ({
  startBoardAgentWorker: mocked.forbiddenTransport
}));
vi.mock("../../artifacts/server/src/worker-health.js", () => ({
  probeWorkerHealth: mocked.forbiddenTransport,
  startWorkerHealth: mocked.forbiddenTransport
}));
vi.mock("../../artifacts/server/src/kernel-maintenance-lease.js", () => ({
  acquireKernelMaintenanceLease: mocked.acquireLease,
  PRODUCTION_MAINTENANCE_LOCK_FILE: "/synthetic-unused-maintenance-lock"
}));

import { main } from "../../artifacts/server/src/main.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.clearAllMocks();
});

function fixture(close: () => Promise<void> = async () => undefined) {
  const signals = new EventEmitter();
  const otherSignalListener = vi.fn();
  signals.on("SIGTERM", otherSignalListener);
  signals.on("SIGINT", otherSignalListener);
  const originalOnce = process.once.bind(process);
  const originalRemove = process.removeListener.bind(process);
  vi.spyOn(process, "once").mockImplementation((event, listener) => {
    if (event === "SIGTERM" || event === "SIGINT") {
      signals.once(event, listener);
      return process;
    }
    return originalOnce(event, listener);
  });
  vi.spyOn(process, "removeListener").mockImplementation((event, listener) => {
    if (event === "SIGTERM" || event === "SIGINT") {
      signals.removeListener(event, listener);
      return process;
    }
    return originalRemove(event, listener);
  });
  const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
  const server = new EventEmitter();
  const runtimeClose = vi.fn(close);
  const leaseClose = vi.fn(async () => undefined);
  mocked.startServer.mockResolvedValue({ server, close: runtimeClose });
  mocked.acquireLease.mockResolvedValue({ close: leaseClose });
  mocked.parseConfig.mockReturnValue({ environment: "production" });
  vi.stubEnv("BOARDAGENT_ENV", "production");
  return { signals, otherSignalListener, server, runtimeClose, leaseClose, stderr };
}

function expectListenersRemoved(f: ReturnType<typeof fixture>) {
  expect(f.signals.listeners("SIGTERM")).toEqual([f.otherSignalListener]);
  expect(f.signals.listeners("SIGINT")).toEqual([f.otherSignalListener]);
  expect(f.server.listenerCount("error")).toBe(0);
  expect(mocked.forbiddenTransport).not.toHaveBeenCalled();
}

describe("server process terminal cleanup", () => {
  it("awaits runtime cleanup after a server error before releasing maintenance authority", async () => {
    let finish: () => void = () => undefined;
    const closed = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const f = fixture(() => closed);
    const running = main(["server"]);
    try {
      await vi.waitFor(() => expect(f.server.listenerCount("error")).toBe(1));
      f.server.emit("error", new Error("synthetic post-start error"));
      await vi.waitFor(() => expect(f.runtimeClose).toHaveBeenCalledOnce());
      expect(f.leaseClose).not.toHaveBeenCalled();
      expect(() =>
        f.server.emit("error", new Error("synthetic error while closing"))
      ).not.toThrow();
    } finally {
      finish();
      await running;
    }
    await expect(running).resolves.toBe(1);
    expect(f.runtimeClose).toHaveBeenCalledOnce();
    expect(f.leaseClose).toHaveBeenCalledOnce();
    expectListenersRemoved(f);
    expect(f.stderr.mock.calls.some(([line]) => String(line).includes('"server.stopped"'))).toBe(
      false
    );
  });

  it.each(["SIGTERM", "SIGINT"] as const)("cleans up once after captured %s", async (signal) => {
    const f = fixture();
    const running = main(["server"]);
    await vi.waitFor(() => expect(f.server.listenerCount("error")).toBe(1));
    // This is a private EventEmitter, not an OS signal or process.emit.
    f.signals.emit(signal);
    await expect(running).resolves.toBe(0);
    expect(f.runtimeClose).toHaveBeenCalledOnce();
    expect(f.leaseClose).toHaveBeenCalledOnce();
    expectListenersRemoved(f);
    expect(f.stderr.mock.calls.some(([line]) => String(line).includes('"server.stopped"'))).toBe(
      true
    );
  });

  it("reports an error raised during graceful shutdown instead of success", async () => {
    let finish: () => void = () => undefined;
    const closed = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const f = fixture(() => closed);
    const running = main(["server"]);
    try {
      await vi.waitFor(() => expect(f.server.listenerCount("error")).toBe(1));
      f.signals.emit("SIGTERM");
      await vi.waitFor(() => expect(f.runtimeClose).toHaveBeenCalledOnce());
      expect(f.leaseClose).not.toHaveBeenCalled();
      f.server.emit("error", new Error("synthetic error during graceful shutdown"));
    } finally {
      finish();
      await running;
    }
    await expect(running).resolves.toBe(1);
    expect(f.runtimeClose).toHaveBeenCalledOnce();
    expect(f.leaseClose).toHaveBeenCalledOnce();
    expectListenersRemoved(f);
    expect(f.stderr.mock.calls.some(([line]) => String(line).includes('"server.stopped"'))).toBe(
      false
    );
  });

  it("reports shutdown failure and still removes its listeners and maintenance lease", async () => {
    const f = fixture(async () => {
      throw new Error("synthetic application cleanup failure");
    });
    const running = main(["server"]);
    await vi.waitFor(() => expect(f.server.listenerCount("error")).toBe(1));
    f.signals.emit("SIGTERM");
    await expect(running).resolves.toBe(1);
    expect(f.runtimeClose).toHaveBeenCalledOnce();
    expect(f.leaseClose).toHaveBeenCalledOnce();
    expectListenersRemoved(f);
    expect(f.stderr.mock.calls.some(([line]) => String(line).includes('"server.stopped"'))).toBe(
      false
    );
  });
});
