import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({ request: vi.fn() }));
// Inert replacement installed before module import; this fixture never opens a socket.
vi.mock("node:https", () => ({ request: mocked.request }));

import { fetchPinnedCimdDocument } from "../../artifacts/server/src/client-registration.js";

afterEach(() => {
  vi.useRealTimers();
  mocked.request.mockReset();
});

function fixture(headers: Record<string, string> = {}) {
  const response = Object.assign(new EventEmitter(), {
    statusCode: 200,
    headers,
    errorListenerPresentAtDestruction: false,
    destroy: vi.fn((error: Error) => {
      response.errorListenerPresentAtDestruction = response.listenerCount("error") > 0;
      // Avoid turning the old missing-listener defect into a global test-process error.
      if (response.errorListenerPresentAtDestruction)
        queueMicrotask(() => {
          response.emit("error", error);
          response.emit("close");
        });
    })
  });
  const request = Object.assign(new EventEmitter(), {
    end: vi.fn(),
    setTimeout: vi.fn(),
    destroy: vi.fn((error = new Error("synthetic request cleanup")) => {
      queueMicrotask(() => {
        request.emit("error", error);
        request.emit("close");
      });
    })
  });
  let receive: (() => void) | undefined;
  mocked.request.mockImplementation((_url, _options, callback) => {
    receive = () => callback(response);
    return request;
  });
  return { response, request, receive: () => receive?.() };
}

function attempt(signal?: AbortSignal) {
  return fetchPinnedCimdDocument({
    clientId: "https://synthetic-client.example/metadata",
    pinnedAddresses: [{ address: "8.8.8.8", family: 4 }],
    maxBytes: 1024,
    timeoutMs: 100,
    ...(signal === undefined ? {} : { signal })
  });
}

describe("in-memory CIMD response lifecycle", () => {
  it.each([{ "content-encoding": "gzip" }, { "content-length": "2048" }])(
    "observes rejected response errors before destroying the response (%j)",
    async (headers) => {
      const f = fixture(headers);
      let settled: unknown;
      const pending = attempt().then(
        (value) => {
          settled = value;
        },
        (error: unknown) => {
          settled = error;
        }
      );
      f.receive();
      try {
        expect(f.response.errorListenerPresentAtDestruction).toBe(true);
        await pending;
        expect(settled).toMatchObject({ code: "cimd_response_refused" });
      } finally {
        f.request.destroy();
        await pending;
      }
    }
  );

  it("times out an active but incomplete response and removes its timer", async () => {
    vi.useFakeTimers();
    const f = fixture({ "content-type": "application/json" });
    let settled: unknown;
    const pending = attempt().then(
      (value) => {
        settled = value;
      },
      (error: unknown) => {
        settled = error;
      }
    );
    f.receive();
    try {
      for (let i = 0; i < 4; i += 1) {
        f.response.emit("data", Buffer.from(" "));
        await vi.advanceTimersByTimeAsync(40);
      }
      expect(settled).toMatchObject({ code: "cimd_timeout" });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      f.request.destroy();
      await vi.advanceTimersByTimeAsync(0);
      await pending;
    }
  });

  it("accepts exactly bounded completed bytes and leaves no deadline or destruction", async () => {
    vi.useFakeTimers();
    const f = fixture({ "content-type": "application/json", "content-length": "1024" });
    const pending = attempt();
    f.receive();
    f.response.emit("data", Buffer.alloc(512, "a"));
    await vi.advanceTimersByTimeAsync(40);
    f.response.emit("data", Buffer.alloc(512, "b"));
    f.response.emit("end");
    await expect(pending).resolves.toMatchObject({
      statusCode: 200,
      contentType: "application/json",
      body: Buffer.concat([Buffer.alloc(512, "a"), Buffer.alloc(512, "b")])
    });
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(200);
    expect(f.request.destroy).not.toHaveBeenCalled();
    expect(f.response.destroy).not.toHaveBeenCalled();
    f.response.emit("close");
    f.request.emit("close");
  });

  it.each(["error", "aborted", "close"] as const)(
    "refuses response %s before completion and ignores late data/end/errors",
    async (event) => {
      vi.useFakeTimers();
      const f = fixture();
      const marker = new Error("synthetic response failure");
      const pending = attempt().catch((error: unknown) => error);
      f.receive();
      f.response.emit("data", Buffer.from("prefix"));
      f.response.emit(event, marker);
      const error = await pending;
      if (event === "error") expect(error).toBe(marker);
      else expect(error).toMatchObject({ code: "cimd_response_refused" });
      expect(f.request.destroy).toHaveBeenCalledTimes(1);
      expect(f.response.destroy).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
      f.response.emit("data", Buffer.from("late"));
      f.response.emit("end");
      f.response.emit("error", new Error("late response failure"));
      f.request.emit("error", new Error("late request failure"));
      await vi.advanceTimersByTimeAsync(0);
      expect(await pending).toBe(error);
    }
  );

  it.each(["error", "close"] as const)(
    "cleans up a request %s before any response",
    async (event) => {
      vi.useFakeTimers();
      const f = fixture();
      const marker = new Error("synthetic request failure");
      const pending = attempt().catch((error: unknown) => error);
      f.request.emit(event, marker);
      const error = await pending;
      if (event === "error") expect(error).toBe(marker);
      else expect(error).toMatchObject({ code: "cimd_fetch_failed" });
      expect(vi.getTimerCount()).toBe(0);
      expect(f.request.destroy).toHaveBeenCalledTimes(1);
      f.receive();
      expect(f.response.errorListenerPresentAtDestruction).toBe(true);
      await vi.advanceTimersByTimeAsync(0);
      expect(await pending).toBe(error);
    }
  );

  it("refuses streamed bytes beyond the limit and cannot later resolve", async () => {
    vi.useFakeTimers();
    const f = fixture();
    const pending = attempt().catch((error: unknown) => error);
    f.receive();
    f.response.emit("data", Buffer.alloc(1024));
    f.response.emit("data", Buffer.from("x"));
    f.response.emit("end");
    await expect(pending).resolves.toMatchObject({ code: "client_metadata_size_refused" });
    expect(f.response.errorListenerPresentAtDestruction).toBe(true);
    expect(f.request.destroy).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("times out before headers and destroys a subsequently arriving response safely", async () => {
    vi.useFakeTimers();
    const f = fixture();
    const pending = attempt().catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(101);
    await expect(pending).resolves.toMatchObject({ code: "cimd_timeout" });
    expect(f.request.destroy).toHaveBeenCalledTimes(1);
    f.receive();
    expect(f.response.errorListenerPresentAtDestruction).toBe(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not open a request for an already cancelled attempt", async () => {
    vi.useFakeTimers();
    fixture();
    const controller = new AbortController();
    controller.abort();
    await expect(attempt(controller.signal)).rejects.toMatchObject({ code: "cimd_timeout" });
    expect(mocked.request).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels both streams at the shared deadline and removes its abort listener", async () => {
    vi.useFakeTimers();
    const f = fixture();
    const controller = new AbortController();
    const removeListener = vi.spyOn(controller.signal, "removeEventListener");
    const pending = attempt(controller.signal).catch((error: unknown) => error);
    f.receive();
    controller.abort();
    await expect(pending).resolves.toMatchObject({ code: "cimd_timeout" });
    expect(f.request.destroy).toHaveBeenCalledTimes(1);
    expect(f.response.destroy).toHaveBeenCalledTimes(1);
    expect(removeListener).toHaveBeenCalledWith("abort", expect.any(Function));
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(["request", "end"] as const)(
    "clears the deadline when %s throws synchronously",
    async (phase) => {
      vi.useFakeTimers();
      const f = fixture();
      const marker = new Error("synthetic synchronous failure");
      const fail = () => {
        throw marker;
      };
      if (phase === "request") mocked.request.mockImplementation(fail);
      else f.request.end.mockImplementation(fail);
      await expect(attempt()).rejects.toBe(marker);
      expect(vi.getTimerCount()).toBe(0);
    }
  );
});
