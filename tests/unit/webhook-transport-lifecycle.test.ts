import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({ request: vi.fn() }));
// Replace HTTPS before importing the transport: these tests cannot open sockets.
vi.mock("node:https", () => ({ request: mocked.request }));

import { HttpsWebhookDeliveryTransport } from "../../artifacts/server/src/notification-worker.js";
import { WebhookPreconnectError } from "../../artifacts/server/src/webhook-attempt.js";
import { sha256Hex } from "../../lib/contracts/src/index.js";

function fixture() {
  const response = Object.assign(new EventEmitter(), { statusCode: 200, destroy: vi.fn() });
  const request = Object.assign(new EventEmitter(), {
    destroyed: false,
    end: vi.fn(),
    setTimeout: vi.fn(),
    destroy(error?: Error) {
      this.destroyed = true;
      queueMicrotask(() => request.emit("error", error ?? new Error("test cleanup")));
      return this;
    }
  });
  let receive: (() => void) | undefined;
  mocked.request.mockImplementation((_endpoint, _options, callback) => {
    receive = () => callback(response);
    return request;
  });
  const controller = new AbortController();
  const input = {
    endpoint: "https://synthetic-webhook.example/wake",
    address: "93.184.216.34",
    headers: {},
    body: Buffer.from("synthetic wake"),
    signal: controller.signal
  };
  return { request, response, input, controller, receive: () => receive?.() };
}

afterEach(() => {
  vi.useRealTimers();
  mocked.request.mockReset();
});

describe("in-memory webhook transport lifecycle", () => {
  it.each(["ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH"])(
    "marks a matching %s failure before TCP connection as fallback-safe",
    async (code) => {
      const f = fixture();
      const outcome = new HttpsWebhookDeliveryTransport(100)
        .deliver(f.input)
        .catch((error: unknown) => error);
      f.request.emit("socket", Object.assign(new EventEmitter(), { connecting: true }));
      f.request.emit(
        "error",
        Object.assign(new Error("synthetic refusal"), {
          code,
          syscall: "connect",
          address: f.input.address,
          port: 443
        })
      );
      expect(await outcome).toBeInstanceOf(WebhookPreconnectError);
      expect(f.request.destroyed).toBe(true);
    }
  );

  it("does not mark a connect error safe when its socket was already connected", async () => {
    const f = fixture();
    const outcome = new HttpsWebhookDeliveryTransport(100)
      .deliver(f.input)
      .catch((error: unknown) => error);
    f.request.emit("socket", Object.assign(new EventEmitter(), { connecting: false }));
    f.request.emit(
      "error",
      Object.assign(new Error("synthetic refusal"), {
        code: "ECONNREFUSED",
        syscall: "connect",
        address: f.input.address,
        port: 443
      })
    );
    expect(await outcome).not.toBeInstanceOf(WebhookPreconnectError);
  });

  it("handles an abort during request creation before ending the body", async () => {
    const f = fixture();
    const create = mocked.request.getMockImplementation()!;
    mocked.request.mockImplementation((...args: unknown[]) => {
      const result = create(...args);
      f.controller.abort();
      return result;
    });
    const outcome = new HttpsWebhookDeliveryTransport(100)
      .deliver(f.input)
      .catch((error: unknown) => error);
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.request.end).not.toHaveBeenCalled();
    expect(f.request.destroyed).toBe(true);
  });

  it("destroys a response arriving after cancellation without changing the result", async () => {
    const f = fixture();
    const outcome = new HttpsWebhookDeliveryTransport(100)
      .deliver(f.input)
      .catch((error: unknown) => error);
    f.controller.abort();
    f.receive();
    f.response.emit("error", new Error("synthetic late response"));
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.response.destroy).toHaveBeenCalledTimes(1);
  });

  it("cleans up a synchronous request construction failure", async () => {
    vi.useFakeTimers();
    const f = fixture();
    mocked.request.mockImplementation(() => {
      throw new Error("synthetic construction failure");
    });
    const outcome = new HttpsWebhookDeliveryTransport(100)
      .deliver(f.input)
      .catch((error: unknown) => error);
    expect(await outcome).toMatchObject({ message: "synthetic construction failure" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("accepts exactly the response byte limit and cleans progress listeners", async () => {
    const f = fixture();
    const socket = Object.assign(new EventEmitter(), { connecting: true });
    const outcome = new HttpsWebhookDeliveryTransport(100, 1).deliver(f.input);
    f.request.emit("socket", socket);
    socket.emit("connect");
    f.receive();
    f.response.emit("data", Buffer.from("."));
    f.response.emit("end");
    await expect(outcome).resolves.toMatchObject({ responseSha256: sha256Hex(".") });
    expect(socket.listenerCount("connect")).toBe(0);
    expect(socket.listenerCount("secureConnect")).toBe(0);
    expect(f.request.listenerCount("socket")).toBe(0);
    expect(f.request.listenerCount("finish")).toBe(0);
    expect(f.response.listenerCount("data")).toBe(0);
  });

  it.each(["connect", "secureConnect", "finish", "response"] as const)(
    "refuses fallback after %s even for a connect-shaped error",
    async (progress) => {
      const f = fixture();
      const socket = Object.assign(new EventEmitter(), { connecting: true });
      const outcome = new HttpsWebhookDeliveryTransport(100)
        .deliver(f.input)
        .catch((error: unknown) => error);
      f.request.emit("socket", socket);
      if (progress === "response") f.receive();
      else if (progress === "finish") f.request.emit("finish");
      else socket.emit(progress);
      f.request.emit(
        "error",
        Object.assign(new Error("synthetic refusal"), {
          code: "ECONNREFUSED",
          syscall: "connect",
          address: f.input.address,
          port: 443
        })
      );
      expect(await outcome).not.toBeInstanceOf(WebhookPreconnectError);
    }
  );

  it.each([
    { code: "ECONNRESET", syscall: "connect" },
    { code: "ETIMEDOUT", syscall: "connect" },
    { code: "ERR_TLS_CERT_ALTNAME_INVALID", syscall: "connect" },
    { code: "ECONNREFUSED", syscall: "write" },
    { code: "ECONNREFUSED", syscall: "connect", address: "93.184.216.35" },
    { code: "ECONNREFUSED", syscall: "connect", port: 8443 }
  ])("refuses ambiguous or mismatched preconnection errors: %j", async (fields) => {
    const f = fixture();
    const outcome = new HttpsWebhookDeliveryTransport(100)
      .deliver(f.input)
      .catch((error: unknown) => error);
    f.request.emit("socket", Object.assign(new EventEmitter(), { connecting: true }));
    f.request.emit(
      "error",
      Object.assign(new Error("synthetic failure"), {
        address: f.input.address,
        port: 443,
        ...fields
      })
    );
    expect(await outcome).not.toBeInstanceOf(WebhookPreconnectError);
  });

  it.each(["abort", "oversize", "aborted-response", "closed-response"] as const)(
    "settles %s before a late response end can report success",
    async (failure) => {
      const f = fixture();
      const outcome = new HttpsWebhookDeliveryTransport(100, 1)
        .deliver(f.input)
        .catch((error: unknown) => error);
      f.receive();
      if (failure === "abort") f.controller.abort();
      else if (failure === "oversize") f.response.emit("data", Buffer.from("too large"));
      else if (failure === "aborted-response") f.response.emit("aborted");
      else f.response.emit("close");
      f.response.emit("end");
      expect(await outcome).toBeInstanceOf(Error);
      expect(f.request.destroyed).toBe(true);
    }
  );

  it("cleans up after a synchronous request end failure", async () => {
    vi.useFakeTimers();
    const f = fixture();
    f.request.end.mockImplementation(() => {
      throw new Error("synthetic end failure");
    });
    const outcome = new HttpsWebhookDeliveryTransport(100)
      .deliver(f.input)
      .catch((error: unknown) => error);
    expect(await outcome).toBeInstanceOf(Error);
    expect(vi.getTimerCount()).toBe(0);
    expect(f.request.destroyed).toBe(true);
  });

  it("keeps the exact endpoint and returns only its pinned address to either lookup callback", async () => {
    const f = fixture();
    const outcome = new HttpsWebhookDeliveryTransport(100).deliver(f.input);
    const options = mocked.request.mock.calls[0]?.[1];
    expect(mocked.request.mock.calls[0]?.[0]).toBe(f.input.endpoint);
    expect(options).toMatchObject({ agent: false, method: "POST", family: 4 });
    expect(options).not.toHaveProperty("rejectUnauthorized", false);
    expect(options).not.toHaveProperty("checkServerIdentity");
    const one = vi.fn(),
      all = vi.fn();
    options.lookup("synthetic-webhook.example", {}, one);
    options.lookup("synthetic-webhook.example", { all: true }, all);
    expect(one).toHaveBeenCalledWith(null, f.input.address, 4);
    expect(all).toHaveBeenCalledWith(null, [{ address: f.input.address, family: 4 }]);
    f.receive();
    f.response.emit("end");
    await outcome;
  });
  it("refuses an already-aborted attempt without creating or ending a request", async () => {
    const f = fixture();
    f.controller.abort();
    const attempted = new HttpsWebhookDeliveryTransport(100).deliver(f.input);
    const outcome = attempted.catch((error: unknown) => error);
    try {
      expect(mocked.request).not.toHaveBeenCalled();
      expect(f.request.end).not.toHaveBeenCalled();
      expect(await outcome).toBeInstanceOf(Error);
    } finally {
      if (mocked.request.mock.calls.length > 0) f.request.destroy();
      await outcome;
    }
  });

  it("enforces a total deadline despite response chunks that keep the socket active", async () => {
    vi.useFakeTimers();
    const f = fixture();
    let settled: unknown;
    const outcome = new HttpsWebhookDeliveryTransport(100).deliver(f.input).then(
      (value) => {
        settled = value;
      },
      (error: unknown) => {
        settled = error;
      }
    );
    f.receive();
    try {
      for (let index = 0; index < 4; index += 1) {
        f.response.emit("data", Buffer.from("."));
        await vi.advanceTimersByTimeAsync(40);
      }
      expect(settled).toBeInstanceOf(Error);
      expect(f.request.destroyed).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      f.request.destroy();
      await vi.advanceTimersByTimeAsync(0);
      await outcome;
    }
  });

  it("returns exact response evidence and clears deadline and abort handling on completion", async () => {
    vi.useFakeTimers();
    const f = fixture();
    const outcome = new HttpsWebhookDeliveryTransport(100).deliver(f.input);
    f.receive();
    f.response.emit("data", Buffer.from("accepted"));
    f.response.emit("end");
    await expect(outcome).resolves.toEqual({
      statusCode: 200,
      responseSha256: sha256Hex("accepted")
    });
    f.controller.abort();
    await vi.advanceTimersByTimeAsync(200);
    expect(f.request.destroyed).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });
});
