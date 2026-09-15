import { describe, expect, it } from "vitest";
import type { Transport } from "@modelcontextprotocol/server";
import { ResourceObservedMcpServer } from "../../artifacts/server/src/resource-delivery-transport.js";

import {
  ResourceDeliveryCollector,
  attachPreparedResource,
  registerPreparedResource,
  registerResourceResponse,
  type ResourceDeliveryOutcome
} from "../../artifacts/server/src/resource-delivery.js";

function fixture(id = "prepared-one", text = 'exact "source"\nΔ') {
  const observations: ResourceDeliveryOutcome[] = [];
  const prepared = {
    preparedEventId: id,
    byteLength: Buffer.byteLength(text),
    record: async (outcome: ResourceDeliveryOutcome) => {
      observations.push(outcome);
    }
  };
  const source = attachPreparedResource({ text }, prepared);
  const output = { contents: [{ uri: "board://synthetic", mimeType: "text/plain", text }] };
  const collector = new ResourceDeliveryCollector();
  collector.run(() => {
    registerPreparedResource(source, 41);
    registerResourceResponse(source, 41, output);
  });
  const message = { jsonrpc: "2.0", id: 41, result: output };
  return { collector, source, output, message, prepared, observations };
}

describe("private resource delivery observations", () => {
  it("accepts the pinned modern SDK complete result discriminator", async () => {
    const f = fixture();
    f.collector.verifyResponse(200, "application/json", {
      ...f.message,
      result: { ...f.output, resultType: "complete" }
    });
    await f.collector.settle("completed", 100);
    expect(f.observations[0]?.outcome).toBe("completed");
  });

  it("binds the actual successful response and records only server handoff once", async () => {
    const f = fixture();
    f.collector.verifyResponse(200, "application/json", f.message);
    expect(await f.collector.settle("completed", 800)).toEqual([]);
    expect(await f.collector.settle("interrupted", 801)).toEqual([]);
    expect(f.observations).toEqual([
      {
        outcome: "completed",
        bytesTransferred: f.prepared.byteLength,
        responseBytesQueued: 800,
        observationBasis: "node_response_finish"
      }
    ]);
  });

  it("records unknown canonical bytes after a partial wrapped response", async () => {
    const f = fixture();
    f.collector.verifyResponse(200, "application/json", f.message);
    await f.collector.settle("interrupted", 7);
    expect(f.observations[0]).toMatchObject({
      outcome: "interrupted",
      bytesTransferred: null,
      responseBytesQueued: 7,
      observationBasis: "node_response_interruption"
    });
  });

  it("distinguishes a pre-write interruption from a throwing write attempt", async () => {
    const before = fixture();
    const attempted = fixture();
    before.collector.verifyResponse(200, "application/json", before.message);
    attempted.collector.verifyResponse(200, "application/json", attempted.message);
    await before.collector.settle("interrupted", 0, false);
    await attempted.collector.settle("interrupted", 0, true);
    expect(before.observations[0]?.bytesTransferred).toBe(0);
    expect(attempted.observations[0]?.bytesTransferred).toBeNull();
  });

  it.each([
    ["SDK error", { jsonrpc: "2.0", id: 41, error: { code: -32603 } }],
    ["wrong request", { jsonrpc: "2.0", id: 42, result: { contents: [] } }],
    ["changed result", { jsonrpc: "2.0", id: 41, result: { contents: [] } }],
    [
      "duplicate request IDs",
      [
        { jsonrpc: "2.0", id: 41, result: {} },
        { jsonrpc: "2.0", id: 41, result: {} }
      ]
    ]
  ])("never completes %s even when HTTP finishes", async (_label, message) => {
    const f = fixture();
    f.collector.verifyResponse(200, "application/json", message);
    await f.collector.settle("completed", 100);
    expect(f.observations[0]).toMatchObject({
      outcome: "interrupted",
      bytesTransferred: null,
      observationBasis: "response_not_associated"
    });
  });

  it("does not arm an error result or unsuccessful HTTP status", async () => {
    for (const variant of ["error", "typed-error", "status", "content-type"]) {
      const f = fixture();
      f.collector.verifyResponse(
        variant === "status" ? 500 : 200,
        variant === "content-type" ? "text/event-stream" : "application/json",
        {
          ...f.message,
          result: {
            ...f.output,
            ...(variant === "error" ? { isError: true } : {}),
            ...(variant === "typed-error" ? { resultType: "input_required" } : {})
          }
        }
      );
      await f.collector.settle("completed", 500);
      expect(f.observations[0]?.outcome).toBe("interrupted");
    }
  });

  it("does not let a post-registration mutation change the bound response", async () => {
    const f = fixture();
    f.output.contents[0]!.text = "substituted source";
    f.collector.verifyResponse(200, "application/json", f.message);
    await f.collector.settle("completed", 100);
    expect(f.observations[0]?.outcome).toBe("interrupted");
  });

  it("keeps unvalidated callback output unassociated", async () => {
    const f = fixture();
    const collector = new ResourceDeliveryCollector();
    collector.run(() => registerPreparedResource(f.source, 41));
    collector.verifyResponse(200, "application/json", f.message);
    await collector.settle("completed", 100);
    expect(f.observations[0]?.outcome).toBe("interrupted");
  });

  it("isolates simultaneous request collectors and serializes no private handle", async () => {
    const one = fixture("one");
    const two = fixture("two");
    const first = new ResourceDeliveryCollector();
    const second = new ResourceDeliveryCollector();
    await Promise.all([
      first.run(async () => {
        await Promise.resolve();
        registerResourceResponse(one.source, 41, one.output);
      }),
      second.run(async () => {
        await Promise.resolve();
        registerResourceResponse(two.source, 42, two.output);
      })
    ]);
    first.verifyResponse(200, "application/json", one.message);
    second.verifyResponse(200, "application/json", { ...two.message, id: 42 });
    await Promise.all([first.settle("completed", 100), second.settle("interrupted", 8)]);
    expect(one.observations[0]?.outcome).toBe("completed");
    expect(two.observations[0]?.bytesTransferred).toBeNull();
    expect(JSON.stringify(one.source)).toBe(JSON.stringify({ text: one.source.text }));
  });

  it("preserves an outcome audit failure and never retries it after handoff", async () => {
    const collector = new ResourceDeliveryCollector();
    const failure = new Error("synthetic outcome append unavailable");
    let calls = 0;
    collector.register(
      {
        preparedEventId: "failure",
        byteLength: 1,
        record: async () => {
          calls += 1;
          throw failure;
        }
      },
      1,
      { contents: [] }
    );
    collector.verifyResponse(200, "application/json", {
      jsonrpc: "2.0",
      id: 1,
      result: { contents: [] }
    });
    const firstSettlement = collector.settle("completed", 99);
    const failures = await firstSettlement;
    expect(failures).toEqual([failure]);
    const repeatedSettlement = collector.settle("completed", 99);
    expect(repeatedSettlement).toBe(firstSettlement);
    expect(await repeatedSettlement).toBe(failures);
    expect(calls).toBe(1);
  });

  it.each(["application/json", "text/event-stream"])(
    "binds the original SDK %s response without consuming it",
    async (mediaType) => {
      const f = fixture();
      const response = new Response("wire bytes remain untouched", {
        headers: { "content-type": mediaType }
      });
      f.collector.bindResponse(response);
      f.collector.acceptResponse(response);
      await f.collector.send(f.message, async () => undefined);
      expect(response.bodyUsed).toBe(false);
      await f.collector.settle("completed", 27);
      expect(f.observations[0]?.outcome).toBe("completed");
      expect(await response.text()).toBe("wire bytes remain untouched");
    }
  );

  it("refuses an identical replacement Response object", async () => {
    const f = fixture();
    const original = Response.json(f.message);
    f.collector.bindResponse(original);
    f.collector.acceptResponse(Response.json(f.message));
    await f.collector.send(f.message, async () => undefined);
    await f.collector.settle("completed", 100);
    expect(f.observations[0]?.observationBasis).toBe("response_not_associated");
  });

  it("waits for a pending send failure after finish and records interruption once", async () => {
    const f = fixture();
    const response = Response.json(f.message);
    f.collector.bindResponse(response);
    f.collector.acceptResponse(response);
    let fail: (reason: Error) => void = () => undefined;
    const operation = f.collector.send(
      f.message,
      () =>
        new Promise<void>((_resolve, reject) => {
          fail = reject;
        })
    );
    const caught = operation.catch((error: unknown) => error);
    const settled = f.collector.settle("completed", 100);
    await Promise.resolve();
    expect(f.observations).toEqual([]);
    const failure = new Error("synthetic transport serialization failure");
    fail(failure);
    expect(await caught).toBe(failure);
    expect(await settled).toEqual([]);
    expect(f.observations[0]?.outcome).toBe("interrupted");
    expect(await f.collector.settle("completed", 100)).toEqual([]);
    expect(f.observations).toHaveLength(1);
  });

  it("does not let duplicate terminals or out-of-band transport errors become completed", async () => {
    for (const fault of ["duplicate", "error"] as const) {
      const f = fixture();
      const response = Response.json(f.message);
      f.collector.bindResponse(response);
      f.collector.acceptResponse(response);
      await f.collector.send(f.message, async () => undefined);
      if (fault === "duplicate") await f.collector.send(f.message, async () => undefined);
      else f.collector.transportError();
      await f.collector.settle("completed", 100);
      expect(f.observations[0]?.outcome).toBe("interrupted");
    }
  });

  it("rejects the unsupported data result discriminator", async () => {
    const f = fixture();
    const response = Response.json(f.message);
    f.collector.bindResponse(response);
    f.collector.acceptResponse(response);
    await f.collector.send(
      { ...f.message, result: { ...f.output, resultType: "data" } },
      async () => undefined
    );
    await f.collector.settle("completed", 100);
    expect(f.observations[0]?.outcome).toBe("interrupted");
  });

  it("ignores related notifications and input-required responses as completion evidence", async () => {
    const f = fixture();
    const response = Response.json(f.message);
    f.collector.bindResponse(response);
    f.collector.acceptResponse(response);
    await f.collector.send(
      { jsonrpc: "2.0", method: "notifications/progress", params: {} },
      async () => undefined
    );
    await f.collector.send(
      { ...f.message, result: { ...f.output, resultType: "input_required" } },
      async () => undefined
    );
    await f.collector.settle("completed", 100);
    expect(f.observations[0]?.outcome).toBe("interrupted");
  });
  it("delegates the public Transport lifecycle, callbacks, session and protocol methods", async () => {
    const collector = new ResourceDeliveryCollector();
    const calls: string[] = [];
    const failure = new Error("synthetic delegated send failure");
    const underlying: Transport = {
      start: async () => {
        calls.push("start");
      },
      close: async () => {
        calls.push("close");
        underlying.onclose?.();
      },
      send: async () => {
        throw failure;
      },
      onerror: () => {
        calls.push("original-error");
      },
      sessionId: "before",
      hasPerRequestStream: true,
      setProtocolVersion: (version) => {
        calls.push(`version:${version}`);
      },
      setSupportedProtocolVersions: (versions) => {
        calls.push(`supported:${versions.join(",")}`);
      }
    };
    const server = new ResourceObservedMcpServer({ name: "transport-observer-test", version: "1" });
    server.server.onerror = () => {
      calls.push("server-error");
    };
    await collector.run(() => server.connect(underlying));
    const delegated = server.server.transport!;
    expect(delegated).not.toBe(underlying);
    expect(delegated.hasPerRequestStream).toBe(true);
    expect(delegated.sessionId).toBe("before");
    delegated.sessionId = "after";
    expect(underlying.sessionId).toBe("after");
    delegated.setProtocolVersion!("2025-11-25");
    expect(delegated.onmessage).toBe(underlying.onmessage);
    expect(delegated.onclose).toBe(underlying.onclose);
    underlying.onerror!(failure);
    await expect(delegated.send({ jsonrpc: "2.0", id: 1, result: {} })).rejects.toBe(failure);
    await server.close();
    expect(calls.filter((value) => value === "start")).toHaveLength(1);
    expect(calls.filter((value) => value === "close")).toHaveLength(1);
    expect(calls).toContain("version:2025-11-25");
    expect(calls.some((value) => value.startsWith("supported:"))).toBe(true);
    expect(calls).toContain("original-error");
    expect(calls).toContain("server-error");
  });
});
