import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { z } from "zod";
import { describe, expect, it } from "vitest";
import { ResourceObservedMcpServer } from "../../artifacts/server/src/resource-delivery-transport.js";
import { ResourceDeliveryCollector } from "../../artifacts/server/src/resource-delivery.js";
import {
  ResponseAllocationManager,
  loadWithResponseAllocation,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
const sourcePlan = responseAllocationPlan({
  kind: "document",
  representation: "tool",
  sourceId: "synthetic-version",
  sourceVersion: "1",
  sha256: "a".repeat(64),
  canonicalBytes: 10_485_760
});

describe("SDK producer allocation lifetime", () => {
  it.each(["2026-07-28", "2025-11-25"] as const)(
    "holds the lease through actual SDK output validation after callback return (%s)",
    async (version) => {
      const manager = new ResponseAllocationManager();
      const abort = new AbortController();
      const owner = manager.openRequest(abort.signal);
      const collector = new ResourceDeliveryCollector(owner);
      const validationEntered = gate();
      const validationFinish = gate();
      const expectedEra = version === "2025-11-25" ? "legacy" : "modern";
      const servers: ResourceObservedMcpServer[] = [];
      let callbackReturned = false;
      let callbackEra: "modern" | "legacy" | undefined;
      // Use the SDK HTTP classifier and per-request Server setup. Injected fetch
      // keeps the fixture local while the SDK owns framing and era negotiation.
      const handler = createMcpHandler(
        (requestContext) => {
          const instance = new ResourceObservedMcpServer(
            { name: "allocation-lifetime-fixture", version: "1" },
            { supportedProtocolVersions: [version] }
          );
          servers.push(instance);
          instance.registerTool(
            "synthetic_capacity",
            {
              inputSchema: z.object({}),
              // This gate belongs to the pinned SDK's validation after the app callback.
              outputSchema: z.object({ body: z.string() }).superRefine(async () => {
                validationEntered.release();
                await validationFinish.promise;
              })
            },
            async () => {
              await loadWithResponseAllocation(sourcePlan, async () => "synthetic-small-body");
              callbackEra = requestContext.era;
              callbackReturned = true;
              return {
                content: [{ type: "text", text: "synthetic-small-body" }],
                structuredContent: { body: "synthetic-small-body" }
              };
            }
          );
          return instance;
        },
        { legacy: "stateless", responseMode: "json", maxSubscriptions: 0, keepAliveMs: 0 }
      );
      const transport = new StreamableHTTPClientTransport(
        new URL("https://allocation-fixture.test/mcp"),
        {
          fetch: (input, init) =>
            owner.run(() => collector.run(() => handler.fetch(new Request(input, init))))
        }
      );
      const client = new Client(
        { name: "allocation-lifetime-client", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: version === "2025-11-25" ? "legacy" : { pin: version } }
        }
      );
      try {
        await client.connect(transport);
        expect(client.getNegotiatedProtocolVersion()).toBe(version);
        expect(client.getProtocolEra()).toBe(expectedEra);
        if (expectedEra === "modern") expect(client.getDiscoverResult()).toBeDefined();
        else expect(client.getDiscoverResult()).toBeUndefined();
        const call = client
          .callTool({ name: "synthetic_capacity", arguments: {} })
          .catch((error: unknown) => error);
        await Promise.race([
          validationEntered.promise,
          call.then(() => {
            throw new Error("tool completed before the SDK output-validation gate");
          })
        ]);
        expect(callbackReturned).toBe(true);
        expect(callbackEra).toBe(expectedEra);
        // These lifecycle markers are synthetic. The separate native HTTPS
        // fixture owns proof of actual socket interruption and collector cleanup.
        abort.abort();
        owner.nativeTerminal();
        const settlement = collector.settle("interrupted", 0, false);
        await Promise.resolve();
        expect(manager.accounting.usedUnits).toBe(1_281);
        await client.close();
        validationFinish.release();
        await settlement;
        await call;
        expect(manager.accounting.usedUnits).toBe(0);
      } finally {
        validationFinish.release();
        await client.close();
        await handler.close();
        await Promise.all(servers.map((server) => server.close()));
      }
    }
  );

  it("refuses constructor options that would register eager handlers on a discarded base Server", () => {
    expect(
      () =>
        new ResourceObservedMcpServer(
          { name: "fixture", version: "1" },
          { capabilities: { tools: {} } }
        )
    ).toThrow("deferred capability registration");
  });
});
