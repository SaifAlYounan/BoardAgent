import {
  McpServer,
  Server,
  type Transport,
  type ServerOptions,
  type Implementation,
  type JSONRPCRequest,
  type Result,
  type ServerContext
} from "@modelcontextprotocol/server";
import { currentResponseAllocationOwner } from "./response-allocation.js";

import {
  currentResourceDeliveryCollector,
  type ResourceDeliveryCollector
} from "./resource-delivery.js";

// Delegate the complete public Transport interface. The SDK still owns the real
// transport, its HTTP response construction, lifecycle and protocol behavior.
function observedTransport(transport: Transport, collector: ResourceDeliveryCollector): Transport {
  return {
    start: () => transport.start(),
    close: () => transport.close(),
    send: (message, options) => collector.send(message, () => transport.send(message, options)),
    get onmessage() {
      return transport.onmessage;
    },
    set onmessage(value) {
      transport.onmessage = value;
    },
    get onclose() {
      return transport.onclose;
    },
    set onclose(value) {
      transport.onclose = value;
    },
    get onerror() {
      return transport.onerror;
    },
    set onerror(value) {
      transport.onerror = (error) => {
        collector.transportError();
        value?.(error);
      };
    },
    get sessionId() {
      return transport.sessionId;
    },
    set sessionId(value) {
      transport.sessionId = value;
    },
    ...(transport.hasPerRequestStream === undefined
      ? {}
      : {
          hasPerRequestStream: transport.hasPerRequestStream
        }),
    ...(transport.setProtocolVersion === undefined
      ? {}
      : {
          setProtocolVersion: (version: string) => transport.setProtocolVersion!(version)
        }),
    ...(transport.setSupportedProtocolVersions === undefined
      ? {}
      : {
          setSupportedProtocolVersions: (versions: string[]) =>
            transport.setSupportedProtocolVersions!(versions)
        })
  };
}

// Both supported SDK HTTP eras call this public method on the factory product.
// Capture the request's collector now; later legacy stream pulls may run outside
// the original AsyncLocalStorage context. Direct SDK clients remain prepared-only.
// The pinned SDK documents _wrapHandler as its protected extension hook. Awaiting
// super's wrapper includes application work, output validation and result projection.
class AllocationObservedServer extends Server {
  protected override _wrapHandler(
    method: string,
    handler: (request: JSONRPCRequest, ctx: ServerContext) => Promise<Result>
  ): (request: JSONRPCRequest, ctx: ServerContext) => Promise<Result> {
    const wrapped = super._wrapHandler(method, handler);
    const owner = currentResponseAllocationOwner();
    if (!owner || (method !== "tools/call" && method !== "resources/read")) return wrapped;
    return (request, ctx) => owner.produce(() => wrapped(request, ctx));
  }
}

export class ResourceObservedMcpServer extends McpServer {
  public override readonly server: AllocationObservedServer;
  public constructor(info: Implementation, options?: ServerOptions) {
    // McpServer eagerly registers handlers only for these capability options. This
    // factory registers them later through public registerTool/registerResource.
    if (
      options?.capabilities?.tools ||
      options?.capabilities?.resources ||
      options?.capabilities?.prompts
    )
      throw new Error("observed MCP factory requires deferred capability registration");
    super(info, options);
    this.server = new AllocationObservedServer(info, options);
  }
  public override connect(transport: Transport): Promise<void> {
    const collector = currentResourceDeliveryCollector();
    return super.connect(collector ? observedTransport(transport, collector) : transport);
  }
}
