import type { JsonValue } from "../../lib/contracts/src/index.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import { ResponseAllocationManager } from "../../artifacts/server/src/response-allocation.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";

// Direct repository fixtures have no native HTTP exchange or SDK producer wrapper.
// This synthetic owner scopes allocation to the awaited repository operation only.
// Closing its two lifecycle flags records no resource-delivery audit or HTTP outcome.
export async function withDirectResponseAllocation<T>(read: () => Promise<T>): Promise<T> {
  const manager = new ResponseAllocationManager();
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(read);
  } finally {
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}

/**
 * Direct-fixture read repository: every read runs under its own synthetic allocation
 * owner, exactly one per awaited operation, as the native HTTP request boundary does.
 * Test-only; the runtime never constructs this class.
 */
export class DirectReadRepository extends PgSurfaceReadRepository {
  public override executeRead(
    principal: SurfacePrincipal,
    tool: string,
    rawInput: JsonValue
  ): ReturnType<PgSurfaceReadRepository["executeRead"]> {
    return withDirectResponseAllocation(() => super.executeRead(principal, tool, rawInput));
  }

  public override readResource(
    principal: SurfacePrincipal,
    uri: URL
  ): ReturnType<PgSurfaceReadRepository["readResource"]> {
    return withDirectResponseAllocation(() => super.readResource(principal, uri));
  }
}

/**
 * In-process MCP handler fixtures: open one request owner around each handler fetch,
 * mirroring `http-runtime.ts` (`admission.openRequest` → `owner.run(mcp.fetch)`), then
 * close its two lifecycle flags once the response is produced. No delivery audit.
 */
export async function fetchWithDirectRequestOwner(
  fetch: () => Promise<Response>
): Promise<Response> {
  const manager = new ResponseAllocationManager();
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.run(fetch);
  } finally {
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}
