import type { ResponseAllocationOwner } from "./response-allocation.js";
import { AsyncLocalStorage } from "node:async_hooks";
import { isDeepStrictEqual } from "node:util";

export interface ResourceDeliveryOutcome {
  readonly outcome: "completed" | "interrupted";
  readonly bytesTransferred: number | null;
  readonly responseBytesQueued: number;
  readonly observationBasis:
    "node_response_finish" | "node_response_interruption" | "response_not_associated";
}

export interface PreparedResourceDelivery {
  readonly preparedEventId: string;
  readonly byteLength: number;
  readonly record: (outcome: ResourceDeliveryOutcome) => Promise<void>;
}

const preparedResults = new WeakMap<object, PreparedResourceDelivery>();
const activeDelivery = new AsyncLocalStorage<ResourceDeliveryCollector>();

export function attachPreparedResource<T extends object>(
  result: T,
  prepared: PreparedResourceDelivery
): T {
  preparedResults.set(result, prepared);
  return result;
}

interface RegisteredDelivery {
  readonly prepared: PreparedResourceDelivery;
  readonly requestId: string | number;
  expectedResult: Readonly<Record<string, unknown>> | null;
  associated: boolean;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Called only after the MCP callback has validated and constructed its result.
// Nothing from this map or collector is serialized onto the public surface.
export function registerResourceResponse(
  source: object,
  requestId: string | number,
  expectedResult: Readonly<Record<string, unknown>>
): void {
  const prepared = preparedResults.get(source);
  if (prepared) activeDelivery.getStore()?.register(prepared, requestId, expectedResult);
}

export function registerPreparedResource(source: object, requestId: string | number): void {
  const prepared = preparedResults.get(source);
  if (prepared) activeDelivery.getStore()?.register(prepared, requestId, null);
}

export class ResourceDeliveryCollector {
  private readonly deliveries = new Map<string, RegisteredDelivery>();
  private settled = false;
  private response: Response | undefined;
  private responseAccepted = false;
  private transportFailed = false;
  private readonly terminalCounts = new Map<string | number, number>();
  private readonly pendingSends = new Set<Promise<void>>();
  private settlement: Promise<readonly Error[]> | undefined;
  public constructor(private readonly allocationOwner?: ResponseAllocationOwner) {}

  public run<T>(work: () => T): T {
    return activeDelivery.run(this, work);
  }

  public get hasPreparedResources(): boolean {
    return this.deliveries.size > 0;
  }

  public register(
    prepared: PreparedResourceDelivery,
    requestId: string | number,
    expectedResult: Readonly<Record<string, unknown>> | null
  ): void {
    if (this.settled) throw new Error("resource delivery observation already settled");
    const existing = this.deliveries.get(prepared.preparedEventId);
    if (existing) {
      if (existing.prepared !== prepared || existing.requestId !== requestId)
        throw new Error("ambiguous prepared resource response binding");
      if ((this.terminalCounts.get(requestId) ?? 0) > 0) {
        existing.expectedResult = null;
        existing.associated = false;
      } else if (expectedResult !== null) existing.expectedResult = structuredClone(expectedResult);
      return;
    }
    this.deliveries.set(prepared.preparedEventId, {
      prepared,
      requestId,
      expectedResult:
        expectedResult === null || (this.terminalCounts.get(requestId) ?? 0) > 0
          ? null
          : structuredClone(expectedResult),
      associated: false
    });
  }

  public bindResponse(response: Response): void {
    if (this.response !== undefined && this.response !== response) this.transportFailed = true;
    this.response = response;
  }

  public acceptResponse(response: Response): void {
    const mediaType = response.headers.get("content-type")?.split(";")[0]?.trim();
    this.responseAccepted =
      response === this.response &&
      response.status >= 200 &&
      response.status < 300 &&
      (mediaType === "application/json" || mediaType === "text/event-stream");
  }

  public transportError(): void {
    this.transportFailed = true;
  }

  // The SDK has already validated/encoded the terminal message. The pinned
  // transports serialize it synchronously inside send; no await separates this
  // comparison from that invocation. Never infer success merely from send resolving:
  // original response identity, eligible headers, and Node finish are also required.
  public send(message: unknown, send: () => Promise<void>): Promise<void> {
    if (!object(message) || !("result" in message || "error" in message)) return send();
    const id = message["id"];
    if (typeof id !== "string" && typeof id !== "number") return send();
    const count = (this.terminalCounts.get(id) ?? 0) + 1;
    this.terminalCounts.set(id, count);
    for (const delivery of this.deliveries.values()) {
      if (delivery.requestId !== id) continue;
      delivery.associated = count === 1 && this.matchesResult(delivery, message);
      // The first actual terminal comparison is final. Keep the small handle/count;
      // do not retain the complete structured clone through native drain/audit I/O.
      delivery.expectedResult = null;
    }
    let operation: Promise<void>;
    try {
      operation = send();
    } catch (error) {
      this.transportError();
      throw error;
    }
    const result = operation.catch((error: unknown) => {
      this.transportError();
      throw error;
    });
    const tracked = result.catch(() => undefined);
    this.pendingSends.add(tracked);
    void tracked.then(() => this.pendingSends.delete(tracked));
    return result;
  }

  private matchesResult(delivery: RegisteredDelivery, message: Record<string, unknown>): boolean {
    if (delivery.expectedResult === null || message["jsonrpc"] !== "2.0" || "error" in message)
      return false;
    const result = message["result"];
    if (
      !object(result) ||
      (result["isError"] !== undefined && result["isError"] !== false) ||
      (result["resultType"] !== undefined && result["resultType"] !== "complete")
    )
      return false;
    return Object.entries(delivery.expectedResult).every(([key, value]) =>
      isDeepStrictEqual(result[key], value)
    );
  }

  // Existing direct repository probes can explicitly verify a decoded response.
  // Native HTTP does not decode, clone, or buffer a second response body.
  public verifyResponse(status: number, contentType: string | null, body: unknown): void {
    this.responseAccepted = true;
    const messages = Array.isArray(body) ? body : [body];
    for (const delivery of this.deliveries.values()) {
      delivery.associated = false;
      if (delivery.expectedResult === null) continue;
      if (
        status < 200 ||
        status >= 300 ||
        contentType?.split(";")[0]?.trim() !== "application/json"
      )
        continue;
      const matches = messages.filter(
        (message) => object(message) && message["id"] === delivery.requestId
      );
      if (matches.length !== 1) continue;
      const message = matches[0];
      if (object(message)) delivery.associated = this.matchesResult(delivery, message);
      delivery.expectedResult = null;
    }
  }

  public settle(
    outcome: "completed" | "interrupted",
    responseBytesQueued: number,
    responseWriteAttempted = responseBytesQueued > 0
  ): Promise<readonly Error[]> {
    this.settlement ??= this.finishSettlement(outcome, responseBytesQueued, responseWriteAttempted);
    return this.settlement;
  }

  private async finishSettlement(
    outcome: "completed" | "interrupted",
    responseBytesQueued: number,
    responseWriteAttempted: boolean
  ): Promise<readonly Error[]> {
    // A disconnected HTTP exchange can end while its DB/SDK producer is alive.
    await this.allocationOwner?.whenProducersDone();
    this.settled = true;
    await Promise.all(this.pendingSends);
    const preparedDeliveries = [...this.deliveries.values()].map(({ prepared, associated }) => ({
      prepared,
      associated
    }));
    for (const delivery of this.deliveries.values()) delivery.expectedResult = null;
    this.deliveries.clear();
    this.terminalCounts.clear();
    this.pendingSends.clear();
    this.response = undefined;
    const failures: Error[] = [];
    for (const { prepared, associated } of preparedDeliveries) {
      const bound = associated && this.responseAccepted && !this.transportFailed;
      const complete = bound && outcome === "completed";
      try {
        await prepared.record({
          outcome: complete ? "completed" : "interrupted",
          bytesTransferred: complete ? prepared.byteLength : responseWriteAttempted ? null : 0,
          responseBytesQueued,
          observationBasis: !bound
            ? "response_not_associated"
            : complete
              ? "node_response_finish"
              : "node_response_interruption"
        });
      } catch (error) {
        failures.push(error instanceof Error ? error : new Error("resource outcome audit failed"));
      }
    }
    this.allocationOwner?.collectorSettled();
    return failures;
  }
}

export function currentResourceDeliveryCollector(): ResourceDeliveryCollector | undefined {
  return activeDelivery.getStore();
}

export function bindResourceDeliveryResponse(response: Response): Response {
  activeDelivery.getStore()?.bindResponse(response);
  return response;
}
