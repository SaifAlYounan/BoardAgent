import { describe, expect, it, vi } from "vitest";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  loadWithResponseAllocation
} from "../../artifacts/server/src/response-allocation.js";
import { ResourceDeliveryCollector } from "../../artifacts/server/src/resource-delivery.js";

const plan = (
  kind: "document" | "export",
  bytes: number,
  representation: "tool" | "resource" = "tool"
) =>
  responseAllocationPlan({
    kind,
    representation,
    canonicalBytes: bytes,
    sourceId: "synthetic-immutable-id",
    sourceVersion: "version-7",
    sha256: "a".repeat(64)
  });
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

describe("private response allocation", () => {
  it("reserves proportional units, shares tool/resource accounting and keeps 100 small reads eligible", () => {
    const manager = new ResponseAllocationManager();
    const leases = [];
    for (;;) {
      try {
        leases.push(
          manager.tryReserve(plan("export", 1_048_576, leases.length % 2 ? "tool" : "resource"))
        );
      } catch (error) {
        expect(error).toBeInstanceOf(ResponseAllocationUnavailable);
        break;
      }
    }
    expect(manager.accounting.largeUsedUnits).toBe(1_885);
    for (let index = 0; index < 100; index += 1)
      leases.push(manager.tryReserve(plan("document", 4_096, index % 2 ? "tool" : "resource")));
    expect(manager.accounting.usedUnits).toBe(1_985);
    for (const lease of leases) {
      lease.release();
      lease.release();
    }
    expect(manager.accounting).toEqual({ usedUnits: 0, largeUsedUnits: 0 });
  });

  it("refuses before calling a content/storage loader and allows a later request after release", async () => {
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(plan("document", 10_485_760));
    const owner = manager.openRequest(new AbortController().signal);
    const load = vi.fn(async () => "never materialized");
    await expect(
      owner.produce(() =>
        loadWithResponseAllocation(plan("document", 10_485_760, "resource"), load)
      )
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(load).not.toHaveBeenCalled();
    owner.nativeTerminal();
    owner.collectorSettled();
    held.release();
    const retry = manager.openRequest(new AbortController().signal);
    await expect(
      retry.produce(() => loadWithResponseAllocation(plan("document", 10_485_760), load))
    ).resolves.toBe("never materialized");
    expect(load).toHaveBeenCalledTimes(1);
    retry.nativeTerminal();
    retry.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("does not accept forged weights or unsafe metadata arithmetic", () => {
    const manager = new ResponseAllocationManager();
    const maximum = plan("document", 10_485_760);
    const lease = manager.tryReserve({ ...maximum, units: 0 });
    expect(manager.accounting.usedUnits).toBe(1_281);
    for (const bytes of [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      -1,
      1.5,
      Number.MAX_SAFE_INTEGER,
      10_485_761
    ])
      expect(() => plan("document", bytes)).toThrow(RangeError);
    lease.release();
  });

  it("rejects later loads after disconnect and keeps an earlier lease charged until producer and collector finish", async () => {
    const manager = new ResponseAllocationManager();
    const controller = new AbortController();
    const owner = manager.openRequest(controller.signal);
    const collector = new ResourceDeliveryCollector(owner);
    const firstLoad = gate();
    const entered = gate();
    const lateLoad = vi.fn(async () => "must not run");
    const producing = owner.produce(async () => {
      await loadWithResponseAllocation(plan("document", 10_485_760), async () => {
        entered.release();
        await firstLoad.promise;
        return "content";
      });
      return loadWithResponseAllocation(plan("export", 1_048_576), lateLoad);
    });
    const observedFailure = producing.catch((error: unknown) => error);
    await entered.promise;
    controller.abort();
    owner.nativeTerminal();
    const settled = collector.settle("interrupted", 0, false);
    await Promise.resolve();
    expect(manager.accounting.usedUnits).toBe(1_281);
    expect(() => manager.tryReserve(plan("document", 10_485_760))).toThrow(
      ResponseAllocationUnavailable
    );
    firstLoad.release();
    expect(await observedFailure).toBeInstanceOf(ResponseAllocationUnavailable);
    await settled;
    expect(lateLoad).not.toHaveBeenCalled();
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("does not release merely because the producer or native writer finishes", async () => {
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    await owner.produce(() =>
      loadWithResponseAllocation(plan("export", 1_048_576), async () => "content")
    );
    expect(manager.accounting.usedUnits).toBe(65);
    owner.nativeTerminal();
    expect(manager.accounting.usedUnits).toBe(65);
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("fails closed if a selected loader is called without the native request owner", async () => {
    const load = vi.fn(async () => "not loaded");
    await expect(loadWithResponseAllocation(plan("document", 1), load)).rejects.toThrow(
      "native response allocation owner"
    );
    expect(load).not.toHaveBeenCalled();
  });
});
