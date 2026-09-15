import { describe, expect, it } from "vitest";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

const list = (raw = 0, json = "0", properties = "0", containers = "0") =>
  responseAllocationPlan({
    kind: "communications_list",
    representation: "tool",
    sourceId: "synthetic-page-frontier",
    sourceVersion: "1",
    sha256: "a".repeat(64),
    canonicalBytes: raw,
    listProjection: {
      jsonUpperBytes: json,
      propertyCount: properties,
      objectOrArrayCount: containers
    }
  });

function document(bytes: number) {
  return responseAllocationPlan({
    kind: "document",
    representation: "tool",
    sourceId: "synthetic-document",
    sourceVersion: "1",
    sha256: "b".repeat(64),
    canonicalBytes: bytes
  });
}

describe("communications list allocation growth", () => {
  it("keeps an existing document reservation as a control", () => {
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(document(4_096));
    expect(manager.accounting).toEqual({ usedUnits: 1, largeUsedUnits: 0 });
    held.release();
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("admits inspection before extending the same reservation for encoding", () => {
    const manager = new ResponseAllocationManager();
    const initial = list(5_242_880);
    const held = manager.tryReserve(initial);
    expect(manager.accounting).toEqual({ usedUnits: 641, largeUsedUnits: 641 });
    held.increase(list(5_242_880, "1048576"));
    expect(manager.accounting).toEqual({ usedUnits: 649, largeUsedUnits: 649 });
    held.increase(list(5_242_880, "1048576"));
    expect(manager.accounting.usedUnits).toBe(649);
    held.release();
    held.release();
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("reclassifies the whole lease when a small read grows", () => {
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(list());
    expect(manager.accounting).toEqual({ usedUnits: 1, largeUsedUnits: 0 });
    held.increase(list(0, "131072"));
    expect(manager.accounting).toEqual({ usedUnits: 2, largeUsedUnits: 2 });
    held.release();
    expect(manager.accounting).toEqual({ usedUnits: 0, largeUsedUnits: 0 });
  });

  it("preserves the original lease when growth would consume the small-read reserve", () => {
    const manager = new ResponseAllocationManager();
    const large = manager.tryReserve(list(0, "251514880"));
    expect(manager.accounting.largeUsedUnits).toBe(1919);
    const small = manager.tryReserve(list());
    expect(() => small.increase(list(0, "131072"))).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting).toEqual({ usedUnits: 1920, largeUsedUnits: 1919 });
    large.release();
    small.increase(list(0, "131072"));
    expect(manager.accounting).toEqual({ usedUnits: 2, largeUsedUnits: 2 });
    small.release();
  });

  it("charges only the increase and retains room for 100 small requests", () => {
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(list(0, "131072"));
    const small = Array.from({ length: 100 }, () => manager.tryReserve(document(1)));
    held.increase(list(0, "251645952"));
    expect(manager.accounting).toEqual({ usedUnits: 2020, largeUsedUnits: 1920 });
    expect(() => held.increase(list(0, "251777024"))).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(2020);
    for (const lease of small) lease.release();
    held.release();
  });

  it("recomputes forged weights and rejects a released lease", () => {
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve({ ...list(), units: 0 });
    held.increase({ ...list(0, "131072"), units: 0, wireUpperBytes: 0 });
    expect(manager.accounting.usedUnits).toBe(2);
    held.release();
    expect(() => held.increase(list(0, "262144"))).toThrow();
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("rejects a different payload frontier, raw size, kind or decreasing bound", () => {
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(list(1, "100", "10", "3"));
    for (const next of [
      { ...list(1, "200", "10", "3"), sourceId: "substitute" },
      { ...list(1, "200", "10", "3"), sourceVersion: "2" },
      { ...list(1, "200", "10", "3"), sha256: "c".repeat(64) },
      list(2, "200", "10", "3"),
      list(1, "99", "10", "3"),
      list(1, "100", "9", "3"),
      list(1, "100", "10", "2"),
      document(1)
    ])
      expect(() => held.increase(next)).toThrow();
    expect(manager.accounting.usedUnits).toBe(1);
    held.release();
  });

  it("copies scalar plans and refuses malformed, excessive or overflowing metadata", () => {
    const input = list();
    expect(Object.isFrozen(input)).toBe(true);
    expect(Object.isFrozen(input.listProjection)).toBe(true);
    for (const scalar of ["-1", "01", "1.5", "NaN", "1e6", "", "9".repeat(25)])
      expect(() => list(0, scalar)).toThrow();
    expect(() => list(0, "9007199254740991")).toThrow(ResponseAllocationUnavailable);
    for (const bytes of [-1, 0.5, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER])
      expect(() => list(bytes)).toThrow();
    // Lists have no new per-document 10 MiB ceiling; capacity is still enforced.
    expect(list(10_485_761).canonicalBytes).toBe(10_485_761);
  });

  it("rejects list-only metrics on an unrelated representation", () => {
    expect(() => responseAllocationPlan({ ...list(), representation: "resource" })).toThrow();
    expect(() => responseAllocationPlan({ ...list(), kind: "document" })).toThrow();
    const { listProjection: removed, ...incomplete } = list();
    expect(removed).toBeDefined();
    expect(() => responseAllocationPlan(incomplete)).toThrow();
  });

  it("retains the increased reservation until producer, native and collector completion", async () => {
    const manager = new ResponseAllocationManager();
    const controller = new AbortController();
    const owner = manager.openRequest(controller.signal);
    let finish!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const ready = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const work = owner.produce(async () => {
      const reservation = owner.reserve(list());
      reservation.increase(list(0, "131072"));
      entered();
      await gate;
      expect(() => reservation.increase(list(0, "262144"))).toThrow(ResponseAllocationUnavailable);
    });
    const observed = work.catch((error: unknown) => {
      entered();
      return error;
    });
    await ready;
    controller.abort();
    owner.nativeTerminal();
    owner.collectorSettled();
    try {
      expect(manager.accounting.usedUnits).toBe(2);
    } finally {
      finish();
    }
    expect(await observed).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
