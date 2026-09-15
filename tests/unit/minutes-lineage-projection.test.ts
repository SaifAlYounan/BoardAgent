import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  MINUTES_LINEAGE_PREFLIGHT_SQL,
  MINUTES_LINEAGE_CONTENT_SQL,
  minutesLineageProjectionCost,
  minutesLineageProjectionPlan,
  loadAdmittedMinutesLineage,
  type MinutesLineageMetadata
} from "../../artifacts/server/src/minutes-lineage-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_MINUTES_LINEAGE_SQL } from "../helpers/minutes-lineage-original-sql.js";

// Actual public parse/registry/caller; synthetic authority and transaction only.
// The query collaborator models fresh rows; it does not execute PostgreSQL/RLS.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, work: (client: PoolClient) => Promise<unknown>) =>
        work((pool as unknown as { fixtureClient: PoolClient }).fixtureClient)
    )
  };
});
const id = (n: number) => `01993500-0000-7000-8000-${String(n).padStart(12, "0")}`;
const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
interface Cycle {
  correction_cycle_id: string;
  original_minutes_id: string;
  replacement_minutes_id: string;
  reason: string;
  secretary_member_id: string;
  created_at: string | null;
}
interface Stored {
  view: Cycle;
  raw: string;
}
function source(): Stored[] {
  return [
    {
      view: {
        correction_cycle_id: id(10),
        original_minutes_id: id(1),
        replacement_minutes_id: id(2),
        reason: 'First "correction" Δ',
        secretary_member_id: id(90),
        created_at: "2026-09-12T12:00:00.000001Z"
      },
      raw: "2026-09-12 12:00:00.000001+00"
    },
    {
      view: {
        correction_cycle_id: id(11),
        original_minutes_id: id(2),
        replacement_minutes_id: id(3),
        reason: "Second correction 🙂",
        secretary_member_id: id(90),
        created_at: "2026-09-12T12:00:00.000002Z"
      },
      raw: "2026-09-12 12:00:00.000002+00"
    }
  ];
}
function measure(rows: readonly Stored[]): MinutesLineageMetadata[] {
  return rows.map(({ view, raw }) => ({
    correction_cycle_id: view.correction_cycle_id,
    original_minutes_id: view.original_minutes_id,
    replacement_minutes_id: view.replacement_minutes_id,
    secretary_member_id: view.secretary_member_id,
    reason_utf8: String(Buffer.byteLength(view.reason)),
    reason_sha256: sha(view.reason),
    created_at: view.created_at,
    raw_created_at: raw,
    cycle_count: String(rows.length)
  }));
}
function scalarBytes(rows: readonly Stored[]): number {
  // Independent original six-field list, not production scalar map or constants.
  let n = Buffer.byteLength(id(2));
  for (const { view } of rows)
    for (const value of [
      view.correction_cycle_id,
      view.original_minutes_id,
      view.replacement_minutes_id,
      view.reason,
      view.secretary_member_id,
      view.created_at
    ])
      n += value === null ? 0 : Buffer.byteLength(value);
  return n;
}
function envelope(rows: readonly Stored[]): JsonValue {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: "get_minutes_lineage",
    status: "ok",
    reference: id(2),
    resource_uri: null,
    data: { minutes_id: id(2), correction_cycles: rows.map(({ view }) => ({ ...view })) }
  };
}
function shape(value: unknown) {
  let properties = 0,
    containers = 0;
  const stack = [value];
  while (stack.length) {
    const node = stack.pop();
    if (node !== null && typeof node === "object") {
      containers++;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      for (const child of Object.values(node)) stack.push(child);
    }
  }
  return { properties, containers };
}
function fixture(initial = source()) {
  const state = {
    rows: initial,
    constructions: 0,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined,
    metadataOverride: undefined as MinutesLineageMetadata[] | undefined,
    contentOverride: undefined as unknown[] | undefined
  };
  const ordered = () =>
    [...state.rows].sort(
      (a, b) =>
        a.raw.localeCompare(b.raw) ||
        a.view.correction_cycle_id.localeCompare(b.view.correction_cycle_id)
    );
  const query = vi.fn(async (sql: string, params?: unknown[]) => {
    expect(params?.[0]).toBe(id(2));
    if (sql === MINUTES_LINEAGE_PREFLIGHT_SQL) {
      const rows = state.metadataOverride ?? measure(ordered());
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === ORIGINAL_MINUTES_LINEAGE_SQL || sql === MINUTES_LINEAGE_CONTENT_SQL)
      await state.beforeContent?.();
    if (sql === ORIGINAL_MINUTES_LINEAGE_SQL) {
      state.constructions++;
      return { rows: [{ items: ordered().map((row) => ({ ...row.view })) }] };
    }
    if (sql !== MINUTES_LINEAGE_CONTENT_SQL) throw new Error("unexpected lineage SQL");
    if (state.contentOverride) return { rows: state.contentOverride };
    const rows = ordered(),
      current = measure(rows),
      expected = JSON.parse(String(params?.[1])) as Omit<MinutesLineageMetadata, "cycle_count">[];
    const fits =
      current.length <= Number(params?.[2]) &&
      current.length <= 2 &&
      scalarBytes(rows) <= Number(params?.[3]) &&
      current.every((row) => {
        const { cycle_count: _count, ...tuple } = row;
        return expected.some((bound) => JSON.stringify(bound) === JSON.stringify(tuple));
      });
    if (fits) state.constructions++;
    return {
      rows: [
        {
          cycle_count: String(rows.length),
          scalar_utf8: String(scalarBytes(rows)),
          fits,
          items: fits ? rows.map((row) => ({ ...row.view })) : null
        }
      ]
    };
  });
  const client = { query } as unknown as PoolClient;
  const repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
    cursorKey: Buffer.alloc(32, 1)
  });
  const principal: SurfacePrincipal = {
    organizationId: id(99),
    memberId: id(98),
    serviceOrigin: "https://boardagent.test",
    clientId: id(97),
    protocolClientId: "minutes-lineage-unit",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture",
    scopes: ["governance:read"],
    roles: ["member"],
    boardIds: [id(94)]
  };
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    dispatch(
      client: PoolClient,
      principal: SurfacePrincipal,
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readMinutes(
      client: PoolClient,
      principal: SurfacePrincipal,
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, name, input) => {
    if (name !== "get_minutes_lineage") throw new Error("out-of-scope dispatch");
    return seam.readMinutes(connection, actor, name, input);
  });
  return {
    state,
    query,
    liveActor,
    authorize,
    helper: () => loadAdmittedMinutesLineage(client, id(2)),
    read: () =>
      repo.executeRead(principal, "get_minutes_lineage", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: id(2)
      })
  };
}
const small = () =>
  responseAllocationPlan({
    kind: "document",
    representation: "resource",
    sourceId: "small",
    sourceVersion: "1",
    sha256: "a".repeat(64),
    canonicalBytes: 1
  });
async function owned<T>(manager: ResponseAllocationManager, work: () => Promise<T>) {
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(work);
  } finally {
    try {
      owner.nativeTerminal();
    } finally {
      owner.collectorSettled();
    }
  }
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

describe("minutes lineage projection admission", () => {
  it("refuses the public caller before full construction under complete shared occupancy", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(),
      leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    let failure: unknown;
    try {
      try {
        await owned(manager, () => f.read());
      } catch (error) {
        failure = error;
      }
      expect(
        f.state.constructions,
        "old caller attempted full lineage construction before admission"
      ).toBe(0);
      expect(failure).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.liveActor).toHaveBeenCalledOnce();
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(
        f.query.mock.calls.filter(([sql]) => sql === MINUTES_LINEAGE_PREFLIGHT_SQL)
      ).toHaveLength(1);
      expect(f.query.mock.calls.some(([sql]) => sql === MINUTES_LINEAGE_CONTENT_SQL)).toBe(false);
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  for (const collaborator of ["liveActor", "authorize"] as const)
    it(`rejects ${collaborator} denial before SQL`, async () => {
      const f = fixture(),
        denied = new Error("synthetic initial denial");
      if (collaborator === "liveActor") f.liveActor.mockRejectedValueOnce(denied);
      else
        f.authorize.mockImplementationOnce(() => {
          throw denied;
        });
      await expect(owned(new ResponseAllocationManager(), () => f.read())).rejects.toBe(denied);
      expect(f.query).not.toHaveBeenCalled();
    });
  for (const count of [0, 1, 2])
    it(`preserves exact original public ${count}-cycle output`, async () => {
      const rows = source().slice(0, count),
        f = fixture(rows),
        expected = envelope(rows);
      const result = await owned(new ResponseAllocationManager(), () => f.read());
      expect(result).toEqual(expected);
      expect(JSON.stringify(result)).toBe(JSON.stringify(expected));
      expect(canonicalJson(result)).toBe(canonicalJson(expected));
      expect(f.state.constructions).toBe(1);
    });
  it("preserves the UUID tiebreak when timestamps tie and insertion order differs", async () => {
    const rows = source();
    rows[1]!.raw = rows[0]!.raw;
    rows[1]!.view.created_at = rows[0]!.view.created_at;
    const f = fixture([...rows].reverse());
    expect(await owned(new ResponseAllocationManager(), () => f.helper())).toEqual(
      rows.map((x) => x.view)
    );
  });
  for (const change of ["same-width-reason", "wider-reason", "new-id", "raw-microseconds"] as const)
    it(`refuses fresh ${change} before modeled construction`, async () => {
      const f = fixture();
      f.state.afterMetadata = () => {
        if (change === "same-width-reason")
          f.state.rows[0]!.view.reason = f.state.rows[0]!.view.reason.replace("First", "Other");
        else if (change === "wider-reason") f.state.rows[0]!.view.reason += "🙂";
        else if (change === "new-id") f.state.rows[0]!.view.correction_cycle_id = id(12);
        else f.state.rows[0]!.raw = "2026-09-12 12:00:00.000003+00";
      };
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.state.constructions).toBe(0);
    });
  it("refuses empty-to-visible growth rather than silently returning empty", async () => {
    const f = fixture([]);
    f.state.afterMetadata = () => {
      f.state.rows = source().slice(0, 1);
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  for (const remaining of [0, 1])
    it(`admits a ${remaining}-row hidden subset without absolute ordinal binding`, async () => {
      const f = fixture();
      f.state.afterMetadata = () => {
        f.state.rows = f.state.rows.slice(2 - remaining);
      };
      const result = await owned(new ResponseAllocationManager(), () => f.helper());
      expect(result).toEqual(
        source()
          .slice(2 - remaining)
          .map((x) => x.view)
      );
      expect(f.state.constructions).toBe(1);
    });
  it("bounds escaping and actual graph/wire independently for flat adversarial strings", () => {
    for (const text of ['\u0001\n\r\t\\"🙂', "Δ".repeat(257), '\\"'.repeat(1024)]) {
      const rows = source();
      rows[0]!.view.reason = text;
      rows[1]!.view.created_at = null;
      const cost = minutesLineageProjectionCost({
        cycle_count: "2",
        scalar_utf8: String(scalarBytes(rows))
      });
      const plan = minutesLineageProjectionPlan(id(2), measure(rows));
      const data = { minutes_id: id(2), correction_cycles: rows.map((x) => ({ ...x.view })) };
      const expected = envelope(rows),
        wire = {
          content: [{ type: "text", text: JSON.stringify(expected) }],
          structuredContent: expected
        },
        actualGraph = shape(wire);
      expect(BigInt(Buffer.byteLength(JSON.stringify(data)))).toBeLessThanOrEqual(
        BigInt(cost.jsonUpperBytes)
      );
      expect(actualGraph.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
      expect(actualGraph.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
      expect(cost.propertyCount).toBe("37");
      expect(cost.objectOrArrayCount).toBe("9");
    }
  });
  it("admits two schema-maximum UTF8 reasons with 100 ordinary small leases", async () => {
    const rows = source();
    for (const row of rows) row.view.reason = "🙂".repeat(65_536);
    expect([...rows[0]!.view.reason]).toHaveLength(65_536);
    expect(Buffer.byteLength(rows[0]!.view.reason)).toBe(262_144);
    const metadata = measure(rows),
      cost = minutesLineageProjectionCost({
        cycle_count: "2",
        scalar_utf8: String(scalarBytes(rows))
      });
    expect(cost).toEqual({
      jsonUpperBytes: "3148363",
      propertyCount: "37",
      objectOrArrayCount: "9"
    });
    const plan = minutesLineageProjectionPlan(id(2), metadata);
    expect(plan.units).toBe(25);
    expect(Buffer.byteLength(JSON.stringify(envelope(rows)))).toBeLessThan(
      Number(cost.jsonUpperBytes) + 4096
    );
    const manager = new ResponseAllocationManager(),
      leases = Array.from({ length: 100 }, () => manager.tryReserve(small())),
      f = fixture(rows);
    const owner = manager.openRequest(new AbortController().signal);
    try {
      expect(await owner.produce(() => f.helper())).toEqual(rows.map((x) => x.view));
      expect(manager.accounting.usedUnits).toBe(125);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(125);
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(100);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("crosses the exact one-unit boundary with one additional admitted UTF8 byte", () => {
    const rows = source().slice(0, 1);
    rows[0]!.view.reason = "a".repeat(19_305);
    expect(scalarBytes(rows)).toBe(19_512);
    const cost = minutesLineageProjectionCost({
      cycle_count: "1",
      scalar_utf8: String(scalarBytes(rows))
    });
    expect(cost).toEqual({
      jsonUpperBytes: "117280",
      propertyCount: "31",
      objectOrArrayCount: "8"
    });
    expect(65_536 + 8 * (117_280 + 4_096) + 256 * 31 + 512 * 8).toBe(1_048_576);
    expect(minutesLineageProjectionPlan(id(2), measure(rows)).units).toBe(1);
    rows[0]!.view.reason += "a";
    expect(minutesLineageProjectionPlan(id(2), measure(rows)).units).toBe(2);
  });
  it("retains the admitted empty response through both settlement markers", async () => {
    const f = fixture([]),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      expect(await owner.produce(() => f.helper())).toEqual([]);
      expect(manager.accounting.usedUnits).toBe(1);
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(1);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("rejects resource/raw representations and retains scalar overflow policy", () => {
    const base = minutesLineageProjectionPlan(id(2), []);
    expect(() => responseAllocationPlan({ ...base, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...base, canonicalBytes: 1 })).toThrow(TypeError);
    expect(() => minutesLineageProjectionCost({ cycle_count: "3", scalar_utf8: "36" })).toThrow(
      ResponseAllocationUnavailable
    );
    expect(() =>
      minutesLineageProjectionCost({ cycle_count: "0", scalar_utf8: "9".repeat(25) })
    ).toThrow(ResponseAllocationUnavailable);
    expect(() => minutesLineageProjectionCost({ cycle_count: "00", scalar_utf8: "36" })).toThrow(
      TypeError
    );
  });
  it("rejects third-row, duplicate and wrong-selector metadata before content", async () => {
    for (const kind of ["third", "duplicate", "selector"]) {
      const f = fixture(),
        rows = measure(source());
      if (kind === "third")
        rows.push({ ...rows[0]!, correction_cycle_id: id(12), cycle_count: "3" });
      else if (kind === "duplicate") rows[1] = { ...rows[0]! };
      else rows[0] = { ...rows[0]!, original_minutes_id: id(60), replacement_minutes_id: id(61) };
      f.state.metadataOverride = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        kind === "third" ? ResponseAllocationUnavailable : TypeError
      );
      expect(f.query.mock.calls.some(([sql]) => sql === MINUTES_LINEAGE_CONTENT_SQL)).toBe(false);
    }
  });
  it("rejects dishonest loaded digest, length, extra field and reversed array", async () => {
    for (const kind of ["digest", "length", "extra", "order"]) {
      const f = fixture(),
        items = source().map((x) => ({ ...x.view }));
      if (kind === "digest") items[0]!.reason = items[0]!.reason.replace("First", "Other");
      else if (kind === "length") items[0]!.reason += "x";
      else if (kind === "extra") Object.assign(items[0]!, { unmeasured: "x" });
      else items.reverse();
      f.state.contentOverride = [
        { cycle_count: "2", scalar_utf8: String(scalarBytes(source())), fits: true, items }
      ];
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
  it("prevents content after metadata-time disconnect", async () => {
    const f = fixture(),
      controller = new AbortController(),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(controller.signal);
    f.state.afterMetadata = () => controller.abort();
    try {
      await expect(owner.produce(() => f.helper())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.query.mock.calls.some(([sql]) => sql === MINUTES_LINEAGE_CONTENT_SQL)).toBe(false);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains an early-disconnect lease while the actual helper producer query is held", async () => {
    const f = fixture(),
      entered = gate(),
      release = gate(),
      controller = new AbortController(),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(controller.signal);
    f.state.beforeContent = async () => {
      entered.release();
      await release.promise;
    };
    const produced = owner.produce(() => f.helper());
    const settled = produced.then(
      (value) => ({ ok: true as const, value }),
      (error) => ({ ok: false as const, error })
    );
    let deadline: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        entered.promise,
        settled.then((outcome) => {
          throw new Error("producer settled before the content gate", {
            cause: outcome.ok ? undefined : outcome.error
          });
        }),
        new Promise<never>((_resolve, reject) => {
          deadline = setTimeout(() => reject(new Error("content gate entry timed out")), 2_000);
        })
      ]);
      expect(manager.accounting.usedUnits).toBe(1);
      controller.abort();
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(1);
      release.release();
      const outcome = await settled;
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) expect(outcome.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      if (deadline !== undefined) clearTimeout(deadline);
      release.release();
      controller.abort();
      try {
        owner.nativeTerminal();
      } finally {
        owner.collectorSettled();
      }
    }
  });
});
