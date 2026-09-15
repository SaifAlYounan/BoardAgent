import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  loadAdmittedTaskProjection,
  TASK_PROJECTION_PREFLIGHT_SQL,
  TASK_PROJECTION_CONTENT_SQL,
  taskProjectionCost,
  taskProjectionPlan,
  type TaskProjectionMetadata
} from "../../artifacts/server/src/task-projection-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_TASK_RESOURCE_SQL } from "../helpers/task-resource-original-sql.js";

const id = (n: number) => `01993400-0000-7000-8000-${String(n).padStart(12, "0")}`;
const at = "2026-09-12T18:00:00.000000Z";
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
type Evidence = {
  evidence_id: string;
  canonical_text: string | null;
  document_references: JsonValue;
  resource_references: JsonValue;
  sha256: string;
  state: string;
};
function graph(closed = true, description = "Deliver the synthetic report Δ 🙂\n") {
  return {
    schema_version: "boardagent.task-resource.v1",
    task_id: id(1),
    board_id: id(2),
    source_minutes_id: closed ? id(3) : null,
    source_minutes_version_id: closed ? id(4) : null,
    source_minutes_sha256: closed ? "a".repeat(64) : null,
    owner_member_id: id(5),
    due_at: at,
    description_schema: "boardagent.task.v1",
    canonical_description: description,
    required_evidence: {
      text: "Canonical report.",
      items: [{ kind: "document" }, [], null, true]
    } as JsonValue,
    task_sha256: "b".repeat(64),
    state: closed ? "completed" : "open",
    row_version: "7",
    evidence: (closed
      ? [
          {
            evidence_id: id(6),
            canonical_text: 'First synthetic evidence "Δ".',
            document_references: [{ document_id: id(7), version: 1 }],
            resource_references: [],
            sha256: "c".repeat(64),
            state: "submitted"
          },
          {
            evidence_id: id(8),
            canonical_text: null,
            document_references: [],
            resource_references: [
              { uri: "board://synthetic/documents/1", note: "🙂" },
              [1e40, null]
            ],
            sha256: "d".repeat(64),
            state: "accepted"
          }
        ]
      : []) as Evidence[],
    closure: closed
      ? {
          closure_id: id(9),
          accepted_evidence_manifest: [{ evidence_id: id(8), sha256: "d".repeat(64) }] as JsonValue,
          closure_sha256: "e".repeat(64)
        }
      : null
  };
}
type Payload = ReturnType<typeof graph>;
type Metadata = { -readonly [K in keyof TaskProjectionMetadata]: TaskProjectionMetadata[K] };
function shape(value: unknown) {
  const stack: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (stack.length) {
    const item = stack.pop();
    if (item && typeof item === "object") {
      containers += 1;
      if (!Array.isArray(item)) properties += Object.keys(item).length;
      for (const child of Object.values(item)) stack.push(child);
    }
  }
  return { properties, containers };
}
// Independent enumeration, without using helper field maps or bound constants.
function measure(q: Payload): Metadata {
  const values: unknown[] = [
    q.schema_version,
    q.task_id,
    q.board_id,
    q.source_minutes_id,
    q.source_minutes_version_id,
    q.source_minutes_sha256,
    q.owner_member_id,
    q.due_at,
    q.description_schema,
    q.canonical_description,
    q.task_sha256,
    q.state,
    q.row_version
  ];
  const json: unknown[] = [q.required_evidence];
  for (const evidence of q.evidence) {
    values.push(evidence.evidence_id, evidence.canonical_text, evidence.sha256, evidence.state);
    json.push(evidence.document_references, evidence.resource_references);
  }
  if (q.closure) {
    values.push(q.closure.closure_id, q.closure.closure_sha256);
    json.push(q.closure.accepted_evidence_manifest);
  }
  const nested = json.map(shape).reduce((sum, item) => ({
    properties: sum.properties + item.properties,
    containers: sum.containers + item.containers
  }));
  return {
    id: q.task_id,
    board_id: q.board_id,
    row_version: q.row_version,
    closure_id: q.closure?.closure_id ?? null,
    // Synthetic exact-content observation, not a claimed reimplementation of the
    // PostgreSQL private digest expression.
    observation_sha256: digest(JSON.stringify(q)),
    evidence_count: String(q.evidence.length),
    closure_count: q.closure ? "1" : "0",
    scalar_utf8: String(
      values.reduce<number>((sum, v) => sum + (v === null ? 0 : Buffer.byteLength(String(v))), 0)
    ),
    json_utf8: String(
      json.reduce<number>((sum, v) => sum + Buffer.byteLength(JSON.stringify(v)), 0)
    ),
    json_properties: String(nested.properties),
    json_containers: String(nested.containers)
  };
}
function fixture(q = graph()) {
  const metadata = measure(q);
  const state = {
    missing: false,
    hidden: false,
    fits: true,
    payload: q as Payload | Record<string, JsonValue>,
    returnedClosureId: metadata.closure_id,
    constructions: 0,
    beforeContent: undefined as undefined | (() => Promise<void>),
    afterMetadata: undefined as undefined | (() => void)
  };
  const visible = (values?: unknown[]) =>
    !state.missing &&
    values?.[0] === metadata.board_id &&
    values[1] === metadata.id &&
    (values[2] !== true || q.source_minutes_id !== null) &&
    values[3] === id(98);
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === TASK_PROJECTION_PREFLIGHT_SQL) {
      state.afterMetadata?.();
      return { rows: visible(values) ? [{ ...metadata }] : [] };
    }
    if (sql === TASK_PROJECTION_CONTENT_SQL) {
      await state.beforeContent?.();
      if (state.hidden || !visible(values)) return { rows: [] };
      if (state.fits) state.constructions += 1;
      return {
        rows: [
          {
            id: metadata.id,
            row_version: metadata.row_version,
            closure_id: state.returnedClosureId,
            observation_sha256: metadata.observation_sha256,
            fits: state.fits,
            payload: state.fits ? state.payload : null
          }
        ]
      };
    }
    // Supports the old query and exact original values: the intended baseline
    // failure is premature full construction, not an unrecognized SQL string.
    if (sql === ORIGINAL_TASK_RESOURCE_SQL) {
      state.constructions += 1;
      return {
        rows: visible(values) ? [{ id: q.task_id, row_version: q.row_version, payload: q }] : []
      };
    }
    throw new Error("unexpected task fixture query");
  });
  const client = { query } as unknown as PoolClient;
  const repository = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repository as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    loadBoardResource(
      client: PoolClient,
      principal: SurfacePrincipal,
      uri: URL
    ): Promise<{ bytes: Buffer; objectVersion: bigint; entityType: string } | null>;
  };
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const principal = { organizationId: id(99), memberId: id(98) } as SurfacePrincipal;
  const input = { boardId: q.board_id, taskId: q.task_id, actionOnly: false, memberId: id(98) };
  return {
    q,
    metadata,
    state,
    query,
    client,
    authorize,
    input,
    read: (kind: "tasks" | "action-items" = "tasks") =>
      seam.loadBoardResource(
        client,
        principal,
        new URL(`board://${q.board_id}/${kind}/${q.task_id}`)
      ),
    helper: () => loadAdmittedTaskProjection(client, input)
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
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}
function boundaryMetadata(): Metadata {
  return {
    id: id(1),
    board_id: id(2),
    row_version: "1",
    closure_id: null,
    observation_sha256: "a".repeat(64),
    evidence_count: "0",
    closure_count: "0",
    scalar_utf8: "0",
    json_utf8: "251637588",
    json_properties: "1",
    json_containers: "1"
  };
}

describe("task resource measured projection admission", () => {
  it("refuses the saturated old resource caller before full content construction", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    const held = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.state.constructions).toBe(0);
      expect(
        f.query.mock.calls.filter(([sql]) => sql === TASK_PROJECTION_PREFLIGHT_SQL)
      ).toHaveLength(1);
      expect(f.query.mock.calls.some(([sql]) => sql === TASK_PROJECTION_CONTENT_SQL)).toBe(false);
    } finally {
      for (const lease of held) lease.release();
    }
  });
  for (const closed of [true, false])
    it(`preserves frozen original bytes with closure=${String(closed)}`, async () => {
      const f = fixture(graph(closed)),
        manager = new ResponseAllocationManager();
      const result = await owned(manager, () => f.read());
      const expected = readFileSync(
        path.resolve(
          import.meta.dirname,
          `../fixtures/task-resource-${closed ? "closed" : "open"}.txt`
        )
      );
      expect(result?.bytes).toEqual(expected);
      expect(result?.objectVersion).toBe(7n);
      expect(result?.entityType).toBe("task");
      expect(JSON.parse(expected.toString("utf8"))).toEqual(f.q);
      expect(Object.keys(f.q)).toHaveLength(16);
      for (const evidence of f.q.evidence) expect(Object.keys(evidence)).toHaveLength(6);
      if (f.q.closure) expect(Object.keys(f.q.closure)).toHaveLength(3);
      expect(f.authorize).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        "get_task",
        {}
      );
      expect(f.state.constructions).toBe(1);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  it("serves the action-item alias of a minutes-sourced task and refuses it for a sourceless task", async () => {
    const sourced = fixture(),
      manager = new ResponseAllocationManager();
    const result = await owned(manager, () => sourced.read("action-items"));
    expect(result?.entityType).toBe("action_item");
    expect(result?.bytes).toEqual(
      readFileSync(path.resolve(import.meta.dirname, "../fixtures/task-resource-closed.txt"))
    );
    expect(sourced.authorize).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      "get_action_item",
      {}
    );
    expect(
      sourced.query.mock.calls.find(([sql]) => sql === TASK_PROJECTION_CONTENT_SQL)?.[1]?.[2]
    ).toBe(true);
    const sourceless = fixture(graph(false));
    expect(await owned(manager, () => sourceless.read("action-items"))).toBeNull();
    expect(sourceless.state.constructions).toBe(0);
    expect(sourceless.query).toHaveBeenCalledTimes(1);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("returns absent roots without loading a payload", async () => {
    const f = fixture();
    f.state.missing = true;
    const manager = new ResponseAllocationManager();
    expect(await owned(manager, f.helper)).toBeNull();
    expect(f.state.constructions).toBe(0);
    expect(f.query).toHaveBeenCalledTimes(1);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("requires an explicit native owner for a visible task", async () => {
    const f = fixture();
    await expect(f.helper()).rejects.toThrow("native response allocation owner is required");
    expect(f.query.mock.calls.some(([sql]) => sql === TASK_PROJECTION_CONTENT_SQL)).toBe(false);
  });
  it("keeps the board, task, alias and principal selectors at both boundaries", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    expect(
      await owned(manager, () =>
        loadAdmittedTaskProjection(f.client, { ...f.input, boardId: id(90) })
      )
    ).toBeNull();
    expect(
      await owned(manager, () =>
        loadAdmittedTaskProjection(f.client, { ...f.input, memberId: id(91) })
      )
    ).toBeNull();
    await owned(manager, f.helper);
    expect(
      f.query.mock.calls.find(([sql]) => sql === TASK_PROJECTION_CONTENT_SQL)?.[1]?.slice(0, 4)
    ).toEqual([f.q.board_id, f.q.task_id, false, id(98)]);
  });
  it("binds the observed identity, both counts and every fresh scalar cost", async () => {
    const f = fixture();
    await owned(new ResponseAllocationManager(), f.helper);
    const call = f.query.mock.calls.find(([sql]) => sql === TASK_PROJECTION_CONTENT_SQL)!;
    expect(call[1]).toEqual([
      f.metadata.board_id,
      f.metadata.id,
      false,
      id(98),
      f.metadata.observation_sha256,
      f.metadata.evidence_count,
      f.metadata.closure_count,
      f.metadata.scalar_utf8,
      f.metadata.json_utf8,
      f.metadata.json_properties,
      f.metadata.json_containers
    ]);
  });
  it("refuses a present changed or larger projection instead of pretending it vanished", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.fits = false;
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
      expect(manager.accounting.usedUnits).toBe(taskProjectionPlan(f.metadata).units);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
    f.state.hidden = true;
    expect(await owned(manager, f.helper)).toBeNull();
  });
  it("returns same-cost current content within the bound identities", async () => {
    const f = fixture();
    f.state.payload = graph(true, "Deliver the synthetic report Ω 🙂\n");
    const fresh = measure(f.state.payload as Payload);
    expect(fresh.scalar_utf8).toBe(f.metadata.scalar_utf8);
    expect(fresh.json_utf8).toBe(f.metadata.json_utf8);
    expect((await owned(new ResponseAllocationManager(), f.helper))?.payload).toEqual(
      f.state.payload
    );
  });
  it("rejects a returned closure substitution even when a synthetic row says fits", async () => {
    const f = fixture();
    f.state.returnedClosureId = id(90);
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(
      "task projection identity is invalid"
    );
  });
  it("rejects a payload tuple that differs from the selected private row", async () => {
    for (const payload of [
      { ...graph(), board_id: id(90) },
      { ...graph(), evidence: [] },
      { ...graph(), closure: null },
      { ...graph(), closure: { ...graph().closure!, closure_id: id(90) } }
    ]) {
      const f = fixture();
      f.state.payload = payload as unknown as Payload;
      await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(
        "task projection payload identity is invalid"
      );
    }
  });
  it("refuses known oversized JSON before issuing content", async () => {
    const f = fixture();
    f.metadata.json_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.query.mock.calls.some(([sql]) => sql === TASK_PROJECTION_CONTENT_SQL)).toBe(false);
  });
  it("does not begin content after metadata-time disconnect", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    const owner = manager.openRequest(abort.signal);
    f.state.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query.mock.calls.some(([sql]) => sql === TASK_PROJECTION_CONTENT_SQL)).toBe(false);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("retains the lease after early terminal signals while content is still pending", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    let enter!: () => void, release!: () => void;
    const entered = new Promise<void>((r) => {
        enter = r;
      }),
      gate = new Promise<void>((r) => {
        release = r;
      });
    f.state.beforeContent = async () => {
      enter();
      await gate;
    };
    const owner = manager.openRequest(abort.signal),
      pending = owner.produce(f.helper);
    await entered;
    abort.abort();
    owner.nativeTerminal();
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(taskProjectionPlan(f.metadata).units);
    release();
    await expect(pending).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("has an exact 1920-unit boundary, recomputes forged weights and preserves 100 small reservations", () => {
    const metadata = boundaryMetadata(),
      manager = new ResponseAllocationManager();
    const plan = taskProjectionPlan(metadata);
    expect(plan.units).toBe(1920);
    const large = manager.tryReserve(plan),
      ordinary = taskProjectionPlan(measure(graph()));
    expect(ordinary.units).toBe(1);
    const held = Array.from({ length: 100 }, () => manager.tryReserve(ordinary));
    expect(manager.accounting).toEqual({ usedUnits: 2020, largeUsedUnits: 1920 });
    for (const lease of held) lease.release();
    large.release();
    metadata.json_utf8 = "251644841";
    expect(taskProjectionPlan(metadata).units).toBe(1920);
    metadata.json_utf8 = "251644842";
    const over = taskProjectionPlan(metadata);
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve({ ...over, units: 1 })).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects unsupported representations and malformed or overflowing scalars", () => {
    const metadata = measure(graph()),
      plan = taskProjectionPlan(metadata);
    expect(() => responseAllocationPlan({ ...plan, representation: "tool" })).toThrow(
      "requires resource representation"
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(
      "requires resource representation"
    );
    for (const value of ["-1", "01", "1.0", "1e2"]) {
      metadata.json_utf8 = value;
      expect(() => taskProjectionPlan(metadata)).toThrow(TypeError);
    }
    metadata.json_utf8 = "9".repeat(25);
    expect(() => taskProjectionPlan(metadata)).toThrow(ResponseAllocationUnavailable);
    metadata.json_utf8 = "0";
    metadata.closure_count = "2";
    expect(() => taskProjectionPlan(metadata)).toThrow("closure identity");
    metadata.closure_count = "0";
    expect(() => taskProjectionPlan(metadata)).toThrow("closure identity");
    metadata.closure_count = "1";
    metadata.observation_sha256 = "z".repeat(64);
    expect(() => taskProjectionPlan(metadata)).toThrow("observation hash");
    metadata.observation_sha256 = "a".repeat(64);
    metadata.row_version = "0";
    expect(() => taskProjectionPlan(metadata)).toThrow("row version");
  });
  it("counts small-byte JSON with many containers instead of treating it as flat strings", () => {
    const q = graph();
    q.required_evidence = { nested: Array.from({ length: 3000 }, () => []) };
    const metadata = measure(q),
      cost = taskProjectionCost(metadata);
    expect(Number(metadata.json_utf8)).toBeLessThan(20000);
    expect(Number(metadata.json_containers)).toBeGreaterThan(3000);
    expect(BigInt(shape(q).containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    expect(taskProjectionPlan(metadata).units).toBeGreaterThan(
      taskProjectionPlan({ ...metadata, json_properties: "0", json_containers: "0" }).units
    );
  });
  it("bounds independent UTF8 serialization and graph oracles for escaped text and arbitrary JSON", () => {
    const atoms = ["", "\b", "\t", "\n", "\f", "\r", '"', "\\", "Δ", "🙂", " "];
    for (let n = 0; n < 32; n += 1) {
      const text = Array.from({ length: 64 }, (_, i) => atoms[(i * 7 + n) % atoms.length]).join("");
      const q = graph(true, text);
      q.required_evidence = {
        [text]: [{}, [], { text, number: 1e100, tiny: 1e-100, flag: false, empty: null }]
      };
      q.evidence[0]!.canonical_text = text;
      q.evidence[1]!.resource_references = [text, { [text]: text }];
      const metadata = measure(q),
        cost = taskProjectionCost(metadata),
        actual = shape(q);
      const json = JSON.stringify(q);
      expect(BigInt(Buffer.byteLength(json))).toBeLessThanOrEqual(BigInt(cost.jsonUpperBytes));
      expect(BigInt(actual.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
      expect(BigInt(actual.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
      const wire = JSON.stringify({
        contents: [
          {
            uri: `board://${q.board_id}/tasks/${q.task_id}`,
            mimeType: "application/json",
            text: json
          }
        ]
      });
      expect(Buffer.byteLength(wire)).toBeLessThanOrEqual(
        taskProjectionPlan(metadata).wireUpperBytes
      );
    }
  });
});
