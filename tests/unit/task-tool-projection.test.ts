import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import {
  TASK_TOOL_PREFLIGHT_SQL,
  TASK_TOOL_CONTENT_SQL,
  taskToolProjectionCost,
  taskToolProjectionPlan,
  loadAdmittedTaskToolProjection,
  type TaskToolProjectionMetadata
} from "../../artifacts/server/src/task-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_TASK_TOOL_SQL } from "../helpers/task-tool-original-sql.js";

// The transaction port and authority collaborators are synthetic. The public
// executeRead input/registry path and exact get_task/get_action_item branch run.
// These unit models do not execute PostgreSQL, prove RLS, or mutate storage.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected task tool fixture pool");
        return callback(client);
      }
    )
  };
});
const id = (n: number) => `01993500-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const bytes = () =>
  readFileSync(path.resolve(import.meta.dirname, "../fixtures/task-tool-view.txt"));
interface Evidence extends Record<string, JsonValue> {
  review: Record<string, JsonValue> | null;
}
interface View extends Record<string, JsonValue> {
  task_id: string;
  board_id: string;
  source_minutes_id: string | null;
  evidence: Evidence[];
  closure: Record<string, JsonValue> | null;
  correction_cycles: Array<Record<string, JsonValue>>;
}
const graph = () => JSON.parse(bytes().toString("utf8")) as View;
function shape(value: unknown) {
  const pending: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const node = pending.pop();
    if (node !== null && typeof node === "object") {
      containers += 1;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      for (const child of Object.values(node)) pending.push(child);
    }
  }
  return { properties, containers };
}
type Metadata = {
  -readonly [K in keyof TaskToolProjectionMetadata]: TaskToolProjectionMetadata[K];
};
const rootKeys = [
  "task_id",
  "board_id",
  "source_meeting_id",
  "source_minutes_id",
  "source_minutes_version_id",
  "source_minutes_sha256",
  "source_locator",
  "owner_member_id",
  "due_at",
  "description_schema",
  "canonical_description",
  "required_evidence",
  "task_sha256",
  "state",
  "row_version",
  "evidence",
  "closure",
  "correction_cycles",
  "created_at",
  "completed_at",
  "cancelled_at"
];
const evidenceKeys = [
  "evidence_id",
  "canonical_text",
  "document_references",
  "resource_references",
  "sha256",
  "state",
  "row_version",
  "submitted_at",
  "review"
];
const reviewKeys = ["review_id", "decision", "reason", "secretary_member_id", "reviewed_at"];
const closureKeys = [
  "closure_id",
  "primary_evidence_id",
  "accepted_evidence_manifest",
  "source_minutes_sha256",
  "secretary_member_id",
  "closure_sha256",
  "closed_at"
];
const cycleKeys = ["cycle_id", "prior_task_id", "replacement_task_id", "reason", "created_at"];
const jsonKeys = new Set([
  "source_locator",
  "required_evidence",
  "document_references",
  "resource_references",
  "accepted_evidence_manifest"
]);
// Independent full inventory, never production field arrays/constants.
function measure(q: View): Metadata {
  let s = 0,
    n = 0,
    p = 0,
    o = 0,
    r = 0;
  const flat = (record: Record<string, JsonValue>, keys: readonly string[]) => {
    for (const key of keys) {
      const value = record[key];
      if (value === null || value === undefined) continue;
      if (jsonKeys.has(key)) {
        // JS spelling is a unit oracle only. PostgreSQL::text numeric expansion and
        // whitespace require the separate original-SQL PostgreSQL comparison.
        n += Buffer.byteLength(JSON.stringify(value));
        const counts = shape(value);
        p += counts.properties;
        o += counts.containers;
      } else if (typeof value !== "object") s += Buffer.byteLength(String(value));
    }
  };
  flat(q, rootKeys);
  for (const evidence of q.evidence) {
    flat(evidence, evidenceKeys);
    if (evidence.review !== null) {
      r += 1;
      flat(evidence.review, reviewKeys);
    }
  }
  if (q.closure !== null) flat(q.closure, closureKeys);
  for (const cycle of q.correction_cycles) flat(cycle, cycleKeys);
  return {
    task_id: q.task_id,
    board_id: q.board_id,
    member_id: id(98),
    row_version: String(q["row_version"]),
    evidence_count: String(q.evidence.length),
    review_count: String(r),
    closure_count: q.closure === null ? "0" : "1",
    cycle_count: String(q.correction_cycles.length),
    scalar_utf8: String(s),
    json_utf8: String(n),
    json_properties: String(p),
    json_containers: String(o),
    // Synthetic exact-content observation, not a claimed reimplementation or test
    // of the PostgreSQL private digest expression.
    observation_sha256: digest(JSON.stringify(q))
  };
}
function fixture(q = graph()) {
  const state = {
    view: q as View,
    missing: false,
    hidden: false,
    fits: true,
    constructions: 0,
    contentRow: undefined as Record<string, unknown> | undefined,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined
  };
  const metadata = measure(q);
  const visible = (values?: unknown[]) =>
    !state.missing &&
    values?.[0] === metadata.task_id &&
    (values[1] !== true || q.source_minutes_id !== null) &&
    values[2] === metadata.member_id;
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === TASK_TOOL_PREFLIGHT_SQL) {
      state.afterMetadata?.();
      return { rows: visible(values) ? [{ ...metadata }] : [] };
    }
    if (sql === TASK_TOOL_CONTENT_SQL) {
      await state.beforeContent?.();
      if (state.hidden || !visible(values)) return { rows: [] };
      const binding = {
        task_id: metadata.task_id,
        board_id: metadata.board_id,
        member_id: metadata.member_id,
        observation_sha256: metadata.observation_sha256,
        fits: state.fits
      };
      if (state.contentRow) return { rows: [{ ...binding, ...state.contentRow }] };
      if (!state.fits) return { rows: [{ ...binding, view: null }] };
      state.constructions += 1;
      return { rows: [{ ...binding, view: state.view }] };
    }
    if (sql === ORIGINAL_TASK_TOOL_SQL) {
      // The old caller succeeds with real original-shaped content, so baseline
      // admission failures cannot be attributed to an unsupported query mock.
      if (!visible(values)) return { rows: [] };
      state.constructions += 1;
      return { rows: [{ view: state.view }] };
    }
    throw new Error("unexpected task tool fixture query");
  });
  const client = { query } as unknown as PoolClient;
  const repository = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
    cursorKey: Buffer.alloc(32, 1)
  });
  const principal: SurfacePrincipal = {
    organizationId: id(99),
    memberId: id(98),
    serviceOrigin: "https://boardagent.test",
    clientId: id(97),
    protocolClientId: "task-tool-fixture",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture-key",
    scopes: ["governance:read"],
    roles: ["member"],
    boardIds: [id(2)]
  };
  const seam = repository as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    dispatch(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readTask(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, tool, input) => {
    if (tool !== "get_task" && tool !== "get_action_item")
      throw new Error("out-of-scope fixture dispatch");
    return seam.readTask(connection, actor, tool, input);
  });
  const input = { taskId: id(1), actionOnly: false, memberId: id(98) };
  return {
    state,
    metadata,
    query,
    client,
    authorize,
    input,
    read: (tool: "get_task" | "get_action_item" = "get_task") =>
      repository.executeRead(principal, tool, {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        task_id: id(1)
      }),
    helper: () => loadAdmittedTaskToolProjection(client, input)
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

describe("get_task/get_action_item measured projection admission", () => {
  it("refuses the saturated old tool caller before full content construction", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    const held = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
    try {
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.state.constructions).toBe(0);
      expect(f.query.mock.calls.filter(([sql]) => sql === TASK_TOOL_PREFLIGHT_SQL)).toHaveLength(1);
      expect(f.query.mock.calls.some(([sql]) => sql === TASK_TOOL_CONTENT_SQL)).toBe(false);
    } finally {
      for (const lease of held) lease.release();
    }
  });
  for (const tool of ["get_task", "get_action_item"] as const)
    it(`preserves the frozen original ${tool} view inside the ordinary tool result`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager();
      const result = await owned(manager, () => f.read(tool));
      expect(result).toEqual({
        schema_version: "boardagent.tool-result.v1",
        tool,
        status: "ok",
        reference: id(1),
        resource_uri: null,
        data: { task: graph() }
      });
      expect(Buffer.from(canonicalJson((result.data as { task: JsonValue }).task))).toEqual(
        bytes()
      );
      expect(Object.keys(graph())).toEqual(expect.arrayContaining(rootKeys));
      expect(Object.keys(graph())).toHaveLength(21);
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(f.authorize.mock.calls[0]?.[2]).toBe(tool);
      expect(f.state.constructions).toBe(1);
      expect(
        f.query.mock.calls.find(([sql]) => sql === TASK_TOOL_CONTENT_SQL)?.[1]?.slice(0, 3)
      ).toEqual([id(1), tool === "get_action_item", id(98)]);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  it("reports an absent or sourceless action item as null without loading content", async () => {
    const f = fixture();
    f.state.missing = true;
    const manager = new ResponseAllocationManager();
    expect((await owned(manager, () => f.read())).data).toEqual({ task: null });
    expect(f.state.constructions).toBe(0);
    expect(f.query).toHaveBeenCalledTimes(1);
    const sourceless = fixture({ ...graph(), source_minutes_id: null });
    expect((await owned(manager, () => sourceless.read("get_action_item"))).data).toEqual({
      task: null
    });
    expect(sourceless.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("requires an explicit native owner for a visible task", async () => {
    const f = fixture();
    await expect(f.helper()).rejects.toThrow("native response allocation owner is required");
    expect(f.query.mock.calls.some(([sql]) => sql === TASK_TOOL_CONTENT_SQL)).toBe(false);
  });
  it("binds the board, observed identity, every count and every fresh scalar cost", async () => {
    const f = fixture();
    await owned(new ResponseAllocationManager(), f.helper);
    const call = f.query.mock.calls.find(([sql]) => sql === TASK_TOOL_CONTENT_SQL)!;
    expect(call[1]).toEqual([
      id(1),
      false,
      id(98),
      f.metadata.board_id,
      f.metadata.observation_sha256,
      f.metadata.evidence_count,
      f.metadata.review_count,
      f.metadata.closure_count,
      f.metadata.cycle_count,
      f.metadata.scalar_utf8,
      f.metadata.json_utf8,
      f.metadata.json_properties,
      f.metadata.json_containers
    ]);
    expect(f.metadata).toMatchObject({
      evidence_count: "2",
      review_count: "1",
      closure_count: "1",
      cycle_count: "1"
    });
  });
  it("refuses a present changed or larger graph instead of pretending it vanished", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.fits = false;
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
      expect(manager.accounting.usedUnits).toBe(taskToolProjectionPlan(f.metadata).units);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
    f.state.hidden = true;
    expect(await owned(manager, f.helper)).toBeNull();
  });
  it("rejects identity substitution and count drift even when a synthetic row says fits", async () => {
    for (const [row, message] of [
      [{ board_id: id(90) }, "task tool projection identity is invalid"],
      [{ observation_sha256: "b".repeat(64) }, "task tool projection identity is invalid"],
      [{ view: { ...graph(), board_id: id(90) } }, "task tool payload identity is invalid"],
      [{ view: { ...graph(), evidence: [] } }, "task tool payload identity is invalid"],
      [{ view: { ...graph(), correction_cycles: [] } }, "task tool payload identity is invalid"],
      [{ view: { ...graph(), closure: null } }, "task tool payload identity is invalid"],
      [{ view: [] }, "task tool projection identity is invalid"]
    ] as const) {
      const f = fixture();
      f.state.contentRow = row as Record<string, unknown>;
      await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(message);
    }
  });
  it("refuses known oversized JSON before issuing content", async () => {
    const f = fixture();
    f.metadata.json_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.query.mock.calls.some(([sql]) => sql === TASK_TOOL_CONTENT_SQL)).toBe(false);
  });
  it("does not begin content after metadata-time disconnect", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    const owner = manager.openRequest(abort.signal);
    f.state.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query.mock.calls.some(([sql]) => sql === TASK_TOOL_CONTENT_SQL)).toBe(false);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("recomputes forged weights and rejects unsupported representations or invalid counts", () => {
    const metadata = measure(graph()),
      manager = new ResponseAllocationManager();
    const plan = taskToolProjectionPlan(metadata);
    expect(plan.units).toBe(1);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      "requires tool representation"
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(
      "requires tool representation"
    );
    const huge = taskToolProjectionPlan({ ...metadata, json_utf8: "999999999" });
    expect(huge.units).toBeGreaterThan(1920);
    expect(() => manager.tryReserve({ ...huge, units: 1 })).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
    expect(() => taskToolProjectionPlan({ ...metadata, review_count: "3" })).toThrow(
      "review count"
    );
    expect(() => taskToolProjectionPlan({ ...metadata, closure_count: "2" })).toThrow(
      "closure count"
    );
    expect(() => taskToolProjectionPlan({ ...metadata, row_version: "0" })).toThrow("row version");
    expect(() =>
      taskToolProjectionPlan({ ...metadata, observation_sha256: "z".repeat(64) })
    ).toThrow("observation hash");
    for (const value of ["-1", "01", "1.0", "1e2"])
      expect(() => taskToolProjectionPlan({ ...metadata, scalar_utf8: value })).toThrow(TypeError);
    expect(() => taskToolProjectionPlan({ ...metadata, scalar_utf8: "9".repeat(25) })).toThrow(
      ResponseAllocationUnavailable
    );
  });
  it("bounds independent UTF8 serialization and graph oracles for escaped text and arbitrary JSON", () => {
    const atoms = ["", "\b", "\t", "\n", "\f", "\r", '"', "\\", "Δ", "🙂", " "];
    for (let n = 0; n < 32; n += 1) {
      const text = Array.from({ length: 64 }, (_, i) => atoms[(i * 7 + n) % atoms.length]).join("");
      const q = graph();
      q["canonical_description"] = text;
      q["required_evidence"] = {
        [text]: [{}, [], { text, number: 1e100, tiny: 1e-100, flag: false, empty: null }]
      };
      q["source_locator"] = { section: text };
      q.evidence[0]!["canonical_text"] = text;
      q.evidence[1]!.review!["reason"] = text;
      q.closure!["accepted_evidence_manifest"] = [{ [text]: text }, [text]];
      q.correction_cycles[0]!["reason"] = text;
      const metadata = measure(q),
        cost = taskToolProjectionCost(metadata),
        actual = shape(q);
      const json = JSON.stringify({ task: q });
      expect(BigInt(Buffer.byteLength(json))).toBeLessThanOrEqual(BigInt(cost.jsonUpperBytes));
      expect(BigInt(actual.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
      expect(BigInt(actual.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
      const wire = JSON.stringify({
        content: [{ type: "text", text: json }],
        structuredContent: { task: q }
      });
      expect(Buffer.byteLength(wire)).toBeLessThanOrEqual(
        taskToolProjectionPlan(metadata).wireUpperBytes
      );
    }
  });
});
