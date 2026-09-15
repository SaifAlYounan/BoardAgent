import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  DRAFT_RESUME_PREFLIGHT_SQL,
  DRAFT_RESUME_CONTENT_SQL,
  draftResumeProjectionCost,
  draftResumeProjectionPlan,
  loadAdmittedResumeDraft,
  type DraftResumeMetadata
} from "../../artifacts/server/src/draft-resume-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { ORIGINAL_RESUME_DRAFT_SQL } from "../helpers/draft-resume-original-sql.js";

// Public registry/input/dispatch/result are real. Only transaction, authority and
// SQL are modeled. These meeting-draft literals do not claim normal writer or
// PG reachability, nor actual PG numeric normalization/recursive fault proof.
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
type Item = Record<string, JsonValue>;
const id = (n: number) => "01993700-0000-7000-8000-" + String(n).padStart(12, "0");
const principal: SurfacePrincipal = {
  organizationId: id(1),
  memberId: id(2),
  serviceOrigin: "https://boardagent.test",
  clientId: id(3),
  protocolClientId: "resume-draft-unit",
  accessTokenRecordId: id(4),
  tokenJti: id(5),
  keyId: "fixture",
  scopes: ["governance:read"],
  roles: ["member"],
  boardIds: [id(6)]
};
const literal = (name: "full" | "absent") =>
  readFileSync(new URL(`../fixtures/draft-resume-${name}.txt`, import.meta.url), "utf8").trim();
const full = () => JSON.parse(literal("full")) as { data: { draft: Item } };
const rootFlat = [
  "draft_id",
  "board_id",
  "draft_type",
  "current_step",
  "state",
  "ruleset_id",
  "package_sha256",
  "row_version",
  "expires_at"
] as const;
const stepFlat = [
  "step_id",
  "ordinal",
  "question_code",
  "value_schema",
  "value_sha256",
  "recommended_rule_id",
  "override_selected",
  "override_reason",
  "attempt",
  "recorded_at"
] as const;
function graph(roots: readonly unknown[]) {
  const seen = new Set<object>(),
    stack = [...roots];
  let properties = 0,
    containers = 0;
  while (stack.length) {
    const value = stack.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (!Array.isArray(value)) properties += Object.keys(value).length;
    stack.push(...Object.values(value));
  }
  return { properties, containers };
}
const digest = (value: unknown) => createHash("sha256").update(canonicalJson(value)).digest("hex");
type State = {
  view: Item | null;
  rawCanonical: string[];
  rawExpires: string;
  rawRecorded: string[];
};
const steps = (state: State) => (state.view ? (state.view["steps"] as Item[]) : []);
function initial(): State {
  const view = full().data.draft,
    selected = view["steps"] as Item[];
  return {
    view,
    rawCanonical: selected.map((step) => JSON.stringify(step["canonical_value"])),
    rawExpires: "2026-09-14 00:00:00.000001+00",
    rawRecorded: selected.map((step) => String(step["recorded_at"]))
  };
}
const scalarBytes = (value: unknown) => (value === null ? 0 : Buffer.byteLength(String(value)));
function measure(state: State): DraftResumeMetadata {
  if (!state.view)
    return {
      row_count: "0",
      step_count: "0",
      scalar_utf8: "0",
      json_utf8: "0",
      json_properties: "0",
      json_containers: "0",
      observation_sha256: digest([])
    };
  const children = steps(state),
    jsonRoots = children.flatMap((step) => [step["canonical_value"], step["citation_snapshot"]]);
  const shapes = jsonRoots.map((root) => graph([root]));
  // Independent complete public fields; JSON.stringify is explicitly the unit
  // model for N. The actual PostgreSQL normalized-text oracle is separate work.
  return {
    row_count: "1",
    step_count: String(children.length),
    scalar_utf8: String(
      rootFlat.reduce((n, key) => n + scalarBytes(state.view![key]), 0) +
        children.reduce(
          (n, step) => n + stepFlat.reduce((m, key) => m + scalarBytes(step[key]), 0),
          0
        )
    ),
    json_utf8: String(
      jsonRoots.reduce<number>((n, value) => n + Buffer.byteLength(JSON.stringify(value)), 0)
    ),
    json_properties: String(shapes.reduce((n, shape) => n + shape.properties, 0)),
    json_containers: String(shapes.reduce((n, shape) => n + shape.containers, 0)),
    observation_sha256: digest([
      state.view,
      state.rawCanonical,
      state.rawExpires,
      state.rawRecorded
    ])
  };
}
const result = (view: Item | null) => ({
  schema_version: "boardagent.tool-result.v1",
  tool: "resume_draft",
  status: "ok",
  reference: id(10),
  resource_uri: null,
  data: { draft: view }
});
function fixture(manager: ResponseAllocationManager) {
  const state = initial();
  let contentCalls = 0,
    constructions = 0;
  const reservations: number[] = [];
  const controls: {
    afterMetadata?: () => void | Promise<void>;
    beforeContent?: () => void | Promise<void>;
    metadataRows?: unknown[];
    contentRows?: unknown[];
  } = {};
  const query = vi.fn(async (sql: string, args?: unknown[]) => {
    expect(args?.slice(0, 2)).toEqual([id(10), principal.memberId]);
    if (sql === DRAFT_RESUME_PREFLIGHT_SQL) {
      const m = measure(state);
      await controls.afterMetadata?.();
      return { rows: controls.metadataRows ?? [m] };
    }
    if (sql !== DRAFT_RESUME_CONTENT_SQL && sql !== ORIGINAL_RESUME_DRAFT_SQL)
      throw new Error("unexpected draft fixture query");
    contentCalls++;
    reservations.push(manager.accounting.usedUnits);
    await controls.beforeContent?.();
    if (sql === DRAFT_RESUME_CONTENT_SQL) {
      if (controls.contentRows) return { rows: controls.contentRows };
      const m = measure(state),
        expected = args?.slice(2);
      const fits =
        m.row_count === "0" ||
        (m.row_count === expected?.[0] &&
          m.step_count === expected?.[1] &&
          m.observation_sha256 === expected?.[6] &&
          [m.scalar_utf8, m.json_utf8, m.json_properties, m.json_containers].every(
            (value, index) => BigInt(value) <= BigInt(String(expected?.[index + 2]))
          ));
      if (!fits) return { rows: [{ fits: false, view: null }] };
    }
    if (state.view) constructions++;
    return {
      rows: state.view
        ? [
            sql === DRAFT_RESUME_CONTENT_SQL
              ? { fits: true, view: state.view }
              : { view: state.view }
          ]
        : []
    };
  });
  const client = { query } as unknown as PoolClient;
  const repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
    cursorKey: Buffer.alloc(32, 1)
  });
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
  };
  const live = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  return {
    state,
    controls,
    query,
    client,
    live,
    authorize,
    reservations,
    get contentCalls() {
      return contentCalls;
    },
    get constructions() {
      return constructions;
    },
    read: () =>
      repo.executeRead(principal, "resume_draft", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        draft_id: id(10)
      }),
    load: () => loadAdmittedResumeDraft(client, id(10), principal.memberId)
  };
}
const terminal = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
async function owned<T>(manager: ResponseAllocationManager, work: () => Promise<T>) {
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(work);
  } finally {
    terminal(owner);
  }
}
const one = responseAllocationPlan({
  kind: "document",
  representation: "tool",
  canonicalBytes: 1,
  sourceId: "occupancy",
  sourceVersion: "1",
  sha256: "a".repeat(64)
});
const capture = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error) => ({ ok: false as const, error })
  );

describe("dynamic resume draft response admission", () => {
  it("preserves the complete original public meeting draft and every ordered attempt", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      actual = await owned(manager, f.read);
    expect(canonicalJson(actual)).toBe(literal("full"));
    expect(actual).toEqual(result(f.state.view));
    expect(f.constructions).toBe(1);
    expect(Object.keys(f.state.view!).sort()).toEqual([...rootFlat, "steps"].sort());
    for (const step of steps(f.state))
      expect(Object.keys(step).sort()).toEqual(
        [...stepFlat, "canonical_value", "citation_snapshot"].sort()
      );
    expect(steps(f.state).map((step) => [step["ordinal"], step["attempt"]])).toEqual([
      [0, 1],
      [0, 2],
      [1, 1]
    ]);
    expect(JSON.stringify(actual)).toBe(JSON.stringify(result(f.state.view)));
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves the original absent draft envelope and requested reference", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager);
    f.state.view = null;
    expect(canonicalJson(await owned(manager, f.read))).toBe(literal("absent"));
    expect(f.constructions).toBe(0);
  });
  it("requires an owner before public draft metadata", async () => {
    const f = fixture(new ResponseAllocationManager());
    await expect(f.read()).rejects.toThrow("owner");
    expect(f.query).not.toHaveBeenCalled();
  });
  it("refuses public full construction at all2048 occupied units", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      occupied = manager.openRequest(new AbortController().signal);
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 2048; i++) occupied.reserve(one);
      });
      await expect(owned(manager, f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.contentCalls).toBe(0);
      expect(manager.accounting.usedUnits).toBe(2048);
    } finally {
      terminal(occupied);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("holds the public visible draft through both terminal signals", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      owner = manager.openRequest(new AbortController().signal);
    try {
      const actual = await owner.produce(f.read);
      expect(actual).toEqual(result(f.state.view));
      expect(f.reservations).toEqual([1]);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(1);
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      terminal(owner);
    }
  });
  it("reserves the public absent draft envelope until settlement", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      owner = manager.openRequest(new AbortController().signal);
    f.state.view = null;
    try {
      expect(await owner.produce(f.read)).toEqual(result(null));
      expect(f.reservations).toEqual([1]);
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      terminal(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("aborts the public read after metadata without full construction", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    f.controls.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.contentCalls).toBe(0);
    } finally {
      terminal(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains a held public producer after abort and releases after bounded cleanup", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    let enter!: () => void,
      release!: () => void,
      done = false,
      timer: ReturnType<typeof setTimeout> | undefined;
    const entered = new Promise<void>((resolve) => {
        enter = resolve;
      }),
      gate = new Promise<void>((resolve) => {
        release = resolve;
      });
    f.controls.beforeContent = async () => {
      enter();
      await gate;
    };
    const settled = capture(owner.produce(f.read)).finally(() => {
      done = true;
    });
    const failures: unknown[] = [];
    try {
      await Promise.race([
        entered,
        settled.then(() => {
          throw new Error("producer settled before content gate");
        }),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error("content gate deadline")), 2000);
        })
      ]);
      expect(manager.accounting.usedUnits).toBe(1);
      abort.abort();
      terminal(owner);
      expect(manager.accounting.usedUnits).toBe(1);
      release();
      await vi.waitFor(() => expect(done).toBe(true), { timeout: 1000 });
      const outcome = await settled;
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) expect(outcome.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(manager.accounting.usedUnits).toBe(0);
    } catch (error) {
      failures.push(error);
    } finally {
      if (timer) clearTimeout(timer);
      release();
      abort.abort();
      terminal(owner);
      try {
        await vi.waitFor(() => expect(done).toBe(true), { timeout: 1000 });
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length) throw new AggregateError(failures, "held draft fixture failures");
  });
  for (const authority of ["actor", "authorization"] as const)
    it("preserves " + authority + " refusal before projection", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(manager),
        error = new Error("synthetic authority refusal");
      if (authority === "actor") f.live.mockRejectedValueOnce(error);
      else
        f.authorize.mockImplementationOnce(() => {
          throw error;
        });
      await expect(owned(manager, f.read)).rejects.toBe(error);
      expect(f.query).not.toHaveBeenCalled();
      expect(manager.accounting.usedUnits).toBe(0);
    });
  it("preserves original selected-query errors unchanged", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      error = new Error("synthetic selected UTF8/JSON query error");
    f.query.mockRejectedValueOnce(error);
    await expect(owned(manager, f.read)).rejects.toBe(error);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects a pre-aborted producer before any query", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    abort.abort();
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    } finally {
      terminal(owner);
    }
    expect(f.query).not.toHaveBeenCalled();
  });
  it("independently bounds complete retained UTF8 and nested JSON graphs", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      m = measure(f.state),
      plan = draftResumeProjectionPlan(id(10), m);
    const rows = await owned(manager, f.load),
      actual = result(f.state.view),
      wire = {
        content: [{ type: "text", text: JSON.stringify(actual) }],
        structuredContent: actual
      };
    const shape = graph([rows, wire]),
      v = plan.listProjection!;
    const j =
      4096n +
      512n +
      512n * BigInt(m.step_count) +
      6n * BigInt(m.scalar_utf8) +
      2n * BigInt(m.json_utf8);
    expect(v.jsonUpperBytes).toBe(String(j));
    expect(shape.properties).toBeLessThanOrEqual(Number(v.propertyCount));
    expect(shape.containers).toBeLessThanOrEqual(Number(v.objectOrArrayCount));
    expect(Buffer.byteLength(JSON.stringify(rows))).toBeLessThanOrEqual(Number(j));
    expect(Buffer.byteLength(JSON.stringify(actual))).toBeLessThanOrEqual(Number(j) + 4096);
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves zero-step and nullable draft fields", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager);
    f.state.view!["steps"] = [];
    f.state.rawCanonical = [];
    f.state.rawRecorded = [];
    const rows = await owned(manager, f.load);
    expect(rows).toEqual([{ fits: true, view: f.state.view }]);
    expect(measure(f.state).json_containers).toBe("0");
  });
  it("allows complete disappearance after a nonempty preflight", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager);
    f.controls.afterMetadata = () => {
      f.state.view = null;
    };
    expect(await owned(manager, f.load)).toEqual([]);
    expect(f.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses a newcomer after an empty preflight", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      saved = f.state.view;
    f.state.view = null;
    f.controls.afterMetadata = () => {
      f.state.view = saved;
    };
    await expect(owned(manager, f.load)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(f.constructions).toBe(0);
  });
  const changes = [
    "new-step",
    "partial-subset",
    "same-cost-value",
    "same-cost-reason",
    "same-cost-raw-json",
    "same-cost-private-time"
  ] as const;
  for (const change of changes)
    it("refuses the modeled " + change + " freshness change before construction", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(manager),
        before = measure(f.state);
      f.controls.afterMetadata = () => {
        const children = steps(f.state);
        if (change === "new-step") {
          children.push({ ...children[2]!, step_id: id(99), ordinal: 2 });
          f.state.rawCanonical.push("null");
          f.state.rawRecorded.push(String(children[2]!["recorded_at"]));
        } else if (change === "partial-subset") {
          children.pop();
          f.state.rawCanonical.pop();
          f.state.rawRecorded.pop();
        } else if (change === "same-cost-value") {
          (children[0]!["canonical_value"] as Item)["text"] =
            'Mining Θ exploration\\review\n\t"minutes"';
        } else if (change === "same-cost-reason")
          children[1]!["override_reason"] = "Use revised agenda — C";
        else if (change === "same-cost-raw-json") {
          const value = JSON.parse(f.state.rawCanonical[0]!) as Item;
          f.state.rawCanonical[0] = JSON.stringify(
            Object.fromEntries(Object.entries(value).reverse())
          );
        } else f.state.rawRecorded[0] = f.state.rawRecorded[0]!.replace("000001", "000002");
        const after = measure(f.state);
        expect(after.observation_sha256).not.toBe(before.observation_sha256);
        if (change.startsWith("same-cost"))
          for (const field of [
            "row_count",
            "step_count",
            "scalar_utf8",
            "json_utf8",
            "json_properties",
            "json_containers"
          ] as const)
            expect(after[field]).toBe(before[field]);
        // Changes here are an in-memory query model, not mutations of actual
        // immutable rows or claims about a reachable normal writer transition.
      };
      await expect(owned(manager, f.load)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.constructions).toBe(0);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  const invalids = [
    "negative",
    "leading-zero",
    "decimal",
    "too-wide",
    "two-roots",
    "empty-with-step",
    "empty-with-bytes",
    "no-citation-node",
    "too-few-json-bytes",
    "bad-digest"
  ] as const;
  for (const invalid of invalids)
    it("rejects " + invalid + " scalar metadata before content", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(manager),
        m = { ...measure(f.state) };
      if (invalid === "negative") m.scalar_utf8 = "-1";
      else if (invalid === "leading-zero") m.step_count = "03";
      else if (invalid === "decimal") m.json_utf8 = "3.5";
      else if (invalid === "too-wide") m.scalar_utf8 = "9".repeat(25);
      else if (invalid === "two-roots") m.row_count = "2";
      else if (invalid === "empty-with-step") m.row_count = "0";
      else if (invalid === "empty-with-bytes") m.step_count = "0";
      else if (invalid === "no-citation-node") m.json_containers = "0";
      else if (invalid === "too-few-json-bytes") m.json_utf8 = "1";
      else m.observation_sha256 = "x".repeat(64);
      f.controls.metadataRows = [m];
      await expect(owned(manager, f.load)).rejects.toThrow();
      expect(f.contentCalls).toBe(0);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  for (const bad of [
    "metadata-empty",
    "metadata-duplicate",
    "content-duplicate",
    "content-wrong-id",
    "content-nonboolean",
    "content-null"
  ] as const)
    it("rejects " + bad + " contract corruption", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(manager),
        m = measure(f.state);
      if (bad === "metadata-empty") f.controls.metadataRows = [];
      else if (bad === "metadata-duplicate") f.controls.metadataRows = [m, m];
      else if (bad === "content-duplicate")
        f.controls.contentRows = [
          { fits: true, view: f.state.view },
          { fits: true, view: f.state.view }
        ];
      else if (bad === "content-wrong-id")
        f.controls.contentRows = [{ fits: true, view: { ...f.state.view, draft_id: id(999) } }];
      else if (bad === "content-nonboolean")
        f.controls.contentRows = [{ fits: "true", view: f.state.view }];
      else f.controls.contentRows = [{ fits: true, view: null }];
      await expect(owned(manager, f.load)).rejects.toThrow(TypeError);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  it("keeps the large measured draft separate from100 small reservations", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture(manager),
      large = manager.openRequest(new AbortController().signal),
      small = manager.openRequest(new AbortController().signal);
    steps(f.state)[0]!["value_schema"] = "boardagent." + "x".repeat(1048576) + ".v1";
    const plan = draftResumeProjectionPlan(id(10), measure(f.state));
    expect(plan.units).toBeGreaterThan(1);
    try {
      await large.produce(f.load);
      await small.produce(async () => {
        for (let n = 0; n < 100; n++) small.reserve(one);
      });
      expect(manager.accounting.usedUnits).toBe(plan.units + 100);
    } finally {
      terminal(large);
      terminal(small);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves tool-only authority and the1920/1921 reservation boundary", async () => {
    // Independent algebraic metrics, not a claimed normal stored/writer fixture.
    const m: DraftResumeMetadata = {
      row_count: "1",
      step_count: "1",
      scalar_utf8: "41939656",
      json_utf8: "6",
      json_properties: "0",
      json_containers: "1",
      observation_sha256: "a".repeat(64)
    };
    const accepted = draftResumeProjectionPlan(id(10), m),
      refused = draftResumeProjectionPlan(id(10), { ...m, scalar_utf8: "41939657" });
    expect(accepted.units).toBe(1920);
    expect(refused.units).toBe(1921);
    expect(() => responseAllocationPlan({ ...accepted, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...accepted, canonicalBytes: 1 })).toThrow(TypeError);
    expect(draftResumeProjectionCost(m)).toEqual({
      jsonUpperBytes: "251643068",
      propertyCount: "56",
      objectOrArrayCount: "17"
    });
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(async () => {
        expect(() => owner.reserve(refused)).toThrow(ResponseAllocationUnavailable);
        expect(manager.accounting.usedUnits).toBe(0);
        owner.reserve(accepted);
        expect(manager.accounting.usedUnits).toBe(1920);
      });
    } finally {
      terminal(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
