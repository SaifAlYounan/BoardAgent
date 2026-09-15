import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  GOVERNANCE_PROFILE_TOOL_PREFLIGHT_SQL,
  GOVERNANCE_PROFILE_TOOL_CONTENT_SQL,
  RULESET_TOOL_PREFLIGHT_SQL,
  RULESET_TOOL_CONTENT_SQL,
  governanceToolProjectionCost,
  governanceToolProjectionPlan,
  loadAdmittedGovernanceToolProjection,
  type GovernanceToolProjectionMetadata,
  type GovernanceToolSelector
} from "../../artifacts/server/src/governance-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_PROFILE_TOOL_SQL,
  ORIGINAL_RULESET_TOOL_SQL
} from "../helpers/governance-tool-original-sql.js";

// Synthetic transaction and authority collaborators; real public input/registry
// path and exact readRules caller. These units do not execute SQL or prove RLS.
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
type Kind = GovernanceToolSelector["kind"];
type View = Record<string, JsonValue>;
const id = (n: number) => `01993500-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const load = (kind: Kind): View =>
  JSON.parse(
    readFileSync(new URL(`../fixtures/governance-tool-${kind}.json`, import.meta.url), "utf8")
  ) as View;
const original = { profile: ORIGINAL_PROFILE_TOOL_SQL, ruleset: ORIGINAL_RULESET_TOOL_SQL };
const preflight = {
  profile: GOVERNANCE_PROFILE_TOOL_PREFLIGHT_SQL,
  ruleset: RULESET_TOOL_PREFLIGHT_SQL
};
const content = { profile: GOVERNANCE_PROFILE_TOOL_CONTENT_SQL, ruleset: RULESET_TOOL_CONTENT_SQL };
const tool = { profile: "get_board_governance_profile", ruleset: "get_ruleset" };

function shape(value: unknown) {
  const pending = [value];
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
function measure(kind: Kind, view: View): GovernanceToolProjectionMetadata {
  // Independently enumerate all original fields; do not import production maps
  // or fixed byte/property constants. JS JSON spelling is only a unit oracle;
  // actual PostgreSQL::text whitespace/numerics need separate PG verification.
  const roots: JsonValue[] = [view["canonical_payload"]!];
  const flat =
    kind === "profile"
      ? [
          view["profile_id"],
          view["board_id"],
          view["version"],
          view["state"],
          view["schema_version"],
          view["sha256"],
          view["supersedes_id"],
          view["created_at"],
          view["activated_at"]
        ]
      : [
          view["ruleset_id"],
          view["board_id"],
          view["profile_id"],
          view["version"],
          view["state"],
          view["schema_version"],
          view["sha256"],
          view["supersedes_id"],
          view["created_at"],
          view["activated_at"]
        ];
  let rules = 0;
  if (kind === "profile") roots.push(view["source_agreement_references"]!);
  else
    for (const item of view["rules"] as View[]) {
      rules += 1;
      for (const value of [
        item["rule_id"],
        item["matter_type_id"],
        item["priority"],
        item["specificity"],
        item["approval_rule_id"],
        item["sha256"]
      ])
        flat.push(value);
      roots.push(item["condition"]!);
    }
  let bytes = 0,
    properties = 0,
    containers = 0;
  for (const root of roots) {
    bytes += Buffer.byteLength(JSON.stringify(root));
    const count = shape(root);
    properties += count.properties;
    containers += count.containers;
  }
  return {
    entity_id: String(view[kind === "profile" ? "profile_id" : "ruleset_id"]),
    board_id: String(view["board_id"]),
    version: Number(view["version"]),
    rule_count: String(rules),
    scalar_utf8: String(
      flat.reduce<number>(
        (sum, value) =>
          sum + (value === null || value === undefined ? 0 : Buffer.byteLength(String(value))),
        0
      )
    ),
    json_utf8: String(bytes),
    json_properties: String(properties),
    json_containers: String(containers),
    observation_sha256: digest(view) // Synthetic binding, not a SQL digest oracle.
  };
}
function envelope(kind: Kind, selector: number | string | null, view: View | null): JsonValue {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: tool[kind],
    status: "ok",
    reference: kind === "profile" ? null : selector,
    resource_uri: view
      ? `board://${id(2)}/${kind === "profile" ? "governance-profile" : "rulesets"}/${String(view["version"])}`
      : null,
    data: kind === "profile" ? { profile: view } : { ruleset: view }
  };
}
function fixture(kind: Kind, selector: number | string | null = null) {
  const state = {
    view: load(kind),
    missing: false,
    hidden: false,
    constructions: 0,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined,
    contentRows: undefined as unknown[] | undefined
  };
  const query = vi.fn(async (sql: string, params?: unknown[]) => {
    expect(params?.[0]).toBe(id(2));
    expect(params?.[1]).toBe(selector);
    if (sql === preflight[kind]) {
      const rows = state.missing ? [] : [measure(kind, state.view)];
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === original[kind] || sql === content[kind]) await state.beforeContent?.();
    if (sql === original[kind]) {
      if (state.missing) return { rows: [] };
      state.constructions += 1;
      return { rows: [{ view: state.view }] };
    }
    if (sql !== content[kind]) throw new Error("unexpected governance fixture SQL");
    if (state.contentRows) return { rows: state.contentRows };
    if (state.hidden) return { rows: [] };
    const current = measure(kind, state.view);
    const fits =
      params?.[2] === current.entity_id &&
      params[3] === current.version &&
      params[4] === current.observation_sha256 &&
      params[5] === current.rule_count &&
      ["scalar_utf8", "json_utf8", "json_properties", "json_containers"].every(
        (key, index) =>
          BigInt(current[key as keyof GovernanceToolProjectionMetadata]) <=
          BigInt(String(params[6 + index]))
      );
    if (fits) state.constructions += 1;
    return { rows: [{ ...current, fits, view: fits ? state.view : null }] };
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
    protocolClientId: "governance-projection-unit",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture",
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
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readRules(
      client: PoolClient,
      actor: SurfacePrincipal,
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, name, input) => {
    if (name !== tool[kind]) throw new Error("out-of-scope dispatch");
    return seam.readRules(connection, actor, name, input);
  });
  const input: GovernanceToolSelector =
    kind === "profile"
      ? { kind, boardId: id(2), version: selector as number | null }
      : { kind, boardId: id(2), rulesetId: selector as string | null };
  return {
    state,
    query,
    client,
    liveActor,
    authorize,
    helper: () => loadAdmittedGovernanceToolProjection(client, input),
    read: () =>
      repository.executeRead(principal, tool[kind], {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: id(2),
        ...(kind === "profile" ? { version: selector } : { ruleset_id: selector })
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
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

describe("governance tool projection admission", () => {
  for (const kind of ["profile", "ruleset"] as const) {
    it(`refuses public ${kind} before full construction under complete shared occupancy`, async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(kind);
      const leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
      let failure: unknown;
      try {
        try {
          await owned(manager, () => f.read());
        } catch (error) {
          failure = error;
        }
        expect(f.state.constructions, "old caller attempted full projection before admission").toBe(
          0
        );
        expect(failure).toBeInstanceOf(ResponseAllocationUnavailable);
        expect(f.liveActor).toHaveBeenCalledOnce();
        expect(f.authorize).toHaveBeenCalledOnce();
        expect(f.query.mock.calls.filter(([sql]) => sql === preflight[kind])).toHaveLength(1);
        expect(f.query.mock.calls.some(([sql]) => sql === content[kind])).toBe(false);
      } finally {
        for (const lease of leases) lease.release();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    });
    for (const collaborator of ["liveActor", "authorize"] as const) {
      it(`rejects ${kind} ${collaborator} denial before metadata or content`, async () => {
        const f = fixture(kind),
          denied = new Error("synthetic authority denied");
        if (collaborator === "liveActor") f.liveActor.mockRejectedValueOnce(denied);
        else
          f.authorize.mockImplementationOnce(() => {
            throw denied;
          });
        await expect(owned(new ResponseAllocationManager(), () => f.read())).rejects.toBe(denied);
        expect(f.query).not.toHaveBeenCalled();
        expect(f.state.constructions).toBe(0);
      });
    }
    for (const explicit of [false, true]) {
      it(`preserves original public ${kind} ${explicit ? "explicit" : "current"} envelope and bytes`, async () => {
        const selector = explicit ? (kind === "profile" ? 1 : id(3)) : null;
        const f = fixture(kind, selector),
          expected = envelope(kind, selector, load(kind));
        const result = await owned(new ResponseAllocationManager(), () => f.read());
        expect(result).toEqual(expected);
        expect(JSON.stringify(result)).toBe(JSON.stringify(expected));
        expect(canonicalJson(result)).toBe(canonicalJson(expected));
        expect(f.state.constructions).toBe(1);
      });
    }
    it(`preserves absent ${kind} null envelope without charging content`, async () => {
      const f = fixture(kind);
      f.state.missing = true;
      const manager = new ResponseAllocationManager();
      expect(await owned(manager, () => f.read())).toEqual(envelope(kind, null, null));
      expect(f.state.constructions).toBe(0);
      expect(manager.accounting.usedUnits).toBe(0);
    });
    it(`returns null when fresh ${kind} selection disappears after reservation`, async () => {
      const f = fixture(kind),
        manager = new ResponseAllocationManager();
      f.state.afterMetadata = () => {
        f.state.hidden = true;
      };
      expect(await owned(manager, () => f.helper())).toBeNull();
      expect(f.state.constructions).toBe(0);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  }
  it("retains inherited policy above exact SDK graph and bounds escaped arbitrary JSON independently", () => {
    for (const kind of ["profile", "ruleset"] as const) {
      const view = load(kind);
      view["canonical_payload"] = {
        data: Array.from({ length: 80 }, (_, n) => ({
          [String(n) + '\\"Δ']: [
            [],
            { value: '\u0001\n\r\t\\"🙂'.repeat(n + 1), other: [null, true, false, n] }
          ]
        }))
      };
      const meta = measure(kind, view),
        cost = governanceToolProjectionCost(kind, meta);
      const result = envelope(kind, null, view);
      const json = Buffer.from(JSON.stringify(result));
      expect(BigInt(json.length)).toBeLessThanOrEqual(BigInt(cost.jsonUpperBytes) + 4096n);
      const sdkValue = {
        content: [{ type: "text", text: json.toString() }],
        structuredContent: result
      };
      const graph = shape(sdkValue);
      // Complete actual wrapper graph plus the inherited12-property policy
      // allowance; no production field map or view-node constants are reused.
      expect(BigInt(cost.propertyCount)).toBe(BigInt(graph.properties) + 12n);
      expect(BigInt(cost.objectOrArrayCount)).toBe(BigInt(graph.containers));
      const sdk = Buffer.from(JSON.stringify(sdkValue));
      expect(sdk.length).toBeLessThanOrEqual(
        governanceToolProjectionPlan(kind, meta).wireUpperBytes
      );
    }
  });
  it("refuses parent JSON replacement even with unchanged stored hash and equal scalar costs", async () => {
    const f = fixture("profile");
    const before = measure("profile", f.state.view),
      storedHash = f.state.view["sha256"];
    f.state.afterMetadata = () => {
      (f.state.view["canonical_payload"] as View)["threshold"] = 0.6;
      const after = measure("profile", f.state.view);
      expect({ ...after, observation_sha256: before.observation_sha256 }).toEqual(before);
      expect(after.observation_sha256).not.toBe(before.observation_sha256);
      expect(f.state.view["sha256"]).toBe(storedHash);
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("refuses newly inserted rule rows before nested construction", async () => {
    const f = fixture("ruleset");
    f.state.afterMetadata = () => {
      (f.state.view["rules"] as JsonValue[]).push({
        ...(f.state.view["rules"] as View[])[0]!,
        rule_id: id(8)
      });
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("refuses a fresh current-selector replacement instead of reporting absence", async () => {
    const f = fixture("profile");
    f.state.afterMetadata = () => {
      f.state.view["profile_id"] = id(8);
      f.state.view["version"] = 2;
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("retains both helper reservations through producer completion until native and collector settlement", async () => {
    const manager = new ResponseAllocationManager(),
      a = fixture("profile"),
      b = fixture("ruleset");
    const owner = manager.openRequest(new AbortController().signal);
    await owner.produce(async () => {
      await a.helper();
      await b.helper();
    });
    const expected =
      governanceToolProjectionPlan("profile", measure("profile", a.state.view)).units +
      governanceToolProjectionPlan("ruleset", measure("ruleset", b.state.view)).units;
    expect(manager.accounting.usedUnits).toBe(expected);
    owner.nativeTerminal();
    expect(manager.accounting.usedUnits).toBe(expected);
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("keeps an early-disconnect reservation until the actual modeled producer finishes", async () => {
    const manager = new ResponseAllocationManager(),
      controller = new AbortController(),
      f = fixture("ruleset");
    const entered = gate(),
      finish = gate();
    f.state.beforeContent = async () => {
      entered.release();
      await finish.promise;
    };
    const owner = manager.openRequest(controller.signal);
    const pending = owner.produce(() => f.helper());
    const caught = pending.then(
      () => null,
      (error: unknown) => error
    );
    try {
      await Promise.race([
        entered.promise,
        pending.then(() => {
          throw new Error("content never held");
        })
      ]);
      controller.abort();
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      finish.release();
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(await caught).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("admits ordinary governance alongside 100 small reservations", async () => {
    const manager = new ResponseAllocationManager(),
      leases = Array.from({ length: 100 }, () => manager.tryReserve(small()));
    try {
      const f = fixture("ruleset");
      expect(await owned(manager, () => f.helper())).toEqual(f.state.view);
      expect(manager.accounting.usedUnits).toBe(100);
    } finally {
      for (const lease of leases) lease.release();
    }
  });
  it("retains fixed pipeline allowances and the exact large-lane policy boundary", () => {
    // Scalar-only arithmetic vectors, not stored JSON fixtures or maximum-size
    // acceptance claims. These fixed answers were derived independently.
    const base = {
      ...measure("profile", load("profile")),
      rule_count: "0",
      scalar_utf8: "0",
      json_utf8: "0",
      json_properties: "0",
      json_containers: "0"
    };
    const profile = governanceToolProjectionPlan("profile", base);
    const ruleset = governanceToolProjectionPlan("ruleset", base);
    expect(profile.listProjection).toEqual({
      jsonUpperBytes: "241",
      propertyCount: "34",
      objectOrArrayCount: "6"
    });
    expect(profile.wireUpperBytes).toBe(78547);
    expect(ruleset.listProjection).toEqual({
      jsonUpperBytes: "239",
      propertyCount: "35",
      objectOrArrayCount: "7"
    });
    expect(ruleset.wireUpperBytes).toBe(78541);
    const boundary = governanceToolProjectionPlan("profile", { ...base, json_utf8: "251644239" });
    const over = governanceToolProjectionPlan("profile", { ...base, json_utf8: "251644240" });
    expect(boundary.units).toBe(1920);
    expect(over.units).toBe(1921);
    const manager = new ResponseAllocationManager(),
      lease = manager.tryReserve(boundary);
    lease.release();
    expect(() => manager.tryReserve(over)).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects malformed or oversized scalar metadata and wrong plan representation", () => {
    const metadata = measure("profile", load("profile"));
    expect(() => governanceToolProjectionCost("profile", { ...metadata, json_utf8: "01" })).toThrow(
      TypeError
    );
    expect(() =>
      governanceToolProjectionCost("profile", { ...metadata, json_utf8: "9".repeat(25) })
    ).toThrow(ResponseAllocationUnavailable);
    const plan = governanceToolProjectionPlan("profile", metadata);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
  });
});
