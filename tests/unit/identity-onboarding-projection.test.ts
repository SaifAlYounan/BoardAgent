import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  IDENTITY_ONBOARDING_PREFLIGHT_SQL,
  IDENTITY_ONBOARDING_CONTENT_SQL,
  identityOnboardingProjectionCost,
  identityOnboardingProjectionPlan,
  loadAdmittedWhoami,
  loadAdmittedOnboarding,
  type IdentityOnboardingKind,
  type IdentityOnboardingMetadata
} from "../../artifacts/server/src/identity-onboarding-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_WHOAMI_SQL,
  ORIGINAL_ONBOARDING_SQL
} from "../helpers/identity-onboarding-original-sql.js";

// Public parser/registry and the three route callers are real. Authority, transaction,
// SQL and source fixtures are modeled; these units prove neither PG evaluation nor RLS.
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
type Tool = "whoami" | "get_onboarding" | "get_onboarding_status";
type Item = Record<string, JsonValue>;
const tools: readonly Tool[] = ["whoami", "get_onboarding", "get_onboarding_status"];
const id = (n: number) => `01993700-0000-7000-8000-${String(n).padStart(12, "0")}`;
const sha = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const object = (value: JsonValue): Item => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("literal object expected");
  return value as Item;
};
function graph(value: unknown) {
  const pending = [value],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const node = pending.pop();
    if (node === null || typeof node !== "object" || seen.has(node)) continue;
    seen.add(node);
    containers++;
    if (!Array.isArray(node)) properties += Object.keys(node).length;
    for (const child of Object.values(node)) pending.push(child);
  }
  return { properties, containers };
}
const principal: SurfacePrincipal = {
  organizationId: id(90),
  memberId: id(1),
  serviceOrigin: "https://boardagent.test",
  clientId: id(91),
  protocolClientId: 'synthetic "client" Δ',
  accessTokenRecordId: id(92),
  tokenJti: id(93),
  keyId: "fixture",
  roles: ["member", "secretariat"],
  scopes: ["governance:read"],
  boardIds: [id(2)]
};
const whoami = (): Item => ({
  member_id: id(1),
  member_kind: "human",
  display_name: 'Synthetic "Δ" 🙂',
  state: "active",
  accountable_principal_id: null,
  identity_generation: "9007199254740993",
  onboarding_generation: "2",
  roles: [...principal.roles],
  scopes: [...principal.scopes],
  board_ids: [...principal.boardIds],
  protocol_client_id: principal.protocolClientId,
  session_token_record_id: principal.accessTokenRecordId,
  recent_auth: {
    proof: 'synthetic proof "Δ"\n',
    session_id: id(94),
    authenticated_at: "2026-09-13T00:00:00.000001Z",
    expires_at: "2026-09-13T00:10:00.000001Z"
  }
});
const onboarding = (): Item => ({
  board_id: id(2),
  seat_role: "voting_member",
  terms: {
    version_id: id(20),
    version: 2,
    schema_version: "boardagent.onboarding-terms.v1",
    canonical_text: 'Synthetic terms "Δ"\n🙂',
    sha256: "a".repeat(64),
    material_change: true,
    effective_at: "2026-09-13T00:00:00.000001Z"
  },
  secretary_support: {
    version_id: id(21),
    version: 3,
    name: 'Synthetic support "Δ"',
    contact_methods: [{ kind: "example", value: ["Δ", null, {}, [false, 0.5]] }],
    sha256: "b".repeat(64)
  },
  attested: false,
  attested_at: null,
  presentation_choice: null,
  local_memory_choice: null
});
const WHOAMI_FLAT = [
  "member_id",
  "member_kind",
  "display_name",
  "state",
  "accountable_principal_id",
  "identity_generation",
  "onboarding_generation",
  "protocol_client_id",
  "session_token_record_id"
];
const AUTH_FLAT = ["proof", "session_id", "authenticated_at", "expires_at"];
const ONBOARDING_FLAT = [
  "board_id",
  "seat_role",
  "attested",
  "attested_at",
  "presentation_choice",
  "local_memory_choice"
];
const TERMS_FLAT = [
  "version_id",
  "version",
  "schema_version",
  "canonical_text",
  "sha256",
  "material_change",
  "effective_at"
];
const SUPPORT_FLAT = ["version_id", "version", "name", "sha256"];
function measure(
  kind: IdentityOnboardingKind,
  views: readonly Item[],
  privateVersion = "1"
): IdentityOnboardingMetadata {
  let s = 0,
    n = 0,
    p = 0,
    o = 0,
    a = 0;
  const flat = (view: Item, keys: readonly string[]) => {
    for (const key of keys) {
      const value = view[key];
      s += value === null ? 0 : Buffer.byteLength(String(value));
    }
  };
  const json = (value: JsonValue) => {
    n += Buffer.byteLength(JSON.stringify(value));
    const g = graph(value);
    p += g.properties;
    o += g.containers;
  };
  for (const view of views) {
    if (kind === "whoami") {
      flat(view, WHOAMI_FLAT);
      for (const key of ["roles", "scopes", "board_ids"]) json(view[key]!);
      if (view.recent_auth !== null) {
        a++;
        flat(object(view.recent_auth!), AUTH_FLAT);
      }
    } else {
      flat(view, ONBOARDING_FLAT);
      flat(object(view.terms!), TERMS_FLAT);
      flat(object(view.secretary_support!), SUPPORT_FLAT);
      json(object(view.secretary_support!).contact_methods!);
    }
  }
  return {
    row_count: String(views.length),
    recent_auth_count: String(a),
    scalar_utf8: String(s),
    normalized_json_utf8: String(n),
    json_property_count: String(p),
    json_container_count: String(o),
    observation_sha256: sha(
      views.length ? canonicalJson({ views: [...views], privateVersion }) : ""
    )
  };
}
function expected(tool: Tool, views: readonly Item[]): SurfaceToolResult {
  const first = views[0];
  let data: JsonValue;
  if (tool === "whoami") {
    if (!first) throw new Error("identity unavailable");
    data = first;
  } else if (tool === "get_onboarding") data = { onboarding: first ?? null };
  else
    data = {
      board_id: id(2),
      status: !first ? "unavailable" : first.attested === true ? "current" : "required",
      terms_version_id: first ? object(first.terms!).version_id! : null
    };
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: tool === "whoami" ? id(1) : tool === "get_onboarding" ? id(2) : null,
    resource_uri: null,
    data
  };
}
function fixture() {
  const state = {
    whoami: [whoami()],
    onboarding: [onboarding()],
    privateVersion: "1",
    constructions: 0,
    afterMetadata: undefined as (() => void) | undefined,
    metadataOverride: undefined as unknown[] | undefined,
    contentOverride: undefined as unknown[] | undefined,
    contentError: undefined as Error | undefined
  };
  const query = vi.fn(async (sql: string, parameters: unknown[] = []) => {
    for (const kind of ["whoami", "onboarding"] as const) {
      const original = kind === "whoami" ? ORIGINAL_WHOAMI_SQL : ORIGINAL_ONBOARDING_SQL;
      if (
        ![
          original,
          IDENTITY_ONBOARDING_PREFLIGHT_SQL[kind],
          IDENTITY_ONBOARDING_CONTENT_SQL[kind]
        ].includes(sql)
      )
        continue;
      const count = kind === "whoami" ? 6 : 2;
      expect(parameters.slice(0, count)).toEqual(
        kind === "whoami"
          ? [
              principal.memberId,
              principal.roles,
              principal.scopes,
              principal.boardIds,
              principal.protocolClientId,
              principal.accessTokenRecordId
            ]
          : [id(2), principal.memberId]
      );
      const views = state[kind],
        m = measure(kind, views, state.privateVersion);
      if (sql === IDENTITY_ONBOARDING_PREFLIGHT_SQL[kind]) {
        const rows = state.metadataOverride ?? [m];
        state.afterMetadata?.();
        return { rows };
      }
      if (state.contentError) throw state.contentError;
      if (state.contentOverride) return { rows: state.contentOverride };
      if (sql === IDENTITY_ONBOARDING_CONTENT_SQL[kind]) {
        const b = parameters.slice(count);
        const fits =
          views.length === 0 ||
          (m.row_count === b[0] &&
            m.recent_auth_count === b[1] &&
            BigInt(m.scalar_utf8) <= BigInt(String(b[2])) &&
            BigInt(m.normalized_json_utf8) <= BigInt(String(b[3])) &&
            BigInt(m.json_property_count) <= BigInt(String(b[4])) &&
            BigInt(m.json_container_count) <= BigInt(String(b[5])) &&
            m.observation_sha256 === b[6]);
        if (!fits) return { rows: [{ fits: false, view: null }] };
      }
      state.constructions++;
      return { rows: views.map((view) => ({ ...(sql === original ? {} : { fits: true }), view })) };
    }
    throw new Error("unexpected identity/onboarding SQL");
  });
  const client = { query } as unknown as PoolClient,
    repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
      cursorKey: Buffer.alloc(32, 1)
    });
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    dispatch(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    whoami(client: PoolClient, actor: SurfacePrincipal): Promise<SurfaceToolResult>;
    getOnboarding(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      boardId: string
    ): Promise<SurfaceToolResult>;
  };
  const live = vi.spyOn(seam, "liveActor").mockResolvedValue({}),
    authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((c, a, t, input) => {
    if (!tools.includes(t as Tool)) throw new Error("out-of-scope dispatch");
    return t === "whoami" ? seam.whoami(c, a) : seam.getOnboarding(c, a, t, String(input.board_id));
  });
  return {
    state,
    query,
    client,
    live,
    authorize,
    read: (tool: Tool) =>
      repo.executeRead(principal, tool, {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        ...(tool === "whoami" ? {} : { board_id: id(2) })
      }),
    helper: (kind: IdentityOnboardingKind) =>
      kind === "whoami"
        ? loadAdmittedWhoami(client, principal)
        : loadAdmittedOnboarding(client, id(2), id(1))
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
describe("identity and onboarding projection admission", () => {
  for (const tool of tools) {
    it(`preserves the original complete ${tool} result`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager(),
        kind = tool === "whoami" ? "whoami" : "onboarding";
      const result = await owned(manager, () => f.read(tool));
      expect(result).toEqual(expected(tool, f.state[kind]));
      expect(canonicalJson(result)).toBe(canonicalJson(expected(tool, f.state[kind])));
      expect(JSON.stringify(result)).toBe(JSON.stringify(expected(tool, f.state[kind])));
      expect(f.live).toHaveBeenCalledTimes(1);
      expect(f.authorize).toHaveBeenCalledTimes(1);
    });
    it(`refuses saturated public ${tool} before its full constructor`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager(),
        occupied = manager.openRequest(new AbortController().signal);
      try {
        await occupied.produce(async () => {
          for (let i = 0; i < 2048; i++) occupied.reserve(small());
        });
        const result = await owned(manager, () => f.read(tool)).then(
          () => null,
          (error) => error
        );
        expect(f.state.constructions).toBe(0);
        expect(result).toBeInstanceOf(ResponseAllocationUnavailable);
      } finally {
        occupied.nativeTerminal();
        occupied.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    });
    it(`requires an owner for public ${tool} before metadata`, async () => {
      const f = fixture();
      await expect(f.read(tool)).rejects.toBeInstanceOf(TypeError);
      expect(f.query).not.toHaveBeenCalled();
      expect(f.state.constructions).toBe(0);
    });
  }
  it("preserves absent member and all three onboarding status states", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.whoami = [];
    await expect(owned(manager, () => f.read("whoami"))).rejects.toThrow("identity unavailable");
    for (const state of ["unavailable", "required", "current"] as const) {
      f.state.onboarding =
        state === "unavailable" ? [] : [{ ...onboarding(), attested: state === "current" }];
      expect((await owned(manager, () => f.read("get_onboarding_status"))).data).toEqual(
        expected("get_onboarding_status", f.state.onboarding).data
      );
      expect((await owned(manager, () => f.read("get_onboarding"))).data).toEqual({
        onboarding: f.state.onboarding[0] ?? null
      });
    }
  });
  it("preserves absent recent auth and nullable members without numeric generation rounding", async () => {
    const f = fixture();
    f.state.whoami[0]!.recent_auth = null;
    expect(await owned(new ResponseAllocationManager(), () => f.read("whoami"))).toEqual(
      expected("whoami", f.state.whoami)
    );
  });
  for (const kind of ["whoami", "onboarding"] as const) {
    it(`bounds independent retained PG and SDK graphs for ${kind}`, async () => {
      const f = fixture();
      if (kind === "onboarding")
        f.state.onboarding = Array.from({ length: 3 }, () => structuredClone(onboarding()));
      const m = measure(kind, f.state[kind]),
        cost = identityOnboardingProjectionCost(kind, m),
        plan = identityOnboardingProjectionPlan(kind, "test", m);
      expect(cost).toEqual({
        jsonUpperBytes: String(
          2 +
            1000 * f.state[kind].length +
            6 * Number(m.scalar_utf8) +
            Number(m.normalized_json_utf8)
        ),
        propertyCount: String(
          32 +
            (kind === "whoami"
              ? 15 * f.state[kind].length + 4 * Number(m.recent_auth_count)
              : 22 * f.state[kind].length) +
            Number(m.json_property_count)
        ),
        objectOrArrayCount: String(
          12 +
            (kind === "whoami"
              ? 2 * f.state[kind].length + Number(m.recent_auth_count)
              : 4 * f.state[kind].length) +
            Number(m.json_container_count)
        )
      });
      const rows = await owned(new ResponseAllocationManager(), () => f.helper(kind));
      for (const tool of kind === "whoami"
        ? ["whoami" as const]
        : ["get_onboarding" as const, "get_onboarding_status" as const]) {
        const result = expected(
            tool,
            rows.map((r) => object(r.view))
          ),
          wire = {
            content: [{ type: "text", text: JSON.stringify(result) }],
            structuredContent: result
          };
        const retained = graph([rows, wire]);
        expect(retained.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
        expect(retained.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
        expect(Buffer.byteLength(JSON.stringify(rows))).toBeLessThanOrEqual(
          Number(cost.jsonUpperBytes)
        );
        expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
      }
    });
    it(`refuses same-cost private identity changes for ${kind}`, async () => {
      const f = fixture(),
        before = measure(kind, f.state[kind]);
      f.state.afterMetadata = () => {
        f.state.privateVersion = "2";
      };
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper(kind))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      const after = measure(kind, f.state[kind], "2");
      expect({ ...after, observation_sha256: before.observation_sha256 }).toEqual(before);
      expect(after.observation_sha256).not.toBe(before.observation_sha256);
      expect(f.state.constructions).toBe(0);
    });
    it(`binds actual same-cost public text or JSON in ${kind}`, async () => {
      const f = fixture(),
        before = measure(kind, f.state[kind]);
      f.state.afterMetadata = () => {
        if (kind === "whoami") f.state.whoami[0]!.display_name = 'Synthetic "Ω" 🙂';
        else
          object(f.state.onboarding[0]!.secretary_support!).contact_methods = [
            { kind: "example", value: ["Δ", null, {}, [false, 0.6]] }
          ];
      };
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper(kind))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      const after = measure(kind, f.state[kind]);
      expect({ ...after, observation_sha256: before.observation_sha256 }).toEqual(before);
      expect(after.observation_sha256).not.toBe(before.observation_sha256);
      expect(f.state.constructions).toBe(0);
    });
    it(`allows only a complete fresh disappearance for ${kind}`, async () => {
      const f = fixture();
      f.state.afterMetadata = () => {
        f.state[kind] = [];
      };
      expect(await owned(new ResponseAllocationManager(), () => f.helper(kind))).toEqual([]);
    });
    it(`retains its ${kind} lease until both owner signals`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager(),
        owner = manager.openRequest(new AbortController().signal);
      try {
        await owner.produce(() => f.helper(kind));
        expect(manager.accounting.usedUnits).toBe(1);
        owner.nativeTerminal();
        expect(manager.accounting.usedUnits).toBe(1);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    });
  }
  it("refuses a nonempty onboarding subset and accounts for every discarded status row", async () => {
    const f = fixture();
    f.state.onboarding = [onboarding(), structuredClone(onboarding())];
    f.state.afterMetadata = () => {
      f.state.onboarding.pop();
    };
    await expect(
      owned(new ResponseAllocationManager(), () => f.helper("onboarding"))
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(f.state.constructions).toBe(0);
  });
  it("counts deeply nested arbitrary contact JSON rather than only its text bytes", () => {
    const view = onboarding();
    object(view.secretary_support!).contact_methods = Array.from({ length: 200 }, () => ({
      a: [{}, []]
    }));
    const m = measure("onboarding", [view]),
      c = identityOnboardingProjectionCost("onboarding", m);
    expect(m.json_property_count).toBe("200");
    expect(m.json_container_count).toBe("801");
    expect(c.propertyCount).toBe("254");
    expect(c.objectOrArrayCount).toBe("817");
  });
  for (const [label, patch] of [
    ["leading zero", { row_count: "01" }],
    ["too many whoami roots", { row_count: "2" }],
    ["auth without member", { recent_auth_count: "2" }],
    ["missing JSON roots", { json_container_count: "0" }],
    ["negative bytes", { scalar_utf8: "-1" }],
    ["bad digest", { observation_sha256: "x" }]
  ] as const) {
    it(`rejects metadata ${label} before content`, async () => {
      const f = fixture();
      f.state.metadataOverride = [{ ...measure("whoami", f.state.whoami), ...patch }];
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper("whoami"))
      ).rejects.toBeInstanceOf(TypeError);
      expect(f.state.constructions).toBe(0);
    });
  }
  it("refuses overlong aggregate decimals without coercion", () => {
    const m = measure("onboarding", [onboarding()]);
    expect(() =>
      identityOnboardingProjectionCost("onboarding", { ...m, scalar_utf8: "1".repeat(25) })
    ).toThrow(ResponseAllocationUnavailable);
  });
  for (const [label, rows] of [
    ["false global sentinel", [{ fits: false, view: null }]],
    ["missing fits", [{ view: whoami() }]],
    ["wrong member", [{ fits: true, view: { ...whoami(), member_id: id(999) } }]]
  ] as const) {
    it(`rejects ${label} after admitted query`, async () => {
      const f = fixture();
      f.state.contentOverride = [...rows];
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper("whoami"))
      ).rejects.toBeInstanceOf(
        label === "false global sentinel" ? ResponseAllocationUnavailable : TypeError
      );
    });
  }
  it("keeps the private kind tool-only with no canonical bytes", () => {
    const plan = identityOnboardingProjectionPlan("whoami", "test", measure("whoami", [whoami()]));
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
  });
  it("enforces the independently derived 1920/1921 reservation boundary", async () => {
    // Ten-row pure scalar vector, not a claim that a complete writer fixture has this exact size.
    const m: IdentityOnboardingMetadata = {
      row_count: "10",
      recent_auth_count: "0",
      scalar_utf8: "41937316",
      normalized_json_utf8: "20",
      json_property_count: "0",
      json_container_count: "10",
      observation_sha256: "a".repeat(64)
    };
    const accepted = identityOnboardingProjectionPlan("onboarding", "boundary", m),
      refused = identityOnboardingProjectionPlan("onboarding", "boundary", {
        ...m,
        scalar_utf8: "41937317"
      });
    expect(accepted.units).toBe(1920);
    expect(refused.units).toBe(1921);
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(async () => owner.reserve(refused))).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(manager.accounting.usedUnits).toBe(0);
      await owner.produce(async () => owner.reserve(accepted));
      expect(manager.accounting.usedUnits).toBe(1920);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("propagates query failure and releases the retained reservation", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      failure = new Error("synthetic content SQL failure");
    f.state.contentError = failure;
    await expect(owned(manager, () => f.helper("whoami"))).rejects.toBe(failure);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses an abort after preflight before content", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      controller = new AbortController(),
      owner = manager.openRequest(controller.signal);
    f.state.afterMetadata = () => controller.abort();
    try {
      await expect(owner.produce(() => f.helper("whoami"))).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  for (const phase of ["live", "authorize"] as const)
    it(`preserves ${phase} denial before all SQL`, async () => {
      const f = fixture(),
        error = new Error(`synthetic ${phase} denial`);
      if (phase === "live") f.live.mockRejectedValue(error);
      else
        f.authorize.mockImplementation(() => {
          throw error;
        });
      await expect(
        owned(new ResponseAllocationManager(), () => f.read("get_onboarding"))
      ).rejects.toBe(error);
      expect(f.query).not.toHaveBeenCalled();
    });
  it("admits an actual maximum-character terms body alongside 100 small leases", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      occupied = manager.openRequest(new AbortController().signal),
      view = onboarding();
    object(view.terms!).canonical_text = "🙂".repeat(1_048_576);
    f.state.onboarding = [view];
    const m = measure("onboarding", f.state.onboarding);
    expect(Buffer.byteLength(String(object(view.terms!).canonical_text))).toBe(4_194_304);
    const plan = identityOnboardingProjectionPlan("onboarding", "max ordinary terms", m);
    expect(plan.units).toBe(193);
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 100; i++) occupied.reserve(small());
      });
      await owned(manager, () => f.helper("onboarding"));
      expect(manager.accounting.usedUnits).toBe(100);
    } finally {
      occupied.nativeTerminal();
      occupied.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
