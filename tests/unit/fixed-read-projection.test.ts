import { createHmac } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  fixedReadPlan,
  type FixedReadKind as AllFixedReadKind
} from "../../artifacts/server/src/fixed-read-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_DRAFTS_SQL,
  ORIGINAL_WEBHOOKS_SQL,
  ORIGINAL_RETENTION_SQL
} from "../helpers/fixed-read-original-sql.js";

// Registry/input/parser/dispatch/output are real. Transaction, authority and SQL
// are modeled here; actual PostgreSQL/native proof remains separate.
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
type FixedReadKind = Exclude<AllFixedReadKind, "list_members" | "list_enrollments">;
type Item = Record<string, JsonValue>;
type Row = { item: Item; cursor_at: string; cursor_id: string };
const id = (n: number) => "01993700-0000-7000-8000-" + String(n).padStart(12, "0");
const key = Buffer.alloc(32, 1);
const kinds: readonly FixedReadKind[] = [
  "list_my_drafts",
  "list_my_webhooks",
  "get_retention_policy"
];
const original = {
  list_my_drafts: ORIGINAL_DRAFTS_SQL,
  list_my_webhooks: ORIGINAL_WEBHOOKS_SQL,
  get_retention_policy: ORIGINAL_RETENTION_SQL
} as const;
const principal: SurfacePrincipal = {
  organizationId: id(1),
  memberId: id(2),
  serviceOrigin: "https://boardagent.test",
  clientId: id(3),
  protocolClientId: "fixed-read-unit",
  accessTokenRecordId: id(4),
  tokenJti: id(5),
  keyId: "fixture",
  scopes: ["governance:read"],
  roles: ["member"],
  boardIds: [id(6)]
};
const retention = (count: string) => ({
  schema_version: "boardagent.retention-policy.v1",
  governance_records: "indefinite",
  physical_purge_available: false,
  soft_delete_behavior: "hidden_from_ordinary_surfaces_with_permanent_snapshot_and_tombstone",
  ephemeral_classes: {
    authorization_codes: "short_lived_then_inert",
    action_stages: "ten_minutes_then_inert",
    enrollment_links: "bounded_one_use",
    export_artifacts: "operator_configured_expiry_with_permanent_receipt"
  },
  retained_snapshot_count: count
});
function row(kind: Exclude<FixedReadKind, "get_retention_policy">, n: number): Row {
  const at = "2026-09-13T00:00:00.000001Z";
  return {
    cursor_at: at,
    cursor_id: id(n),
    item:
      kind === "list_my_drafts"
        ? {
            draft_id: id(n),
            board_id: id(6),
            draft_type: "proposal",
            current_step: 2147483647,
            state: "ready_to_confirm",
            ruleset_id: id(7),
            package_sha256: "a".repeat(64),
            row_version: "9223372036854775807",
            expires_at: "294276-12-31T23:59:59.999999Z",
            created_at: at
          }
        : {
            webhook_id: id(n),
            state: "disabled",
            endpoint_fingerprint: "a".repeat(64),
            ssrf_validation_receipt_sha256: "b".repeat(64),
            generation: "9223372036854775807",
            key_id: id(8),
            created_at: at,
            disabled_at: "294276-12-31T23:59:59.999999Z"
          }
  };
}
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
function fixture(kind: FixedReadKind, manager: ResponseAllocationManager, amount = 2) {
  let source =
    kind === "get_retention_policy"
      ? []
      : Array.from({ length: amount }, (_, n) => row(kind, amount - n));
  const queryReservations: number[] = [];
  const query = vi.fn(async (sql: string, args?: unknown[]) => {
    expect(sql).toBe(original[kind]);
    queryReservations.push(manager.accounting.usedUnits);
    if (kind === "get_retention_policy") return { rows: [{ count: "9223372036854775807" }] };
    const at = args?.[kind === "list_my_drafts" ? 2 : 1],
      cursor = args?.[kind === "list_my_drafts" ? 3 : 2];
    const take = args?.[kind === "list_my_drafts" ? 4 : 3];
    expect(args?.[0]).toBe(principal.memberId);
    if (kind === "list_my_drafts") expect(args?.[1]).toBeNull();
    expect(typeof take).toBe("number");
    const selected = source
      .filter(
        (r) =>
          at === null ||
          r.cursor_at < String(at) ||
          (r.cursor_at === at && r.cursor_id < String(cursor))
      )
      .slice(0, take as number);
    return { rows: selected };
  });
  const client = { query } as unknown as PoolClient;
  const repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
    cursorKey: key
  });
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const read = (limit = 100, cursor: string | null = null) =>
    repo.executeRead(principal, kind, {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      ...(kind === "get_retention_policy"
        ? {}
        : { limit, cursor, ...(kind === "list_my_drafts" ? { draft_type: null } : {}) })
    });
  return {
    query,
    read,
    source,
    queryReservations,
    liveActor,
    authorize,
    empty: () => {
      source = [];
    }
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
const result = (kind: FixedReadKind, data: JsonValue) => ({
  schema_version: "boardagent.tool-result.v1",
  tool: kind,
  status: "ok",
  reference: null,
  resource_uri: null,
  data
});

describe("fixed bounded draft, webhook and retention reads", () => {
  for (const kind of kinds) {
    it("requires an owner before the " + kind + " query", async () => {
      const f = fixture(kind, new ResponseAllocationManager());
      await expect(f.read()).rejects.toThrow("owner");
      expect(f.query).not.toHaveBeenCalled();
    });
    it("refuses " + kind + " before fetching any rows at full capacity", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(kind, manager);
      const occupied = manager.openRequest(new AbortController().signal);
      const one = responseAllocationPlan({
        kind: "document",
        representation: "tool",
        canonicalBytes: 1,
        sourceId: "occupancy",
        sourceVersion: "1",
        sha256: "a".repeat(64)
      });
      try {
        await occupied.produce(async () => {
          for (let n = 0; n < 2048; n++) occupied.reserve(one);
        });
        await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(f.query).not.toHaveBeenCalled();
        expect(manager.accounting.usedUnits).toBe(2048);
      } finally {
        terminal(occupied);
      }
      expect(manager.accounting.usedUnits).toBe(0);
    });
    it(
      "reserves before " + kind + " SQL and retains the allocation through both terminal signals",
      async () => {
        const manager = new ResponseAllocationManager(),
          f = fixture(kind, manager);
        const owner = manager.openRequest(new AbortController().signal);
        const expectedUnits = kind === "get_retention_policy" ? 1 : 8;
        try {
          const actual = await owner.produce(() => f.read());
          expect(f.queryReservations).toEqual([expectedUnits]);
          expect(manager.accounting.usedUnits).toBe(expectedUnits);
          const expected = result(
            kind,
            kind === "get_retention_policy"
              ? retention("9223372036854775807")
              : { items: f.source.map((r) => r.item), next_cursor: null }
          );
          expect(actual).toEqual(expected);
          expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
          owner.nativeTerminal();
          expect(manager.accounting.usedUnits).toBe(expectedUnits);
          owner.collectorSettled();
          expect(manager.accounting.usedUnits).toBe(0);
        } finally {
          terminal(owner);
        }
      }
    );
    it("preserves original " + kind + " query errors and settles reservations", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(kind, manager),
        error = new Error("synthetic SQL rejection");
      f.query.mockRejectedValueOnce(error);
      await expect(owned(manager, () => f.read())).rejects.toBe(error);
      expect(manager.accounting.usedUnits).toBe(0);
    });
    it("rejects aborted " + kind + " before the query", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(kind, manager),
        abort = new AbortController();
      const owner = manager.openRequest(abort.signal);
      abort.abort();
      try {
        await expect(owner.produce(() => f.read())).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
      } finally {
        terminal(owner);
      }
      expect(f.query).not.toHaveBeenCalled();
      expect(manager.accounting.usedUnits).toBe(0);
    });
    for (const collaborator of ["actor", "authorization"] as const)
      it("keeps " + collaborator + " denial before " + kind + " projection", async () => {
        const manager = new ResponseAllocationManager(),
          f = fixture(kind, manager),
          error = new Error("synthetic authority refusal");
        if (collaborator === "actor") f.liveActor.mockRejectedValueOnce(error);
        else
          f.authorize.mockImplementationOnce(() => {
            throw error;
          });
        await expect(owned(manager, () => f.read())).rejects.toBe(error);
        expect(f.query).not.toHaveBeenCalled();
        expect(manager.accounting.usedUnits).toBe(0);
      });
  }
  for (const kind of ["list_my_drafts", "list_my_webhooks"] as const) {
    it(
      "charges the " + kind + " original maximum501 rows and preserves actual public cursors",
      async () => {
        const manager = new ResponseAllocationManager(),
          f = fixture(kind, manager, 501);
        const owner = manager.openRequest(new AbortController().signal);
        try {
          const actual = await owner.produce(() => f.read(500));
          expect(f.queryReservations).toEqual([37]);
          expect(manager.accounting.usedUnits).toBe(37);
          const data = actual.data as Item,
            cursor = data.next_cursor;
          expect(data.items).toEqual(f.source.slice(0, 500).map((r) => r.item));
          expect(typeof cursor).toBe("string");
          const [encoded, mac] = (cursor as string).split(".");
          const payloadText = Buffer.from(encoded!, "base64url").toString("utf8");
          expect(mac).toBe(
            createHmac("sha256", key)
              .update("boardagent.cursor.v1\0")
              .update(payloadText)
              .digest("base64url")
          );
          const payload = JSON.parse(payloadText);
          expect(payload).toMatchObject({
            schema_version: "boardagent.cursor.v1",
            organization_id: principal.organizationId,
            member_id: principal.memberId,
            tool: kind,
            board_id: null,
            after: canonicalJson({ at: f.source[499]!.cursor_at, id: f.source[499]!.cursor_id })
          });
          expect(payload.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
          const wire = {
            content: [{ type: "text", text: JSON.stringify(actual) }],
            structuredContent: actual
          };
          const shape = graph([f.source, wire]),
            bound = fixedReadPlan(kind, principal.memberId, 500);
          expect(shape.properties).toBeLessThanOrEqual(Number(bound.listProjection!.propertyCount));
          expect(shape.containers).toBeLessThanOrEqual(
            Number(bound.listProjection!.objectOrArrayCount)
          );
          expect(Buffer.byteLength(JSON.stringify(f.source))).toBeLessThanOrEqual(
            Number(bound.listProjection!.jsonUpperBytes)
          );
          expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(bound.wireUpperBytes);
          terminal(owner);
          const next = await owned(manager, () => f.read(500, cursor as string));
          expect(next.data).toEqual({ items: [f.source[500]!.item], next_cursor: null });
        } finally {
          terminal(owner);
        }
        expect(manager.accounting.usedUnits).toBe(0);
      }
    );
    it("retains the empty " + kind + " envelope and fixed reservation", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(kind, manager);
      f.empty();
      const actual = await owned(manager, () => f.read(1));
      expect(actual).toEqual(result(kind, { items: [], next_cursor: null }));
      expect(f.queryReservations).toEqual([1]);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  }
  it("retention count and complete fixed graph fit one unit", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture("get_retention_policy", manager);
    const actual = await owned(manager, () => f.read()),
      bound = fixedReadPlan("get_retention_policy", principal.memberId);
    const rows = [{ count: "9223372036854775807" }],
      wire = {
        content: [{ type: "text", text: JSON.stringify(actual) }],
        structuredContent: actual
      };
    const shape = graph([rows, wire]);
    expect(shape.properties).toBeLessThanOrEqual(Number(bound.listProjection!.propertyCount));
    expect(shape.containers).toBeLessThanOrEqual(Number(bound.listProjection!.objectOrArrayCount));
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(bound.wireUpperBytes);
    expect(bound.units).toBe(1);
  });
  it("preserves the original fixed kinds and rejects invalid plans", () => {
    for (const limit of [0, -1, 501, Number.MAX_SAFE_INTEGER, 1.5, NaN]) {
      expect(() => fixedReadPlan("list_my_drafts", principal.memberId, limit)).toThrow(TypeError);
    }
    expect(() => fixedReadPlan("get_export_status" as FixedReadKind, principal.memberId)).toThrow(
      TypeError
    );
    expect(() => fixedReadPlan("get_retention_policy", principal.memberId, 1)).toThrow(TypeError);
    const plan = fixedReadPlan("list_my_webhooks", principal.memberId, 500);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    expect(plan.units).toBe(37);
  });
});
