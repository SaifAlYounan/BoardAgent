import { createHmac } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import { fixedReadPlan } from "../../artifacts/server/src/fixed-read-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_MEMBERS_SQL,
  ORIGINAL_ENROLLMENTS_SQL
} from "../helpers/fixed-identity-original-sql.js";

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

type FixedReadKind = "list_members" | "list_enrollments";
type Item = Record<string, JsonValue>;
type Row = { item: Item; cursor_at: string; cursor_id: string };
const id = (n: number) => "01993700-0000-7000-8000-" + String(n).padStart(12, "0");
const key = Buffer.alloc(32, 1);
const kinds: readonly FixedReadKind[] = ["list_members", "list_enrollments"];
const original = { list_members: ORIGINAL_MEMBERS_SQL, list_enrollments: ORIGINAL_ENROLLMENTS_SQL };
const principal: SurfacePrincipal = {
  organizationId: id(1),
  memberId: id(2),
  serviceOrigin: "https://boardagent.test",
  clientId: id(3),
  protocolClientId: "fixed-identity-unit",
  accessTokenRecordId: id(4),
  tokenJti: id(5),
  keyId: "fixture",
  scopes: ["secretariat:admin"],
  roles: ["secretariat"],
  boardIds: [id(6)]
};
function row(kind: FixedReadKind, n: number): Row {
  const at = "2026-09-13T00:00:00.000001Z";
  //512 actual PostgreSQL-compatible Unicode characters: astral UTF8 or escaped
  //U+0001 controls. This is not512UTF8 bytes and contains no PostgreSQL NUL.
  const long = n % 2 === 0 ? "🙂".repeat(512) : "\u0001".repeat(512);
  return {
    cursor_at: at,
    cursor_id: id(n),
    item:
      kind === "list_members"
        ? {
            member_id: id(n),
            member_kind: "ai_system",
            display_name: long,
            state: "pending_activation",
            accountable_principal_id: id(7),
            identity_generation: "9223372036854775807",
            onboarding_generation: "9223372036854775807",
            row_version: "9223372036854775807",
            membership:
              n % 3 === 0
                ? null
                : {
                    membership_id: id(n + 1000),
                    board_id: id(6),
                    seat_role: "voting_member",
                    is_chair: true,
                    is_secretary: true,
                    voting_weight: "1000000000",
                    state: "suspended",
                    entitlement_generation: "9223372036854775807"
                  },
            created_at: at
          }
        : {
            invitation_id: id(n),
            member_id: id(8),
            issued_by: id(2),
            handoff_method: long,
            state: n % 3 === 0 ? "issued" : "consumed",
            issued_at: at,
            expires_at: "2026-09-14T00:00:00.000001Z",
            consumed_at: n % 3 === 0 ? null : at,
            pending_activation_member_id: n % 3 === 0 ? null : id(9)
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
  let source = Array.from({ length: amount }, (_, n) => row(kind, amount - n));
  const queryReservations: number[] = [];
  const query = vi.fn(async (sql: string, args?: unknown[]) => {
    expect(sql).toBe(original[kind]);
    queryReservations.push(manager.accounting.usedUnits);
    const member = kind === "list_members",
      at = args?.[member ? 2 : 1],
      cursor = args?.[member ? 3 : 2],
      take = args?.[member ? 4 : 3];
    expect(args?.[0]).toBeNull();
    if (member) expect(args?.[1]).toBeNull();
    expect(typeof take).toBe("number");
    return {
      rows: source
        .filter(
          (r) =>
            at === null ||
            r.cursor_at < String(at) ||
            (r.cursor_at === at && r.cursor_id < String(cursor))
        )
        .slice(0, take as number)
    };
  });
  const client = { query } as unknown as PoolClient,
    repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
      cursorKey: key
    });
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({}),
    authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const read = (limit = 100, cursor: string | null = null) =>
    repo.executeRead(principal, kind, {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      limit,
      cursor,
      state: null,
      ...(kind === "list_members" ? { board_id: null } : {})
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

describe("fixed bounded member and enrollment lists", () => {
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
        const expectedUnits = 8;
        try {
          const actual = await owner.produce(() => f.read());
          expect(f.queryReservations).toEqual([expectedUnits]);
          expect(manager.accounting.usedUnits).toBe(expectedUnits);
          const expected = result(kind, { items: f.source.map((r) => r.item), next_cursor: null });
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
  for (const kind of ["list_members", "list_enrollments"] as const) {
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
          for (const r of f.source) {
            const field = r.item[kind === "list_members" ? "display_name" : "handoff_method"];
            expect([...String(field)]).toHaveLength(512);
            expect(Buffer.byteLength(JSON.stringify(field))).toBeLessThanOrEqual(3074);
            for (const k of Object.keys(r.item))
              expect(Buffer.byteLength(k)).toBeLessThanOrEqual(64);
          }
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

  for (const kind of kinds)
    it("preserves original complete " + kind + " before caller admission", async () => {
      const manager = new ResponseAllocationManager(),
        f = fixture(kind, manager);
      const actual = await owned(manager, () => f.read());
      expect(actual).toEqual(
        result(kind, { items: f.source.map((r) => r.item), next_cursor: null })
      );
      expect(JSON.stringify(actual)).toBe(
        JSON.stringify(result(kind, { items: f.source.map((r) => r.item), next_cursor: null }))
      );
    });
  it("preserves repeated member occurrences with distinct memberships", async () => {
    const manager = new ResponseAllocationManager(),
      f = fixture("list_members", manager);
    f.source[1]!.item = { ...f.source[0]!.item, membership: f.source[1]!.item.membership! };
    f.source[1]!.cursor_id = f.source[0]!.cursor_id;
    const actual = await owned(manager, () => f.read());
    expect(actual.data).toEqual({ items: f.source.map((r) => r.item), next_cursor: null });
    expect((actual.data as Item).items).toHaveLength(2);
    // This preserves the existing query's duplicate occurrences, without claiming
    // to fix its existing member-only cursor ordering or skipped equal anchors.
  });
});
