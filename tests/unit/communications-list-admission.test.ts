import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  COMMUNICATIONS_PREFLIGHT_SQL,
  COMMUNICATIONS_CONTENT_SQL,
  PROPOSAL_INSPECTION_SQL,
  loadAdmittedCommunicationsList
} from "../../artifacts/server/src/communications-list-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

const id = (n: number) => `01993300-0000-7000-8000-${String(n).padStart(12, "0")}`;
const at = "2026-09-12T15:00:00.000000Z";
const inputs = (kind: "proposals" | "secretariat") => ({
  kind,
  boardId: id(1),
  memberId: id(2),
  state: null,
  cursorAt: null,
  cursorId: null,
  limit: 2
});

function fixture(
  kind: "proposals" | "secretariat",
  value: JsonValue = { exact: "Δ", aa: 1, z: 2 }
) {
  const raw = Buffer.from(JSON.stringify(value));
  const hash = createHash("sha256").update(raw).digest("hex");
  const metadata = {
    id: id(3),
    row_version: "1",
    cursor_at: at,
    canonical_bytes: kind === "proposals" ? String(raw.length) : "0",
    sha256: kind === "proposals" ? hash : null,
    supported: true,
    json_upper: "1000",
    property_count: "13",
    object_count: "2"
  };
  const item =
    kind === "proposals"
      ? { proposal_id: id(3), row_version: "1", payload_sha256: hash, payload: value }
      : { request_id: id(3), row_version: "1", turns: [] };
  let fullConstruction = 0;
  const query = vi.fn(
    async (sql: string, _values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }> => {
      if (sql === COMMUNICATIONS_PREFLIGHT_SQL[kind]) return { rows: [{ ...metadata }] };
      if (sql === PROPOSAL_INSPECTION_SQL)
        return { rows: [{ fits: true, cursor_id: id(3), cursor_at: at, raw_payload: raw }] };
      if (sql === COMMUNICATIONS_CONTENT_SQL[kind]) {
        fullConstruction += 1;
        return {
          rows: [
            {
              fits: true,
              cursor_id: id(3),
              cursor_at: at,
              item: kind === "proposals" ? { ...item, payload: null } : item
            }
          ]
        };
      }
      // Faithful legacy combined row supports the positive control and lets the
      // saturation baseline fail on actual premature construction, not a mock error.
      if (sql.startsWith("select jsonb_build_object(")) {
        fullConstruction += 1;
        return { rows: [{ cursor_id: id(3), cursor_at: at, item }] };
      }
      throw new Error("unexpected communications fixture query");
    }
  );
  return {
    raw,
    hash,
    item,
    metadata,
    query,
    client: { query } as unknown as PoolClient,
    constructions: () => fullConstruction
  };
}

function privateList(client: PoolClient, kind: "proposals" | "secretariat", limit = 2) {
  const repository = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repository as unknown as {
    readCommunications(
      client: PoolClient,
      principal: SurfacePrincipal,
      tool: string,
      input: Record<string, JsonValue>
    ): Promise<{ data: JsonValue }>;
  };
  return seam.readCommunications(
    client,
    { organizationId: id(99), memberId: id(2) } as SurfacePrincipal,
    kind === "proposals" ? "list_proposals" : "list_secretariat_requests",
    { board_id: id(1), limit, state: null, cursor: null }
  );
}

describe("communications list preconstruction admission", () => {
  it.each(["proposals", "secretariat"] as const)(
    "refuses a saturated %s list before full construction",
    async (kind) => {
      const f = fixture(kind);
      const manager = new ResponseAllocationManager();
      const held = [
        manager.tryReserve(
          responseAllocationPlan({
            kind: "communications_list",
            representation: "tool",
            sourceId: "other-frontier",
            sourceVersion: "1",
            sha256: "b".repeat(64),
            canonicalBytes: 0,
            listProjection: {
              jsonUpperBytes: "251645952",
              propertyCount: "0",
              objectOrArrayCount: "0"
            }
          })
        )
      ];
      for (let n = 0; n < 128; n += 1)
        held.push(
          manager.tryReserve(
            responseAllocationPlan({
              kind: "document",
              representation: "tool",
              sourceId: "small",
              sourceVersion: "1",
              sha256: "c".repeat(64),
              canonicalBytes: 1
            })
          )
        );
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(owner.produce(() => privateList(f.client, kind))).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(f.constructions()).toBe(0);
        expect(f.query).toHaveBeenCalledTimes(1);
        expect(f.query.mock.calls[0]?.[0]).toBe(COMMUNICATIONS_PREFLIGHT_SQL[kind]);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        for (const lease of held) lease.release();
      }
    }
  );

  it.each(["proposals", "secretariat"] as const)(
    "preserves a positive %s page control",
    async (kind) => {
      const f = fixture(kind);
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        const returned = await owner.produce(() => privateList(f.client, kind));
        expect(returned.data).toEqual({ items: [f.item], next_cursor: null });
        expect(f.constructions()).toBe(1);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
  );

  it.each([null, false, 0])(
    "splices the exact primitive payload %s using presence rather than truthiness",
    async (value) => {
      const f = fixture("proposals", value);
      const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
      try {
        const rows = await owner.produce(() =>
          loadAdmittedCommunicationsList(f.client, inputs("proposals"))
        );
        expect(rows).toEqual([{ item: f.item, cursor_id: id(3), cursor_at: at }]);
        expect(f.query).toHaveBeenCalledTimes(3);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
  );

  it("refuses a known oversized nonpayload projection before inspecting raw bytes", async () => {
    const f = fixture("proposals");
    f.metadata.json_upper = "300000000";
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedCommunicationsList(f.client, inputs("proposals")))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.constructions()).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("stops after cancellation during scalar preflight", async () => {
    const f = fixture("proposals");
    const controller = new AbortController();
    f.query.mockImplementationOnce(async () => {
      controller.abort();
      return { rows: [f.metadata] };
    });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(controller.signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedCommunicationsList(f.client, inputs("proposals")))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it.each(["proposals", "secretariat"] as const)(
    "retains %s reservation after a fresh global gate refusal",
    async (kind) => {
      const f = fixture(kind);
      const original = f.query.getMockImplementation()!;
      f.query.mockImplementation(async (sql, values) =>
        sql === COMMUNICATIONS_CONTENT_SQL[kind]
          ? { rows: [{ fits: false, cursor_id: id(3), cursor_at: at, item: null }] }
          : original(sql, values)
      );
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(
          owner.produce(() => loadAdmittedCommunicationsList(f.client, inputs(kind)))
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(manager.accounting.usedUnits).toBeGreaterThan(0);
        owner.nativeTerminal();
        expect(manager.accounting.usedUnits).toBeGreaterThan(0);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
  );

  it("removes unseen proposal IDs from the final SQL frontier before content construction", async () => {
    const f = fixture("proposals");
    const original = f.query.getMockImplementation()!;
    f.query.mockImplementation(async (sql, values) => {
      if (sql === COMMUNICATIONS_PREFLIGHT_SQL.proposals)
        return { rows: [f.metadata, { ...f.metadata, id: id(4) }] };
      return original(sql, values);
    });
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    try {
      await owner.produce(() => loadAdmittedCommunicationsList(f.client, inputs("proposals")));
      const final = f.query.mock.calls.find(
        ([sql]) => sql === COMMUNICATIONS_CONTENT_SQL.proposals
      )!;
      expect(JSON.parse(final[1]![6] as string).map((row: { id: string }) => row.id)).toEqual([
        id(3)
      ]);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("requires an owner before issuing a query", async () => {
    const f = fixture("proposals");
    await expect(loadAdmittedCommunicationsList(f.client, inputs("proposals"))).rejects.toThrow(
      "native response allocation owner"
    );
    expect(f.query).not.toHaveBeenCalled();
  });

  it("charges all 501 selected roots before returning a 500-item page and cursor", async () => {
    const f = fixture("secretariat");
    const frontier = Array.from({ length: 501 }, (_, n) => ({ ...f.metadata, id: id(1000 - n) }));
    const manager = new ResponseAllocationManager();
    const query = vi.fn(async (sql: string, values: unknown[]) => {
      expect(values[5]).toBe(501);
      if (sql === COMMUNICATIONS_PREFLIGHT_SQL.secretariat) return { rows: frontier };
      if (sql === COMMUNICATIONS_CONTENT_SQL.secretariat) {
        expect(JSON.parse(values[6] as string)).toHaveLength(501);
        // The complete page metadata is charged before the mock constructs any
        // rows; the discarded lookahead is included in that same reservation.
        expect(manager.accounting.usedUnits).toBeGreaterThan(3);
        return {
          rows: frontier.map((row) => ({
            fits: true,
            cursor_id: row.id,
            cursor_at: at,
            item: { request_id: row.id, row_version: "1", turns: [] }
          }))
        };
      }
      throw new Error("unexpected maximum-page query");
    });
    const owner = manager.openRequest(new AbortController().signal);
    try {
      const returned = await owner.produce(() =>
        privateList({ query } as unknown as PoolClient, "secretariat", 500)
      );
      const page = returned.data as { items: Array<{ request_id: string }>; next_cursor: string };
      expect(page.items).toHaveLength(500);
      expect(page.items.map((item) => item.request_id)).toEqual(
        frontier.slice(0, 500).map((row) => row.id)
      );
      expect(page.next_cursor).toEqual(expect.any(String));
      expect(page.next_cursor.length).toBeGreaterThan(0);
      expect(query).toHaveBeenCalledTimes(2);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
